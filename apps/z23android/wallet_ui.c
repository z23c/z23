/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_ui.h"
#include "base/cleanse.h"
#include "controller.h"
#include "fleet.h"
#include "jni_util.h"
#include "secure_window.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MATCH (-1)
#define WRAP (-2)
#define WHITE 0xffffffffu
#define SOFT 0xffd0d0d0u
#define AMBER 0xffe8b04cu
#define BUTTON_COLOR 0xff2b2b2bu
#define MEMO_PANEL 0xff1c2430u
#define MEMO_SP 14.0f
#define QR_DP 260.0f
#define INPUT_TYPE_DECIMAL 8194 /* TYPE_CLASS_NUMBER | TYPE_NUMBER_FLAG_DECIMAL */
#define IME_NO_LEARNING 0x1000000 /* IME_FLAG_NO_PERSONALIZED_LEARNING */
#define AMOUNT_TEXT_CAP 64

static struct {
    jobject activity, container, input, buttons[WALLET_ITEMS_MAX];
    size_t button_item[WALLET_ITEMS_MAX], button_count;
    struct wallet_screen screen;
    unsigned version;
    bool drawn;
} ui;

/* ---- widgets ---- */

/* Text is never selectable: a long press would offer Copy and Share, and the clipboard is open to other apps. */
static bool text_view(JNIEnv *env, const char *text, float sp, uint32_t color)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.activity);
    bool ok = view && zj_typography(env, view, sp, (jint)color) && zj_padding(env, view, 0, 6) && zj_text(env, view, text) &&
        zj_bool_property(env, view, "setTextIsSelectable", false) && zj_bool_property(env, view, "setLongClickable", false) &&
        zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 0, 0, 0) && zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
/* Words written by another person: on a panel of their own, in a smaller size, so they cannot pass for a line the wallet wrote. */
static bool memo_view(JNIEnv *env, const char *text)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.activity);
    bool ok = view && zj_typography(env, view, MEMO_SP, (jint)SOFT) && zj_pill(env, view, (jint)MEMO_PANEL, 8.0f) && zj_padding(env, view, 12, 10) &&
        zj_text(env, view, text) && zj_bool_property(env, view, "setTextIsSelectable", false) &&
        zj_bool_property(env, view, "setLongClickable", false) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 2, 0, 2) &&
        zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool qr_view(JNIEnv *env, const char *code)
{
    size_t size = 0;
    unsigned char *bmp = zapp_fleet_qr_bmp(code, &size);
    jobject view = bmp ? zj_widget(env, "android/widget/ImageView", ui.activity) : NULL;
    bool ok = view && zj_bitmap(env, view, bmp, size) && zj_margins(env, view, zj_dp(QR_DP), zj_dp(QR_DP), 0.0f, 0, 8, 0, 8) &&
        zj_append(env, ui.container, view);
    free(bmp);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool input_view(JNIEnv *env, const char *hint)
{
    jobject view = zj_widget(env, "android/widget/EditText", ui.activity);
    bool ok = view && zj_typography(env, view, 18.0f, (jint)WHITE) && zj_int_property(env, view, "setInputType", INPUT_TYPE_DECIMAL) &&
        zj_int_property(env, view, "setImeOptions", IME_NO_LEARNING) && zj_int_property(env, view, "setHintTextColor", (jint)0xff808080u) &&
        zj_char_sequence(env, view, "setHint", hint) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 8, 0, 0) &&
        zj_append(env, ui.container, view) && zj_keep(env, &ui.input, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool button_view(JNIEnv *env, size_t item, const char *text)
{
    jobject view = zj_widget(env, "android/widget/Button", ui.activity);
    bool ok = view && ui.button_count < WALLET_ITEMS_MAX && zj_typography(env, view, 16.0f, (jint)WHITE) &&
        zj_bool_property(env, view, "setAllCaps", false) && zj_pill(env, view, (jint)BUTTON_COLOR, 24.0f) &&
        zj_flatten(env, view) && zj_text(env, view, text) && zj_margins(env, view, MATCH, WRAP, 0.0f, 4, 4, 4, 4) &&
        zj_append(env, ui.container, view) && zj_keep(env, &ui.buttons[ui.button_count], view);
    if (ok) ui.button_item[ui.button_count++] = item;
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}

static bool draw_item(JNIEnv *env, size_t index)
{
    const struct wallet_item *item = &ui.screen.items[index];
    switch (item->kind) {
    case WALLET_ITEM_TITLE: return text_view(env, item->text, 24.0f, WHITE);
    case WALLET_ITEM_AMOUNT: return text_view(env, item->text, 40.0f, WHITE);
    case WALLET_ITEM_TEXT: return text_view(env, item->text, 16.0f, SOFT);
    case WALLET_ITEM_NOTE: return text_view(env, item->text, 14.0f, AMBER);
    case WALLET_ITEM_MEMO: return memo_view(env, item->text);
    case WALLET_ITEM_ADDRESS: return text_view(env, item->text, 18.0f, WHITE);
    case WALLET_ITEM_QR: return qr_view(env, item->text);
    case WALLET_ITEM_INPUT: return input_view(env, item->text);
    case WALLET_ITEM_BUTTON: return button_view(env, index, item->text);
    }
    return false;
}

static void release_widgets(JNIEnv *env)
{
    jmethodID clear = ui.container ? zj_method(env, ui.container, "removeAllViews", "()V") : NULL;
    if (clear) (*env)->CallVoidMethod(env, ui.container, clear);
    (void)zj_clean(env);
    for (size_t i = 0; i < ui.button_count; ++i) (*env)->DeleteGlobalRef(env, ui.buttons[i]);
    ui.button_count = 0;
    if (ui.input) (*env)->DeleteGlobalRef(env, ui.input);
    ui.input = NULL;
}

void zapp_wallet_ui_clear(JNIEnv *env)
{
    release_widgets(env);
    memory_cleanse(&ui.screen, sizeof(ui.screen));
    ui.drawn = false;
}

void zapp_wallet_ui_render(JNIEnv *env)
{
    if (!ui.container) return;
    unsigned version = wallet_screens_snapshot(&ui.screen);
    if (ui.drawn && version == ui.version) return;
    release_widgets(env);
    for (size_t i = 0; i < ui.screen.count; ++i) (void)draw_item(env, i);
    ui.version = version;
    ui.drawn = true;
}

/* ---- input ---- */

bool zapp_wallet_ui_hit(JNIEnv *env, float x, float y, size_t *button)
{
    for (size_t i = 0; i < ui.button_count; ++i)
        if (zj_hit(env, ui.buttons[i], x, y)) { *button = i; return true; }
    return false;
}

/* The amount field's text, or false when it cannot be read or does not fit. */
static bool read_input(JNIEnv *env, char *out, size_t cap)
{
    bool ok = false;
    out[0] = '\0';
    if (!ui.input || (*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject text = zj_object_property(env, ui.input, "getText", "()Landroid/text/Editable;");
    jobject string = text ? zj_object_property(env, text, "toString", "()Ljava/lang/String;") : NULL;
    ok = string && zj_copy_utf(env, (jstring)string, out, cap);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}

void zapp_wallet_ui_dropped(JNIEnv *env, unsigned shell_drops)
{
    static unsigned seen;
    unsigned total = zapp_secure_window_obscured_gestures() + shell_drops;
    wallet_screens_dropped(total >= seen ? total - seen : total);
    seen = total;
    zapp_wallet_ui_render(env);
}

void zapp_wallet_ui_tick(JNIEnv *env)
{
    wallet_screens_tick();
    zapp_wallet_ui_render(env);
}

enum wallet_outcome zapp_wallet_ui_press(JNIEnv *env, size_t button)
{
    enum wallet_outcome outcome = WALLET_STAY;
    if (button >= ui.button_count) return outcome;
    const struct wallet_item item = ui.screen.items[ui.button_item[button]];
    if (item.action == WALLET_ACT_SET_AMOUNT) {
        char amount[AMOUNT_TEXT_CAP];
        (void)wallet_screens_set_amount(read_input(env, amount, sizeof(amount)) ? amount : "?");
        memory_cleanse(amount, sizeof(amount));
    } else outcome = wallet_screens_activate(item.action, item.arg);
    if (outcome == WALLET_STAY) zapp_wallet_ui_render(env);
    return outcome;
}

/* ---- lifecycle ---- */

bool zapp_wallet_ui_create(JNIEnv *env, jobject activity, jobject container)
{
    if (ui.container) return false;
    ui.activity = (*env)->NewGlobalRef(env, activity);
    ui.container = (*env)->NewGlobalRef(env, container);
    if (ui.activity && ui.container) return true;
    zapp_wallet_ui_destroy(env);
    return false;
}

void zapp_wallet_ui_destroy(JNIEnv *env)
{
    zapp_wallet_ui_clear(env);
    if (ui.container) (*env)->DeleteGlobalRef(env, ui.container);
    if (ui.activity) (*env)->DeleteGlobalRef(env, ui.activity);
    memset(&ui, 0, sizeof(ui));
}

/* ---- binding to the app ---- */

static struct { void (*changed)(void); } bound;

static bool bound_secure(void *activity, bool on) { return zapp_secure_window(activity, on); }
static bool bound_run(void *ctx, const char *op, const char *arg, char *out, size_t cap)
{
    (void)ctx;
    return zapp_controller_wallet_run(op, arg, out, cap);
}
static uint64_t bound_now(void *ctx)
{
    struct timespec at;
    (void)ctx;
    clock_gettime(CLOCK_MONOTONIC, &at);
    return (uint64_t)at.tv_sec * 1000u + (uint64_t)at.tv_nsec / 1000000u;
}
static void bound_changed(void *ctx)
{
    (void)ctx;
    if (bound.changed) bound.changed();
}

bool zapp_wallet_attach(ANativeActivity *activity, void (*changed)(void))
{
    struct wallet_env env = {activity, bound_secure, bound_run, bound_changed, bound_now, true};
    bound.changed = changed;
    return activity && wallet_screens_init(&env);
}
void zapp_wallet_detach(void) { wallet_screens_shutdown(); }
