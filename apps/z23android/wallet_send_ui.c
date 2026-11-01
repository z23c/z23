/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_send_ui.h"
#include "base/cleanse.h"
#include "controller.h"
#include "device_key.h"
#include "jni_util.h"
#include "scan.h"
#include "secure_window.h"
#include "wallet_send_device.h"
#include "wallet_send_node.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#define MATCH (-1)
#define WRAP (-2)
#define WHITE 0xffffffffu
#define SOFT 0xffd0d0d0u
#define AMBER 0xffe8b04cu
#define BUTTON_COLOR 0xff2b2b2bu
#define SEND_COLOR 0xff1f6f3fu
#define MEMO_PANEL 0xff1c2430u
#define INPUT_TYPE_DECIMAL 8194          /* TYPE_CLASS_NUMBER | TYPE_NUMBER_FLAG_DECIMAL */
#define INPUT_TYPE_ADDRESS 0x80001       /* TYPE_CLASS_TEXT | TYPE_TEXT_FLAG_NO_SUGGESTIONS */
#define IME_NO_LEARNING 0x1000000        /* IME_FLAG_NO_PERSONALIZED_LEARNING */
#define GRAVITY_CENTER_HORIZONTAL 1
#define BUTTONS_MAX 8
#define TEXT_CAP (ZAPP_PAY_INPUT_MAX + 1)
#define DETACH_WAIT_STEPS 12

enum button { B_SEND, B_CANCEL, B_RETRY, B_DONE, B_SCAN, B_ENTER, B_USE_ADDRESS, B_SET_AMOUNT };

static struct {
    ANativeActivity *activity;
    JavaVM *vm;
    jobject app, container, address_input, amount_input, buttons[BUTTONS_MAX];
    enum button button_id[BUTTONS_MAX];
    size_t button_count;
    struct wss *screen, *retired;
    struct wsn node;
    struct wsd device;
    void (*changed)(void);
    bool flow;       /* a payment is open on the screen and has not been left */
    bool entering;   /* the address field is shown */
    bool dropped;    /* a tap was dropped because another window covered the app */
    char notice[WSS_LINE];
    char hint[WSS_LINE];
    unsigned version, drawn_version;
    struct wss_view drawn;
    bool is_drawn;
} ui;

/* ---- the host: clock, random bytes and a JVM-attached worker ---- */

static bool host_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    size_t got = 0;
    while (got < len) {
        ssize_t n = getrandom(out + got, len - got, 0);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}
static uint64_t host_now(void *ctx)
{
    struct timespec at;
    (void)ctx;
    clock_gettime(CLOCK_MONOTONIC, &at);
    return (uint64_t)at.tv_sec * 1000u + (uint64_t)at.tv_nsec / 1000000u;
}
static void host_redraw(void *ctx)
{
    (void)ctx;
    if (ui.changed) ui.changed();
}

/* The worker's JNIEnv: the keystore calls need the environment of the thread that makes them, and only a worker
 * that this file attached has one. */
static _Thread_local JNIEnv *worker_env;
static _Thread_local struct zapp_devkey_jni worker_key;
struct launch { void (*job)(void *arg); void *arg; };
static void *worker_main(void *raw)
{
    struct launch launch = *(struct launch *)raw;
    JNIEnv *env = NULL;
    free(raw);
    bool attached = ui.vm && (*ui.vm)->AttachCurrentThread(ui.vm, &env, NULL) == JNI_OK;
    worker_env = attached ? env : NULL;
    launch.job(launch.arg);
    worker_env = NULL;
    if (attached) (*ui.vm)->DetachCurrentThread(ui.vm);
    return NULL;
}
static bool host_spawn(void *ctx, void (*job)(void *arg), void *arg)
{
    pthread_t thread;
    struct launch *launch = malloc(sizeof(*launch));
    (void)ctx;
    if (!launch) return false;
    *launch = (struct launch){job, arg};
    if (pthread_create(&thread, NULL, worker_main, launch) != 0) { free(launch); return false; }
    (void)pthread_detach(thread);
    return true;
}
static bool key_ops(void *ctx, struct zapp_devkey_ops *out)
{
    (void)ctx;
    if (!worker_env || !ui.app) return false;
    worker_key = (struct zapp_devkey_jni){worker_env, ui.app};
    zapp_devkey_jni_ops(out, &worker_key);
    return true;
}
static bool node_run(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    (void)ctx;
    return zapp_controller_send_run(op, input, timeout_ms, out, cap);
}
static bool node_paused(void *ctx)
{
    (void)ctx;
    return zapp_controller_node_paused();
}

bool zapp_send_attach(ANativeActivity *activity, void (*changed)(void))
{
    struct wss_deps deps = {.network = ZAPP_SCAN_NETWORK};
    if (!activity || ui.screen) return false;
    if (ui.retired && wss_destroy(ui.retired)) ui.retired = NULL;
    ui.activity = activity;
    ui.vm = activity->vm;
    ui.changed = changed;
    wsn_init(&ui.node, &(struct wsn_runner){NULL, node_run, node_paused}, ZAPP_SCAN_NETWORK);
    wsn_ops(&ui.node, &deps.node);
    if (!wsd_init(&ui.device, NULL, key_ops, activity->internalDataPath)) return false;
    wsd_ops(&ui.device, &deps.device);
    deps.host = (struct wss_host_ops){NULL, host_random, host_now, host_spawn, host_redraw, NULL};
    zapp_secure_window_ops(&deps.secure, activity);
    ui.screen = wss_create(&deps);
    return ui.screen != NULL;
}

void zapp_send_detach(JNIEnv *env)
{
    struct timespec step = {.tv_nsec = 250000000L};
    for (int i = 0; ui.screen && i < DETACH_WAIT_STEPS; ++i) {
        if (wss_destroy(ui.screen)) ui.screen = NULL;
        else { wss_on_tick(ui.screen); nanosleep(&step, NULL); }
    }
    /* A wallet that is still locking keeps its screen and the activity reference its worker may use. */
    if (ui.screen) { ui.retired = ui.screen; ui.screen = NULL; }
    else if (ui.app) { (*env)->DeleteGlobalRef(env, ui.app); ui.app = NULL; }
    ui.flow = false;
    ui.activity = NULL;
}

/* ---- widgets ---- */

static bool text_view(JNIEnv *env, const char *text, float sp, uint32_t color)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.app);
    bool ok = view && zj_typography(env, view, sp, (jint)color) && zj_padding(env, view, 0, 6) && zj_text(env, view, text) &&
              zj_bool_property(env, view, "setTextIsSelectable", false) && zj_bool_property(env, view, "setLongClickable", false) &&
              zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 0, 0, 0) && zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
/* Words written by another person, on a panel of their own so they cannot pass for a line the wallet wrote. */
static bool memo_view(JNIEnv *env, const char *text)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.app);
    bool ok = view && zj_typography(env, view, 14.0f, (jint)SOFT) && zj_pill(env, view, (jint)MEMO_PANEL, 8.0f) &&
              zj_padding(env, view, 12, 10) && zj_text(env, view, text) && zj_bool_property(env, view, "setTextIsSelectable", false) &&
              zj_bool_property(env, view, "setLongClickable", false) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 2, 0, 2) &&
              zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool input_view(JNIEnv *env, const char *hint, int type, jobject *keep)
{
    jobject view = zj_widget(env, "android/widget/EditText", ui.app);
    bool ok = view && zj_typography(env, view, 18.0f, (jint)WHITE) && zj_int_property(env, view, "setInputType", type) &&
              zj_int_property(env, view, "setImeOptions", IME_NO_LEARNING) && zj_int_property(env, view, "setHintTextColor", (jint)0xff808080u) &&
              zj_char_sequence(env, view, "setHint", hint) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 8, 0, 0) &&
              zj_append(env, ui.container, view) && zj_keep(env, keep, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
/* Send is the one button that moves money: the platform drops its touches while another window covers it, in addition to
 * the native filter of the shell. */
static bool button_view(JNIEnv *env, enum button id, const char *text, uint32_t color, bool filter_obscured)
{
    jobject view = zj_widget(env, "android/widget/Button", ui.app);
    bool ok = view && ui.button_count < BUTTONS_MAX && zj_typography(env, view, 16.0f, (jint)WHITE) &&
              zj_bool_property(env, view, "setAllCaps", false) && zj_pill(env, view, (jint)color, 24.0f) && zj_flatten(env, view) &&
              zj_text(env, view, text) && zj_margins(env, view, MATCH, WRAP, 0.0f, 4, 4, 4, 4) &&
              (!filter_obscured || zj_bool_property(env, view, "setFilterTouchesWhenObscured", true)) &&
              zj_append(env, ui.container, view) && zj_keep(env, &ui.buttons[ui.button_count], view);
    if (ok) ui.button_id[ui.button_count++] = id;
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static void release_widgets(JNIEnv *env)
{
    jmethodID clear = ui.container ? zj_method(env, ui.container, "removeAllViews", "()V") : NULL;
    if (clear) (*env)->CallVoidMethod(env, ui.container, clear);
    (void)zj_clean(env);
    for (size_t i = 0; i < ui.button_count; ++i) (*env)->DeleteGlobalRef(env, ui.buttons[i]);
    ui.button_count = 0;
    if (ui.address_input) (*env)->DeleteGlobalRef(env, ui.address_input);
    if (ui.amount_input) (*env)->DeleteGlobalRef(env, ui.amount_input);
    ui.address_input = ui.amount_input = NULL;
}

/* ---- drawing ---- */

static void line_if(JNIEnv *env, const char *text, float sp, uint32_t color)
{
    if (text[0]) (void)text_view(env, text, sp, color);
}
static void draw_review(JNIEnv *env, const struct wss_view *v)
{
    char text[WSS_LINE + 32];
    (void)text_view(env, v->amount, 40.0f, WHITE);
    snprintf(text, sizeof(text), "%s payment", v->kind);
    (void)text_view(env, text, 16.0f, SOFT);
    (void)text_view(env, "To", 14.0f, SOFT);
    (void)text_view(env, v->address, 18.0f, WHITE);
    snprintf(text, sizeof(text), "Fee %s", v->fee);
    (void)text_view(env, text, 16.0f, SOFT);
    if (v->remains[0]) {
        snprintf(text, sizeof(text), "%s left after this payment", v->remains);
        (void)text_view(env, text, 16.0f, SOFT);
    }
    line_if(env, v->fleet, 14.0f, SOFT);
    line_if(env, v->warning, 14.0f, AMBER);
    line_if(env, v->note, 14.0f, AMBER);
    if (v->memo[0]) {
        (void)text_view(env, v->memo_label, 14.0f, SOFT);
        (void)memo_view(env, v->memo);
    }
}
static void draw_flow(JNIEnv *env, const struct wss_view *v)
{
    if (v->review) draw_review(env, v);
    line_if(env, v->status, 16.0f, v->check_history ? AMBER : SOFT);
    line_if(env, ui.hint, 14.0f, AMBER);
    if (ui.dropped) (void)text_view(env, "Another app is drawing over this screen, so your tap was ignored.", 14.0f, AMBER);
    if (v->state == WS_PARSED) {
        (void)input_view(env, "Amount in ZCL", INPUT_TYPE_DECIMAL, &ui.amount_input);
        (void)button_view(env, B_SET_AMOUNT, "Set amount", BUTTON_COLOR, false);
    }
    if (v->can_send) (void)button_view(env, B_SEND, "Send", SEND_COLOR, true);
    if (v->can_retry) (void)button_view(env, B_RETRY, "Try again", BUTTON_COLOR, false);
    if (v->can_cancel) (void)button_view(env, B_CANCEL, "Cancel", BUTTON_COLOR, false);
    if (v->can_leave && v->state != WS_BROADCAST) (void)button_view(env, B_SCAN, "Scan another code", BUTTON_COLOR, false);
    if (v->can_leave) (void)button_view(env, B_DONE, "Done", BUTTON_COLOR, false);
}
/* No payment is open: a notice, and the two ways to name one. */
static void draw_blank(JNIEnv *env)
{
    line_if(env, ui.notice, 16.0f, SOFT);
    (void)button_view(env, B_SCAN, "Scan again", BUTTON_COLOR, false);
    (void)button_view(env, B_ENTER, "Enter address", BUTTON_COLOR, false);
    if (ui.entering) {
        (void)input_view(env, "Address or payment code", INPUT_TYPE_ADDRESS, &ui.address_input);
        (void)button_view(env, B_USE_ADDRESS, "Use this address", BUTTON_COLOR, false);
    }
    (void)button_view(env, B_DONE, "Back", BUTTON_COLOR, false);
}

void zapp_send_ui_render(JNIEnv *env)
{
    struct wss_view v;
    if (!ui.container) return;
    memset(&v, 0, sizeof(v));
    if (ui.flow && ui.screen) {
        wss_view(ui.screen, &v);
        v.elapsed_s = 0;
    }
    if (ui.is_drawn && ui.drawn_version == ui.version && !memcmp(&v, &ui.drawn, sizeof(v))) return;
    release_widgets(env);
    (void)text_view(env, "Send", 24.0f, WHITE);
    if (ui.flow && ui.screen) draw_flow(env, &v);
    else draw_blank(env);
    /* The phone must not sleep while a payment is built: it takes about two minutes. */
    (void)zj_bool_property(env, ui.container, "setKeepScreenOn", v.busy);
    ui.drawn = v;
    ui.drawn_version = ui.version;
    ui.is_drawn = true;
}
void zapp_send_ui_clear(JNIEnv *env)
{
    release_widgets(env);
    (void)zj_bool_property(env, ui.container, "setKeepScreenOn", false);
    memory_cleanse(&ui.drawn, sizeof(ui.drawn));
    ui.is_drawn = false;
}

/* ---- opening and leaving ---- */

static void say(char *field, const char *text)
{
    snprintf(field, WSS_LINE, "%s", text);
    ui.version++;
}
static void open_payment(const struct zapp_payment *pay)
{
    if (ui.screen && wss_begin(ui.screen, pay)) {
        ui.flow = true;
        ui.notice[0] = ui.hint[0] = 0;
        ui.entering = false;
        ui.dropped = false;
        ui.version++;
        return;
    }
    const char *refused = zapp_secure_window_refusal();
    char text[WSS_LINE];
    if (refused) snprintf(text, sizeof(text), "This phone would not let the app %s, so the payment is not shown.", refused);
    else snprintf(text, sizeof(text), "Another payment is still finishing. Try again in a moment.");
    ui.flow = false;
    say(ui.notice, text);
}
void zapp_send_ui_open(JNIEnv *env, const struct zapp_payment *pay, const char *notice)
{
    ui.entering = false;
    ui.hint[0] = 0;
    say(ui.notice, notice ? notice : "");
    if (pay) open_payment(pay);
    else ui.flow = false;
    zapp_send_ui_render(env);
}

bool zapp_send_ui_leave(JNIEnv *env)
{
    if (ui.flow && ui.screen) {
        if (!wss_end(ui.screen)) return false;
        ui.flow = false;
    }
    ui.entering = false;
    ui.notice[0] = ui.hint[0] = 0;
    ui.dropped = false;
    ui.version++;
    zapp_send_ui_clear(env);
    return true;
}
void zapp_send_ui_pause(void)
{
    if (ui.flow && ui.screen) wss_on_pause(ui.screen);
}
void zapp_send_ui_tick(JNIEnv *env)
{
    if (ui.flow && ui.screen) wss_on_tick(ui.screen);
    if (ui.retired && wss_destroy(ui.retired)) ui.retired = NULL;
    else if (ui.retired) wss_on_tick(ui.retired);
    (void)env;
}
bool zapp_send_ui_owes(void) { return ui.flow || ui.retired; }
void zapp_send_ui_dropped(JNIEnv *env)
{
    ui.dropped = true;
    ui.version++;
    zapp_send_ui_render(env);
}

/* ---- input ---- */

bool zapp_send_ui_hit(JNIEnv *env, float x, float y, size_t *button)
{
    for (size_t i = 0; i < ui.button_count; ++i)
        if (zj_hit(env, ui.buttons[i], x, y)) { *button = i; return true; }
    return false;
}
/* The text of a field, or false when it cannot be read or does not fit. */
static bool read_input(JNIEnv *env, jobject input, char *out, size_t cap)
{
    bool ok = false;
    out[0] = 0;
    if (!input || (*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject text = zj_object_property(env, input, "getText", "()Landroid/text/Editable;");
    jobject string = text ? zj_object_property(env, text, "toString", "()Ljava/lang/String;") : NULL;
    ok = string && zj_copy_utf(env, (jstring)string, out, cap);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
/* The same parser as a scanned code: an address typed or pasted is a payment with no amount, a payment code is read whole. */
static void use_address(JNIEnv *env)
{
    char *text = calloc(1, TEXT_CAP);
    struct zapp_payment pay;
    if (!text) return;
    if (!read_input(env, ui.address_input, text, TEXT_CAP)) text[0] = 0;
    enum zapp_pay_refusal why = zapp_payment_parse(text, strlen(text), ZAPP_SCAN_NETWORK, &pay);
    memory_cleanse(text, TEXT_CAP);
    free(text);
    if (why != ZAPP_PAY_OK) {
        say(ui.notice, zapp_scan_refusal_text(why));
        return;
    }
    ui.entering = false;
    say(ui.notice, "");
    open_payment(&pay);
    memory_cleanse(&pay, sizeof(pay));
}
static void set_amount(JNIEnv *env)
{
    char text[64];
    uint64_t zat = 0;
    bool ok = read_input(env, ui.amount_input, text, sizeof(text)) && zapp_zat_parse(text, &zat) && zat > 0;
    memory_cleanse(text, sizeof(text));
    if (!ok) { say(ui.hint, "That is not an amount. Write it in ZCL, for example 1.5."); return; }
    ui.hint[0] = 0;
    ui.version++;
    wss_edit_amount(ui.screen, zat);
}

/* The buttons that act on the flow. The first is the only call that starts an authentication: the owner's tap on the
 * Send button of the plan on screen. */
static void press_flow(JNIEnv *env, int id)
{
    if (!ui.flow || !ui.screen) return;
    if (id == B_SEND) wss_tap_send(ui.screen, ui.drawn.serial);
    else if (id == B_CANCEL) wss_tap_cancel(ui.screen);
    else if (id == B_RETRY) wss_tap_retry(ui.screen);
    else if (id == B_SET_AMOUNT) set_amount(env);
}
enum zapp_send_outcome zapp_send_ui_press(JNIEnv *env, size_t button)
{
    enum zapp_send_outcome outcome = ZAPP_SEND_STAY;
    if (button >= ui.button_count) return outcome;
    ui.dropped = false;
    int id = (int)ui.button_id[button];
    if (id == B_DONE) outcome = ZAPP_SEND_LEAVE;
    else if (id == B_SCAN) outcome = ZAPP_SEND_SCAN;
    else if (id == B_ENTER) { ui.entering = true; ui.version++; }
    else if (id == B_USE_ADDRESS) use_address(env);
    else press_flow(env, id);
    if (outcome == ZAPP_SEND_STAY) zapp_send_ui_render(env);
    return outcome;
}

/* ---- lifecycle ---- */

bool zapp_send_ui_create(JNIEnv *env, jobject activity, jobject container)
{
    if (ui.container) return false;
    /* A reference left by a screen that was still locking stays with its worker; this activity gets its own. */
    ui.app = (*env)->NewGlobalRef(env, activity);
    ui.container = (*env)->NewGlobalRef(env, container);
    if (ui.app && ui.container && zj_int_property(env, ui.container, "setGravity", GRAVITY_CENTER_HORIZONTAL)) return true;
    zapp_send_ui_destroy(env);
    return false;
}
void zapp_send_ui_destroy(JNIEnv *env)
{
    zapp_send_ui_clear(env);
    if (ui.container) (*env)->DeleteGlobalRef(env, ui.container);
    ui.container = NULL;
}
