/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "shell.h"
#include "camera.h"
#include "controller.h"
#include "home.h"
#include "jni_util.h"
#include "launcher.h"
#include "layout.h"
#include "secure_window.h"
#include "surface.h"
#include "pay_stash.h"
#include "setup_state.h"
#include "wallet_setup_ui.h"
#include "wallet_send_ui.h"
#include "wallet_ui.h"
#include <android/keycodes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MATCH (-1)
#define WRAP (-2)
#define NAV_MAX 16u
#define PATH_CAP 640
#define DARK 0xff111111u
#define BUTTON_COLOR 0xff2b2b2bu
#define WHITE 0xffffffffu
#define GRAVITY_CENTER_HORIZONTAL 1

enum screen { SCREEN_HOME, SCREEN_ASSISTANT, SCREEN_APPS, SCREEN_SETTINGS, SCREEN_SCAN, SCREEN_WALLET, SCREEN_SEND, SCREEN_SETUP, SCREEN_COUNT };
enum command { CMD_HOME, CMD_APPS, CMD_SETTINGS, CMD_HOME_SETTINGS, CMD_LAYOUT, CMD_SCAN_CANCEL, CMD_CAMERA_SETTINGS, CMD_CAMERA_PASTE, CMD_OUTCOME_DISMISS };
enum target_kind { TARGET_NONE, TARGET_NAV, TARGET_ROW, TARGET_TILE, TARGET_WALLET, TARGET_SEND, TARGET_SETUP };

struct nav { jobject view; enum command command; size_t arg; };
struct target { enum target_kind kind; size_t index; char id[ZAPP_NAME_CAP]; size_t card; unsigned button; };

static struct {
    jobject activity, roots[SCREEN_COUNT];
    zapp_native_action send;
    jobject notice_views[SCREEN_COUNT], outcome_view, outcome_panel, status_view, scan_view, scan_camera, scan_panel, apps_list;
    enum screen current, before_scan;
    bool send_from_wallet;
    bool preview, pair_seen, scan_dismissed, user_layout, rendered, camera_waiting;
    bool setup_offered;   /* the first launch without a wallet opened the setup screens once */
    unsigned scans_seen;
    struct zapp_layout *layout;
    char builtin[ZAPP_NAME_CAP], layout_notice[320], action_notice[160];
    char node_notice[sizeof(((struct zapp_view *)0)->node_action_notice)]; /* shown when the shell has no notice of its own */
    char files[PATH_CAP], external[PATH_CAP];
    struct timespec user_stamp;
    struct json_value phone, app_cards[ZAPP_LAUNCHER_MAX];
    bool phone_ok;
    struct zapp_launcher_app apps[ZAPP_LAUNCHER_MAX];
    size_t app_count;
    jobject rows[ZAPP_LAUNCHER_MAX];
    size_t row_count;
    struct nav navs[NAV_MAX];
    size_t nav_count;
    struct target pressed;
    float down_x, down_y;
    /* Obscured touches are dropped while the wallet is shown, whatever the window gate does. */
    struct zapp_touch_gate gate;
} shell;

static void go(JNIEnv *env, enum screen next);
static void show_home(JNIEnv *env);

/* ---- paths and the layout choice ---- */

static bool directory(JNIEnv *env, jobject activity, const char *method, const char *sig, char *out, size_t cap)
{
    bool ok;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jmethodID get = zj_method(env, activity, method, sig);
    jobject dir = get ? (*env)->CallObjectMethod(env, activity, get, NULL) : NULL;
    jobject path = zj_clean(env) && dir ? zj_object_property(env, dir, "getAbsolutePath", "()Ljava/lang/String;") : NULL;
    ok = path && zj_copy_utf(env, (jstring)path, out, cap);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static void choice_path(char *out, size_t cap) { snprintf(out, cap, "%s/home_layout", shell.files); }
static void load_choice(void)
{
    char path[PATH_CAP], name[ZAPP_NAME_CAP] = "";
    choice_path(path, sizeof(path));
    FILE *file = fopen(path, "r");
    if (file) { if (!fgets(name, sizeof(name), file)) name[0] = 0; fclose(file); }
    name[strcspn(name, "\n")] = 0;
    snprintf(shell.builtin, sizeof(shell.builtin), "%s", zapp_home_layout(name) ? name : zapp_home_layout_name(0));
}
static void save_choice(void)
{
    char path[PATH_CAP];
    choice_path(path, sizeof(path));
    FILE *file = fopen(path, "w");
    if (!file) return;
    fprintf(file, "%s\n", shell.builtin);
    fclose(file);
}
static void replace_layout(struct zapp_layout *layout, bool user)
{
    zapp_layout_free(shell.layout);
    shell.layout = layout; shell.user_layout = user;
}
static void adopt_builtin(const char *notice)
{
    const char *document = zapp_home_layout(shell.builtin);
    char reason[160];
    snprintf(shell.layout_notice, sizeof(shell.layout_notice), "%s", notice);
    replace_layout(document ? zapp_layout_parse(document, strlen(document), reason, sizeof(reason)) : NULL, false);
}
static void adopt_user(const char *path)
{
    size_t length = 0;
    char reason[160], notice[sizeof(shell.layout_notice)];
    char *data = zapp_layout_read(path, &length, reason, sizeof(reason));
    struct zapp_layout *layout = data ? zapp_layout_parse(data, length, reason, sizeof(reason)) : NULL;
    if (layout && !zapp_layout_screen(layout, "home")) {
        zapp_layout_free(layout); layout = NULL;
        snprintf(reason, sizeof(reason), "it has no home screen");
    }
    free(data);
    if (layout) { shell.layout_notice[0] = 0; replace_layout(layout, true); return; }
    snprintf(notice, sizeof(notice), "Layout file not used: %s. Showing the built-in layout.", reason);
    adopt_builtin(notice);
}
/* Reads layouts/home.json from the app's external files folder when it is new or changed; no file
 * means the built-in layout. */
static void load_layout(void)
{
    char path[PATH_CAP];
    struct stat info;
    snprintf(path, sizeof(path), "%s/layouts/home.json", shell.external);
    bool present = shell.external[0] && lstat(path, &info) == 0 && S_ISREG(info.st_mode);
    if (!present) {
        if (shell.user_layout || !shell.layout || shell.layout_notice[0]) adopt_builtin("");
        memset(&shell.user_stamp, 0, sizeof(shell.user_stamp));
        return;
    }
    if (shell.layout && info.st_mtim.tv_sec == shell.user_stamp.tv_sec && info.st_mtim.tv_nsec == shell.user_stamp.tv_nsec) return;
    shell.user_stamp = info.st_mtim;
    adopt_user(path);
}

/* ---- cards ---- */

static void release_cards(void)
{
    for (size_t i = 0; i < shell.app_count; ++i) json_free(&shell.app_cards[i]);
    shell.app_count = 0;
}
static void refresh_apps(JNIEnv *env, bool icons)
{
    char text[ZAPP_APP_CARD_CAP];
    release_cards();
    zapp_launcher_release(env, shell.apps, ZAPP_LAUNCHER_MAX);
    size_t count = zapp_launcher_list(env, shell.activity, shell.apps, ZAPP_LAUNCHER_MAX, icons);
    for (size_t i = 0; i < count; ++i) {
        size_t length = zapp_home_app_card(&shell.apps[i].entry, text, sizeof(text));
        json_init(&shell.app_cards[i]);
        if (!length || !json_read(&shell.app_cards[i], text, length)) json_init(&shell.app_cards[i]);
    }
    shell.app_count = count;
}
static void set_phone_card(const struct zapp_view *view)
{
    char text[2048];
    size_t length = zapp_home_phone_card(view, shell.preview, text, sizeof(text));
    if (shell.phone_ok) json_free(&shell.phone);
    json_init(&shell.phone);
    shell.phone_ok = length && json_read(&shell.phone, text, length);
}

/* ---- widgets of the app-drawn screens ---- */

static bool label(JNIEnv *env, jobject parent, const char *text, float sp, uint32_t color)
{
    jobject view = zj_widget(env, "android/widget/TextView", shell.activity);
    bool ok = view && zj_typography(env, view, sp, (jint)color) && zj_padding(env, view, 0, 6) && zj_text(env, view, text) &&
        zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 0, 0, 0) && zj_append(env, parent, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool button(JNIEnv *env, jobject parent, const char *text, enum command command, size_t arg, int weight)
{
    jobject view = zj_widget(env, "android/widget/Button", shell.activity);
    bool ok = view && shell.nav_count < NAV_MAX && zj_typography(env, view, 16.0f, (jint)WHITE) &&
        zj_bool_property(env, view, "setAllCaps", false) && zj_pill(env, view, (jint)BUTTON_COLOR, 24.0f) &&
        zj_flatten(env, view) && zj_text(env, view, text) && zj_margins(env, view, weight ? 0 : MATCH, WRAP, (float)weight, 4, 4, 4, 4) &&
        zj_append(env, parent, view) && zj_keep(env, &shell.navs[shell.nav_count].view, view);
    if (ok) { shell.navs[shell.nav_count].command = command; shell.navs[shell.nav_count++].arg = arg; }
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static jobject column(JNIEnv *env, uint32_t color, int padding_dp, bool horizontal)
{
    jobject view = zj_widget(env, "android/widget/LinearLayout", shell.activity);
    bool ok = view && zj_int_property(env, view, "setOrientation", horizontal ? 0 : 1) &&
        zj_int_property(env, view, "setBackgroundColor", (jint)color) && zj_padding(env, view, padding_dp, padding_dp);
    return ok ? view : NULL;
}
static jobject bar(JNIEnv *env, uint32_t color)
{
    jobject view = zj_widget(env, "android/widget/TextView", shell.activity);
    bool ok = view && zj_typography(env, view, 14.0f, (jint)WHITE) && zj_padding(env, view, 16, 10) &&
        zj_int_property(env, view, "setBackgroundColor", (jint)color) && zj_visible(env, view, false);
    return ok ? view : NULL;
}
/* A red notice bar at the top of a screen. */
static bool add_notice(JNIEnv *env, jobject root, enum screen which)
{
    jobject notice = bar(env, 0xff7a1f1fu);
    bool ok = notice && zj_append(env, root, notice) && zj_keep(env, &shell.notice_views[which], notice);
    if (notice) (*env)->DeleteLocalRef(env, notice);
    return ok;
}
static bool build_outcome(JNIEnv *env, jobject root)
{
    jobject outcome = bar(env, 0xff2b2b2bu), panel = column(env, DARK, 0, false);
    return outcome && panel && zj_bool_property(env, outcome, "setTextIsSelectable", true) &&
        zj_keep(env, &shell.outcome_view, outcome) && zj_keep(env, &shell.outcome_panel, panel) &&
        zj_visible(env, panel, false) && zj_append(env, panel, outcome) &&
        button(env, panel, "Dismiss", CMD_OUTCOME_DISMISS, 0, 0) && zj_append(env, root, panel);
}
/* Notice and scan outcome bars, the layout's host, and a footer that always offers Apps and Settings. */
static bool build_home(JNIEnv *env, jobject root)
{
    jobject host = zj_widget(env, "android/widget/FrameLayout", shell.activity);
    jobject footer = column(env, DARK, 8, true);
    bool ok = host && footer && add_notice(env, root, SCREEN_HOME) && build_outcome(env, root) && zj_padding(env, host, 20, 24) && zj_margins(env, host, MATCH, 0, 1.0f, 0, 0, 0, 0) &&
        zapp_surface_create(env, shell.activity, host) &&
        zj_append(env, root, host) && zj_append(env, root, footer) &&
        button(env, footer, "Apps", CMD_APPS, 0, 1) && button(env, footer, "Settings", CMD_SETTINGS, 0, 1);
    return ok;
}
static bool build_apps(JNIEnv *env, jobject root)
{
    jobject header = column(env, DARK, 0, true), scroll = zj_widget(env, "android/widget/ScrollView", shell.activity);
    jobject list = column(env, DARK, 8, false);
    bool ok = header && scroll && list && add_notice(env, root, SCREEN_APPS) && button(env, header, "Home", CMD_HOME, 0, 1) &&
        button(env, header, "Android home settings", CMD_HOME_SETTINGS, 0, 2) && zj_append(env, root, header) &&
        zj_margins(env, scroll, MATCH, 0, 1.0f, 0, 0, 0, 0) && zj_append(env, scroll, list) && zj_append(env, root, scroll) &&
        zj_keep(env, &shell.apps_list, list);
    return ok;
}
/* A scroll view filling the rest of root around a column for the screen's content, so large text or a sideways
 * phone cuts nothing off. Returns the column as a local reference the caller deletes, or NULL on failure. */
static jobject scroll_column(JNIEnv *env, jobject root, int padding_dp)
{
    jobject scroll = zj_widget(env, "android/widget/ScrollView", shell.activity), content = column(env, DARK, padding_dp, false);
    bool ok = scroll && content && zj_margins(env, scroll, MATCH, 0, 1.0f, 0, 0, 0, 0) && zj_append(env, scroll, content) &&
        zj_append(env, root, scroll);
    if (scroll) (*env)->DeleteLocalRef(env, scroll);
    if (!ok && content) { (*env)->DeleteLocalRef(env, content); content = NULL; }
    return content;
}
static bool build_settings(JNIEnv *env, jobject root)
{
    jobject status = zj_widget(env, "android/widget/TextView", shell.activity);
    jobject content = status && add_notice(env, root, SCREEN_SETTINGS) ? scroll_column(env, root, 0) : NULL;
    bool ok = content && label(env, content, "Home settings", 24.0f, WHITE) && zj_typography(env, status, 15.0f, (jint)0xffb0b0b0u) &&
        zj_append(env, content, status) && zj_keep(env, &shell.status_view, status);
    for (size_t i = 0; ok && i < zapp_home_layout_count(); ++i) {
        char text[ZAPP_NAME_CAP + 16];
        snprintf(text, sizeof(text), "Layout: %s", zapp_home_layout_name(i));
        ok = button(env, content, text, CMD_LAYOUT, i, 0);
    }
    ok = ok && button(env, content, "Android home settings", CMD_HOME_SETTINGS, 0, 0) && button(env, content, "Home", CMD_HOME, 0, 0);
    if (status) (*env)->DeleteLocalRef(env, status);
    if (content) (*env)->DeleteLocalRef(env, content);
    return ok;
}
/* The line under the camera picture that says what to aim at. */
static bool scan_hint(JNIEnv *env, jobject camera)
{
    jobject hint = zj_widget(env, "android/widget/TextView", shell.activity);
    bool ok = hint && zj_typography(env, hint, 17.0f, (jint)WHITE) && zj_padding(env, hint, 16, 10) &&
        zj_int_property(env, hint, "setGravity", GRAVITY_CENTER_HORIZONTAL) &&
        zj_text(env, hint, zapp_camera_screen(ZAPP_CAMERA_GRANTED).hint) && zj_margins(env, hint, MATCH, WRAP, 0.0f, 0, 0, 0, 0) &&
        zj_append(env, camera, hint);
    if (hint) (*env)->DeleteLocalRef(env, hint);
    return ok;
}
/* The camera preview, the line that says what to point it at, and Cancel. */
static bool build_scan_camera(JNIEnv *env, jobject root)
{
    jobject camera = column(env, 0xff000000u, 0, false);
    jobject image = zj_widget(env, "android/widget/ImageView", shell.activity);
    bool ok = camera && image && zj_margins(env, image, MATCH, 0, 1.0f, 0, 0, 0, 0) && zj_append(env, camera, image) &&
        zj_keep(env, &shell.scan_view, image) && scan_hint(env, camera) && button(env, camera, "Cancel", CMD_SCAN_CANCEL, 0, 0) &&
        zj_margins(env, camera, MATCH, 0, 1.0f, 0, 0, 0, 0) && zj_append(env, root, camera) && zj_keep(env, &shell.scan_camera, camera);
    if (image) (*env)->DeleteLocalRef(env, image);
    if (camera) (*env)->DeleteLocalRef(env, camera);
    return ok;
}
/* The words and the two buttons that lead on when camera access is off. Hidden until that state. */
static bool build_scan_panel(JNIEnv *env, jobject root)
{
    struct zapp_camera_screen words = zapp_camera_screen(ZAPP_CAMERA_SETTINGS);
    jobject panel = column(env, DARK, 16, false);
    bool ok = panel && zj_margins(env, panel, MATCH, WRAP, 0.0f, 0, 0, 0, 0) && zj_append(env, root, panel) &&
        zj_keep(env, &shell.scan_panel, panel) && label(env, panel, words.text, 17.0f, WHITE) &&
        button(env, panel, words.open, CMD_CAMERA_SETTINGS, 0, 0) && button(env, panel, words.paste, CMD_CAMERA_PASTE, 0, 0) &&
        zj_visible(env, panel, false);
    if (panel) (*env)->DeleteLocalRef(env, panel);
    return ok;
}
static bool build_scan(JNIEnv *env, jobject root)
{
    return build_scan_camera(env, root) && build_scan_panel(env, root);
}
/* The scan screen shows the camera, or, when camera access is off, the words and the buttons that lead on. */
static void show_scan_screen(JNIEnv *env, enum zapp_camera_access access)
{
    bool preview = zapp_camera_screen(access).preview;
    (void)zj_visible(env, shell.scan_camera, preview);
    (void)zj_visible(env, shell.scan_panel, !preview);
}
/* A screen with a text field takes the keyboard's height as padding at its bottom (the system window insets include the
 * keyboard under adjustResize), so its scroll view ends above the keyboard and the focused field scrolls into view. The
 * window draws behind the system bars (setDecorFitsSystemWindows false), so no screen is resized unless it asks. */
static bool fits_keyboard(JNIEnv *env, jobject root) { return zj_bool_property(env, root, "setFitsSystemWindows", true); }
/* The wallet pages scroll above a fixed bar that holds their Back. */
static bool build_wallet(JNIEnv *env, jobject root)
{
    jobject content = fits_keyboard(env, root) ? scroll_column(env, root, 16) : NULL, footer = content ? column(env, DARK, 0, false) : NULL;
    bool ok = footer && zj_padding4(env, footer, 16, 0, 16, 8) && zj_append(env, root, footer) &&
        zapp_wallet_ui_create(env, shell.activity, content, footer);
    if (footer) (*env)->DeleteLocalRef(env, footer);
    if (content) (*env)->DeleteLocalRef(env, content);
    return ok;
}
static bool build_send(JNIEnv *env, jobject root)
{
    jobject content = fits_keyboard(env, root) && add_notice(env, root, SCREEN_SEND) ? scroll_column(env, root, 16) : NULL;
    bool ok = content && zapp_send_ui_create(env, shell.activity, content);
    if (content) (*env)->DeleteLocalRef(env, content);
    return ok;
}
static bool build_setup(JNIEnv *env, jobject root)
{
    jobject content = fits_keyboard(env, root) && add_notice(env, root, SCREEN_SETUP) ? scroll_column(env, root, 16) : NULL;
    bool ok = content && zapp_setup_ui_create(env, shell.activity, content);
    if (content) (*env)->DeleteLocalRef(env, content);
    return ok;
}
static bool add_screen(JNIEnv *env, jobject stage, enum screen which, jobject root)
{
    bool ok = root && zj_margins(env, root, MATCH, MATCH, 0.0f, 0, 0, 0, 0) && zj_visible(env, root, which == SCREEN_HOME) &&
        zj_append(env, stage, root) && zj_keep(env, &shell.roots[which], root);
    if (root && which != SCREEN_ASSISTANT) (*env)->DeleteLocalRef(env, root);
    return ok;
}
static bool build_pages(JNIEnv *env, jobject stage, jobject home, jobject apps, jobject settings)
{
    jobject scan = column(env, 0xff000000u, 0, false), wallet = column(env, DARK, 0, false), send = column(env, DARK, 0, false), setup = column(env, DARK, 0, false);
    return build_home(env, home) && build_apps(env, apps) && build_settings(env, settings) && build_scan(env, scan) &&
           build_wallet(env, wallet) && build_send(env, send) && build_setup(env, setup) && add_screen(env, stage, SCREEN_HOME, home) &&
           add_screen(env, stage, SCREEN_APPS, apps) && add_screen(env, stage, SCREEN_SETTINGS, settings) &&
           add_screen(env, stage, SCREEN_SCAN, scan) && add_screen(env, stage, SCREEN_WALLET, wallet) &&
           add_screen(env, stage, SCREEN_SEND, send) && add_screen(env, stage, SCREEN_SETUP, setup);
}
static bool build_stage(JNIEnv *env, jobject assistant)
{
    jobject stage = zj_widget(env, "android/widget/FrameLayout", shell.activity);
    jobject home = column(env, DARK, 0, false), apps = column(env, DARK, 12, false), settings = column(env, DARK, 20, false);
    bool ok = stage && build_pages(env, stage, home, apps, settings) && add_screen(env, stage, SCREEN_ASSISTANT, assistant);
    if (ok) {
        jmethodID set = zj_method(env, shell.activity, "setContentView", "(Landroid/view/View;)V");
        if (set) (*env)->CallVoidMethod(env, shell.activity, set, stage);
        ok = set && zj_clean(env);
    }
    return ok;
}

/* ---- immersive mode ---- */

/* Hides the system bars; a swipe from the edge shows them briefly. The controller exists only once
 * the window is attached, so this runs again on resume and focus. */
void zapp_shell_immersive(JNIEnv *env)
{
    if (!shell.activity || (*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return; }
    jobject window = zj_object_property(env, shell.activity, "getWindow", "()Landroid/view/Window;");
    jmethodID fits = window ? zj_method(env, window, "setDecorFitsSystemWindows", "(Z)V") : NULL;
    if (fits) (*env)->CallVoidMethod(env, window, fits, JNI_FALSE);
    jobject controller = fits && zj_clean(env) ? zj_object_property(env, window, "getInsetsController", "()Landroid/view/WindowInsetsController;") : NULL;
    jclass type = controller ? (*env)->FindClass(env, "android/view/WindowInsets$Type") : NULL;
    jmethodID bars = type && zj_clean(env) ? (*env)->GetStaticMethodID(env, type, "systemBars", "()I") : NULL;
    jint mask = bars ? (*env)->CallStaticIntMethod(env, type, bars) : 0;
    jmethodID hide = mask && zj_clean(env) ? zj_method(env, controller, "hide", "(I)V") : NULL;
    jmethodID behavior = hide ? zj_method(env, controller, "setSystemBarsBehavior", "(I)V") : NULL;
    if (behavior) {
        (*env)->CallVoidMethod(env, controller, hide, mask);
        (*env)->CallVoidMethod(env, controller, behavior, 2);
    }
    (void)zj_clean(env);
    (*env)->PopLocalFrame(env, NULL);
}

/* ---- navigation ---- */

static void set_text(JNIEnv *env, jobject view, const char *text)
{
    if (view) { (void)zj_text(env, view, text); (void)zj_visible(env, view, text[0] != 0); }
}
static void set_outcome(JNIEnv *env, const char *text)
{
    set_text(env, shell.outcome_view, text);
    if (shell.outcome_panel) (void)zj_visible(env, shell.outcome_panel, text[0] != 0);
}
static void show_notice(JNIEnv *env)
{
    const char *text = shell.action_notice[0] ? shell.action_notice : shell.node_notice[0] ? shell.node_notice : shell.layout_notice;
    for (int i = 0; i < SCREEN_COUNT; ++i) set_text(env, shell.notice_views[i], text);
}
static void settings_status(JNIEnv *env)
{
    char text[400];
    if (shell.user_layout) snprintf(text, sizeof(text), "Using layouts/home.json from the app's files folder. Delete it to use a built-in layout.");
    else snprintf(text, sizeof(text), "Using the built-in %s layout.%s", shell.builtin, shell.layout_notice[0] ? " The layout file was not used." : "");
    (void)zj_text(env, shell.status_view, text);
}
/* Adds the list row of app i: its icon and label. False when the local reference frame could not open. */
static bool add_app_row(JNIEnv *env, size_t i)
{
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject row = column(env, DARK, 4, true), icon = zj_widget(env, "android/widget/ImageView", shell.activity);
    jmethodID set = icon ? zj_method(env, icon, "setImageDrawable", "(Landroid/graphics/drawable/Drawable;)V") : NULL;
    if (set && shell.apps[i].icon) (*env)->CallVoidMethod(env, icon, set, shell.apps[i].icon);
    bool ok = row && icon && zj_clean(env) && zj_margins(env, icon, zj_dp(40.0f), zj_dp(40.0f), 0.0f, 0, 0, 12, 0) &&
        zj_int_property(env, row, "setGravity", 16) && zj_append(env, row, icon) &&
        label(env, row, shell.apps[i].entry.label, 17.0f, WHITE) && zj_append(env, shell.apps_list, row) &&
        zj_keep(env, &shell.rows[shell.row_count], row);
    if (ok) ++shell.row_count;
    (*env)->PopLocalFrame(env, NULL);
    return true;
}
static void fill_apps(JNIEnv *env)
{
    jmethodID clear = zj_method(env, shell.apps_list, "removeAllViews", "()V");
    if (clear) (*env)->CallVoidMethod(env, shell.apps_list, clear);
    for (size_t i = 0; i < shell.row_count; ++i) (*env)->DeleteGlobalRef(env, shell.rows[i]);
    shell.row_count = 0;
    for (size_t i = 0; i < shell.app_count && add_app_row(env, i); ++i) {}
}
static void enter_wallet(JNIEnv *env)
{
    (void)wallet_screens_open(WALLET_PAGE_FUNDS);
    zapp_wallet_ui_render(env);
}
static void leave_wallet(JNIEnv *env)
{
    /* Leaving for any screen, in the app or out of it, keeps the window protection until a tick finds the next screen
     * drawn (wallet_screens_settle), so a screen recording never catches the wallet content unprotected. */
    wallet_screens_pause();
    zapp_wallet_ui_clear(env);
}
/* The Send screen is left only when its flow is over and the wallet is locked; while a payment is being built or the
 * wallet is open the owner stays, and the next tick or tap tries again. */
static bool leave_send(JNIEnv *env)
{
    if (zapp_send_ui_leave(env)) return true;
    snprintf(shell.action_notice, sizeof(shell.action_notice), "Wait for the payment to finish. This screen closes when the wallet is locked.");
    show_notice(env);
    return false;
}
/* Remembers where Send was opened from, so Back returns there; a scan begun on Send keeps the place Send began. */
static void note_send_origin(enum screen next)
{
    if (next != SCREEN_SEND || shell.current == SCREEN_SEND) return;
    enum screen origin = shell.current == SCREEN_SCAN ? shell.before_scan : shell.current;
    shell.send_from_wallet = zapp_home_send_opened_from_wallet(origin == SCREEN_SEND, origin == SCREEN_WALLET, shell.send_from_wallet);
}
/* Setup is left only when no job runs and no recovery words are held: the words are shown once. A job that runs says so. */
static bool leave_setup(JNIEnv *env)
{
    if (zapp_setup_ui_leave(env)) return true;
    zapp_setup_ui_leave_notice(shell.action_notice, sizeof(shell.action_notice));
    show_notice(env);
    return false;
}
/* The wallet and the payment screens open only once setup is confirmed; until then the way to them is the setup screens. */
static enum screen screen_for(enum screen next)
{
    bool wallet = next == SCREEN_WALLET || next == SCREEN_SEND;
    return wallet && !shell.preview && zapp_setup_state(shell.files) != ZAPP_SETUP_READY ? SCREEN_SETUP : next;
}
/* The Assistant takes pasted fleet invitations and laptop pairing descriptors and shows the conversation, so it gets the
 * window protections of the wallet screens. They read only the environment and the activity object. */
static bool protect_window(JNIEnv *env, bool on)
{
    ANativeActivity window = {.env = env, .clazz = shell.activity};
    return zapp_secure_window(&window, on);
}
static bool wallet_screen(enum screen s) { return s == SCREEN_WALLET || s == SCREEN_SEND || s == SCREEN_SETUP; }
/* What the owner is told when the window could not be protected; read before any later call resets the reason. */
static void assistant_refused(char *out, size_t cap)
{
    const char *refused = zapp_secure_window_refusal();
    snprintf(out, cap, "This phone would not let the app %s, so the assistant is not shown.", refused ? refused : "protect the screen");
}
/* The touch gate and the Assistant's window protection for the screen about to be shown. */
static void set_protection(JNIEnv *env, enum screen next)
{
    if (wallet_screen(next) || next == SCREEN_ASSISTANT) shell.gate.protect = true;
    else zapp_touch_gate_release(&shell.gate);
    if (shell.current == SCREEN_ASSISTANT && next != SCREEN_ASSISTANT && !wallet_screen(next)) (void)protect_window(env, false);
}
/* What a screen does as it comes into view. */
static void enter_screen(JNIEnv *env, enum screen next)
{
    if (next == SCREEN_APPS) { refresh_apps(env, true); fill_apps(env); }
    if (next == SCREEN_SETTINGS) settings_status(env);
    if (next == SCREEN_SCAN) { zapp_shell_immersive(env); show_scan_screen(env, ZAPP_CAMERA_GRANTED); }
    if (next == SCREEN_WALLET) enter_wallet(env);
    if (next == SCREEN_SETUP) (void)zapp_setup_ui_open(env);
}
static bool leave_screen(JNIEnv *env, enum screen next)
{
    if (shell.current == SCREEN_SETUP && next != SCREEN_SETUP && !leave_setup(env)) return false;
    if (shell.current == SCREEN_SEND && next != SCREEN_SEND && !leave_send(env)) return false;
    if (shell.current == SCREEN_WALLET) leave_wallet(env);
    return true;
}
static void go(JNIEnv *env, enum screen next)
{
    next = screen_for(next);
    note_send_origin(next);
    if (!leave_screen(env, next)) return;
    char why[sizeof(shell.action_notice)] = "";
    if (next == SCREEN_ASSISTANT && !protect_window(env, true)) {
        assistant_refused(why, sizeof(why));
        next = SCREEN_HOME;
    }
    set_protection(env, next);
    if (next != SCREEN_SCAN) shell.camera_waiting = false;
    /* An outcome line under More belongs to the visit that showed it; the camera screen is part of that visit. */
    if (shell.current == SCREEN_ASSISTANT && next != SCREEN_ASSISTANT && next != SCREEN_SCAN) zapp_controller_clear_result();
    shell.current = next;
    snprintf(shell.action_notice, sizeof(shell.action_notice), "%s", why);
    set_outcome(env, "");
    enter_screen(env, next);
    for (int i = 0; i < SCREEN_COUNT; ++i) (void)zj_visible(env, shell.roots[i], i == (int)next);
    if (next == SCREEN_SETUP) zapp_setup_ui_render(env);
    if (next == SCREEN_HOME) show_home(env);
    show_notice(env);
}
/* Opens the Send screen with its flow: a payment, a notice, or, with sweep, the move of public funds into the private
 * balance. When setup is not finished, go shows the setup screens and nothing opens. */
static void open_send(JNIEnv *env, const struct zapp_payment *pay, const char *notice, bool sweep)
{
    go(env, SCREEN_SEND);
    if (shell.current != SCREEN_SEND) return;
    if (sweep) zapp_send_ui_open_sweep(env);
    else zapp_send_ui_open(env, pay, notice);
}
static void show_home(JNIEnv *env)
{
    const struct json_value *cards[ZAPP_LAUNCHER_MAX + 1];
    size_t count = 0;
    if (!shell.phone_ok || shell.current != SCREEN_HOME) return;
    cards[count++] = &shell.phone;
    for (size_t i = 0; i < shell.app_count; ++i) cards[count++] = &shell.app_cards[i];
    if (shell.layout && !zapp_surface_show(env, shell.layout, "home", cards, count, zapp_home_action_label)) {
        if (shell.user_layout) adopt_builtin("Layout file not used: it could not be drawn. Showing the built-in layout.");
        if (shell.layout) (void)zapp_surface_show(env, shell.layout, "home", cards, count, zapp_home_action_label);
    }
    show_notice(env);
}
static void back(JNIEnv *env)
{
    if (shell.current == SCREEN_SCAN) {
        zapp_camera_stop(); shell.scan_dismissed = true;
        zapp_pay_stash_clear();   /* a code still being decoded is dropped when it finishes */
        go(env, shell.before_scan);
    } else if (shell.current == SCREEN_WALLET) {
        if (wallet_screens_back()) zapp_wallet_ui_render(env);
        else go(env, SCREEN_HOME);
    } else if (shell.current == SCREEN_SEND) {
        go(env, shell.send_from_wallet ? SCREEN_WALLET : SCREEN_HOME);
    } else if (shell.current != SCREEN_HOME) go(env, SCREEN_HOME);
    else set_outcome(env, "");
}
static void choose_layout(JNIEnv *env, size_t index)
{
    const char *name = zapp_home_layout_name(index);
    if (!name) return;
    snprintf(shell.builtin, sizeof(shell.builtin), "%s", name);
    save_choice();
    if (!shell.user_layout) adopt_builtin("");
    settings_status(env);
}
static void open_home_settings(JNIEnv *env)
{
    if (zapp_launcher_home_settings(env, shell.activity)) { set_outcome(env, ""); return; }
    snprintf(shell.action_notice, sizeof(shell.action_notice), "Could not open Android settings.");
    show_notice(env);
}
/* Opens the system settings page for this app, where the camera permission is allowed. */
static void open_camera_settings(JNIEnv *env)
{
    if (zapp_camera_open_settings()) { set_outcome(env, ""); return; }
    snprintf(shell.action_notice, sizeof(shell.action_notice), "Could not open Android settings.");
    show_notice(env);
}
/* Starts a camera scan. With camera access off, the scan screen opens with its words and buttons instead: nothing is
 * requested and no scan runs until the owner returns with access given. */
static void begin_scan(JNIEnv *env)
{
    enum zapp_camera_access access = zapp_camera_access_now();
    if (access != ZAPP_CAMERA_SETTINGS) { shell.send("scan", ""); return; }
    shell.before_scan = shell.current;
    go(env, SCREEN_SCAN);
    shell.camera_waiting = true;
    show_scan_screen(env, access);
}
/* Shown again with camera access given, the scan that the screen was waiting for starts by itself. */
static void resume_scan(JNIEnv *env)
{
    if (!shell.camera_waiting || zapp_camera_access_now() != ZAPP_CAMERA_GRANTED) return;
    shell.camera_waiting = false;
    show_scan_screen(env, ZAPP_CAMERA_GRANTED);
    shell.send("scan", "");
}
static void run_nav(JNIEnv *env, const struct nav *nav)
{
    switch (nav->command) {
    case CMD_HOME: go(env, SCREEN_HOME); break;
    case CMD_APPS: go(env, SCREEN_APPS); break;
    case CMD_SETTINGS: go(env, SCREEN_SETTINGS); break;
    case CMD_HOME_SETTINGS: open_home_settings(env); break;
    case CMD_LAYOUT: choose_layout(env, nav->arg); break;
    case CMD_SCAN_CANCEL: back(env); break;
    case CMD_CAMERA_SETTINGS: open_camera_settings(env); break;
    case CMD_CAMERA_PASTE: open_send(env, NULL, "", false); break;
    case CMD_OUTCOME_DISMISS: set_outcome(env, ""); break;
    }
}
static void launch(JNIEnv *env, const char *package, const char *activity, const char *name)
{
    if (zapp_launcher_start(env, shell.activity, package, activity)) { set_outcome(env, ""); return; }
    snprintf(shell.action_notice, sizeof(shell.action_notice), "Could not open %.100s.", name);
    show_notice(env);
}
static void run_tile(JNIEnv *env, const struct target *target)
{
    char package[ZAPP_APP_PACKAGE_CAP] = "", activity[ZAPP_APP_ACTIVITY_CAP] = "", name[ZAPP_APP_LABEL_CAP] = "";
    if (!strcmp(target->id, "scan")) begin_scan(env);
    else if (!strcmp(target->id, "assistant")) go(env, SCREEN_ASSISTANT);
    else if (!strcmp(target->id, "wallet")) go(env, shell.preview || zapp_setup_state(shell.files) == ZAPP_SETUP_READY ? SCREEN_WALLET : SCREEN_SETUP);
    else if (!strcmp(target->id, "apps")) go(env, SCREEN_APPS);
    else if (!strcmp(target->id, "settings")) go(env, SCREEN_SETTINGS);
    else if (!strcmp(target->id, "node_toggle")) {
        char label[32] = "";
        (void)zapp_card_field(&shell.phone, "node_button", label, sizeof(label));
        const char *action = zapp_home_node_action_for_label(label);
        if (action[0]) shell.send(action, "");
    }
    else if (!strcmp(target->id, "launch") && target->card != ZAPP_NO_CARD && target->card > 0 &&
             target->card <= shell.app_count && zapp_card_field(&shell.app_cards[target->card - 1], "package", package, sizeof(package))) {
        (void)zapp_card_field(&shell.app_cards[target->card - 1], "label", name, sizeof(name));
        (void)zapp_card_field(&shell.app_cards[target->card - 1], "activity", activity, sizeof(activity));
        launch(env, package, activity, name);
    }
}
static bool find_target(JNIEnv *env, float x, float y, struct target *target)
{
    memset(target, 0, sizeof(*target));
    for (size_t i = 0; i < shell.nav_count; ++i)
        if (zj_hit(env, shell.navs[i].view, x, y)) { target->kind = TARGET_NAV; target->index = i; return true; }
    if (shell.current == SCREEN_WALLET && zapp_wallet_ui_hit(env, x, y, &target->index)) { target->kind = TARGET_WALLET; return true; }
    if (shell.current == SCREEN_SEND && zapp_send_ui_hit(env, x, y, &target->index, &target->button)) { target->kind = TARGET_SEND; return true; }
    if (shell.current == SCREEN_SETUP && zapp_setup_ui_hit(env, x, y, &target->index, &target->button)) { target->kind = TARGET_SETUP; return true; }
    for (size_t i = 0; shell.current == SCREEN_APPS && i < shell.row_count; ++i)
        if (zj_hit(env, shell.rows[i], x, y)) { target->kind = TARGET_ROW; target->index = i; return true; }
    if (shell.current == SCREEN_HOME && zapp_surface_hit(env, x, y, target->id, &target->card)) {
        target->kind = TARGET_TILE;
        return true;
    }
    return false;
}
/* Send and setup screens redraw between a press and its release, so their buttons are matched by identity. */
static bool by_button(const struct target *t) { return t->kind == TARGET_SEND || t->kind == TARGET_SETUP; }
static bool same_target(const struct target *a, const struct target *b)
{
    return a->kind == b->kind && !strcmp(a->id, b->id) &&
           zapp_home_same_press(a->index, by_button(a), a->button, b->index, by_button(b), b->button);
}
static void run_wallet(JNIEnv *env, size_t button)
{
    enum wallet_outcome outcome = zapp_wallet_ui_press(env, button);
    uint64_t spendable = 0;
    if (outcome == WALLET_SEND && wallet_screens_spendable(&spendable)) zapp_send_ui_known_balance(spendable);
    if (outcome == WALLET_SEND) open_send(env, NULL, "", false);
    else if (outcome == WALLET_MAKE_PRIVATE) open_send(env, NULL, "", true);
    else if (outcome == WALLET_START_NODE) shell.send("node_start", "");
    else if (outcome == WALLET_LEAVE) go(env, SCREEN_HOME);
}
/* Receive on the wallet screen, for a Send page that had nothing to send. Back on Receive returns to Funds. */
static void open_receive(JNIEnv *env)
{
    go(env, SCREEN_WALLET);
    if (shell.current != SCREEN_WALLET) return;
    (void)wallet_screens_activate(WALLET_ACT_RECEIVE, 0);
    zapp_wallet_ui_render(env);
}
/* The Send screen: Scan code leaves it first, so a scan never starts while a lock is owed. */
static void run_send(JNIEnv *env, size_t button)
{
    enum zapp_send_outcome outcome = zapp_send_ui_press(env, button);
    if (outcome == ZAPP_SEND_SCAN && leave_send(env)) begin_scan(env);
    else if (outcome == ZAPP_SEND_LEAVE) go(env, shell.send_from_wallet ? SCREEN_WALLET : SCREEN_HOME);
    else if (outcome == ZAPP_SEND_RECEIVE) open_receive(env);
}
/* The setup screens: Continue leaves for the wallet once setup finished, and for Home otherwise. */
static void run_setup(JNIEnv *env, size_t button)
{
    if (zapp_setup_ui_press(env, button) != ZAPP_SETUP_LEAVE) return;
    go(env, SCREEN_HOME);
    if (zapp_setup_state(shell.files) == ZAPP_SETUP_READY) go(env, SCREEN_WALLET);
}
static void tap(JNIEnv *env, float x, float y)
{
    struct target now, before = shell.pressed;
    memset(&shell.pressed, 0, sizeof(shell.pressed));
    if (before.kind == TARGET_NONE || !find_target(env, x, y, &now) || !same_target(&before, &now)) return;
    if (now.kind == TARGET_NAV) run_nav(env, &shell.navs[now.index]);
    else if (now.kind == TARGET_WALLET) run_wallet(env, now.index);
    else if (now.kind == TARGET_SEND) run_send(env, now.index);
    else if (now.kind == TARGET_SETUP) run_setup(env, now.index);
    else if (now.kind == TARGET_ROW) launch(env, shell.apps[now.index].entry.package, shell.apps[now.index].entry.activity, shell.apps[now.index].entry.label);
    else run_tile(env, &now);
}
static void touch(JNIEnv *env, const AInputEvent *event)
{
    int32_t action = AMotionEvent_getAction(event) & AMOTION_EVENT_ACTION_MASK;
    float x = AMotionEvent_getX(event, 0), y = AMotionEvent_getY(event, 0);
    if (action == AMOTION_EVENT_ACTION_DOWN) {
        shell.down_x = x; shell.down_y = y;
        if (!find_target(env, x, y, &shell.pressed)) shell.pressed.kind = TARGET_NONE;
    } else if (action == AMOTION_EVENT_ACTION_MOVE) {
        if (x - shell.down_x > 20 || shell.down_x - x > 20 || y - shell.down_y > 20 || shell.down_y - y > 20) shell.pressed.kind = TARGET_NONE;
    } else if (action == AMOTION_EVENT_ACTION_CANCEL) shell.pressed.kind = TARGET_NONE;
    else if (action == AMOTION_EVENT_ACTION_UP) tap(env, x, y);
}
/* The keyboard's action key in a wallet field presses the button that belongs to the field: Set amount, or Use this address
 * on Send. True when such a field has the focus: the key goes no further, and its release presses the button. */
static bool field_key(JNIEnv *env, bool release)
{
    size_t button = 0;
    if (shell.current == SCREEN_WALLET && zapp_wallet_ui_field_button(env, &button)) {
        if (release) run_wallet(env, button);
        return true;
    }
    if (shell.current == SCREEN_SEND && zapp_send_ui_field_button(env, &button)) {
        if (release) run_send(env, button);
        return true;
    }
    return false;
}
bool zapp_shell_editor(JNIEnv *env) { return field_key(env, true); }
bool zapp_shell_input(JNIEnv *env, const AInputEvent *event)
{
    if (!shell.activity || !event) return false;
    int32_t type = AInputEvent_getType(event);
    int32_t key = type == AINPUT_EVENT_TYPE_KEY ? AKeyEvent_getKeyCode(event) : AKEYCODE_UNKNOWN;
    if (key == AKEYCODE_BACK) {
        if (AKeyEvent_getAction(event) == AKEY_EVENT_ACTION_UP) back(env);
        return true;
    }
    if ((key == AKEYCODE_ENTER || key == AKEYCODE_NUMPAD_ENTER) && field_key(env, AKeyEvent_getAction(event) == AKEY_EVENT_ACTION_UP)) return true;
    if (type == AINPUT_EVENT_TYPE_MOTION && zapp_touch_gate_drops(&shell.gate, AMotionEvent_getAction(event), AMotionEvent_getFlags(event))) {
        memset(&shell.pressed, 0, sizeof(shell.pressed));
        zapp_shell_dropped(env);
        return true;
    }
    if (type == AINPUT_EVENT_TYPE_MOTION && shell.current != SCREEN_ASSISTANT) touch(env, event);
    return false;
}
bool zapp_shell_assistant(void) { return shell.current == SCREEN_ASSISTANT; }

/* ---- lifecycle ---- */

void zapp_shell_notice(JNIEnv *env, const char *text)
{
    if (!shell.activity || !text) return;
    snprintf(shell.action_notice, sizeof(shell.action_notice), "%s", text);
    show_notice(env);
}
void zapp_shell_preview(JNIEnv *env, const unsigned char *bmp, size_t len)
{
    if (shell.activity && shell.current == SCREEN_SCAN) (void)zj_bitmap(env, shell.scan_view, bmp, len);
}
/* Whether a finished scan opens the Send screen: a payment code, accepted or refused, and any scan that was started on
 * Send and is not a fleet invitation or a pairing code. */
static bool scan_goes_to_send(const struct zapp_view *view)
{
    enum zapp_scan_target target = zapp_home_scan_target(view->scan_kind, view->pair_offer[0] != 0);
    return target == ZAPP_SCAN_TO_PAYMENT_REVIEW || zapp_home_scan_stays_on_send(shell.before_scan == SCREEN_SEND, target);
}
/* After a scan: a payment code opens the Send screen with its review, or with the reason it was refused; a fleet
 * invitation opens the assistant with its review, a laptop pairing code opens its review, and anything else is shown
 * on Home with its text, or, when the scan began on Send, stays on Send. A cancelled scan never gets here. An outcome
 * shown on Home, the wallet or Send leaves the assistant's outcome line, so More never shows it later as current. */
static void finish_scan(JNIEnv *env, const struct zapp_view *view)
{
    char text[ZAPP_NOTICE_CAP + sizeof(view->scan_text) + 4];
    enum zapp_scan_target target = zapp_home_scan_target(view->scan_kind, view->pair_offer[0] != 0);
    if (target == ZAPP_SCAN_TO_PAIR_REVIEW) shell.pair_seen = true;
    if (scan_goes_to_send(view)) {
        struct zapp_payment pay;
        bool have = zapp_pay_stash_take(&pay);
        const char *why = zapp_home_send_notice(view->scan_kind, view->scan_text, view->result);
        open_send(env, have ? &pay : NULL, have ? "" : why, false);
        memory_cleanse(&pay, sizeof(pay));
        zapp_controller_clear_result();
        return;
    }
    if (zapp_home_scan_returns_to_wallet(target, shell.before_scan == SCREEN_WALLET && shell.current == SCREEN_WALLET)) {
        wallet_screens_scan_notice(view->result);
        zapp_wallet_ui_render(env);
        zapp_controller_clear_result();
        return;
    }
    bool home = target == ZAPP_SCAN_TO_HOME;
    if (!home) go(env, SCREEN_ASSISTANT);
    if (target == ZAPP_SCAN_TO_FLEET_REVIEW) zapp_native_ui_open_details(env);
    if (!home) return;
    snprintf(text, sizeof(text), "%s%s%s", view->result, view->scan_text[0] ? "\n\n" : "", view->scan_text);
    go(env, SCREEN_HOME);
    set_outcome(env, text);
    zapp_controller_clear_result();
}

/* The camera screen opens while a scan runs and closes when it ends; a payment code goes from the camera screen
 * straight to Send and does not pass through the screen it came from. */
static void render_scan(JNIEnv *env, const struct zapp_view *view, bool finished, bool dismissed)
{
    if (view->scanning) {
        if (shell.current != SCREEN_SCAN && !dismissed) { shell.before_scan = shell.current; go(env, SCREEN_SCAN); }
        return;
    }
    shell.scan_dismissed = false;
    if (shell.camera_waiting) return;
    if (finished && dismissed) zapp_pay_stash_clear();
    if (shell.current == SCREEN_SCAN && !(finished && !dismissed && scan_goes_to_send(view))) go(env, shell.before_scan);
    if (finished && !dismissed) finish_scan(env, view);
}
/* Once the commit starts the owner returns to the wallet screen at once; the payment goes on in the background. */
static void to_wallet_when_building(JNIEnv *env)
{
    if (shell.current == SCREEN_SEND && zapp_send_ui_take_background()) go(env, SCREEN_WALLET);
}
void zapp_shell_render(JNIEnv *env, const struct zapp_view *view)
{
    if (!shell.activity || !view) return;
    /* A payment kept from the activity that was replaced is shown with its progress or outcome. */
    if (zapp_send_ui_take_reshow()) go(env, SCREEN_SEND);
    if (!shell.rendered) {
        shell.rendered = true; shell.scans_seen = view->scans_done; shell.scan_dismissed = view->scanning;
    }
    /* The first launch without a wallet opens the setup screens once; the Wallet tile opens them after that. */
    if (!shell.setup_offered && !shell.preview && zapp_setup_state(shell.files) == ZAPP_SETUP_NEEDED) { shell.setup_offered = true; go(env, SCREEN_SETUP); }
    bool finished = view->scans_done != shell.scans_seen, dismissed = shell.scan_dismissed;
    shell.scans_seen = view->scans_done;
    render_scan(env, view, finished, dismissed);
    if (zapp_home_offer_jump(view->pair_offer[0] != 0, shell.current == SCREEN_SCAN, &shell.pair_seen)) go(env, SCREEN_ASSISTANT);
    set_phone_card(view);
    if (strcmp(shell.node_notice, view->node_action_notice)) {
        snprintf(shell.node_notice, sizeof(shell.node_notice), "%s", view->node_action_notice);
        show_notice(env);
    }
    show_home(env);
    if (shell.current == SCREEN_WALLET) zapp_wallet_ui_render(env);
    if (shell.current == SCREEN_SEND) { zapp_send_ui_render(env); to_wallet_when_building(env); }
    if (shell.current == SCREEN_SETUP) zapp_setup_ui_render(env);
}
void zapp_shell_pause(JNIEnv *env)
{
    if (shell.activity && shell.current == SCREEN_SEND) {
        /* A flow in authentication or building stays on this screen: the system credential screen pauses the app and its
         * result completes the payment, and a running commit is never cancelled. Any other flow is cancelled and returns
         * to Home, and a flow that ended returns to Home. */
        zapp_send_ui_pause();
        go(env, SCREEN_HOME);
        return;
    }
    if (shell.activity && shell.current == SCREEN_SETUP) {
        /* Setup stays: a job may be waiting on the screen lock, and the words are held until confirmed. Only the drawn words go. */
        zapp_setup_ui_pause(env);
        return;
    }
    if (!shell.activity || shell.current != SCREEN_WALLET) return;
    go(env, SCREEN_HOME);
}
void zapp_shell_dropped(JNIEnv *env)
{
    if (shell.activity && shell.current == SCREEN_SEND) zapp_send_ui_dropped(env);
    if (shell.activity && shell.current == SCREEN_SETUP) zapp_setup_ui_dropped(env);
    if (shell.activity && shell.current == SCREEN_WALLET) zapp_wallet_ui_dropped(env, shell.gate.obscured_gestures);
}
void zapp_shell_tick(JNIEnv *env)
{
    if (!shell.activity) return;
    /* Ticks are what ask again for a lock that is owed, on this screen or off it. */
    zapp_send_ui_tick(env);
    if (shell.current == SCREEN_SEND) {
        zapp_send_ui_render(env);
        to_wallet_when_building(env);
        return;
    }
    if (shell.current == SCREEN_SETUP) {
        zapp_setup_ui_tick(env);
        return;
    }
    /* Off the wallet screens, the first tick after the app returned finds Home on screen: the protection a pause
     * kept can go. */
    if (shell.current == SCREEN_WALLET) zapp_wallet_ui_tick(env);
    else wallet_screens_settle();
}
void zapp_shell_focus(JNIEnv *env)
{
    if (!shell.activity) return;
    zapp_shell_immersive(env);
    if (shell.current == SCREEN_SEND) zapp_send_ui_focus(env);
}
void zapp_shell_resume(JNIEnv *env)
{
    if (!shell.activity) return;
    zapp_shell_immersive(env);
    refresh_apps(env, false);
    load_layout();
    if (shell.current == SCREEN_SETUP) zapp_setup_ui_render(env);
    else if (shell.current == SCREEN_SCAN) resume_scan(env);
    else if (shell.current == SCREEN_APPS || shell.current == SCREEN_SETTINGS || shell.current == SCREEN_WALLET) go(env, SCREEN_HOME);
    else if (shell.current == SCREEN_ASSISTANT && !protect_window(env, true)) go(env, SCREEN_HOME);
    else show_home(env);
}
void zapp_shell_destroy(JNIEnv *env)
{
    if (!shell.activity) return;
    leave_wallet(env);
    wallet_screens_close();
    zapp_wallet_ui_destroy(env);
    zapp_send_ui_destroy(env);
    zapp_setup_ui_destroy(env);
    zapp_pay_stash_clear();
    zapp_surface_destroy(env);
    for (size_t i = 0; i < shell.nav_count; ++i) (*env)->DeleteGlobalRef(env, shell.navs[i].view);
    for (size_t i = 0; i < shell.row_count; ++i) (*env)->DeleteGlobalRef(env, shell.rows[i]);
    for (int i = 0; i < SCREEN_COUNT; ++i) if (shell.roots[i]) (*env)->DeleteGlobalRef(env, shell.roots[i]);
    jobject *views[] = {&shell.notice_views[SCREEN_HOME], &shell.notice_views[SCREEN_APPS], &shell.notice_views[SCREEN_SETTINGS], &shell.notice_views[SCREEN_SEND], &shell.notice_views[SCREEN_SETUP], &shell.outcome_view, &shell.outcome_panel, &shell.status_view, &shell.scan_view, &shell.scan_camera, &shell.scan_panel, &shell.apps_list};
    for (size_t i = 0; i < sizeof(views) / sizeof(views[0]); ++i) if (*views[i]) (*env)->DeleteGlobalRef(env, *views[i]);
    release_cards();
    zapp_launcher_release(env, shell.apps, ZAPP_LAUNCHER_MAX);
    if (shell.phone_ok) json_free(&shell.phone);
    zapp_layout_free(shell.layout);
    (*env)->DeleteGlobalRef(env, shell.activity);
    memset(&shell, 0, sizeof(shell));
}
bool zapp_shell_create(JNIEnv *env, jobject activity, jobject assistant, zapp_native_action send, bool preview)
{
    char layouts[PATH_CAP + 16];
    if (shell.activity || !send) return false;
    shell.activity = (*env)->NewGlobalRef(env, activity);
    shell.send = send; shell.preview = preview;
    if (!shell.activity || !directory(env, activity, "getFilesDir", "()Ljava/io/File;", shell.files, sizeof(shell.files))) goto fail;
    (void)directory(env, activity, "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;", shell.external, sizeof(shell.external));
    if (shell.external[0]) { snprintf(layouts, sizeof(layouts), "%s/layouts", shell.external); (void)mkdir(layouts, 0700); }
    load_choice();
    if (!build_stage(env, assistant)) goto fail;
    load_layout();
    refresh_apps(env, false);
    zapp_shell_immersive(env);
    return true;
fail:
    zapp_shell_destroy(env);
    return false;
}
