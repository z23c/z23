/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "shell.h"
#include "camera.h"
#include "home.h"
#include "jni_util.h"
#include "launcher.h"
#include "layout.h"
#include "surface.h"
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

enum screen { SCREEN_HOME, SCREEN_ASSISTANT, SCREEN_APPS, SCREEN_SETTINGS, SCREEN_SCAN, SCREEN_COUNT };
enum command { CMD_HOME, CMD_APPS, CMD_SETTINGS, CMD_HOME_SETTINGS, CMD_LAYOUT, CMD_SCAN_CANCEL };
enum target_kind { TARGET_NONE, TARGET_NAV, TARGET_ROW, TARGET_TILE };

struct nav { jobject view; enum command command; size_t arg; };
struct target { enum target_kind kind; size_t index; char id[ZAPP_NAME_CAP]; size_t card; };

static struct {
    jobject activity, roots[SCREEN_COUNT];
    zapp_native_action send;
    jobject notice_views[SCREEN_COUNT], outcome_view, status_view, scan_view, apps_list;
    enum screen current, before_scan;
    bool preview, pair_seen, scan_dismissed, user_layout, rendered;
    unsigned scans_seen;
    struct zapp_layout *layout;
    char builtin[ZAPP_NAME_CAP], layout_notice[320], action_notice[160];
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
static char *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    char *data = file ? malloc(ZAPP_LAYOUT_MAX_BYTES + 2) : NULL;
    if (data) *length = fread(data, 1, ZAPP_LAYOUT_MAX_BYTES + 1, file);
    if (file) fclose(file);
    return data;
}
static void adopt_user(const char *path)
{
    size_t length = 0;
    char reason[160], notice[sizeof(shell.layout_notice)];
    char *data = read_file(path, &length);
    struct zapp_layout *layout = data ? zapp_layout_parse(data, length, reason, sizeof(reason)) : NULL;
    if (!data) snprintf(reason, sizeof(reason), "cannot read the file");
    else if (layout && !zapp_layout_screen(layout, "home")) {
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
    bool present = shell.external[0] && stat(path, &info) == 0 && S_ISREG(info.st_mode);
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
/* Notice and scan outcome bars, the layout's host, and a footer that always offers Apps and Settings. */
static bool build_home(JNIEnv *env, jobject root)
{
    jobject host = zj_widget(env, "android/widget/FrameLayout", shell.activity);
    jobject outcome = bar(env, 0xff2b2b2bu), footer = column(env, DARK, 8, true);
    bool ok = host && outcome && footer && add_notice(env, root, SCREEN_HOME) && zj_bool_property(env, outcome, "setTextIsSelectable", true) &&
        zj_keep(env, &shell.outcome_view, outcome) && zj_padding(env, host, 20, 24) && zj_margins(env, host, MATCH, 0, 1.0f, 0, 0, 0, 0) &&
        zapp_surface_create(env, shell.activity, host) &&
        zj_append(env, root, outcome) && zj_append(env, root, host) && zj_append(env, root, footer) &&
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
static bool build_settings(JNIEnv *env, jobject root)
{
    jobject status = zj_widget(env, "android/widget/TextView", shell.activity);
    bool ok = add_notice(env, root, SCREEN_SETTINGS) && label(env, root, "Home settings", 24.0f, WHITE) && status && zj_typography(env, status, 15.0f, (jint)0xffb0b0b0u) &&
        zj_append(env, root, status) && zj_keep(env, &shell.status_view, status);
    for (size_t i = 0; ok && i < zapp_home_layout_count(); ++i) {
        char text[ZAPP_NAME_CAP + 16];
        snprintf(text, sizeof(text), "Layout: %s", zapp_home_layout_name(i));
        ok = button(env, root, text, CMD_LAYOUT, i, 0);
    }
    ok = ok && button(env, root, "Android home settings", CMD_HOME_SETTINGS, 0, 0) && button(env, root, "Home", CMD_HOME, 0, 0);
    if (status) (*env)->DeleteLocalRef(env, status);
    return ok;
}
static bool build_scan(JNIEnv *env, jobject root)
{
    jobject image = zj_widget(env, "android/widget/ImageView", shell.activity);
    bool ok = image && zj_margins(env, image, MATCH, 0, 1.0f, 0, 0, 0, 0) && zj_append(env, root, image) &&
        zj_keep(env, &shell.scan_view, image) && button(env, root, "Cancel", CMD_SCAN_CANCEL, 0, 0);
    if (image) (*env)->DeleteLocalRef(env, image);
    return ok;
}
static bool add_screen(JNIEnv *env, jobject stage, enum screen which, jobject root)
{
    bool ok = root && zj_margins(env, root, MATCH, MATCH, 0.0f, 0, 0, 0, 0) && zj_visible(env, root, which == SCREEN_HOME) &&
        zj_append(env, stage, root) && zj_keep(env, &shell.roots[which], root);
    if (root && which != SCREEN_ASSISTANT) (*env)->DeleteLocalRef(env, root);
    return ok;
}
static bool build_stage(JNIEnv *env, jobject assistant)
{
    jobject stage = zj_widget(env, "android/widget/FrameLayout", shell.activity);
    jobject home = column(env, DARK, 0, false), apps = column(env, DARK, 12, false);
    jobject settings = column(env, DARK, 20, false), scan = column(env, 0xff000000u, 0, false);
    bool ok = stage && build_home(env, home) && build_apps(env, apps) && build_settings(env, settings) && build_scan(env, scan) &&
        add_screen(env, stage, SCREEN_HOME, home) && add_screen(env, stage, SCREEN_ASSISTANT, assistant) &&
        add_screen(env, stage, SCREEN_APPS, apps) && add_screen(env, stage, SCREEN_SETTINGS, settings) &&
        add_screen(env, stage, SCREEN_SCAN, scan);
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
static void show_notice(JNIEnv *env)
{
    const char *text = shell.action_notice[0] ? shell.action_notice : shell.layout_notice;
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
static void go(JNIEnv *env, enum screen next)
{
    shell.current = next;
    shell.action_notice[0] = 0;
    set_text(env, shell.outcome_view, "");
    if (next == SCREEN_APPS) { refresh_apps(env, true); fill_apps(env); }
    if (next == SCREEN_SETTINGS) settings_status(env);
    if (next == SCREEN_SCAN) zapp_shell_immersive(env);
    for (int i = 0; i < SCREEN_COUNT; ++i) (void)zj_visible(env, shell.roots[i], i == (int)next);
    if (next == SCREEN_HOME) show_home(env);
    show_notice(env);
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
        go(env, shell.before_scan);
    } else if (shell.current != SCREEN_HOME) go(env, SCREEN_HOME);
    else set_text(env, shell.outcome_view, "");
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
    if (zapp_launcher_home_settings(env, shell.activity)) { set_text(env, shell.outcome_view, ""); return; }
    snprintf(shell.action_notice, sizeof(shell.action_notice), "Could not open Android settings.");
    show_notice(env);
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
    }
}
static void launch(JNIEnv *env, const char *package, const char *activity, const char *name)
{
    if (zapp_launcher_start(env, shell.activity, package, activity)) { set_text(env, shell.outcome_view, ""); return; }
    snprintf(shell.action_notice, sizeof(shell.action_notice), "Could not open %.100s.", name);
    show_notice(env);
}
static void run_tile(JNIEnv *env, const struct target *target)
{
    char package[ZAPP_APP_PACKAGE_CAP] = "", activity[ZAPP_APP_ACTIVITY_CAP] = "", name[ZAPP_APP_LABEL_CAP] = "";
    if (!strcmp(target->id, "scan")) shell.send("scan", "");
    else if (!strcmp(target->id, "assistant")) go(env, SCREEN_ASSISTANT);
    else if (!strcmp(target->id, "apps")) go(env, SCREEN_APPS);
    else if (!strcmp(target->id, "settings")) go(env, SCREEN_SETTINGS);
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
    for (size_t i = 0; shell.current == SCREEN_APPS && i < shell.row_count; ++i)
        if (zj_hit(env, shell.rows[i], x, y)) { target->kind = TARGET_ROW; target->index = i; return true; }
    if (shell.current == SCREEN_HOME && zapp_surface_hit(env, x, y, target->id, &target->card)) {
        target->kind = TARGET_TILE;
        return true;
    }
    return false;
}
static bool same_target(const struct target *a, const struct target *b)
{
    return a->kind == b->kind && a->index == b->index && !strcmp(a->id, b->id);
}
static void tap(JNIEnv *env, float x, float y)
{
    struct target now, before = shell.pressed;
    memset(&shell.pressed, 0, sizeof(shell.pressed));
    if (before.kind == TARGET_NONE || !find_target(env, x, y, &now) || !same_target(&before, &now)) return;
    if (now.kind == TARGET_NAV) run_nav(env, &shell.navs[now.index]);
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
bool zapp_shell_input(JNIEnv *env, const AInputEvent *event)
{
    if (!shell.activity || !event) return false;
    int32_t type = AInputEvent_getType(event);
    if (type == AINPUT_EVENT_TYPE_KEY && AKeyEvent_getKeyCode(event) == AKEYCODE_BACK) {
        if (AKeyEvent_getAction(event) == AKEY_EVENT_ACTION_UP) back(env);
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
/* After a scan: a fleet invitation opens the assistant with its review, a laptop pairing code opens its
 * review, and anything else is shown on Home with its text. A cancelled scan never gets here. */
static void finish_scan(JNIEnv *env, const struct zapp_view *view)
{
    char text[ZAPP_NOTICE_CAP + sizeof(view->scan_text) + 4];
    enum zapp_scan_target target = zapp_home_scan_target(view->scan_kind, view->pair_offer[0] != 0);
    if (target == ZAPP_SCAN_TO_PAIR_REVIEW) shell.pair_seen = true;
    if (target != ZAPP_SCAN_TO_HOME) go(env, SCREEN_ASSISTANT);
    if (target == ZAPP_SCAN_TO_FLEET_REVIEW) zapp_native_ui_open_details(env);
    if (target != ZAPP_SCAN_TO_HOME) return;
    snprintf(text, sizeof(text), "%s%s%s", view->result, view->scan_text[0] ? "\n\n" : "", view->scan_text);
    go(env, SCREEN_HOME);
    set_text(env, shell.outcome_view, text);
}

void zapp_shell_render(JNIEnv *env, const struct zapp_view *view)
{
    if (!shell.activity || !view) return;
    if (!shell.rendered) {
        shell.rendered = true; shell.scans_seen = view->scans_done; shell.scan_dismissed = view->scanning;
    }
    bool finished = view->scans_done != shell.scans_seen, dismissed = shell.scan_dismissed;
    shell.scans_seen = view->scans_done;
    if (view->scanning) {
        if (shell.current != SCREEN_SCAN && !dismissed) { shell.before_scan = shell.current; go(env, SCREEN_SCAN); }
    } else {
        shell.scan_dismissed = false;
        if (shell.current == SCREEN_SCAN) go(env, shell.before_scan);
        if (finished && !dismissed) finish_scan(env, view);
    }
    if (zapp_home_offer_jump(view->pair_offer[0] != 0, shell.current == SCREEN_SCAN, &shell.pair_seen)) go(env, SCREEN_ASSISTANT);
    set_phone_card(view);
    show_home(env);
}
void zapp_shell_resume(JNIEnv *env)
{
    if (!shell.activity) return;
    zapp_shell_immersive(env);
    refresh_apps(env, false);
    load_layout();
    if (shell.current == SCREEN_APPS || shell.current == SCREEN_SETTINGS) go(env, SCREEN_HOME);
    else show_home(env);
}
void zapp_shell_destroy(JNIEnv *env)
{
    if (!shell.activity) return;
    zapp_surface_destroy(env);
    for (size_t i = 0; i < shell.nav_count; ++i) (*env)->DeleteGlobalRef(env, shell.navs[i].view);
    for (size_t i = 0; i < shell.row_count; ++i) (*env)->DeleteGlobalRef(env, shell.rows[i]);
    for (int i = 0; i < SCREEN_COUNT; ++i) if (shell.roots[i]) (*env)->DeleteGlobalRef(env, shell.roots[i]);
    jobject *views[] = {&shell.notice_views[SCREEN_HOME], &shell.notice_views[SCREEN_APPS], &shell.notice_views[SCREEN_SETTINGS], &shell.outcome_view, &shell.status_view, &shell.scan_view, &shell.apps_list};
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
    if (shell.external[0]) { snprintf(layouts, sizeof(layouts), "%s/layouts", shell.external); (void)mkdir(layouts, 0770); }
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
