/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "clip_screen.h"
#include "clip_capture.h"
#include "clip_player.h"
#include "clip_store.h"
#include <android/log.h>
#include <android/looper.h>
#include <android/native_window_jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define TAG "z23"
#define TICK_NS 200000000L
#define HEALTH_EVERY_MS 5000
#define PAUSE_WAIT_MS 2000
#define SWIPE_DP 80.0f
#define TAP_DP 16.0f
#define FRAME_TEXT_SP 18.0f
#define GRAVITY_CENTER 17
#define GRAVITY_TOP_CENTER 49
#define GRAVITY_BOTTOM_CENTER 81
#define GRAVITY_BOTTOM_LEFT 83
#define MATCH (-1)
#define WRAP (-2)
#define COLOR_TEXT ((jint)0xffffffff)
#define COLOR_SCRIM ((jint)0x99000000)
#define COLOR_RECORD ((jint)0xffd32f2f)
#define COLOR_CHOICE ((jint)0xff37474f)
#define COLOR_CHOSEN ((jint)0xff2e7d32)

enum phase { PHASE_PERMISSION, PHASE_READY, PHASE_RECORDING, PHASE_FINISHING, PHASE_REVIEW, PHASE_WATCH, PHASE_REFUSED };
enum control { C_RECORD, C_CAPTION, C_LEVEL, C_SAVE = C_LEVEL + 5, C_DISCARD, C_COUNT };

static const char *const level_names[5] = {"General", "Mild", "Sensitive", "Mature", "Explicit"};
static const char *const level_meanings[5] = {
    "Suitable for all ages. No nudity, sexual content, strong language, drug use or realistic violence.",
    "Mild language or mild action violence. No sexual content.",
    "Some strong language, non-graphic violence, brief non-sexual nudity, references to drugs.",
    "Strong language, graphic violence, non-explicit sexual content. Adults.",
    "Explicit sexual content or extreme violence. Adults.",
};

static struct {
    bool active, paused, left, keyboard, sized, error_shown, hot, unsaved;
    struct zapp_clip_camera_gate gate;
    enum zapp_clip_mode mode;
    enum phase phase;
    JavaVM *vm;
    jobject activity, root, surface, status, notice, info, panel, title, controls[C_COUNT];
    ANativeWindow *window;
    char dir[600], pending[640], encoder[64];
    float density;
    struct zapp_clip_recorder *recorder;
    struct zapp_clip_player *player;
    struct zapp_clip clips[ZAPP_CLIP_LIST_MAX];
    size_t count, total, index;
    int level;
    enum zapp_pace pace;
    int thermal;
    int64_t duration_ms, health_at_ms, stop_asked_ms;
    ALooper *looper;
    int timer;
    float down_x, down_y;
} s;

/* JNI helpers. Every call clears a pending exception and reports whether the call succeeded. */
static bool clean(JNIEnv *env)
{
    if (!(*env)->ExceptionCheck(env)) return true;
    (*env)->ExceptionClear(env);
    return false;
}

static jmethodID method_of(JNIEnv *env, jobject obj, const char *name, const char *sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID id = cls ? (*env)->GetMethodID(env, cls, name, sig) : NULL;
    bool ok = clean(env) && id;
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok ? id : NULL;
}

static bool call_void(JNIEnv *env, jobject obj, const char *name, const char *sig, ...)
{
    jmethodID id = method_of(env, obj, name, sig);
    if (!id) return false;
    va_list args;
    va_start(args, sig);
    (*env)->CallVoidMethodV(env, obj, id, args);
    va_end(args);
    return clean(env);
}

static jobject call_object(JNIEnv *env, jobject obj, const char *name, const char *sig, ...)
{
    jmethodID id = method_of(env, obj, name, sig);
    if (!id) return NULL;
    va_list args;
    va_start(args, sig);
    jobject result = (*env)->CallObjectMethodV(env, obj, id, args);
    va_end(args);
    return clean(env) ? result : NULL;
}

static jint call_int(JNIEnv *env, jobject obj, const char *name, const char *sig, ...)
{
    jmethodID id = method_of(env, obj, name, sig);
    if (!id) return -1;
    va_list args;
    va_start(args, sig);
    jint result = (*env)->CallIntMethodV(env, obj, id, args);
    va_end(args);
    return clean(env) ? result : -1;
}

static bool call_bool(JNIEnv *env, jobject obj, const char *name, const char *sig, ...)
{
    jmethodID id = method_of(env, obj, name, sig);
    bool value = false;
    if (id) {
        va_list args;
        va_start(args, sig);
        value = (*env)->CallBooleanMethodV(env, obj, id, args);
        va_end(args);
    }
    return clean(env) && value;
}

static jobject create(JNIEnv *env, const char *class_name, const char *sig, ...)
{
    jclass cls = (*env)->FindClass(env, class_name);
    jmethodID ctor = clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", sig) : NULL;
    jobject obj = NULL;
    if (ctor) {
        va_list args;
        va_start(args, sig);
        obj = (*env)->NewObjectV(env, cls, ctor, args);
        va_end(args);
    }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return clean(env) ? obj : NULL;
}

static jstring make_string(JNIEnv *env, const char *value)
{
    size_t length = strlen(value);
    jbyteArray bytes = (*env)->NewByteArray(env, (jsize)length);
    jstring encoding = (*env)->NewStringUTF(env, "UTF-8");
    jstring result = NULL;
    if (bytes && encoding) {
        (*env)->SetByteArrayRegion(env, bytes, 0, (jsize)length, (const jbyte *)value);
        result = create(env, "java/lang/String", "([BLjava/lang/String;)V", bytes, encoding);
    }
    (void)clean(env);
    return result;
}

static int dp(float value) { return (int)(value * s.density + 0.5f); }

static bool set_text(JNIEnv *env, jobject view, const char *text)
{
    jstring string = make_string(env, text);
    bool ok = string && call_void(env, view, "setText", "(Ljava/lang/CharSequence;)V", string);
    if (string) (*env)->DeleteLocalRef(env, string);
    return ok;
}

static void show(JNIEnv *env, jobject view, bool visible)
{
    if (view) (void)call_void(env, view, "setVisibility", "(I)V", visible ? 0 : 8);
}

static jobject keep(JNIEnv *env, jobject local)
{
    jobject global = local ? (*env)->NewGlobalRef(env, local) : NULL;
    return clean(env) ? global : NULL;
}

/* Views */
static jobject widget(JNIEnv *env, const char *class_name)
{
    return create(env, class_name, "(Landroid/content/Context;)V", s.activity);
}

static void style_text(JNIEnv *env, jobject view, float sp, jint background, int pad_dp, int gravity)
{
    (void)call_void(env, view, "setTextSize", "(F)V", (double)sp);
    (void)call_void(env, view, "setTextColor", "(I)V", COLOR_TEXT);
    (void)call_void(env, view, "setBackgroundColor", "(I)V", background);
    (void)call_void(env, view, "setPadding", "(IIII)V", dp((float)pad_dp), dp((float)pad_dp), dp((float)pad_dp), dp((float)pad_dp));
    (void)call_void(env, view, "setGravity", "(I)V", gravity);
}

static bool place_frame(JNIEnv *env, jobject parent, jobject view, int width, int height, int gravity, int margin_dp)
{
    jobject params = create(env, "android/widget/FrameLayout$LayoutParams", "(III)V", width, height, gravity);
    bool ok = params && call_void(env, params, "setMargins", "(IIII)V", 0, dp((float)margin_dp), 0, dp((float)margin_dp)) &&
        call_void(env, view, "setLayoutParams", "(Landroid/view/ViewGroup$LayoutParams;)V", params) &&
        call_void(env, parent, "addView", "(Landroid/view/View;)V", view);
    if (params) (*env)->DeleteLocalRef(env, params);
    return ok;
}

static bool place_linear(JNIEnv *env, jobject parent, jobject view, int width, float weight, int margin_dp)
{
    jobject params = create(env, "android/widget/LinearLayout$LayoutParams", "(IIF)V", width, WRAP, (double)weight);
    bool ok = params && call_void(env, params, "setMargins", "(IIII)V", 0, 0, 0, dp((float)margin_dp)) &&
        call_void(env, view, "setLayoutParams", "(Landroid/view/ViewGroup$LayoutParams;)V", params) &&
        call_void(env, parent, "addView", "(Landroid/view/View;)V", view);
    if (params) (*env)->DeleteLocalRef(env, params);
    return ok;
}

static jobject text_view(JNIEnv *env, jobject parent, float sp, jint background, int gravity_in, int width, int gravity, int margin)
{
    jobject view = widget(env, "android/widget/TextView");
    if (view) {
        style_text(env, view, sp, background, 12, gravity_in);
        if (!place_frame(env, parent, view, width, WRAP, gravity, margin)) { (*env)->DeleteLocalRef(env, view); view = NULL; }
    }
    return view;
}

static jobject button(JNIEnv *env, jobject parent, const char *label, jint color, float sp, int pad_dp, int gravity, float weight)
{
    jobject view = widget(env, "android/widget/Button");
    if (!view) return NULL;
    style_text(env, view, sp, color, pad_dp, gravity);
    (void)call_void(env, view, "setAllCaps", "(Z)V", (jboolean)false);
    bool ok = set_text(env, view, label) && (!parent || place_linear(env, parent, view, weight > 0.0f ? 0 : MATCH, weight, 8));
    if (!ok) { (*env)->DeleteLocalRef(env, view); view = NULL; }
    return view;
}

static void level_text(char *out, size_t cap, int level)
{
    (void)snprintf(out, cap, "%s: %s", level_names[level], level_meanings[level]);
}

static bool build_caption(JNIEnv *env, jobject panel)
{
    jobject field = keep(env, widget(env, "android/widget/EditText"));
    s.controls[C_CAPTION] = field;
    if (!field) return false;
    (void)call_void(env, field, "setTextColor", "(I)V", COLOR_TEXT);
    (void)call_void(env, field, "setHintTextColor", "(I)V", (jint)0xff9e9e9e);
    (void)call_void(env, field, "setMaxLines", "(I)V", 2);
    jstring hint = make_string(env, "Caption (optional)");
    if (hint) (void)call_void(env, field, "setHint", "(Ljava/lang/CharSequence;)V", hint);
    return place_linear(env, panel, field, MATCH, 0.0f, 8);
}

static bool build_levels(JNIEnv *env, jobject panel)
{
    char text[200];
    for (int i = 0; i < 5; ++i) {
        level_text(text, sizeof(text), i);
        s.controls[C_LEVEL + i] = keep(env, button(env, panel, text, COLOR_CHOICE, 12.0f, 4, 19, 0.0f));
        if (!s.controls[C_LEVEL + i]) return false;
    }
    return true;
}

/* Discard and Save sit under the title so that they stay on screen whatever the level list needs. */
static bool build_actions(JNIEnv *env, jobject panel)
{
    jobject row = create(env, "android/widget/LinearLayout", "(Landroid/content/Context;)V", s.activity);
    if (!row) return false;
    s.controls[C_DISCARD] = keep(env, button(env, row, "Discard", COLOR_CHOICE, 18.0f, 12, 17, 1.0f));
    s.controls[C_SAVE] = keep(env, button(env, row, "Save", COLOR_CHOSEN, 18.0f, 12, 17, 1.0f));
    return s.controls[C_DISCARD] && s.controls[C_SAVE] && place_linear(env, panel, row, MATCH, 0.0f, 8);
}

static bool build_panel(JNIEnv *env)
{
    jobject panel = create(env, "android/widget/LinearLayout", "(Landroid/content/Context;)V", s.activity);
    if (!panel || !call_void(env, panel, "setOrientation", "(I)V", 1) ||
        !call_void(env, panel, "setBackgroundColor", "(I)V", (jint)0xf2101214) ||
        !call_void(env, panel, "setPadding", "(IIII)V", dp(16), dp(12), dp(16), dp(12))) return false;
    s.title = keep(env, widget(env, "android/widget/TextView"));
    if (!s.title || !set_text(env, s.title, "Choose a content level")) return false;
    style_text(env, s.title, 18.0f, 0, 4, 3);
    s.panel = keep(env, panel);
    return place_linear(env, panel, s.title, MATCH, 0.0f, 8) && build_actions(env, panel) &&
        build_caption(env, panel) && build_levels(env, panel) && s.panel &&
        call_void(env, s.root, "addView", "(Landroid/view/View;)V", s.panel);
}

static bool build_views(JNIEnv *env)
{
    s.root = keep(env, widget(env, "android/widget/FrameLayout"));
    s.surface = s.root ? keep(env, widget(env, "android/view/SurfaceView")) : NULL;
    if (!s.surface || !call_void(env, s.root, "setBackgroundColor", "(I)V", (jint)0xff000000) ||
        !place_frame(env, s.root, s.surface, 1, 1, GRAVITY_CENTER, 0)) return false;
    s.status = keep(env, text_view(env, s.root, 16.0f, COLOR_SCRIM, GRAVITY_CENTER, WRAP, GRAVITY_TOP_CENTER, 12));
    s.notice = keep(env, text_view(env, s.root, FRAME_TEXT_SP, COLOR_SCRIM, GRAVITY_CENTER, MATCH, GRAVITY_CENTER, 0));
    s.info = keep(env, text_view(env, s.root, 16.0f, COLOR_SCRIM, 3, MATCH, GRAVITY_BOTTOM_LEFT, 24));
    jobject record = button(env, NULL, "Record", COLOR_RECORD, 20.0f, 12, 17, 0.0f);
    s.controls[C_RECORD] = keep(env, record);
    bool ok = s.status && s.notice && s.info && record &&
        place_frame(env, s.root, record, dp(200.0f), dp(64.0f), GRAVITY_BOTTOM_CENTER, 32);
    ok = ok && build_panel(env);
    if (record) (*env)->DeleteLocalRef(env, record);
    return ok;
}

static void drop_views(JNIEnv *env)
{
    jobject *list[] = {&s.root, &s.surface, &s.status, &s.notice, &s.info, &s.panel, &s.title};
    for (size_t i = 0; i < sizeof(list) / sizeof(list[0]); ++i)
        if (*list[i]) { (*env)->DeleteGlobalRef(env, *list[i]); *list[i] = NULL; }
    for (int i = 0; i < C_COUNT; ++i)
        if (s.controls[i]) { (*env)->DeleteGlobalRef(env, s.controls[i]); s.controls[i] = NULL; }
}

/* Screen state */
static bool permission_granted(JNIEnv *env, const char *name)
{
    jstring string = (*env)->NewStringUTF(env, name);
    jint result = string ? call_int(env, s.activity, "checkSelfPermission", "(Ljava/lang/String;)I", string) : -1;
    if (string) (*env)->DeleteLocalRef(env, string);
    return result == 0;
}

static bool recording_permitted(JNIEnv *env)
{
    return permission_granted(env, "android.permission.CAMERA") && permission_granted(env, "android.permission.RECORD_AUDIO");
}

static void ask_permissions(JNIEnv *env)
{
    jclass string_cls = (*env)->FindClass(env, "java/lang/String");
    jobjectArray names = string_cls ? (*env)->NewObjectArray(env, 2, string_cls, NULL) : NULL;
    jstring camera = (*env)->NewStringUTF(env, "android.permission.CAMERA");
    jstring microphone = (*env)->NewStringUTF(env, "android.permission.RECORD_AUDIO");
    if (names && camera && microphone) {
        (*env)->SetObjectArrayElement(env, names, 0, camera);
        (*env)->SetObjectArrayElement(env, names, 1, microphone);
        (void)call_void(env, s.activity, "requestPermissions", "([Ljava/lang/String;I)V", names, 2);
    }
    (void)clean(env);
}

static void refuse(JNIEnv *env, const char *message)
{
    s.phase = PHASE_REFUSED;
    (void)set_text(env, s.notice, message);
}

static int file_size_kb(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (int)(st.st_size / 1024) : 0;
}

static void release_window(void)
{
    if (s.window) ANativeWindow_release(s.window);
    s.window = NULL;
}

/* The preview or video surface once the SurfaceView has created it. */
static bool acquire_window(JNIEnv *env)
{
    if (s.window) return true;
    jobject holder = call_object(env, s.surface, "getHolder", "()Landroid/view/SurfaceHolder;");
    jobject surface = holder ? call_object(env, holder, "getSurface", "()Landroid/view/Surface;") : NULL;
    if (surface && call_bool(env, surface, "isValid", "()Z")) s.window = ANativeWindow_fromSurface(env, surface);
    return s.window != NULL;
}

static void layout_surface(JNIEnv *env)
{
    jint w = call_int(env, s.root, "getWidth", "()I"), h = call_int(env, s.root, "getHeight", "()I");
    int fit_w = 0, fit_h = 0;
    if (s.sized || w <= 0 || h <= 0) return;
    zapp_clip_fit(w, h, 480, 854, &fit_w, &fit_h);
    jobject params = create(env, "android/widget/FrameLayout$LayoutParams", "(III)V", fit_w, fit_h, GRAVITY_CENTER);
    if (params && call_void(env, s.surface, "setLayoutParams", "(Landroid/view/ViewGroup$LayoutParams;)V", params)) s.sized = true;
    if (params) (*env)->DeleteLocalRef(env, params);
}

static bool notice_visible(void)
{
    bool paused = s.player && zapp_clip_player_paused(s.player);
    return s.phase == PHASE_REFUSED || (s.phase == PHASE_WATCH && (s.count == 0 || paused || s.error_shown));
}

static bool surface_visible(void)
{
    return s.phase != PHASE_REFUSED && s.phase != PHASE_PERMISSION && !(s.phase == PHASE_WATCH && s.count == 0);
}

static void show_phase(JNIEnv *env)
{
    bool record = s.mode == ZAPP_CLIP_RECORD;
    show(env, s.controls[C_RECORD], record && (s.phase == PHASE_READY || s.phase == PHASE_RECORDING));
    show(env, s.panel, s.phase == PHASE_REVIEW);
    show(env, s.notice, notice_visible());
    show(env, s.status, s.phase == PHASE_READY || s.phase == PHASE_RECORDING || s.phase == PHASE_FINISHING);
    show(env, s.info, s.phase == PHASE_WATCH && s.count > 0);
    show(env, s.surface, surface_visible());
    if (s.controls[C_RECORD]) (void)set_text(env, s.controls[C_RECORD], s.phase == PHASE_RECORDING ? "Stop" : "Record");
}

static void select_level(JNIEnv *env, int level)
{
    s.level = level;
    for (int i = 0; i < 5; ++i)
        (void)call_void(env, s.controls[C_LEVEL + i], "setBackgroundColor", "(I)V", i == level ? COLOR_CHOSEN : COLOR_CHOICE);
}

static int64_t now_ms(void)
{
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ? (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 : 0;
}

/* Advances the thermal latch from a fresh status; false while recording must stay refused. */
static bool thermal_allows(JNIEnv *env)
{
    int status = zapp_clip_thermal_status(env, s.activity);
    return zapp_clip_thermal_track(&s.pace, status < 0 ? 0 : status);
}

static const char *ready_text(void)
{
    if (s.unsaved) return "The last recording was not saved";
    return s.recorder ? "Ready" : "Tap Record to open the camera preview";
}

static void new_pending(void)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_REALTIME, &now);
    (void)snprintf(s.pending, sizeof(s.pending), "%s/%s-%lld.mp4", s.dir, ZAPP_CLIP_PENDING_PREFIX,
                   (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

static void enter_ready(JNIEnv *env)
{
    struct zapp_codec_info codecs[128];
    size_t count = zapp_clip_list_codecs(env, codecs, 128);
    for (size_t i = 0; i < count; ++i)
        __android_log_print(ANDROID_LOG_INFO, TAG, "clip codec %s encoder=%d hardware=%d avc=%d",
                            codecs[i].name, codecs[i].encoder, codecs[i].hardware, codecs[i].avc);
    int pick = zapp_clip_pick_encoder(codecs, count);
    if (pick < 0) { refuse(env, ZAPP_CLIP_NO_ENCODER); return; }
    (void)snprintf(s.encoder, sizeof(s.encoder), "%s", codecs[pick].name);
    s.phase = PHASE_READY;
    (void)set_text(env, s.status, ready_text());
}

static void enter_review(JNIEnv *env, int64_t duration_ms)
{
    s.duration_ms = duration_ms;
    s.phase = PHASE_REVIEW;
    select_level(env, 0);
    (void)set_text(env, s.controls[C_CAPTION], "");
    (void)set_text(env, s.title, "Choose a content level");
}

/* Takes the finished recording from the worker: the level choice, or the reason nothing was kept. */
static void collect_recording(JNIEnv *env)
{
    int64_t duration_ms = zapp_clip_recorder_collect(s.recorder);
    const char *why = zapp_clip_recorder_message(s.recorder);
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip collected after %lld ms", (long long)(now_ms() - s.stop_asked_ms));
    if (duration_ms > 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "clip recorded %lld ms, %d KiB", (long long)duration_ms, file_size_kb(s.pending));
        enter_review(env, duration_ms);
    } else {
        s.phase = PHASE_READY;
        (void)set_text(env, s.status, why[0] ? why : "Nothing was recorded. Try again.");
    }
}

/* Asks the worker to end the recording; tick_finishing takes the result, so the main thread never waits. */
static void finish_recording(JNIEnv *env)
{
    zapp_clip_recorder_request_stop(s.recorder);
    s.stop_asked_ms = now_ms();
    s.phase = PHASE_FINISHING;
    (void)set_text(env, s.status, "Saving...");
}

/* The activity is leaving: the worker gets a short, bounded time to close the file. */
static void settle_recording(JNIEnv *env)
{
    if (s.phase == PHASE_RECORDING) finish_recording(env);
    if (s.phase != PHASE_FINISHING) return;
    bool done = zapp_clip_recorder_wait(s.recorder, PAUSE_WAIT_MS);
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip pause waited %lld ms, finished %d", (long long)(now_ms() - s.stop_asked_ms), done);
    if (done) collect_recording(env);
    else { s.phase = PHASE_READY; s.unsaved = true; }
}

static void start_recording(JNIEnv *env)
{
    char error[160] = "";
    if (!thermal_allows(env)) { (void)set_text(env, s.status, ZAPP_CLIP_TOO_HOT); return; }
    new_pending();
    s.unsaved = false;
    if (!zapp_clip_recorder_start(s.recorder, s.pending, error, sizeof(error))) { (void)set_text(env, s.status, error); return; }
    s.phase = PHASE_RECORDING;
    s.health_at_ms = 0;
}

static void caption_utf8(JNIEnv *env, char *out, size_t cap)
{
    out[0] = '\0';
    jobject text = call_object(env, s.controls[C_CAPTION], "getText", "()Landroid/text/Editable;");
    jobject string = text ? call_object(env, text, "toString", "()Ljava/lang/String;") : NULL;
    jstring encoding = string ? (*env)->NewStringUTF(env, "UTF-8") : NULL;
    jbyteArray bytes = encoding ? call_object(env, string, "getBytes", "(Ljava/lang/String;)[B", encoding) : NULL;
    jsize n = bytes ? (*env)->GetArrayLength(env, bytes) : 0;
    if (n >= (jsize)cap) {
        n = (jsize)cap - 1;
        jbyte first = 0;
        while (n > 0) {
            (*env)->GetByteArrayRegion(env, bytes, n, 1, &first);
            if ((first & 0xc0) != 0x80) break;
            --n;
        }
    }
    if (bytes && n > 0) (*env)->GetByteArrayRegion(env, bytes, 0, n, (jbyte *)out);
    out[n > 0 ? n : 0] = '\0';
    (void)clean(env);
}

static void load_list(void)
{
    s.count = zapp_clip_store_list(s.dir, s.clips, ZAPP_CLIP_LIST_MAX, &s.total);
    if (s.index >= s.count) s.index = 0;
}

static void save_clip(JNIEnv *env)
{
    struct zapp_clip_meta meta = {.level = (uint8_t)(s.level + 1), .created_at = (int64_t)time(NULL), .duration_ms = s.duration_ms};
    char id[ZAPP_CLIP_ID_CAP], error[128];
    caption_utf8(env, meta.caption, sizeof(meta.caption));
    if (!zapp_clip_store_commit(s.dir, s.pending, &meta, id, error, sizeof(error))) { (void)set_text(env, s.title, error); return; }
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip saved %.16s level %d %lld ms", id, meta.level, (long long)meta.duration_ms);
    s.phase = PHASE_READY;
    (void)set_text(env, s.status, "Saved");
}

static void discard_clip(JNIEnv *env)
{
    (void)unlink(s.pending);
    s.phase = PHASE_READY;
    (void)set_text(env, s.status, ready_text());
}

static void hide_keyboard(JNIEnv *env)
{
    if (!s.keyboard) return;
    jobject method = call_object(env, s.activity, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
                                 (*env)->NewStringUTF(env, "input_method"));
    jobject token = method ? call_object(env, s.controls[C_CAPTION], "getWindowToken", "()Landroid/os/IBinder;") : NULL;
    if (token) (void)call_bool(env, method, "hideSoftInputFromWindow", "(Landroid/os/IBinder;I)Z", token, 0);
    s.keyboard = false;
}

static void focus_caption(JNIEnv *env)
{
    (void)call_bool(env, s.controls[C_CAPTION], "requestFocus", "()Z");
    jobject method = call_object(env, s.activity, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
                                 (*env)->NewStringUTF(env, "input_method"));
    if (method && s.controls[C_CAPTION]) {
        jmethodID show_input = method_of(env, method, "showSoftInput", "(Landroid/view/View;I)Z");
        if (show_input) (void)(*env)->CallBooleanMethod(env, method, show_input, s.controls[C_CAPTION], 0);
        (void)clean(env);
    }
    s.keyboard = true;
}

/* Watching */
static void play_current(JNIEnv *env)
{
    char text[ZAPP_CLIP_CAPTION_CAP + 80];
    if (s.player) { zapp_clip_player_close(s.player); s.player = NULL; }
    s.error_shown = false;
    if (s.count == 0 || !acquire_window(env)) return;
    const struct zapp_clip *clip = &s.clips[s.index];
    s.player = zapp_clip_player_open(s.dir, clip->id, s.window);
    (void)snprintf(text, sizeof(text), "%s  %zu/%zu%s%s%s", level_names[clip->meta.level - 1], s.index + 1, s.count,
                   s.total > s.count ? "  (older clips are not shown)" : "", clip->meta.caption[0] ? "\n" : "", clip->meta.caption);
    (void)set_text(env, s.info, text);
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip watch %zu/%zu %.16s", s.index + 1, s.count, clip->id);
}

static void step_clip(JNIEnv *env, int direction)
{
    if (s.count < 2) return;
    s.index = (s.index + (size_t)(direction > 0 ? 1 : s.count - 1)) % s.count;
    play_current(env);
}

static void tick_watch(JNIEnv *env)
{
    char error[160];
    if (s.count == 0) { show_phase(env); return; }
    if (!s.window && !acquire_window(env)) return;
    if (!s.player) { play_current(env); return; }
    if (zapp_clip_player_error(s.player, error, sizeof(error))) {
        (void)set_text(env, s.notice, error);
        s.error_shown = true;
    } else if (zapp_clip_player_finished(s.player)) {
        play_current(env);
    }
}

/* Recording */
static void log_health(JNIEnv *env)
{
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip health t=%lld ms battery=%d%% thermal=%d",
                        (long long)zapp_clip_recorder_elapsed_ms(s.recorder),
                        zapp_clip_battery_percent(env, s.activity), zapp_clip_thermal_status(env, s.activity));
}

static void tick_recording(JNIEnv *env)
{
    char label[48];
    int64_t ms = zapp_clip_recorder_elapsed_ms(s.recorder);
    (void)snprintf(label, sizeof(label), "Recording %02d:%02d / %02d:%02d", (int)(ms / 60000), (int)(ms / 1000 % 60),
                   (int)(zapp_clip_profile.max_ms / 60000), (int)(zapp_clip_profile.max_ms / 1000 % 60));
    (void)set_text(env, s.status, label);
    if (ms >= s.health_at_ms) {
        log_health(env);
        s.health_at_ms = (ms / HEALTH_EVERY_MS + 1) * HEALTH_EVERY_MS;
    }
    if (zapp_clip_thermal_stops(s.thermal)) __android_log_print(ANDROID_LOG_WARN, TAG, "clip recording stopped by thermal status");
    else if (zapp_clip_recorder_running(s.recorder)) return;
    finish_recording(env);
}

static void tick_finishing(JNIEnv *env)
{
    if (!zapp_clip_recorder_running(s.recorder)) collect_recording(env);
}

/* Opens the camera onto the preview; a failure is shown on the status line and the next Record tap retries. */
static bool open_camera(JNIEnv *env)
{
    char error[160] = "";
    if (!acquire_window(env)) return false;
    s.recorder = zapp_clip_recorder_open(s.window, s.encoder, error, sizeof(error));
    if (s.recorder == NULL) zapp_clip_gate_wait(&s.gate);
    (void)set_text(env, s.status, s.recorder ? ready_text() : error[0] ? error : "The camera is not available. Tap Record to try again.");
    return s.recorder != NULL;
}

/* A Record tap: the first one opens the preview (a lost camera is replaced the same way), the next one records. */
static void tap_record(JNIEnv *env)
{
    if (s.recorder && zapp_clip_recorder_camera_lost(s.recorder)) {
        zapp_clip_recorder_close(s.recorder);
        s.recorder = NULL;
    }
    if (zapp_clip_gate_tap(&s.gate, s.recorder != NULL)) start_recording(env);
    else if (open_camera(env)) (void)set_text(env, s.status, "Preview is on. Tap Record again to start recording.");
}

/* The camera went away while idle: say so and wait for the person to ask again. */
static void lose_camera(JNIEnv *env)
{
    (void)set_text(env, s.status, zapp_clip_recorder_message(s.recorder)[0] ? zapp_clip_recorder_message(s.recorder) :
                   "The camera stopped. Tap Record to try again.");
    zapp_clip_recorder_close(s.recorder);
    s.recorder = NULL;
    zapp_clip_gate_wait(&s.gate);
}

static void tick_ready(JNIEnv *env)
{
    if (s.recorder && zapp_clip_recorder_camera_lost(s.recorder)) { lose_camera(env); return; }
    bool allowed = s.pace != ZAPP_PACE_PAUSE;
    if (!allowed || s.hot) (void)set_text(env, s.status, allowed ? ready_text() : ZAPP_CLIP_TOO_HOT);
    s.hot = !allowed;
    if (!s.recorder && zapp_clip_gate_may_open(&s.gate)) (void)open_camera(env);
}

static void tick(JNIEnv *env)
{
    if (!s.active || s.paused) return;
    layout_surface(env);
    int status = zapp_clip_thermal_status(env, s.activity);
    s.thermal = status < 0 ? 0 : status;
    (void)zapp_clip_thermal_track(&s.pace, s.thermal);
    switch (s.phase) {
    case PHASE_PERMISSION: if (recording_permitted(env)) enter_ready(env); break;
    case PHASE_READY: tick_ready(env); break;
    case PHASE_RECORDING: tick_recording(env); break;
    case PHASE_FINISHING: tick_finishing(env); break;
    case PHASE_WATCH: tick_watch(env); break;
    default: break;
    }
    show_phase(env);
}

static int timer_ready(int fd, int events, void *context)
{
    (void)events; (void)context;
    unsigned long long expirations;
    JNIEnv *env = NULL;
    if (read(fd, &expirations, sizeof(expirations)) < 0 || !s.vm || (*s.vm)->GetEnv(s.vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return 1;
    if ((*env)->PushLocalFrame(env, 64) != JNI_OK) { (void)clean(env); return 1; }
    tick(env);
    (*env)->PopLocalFrame(env, NULL);
    return 1;
}

static bool start_timer(void)
{
    struct itimerspec spec = {.it_interval = {.tv_nsec = TICK_NS}, .it_value = {.tv_nsec = TICK_NS}};
    s.looper = ALooper_forThread();
    s.timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (!s.looper || s.timer < 0 || timerfd_settime(s.timer, 0, &spec, NULL) != 0) return false;
    return ALooper_addFd(s.looper, s.timer, ALOOPER_POLL_CALLBACK, ALOOPER_EVENT_INPUT, timer_ready, NULL) == 1;
}

static void stop_timer(void)
{
    if (s.looper && s.timer >= 0) ALooper_removeFd(s.looper, s.timer);
    if (s.timer >= 0) (void)close(s.timer);
    s.timer = -1;
    s.looper = NULL;
}

static bool read_density(JNIEnv *env)
{
    jobject resources = call_object(env, s.activity, "getResources", "()Landroid/content/res/Resources;");
    jobject metrics = resources ? call_object(env, resources, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;") : NULL;
    jclass cls = metrics ? (*env)->GetObjectClass(env, metrics) : NULL;
    jfieldID field = cls ? (*env)->GetFieldID(env, cls, "density", "F") : NULL;
    if (!clean(env) || !field) return false;
    s.density = (*env)->GetFloatField(env, metrics, field);
    return clean(env) && s.density > 0.0f;
}

static void release_media(JNIEnv *env)
{
    (void)env;
    if (s.player) { zapp_clip_player_close(s.player); s.player = NULL; }
    if (s.recorder) { zapp_clip_recorder_close(s.recorder); s.recorder = NULL; }
    release_window();
}

static bool attach(JNIEnv *env)
{
    jobject params = create(env, "android/view/ViewGroup$LayoutParams", "(II)V", MATCH, MATCH);
    bool ok = params && call_void(env, s.activity, "addContentView", "(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V", s.root, params);
    if (params) (*env)->DeleteLocalRef(env, params);
    return ok;
}

static void begin(JNIEnv *env)
{
    if (s.mode == ZAPP_CLIP_WATCH) {
        load_list();
        s.phase = PHASE_WATCH;
        (void)set_text(env, s.notice, "No clips yet. Record one first.");
    } else if (recording_permitted(env)) {
        enter_ready(env);
    } else {
        s.phase = PHASE_PERMISSION;
        (void)set_text(env, s.notice, "Allow the camera and microphone to record a clip.");
        ask_permissions(env);
    }
    show_phase(env);
}

/* Names the clips folder, then builds and attaches the views and starts the tick. */
static bool prepare(JNIEnv *env, const char *files_dir)
{
    int n = snprintf(s.dir, sizeof(s.dir), "%s/clips", files_dir);
    return n > 0 && (size_t)n + 48 < sizeof(s.pending) && (*env)->GetJavaVM(env, &s.vm) == JNI_OK &&
        (mkdir(s.dir, 0700) == 0 || access(s.dir, W_OK) == 0) && read_density(env) && build_views(env) && start_timer() && attach(env);
}

bool zapp_clip_screen_open(JNIEnv *env, jobject activity, const char *files_dir, enum zapp_clip_mode mode)
{
    if (s.active || !env || !activity || !files_dir) return false;
    if ((*env)->PushLocalFrame(env, 64) != JNI_OK) { (void)clean(env); return false; }
    memset(&s, 0, sizeof(s));
    s.timer = -1;
    s.mode = mode;
    s.activity = keep(env, activity);
    s.pace = ZAPP_CLIP_PACE_UNKNOWN;
    zapp_clip_gate_init(&s.gate);
    bool ok = s.activity && prepare(env, files_dir);
    (void)zapp_clip_store_clean(s.dir, zapp_clip_recorder_path_owned);
    s.active = ok;
    if (ok) begin(env);
    else { stop_timer(); drop_views(env); if (s.activity) (*env)->DeleteGlobalRef(env, s.activity); s.activity = NULL; }
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}

bool zapp_clip_screen_active(void) { return s.active; }

void zapp_clip_screen_close(JNIEnv *env)
{
    if (!s.active) return;
    (*env)->PushLocalFrame(env, 16);
    stop_timer();
    release_media(env);
    if (s.pending[0] != '\0') (void)unlink(s.pending);
    hide_keyboard(env);
    jobject parent = call_object(env, s.root, "getParent", "()Landroid/view/ViewParent;");
    if (parent) (void)call_void(env, parent, "removeView", "(Landroid/view/View;)V", s.root);
    drop_views(env);
    (*env)->DeleteGlobalRef(env, s.activity);
    memset(&s, 0, sizeof(s));
    s.timer = -1;
    (*env)->PopLocalFrame(env, NULL);
}

bool zapp_clip_screen_back(JNIEnv *env)
{
    if (!s.active) return false;
    if (s.keyboard) { hide_keyboard(env); return true; }
    if (s.phase == PHASE_FINISHING) return true;
    if (s.phase == PHASE_RECORDING) { finish_recording(env); show_phase(env); return true; }
    if (s.phase == PHASE_REVIEW) { discard_clip(env); show_phase(env); return true; }
    zapp_clip_screen_close(env);
    return true;
}

void zapp_clip_screen_pause(JNIEnv *env)
{
    if (!s.active) return;
    s.paused = true;
    s.left = s.left || s.phase == PHASE_PERMISSION;
    settle_recording(env);
    release_media(env);
    zapp_clip_gate_pause(&s.gate);
    s.pace = ZAPP_CLIP_PACE_UNKNOWN;
}

void zapp_clip_screen_resume(JNIEnv *env)
{
    if (!s.active) return;
    s.paused = false;
    if (s.unsaved && s.phase == PHASE_READY) (void)set_text(env, s.status, ready_text());
    if (s.phase != PHASE_PERMISSION) return;
    if (recording_permitted(env)) enter_ready(env);
    else if (s.left) refuse(env, "Camera and microphone access are needed to record a clip. "
                                  "Allow them in the app's permissions in Settings, then open this screen again.");
    show_phase(env);
}

/* Input */
static bool hit(JNIEnv *env, jobject view, float x, float y)
{
    jint xy[2] = {0};
    if (!view || !call_bool(env, view, "isShown", "()Z")) return false;
    jintArray pos = (*env)->NewIntArray(env, 2);
    if (!pos) return false;
    (void)call_void(env, view, "getLocationInWindow", "([I)V", pos);
    (*env)->GetIntArrayRegion(env, pos, 0, 2, xy);
    jint w = call_int(env, view, "getWidth", "()I"), h = call_int(env, view, "getHeight", "()I");
    (*env)->DeleteLocalRef(env, pos);
    return clean(env) && x >= (float)xy[0] && y >= (float)xy[1] && x < (float)(xy[0] + w) && y < (float)(xy[1] + h);
}

static void press(JNIEnv *env, float x, float y)
{
    for (int i = 0; i < C_COUNT; ++i) {
        if (!s.controls[i] || !hit(env, s.controls[i], x, y)) continue;
        if (i != C_CAPTION) hide_keyboard(env);
        if (i == C_RECORD && s.phase == PHASE_READY) tap_record(env);
        else if (i == C_RECORD && s.phase == PHASE_RECORDING) finish_recording(env);
        else if (i == C_CAPTION) focus_caption(env);
        else if (i >= C_LEVEL && i < C_SAVE) select_level(env, i - C_LEVEL);
        else if (i == C_SAVE) save_clip(env);
        else if (i == C_DISCARD) discard_clip(env);
        return;
    }
}

static void gesture(JNIEnv *env, float x, float y)
{
    float dx = x - s.down_x, dy = y - s.down_y;
    float adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
    if (s.phase == PHASE_WATCH && ady > (float)dp(SWIPE_DP) && ady > adx) step_clip(env, dy < 0 ? 1 : -1);
    else if (adx > (float)dp(TAP_DP) || ady > (float)dp(TAP_DP)) return;
    else if (s.phase == PHASE_WATCH && s.player) {
        bool pause = !zapp_clip_player_paused(s.player);
        zapp_clip_player_set_paused(s.player, pause);
        if (pause) (void)set_text(env, s.notice, "Paused");
    } else press(env, x, y);
}

bool zapp_clip_screen_input(JNIEnv *env, const AInputEvent *event)
{
    if (!s.active || !event) return false;
    if (AInputEvent_getType(event) == AINPUT_EVENT_TYPE_KEY) {
        if (AKeyEvent_getKeyCode(event) != AKEYCODE_BACK) return false;
        return AKeyEvent_getAction(event) != AKEY_EVENT_ACTION_UP || zapp_clip_screen_back(env);
    }
    if (AInputEvent_getType(event) != AINPUT_EVENT_TYPE_MOTION) return false;
    int32_t action = AMotionEvent_getAction(event) & AMOTION_EVENT_ACTION_MASK;
    float x = AMotionEvent_getX(event, 0), y = AMotionEvent_getY(event, 0);
    if (action == AMOTION_EVENT_ACTION_DOWN) { s.down_x = x; s.down_y = y; }
    else if (action == AMOTION_EVENT_ACTION_UP) {
        if ((*env)->PushLocalFrame(env, 32) == JNI_OK) { gesture(env, x, y); (*env)->PopLocalFrame(env, NULL); }
        if (s.active) show_phase(env);
    }
    return true;
}
