/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "secure_window.h"
#include <stddef.h>

static struct zapp_touch_gate gate;

bool zapp_touch_gate_drops(struct zapp_touch_gate *state, int32_t action, int32_t flags)
{
    int32_t kind = action & ZAPP_MOTION_ACTION_MASK;
    bool cancel = kind == ZAPP_MOTION_CANCEL;
    if (state->protect && (flags & ZAPP_MOTION_OBSCURED)) {
        if (!cancel && (!state->poisoned || kind == ZAPP_MOTION_DOWN)) state->obscured_gestures++;
        state->poisoned = !cancel;
        return !cancel;
    }
    if (kind == ZAPP_MOTION_DOWN) state->poisoned = false;
    return state->poisoned && !cancel;
}
void zapp_touch_gate_release(struct zapp_touch_gate *state)
{
    if (state->protect) state->poisoned = true;
    state->protect = false;
}

unsigned zapp_secure_window_obscured_gestures(void) { return gate.obscured_gestures; }
void zapp_secure_window_release(void) { zapp_touch_gate_release(&gate); }

bool zapp_secure_window_drops_motion(int32_t action, int32_t flags)
{
    return zapp_touch_gate_drops(&gate, action, flags);
}

/* The first protection the last apply could not give, in words that end "this phone would not let the app ...". */
static const char *refusal;
const char *zapp_secure_window_refusal(void) { return refusal; }
/* A member the caller left NULL cannot be given, so it is refused. */
static bool attempt(bool (*protect)(void *ctx, bool on), void *ctx, bool on, const char *what)
{
    bool ok = protect && protect(ctx, on);
    if (!ok && !refusal) refusal = what;
    return ok;
}
bool zapp_secure_window_apply(const struct zapp_secure_ops *ops, bool on)
{
    refusal = NULL;
    if (on) gate.protect = true;
    bool flagged = attempt(ops->flag_secure, ops->ctx, on, "hide the screen from screenshots and recordings");
    bool filtered = attempt(ops->filter_touches, ops->ctx, on, "ignore touches that pass through another window");
    bool covered = attempt(ops->hide_overlays, ops->ctx, on, "stop other apps from drawing over the screen");
    bool hidden = attempt(ops->recents, ops->ctx, on, "hide the screen in the list of recent apps");
    bool guarded = attempt(ops->accessibility, ops->ctx, on, "keep out screen readers that are not allowed sensitive data");
    if (!on) zapp_secure_window_release();
    return flagged && filtered && covered && hidden && guarded;
}

bool zapp_clip_copy(const struct zapp_clip_ops *ops, const char *text, int64_t *stamp)
{
    int64_t unused;
    return ops && ops->put && text && text[0] && ops->put(ops->ctx, text, stamp ? stamp : &unused);
}
bool zapp_clip_expire(const struct zapp_clip_ops *ops, int64_t stamp)
{
    int64_t held = 0;
    if (!ops || !ops->current || !ops->clear) return false;
    enum zapp_clip_state state = ops->current(ops->ctx, &held);
    if (state == ZAPP_CLIP_UNREADABLE) return false;
    return state == ZAPP_CLIP_EMPTY || held != stamp || ops->clear(ops->ctx);
}
bool zapp_clip_settle(const struct zapp_clip_ops *ops, int64_t stamp, unsigned attempts)
{
    for (unsigned i = 0; i < attempts; ++i) {
        if (zapp_clip_expire(ops, stamp)) return true;
        if (ops && ops->pause && i + 1 < attempts) ops->pause(ops->ctx);
    }
    return false;
}

#ifdef __ANDROID__
#include "jni_util.h"
#include <assert.h>

#define WINDOW_FLAG_SECURE 0x2000 /* WindowManager.LayoutParams.FLAG_SECURE */
#define PERMISSION_GRANTED 0 /* PackageManager.PERMISSION_GRANTED */
#define ACCESSIBILITY_DATA_SENSITIVE_AUTO 0
#define ACCESSIBILITY_DATA_SENSITIVE_YES 1

static jobject window_of(JNIEnv *env, ANativeActivity *activity)
{
    return zj_object_property(env, activity->clazz, "getWindow", "()Landroid/view/Window;");
}
/* Reads the int field "flags" of the window attributes. */
static bool window_attribute(JNIEnv *env, jobject window, const char *name, jint *value)
{
    jobject attributes = zj_object_property(env, window, "getAttributes", "()Landroid/view/WindowManager$LayoutParams;");
    jclass type = attributes ? (*env)->GetObjectClass(env, attributes) : NULL;
    jfieldID field = type && zj_clean(env) ? (*env)->GetFieldID(env, type, name, "I") : NULL;
    if (field) *value = (*env)->GetIntField(env, attributes, field);
    return zj_clean(env) && field;
}
/* Sets or clears FLAG_SECURE through the Window on the UI thread, where the change is made before the call
 * returns, and reads the attributes back. A flag that was only queued would leave a first frame unprotected. */
static bool jni_flag_secure(void *context, bool on)
{
    ANativeActivity *activity = context;
    JNIEnv *env = activity->env;
    jint flags = 0;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject window = window_of(env, activity);
    bool ok = window && zj_int_property(env, window, on ? "addFlags" : "clearFlags", WINDOW_FLAG_SECURE) &&
        window_attribute(env, window, "flags", &flags) && ((flags & WINDOW_FLAG_SECURE) != 0) == on;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
/* Windows of other apps are not drawn over this one. The platform has no public getter for this setting, and the
 * attribute that holds it is a hidden field, so the confirmation is that the app holds HIDE_OVERLAY_WINDOWS (which
 * the setting needs) and that the call returned without an exception. */
static bool jni_hide_overlays(void *context, bool on)
{
    ANativeActivity *activity = context;
    JNIEnv *env = activity->env;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jmethodID check = zj_method(env, activity->clazz, "checkSelfPermission", "(Ljava/lang/String;)I");
    jstring permission = check ? zj_string(env, "android.permission.HIDE_OVERLAY_WINDOWS") : NULL;
    bool granted = permission && (*env)->CallIntMethod(env, activity->clazz, check, permission) == PERMISSION_GRANTED;
    jobject window = zj_clean(env) && granted ? window_of(env, activity) : NULL;
    bool ok = window && zj_bool_property(env, window, "setHideOverlayWindows", on);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
/* The system does not capture the recents thumbnail. The platform has no getter, so the call completing
 * without an exception is the only confirmation; FLAG_SECURE blanks the capture as well. */
static bool jni_recents(void *context, bool on)
{
    ANativeActivity *activity = context;
    return zj_bool_property(activity->env, activity->clazz, "setRecentsScreenshotEnabled", !on);
}
/* The decor view, and so every view under it that does not choose for itself, is marked accessibility-data
 * sensitive; the mode is read back. */
static bool jni_accessibility(void *context, bool on)
{
    ANativeActivity *activity = context;
    JNIEnv *env = activity->env;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject window = window_of(env, activity);
    jobject decor = window ? zj_object_property(env, window, "getDecorView", "()Landroid/view/View;") : NULL;
    jmethodID get = decor ? zj_method(env, decor, "isAccessibilityDataSensitive", "()Z") : NULL;
    bool ok = decor && get &&
        zj_int_property(env, decor, "setAccessibilityDataSensitive", on ? ACCESSIBILITY_DATA_SENSITIVE_YES : ACCESSIBILITY_DATA_SENSITIVE_AUTO) &&
        (*env)->CallBooleanMethod(env, decor, get) == (jboolean)on;
    ok = zj_clean(env) && ok;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static bool jni_filter_touches(void *context, bool on)
{
    ANativeActivity *activity = context;
    JNIEnv *env = activity->env;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject window = window_of(env, activity);
    jobject decor = window ? zj_object_property(env, window, "getDecorView", "()Landroid/view/View;") : NULL;
    jmethodID get = decor ? zj_method(env, decor, "getFilterTouchesWhenObscured", "()Z") : NULL;
    bool ok = decor && zj_bool_property(env, decor, "setFilterTouchesWhenObscured", on) && get &&
        (*env)->CallBooleanMethod(env, decor, get) == (jboolean)on;
    ok = zj_clean(env) && ok;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
void zapp_secure_window_ops(struct zapp_secure_ops *ops, ANativeActivity *activity)
{
    *ops = (struct zapp_secure_ops){activity, jni_flag_secure, jni_filter_touches, jni_hide_overlays, jni_recents, jni_accessibility};
}
bool zapp_secure_window(ANativeActivity *activity, bool on)
{
    struct zapp_secure_ops ops;
    zapp_secure_window_ops(&ops, activity);
    return zapp_secure_window_apply(&ops, on);
}
bool zapp_secure_window_drops(const AInputEvent *event)
{
    if (!event || AInputEvent_getType(event) != AINPUT_EVENT_TYPE_MOTION) return false;
    return zapp_secure_window_drops_motion(AMotionEvent_getAction(event), AMotionEvent_getFlags(event));
}
static_assert((ZAPP_MOTION_OBSCURED & AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED) == AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED, "obscured flag");
static_assert(ZAPP_MOTION_ACTION_MASK == AMOTION_EVENT_ACTION_MASK && ZAPP_MOTION_DOWN == AMOTION_EVENT_ACTION_DOWN &&
              ZAPP_MOTION_CANCEL == AMOTION_EVENT_ACTION_CANCEL, "motion actions");

/* ---- sensitive clipboard ---- */

#include <android/log.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define CLIP_SENSITIVE_EXTRA "android.content.extra.IS_SENSITIVE" /* ClipDescription.EXTRA_IS_SENSITIVE */
#define CLIP_LABEL "Z23 address"
#define CLIP_RETRY_SECONDS 10 /* between tries of a clear that was refused */
#define CLIP_RETRY_ATTEMPTS 2160u /* six hours of tries */
#define CLIP_LOG(what) __android_log_print(ANDROID_LOG_WARN, "z23", "clipboard: %s", what)

struct jni_clip { JNIEnv *env; jobject manager; bool refusal_logged; };
static bool jni_clip_clear(void *context);

/* A ClipData of plain text. */
static jobject plain_clip(JNIEnv *env, const char *text)
{
    jclass data = (*env)->FindClass(env, "android/content/ClipData");
    jmethodID plain = data ? (*env)->GetStaticMethodID(env, data, "newPlainText",
        "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;") : NULL;
    jstring label = zj_clean(env) && plain ? zj_string(env, CLIP_LABEL) : NULL, body = label ? zj_string(env, text) : NULL;
    jobject clip = body ? (*env)->CallStaticObjectMethod(env, data, plain, label, body) : NULL;
    return zj_clean(env) ? clip : NULL;
}
/* A PersistableBundle that holds the sensitive extra set to true. */
static jobject sensitive_extras(JNIEnv *env)
{
    jclass bundle = (*env)->FindClass(env, "android/os/PersistableBundle");
    jmethodID make = bundle ? (*env)->GetMethodID(env, bundle, "<init>", "()V") : NULL;
    jmethodID put = make ? (*env)->GetMethodID(env, bundle, "putBoolean", "(Ljava/lang/String;Z)V") : NULL;
    jobject extras = zj_clean(env) && put ? (*env)->NewObject(env, bundle, make) : NULL;
    jstring key = extras ? zj_string(env, CLIP_SENSITIVE_EXTRA) : NULL;
    if (key) (*env)->CallVoidMethod(env, extras, put, key, JNI_TRUE);
    return key && zj_clean(env) ? extras : NULL;
}
/* A plain-text clip whose description carries the sensitive extra. */
static jobject sensitive_clip(JNIEnv *env, const char *text)
{
    jobject clip = plain_clip(env, text);
    jobject description = clip ? zj_object_property(env, clip, "getDescription", "()Landroid/content/ClipDescription;") : NULL;
    jobject extras = description ? sensitive_extras(env) : NULL;
    jmethodID set = extras ? zj_method(env, description, "setExtras", "(Landroid/os/PersistableBundle;)V") : NULL;
    if (set) (*env)->CallVoidMethod(env, description, set, extras);
    return set && zj_clean(env) ? clip : NULL;
}
/* A refused read (SecurityException while the app has no focus) is UNREADABLE; no clip at all is EMPTY. */
static enum zapp_clip_state stamp_of(JNIEnv *env, jobject manager, int64_t *stamp)
{
    jmethodID read = zj_method(env, manager, "getPrimaryClipDescription", "()Landroid/content/ClipDescription;");
    jobject description = read ? (*env)->CallObjectMethod(env, manager, read) : NULL;
    if (!read || !zj_clean(env)) return ZAPP_CLIP_UNREADABLE;
    if (!description) return ZAPP_CLIP_EMPTY;
    jmethodID get = zj_method(env, description, "getTimestamp", "()J");
    jlong value = get ? (*env)->CallLongMethod(env, description, get) : 0;
    if (!get || !zj_clean(env)) return ZAPP_CLIP_UNREADABLE;
    *stamp = (int64_t)value;
    return ZAPP_CLIP_HELD;
}
static bool jni_clip_put(void *context, const char *text, int64_t *stamp)
{
    struct jni_clip *clip = context;
    JNIEnv *env = clip->env;
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject data = sensitive_clip(env, text);
    jmethodID set = data ? zj_method(env, clip->manager, "setPrimaryClip", "(Landroid/content/ClipData;)V") : NULL;
    if (set) (*env)->CallVoidMethod(env, clip->manager, set, data);
    bool placed = set && zj_clean(env), ok = placed && stamp_of(env, clip->manager, stamp) == ZAPP_CLIP_HELD;
    if (placed && !ok) (void)jni_clip_clear(context);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
static enum zapp_clip_state jni_clip_current(void *context, int64_t *stamp)
{
    struct jni_clip *clip = context;
    JNIEnv *env = clip->env;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return ZAPP_CLIP_UNREADABLE; }
    enum zapp_clip_state state = stamp_of(env, clip->manager, stamp);
    (*env)->PopLocalFrame(env, NULL);
    if (state == ZAPP_CLIP_UNREADABLE && !clip->refusal_logged) {
        clip->refusal_logged = true;
        CLIP_LOG("the copied address cannot be read now (the app is in the background); trying again");
    }
    return state;
}
static bool jni_clip_clear(void *context)
{
    struct jni_clip *clip = context;
    jmethodID clear = zj_method(clip->env, clip->manager, "clearPrimaryClip", "()V");
    if (clear) (*clip->env)->CallVoidMethod(clip->env, clip->manager, clear);
    return clear && zj_clean(clip->env);
}
/* On the clock that keeps counting while the phone sleeps. */
static void sleep_seconds(time_t seconds)
{
    struct timespec left = {seconds, 0};
    while (clock_nanosleep(CLOCK_BOOTTIME, 0, &left, &left) == EINTR) {}
}
static void jni_clip_pause(void *context)
{
    (void)context;
    sleep_seconds(CLIP_RETRY_SECONDS);
}
static struct zapp_clip_ops clip_ops(struct jni_clip *clip)
{
    return (struct zapp_clip_ops){clip, jni_clip_put, jni_clip_current, jni_clip_clear, jni_clip_pause};
}

struct clip_expiry { JavaVM *vm; jobject manager; int64_t stamp; };
/* Waits out the delay, then clears the clip while it is still ours. From Android 10 a background app cannot read the
 * clipboard, so a refused read is retried every few seconds until the app has focus again. */
static void *clip_expiry_run(void *argument)
{
    struct clip_expiry *job = argument;
    JNIEnv *env = NULL;
    sleep_seconds(ZAPP_CLIP_CLEAR_SECONDS);
    if ((*job->vm)->AttachCurrentThread(job->vm, &env, NULL) != JNI_OK) { CLIP_LOG("clearing the copied address failed: no JNI thread"); free(job); return NULL; }
    struct jni_clip clip = {env, job->manager, false};
    struct zapp_clip_ops ops = clip_ops(&clip);
    if (!zapp_clip_settle(&ops, job->stamp, CLIP_RETRY_ATTEMPTS)) CLIP_LOG("the copied address could not be cleared and may still be on the clipboard");
    (*env)->DeleteGlobalRef(env, job->manager);
    (*job->vm)->DetachCurrentThread(job->vm);
    free(job);
    return NULL;
}
static bool schedule_expiry(ANativeActivity *activity, jobject manager, int64_t stamp)
{
    pthread_t thread;
    struct clip_expiry *job = malloc(sizeof(*job));
    if (!job) return false;
    *job = (struct clip_expiry){activity->vm, (*activity->env)->NewGlobalRef(activity->env, manager), stamp};
    bool ok = job->manager && pthread_create(&thread, NULL, clip_expiry_run, job) == 0;
    if (ok) { (void)pthread_detach(thread); return true; }
    if (job->manager) (*activity->env)->DeleteGlobalRef(activity->env, job->manager);
    free(job);
    return false;
}
bool zapp_clipboard_copy_sensitive(ANativeActivity *activity, const char *text)
{
    JNIEnv *env = activity->env;
    int64_t stamp = 0;
    bool ok = false;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); CLIP_LOG("copy failed: no local frame"); return false; }
    jstring service = zj_string(env, "clipboard");
    jmethodID get = service ? zj_method(env, activity->clazz, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;") : NULL;
    jobject manager = get ? (*env)->CallObjectMethod(env, activity->clazz, get, service) : NULL;
    struct jni_clip clip = {env, zj_clean(env) ? manager : NULL, false};
    struct zapp_clip_ops ops = clip_ops(&clip);
    if (!clip.manager) CLIP_LOG("copy failed: no clipboard service");
    else if (!zapp_clip_copy(&ops, text, &stamp)) CLIP_LOG("copy failed: setPrimaryClip refused the address");
    else if (!schedule_expiry(activity, clip.manager, stamp)) {
        CLIP_LOG("copy undone: the clear could not be scheduled");
        (void)zapp_clip_expire(&ops, stamp);
    } else ok = true;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
#endif
