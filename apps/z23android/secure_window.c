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
/* Reads an int field of the window attributes ("flags" or "privateFlags"). */
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
bool zapp_secure_window(ANativeActivity *activity, bool on)
{
    struct zapp_secure_ops ops = {activity, jni_flag_secure, jni_filter_touches, jni_hide_overlays, jni_recents, jni_accessibility};
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
#endif
