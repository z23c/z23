/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "secure_window.h"

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

bool zapp_secure_window_apply(const struct zapp_secure_ops *ops, bool on)
{
    if (on) gate.protect = true;
    bool flagged = ops->flag_secure(ops->ctx, on);
    bool filtered = ops->filter_touches(ops->ctx, on);
    if (!on) zapp_secure_window_release();
    return flagged && filtered;
}

#ifdef __ANDROID__
#include "jni_util.h"
#include <android/window.h>
#include <assert.h>

static bool ndk_flag_secure(void *context, bool on)
{
    ANativeActivity_setWindowFlags(context, on ? AWINDOW_FLAG_SECURE : 0, on ? 0 : AWINDOW_FLAG_SECURE);
    return true;
}
static bool jni_filter_touches(void *context, bool on)
{
    ANativeActivity *activity = context;
    JNIEnv *env = activity->env;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject window = zj_object_property(env, activity->clazz, "getWindow", "()Landroid/view/Window;");
    jobject decor = window ? zj_object_property(env, window, "getDecorView", "()Landroid/view/View;") : NULL;
    bool ok = decor && zj_bool_property(env, decor, "setFilterTouchesWhenObscured", on);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
bool zapp_secure_window(ANativeActivity *activity, bool on)
{
    struct zapp_secure_ops ops = {activity, ndk_flag_secure, jni_filter_touches};
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
