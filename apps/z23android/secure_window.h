/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SECURE_WINDOW_H
#define ZAPP_SECURE_WINDOW_H
#include <stdbool.h>
#include <stdint.h>

/* Screen protection for wallet screens: FLAG_SECURE blocks screenshots, screen recording and the
 * recents thumbnail. Touches that arrive through an overlay are dropped in the native input path:
 * the activity input queue hands events to native code before any view, and an event native code
 * finishes as handled never reaches a view. Events it leaves unhandled still do, so the filter must
 * drop them here and cannot rely on a view. */
struct zapp_secure_ops {
    void *ctx;
    bool (*flag_secure)(void *ctx, bool on);
    bool (*filter_touches)(void *ctx, bool on);
};
/* Applies both protections, or removes both, and attempts each even when the other fails. False
 * means a protection is not in force: the caller must not show wallet content. */
bool zapp_secure_window_apply(const struct zapp_secure_ops *ops, bool on);

/* AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED (0x1) and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED (0x2,
 * API 29; the NDK header has no name for it, but the raw flags carry it). */
#define ZAPP_MOTION_OBSCURED 0x3
/* AMOTION_EVENT_ACTION_MASK, _DOWN and _CANCEL. */
#define ZAPP_MOTION_ACTION_MASK 0xff
#define ZAPP_MOTION_DOWN 0
#define ZAPP_MOTION_CANCEL 3
/* Gesture state for the drop rule. */
struct zapp_touch_gate {
    bool protect;                 /* Wallet screens are showing. */
    bool poisoned;                /* The rest of the current gesture is dropped. */
    unsigned obscured_gestures;   /* Gestures cut by an obscured event; a screen reads it to explain why. */
};
/* True when the motion event must not reach any screen. While protect is set, an obscured event is
 * dropped and so is the rest of its gesture, up to the next unobscured DOWN, so a gesture cut by an
 * overlay can never complete as a tap. Cancel events always pass so screens can disarm. */
bool zapp_touch_gate_drops(struct zapp_touch_gate *gate, int32_t action, int32_t flags);
/* Ends protection on a gate. A gesture in progress stays dropped up to its end, so its UP cannot act
 * on whatever screen comes next. */
void zapp_touch_gate_release(struct zapp_touch_gate *gate);
/* The same rule on the window gate that zapp_secure_window_apply sets and clears. */
bool zapp_secure_window_drops_motion(int32_t action, int32_t flags);
/* Number of gestures dropped so far because another window was drawing over this one. Any app's
 * overlay sets the partial flag, so a wallet screen compares this with the value it last saw and
 * tells the owner why a tap did nothing. UI thread only. */
unsigned zapp_secure_window_obscured_gestures(void);
/* The window is gone or no longer protected: stop dropping. Called on every activity teardown. */
void zapp_secure_window_release(void);

#ifdef __ANDROID__
#include <android/input.h>
#include <android/native_activity.h>
/* Call from the UI thread on entering (on) and leaving (off) the wallet screens. The window flag
 * takes effect when the UI thread next runs its looper. */
bool zapp_secure_window(ANativeActivity *activity, bool on);
/* True when the input event is a motion event the gate drops. Call on the UI thread. */
bool zapp_secure_window_drops(const AInputEvent *event);
#endif
#endif
