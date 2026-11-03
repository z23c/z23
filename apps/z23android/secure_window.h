/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SECURE_WINDOW_H
#define ZAPP_SECURE_WINDOW_H
#include <stdbool.h>
#include <stddef.h>
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
    /* An overlay window cannot be drawn over the app (Window.setHideOverlayWindows, needs the HIDE_OVERLAY_WINDOWS
     * permission). A tap filter cannot see an overlay that covers a code and takes no tap. */
    bool (*hide_overlays)(void *ctx, bool on);
    /* The recents thumbnail is not captured (Activity.setRecentsScreenshotEnabled). */
    bool (*recents)(void *ctx, bool on);
    /* Accessibility services that do not declare access to sensitive data cannot read the window. */
    bool (*accessibility)(void *ctx, bool on);
};
/* Applies every protection, or removes every one, and attempts each even when another fails. False means a
 * protection is not in force: the caller must not show wallet content. A member left NULL is a protection
 * the caller cannot give, so it is a refusal too; the Android constructor sets all five. */
bool zapp_secure_window_apply(const struct zapp_secure_ops *ops, bool on);

/* In plain words, what the first refused protection of the last zapp_secure_window_apply could not do, as the end of
 * "this phone would not let the app ...", or NULL when none was refused. UI thread only. */
const char *zapp_secure_window_refusal(void);

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

/* A copied address is marked sensitive, so the system hides it in its clipboard preview, and is taken off the
 * clipboard after this many seconds, if the clip is still the one the app put there. */
#define ZAPP_CLIP_CLEAR_SECONDS 60
/* What the app can learn of the clipboard. From Android 10 a clip can be read only while the app has focus, so a refused
 * read is its own answer and never means the clipboard is empty. */
enum zapp_clip_state { ZAPP_CLIP_EMPTY, ZAPP_CLIP_HELD, ZAPP_CLIP_UNREADABLE };
struct zapp_clip_ops {
    void *ctx;
    /* Puts text on the clipboard as a sensitive clip and reports the stamp that identifies that clip. */
    bool (*put)(void *ctx, const char *text, int64_t *stamp);
    /* What the clipboard holds now; stamp is set only for ZAPP_CLIP_HELD. */
    enum zapp_clip_state (*current)(void *ctx, int64_t *stamp);
    bool (*clear)(void *ctx);
    /* Waits before the next try of zapp_clip_settle. Optional. */
    void (*pause)(void *ctx);
};
/* False for empty text, a missing member or a clipboard that refused the clip. */
bool zapp_clip_copy(const struct zapp_clip_ops *ops, const char *text, int64_t *stamp);
/* Clears the clipboard only while its clip is the one with this stamp. True when the clipboard no longer holds that
 * clip: it was empty, something else replaced it, or it was cleared. False when that could not be settled: the clip
 * could not be read (the app is in the background) or the clear was refused. Never true without one of those. */
bool zapp_clip_expire(const struct zapp_clip_ops *ops, int64_t stamp);
/* zapp_clip_expire again, after ops->pause, up to attempts times, so a clear that was due in the background happens at
 * the next focus. False when every attempt failed. */
bool zapp_clip_settle(const struct zapp_clip_ops *ops, int64_t stamp, unsigned attempts);

/* A copied address must also leave the clipboard when the process dies during the wait. Each copy writes a mark, the
 * clip's stamp and the wall-clock time of the copy and never the address, to a 0600 file in the app's files directory.
 * When the window next has focus, a clip that still carries the marked stamp and is older than the clear interval is
 * cleared, and the mark is removed. */
#define ZAPP_CLIP_MARK_FILE "clip_stamp"
struct zapp_clip_mark { int64_t stamp, copied_ms; };
/* Writes the mark atomically with mode 0600. */
bool zapp_clip_mark_save(const char *path, const struct zapp_clip_mark *mark);
/* False when the file is absent or not a mark. */
bool zapp_clip_mark_load(const char *path, struct zapp_clip_mark *mark);
/* Removes the file when it holds this stamp or is not a mark; a newer copy's mark stays. */
void zapp_clip_mark_forget(const char *path, int64_t stamp);
enum zapp_clip_verdict {
    ZAPP_CLIP_LEAVE,      /* Nothing to do yet: unreadable, or the clip is still within the clear interval. */
    ZAPP_CLIP_DROP_MARK,  /* The clipboard no longer holds the marked clip. */
    ZAPP_CLIP_PURGE       /* The marked clip is still there past the interval (or the clock went back): clear it. */
};
/* held is meaningful only for ZAPP_CLIP_HELD. */
enum zapp_clip_verdict zapp_clip_leftover(enum zapp_clip_state state, int64_t held, const struct zapp_clip_mark *mark, int64_t now_ms);
/* Settles the mark at path once: clears our clip when it is overdue and removes the mark. True when no mark is left;
 * false when the clipboard cannot be read now, the clip is not yet due or the clear was refused. */
bool zapp_clip_recover(const struct zapp_clip_ops *ops, const char *path, int64_t now_ms);

#ifdef __ANDROID__
#include <android/input.h>
#include <android/native_activity.h>
/* Call from the UI thread on entering (on) and leaving (off) the wallet screens. Both protections are set
 * through JNI before the call returns and read back; false means one is not in force. */
bool zapp_secure_window(ANativeActivity *activity, bool on);
/* The five protections of the activity as typed operations, for a screen that applies them itself. */
void zapp_secure_window_ops(struct zapp_secure_ops *ops, ANativeActivity *activity);
/* True when the input event is a motion event the gate drops. Call on the UI thread. */
bool zapp_secure_window_drops(const AInputEvent *event);
/* Puts the text on the clipboard as a sensitive clip and clears it after ZAPP_CLIP_CLEAR_SECONDS while it is still
 * that clip. Call on the UI thread. False, with a contextual line in the log, when the clipboard refused or the
 * clearing could not be scheduled; the clipboard then does not keep the text. */
bool zapp_clipboard_copy_sensitive(ANativeActivity *activity, const char *text);
/* Runs zapp_clip_recover on the system clipboard. Call on the UI thread when the window gains focus, the first moment
 * the clipboard can be read. */
void zapp_clipboard_recover(ANativeActivity *activity);
/* What the clipboard holds, from the clip's description alone: reading it shows no system notice. stamp is set only for
 * ZAPP_CLIP_HELD and changes with every new clip. Call on the UI thread. */
enum zapp_clip_state zapp_clipboard_stamp(ANativeActivity *activity, int64_t *stamp);
/* The text of the clip's first item, never what a URI names. False, with out wiped, when there is no text, it does not fit
 * in cap or the app has no focus. The system may tell the owner that the app read the clipboard. Call on the UI thread. */
bool zapp_clipboard_text(ANativeActivity *activity, char *out, size_t cap);
#endif
#endif
