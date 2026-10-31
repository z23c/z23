/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "secure_window.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct fake { bool secure, filtered, flag_ok, filter_ok; int calls; };
static bool f_flag(void *c, bool on) { struct fake *f = c; f->calls++; if (f->flag_ok) f->secure = on; return f->flag_ok; }
static bool f_filter(void *c, bool on) { struct fake *f = c; f->calls++; if (f->filter_ok) f->filtered = on; return f->filter_ok; }

/* A screen that arms on DOWN and acts on UP, like the shell. */
struct screen { bool armed; int taps; };
static void deliver(struct screen *s, struct zapp_touch_gate *g, int32_t action, int32_t flags)
{
    if (zapp_touch_gate_drops(g, action, flags)) return;
    if (action == ZAPP_MOTION_DOWN) s->armed = true;
    else if (action == ZAPP_MOTION_CANCEL) s->armed = false;
    else if (action == 1 && s->armed) { s->armed = false; s->taps++; }
}
static void obscured_taps_arm_nothing(void)
{
    struct zapp_touch_gate g = {.protect = true};
    struct screen s = {0};
    deliver(&s, &g, ZAPP_MOTION_DOWN, 1); deliver(&s, &g, 1, 1);
    assert(!s.armed && s.taps == 0);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 2); deliver(&s, &g, 1, 2);
    assert(!s.armed && s.taps == 0);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0); deliver(&s, &g, 1, 0);
    assert(s.taps == 1);
}
static void a_cut_gesture_never_completes(void)
{
    struct zapp_touch_gate g = {.protect = true};
    struct screen s = {0};
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0);
    deliver(&s, &g, 2, 1);
    deliver(&s, &g, 1, 0);
    assert(s.taps == 0);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0); deliver(&s, &g, 1, 0);
    assert(s.taps == 1);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0); deliver(&s, &g, 2, 2); deliver(&s, &g, ZAPP_MOTION_CANCEL, 2);
    assert(!s.armed);
}
static void a_clean_cancel_disarms_a_cut_gesture(void)
{
    struct zapp_touch_gate g = {.protect = true};
    struct screen s = {0};
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0);
    assert(s.armed);
    deliver(&s, &g, 2, 1);
    deliver(&s, &g, ZAPP_MOTION_CANCEL, 0);
    assert(!s.armed);
}
static void release_mid_gesture_drops_the_up(void)
{
    struct zapp_touch_gate g = {.protect = true};
    struct screen s = {0};
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0);
    zapp_touch_gate_release(&g);
    deliver(&s, &g, 1, 0);
    assert(s.taps == 0);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0); deliver(&s, &g, 1, 0);
    assert(s.taps == 1);
    s.armed = false;
    zapp_touch_gate_release(&g);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 1); deliver(&s, &g, 1, 1);
    assert(s.taps == 2);
}
static void cut_gestures_are_counted_once(void)
{
    struct zapp_touch_gate g = {.protect = true};
    struct screen s = {0};
    deliver(&s, &g, ZAPP_MOTION_DOWN, 1); deliver(&s, &g, 2, 1); deliver(&s, &g, 1, 2);
    assert(g.obscured_gestures == 1);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 2);
    assert(g.obscured_gestures == 2);
    deliver(&s, &g, 1, 2);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0); deliver(&s, &g, 1, 0);
    assert(g.obscured_gestures == 2 && s.taps == 1);
    deliver(&s, &g, ZAPP_MOTION_DOWN, 0); deliver(&s, &g, 2, 1); deliver(&s, &g, ZAPP_MOTION_CANCEL, 1);
    assert(g.obscured_gestures == 3);
}
static void unprotected_windows_pass_everything(void)
{
    struct zapp_touch_gate g = {0};
    struct screen s = {0};
    deliver(&s, &g, ZAPP_MOTION_DOWN, 1); deliver(&s, &g, 1, 1);
    assert(s.taps == 1);
}

/* The five protections of the Android window, over a fake that can refuse each one. */
enum { P_FLAG, P_FILTER, P_OVERLAYS, P_RECENTS, P_A11Y, P_COUNT };
struct window { bool on[P_COUNT], ok[P_COUNT]; };
static bool set(void *c, int which, bool on)
{
    struct window *w = c;
    if (w->ok[which]) w->on[which] = on;
    return w->ok[which];
}
static bool w_flag(void *c, bool on) { return set(c, P_FLAG, on); }
static bool w_filter(void *c, bool on) { return set(c, P_FILTER, on); }
static bool w_overlays(void *c, bool on) { return set(c, P_OVERLAYS, on); }
static bool w_recents(void *c, bool on) { return set(c, P_RECENTS, on); }
static bool w_a11y(void *c, bool on) { return set(c, P_A11Y, on); }
static void every_protection_is_needed(void)
{
    struct window w;
    struct zapp_secure_ops ops = {.ctx = &w, .flag_secure = w_flag, .filter_touches = w_filter, .hide_overlays = w_overlays,
                                  .recents = w_recents, .accessibility = w_a11y};
    for (int p = 0; p < P_COUNT; ++p) w.ok[p] = true;
    assert(zapp_secure_window_apply(&ops, true));
    for (int p = 0; p < P_COUNT; ++p) assert(w.on[p]);
    assert(zapp_secure_window_apply(&ops, false));
    for (int p = 0; p < P_COUNT; ++p) assert(!w.on[p]);
    for (int refused = 0; refused < P_COUNT; ++refused) {      /* one refusal is a refusal, and the others are still applied */
        memset(&w, 0, sizeof(w));
        for (int p = 0; p < P_COUNT; ++p) w.ok[p] = p != refused;
        assert(!zapp_secure_window_apply(&ops, true));
        for (int p = 0; p < P_COUNT; ++p) assert(w.on[p] == (p != refused));
        assert(!zapp_secure_window_apply(&ops, false));
        for (int p = 0; p < P_COUNT; ++p) assert(!w.on[p]);
    }
    zapp_secure_window_release();
}

int main(void)
{
    struct fake f = {.flag_ok = true, .filter_ok = true};
    struct zapp_secure_ops ops = {.ctx = &f, .flag_secure = f_flag, .filter_touches = f_filter};
    assert(zapp_secure_window_apply(&ops, true) && f.secure && f.filtered);
    assert(zapp_secure_window_apply(&ops, false) && !f.secure && !f.filtered);
    f.flag_ok = false;
    assert(!zapp_secure_window_apply(&ops, true) && f.filtered && f.calls == 6);
    f.flag_ok = true; f.filter_ok = false; f.secure = f.filtered = false;
    assert(!zapp_secure_window_apply(&ops, true) && f.secure && !f.filtered);
    assert(!zapp_secure_window_apply(&ops, false) && !f.secure);
    assert(!zapp_secure_window_drops_motion(ZAPP_MOTION_DOWN, 1));
    f.filter_ok = true; assert(zapp_secure_window_apply(&ops, true));
    assert(zapp_secure_window_drops_motion(ZAPP_MOTION_DOWN, 1) && !zapp_secure_window_drops_motion(ZAPP_MOTION_DOWN, 0));
    assert(zapp_secure_window_apply(&ops, false) && !zapp_secure_window_drops_motion(ZAPP_MOTION_DOWN, 1));
    assert(zapp_secure_window_obscured_gestures() == 1);
    obscured_taps_arm_nothing();
    a_cut_gesture_never_completes();
    a_clean_cancel_disarms_a_cut_gesture();
    release_mid_gesture_drops_the_up();
    cut_gestures_are_counted_once();
    unprotected_windows_pass_everything();
    every_protection_is_needed();
    puts("secure_window_test: ok");
    return 0;
}
