/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "secure_window.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

struct fake { bool secure, filtered, flag_ok, filter_ok; int calls; };
static bool f_flag(void *c, bool on) { struct fake *f = c; f->calls++; if (f->flag_ok) f->secure = on; return f->flag_ok; }
static bool f_extra(void *c, bool on) { (void)c; (void)on; return true; }
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
/* A protection the caller cannot give is a refusal, and the refusal says in words which one. */
static void a_missing_protection_is_a_refusal(void)
{
    struct window w;
    struct zapp_secure_ops full = {.ctx = &w, .flag_secure = w_flag, .filter_touches = w_filter, .hide_overlays = w_overlays,
                                   .recents = w_recents, .accessibility = w_a11y};
    static const char *const words[P_COUNT] = {
        "hide the screen from screenshots and recordings", "ignore touches that pass through another window",
        "stop other apps from drawing over the screen", "hide the screen in the list of recent apps",
        "keep out screen readers that are not allowed sensitive data"};
    for (int p = 0; p < P_COUNT; ++p) w.ok[p] = true;
    assert(zapp_secure_window_apply(&full, true) && !zapp_secure_window_refusal());
    for (int missing = 0; missing < P_COUNT; ++missing) {
        struct zapp_secure_ops ops = full;
        bool (**member[P_COUNT])(void *, bool) = {&ops.flag_secure, &ops.filter_touches, &ops.hide_overlays, &ops.recents, &ops.accessibility};
        *member[missing] = NULL;
        memset(&w.on, 0, sizeof(w.on));
        assert(!zapp_secure_window_apply(&ops, true));
        assert(zapp_secure_window_refusal() && !strcmp(zapp_secure_window_refusal(), words[missing]));
        for (int p = 0; p < P_COUNT; ++p) assert(w.on[p] == (p != missing));
    }
    for (int refused = 0; refused < P_COUNT; ++refused) {       /* a refusal by the platform is named the same way */
        for (int p = 0; p < P_COUNT; ++p) w.ok[p] = p != refused;
        assert(!zapp_secure_window_apply(&full, false) && !strcmp(zapp_secure_window_refusal(), words[refused]));
    }
    for (int p = 0; p < P_COUNT; ++p) w.ok[p] = p != 3 && p != 4;   /* several refusals: the first is named */
    assert(!zapp_secure_window_apply(&full, false) && !strcmp(zapp_secure_window_refusal(), words[3]));
    for (int p = 0; p < P_COUNT; ++p) w.ok[p] = true;
    assert(zapp_secure_window_apply(&full, false) && !zapp_secure_window_refusal());
    zapp_secure_window_release();
}

/* A fake clipboard holding one clip: its text and the stamp the system gave it. While unreadable it answers like an
 * app in the background: it cannot be read. */
struct board { char text[64]; int64_t stamp, next_stamp; bool has, put_ok, clear_ok, unreadable; int clears, reads, pauses, readable_after; };
static bool b_put(void *c, const char *text, int64_t *stamp)
{
    struct board *b = c;
    if (!b->put_ok) return false;
    snprintf(b->text, sizeof(b->text), "%s", text);
    *stamp = b->stamp = b->next_stamp++;
    b->has = true;
    return true;
}
static enum zapp_clip_state b_current(void *c, int64_t *stamp)
{
    struct board *b = c;
    b->reads++;
    if (b->unreadable) return ZAPP_CLIP_UNREADABLE;
    if (!b->has) return ZAPP_CLIP_EMPTY;
    *stamp = b->stamp;
    return ZAPP_CLIP_HELD;
}
static bool b_clear(void *c)
{
    struct board *b = c;
    b->clears++;
    if (b->clear_ok) { b->has = false; b->text[0] = '\0'; }
    return b->clear_ok;
}
static void b_pause(void *c)
{
    struct board *b = c;
    if (++b->pauses == b->readable_after) b->unreadable = false;    /* the app came back to the front */
}
static struct board fresh_board(void) { return (struct board){.put_ok = true, .clear_ok = true, .next_stamp = 100}; }
static void an_empty_copy_is_refused(void)
{
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp = 0;
    assert(!zapp_clip_copy(&ops, "", &stamp) && !zapp_clip_copy(&ops, NULL, &stamp) && !b.has);
    assert(!zapp_clip_copy(NULL, "zs1abc", &stamp));
    b.put_ok = false;
    assert(!zapp_clip_copy(&ops, "zs1abc", &stamp) && !b.has);
}
static void the_clipboard_clears_only_our_clip(void)
{
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp = 0, other = 0;
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp) && b.has && !strcmp(b.text, "zs1abc") && stamp == 100);
    assert(zapp_clip_expire(&ops, stamp) && !b.has && b.clears == 1);        /* untouched for a minute: cleared */
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp));
    assert(zapp_clip_copy(&ops, "something else", &other) && other != stamp);  /* replaced by another copy */
    assert(zapp_clip_expire(&ops, stamp) && b.has && !strcmp(b.text, "something else") && b.clears == 1);
    assert(zapp_clip_expire(&ops, other) && !b.has && b.clears == 2);
    assert(zapp_clip_expire(&ops, other) && b.clears == 2);                  /* nothing left to clear */
}
static void a_refused_clear_is_reported(void)
{
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp = 0;
    b.clear_ok = false;
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp) && !zapp_clip_expire(&ops, stamp) && b.has);
    assert(!zapp_clip_expire(NULL, stamp));
}
/* In the background the clipboard cannot be read: that is not "gone", so expire reports false and clears nothing. */
static void an_unreadable_clipboard_is_never_reported_cleared(void)
{
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp = 0;
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp));
    b.unreadable = true;
    assert(!zapp_clip_expire(&ops, stamp) && b.clears == 0 && b.has);
    b.unreadable = false;
    assert(zapp_clip_expire(&ops, stamp) && b.clears == 1 && !b.has);        /* back in the front: cleared */
}
static void the_clear_retries_until_the_app_has_focus(void)
{
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp = 0;
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp));
    b.unreadable = true;
    b.readable_after = 3;                                                    /* readable again after the third wait */
    assert(zapp_clip_settle(&ops, stamp, 10) && b.reads == 4 && b.pauses == 3 && b.clears == 1 && !b.has);
    b = fresh_board();                                                       /* never in front: gives up, clears nothing */
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp));
    b.unreadable = true;
    assert(!zapp_clip_settle(&ops, stamp, 5) && b.reads == 5 && b.pauses == 4 && b.clears == 0 && b.has);
    b = fresh_board();                                                       /* a clip someone else put there is left alone */
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp));
    b.unreadable = true;
    b.readable_after = 1;
    int64_t other = 0;
    assert(b_put(&b, "someone else", &other));
    assert(zapp_clip_settle(&ops, stamp, 5) && b.clears == 0 && b.has && !strcmp(b.text, "someone else"));
}

/* The copy mark: what survives a dead process, and when a later start clears the clipboard. */
#define MINUTE_MS 60000
static void mark_files_hold_only_the_stamp(const char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, ZAPP_CLIP_MARK_FILE);
    struct zapp_clip_mark mark = {100, 5000}, back;
    assert(!zapp_clip_mark_load(path, &back));
    assert(zapp_clip_mark_save(path, &mark));
    struct stat st;
    assert(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    assert(zapp_clip_mark_load(path, &back) && back.stamp == 100 && back.copied_ms == 5000);
    FILE *f = fopen(path, "r");
    char text[64] = {0};
    assert(f && fgets(text, sizeof(text), f) && !fgets(text, sizeof(text), f));
    (void)fclose(f);
    zapp_clip_mark_forget(path, 101);                       /* another copy's stamp: the mark stays */
    assert(zapp_clip_mark_load(path, &back));
    zapp_clip_mark_forget(path, 100);
    assert(!zapp_clip_mark_load(path, &back) && access(path, F_OK) != 0);
    f = fopen(path, "w");                                   /* a file that is not a mark */
    assert(f && fputs("garbage\n", f) >= 0);
    (void)fclose(f);
    assert(!zapp_clip_mark_load(path, &back));
    zapp_clip_mark_forget(path, 100);
    assert(access(path, F_OK) != 0);
}
static void leftover_decision(void)
{
    struct zapp_clip_mark mark = {100, 1000};
    assert(zapp_clip_leftover(ZAPP_CLIP_UNREADABLE, 0, &mark, 1000 + 10 * MINUTE_MS) == ZAPP_CLIP_LEAVE);
    assert(zapp_clip_leftover(ZAPP_CLIP_EMPTY, 0, &mark, 1000 + 10 * MINUTE_MS) == ZAPP_CLIP_DROP_MARK);
    assert(zapp_clip_leftover(ZAPP_CLIP_HELD, 101, &mark, 1000 + 10 * MINUTE_MS) == ZAPP_CLIP_DROP_MARK);   /* not ours */
    assert(zapp_clip_leftover(ZAPP_CLIP_HELD, 100, &mark, 1000 + MINUTE_MS - 1) == ZAPP_CLIP_LEAVE);        /* too young */
    assert(zapp_clip_leftover(ZAPP_CLIP_HELD, 100, &mark, 1000 + MINUTE_MS) == ZAPP_CLIP_PURGE);
    assert(zapp_clip_leftover(ZAPP_CLIP_HELD, 100, &mark, 999) == ZAPP_CLIP_PURGE);                         /* clock went back */
}
static void recover_clears_an_overdue_clip_and_removes_the_mark(const char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, ZAPP_CLIP_MARK_FILE);
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp;
    struct zapp_clip_mark mark;
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp));
    mark = (struct zapp_clip_mark){stamp, 1000};
    assert(zapp_clip_mark_save(path, &mark));
    assert(!zapp_clip_recover(&ops, path, 1000 + MINUTE_MS - 1) && b.has && b.clears == 0 && zapp_clip_mark_load(path, &mark));
    b.unreadable = true;                                    /* no focus: nothing is read, the mark stays */
    assert(!zapp_clip_recover(&ops, path, 1000 + 5 * MINUTE_MS) && b.has && b.clears == 0 && zapp_clip_mark_load(path, &mark));
    b.unreadable = false;
    b.clear_ok = false;                                     /* a refused clear keeps the mark for the next focus */
    assert(!zapp_clip_recover(&ops, path, 1000 + 5 * MINUTE_MS) && b.has && b.clears == 1 && zapp_clip_mark_load(path, &mark));
    b.clear_ok = true;
    assert(zapp_clip_recover(&ops, path, 1000 + 5 * MINUTE_MS) && !b.has && b.clears == 2 && !zapp_clip_mark_load(path, &mark));
}
static void recover_leaves_someone_elses_clip(const char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, ZAPP_CLIP_MARK_FILE);
    struct board b = fresh_board();
    struct zapp_clip_ops ops = {&b, b_put, b_current, b_clear, b_pause};
    int64_t stamp;
    /* Someone else's clip is never cleared; the mark is dropped. */
    assert(zapp_clip_copy(&ops, "zs1abc", &stamp) && zapp_clip_mark_save(path, &(struct zapp_clip_mark){stamp, 1000}));
    assert(zapp_clip_copy(&ops, "something else", &stamp));
    assert(zapp_clip_recover(&ops, path, 1000 + 5 * MINUTE_MS) && b.has && !strcmp(b.text, "something else") && b.clears == 0);
    assert(access(path, F_OK) != 0);
    assert(zapp_clip_recover(&ops, path, 1000 + 5 * MINUTE_MS) && b.clears == 0);   /* no mark: nothing to do */
    assert(!zapp_clip_recover(NULL, path, 0));
}

int main(int argc, char **argv)
{
    struct fake f = {.flag_ok = true, .filter_ok = true};
    struct zapp_secure_ops ops = {.ctx = &f, .flag_secure = f_flag, .filter_touches = f_filter,
                                  .hide_overlays = f_extra, .recents = f_extra, .accessibility = f_extra};
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
    a_missing_protection_is_a_refusal();
    an_empty_copy_is_refused();
    the_clipboard_clears_only_our_clip();
    a_refused_clear_is_reported();
    an_unreadable_clipboard_is_never_reported_cleared();
    the_clear_retries_until_the_app_has_focus();
    assert(argc == 2);
    const char *dir = argv[1];
    mark_files_hold_only_the_stamp(dir);
    leftover_decision();
    recover_clears_an_overdue_clip_and_removes_the_mark(dir);
    recover_leaves_someone_elses_clip(dir);
    puts("secure_window_test: ok");
    return 0;
}
