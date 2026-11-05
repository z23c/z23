/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the sync_rate_below_floor condition — the OBSERVATIONAL
 * fold-throughput-vs-floor performance regression naming (perf-named-
 * conditions workflow). Covers: (a) a synthetic below-floor rate with peers
 * + pending work sustained for K consecutive windows raises the typed
 * blocker, (b) it clears once the rate recovers, (c) a healthy fold (rate
 * comfortably above floor) never false-fires across many windows, (d) a
 * window ibd_throttle's own injected sleep dominates is skipped rather than
 * counted as a slow window (measures real work, not deliberate throttle),
 * and (e) the "peers exist AND pending work" gate — no peers, or the
 * backlog already drained (network_tip <= log_head) — never trips and
 * honestly clears an already-active episode.
 *
 * condition_tick_one() gates a NOT-YET-active condition's detect() calls by
 * real wall-clock poll_secs (30s here), so this test installs the same fake
 * clock_iface_t the other condition tests use to advance wall time without
 * sleeping. The rate math itself is driven independently via the
 * *_test_set_now_us_override hook — platform_time_monotonic_us() is NOT
 * usable under the shared fake clock fixture (its now_monotonic_ns always
 * returns a fixed constant), so this condition's own monotonic sample must
 * be test-injected to get a meaningful elapsed_us between windows. */

#include "test/test_core.h"

#include "base/text_fit.h"
#include "conditions/sync_rate_below_floor.h"
#include "framework/condition.h"
#include "json/json.h"
#include "net/connman.h"
#include "net/download.h"
#include "net/protocol.h"
#include "platform/clock.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "util/blocker.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SRBF_CHECK(name, expr) do { \
    printf("sync_rate_below_floor: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct srbf_fake_clock {
    _Atomic int64_t wall_ms;
    _Atomic int64_t mono_ns;
};

static int64_t srbf_fake_now_mono(void *self)
{
    struct srbf_fake_clock *c = (struct srbf_fake_clock *)self;
    return atomic_load(&c->mono_ns);
}

static int64_t srbf_fake_now_wall(void *self)
{
    struct srbf_fake_clock *c = (struct srbf_fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

static void srbf_fake_clock_install(struct srbf_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    atomic_store(&c->mono_ns, 1);
    static clock_iface_t iface;
    iface.now_monotonic_ns = srbf_fake_now_mono;
    iface.now_wall_ms = srbf_fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void srbf_fake_clock_set(struct srbf_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
}

static void srbf_reset(struct connman *cm, struct download_manager *dm,
                       struct main_state *ms)
{
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    sync_rate_below_floor_test_reset();
    sticky_escalator_test_reset();
    memset(cm, 0, sizeof(*cm));
    memset(dm, 0, sizeof(*dm));
    memset(ms, 0, sizeof(*ms));
    main_state_init(ms);
    /* Keep the zeroed IBD tip age and no-checkpoint flag. */
    ms->nMaxTipAge = 0;
    ms->fCheckpointsEnabled = false;
    zcl_mutex_init(&cm->manager.cs_nodes);
    zcl_mutex_init(&dm->cs);
    sync_monitor_init();
    sync_monitor_set_context(cm, dm, ms);
    register_sync_rate_below_floor();
}

static void srbf_cleanup(void)
{
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    sync_rate_below_floor_test_reset();
    sticky_escalator_test_reset();
    sync_monitor_set_context(NULL, NULL, NULL);
    clock_reset_default();
}

/* One simulated sampling window: advances both the wall clock (so the
 * poll_secs gate — or the always-open active-episode path — lets detect()
 * run) and the condition's own injected monotonic clock/cursor/throttle
 * inputs, then ticks the engine once. */
static void srbf_tick(struct srbf_fake_clock *fc, int64_t wall_s,
                      int64_t mono_us, int64_t cursor, int64_t throttle_us)
{
    srbf_fake_clock_set(fc, wall_s);
    sync_rate_below_floor_test_set_now_us_override(mono_us);
    sync_rate_below_floor_test_set_cursor_override(cursor);
    sync_rate_below_floor_test_set_throttle_wait_us_override(throttle_us);
    condition_engine_tick();
}

static bool srbf_overflow_floor_uses_default(struct srbf_fake_clock *fc,
                                              int64_t wall_s,
                                              int64_t window_us)
{
    const char *old = getenv("ZCL_SYNC_RATE_FLOOR_BPS");
    const bool old_was_set = old != NULL;
    char *old_copy = old_was_set ? strdup(old) : NULL;
    if (old_was_set && !old_copy)
        return false;
    if (setenv("ZCL_SYNC_RATE_FLOOR_BPS", "9223372036854776", 1) != 0) {
        free(old_copy);
        return false;
    }

    struct connman cm;
    struct download_manager dm;
    struct main_state ms;
    srbf_reset(&cm, &dm, &ms);
    srbf_fake_clock_install(fc, wall_s);
    sync_rate_below_floor_test_set_log_head_override(0);

    struct p2p_node peer = {0};
    peer.id = 1;
    peer.starting_height = 10000;
    peer.state = PEER_ACTIVE;
    peer.services = NODE_NETWORK;
    struct p2p_node *peers[1] = { &peer };
    cm.manager.nodes = peers;
    cm.manager.num_nodes = 1;

    int64_t mono_us = 1000000000;
    int64_t cursor = 0;
    srbf_tick(fc, wall_s, mono_us, cursor, 0);
    for (int i = 0; i < 5; i++) {
        mono_us += window_us;
        cursor++;
        srbf_tick(fc, wall_s + 30 * (i + 1), mono_us, cursor, 0);
    }
    const bool tripped = sync_rate_below_floor_test_remedy_calls() == 1 &&
                         blocker_exists("sync_rate_below_floor");
    srbf_cleanup();
    main_state_free(&ms);

    const int restore_rc = old_was_set
                               ? setenv("ZCL_SYNC_RATE_FLOOR_BPS", old_copy, 1)
                               : unsetenv("ZCL_SYNC_RATE_FLOOR_BPS");
    free(old_copy);
    return tripped && restore_rc == 0;
}

static bool srbf_check_detected_rate_details(void)
{
        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        bool dumped = condition_engine_dump_state_json(&dump, NULL);
        bool okd = dumped;
        const struct json_value *conditions = json_get(&dump, "conditions");
        const struct json_value *found = NULL;
        for (size_t i = 0; conditions && i < json_size(conditions); i++) {
            const struct json_value *c = json_at(conditions, i);
            const struct json_value *nm = c ? json_get(c, "name") : NULL;
            if (nm && strcmp(json_get_str(nm), "sync_rate_below_floor") == 0) {
                found = c;
                break;
            }
        }
        const struct json_value *detail = found ? json_get(found, "detail") : NULL;
        okd = okd && detail != NULL;
        okd = okd &&
              json_get_int(json_get(detail, "observed_bps_x1000")) == 100;
        okd = okd &&
              json_get_int(json_get(detail, "floor_bps_x1000")) == 1000;
        okd = okd &&
              json_get_int(json_get(detail, "network_tip_at_detect")) == 10000;
        okd = okd && json_get_int(json_get(detail, "log_head_at_detect")) == 0;
        json_free(&dump);
    return okd;
}

#define fc (*fake_clock)
#define t0 (*start_wall)
#define WINDOW_US (*window_duration)
static int srbf_check_healthy_fold_windows(
    int failures, struct srbf_fake_clock *fake_clock,
    const int64_t *start_wall, const int64_t *window_duration)
{
    /* ---- (c) a healthy fold (comfortably above floor) never false-fires ---- */
    {
        struct connman cm; struct download_manager dm; struct main_state ms;
        srbf_reset(&cm, &dm, &ms);
        srbf_fake_clock_install(&fc, t0);
        sync_rate_below_floor_test_set_log_head_override(0);

        struct p2p_node peer = {0};
        peer.id = 1;
        peer.starting_height = 10000;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        int64_t mono = 1000000000;
        int64_t cur = 0;
        srbf_tick(&fc, t0, mono, cur, 0);
        bool ok = true;
        for (int i = 0; i < 10; i++) {
            mono += WINDOW_US;
            cur += 50; /* 50 blocks / 10s == 5 bps, 5x the default floor */
            srbf_tick(&fc, t0 + 30 * (i + 1), mono, cur, 0);
            ok = ok && condition_engine_get_active_count() == 0;
        }
        ok = ok && sync_rate_below_floor_test_remedy_calls() == 0;
        /* A healthy fold never nudges the ladder. */
        ok = ok && !sticky_escalator_test_armed();
        SRBF_CHECK("rate comfortably above floor never trips across many "
                  "windows", ok);
        srbf_cleanup();
        main_state_free(&ms);
    }
    return failures;
}

static int srbf_check_throttle_dominated_window(
    int failures, struct srbf_fake_clock *fake_clock,
    const int64_t *start_wall, const int64_t *window_duration)
{
    /* ---- (d) throttle-dominated window is skipped, not counted ---- */
    {
        struct connman cm; struct download_manager dm; struct main_state ms;
        srbf_reset(&cm, &dm, &ms);
        srbf_fake_clock_install(&fc, t0);
        sync_rate_below_floor_test_set_log_head_override(0);

        struct p2p_node peer = {0};
        peer.id = 1;
        peer.starting_height = 10000;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        int64_t mono = 1000000000;
        int64_t cur = 0;
        int64_t throttle = 0;
        srbf_tick(&fc, t0, mono, cur, throttle);

        /* Naive (elapsed_us-only) rate would read as slow (1 block / 10s ==
         * 0.1 bps, below floor), but 9.5s of that 10s window was
         * ibd_throttle's OWN deliberate sleep (a real, honest workload can
         * legitimately look this slow while heavily rate-limited) — the
         * effective post-subtraction window (0.5s) is below
         * SYNC_RATE_MIN_WINDOW_US, so this sample must be skipped entirely,
         * not counted toward the below-floor streak. */
        mono += WINDOW_US;
        cur += 1;
        throttle += 9500000;
        srbf_tick(&fc, t0 + 30, mono, cur, throttle);

        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        bool dumped = condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *conditions = json_get(&dump, "conditions");
        const struct json_value *found = NULL;
        for (size_t i = 0; conditions && i < json_size(conditions); i++) {
            const struct json_value *c = json_at(conditions, i);
            const struct json_value *nm = c ? json_get(c, "name") : NULL;
            if (nm && strcmp(json_get_str(nm), "sync_rate_below_floor") == 0) {
                found = c;
                break;
            }
        }
        const struct json_value *detail = found ? json_get(found, "detail") : NULL;
        bool ok = dumped && detail != NULL;
        ok = ok &&
             json_get_int(json_get(detail, "below_floor_streak")) == 0;
        json_free(&dump);
        ok = ok && condition_engine_get_active_count() == 0;
        SRBF_CHECK("a throttle-dominated window is skipped, not counted "
                  "below-floor", ok);
        srbf_cleanup();
        main_state_free(&ms);
    }
    return failures;
}
#undef WINDOW_US
#undef t0
#undef fc

/* ---- measured-gap cases: window arithmetic, streak, floor env, gate
 * resets, dominant blocker capture, detail/dump keys, real-clock path and
 * test_reset ---- */

/* Like `ok = ok && expr`, but names the first failing line. */
#define SRBF_AND(ok, expr) do { \
    if ((ok) && !(expr)) { \
        printf("[srbf line %d failed] ", __LINE__); \
        (ok) = false; \
    } \
} while (0)

#define SRBF_COND "sync_rate_below_floor"

/* cleared_count is cumulative across resets, so each case counts from here. */
static int srbf_cleared_base;

struct srbf_fx {
    struct connman cm;
    struct download_manager dm;
    struct main_state ms;
    struct p2p_node peer;
    struct p2p_node *peers[1];
    struct srbf_fake_clock fc;
    int64_t wall;
    int64_t mono;   /* microseconds */
    int64_t cursor;
};

static struct srbf_fx *srbf_fx_new(int64_t wall, int peer_height,
                                   int64_t log_head)
{
    struct srbf_fx *x = calloc(1, sizeof(*x));
    if (!x)
        return NULL;
    srbf_reset(&x->cm, &x->dm, &x->ms);
    srbf_fake_clock_install(&x->fc, wall);
    sync_rate_below_floor_test_set_log_head_override(log_head);
    x->peer.id = 1;
    x->peer.starting_height = peer_height;
    x->peer.state = PEER_ACTIVE;
    x->peer.services = NODE_NETWORK;
    x->peers[0] = &x->peer;
    x->cm.manager.nodes = x->peers;
    x->cm.manager.num_nodes = 1;
    x->wall = wall;
    x->mono = 1000000000;
    x->cursor = 1000;
    struct condition_runtime_snapshot s;
    srbf_cleared_base = condition_engine_get_registered_snapshot(SRBF_COND, &s)
                            ? s.cleared_count : -1;
    return x;
}

static void srbf_fx_free(struct srbf_fx *x)
{
    srbf_cleanup();
    main_state_free(&x->ms);
    free(x);
}

/* One engine tick 30s later; the injected clock moves dmono_us and the apply
 * cursor moves dcursor, with the throttle total pinned at `throttle`. */
static void srbf_step(struct srbf_fx *x, int64_t dmono_us, int64_t dcursor,
                      int64_t throttle)
{
    x->mono += dmono_us;
    x->cursor += dcursor;
    x->wall += 30;
    srbf_tick(&x->fc, x->wall, x->mono, x->cursor, throttle);
}

/* The same tick with no override at all: now, cursor, log_head and throttle
 * all come from the real readers, and the fake monotonic clock supplies
 * time. */
static void srbf_step_real(struct srbf_fx *x, int64_t dmono_us)
{
    x->mono += dmono_us;
    x->wall += 30;
    atomic_store(&x->fc.mono_ns, x->mono * 1000);
    srbf_fake_clock_set(&x->fc, x->wall);
    condition_engine_tick();
}

static int64_t srbf_geti(const struct json_value *o, const char *k)
{
    const struct json_value *v = o ? json_get(o, k) : NULL;
    return v ? json_get_int(v) : INT64_MIN;
}

static bool srbf_getb(const struct json_value *o, const char *k, bool want)
{
    const struct json_value *v = o ? json_get(o, k) : NULL;
    return v && json_get_bool(v) == want;
}

static bool srbf_gets(const struct json_value *o, const char *k,
                      const char *want)
{
    const struct json_value *v = o ? json_get(o, k) : NULL;
    const char *s = v ? json_get_str(v) : NULL;
    return s && strcmp(s, want) == 0;
}

/* Expected values for every key of the dump and detail JSON. */
struct srbf_expect {
    bool active;
    bool pending;
    int64_t cur_bps;
    int64_t cur_floor;
    int64_t streak;
    int64_t at_bps;
    int64_t at_floor;
    int64_t tip;
    int64_t head;
    int64_t last_fire;
    const char *id;
    const char *reason;
};

static bool srbf_dump_matches(const struct srbf_expect *e)
{
    struct json_value o;
    json_init(&o);
    bool ok = sync_rate_below_floor_dump_state_json(&o, "x");
    SRBF_AND(ok, srbf_getb(&o, "active", e->active));
    SRBF_AND(ok, srbf_getb(&o, "pending_work", e->pending));
    SRBF_AND(ok, srbf_geti(&o, "current_bps_x1000") == e->cur_bps);
    SRBF_AND(ok, srbf_geti(&o, "current_floor_bps_x1000") == e->cur_floor);
    SRBF_AND(ok, srbf_geti(&o, "below_floor_streak") == e->streak);
    SRBF_AND(ok, srbf_geti(&o, "consecutive_ticks_required") == 5);
    SRBF_AND(ok, srbf_geti(&o, "observed_bps_x1000_at_detect") == e->at_bps);
    SRBF_AND(ok, srbf_geti(&o, "floor_bps_x1000_at_detect") == e->at_floor);
    SRBF_AND(ok, srbf_geti(&o, "network_tip_at_detect") == e->tip);
    SRBF_AND(ok, srbf_geti(&o, "log_head_at_detect") == e->head);
    SRBF_AND(ok, srbf_gets(&o, "dominant_blocker_id_at_detect", e->id));
    SRBF_AND(ok, srbf_geti(&o, "last_fire_unix") == e->last_fire);
    json_free(&o);
    return ok;
}

static bool srbf_detail_matches(const struct srbf_expect *e)
{
    struct json_value dump;
    json_init(&dump);
    json_set_object(&dump);
    bool ok = condition_engine_dump_state_json(&dump, NULL);
    const struct json_value *conds = json_get(&dump, "conditions");
    const struct json_value *d = NULL;
    for (size_t i = 0; ok && conds && i < json_size(conds); i++) {
        const struct json_value *c = json_at(conds, i);
        const struct json_value *nm = c ? json_get(c, "name") : NULL;
        if (nm && strcmp(json_get_str(nm), SRBF_COND) == 0)
            d = json_get(c, "detail");
    }
    SRBF_AND(ok, d != NULL);
    SRBF_AND(ok, srbf_geti(d, "observed_bps_x1000") == e->at_bps);
    SRBF_AND(ok, srbf_geti(d, "floor_bps_x1000") == e->at_floor);
    SRBF_AND(ok, srbf_geti(d, "network_tip_at_detect") == e->tip);
    SRBF_AND(ok, srbf_geti(d, "log_head_at_detect") == e->head);
    SRBF_AND(ok, srbf_gets(d, "dominant_blocker_id", e->id));
    SRBF_AND(ok, srbf_gets(d, "dominant_blocker_reason", e->reason));
    SRBF_AND(ok, srbf_geti(d, "last_fire_unix") == e->last_fire);
    SRBF_AND(ok, srbf_geti(d, "current_bps_x1000") == e->cur_bps);
    SRBF_AND(ok, srbf_geti(d, "current_floor_bps_x1000") == e->cur_floor);
    SRBF_AND(ok, srbf_geti(d, "below_floor_streak") == e->streak);
    SRBF_AND(ok, srbf_getb(d, "pending_work", e->pending));
    json_free(&dump);
    return ok;
}

static int64_t srbf_cur_bps(void)
{
    struct json_value o;
    json_init(&o);
    int64_t v = sync_rate_below_floor_dump_state_json(&o, "x")
                    ? srbf_geti(&o, "current_bps_x1000") : INT64_MIN;
    json_free(&o);
    return v;
}

static int64_t srbf_streak(void)
{
    struct json_value o;
    json_init(&o);
    int64_t v = sync_rate_below_floor_dump_state_json(&o, "x")
                    ? srbf_geti(&o, "below_floor_streak") : INT64_MIN;
    json_free(&o);
    return v;
}

/* No episode ever began (a spurious detect() is cleared by witness() inside
 * the same tick, so only cleared_count shows it). */
static bool srbf_no_episode(void)
{
    struct condition_runtime_snapshot s;
    bool ok = condition_engine_get_registered_snapshot(SRBF_COND, &s);
    SRBF_AND(ok, s.cleared_count == srbf_cleared_base && !s.currently_active);
    SRBF_AND(ok, sync_rate_below_floor_test_remedy_calls() == 0);
    return ok && condition_engine_get_active_count() == 0;
}

/* Skipped windows, exact boundaries, duplicate clocks, rewinds and a
 * throttle that moved backwards, each read back through current_bps. */
static bool srbf_window_arithmetic(struct srbf_fx *x)
{
    srbf_step(x, 0, 0, 0);
    srbf_step(x, 1999999, 2000000, 0);
    bool ok = srbf_cur_bps() == -1;
    srbf_step(x, 2000000, 2000000, 0);
    SRBF_AND(ok, srbf_cur_bps() == 1000000000);
    SRBF_AND(ok, srbf_streak() == 0);
    srbf_step(x, 0, 100, 0);
    SRBF_AND(ok, srbf_cur_bps() == 1000000000);
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_cur_bps() == 10100);
    srbf_step(x, 1, 100, 0);
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_cur_bps() == 100);
    srbf_step(x, 10000000, -50, 0);
    SRBF_AND(ok, srbf_cur_bps() == 0);
    srbf_step(x, 10000000, 0, 1000000);
    SRBF_AND(ok, srbf_cur_bps() == 0);
    SRBF_AND(ok, srbf_streak() == 3);
    srbf_step(x, 2000000, 2, 0);
    SRBF_AND(ok, srbf_cur_bps() == 1000);
    SRBF_AND(ok, srbf_streak() == 0);
    return ok && srbf_no_episode();
}

/* 3 below, 1 above, 4 below stays quiet; the 5th below trips; 4 is not 5. */
static bool srbf_streak_needs_five(struct srbf_fx *x)
{
    srbf_step(x, 0, 0, 0);
    for (int i = 0; i < 3; i++)
        srbf_step(x, 10000000, 1, 0);
    srbf_step(x, 10000000, 1000, 0);
    for (int i = 0; i < 4; i++)
        srbf_step(x, 10000000, 1, 0);
    bool ok = condition_engine_get_active_count() == 0;
    SRBF_AND(ok, srbf_streak() == 4);
    SRBF_AND(ok, sync_rate_below_floor_test_remedy_calls() == 0);
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, condition_engine_get_active_count() == 1);
    return ok && sync_rate_below_floor_test_remedy_calls() == 1;
}

struct srbf_env_save {
    char *old;
    bool had;
    bool armed;
};

static bool srbf_env_put(const char *val, struct srbf_env_save *s)
{
    const char *o = getenv("ZCL_SYNC_RATE_FLOOR_BPS");
    s->old = o ? strdup(o) : NULL;
    if (o && !s->old)
        return false;
    s->had = o != NULL;
    s->armed = true;
    return setenv("ZCL_SYNC_RATE_FLOOR_BPS", val, 1) == 0;
}

static bool srbf_env_restore(struct srbf_env_save *s)
{
    if (!s->armed)
        return true;
    int rc = s->had ? setenv("ZCL_SYNC_RATE_FLOOR_BPS", s->old, 1)
                    : unsetenv("ZCL_SYNC_RATE_FLOOR_BPS");
    free(s->old);
    s->old = NULL;
    s->armed = false;
    return rc == 0;
}

static int64_t srbf_floor_for_env(const char *val, bool *ok)
{
    struct srbf_env_save s = {0};
    int64_t floor = INT64_MIN;
    if (srbf_env_put(val, &s)) {
        struct json_value o;
        json_init(&o);
        if (sync_rate_below_floor_dump_state_json(&o, "x"))
            floor = srbf_geti(&o, "current_floor_bps_x1000");
        json_free(&o);
    } else {
        *ok = false;
    }
    if (!srbf_env_restore(&s))
        *ok = false;
    return floor;
}

/* Only a clean positive decimal that fits is a floor; one digit ("5", "9"),
 * a hex-looking digit ("a"), zero, negative and trailing junk are covered. */
static bool srbf_floor_env_parsing(void)
{
    bool ok = true;
    SRBF_AND(ok, srbf_floor_for_env("5", &ok) == 5000);
    SRBF_AND(ok, srbf_floor_for_env("9", &ok) == 9000);
    SRBF_AND(ok, srbf_floor_for_env("a", &ok) == 1000);
    SRBF_AND(ok, srbf_floor_for_env("0", &ok) == 1000);
    SRBF_AND(ok, srbf_floor_for_env("-3", &ok) == 1000);
    SRBF_AND(ok, srbf_floor_for_env("12x", &ok) == 1000);
    SRBF_AND(ok, srbf_floor_for_env("", &ok) == 1000);
    SRBF_AND(ok, srbf_floor_for_env("9223372036854775", &ok) ==
                     9223372036854775000);
    return ok;
}

/* A queue-stuck blocker "Q" (one character) is captured as the dominant
 * blocker when the episode starts, and named in the blocker reason. */
static bool srbf_trip_with_blocker(struct srbf_fx *x)
{
    struct blocker_record r;
    bool ok = blocker_init(&r, "Q", "test_owner", BLOCKER_TRANSIENT,
                           "queue stuck here");
    if (ok)
        (void)blocker_set(&r);
    srbf_step(x, 0, 0, 0);
    for (int i = 0; i < 5; i++)
        srbf_step(x, 10000000, 1, 0);
    return ok;
}

static bool srbf_reason_matches_trip(void)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    bool found = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, SRBF_COND) != 0)
            continue;
        found = strstr(snaps[i].reason, "fold rate 0.100 bps below floor "
                                        "1.000 bps for >= 5") != NULL;
        found = found && strstr(snaps[i].reason, "blocker=Q") != NULL;
        found = found && strstr(snaps[i].reason, ZCL_TEXT_FIT_MARKER_TAG);
    }
    return found;
}

static bool srbf_episode_details(void)
{
    struct condition_runtime_snapshot s;
    bool ok = condition_engine_get_registered_snapshot(SRBF_COND, &s);
    SRBF_AND(ok, s.currently_active && s.cleared_count == srbf_cleared_base);
    SRBF_AND(ok, s.last_outcome == COND_REMEDY_UNWITNESSED);
    SRBF_AND(ok, sticky_escalator_test_armed());
    SRBF_AND(ok, srbf_reason_matches_trip());
    return ok;
}

static struct srbf_expect srbf_trip_expect(const struct srbf_fx *x)
{
    struct srbf_expect e = {
        .active = true, .pending = true, .cur_bps = 100, .cur_floor = 1000,
        .streak = 5, .at_bps = 100, .at_floor = 1000, .tip = 10000,
        .head = 5, .last_fire = x->wall, .id = "Q",
        .reason = "queue stuck here",
    };
    return e;
}

/* test_reset() after a dirty episode leaves nothing behind; the next run
 * uses only the real readers (no override at all) and still trips. */
static bool srbf_reset_then_real_path(struct srbf_fx *x)
{
    sync_rate_below_floor_test_set_cursor_override(50);
    sync_rate_below_floor_test_set_log_head_override(99999999999);
    sync_rate_below_floor_test_set_throttle_wait_us_override(7);
    sync_rate_below_floor_test_set_now_us_override(12345);
    sync_rate_below_floor_test_reset();
    struct srbf_expect e = {
        .cur_bps = -1, .cur_floor = 1000, .at_bps = -1, .at_floor = -1,
        .tip = -1, .head = -1, .id = "", .reason = "",
    };
    bool ok = srbf_dump_matches(&e);
    SRBF_AND(ok, srbf_detail_matches(&e));
    SRBF_AND(ok, !blocker_exists(SRBF_COND));
    SRBF_AND(ok, sync_rate_below_floor_test_remedy_calls() == 0);
    SRBF_AND(ok, condition_engine_get_active_count() == 0);
    for (int i = 0; i < 6; i++)
        srbf_step_real(x, 10000000);
    SRBF_AND(ok, sync_rate_below_floor_test_remedy_calls() == 1);
    return ok && condition_engine_get_active_count() == 1;
}

static bool srbf_blocker_episode_and_reset(int64_t t0)
{
    struct srbf_fx *x = srbf_fx_new(t0, 10000, 5);
    if (!x)
        return false;
    bool ok = srbf_trip_with_blocker(x);
    struct srbf_expect e = srbf_trip_expect(x);
    SRBF_AND(ok, srbf_episode_details());
    SRBF_AND(ok, srbf_dump_matches(&e));
    SRBF_AND(ok, srbf_detail_matches(&e));
    SRBF_AND(ok, srbf_reset_then_real_path(x));
    srbf_fx_free(x);
    return ok;
}

/* A second episode, with the blocker gone, must not keep the first one's
 * dominant blocker id or reason. */
static bool srbf_second_episode_forgets_blocker(int64_t t0)
{
    struct srbf_fx *x = srbf_fx_new(t0, 10000, 5);
    if (!x)
        return false;
    bool ok = srbf_trip_with_blocker(x);
    srbf_step(x, 10000000, 1000, 0);
    SRBF_AND(ok, condition_engine_get_active_count() == 0);
    blocker_clear("Q");
    for (int i = 0; i < 5; i++)
        srbf_step(x, 10000000, 1, 0);
    struct srbf_expect e = srbf_trip_expect(x);
    e.id = "";
    e.reason = "";
    SRBF_AND(ok, condition_engine_get_active_count() == 1);
    SRBF_AND(ok, srbf_dump_matches(&e));
    SRBF_AND(ok, srbf_detail_matches(&e));
    srbf_fx_free(x);
    return ok;
}

/* While an episode is active: an exactly-at-floor window clears it, and a
 * vanished peer set clears it and its blocker too. */
static bool srbf_witness_clears(int64_t t0)
{
    struct srbf_fx *x = srbf_fx_new(t0, 10000, 5);
    if (!x)
        return false;
    srbf_step(x, 0, 0, 0);
    for (int i = 0; i < 5; i++)
        srbf_step(x, 10000000, 1, 0);
    bool ok = condition_engine_get_active_count() == 1;
    srbf_step(x, 10000000, 10, 0);
    SRBF_AND(ok, srbf_cur_bps() == 1000);
    SRBF_AND(ok, condition_engine_get_active_count() == 0);
    SRBF_AND(ok, !blocker_exists(SRBF_COND));
    for (int i = 0; i < 5; i++)
        srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, condition_engine_get_active_count() == 1);
    x->cm.manager.num_nodes = 0;
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, condition_engine_get_active_count() == 0);
    SRBF_AND(ok, !blocker_exists(SRBF_COND));
    srbf_fx_free(x);
    return ok;
}

/* The peers+work gate resets the sampling state on every exit, and a restart
 * needs a fresh baseline before any window counts. */
static bool srbf_gate_resets_sampling(int64_t t0)
{
    struct srbf_fx *x = srbf_fx_new(t0, 10000, 5);
    if (!x)
        return false;
    srbf_step(x, 0, 0, 0);
    for (int i = 0; i < 3; i++)
        srbf_step(x, 10000000, 1, 0);
    bool ok = srbf_streak() == 3;
    x->cm.manager.num_nodes = 0;
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_streak() == 0);
    x->cm.manager.num_nodes = 1;
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_streak() == 0);
    srbf_step(x, 10000000, 1, 0);
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_streak() == 2);
    sync_rate_below_floor_test_set_log_head_override(10000);
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_streak() == 0);
    sync_rate_below_floor_test_set_log_head_override(5);
    srbf_step(x, 10000000, 1, 0);
    for (int i = 0; i < 4; i++)
        srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_no_episode());
    sync_monitor_set_context(NULL, NULL, NULL);
    srbf_step(x, 10000000, 1, 0);
    SRBF_AND(ok, srbf_streak() == 0);
    SRBF_AND(ok, srbf_no_episode());
    srbf_fx_free(x);
    return ok;
}

/* A peer at height 1 with log_head 0 is pending work. */
static bool srbf_height_one_is_work(int64_t t0)
{
    struct srbf_fx *x = srbf_fx_new(t0, 1, 0);
    if (!x)
        return false;
    srbf_step(x, 0, 0, 0);
    for (int i = 0; i < 5; i++)
        srbf_step(x, 10000000, 1, 0);
    bool ok = condition_engine_get_active_count() == 1;
    srbf_fx_free(x);
    return ok;
}

/* The real readers: a fake monotonic clock and no override trip it; a mixed
 * first sample (real cursor/throttle, then injected) is measured exactly;
 * an injected now of 0 is a real instant, not "unset". */
static bool srbf_real_readers(int64_t t0)
{
    /* Nothing injected: the fake monotonic clock and the real (zero) cursor
     * make every window a zero rate, and five of them trip it. */
    struct srbf_fx *x = srbf_fx_new(t0, 10000, -1);
    if (!x)
        return false;
    for (int i = 0; i < 6; i++)
        srbf_step_real(x, 10000000);
    bool ok = sync_rate_below_floor_test_remedy_calls() == 1;
    srbf_fx_free(x);

    /* Real first sample (cursor 0, throttle 0), injected second sample:
     * 5 blocks over the 10s window minus 5s of throttle is exactly 1 bps. */
    x = srbf_fx_new(t0, 10000, -1);
    if (!x)
        return false;
    srbf_step_real(x, 0);
    x->cursor = 0;
    srbf_step(x, 10000000, 5, 5000000);
    SRBF_AND(ok, srbf_cur_bps() == 1000);
    srbf_fx_free(x);

    /* An injected now of 0 is an instant, not "unset": the window below is
     * 10s long, not 5s (the fake monotonic clock reads 5s). */
    x = srbf_fx_new(t0, 10000, 0);
    if (!x)
        return false;
    atomic_store(&x->fc.mono_ns, 5000000000);
    x->mono = 0;
    x->cursor = 0;
    srbf_step(x, 0, 0, 0);
    srbf_step(x, 10000000, 5, 0);
    SRBF_AND(ok, srbf_cur_bps() == 500);
    srbf_fx_free(x);
    return ok;
}

static int srbf_check_measured_gaps(int64_t t0)
{
    int failures = 0;
    struct srbf_fx *x = srbf_fx_new(t0, 10000, 0);
    bool ok = x != NULL;
    if (x)
        ok = srbf_window_arithmetic(x);
    if (x)
        srbf_fx_free(x);
    SRBF_CHECK("window arithmetic: skips, exact boundaries, rewinds", ok);
    x = srbf_fx_new(t0, 10000, 0);
    ok = x != NULL && srbf_streak_needs_five(x);
    if (x)
        srbf_fx_free(x);
    SRBF_CHECK("five consecutive below-floor windows, not four", ok);
    SRBF_CHECK("floor env: clean positive decimals only",
               srbf_floor_env_parsing());
    SRBF_CHECK("dominant blocker, detail and dump keys, reset, real path",
               srbf_blocker_episode_and_reset(t0));
    SRBF_CHECK("a second episode forgets the first dominant blocker",
               srbf_second_episode_forgets_blocker(t0));
    SRBF_CHECK("witness clears at the floor and when peers vanish",
               srbf_witness_clears(t0));
    SRBF_CHECK("the gate resets sampling and a restart needs a baseline",
               srbf_gate_resets_sampling(t0));
    SRBF_CHECK("peer height 1 over log_head 0 is pending work",
               srbf_height_one_is_work(t0));
    SRBF_CHECK("real readers drive the rate when nothing is injected",
               srbf_real_readers(t0));
    return failures;
}

int test_sync_rate_below_floor(void);
int test_sync_rate_below_floor(void)
{
    printf("\n=== sync_rate_below_floor condition tests ===\n");
    int failures = 0;
    struct srbf_fake_clock fc;
    int64_t t0 = 4000000000;
    const int64_t WINDOW_US = 10 * 1000 * 1000; /* 10s per simulated window */

    SRBF_CHECK("overflowing floor configuration falls back to the default",
               srbf_overflow_floor_uses_default(&fc, t0, WINDOW_US));

    /* ---- (a) sustained below-floor rate with peers+work trips it ---- */
    {
        struct connman cm; struct download_manager dm; struct main_state ms;
        srbf_reset(&cm, &dm, &ms);
        srbf_fake_clock_install(&fc, t0);
        sync_rate_below_floor_test_set_log_head_override(0);

        struct p2p_node peer = {0};
        peer.id = 1;
        peer.starting_height = 10000;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        /* 1 block per 10s window == 0.1 bps, comfortably below the default
         * 1 bps floor. First tick only establishes the baseline sample. */
        int64_t mono = 1000000000;
        int64_t cur = 0;
        srbf_tick(&fc, t0, mono, cur, 0);
        bool ok = true;
        ok = ok && condition_engine_get_active_count() == 0;

        for (int i = 0; i < 5; i++) {
            mono += WINDOW_US;
            cur += 1;
            srbf_tick(&fc, t0 + 30 * (i + 1), mono, cur, 0);
        }
        ok = ok && sync_rate_below_floor_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && blocker_exists("sync_rate_below_floor");
        SRBF_CHECK("K consecutive below-floor windows (peers+work) trips it",
                  ok);

        /* ACT (Pillar 1): the remedy did not merely NAME the slowdown — it
         * invoked the always-terminating recovery ladder. Witness the ladder
         * arm, not just the blocker. */
        SRBF_CHECK("sustained growing-gap remedy ARMS the recovery ladder",
                  sticky_escalator_test_armed());

        bool okd = srbf_check_detected_rate_details();
        SRBF_CHECK("detail names observed_bps vs floor_bps + network state",
                  okd);

        /* ---- (b) recovery clears it: a fast window pushes bps over floor */
        mono += WINDOW_US;
        cur += 1000; /* 1000 blocks / 10s == 100 bps, well over the floor */
        srbf_tick(&fc, t0 + 200, mono, cur, 0);

        bool ok2 = true;
        ok2 = ok2 && !blocker_exists("sync_rate_below_floor");
        ok2 = ok2 && condition_engine_get_active_count() == 0;
        SRBF_CHECK("rate recovering above floor clears the blocker", ok2);

        srbf_cleanup();
        main_state_free(&ms);
    }

    failures = srbf_check_healthy_fold_windows(
        failures, &fc, &t0, &WINDOW_US);

    failures = srbf_check_throttle_dominated_window(
        failures, &fc, &t0, &WINDOW_US);

    /* ---- (e) the peers+work gate: no peers, or backlog drained ---- */
    {
        struct connman cm; struct download_manager dm; struct main_state ms;
        srbf_reset(&cm, &dm, &ms);
        srbf_fake_clock_install(&fc, t0);
        sync_rate_below_floor_test_set_log_head_override(0);
        /* No peers registered at all. */
        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;

        int64_t mono = 1000000000;
        int64_t cur = 0;
        bool ok = true;
        for (int i = 0; i < 6; i++) {
            mono += WINDOW_US;
            cur += 1;
            srbf_tick(&fc, t0 + 30 * (i + 1), mono, cur, 0);
            ok = ok && condition_engine_get_active_count() == 0;
        }
        SRBF_CHECK("no peers never trips regardless of cursor stall", ok);

        /* Now add a peer whose height is AT (not above) log_head — no
         * pending work, even though a peer is connected. Use a nonzero
         * height so this exercises the "network_tip <= log_head" equality
         * comparison distinctly from the "no usable peer height" shortcut. */
        sync_rate_below_floor_test_set_log_head_override(100);
        struct p2p_node peer = {0};
        peer.id = 1;
        peer.starting_height = 100; /* == log_head override above */
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        for (int i = 0; i < 6; i++) {
            mono += WINDOW_US;
            cur += 1;
            srbf_tick(&fc, t0 + 400 + 30 * (i + 1), mono, cur, 0);
            ok = ok && condition_engine_get_active_count() == 0;
        }
        SRBF_CHECK("network_tip <= log_head (no backlog) never trips", ok);
        srbf_cleanup();
        main_state_free(&ms);
    }

    failures += srbf_check_measured_gaps(t0 + 100000);

    printf("=== test_sync_rate_below_floor complete: %d failure(s) ===\n",
           failures);
    return failures;
}
