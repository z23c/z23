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
#include <stdio.h>
#include <string.h>

#define SRBF_CHECK(name, expr) do { \
    printf("sync_rate_below_floor: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct srbf_fake_clock {
    _Atomic int64_t wall_ms;
};

static int64_t srbf_fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t srbf_fake_now_wall(void *self)
{
    struct srbf_fake_clock *c = (struct srbf_fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

static void srbf_fake_clock_install(struct srbf_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
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
    zcl_mutex_init(&cm->manager.cs_nodes);
    zcl_mutex_init(&dm->cs);
    zcl_mutex_init(&ms->cs_main);
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

int test_sync_rate_below_floor(void);
int test_sync_rate_below_floor(void)
{
    printf("\n=== sync_rate_below_floor condition tests ===\n");
    int failures = 0;
    struct srbf_fake_clock fc;
    int64_t t0 = 4000000000;
    const int64_t WINDOW_US = 10 * 1000 * 1000; /* 10s per simulated window */

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
    }

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
    }

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
    }

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
    }

    printf("=== test_sync_rate_below_floor complete: %d failure(s) ===\n",
           failures);
    return failures;
}
