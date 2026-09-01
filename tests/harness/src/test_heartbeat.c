/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property tests for engine/modules/health/heartbeat — the unified watchdog
 * surface. The architectural invariant this protects: edge-triggered
 * stall firing. A subsystem that misses one deadline must get exactly
 * one on_stall call, not a flood of them every sweep cycle. A
 * subsequent fresh heartbeat must re-arm the edge so the next stall
 * fires again.
 */

#include "test/test_core.h"
#include "health/heartbeat.h"
#include "core/utiltime.h"

#include <stdatomic.h>
#include <string.h>
#include <time.h>

static _Atomic int g_stall_count;
static _Atomic int g_last_ctx_value;

static void stall_cb(void *ctx)
{
    atomic_fetch_add(&g_stall_count, 1);
    atomic_store(&g_last_ctx_value, (int)(intptr_t)ctx);
}

static void sleep_ms(int ms)
{
    struct timespec ts = {
        .tv_sec  = ms / 1000,
        .tv_nsec = (long)(ms % 1000) * 1000000L,
    };
    nanosleep(&ts, NULL);
}

/* Monotonic elapsed microseconds since an arbitrary fixed point. Used
 * by the periodic-tick test to bound observation against REAL elapsed
 * time rather than a single fixed sleep whose duration is at the mercy
 * of scheduler jitter (CLOCK_MONOTONIC is unaffected by wall-clock
 * adjustments). */
static int64_t monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // platform-ok:test-monotonic-jitter-realtime
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int test_heartbeat_register_and_snapshot(void)
{
    int failures = 0;
    TEST("heartbeat: register + snapshot reports the entry") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);

        health_subsystem_id id = health_register("test.foo", 10,
                                                  stall_cb, (void *)0xAA);
        ASSERT(id >= 0);

        struct health_snapshot snap[4];
        int n = health_snapshot_all(snap, 4);
        ASSERT(n == 1);
        ASSERT_STR_EQ(snap[0].name, "test.foo");
        ASSERT(snap[0].deadline_secs == 10);
        ASSERT(snap[0].on_stall_fired == 0);
        ASSERT(!snap[0].currently_stalled);

        health_unregister(id);
        n = health_snapshot_all(snap, 4);
        ASSERT(n == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_heartbeat_edge_triggered_stall(void)
{
    int failures = 0;
    TEST("heartbeat: stall fires exactly once per missed-deadline edge") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);
        atomic_store(&g_last_ctx_value, 0);

        health_set_check_interval_ms(20);
        ASSERT(health_start());

        /* Deadline = 1s; register, then wait > 1.1s without heartbeating.
         * The sweeper runs every 20ms, so it has ~50+ chances to call
         * the callback. Edge trigger must clamp to exactly one. */
        health_subsystem_id id = health_register("test.bar", 1,
                                                  stall_cb, (void *)0xBB);
        ASSERT(id >= 0);

        sleep_ms(1300);

        int n = atomic_load(&g_stall_count);
        if (n != 1) {
            printf("FAIL (expected 1 stall fire, got %d)\n", n);
            failures++; goto _cleanup;
        }
        ASSERT(atomic_load(&g_last_ctx_value) == 0xBB);

        /* A fresh heartbeat re-arms the edge. Subsequent stall should
         * fire one more time. */
        health_heartbeat(id);
        sleep_ms(1300);

        n = atomic_load(&g_stall_count);
        if (n != 2) {
            printf("FAIL (expected 2 stall fires after re-arm, got %d)\n", n);
            failures++; goto _cleanup;
        }

        PASS();
_cleanup:
        health_unregister(id);
        health_stop();
    } _test_next:;
    return failures;
}

static int test_heartbeat_resets_freshness(void)
{
    int failures = 0;
    TEST("heartbeat: keeping the beat fresh prevents stall firing") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);
        health_set_check_interval_ms(20);
        ASSERT(health_start());

        health_subsystem_id id = health_register("test.baz", 1,
                                                  stall_cb, NULL);
        ASSERT(id >= 0);

        /* Beat every 100ms for 1.5s. Deadline is 1s, so freshness is
         * always within budget; stall must not fire. */
        for (int i = 0; i < 15; i++) {
            health_heartbeat(id);
            sleep_ms(100);
        }
        int n = atomic_load(&g_stall_count);
        if (n != 0) {
            printf("FAIL (kept beating but stall fired %d times)\n", n);
            failures++; goto _cleanup;
        }
        PASS();
_cleanup:
        health_unregister(id);
        health_stop();
    } _test_next:;
    return failures;
}

static int test_heartbeat_registry_full(void)
{
    int failures = 0;
    TEST("heartbeat: registry-full returns HEALTH_INVALID_ID") {
        health_reset_for_test();
        health_subsystem_id ids[HEALTH_REGISTRY_CAP];
        char name[32];
        for (int i = 0; i < HEALTH_REGISTRY_CAP; i++) {
            snprintf(name, sizeof(name), "test.fill.%d", i);
            ids[i] = health_register(name, 10, stall_cb, NULL);
            ASSERT(ids[i] >= 0);
        }
        health_subsystem_id overflow = health_register("test.overflow", 10,
                                                        stall_cb, NULL);
        ASSERT(overflow == HEALTH_INVALID_ID);

        for (int i = 0; i < HEALTH_REGISTRY_CAP; i++)
            health_unregister(ids[i]);
        PASS();
    } _test_next:;
    return failures;
}

static int test_heartbeat_invalid_inputs(void)
{
    int failures = 0;
    TEST("heartbeat: invalid inputs return HEALTH_INVALID_ID without crashing") {
        health_reset_for_test();
        ASSERT(health_register(NULL, 10, stall_cb, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register("test.null", 10, NULL, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register("test.bad", 0,  stall_cb, NULL) == HEALTH_INVALID_ID);
        ASSERT(health_register("test.bad", -1, stall_cb, NULL) == HEALTH_INVALID_ID);

        /* Heartbeats on invalid ids are silent no-ops. */
        health_heartbeat(-1);
        health_heartbeat(HEALTH_REGISTRY_CAP);
        health_heartbeat(HEALTH_REGISTRY_CAP + 1000);
        health_unregister(-1);
        health_unregister(HEALTH_REGISTRY_CAP);
        PASS();
    } _test_next:;
    return failures;
}

static int test_heartbeat_periodic_tick(void)
{
    int failures = 0;
    TEST("heartbeat: periodic tick fires repeatedly on cadence (NOT edge-triggered)") {
        health_reset_for_test();
        atomic_store(&g_stall_count, 0);
        health_set_check_interval_ms(20);
        ASSERT(health_start());

        /* period = 1s. Over 3.3s we expect ~3 fires. The test gives a
         * generous tolerance (2..5) because sweeper jitter is real.
         *
         * Rather than trust a single fixed sleep_ms(3300) (whose actual
         * duration drifts under scheduler load — wall-clock-sensitive),
         * poll a monotonic clock in ~100ms steps and capture the live
         * callback count at each checkpoint until REAL elapsed time has
         * crossed 3300ms. The fire count we judge is the one observed at
         * the confirmed 3300ms boundary, so the 2..5 band is measured
         * against genuine elapsed time, not a possibly-short/long sleep.
         * Detection power is intact: a missed-fire bug still yields <2,
         * a duplicate/runaway-fire bug still yields >5, deterministically. */
        health_subsystem_id id = health_register_periodic("test.tick", 1,
                                                           stall_cb, NULL);
        ASSERT(id >= 0);

        const int64_t start_us  = monotonic_us();
        const int64_t window_us = 3300 * 1000;  /* observe over 3.3s real time */
        int n = atomic_load(&g_stall_count);
        for (;;) {
            int64_t elapsed_us = monotonic_us() - start_us;
            /* Record the count observed at this checkpoint. The final
             * recorded value is the one at/after the 3300ms boundary. */
            n = atomic_load(&g_stall_count);
            if (elapsed_us >= window_us)
                break;
            sleep_ms(100);
        }

        if (n < 2 || n > 5) {
            printf("FAIL (expected 2..5 periodic fires, got %d)\n", n);
            failures++; goto _cleanup;
        }

        /* Snapshot should mark it periodic. */
        struct health_snapshot snap[4];
        int got = health_snapshot_all(snap, 4);
        if (got != 1 || !snap[0].periodic || snap[0].currently_stalled) {
            printf("FAIL (snapshot wrong: got=%d periodic=%d stalled=%d)\n",
                   got, snap[0].periodic, snap[0].currently_stalled);
            failures++; goto _cleanup;
        }

        /* Heartbeat is a no-op for periodic entries — the fire count
         * should keep climbing on cadence regardless. */
        for (int i = 0; i < 5; i++) health_heartbeat(id);
        PASS();
_cleanup:
        health_unregister(id);
        health_stop();
    } _test_next:;
    return failures;
}

int test_heartbeat(void)
{
    int failures = 0;
    failures += test_heartbeat_register_and_snapshot();
    failures += test_heartbeat_invalid_inputs();
    failures += test_heartbeat_registry_full();
    failures += test_heartbeat_resets_freshness();
    failures += test_heartbeat_edge_triggered_stall();
    failures += test_heartbeat_periodic_tick();
    return failures;
}
