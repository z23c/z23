/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_self_heal_supervisor -- self_heal_register() must fail LOUD, not
 * with a bare LOG_WARN, when supervisor_register_in_domain() fails. That
 * registration is the only cadence the condition engine, blocker escape
 * sweep, and remedy ladder ride on; losing it silently loses the whole
 * spine. Drives the real failure path by filling the supervisor registry
 * to capacity first (mirrors test_supervisor.c's "registry capacity"
 * case), then asserts a PERMANENT "self_heal.unsupervised" blocker +
 * EV_OPERATOR_NEEDED fired. A sibling case proves the healthy path stays
 * silent (no blocker, no page). */

#include "test/test_core.h"

#include "event/event.h"
#include "framework/condition.h"
#include "platform/time_compat.h"
#include "supervisors/self_heal.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define SHS_CHECK(name, expr) do {                               \
    printf("self_heal_supervisor: %s... ", (name));              \
    if ((expr)) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                       \
} while (0)

static _Atomic int g_shs_operator_events;

static void shs_operator_observer(enum event_type type, uint32_t peer_id,
                                  const void *payload, uint32_t payload_len,
                                  void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_shs_operator_events, 1);
}

static void shs_fill_registry(struct liveness_contract pool[SUPERVISOR_CAP])
{
    for (int i = 0; i < SUPERVISOR_CAP; i++) {
        char nm[SUPERVISOR_NAME_MAX];
        snprintf(nm, sizeof(nm), "shs.filler.%d", i);
        liveness_contract_init(&pool[i], nm);
        (void)supervisor_register(&pool[i]);
    }
}

/* ── Slow-remedy condition: proves a heavy remedy on the condition runner
 *    thread does NOT freeze the root supervisor sweep heartbeat ─────────── */
static _Atomic bool g_slow_entered;   /* remedy has begun sleeping */
static _Atomic bool g_slow_stop;      /* ask the remedy to return early */

static bool shs_slow_detect(void) { return true; }

static enum condition_remedy_result shs_slow_remedy(void)
{
    atomic_store(&g_slow_entered, true);
    /* Sleep up to ~1.5s in 50ms slices; return early when the test tears down.
     * This is the "deliberately-slow remedy" the sweep must survive. */
    for (int i = 0; i < 30 && !atomic_load(&g_slow_stop); i++) {
        struct timespec req = { 0, 50L * 1000000L };
        nanosleep(&req, NULL);
    }
    return COND_REMEDY_FAILED;         /* never clears; keeps re-running */
}

static bool shs_slow_witness(int64_t t) { (void)t; return false; }

static struct condition c_shs_slow = {
    .name = "test.shs_slow_remedy",
    .severity = COND_WARN,
    .poll_secs = 1,
    .backoff_secs = 0,
    .max_attempts = 1000000,           /* never page during the test window */
    .detect = shs_slow_detect,
    .remedy = shs_slow_remedy,
    .witness = shs_slow_witness,
    .witness_window_secs = 120,
};

int test_self_heal_supervisor(void)
{
    printf("\n=== self_heal_supervisor tests ===\n");
    int failures = 0;

    /* ── registration failure fails LOUD ─────────────────────────── */
    supervisor_reset_for_testing();
    blocker_reset_for_testing();
    self_heal_test_reset();
    atomic_store(&g_shs_operator_events, 0);
    event_observe(EV_OPERATOR_NEEDED, shs_operator_observer, NULL);

    {
        static struct liveness_contract pool[SUPERVISOR_CAP];
        shs_fill_registry(pool);

        struct main_state ms;
        main_state_init(&ms);
        self_heal_register(&ms);

        SHS_CHECK("registry full -> self_heal.unsupervised blocker set",
                  blocker_exists("self_heal.unsupervised"));
        SHS_CHECK("blocker class is PERMANENT (operator clears, no auto-retry)",
                  blocker_class_for("self_heal.unsupervised") ==
                  (int)BLOCKER_PERMANENT);
        SHS_CHECK("EV_OPERATOR_NEEDED paged the operator",
                  atomic_load(&g_shs_operator_events) > 0);

        main_state_free(&ms);
    }

    event_clear_observers(EV_OPERATOR_NEEDED);
    supervisor_reset_for_testing();
    blocker_reset_for_testing();
    self_heal_test_reset();

    /* ── healthy registration stays silent ───────────────────────── */
    atomic_store(&g_shs_operator_events, 0);
    event_observe(EV_OPERATOR_NEEDED, shs_operator_observer, NULL);

    {
        struct main_state ms;
        main_state_init(&ms);
        self_heal_register(&ms);

        SHS_CHECK("healthy registration sets NO self_heal.unsupervised blocker",
                  !blocker_exists("self_heal.unsupervised"));
        SHS_CHECK("healthy registration pages nobody",
                  atomic_load(&g_shs_operator_events) == 0);

        main_state_free(&ms);
    }

    event_clear_observers(EV_OPERATOR_NEEDED);
    supervisor_reset_for_testing();
    blocker_reset_for_testing();
    self_heal_test_reset();

    /* ── a slow remedy does NOT freeze the root sweep heartbeat ───────────
     * Regression guard: the condition engine must never run INLINE on the
     * supervisor sweep thread, where a >30s remedy pass freezes
     * supervisor_sweep_heartbeat() and the backstop declares a FATAL freeze.
     * The engine runs on the dedicated `zcl_self_heal` runner thread; a
     * slow remedy must therefore leave the root sweep beating freely. */
    supervisor_reset_for_testing();
    blocker_reset_for_testing();
    self_heal_test_reset();
    condition_engine_reset_for_testing();
    atomic_store(&g_slow_entered, false);
    atomic_store(&g_slow_stop, false);

    {
        struct main_state ms;
        main_state_init(&ms);

        SHS_CHECK("slow-remedy condition registered",
                  condition_register(&c_shs_slow));

        self_heal_register(&ms);

        /* Fast sweep so heartbeat increments are easy to observe. */
        supervisor_set_tick_ms_for_testing(10);
        SHS_CHECK("supervisor thread started", supervisor_start());
        SHS_CHECK("self_heal runner thread started", self_heal_start());

        /* Wait until the slow remedy is actually in-flight (bounded ~3s). */
        bool entered = false;
        for (int i = 0; i < 300; i++) {
            if (atomic_load(&g_slow_entered)) { entered = true; break; }
            struct timespec req = { 0, 10L * 1000000L };
            nanosleep(&req, NULL);
        }
        SHS_CHECK("slow remedy ran on the runner thread (not the sweep)",
                  entered);

        /* While the remedy is mid-sleep, the root sweep MUST keep beating. */
        uint64_t hb0 = supervisor_sweep_heartbeat();
        struct timespec win = { 0, 400L * 1000000L };   /* 400 ms window */
        nanosleep(&win, NULL);
        uint64_t hb1 = supervisor_sweep_heartbeat();

        /* At a 10ms tick over 400ms the sweep should advance ~40 times; even
         * with heavy jitter it must advance well clear of a frozen (==) count.
         * The OLD inline design would have frozen it here (delta 0). */
        SHS_CHECK("root sweep heartbeat keeps advancing during the slow remedy "
                  "(never frozen)", (hb1 - hb0) >= 5);

        /* Tear down: release the remedy, join the runner, stop the sweep. */
        atomic_store(&g_slow_stop, true);
        self_heal_stop();
        supervisor_stop();
        main_state_free(&ms);
    }

    supervisor_reset_for_testing();
    blocker_reset_for_testing();
    self_heal_test_reset();
    condition_engine_reset_for_testing();

    printf("=== self_heal_supervisor: %d failure(s) ===\n", failures);
    return failures;
}
