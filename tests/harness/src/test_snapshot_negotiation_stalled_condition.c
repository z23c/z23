/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/runtime.h"
#include "framework/condition.h"
#include "net/snapshot_sync_contract.h"
#include "platform/clock.h"

#include <stdatomic.h>
#include <string.h>

#define SNS_CHECK(name, expr) do { \
    printf("snapshot_negotiation_stalled_condition: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_snapshot_negotiation_stalled(void);
void snapshot_negotiation_stalled_test_reset(void);
int snapshot_negotiation_stalled_test_remedy_calls(void);
int64_t snapsync_now_us_internal(void);

/* Fake wall+mono clock so the cooldown-rearm test below can drive the
 * condition engine's backoff/cooldown cadence deterministically instead of
 * waiting on real time (600s cooldown). Mirrors test_sync_watchdog_conditions.c. */
struct fake_clock {
    _Atomic int64_t mono_ns;
    _Atomic int64_t wall_ms;
};

static int64_t fake_now_mono(void *self)
{
    return atomic_load(&((struct fake_clock *)self)->mono_ns);
}

static int64_t fake_now_wall(void *self)
{
    return atomic_load(&((struct fake_clock *)self)->wall_ms);
}

static void fake_clock_install(struct fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    atomic_store(&c->mono_ns, unix_s * 1000000000LL);
    static clock_iface_t iface;
    iface.now_monotonic_ns = fake_now_mono;
    iface.now_wall_ms = fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void fake_clock_set(struct fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    atomic_store(&c->mono_ns, unix_s * 1000000000LL);
}

static void reset_sns(struct snapshot_sync_service *svc,
                      struct app_runtime_context *runtime)
{
    condition_engine_reset_for_testing();
    snapshot_negotiation_stalled_test_reset();
    memset(svc, 0, sizeof(*svc));
    memset(runtime, 0, sizeof(*runtime));
    snapsync_init(svc, NULL);
    runtime->snapshot_sync = svc;
    app_runtime_set_current(runtime);
}

static void cleanup_sns(void)
{
    app_runtime_set_current(NULL);
    condition_engine_reset_for_testing();
    clock_reset_default();
}

/* Scenario: a negotiation stalled past the timeout is remedied (peer
 * blacklisted, state reset to IDLE) and the condition clears once a
 * different peer negotiates. Returns the verdict; the caller logs it. */
static bool sns_stalled_negotiation_resets_and_blacklists_peer(
    struct snapshot_sync_service *svc)
{
    bool ok = true;

    svc->state = SNAPSYNC_NEGOTIATING;
    svc->offered_height = 3000000;
    svc->offered_count = 1350000;
    svc->serving_peer_id = 11;
    svc->start_time_us =
        snapsync_now_us_internal() -
        ((int64_t)SNAPSYNC_NEGOTIATION_TIMEOUT_SECS + 1) * 1000000LL;

    condition_engine_tick();
    ok = ok && snapshot_negotiation_stalled_test_remedy_calls() == 1;
    ok = ok && svc->state == SNAPSYNC_IDLE;
    ok = ok && snapsync_is_peer_blacklisted(svc, 11);
    /* Honest witness (Law 7): the remedy reset + blacklisted the dead
     * peer, but the symptom has not yet MOVED — no fresh negotiation is
     * advancing, so the condition stays active (unwitnessed). The reset's
     * real forward progress is that a DIFFERENT peer can now negotiate. */
    ok = ok && condition_engine_get_active_count() == 1;
    svc->state = SNAPSYNC_NEGOTIATING;
    svc->serving_peer_id = 14;
    svc->offered_height = 3000001;
    svc->offered_count = 1350001;
    condition_engine_tick();
    ok = ok && condition_engine_get_active_count() == 0;
    return ok;
}

/* Scenario: a negotiation younger than the timeout must be left alone. */
static bool sns_fresh_negotiation_is_not_reset(
    struct snapshot_sync_service *svc)
{
    bool ok = true;

    svc->state = SNAPSYNC_NEGOTIATING;
    svc->offered_height = 3000000;
    svc->offered_count = 1350000;
    svc->serving_peer_id = 12;
    svc->start_time_us = snapsync_now_us_internal();

    condition_engine_tick();
    ok = ok && snapshot_negotiation_stalled_test_remedy_calls() == 0;
    ok = ok && svc->state == SNAPSYNC_NEGOTIATING;
    ok = ok && !snapsync_is_peer_blacklisted(svc, 12);
    return ok;
}

/* Scenario: the receive state must never be treated as a stalled
 * negotiation. */
static bool sns_receive_state_is_not_negotiation_stall(
    struct snapshot_sync_service *svc)
{
    bool ok = true;

    svc->state = SNAPSYNC_RECEIVING;
    svc->offered_height = 3000000;
    svc->offered_count = 1350000;
    svc->serving_peer_id = 13;
    svc->start_time_us =
        snapsync_now_us_internal() -
        ((int64_t)SNAPSYNC_NEGOTIATION_TIMEOUT_SECS + 1) * 1000000LL;

    struct snapsync_negotiation_status st;
    snapsync_get_negotiation_status(svc, &st);
    ok = ok && !st.negotiating;
    ok = ok && !st.stalled;
    ok = ok && !snapsync_check_negotiation_stall();
    ok = ok && svc->state == SNAPSYNC_RECEIVING;
    return ok;
}

/* Scenario: the same peer stalling twice drives the condition to
 * max_attempts and the engine pages the operator exactly once. */
static bool sns_pages_operator_once_at_attempt_cap(
    struct snapshot_sync_service *svc,
    struct fake_clock *clock,
    int64_t stall_offset_us)
{
    bool ok = true;

    svc->state = SNAPSYNC_NEGOTIATING;
    svc->offered_height = 3200000;
    svc->offered_count = 1360000;
    svc->serving_peer_id = 21;
    svc->start_time_us = snapsync_now_us_internal() - stall_offset_us;

    condition_engine_tick();  /* attempt 1/2 */
    ok = ok && snapshot_negotiation_stalled_test_remedy_calls() == 1;
    ok = ok && svc->state == SNAPSYNC_IDLE;
    ok = ok && condition_engine_get_active_count() == 1;

    /* Same peer offer stalls again (persistent external fault, not a
     * fresh peer/height) so the witness stays false and the episode
     * does not clear between attempts. */
    fake_clock_set(clock, 10061);
    svc->state = SNAPSYNC_NEGOTIATING;
    svc->offered_height = 3200000;
    svc->offered_count = 1360000;
    svc->serving_peer_id = 21;
    svc->start_time_us = snapsync_now_us_internal() - stall_offset_us;

    condition_engine_tick();  /* attempt 2/2 — hits max_attempts */
    ok = ok && snapshot_negotiation_stalled_test_remedy_calls() == 2;
    ok = ok && condition_engine_get_active_count() == 1;

    struct condition_runtime_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    ok = ok && condition_engine_get_registered_snapshot(
                   "snapshot_negotiation_stalled", &snap);
    ok = ok && snap.max_attempts == 2;
    ok = ok && snap.attempts == 2;
    ok = ok && snap.operator_needed_emitted;
    return ok;
}

/* Scenario: the same fault persisting a third time, past max_attempts,
 * re-arms on cooldown instead of latching at operator_needed forever. */
static bool sns_rearms_on_cooldown_past_max_attempts(
    struct snapshot_sync_service *svc,
    struct fake_clock *clock,
    int64_t stall_offset_us)
{
    bool ok = true;

    /* Same fault persists a THIRD time, past max_attempts. Without the
     * cooldown fields this would stay latched at operator_needed forever
     * (condition_cooldown_rearm returns false when cooldown_secs<=0) and
     * the remedy would never be called again. */
    fake_clock_set(clock, 10122);
    svc->state = SNAPSYNC_NEGOTIATING;
    svc->offered_height = 3200000;
    svc->offered_count = 1360000;
    svc->serving_peer_id = 21;
    svc->start_time_us = snapsync_now_us_internal() - stall_offset_us;

    condition_engine_tick();
    ok = ok && snapshot_negotiation_stalled_test_remedy_calls() == 3;
    ok = ok && condition_engine_get_active_count() == 1;

    struct condition_runtime_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    ok = ok && condition_engine_get_registered_snapshot(
                   "snapshot_negotiation_stalled", &snap);
    ok = ok && snap.attempts < snap.max_attempts;  /* re-armed, not latched */
    return ok;
}

int test_snapshot_negotiation_stalled_condition(void)
{
    printf("\n=== snapshot_negotiation_stalled condition tests ===\n");
    int failures = 0;

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_sns(&svc, &runtime);
        register_snapshot_negotiation_stalled();
        bool ok = sns_stalled_negotiation_resets_and_blacklists_peer(&svc);
        SNS_CHECK("stalled negotiation resets and blacklists peer", ok);
        cleanup_sns();
    }

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_sns(&svc, &runtime);
        register_snapshot_negotiation_stalled();
        bool ok = sns_fresh_negotiation_is_not_reset(&svc);
        SNS_CHECK("fresh negotiation is not reset", ok);
        cleanup_sns();
    }

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_sns(&svc, &runtime);
        bool ok = sns_receive_state_is_not_negotiation_stall(&svc);
        SNS_CHECK("receive state is not treated as negotiation stall", ok);
        cleanup_sns();
    }

    {
        /* Regression for the missing cooldown_secs/cooldown_max_rearms: a
         * peer stalling mid negotiation is a purely transient external fault
         * (the remedy blacklists the peer + resets to IDLE). Before this fix
         * cooldown_secs was 0 ("legacy"), so condition_cooldown_rearm()
         * refused to reset the attempt budget once attempts hit
         * max_attempts=2 and the engine paged the operator FOREVER. Drive
         * the same persistent stall past max_attempts and assert the engine
         * re-arms and calls the remedy again instead of latching. */
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        struct fake_clock clock;
        reset_sns(&svc, &runtime);
        register_snapshot_negotiation_stalled();
        fake_clock_install(&clock, 10000);

        const int64_t stall_offset_us =
            ((int64_t)SNAPSYNC_NEGOTIATION_TIMEOUT_SECS + 1) * 1000000LL;

        bool ok = sns_pages_operator_once_at_attempt_cap(
            &svc, &clock, stall_offset_us);
        SNS_CHECK("pages operator once at the attempt cap", ok);

        bool rearmed = sns_rearms_on_cooldown_past_max_attempts(
            &svc, &clock, stall_offset_us);
        ok = ok && rearmed;
        SNS_CHECK("re-arms on cooldown past max_attempts instead of "
                  "latching forever",
                  ok);
        cleanup_sns();
    }

    cleanup_sns();
    return failures;
}
