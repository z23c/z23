/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proof for the folded recovery_coordinator. Its cheap rungs (cursor
 * warm-restart, bounded range re-derive, segment refetch-by-hash) are no
 * longer dispatched here — the reducer_frontier_reconcile_light and
 * segment_corruption conditions own them at equal/higher cadence (covered by
 * test_reducer_frontier_reconcile_light / test_segment_corruption). The
 * coordinator's sole remaining job is the naming fallback: on an unresolved
 * CRITICAL that no cheap self-healing condition owns, name a typed blocker so
 * a silent halt is unrepresentable.
 *
 *   gate:    no unresolved critical      -> quiet (no blocker, no run)
 *   fire:    unresolved critical, no owning condition active -> name blocker
 *   suppress: unresolved critical IS an owning condition (active) -> quiet
 *   naming:  the typed blocker is a retry-forever DEPENDENCY (no silent halt)
 */

#include "test/test_core.h"

#include "services/recovery_coordinator.h"
#include "framework/condition.h"
#include "event/event.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define RC_CHECK(name, expr) do { \
    printf("recovery_coordinator: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── condition fixture: detect-true CRITICAL that never witnesses clear, so a
 * couple of ticks exhaust max_attempts and it becomes an unresolved critical
 * while staying currently_active. ────────────────────────────────────── */

static enum condition_remedy_result cf_remedy(void)  { return COND_REMEDY_OK; }
static bool cf_detect(void)  { return true; }
static bool cf_witness(int64_t t) { (void)t; return false; }

static void drive_to_unresolved_critical(struct condition *c)
{
    (void)condition_register(c);
    condition_engine_tick();
    condition_engine_tick();
}

static void rc_reset(void)
{
    condition_engine_reset_for_testing();
    event_log_init();
    blocker_module_init();
    blocker_reset_for_testing();
    recovery_coordinator_test_reset();
}

int test_recovery_coordinator(void);
int test_recovery_coordinator(void)
{
    printf("\n=== recovery_coordinator (naming-fallback fold) ===\n");
    int failures = 0;
    const char *BLOCKER_ID = "recovery_coordinator.no_applicable_rung";

    /* ── 1. no unresolved critical -> coordinator stays quiet ─────────── */
    {
        rc_reset();
        recovery_coordinator_test_drive();
        RC_CHECK("gate: no unresolved critical -> no run",
                 recovery_coordinator_test_runs() == 0);
        RC_CHECK("gate: no unresolved critical -> no blocker",
                 blocker_fire_count_for_testing(BLOCKER_ID) == 0);
    }

    /* ── 2. unresolved critical, no owning condition active -> name blocker */
    {
        rc_reset();
        static struct condition c_other = {
            .name = "rc_other_critical",
            .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
            .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
            .witness = cf_witness, .witness_window_secs = 60,
        };
        drive_to_unresolved_critical(&c_other);
        RC_CHECK("fire: an unresolved critical exists",
                 condition_engine_get_unresolved_critical_count() > 0);

        recovery_coordinator_test_drive();
        RC_CHECK("fire: coordinator ran", recovery_coordinator_test_runs() == 1);
        RC_CHECK("fire: named the typed blocker",
                 blocker_fire_count_for_testing(BLOCKER_ID) > 0);
        RC_CHECK("fire: blocker counter advanced",
                 recovery_coordinator_test_blocker_fires() == 1);
    }

    /* ── 3. the unresolved critical IS an owning condition -> suppressed ─ */
    {
        rc_reset();
        /* Named exactly as the reconcile condition that owns rungs 1-2; when
         * IT is the active healer the coordinator must not name a blocker. */
        static struct condition c_owning = {
            .name = "reducer_frontier_reconcile_light",
            .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
            .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
            .witness = cf_witness, .witness_window_secs = 60,
        };
        drive_to_unresolved_critical(&c_owning);
        struct condition_runtime_snapshot snap;
        RC_CHECK("suppress: owning condition is currently_active",
                 condition_engine_get_registered_snapshot(
                     "reducer_frontier_reconcile_light", &snap) &&
                 snap.currently_active);
        RC_CHECK("suppress: it is an unresolved critical",
                 condition_engine_get_unresolved_critical_count() > 0);

        recovery_coordinator_test_drive();
        RC_CHECK("suppress: coordinator stayed quiet (no run)",
                 recovery_coordinator_test_runs() == 0);
        RC_CHECK("suppress: no blocker named while owning healer is active",
                 blocker_fire_count_for_testing(BLOCKER_ID) == 0);
    }

    /* ── 4. naming fallback: typed retry-forever DEPENDENCY blocker ────── */
    {
        rc_reset();
        recovery_coordinator_test_name_blocker();
        RC_CHECK("naming: typed blocker named (no silent halt)",
                 blocker_fire_count_for_testing(BLOCKER_ID) > 0);
        struct blocker_snapshot snaps[16];
        int n = blocker_snapshot_all(snaps, 16);
        bool retry_forever_dependency = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, BLOCKER_ID) == 0) {
                retry_forever_dependency =
                    snaps[i].class == BLOCKER_DEPENDENCY &&
                    snaps[i].retry_budget == -1;
                break;
            }
        }
        RC_CHECK("naming: blocker is a retry-forever DEPENDENCY (guard kept)",
                 retry_forever_dependency);
        blocker_reset_for_testing();
    }

    printf("recovery_coordinator: %d failures\n", failures);
    return failures;
}
