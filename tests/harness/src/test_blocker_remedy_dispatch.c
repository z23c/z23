/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registration is not dispatch.
 *
 * engine/conditions/include/conditions/blocker_remedy_bindings.def declares that
 * `hotswap.retired_generation_undrained` is auto-remedied by
 * ESCAPE(hotswap_reclaim_retry), and check-blocker-remedy fails the build if
 * that action has no blocker_register_escape() call site. Both of those are
 * BUILD-time facts. Neither proves the remedy ever runs: on the canonical
 * node 2026-07-27 `dumpstate blocker` reported escape_dispatched_total = 0
 * while three blockers had fired 23,868 times between them.
 *
 * This test drives the PRODUCTION raise site and asserts the whole chain end
 * to end:
 *
 *   1. BINDING JOIN — the remedy the .def declares for the id, the
 *      escape_action string the production raise site writes into the
 *      record, and the name in the live escape registry are the SAME name.
 *      This is the link the teeth-check breaks.
 *   2. DISPATCH — blocker_supervisor_sweep() fires it on the deadline edge
 *      and the process-wide escape_dispatched_total counter MOVES. Not
 *      "returns 1": the counter the operator reads.
 *   3. THE REMEDY RAN — the installed reclaim seam was actually invoked,
 *      and a reclaim that genuinely drained clears the blocker while a
 *      partial one leaves it named.
 *   4. RETRY BUDGET CONSUMED — every dispatch charges retry_count, and a
 *      record with a finite budget stops dispatching once it is spent.
 *      Before this landed, blocker_record_retry() had ZERO production
 *      callers, so retry_count was 0 on every live blocker forever.
 *   5. RE-ARM — a still-live blocker that re-fires with a fresh deadline
 *      horizon gets its remedy driven AGAIN. The pre-existing coverage in
 *      test_blocker.c calls blocker_clear() between crossings, which hides
 *      the case that matters live: the blocker is not going away, and the
 *      escape used to latch after exactly one dispatch per registry
 *      lifetime.
 *
 * The hotswap retire blocker is used because it is a real production
 * binding whose remedy reaches the outside world through an injectable seam
 * (hotswap_retire_blocker_set_reclaimer), so the dispatch is genuine and the
 * effect is observable without touching a datadir or a live subsystem. */

#include "test/test_core.h"

#include "conditions/blocker_handoff_registry.h"
#include "hotswap/hotswap_retire_blocker.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define BRD_CHECK(name, expr) do { \
    printf("blocker_remedy_dispatch: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static atomic_int  g_reclaim_calls;
static atomic_bool g_reclaim_drains;

static bool reclaim_seam(void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_reclaim_calls, 1);
    return atomic_load(&g_reclaim_drains);
}

/* Pull the action name out of the .def remedy token "ESCAPE(<action>)".
 * Returns false for any other remedy shape (OWNER, a condition name). */
static bool escape_action_from_remedy(const char *remedy, char *out, size_t cap)
{
    if (!remedy || !out || cap == 0) return false;
    const char *p = strstr(remedy, "ESCAPE(");
    if (!p) return false;
    p += 7;
    const char *end = strchr(p, ')');
    if (!end || (size_t)(end - p) >= cap) return false;
    memcpy(out, p, (size_t)(end - p));
    out[end - p] = '\0';
    return true;
}

int test_blocker_remedy_dispatch(void)
{
    int failures = 0;
    printf("\n=== blocker remedy dispatch tests ===\n");

    /* ── 1. Binding join: .def row -> raise site -> escape registry ─── */
    char declared_action[BLOCKER_ACTION_MAX];
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(1000000);
        blocker_set_rate_limit_ms_for_testing(0);
        hotswap_retire_blocker_reset_for_testing();

        const char *remedy = "", *decision = "";
        bool human = true;
        bool bound = blocker_handoff_lookup(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID,
                                            &remedy, &decision, &human);
        BRD_CHECK("the id has a row in blocker_remedy_bindings.def", bound);
        BRD_CHECK("that row declares an AUTOMATIC remedy, not OWNER", !human);

        declared_action[0] = '\0';
        bool parsed = escape_action_from_remedy(remedy, declared_action,
                                                sizeof(declared_action));
        BRD_CHECK("the declared remedy is an ESCAPE(<action>)", parsed);

        /* Raise through the production path — it self-registers the escape. */
        hotswap_retire_blocker_raise();

        struct blocker_snapshot s;
        int n = blocker_snapshot_all(&s, 1);
        BRD_CHECK("the production raise site names that exact id",
                  n == 1 &&
                  strcmp(s.id, HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID) == 0);
        BRD_CHECK("the record's escape_action IS the .def-declared action",
                  n == 1 && parsed &&
                  strcmp(s.escape_action, declared_action) == 0);
        BRD_CHECK("that action resolves in the live escape registry",
                  parsed && blocker_lookup_escape(declared_action) != NULL);
        BRD_CHECK("the blocker carries a deadline (something WILL be tried)",
                  n == 1 && s.escape_deadline_us > 0);
    }

    /* ── 2+3. Dispatch moves the counter, and the remedy really runs ── */
    {
        atomic_store(&g_reclaim_calls, 0);
        atomic_store(&g_reclaim_drains, false);
        hotswap_retire_blocker_set_reclaimer(reclaim_seam, NULL);

        int before = blocker_escape_dispatched_count();
        BRD_CHECK("counter starts at 0 for this registry generation",
                  before == 0);

        int fired = blocker_supervisor_sweep();
        BRD_CHECK("before the deadline: nothing dispatched", fired == 0);
        BRD_CHECK("before the deadline: counter unmoved",
                  blocker_escape_dispatched_count() == before);
        BRD_CHECK("before the deadline: the remedy has NOT run",
                  atomic_load(&g_reclaim_calls) == 0);

        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        fired = blocker_supervisor_sweep();
        BRD_CHECK("on the deadline edge: one escape dispatched", fired == 1);
        BRD_CHECK("escape_dispatched_total MOVED (the operator-visible "
                  "counter, 0 on the live node today)",
                  blocker_escape_dispatched_count() == before + 1);
        BRD_CHECK("the remedy actually RAN (reclaim seam invoked once)",
                  atomic_load(&g_reclaim_calls) == 1);
        BRD_CHECK("a reclaim that did not drain leaves the blocker named "
                  "(no self-certifying cure)",
                  blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));

        struct blocker_snapshot s;
        int n = blocker_snapshot_all(&s, 1);
        BRD_CHECK("the dispatch CHARGED the retry budget (retry_count 0->1)",
                  n == 1 && s.retry_count == 1);
    }

    /* ── 5. Re-arm: a still-live blocker keeps getting its remedy driven ─
     * No blocker_clear() anywhere in this block. The blocker stays in the
     * registry the whole time — exactly the live shape. */
    {
        int before = blocker_escape_dispatched_count();
        int calls_before = atomic_load(&g_reclaim_calls);

        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        int fired = blocker_supervisor_sweep();
        BRD_CHECK("within one deadline crossing the escape does not re-fire",
                  fired == 0 &&
                  blocker_escape_dispatched_count() == before);

        /* The retention re-fires (the fault is still live) — that anchors a
         * fresh deadline horizon, which must re-arm the edge. */
        hotswap_retire_blocker_raise();
        BRD_CHECK("the blocker is still the same single live claim",
                  blocker_count_active() == 1 &&
                  blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));

        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        fired = blocker_supervisor_sweep();
        BRD_CHECK("the next crossing dispatches AGAIN (a live blocker is not "
                  "a one-shot alarm)", fired == 1);
        BRD_CHECK("counter moved on the second dispatch",
                  blocker_escape_dispatched_count() == before + 1);
        BRD_CHECK("the remedy ran a second time",
                  atomic_load(&g_reclaim_calls) == calls_before + 1);

        struct blocker_snapshot s;
        int n = blocker_snapshot_all(&s, 1);
        BRD_CHECK("retry_count charged again (0->1->2)",
                  n == 1 && s.retry_count == 2);
    }

    /* ── 3b. A reclaim that genuinely drained clears the claim ──────── */
    {
        atomic_store(&g_reclaim_drains, true);
        hotswap_retire_blocker_raise();
        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        int fired = blocker_supervisor_sweep();
        BRD_CHECK("draining reclaim dispatched", fired == 1);
        BRD_CHECK("a remedy that MOVED the symptom clears the blocker",
                  !blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));
        hotswap_retire_blocker_set_reclaimer(NULL, NULL);
        hotswap_retire_blocker_reset_for_testing();
    }

    /* ── 4. A finite retry budget is spent, then dispatch stops ─────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(5000000);
        blocker_set_rate_limit_ms_for_testing(0);
        hotswap_retire_blocker_reset_for_testing();
        hotswap_retire_blocker_register_escape();
        atomic_store(&g_reclaim_calls, 0);
        atomic_store(&g_reclaim_drains, false);
        hotswap_retire_blocker_set_reclaimer(reclaim_seam, NULL);

        /* Same real, registered remedy; a finite budget instead of the
         * production -1 so exhaustion is observable. */
        struct blocker_record r;
        BRD_CHECK("budget fixture: blocker_init",
                  blocker_init(&r, "budget.fixture", "test",
                               BLOCKER_DEPENDENCY, "reason gen 0"));
        r.escape_deadline_secs = 10;
        r.retry_budget = 2;
        snprintf(r.escape_action, sizeof(r.escape_action), "%s",
                 HOTSWAP_RETIRE_ESCAPE_ACTION);
        (void)blocker_set(&r);

        int dispatched = 0;
        for (int gen = 1; gen <= 4; gen++) {
            blocker_advance_clock_for_testing(11 * 1000000);
            dispatched += blocker_supervisor_sweep();
            /* Re-fire with a changed reason: a genuinely new occurrence,
             * which anchors a fresh horizon and re-arms the edge. */
            snprintf(r.reason, sizeof(r.reason), "reason gen %d", gen);
            (void)blocker_set(&r);
        }

        BRD_CHECK("dispatch stopped at the declared budget (2 of 4 "
                  "crossings)", dispatched == 2);
        BRD_CHECK("the escape counter agrees with the budget",
                  blocker_escape_dispatched_count() == 2);
        BRD_CHECK("the remedy ran exactly twice", atomic_load(&g_reclaim_calls) == 2);

        struct blocker_snapshot s;
        int n = blocker_snapshot_all(&s, 1);
        BRD_CHECK("retry_count == retry_budget (the budget was CONSUMED, "
                  "not decoration)",
                  n == 1 && s.retry_count == 2 && s.retry_budget == 2);

        hotswap_retire_blocker_set_reclaimer(NULL, NULL);
        hotswap_retire_blocker_reset_for_testing();
        blocker_reset_for_testing();
    }

    printf("=== blocker remedy dispatch: %d failure(s) ===\n", failures);
    return failures;
}
