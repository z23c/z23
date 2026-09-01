/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the supervisor progress POLICY — "count results, not
 * activity" (platform/modules/util/src/supervisor.c, util/supervisor.h).
 *
 * What this is defending
 * -----------------------
 * NO_PROGRESS detection existed and worked, but it was gated on
 * progress_max_quiet_us > 0, and that field zero-initializes. So "nobody
 * decided" and "deliberately off" were the same value, and ~40 sites wrote a
 * literal 0. The measurable consequence on the canonical node 2026-07-28:
 *
 *   chain.op_return_backfill  ticks_run 13083  holes 13083  blocks_folded 0
 *                             stall_reason "none"  stall_fires 0
 *
 * Thirteen thousand runs, zero results, self-reported healthy.
 *
 * The tests below pin the four properties that make that unrepresentable:
 *
 *   1. UNDECLARED is the zero-init value, is counted as debt, and — this is
 *      the compatibility half — still does NOT stall. Turning detection on
 *      everywhere at once would be a different (and reckless) change.
 *   2. ARMED fires NO_PROGRESS on a frozen marker, exactly once (edge).
 *   3. An idle report keeps an ARMED child healthy WITHOUT moving the marker,
 *      so "caught up" is expressible and cannot be mistaken for work done.
 *      Without this property nothing could be armed safely.
 *   4. EXEMPT is off on purpose, carries an operator-readable reason, and
 *      refuses a blank one (a blank exemption is indistinguishable from an
 *      omission, so it must not be accepted as a declaration).
 *
 * Plus the registry-headroom floor: the live node was at 64 children against
 * a cap of 64, one register away from running a subsystem unsupervised.
 *
 * Time-driven paths use supervisor_sweep_once_for_testing() rather than real
 * sleeps, so the whole group runs in microseconds. */

#include "test/test_core.h"
#include "util/supervisor.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define PP_CHECK(name, expr) do { \
    printf("supervisor_progress_policy: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Backdate a contract's quiet clock so an armed child looks frozen without
 * waiting real time. Mirrors what the sweep reads. */
static void backdate_quiet(struct liveness_contract *c, int64_t age_us)
{
    atomic_store(&c->progress_changed_at_us,
                 atomic_load(&c->progress_changed_at_us) - age_us);
}

static int stall_of(const struct liveness_contract *c)
{
    return atomic_load(&c->stall_reason);
}

int test_supervisor_progress_policy(void)
{
    int failures = 0;

    /* ── 1. UNDECLARED: zero-init, counted, and still silent ─────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "test.undeclared");
        supervisor_child_id id = supervisor_register(&c);

        PP_CHECK("zero-init policy is UNDECLARED",
            atomic_load(&c.progress_policy) ==
                (int)SUPERVISOR_PROGRESS_UNDECLARED);
        PP_CHECK("undeclared child is counted as debt",
            supervisor_progress_undeclared_count() == 1);

        /* Compatibility: an undeclared child must behave EXACTLY as before —
         * detection off. A frozen marker, however old, raises nothing. */
        backdate_quiet(&c, (int64_t)86400 * 1000000); /* a full day */
        supervisor_sweep_once_for_testing();
        PP_CHECK("undeclared does NOT stall (behaviour unchanged)",
            stall_of(&c) == SUPERVISOR_STALL_NONE &&
            atomic_load(&c.stall_fires) == 0);

        supervisor_unregister(id);
    }

    /* ── 2. ARMED: a frozen marker stalls, once ──────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "test.armed");
        supervisor_child_id id = supervisor_register(&c);
        supervisor_set_progress_max_quiet(id, 1000000); /* 1 s */

        PP_CHECK("set_progress_max_quiet(>0) declares ARMED",
            atomic_load(&c.progress_policy) ==
                (int)SUPERVISOR_PROGRESS_ARMED);
        PP_CHECK("armed child is not counted as debt",
            supervisor_progress_undeclared_count() == 0);

        /* Fresh: not yet quiet for the window. */
        supervisor_sweep_once_for_testing();
        PP_CHECK("armed child within its window does not stall",
            stall_of(&c) == SUPERVISOR_STALL_NONE);

        /* Ticking is ACTIVITY, not results — it must NOT save the child.
         * This is the exact property the live node's 13083 ticks violated. */
        backdate_quiet(&c, 5000000); /* 5 s > 1 s window */
        for (int i = 0; i < 5; i++) supervisor_tick(id);
        supervisor_sweep_once_for_testing();
        PP_CHECK("ticking does not clear a frozen marker -> NO_PROGRESS",
            stall_of(&c) == SUPERVISOR_STALL_NO_PROGRESS);
        PP_CHECK("NO_PROGRESS fired exactly once (edge-triggered)",
            atomic_load(&c.stall_fires) == 1);

        supervisor_sweep_once_for_testing();
        PP_CHECK("still-frozen armed child does not re-fire",
            atomic_load(&c.stall_fires) == 1);

        /* Real progress rearms. */
        supervisor_progress(id, 42);
        PP_CHECK("progress clears NO_PROGRESS",
            stall_of(&c) == SUPERVISOR_STALL_NONE);

        supervisor_unregister(id);
    }

    /* ── 3. Idle: healthy without claiming credit ────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "test.idle");
        supervisor_child_id id = supervisor_register(&c);
        supervisor_set_progress_max_quiet(id, 1000000);
        supervisor_progress(id, 7);

        int64_t marker_before = atomic_load(&c.progress_marker);
        backdate_quiet(&c, 5000000);
        supervisor_progress_idle(id);
        supervisor_sweep_once_for_testing();

        PP_CHECK("idle report keeps an armed child healthy",
            stall_of(&c) == SUPERVISOR_STALL_NONE &&
            atomic_load(&c.stall_fires) == 0);
        PP_CHECK("idle does NOT move the progress marker",
            atomic_load(&c.progress_marker) == marker_before);
        PP_CHECK("idle is counted separately from ticks",
            atomic_load(&c.idle_ticks) == 1 &&
            atomic_load(&c.ticks_run) == 0);

        /* And the converse — the property that makes the whole thing work.
         * Stop reporting idle and the same child stalls, so a service that
         * silently stops declaring itself caught-up is caught. */
        backdate_quiet(&c, 5000000);
        supervisor_sweep_once_for_testing();
        PP_CHECK("without an idle report the same child stalls",
            stall_of(&c) == SUPERVISOR_STALL_NO_PROGRESS);

        /* Idle also rearms after a stall (a wedged service that catches up). */
        supervisor_progress_idle(id);
        PP_CHECK("idle clears a NO_PROGRESS stall",
            stall_of(&c) == SUPERVISOR_STALL_NONE);

        supervisor_unregister(id);
    }

    /* ── 4. EXEMPT: off on purpose, with a reason ────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "test.exempt");
        supervisor_child_id id = supervisor_register(&c);
        supervisor_set_progress_exempt(id,
            "pure sampler: publishes a gauge, produces no work units");

        PP_CHECK("set_progress_exempt declares EXEMPT",
            atomic_load(&c.progress_policy) ==
                (int)SUPERVISOR_PROGRESS_EXEMPT);
        PP_CHECK("exempt records an operator-readable reason",
            strstr(c.progress_exempt_reason, "pure sampler") != NULL);
        PP_CHECK("exempt is not counted as debt",
            supervisor_progress_undeclared_count() == 0);

        backdate_quiet(&c, (int64_t)86400 * 1000000);
        supervisor_sweep_once_for_testing();
        PP_CHECK("exempt child never stalls on a frozen marker",
            stall_of(&c) == SUPERVISOR_STALL_NONE);

        supervisor_unregister(id);
    }

    /* A blank justification must be REFUSED, not stored. An exemption with
     * nothing behind it reads as "someone considered this" while carrying
     * exactly as much information as the omission it replaced. */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "test.blank_exempt");
        supervisor_child_id id = supervisor_register(&c);
        supervisor_set_progress_exempt(id, "");
        PP_CHECK("empty exemption reason is refused -> stays UNDECLARED",
            atomic_load(&c.progress_policy) ==
                (int)SUPERVISOR_PROGRESS_UNDECLARED &&
            supervisor_progress_undeclared_count() == 1);

        supervisor_set_progress_exempt(id, NULL);
        PP_CHECK("NULL exemption reason is refused -> stays UNDECLARED",
            atomic_load(&c.progress_policy) ==
                (int)SUPERVISOR_PROGRESS_UNDECLARED);

        supervisor_unregister(id);
    }

    /* ── 5. Raw-field armers are reported honestly ───────────────────── */
    /* Three children (chain.coord_escalation, net.outbound_floor, the
     * staged-sync stages) arm by storing the field directly instead of
     * calling the setter. They ARE armed; reporting them as undeclared
     * because they skipped the API would be a lie, and gating the sweep on
     * the declared field would silently disarm them. */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "test.raw_armer");
        supervisor_child_id id = supervisor_register(&c);
        atomic_store(&c.progress_max_quiet_us, (int64_t)1000000);

        PP_CHECK("raw-field armer is not counted as debt",
            supervisor_progress_undeclared_count() == 0);

        backdate_quiet(&c, 5000000);
        supervisor_sweep_once_for_testing();
        PP_CHECK("raw-field armer still stalls (no silent disarm)",
            stall_of(&c) == SUPERVISOR_STALL_NO_PROGRESS);

        supervisor_unregister(id);
    }

    /* ── 6. Registry headroom ────────────────────────────────────────── */
    /* The canonical node measured child_count 64 against SUPERVISOR_CAP 64:
     * the next subsystem to register would have been rejected and run
     * unsupervised. Assert real margin above the live population so this
     * fails in CI rather than on a node. */
    supervisor_reset_for_testing();
    {
        PP_CHECK("empty registry reports full headroom",
            supervisor_child_headroom() == SUPERVISOR_CAP);
        PP_CHECK("cap leaves >=32 slots above the observed live population(64)",
            SUPERVISOR_CAP - 64 >= 32);

        static struct liveness_contract c;
        liveness_contract_init(&c, "test.headroom");
        supervisor_child_id id = supervisor_register(&c);
        PP_CHECK("headroom decrements on register",
            supervisor_child_headroom() == SUPERVISOR_CAP - 1);
        supervisor_unregister(id);
    }

    /* ── 7. The dump an operator actually reads ──────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract armed, exempt, undecl;
        liveness_contract_init(&armed,  "test.dump_armed");
        liveness_contract_init(&exempt, "test.dump_exempt");
        liveness_contract_init(&undecl, "test.dump_undeclared");
        supervisor_child_id a = supervisor_register(&armed);
        supervisor_child_id e = supervisor_register(&exempt);
        supervisor_child_id u = supervisor_register(&undecl);
        supervisor_set_progress_max_quiet(a, 1000000);
        supervisor_set_progress_exempt(e, "no work units by construction");
        supervisor_progress_idle(a);

        struct json_value out;
        json_init(&out);
        PP_CHECK("dump succeeds", supervisor_dump_state_json(&out, NULL));

        const struct json_value *debt = json_get(&out,
                                                 "progress_undeclared_count");
        PP_CHECK("dump publishes progress_undeclared_count (=1)",
            debt && json_get_int(debt) == 1);
        const struct json_value *head = json_get(&out, "child_headroom");
        PP_CHECK("dump publishes registry headroom",
            head && json_get_int(head) == SUPERVISOR_CAP - 3);

        /* Children without a domain land in root_orphans[]. Walk it and
         * confirm each policy is named, the reason survives verbatim, and
         * idle_ticks is reported apart from ticks_run. */
        const struct json_value *kids = json_get(&out, "root_orphans");
        bool saw_armed = false, saw_exempt = false, saw_undeclared = false;
        bool saw_reason = false, saw_idle = false;
        for (size_t i = 0; kids && i < json_size(kids); i++) {
            const struct json_value *k = json_at(kids, i);
            const struct json_value *pol = k ? json_get(k, "progress_policy")
                                             : NULL;
            const char *p = pol ? json_get_str(pol) : NULL;
            if (!p) continue;
            if (strcmp(p, "armed") == 0) {
                saw_armed = true;
                const struct json_value *it = json_get(k, "idle_ticks");
                const struct json_value *tr = json_get(k, "ticks_run");
                saw_idle = it && tr && json_get_int(it) == 1 &&
                           json_get_int(tr) == 0;
            } else if (strcmp(p, "exempt") == 0) {
                saw_exempt = true;
                const struct json_value *r =
                    json_get(k, "progress_exempt_reason");
                const char *rs = r ? json_get_str(r) : NULL;
                saw_reason = rs && strcmp(rs,
                    "no work units by construction") == 0;
            } else if (strcmp(p, "undeclared") == 0) {
                saw_undeclared = true;
            }
        }
        PP_CHECK("dump names each child's policy",
            saw_armed && saw_exempt && saw_undeclared);
        PP_CHECK("dump carries the exemption reason verbatim", saw_reason);
        PP_CHECK("dump separates idle_ticks from ticks_run", saw_idle);

        json_free(&out);
        supervisor_unregister(a);
        supervisor_unregister(e);
        supervisor_unregister(u);
    }

    supervisor_reset_for_testing();
    return failures;
}
