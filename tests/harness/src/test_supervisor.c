/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the supervisor primitive (platform/modules/util/src/supervisor.c).
 *
 * Coverage:
 *   - liveness_contract_init: name truncation, default fields
 *   - registration: register/unregister, duplicate rejection, capacity
 *   - child-side: tick monotonicity, progress edge-rearm, stall report
 *   - supervisor loop: period drives on_tick, deadline fires on_stall,
 *     progress-frozen fires on_stall, edge-once not every tick
 *   - lifecycle: start/stop idempotency, second start returns true
 *   - introspection: snapshot_all + dump_state_json shape
 *
 * The supervisor's loop is time-driven; tests use
 * supervisor_set_tick_ms_for_testing(5) to keep each sub-test under
 * ~150 ms. supervisor_reset_for_testing() runs between sub-tests to
 * keep the registry clean. */

#include "test/test_core.h"
#include "supervisors/legacy_mirror_supervisor.h"
#include "util/supervisor.h"
#include "util/blocker.h"
#include "json/json.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define SUP_CHECK(name, expr) do { \
    printf("supervisor: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* Test contract state for callback tracking. */
struct cb_counts {
    _Atomic int tick_calls;
    _Atomic int stall_calls;
};

static void inc_tick(struct liveness_contract *self)
{
    struct cb_counts *cc = (struct cb_counts *)self->ctx;
    if (cc) atomic_fetch_add(&cc->tick_calls, 1);
}

static void inc_stall(struct liveness_contract *self)
{
    struct cb_counts *cc = (struct cb_counts *)self->ctx;
    if (cc) atomic_fetch_add(&cc->stall_calls, 1);
}

/* Deliberately slow on_tick: blocks 150 ms (simulating a child whose tick
 * commits a SQLite transaction under IO pressure). It runs on the tick-runner
 * thread, so it must NOT freeze the sweep heartbeat. */
static void slow_tick(struct liveness_contract *self)
{
    struct cb_counts *cc = (struct cb_counts *)self->ctx;
    struct timespec ts = { 0, 150 * 1000000L };
    nanosleep(&ts, NULL);
    if (cc) atomic_fetch_add(&cc->tick_calls, 1);
}

/* Process-wide stall-observer probe (the supervisor_set_stall_observer
 * seam used by the ops.debug.bundle auto-capture). */
static _Atomic int  g_obs_calls;
static char         g_obs_name[SUPERVISOR_NAME_MAX];
static _Atomic int  g_obs_reason;

static void obs_stall(const char *child_name,
                      enum supervisor_stall_reason reason)
{
    atomic_fetch_add(&g_obs_calls, 1);
    snprintf(g_obs_name, sizeof(g_obs_name), "%s",
             child_name ? child_name : "");
    atomic_store(&g_obs_reason, (int)reason);
}

/* Restart-policy probe: a fake worker whose on_respawn just records the call.
 * When `redie` is set, it re-marks the worker EXITED (simulates a worker that
 * dies again immediately) so the storm cap can be exercised deterministically
 * without real threads or real time. */
struct restart_probe {
    _Atomic int  respawn_calls;
    _Atomic int  stall_calls;
    _Atomic bool redie;
};

static bool probe_respawn(struct liveness_contract *self)
{
    struct restart_probe *p = (struct restart_probe *)self->ctx;
    if (!p) return true;
    atomic_fetch_add(&p->respawn_calls, 1);
    /* Mimic a real worker: on a successful respawn the fresh worker publishes
     * its own state on entry — ALIVE normally, or EXITED if it dies at once
     * (redie, to exercise the storm cap). The supervisor holds RESTARTING while
     * on_respawn runs and never writes ALIVE itself. */
    atomic_store(&self->worker_state,
                 atomic_load(&p->redie) ? SUPERVISOR_WORKER_EXITED
                                        : SUPERVISOR_WORKER_ALIVE);
    return true;   /* handled */
}

static void probe_stall(struct liveness_contract *self)
{
    struct restart_probe *p = (struct restart_probe *)self->ctx;
    if (p) atomic_fetch_add(&p->stall_calls, 1);
}

int test_supervisor(void)
{
    printf("\n=== supervisor tests ===\n");
    int failures = 0;

    /* ── liveness_contract_init basics ──────────────────────────── */
    {
        struct liveness_contract c;
        liveness_contract_init(&c, "alpha");
        SUP_CHECK("init sets name", strcmp(c.name, "alpha") == 0);
        SUP_CHECK("init sets parent -1", c.parent == -1);
        SUP_CHECK("init clears stall_reason",
            atomic_load(&c.stall_reason) == SUPERVISOR_STALL_NONE);
        SUP_CHECK("init clears ticks_run", atomic_load(&c.ticks_run) == 0u);

        /* Name truncation. */
        char long_name[SUPERVISOR_NAME_MAX + 32];
        memset(long_name, 'x', sizeof(long_name));
        long_name[sizeof(long_name) - 1] = '\0';
        struct liveness_contract c2;
        liveness_contract_init(&c2, long_name);
        SUP_CHECK("init truncates over-long name",
            strlen(c2.name) == SUPERVISOR_NAME_MAX - 1);
        SUP_CHECK("init NULL name is safe (empty)",
            (liveness_contract_init(&c2, NULL), c2.name[0] == '\0'));
    }

    /* ── stall reason naming ────────────────────────────────────── */
    SUP_CHECK("reason_name(NONE)",
        strcmp(supervisor_stall_reason_name(SUPERVISOR_STALL_NONE),
               "none") == 0);
    SUP_CHECK("reason_name(TIME_DEADLINE)",
        strcmp(supervisor_stall_reason_name(SUPERVISOR_STALL_TIME_DEADLINE),
               "time_deadline") == 0);
    SUP_CHECK("reason_name(NO_PROGRESS)",
        strcmp(supervisor_stall_reason_name(SUPERVISOR_STALL_NO_PROGRESS),
               "no_progress") == 0);
    SUP_CHECK("reason_name(invalid) -> (invalid)",
        strcmp(supervisor_stall_reason_name((enum supervisor_stall_reason)99),
               "(invalid)") == 0);

    /* Optional legacy dependencies are advisory. Prove their failure policy
     * is bounded without clocks, sockets, or a live zclassicd. */
    SUP_CHECK("legacy retry uses base while healthy",
        legacy_mirror_supervisor_backoff_secs(3, 0) == 3);
    SUP_CHECK("legacy retry backs off exponentially",
        legacy_mirror_supervisor_backoff_secs(3, 1) == 6 &&
        legacy_mirror_supervisor_backoff_secs(3, 4) == 48);
    SUP_CHECK("legacy retry caps at five minutes",
        legacy_mirror_supervisor_backoff_secs(3, 1000) == 300 &&
        legacy_mirror_supervisor_backoff_secs(600, 0) == 300);
    SUP_CHECK("legacy stall diagnostics retain first and powers of two",
        legacy_mirror_supervisor_should_emit_stall(1) &&
        legacy_mirror_supervisor_should_emit_stall(2) &&
        !legacy_mirror_supervisor_should_emit_stall(3) &&
        legacy_mirror_supervisor_should_emit_stall(1024));
    SUP_CHECK("legacy stall diagnostics reject zero",
        !legacy_mirror_supervisor_should_emit_stall(0));

    /* ── register / unregister ──────────────────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract a;
        static struct liveness_contract b;
        liveness_contract_init(&a, "reg.a");
        liveness_contract_init(&b, "reg.b");

        supervisor_child_id ida = supervisor_register(&a);
        supervisor_child_id idb = supervisor_register(&b);
        SUP_CHECK("register returns >=0 for a", ida >= 0);
        SUP_CHECK("register returns >=0 for b", idb >= 0);
        SUP_CHECK("ids are distinct", ida != idb);

        /* Duplicate name rejection. */
        static struct liveness_contract dup;
        liveness_contract_init(&dup, "reg.a");
        supervisor_child_id id_dup = supervisor_register(&dup);
        SUP_CHECK("duplicate name rejected",
            id_dup == SUPERVISOR_INVALID_ID);

        /* NULL pointer rejected. */
        supervisor_child_id id_null = supervisor_register(NULL);
        SUP_CHECK("NULL contract rejected",
            id_null == SUPERVISOR_INVALID_ID);

        supervisor_unregister(ida);
        supervisor_unregister(idb);
    }

    /* ── unregister keeps every surviving id valid ──────────────────
     * The file-service restart pattern (register wkr, server, manifest;
     * retire server, manifest, wkr; start again) used to orphan the
     * manifest entry: unregister moved the last child into the freed
     * slot, so the moved owner's cached id went stale, its retire
     * missed, and the next start failed with a duplicate-name FAIL.
     * Retire a MIDDLE child, retire the moved one by its (unchanged)
     * id, then re-register the same name: it must succeed, and the
     * survivor must still answer on its original id. */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract ra, rb, rc;
        liveness_contract_init(&ra, "re.a");
        liveness_contract_init(&rb, "re.b");
        liveness_contract_init(&rc, "re.c");

        supervisor_child_id ida = supervisor_register(&ra);
        supervisor_child_id idb = supervisor_register(&rb);
        supervisor_child_id idc = supervisor_register(&rc);
        SUP_CHECK("re-register pattern: three registered",
            ida >= 0 && idb >= 0 && idc >= 0);

        supervisor_unregister(idb);
        supervisor_unregister(idc);
        /* The survivor answers on its original id (no silent move). */
        supervisor_tick(ida);
        SUP_CHECK("survivor keeps its id after a middle unregister",
            atomic_load(&ra.ticks_run) == 1u);

        static struct liveness_contract rc2;
        liveness_contract_init(&rc2, "re.c");
        supervisor_child_id idc2 = supervisor_register(&rc2);
        SUP_CHECK("retired name re-registers cleanly (no duplicate FAIL)",
            idc2 >= 0);

        supervisor_unregister(ida);
        supervisor_unregister(idc2);
        SUP_CHECK("registry drains back to empty",
            supervisor_child_headroom() == SUPERVISOR_CAP);
    }

    /* ── registry capacity ───────────────────────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract pool[SUPERVISOR_CAP + 4];
        for (int i = 0; i < SUPERVISOR_CAP; i++) {
            char nm[SUPERVISOR_NAME_MAX];
            snprintf(nm, sizeof(nm), "cap.%d", i);
            liveness_contract_init(&pool[i], nm);
            supervisor_child_id id = supervisor_register(&pool[i]);
            if (id < 0) { failures++; break; }
        }
        /* One more should fail. */
        liveness_contract_init(&pool[SUPERVISOR_CAP], "cap.overflow");
        supervisor_child_id over =
            supervisor_register(&pool[SUPERVISOR_CAP]);
        SUP_CHECK("registry rejects past capacity",
            over == SUPERVISOR_INVALID_ID);
    }

    /* ── tick monotonicity + ticks_run counter ──────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "tick.basic");
        supervisor_child_id id = supervisor_register(&c);
        SUP_CHECK("tick register ok", id >= 0);

        uint32_t before = atomic_load(&c.ticks_run);
        supervisor_tick(id);
        supervisor_tick(id);
        supervisor_tick(id);
        uint32_t after = atomic_load(&c.ticks_run);
        SUP_CHECK("tick increments ticks_run by 3", after - before == 3);

        /* Tick clears TIME_DEADLINE / CHILD_REPORTED stall flags. */
        atomic_store(&c.stall_reason, SUPERVISOR_STALL_TIME_DEADLINE);
        supervisor_tick(id);
        SUP_CHECK("tick clears TIME_DEADLINE stall",
            atomic_load(&c.stall_reason) == SUPERVISOR_STALL_NONE);

        atomic_store(&c.stall_reason, SUPERVISOR_STALL_CHILD_REPORTED);
        supervisor_tick(id);
        SUP_CHECK("tick clears CHILD_REPORTED stall",
            atomic_load(&c.stall_reason) == SUPERVISOR_STALL_NONE);
    }

    /* ── progress edge-rearm ─────────────────────────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "progress.basic");
        supervisor_child_id id = supervisor_register(&c);

        supervisor_progress(id, 100);
        SUP_CHECK("progress sets marker to 100",
            atomic_load(&c.progress_marker) == 100);
        supervisor_progress(id, 200);
        SUP_CHECK("progress advances to 200",
            atomic_load(&c.progress_marker) == 200);

        /* Same value is a no-op for changed_at. */
        atomic_store(&c.stall_reason, SUPERVISOR_STALL_NO_PROGRESS);
        supervisor_progress(id, 200);  /* unchanged */
        SUP_CHECK("same-value progress does NOT clear NO_PROGRESS",
            atomic_load(&c.stall_reason) == SUPERVISOR_STALL_NO_PROGRESS);

        /* A change clears NO_PROGRESS. */
        supervisor_progress(id, 201);
        SUP_CHECK("changed progress clears NO_PROGRESS",
            atomic_load(&c.stall_reason) == SUPERVISOR_STALL_NONE);
    }

    /* ── child-reported stall (rising edge only) ────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        static struct cb_counts cc = {0};
        liveness_contract_init(&c, "stall.report");
        c.ctx = &cc;
        c.on_stall = inc_stall;
        supervisor_child_id id = supervisor_register(&c);

        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
        SUP_CHECK("first report fires callback",
            atomic_load(&cc.stall_calls) == 1);

        /* Second report while stall_reason != NONE is a no-op. */
        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
        SUP_CHECK("second report (already stalled) does not re-fire",
            atomic_load(&cc.stall_calls) == 1);

        /* Tick clears, then re-fire works. */
        supervisor_tick(id);
        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
        SUP_CHECK("after tick+report, callback re-fires",
            atomic_load(&cc.stall_calls) == 2);
    }

    /* ── process-wide stall observer (ops.debug.bundle seam) ─────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        liveness_contract_init(&c, "stall.observer");
        supervisor_child_id id = supervisor_register(&c);

        atomic_store(&g_obs_calls, 0);
        g_obs_name[0] = '\0';
        atomic_store(&g_obs_reason, -1);
        supervisor_set_stall_observer(obs_stall);

        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
        SUP_CHECK("observer fired once",
            atomic_load(&g_obs_calls) == 1);
        SUP_CHECK("observer saw child name",
            strcmp(g_obs_name, "stall.observer") == 0);
        SUP_CHECK("observer saw reason",
            atomic_load(&g_obs_reason) ==
                (int)SUPERVISOR_STALL_CHILD_REPORTED);

        /* Second report while stall_reason != NONE is a no-op here too. */
        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
        SUP_CHECK("observer edge-triggered (no re-fire)",
            atomic_load(&g_obs_calls) == 1);

        /* Cleared observer: no fire (and no crash on the NULL path). */
        supervisor_set_stall_observer(NULL);
        supervisor_tick(id);
        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
        SUP_CHECK("cleared observer does not fire",
            atomic_load(&g_obs_calls) == 1);
    }

    /* ── supervisor loop drives on_tick when period_secs>0 ──────── */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);
    {
        static struct liveness_contract c;
        static struct cb_counts cc;
        memset(&cc, 0, sizeof(cc));
        liveness_contract_init(&c, "loop.tick");
        c.ctx = &cc;
        c.on_tick = inc_tick;
        atomic_store(&c.period_secs, 0);  /* 0 = use micro period below */
        supervisor_child_id id = supervisor_register(&c);
        (void)id;

        /* Configure a 0-sec period so every loop iteration triggers
         * on_tick (period_secs > 0 check uses *=1e6 microseconds, but
         * the loop also checks (now - last_tick) >= period * 1e6, so 0
         * is treated as "disabled". Use 1 second period and run the
         * loop for 1.2 s? Slow. Instead test via direct sweep:
         * supervisor_set_period to 1, then bypass time by manipulating
         * last_tick. Simpler: assert the supervisor thread starts and
         * dispatches at least once when period is reachable. */
        SUP_CHECK("supervisor_start succeeds", supervisor_start());

        /* Backdate last_tick by 2 seconds so a period_secs=1 will fire
         * on next sweep (~5 ms away). */
        atomic_store(&c.last_tick_us,
            atomic_load(&c.last_tick_us) - 2000000);
        atomic_store(&c.period_secs, 1);

        sleep_ms(80);  /* allow ≥10 sweeps */
        SUP_CHECK("on_tick fired at least once",
            atomic_load(&cc.tick_calls) >= 1);
        SUP_CHECK("ticks_run advanced",
            atomic_load(&c.ticks_run) >= 1u);

        supervisor_stop();
    }

    /* Explicit event wake bypasses the periodic cadence. */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(1000);
    {
        static struct liveness_contract c;
        static struct cb_counts cc;
        memset(&cc, 0, sizeof(cc));
        liveness_contract_init(&c, "loop.event_wake");
        c.ctx = &cc;
        c.on_tick = inc_tick;
        supervisor_child_id id = supervisor_register(&c);
        SUP_CHECK("event-wake register ok", id >= 0);
        SUP_CHECK("supervisor_start succeeds (event wake)",
                  supervisor_start());
        supervisor_request_tick(id);
        sleep_ms(80);
        SUP_CHECK("event wake fires before one-second period",
                  atomic_load(&cc.tick_calls) == 1);
        supervisor_stop();
    }

    /* ── deadline triggers on_stall once (edge-triggered) ───────── */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);
    {
        static struct liveness_contract c;
        static struct cb_counts cc;
        memset(&cc, 0, sizeof(cc));
        liveness_contract_init(&c, "loop.deadline");
        c.ctx = &cc;
        c.on_stall = inc_stall;
        atomic_store(&c.deadline_secs, 1);
        supervisor_child_id id = supervisor_register(&c);
        (void)id;

        /* Backdate last_tick by 5 s so deadline fires next sweep. */
        atomic_store(&c.last_tick_us,
            atomic_load(&c.last_tick_us) - 5000000);

        SUP_CHECK("supervisor_start succeeds", supervisor_start());
        sleep_ms(80);
        SUP_CHECK("deadline fires on_stall exactly once",
            atomic_load(&cc.stall_calls) == 1);
        SUP_CHECK("stall_reason = TIME_DEADLINE",
            atomic_load(&c.stall_reason) ==
                SUPERVISOR_STALL_TIME_DEADLINE);
        SUP_CHECK("stall_fires counter advanced",
            atomic_load(&c.stall_fires) == 1u);

        /* Further sweeps must NOT re-fire (edge-once). */
        sleep_ms(80);
        SUP_CHECK("deadline stall does not re-fire while still stalled",
            atomic_load(&cc.stall_calls) == 1);

        supervisor_stop();
    }

    /* ── progress-frozen triggers on_stall ──────────────────────── */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);
    {
        static struct liveness_contract c;
        static struct cb_counts cc;
        memset(&cc, 0, sizeof(cc));
        liveness_contract_init(&c, "loop.progress_frozen");
        c.ctx = &cc;
        c.on_stall = inc_stall;
        /* No deadline; only progress check. */
        atomic_store(&c.progress_max_quiet_us, 500000);  /* 0.5 s */
        supervisor_child_id id = supervisor_register(&c);
        (void)id;

        /* Backdate progress_changed_at by 2 s. */
        atomic_store(&c.progress_changed_at_us,
            atomic_load(&c.progress_changed_at_us) - 2000000);

        SUP_CHECK("supervisor_start succeeds (progress test)",
            supervisor_start());
        sleep_ms(80);
        SUP_CHECK("frozen progress fires on_stall",
            atomic_load(&cc.stall_calls) == 1);
        SUP_CHECK("stall_reason = NO_PROGRESS",
            atomic_load(&c.stall_reason) ==
                SUPERVISOR_STALL_NO_PROGRESS);

        supervisor_stop();
    }

    /* ── completed child is no longer stall-monitorable ──────────── */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);
    {
        static struct liveness_contract c;
        static struct cb_counts cc;
        memset(&cc, 0, sizeof(cc));
        liveness_contract_init(&c, "loop.completed");
        c.ctx = &cc;
        c.on_stall = inc_stall;
        atomic_store(&c.deadline_secs, 1);
        atomic_store(&c.progress_max_quiet_us, 500000);
        supervisor_child_id id = supervisor_register(&c);
        SUP_CHECK("completed child register ok", id >= 0);

        supervisor_child_complete(id);
        atomic_store(&c.last_tick_us,
            atomic_load(&c.last_tick_us) - 5000000);
        atomic_store(&c.progress_changed_at_us,
            atomic_load(&c.progress_changed_at_us) - 2000000);

        SUP_CHECK("complete disables deadline",
            atomic_load(&c.deadline_secs) == 0);
        SUP_CHECK("complete marks child completed",
            atomic_load(&c.completed));
        SUP_CHECK("supervisor_start succeeds (complete test)",
            supervisor_start());
        sleep_ms(80);
        SUP_CHECK("completed child does not fire on_stall",
            atomic_load(&cc.stall_calls) == 0);
        SUP_CHECK("completed child keeps stall_reason NONE",
            atomic_load(&c.stall_reason) == SUPERVISOR_STALL_NONE);
        SUP_CHECK("completed child stall_fires stays 0",
            atomic_load(&c.stall_fires) == 0u);

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        SUP_CHECK("completed child remains introspectable", n == 1);
        SUP_CHECK("snapshot marks child completed",
            n == 1 && snaps[0].completed);

        supervisor_stop();
    }

    /* ── lifecycle: start idempotency + stop without start ──────── */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);
    {
        SUP_CHECK("supervisor_stop without start is safe",
            (supervisor_stop(), true));
        SUP_CHECK("first start returns true", supervisor_start());
        SUP_CHECK("second start returns true (idempotent)",
            supervisor_start());
        supervisor_stop();
        SUP_CHECK("stop+start cycle works",
            (supervisor_start() && (supervisor_stop(), true)));
    }

    /* ── snapshot_all + dump_state_json shape ───────────────────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract one;
        static struct liveness_contract two;
        liveness_contract_init(&one, "snap.one");
        liveness_contract_init(&two, "snap.two");
        atomic_store(&one.period_secs,   30);
        atomic_store(&one.deadline_secs, 120);
        atomic_store(&two.period_secs,   60);
        supervisor_child_id ida = supervisor_register(&one);
        supervisor_child_id idb = supervisor_register(&two);
        (void)ida; (void)idb;

        supervisor_tick(ida);
        supervisor_progress(ida, 42);

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        SUP_CHECK("snapshot returns 2 children", n == 2);
        bool found_one = false, found_two = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].name, "snap.one") == 0) {
                found_one = true;
                if (snaps[i].progress_marker != 42) failures++;
                if (snaps[i].period_secs != 30)    failures++;
                if (snaps[i].deadline_secs != 120) failures++;
            }
            if (strcmp(snaps[i].name, "snap.two") == 0)
                found_two = true;
        }
        SUP_CHECK("snapshot includes snap.one with fields", found_one);
        SUP_CHECK("snapshot includes snap.two", found_two);

        /* JSON dump shape. */
        struct json_value v;
        json_init(&v);
        SUP_CHECK("dump_state_json returns true",
            supervisor_dump_state_json(&v, NULL));
        const struct json_value *count = json_get(&v, "child_count");
        SUP_CHECK("dump has child_count=2",
            count && json_get_int(count) == 2);
        /* After the supervisor tree split, children registered without a
         * domain appear in root_orphans[], not the top-level children[]
         * key (which no longer exists). */
        const struct json_value *kids = json_get(&v, "root_orphans");
        SUP_CHECK("dump has root_orphans array of size 2",
            kids && json_size(kids) == 2);
        json_free(&v);
    }

    /* ── restart policy: names + default is TEMPORARY ───────────────── */
    SUP_CHECK("policy_name(TEMPORARY)",
        strcmp(supervisor_restart_policy_name(SUPERVISOR_RESTART_TEMPORARY),
               "temporary") == 0);
    SUP_CHECK("policy_name(TRANSIENT)",
        strcmp(supervisor_restart_policy_name(SUPERVISOR_RESTART_TRANSIENT),
               "transient") == 0);
    SUP_CHECK("policy_name(PERMANENT)",
        strcmp(supervisor_restart_policy_name(SUPERVISOR_RESTART_PERMANENT),
               "permanent") == 0);
    {
        struct liveness_contract c;
        liveness_contract_init(&c, "policy.default");
        SUP_CHECK("init defaults restart_policy to TEMPORARY",
            atomic_load(&c.restart_policy) == SUPERVISOR_RESTART_TEMPORARY);
        SUP_CHECK("init defaults worker_state to UNKNOWN",
            atomic_load(&c.worker_state) == SUPERVISOR_WORKER_UNKNOWN);
    }

    /* ── TEMPORARY child that dies stays dead (current behavior) ─────── */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        static struct restart_probe p;
        memset(&p, 0, sizeof p);
        liveness_contract_init(&c, "restart.temporary");
        c.ctx = &p;
        c.on_respawn = probe_respawn;      /* present, but policy is TEMPORARY */
        supervisor_child_id id = supervisor_register(&c);
        supervisor_worker_alive(id);
        supervisor_worker_exited(id);      /* the worker dies */
        supervisor_sweep_once_for_testing();
        SUP_CHECK("TEMPORARY child is never respawned",
            atomic_load(&p.respawn_calls) == 0);
        SUP_CHECK("TEMPORARY dead worker stays EXITED",
            atomic_load(&c.worker_state) == SUPERVISOR_WORKER_EXITED);
        SUP_CHECK("TEMPORARY restart_count stays 0",
            atomic_load(&c.restart_count) == 0u);
    }

    /* ── PERMANENT child that dies is respawned (once, then left alive) ─ */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        static struct restart_probe p;
        memset(&p, 0, sizeof p);
        liveness_contract_init(&c, "restart.permanent");
        c.ctx = &p;
        c.on_respawn = probe_respawn;
        supervisor_child_id id = supervisor_register(&c);
        supervisor_set_restart_policy(id, SUPERVISOR_RESTART_PERMANENT,
                                      /*N=*/5, /*M_secs=*/60);
        supervisor_worker_alive(id);

        supervisor_sweep_once_for_testing();     /* healthy: no respawn */
        SUP_CHECK("PERMANENT alive worker is not respawned",
            atomic_load(&p.respawn_calls) == 0);

        supervisor_worker_exited(id);            /* the worker dies */
        supervisor_sweep_once_for_testing();
        SUP_CHECK("PERMANENT dead worker is respawned once",
            atomic_load(&p.respawn_calls) == 1);
        SUP_CHECK("respawn marks the worker ALIVE again",
            atomic_load(&c.worker_state) == SUPERVISOR_WORKER_ALIVE);
        SUP_CHECK("restart_count advanced to 1",
            atomic_load(&c.restart_count) == 1u);

        supervisor_sweep_once_for_testing();     /* alive again: no re-respawn */
        SUP_CHECK("no double-respawn while the worker is alive",
            atomic_load(&p.respawn_calls) == 1);
    }

    /* ── restart storm: N+1 deaths in the window → give up + name blocker ─ */
    supervisor_reset_for_testing();
    {
        static struct liveness_contract c;
        static struct restart_probe p;
        memset(&p, 0, sizeof p);
        atomic_store(&p.redie, true);        /* every respawn re-dies at once */
        liveness_contract_init(&c, "restart.storm");
        c.ctx = &p;
        c.on_respawn = probe_respawn;
        c.on_stall   = probe_stall;
        supervisor_child_id id = supervisor_register(&c);
        /* Huge window so all deaths fall inside it — deterministic, no clock. */
        supervisor_set_restart_policy(id, SUPERVISOR_RESTART_PERMANENT,
                                      /*N=*/3, /*M_secs=*/3600);
        supervisor_worker_alive(id);
        supervisor_worker_exited(id);        /* first death */

        for (int i = 0; i < 10; i++) supervisor_sweep_once_for_testing();

        SUP_CHECK("storm caps respawns at intensity_max (3)",
            atomic_load(&p.respawn_calls) == 3);
        SUP_CHECK("storm reaches restart_count == cap",
            atomic_load(&c.restart_count) == 3u);
        SUP_CHECK("storm sets REPEATED_RESTART stall reason",
            atomic_load(&c.stall_reason) ==
                SUPERVISOR_STALL_REPEATED_RESTART);
        SUP_CHECK("storm fires on_stall exactly once (sticky, no re-fire)",
            atomic_load(&p.stall_calls) == 1);
        SUP_CHECK("storm stops respawning after escalation",
            atomic_load(&p.respawn_calls) == 3);
    }

    /* ── slow on_tick runs on the RUNNER, not the sweep ─────────────────
     * The regression this whole lane exists for: a child whose on_tick blocks
     * (SQLite commit → fsync → jbd2_log_wait_commit under IO pressure) must NOT
     * freeze the sweep heartbeat and get a healthy node killed by the backstop.
     * With the tick-runner thread the sweep keeps heartbeating while the slow
     * tick runs elsewhere. */
    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);
    {
        static struct liveness_contract c;
        static struct cb_counts cc;
        memset(&cc, 0, sizeof(cc));
        liveness_contract_init(&c, "loop.slow_tick");
        c.ctx = &cc;
        c.on_tick = slow_tick;             /* blocks 150 ms */
        supervisor_child_id id = supervisor_register(&c);
        (void)id;

        SUP_CHECK("supervisor_start succeeds (slow tick)", supervisor_start());
        /* Make the child due so the runner picks it up promptly. */
        atomic_store(&c.last_tick_us, atomic_load(&c.last_tick_us) - 2000000);
        atomic_store(&c.period_secs, 1);

        sleep_ms(30);                       /* let the runner ENTER slow_tick */
        SUP_CHECK("active callback names the blocking child",
            strcmp(supervisor_active_callback_name(), "loop.slow_tick") == 0);
        uint64_t hb0 = supervisor_sweep_heartbeat();
        sleep_ms(120);                      /* runner still inside the 150ms tick */
        uint64_t hb1 = supervisor_sweep_heartbeat();
        SUP_CHECK("sweep heartbeat keeps advancing while a child tick blocks",
            hb1 - hb0 >= 3);

        sleep_ms(150);                      /* let the slow tick finish */
        SUP_CHECK("slow on_tick actually executed on the runner",
            atomic_load(&cc.tick_calls) >= 1);
        SUP_CHECK("active callback clears after the child returns",
            strcmp(supervisor_active_callback_name(), "none") == 0);
        SUP_CHECK("runner thread is alive", supervisor_tick_runner_running());
        supervisor_stop();
    }

    /* ── a wedged tick-runner becomes a NAMED blocker (edge-triggered) ─────
     * A child on_tick that never returns freezes the runner heartbeat. The
     * sweep detects the lapse and names supervisor.tick_runner_wedged — a
     * blocker, never a dead node. Recovery clears it. */
    supervisor_reset_for_testing();
    blocker_reset_for_testing();
    {
        supervisor_tick_runner_setup_for_testing(/*deadline_secs=*/1);
        supervisor_tick_runner_backdate_hb_for_testing(5000000);  /* 5 s ago */
        uint32_t fires0 = supervisor_tick_runner_stall_fires();

        supervisor_tick_runner_monitor_for_testing();
        SUP_CHECK("wedged runner fires stall exactly once",
            supervisor_tick_runner_stall_fires() - fires0 == 1);
        SUP_CHECK("wedged runner names supervisor.tick_runner_wedged blocker",
            blocker_exists("supervisor.tick_runner_wedged"));

        /* Sticky edge: a second monitor pass while still wedged does not re-fire. */
        supervisor_tick_runner_monitor_for_testing();
        SUP_CHECK("wedged runner stall is sticky (no re-fire)",
            supervisor_tick_runner_stall_fires() - fires0 == 1);

        /* Recovery: a fresh heartbeat within the deadline clears the blocker. */
        supervisor_tick_runner_backdate_hb_for_testing(0);
        supervisor_tick_runner_monitor_for_testing();
        SUP_CHECK("runner heartbeat resumes -> blocker cleared",
            !blocker_exists("supervisor.tick_runner_wedged"));

        blocker_reset_for_testing();
    }

    /* Restore default tick period for any later tests. */
    supervisor_set_tick_ms_for_testing(1000);
    supervisor_reset_for_testing();
    return failures;
}
