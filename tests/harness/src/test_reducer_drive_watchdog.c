/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the reducer_drive_watchdog condition (Lane 0.3) + the
 * "reducer_drive" dumpstate subsystem it owns (Lane 0.4).
 *
 * The condition compares two consecutive detect() ticks of the (test-
 * injected) utxo_apply cursor once the drive has been active longer than
 * a (test-forced) threshold. condition_tick_one() gates a NOT-YET-active
 * condition's detect() calls by real wall-clock poll_secs, so this test
 * installs the same fake clock_iface_t the sync_watchdog condition tests
 * use to advance wall time without sleeping. reducer_drive_age_us() itself
 * reads GetTimeMicros() (real time, not the fake clock — see
 * core/modules/core/src/utiltime.c), so a short real nanosleep is used to get a
 * nonzero age; the forced threshold of 0s means any nonzero age trips it.
 */

#include "test/test_core.h"

#include "conditions/batch_fsync_slow.h"
#include "conditions/reducer_drive_watchdog.h"
#include "framework/condition.h"
#include "json/json.h"
#include "platform/clock.h"
#include "services/reducer_drain.h"
#include "services/reducer_ingest_service.h"
#include "services/sticky_escalator.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/reducer_drive_guard.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define RDW_CHECK(name, expr) do { \
    printf("reducer_drive_watchdog: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct rdw_fake_clock {
    _Atomic int64_t wall_ms;
};

static int64_t rdw_fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t rdw_fake_now_wall(void *self)
{
    struct rdw_fake_clock *c = (struct rdw_fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

static void rdw_fake_clock_install(struct rdw_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    static clock_iface_t iface;
    iface.now_monotonic_ns = rdw_fake_now_mono;
    iface.now_wall_ms = rdw_fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void rdw_fake_clock_set(struct rdw_fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
}

/* A few ms of REAL sleep so reducer_drive_age_us() (GetTimeMicros(), not the
 * fake clock) reports a nonzero age. */
static void rdw_real_nap(void)
{
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 3 * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

static void rdw_reset(void)
{
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    reducer_drive_watchdog_test_reset();
    sticky_escalator_test_reset();
    /* reducer_drive_guard has no test-reset hook of its own (it is a bare
     * enter/exit counter) — make sure no earlier test group left a drive
     * "active" behind by forcing it fully closed. */
    while (reducer_drive_active())
        reducer_drive_exit();
    /* register_reducer_drive_watchdog re-registers the blocker escape after
     * blocker_reset_for_testing() wiped the escape registry above. */
    register_reducer_drive_watchdog();
}

static void rdw_cleanup(void)
{
    while (reducer_drive_active())
        reducer_drive_exit();
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    reducer_drive_watchdog_test_reset();
    sticky_escalator_test_reset();
    clock_reset_default();
}

int test_reducer_drive_watchdog(void);
int test_reducer_drive_watchdog(void)
{
    printf("\n=== reducer_drive_watchdog condition + dumpstate tests ===\n");
    int failures = 0;
    struct rdw_fake_clock fc;
    int64_t t0 = 2000000000;

    /* ---- (a) injected spin: detect fires + blocker named ---- */
    {
        rdw_reset();
        rdw_fake_clock_install(&fc, t0);
        reducer_drive_watchdog_test_set_threshold_secs(0);
        reducer_drive_watchdog_test_set_cursor_override(100);

        reducer_drive_enter_labeled("test_drive");
        rdw_real_nap();

        condition_engine_tick(); /* tick 1: baseline only, cursor=100 */
        bool ok = true;
        ok = ok && reducer_drive_watchdog_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        RDW_CHECK("baseline tick does not trip", ok);

        rdw_fake_clock_set(&fc, t0 + 20); /* clear the poll_secs gate */
        condition_engine_tick(); /* tick 2: cursor still 100 -> trip + remedy */

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_drive_watchdog", &snap);
        bool ok2 = true;
        ok2 = ok2 && reducer_drive_watchdog_test_remedy_calls() == 1;
        ok2 = ok2 && condition_engine_get_active_count() == 1;
        ok2 = ok2 && got && snap.currently_active;
        ok2 = ok2 && blocker_exists("reducer_drive_stuck");
        RDW_CHECK("frozen cursor across two ticks trips + fires remedy once",
                 ok2);

        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        bool found_reason = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "reducer_drive_stuck") == 0 &&
                strstr(snaps[i].reason, "test_drive") != NULL) {
                found_reason = true;
                break;
            }
        }
        RDW_CHECK("blocker detail names the driver label", found_reason);

        /* ---- (a2) ACT (Pillar 1): the blocker carries a deadline-gated
         * escape, and blocker_supervisor_sweep() ACTUATES it into the recovery
         * ladder once the deadline lapses — not just a named blocker. ---- */
        bool esc_wired = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "reducer_drive_stuck") == 0) {
                esc_wired = strcmp(snaps[i].escape_action,
                                   "reducer_drive_ladder_kick") == 0 &&
                            snaps[i].escape_deadline_us > 0;
                break;
            }
        }
        RDW_CHECK("blocker arms a deadline-gated ladder-kick escape", esc_wired);

        bool armed_before = sticky_escalator_test_armed();
        int dispatched_before = blocker_escape_dispatched_count();
        /* Push the blocker's monotonic clock past the escape deadline (60s) so
         * the sweep fires the escape edge. Then restore the real clock so the
         * later sub-tests are unaffected. */
        blocker_advance_clock_for_testing(70LL * 1000 * 1000);
        int fired = blocker_supervisor_sweep();
        bool ok_escape = !armed_before &&
                         fired >= 1 &&
                         blocker_escape_dispatched_count() > dispatched_before &&
                         sticky_escalator_test_armed();
        blocker_set_clock_for_testing(0);
        RDW_CHECK("deadline sweep actuates the escape -> ARMS the ladder",
                 ok_escape);

        /* ---- (b) cursor movement clears it ---- */
        reducer_drive_watchdog_test_set_cursor_override(101);
        rdw_fake_clock_set(&fc, t0 + 40);
        condition_engine_tick(); /* cursor advanced past frozen -> witness clears */

        bool ok3 = true;
        ok3 = ok3 && !blocker_exists("reducer_drive_stuck");
        ok3 = ok3 && condition_engine_get_active_count() == 0;
        struct condition_runtime_snapshot snap3;
        bool got3 = condition_engine_get_registered_snapshot(
            "reducer_drive_watchdog", &snap3);
        ok3 = ok3 && got3 && snap3.cleared_count == 1;
        RDW_CHECK("cursor advance past the frozen height clears the blocker",
                 ok3);

        /* ---- (c) drive exit clears it (re-trip first) ---- */
        reducer_drive_watchdog_test_set_cursor_override(200);
        rdw_fake_clock_set(&fc, t0 + 60);
        condition_engine_tick(); /* baseline reset to 200, no trip */
        rdw_fake_clock_set(&fc, t0 + 80);
        condition_engine_tick(); /* cursor unchanged -> re-trip */

        bool ok4 = true;
        ok4 = ok4 && blocker_exists("reducer_drive_stuck");
        ok4 = ok4 && condition_engine_get_active_count() == 1;
        RDW_CHECK("re-trip after a fresh frozen cursor", ok4);

        reducer_drive_exit();
        rdw_fake_clock_set(&fc, t0 + 100);
        condition_engine_tick(); /* drive inactive -> witness clears */

        bool ok5 = true;
        ok5 = ok5 && !blocker_exists("reducer_drive_stuck");
        ok5 = ok5 && condition_engine_get_active_count() == 0;
        ok5 = ok5 && !reducer_drive_active();
        RDW_CHECK("drive exit clears the blocker", ok5);
    }

    /* ---- (d) dumpstate subsystem ---- */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "reducer_drive_dump", "d");
        bool ok = progress_store_open(dir);
        RDW_CHECK("dump: progress_store opens", ok);

        if (ok) {
            sqlite3 *db = progress_store_db();
            char *err = NULL;
            bool seeded =
                sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                    SQLITE_OK &&
                coins_kv_set_applied_height_in_tx(db, 4242) &&
                sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
            if (err) sqlite3_free(err);
            RDW_CHECK("dump: seed coins_applied_height", seeded);

            struct json_value v;
            json_init(&v);
            bool dumped = reducer_drive_dump_state_json(&v, NULL);
            bool okd = true;
            okd = okd && dumped;
            okd = okd && json_get(&v, "active") != NULL;
            okd = okd && json_get_bool(json_get(&v, "active")) == false;
            okd = okd && json_get(&v, "label") != NULL;
            okd = okd && json_get(&v, "age_us") != NULL;
            okd = okd && json_get(&v, "watchdog_threshold_secs") != NULL;
            okd = okd && json_get_int(
                json_get(&v, "watchdog_threshold_secs")) == 0;
            okd = okd && json_get(&v, "last_watchdog_fire_unix") != NULL;
            okd = okd &&
                  json_get_int(json_get(&v, "last_watchdog_fire_unix")) > 0;
            okd = okd && json_get(&v, "utxo_apply_cursor") != NULL;
            okd = okd &&
                  json_get_int(json_get(&v, "utxo_apply_cursor")) == 200;
            okd = okd && json_get(&v, "coins_applied_read_ok") != NULL;
            okd = okd && json_get_bool(
                json_get(&v, "coins_applied_read_ok")) == true;
            okd = okd && json_get(&v, "coins_applied_height") != NULL;
            okd = okd &&
                  json_get_int(json_get(&v, "coins_applied_height")) == 4242;
            RDW_CHECK("dump emits all documented fields with live values",
                     okd);

            /* Drive+fsync telemetry (Gap 1 + Gap 2): the four drain-exit
             * counters and the two fsync-timing fields are always emitted
             * (even before anything has ever been observed — 0 is a valid,
             * present value), unlike stage_spin which is omitted entirely
             * when empty. */
            bool okt = true;
            okt = okt && json_get(&v, "drain_exit_converged_total") != NULL;
            okt = okt && json_get(&v, "drain_exit_budget_total") != NULL;
            okt = okt && json_get(&v, "drain_last_round_advances") != NULL;
            okt = okt && json_get(&v, "drain_last_elapsed_us") != NULL;
            const struct json_value *stage_us =
                json_get(&v, "drain_last_stage_us");
            okt = okt && stage_us != NULL;
            static const char *const stage_names[] = {
                "header_admit", "validate_headers", "body_fetch", "body_persist",
                "script_validate", "proof_validate", "utxo_apply", "tip_finalize"
            };
            for (size_t i = 0; stage_us &&
                 i < sizeof(stage_names) / sizeof(stage_names[0]); i++)
                okt = okt && json_get(stage_us, stage_names[i]) != NULL;
            okt = okt && json_get(&v, "fsync_last_flush_us") != NULL;
            okt = okt && json_get(&v, "fsync_flush_us_ewma") != NULL;
            RDW_CHECK("dump carries the drain-exit + fsync-timing fields",
                     okt);

            /* Append-path attribution (storage/event_log.h): event_log_deferred
             * says which mode the log is in right now, which does not answer how
             * many appends actually paid the two-fsync price during a fold —
             * that split is the whole point of these three. All three are always
             * emitted so a before/after diff over a fold is one dump apart. */
            bool oka = true;
            oka = oka && json_get(&v, "event_log_deferred") != NULL;
            oka = oka && json_get(&v, "event_log_barrier_appends") != NULL;
            oka = oka && json_get(&v, "event_log_deferred_appends") != NULL;
            oka = oka && json_get(&v, "event_log_barrier_us_total") != NULL;
            RDW_CHECK("dump carries the event_log append-path attribution",
                      oka);
            json_free(&v);
        }

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ---- (e) drain-exit telemetry: reducer_drain.c's exit-stats snapshot
     * deconflates converged vs budget-ceiling (see reducer_drain.c's doc
     * comment). Drive the counters directly via the ZCL_TESTING reset +
     * snapshot pair — the exact break-site attribution is exercised end to
     * end by test_mint_fold_livelock (Scenario A: frontier-stall increments
     * NEITHER counter; Scenario B: a converged kick increments
     * exit_converged_total) in test_reducer_step_drain_harness.c. Here we
     * only guard the snapshot/reset plumbing itself. ---- */
    {
        reducer_drain_exit_stats_reset_for_testing();
        struct reducer_drain_exit_stats des;
        reducer_drain_exit_stats_snapshot(&des);
        bool ok = des.exit_converged_total == 0 &&
                  des.exit_budget_total == 0 &&
                  des.last_round_advances == 0 &&
                  des.last_elapsed_us == 0;
        RDW_CHECK("drain-exit stats: reset zeroes all four fields", ok);
    }

    /* ---- (f) batch_fsync_slow condition: injected slow flush trips it,
     * a raised budget clears it, and a healthy (fast, unmodified) flush
     * never false-fires. GetTimeMicros() (which the precommit timing wrap
     * uses) routes through the SAME overridable platform.clock the fake
     * wall clock above installs (clock_now_wall_ms — see
     * platform/modules/platform/include/platform/time_compat.h), so it is frozen
     * whenever that fake clock is still active — a real nanosleep would
     * measure 0us elapsed, not the injected delay. Restore the REAL clock
     * for this section so the injected-delay timing is genuine. To keep
     * each detect() a "first tick" (last_poll_unix == 0, which
     * condition_tick_one always polls regardless of poll_secs — see
     * framework/condition.c), each phase gets its OWN fresh
     * condition_engine_reset_for_testing() + re-register instead of
     * waiting out real wall-clock poll_secs between ticks: the fsync
     * timing atomics (engine/reducer/services/src/reducer_body_fsync.c) are a
     * SEPARATE module and are untouched by a condition-engine reset, so
     * the EWMA carries across phases exactly as it would across real
     * ticks. ---- */
    {
        clock_reset_default();
        blocker_module_init();
        blocker_reset_for_testing();
        reducer_body_fsync_test_reset();
        batch_fsync_slow_test_reset();

        /* (f1) healthy path: an unmodified (fast) precommit flush (no
         * pending bodies, no open event log — real work, sub-millisecond)
         * must never trip the condition. Drive the predicate against a
         * tight 10ms test budget (not just the generous 4s production
         * default), so "healthy" is proven against the SAME budget the
         * slow-flush case below uses. */
        condition_engine_reset_for_testing();
        register_batch_fsync_slow();
        batch_fsync_slow_test_set_budget_us(10000); /* 10ms */
        bool trig1 = reducer_body_fsync_test_trigger_precommit();
        condition_engine_tick();
        bool ok_healthy = trig1 && !blocker_exists("batch_fsync_slow") &&
                          condition_engine_get_active_count() == 0;
        RDW_CHECK("batch_fsync_slow: healthy fast flush does not false-fire",
                 ok_healthy);

        /* (f2) ONE injected 320ms-slow flush against the same 10ms budget
         * trips the condition on EITHER EWMA path, which is what makes this
         * deterministic. The update is
         *     next = (prev == 0) ? sample : prev + (sample - prev) / 16
         * so if f1's real flush measured exactly 0us (the "never sampled"
         * sentinel) the EWMA seeds to the full 320000us; if f1 measured any
         * non-zero time the EWMA instead damps to ~320000/16 = 20000us.
         * BOTH clear the 10ms budget, the damped path by 2x.
         * The delay must stay above 16 * budget for that to hold: an 80ms
         * injection damps to ~5000us, which is UNDER the 10ms budget, so it
         * tripped only when f1 happened to measure 0us — a coin-flip on
         * scheduling noise. A fresh engine reset + re-register gives this
         * its own "first tick" (bypasses the poll_secs gate) without a real
         * 20s wait. */
        condition_engine_reset_for_testing();
        register_batch_fsync_slow();
        batch_fsync_slow_test_set_budget_us(10000); /* 10ms, same as f1 */
        reducer_body_fsync_test_set_inject_delay_us(320 * 1000);
        bool trig2 = reducer_body_fsync_test_trigger_precommit();
        condition_engine_tick();
        bool ok_slow = trig2 && blocker_exists("batch_fsync_slow") &&
                       condition_engine_get_active_count() == 1 &&
                       batch_fsync_slow_test_remedy_calls() == 1;
        RDW_CHECK("batch_fsync_slow: injected slow flush trips the blocker",
                 ok_slow);

        {
            struct blocker_snapshot snaps[BLOCKER_CAP];
            int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
            bool found_reason = false;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].id, "batch_fsync_slow") == 0 &&
                    strstr(snaps[i].reason, "flush_us_ewma=") != NULL &&
                    strstr(snaps[i].reason, "budget_us=") != NULL) {
                    found_reason = true;
                    break;
                }
            }
            RDW_CHECK("batch_fsync_slow: blocker names the EWMA + budget",
                     found_reason);
        }

        /* (f3) raise the budget WAY above the (now-elevated) EWMA on the
         * SAME (still-active) episode — an active episode's witness is
         * checked on EVERY tick regardless of poll_secs (see
         * framework/condition.c's condition_tick_one), so no reset/clock
         * trick is needed here; this is the deterministic way to prove the
         * witness clears on a fresh read without waiting out 16 rounds of
         * 1/16 EWMA decay. */
        reducer_body_fsync_test_set_inject_delay_us(0);
        batch_fsync_slow_test_set_budget_us(60LL * 1000 * 1000); /* 60s */
        condition_engine_tick();
        bool ok_clear = !blocker_exists("batch_fsync_slow") &&
                        condition_engine_get_active_count() == 0;
        RDW_CHECK("batch_fsync_slow: budget clearing the EWMA clears "
                 "the blocker", ok_clear);

        /* dumpstate carries live fsync timing after real activity. */
        struct json_value v2;
        json_init(&v2);
        bool dumped2 = reducer_drive_dump_state_json(&v2, NULL);
        bool okd2 = dumped2 &&
            json_get(&v2, "fsync_flush_us_ewma") != NULL &&
            json_get_int(json_get(&v2, "fsync_flush_us_ewma")) > 0;
        RDW_CHECK("batch_fsync_slow: dumpstate reflects live EWMA activity",
                 okd2);
        json_free(&v2);

        batch_fsync_slow_test_reset();
        reducer_body_fsync_test_reset();
        condition_engine_reset_for_testing();
        blocker_reset_for_testing();
    }

    rdw_cleanup();

    printf("=== test_reducer_drive_watchdog complete: %d failure(s) ===\n",
           failures);
    return failures;
}
