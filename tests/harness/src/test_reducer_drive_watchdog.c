/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the reducer_drive_watchdog condition and the "reducer_drive"
 * dumpstate subsystem.
 *
 * The condition compares two consecutive detect() ticks of the injected
 * utxo_apply cursor once the drive has been active past a forced threshold.
 * A fake clock_iface_t advances wall time for condition_tick_one's poll_secs
 * gate; reducer_drive_age_us() reads real GetTimeMicros(), so a short nanosleep
 * gives a nonzero age (threshold 0s trips on any nonzero age).
 */

#include "test/test_core.h"

#include "conditions/batch_fsync_slow.h"
#include "conditions/reducer_drive_watchdog.h"
#include "framework/condition.h"
#include "jobs/catchup_cadence.h"
#include "json/json.h"
#include "net/connman.h"
#include "net/protocol.h"
#include "platform/clock.h"
#include "services/reducer_drain.h"
#include "services/reducer_ingest_service.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/reducer_drive_guard.h"
#include "util/sync.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
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
    /* reducer_drive_guard has no reset hook: force any leftover drive closed. */
    while (reducer_drive_active())
        reducer_drive_exit();
    /* Re-register the blocker escape wiped by blocker_reset_for_testing(). */
    register_reducer_drive_watchdog();
}

static bool rdw_batch_fsync_overflow_fails_closed(void)
{
    const char *old_budget = getenv("ZCL_BATCH_FSYNC_SLOW_EWMA_US");
    char *old_budget_copy = old_budget != NULL ? strdup(old_budget) : NULL;
    bool saved_budget = old_budget == NULL || old_budget_copy != NULL;
    bool env_set = saved_budget &&
                   setenv("ZCL_BATCH_FSYNC_SLOW_EWMA_US",
                          "9223372036854775808", 1) == 0;
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    batch_fsync_slow_test_reset();
    reducer_body_fsync_test_reset();
    batch_fsync_slow_test_set_budget_us(-1);
    reducer_body_fsync_test_set_inject_delay_us(5LL * 1000 * 1000);
    register_batch_fsync_slow();
    bool triggered = env_set && reducer_body_fsync_test_trigger_precommit();
    condition_engine_tick();
    bool detected = triggered && blocker_exists("batch_fsync_slow") &&
                    batch_fsync_slow_test_remedy_calls() == 1;
    reducer_body_fsync_test_set_inject_delay_us(0);
    if (old_budget_copy != NULL) {
        (void)setenv("ZCL_BATCH_FSYNC_SLOW_EWMA_US", old_budget_copy, 1);
        free(old_budget_copy);
    } else if (old_budget == NULL) {
        (void)unsetenv("ZCL_BATCH_FSYNC_SLOW_EWMA_US");
    }
    return detected;
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

/* (g) R1 catch-up round cadence: while the catch-up gate is open (peers
 * connected and network-tip gap >= ZCL_CATCHUP_GAP_THRESHOLD), the batched
 * pre-commit hook pays the body+event_log fdatasync once per
 * ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL commits (default 8) instead of per batch
 * commit, each flush keeps its exact veto verdict, and closing the gate restores
 * per-commit fsync on the next commit. Fixture mirrors test_catchup_cadence.c.
 * Separate function to stay under the cyclomatic-complexity pin; returns its
 * failure count. */
static int rdw_test_r1_cadence(void)
{
    int failures = 0;
    {
        reducer_body_fsync_test_reset();

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        zcl_mutex_init(&cm.manager.cs_nodes);
        struct p2p_node peer;
        memset(&peer, 0, sizeof(peer));
        peer.id = 1;
        peer.starting_height = 100000;
        peer.state = PEER_ACTIVE;
        peer.services = NODE_NETWORK;
        struct p2p_node *peers[1] = { &peer };
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;
        sync_monitor_set_context(&cm, NULL, NULL);
        catchup_cadence_test_set_log_head_override(0); /* gap = 100000 */
        RDW_CHECK("R1 cadence: catch-up gate opens (peers + gap >= threshold)",
                  catchup_cadence_active());

        uint64_t fc0 = 0, ft0 = 0, fc1 = 0, ft1 = 0;
        reducer_body_fsync_totals_snapshot(&fc0, &ft0);
        bool all_true = true;
        for (int i = 0; i < 8; i++)
            all_true = all_true && reducer_body_fsync_test_trigger_precommit();
        reducer_body_fsync_totals_snapshot(&fc1, &ft1);
        RDW_CHECK("R1 cadence: no commit is vetoed while the gate is open",
                  all_true);
        RDW_CHECK("R1 cadence: eight catch-up commits pay at most two "
                  "durability flushes (round cadence, default interval 8)",
                  fc1 - fc0 <= 2);

        /* Gate closes (gap shrinks under the threshold) -> the strict
         * per-commit regime is restored on the very next commits. */
        catchup_cadence_test_set_log_head_override(99600); /* gap 400 < 500 */
        RDW_CHECK("R1 cadence: gate closes as the gap shrinks",
                  !catchup_cadence_active());
        fc0 = fc1;
        all_true = true;
        for (int i = 0; i < 2; i++)
            all_true = all_true && reducer_body_fsync_test_trigger_precommit();
        reducer_body_fsync_totals_snapshot(&fc1, &ft1);
        RDW_CHECK("R1 cadence: strict per-commit regime restored at "
                  "convergence (2 commits, 2 flushes)",
                  all_true && fc1 - fc0 == 2);

        /* The interval knob is honored (and clamped): 3 -> 6 commits pay
         * exactly 2 flushes. */
        catchup_cadence_test_set_log_head_override(0);
        (void)catchup_cadence_active();
        setenv("ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL", "3", 1);
        reducer_body_fsync_test_reset();
        reducer_body_fsync_totals_snapshot(&fc0, &ft0);
        all_true = true;
        for (int i = 0; i < 6; i++)
            all_true = all_true && reducer_body_fsync_test_trigger_precommit();
        reducer_body_fsync_totals_snapshot(&fc1, &ft1);
        RDW_CHECK("R1 cadence: ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL=3 honored "
                  "(6 commits, 2 flushes)",
                  all_true && fc1 - fc0 == 2);
        unsetenv("ZCL_CATCHUP_FSYNC_COMMIT_INTERVAL");

        catchup_cadence_test_reset();
        sync_monitor_set_context(NULL, NULL, NULL);
        (void)catchup_cadence_active();  /* re-refresh the gate: closed */
        reducer_body_fsync_test_reset();
    }
    return failures;
}

enum rdw_json_kind {
    RDW_JSON_PRESENT = 0,
    RDW_JSON_BOOL_EQ,
    RDW_JSON_INT_EQ,
    RDW_JSON_INT_GT
};

struct rdw_json_expect {
    const char *key;
    enum rdw_json_kind kind;
    int64_t value;
};

static bool rdw_json_fields_match(const struct json_value *v,
                                  const struct rdw_json_expect *rows,
                                  size_t n)
{
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++) {
        switch (rows[i].kind) {
        case RDW_JSON_PRESENT:
            ok = json_get(v, rows[i].key) != NULL;
            break;
        case RDW_JSON_BOOL_EQ:
            ok = json_get_bool(json_get(v, rows[i].key)) ==
                 (rows[i].value != 0);
            break;
        case RDW_JSON_INT_EQ:
            ok = json_get_int(json_get(v, rows[i].key)) == rows[i].value;
            break;
        case RDW_JSON_INT_GT:
            ok = json_get_int(json_get(v, rows[i].key)) > rows[i].value;
            break;
        }
    }
    return ok;
}

static bool rdw_spin_baseline_quiet(struct rdw_fake_clock *fc, int64_t t0)
{
    rdw_reset();
    rdw_fake_clock_install(fc, t0);
    reducer_drive_watchdog_test_set_threshold_secs(0);
    reducer_drive_watchdog_test_set_cursor_override(100);

    reducer_drive_enter_labeled("test_drive");
    rdw_real_nap();

    condition_engine_tick(); /* tick 1: baseline only, cursor=100 */
    bool ok = true;
    ok = ok && reducer_drive_watchdog_test_remedy_calls() == 0;
    ok = ok && condition_engine_get_active_count() == 0;
    return ok;
}

static bool rdw_spin_frozen_cursor_tripped(struct rdw_fake_clock *fc,
                                           int64_t t0)
{
    rdw_fake_clock_set(fc, t0 + 20); /* clear the poll_secs gate */
    condition_engine_tick(); /* tick 2: cursor still 100 -> trip + remedy */

    struct condition_runtime_snapshot snap;
    bool got = condition_engine_get_registered_snapshot(
        "reducer_drive_watchdog", &snap);
    bool ok2 = true;
    ok2 = ok2 && reducer_drive_watchdog_test_remedy_calls() == 1;
    ok2 = ok2 && condition_engine_get_active_count() == 1;
    ok2 = ok2 && got && snap.currently_active;
    ok2 = ok2 && blocker_exists("reducer_drive_stuck");
    return ok2;
}

static bool rdw_stuck_blocker_names_test_drive(
    const struct blocker_snapshot *snaps, int n)
{
    bool found_reason = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "reducer_drive_stuck") == 0 &&
            strstr(snaps[i].reason, "test_drive") != NULL) {
            found_reason = true;
            break;
        }
    }
    return found_reason;
}

static bool rdw_stuck_blocker_arms_ladder_kick(
    const struct blocker_snapshot *snaps, int n)
{
    bool esc_wired = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "reducer_drive_stuck") == 0) {
            esc_wired = strcmp(snaps[i].escape_action,
                               "reducer_drive_ladder_kick") == 0 &&
                        snaps[i].escape_deadline_us > 0;
            break;
        }
    }
    return esc_wired;
}

static bool rdw_escape_sweep_arms_ladder(void)
{
    bool armed_before = sticky_escalator_test_armed();
    int dispatched_before = blocker_escape_dispatched_count();
    /* Push the blocker clock past the 60s escape deadline so the sweep fires,
     * then restore the real clock. */
    blocker_advance_clock_for_testing(70LL * 1000 * 1000);
    int fired = blocker_supervisor_sweep();
    bool ok_escape = !armed_before &&
                     fired >= 1 &&
                     blocker_escape_dispatched_count() > dispatched_before &&
                     sticky_escalator_test_armed();
    blocker_set_clock_for_testing(0);
    return ok_escape;
}

static bool rdw_cursor_advance_cleared(struct rdw_fake_clock *fc, int64_t t0)
{
    reducer_drive_watchdog_test_set_cursor_override(101);
    rdw_fake_clock_set(fc, t0 + 40);
    condition_engine_tick(); /* cursor advanced past frozen -> witness clears */

    bool ok3 = true;
    ok3 = ok3 && !blocker_exists("reducer_drive_stuck");
    ok3 = ok3 && condition_engine_get_active_count() == 0;
    struct condition_runtime_snapshot snap3;
    bool got3 = condition_engine_get_registered_snapshot(
        "reducer_drive_watchdog", &snap3);
    ok3 = ok3 && got3 && snap3.cleared_count == 1;
    return ok3;
}

static bool rdw_fresh_frozen_cursor_retripped(struct rdw_fake_clock *fc,
                                              int64_t t0)
{
    reducer_drive_watchdog_test_set_cursor_override(200);
    rdw_fake_clock_set(fc, t0 + 60);
    condition_engine_tick(); /* baseline reset to 200, no trip */
    rdw_fake_clock_set(fc, t0 + 80);
    condition_engine_tick(); /* cursor unchanged -> re-trip */

    bool ok4 = true;
    ok4 = ok4 && blocker_exists("reducer_drive_stuck");
    ok4 = ok4 && condition_engine_get_active_count() == 1;
    return ok4;
}

static bool rdw_drive_exit_cleared(struct rdw_fake_clock *fc, int64_t t0)
{
    reducer_drive_exit();
    rdw_fake_clock_set(fc, t0 + 100);
    condition_engine_tick(); /* drive inactive -> witness clears */

    bool ok5 = true;
    ok5 = ok5 && !blocker_exists("reducer_drive_stuck");
    ok5 = ok5 && condition_engine_get_active_count() == 0;
    ok5 = ok5 && !reducer_drive_active();
    return ok5;
}

static bool rdw_dump_documented_fields(const struct json_value *v,
                                       bool dumped)
{
    static const struct rdw_json_expect rows[] = {
        { .key = "active", .kind = RDW_JSON_PRESENT, .value = 0 },
        { .key = "active", .kind = RDW_JSON_BOOL_EQ, .value = 0 },
        { .key = "label", .kind = RDW_JSON_PRESENT, .value = 0 },
        { .key = "age_us", .kind = RDW_JSON_PRESENT, .value = 0 },
        { .key = "watchdog_threshold_secs", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "watchdog_threshold_secs", .kind = RDW_JSON_INT_EQ,
          .value = 0 },
        { .key = "last_watchdog_fire_unix", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "last_watchdog_fire_unix", .kind = RDW_JSON_INT_GT,
          .value = 0 },
        { .key = "utxo_apply_cursor", .kind = RDW_JSON_PRESENT, .value = 0 },
        { .key = "utxo_apply_cursor", .kind = RDW_JSON_INT_EQ, .value = 200 },
        { .key = "coins_applied_read_ok", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "coins_applied_read_ok", .kind = RDW_JSON_BOOL_EQ,
          .value = 1 },
        { .key = "coins_applied_height", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "coins_applied_height", .kind = RDW_JSON_INT_EQ,
          .value = 4242 },
    };
    return dumped &&
           rdw_json_fields_match(v, rows, sizeof rows / sizeof rows[0]);
}

static bool rdw_dump_drain_fsync_fields(const struct json_value *v)
{
    /* Drive+fsync telemetry (drain-exit counters, fsync timing) is always
     * emitted, 0 included, unlike stage_spin. */
    static const struct rdw_json_expect drain_totals[] = {
        { .key = "drain_exit_converged_total", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "drain_exit_budget_total", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "drain_last_round_advances", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "drain_last_elapsed_us", .kind = RDW_JSON_PRESENT,
          .value = 0 },
    };
    bool okt = rdw_json_fields_match(
        v, drain_totals, sizeof drain_totals / sizeof drain_totals[0]);
    const struct json_value *stage_us =
        json_get(v, "drain_last_stage_us");
    okt = okt && stage_us != NULL;
    static const char *const stage_names[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize"
    };
    for (size_t i = 0; stage_us &&
         i < sizeof(stage_names) / sizeof(stage_names[0]); i++)
        okt = okt && json_get(stage_us, stage_names[i]) != NULL;
    static const struct rdw_json_expect fsync_fields[] = {
        { .key = "fsync_last_flush_us", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "fsync_flush_us_ewma", .kind = RDW_JSON_PRESENT,
          .value = 0 },
    };
    okt = okt && rdw_json_fields_match(
        v, fsync_fields, sizeof fsync_fields / sizeof fsync_fields[0]);
    return okt;
}

static bool rdw_dump_event_log_fields(const struct json_value *v)
{
    /* event_log_deferred, plus the append-path split: all always emitted. */
    static const struct rdw_json_expect rows[] = {
        { .key = "event_log_deferred", .kind = RDW_JSON_PRESENT, .value = 0 },
        { .key = "event_log_barrier_appends", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "event_log_deferred_appends", .kind = RDW_JSON_PRESENT,
          .value = 0 },
        { .key = "event_log_barrier_us_total", .kind = RDW_JSON_PRESENT,
          .value = 0 },
    };
    return rdw_json_fields_match(v, rows, sizeof rows / sizeof rows[0]);
}

static bool rdw_drain_exit_stats_are_zero(void)
{
    reducer_drain_exit_stats_reset_for_testing();
    struct reducer_drain_exit_stats des;
    reducer_drain_exit_stats_snapshot(&des);
    return des.exit_converged_total == 0 &&
           des.exit_budget_total == 0 &&
           des.last_round_advances == 0 &&
           des.last_elapsed_us == 0;
}

static bool rdw_batch_fsync_healthy_quiet(void)
{
    condition_engine_reset_for_testing();
    register_batch_fsync_slow();
    batch_fsync_slow_test_set_budget_us(10000); /* 10ms */
    bool trig1 = reducer_body_fsync_test_trigger_precommit();
    condition_engine_tick();
    return trig1 && !blocker_exists("batch_fsync_slow") &&
           condition_engine_get_active_count() == 0;
}

static bool rdw_batch_fsync_slow_trips(void)
{
    condition_engine_reset_for_testing();
    register_batch_fsync_slow();
    batch_fsync_slow_test_set_budget_us(10000); /* 10ms, same as f1 */
    reducer_body_fsync_test_set_inject_delay_us(320 * 1000);
    bool trig2 = reducer_body_fsync_test_trigger_precommit();
    condition_engine_tick();
    return trig2 && blocker_exists("batch_fsync_slow") &&
           condition_engine_get_active_count() == 1 &&
           batch_fsync_slow_test_remedy_calls() == 1;
}

static bool rdw_batch_fsync_reason_names_ewma(void)
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
    return found_reason;
}

static bool rdw_batch_fsync_budget_clears(void)
{
    reducer_body_fsync_test_set_inject_delay_us(0);
    batch_fsync_slow_test_set_budget_us(60LL * 1000 * 1000); /* 60s */
    condition_engine_tick();
    return !blocker_exists("batch_fsync_slow") &&
           condition_engine_get_active_count() == 0;
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
        bool ok = rdw_spin_baseline_quiet(&fc, t0);
        RDW_CHECK("baseline tick does not trip", ok);

        bool ok2 = rdw_spin_frozen_cursor_tripped(&fc, t0);
        RDW_CHECK("frozen cursor across two ticks trips + fires remedy once",
                  ok2);

        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        bool found_reason = rdw_stuck_blocker_names_test_drive(snaps, n);
        RDW_CHECK("blocker detail names the driver label", found_reason);

        /* ---- (a2) the blocker carries a deadline-gated escape that
         * blocker_supervisor_sweep() actuates into the recovery ladder. ---- */
        bool esc_wired = rdw_stuck_blocker_arms_ladder_kick(snaps, n);
        RDW_CHECK("blocker arms a deadline-gated ladder-kick escape",
                  esc_wired);

        bool ok_escape = rdw_escape_sweep_arms_ladder();
        RDW_CHECK("deadline sweep actuates the escape -> ARMS the ladder",
                  ok_escape);

        /* ---- (b) cursor movement clears it ---- */
        bool ok3 = rdw_cursor_advance_cleared(&fc, t0);
        RDW_CHECK("cursor advance past the frozen height clears the blocker",
                  ok3);

        /* ---- (c) drive exit clears it (re-trip first) ---- */
        bool ok4 = rdw_fresh_frozen_cursor_retripped(&fc, t0);
        RDW_CHECK("re-trip after a fresh frozen cursor", ok4);

        bool ok5 = rdw_drive_exit_cleared(&fc, t0);
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
            bool okd = rdw_dump_documented_fields(&v, dumped);
            RDW_CHECK("dump emits all documented fields with live values",
                      okd);

            bool okt = rdw_dump_drain_fsync_fields(&v);
            RDW_CHECK("dump carries the drain-exit + fsync-timing fields",
                      okt);

            bool oka = rdw_dump_event_log_fields(&v);
            RDW_CHECK("dump carries the event_log append-path attribution",
                      oka);
            json_free(&v);
        }

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ---- (e) drain-exit telemetry: drive the reducer_drain.c exit-stats counters
     * via the ZCL_TESTING reset + snapshot pair; break-site attribution is covered
     * by test_mint_fold_livelock. Guards only the snapshot/reset plumbing. ---- */
    {
        bool ok = rdw_drain_exit_stats_are_zero();
        RDW_CHECK("drain-exit stats: reset zeroes all four fields", ok);
    }

    /* ---- (f) batch_fsync_slow: an injected slow flush trips it, a raised budget
     * clears it, a healthy flush never false-fires. GetTimeMicros() routes through
     * the overridable platform.clock, so restore the real clock here or an injected
     * delay measures 0us. Each phase gets a fresh condition_engine_reset_for_testing()
     * so detect() is a "first tick" (bypasses poll_secs); the fsync-timing atomics
     * are a separate module, so the EWMA carries across phases. ---- */
    {
        clock_reset_default();
        blocker_module_init();
        blocker_reset_for_testing();
        reducer_body_fsync_test_reset();
        batch_fsync_slow_test_reset();

        /* (f1) an unmodified fast flush never trips the condition, proven against
         * the same 10ms budget the slow case uses. */
        bool ok_healthy = rdw_batch_fsync_healthy_quiet();
        RDW_CHECK("batch_fsync_slow: healthy fast flush does not false-fire",
                  ok_healthy);

        /* (f2) One injected 320ms flush against the 10ms budget trips on either EWMA
         * path: next = (prev == 0) ? sample : prev + (sample - prev) / 16, so it
         * seeds to 320000us or damps to ~20000us; both exceed 10ms. The delay must
         * stay above 16 * budget. A fresh engine reset gives a "first tick". */
        bool ok_slow = rdw_batch_fsync_slow_trips();
        RDW_CHECK("batch_fsync_slow: injected slow flush trips the blocker",
                  ok_slow);

        bool found_reason = rdw_batch_fsync_reason_names_ewma();
        RDW_CHECK("batch_fsync_slow: blocker names the EWMA + budget",
                  found_reason);

        /* (f3) raise the budget far above the elevated EWMA on the same active
         * episode: an active episode is checked every tick, so the witness clears
         * without a reset or waiting out EWMA decay. */
        bool ok_clear = rdw_batch_fsync_budget_clears();
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

        /* strtoll() reports ERANGE by returning LLONG_MAX for this runtime
         * flag. Treat that malformed value as the documented default rather
         * than accepting an effectively unreachable alert threshold. The
         * production condition must still report a real 5s flush against its
         * documented 4s default. */
        RDW_CHECK("batch_fsync_slow: ERANGE budget fails closed to default",
                  rdw_batch_fsync_overflow_fails_closed());

        batch_fsync_slow_test_reset();
        reducer_body_fsync_test_reset();
        condition_engine_reset_for_testing();
        blocker_reset_for_testing();
    }

    /* ---- (g) R1 catch-up round cadence — see rdw_test_r1_cadence above. ---- */
    failures += rdw_test_r1_cadence();

    rdw_cleanup();

    printf("=== test_reducer_drive_watchdog complete: %d failure(s) ===\n",
           failures);
    return failures;
}
