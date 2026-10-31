/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_catchup_lock_guard — see the header for the three-mechanism
 * contract (commit cadence, BUSY_SNAPSHOT restart, abort-streak park). */

// one-result-type-ok:seatbelt-plain-bool — E2 (one way out):
// node_db_catchup_lock_guard is a small predicate/counter module behind
// the single LOCKED plain-int surface node_db_catchup_service_run. Every
// predicate is a pure decision (its caller already owns the one failure
// exit), note_* are fire-and-forget counters, and every state transition
// that matters (park, restart, blocker named) is logged via LOG_WARN at
// the transition point, so the reason travels with the failure. A
// zcl_result here would add a second result type the sole caller would
// immediately collapse back into its int contract.

#include "services/node_db_catchup_lock_guard.h"

#include "config/db_service.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>

extern volatile sig_atomic_t g_shutdown_requested;

/* ── Commit cadence ─────────────────────────────────────────────── */
#ifdef ZCL_TESTING
static _Atomic int g_test_batch_size = 0;
static _Atomic int g_test_batch_max_secs = -1;
static _Atomic int g_test_height_delay_ms = 0;
static _Atomic bool g_test_fake_clock = false;
static _Atomic int64_t g_test_clock_ms = 0;
static _Atomic int g_timed_row_commits = 0;
static _Atomic int64_t g_test_reopen_ms = 0;
static _Atomic int64_t g_test_min_real_hold = INT64_MAX;
static _Atomic int g_yield_sleeps = 0;
static _Atomic int g_batch_commits = 0;
#endif

int node_db_catchup_lock_guard_batch_size(void)
{
#ifdef ZCL_TESTING
    int override = atomic_load(&g_test_batch_size);
    if (override > 0)
        return override;
#endif
    return NODE_DB_CATCHUP_COMMIT_BATCH_BLOCKS;
}

int64_t node_db_catchup_lock_guard_now_ms(void)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_test_fake_clock))
        return atomic_load(&g_test_clock_ms);
#endif
    return platform_time_monotonic_ms();
}

bool node_db_catchup_lock_guard_batch_due(int64_t held_ms)
{
    if (held_ms >= (int64_t)node_db_catchup_lock_guard_batch_max_secs() * 1000)
        return true;
    return held_ms >= NODE_DB_CATCHUP_WAITER_MIN_HOLD_MS &&
           node_db_detached_writer_waiting();
}

int node_db_catchup_lock_guard_batch_max_secs(void)
{
#ifdef ZCL_TESTING
    int override = atomic_load(&g_test_batch_max_secs);
    if (override >= 0)
        return override;
#endif
    return NODE_DB_CATCHUP_COMMIT_BATCH_MAX_SECS;
}

void node_db_catchup_lock_guard_yield_to_writers(struct db_service *svc,
                                                  bool drain_queue)
{
    bool drain = drain_queue && svc;

    if (drain)
        (void)db_service_run_pending(svc);
    if (node_db_detached_writer_waiting() && !g_shutdown_requested) {
#ifdef ZCL_TESTING
        atomic_fetch_add(&g_yield_sleeps, 1);
#endif
        platform_sleep_ms(NODE_DB_CATCHUP_YIELD_MS);
#ifdef ZCL_TESTING
        if (atomic_load(&g_test_fake_clock))
            atomic_fetch_add(&g_test_clock_ms, NODE_DB_CATCHUP_YIELD_MS);
#endif
        if (drain)
            (void)db_service_run_pending(svc);
    }
}

void node_db_catchup_lock_guard_note_batch_commit(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_batch_commits, 1);
#endif
}

void node_db_catchup_lock_guard_note_timed_commit(bool rows)
{
#ifdef ZCL_TESTING
    if (rows)
        atomic_fetch_add(&g_timed_row_commits, 1);
#else
    (void)rows;
#endif
}

/* ── BUSY_SNAPSHOT restart ──────────────────────────────────────── */
static _Thread_local int t_snapshot_restart_depth = 0;
static _Atomic int g_snapshot_restarts_total = 0;

bool node_db_catchup_lock_guard_busy_snapshot(const struct node_db *ndb)
{
    return ndb && ndb->db &&
           sqlite3_extended_errcode(ndb->db) == SQLITE_BUSY_SNAPSHOT;
}

bool node_db_catchup_lock_guard_restart_needed(bool failed,
                                               bool busy_snapshot)
{
    if (!failed || !busy_snapshot || g_shutdown_requested)
        return false;
    if (t_snapshot_restart_depth >= NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS) {
        LOG_WARN("catchup",
                 "catchup: SQLITE_BUSY_SNAPSHOT restart budget exhausted "
                 "(%d) — treating as a plain abort",
                 NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS);
        return false;
    }
    t_snapshot_restart_depth++;
    atomic_fetch_add(&g_snapshot_restarts_total, 1);
    LOG_WARN("catchup",
             "catchup: SQLITE_BUSY_SNAPSHOT — rolled back; restarting the "
             "walk from the persisted tip (attempt %d/%d, idempotent "
             "projection re-run)",
             t_snapshot_restart_depth, NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS);
    return true;
}

void node_db_catchup_lock_guard_restart_done(void)
{
    if (t_snapshot_restart_depth > 0)
        t_snapshot_restart_depth--;
}

/* ── Abort-streak park ──────────────────────────────────────────── */
static _Atomic int g_abort_streak = 0;

static void catchup_lock_guard_raise_abort_blocker(int streak)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "%d consecutive catchup passes aborted; worker parked — "
             "clear this blocker to allow one half-open pass",
             streak);
    struct blocker_record rec;
    if (blocker_init(&rec, NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID,
                     "sync.node_db_catchup", BLOCKER_RESOURCE, reason))
        (void)blocker_set(&rec);
    LOG_WARN("catchup", "catchup: %s (blocker %s)", reason,
             NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID);
}

bool node_db_catchup_lock_guard_parked(void)
{
    if (atomic_load(&g_abort_streak) < NODE_DB_CATCHUP_ABORT_STREAK_CAP)
        return false;
    if (blocker_exists(NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID))
        return true; /* parked: the blocker is the live claim, stay quiet */
    /* Operator cleared the blocker: half-open — allow one real pass. */
    atomic_store(&g_abort_streak, 0);
    LOG_WARN("catchup",
             "catchup: abort-streak blocker %s cleared — one half-open "
             "pass allowed", NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID);
    return false;
}

void node_db_catchup_lock_guard_note_outcome(bool pass_failed)
{
    if (!pass_failed) {
        if (atomic_exchange(&g_abort_streak, 0) > 0 &&
            blocker_exists(NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID))
            blocker_clear(NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID);
        return;
    }
    int streak = atomic_fetch_add(&g_abort_streak, 1) + 1;
    if (streak >= NODE_DB_CATCHUP_ABORT_STREAK_CAP)
        catchup_lock_guard_raise_abort_blocker(streak);
}

/* ── Test hooks ─────────────────────────────────────────────────── */
#ifdef ZCL_TESTING
static _Atomic int g_test_force_snapshot_failures = 0;

void node_db_catchup_lock_guard_test_set_batch_size(int blocks)
{
    atomic_store(&g_test_batch_size, blocks);
}

void node_db_catchup_lock_guard_test_set_batch_max_secs(int secs)
{
    atomic_store(&g_test_batch_max_secs, secs);
}

void node_db_catchup_lock_guard_test_set_height_delay_ms(int ms)
{
    atomic_store(&g_test_height_delay_ms, ms);
}

int node_db_catchup_lock_guard_test_yield_sleeps(void)
{
    return atomic_load(&g_yield_sleeps);
}

void node_db_catchup_lock_guard_test_height_delay(void)
{
    int ms = atomic_load(&g_test_height_delay_ms);
    if (ms <= 0)
        return;
    if (atomic_load(&g_test_fake_clock))
        atomic_fetch_add(&g_test_clock_ms, ms);
    else
        platform_sleep_ms(ms);
}

void node_db_catchup_lock_guard_test_note_reopen(int64_t ms)
{
    atomic_store(&g_test_reopen_ms, ms);
}

void node_db_catchup_lock_guard_test_note_cycle(int64_t ms)
{
    int64_t hold = ms - atomic_load(&g_test_reopen_ms);
    if (hold < atomic_load(&g_test_min_real_hold))
        atomic_store(&g_test_min_real_hold, hold);
}

int64_t node_db_catchup_lock_guard_test_min_real_hold(void)
{
    return atomic_load(&g_test_min_real_hold);
}

void node_db_catchup_lock_guard_test_use_fake_clock(bool on)
{
    atomic_store(&g_test_clock_ms, 0);
    atomic_store(&g_test_fake_clock, on);
}

int node_db_catchup_lock_guard_test_timed_row_commits(void)
{
    return atomic_load(&g_timed_row_commits);
}

int node_db_catchup_lock_guard_test_batch_commits(void)
{
    return atomic_load(&g_batch_commits);
}

void node_db_catchup_lock_guard_test_set_abort_streak(int streak)
{
    atomic_store(&g_abort_streak, streak);
}

int node_db_catchup_lock_guard_test_abort_streak(void)
{
    return atomic_load(&g_abort_streak);
}

void node_db_catchup_lock_guard_test_force_snapshot_failures(int n)
{
    atomic_store(&g_test_force_snapshot_failures, n);
}

bool node_db_catchup_lock_guard_test_consume_snapshot_failure(void)
{
    int armed = atomic_load(&g_test_force_snapshot_failures);
    if (armed <= 0)
        return false;
    atomic_fetch_sub(&g_test_force_snapshot_failures, 1);
    return true;
}

int node_db_catchup_lock_guard_test_snapshot_restarts(void)
{
    return atomic_load(&g_snapshot_restarts_total);
}

void node_db_catchup_lock_guard_test_reset(void)
{
    atomic_store(&g_test_batch_size, 0);
    atomic_store(&g_test_batch_max_secs, -1);
    atomic_store(&g_test_height_delay_ms, 0);
    atomic_store(&g_test_fake_clock, false);
    atomic_store(&g_test_clock_ms, 0);
    atomic_store(&g_timed_row_commits, 0);
    atomic_store(&g_test_reopen_ms, 0);
    atomic_store(&g_test_min_real_hold, INT64_MAX);
    atomic_store(&g_yield_sleeps, 0);
    atomic_store(&g_batch_commits, 0);
    atomic_store(&g_abort_streak, 0);
    atomic_store(&g_test_force_snapshot_failures, 0);
    atomic_store(&g_snapshot_restarts_total, 0);
    t_snapshot_restart_depth = 0;
}
#endif
