/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_catchup_lock_guard — the node.db lock-contention seatbelts for
 * the bulk catchup projection walk (node_db_catchup_service.c).
 *
 * Three small, always-on mechanisms, kept out of the service file so the
 * service stays under the E1 file-size ratchet:
 *
 *   1. Commit cadence — the per-batch COMMIT cap (blocks + wall-clock
 *      window) so the single WAL write lock is never held across an
 *      unbounded 100k-block batch (the old shape held it for minutes,
 *      past every other writer's budget, producing "database is locked"
 *      bursts). The block cap defaults to 2000, the value
 *      engine/jobs/include/jobs/catchup_cadence.h documents for the reducer
 *      stages; the window caps the lock hold below this handle's 10 s
 *      busy timeout so any contender's wait can still succeed.
 *
 *   2. BUSY_SNAPSHOT restart — a deferred-BEGIN writer whose read snapshot
 *      was invalidated by a concurrent commit fails its first write with
 *      SQLITE_BUSY_SNAPSHOT, a class the busy handler can never cure (each
 *      attempt burns the full 10 s timeout, then fails identically — the
 *      13–19 s drumbeat of the 2026-07-27 catchup-poison incident). The
 *      only cure is ROLLBACK + a fresh transaction. Catchup is an
 *      idempotent projection re-run, so a bounded whole-walk restart
 *      (re-derived from persisted state) is the safe granularity.
 *
 *   3. Abort-streak park — a pass that keeps failing must not be re-run
 *      forever (the incident re-ran an always-failing pass 13k+ times).
 *      After CATCHUP_ABORT_STREAK_CAP consecutive failed passes the worker
 *      parks behind the named blocker "node_db_catchup.abort_storm" and
 *      each later pass is a no-op until an operator clears the blocker
 *      (half-open: one real pass, which either succeeds and resets the
 *      streak or re-fails and re-parks).
 *
 * I/O-scheduling only: no validation semantics live here. */

#ifndef ZCL_SERVICES_NODE_DB_CATCHUP_LOCK_GUARD_H
#define ZCL_SERVICES_NODE_DB_CATCHUP_LOCK_GUARD_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;

/* ── Commit cadence ─────────────────────────────────────────────── */
#define NODE_DB_CATCHUP_COMMIT_BATCH_BLOCKS 2000
/* Wall-clock cap on one open batch transaction, in seconds. Below the
 * shared handle's 10 s busy timeout (ZCL_NODE_DB_BUSY_TIMEOUT_MS) so a
 * contending writer's busy-handler wait can still land. */
#define NODE_DB_CATCHUP_COMMIT_BATCH_MAX_SECS 5

/* The effective per-batch block cap for this run (test override when set,
 * else the default above). */
int node_db_catchup_lock_guard_batch_size(void);

/* Record one mid-walk batch COMMIT (test/diagnostic counter). */
void node_db_catchup_lock_guard_note_batch_commit(void);

/* ── BUSY_SNAPSHOT restart ──────────────────────────────────────── */
#define NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS 3

/* True when the handle's most recent error is the extended
 * SQLITE_BUSY_SNAPSHOT code — best-effort: on the shared FULLMUTEX handle
 * another thread can interleave and clobber the errcode between the
 * failing call and this read; a false negative just falls back to the
 * plain abort path, a false positive triggers an idempotent re-walk. */
bool node_db_catchup_lock_guard_busy_snapshot(const struct node_db *ndb);

/* Restart decision for a failed pass. True at most
 * NODE_DB_CATCHUP_SNAPSHOT_MAX_RESTARTS times per logical pass (per-thread
 * depth counter): the caller then re-invokes the whole walk and MUST call
 * node_db_catchup_lock_guard_restart_done() when that re-invocation
 * returns. Logs the restart reason itself. */
bool node_db_catchup_lock_guard_restart_needed(bool failed,
                                               bool busy_snapshot);
void node_db_catchup_lock_guard_restart_done(void);

/* ── Abort-streak park ──────────────────────────────────────────── */
#define NODE_DB_CATCHUP_ABORT_STREAK_CAP 8
#define NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID "node_db_catchup.abort_storm"

/* Park gate, evaluated once at the top of every pass. True = the worker
 * is parked behind the named blocker; the pass must do no work. False =
 * run normally (includes the half-open reset after an operator clears the
 * blocker). */
bool node_db_catchup_lock_guard_parked(void);

/* Record the outcome of one logical pass (call exactly once per pass, at
 * the outermost frame — a restarted attempt must not double-count). A
 * failure increments the streak and names the blocker at the cap; a
 * success resets the streak and retires the blocker. */
void node_db_catchup_lock_guard_note_outcome(bool pass_failed);

#ifdef ZCL_TESTING
/* Commit-cadence override: blocks <= 0 restores the default. */
void node_db_catchup_lock_guard_test_set_batch_size(int blocks);
int  node_db_catchup_lock_guard_test_batch_commits(void);
/* Abort-streak fixtures. */
void node_db_catchup_lock_guard_test_set_abort_streak(int streak);
int  node_db_catchup_lock_guard_test_abort_streak(void);
/* Arm n test-injected BUSY_SNAPSHOT write failures, consumed one per
 * block by the walk; the restart plumbing then runs for real. */
void node_db_catchup_lock_guard_test_force_snapshot_failures(int n);
/* Consume one armed injection (true = the walk must fail this block as a
 * simulated BUSY_SNAPSHOT). Always false in non-testing builds — the
 * service calls this only under ZCL_TESTING. */
bool node_db_catchup_lock_guard_test_consume_snapshot_failure(void);
int  node_db_catchup_lock_guard_test_snapshot_restarts(void);
/* Reset every counter/override above (not the blocker registry — tests
 * use blocker_reset_for_testing() for that). */
void node_db_catchup_lock_guard_test_reset(void);
#endif

#endif /* ZCL_SERVICES_NODE_DB_CATCHUP_LOCK_GUARD_H */
