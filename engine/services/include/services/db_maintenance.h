/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Database Maintenance Scheduler
 *
 * SQLite databases degrade without periodic housekeeping:
 *
 *   - The WAL grows until it's checkpointed. An unchecked WAL
 *     on a high-write workload easily doubles the on-disk
 *     footprint and slows queries that span both the main db
 *     and the WAL tail.
 *   - The query planner relies on ANALYZE statistics. As the
 *     data distribution shifts (new blocks, new UTXO patterns)
 *     stale stats cause the planner to pick the wrong index.
 *   - VACUUM reclaims space from deleted rows and defragments
 *     the file. It holds an exclusive lock for the whole
 *     operation, so it's only safe to run when the node is
 *     idle.
 *
 * This service runs one pthread that ticks the three operations
 * on independent schedules. Each successful run updates its
 * last-run timestamp and emits `EV_DB_MAINTENANCE_DONE` with the
 * op name and elapsed ms. Failures emit `EV_DB_MAINTENANCE_FAILED`
 * but do NOT crash the node — housekeeping is advisory.
 *
 * Schedules
 * ---------
 *   wal_checkpoint_minutes  default 15   (cheap — always OK)
 *   analyze_hours           default 24   (cheap — always OK)
 *   vacuum_days             default 7    (expensive — idle-only)
 *
 * VACUUM caveat
 * -------------
 * `vacuum_days` is a *minimum* interval — the scheduler won't
 * attempt a vacuum more often, but it may defer beyond it if the
 * node is not at-tip / not idle. For now the "at-tip and idle"
 * predicate is a caller-supplied callback so this service stays
 * decoupled from chain state.
 *
 * API
 * ---
 *   db_maintenance_start(db, schedule)   — launch the thread
 *   db_maintenance_stop()                — join the thread
 *   db_maintenance_run_now(db, op)       — one-shot (wal|analyze|vacuum)
 *   db_maintenance_set_vacuum_gate(cb)   — caller-supplied "is it OK to vacuum?"
 *
 * Tests call `run_now` directly so they don't have to sleep for
 * a real interval.
 *
 * Boot policy — why this service runs, and why not all of it
 * ---------------------------------------------------------
 * This scheduler owns the ONLY size-triggered WAL checkpoint in the node:
 * the DB_MAINT_DEFAULT_WAL_MAX_BYTES cap that forces a checkpoint when the
 * WAL passes it regardless of the clock. It is also what registers the
 * node_db handle that db_maintenance_checkpoint_now() — the storage-reclaim
 * emergency leg — reaches the database through. Without it started, that
 * leg returns "no registered db" and the WAL has no size bound at all.
 *
 * It used to start only when ZCL_ENABLE_BOOT_DB_MAINT=1 was set in the
 * environment: a variable set nowhere in the repository, in no unit file, in
 * no drop-in and in no env file. A safety net nothing can switch on is not a
 * safety net, so boot now starts it by default and an operator opts out with
 * ZCL_DISABLE_BOOT_DB_MAINT=1.
 *
 * The three ops share a thread but not a risk profile, so boot arms them
 * individually rather than shipping all three or none:
 *
 *   wal      SIZE CAP ARMED. The DB-service writer already runs the periodic
 *            five-minute checkpoint. This scheduler adds only the independent
 *            byte threshold and emergency handle, avoiding two synchronized
 *            periodic checkpoints against the same connection.
 *   analyze  EXEMPT. A full scan of every index on a multi-GB node.db, with
 *            no idle gate and no bound, on the same serialized connection
 *            the writer uses — so it blocks writes for its whole duration.
 *            It has never once run in production (the service never
 *            started), and its first run would land AT BOOT, because an op
 *            that has never run is due immediately. Arming it would trade a
 *            WAL bound for a boot-time write stall on exactly the slow-disk
 *            machines that need the WAL bound most. Still available on
 *            demand through db_maintenance_run_now(db, "analyze").
 *   vacuum   EXEMPT. Rewrites the whole database into a new file and holds
 *            the lock for the duration; it needs an at-tip-and-idle gate,
 *            and the boot path installs none.
 *
 * Declaring the two off legs exempt is the point. The alternative on offer
 * was leaving all three off and calling the whole thing deferred.
 */

#ifndef ZCL_SERVICES_DB_MAINTENANCE_H
#define ZCL_SERVICES_DB_MAINTENANCE_H

#include "models/database.h"
#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

/* ── Tunables / defaults ────────────────────────────────────── */

#define DB_MAINT_DEFAULT_WAL_MINUTES    15
#define DB_MAINT_DEFAULT_ANALYZE_HOURS  24
#define DB_MAINT_DEFAULT_VACUUM_DAYS    7

/* WAL size cap: force a checkpoint if the WAL file exceeds this many
 * bytes, regardless of the normal interval.  Overridable via env
 * ZCL_WAL_MAX_BYTES.  Default 100 MB. */
#define DB_MAINT_DEFAULT_WAL_MAX_BYTES  (100 * 1024 * 1024)

/* Consecutive maintenance runs that yield to an active bulk node_db
 * catchup before one runs anyway.
 *
 * Every op here takes the node.db write lock, and holding it past the
 * catchup walk's 10 s busy timeout is what made that walk's post-commit
 * BEGIN IMMEDIATE fail — so a tick that lands mid-walk steps aside and
 * lets the next one try (the op's last-run stamp is untouched, so it stays
 * due). But housekeeping that defers forever is housekeeping that never
 * happens: a multi-hour catchup would silence the WAL byte cap for its
 * whole duration. After this many yields one run goes ahead, and catchup's
 * own bounded reopen retry (NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS) absorbs
 * the lock it takes — deference is a courtesy, not a veto, and neither
 * side can wedge the other. */
#define DB_MAINT_MAX_CATCHUP_DEFERRALS  8

/* ── Config ─────────────────────────────────────────────────── */

/* Each interval has three states, and the third one is the point:
 *
 *    > 0   run this op on that interval
 *      0   use the DB_MAINT_DEFAULT_* interval for this op
 *    < 0   EXEMPT — the caller has deliberately decided this op does not run
 *          from the scheduler. run_now() still executes it on demand.
 *
 * "Exempt" exists so a caller can arm the cheap ops without arming an
 * expensive one, and say so, instead of the two being packaged together and
 * the whole scheduler being left switched off to avoid the expensive half.
 * An op that is off should be off ON PURPOSE and legible as such. */
struct db_maintenance_schedule {
    int wal_checkpoint_minutes;   /* 0 = use default, <0 = exempt */
    int analyze_hours;            /* 0 = use default, <0 = exempt */
    int vacuum_days;              /* 0 = use default, <0 = exempt */
    int tick_seconds;             /* 0 = 60 s (poll)  */
    int64_t wal_max_bytes;        /* 0 = use default (100MB) */
};

void db_maintenance_schedule_defaults(struct db_maintenance_schedule *s);

/* The boot schedule: only the WAL byte cap is armed here; periodic WAL work is
 * owned by the serialized DB-service writer. ANALYZE and VACUUM are exempt. */
void db_maintenance_schedule_wal_cap_only(
    struct db_maintenance_schedule *s);

/* ── Status snapshot ────────────────────────────────────────── */

struct db_maintenance_status {
    bool    running;
    int64_t wal_last_unix;           /* 0 if never run */
    int64_t wal_last_duration_ms;
    int64_t analyze_last_unix;
    int64_t analyze_last_duration_ms;
    int64_t vacuum_last_unix;
    int64_t vacuum_last_duration_ms;
    int64_t total_runs;
    int64_t total_failures;
    char    last_error[256];
};

void db_maintenance_status_snapshot(struct db_maintenance_status *out);

/* `z23 dumpstate db_maintenance` — WAL/ANALYZE/VACUUM worker snapshot.
 * See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool db_maintenance_dump_state_json(struct json_value *out, const char *key);

/* ── Lifecycle ──────────────────────────────────────────────── */

/* Launch the background thread. `db` must be an opened node_db.
 * Returns a non-ok zcl_result if already running, if db is not open,
 * or if thread create fails. Safe to call from any thread. */
struct zcl_result db_maintenance_start(struct node_db *db,
                                       const struct db_maintenance_schedule *s);

void db_maintenance_stop(void);

/* Run one maintenance op synchronously. `op` is one of:
 *   "wal"     — PRAGMA wal_checkpoint(TRUNCATE)
 *   "analyze" — ANALYZE
 *   "vacuum"  — VACUUM  (caller is responsible for idle check)
 *
 * Returns ZCL_OK on SQLite success. `db` must be opened. Emits the
 * _START / _DONE / _FAILED events on success and failure paths. */
struct zcl_result db_maintenance_run_now(struct node_db *db, const char *op);

/* Checkpoint+truncate the node.db WAL NOW using the db registered by
 * db_maintenance_start — a handle-free entry point for the disk_full reclaim
 * path (which does not own the node_db). Serializes with the maintenance
 * thread. Returns ZCL_OK on success; a non-ok result if maintenance was never
 * started (no db registered) or the checkpoint failed. */
struct zcl_result db_maintenance_checkpoint_now(void);

/* Boot opt-out gate: true only when ZCL_DISABLE_BOOT_DB_MAINT=1 opts the
 * node out of the default-started WAL size-cap scheduler. Any other value
 * (including unset) means boot starts the service. Factored out of the boot
 * service start so the policy is unit-testable without booting a node. */
bool db_maintenance_boot_opted_out(void);

/* ── Vacuum gate ────────────────────────────────────────────── */

/* Caller-supplied predicate that decides whether the scheduler
 * may run a VACUUM. Returns true when the node is at-tip and
 * idle. Default: `NULL` meaning "never vacuum from the scheduler"
 * (run_now still works). Set to a function that checks sync
 * state once boot wiring lands. */
typedef bool (*db_maintenance_vacuum_gate_fn)(void);
void db_maintenance_set_vacuum_gate(db_maintenance_vacuum_gate_fn fn);

#endif /* ZCL_SERVICES_DB_MAINTENANCE_H */
