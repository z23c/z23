/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   This unit holds the shared-connection maintenance-op progress lifecycle and
 *   a lock-free busy-op registry — process-wide plumbing over the node_db
 *   connection handle, not a row record. The validates_* / AR_BEGIN_SAVE
 *   lifecycle applies to the row models that use the handle, not here (same
 *   rationale as database.c).
 *
 * Long-running node.db maintenance-op progress + busy-op registry.
 *
 * PRAGMA quick_check and the staging-cleanup DELETE run for many seconds
 * (minutes on a multi-GB node.db) on the SHARED node.db connection. While one
 * runs, SQLite's serialized per-connection mutex makes every other query on
 * that connection block for the op's full duration — which is exactly why a
 * healthy, tip-ingesting node's status command once went dark for ~11 minutes
 * (db_long_op_progress_cb logged elapsed_ms=647514 for a live quick_check).
 *
 * db_long_op_start/finish (called by db_quick_check_ok and node_db_open in
 * database.c) publish the running op into this lock-free registry so the
 * responsive status/health surfaces can NAME the maintenance op and route
 * around the busy connection by serving an in-memory snapshot, instead of
 * hanging. node_db_long_op_active() is a pure read of in-process atomics — it
 * never touches the DB, so it cannot itself block. Kept separate from the
 * connection open/migration logic in database.c so each file stays cohesive. */

#include "models/database.h"
#include "models/database_internal.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZCL_DB_LONG_OP_PROGRESS_OPS 50000
#define ZCL_DB_LONG_OP_LOG_MS       15000
#define ZCL_DB_LONG_OP_LOG_MIN_BYTES (64LL * 1024LL * 1024LL)
#define ZCL_DB_LONG_OP_BLOCKER_ID   "db.maintenance_slow"

/* Monotonic milliseconds — the single time base for op start/elapsed here and
 * in node_db_long_op_active(), so elapsed math is always internally consistent. */
static int64_t db_long_op_now_ms(void)
{
    return platform_time_monotonic_ms();
}

/* ── Busy-op registry ───────────────────────────────────────────────────
 *
 * Long ops never nest on one connection (SQLite serializes them), so a single
 * active flag + op pointer + start time is sufficient. `op` is always a static
 * string literal, so the pointer is safe to publish atomically. */
static _Atomic(const char *) g_db_long_op_name;
static _Atomic int64_t       g_db_long_op_start_ms;
static _Atomic bool          g_db_long_op_active_flag;

void db_long_op_publish(const char *op, int64_t start_ms)
{
    atomic_store_explicit(&g_db_long_op_name, op, memory_order_relaxed);
    atomic_store_explicit(&g_db_long_op_start_ms, start_ms,
                          memory_order_relaxed);
    atomic_store_explicit(&g_db_long_op_active_flag, true,
                          memory_order_release);
}

void db_long_op_unpublish(void)
{
    atomic_store_explicit(&g_db_long_op_active_flag, false,
                          memory_order_release);
    blocker_clear(ZCL_DB_LONG_OP_BLOCKER_ID);
}

bool node_db_long_op_active(const char **op_out, int64_t *elapsed_ms_out)
{
    if (!atomic_load_explicit(&g_db_long_op_active_flag, memory_order_acquire))
        return false; // raw-return-ok:no-op-running-is-not-an-error
    const char *op =
        atomic_load_explicit(&g_db_long_op_name, memory_order_relaxed);
    int64_t start =
        atomic_load_explicit(&g_db_long_op_start_ms, memory_order_relaxed);
    int64_t now = db_long_op_now_ms();
    if (op_out)
        *op_out = op ? op : "long_op";
    if (elapsed_ms_out)
        *elapsed_ms_out = now > start ? now - start : 0;
    return true;
}

/* Name a maintenance op that has blown its deadline as a typed blocker. Called
 * from the SQLite progress callback (on the op's own thread), which touches only
 * the blocker registry mutex — never the DB — so there is no reentrancy. The
 * blocker primitive rate-limits duplicate sets, so calling it every progress
 * tick is safe; db_long_op_unpublish clears it when the op finishes. TRANSIENT
 * so it stays a visible warning and never hard-gates public serving — the node
 * IS servable meanwhile, from the in-memory snapshot. */
void db_long_op_note_deadline(const char *op, int64_t elapsed_ms)
{
    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "node.db maintenance op '%s' has run %lld ms (> %d ms deadline); "
             "connection is busy — status is served from the in-memory snapshot",
             op ? op : "long_op", (long long)elapsed_ms,
             ZCL_DB_LONG_OP_DEADLINE_MS);
    if (!blocker_init(&r, ZCL_DB_LONG_OP_BLOCKER_ID, "db.maintenance",
                      BLOCKER_TRANSIENT, reason))
        return;
    (void)blocker_set(&r);
}

#ifdef ZCL_TESTING
void node_db_long_op_test_set(const char *op, int64_t elapsed_ms)
{
    int64_t start = db_long_op_now_ms() - (elapsed_ms > 0 ? elapsed_ms : 0);
    db_long_op_publish(op ? op : "test_op", start);
}

void node_db_long_op_test_clear(void)
{
    db_long_op_unpublish();
}
#endif

/* ── Progress-handler lifecycle ─────────────────────────────────────────── */

static bool db_long_op_log_enabled(const char *path)
{
    if (!path || !path[0] || strcmp(path, ":memory:") == 0)
        return false;

    const char *force = getenv("ZCL_DB_LONG_OP_LOG_ALL");
    if (force && force[0] && strcmp(force, "0") != 0)
        return true;

    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    return st.st_size >= ZCL_DB_LONG_OP_LOG_MIN_BYTES;
}

static int db_long_op_progress_cb(void *arg)
{
    struct db_long_op_progress *p = arg;
    if (!p)
        return 0;

    p->callbacks++;
    int64_t now_ms = db_long_op_now_ms();
    if (now_ms - p->start_ms >= ZCL_DB_LONG_OP_DEADLINE_MS)
        db_long_op_note_deadline(p->op, now_ms - p->start_ms);
    if (!p->log_enabled)
        return 0;
    if (now_ms - p->last_log_ms < ZCL_DB_LONG_OP_LOG_MS)
        return 0;

    LOG_INFO("db",
             "db: %s still running path=%s elapsed_ms=%lld callbacks=%llu",
             p->op ? p->op : "long_op",
             p->path ? p->path : "(unknown)",
             (long long)(now_ms - p->start_ms),
             (unsigned long long)p->callbacks);
    p->last_log_ms = now_ms;
    return 0;
}

void db_long_op_start(sqlite3 *db, struct db_long_op_progress *progress,
                      const char *op, const char *path)
{
    if (!progress)
        return;

    progress->op = op;
    progress->path = path ? path : (db ? sqlite3_db_filename(db, "main") : NULL);
    progress->start_ms = db_long_op_now_ms();
    progress->last_log_ms = progress->start_ms;
    progress->callbacks = 0;
    progress->log_enabled = db_long_op_log_enabled(progress->path);

    /* Publish the busy state regardless of log_enabled: the shared connection is
     * occupied either way, and a status call can coincide with it. */
    db_long_op_publish(progress->op, progress->start_ms);

    if (!db || !progress->log_enabled)
        return;

    LOG_INFO("db", "db: %s start path=%s",
             progress->op ? progress->op : "long_op",
             progress->path ? progress->path : "(unknown)");
    sqlite3_progress_handler(db, ZCL_DB_LONG_OP_PROGRESS_OPS,
                             db_long_op_progress_cb, progress);
}

void db_long_op_finish(sqlite3 *db, struct db_long_op_progress *progress,
                       bool ok, int rc)
{
    if (db)
        sqlite3_progress_handler(db, 0, NULL, NULL);
    db_long_op_unpublish();
    if (!progress || !progress->log_enabled)
        return;

    int64_t elapsed_ms = db_long_op_now_ms() - progress->start_ms;
    LOG_INFO("db",
             "db: %s done path=%s ok=%d rc=%d elapsed_ms=%lld callbacks=%llu",
             progress->op ? progress->op : "long_op",
             progress->path ? progress->path : "(unknown)", ok ? 1 : 0, rc,
             (long long)elapsed_ms, (unsigned long long)progress->callbacks);
}

int db_exec_checked_progress(sqlite3 *db, const char *sql,
                             const char *where, const char *path)
{
    struct db_long_op_progress progress;
    db_long_op_start(db, &progress, where, path);
    int rc = db_exec_checked(db, sql, where);
    db_long_op_finish(db, &progress, rc == SQLITE_OK, rc);
    return rc;
}
