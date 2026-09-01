/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: node.db transaction, readonly-query, and runtime-status operations.
 *
 * ar-validate-skip:connection-handle-not-a-row
 * A node_db is a connection/lifecycle object, not a persisted row. */

#include "models/database.h"
#include "models/ar_after_commit.h"
#include "models/database_internal.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

bool node_db_exec(struct node_db *ndb, const char *sql)
{
    if (!ndb->open) return false;
    char *err = NULL;
    int rc = sqlite3_exec(ndb->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN("db", "db: exec failed: %s", err);
        node_db_note_activity(ndb, sql ? sql : "exec", rc);
        sqlite3_free(err);
        return false;
    }
    node_db_note_activity(ndb, sql ? sql : "exec", rc);
    return true;
}

bool node_db_prepare_readonly_stmt(sqlite3 *db, const char *sql,
                                   sqlite3_stmt **stmt_out)
{
    if (!db || !sql || !stmt_out)
        LOG_FAIL("db", "prepare_readonly_stmt called with invalid arguments");

    *stmt_out = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, stmt_out, NULL);
    if (rc != SQLITE_OK || !*stmt_out) {
        LOG_FAIL("db", "prepare_readonly_stmt failed: rc=%d msg=%s sql=%s",
                 rc, sqlite3_errmsg(db), sql);
    }
    if (!sqlite3_stmt_readonly(*stmt_out)) {
        sqlite3_finalize(*stmt_out);
        *stmt_out = NULL;
        LOG_FAIL("db", "prepare_readonly_stmt rejected writable statement: %s",
                 sql);
    }
    return true;
}

bool node_db_prepare_readonly_query(struct node_db *ndb, const char *sql,
                                    sqlite3_stmt **stmt_out)
{
    if (!ndb || !ndb->open || !sql || !stmt_out)
        LOG_FAIL("db", "prepare_readonly_query called with invalid arguments");

    bool ok = node_db_prepare_readonly_stmt(ndb->db, sql, stmt_out);
    node_db_note_activity(ndb, "prepare_readonly_query",
                          (ok && *stmt_out) ? SQLITE_OK : SQLITE_ERROR);
    return ok;
}

/* Preserve the real SQLite rc on a failed BEGIN/COMMIT/ROLLBACK. Callers use
 * it to distinguish retryable BUSY/LOCKED from terminal errors. */
static bool node_db_tx_op(struct node_db *ndb, const char *sql,
                          bool set_tx_open)
{
    bool ok = node_db_exec(ndb, sql);
    int rc = SQLITE_OK;
    if (!ok) {
        struct node_db_status st;
        node_db_get_status(ndb, &st);
        rc = st.last_sqlite_rc;
    }
    node_db_note_tx_state(ndb, set_tx_open && ok, sql, rc);
    return ok;
}

/* These four are the transaction boundary the after_commit hook queue keys
 * on (models/ar_after_commit.h): a hook registered with
 * ar_register_after_commit fires only when the OUTERMOST transaction commits,
 * and is discarded on rollback, so an external observer is never told about a
 * row a later ROLLBACK erases. A handle with no after_commit hooks anywhere
 * pays one increment. */
bool node_db_begin(struct node_db *ndb)
{
    bool ok = node_db_tx_op(ndb, "BEGIN TRANSACTION", true);
    if (ok) ar_after_commit_note_begin();
    return ok;
}

bool node_db_begin_immediate(struct node_db *ndb)
{
    bool ok = node_db_tx_op(ndb, "BEGIN IMMEDIATE", true);
    if (ok) ar_after_commit_note_begin();
    return ok;
}

/* If a write VM is abandoned in RUN state, SQLite rejects every later COMMIT
 * with "statements in progress". Reset only busy write VMs; never finalize a
 * cached statement and never disturb an ordinary BUSY/LOCKED failure. */
static _Atomic uint64_t g_commit_recovery_walks = 0;

static int node_db_reset_abandoned_write_vms(struct node_db *ndb)
{
    int reset = 0;
    for (sqlite3_stmt *s = sqlite3_next_stmt(ndb->db, NULL); s;
         s = sqlite3_next_stmt(ndb->db, s)) {
        if (!sqlite3_stmt_busy(s) || sqlite3_stmt_readonly(s))
            continue;
        const char *sql = sqlite3_sql(s);
        LOG_WARN("db", "db: poisoned COMMIT — resetting abandoned write VM: %s",
                 sql ? sql : "(null)");
        sqlite3_reset(s);
        reset++;
    }
    return reset;
}

bool node_db_commit(struct node_db *ndb)
{
    if (node_db_tx_op(ndb, "COMMIT", false)) {
        /* Durable. If this closed the outermost transaction, the queued
         * after_commit hooks fire here and nowhere earlier. */
        ar_after_commit_note_commit(true);
        return true;
    }
    /* A failed COMMIT can leave the transaction open; keep the queue for the
     * ROLLBACK the caller must now issue. */
    ar_after_commit_note_commit(false);
    const char *msg = ndb && ndb->db ? sqlite3_errmsg(ndb->db) : NULL;
    if (msg && strstr(msg, "statements in progress")) {
        int reset = node_db_reset_abandoned_write_vms(ndb);
        if (reset > 0) {
            atomic_fetch_add(&g_commit_recovery_walks, 1);
            LOG_WARN("db", "db: COMMIT unpoisoned — reset %d abandoned write "
                     "VM(s); caller must ROLLBACK this transaction", reset);
        }
    }
    return false;
}

bool node_db_rollback(struct node_db *ndb)
{
    bool ok = node_db_tx_op(ndb, "ROLLBACK", false);
    /* Discard the queue whether or not the ROLLBACK statement itself
     * succeeded. Not firing a hook is recoverable; announcing a row that was
     * rolled back is not. */
    ar_after_commit_note_rollback();
    return ok;
}

#ifdef ZCL_TESTING
uint64_t node_db_test_commit_recovery_walks(void)
{
    return atomic_load(&g_commit_recovery_walks);
}
#endif

void node_db_set_sync_batch_size(struct node_db *ndb, int batch_size)
{
    if (!ndb) return;
    ndb->sync_batch_size = batch_size > 0 ? batch_size : 1;
    node_db_note_activity(ndb, "set_sync_batch_size", SQLITE_OK);
}

bool node_db_sync_flush(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return false;
    if (ndb->sync_in_batch) {
        bool ok = node_db_commit(ndb);
        ndb->sync_in_batch = false;
        ndb->sync_pending_blocks = 0;
        return ok;
    }
    return true;
}

void node_db_get_status(struct node_db *ndb, struct node_db_status *out)
{
    struct node_db_status empty = {0};
    if (!out) return;
    *out = empty;
    if (!ndb) return;

    if (ndb->state_mutex_init) zcl_mutex_lock(&ndb->state_mutex);
    out->open = ndb->open;
    out->tx_open = ndb->tx_open;
    out->turbo_mode = ndb->turbo_mode;
    out->sync_batch_size = ndb->sync_batch_size;
    out->sync_pending_blocks = ndb->sync_pending_blocks;
    out->last_activity_time = ndb->last_activity_time;
    out->last_sqlite_rc = ndb->last_sqlite_rc;
    snprintf(out->last_op, sizeof(out->last_op), "%s", ndb->last_op);
    if (ndb->state_mutex_init) zcl_mutex_unlock(&ndb->state_mutex);
}
