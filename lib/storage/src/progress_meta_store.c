/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * progress_meta — implementation of the small key/value table colocated
 * with stage_cursor in the progress store (consensus.db). Split out of
 * progress_store.c: this module never touches that file's process-wide
 * singleton statics (g_db / g_path / g_lock / ...) — every function here
 * takes its `sqlite3 *db` as an explicit argument and serializes only
 * through the public progress_store_tx_lock()/progress_store_tx_unlock()
 * API, so it has no shared file-scope state with progress_store.c. See
 * storage/progress_store.h for the full progress_meta contract. */

#include "storage/progress_store.h"

#include <stdio.h>
#include <string.h>

/* ── progress_meta ─────────────────────────────────────────────────────
 *
 * Tiny k/v table colocated with stage_cursor. See header for purpose.
 * Same kernel-primitive justification as stage_cursor — raw sqlite3_step
 * carries the `// raw-sql-ok:kernel-primitive` marker. */

bool progress_meta_table_ensure(sqlite3 *db)
{
    if (!db) return false;
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value BLOB NOT NULL"
        ")",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:progress-store-open-failure
                "[progress_store] progress_meta CREATE failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool progress_meta_set_stmt(sqlite3 *db, const char *key,
                                   const void *value, size_t value_len)
{
    if (!db || !key || !key[0]) return false;
    if (value_len > 0 && !value) return false;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO progress_meta(key, value) VALUES(?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, value ? value : "", (int)value_len,
                      SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

static bool progress_meta_delete_stmt(sqlite3 *db, const char *key)
{
    if (!db || !key || !key[0]) return false;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM progress_meta WHERE key = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool progress_meta_set_in_tx(sqlite3 *db, const char *key,
                             const void *value, size_t value_len)
{
    return progress_meta_set_stmt(db, key, value, value_len);
}

bool progress_meta_delete_in_tx(sqlite3 *db, const char *key)
{
    return progress_meta_delete_stmt(db, key);
}

bool progress_meta_raise_u64_in_tx(sqlite3 *db, const char *key, uint64_t value,
                                   bool *raised, uint64_t *winner)
{
    if (raised) *raised = false;
    if (winner) *winner = value;
    if (!db || !key || !key[0]) return false;

    /* Read the current floor with exact-BLOB semantics (fail closed on any
     * coercible non-BLOB / wrong-length value). Reuses the caller's open txn —
     * progress_meta_get_blob_exact takes the recursive lock internally. */
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool present = false;
    if (!progress_meta_get_blob_exact(db, key, blob, sizeof(blob), &n,
                                      &present))
        return false;
    uint64_t prior = 0;
    if (present) {
        if (n != sizeof(blob))
            return false;  /* malformed floor — never overwrite, fail closed */
        for (int i = 7; i >= 0; i--)
            prior = (prior << 8) | blob[i];
    }

    if (present && value <= prior) {
        if (winner) *winner = prior;
        return true;  /* raise-only: a non-greater value is a no-op */
    }

    uint8_t out[8];
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)((value >> (8 * i)) & 0xff);
    if (!progress_meta_set_in_tx(db, key, out, sizeof(out)))
        return false;
    if (raised) *raised = true;
    if (winner) *winner = value;
    return true;
}

/* Single-source the transaction discipline shared by progress_meta_set and
 * progress_meta_delete: lock, open a transaction, run op, commit on success /
 * roll back on failure, unlock. op binds and steps its own statement.
 *
 * Batch-aware (same proven pattern as stage.c cursor_txn_*): when a
 * transaction is already open on this connection (an outer drain batch or a
 * caller BEGIN — sqlite3_get_autocommit(db)==0), a bare BEGIN IMMEDIATE would
 * fail with "cannot start a transaction within a transaction". Nest as a named
 * SAVEPOINT instead so the op enrolls in the outer transaction and commits /
 * rolls back atomically with it. The savepoint name is distinct from
 * STAGE_CURSOR_SP so it never collides. progress_store_tx_lock is recursive, so
 * re-acquiring inside a batch is safe. This removes the latent nested-BEGIN
 * class for bare call sites (e.g. stage_repair_coin_backfill*) that were safe
 * before only by call ordering. */
#define PROGRESS_META_SP "progress_meta_write"
static void progress_meta_txn_rollback(sqlite3 *db, bool nested)
{
    if (nested) {
        sqlite3_exec(db, "ROLLBACK TO SAVEPOINT " PROGRESS_META_SP,
                     NULL, NULL, NULL);
        sqlite3_exec(db, "RELEASE SAVEPOINT " PROGRESS_META_SP, NULL, NULL, NULL);
    } else {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
}
static bool progress_meta_run_in_tx(sqlite3 *db,
                                    bool (*op)(sqlite3 *, void *), void *arg)
{
    if (!db) return false;
    progress_store_tx_lock();
    bool nested = sqlite3_get_autocommit(db) == 0;
    char *err = NULL;
    if (sqlite3_exec(db, nested ? "SAVEPOINT " PROGRESS_META_SP
                                : "BEGIN IMMEDIATE",
                     NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    bool ok = op(db, arg);
    if (!ok) {
        progress_meta_txn_rollback(db, nested);
        progress_store_tx_unlock();
        return false;
    }
    const char *fini = nested ? "RELEASE SAVEPOINT " PROGRESS_META_SP : "COMMIT";
    if (sqlite3_exec(db, fini, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        /* Commit/release failed: roll the op back so we never leave a
         * half-applied write inside the outer transaction, then report it. */
        progress_meta_txn_rollback(db, nested);
        progress_store_tx_unlock();
        return false;
    }
    progress_store_tx_unlock();
    return ok;
}

struct progress_meta_set_args {
    const char *key;
    const void *value;
    size_t value_len;
};

static bool progress_meta_set_op(sqlite3 *db, void *arg)
{
    struct progress_meta_set_args *a = arg;
    return progress_meta_set_stmt(db, a->key, a->value, a->value_len);
}

static bool progress_meta_delete_op(sqlite3 *db, void *arg)
{
    return progress_meta_delete_stmt(db, (const char *)arg);
}

bool progress_meta_set(sqlite3 *db, const char *key,
                       const void *value, size_t value_len)
{
    struct progress_meta_set_args a = { key, value, value_len };
    return progress_meta_run_in_tx(db, progress_meta_set_op, &a);
}

bool progress_meta_delete(sqlite3 *db, const char *key)
{
    return progress_meta_run_in_tx(db, progress_meta_delete_op, (void *)key);
}

bool progress_meta_get(sqlite3 *db, const char *key,
                       void *out_buf, size_t out_cap,
                       size_t *out_len, bool *out_found)
{
    if (out_found) *out_found = false;
    if (out_len) *out_len = 0;
    if (!db || !key || !key[0]) return false;

    progress_store_tx_lock();
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT value FROM progress_meta WHERE key = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    bool ok = true;
    if (rc == SQLITE_ROW) {
        if (out_found) *out_found = true;
        int n = sqlite3_column_bytes(stmt, 0);
        const void *blob = sqlite3_column_blob(stmt, 0);
        if (out_len) *out_len = (size_t)n;
        if (out_buf && out_cap > 0) {
            size_t copy = (size_t)n < out_cap ? (size_t)n : out_cap;
            if (blob && copy > 0) memcpy(out_buf, blob, copy);
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    progress_store_tx_unlock();
    return ok;
}

bool progress_meta_get_blob_exact(sqlite3 *db, const char *key,
                                  void *out_buf, size_t out_cap,
                                  size_t *out_len, bool *out_found)
{
    if (out_found) *out_found = false;
    if (out_len) *out_len = 0;
    if (out_buf && out_cap > 0)
        memset(out_buf, 0, out_cap);
    if (!db || !key || !key[0]) return false;

    progress_store_tx_lock();
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT value FROM progress_meta WHERE key = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }
    if (sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        progress_store_tx_unlock();
        return false;
    }

    rc = sqlite3_step(stmt);  // raw-sql-ok:kernel-primitive
    bool ok = true;
    if (rc == SQLITE_ROW) {
        if (out_found) *out_found = true;
        if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB) {
            ok = false;
        } else {
            int n = sqlite3_column_bytes(stmt, 0);
            const void *blob = sqlite3_column_blob(stmt, 0);
            if (n < 0 || (n > 0 && !blob) ||
                (out_buf && (size_t)n > out_cap)) {
                ok = false;
            } else if (out_buf && n > 0) {
                memcpy(out_buf, blob, (size_t)n);
            }
            if (ok && out_len) *out_len = (size_t)n;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    progress_store_tx_unlock();
    return ok;
}
