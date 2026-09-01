/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_log_store — implementation. See script_validate_log_store.h. */

#include "script_validate_log_store.h"

#include "platform/time_compat.h"
#include "jobs/stage_log_rows.h"
#include "jobs/stage_row_itag.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Per-batch caches for the script_validate_log write hot path. Both the INSERT
 * statement and the source-epoch authority blob are constant across a drain
 * batch, so they are prepared/read once per (db, batch generation) on the
 * single drain thread and finalized/invalidated at drain teardown via
 * script_validate_log_store_batch_reset(). Outside a batch every call keeps the
 * original fresh-prepare / fresh-read behaviour. */
static _Thread_local sqlite3 *g_ins_db;
static _Thread_local sqlite3_stmt *g_ins_stmt;
static _Thread_local uint64_t g_ins_gen;

static _Thread_local sqlite3 *g_epoch_db;
static _Thread_local uint64_t g_epoch_gen;
static _Thread_local bool g_epoch_valid;
static _Thread_local uint8_t g_epoch_blob[32];
static _Thread_local size_t g_epoch_size;
static _Thread_local bool g_epoch_found;

void script_validate_log_store_batch_reset(void)
{
    if (g_ins_stmt)
        sqlite3_finalize(g_ins_stmt);
    g_ins_stmt = NULL;
    g_ins_db = NULL;
    g_ins_gen = 0;
    g_epoch_valid = false;
    g_epoch_db = NULL;
    g_epoch_gen = 0;
}

/* Read the source-epoch authority blob (a fold-constant within a batch), caching
 * the result per (db, batch generation). Returns false only on a genuine query
 * error, matching progress_meta_get_blob_exact. Caller holds the progress tx
 * lock. */
static bool sv_source_epoch_get(sqlite3 *db, uint8_t out[32], size_t *size_out,
                                bool *found_out)
{
    bool batched = stage_batch_active();
    uint64_t gen = batched ? stage_batch_generation() : 0;
    if (batched && g_epoch_valid && g_epoch_db == db && g_epoch_gen == gen) {
        memcpy(out, g_epoch_blob, sizeof(g_epoch_blob));
        *size_out = g_epoch_size;
        *found_out = g_epoch_found;
        return true;
    }
    uint8_t blob[32] = {0};
    size_t size = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                                      blob, sizeof(blob), &size, &found))
        return false;
    if (batched) {
        g_epoch_db = db;
        g_epoch_gen = gen;
        memcpy(g_epoch_blob, blob, sizeof(blob));
        g_epoch_size = size;
        g_epoch_found = found;
        g_epoch_valid = true;
    }
    memcpy(out, blob, sizeof(blob));
    *size_out = size;
    *found_out = found;
    return true;
}

/* The script_validate_log upsert statement, prepared once per
 * (db, batch generation). Returns NULL on prepare failure. */
static sqlite3_stmt *sv_log_insert_stmt(sqlite3 *db, bool *cached_out)
{
    bool batched = stage_batch_active();
    uint64_t gen = batched ? stage_batch_generation() : 0;
    if (batched && g_ins_stmt && g_ins_db == db && g_ins_gen == gen) {
        sqlite3_reset(g_ins_stmt);
        sqlite3_clear_bindings(g_ins_stmt);
        *cached_out = true;
        return g_ins_stmt;
    }
    if (g_ins_stmt) {
        sqlite3_finalize(g_ins_stmt);
        g_ins_stmt = NULL;
        g_ins_db = NULL;
        g_ins_gen = 0;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, first_failure_txid, "
        " first_failure_vin, first_failure_serror, validated_at, block_hash, "
        " source_epoch_digest, itag) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        -1, &st, NULL) != SQLITE_OK)
        return NULL;
    if (batched) {
        g_ins_db = db;
        g_ins_stmt = st;
        g_ins_gen = gen;
        *cached_out = true;
    } else {
        *cached_out = false;
    }
    return st;
}

/* Release the INSERT statement after use: a cached statement is reset for the
 * next block in the batch; a fresh (unbatched) statement is finalized. */
static void sv_log_insert_release(sqlite3_stmt *stmt, bool cached)
{
    if (cached) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    } else {
        sqlite3_finalize(stmt);
    }
}

/* Idempotent ADD COLUMN: tolerate "duplicate column name" (already migrated),
 * fail loud on any other error. */
static bool add_column_if_missing(sqlite3 *db, const char *alter_sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, alter_sql, NULL, NULL, &err) == SQLITE_OK)
        return true;
    bool dup = err && strstr(err, "duplicate column name") != NULL;
    if (!dup)
        LOG_WARN("script_validate",
                 "[script_validate] schema alter failed: %s",
                 err ? err : "(no message)");
    if (err) sqlite3_free(err);
    return dup;
}

bool script_validate_log_ensure_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height             INTEGER PRIMARY KEY,"
        "  status             TEXT    NOT NULL,"
        "  ok                 INTEGER NOT NULL,"
        "  tx_count           INTEGER NOT NULL,"
        "  input_count        INTEGER NOT NULL,"
        "  first_failure_txid BLOB,"
        "  first_failure_vin  INTEGER,"
        "  first_failure_serror INTEGER,"
        "  validated_at       INTEGER NOT NULL,"
        "  block_hash         BLOB,"
        "  source_epoch_digest BLOB"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("script_validate", "[script_validate] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    /* Idempotent migrations. block_hash binds an ok=1 row to its block so
     * tip_finalize can reject a stale height-keyed orphan row (different hash). */
    if (!add_column_if_missing(db,
            "ALTER TABLE script_validate_log ADD COLUMN first_failure_serror INTEGER"))
        return false;
    if (!add_column_if_missing(db,
            "ALTER TABLE script_validate_log ADD COLUMN block_hash BLOB"))
        return false;
    if (!add_column_if_missing(db,
            "ALTER TABLE script_validate_log ADD COLUMN "
            "source_epoch_digest BLOB"))
        return false;
    /* Per-row integrity tag (see stage_row_itag.h): status IS folded in —
     * script_validate_log is status-covered by the reducer fold. */
    if (!add_column_if_missing(db,
            "ALTER TABLE script_validate_log ADD COLUMN itag BLOB"))
        return false;
    bool ok = stage_row_itag_backfill(db, "script_validate_log");
    if (ok)
        stage_log_rows_seed(db, "script_validate_log");
    return ok;
}

int script_validate_body_persist_log_at(sqlite3 *db, int height,
                                        struct body_persist_row *out)
{
    memset(out, 0, sizeof(*out));
    out->ok = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT source, ok FROM body_persist_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("script_validate", "[script_validate] body_persist_log prepare failed: %s", sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_bind_int(st, 1, height);
    int found = 0;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int source_type = sqlite3_column_type(st, 0);
        int ok_type = sqlite3_column_type(st, 1);
        const unsigned char *src = source_type == SQLITE_TEXT
            ? sqlite3_column_text(st, 0) : NULL;
        int source_size = src ? sqlite3_column_bytes(st, 0) : -1;
        int ok_value = ok_type == SQLITE_INTEGER
            ? sqlite3_column_int(st, 1) : -1;
        bool source_ok = src && source_size > 0 &&
            source_size < (int)sizeof(out->source) &&
            !memchr(src, '\0', (size_t)source_size) &&
            ((ok_value == 1 && source_size == 8 &&
              memcmp(src, "verified", 8) == 0) ||
             (ok_value == 0 && source_size == 15 &&
              memcmp(src, "upstream_failed", 15) == 0));
        if (!source_ok) {
            LOG_WARN("script_validate",
                     "[script_validate] malformed body_persist_log row h=%d",
                     height);
            sqlite3_finalize(st);
            return -1;  // raw-return-ok:logged-above
        }
        memcpy(out->source, src, (size_t)source_size);
        out->source[source_size] = '\0';
        out->ok = ok_value;
        found = 1;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("script_validate",
                 "[script_validate] body_persist_log step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_finalize(st);
    return found;
}

int script_validate_log_verdict_at(sqlite3 *db, int height,
                                   struct script_validate_verdict_row *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, block_hash FROM script_validate_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("script_validate",
                 "[script_validate] verdict_at prepare failed: %s",
                 sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    if (sqlite3_bind_int(st, 1, height) != SQLITE_OK) {
        LOG_WARN("script_validate",
                 "[script_validate] verdict_at bind failed height=%d", height);
        sqlite3_finalize(st);
        return -1;  // raw-return-ok:logged-above
    }
    int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        out->ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER
                    ? sqlite3_column_int(st, 0) : -1;
        int status_type = sqlite3_column_type(st, 1);
        const void *status = status_type == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
        if (status)
            out->evidence = mint_validation_evidence_parse(
                status, (size_t)sqlite3_column_bytes(st, 1));
        int hash_type = sqlite3_column_type(st, 2);
        const void *blob = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 2) : NULL;
        if (blob &&
            sqlite3_column_bytes(st, 2) == 32) {
            memcpy(out->block_hash.data, blob, 32);
            out->has_block_hash = true;
        }
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

bool script_validate_log_insert(sqlite3 *db, int height,
                                const char *status, bool ok,
                                size_t tx_count, size_t input_count,
                                const struct uint256 *first_failure_txid,
                                int first_failure_vin,
                                ScriptError first_failure_serror,
                                const struct uint256 *block_hash)
{
    uint8_t source_epoch[32] = {0};
    size_t source_epoch_size = 0;
    bool source_epoch_found = false;
    progress_store_tx_lock();
    if (!sv_source_epoch_get(db, source_epoch, &source_epoch_size,
                             &source_epoch_found) ||
        (source_epoch_found && source_epoch_size != sizeof(source_epoch))) {
        LOG_WARN("script_validate",
                 "[script_validate] malformed source epoch authority h=%d",
                 height);
        progress_store_tx_unlock();
        return false;
    }
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("script_validate_log", (int64_t)height, ok ? 1 : 0,
                           status, status ? strlen(status) : 0, itag);
    bool stmt_cached = false;
    sqlite3_stmt *stmt = sv_log_insert_stmt(db, &stmt_cached);
    if (!stmt) {
        LOG_WARN("script_validate", "[script_validate] prepare insert failed: %s", sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    int rc;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_text (stmt, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 3, ok ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)tx_count);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)input_count);
    if (first_failure_txid)
        sqlite3_bind_blob(stmt, 6, first_failure_txid->data, 32,
                          SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 6);
    if (first_failure_vin >= 0)
        sqlite3_bind_int(stmt, 7, first_failure_vin);
    else
        sqlite3_bind_null(stmt, 7);
    /* SCRIPT_ERR_OK persists as NULL so the column is never misread. */
    if (first_failure_serror != SCRIPT_ERR_OK)
        sqlite3_bind_int(stmt, 8, (int)first_failure_serror);
    else
        sqlite3_bind_null(stmt, 8);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)platform_time_wall_unix());
    /* Bind the block's own hash so tip_finalize can prove an ok=1 row is THIS
     * block's verdict (reorg-safe); NULL before the candidate is resolved. */
    if (block_hash)
        sqlite3_bind_blob(stmt, 10, block_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 10);
    if (source_epoch_found)
        rc = sqlite3_bind_blob(stmt, 11, source_epoch,
                               (int)sizeof(source_epoch), SQLITE_STATIC);
    else
        rc = sqlite3_bind_null(stmt, 11);
    if (rc != SQLITE_OK) {
        LOG_WARN("script_validate",
                 "[script_validate] source epoch bind failed height=%d",
                 height);
        sv_log_insert_release(stmt, stmt_cached);
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_blob(stmt, 12, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sv_log_insert_release(stmt, stmt_cached);
    if (rc == SQLITE_DONE)
        stage_log_rows_note_insert("script_validate_log");
    progress_store_tx_unlock();
    if (rc != SQLITE_DONE) {
        LOG_WARN("script_validate", "[script_validate] insert height=%d rc=%d", height, rc);
        return false;
    }
    return true;
}

int script_validate_log_lowest_null_block_hash(sqlite3 *db,
                                               int floor_height,
                                               int ceil_height,
                                               int *out_height,
                                               int64_t *out_count)
{
    if (out_height) *out_height = -1;
    if (out_count)  *out_count = 0;
    if (!db) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash scan: NULL db");
        return -1;  // raw-return-ok:logged-above
    }
    if (floor_height < 0) floor_height = 0;
    /* Empty / inverted range is a clean no-op, not an error. */
    if (ceil_height <= floor_height)
        return 0;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT MIN(height), COUNT(*) FROM script_validate_log "
            "WHERE height >= ? AND height < ? AND ok = 1 "
            "AND block_hash IS NULL",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash scan prepare failed: %s",
                 sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_bind_int(st, 1, floor_height);
    sqlite3_bind_int(st, 2, ceil_height);
    int found = 0;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int64_t count = sqlite3_column_int64(st, 1);
        /* MIN over an empty set is SQL NULL — COUNT==0 is the real signal. */
        if (count > 0 &&
            sqlite3_column_type(st, 0) == SQLITE_INTEGER) {
            found = 1;
            if (out_height) *out_height = sqlite3_column_int(st, 0);
            if (out_count)  *out_count = count;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash scan step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return found;
}

bool script_validate_log_delete_null_block_hash_suffix(sqlite3 *db,
                                                       int from_height,
                                                       int64_t *out_deleted)
{
    if (out_deleted) *out_deleted = 0;
    if (!db) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash delete: NULL db");
        return false;
    }
    if (from_height < 0) from_height = 0;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM script_validate_log "
            "WHERE height >= ? AND block_hash IS NULL",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash delete prepare failed: %s",
                 sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int(st, 1, from_height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash delete failed from=%d rc=%d",
                 from_height, rc);
        progress_store_tx_unlock();
        return false;
    }
    int64_t deleted = (int64_t)sqlite3_changes(db);
    if (out_deleted) *out_deleted = deleted;
    stage_log_rows_note_delete("script_validate_log", deleted);
    progress_store_tx_unlock();
    return true;
}
