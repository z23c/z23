/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate_log_store — implementation. See proof_validate_log_store.h. */

#include "proof_validate_log_store.h"

#include "platform/time_compat.h"
#include "jobs/stage_log_rows.h"
#include "jobs/stage_row_itag.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

static bool add_column_if_missing(sqlite3 *db, const char *sql,
                                  const char *column)
{
    char *error = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK)
        return true;
    bool duplicate = error &&
        strstr(error, "duplicate column name") != NULL;
    if (!duplicate)
        LOG_WARN("proof_validate",
                 "[proof_validate] %s migration failed: %s", column,
                 error ? error : "(no message)");
    if (error) sqlite3_free(error);
    return duplicate;
}

bool proof_validate_log_ensure_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height                  INTEGER PRIMARY KEY,"
        "  status                  TEXT    NOT NULL,"
        "  ok                      INTEGER NOT NULL,"
        "  sapling_spends_total    INTEGER NOT NULL,"
        "  sapling_outputs_total   INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash              BLOB,"
        "  source_epoch_digest     BLOB,"
        "  first_failure_txid      BLOB,"
        "  first_failure_proof_type TEXT,"
        "  validated_at            INTEGER NOT NULL"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("proof_validate", "[proof_validate] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    if (!add_column_if_missing(
               db, "ALTER TABLE proof_validate_log ADD COLUMN block_hash BLOB",
               "block_hash") ||
        !add_column_if_missing(
               db, "ALTER TABLE proof_validate_log ADD COLUMN "
                   "source_epoch_digest BLOB",
               "source_epoch_digest"))
        return false;
    /* Per-row integrity tag (see stage_row_itag.h): status IS folded in —
     * proof_validate_log is status-covered by the reducer fold. */
    if (!add_column_if_missing(
               db, "ALTER TABLE proof_validate_log ADD COLUMN itag BLOB",
               "itag"))
        return false;
    bool ok = stage_row_itag_backfill(db, "proof_validate_log");
    if (ok)
        stage_log_rows_seed(db, "proof_validate_log");
    return ok;
}

int proof_validate_script_validate_log_at(sqlite3 *db, int height,
                                          struct script_validate_row *out)
{
    memset(out, 0, sizeof(*out));
    out->ok = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, block_hash FROM script_validate_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("proof_validate", "[proof_validate] script_validate_log prepare failed: %s", sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_bind_int(st, 1, height);
    int found = 0;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        out->ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER
                    ? sqlite3_column_int(st, 0) : -1;
        int status_type = sqlite3_column_type(st, 1);
        const void *status = status_type == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
        if (status)
            out->evidence = mint_validation_evidence_parse(
                status, (size_t)sqlite3_column_bytes(st, 1));
        int hash_type = sqlite3_column_type(st, 2);
        const void *hash = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 2) : NULL;
        int hash_size = hash ? sqlite3_column_bytes(st, 2) : 0;
        if (hash && hash_size == 32) {
            memcpy(out->block_hash.data, hash, 32);
            out->has_block_hash = true;
        }
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

bool proof_validate_log_insert(sqlite3 *db, int height,
                               const char *status, bool ok,
                               size_t sapling_spends_total,
                               size_t sapling_outputs_total,
                               size_t sprout_joinsplits_total,
                               const struct uint256 *block_hash,
                               const struct uint256 *first_failure_txid,
                               const char *first_failure_proof_type)
{
    uint8_t source_epoch[32] = {0};
    size_t source_epoch_size = 0;
    bool source_epoch_found = false;
    progress_store_tx_lock();
    if (!progress_meta_get_blob_exact(
            db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
            source_epoch, sizeof(source_epoch), &source_epoch_size,
            &source_epoch_found) ||
        (source_epoch_found && source_epoch_size != sizeof(source_epoch))) {
        LOG_WARN("proof_validate",
                 "[proof_validate] malformed source epoch authority h=%d",
                 height);
        progress_store_tx_unlock();
        return false;
    }
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("proof_validate_log", (int64_t)height, ok ? 1 : 0,
                           status, status ? strlen(status) : 0, itag);
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, "
        " sapling_outputs_total, sprout_joinsplits_total, "
        " block_hash, first_failure_txid, first_failure_proof_type, "
        " validated_at, source_epoch_digest, itag) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("proof_validate", "[proof_validate] prepare insert failed: %s", sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_text (stmt, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 3, ok ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)sapling_spends_total);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)sapling_outputs_total);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)sprout_joinsplits_total);
    if (block_hash)
        sqlite3_bind_blob(stmt, 7, block_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 7);
    if (first_failure_txid)
        sqlite3_bind_blob(stmt, 8, first_failure_txid->data, 32,
                          SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 8);
    if (first_failure_proof_type)
        sqlite3_bind_text(stmt, 9, first_failure_proof_type, -1,
                          SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 9);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)platform_time_wall_unix());
    if (source_epoch_found)
        rc = sqlite3_bind_blob(stmt, 11, source_epoch,
                               (int)sizeof(source_epoch), SQLITE_STATIC);
    else
        rc = sqlite3_bind_null(stmt, 11);
    if (rc != SQLITE_OK) {
        LOG_WARN("proof_validate",
                 "[proof_validate] source epoch bind failed height=%d",
                 height);
        sqlite3_finalize(stmt);
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_blob(stmt, 12, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE)
        stage_log_rows_note_insert("proof_validate_log");
    progress_store_tx_unlock();
    if (rc != SQLITE_DONE) {
        LOG_WARN("proof_validate", "[proof_validate] insert height=%d rc=%d", height, rc);
        return false;
    }
    return true;
}

int proof_validate_log_lowest_null_block_hash(sqlite3 *db,
                                              int floor_height,
                                              int ceil_height,
                                              int *out_height,
                                              int64_t *out_count)
{
    if (out_height) *out_height = -1;
    if (out_count)  *out_count = 0;
    if (!db) {
        LOG_WARN("proof_validate",
                 "[proof_validate] null-hash scan: NULL db");
        return -1;  // raw-return-ok:logged-above
    }
    if (floor_height < 0) floor_height = 0;
    /* Empty / inverted range is a clean no-op, not an error. */
    if (ceil_height <= floor_height)
        return 0;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT MIN(height), COUNT(*) FROM proof_validate_log "
            "WHERE height >= ? AND height < ? AND ok = 1 "
            "AND block_hash IS NULL",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("proof_validate",
                 "[proof_validate] null-hash scan prepare failed: %s",
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
        LOG_WARN("proof_validate",
                 "[proof_validate] null-hash scan step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return found;
}

bool proof_validate_log_delete_null_block_hash_suffix(sqlite3 *db,
                                                      int from_height,
                                                      int64_t *out_deleted)
{
    if (out_deleted) *out_deleted = 0;
    if (!db) {
        LOG_WARN("proof_validate",
                 "[proof_validate] null-hash delete: NULL db");
        return false;
    }
    if (from_height < 0) from_height = 0;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM proof_validate_log "
            "WHERE height >= ? AND block_hash IS NULL",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("proof_validate",
                 "[proof_validate] null-hash delete prepare failed: %s",
                 sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int(st, 1, from_height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        LOG_WARN("proof_validate",
                 "[proof_validate] null-hash delete failed from=%d rc=%d",
                 from_height, rc);
        progress_store_tx_unlock();
        return false;
    }
    int64_t deleted = (int64_t)sqlite3_changes(db);
    if (out_deleted) *out_deleted = deleted;
    stage_log_rows_note_delete("proof_validate_log", deleted);
    progress_store_tx_unlock();
    return true;
}
