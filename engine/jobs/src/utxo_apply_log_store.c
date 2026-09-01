/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_log_store — implementation. See utxo_apply_log_store.h. */

#include "utxo_apply_log_store.h"

#include "platform/time_compat.h"
#include "jobs/stage_log_rows.h"
#include "jobs/stage_row_itag.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* Idempotent ADD COLUMN: tolerate "duplicate column name" (already migrated). */
static bool add_column_if_missing(sqlite3 *db, const char *alter_sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, alter_sql, NULL, NULL, &err) == SQLITE_OK)
        return true;
    bool dup = err && strstr(err, "duplicate column name") != NULL;
    if (!dup)
        LOG_WARN("utxo_apply", "[utxo_apply] schema alter failed: %s",
                 err ? err : "(no message)");
    if (err) sqlite3_free(err);
    return dup;
}

bool utxo_apply_log_ensure_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height               INTEGER PRIMARY KEY,"
        "  status               TEXT    NOT NULL,"
        "  ok                   INTEGER NOT NULL,"
        "  spent_count          INTEGER NOT NULL,"
        "  added_count          INTEGER NOT NULL,"
        "  total_value_delta    INTEGER NOT NULL,"
        "  first_failure_kind   TEXT,"
        "  first_failure_detail BLOB,"
        "  applied_at           INTEGER NOT NULL,"
        "  itag                 BLOB"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    /* Per-row integrity tag (see stage_row_itag.h): status IS folded into the
     * tag for utxo_apply — the reducer fold parses status into VERIFIED. */
    if (!add_column_if_missing(db,
            "ALTER TABLE utxo_apply_log ADD COLUMN itag BLOB"))
        return false;
    /* Partial index for the dump-state "lowest ok=0 row" query
     * (utxo_apply_stage_dump.c: WHERE ok=0 ORDER BY height ASC LIMIT 1). Without
     * it that SELECT full-scans ~3.18M rows on a healthy node (ok is nowhere in
     * the PRIMARY KEY), so a single `dumpstate utxo_apply` walks the whole log.
     * A partial index keyed on height WHERE ok=0 serves both the filter and the
     * ORDER BY from a tiny (usually empty) index, turning the scan into an
     * indexed lookup. Idempotent; advisory-perf only, so a create failure is
     * logged but does not fail schema-ensure. */
    char *ierr = NULL;
    if (sqlite3_exec(db,
            "CREATE INDEX IF NOT EXISTS idx_utxo_apply_log_ok0 "
            "  ON utxo_apply_log(height) WHERE ok = 0",
            NULL, NULL, &ierr) != SQLITE_OK)
        LOG_WARN("utxo_apply", "[utxo_apply] ok=0 index create failed: %s",
                 ierr ? ierr : "(no message)");
    if (ierr) sqlite3_free(ierr);
    bool ok = stage_row_itag_backfill(db, "utxo_apply_log");
    if (ok)
        stage_log_rows_seed(db, "utxo_apply_log");
    return ok;
}

int utxo_apply_proof_validate_log_at(sqlite3 *db, int height,
                                     struct proof_validate_row *out)
{
    memset(out, 0, sizeof(*out));
    out->ok = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, block_hash FROM proof_validate_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] proof_validate_log prepare failed: %s", sqlite3_errmsg(db));
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

bool utxo_apply_log_insert(sqlite3 *db, int height, const char *status, bool ok,
                           size_t spent_count, size_t added_count,
                           int64_t total_value_delta,
                           const char *failure_kind,
                           const uint8_t failure_detail[36])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("utxo_apply_log", (int64_t)height, ok ? 1 : 0,
                           status, status ? strlen(status) : 0, itag);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log "
        "(height, status, ok, spent_count, added_count, total_value_delta, "
        " first_failure_kind, first_failure_detail, applied_at, itag) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] prepare insert failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_text (stmt, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 3, ok ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)spent_count);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)added_count);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)total_value_delta);
    if (failure_kind)
        sqlite3_bind_text(stmt, 7, failure_kind, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 7);
    if (failure_detail)
        sqlite3_bind_blob(stmt, 8, failure_detail, 36, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 8);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)platform_time_wall_unix());
    sqlite3_bind_blob (stmt, 10, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_WARN("utxo_apply", "[utxo_apply] insert height=%d rc=%d", height, rc);
        return false;
    }
    /* Runs under the caller's progress-store write lock (stage_run_once / the
     * reorg + repair paths that co-commit utxo_apply_log with coin mutations). */
    stage_log_rows_note_insert("utxo_apply_log");
    return true;
}
