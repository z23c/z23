/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_log_store — implementation. See validate_headers_log_store.h. */

#include "validate_headers_log_store.h"

#include "platform/time_compat.h"
#include "jobs/stage_row_itag.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* Idempotent ADD COLUMN: tolerate "duplicate column name" (already migrated),
 * fail loud on any other error. */
static bool add_column_if_missing(sqlite3 *db, const char *alter_sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, alter_sql, NULL, NULL, &err) == SQLITE_OK)
        return true;
    bool dup = err && strstr(err, "duplicate column name") != NULL;
    if (!dup)
        LOG_WARN("validate_headers",
                 "[validate_headers] schema alter failed: %s",
                 err ? err : "(no message)");
    if (err) sqlite3_free(err);
    return dup;
}

bool validate_headers_log_ensure_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  hash         BLOB    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  fail_reason  TEXT,"
        "  validated_at INTEGER NOT NULL,"
        "  itag         BLOB"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("validate_headers", "[validate_headers] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    /* Per-row integrity tag (see stage_row_itag.h): stamp it on existing tables
     * and backfill legacy rows once so the reducer fold can reject a flipped
     * verdict byte and LOWER H* rather than silently raise it. */
    if (!add_column_if_missing(db,
            "ALTER TABLE validate_headers_log ADD COLUMN itag BLOB"))
        return false;
    /* Partial index for the failure-summary reads (COUNT ok=0 + the earliest/
     * latest ok=0 rows in validate_headers_report.c). Without it, COUNT(*)
     * WHERE ok=0 full-scans up to ~3.1M rows (ok=0 is normally empty) under
     * progress_store_tx_lock — the A2 amplifier the utxo_apply
     * idx_utxo_apply_log_ok0 fix addressed. Bounds the non-blocking dumper's
     * lock hold to the handful of failure rows. Idempotent; advisory-perf
     * only, so a create failure is logged but does not fail schema-ensure. */
    char *ierr = NULL;
    if (sqlite3_exec(db,
            "CREATE INDEX IF NOT EXISTS idx_validate_headers_log_ok0 "
            "  ON validate_headers_log(height) WHERE ok = 0",
            NULL, NULL, &ierr) != SQLITE_OK)
        LOG_WARN("validate_headers",
                 "[validate_headers] ok=0 index create failed: %s",
                 ierr ? ierr : "(no message)");
    if (ierr) sqlite3_free(ierr);
    return stage_row_itag_backfill(db, "validate_headers_log");
}

bool validate_headers_log_insert(sqlite3 *db, int height,
                                 const struct uint256 *hash, bool ok,
                                 const char *reason)
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("validate_headers_log", (int64_t)height, ok ? 1 : 0,
                           NULL, 0, itag);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO validate_headers_log "
        "(height, hash, ok, fail_reason, validated_at, itag) "
        "VALUES (?,?,?,?,?,?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("validate_headers", "[validate_headers] prepare insert failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_blob (stmt, 2, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 3, ok ? 1 : 0);
    if (!ok && reason && reason[0])
        sqlite3_bind_text(stmt, 4, reason, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 4);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)platform_time_wall_unix());
    sqlite3_bind_blob (stmt, 6, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_WARN("validate_headers", "[validate_headers] insert height=%d rc=%d", height, rc);
        return false;
    }
    return true;
}
