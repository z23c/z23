/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_fetch_log_store — implementation. See body_fetch_log_store.h. */

#include "body_fetch_log_store.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool body_fetch_log_ensure_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS body_fetch_log ("
        "  height      INTEGER PRIMARY KEY,"
        "  hash        BLOB    NOT NULL,"
        "  source      TEXT    NOT NULL,"
        "  bytes       INTEGER NOT NULL DEFAULT 0,"
        "  fetched_at  INTEGER NOT NULL,"
        "  ok          INTEGER NOT NULL,"
        "  fail_reason TEXT"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("body_fetch", "[body_fetch] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

/* Returns 1 if the complete authority row was retrieved, 0 if absent, -1 on
 * query error or malformed hash. */
int body_fetch_vh_log_at(sqlite3 *db, int height, int *out_ok,
                         struct uint256 *out_hash,
                         char *out_reason, size_t reason_size)
{
    if (!db || !out_ok || !out_hash)
        LOG_ERR("body_fetch", "[body_fetch] validate row read null argument");
    *out_ok = -1;
    memset(out_hash, 0, sizeof(*out_hash));
    if (out_reason && reason_size)
        out_reason[0] = 0;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT ok, hash, COALESCE(fail_reason,'') "
        "FROM validate_headers_log WHERE height = ?",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        LOG_ERR("body_fetch", "[body_fetch] vh log prepare failed: %s",
                sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    int found = 0;
    rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 1);
        int blob_n = sqlite3_column_bytes(st, 1);
        if (!blob || blob_n != 32) {
            sqlite3_finalize(st);
            LOG_ERR("body_fetch",
                    "[body_fetch] malformed validate hash height=%d bytes=%d",
                    height, blob_n);
        }
        *out_ok = sqlite3_column_int(st, 0);
        memcpy(out_hash->data, blob, 32);
        const unsigned char *txt = sqlite3_column_text(st, 2);
        if (txt && out_reason && reason_size)
            snprintf(out_reason, reason_size, "%s", (const char *)txt);
        found = 1;
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        LOG_ERR("body_fetch",
                "[body_fetch] vh log step failed height=%d rc=%d: %s",
                height, rc, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);
    return found;
}

bool body_fetch_log_insert(sqlite3 *db, int height,
                           const struct uint256 *hash,
                           const char *source, int64_t bytes,
                           bool ok, const char *reason)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO body_fetch_log "
        "(height, hash, source, bytes, fetched_at, ok, fail_reason) "
        "VALUES (?,?,?,?,?,?,?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("body_fetch", "[body_fetch] prepare insert failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_blob (stmt, 2, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_text (stmt, 3, source, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)bytes);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)platform_time_wall_unix());
    sqlite3_bind_int  (stmt, 6, ok ? 1 : 0);
    if (reason)
        sqlite3_bind_text(stmt, 7, reason, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 7);

    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_WARN("body_fetch", "[body_fetch] insert height=%d rc=%d", height, rc);
        return false;
    }
    return true;
}
