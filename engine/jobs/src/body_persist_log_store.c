/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_persist_log_store — implementation. See body_persist_log_store.h. */

#include "body_persist_log_store.h"

#include "platform/time_compat.h"
#include "jobs/stage_log_rows.h"
#include "jobs/stage_row_itag.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Per-block prepared-statement cache, mirroring created_outputs_index: inside a
 * stage drain batch the same INSERT / SELECT is issued once per block, so a
 * fresh prepare/finalize each call is pure overhead. Cache both statements
 * thread-locally, keyed on the outer batch generation; outside a batch each
 * call still prepares and finalizes (identical to the historical path). */
static _Thread_local sqlite3      *g_insert_db;
static _Thread_local sqlite3_stmt *g_insert_stmt;
static _Thread_local uint64_t      g_insert_generation;

static _Thread_local sqlite3      *g_fetch_db;
static _Thread_local sqlite3_stmt *g_fetch_stmt;
static _Thread_local uint64_t      g_fetch_generation;

void body_persist_log_store_batch_reset(void)
{
    if (g_insert_stmt)
        sqlite3_finalize(g_insert_stmt);
    g_insert_stmt = NULL;
    g_insert_db = NULL;
    g_insert_generation = 0;

    if (g_fetch_stmt)
        sqlite3_finalize(g_fetch_stmt);
    g_fetch_stmt = NULL;
    g_fetch_db = NULL;
    g_fetch_generation = 0;
}

static sqlite3_stmt *bp_insert_stmt(sqlite3 *db, bool *cached_out)
{
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (batched && g_insert_stmt && g_insert_db == db &&
        g_insert_generation == generation) {
        *cached_out = true;
        return g_insert_stmt;
    }
    if (g_insert_stmt) {
        sqlite3_finalize(g_insert_stmt);
        g_insert_stmt = NULL;
        g_insert_db = NULL;
        g_insert_generation = 0;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO body_persist_log "
        "(height, source, ok, persisted_at, itag) VALUES (?,?,?,?,?)",
        -1, &st, NULL) != SQLITE_OK)
        return NULL;
    if (batched) {
        g_insert_db = db;
        g_insert_stmt = st;
        g_insert_generation = generation;
        *cached_out = true;
    } else {
        *cached_out = false;
    }
    return st;
}

static sqlite3_stmt *bp_fetch_stmt(sqlite3 *db, bool *cached_out)
{
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (batched && g_fetch_stmt && g_fetch_db == db &&
        g_fetch_generation == generation) {
        *cached_out = true;
        return g_fetch_stmt;
    }
    if (g_fetch_stmt) {
        sqlite3_finalize(g_fetch_stmt);
        g_fetch_stmt = NULL;
        g_fetch_db = NULL;
        g_fetch_generation = 0;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT source, ok FROM body_fetch_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK)
        return NULL;
    if (batched) {
        g_fetch_db = db;
        g_fetch_stmt = st;
        g_fetch_generation = generation;
        *cached_out = true;
    } else {
        *cached_out = false;
    }
    return st;
}

/* Idempotent ADD COLUMN: tolerate "duplicate column name" (already migrated). */
static bool add_column_if_missing(sqlite3 *db, const char *alter_sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, alter_sql, NULL, NULL, &err) == SQLITE_OK)
        return true;
    bool dup = err && strstr(err, "duplicate column name") != NULL;
    if (!dup)
        LOG_WARN("body_persist", "[body_persist] schema alter failed: %s",
                 err ? err : "(no message)");
    if (err) sqlite3_free(err);
    return dup;
}

bool body_persist_log_ensure_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  source       TEXT    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  persisted_at INTEGER NOT NULL,"
        "  itag         BLOB"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("body_persist", "[body_persist] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    /* Per-row integrity tag (see stage_row_itag.h). */
    if (!add_column_if_missing(db,
            "ALTER TABLE body_persist_log ADD COLUMN itag BLOB"))
        return false;
    bool ok = stage_row_itag_backfill(db, "body_persist_log");
    /* Seed the O(1) published row counter once per boot (see stage_log_rows.h);
     * the body_persist dump reads it lock-free instead of a blocking COUNT(*). */
    if (ok)
        stage_log_rows_seed(db, "body_persist_log");
    return ok;
}

int body_persist_body_fetch_log_at(sqlite3 *db, int height,
                                   struct body_fetch_row *out)
{
    memset(out, 0, sizeof(*out));
    out->ok = -1;
    bool cached = false;
    sqlite3_stmt *st = bp_fetch_stmt(db, &cached);
    if (!st) {
        LOG_WARN("body_persist", "[body_persist] body_fetch_log prepare failed: %s", sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_reset(st);
    sqlite3_bind_int(st, 1, height);
    int found = 0;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const unsigned char *src = sqlite3_column_text(st, 0);
        if (src)
            snprintf(out->source, sizeof(out->source), "%s",
                     (const char *)src);
        out->ok = sqlite3_column_int(st, 1);
        found = 1;
    }
    /* Release the read cursor before returning: a parked SELECT cursor on the
     * shared WAL connection permanently wedges writers (see MEMORY). */
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    if (!cached)
        sqlite3_finalize(st);
    return found;
}

bool body_persist_log_insert(sqlite3 *db, int height, const char *source, bool ok)
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("body_persist_log", (int64_t)height, ok ? 1 : 0,
                           NULL, 0, itag);

    bool cached = false;
    sqlite3_stmt *stmt = bp_insert_stmt(db, &cached);
    if (!stmt) {
        LOG_WARN("body_persist", "[body_persist] prepare insert failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_reset(stmt);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_text (stmt, 2, source, -1, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 3, ok ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)platform_time_wall_unix());
    sqlite3_bind_blob (stmt, 5, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    if (!cached)
        sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_WARN("body_persist", "[body_persist] insert height=%d rc=%d", height, rc);
        if (cached)
            body_persist_log_store_batch_reset();
        return false;
    }
    /* Runs under the caller's progress-store write lock (stage_run_once). */
    stage_log_rows_note_insert("body_persist_log");
    return true;
}
