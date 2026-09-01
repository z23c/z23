/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * cure_progress_read — bounded read-only progress.kv producer probes. */

#include "storage/cure_progress_read.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int read_sample(sqlite3 *db, const char *sql,
                       int64_t bind_height, int64_t bind_time, bool bind,
                       struct cure_progress_sample *out)
{
    if (!db || !sql || !out)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (bind) {
        sqlite3_bind_int64(st, 1, bind_height);
        sqlite3_bind_int64(st, 2, bind_time);
    }
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    int found = 0;
    if (rc == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
        sqlite3_column_type(st, 1) == SQLITE_INTEGER) {
        out->height = sqlite3_column_int64(st, 0);
        out->time_unix = sqlite3_column_int64(st, 1);
        found = 1;
    } else if (rc != SQLITE_DONE) {
        found = -1;
    }
    sqlite3_finalize(st);
    return found;
}

int cure_progress_read_eta_samples(
    sqlite3 *db, int64_t min_window_seconds,
    struct cure_progress_sample *older, struct cure_progress_sample *newer)
{
    if (!db || !older || !newer || min_window_seconds < 1)
        return -1;
    memset(older, 0, sizeof(*older));
    memset(newer, 0, sizeof(*newer));
    int got = read_sample(
        db, "SELECT height, applied_at FROM utxo_apply_log "
            "WHERE ok=1 AND applied_at>0 ORDER BY height DESC LIMIT 1",
        0, 0, false, newer);
    if (got <= 0)
        return got;
    if (newer->height < 0 || newer->height > INT32_MAX ||
        newer->time_unix <= 0)
        return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height, applied_at FROM utxo_apply_log "
            "WHERE ok=1 AND height<?1 AND applied_at>0 "
            "AND applied_at<=?2-?3 "
            "ORDER BY height DESC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, newer->height);
    sqlite3_bind_int64(st, 2, newer->time_unix);
    sqlite3_bind_int64(st, 3, min_window_seconds);
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    got = 0;
    if (rc == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
        sqlite3_column_type(st, 1) == SQLITE_INTEGER) {
        older->height = sqlite3_column_int64(st, 0);
        older->time_unix = sqlite3_column_int64(st, 1);
        got = 1;
    } else if (rc != SQLITE_DONE) {
        got = -1;
    }
    sqlite3_finalize(st);
    if (got == 1 &&
        (older->height < 0 || older->height > INT32_MAX ||
         older->height >= newer->height || older->time_unix <= 0 ||
         older->time_unix >= newer->time_unix ||
         newer->time_unix - older->time_unix < min_window_seconds))
        return -1;
    return got;
}

int cure_progress_read_body_persist(
    sqlite3 *db, int64_t height, struct cure_body_persist_row *out)
{
    if (!db || !out || height < 0)
        return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT source FROM body_persist_log WHERE height=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, height);
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    int found = 0;
    if (rc == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(st, 0);
        if (text)
            (void)snprintf(out->source, sizeof(out->source), "%s",
                           (const char *)text);
        found = 1;
    } else if (rc != SQLITE_DONE) {
        found = -1;
    }
    sqlite3_finalize(st);
    return found;
}
