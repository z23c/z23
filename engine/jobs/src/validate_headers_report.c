/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_report — read-only SQL reporting over the
 * validate_headers_log table.
 * None of this is on the Job's advance-or-block path; it only summarises
 * already-written rows for diagnostics. */

#include "validate_headers_internal.h"

#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void validate_headers_window_report_init(
    struct validate_headers_window_report *r,
    int64_t start_height,
    int64_t end_height)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->start_height = start_height;
    r->end_height = end_height;
    r->first_failed_height = -1;
    r->first_fail_reason[0] = '\0';
    if (start_height >= 0 && end_height >= start_height)
        r->expected_count = end_height - start_height + 1;
}

bool validate_headers_stage_window_report(
    int64_t start_height,
    int64_t end_height,
    struct validate_headers_window_report *out)
{
    validate_headers_window_report_init(out, start_height, end_height);
    if (!out || out->expected_count <= 0)
        return false;

    sqlite3 *db = progress_store_db();
    if (!db)
        return false;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT COUNT(*),"
        "       SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END)"
        "  FROM validate_headers_log"
        " WHERE height BETWEEN ? AND ?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        /* "no such table" is NORMAL before validate_headers_stage_init
         * has ensured the schema (cold-import boots run this report
         * while boot is still in flight) — report "no data", silently.
         * The old per-call LOG_ERR emitted thousands of journal lines
         * per boot. Anything else is a real error and stays loud. */
        const char *em = sqlite3_errmsg(db);
        if (!em || !strstr(em, "no such table"))
            /* LOG_WARN, not LOG_ERR: LOG_ERR embeds `return -1`, which
             * in this bool function returned TRUE and skipped the
             * tx unlock below — a lock leak on every real DB error. */
            LOG_WARN("validate_headers",
                     "window report count prepare failed: %s",
                     em ? em : "(null)");
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)start_height);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)end_height);
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        out->checked_count = sqlite3_column_int64(st, 0);
        out->failed_count = sqlite3_column_int64(st, 1);
        out->available = true;
    }
    sqlite3_finalize(st);

    rc = sqlite3_prepare_v2(db,
        "SELECT height, COALESCE(fail_reason, '')"
        "  FROM validate_headers_log"
        " WHERE height BETWEEN ? AND ? AND ok=0"
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        const char *em2 = sqlite3_errmsg(db);
        if (!em2 || !strstr(em2, "no such table"))
            /* LOG_WARN, not LOG_ERR — see the count-prepare branch. */
            LOG_WARN("validate_headers",
                     "window report fail prepare failed: %s",
                     em2 ? em2 : "(null)");
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)start_height);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)end_height);
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        out->first_failed_height = sqlite3_column_int64(st, 0);
        const unsigned char *reason = sqlite3_column_text(st, 1);
        snprintf(out->first_fail_reason, sizeof(out->first_fail_reason),
                 "%s", reason ? (const char *)reason : "");
    }
    sqlite3_finalize(st);

    out->complete = out->available &&
                    out->checked_count == out->expected_count;
    progress_store_tx_unlock();
    return out->available;
}

static void validate_headers_failure_summary_init(
    struct validate_headers_failure_summary *s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->first_height = -1;
    s->last_height = -1;
}

void validate_headers_failure_summary_load(
    struct validate_headers_failure_summary *out)
{
    validate_headers_failure_summary_init(out);
    if (!out) return;

    sqlite3 *db = progress_store_db();
    if (!db)
        return;

    /* Observability must never queue behind a fold. The reducer holds
     * progress_store_tx_lock around each bulk header-validation batch; take it
     * NON-BLOCKING (trylock) and, when the fold owns it, report busy and return
     * the init'd summary rather than blocking an RPC worker. Mirrors the A2
     * stage-dump trylock fix. The ok=0 reads below are index-backed
     * (idx_validate_headers_log_ok0), so the successful-trylock hold is bounded
     * to the handful of failure rows, never a full-table scan under the lock. */
    if (!progress_store_tx_trylock()) {
        out->progress_store_busy = true;
        return;
    }
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM validate_headers_log WHERE ok=0",
        -1, &st, NULL);
    if (rc == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        out->count = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    st = NULL;

    rc = sqlite3_prepare_v2(db,
        "SELECT height, COALESCE(fail_reason, '')"
        "  FROM validate_headers_log"
        " WHERE ok=0"
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL);
    if (rc == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        out->first_height = sqlite3_column_int64(st, 0);
        const unsigned char *reason = sqlite3_column_text(st, 1);
        snprintf(out->first_reason, sizeof(out->first_reason),
                 "%s", reason ? (const char *)reason : "");
    }
    sqlite3_finalize(st);
    st = NULL;

    rc = sqlite3_prepare_v2(db,
        "SELECT height, COALESCE(fail_reason, '')"
        "  FROM validate_headers_log"
        " WHERE ok=0"
        " ORDER BY height DESC LIMIT 1",
        -1, &st, NULL);
    if (rc == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        out->last_height = sqlite3_column_int64(st, 0);
        const unsigned char *reason = sqlite3_column_text(st, 1);
        snprintf(out->last_reason, sizeof(out->last_reason),
                 "%s", reason ? (const char *)reason : "");
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
}
