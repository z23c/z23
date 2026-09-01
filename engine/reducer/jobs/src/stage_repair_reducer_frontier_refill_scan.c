/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SELECT-only scan helpers for retained reducer-frontier cursor refill.
 * The owning repair orchestration lives in stage_repair_reducer_frontier_refill.c.
 *
 * // repair-rung-ok:test_stage_repair_script_refill
 */

#include "stage_repair_reducer_frontier_internal.h"

#include "util/log_macros.h"

#include <sqlite3.h>

/* Shared scan runner: `sql` selects the single lowest hole height and binds
 * exactly two integer bounds (start, end). *out_height = -1 when no hole. */
static bool find_lowest_hole_unlocked(
    sqlite3 *db,
    const char *label,
    const char *sql,
    int start_height,
    int end_height,
    int *out_height)
{
    if (out_height)
        *out_height = -1;
    if (!db || !out_height)
        return false;
    if (start_height > end_height)
        return true;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s scan prepare failed: %s",
                 label, sqlite3_errmsg(db));
        return false;
    }

    sqlite3_bind_int(st, 1, start_height);
    sqlite3_bind_int(st, 2, end_height);

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_height = sqlite3_column_int(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s scan failed rc=%d: %s",
                 label, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }

    sqlite3_finalize(st);
    return true;
}

bool stage_reducer_frontier_find_lowest_validate_headers_refill_hole_unlocked(
    sqlite3 *db,
    int start_height,
    int end_height,
    int *out_height)
{
    return find_lowest_hole_unlocked(db, "validate_headers refill",
        "SELECT h.height "
        "FROM header_admit_log h "
        "LEFT JOIN validate_headers_log v ON v.height = h.height "
        "WHERE h.height >= ? AND h.height <= ? "
        "AND v.height IS NULL "
        "ORDER BY h.height ASC LIMIT 1",
        start_height, end_height, out_height);
}

bool stage_reducer_frontier_find_lowest_validate_headers_hash_split_unlocked(
    sqlite3 *db,
    int start_height,
    int end_height,
    int *out_height)
{
    return find_lowest_hole_unlocked(db, "validate_headers hash-split",
        "SELECT v.height "
        "FROM validate_headers_log v "
        "JOIN script_validate_log s ON s.height = v.height "
        "WHERE v.height >= ? AND v.height <= ? "
        "AND v.ok = 1 AND s.ok = 1 "
        "AND length(v.hash) = 32 AND length(s.block_hash) = 32 "
        "AND v.hash <> s.block_hash "
        "ORDER BY v.height ASC LIMIT 1",
        start_height, end_height, out_height);
}

bool stage_reducer_frontier_find_lowest_body_fetch_refill_hole_unlocked(
    sqlite3 *db,
    int start_height,
    int end_height,
    int *out_height)
{
    return find_lowest_hole_unlocked(db, "body_fetch refill",
        "SELECT v.height "
        "FROM validate_headers_log v "
        "LEFT JOIN body_fetch_log b ON b.height = v.height "
        "WHERE v.height >= ? AND v.height <= ? "
        "AND v.ok = 1 AND b.height IS NULL "
        "ORDER BY v.height ASC LIMIT 1",
        start_height, end_height, out_height);
}

bool stage_reducer_frontier_find_lowest_body_persist_refill_hole_unlocked(
    sqlite3 *db,
    int start_height,
    int end_height,
    int *out_height)
{
    return find_lowest_hole_unlocked(db, "body_persist refill",
        "SELECT b.height "
        "FROM body_fetch_log b "
        "LEFT JOIN body_persist_log p ON p.height = b.height "
        "WHERE b.height >= ? AND b.height <= ? "
        "AND b.ok = 1 AND p.height IS NULL "
        "ORDER BY b.height ASC LIMIT 1",
        start_height, end_height, out_height);
}

bool stage_reducer_frontier_find_lowest_script_validate_refill_hole_unlocked(
    sqlite3 *db,
    int start_height,
    int end_height,
    int *out_height)
{
    return find_lowest_hole_unlocked(db, "script_validate refill",
        "SELECT b.height "
        "FROM body_persist_log b "
        "LEFT JOIN script_validate_log s ON s.height = b.height "
        "WHERE b.height >= ? AND b.height <= ? "
        "AND b.ok = 1 AND (s.height IS NULL OR (s.ok=1 AND "
        "(typeof(s.status)!='text' OR "
        "CAST(s.status AS BLOB)!=CAST('verified' AS BLOB)))) "
        "ORDER BY b.height ASC LIMIT 1",
        start_height, end_height, out_height);
}

bool stage_reducer_frontier_find_lowest_proof_validate_refill_hole_unlocked(
    sqlite3 *db,
    int start_height,
    int end_height,
    int *out_height)
{
    return find_lowest_hole_unlocked(db, "proof_validate refill",
        "SELECT s.height "
        "FROM script_validate_log s "
        "LEFT JOIN proof_validate_log p ON p.height = s.height "
        "WHERE s.height >= ? AND s.height <= ? "
        "AND s.ok = 1 AND typeof(s.status)='text' AND "
        "CAST(s.status AS BLOB)=CAST('verified' AS BLOB) AND "
        "(p.height IS NULL OR (p.ok=1 AND (typeof(p.status)!='text' OR "
        "CAST(p.status AS BLOB)!=CAST('verified' AS BLOB)))) "
        "ORDER BY s.height ASC LIMIT 1",
        start_height, end_height, out_height);
}

/* Shared row-presence probe: `sql` is "SELECT 1 FROM <log> WHERE height = ?
 * LIMIT 1". A present row (any verdict) is evidence the stage already
 * spoke at that height. */
static bool log_row_present_unlocked(
    sqlite3 *db,
    const char *label,
    const char *sql,
    int height,
    bool *present)
{
    if (present)
        *present = false;
    if (!db || !present)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s presence prepare failed: %s",
                 label, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *present = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s presence failed h=%d rc=%d: %s",
                 label, height, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }

    sqlite3_finalize(st);
    return true;
}

bool stage_reducer_frontier_body_persist_log_present_unlocked(
    sqlite3 *db,
    int height,
    bool *present)
{
    return log_row_present_unlocked(db, "body_persist",
        "SELECT 1 FROM body_persist_log WHERE height = ? LIMIT 1",
        height, present);
}

bool stage_reducer_frontier_proof_validate_log_present_unlocked(
    sqlite3 *db,
    int height,
    bool *present)
{
    return log_row_present_unlocked(db, "proof_validate",
        "SELECT 1 FROM proof_validate_log WHERE height = ? LIMIT 1",
        height, present);
}
