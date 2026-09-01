/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_log_store — implementation. See tip_finalize_log_store.h. */

#include "tip_finalize_log_store.h"

#include "platform/time_compat.h"
#include "jobs/stage_row_itag.h"
#include "core/arith_uint256.h"
#include "util/boot_scan.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

bool ensure_log_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height           INTEGER PRIMARY KEY,"
        "  status           TEXT    NOT NULL,"
        "  ok               INTEGER NOT NULL,"
        "  work_delta_high  INTEGER NOT NULL,"
        "  work_delta_low   INTEGER NOT NULL,"
        "  utxo_size_after  INTEGER NOT NULL,"
        "  reorg_depth      INTEGER NOT NULL,"
        "  finalized_at     INTEGER NOT NULL"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("tip_finalize", "[tip_finalize] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    if (sqlite3_exec(db,
        "ALTER TABLE tip_finalize_log ADD COLUMN tip_hash BLOB",
        NULL, NULL, &err) != SQLITE_OK) {
        if (!err || strstr(err, "duplicate column name") == NULL) {
            LOG_WARN("tip_finalize", "[tip_finalize] schema alter failed: %s", err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
        sqlite3_free(err);
    }
    /* Per-row integrity tag (see stage_row_itag.h): status is NOT folded in for
     * tip_finalize_log — its reducer verdict is ok-only (status='anchor' feeds a
     * separately-vetted anchor-selection path). The tag covers (height, ok). */
    err = NULL;
    if (sqlite3_exec(db,
        "ALTER TABLE tip_finalize_log ADD COLUMN itag BLOB",
        NULL, NULL, &err) != SQLITE_OK) {
        if (!err || strstr(err, "duplicate column name") == NULL) {
            LOG_WARN("tip_finalize", "[tip_finalize] itag alter failed: %s", err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
        sqlite3_free(err);
    }
    return stage_row_itag_backfill(db, "tip_finalize_log");
}

int utxo_apply_log_at(sqlite3 *db, int height,
                      struct utxo_apply_row *out)
{
    memset(out, 0, sizeof(*out));
    out->ok = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, spent_count, added_count "
        "FROM utxo_apply_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("tip_finalize", "[tip_finalize] utxo_apply_log prepare failed: %s", sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    sqlite3_bind_int(st, 1, height);
    int found = 0;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) == SQLITE_INTEGER) {
            int ok_value = sqlite3_column_int(st, 0);
            out->ok = (ok_value == 0 || ok_value == 1) ? ok_value : -1;
        }
        int status_type = sqlite3_column_type(st, 1);
        const void *status = status_type == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
        if (status)
            out->evidence = mint_validation_evidence_parse(
                status, (size_t)sqlite3_column_bytes(st, 1));
        out->is_anchor = status &&
                         sqlite3_column_bytes(st, 1) == 6 &&
                         memcmp(status, "anchor", 6) == 0;
        out->spent_count = sqlite3_column_type(st, 2) == SQLITE_INTEGER
            ? sqlite3_column_int64(st, 2) : -1;
        out->added_count = sqlite3_column_type(st, 3) == SQLITE_INTEGER
            ? sqlite3_column_int64(st, 3) : -1;
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

bool utxo_apply_sums_through(sqlite3 *db, int height,
                             int64_t *spent_out,
                             int64_t *added_out)
{
    *spent_out = 0;
    *added_out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COALESCE(SUM(spent_count),0), "
        "       COALESCE(SUM(added_count),0) "
        "FROM utxo_apply_log WHERE height <= ? AND ok = 1",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("tip_finalize", "[tip_finalize] utxo_apply_log sum prepare failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        *spent_out = sqlite3_column_int64(st, 0);
        *added_out = sqlite3_column_int64(st, 1);
        ok = true;
    }
    sqlite3_finalize(st);
    return ok;
}

/* Incremental running total of utxo_apply_log's ok=1 (spent,added) prefix — a
 * CACHE of utxo_apply_sums_through(), never a second writable ledger. The pure
 * SUM stays THE authority; this advances by exactly the just-finalized height's
 * OWN ok=1 (spent,added) — the SAME row the SUM would fold in — so the cached
 * total is byte-identical to the full SUM by construction (O(1) per finalize,
 * not O(height)). On ANY doubt — first use, a non-adjacent height (a reorg
 * rewind or an ok=0 skip left a gap), an unknown/negative per-row count, or the
 * periodic self-check stride — it recomputes the full SUM, adopts it, and names
 * any drift between the incremental candidate and the truth. The full SUM IS the
 * self-check: every fallback re-derives the total from durable rows.
 *
 * Volatile: touched ONLY on the reducer drive path under progress_store_tx_lock
 * (single writer), so the three correlated fields stay consistent with plain
 * statics; reset at stage init/shutdown; a crash simply drops it and the next
 * call re-seeds from the full SUM (no durable second ledger to get out of sync
 * with the coins commit — the drain-batch law needs nothing extra here). */
#define TF_SUM_SELFCHECK_STRIDE 32768
static int64_t g_sum_through = INT64_MIN;  /* height covered; INT64_MIN=unseeded */
static int64_t g_sum_spent;
static int64_t g_sum_added;
static int64_t g_sum_since_check;

void utxo_apply_sum_through_reset(void)
{
    g_sum_through = INT64_MIN;
    g_sum_spent = 0;
    g_sum_added = 0;
    g_sum_since_check = 0;
}

bool utxo_apply_sum_through_incremental(sqlite3 *db, int height,
                                        int64_t this_spent, int64_t this_added,
                                        int64_t *spent_out, int64_t *added_out)
{
    bool adjacent = g_sum_through == (int64_t)height - 1 &&
                    this_spent >= 0 && this_added >= 0;
    bool due_selfcheck = g_sum_since_check >= TF_SUM_SELFCHECK_STRIDE;

    if (adjacent && !due_selfcheck) {
        g_sum_spent += this_spent;
        g_sum_added += this_added;
        g_sum_through = height;
        g_sum_since_check++;
        *spent_out = g_sum_spent;
        *added_out = g_sum_added;
        return true;
    }

    /* Fallback / periodic self-check: the full SUM is the authority. */
    boot_scan_bump(boot_scan_counter("reducer_frontier.utxo_sum_full_recompute"));
    int64_t full_spent = 0, full_added = 0;
    if (!utxo_apply_sums_through(db, height, &full_spent, &full_added))
        return false;  // raw-return-ok:utxo_apply_sums_through logged the cause

    if (adjacent) {  /* stride self-check: candidate should equal the truth */
        int64_t cand_spent = g_sum_spent + this_spent;
        int64_t cand_added = g_sum_added + this_added;
        if (cand_spent != full_spent || cand_added != full_added)
            LOG_WARN("tip_finalize",
                     "[tip_finalize] utxo_sum cache drift h=%d "
                     "incremental(spent=%lld,added=%lld) full(spent=%lld,"
                     "added=%lld) — adopting full", height,
                     (long long)cand_spent, (long long)cand_added,
                     (long long)full_spent, (long long)full_added);
    }
    g_sum_spent = full_spent;
    g_sum_added = full_added;
    g_sum_through = height;
    g_sum_since_check = 0;
    *spent_out = full_spent;
    *added_out = full_added;
    return true;
}

bool log_insert(sqlite3 *db, int height, const char *status, bool ok,
                const struct arith_uint256 *work_delta,
                int64_t utxo_size_after, int reorg_depth,
                const struct uint256 *tip_hash)
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("tip_finalize_log", (int64_t)height, ok ? 1 : 0,
                           NULL, 0, itag);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO tip_finalize_log "
        "(height, status, ok, work_delta_high, work_delta_low, "
        " utxo_size_after, reorg_depth, finalized_at, tip_hash, itag) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("tip_finalize", "[tip_finalize] prepare insert failed: %s", sqlite3_errmsg(db));
        return false;
    }

    uint64_t hi = 0, lo = 0;
    if (work_delta) {
        lo = arith_uint256_get_low64(work_delta);
        hi = ((uint64_t)work_delta->pn[3] << 32) | work_delta->pn[2];
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_text (stmt, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 3, ok ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)hi);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)lo);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)utxo_size_after);
    sqlite3_bind_int  (stmt, 7, reorg_depth);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)platform_time_wall_unix());
    if (tip_hash)
        sqlite3_bind_blob(stmt, 9, tip_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 9);
    sqlite3_bind_blob(stmt, 10, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_WARN("tip_finalize", "[tip_finalize] insert height=%d rc=%d", height, rc);
        return false;
    }
    return true;
}

bool finalized_tip_row_at(sqlite3 *db, int height,
                          struct finalized_tip_row *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, tip_hash, status FROM tip_finalize_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("tip_finalize", "[tip_finalize] finalized row prepare failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        out->found = true;
        out->ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                  sqlite3_column_int64(st, 0) == 1;
        int hash_type = sqlite3_column_type(st, 1);
        const void *blob = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        int n = blob ? sqlite3_column_bytes(st, 1) : 0;
        if (blob && n == 32) {
            memcpy(out->tip_hash.data, blob, 32);
            out->has_tip_hash = true;
        }
        int status_type = sqlite3_column_type(st, 2);
        const unsigned char *status = status_type == SQLITE_TEXT
            ? sqlite3_column_text(st, 2) : NULL;
        out->is_anchor = status &&
                         sqlite3_column_bytes(st, 2) == 6 &&
                         memcmp(status, "anchor", 6) == 0;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("tip_finalize", "[tip_finalize] finalized row step failed rc=%d: %s", rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}
