/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * utxo_apply_delta_repair — one-shot stale verdict repairs. These reuse the
 * inverse-delta machinery but are not fork reorg handling. Each is gated by
 * current-binary dry-runs plus a (height,block_hash) one-shot marker. */

#include "jobs/utxo_apply_delta.h"
#include "utxo_apply_delta_internal.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_body_index.h"
#include "jobs/utxo_apply_stage.h"
#include "coins/coins.h"
#include "primitives/block.h"
#include "script/script.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VALUE_OVERFLOW_REPAIR_ACK_ENV "ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK"

/* Keep startup repair O(delta); larger contradictions use copy-only tools. */
#define UNAPPLIED_COIN_SUFFIX_REPAIR_MAX_BLOCKS 4096

static bool unapplied_suffix_exists(sqlite3 *db, int32_t first, bool *exists)
{
    static const char *const sql =
        "SELECT EXISTS("
        " SELECT height FROM utxo_apply_log WHERE height>=?1"
        " UNION ALL SELECT height FROM utxo_apply_delta WHERE height>=?1"
        " UNION ALL SELECT height FROM nullifiers WHERE height>=?1"
        " UNION ALL SELECT height FROM sprout_anchors WHERE height>=?1"
        " UNION ALL SELECT height FROM sapling_anchors WHERE height>=?1"
        " UNION ALL SELECT height FROM coins WHERE height>=?1"
        ")";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] suffix probe prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    if (sqlite3_bind_int(st, 1, first) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] suffix probe bind failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW)
        *exists = sqlite3_column_int(st, 0) != 0;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW) {
        LOG_WARN("utxo_apply", "[utxo_apply] suffix probe step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}

static bool future_coin_bounds(sqlite3 *db, int applied_first,
                               int64_t *count, int *future_first, int *last)
{
    sqlite3_stmt *st = NULL;
    *count = 0;
    *future_first = applied_first;
    *last = applied_first - 1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*),COALESCE(MIN(height),?1),"
            "COALESCE(MAX(height),?1-1) "
            "FROM coins WHERE height>=?1", -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] future coin probe prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, applied_first);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int64(st, 0);
        *future_first = sqlite3_column_int(st, 1);
        *last = sqlite3_column_int(st, 2);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW) {
        LOG_WARN("utxo_apply", "[utxo_apply] future coin probe step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}

static bool future_coin_matches_output(sqlite3 *db,
                                       const struct transaction *tx,
                                       uint32_t vout, int height)
{
    uint8_t script[UTXO_APPLY_SCRIPT_MAX];
    int64_t value = 0;
    int32_t coin_height = -1;
    bool is_coinbase = false;
    size_t script_len = 0;
    if (!coins_kv_get_prevout(db, tx->hash.data, vout, &value, script,
                              sizeof(script), &script_len, &coin_height,
                              &is_coinbase))
        return false;
    const struct tx_out *out = &tx->vout[vout];
    return value == out->value && coin_height == height &&
           is_coinbase == transaction_is_coinbase(tx) &&
           script_len == out->script_pub_key.size &&
           (script_len == 0 ||
            memcmp(script, out->script_pub_key.data, script_len) == 0);
}

/* Prove that rows with creator heights at/above `first` are exactly every
 * spendable output of a canonical, body-readable block suffix.  Inputs are
 * restored separately from their hash-verified pre-suffix creators below. */
static bool prove_exact_future_coin_suffix(
    sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_reader_fn reader, void *reader_user,
    int first, int last, int64_t actual_rows)
{
    if (!ms || !datadir || last < first ||
        last - first + 1 > UNAPPLIED_COIN_SUFFIX_REPAIR_MAX_BLOCKS) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin repair refused range=[%d,%d] "
                 "cap=%d main_state=%p datadir=%p",
                 first, last, UNAPPLIED_COIN_SUFFIX_REPAIR_MAX_BLOCKS,
                 (void *)ms, (const void *)datadir);
        return false;
    }

    int64_t expected_rows = 0;
    for (int h = first; h <= last; h++) {
        struct block_index *bi = stage_body_index_at(ms, h);
        struct block blk;
        block_init(&blk);
        if (!bi || bi->nHeight != h || !bi->phashBlock ||
            !stage_read_block(&blk, bi, h, datadir, reader, reader_user)) {
            block_free(&blk);
            LOG_WARN("utxo_apply",
                     "[utxo_apply] future coin repair refused: canonical "
                     "body unavailable h=%d", h);
            return false;
        }

        bool block_ok = true;
        for (size_t ti = 0; ti < blk.num_vtx && block_ok; ti++) {
            const struct transaction *tx = &blk.vtx[ti];
            for (size_t vo = 0; vo < tx->num_vout; vo++) {
                const struct tx_out *out = &tx->vout[vo];
                if (tx_out_is_null(out) ||
                    script_is_unspendable(&out->script_pub_key))
                    continue;
                if (vo > UINT32_MAX ||
                    !future_coin_matches_output(db, tx, (uint32_t)vo, h)) {
                    LOG_WARN("utxo_apply",
                             "[utxo_apply] future coin repair refused: "
                             "created-output mismatch h=%d tx=%zu vout=%zu",
                             h, ti, vo);
                    block_ok = false;
                    break;
                }
                expected_rows++;
            }
        }
        block_free(&blk);
        if (!block_ok)
            return false;
    }
    if (expected_rows != actual_rows) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin repair refused: row-set mismatch "
                 "range=[%d,%d] expected=%lld actual=%lld",
                 first, last, (long long)expected_rows,
                 (long long)actual_rows);
        return false;
    }
    return true;
}

static bool delete_future_coins(sqlite3 *db, int first, int last,
                                int64_t expected_rows)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM coins WHERE height>=?1 AND height<=?2",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] future coin delete prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, first);
    sqlite3_bind_int(st, 2, last);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    int changed = rc == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || changed != expected_rows) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin delete mismatch rc=%d "
                 "changed=%d expected=%lld", rc, changed,
                 (long long)expected_rows);
        return false;
    }
    return true;
}

bool utxo_apply_reconcile_unapplied_suffix(
    sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_reader_fn reader, void *reader_user)
{
    if (!db)
        LOG_FAIL("utxo_apply", "suffix reconcile: NULL db");

    bool ok = false;
    progress_store_tx_lock();
    uint64_t cursor = 0;
    int32_t coins_applied = -1;
    bool coins_found = false;
    if (!stage_cursor_read_or_zero(db, "utxo_apply", "utxo_apply", &cursor) ||
        !coins_kv_get_applied_height(db, &coins_applied, &coins_found))
        goto done;
    if (!coins_found) {
        ok = true;
        goto done;
    }
    if (cursor > INT_MAX || coins_applied != (int32_t)cursor) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] suffix reconcile deferred: cursor=%llu "
                 "coins_applied=%d found=%d (exact agreement required)",
                 (unsigned long long)cursor, coins_applied, (int)coins_found);
        ok = true;
        goto done;
    }

    bool present = false;
    if (!unapplied_suffix_exists(db, coins_applied, &present))
        goto done;
    if (!present) {
        ok = true;
        goto done;
    }
    if (sqlite3_get_autocommit(db) == 0) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] suffix reconcile refused nested transaction");
        goto done;
    }
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] suffix BEGIN failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        goto done;
    }
    int64_t future_coins = 0;
    int future_first = coins_applied;
    int future_last = coins_applied - 1;
    if (!future_coin_bounds(db, coins_applied, &future_coins, &future_first,
                            &future_last)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        goto done;
    }
    int64_t restored_spends = 0;
    int64_t already_live_spends = 0;
    if (future_coins > 0) {
        if (!prove_exact_future_coin_suffix(
                db, ms, datadir, reader, reader_user, future_first,
                future_last, future_coins) ||
            !delete_future_coins(db, future_first, future_last,
                                 future_coins) ||
            !utxo_apply_restore_suffix_inputs(
                db, ms, datadir, reader, reader_user, coins_applied,
                future_first, future_last, &restored_spends,
                &already_live_spends)) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            goto done;
        }
    }
    if (!utxo_apply_delete_rows_above(db, coins_applied, INT_MAX)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        goto done;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] suffix COMMIT failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        goto done;
    }
    LOG_WARN("utxo_apply",
             "[utxo_apply] removed abandoned kernel suffix at/above "
             "next-unapplied height=%d (cursor and coin frontier agree; "
             "future_range=[%d,%d] future_coins_removed=%lld "
             "restored_spends=%lld already_live_spends=%lld "
             "through_height=%d)",
             coins_applied, future_first, future_last,
             (long long)future_coins, (long long)restored_spends,
             (long long)already_live_spends, future_last);
    ok = true;

done:
    progress_store_tx_unlock();
    return ok;
}

static bool owner_ack_value_overflow_repair(void)
{
    const char *v = getenv(VALUE_OVERFLOW_REPAIR_ACK_ENV);
    return v && strcmp(v, "1") == 0;
}

static int repair_row_still_present(sqlite3 *db, int height,
                                    const char *want_status)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, status FROM utxo_apply_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] repair row prepare failed: %s",
                 sqlite3_errmsg(db));
        return -1;  // raw-return-ok:tri-state-error-logged
    }
    sqlite3_bind_int(st, 1, height);

    bool ok = false;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const unsigned char *status = sqlite3_column_text(st, 1);
        ok = sqlite3_column_int(st, 0) == 0 &&
             status && strcmp((const char *)status, want_status) == 0;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] repair row step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return -1;  // raw-return-ok:tri-state-error-logged
    }
    sqlite3_finalize(st);
    return ok ? 1 : 0;
}

/* Inverse-walk precondition over [first_h, last_h]: every height has a
 * utxo_apply_log row, and a delta row exists iff that row has ok=1 (forward
 * apply persists a delta only on a successful apply, atomically with its log
 * row). utxo_apply_emit_inverse_delta silently no-ops on a missing delta row,
 * so any violation means the rewind would be PARTIAL on a torn datadir —
 * coins keeping heights the cursor no longer covers. Returns 1 consistent,
 * 0 on a violation (counts logged), -1 on error (logged). Caller holds the
 * progress_store tx lock. */
static int inverse_walk_consistent(sqlite3 *db, int first_h, int last_h)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT (?2 - ?1 + 1) - "
            "       (SELECT COUNT(*) FROM utxo_apply_log "
            "         WHERE height BETWEEN ?1 AND ?2), "
            "       (SELECT COUNT(*) FROM utxo_apply_log l "
            "         WHERE l.height BETWEEN ?1 AND ?2 AND l.ok = 1 "
            "           AND NOT EXISTS (SELECT 1 FROM utxo_apply_delta d "
            "                            WHERE d.height = l.height)), "
            "       (SELECT COUNT(*) FROM utxo_apply_delta d "
            "         WHERE d.height BETWEEN ?1 AND ?2 "
            "           AND NOT EXISTS (SELECT 1 FROM utxo_apply_log l "
            "                            WHERE l.height = d.height "
            "                              AND l.ok = 1))",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] inverse walk guard prepare failed: %s",
                 sqlite3_errmsg(db));
        return -1;  // raw-return-ok:tri-state-error-logged
    }
    sqlite3_bind_int(st, 1, first_h);
    sqlite3_bind_int(st, 2, last_h);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc != SQLITE_ROW) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] inverse walk guard step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return -1;  // raw-return-ok:tri-state-error-logged
    }
    sqlite3_int64 missing_log = sqlite3_column_int64(st, 0);
    sqlite3_int64 ok_no_delta = sqlite3_column_int64(st, 1);
    sqlite3_int64 delta_no_ok = sqlite3_column_int64(st, 2);
    sqlite3_finalize(st);
    if (missing_log == 0 && ok_no_delta == 0 && delta_no_ok == 0)
        return 1;
    LOG_WARN("utxo_apply",
             "[utxo_apply] inverse walk range [%d..%d] torn: missing_log=%lld "
             "ok_without_delta=%lld delta_without_ok=%lld",
             first_h, last_h, (long long)missing_log,
             (long long)ok_no_delta, (long long)delta_no_ok);
    return 0;
}

static bool repair_live_lookup(const struct uint256 *txid, uint32_t vout,
                               struct utxo_apply_lookup *out, void *user)
{
    sqlite3 *db = user;
    if (!txid || !out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!db)
        return true;

    int64_t value = 0;
    int32_t height = 0;
    bool is_coinbase = false;
    size_t slen = 0;
    if (!coins_kv_get_prevout(db, txid->data, vout, &value, out->script,
                              UTXO_APPLY_SCRIPT_MAX, &slen, &height,
                              &is_coinbase))
        return true;

    if (slen > UTXO_APPLY_SCRIPT_MAX)
        return false;

    out->found = true;
    out->value = value;
    out->height = (uint32_t)(height < 0 ? 0 : height);
    out->is_coinbase = is_coinbase;
    out->script_len = (uint32_t)slen;
    return true;
}

static bool dry_run_after_inverse(sqlite3 *db, int height, int cursor,
                                  const struct block *blk,
                                  struct delta_summary *dry)
{
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] repair dry-run BEGIN failed h=%d: %s",
                 height, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    for (int h = cursor - 1; h >= height; h--) {
        if (!utxo_apply_emit_inverse_delta(db, h)) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return false;
        }
    }

    utxo_apply_compute_block_delta(blk, (uint32_t)height,
                                   repair_live_lookup, db, dry);
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return true;
}

bool utxo_apply_repair_value_overflow_hole(
    sqlite3 *db,
    int height,
    uint64_t cursor,
    const struct uint256 *block_hash,
    const struct block *blk,
    struct utxo_apply_value_overflow_repair_result *out)
{
    struct utxo_apply_value_overflow_repair_result local;
    memset(&local, 0, sizeof(local));
    local.height = height;
    local.cursor_before = cursor;
    local.cursor_after = cursor;
    if (out)
        *out = local;

    if (!db || !block_hash || !blk) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair refused: bad input "
                 "db=%p block_hash=%p blk=%p",
                 (void *)db, (const void *)block_hash, (const void *)blk);
        return false;
    }
    if (height < 0 || cursor == 0 || (uint64_t)height >= cursor) {
        if (out)
            *out = local;
        return true;
    }

    local.attempted = true;

    if (!owner_ack_value_overflow_repair()) {
        local.owner_refused = true;
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair owner-gated h=%d: "
                 "set %s=1 only on an operator-approved datadir copy",
                 height, VALUE_OVERFLOW_REPAIR_ACK_ENV);
        if (out)
            *out = local;
        return true;
    }

    progress_store_tx_lock();

    /* TOCTOU guard (same family as the Wave-1 stale-script fix): the caller
     * snapshotted `cursor` under the progress lock, released it to read the
     * block body off disk, and re-entered here. If utxo_apply advanced in
     * that gap, an inverse walk keyed to the stale C-1 would rewind the
     * cursor past coins it never unwound. Every cursor writer holds this
     * (recursive) lock through COMMIT, so one re-read covers both walks. */
    uint64_t cursor_now = stage_cursor_persisted(db, "utxo_apply",
                                                 "utxo_apply");
    if (cursor_now != cursor) {
        local.cursor_stale_refused = true;
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair refused h=%d: cursor "
                 "moved %llu -> %llu since snapshot (retry next tick)",
                 height, (unsigned long long)cursor,
                 (unsigned long long)cursor_now);
        progress_store_tx_unlock();
        if (out)
            *out = local;
        return true;
    }

    int C = (int)cursor;
    if ((uint64_t)C != cursor || C <= height) {
        progress_store_tx_unlock();
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair cursor invalid h=%d "
                 "cursor=%llu",
                 height, (unsigned long long)cursor);
        return false;
    }

    int row_present = repair_row_still_present(db, height, "value_overflow");
    if (row_present < 0) {
        progress_store_tx_unlock();
        return false;
    }
    if (row_present == 0) {
        progress_store_tx_unlock();
        if (out)
            *out = local;
        return true;
    }

    bool marker_seen = false;
    if (!repair_marker_have(db, REPAIR_MARKER_KIND_UTXO_VALUE_OVERFLOW,
                            height, block_hash->data, &marker_seen,
                            NULL, 0, NULL)) {
        progress_store_tx_unlock();
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair marker read failed h=%d",
                 height);
        return false;
    }
    if (marker_seen) {
        local.marker_seen = true;
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair skipped h=%d: "
                 "one-shot marker already present",
                 height);
        progress_store_tx_unlock();
        if (out)
            *out = local;
        return true;
    }

    /* Both inverse walks below (the dry-run, then the committing one) span
     * [height .. C-1]; the lock held through COMMIT keeps this verdict valid
     * for both. */
    int walk_ok = inverse_walk_consistent(db, height, C - 1);
    if (walk_ok < 0) {
        progress_store_tx_unlock();
        return false;
    }
    if (walk_ok == 0) {
        local.walk_torn_refused = true;
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair refused h=%d: torn "
                 "log/delta range below cursor %d",
                 height, C);
        progress_store_tx_unlock();
        if (out)
            *out = local;
        return true;
    }

    struct delta_summary dry;
    if (!dry_run_after_inverse(db, height, C, blk, &dry)) {
        progress_store_tx_unlock();
        return false;
    }
    local.dry_run_ok = dry.ok;
    if (!dry.ok) {
        local.genuinely_invalid = true;
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair: H genuinely invalid "
                 "height=%d status=%s kind=%s",
                 height, dry.status ? dry.status : "(null)",
                 dry.failure_kind ? dry.failure_kind : "(null)");
        free_delta(&dry);
        progress_store_tx_unlock();
        if (out)
            *out = local;
        return true;
    }
    free_delta(&dry);

    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair BEGIN failed h=%d: %s",
                 height, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }

    for (int h = C - 1; h >= height; h--) {
        if (!utxo_apply_emit_inverse_delta(db, h)) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            progress_store_tx_unlock();
            return false;
        }
    }
    if (!utxo_apply_delete_rows_above(db, height, C - 1)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    if (!utxo_apply_unwind_write_cursor(db, (uint64_t)height)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    if (!utxo_apply_frontier_set_in_tx(db, height)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    static const uint8_t present = 1;  /* legacy progress_meta presence value */
    if (!repair_marker_note_in_tx(db, REPAIR_MARKER_KIND_UTXO_VALUE_OVERFLOW,
                                  height, block_hash->data, &present,
                                  sizeof(present))) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] value_overflow repair COMMIT failed h=%d: %s",
                 height, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }

    progress_store_tx_unlock();

    local.repaired = true;
    local.cursor_after = (uint64_t)height;
    LOG_WARN("utxo_apply",
             "[utxo_apply] value_overflow repair rewound cursor %llu -> %d "
             "for stale hole h=%d",
             (unsigned long long)cursor, height, height);

    if (out)
        *out = local;
    return true;
}
