/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SQLite-backed coins view over node.db `utxos`.
 *
 * AUTHORITY NOTE: node.db `utxos`
 * and the node_state 'coins_best_block' key are a PROJECTION (rebuildable
 * cache) of the canonical coins_kv store in progress.kv
 * (storage/coins_kv.h). They serve explorer/RPC/wallet reads and the
 * fast-sync SERVE path; consensus and
 * recovery DECISIONS derive the coins-best fact via
 * reducer_frontier_derive_coins_best, never from here. The writes below
 * are projection maintenance.
 *
 * Implements coins_view_vtable so coins_view_cache can flush here.
 * No LevelDB needed at runtime — LevelDB is import-only.
 *
 * Raw-SQL opt-out (DEFENSIVE_CODING.md §1).  This file is the UTXO
 * persistence infrastructure — the very file §1 names as the
 * motivating "we need AR enforcement" example.  Every raw
 * sqlite3_step below is intentional: coins_view_sqlite does not own
 * a `struct node_db` handle (it borrows the sqlite3* directly) and
 * cannot use the AR_* helpers, which are model-side conveniences.
 * Every writer rc is observed and turned into a ROLLBACK on the
 * shared connection, which is what AR_STEP_DONE would do anyway. */
#define ZCL_AR_RAW_SQL

#include <time.h>
#include "storage/coins_view_sqlite.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "coins/coins.h"
#include "coins/utxo_commitment.h"
#include "event/event.h"
#include "script/standard.h"
#include "util/ar_step_readonly.h"
#include "util/db_txn_trace.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── vtable implementations ────────────────────────────────────── */

static bool cvs_get_coins_impl(void *self, const struct uint256 *txid,
                                struct coins *out)
{
    struct coins_view_sqlite *cvs = (struct coins_view_sqlite *)self;
    return coins_view_sqlite_get_coins(cvs, txid, out);
}

static bool cvs_have_coins_impl(void *self, const struct uint256 *txid)
{
    struct coins_view_sqlite *cvs = (struct coins_view_sqlite *)self;
    return coins_view_sqlite_have_coins(cvs, txid);
}

static bool cvs_get_best_block_impl(void *self, struct uint256 *hash)
{
    struct coins_view_sqlite *cvs = (struct coins_view_sqlite *)self;
    return coins_view_sqlite_get_best_block(cvs, hash);
}

static bool cvs_batch_write_impl(void *self, struct coins_map *map_coins,
                                  const struct uint256 *hash_block)
{
    struct coins_view_sqlite *cvs = (struct coins_view_sqlite *)self;
    return coins_view_sqlite_batch_write( // one-write-path-ok:coins-vtable-adapter
        cvs, map_coins, hash_block, NULL);
}

static enum coins_anchor_lookup_result cvs_get_anchor_impl(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    /* Anchors are consensus kernel state in progress.kv even when this view's
     * transparent coins come from node.db (notably -reindex-chainstate). */
    (void)self;
    if (!root)
        return COINS_ANCHOR_ERROR;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    enum anchor_kv_lookup_result r = db
        ? anchor_kv_get(db, (int)pool, root, tree_out, NULL)
        : ANCHOR_KV_ERROR;
    progress_store_tx_unlock();
    switch (r) {
    case ANCHOR_KV_FOUND: return COINS_ANCHOR_FOUND;
    case ANCHOR_KV_MISSING: return COINS_ANCHOR_MISSING;
    case ANCHOR_KV_HISTORY_INCOMPLETE:
        return COINS_ANCHOR_HISTORY_INCOMPLETE;
    case ANCHOR_KV_ERROR:
    default: return COINS_ANCHOR_ERROR;
    }
}

static struct coins_view_vtable cvs_vtable = {
    .get_coins     = cvs_get_coins_impl,
    .have_coins    = cvs_have_coins_impl,
    .get_best_block = cvs_get_best_block_impl,
    .batch_write   = cvs_batch_write_impl,
    .get_stats     = NULL,
    .get_anchor    = cvs_get_anchor_impl,
};

/* max UTXO rows above tip that auto-rewind will touch. A single
 * block in practice commits on the order of 1-20 new UTXOs; 32 is a
 * generous cap that still refuses anything resembling a multi-block
 * drift (which should NEVER be auto-healed — memory rule: never wipe
 * above tip without operator consent). */
#define COINS_AUTO_REWIND_MAX_ROWS 32

/* existence probe. Production schema has `transactions` but the
 * test harness builds a minimal DB with only utxos/node_state/blocks,
 * so the belt-and-suspenders sweep must tolerate the table's absence. */
static bool coins_view_sqlite_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *s = NULL;
    bool exists = false;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC);
        exists = (AR_STEP_ROW_READONLY(s) == SQLITE_ROW);
        sqlite3_finalize(s);
    }
    return exists;
}

/* Shared helper for prepare+bind+step+finalize of a single DELETE.
 * Returns the number of rows deleted, or -1 on error (caller goes to
 * rollback). */
static int coins_view_sqlite_delete_bind_height(sqlite3 *db,
                                                 const char *sql,
                                                 int64_t tip_height,
                                                 const char *label)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        fprintf(stderr,
            "[coins] auto-rewind: prepare %s failed: %s\n",
            label, sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_int64(s, 1, tip_height);
    int rc = AR_STEP_WRITE(s);
    if (rc != SQLITE_DONE) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: %s step failed: %s\n",
            label, sqlite3_errmsg(db));
        sqlite3_finalize(s);
        return -1;
    }
    int changed = sqlite3_changes(db);
    sqlite3_finalize(s);
    return changed;
}

/* Shared crash-recovery rewind for stale UTXO rows above a selected tip.
 *
 * Base behavior: DELETE utxos where height > tip_height, clear the
 * stored `utxo_commitment` row.
 *
 * Additionally:
 *   - Sweep any utxos row whose txid appears in `transactions` with
 *     block_height > tip_height, regardless of the utxos.height column
 *     value. Covers the wrong-height failure mode where a partially-
 *     applied block left utxos rows at height<=tip but the tx_index
 *     row at height=tip+1, so `have_coins(coinbase_txid)` tripped
 *     BIP30 on the orphan coinbase.
 *   - Purge the stale `transactions` rows themselves so the tx_index
 *     stays consistent with the rewound utxos set.
 *
 * max_rows >= 0 enables bounded auto-heal mode: only a one-block overshoot
 * with at most max_rows directly above-tip rows is accepted. max_rows < 0 is
 * explicit recovery mode for callers that have already selected a replacement
 * tip. Returns deleted UTXO rows on COMMIT, 0 for no work, -1 on refusal or
 * SQL failure. Logs + emits an event in both failure and mutation paths. */
int coins_rewind_above_tip(sqlite3 *db, int64_t tip_height, int64_t max_rows)
{
    if (!db || tip_height < 0) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: invalid args db=%p tip_height=%lld\n",
            (void *)db, (long long)tip_height);
        return -1;
    }

    int64_t would_wipe = 0;
    int64_t max_height = 0;
    sqlite3_stmt *count_stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*), COALESCE(MAX(height),0) "
            "FROM utxos WHERE height > ?",
            -1, &count_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: count prepare failed: %s\n",
            sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_int64(count_stmt, 1, tip_height);
    int count_rc = AR_STEP_ROW_READONLY(count_stmt);
    if (count_rc == SQLITE_ROW) {
        would_wipe = sqlite3_column_int64(count_stmt, 0);
        max_height = sqlite3_column_int64(count_stmt, 1);
    } else if (count_rc != SQLITE_DONE) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: count step failed: %s\n",
            sqlite3_errmsg(db));
        sqlite3_finalize(count_stmt);
        return -1;
    }
    sqlite3_finalize(count_stmt);

    if (would_wipe <= 0)
        return 0;

    if (max_rows >= 0 &&
        (max_height != tip_height + 1 || would_wipe > max_rows)) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: guard refused tip_height=%lld "
            "rows=%lld max_height=%lld guard=%lld\n",
            (long long)tip_height, (long long)would_wipe,
            (long long)max_height, (long long)max_rows);
        event_emitf(EV_DB_ERROR, 0,
            "coins_auto_rewind_refused tip_height=%lld rows=%lld "
            "max_height=%lld guard=%lld",
            (long long)tip_height, (long long)would_wipe,
            (long long)max_height, (long long)max_rows);
        return -1;
    }

    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,
            "[coins] auto-rewind: BEGIN failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }

    int deleted_high = coins_view_sqlite_delete_bind_height(db,
        "DELETE FROM utxos WHERE height > ?",
        tip_height, "utxos-high");
    if (deleted_high < 0) goto rollback;

    int deleted_bytxid = 0;
    int deleted_txindex = 0;
    if (coins_view_sqlite_table_exists(db, "transactions")) {
        deleted_bytxid = coins_view_sqlite_delete_bind_height(db,
            "DELETE FROM utxos WHERE txid IN"
            " (SELECT txid FROM transactions WHERE block_height > ?)",
            tip_height, "utxos-by-txid");
        if (deleted_bytxid < 0) goto rollback;

        deleted_txindex = coins_view_sqlite_delete_bind_height(db,
            "DELETE FROM transactions WHERE block_height > ?",
            tip_height, "transactions-high");
        if (deleted_txindex < 0) goto rollback;
    }

    if (sqlite3_exec(db,
            "DELETE FROM node_state WHERE key='utxo_commitment'",
            NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: commitment purge failed: %s\n",
            err ? err : "?");
        sqlite3_free(err);
        goto rollback;
    }

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] auto-rewind: COMMIT failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        goto rollback;
    }

    int deleted_total = deleted_high + deleted_bytxid;
    fprintf(stderr,  // obs-ok:helper-context-logged
        "[coins] auto-rewind: removed %d UTXO row(s) above "
        "tip_height=%lld (high=%d, by-txid=%d, tx_index=%d) "
        "and cleared utxo_commitment — continuing boot\n",
        deleted_total, (long long)tip_height,
        deleted_high, deleted_bytxid, deleted_txindex);
    event_emitf(EV_DB_ERROR, 0,
        "coins_auto_rewind deleted=%d by_txid=%d tx_index=%d tip_height=%lld",
        deleted_high, deleted_bytxid, deleted_txindex,
        (long long)tip_height);
    return deleted_total;

rollback:
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    event_emitf(EV_DB_ERROR, 0,
        "coins_auto_rewind_failed tip_height=%lld",
        (long long)tip_height);
    return -1;
}

/* Legacy-datadir-only reconciliation rung; unreachable on canonical datadirs,
 * where the derived gate in check_tip_consistency already passes
 * (coins_applied_height present => PASS, no reconcile).
 *
 * Boot-time commitment-validated reconciliation of a STALE coins_best_block
 * anchor reset far below the real applied UTXO frontier (e.g. anchor resolves
 * to height 200 while `utxos` holds millions of rows). The strict
 * tip-consistency check below
 * correctly refuses a blind fast-forward; this routine is the ONLY sanctioned
 * way to heal it, and it heals ONLY under cryptographic proof.
 *
 * Why a blind "advance the anchor to the highest cursor" heal is UNSAFE (and
 * is deliberately NOT done here):
 *   - The tip cursors (cec.utxo_max_height, sync_projection_tip_height,
 *     blocks-table status>=3 tip) are NOT independent witnesses: each is a
 *     copy of the same optimistic `new_tip->nHeight` promotion stamp, so a
 *     single bad promotion forges a "quorum".
 *   - MAX(utxos.height) is an output's CREATION height; a torn flush that
 *     dropped SPENDS (lazy/batched coins flush) does not move the max, so a
 *     double-spendable set looks fine by row counts.
 *   - height->hash via `blocks WHERE height=H AND status>=3` can name a losing
 *     orphan sibling after a mid-reorg crash.
 * The only check that survives all three is a content-bearing, height-stamped
 * commitment recompute-match: recompute the canonical SHA3 UTXO commitment
 * over the live `utxos` table and require an exact hash+count match against a
 * previously-stored trusted commitment. A dropped spend changes the hash; a
 * partial future block changes the count or hash.
 *
 * Returns true (anchor healed, caller may continue boot) ONLY when that proof
 * holds. Returns false in every other case (no stored commitment, height not
 * usable, rows above the committed height, recompute mismatch, or anchor hash
 * unresolvable), so the caller keeps the strict FATAL — the gate is never
 * weakened. Never trusts a cursor; never deletes UTXOs. */
static bool coins_reconcile_stale_anchor(sqlite3 *db,
                                         int64_t max_utxo_height,
                                         int64_t stale_tip_height)
{
    /* (1) A trusted, height-stamped commitment must exist to validate against.
     * Checked first: it is cheap and gates the expensive recompute in (4). */
    uint8_t want_hash[32];
    int32_t commit_h = -1;
    uint64_t want_count = 0;
    if (!utxo_commitment_sha3_load(db, want_hash, &commit_h, &want_count)) {
        LOG_WARN("coins",
            "[coins] stale-anchor reconcile refused: no stored utxo_sha3 "
            "commitment to validate the UTXO set against "
            "(stale_tip=%lld max_utxo=%lld) — preserving FATAL",
            (long long)stale_tip_height, (long long)max_utxo_height);
        return false;
    }

    /* (2) The commitment must be strictly ahead of the stale anchor and cover
     * the whole live frontier; a commitment at/below the stale anchor, or
     * below the highest live UTXO row, cannot justify advancing the anchor. */
    if (commit_h <= stale_tip_height || (int64_t)commit_h < max_utxo_height) {
        LOG_WARN("coins",
            "[coins] stale-anchor reconcile refused: commitment height=%d not "
            "usable (stale_tip=%lld max_utxo=%lld) — preserving FATAL",
            commit_h, (long long)stale_tip_height, (long long)max_utxo_height);
        return false;
    }

    /* (3) No utxos rows may exist above the committed height — the commitment
     * covers the entire set; rows above it mean the table diverged from the
     * committed snapshot. (Subsumed by the recompute, but an explicit, cheap
     * guard that fails fast and documents intent.) */
    int64_t rows_above = 0;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT COUNT(*) FROM utxos WHERE height > ?",
                -1, &s, NULL) != SQLITE_OK) {
            LOG_WARN("coins",
                "[coins] stale-anchor reconcile refused: rows-above prepare "
                "failed: %s — preserving FATAL", sqlite3_errmsg(db));
            return false;
        }
        sqlite3_bind_int64(s, 1, commit_h);
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            rows_above = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    if (rows_above != 0) {
        LOG_WARN("coins",
            "[coins] stale-anchor reconcile refused: %lld utxo row(s) above "
            "committed height=%d — preserving FATAL",
            (long long)rows_above, commit_h);
        return false;
    }

    /* (4) CRYPTOGRAPHIC PROOF. Recompute the canonical SHA3 commitment over
     * the live utxos table; require exact hash+count match. This is the only
     * check that detects a torn set (dropped spends do not move MAX(height)
     * but DO change the commitment). No cursor is consulted. */
    uint8_t got_hash[32];
    uint64_t got_count = 0;
    utxo_commitment_sha3_compute(db, got_hash, &got_count);
    if (got_count != want_count || memcmp(got_hash, want_hash, 32) != 0) {
        LOG_WARN("coins",
            "[coins] stale-anchor reconcile refused: UTXO set commitment "
            "MISMATCH at height=%d (got_count=%llu want_count=%llu) — the set "
            "is NOT provably intact; preserving FATAL (operator must restore "
            "or re-derive)",
            commit_h, (unsigned long long)got_count,
            (unsigned long long)want_count);
        return false;
    }

    /* (5) Proven intact at commit_h. Resolve the canonical block hash at that
     * height. Narrow orphan-sibling residual (a mid-reorg crash leaving a
     * losing sibling as the surviving status>=3 row AND carrying a matching
     * full UTXO commitment) is implausible and logged, not silently trusted. */
    uint8_t anchor_hash[32];
    bool anchor_ok = false;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT hash FROM blocks WHERE height=? AND status>=3",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(s, 1, commit_h);
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const void *blob = sqlite3_column_blob(s, 0);
                if (blob && sqlite3_column_bytes(s, 0) == 32) {
                    memcpy(anchor_hash, blob, 32);
                    anchor_ok = true;
                }
            }
            sqlite3_finalize(s);
        }
    }
    if (!anchor_ok) {
        LOG_WARN("coins",
            "[coins] stale-anchor reconcile refused: committed height=%d has "
            "no resolvable status>=3 block hash — preserving FATAL", commit_h);
        return false;
    }

    /* (6) Commit the heal: re-point coins_best_block to the verified block. */
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "INSERT OR REPLACE INTO node_state(key,value) "
                "VALUES('coins_best_block',?)", -1, &s, NULL) != SQLITE_OK) {
            LOG_WARN("coins",
                "[coins] stale-anchor reconcile FAILED: anchor write prepare "
                "failed: %s — preserving FATAL", sqlite3_errmsg(db));
            return false;
        }
        sqlite3_bind_blob(s, 1, anchor_hash, 32, SQLITE_STATIC);
        int rc = AR_STEP_WRITE(s);
        sqlite3_finalize(s);
        if (rc != SQLITE_DONE) {
            LOG_WARN("coins",
                "[coins] stale-anchor reconcile FAILED: anchor write step "
                "rc=%d: %s — preserving FATAL", rc, sqlite3_errmsg(db));
            return false;
        }
    }

    fprintf(stderr,  // obs-ok:helper-context-logged
        "[coins] stale-anchor reconcile OK: coins_best_block re-pointed from "
        "height=%lld to committed+verified height=%d (utxo_count=%llu, SHA3 "
        "commitment matched) — boot continues\n",
        (long long)stale_tip_height, commit_h,
        (unsigned long long)want_count);
    event_emitf(EV_DB_ERROR, 0,
        "coins_stale_anchor_reconciled from_h=%lld to_h=%d count=%llu",
        (long long)stale_tip_height, commit_h,
        (unsigned long long)want_count);
    return true;
}

/* Boot-time integrity check: the UTXO set (`utxos` table) must not be
 * strictly ahead of the coins-flush anchor (`coins_best_block`).  This
 * guards against the class of crash-mid-flush corruption where UTXOs
 * landed but the tip pointer didn't — a silent heal here would
 * de-sync the node from consensus and potentially double-spend on
 * restart.
 *
 * Returns true on OK (consistent OR successfully auto-rewound), false
 * on unrecoverable mismatch; the caller must halt on false.
 *
 * Semantics:
 *   (a) no UTXOs, no tip                 → fresh/clean
 *   (b) UTXOs present, no tip            → MISMATCH (orphan UTXOs)
 *   (c) tip set, no UTXOs                → benign (post-wipe anchor)
 *   (d) tip hash not yet in blocks table → soft WARN (block index lag)
 *   (e) max_utxo_height == tip_height+1
 *       AND count(height > tip_height) <= COINS_AUTO_REWIND_MAX_ROWS
 *                                        → AUTO-REWIND + OK
 *   (f) max_utxo_height > tip_height+1
 *       OR count exceeds the auto-rewind guard
 *                                        → MISMATCH (UTXOs ahead)
 */
static bool coins_view_sqlite_check_tip_consistency(sqlite3 *db)
{
    int64_t max_height = -1;
    bool have_utxos = false;

    /* ── DERIVED-GATE ──────────
     * When coins_kv is the PROVEN authority (coins_kv_is_proven_authority:
     * co-committed coins_applied_height present + migration stamp + a
     * non-empty set — the same rungs the L1 heal demands), the coins-best
     * fact is DERIVABLE from the canonical store and this gate's verdict
     * is simply "derivation resolvable" — PASS. The mirror MAX/COUNT and
     * the node_state 'coins_best_block' key below are CACHES of that fact:
     * drift between them is a stale projection (rebuildable, never
     * consulted by decisions), logged as a diagnostic, never a FATAL,
     * never an auto-rewind, never a guess-reconcile. Legacy datadirs
     * (predicate false / progress store not open) keep the strict legacy
     * gate unchanged. */
    {
        sqlite3 *pdb = progress_store_db();
        int32_t applied = -1;
        if (pdb && coins_kv_is_proven_authority(pdb, &applied)) {
            int64_t mirror_max = -1, mirror_count = 0;
            sqlite3_stmt *ds = NULL;
            if (sqlite3_prepare_v2(db,
                    "SELECT MAX(height), COUNT(*) FROM utxos",
                    -1, &ds, NULL) == SQLITE_OK) {
                if (AR_STEP_ROW_READONLY(ds) == SQLITE_ROW) {
                    if (sqlite3_column_type(ds, 0) == SQLITE_INTEGER)
                        mirror_max = sqlite3_column_int64(ds, 0);
                    mirror_count = sqlite3_column_int64(ds, 1);
                }
                sqlite3_finalize(ds);
            }
            int64_t derived_h = (int64_t)applied - 1;
            if (mirror_max != derived_h)
                printf("[coins] tip check: derived coins-best h=%lld "
                       "(coins_kv authority); mirror max_height=%lld "
                       "count=%lld — anchor cache stale / projection lag "
                       "(rebuildable, not consulted)\n",
                       (long long)derived_h, (long long)mirror_max,
                       (long long)mirror_count);
            else
                printf("[coins] tip check OK: derived coins-best h=%lld "
                       "(coins_kv authority, mirror agrees, count=%lld)\n",
                       (long long)derived_h, (long long)mirror_count);
            return true;
        }
    }

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT MAX(height), COUNT(*) FROM utxos",
            -1, &s, NULL) == SQLITE_OK) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            if (sqlite3_column_type(s, 0) == SQLITE_INTEGER)
                max_height = sqlite3_column_int64(s, 0);
            have_utxos = sqlite3_column_int64(s, 1) > 0;
        }
        sqlite3_finalize(s);
    }

    uint8_t tip_hash[32];
    bool tip_set = false;
    s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM node_state WHERE key='coins_best_block'",
            -1, &s, NULL) == SQLITE_OK) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            int len = sqlite3_column_bytes(s, 0);
            const void *data = sqlite3_column_blob(s, 0);
            if (data && len == 32) {
                memcpy(tip_hash, data, 32);
                tip_set = true;
            }
        }
        sqlite3_finalize(s);
    }

    if (!have_utxos && !tip_set) {
        printf("[coins] tip check: fresh DB (no utxos, no tip)\n");
        return true;
    }
    if (have_utxos && !tip_set) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] DB_ERR_TIP_MISMATCH: utxos present "
            "(max_height=%lld) but coins_best_block is unset — "
            "probable crash between UTXO flush and tip update. "
            "Halt and investigate; do not auto-heal.\n",
            (long long)max_height);
        return false;
    }
    if (!have_utxos && tip_set) {
        printf("[coins] tip check: coins_best_block set, utxos empty — "
               "post-wipe or pre-import anchor, continuing\n");
        return true;
    }

    int64_t tip_height = -1;
    s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height FROM blocks WHERE hash=? AND status>=3",
            -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(s, 1, tip_hash, 32, SQLITE_STATIC);
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            tip_height = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }

    if (tip_height < 0) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] tip check WARN: utxos max_height=%lld, "
            "coins_best_block hash not resolvable in blocks table "
            "(status>=3) — block index load may reconcile, continuing\n",
            (long long)max_height);
        return true;
    }
    if (max_height > tip_height) {
        /* single-block overshoot with a bounded row count is the
         * shape of a SIGKILL between the UTXO flush and the tip
         * update.  Auto-rewind deletes the overshoot rows and clears
         * the (possibly stale) utxo_commitment; the next connect_block
         * then re-lands the deleted rows and recomputes the
         * commitment.  Anything larger than a single-block overshoot
         * or a bounded row delta gets the strict-halt treatment. */
        if (max_height == tip_height + 1) {
            fprintf(stderr,  // obs-ok:helper-context-logged
                "[coins] DB_ERR_TIP_MISMATCH: utxos "
                "max_height=%lld = tip_height+1; attempting "
                "bounded auto-rewind (guard=%d)\n",
                (long long)max_height,
                COINS_AUTO_REWIND_MAX_ROWS);
            if (coins_rewind_above_tip(
                    db, tip_height, COINS_AUTO_REWIND_MAX_ROWS) > 0) {
                event_emitf(EV_DB_ERROR, 0,
                    "coins_tip_heal=bounded-auto-rewind "
                    "max_h=%lld tip_h=%lld guard=%d",
                    (long long)max_height, (long long)tip_height,
                    COINS_AUTO_REWIND_MAX_ROWS);
                return true;
            }
            fprintf(stderr,
                "[coins] DB_ERR_TIP_MISMATCH: auto-rewind refused or "
                "failed — halt and investigate.\n");
            return false;
        }
        if (tip_height > 1000000 && max_height - tip_height > 1000) {
            fprintf(stderr,  // obs-ok:helper-context-logged
                "[coins] tip check WARN: utxos max_height=%lld > "
                "tip_height=%lld by %lld historical blocks — deferring "
                "to block-index/coins anchor reconciliation\n",
                (long long)max_height, (long long)tip_height,
                (long long)(max_height - tip_height));
            event_emitf(EV_DB_ERROR, 0,
                "coins_tip_heal=historical-coins-lag "
                "max_h=%lld tip_h=%lld lag=%lld",
                (long long)max_height, (long long)tip_height,
                (long long)(max_height - tip_height));
            return true;
        }
        /* Last resort before the strict halt: a STALE coins_best_block anchor
         * (e.g. anchor reset to height 200 while the UTXO
         * set is millions of blocks ahead). coins_reconcile_stale_anchor heals
         * ONLY when the live UTXO set is cryptographically proven intact
         * against a stored height-stamped SHA3 commitment; it returns false
         * (preserving this FATAL) for any unproven case, so the gate is never
         * weakened. The single-block auto-rewind (above) and the historical
         * coins-lag escape (tip_height>1000000) are deliberately left intact. */
        if (coins_reconcile_stale_anchor(db, max_height, tip_height))
            return true;
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[coins] DB_ERR_TIP_MISMATCH: utxos max_height=%lld > "
            "tip_height=%lld (UTXOs ahead of tip by %lld blocks) — "
            "halt and investigate; do not auto-heal.\n",
            (long long)max_height, (long long)tip_height,
            (long long)(max_height - tip_height));
        return false;
    }
    printf("[coins] tip check OK: max_utxo_height=%lld tip_height=%lld\n",
           (long long)max_height, (long long)tip_height);
    return true;
}

/* ── Open / Close ──────────────────────────────────────────────── */

bool coins_view_sqlite_open(struct coins_view_sqlite *cvs, sqlite3 *db)
{
    if (!db)
        LOG_FAIL("coins_view", "open: db handle is NULL");
    memset(cvs, 0, sizeof(*cvs));
    cvs->view.vtable = &cvs_vtable;
    cvs->view.impl = cvs;
    pthread_mutex_init(&cvs->mutex, NULL);

    /* prefer a dedicated sqlite3 handle on the same file.
     *
     * SAVEPOINT on the SHARED handle returns SQLITE_BUSY
     * ("cannot open savepoint - SQL statements in progress")
     * whenever any other subsystem's writer VDBE has
     * `nVdbeWrite>0`.  The busy handler is NOT invoked for that
     * guard — the flush bails immediately, the DIRTY+pruned
     * tombstone is retained in RAM but never reaches disk, and
     * the next cache eviction re-reads the stale row → BIP30
     * trip loop.
     *
     * A dedicated handle puts BEGIN IMMEDIATE on a separate
     * `nVdbeWrite` counter.  Cross-connection WAL writer
     * contention is still possible, but that shape IS handled by
     * sqlite3_busy_timeout — unlike the same-connection
     * SAVEPOINT guard.  Cost: one extra SQLite page cache (~MB);
     * live node has 95GB, cost is negligible.
     *
     * Fallback: if the input handle has no backing file
     * (`:memory:` — used only by a handful of unit tests that
     * open a throwaway DB), share the handle with SAVEPOINT
     * nesting.  Production always hits the dedicated-connection
     * path. */
    const char *fname = sqlite3_db_filename(db, "main");
    bool opened_dedicated = false;
    if (fname && fname[0] != '\0') {
        sqlite3 *cdb = NULL;
        int rc = sqlite3_open(fname, &cdb);
        if (rc == SQLITE_OK && cdb) {
            /* Mirror node_db's pragmas so the dedicated handle
             * has matching journal / sync / busy behavior. */
            sqlite3_exec(cdb,
                "PRAGMA journal_mode=WAL;"
                "PRAGMA synchronous=NORMAL;"
                "PRAGMA temp_store=MEMORY;"
                "PRAGMA foreign_keys=ON",
                NULL, NULL, NULL);
            /* 30s matches the flush-time timeout we bump below;
             * long enough for node_db's normal writes to commit
             * even under heavy IBD pressure. */
            sqlite3_busy_timeout(cdb, 30000);
            cvs->db = cdb;
            cvs->owns_db = true;
            opened_dedicated = true;
            /* Opt-in txn diagnostics (ZCL_DB_TXN_TRACE=1); no-op otherwise. */
            zcl_db_txn_trace_register(cdb, "coins_view");
            printf("coins_view_sqlite: dedicated connection "
                   "(path=%s, BEGIN IMMEDIATE mode)\n", fname);
        } else {
            fprintf(stderr,  // obs-ok:helper-context-logged
                "coins_view_sqlite: dedicated open failed (%s): "
                "%s — falling back to shared handle + SAVEPOINT\n",
                fname, sqlite3_errstr(rc));
            if (cdb) sqlite3_close(cdb);
        }
    }
    if (!opened_dedicated) {
        /* `:memory:` tests or dedicated-open failure. */
        cvs->db = db;
        cvs->owns_db = false;
        printf("coins_view_sqlite: using shared connection (SAVEPOINT mode)\n");
    }

    /* Cap WAL size to 100MB to prevent unbounded growth.
     * A 6GB WAL was observed when flush failures accumulated.
     * Apply to BOTH the shared handle (if we're falling back)
     * AND the dedicated handle when we own it — either way the
     * journal file is the same on disk. */
    sqlite3_exec(cvs->db, "PRAGMA journal_size_limit = 104857600",
                 NULL, NULL, NULL);

    int rc;

    rc = sqlite3_prepare_v2(cvs->db,
        "SELECT vout, value, script, height, is_coinbase"
        " FROM utxos WHERE txid=? ORDER BY vout",
        -1, &cvs->stmt_get, NULL);
    if (rc != SQLITE_OK) goto fail;

    rc = sqlite3_prepare_v2(cvs->db,
        "SELECT 1 FROM utxos WHERE txid=? LIMIT 1",
        -1, &cvs->stmt_have, NULL);
    if (rc != SQLITE_OK) goto fail;

    rc = sqlite3_prepare_v2(cvs->db,
        "INSERT OR REPLACE INTO utxos"
        " (txid, vout, value, script, script_type, address_hash,"
        "  height, is_coinbase)"
        " VALUES(?,?,?,?,?,?,?,?)",
        -1, &cvs->stmt_insert, NULL);
    if (rc != SQLITE_OK) goto fail;

    rc = sqlite3_prepare_v2(cvs->db,
        "DELETE FROM utxos WHERE txid=?",
        -1, &cvs->stmt_delete_tx, NULL);
    if (rc != SQLITE_OK) goto fail;

    rc = sqlite3_prepare_v2(cvs->db,
        "SELECT value FROM node_state WHERE key='coins_best_block'",
        -1, &cvs->stmt_best_get, NULL);
    if (rc != SQLITE_OK) goto fail;

    /* CACHE-REFRESH of the derived coins-best (display / legacy-boot
     * fallback only; authority = reducer_frontier_derive_coins_best over
     * coins_kv). Atomic with the mirror rows — correct for a projection. */
    rc = sqlite3_prepare_v2(cvs->db,
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('coins_best_block',?)",
        -1, &cvs->stmt_best_set, NULL);
    if (rc != SQLITE_OK) goto fail;

    rc = sqlite3_prepare_v2(cvs->db,
        "SELECT value FROM node_state WHERE key='utxo_commitment'",
        -1, &cvs->stmt_commit_get, NULL);
    if (rc != SQLITE_OK) goto fail;

    rc = sqlite3_prepare_v2(cvs->db,
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('utxo_commitment',?)",
        -1, &cvs->stmt_commit_set, NULL);
    if (rc != SQLITE_OK) goto fail;

    /* Boot-time integrity check — refuses to open on detected
     * UTXO/tip mismatch.  Caller decides how to halt. */
    if (!coins_view_sqlite_check_tip_consistency(cvs->db)) {
        coins_view_sqlite_close(cvs);
        return false;
    }

    return true;

fail:
    fprintf(stderr, "coins_view_sqlite_open: prepare failed: %s\n",
            sqlite3_errmsg(cvs->db));
    coins_view_sqlite_close(cvs);
    return false;
}

void coins_view_sqlite_close(struct coins_view_sqlite *cvs)
{
    pthread_mutex_lock(&cvs->mutex);
    if (cvs->stmt_get)        { sqlite3_finalize(cvs->stmt_get);        cvs->stmt_get = NULL; }
    if (cvs->stmt_have)       { sqlite3_finalize(cvs->stmt_have);       cvs->stmt_have = NULL; }
    if (cvs->stmt_insert)     { sqlite3_finalize(cvs->stmt_insert);     cvs->stmt_insert = NULL; }
    if (cvs->stmt_delete_tx)  { sqlite3_finalize(cvs->stmt_delete_tx);  cvs->stmt_delete_tx = NULL; }
    if (cvs->stmt_best_get)   { sqlite3_finalize(cvs->stmt_best_get);   cvs->stmt_best_get = NULL; }
    if (cvs->stmt_best_set)   { sqlite3_finalize(cvs->stmt_best_set);   cvs->stmt_best_set = NULL; }
    if (cvs->stmt_commit_get) { sqlite3_finalize(cvs->stmt_commit_get); cvs->stmt_commit_get = NULL; }
    if (cvs->stmt_commit_set) { sqlite3_finalize(cvs->stmt_commit_set); cvs->stmt_commit_set = NULL; }
    if (cvs->owns_db && cvs->db) {
        zcl_db_txn_trace_unregister(cvs->db);
        sqlite3_close(cvs->db);
    }
    cvs->db = NULL;
    cvs->owns_db = false;
    pthread_mutex_unlock(&cvs->mutex);
    pthread_mutex_destroy(&cvs->mutex);
}

/* ── get_coins: build struct coins from SQLite rows ────────────── */

bool coins_view_sqlite_get_coins(struct coins_view_sqlite *cvs,
                                  const struct uint256 *txid,
                                  struct coins *out)
{
    bool found = false;

    coins_init(out);
    if (!cvs || !cvs->db || !cvs->stmt_get || !txid)
        LOG_FAIL("coins_view", "get_coins: invalid arguments (cvs=%p txid=%p)",
                 (const void *)cvs, (const void *)txid);

    pthread_mutex_lock(&cvs->mutex);
    sqlite3_stmt *s = cvs->stmt_get;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, txid->data, 32, SQLITE_STATIC);

    /* Two-pass: first find max vout index, then allocate and fill.
     * This avoids realloc during iteration (which caused heap corruption). */
    uint32_t max_vout = 0;
    int nrows = 0;
    int height = 0;
    int is_coinbase = 0;

    /* Pass 1: find max vout and metadata */
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        uint32_t vi = (uint32_t)sqlite3_column_int(s, 0);
        if (nrows == 0) {
            height = sqlite3_column_int(s, 3);
            is_coinbase = sqlite3_column_int(s, 4);
        }
        if (vi > max_vout) max_vout = vi;
        nrows++;
    }

    if (nrows == 0) {
        sqlite3_reset(s);
        pthread_mutex_unlock(&cvs->mutex);
        return false;
    }
    found = true;

    /* Allocate once */
    if (!coins_alloc(out, (size_t)(max_vout + 1))) {
        sqlite3_reset(s);
        pthread_mutex_unlock(&cvs->mutex);
        LOG_FAIL("coins_view", "get_coins: coins_alloc failed for %u vouts", max_vout + 1);
    }
    out->version = 1;
    out->height = height;
    out->is_coinbase = (is_coinbase != 0);

    /* Pass 2: fill in values */
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, txid->data, 32, SQLITE_STATIC);

    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        uint32_t vi = (uint32_t)sqlite3_column_int(s, 0);
        if (vi >= out->num_vout) continue;

        out->vout[vi].value = sqlite3_column_int64(s, 1);
        const void *script = sqlite3_column_blob(s, 2);
        int script_len = sqlite3_column_bytes(s, 2);
        if (script && script_len > 0) {
            size_t slen = (size_t)script_len;
            if (slen > MAX_SCRIPT_SIZE) slen = MAX_SCRIPT_SIZE;
            memcpy(out->vout[vi].script_pub_key.data, script, slen);
            out->vout[vi].script_pub_key.size = slen;
        }
    }

    coins_cleanup(out);
    sqlite3_reset(s);
    pthread_mutex_unlock(&cvs->mutex);
    return found;
}

/* ── have_coins: existence check ───────────────────────────────── */

bool coins_view_sqlite_have_coins(struct coins_view_sqlite *cvs,
                                   const struct uint256 *txid)
{
    if (!cvs || !cvs->stmt_have || !txid)
        LOG_FAIL("coins_view", "have_coins: invalid arguments");
    pthread_mutex_lock(&cvs->mutex);
    sqlite3_stmt *s = cvs->stmt_have;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, txid->data, 32, SQLITE_STATIC);
    bool found = AR_STEP_ROW_READONLY(s) == SQLITE_ROW;
    sqlite3_reset(s);
    pthread_mutex_unlock(&cvs->mutex);
    return found;
}

/* ── get_best_block — CACHE ACCESSOR ───────────────────────────────
 * Reads the node_state 'coins_best_block' projection key. Decision paths
 * must prefer reducer_frontier_derive_coins_best (the coins_kv-derived
 * authority) and use this only as the legacy/!found fallback. */

bool coins_view_sqlite_get_best_block(struct coins_view_sqlite *cvs,
                                       struct uint256 *hash)
{
    bool found = false;

    if (!cvs || !cvs->db || !hash)
        LOG_FAIL("coins_view", "get_best_block: invalid arguments");
    if (!cvs->stmt_best_get) { uint256_set_null(hash);
        LOG_FAIL("coins_view", "get_best_block: stmt_best_get not prepared"); }
    pthread_mutex_lock(&cvs->mutex);
    sqlite3_stmt *s = cvs->stmt_best_get;
    sqlite3_reset(s);
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        int len = sqlite3_column_bytes(s, 0);
        const void *data = sqlite3_column_blob(s, 0);
        if (data && len >= 32) {
            memcpy(hash->data, data, 32);
            found = true;
        }
    }
    sqlite3_reset(s);
    pthread_mutex_unlock(&cvs->mutex);
    if (found)
        return true;
    uint256_set_null(hash);
    return false;
}

/* ── batch_write: flush dirty coins_map to SQLite ───────────── */

bool coins_view_sqlite_batch_write( // one-write-path-ok:coins-sqlite-writer-impl
    struct coins_view_sqlite *cvs, struct coins_map *map_coins,
    const struct uint256 *hash_block, const struct utxo_commitment *commit)
{
    if (!cvs->db)
        LOG_FAIL("coins_view", "batch_write: db handle is NULL");

    /* Transaction control: dedicated connection uses BEGIN IMMEDIATE.
     * Shared handle (in-memory or fallback) uses SAVEPOINT to nest
     * inside any existing transaction from node_db batch writes. */
    const char *txn_begin = cvs->owns_db ? "BEGIN IMMEDIATE"
                                          : "SAVEPOINT coins_flush";
    const char *txn_commit = cvs->owns_db ? "COMMIT"
                                           : "RELEASE coins_flush";
    const char *txn_rollback = cvs->owns_db ? "ROLLBACK"
                                : "ROLLBACK TO SAVEPOINT coins_flush";

    pthread_mutex_lock(&cvs->mutex);

    /* Reset only OUR prepared statements before the transaction
     * opens.  The old code walked every prepared statement on the
     * shared connection via sqlite3_next_stmt() and reset each —
     * including readers owned by other subsystems (wallet_sqlite,
     * block_index_db, ...) that may have been sitting on SQLITE_ROW
     * mid-iteration.  Resetting someone else's stmt silently
     * rewinds their iterator and skips rows.  Now we only reset
     * statements we own; if an external subsystem is still holding
     * a cursor open, SAVEPOINT will SQLITE_BUSY and we'll bail
     * cleanly — the subsystem is expected to finalize its own
     * iterators before racing with a UTXO flush. */
    if (cvs->stmt_get)        sqlite3_reset(cvs->stmt_get);
    if (cvs->stmt_have)       sqlite3_reset(cvs->stmt_have);
    if (cvs->stmt_insert)     sqlite3_reset(cvs->stmt_insert);
    if (cvs->stmt_delete_tx)  sqlite3_reset(cvs->stmt_delete_tx);
    if (cvs->stmt_best_get)   sqlite3_reset(cvs->stmt_best_get);
    if (cvs->stmt_best_set)   sqlite3_reset(cvs->stmt_best_set);
    if (cvs->stmt_commit_get) sqlite3_reset(cvs->stmt_commit_get);
    if (cvs->stmt_commit_set) sqlite3_reset(cvs->stmt_commit_set);

    /* Bump busy timeout for the flush — during IBD, WAL contention
     * from background readers/checkpointers makes SQLITE_BUSY common.
     * Without adequate timeout, flush failures cause unbounded memory
     * growth (71GB WAL observed in production). */
    sqlite3_busy_timeout(cvs->db, 30000); /* 30s for flush */
    {
        char *txn_err = NULL;
        int txn_rc = sqlite3_exec(cvs->db, txn_begin,
                                   NULL, NULL, &txn_err);
        if (txn_rc != SQLITE_OK) {
            fprintf(stderr, "coins_flush: %s failed rc=%d: %s\n",  // obs-ok:helper-context-logged
                    txn_begin, txn_rc, txn_err ? txn_err : "unknown");
            if (txn_err) sqlite3_free(txn_err);
            sqlite3_busy_timeout(cvs->db, 10000); /* restore */
            pthread_mutex_unlock(&cvs->mutex);
            return false;
        }
    }

    int write_errors = 0;
    size_t entries_written = 0;
    size_t entries_deleted = 0;

    for (size_t i = 0; i < map_coins->num_buckets; i++) {
        struct coins_map_entry *e = &map_coins->buckets[i];
        if (!e->occupied || !(e->entry.flags & COINS_CACHE_DIRTY))
            continue;

        if (coins_is_pruned(&e->entry.coins)) {
            /* All outputs spent — remove from SQLite */
            sqlite3_reset(cvs->stmt_delete_tx);
            sqlite3_bind_blob(cvs->stmt_delete_tx, 1,
                              e->txid.data, 32, SQLITE_STATIC);
            int rc = sqlite3_step(cvs->stmt_delete_tx); // raw-sql-ok:cvs-zcl-ar-raw-sql-rationale
            if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
                fprintf(stderr, "coins_flush: DELETE failed rc=%d: %s\n",  // obs-ok:helper-context-logged
                        rc, sqlite3_errmsg(cvs->db));
                write_errors++;
            } else {
                entries_deleted++;
            }
        } else {
            /* Delete stale rows first, then insert current outputs */
            sqlite3_reset(cvs->stmt_delete_tx);
            sqlite3_bind_blob(cvs->stmt_delete_tx, 1,
                              e->txid.data, 32, SQLITE_STATIC);
            int rc = sqlite3_step(cvs->stmt_delete_tx); // raw-sql-ok:cvs-zcl-ar-raw-sql-rationale
            if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
                fprintf(stderr, "coins_flush: pre-DELETE failed rc=%d: %s\n",  // obs-ok:write_errors-counted-and-rolled-back-below
                        rc, sqlite3_errmsg(cvs->db));
                write_errors++;
            }

            const struct coins *cc = &e->entry.coins;
            for (size_t vi = 0; vi < cc->num_vout; vi++) {
                if (tx_out_is_null(&cc->vout[vi]))
                    continue;

                uint8_t addr_hash[20];
                bool has_addr = false;
                enum script_type stype = utxo_classify_script(
                    cc->vout[vi].script_pub_key.data,
                    cc->vout[vi].script_pub_key.size,
                    addr_hash, &has_addr);

                sqlite3_stmt *ins = cvs->stmt_insert;
                sqlite3_reset(ins);
                sqlite3_bind_blob(ins, 1, e->txid.data, 32, SQLITE_STATIC);
                sqlite3_bind_int(ins, 2, (int)vi);
                sqlite3_bind_int64(ins, 3, cc->vout[vi].value);
                sqlite3_bind_blob(ins, 4,
                    cc->vout[vi].script_pub_key.data,
                    (int)cc->vout[vi].script_pub_key.size,
                    SQLITE_STATIC);
                sqlite3_bind_int(ins, 5, stype);
                if (has_addr)
                    sqlite3_bind_blob(ins, 6, addr_hash, 20, SQLITE_STATIC);
                else
                    sqlite3_bind_null(ins, 6);
                sqlite3_bind_int(ins, 7, cc->height);
                sqlite3_bind_int(ins, 8, cc->is_coinbase ? 1 : 0);
                rc = sqlite3_step(ins); // raw-sql-ok:cvs-zcl-ar-raw-sql-rationale
                if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
                    fprintf(stderr, "coins_flush: INSERT failed rc=%d "  // obs-ok:write_errors-counted-and-rolled-back-below
                            "h=%d vout=%zu: %s\n",
                            rc, cc->height, vi, sqlite3_errmsg(cvs->db));
                    write_errors++;
                } else {
                    entries_written++;
                }
            }
        }
    }

    if (write_errors > 0) {
        fprintf(stderr, "coins_flush: %d write errors! "  // obs-ok:paired-with-event_emitf-below
                "Rolling back to prevent UTXO loss "
                "(wrote=%zu deleted=%zu)\n",
                write_errors, entries_written, entries_deleted);
        event_emitf(EV_COINS_FLUSH_FAILED, 0,
                    "write_errors=%d wrote=%zu deleted=%zu",
                    write_errors, entries_written, entries_deleted);
        sqlite3_exec(cvs->db, txn_rollback, NULL, NULL, NULL);
        pthread_mutex_unlock(&cvs->mutex);
        return false;
    }

    /* Verify: at least one operation should have occurred if map had dirty
     * entries. Count actual dirty entries — map_coins->size includes clean
     * (read-only) entries that don't need flushing. */
    if (entries_written == 0 && entries_deleted == 0) {
        size_t dirty_count = 0;
        for (size_t di = 0; di < map_coins->num_buckets; di++) {
            struct coins_map_entry *de = &map_coins->buckets[di];
            if (de->occupied && (de->entry.flags & COINS_CACHE_DIRTY))
                dirty_count++;
        }
        if (dirty_count > 0) {
            fprintf(stderr, "coins_flush: WARNING zero operations with "  // obs-ok:warning-only-on-best-effort-path
                    "%zu dirty entries (total=%zu) — possible silent failure\n",
                    dirty_count, map_coins->size);
        }
    }

    /* Update best block hash */
    if (hash_block && !uint256_is_null(hash_block)) {
        sqlite3_reset(cvs->stmt_best_set);
        sqlite3_bind_blob(cvs->stmt_best_set, 1,
                          hash_block->data, 32, SQLITE_STATIC);
        int rc = sqlite3_step(cvs->stmt_best_set); // raw-sql-ok:cvs-zcl-ar-raw-sql-rationale
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            fprintf(stderr, "coins_flush: best_block UPDATE failed rc=%d: "  // obs-ok:paired-with-return-false-below
                    "%s\n", rc, sqlite3_errmsg(cvs->db));
            sqlite3_exec(cvs->db, txn_rollback, NULL, NULL, NULL);
            pthread_mutex_unlock(&cvs->mutex);
            return false;
        }
    }

    /* Write UTXO commitment inside the same transaction (atomic with
     * the coins flush). Kept inside the same transaction as the coins
     * flush so no window exists where a concurrent reader could block
     * the next SAVEPOINT. */
    if (commit) {
        uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE];
        utxo_commitment_serialize(commit, buf);
        sqlite3_reset(cvs->stmt_commit_set);
        sqlite3_bind_blob(cvs->stmt_commit_set, 1,
                          buf, UTXO_COMMITMENT_SERIALIZED_SIZE, SQLITE_STATIC);
        int rc = AR_STEP_WRITE(cvs->stmt_commit_set);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            fprintf(stderr, "coins_flush: commitment UPDATE failed rc=%d: "  // obs-ok:non-fatal-commitment-is-optional
                    "%s\n", rc, sqlite3_errmsg(cvs->db));
            /* Non-fatal: commitment is optional, don't rollback coins */
        }
    }

    /* Reset only OUR statements before COMMIT/RELEASE (see the
     * rationale on the pre-BEGIN reset above). */
    if (cvs->stmt_get)        sqlite3_reset(cvs->stmt_get);
    if (cvs->stmt_have)       sqlite3_reset(cvs->stmt_have);
    if (cvs->stmt_insert)     sqlite3_reset(cvs->stmt_insert);
    if (cvs->stmt_delete_tx)  sqlite3_reset(cvs->stmt_delete_tx);
    if (cvs->stmt_best_get)   sqlite3_reset(cvs->stmt_best_get);
    if (cvs->stmt_best_set)   sqlite3_reset(cvs->stmt_best_set);
    if (cvs->stmt_commit_get) sqlite3_reset(cvs->stmt_commit_get);
    if (cvs->stmt_commit_set) sqlite3_reset(cvs->stmt_commit_set);

    {
        char *errmsg = NULL;
        int rc = sqlite3_exec(cvs->db, txn_commit, NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "coins_flush: %s failed: %s\n",  // obs-ok:paired-with-return-false-below
                    txn_commit, errmsg ? errmsg : "unknown");
            if (errmsg) sqlite3_free(errmsg);
            sqlite3_exec(cvs->db, txn_rollback, NULL, NULL, NULL);
            sqlite3_busy_timeout(cvs->db, 10000); /* restore */
            pthread_mutex_unlock(&cvs->mutex);
            return false;
        }
    }
    sqlite3_busy_timeout(cvs->db, 10000); /* restore default */

    /* Post-commit observability: both sides of the invariant we
     * enforce at boot.  Cheap to compute (MAX + COUNT on a single
     * table) and invaluable when triaging an IBD divergence. */
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(cvs->db,
                "SELECT IFNULL(MAX(height), -1), COUNT(*) FROM utxos",
                -1, &s, NULL) == SQLITE_OK) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int64_t max_h = sqlite3_column_int64(s, 0);
                int64_t count = sqlite3_column_int64(s, 1);
                int tip_h = (hash_block && !uint256_is_null(hash_block))
                          ? 1 : 0; /* presence flag; hash itself not resolved here */
                printf("[coins] flush ok: max_height=%lld utxos=%lld "
                       "tip_written=%d wrote=%zu deleted=%zu\n",
                       (long long)max_h, (long long)count, tip_h,
                       entries_written, entries_deleted);
            }
            sqlite3_finalize(s);
        }
    }

    pthread_mutex_unlock(&cvs->mutex);
    return true;
}

/* ── UTXO commitment persistence ───────────────────────────────── */

bool coins_view_sqlite_read_commitment(struct coins_view_sqlite *cvs,
                                        struct utxo_commitment *uc)
{
    if (!cvs || !cvs->db || !uc) { if (uc) utxo_commitment_init(uc);
        LOG_FAIL("coins_view", "read_commitment: invalid arguments"); }
    if (!cvs->stmt_commit_get) { utxo_commitment_init(uc);
        LOG_FAIL("coins_view", "read_commitment: stmt_commit_get not prepared"); }
    pthread_mutex_lock(&cvs->mutex);
    sqlite3_reset(cvs->stmt_commit_get);
    if (AR_STEP_ROW_READONLY(cvs->stmt_commit_get) == SQLITE_ROW) {
        int len = sqlite3_column_bytes(cvs->stmt_commit_get, 0);
        const void *data = sqlite3_column_blob(cvs->stmt_commit_get, 0);
        sqlite3_reset(cvs->stmt_commit_get);
        pthread_mutex_unlock(&cvs->mutex);
        if (data && len >= UTXO_COMMITMENT_SERIALIZED_SIZE)
            return utxo_commitment_deserialize(uc, data, (size_t)len);
        utxo_commitment_init(uc);
        return false;
    }
    sqlite3_reset(cvs->stmt_commit_get);
    pthread_mutex_unlock(&cvs->mutex);
    utxo_commitment_init(uc);
    return false;
}
