/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_view_kv — implementation. See storage/coins_view_kv.h.
 *
 * Read-only coins_view backed by coins_kv (the canonical UTXO set in
 * progress.kv). Mirrors coins_view_sqlite's vtable-thunk pattern,
 * fetching the process-global progress.kv handle lazily per call. */

#include "storage/coins_view_kv.h"

#include "coins/coins.h"
#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>

/* ── vtable implementations ──────────────────────────────────────── */

static bool ckv_get_coins_impl(void *self, const struct uint256 *txid,
                               struct coins *out)
{
    (void)self;
    if (!txid || !out) return false;
    /* coins_init's out and returns false on no-live-rows — same contract as
     * cvp_get_coins_impl. Bind the handle lazily: NULL store → absent. */
    sqlite3 *db = progress_store_db();
    if (!db) {
        coins_init(out);
        return false;
    }
    return coins_kv_get_coins(db, txid->data, out);
}

static bool ckv_have_coins_impl(void *self, const struct uint256 *txid)
{
    (void)self;
    if (!txid) return false;
    /* "have" = any live output of txid exists. Reuse get_coins (the extra
     * reconstruction is acceptable on this read-only miss path) and release
     * the coins — byte-for-byte the same shape as cvp_have_coins_impl. */
    sqlite3 *db = progress_store_db();
    if (!db) return false;
    struct coins c;
    bool found = coins_kv_get_coins(db, txid->data, &c);
    if (found) coins_free(&c);
    return found;
}

static bool ckv_get_best_block_impl(void *self, struct uint256 *hash)
{
    /* coins_kv stores no best-block hash: the tip_finalize cursor is the
     * definitional tip for the authoritative read path. Report "unknown",
     * exactly like cvp_get_best_block_impl (callers tolerate false here). */
    (void)self;
    if (hash) uint256_set_null(hash);
    return false;
}

static bool ckv_batch_write_impl(void *self, struct coins_map *map_coins,
                                 const struct uint256 *hash_block)
{
    /* Read-only: the stage authors UTXO state by writing coins_kv inside the
     * apply txn, so flushing the legacy cache back through this view would be
     * a second writer — exactly what the single-writer authority forbids.
     * Reaching here means the cache was wired to flush to the coins_kv
     * backing, which is a programming error (identical to
     * cvp_batch_write_impl). */
    (void)self; (void)map_coins; (void)hash_block;
    LOG_FAIL("coins_view_kv",
             "batch_write called: coins_kv view is read-only (stage authors "
             "UTXO via the apply txn); cache must not flush here");
}

static bool ckv_get_stats_impl(void *self, struct coins_stats *stats)
{
    (void)self; (void)stats;
    return false;
}

static enum coins_anchor_lookup_result ckv_get_anchor_impl(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    (void)self;
    if (!root)
        return COINS_ANCHOR_ERROR;
    /* The singleton progress.kv connection is transaction-scoped, not merely
     * statement-threadsafe.  Serialize this read so mempool/connect cannot
     * observe an anchor inserted by an uncommitted reducer transaction.  The
     * lock is recursive for callers already inside the stage transaction. */
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

static struct coins_view_vtable ckv_vtable = {
    .get_coins      = ckv_get_coins_impl,
    .have_coins     = ckv_have_coins_impl,
    .get_best_block = ckv_get_best_block_impl,
    .batch_write    = ckv_batch_write_impl,
    .get_stats      = ckv_get_stats_impl,
    .get_anchor     = ckv_get_anchor_impl,
};

bool coins_view_kv_init(struct coins_view_kv *ckv)
{
    if (!ckv)
        LOG_FAIL("coins_view_kv", "init: NULL arg");
    ckv->view.vtable = &ckv_vtable;
    ckv->view.impl   = ckv;
    return true;
}
