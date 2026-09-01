/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Reorg-safe wallet projection rollback for one disconnected block. */

#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"
#include "models/db_txn.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"

struct wallet_disconnect_block_ctx {
    const struct block *blk;
    const bool *keep_pending;
    bool ok;
};

static bool wallet_disconnect_block_write(struct node_db *ndb, void *opaque)
{
    struct wallet_disconnect_block_ctx *ctx = opaque;
    if (!ndb || !ndb->open || !ctx || !ctx->blk || !ctx->keep_pending)
        LOG_FAIL("sync", "wallet disconnect block: invalid context");
    if (ndb->sync_in_batch && !node_db_sync_flush(ndb))
        LOG_FAIL("sync", "wallet disconnect block: pending batch flush failed");
    DB_TXN_SCOPE(txn, ndb, "wallet.disconnect_block");
    if (!txn)
        LOG_FAIL("sync", "wallet disconnect block: transaction begin failed");

    for (size_t i = 0; i < ctx->blk->num_vtx; i++) {
        const struct transaction *tx = &ctx->blk->vtx[i];
        bool found = false;
        /* Outputs from the losing block are no longer confirmed money;
         * reconnect recreates them idempotently. */
        if (!db_wallet_utxo_delete_for_tx(ndb, tx->hash.data) ||
            !db_sapling_note_delete_for_tx(ndb, tx->hash.data))
            LOG_FAIL("sync", "wallet disconnect output retract failed tx=%zu", i);
        if (ctx->keep_pending[i] && !transaction_is_coinbase(tx)) {
            if (!db_wallet_tx_mark_unconfirmed(ndb, tx->hash.data, &found))
                LOG_FAIL("sync", "wallet disconnect unconfirm failed tx=%zu", i);
            continue;
        }
        if (!db_wallet_utxo_release_spent_by(ndb, tx->hash.data) ||
            !db_sapling_note_release_reservation(ndb, tx->hash.data))
            LOG_FAIL("sync", "wallet disconnect reservation release failed tx=%zu", i);
        if (!db_wallet_tx_mark_unconfirmed(ndb, tx->hash.data, &found))
            LOG_FAIL("sync", "wallet disconnect lookup failed tx=%zu", i);
        if (found && !db_wallet_tx_delete(ndb, tx->hash.data))
            LOG_FAIL("sync", "wallet disconnect delete failed tx=%zu", i);
    }
    if (!(ctx->ok = db_txn_commit(txn)))
        LOG_FAIL("sync", "wallet disconnect transaction commit failed");
    return true;
}

bool node_db_sync_wallet_disconnect_block(struct node_db *ndb,
                                           const struct block *blk,
                                           const bool *keep_pending)
{
    struct wallet_disconnect_block_ctx ctx = {
        .blk = blk, .keep_pending = keep_pending, .ok = false,
    };
    if (!ndb || !ndb->open || !blk || !keep_pending)
        LOG_FAIL("sync", "wallet disconnect block: invalid arguments");
    return sync_run_write(ndb, wallet_disconnect_block_write, &ctx) && ctx.ok;
}
