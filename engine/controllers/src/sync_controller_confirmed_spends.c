/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomically reconcile wallet notes spent by canonical tx bodies. */

#include "controllers/sync_controller.h"

#include "chain/chain.h"
#include "models/database.h"
#include "models/db_txn.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "sync_controller_internal.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <stdlib.h>
#include <string.h>

struct confirmed_sapling_spends_ctx {
    const struct transaction *tx;
    size_t marked;
};

static bool confirmed_sapling_spends_write(struct node_db *ndb, void *opaque)
{
    struct confirmed_sapling_spends_ctx *ctx = opaque;
    if (!ndb || !ndb->open || !ctx || !ctx->tx)
        LOG_FAIL("sync", "confirmed_sapling_spends_write: invalid context");

    DB_TXN_SCOPE(txn, ndb, "wallet.sapling_note_confirmed_spends");
    if (!txn)
        LOG_FAIL("sync",
                 "confirmed_sapling_spends_write: transaction begin failed");

    for (size_t i = 0; i < ctx->tx->num_shielded_spend; i++) {
        enum db_mark_spent_result result = db_sapling_note_mark_spent(
            ndb, ctx->tx->v_shielded_spend[i].nullifier.data,
            ctx->tx->hash.data);
        if (result == DB_MARK_SPENT_ERROR)
            LOG_FAIL("sync",
                     "confirmed_sapling_spends_write: spend %zu failed",
                     i);
        ctx->marked++;
    }
    if (!db_txn_commit(txn))
        LOG_FAIL("sync",
                 "confirmed_sapling_spends_write: transaction commit failed");
    return true;
}

bool node_db_sync_confirmed_sapling_spends(
    struct node_db *ndb, const struct transaction *tx)
{
    if (!ndb || !ndb->open || !tx || tx->num_shielded_spend == 0)
        LOG_FAIL("sync", "confirmed_sapling_spends: invalid args or no spends");
    struct confirmed_sapling_spends_ctx ctx = {
        .tx = tx,
        .marked = 0,
    };
    if (!sync_run_write(ndb, confirmed_sapling_spends_write, &ctx))
        LOG_FAIL("sync", "confirmed_sapling_spends: atomic write failed");
    if (ctx.marked != tx->num_shielded_spend)
        LOG_FAIL("sync", "confirmed_sapling_spends: marked=%zu expected=%zu",
                 ctx.marked, tx->num_shielded_spend);
    return true;
}

static bool reconcile_one_canonical_note(
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    const uint8_t nullifier[32], int64_t height)
{
    if (height < 0 || height > INT32_MAX)
        LOG_FAIL("sync", "canonical note height is out of range");

    zcl_mutex_lock(&ms->cs_main);
    struct block_index *bi = active_chain_at(&ms->chain_active, (int)height);
    zcl_mutex_unlock(&ms->cs_main);
    if (!bi)
        LOG_FAIL("sync", "canonical note block is outside active chain");

    struct block block;
    block_init(&block);
    if (!read_block_from_disk_index(&block, bi, datadir)) {
        block_free(&block);
        LOG_FAIL("sync", "canonical note block body is unavailable");
    }
    struct uint256 actual_hash;
    block_header_get_hash(&block.header, &actual_hash);
    zcl_mutex_lock(&ms->cs_main);
    bool still_canonical =
        active_chain_at(&ms->chain_active, (int)height) == bi &&
        block_map_find(&ms->map_block_index, &actual_hash) == bi;
    zcl_mutex_unlock(&ms->cs_main);
    if (!still_canonical) {
        block_free(&block);
        LOG_FAIL("sync", "canonical note block body is not the active index");
    }

    bool found = false;
    for (size_t i = 0; i < block.num_vtx && !found; i++) {
        for (size_t j = 0; j < block.vtx[i].num_shielded_spend; j++) {
            if (memcmp(block.vtx[i].v_shielded_spend[j].nullifier.data,
                       nullifier, 32) != 0)
                continue;
            transaction_compute_hash(&block.vtx[i]);
            found = node_db_sync_confirmed_sapling_spends(
                ndb, &block.vtx[i]);
            break;
        }
    }
    block_free(&block);
    if (!found)
        LOG_FAIL("sync", "canonical nullifier has no exact active block spender");
    return true;
}

bool node_db_reconcile_canonical_sapling_notes(
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    size_t *reconciled_out)
{
    if (reconciled_out)
        *reconciled_out = 0;
    if (!ndb || !ndb->open || !ms || !datadir)
        LOG_FAIL("sync", "canonical note reconciliation: invalid argument");

    sqlite3 *db = progress_store_db();
    int64_t activation_cursor = -1;
    bool cursor_found = false;
    progress_store_tx_lock();
    bool complete = db && nullifier_kv_activation_cursor(
        db, &activation_cursor, &cursor_found);
    progress_store_tx_unlock();
    if (!complete || !cursor_found || activation_cursor != 0)
        LOG_FAIL("sync", "canonical nullifier history is not complete");

    struct db_sapling_note *notes = NULL;
    int count = db_sapling_note_list_unspent_alloc(ndb, &notes);
    if (count < 0)
        LOG_FAIL("sync", "canonical note reconciliation: note read failed");
    for (int i = 0; i < count; i++) {
        bool found = false;
        int64_t height = -1;
        progress_store_tx_lock();
        bool read_ok = nullifier_kv_get(
            db, notes[i].nullifier, NULLIFIER_POOL_SAPLING, &found, &height);
        progress_store_tx_unlock();
        if (!read_ok) {
            free(notes);
            LOG_FAIL("sync", "canonical note reconciliation: lookup failed");
        }
        if (!found)
            continue;
        if (!reconcile_one_canonical_note(
                ndb, ms, datadir, notes[i].nullifier, height)) {
            free(notes);
            return false; // raw-return-ok:callee logged exact reconciliation failure
        }
        if (reconciled_out)
            (*reconciled_out)++;
    }
    free(notes);
    return true;
}
