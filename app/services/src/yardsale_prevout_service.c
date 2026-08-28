/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: confirmed-prevout fetch for the buyer's zswap chain-content
 * port — see services/yardsale_prevout_service.h for the design framing.
 * Mirrors the raw-transaction controller's canonical node-db lookup, minus
 * every fallback: no mempool, no wallet projections, no legacy txindex.
 * A swap's token input is signed only if the chain itself holds it. */

#include "services/yardsale_prevout_service.h"

#include "base/result.h"
#include "models/database.h"
#include "models/tx_index.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <string.h>

static bool yardsale_prevout_read_disk(struct block *out,
                                       const struct block_index *index,
                                       const char *datadir, void *ctx)
{
    (void)ctx;
    return read_block_from_disk_index(out, index, datadir);
}

struct yardsale_prevout_chain_snapshot {
    struct block_index *tip;
    struct block_index *block;
    struct uint256 tip_hash;
    struct uint256 block_hash;
    int tip_height;
};

static bool yardsale_prevout_chain_snapshot(
    const struct yardsale_prevout_view *view, const struct db_tx_index *row,
    struct yardsale_prevout_chain_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    out->tip_height = -1;
    zcl_mutex_lock(&view->state->cs_main);
    out->tip = active_chain_tip(&view->state->chain_active);
    out->block = active_chain_at(&view->state->chain_active,
                                 row->block_height);
    if (out->tip && out->tip->phashBlock) {
        out->tip_height = out->tip->nHeight;
        out->tip_hash = *out->tip->phashBlock;
    }
    if (out->block && out->block->phashBlock)
        out->block_hash = *out->block->phashBlock;
    zcl_mutex_unlock(&view->state->cs_main);
    return out->tip && out->tip_height >= 0 && out->block &&
        out->block->phashBlock &&
        memcmp(row->block_hash, out->block_hash.data,
               sizeof(row->block_hash)) == 0;
}

static bool yardsale_prevout_chain_unchanged(
    const struct yardsale_prevout_view *view, int block_height,
    const struct yardsale_prevout_chain_snapshot *snapshot)
{
    zcl_mutex_lock(&view->state->cs_main);
    struct block_index *tip = active_chain_tip(&view->state->chain_active);
    struct block_index *block =
        active_chain_at(&view->state->chain_active, block_height);
    bool unchanged = tip == snapshot->tip && block == snapshot->block &&
        tip && tip->phashBlock && block && block->phashBlock &&
        uint256_cmp(tip->phashBlock, &snapshot->tip_hash) == 0 &&
        uint256_cmp(block->phashBlock, &snapshot->block_hash) == 0;
    zcl_mutex_unlock(&view->state->cs_main);
    return unchanged;
}

static struct zcl_result yardsale_prevout_projection_check(
    const struct yardsale_prevout_view *view, const uint8_t txid[32],
    uint32_t vout, const uint8_t token_id[32], uint64_t token_amount,
    int tip_height)
{
    int32_t cursor = -1;
    if (!zslp_ledger_get_cursor(view->node_db, &cursor, NULL) ||
        !zslp_validity_is_caught_up(view->node_db, tip_height, NULL) ||
        cursor != tip_height)
        return ZCL_ERR(-5, "prevout fetch: strict token projection is stale "
                           "for the active tip");
    char validity_reason[64] = "unknown";
    if (zslp_validity_get(view->node_db, txid, validity_reason,
                          sizeof(validity_reason)) != ZSLP_VALIDITY_VALID)
        return ZCL_ERR(-6, "prevout fetch: token ancestry is not strictly "
                           "valid (%s)", validity_reason);
    enum zslp_ledger_outpoint_state ledger =
        zslp_ledger_token_outpoint_state(view->node_db, txid, vout,
                                         token_id, token_amount);
    if (ledger == ZSLP_LEDGER_OUTPOINT_UNSPENT_TOKEN)
        return ZCL_OK;
    static const char *const reasons[] = {
        "query failed", "row absent", "row mismatch", "output spent",
    };
    unsigned reason_i = ledger <= ZSLP_LEDGER_OUTPOINT_SPENT
        ? (unsigned)ledger : 0u;
    return ZCL_ERR(-7, "prevout fetch: strict token outpoint refused (%s)",
                   reasons[reason_i]);
}

struct zcl_result yardsale_prevout_fetch_confirmed(void *ctx,
                                                   const uint8_t txid[32],
                                                   uint32_t vout,
                                                   const uint8_t token_id[32],
                                                   uint64_t token_amount,
                                                   struct transaction *tx_out)
{
    const struct yardsale_prevout_view *view = ctx;
    if (!view || !view->state || !view->node_db || !view->node_db->open ||
        !view->datadir || !txid || !token_id || !tx_out)
        return ZCL_ERR(-1, "prevout fetch: unwired chain view");

    struct db_tx_index row;
    if (!db_tx_find(view->node_db, txid, &row))
        return ZCL_ERR(-2, "prevout fetch: txid never finalized on "
                           "this node");
    if (row.block_height < 0 || row.tx_index < 0) {
        LOG_WARN("yardsale", "prevout fetch: locator rejected negative "
                 "position (height=%d tx_index=%d)",
                 row.block_height, row.tx_index);
        return ZCL_ERR(-3, "prevout fetch: malformed locator row");
    }

    struct yardsale_prevout_chain_snapshot snapshot;
    if (!yardsale_prevout_chain_snapshot(view, &row, &snapshot))
        return ZCL_ERR(-4, "prevout fetch: locator is not on the "
                           "active chain");
    struct zcl_result projection = yardsale_prevout_projection_check(
        view, txid, vout, token_id, token_amount, snapshot.tip_height);
    if (!projection.ok)
        return projection;

    struct block blk;
    block_init(&blk);
    struct zcl_result out =
        ZCL_ERR(-8, "prevout fetch: confirmed body unreadable or "
                    "txid mismatch");
    yardsale_prevout_read_block_fn read_block = view->read_block
        ? view->read_block : yardsale_prevout_read_disk;
    if (read_block(&blk, snapshot.block, view->datadir,
                   view->read_block_ctx) &&
        (size_t)row.tx_index < blk.num_vtx &&
        memcmp(blk.vtx[row.tx_index].hash.data, txid, 32) == 0) {
        struct uint256 body_hash;
        block_header_get_hash(&blk.header, &body_hash);
        if (!yardsale_prevout_chain_unchanged(view, row.block_height,
                                               &snapshot)) {
            out = ZCL_ERR(-9, "prevout fetch: active chain changed during "
                              "the verified read");
        } else if (!(projection = yardsale_prevout_projection_check(
                         view, txid, vout, token_id, token_amount,
                         snapshot.tip_height)).ok) {
            out = projection;
        } else if (uint256_cmp(&body_hash, &snapshot.block_hash) == 0) {
            struct transaction candidate;
            transaction_init(&candidate);
            if (transaction_copy(&candidate, &blk.vtx[row.tx_index])) {
                transaction_free(tx_out);
                *tx_out = candidate;
                out = ZCL_OK;
            } else {
                transaction_free(&candidate);
                out = ZCL_ERR(-11, "prevout fetch: body copy failed");
            }
        } else {
            LOG_WARN("yardsale", "prevout fetch: body hash mismatch "
                     "(height=%d tx_index=%d)", row.block_height,
                     row.tx_index);
        }
    }
    block_free(&blk);
    return out;
}
