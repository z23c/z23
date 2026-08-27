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
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <string.h>

struct zcl_result yardsale_prevout_fetch_confirmed(void *ctx,
                                                   const uint8_t txid[32],
                                                   struct transaction *tx_out)
{
    const struct yardsale_prevout_view *view = ctx;
    if (!view || !view->state || !view->node_db || !view->node_db->open ||
        !view->datadir || !txid || !tx_out)
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

    struct block_index *bi = active_chain_at(&view->state->chain_active,
                                             row.block_height);
    if (!bi || !bi->phashBlock ||
        memcmp(row.block_hash, bi->phashBlock->data,
               sizeof(row.block_hash)) != 0)
        return ZCL_ERR(-4, "prevout fetch: locator is not on the "
                           "active chain");

    struct block blk;
    block_init(&blk);
    struct zcl_result out =
        ZCL_ERR(-5, "prevout fetch: confirmed body unreadable or "
                    "txid mismatch");
    if (read_block_from_disk_index(&blk, bi, view->datadir) &&
        (size_t)row.tx_index < blk.num_vtx &&
        memcmp(blk.vtx[row.tx_index].hash.data, txid, 32) == 0) {
        struct uint256 body_hash;
        block_header_get_hash(&blk.header, &body_hash);
        if (uint256_cmp(&body_hash, bi->phashBlock) == 0) {
            transaction_free(tx_out);
            transaction_init(tx_out);
            if (transaction_copy(tx_out, &blk.vtx[row.tx_index]))
                out = ZCL_OK;
            else
                out = ZCL_ERR(-6, "prevout fetch: body copy failed");
        } else {
            LOG_WARN("yardsale", "prevout fetch: body hash mismatch "
                     "(height=%d tx_index=%d)", row.block_height,
                     row.tx_index);
        }
    }
    block_free(&blk);
    return out;
}
