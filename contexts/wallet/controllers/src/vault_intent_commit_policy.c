/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: narrow restart policy for already-prepared vault transactions. */

#include "controllers/vault_intent_controller.h"

#include "controllers/wallet_helpers.h"
#include "chain/chain.h"
#include "models/vault_intent.h"
#include "validation/main_state.h"

#include <string.h>

bool vault_intent_prepared_retry_allowed(
    const struct vault_intent_row *row, bool prepared_raw)
{
    /* Exact signed bytes created by an authorized commit may finish after a
     * restart or expiry. No planned, terminal, or byte-less intent receives
     * renewed spend authority through this recovery exception. */
    return row && prepared_raw && row->state == VAULT_INTENT_PROVING;
}

bool vault_intent_anchor_current(const struct wallet_rpc_context *ctx,
                                 const struct vault_intent_row *row)
{
    if (!ctx || !ctx->main_state || !row)
        return false;
    struct block_index *tip =
        active_chain_tip(&ctx->main_state->chain_active);
    return tip && tip->nHeight == row->anchor_height &&
        memcmp(tip->hashBlock.data, row->anchor_hash, 32) == 0;
}
