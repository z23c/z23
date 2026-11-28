/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * PURPOSE: Bind private mining-template v6 transactions to their wire and txid. */
#ifndef ZCL_RESEARCH_TEMPLATE_TRANSACTION_H
#define ZCL_RESEARCH_TEMPLATE_TRANSACTION_H

#include "chain/chainparams.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "services/ironwood_checked_wire.h"
#include "validation/main_constants.h"

static inline bool research_template_private_active(const struct chain_params *params)
{
    const struct chain_research_descriptor *p = chain_research_profile_current();
    return p && p->id == CHAIN_RESEARCH_IRONWOOD && params == p->chain &&
           chain_params_get() == p->chain;
}

static inline bool research_template_is_v6(const struct transaction *tx)
{
    return tx && ((tx->overwintered && tx->version == IRONWOOD_TX_VERSION &&
                   tx->version_group_id == IRONWOOD_VERSION_GROUP_ID) ||
                  tx->v6_wire.data || tx->v6_wire.size);
}

/* Legacy serialization is unchanged; v6 is accepted only in the explicitly
 * selected private profile and only after binding all decoded model fields. */
static inline bool research_template_write_tx(const struct chain_params *params,
    const struct transaction *tx, struct byte_stream *out)
{
    if (!tx || !out) return false;
    if (!research_template_is_v6(tx)) return transaction_serialize(tx, out);
    if (!research_template_private_active(params)) return false;
    struct v6_wire_view view;
    return ironwood_checked_wire(tx, MAX_BLOCK_SIZE, &view).ok &&
           stream_write_bytes(out, tx->v6_wire.data, tx->v6_wire.size);
}

static inline bool research_template_txid(const struct chain_params *params,
    const struct transaction *tx, struct uint256 *out)
{
    if (!tx || !out) return false;
    if (!research_template_is_v6(tx)) return transaction_hash_serialized(tx, out);
    if (!research_template_private_active(params)) return false;
    struct v6_wire_view view;
    if (!ironwood_checked_wire(tx, MAX_BLOCK_SIZE, &view).ok) return false;
    *out = tx->hash;
    return true;
}
#endif
