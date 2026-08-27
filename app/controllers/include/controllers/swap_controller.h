/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Swap Controller — RPC commands for HTLC atomic swaps.
 *
 * Commands:
 *   swap_initiate    — create HTLC, generate secret, return contract
 *   swap_participate — create counter-HTLC for a given secret_hash
 *   swap_redeem      — claim funds with preimage
 *   swap_refund      — reclaim funds after locktime
 *   swap_list        — list swap contracts
 *   swap_chains      — list supported chains */

#ifndef ZCL_CONTROLLERS_SWAP_H
#define ZCL_CONTROLLERS_SWAP_H

#include "rpc/server.h"
#include "models/database.h"

struct wallet;
struct tx_mempool;
struct main_state;
struct coins_view_cache;
struct connman;

/* Wire the persistence + chain/wallet context for the swap RPCs: the node_db
 * (contract persistence), the wallet (keys + fee), the mempool + coins tip
 * (funding lookup + acceptance), the chain tip (height for CLTV + locktime
 * anchoring), and connman (relay). Any NULL leaves the corresponding RPC
 * returning a clear "node context unavailable" error rather than crashing. */
void rpc_swap_set_context(struct node_db *ndb, struct wallet *w,
                          struct tx_mempool *mp, struct main_state *ms,
                          struct coins_view_cache *coins_tip,
                          struct connman *cm);

void register_swap_rpc_commands(struct rpc_table *t);

#include "json/json.h"
bool api_swap_list(struct json_value *result);
bool api_swap_chains(struct json_value *result);

/* Convert an RPC-supplied swap amount (whole coins) into zatoshis.
 * The contract model documents amount as positive with no zero-value
 * swaps, and the value persists as int64_t — so this refuses everything
 * else the wire can hand us: zero/negative, NaN, infinities, and any
 * magnitude whose zatoshis would overflow. Returns false with *zat_out
 * untouched on refusal. Exported so the money-shape contract is pinned
 * directly, not only through the RPC plumbing. */
bool swap_amount_to_zat(double amount_coins, int64_t *zat_out);

#endif
