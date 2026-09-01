/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_BLOCKCHAIN_H
#define ZCL_RPC_BLOCKCHAIN_H

#include "rpc/server.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include <stdbool.h>
#include <stdint.h>

struct coins_view_db;
struct coins_view_cache;
struct node_db;
void rpc_blockchain_set_state(struct main_state *ms, struct tx_mempool *mp,
                               const char *datadir);
void rpc_blockchain_set_coins_db(struct coins_view_db *cvdb,
                                  struct coins_view_cache *coins_tip);
void rpc_blockchain_set_node_db(struct node_db *ndb);
void register_blockchain_rpc_commands(struct rpc_table *t);

/* MMR (Merkle Mountain Range) — append block hashes for power node sync */
struct mmr;
void rpc_blockchain_mmr_append(const uint8_t block_hash[32]);
void rpc_blockchain_mmr_init_from_state(struct node_db *ndb);
void rpc_blockchain_mmr_catchup(struct main_state *ms);
void rpc_blockchain_mmr_save(struct node_db *ndb);
bool rpc_blockchain_mmr_snapshot(uint8_t root[32], uint64_t *num_leaves,
                                 uint32_t *num_peaks);

/* MMB (Merkle Mountain Belt) — O(1) append, rich FlyClient leaves.
 * Runs alongside MMR during transition. */
struct mmb;
struct mmb_leaf;
void rpc_blockchain_mmb_append(const struct mmb_leaf *leaf);
void rpc_blockchain_mmb_init_from_state(struct node_db *ndb);
void rpc_blockchain_mmb_catchup(struct main_state *ms);
void rpc_blockchain_mmb_save(struct node_db *ndb);
bool rpc_blockchain_mmb_snapshot(uint8_t root[32], uint64_t *num_leaves,
                                 uint32_t *num_mountains);

/* Advisory commitment MMR — associates locally recorded UTXO roots with the
 * node's header history every 100 blocks. ZClassic headers do not commit these
 * roots, so peer-provided values are not consensus/PoW-bound state.
 * Each leaf: SHA3(height || block_hash || utxo_root).
 * Used to verify imported UTXO snapshots without replaying history. */
void rpc_blockchain_commitment_mmr_init_from_state(struct node_db *ndb);
void rpc_blockchain_commitment_mmr_save(struct node_db *ndb);
bool rpc_blockchain_commitment_mmr_snapshot(uint8_t root[32],
                                            uint64_t *num_leaves,
                                            uint32_t *num_peaks);

/* Append commitment at current height if it's a commitment interval.
 * Called from connect_block after UTXO set is updated.
 * Uses the incremental XOR accumulator (O(1)) instead of full SHA3 scan. */
void rpc_blockchain_maybe_commit(int32_t height,
                                  const uint8_t block_hash[32],
                                  const uint8_t xor_accumulator[32],
                                  uint64_t utxo_count);

#endif
