/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_MINER_H
#define ZCL_MINER_H

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include <stdbool.h>
#include <stdint.h>

struct block_template {
    struct block block;
    int64_t *tx_fees;
    unsigned int *tx_sig_ops;
    size_t num_entries;
};

void block_template_init(struct block_template *bt);
void block_template_free(struct block_template *bt);

struct block_template *create_new_block(const struct script *coinbase_script,
                                         struct main_state *ms,
                                         struct coins_view_cache *coins_tip,
                                         struct tx_mempool *mempool,
                                         const struct chain_params *params);

void increment_extra_nonce(struct block *pblock,
                           struct block_index *pindex_prev,
                           unsigned int *extra_nonce);

/* Solve the Equihash proof-of-work for `block` at `height`, filling
 * block->header.nNonce and block->header.nSolution with a witness that
 * passes the consensus check (a valid Equihash answer whose resulting
 * block hash is <= the target encoded by header.nBits). The header's
 * other fields (version, hashPrevBlock, merkle root, sapling root,
 * nTime, nBits) must already be set — typically by create_new_block().
 *
 * Uses the generic reference solver, which is fast for the small
 * regtest/testnet (N,K) sets but NOT a competitive mainnet miner: a
 * (200,9) or (192,7) solve here would be very slow. `max_nonces` bounds
 * the nonce search (0 = a sane default); the function returns false if no
 * witness is found within that budget (the caller may retry / give up).
 *
 * On success the block is consensus-valid PoW and ready to submit through
 * the reducer front door. */
bool mine_block_pow(struct block *block, int height,
                    const struct chain_params *params,
                    uint64_t max_nonces);

#endif
