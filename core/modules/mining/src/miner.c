/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "mining/miner.h"
#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/check_block.h"
#include "validation/check_transaction.h"
#include "validation/connect_block.h"
#include "validation/process_block.h"
#include "validation/sigops.h"
#include "validation/update_coins.h"
#include "validation/main_constants.h"
#include "chain/subsidy.h"
#include "chain/pow.h"
#include "consensus/upgrades.h"
#include "bloom/merkle.h"
#include "core/random.h"
#include "domain/consensus/coinbase.h"
#include "script/script.h"
#include "script/script_flags.h"
#include "util/timedata.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util/safe_alloc.h"

static void block_compute_merkle_root(struct block *b)
{
    struct uint256 *txids = zcl_malloc(b->num_vtx * sizeof(struct uint256), "merkle_txids");
    if (!txids) {
        LOG_WARN("mining", "block_compute_merkle_root: malloc failed");
        return;
    }
    for (size_t i = 0; i < b->num_vtx; i++)
        txids[i] = b->vtx[i].hash;
    b->header.hashMerkleRoot = compute_merkle_root(txids, b->num_vtx);
    free(txids);
}

void block_template_init(struct block_template *bt)
{
    block_init(&bt->block);
    bt->tx_fees = NULL;
    bt->tx_sig_ops = NULL;
    bt->num_entries = 0;
}

void block_template_free(struct block_template *bt)
{
    block_free(&bt->block);
    free(bt->tx_fees);
    free(bt->tx_sig_ops);
    bt->tx_fees = NULL;
    bt->tx_sig_ops = NULL;
    bt->num_entries = 0;
}

static struct block_template *create_new_block_locked(
                                         const struct script *coinbase_script,
                                         struct main_state *ms,
                                         struct coins_view_cache *coins_tip,
                                         struct tx_mempool *mempool,
                                         const struct chain_params *params)
{
    struct block_template *bt = zcl_malloc(sizeof(struct block_template), "block_template");
    if (!bt)
        return NULL;
    block_template_init(bt);

    struct block_index *pindex_prev = active_chain_tip(&ms->chain_active);
    if (!pindex_prev) {
        block_template_free(bt);
        free(bt);
        return NULL;
    }

    int height = pindex_prev->nHeight + 1;

    /* Collect transactions from mempool */
    size_t max_txs = 1 + mempool->num_entries;
    bt->block.vtx = zcl_calloc(max_txs, sizeof(struct transaction), "block_transactions");
    if (!bt->block.vtx) {
        block_template_free(bt);
        free(bt);
        return NULL;
    }
    bt->tx_fees = zcl_calloc(max_txs, sizeof(int64_t), "tx_fees");
    bt->tx_sig_ops = zcl_calloc(max_txs, sizeof(unsigned int), "tx_sig_ops");
    if (!bt->tx_fees || !bt->tx_sig_ops) {
        block_template_free(bt);
        free(bt);
        return NULL;
    }

    /* Placeholder coinbase at index 0 */
    transaction_init(&bt->block.vtx[0]);
    bt->block.num_vtx = 1;
    bt->tx_fees[0] = 0;
    bt->tx_sig_ops[0] = 0;
    bt->num_entries = 1;

    int64_t total_fees = 0;
    unsigned int blk_sig_ops = 100;
    uint64_t block_size = 1000;

    /* Add mempool transactions (simple greedy by order) */
    for (size_t i = 0; i < mempool->num_entries; i++) {
        const struct transaction *tx = &mempool->entries[i].tx;

        if (transaction_is_coinbase(tx))
            continue;

        uint64_t tx_size = 250;
        /* Cap the block we BUILD at the mining policy size (200KB, matching
         * zclassicd's miner), not the 2MB consensus reject limit. */
        if (block_size + tx_size >= DEFAULT_BLOCK_MAX_SIZE)
            continue;

        unsigned int tx_sigops = (unsigned int)get_legacy_sig_op_count(
            tx, SCRIPT_VERIFY_P2SH);
        if (blk_sig_ops + tx_sigops >= MAX_BLOCK_SIGOPS)
            continue;

        if (!coins_view_cache_have_inputs(coins_tip, tx))
            continue;

        int64_t value_in = coins_view_cache_get_value_in(coins_tip, tx);
        int64_t value_out = transaction_get_value_out(tx);
        int64_t tx_fee = value_in - value_out;

        size_t idx = bt->block.num_vtx;
        transaction_init(&bt->block.vtx[idx]);
        transaction_copy(&bt->block.vtx[idx], tx);
        bt->tx_fees[idx] = tx_fee;
        bt->tx_sig_ops[idx] = tx_sigops;
        bt->block.num_vtx++;
        bt->num_entries++;

        total_fees += tx_fee;
        blk_sig_ops += tx_sigops;
        block_size += tx_size;
    }

    /* Create coinbase transaction. Allocation is an adapter concern
     * (lives here); shaping (scriptSig, vout value, version/group_id
     * per epoch, hash) is pure and lives in
     * domain/consensus/coinbase.c. */
    struct transaction *coinbase = &bt->block.vtx[0];
    transaction_free(coinbase);
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1)) {
        block_template_free(bt);
        free(bt);
        return NULL;
    }
    struct domain_consensus_coinbase_inputs cb_in = {
        .n_height     = height,
        .subsidy      = get_block_subsidy(height, &params->consensus),
        .total_fees   = total_fees,
        .miner_script = coinbase_script,
        .params       = &params->consensus,
    };
    struct zcl_result cb_r = domain_consensus_coinbase_build(&cb_in, coinbase);
    if (!cb_r.ok) {
        fprintf(stderr, "[miner] coinbase_build failed at height %d: "
                "code=%d %s (%s:%d)\n", height, cb_r.code, cb_r.message,
                cb_r.source_file, cb_r.source_line);
        block_template_free(bt);
        free(bt);
        return NULL;
    }

    /* The pure builder sets version/group_id per epoch but leaves the
     * overwintered flag at transaction_init's false; setting the flag from
     * the wire-shape fields the builder just chose is an adapter concern
     * (every other tx builder in the tree does it explicitly: wallet.c,
     * transaction_controller.c, ...). Without it a locally-mined coinbase
     * at a post-Overwinter height fails the contextual Sapling-structural
     * rule tx-overwintered-flag-not-set
     * (core/consensus/src/sapling_structural.c), so a chain with
     * Overwinter/Sapling active (e.g. -regtestshielded) wedges on its own
     * mined blocks. */
    if (coinbase->version_group_id != 0)
        coinbase->overwintered = true;

    bt->tx_fees[0] = -total_fees;

    /* Fill in header */
    if (!pindex_prev->phashBlock) return NULL;
    bt->block.header.hashPrevBlock = *pindex_prev->phashBlock;
    bt->block.header.nTime = (uint32_t)GetAdjustedTime();
    bt->block.header.nBits = GetNextWorkRequired(pindex_prev,
                                                  &bt->block.header, &params->consensus);

    block_compute_merkle_root(&bt->block);

    return bt;
}

struct block_template *create_new_block(const struct script *coinbase_script,
                                         struct main_state *ms,
                                         struct coins_view_cache *coins_tip,
                                         struct tx_mempool *mempool,
                                         const struct chain_params *params)
{
    if (!ms)
        return NULL;
    /* A template is one coherent projection of tip + mempool + coins. Tip
     * finalize uses this same ownership lock while it publishes the new
     * coins generation and removes confirmed entries, so selection can see
     * either side of that transition but never a mixture. */
    zcl_mutex_lock(&ms->cs_main);
    zcl_mutex_lock(&mempool->cs);
    struct block_template *bt = create_new_block_locked(
        coinbase_script, ms, coins_tip, mempool, params);
    zcl_mutex_unlock(&mempool->cs);
    zcl_mutex_unlock(&ms->cs_main);
    return bt;
}

void increment_extra_nonce(struct block *pblock,
                           struct block_index *pindex_prev,
                           unsigned int *extra_nonce)
{
    static struct uint256 hash_prev_block;
    if (uint256_cmp(&hash_prev_block, &pblock->header.hashPrevBlock) != 0) {
        *extra_nonce = 0;
        hash_prev_block = pblock->header.hashPrevBlock;
    }
    (*extra_nonce)++;

    int height = pindex_prev->nHeight + 1;
    struct transaction *cb = &pblock->vtx[0];

    /* scriptSig shaping is pure — delegate to domain layer. The
     * legacy semantics (3-byte BIP34 height push followed by a
     * minimal-length extra-nonce push, zero nonce -> single zero byte)
     * are preserved exactly. */
    struct zcl_result sr = domain_consensus_coinbase_script_sig_with_extra_nonce(
            height, *extra_nonce, &cb->vin[0].script_sig);
    if (!sr.ok) {
        fprintf(stderr, "[miner] increment_extra_nonce script_sig failed "
                "at height %d: code=%d %s (%s:%d)\n", height, sr.code,
                sr.message, sr.source_file, sr.source_line);
        return;
    }

    transaction_compute_hash(cb);
    block_compute_merkle_root(pblock);
}

/* Build the personalised BLAKE2b state and feed the header's
 * pre-solution bytes + the 32-byte nonce, EXACTLY as the consensus
 * verifier does (domain/consensus/equihash.c). Solving against this
 * state guarantees the witness verifies. */
static void miner_build_eh_state(const struct block_header *h,
                                 const struct equihash_params *ep,
                                 struct blake2b_ctx *out_state)
{
    equihash_initialise_state(ep, out_state);

    uint8_t le[4];
    le[0] = (uint8_t)((uint32_t)h->nVersion        & 0xff);
    le[1] = (uint8_t)(((uint32_t)h->nVersion >>  8) & 0xff);
    le[2] = (uint8_t)(((uint32_t)h->nVersion >> 16) & 0xff);
    le[3] = (uint8_t)(((uint32_t)h->nVersion >> 24) & 0xff);
    blake2b_update(out_state, le, 4);

    blake2b_update(out_state, h->hashPrevBlock.data,        32);
    blake2b_update(out_state, h->hashMerkleRoot.data,       32);
    blake2b_update(out_state, h->hashFinalSaplingRoot.data, 32);

    le[0] = (uint8_t)(h->nTime        & 0xff);
    le[1] = (uint8_t)((h->nTime >>  8) & 0xff);
    le[2] = (uint8_t)((h->nTime >> 16) & 0xff);
    le[3] = (uint8_t)((h->nTime >> 24) & 0xff);
    blake2b_update(out_state, le, 4);

    le[0] = (uint8_t)(h->nBits        & 0xff);
    le[1] = (uint8_t)((h->nBits >>  8) & 0xff);
    le[2] = (uint8_t)((h->nBits >> 16) & 0xff);
    le[3] = (uint8_t)((h->nBits >> 24) & 0xff);
    blake2b_update(out_state, le, 4);

    blake2b_update(out_state, h->nNonce.data, 32);
}

bool mine_block_pow(struct block *block, int height,
                    const struct chain_params *params,
                    uint64_t max_nonces)
{
    if (!block || !params)
        LOG_FAIL("mining", "mine_block_pow: null %s",
                 !block ? "block" : "params");

    unsigned int n = chain_params_equihash_n(params, height);
    unsigned int k = chain_params_equihash_k(params, height);

    /* Refuse an (N,K) this build's bit-packers cannot represent BEFORE any
     * of it reaches them — the packers assert on their width assumptions and
     * assert is live in release builds. */
    if (!equihash_params_supported(n, k))
        LOG_FAIL("mining", "mine_block_pow: unsupported equihash parameters "
                 "N=%u K=%u at height %d", n, k, height);

    struct equihash_params ep;
    equihash_params_init(&ep, n, k);
    if (ep.solution_width > MAX_SOLUTION_SIZE) {
        fprintf(stderr, "[miner] equihash solution width %zu exceeds cap %d "
                "(N=%u K=%u)\n", ep.solution_width, MAX_SOLUTION_SIZE, n, k);
        return false;
    }

    /* PoW target from nBits — the same compact decode the verifier uses. */
    struct arith_uint256 target;
    bool neg = false, over = false;
    arith_uint256_set_compact(&target, block->header.nBits, &neg, &over);
    if (neg || over || arith_uint256_is_zero(&target)) {
        fprintf(stderr, "[miner] malformed nBits=0x%08x at height %d\n",
                block->header.nBits, height);
        return false;
    }

    if (max_nonces == 0)
        max_nonces = 1u << 20; /* generous; small (N,K) solve in << this */

    /* Start the nonce at zero and increment a little-endian counter in the
     * low 8 bytes of the 32-byte nonce. Deterministic and reproducible. */
    memset(block->header.nNonce.data, 0, 32);

    for (uint64_t attempt = 0; attempt < max_nonces; attempt++) {
        struct blake2b_ctx state;
        miner_build_eh_state(&block->header, &ep, &state);

        unsigned char soln[MAX_SOLUTION_SIZE];
        if (equihash_basic_solve(&ep, &state, soln, sizeof(soln))) {
            memcpy(block->header.nSolution, soln, ep.solution_width);
            block->header.nSolutionSize = ep.solution_width;

            struct uint256 hash;
            block_header_get_hash(&block->header, &hash);
            struct arith_uint256 hash_arith;
            uint256_to_arith(&hash_arith, &hash);
            if (arith_uint256_compare(&hash_arith, &target) <= 0)
                return true; /* valid Equihash + hash <= target */
        }

        /* Advance the little-endian nonce counter and retry. */
        for (int b = 0; b < 32; b++) {
            if (++block->header.nNonce.data[b] != 0)
                break;
        }
    }

    fprintf(stderr, "[miner] mine_block_pow: no PoW within %llu nonces "
            "(height %d, N=%u K=%u)\n",
            (unsigned long long)max_nonces, height, n, k);
    return false;
}
