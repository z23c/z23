/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_regtest_generate — regression test for the regtest `generate` RPC.
 *
 * THE BUG THIS GUARDS
 * -------------------
 * The `generate N` RPC (engine/controllers/src/mining_controller.c) built a
 * block template and submitted it straight through the reducer front door
 * (reducer_ingest_block) WITHOUT ever solving the Equihash proof-of-work.
 * The reducer's first gate is check_block(..., check_pow=true, ...), which
 * verifies a real Equihash witness (size-demuxed to the chain's (N,K) — for
 * regtest that is (48,5), a 36-byte solution). With nNonce=0 and an empty
 * nSolution the block was rejected at intake every time, so the tip never
 * advanced: the S3 chaos harness saw bootstrap tip stuck at genesis (h0).
 *
 * THE FIX
 * -------
 * core/modules/mining/src/miner.c::mine_block_pow() now solves the Equihash PoW
 * (core/modules/crypto/src/equihash.c::equihash_basic_solve) and searches nonces
 * until the block hash is <= the nBits target. rpc_generate() calls it
 * before submitting, so each generated block carries a valid witness and
 * passes the SAME stateless gate the reducer applies.
 *
 * WHAT THIS TEST ASSERTS (real consensus, no stubs)
 * -------------------------------------------------
 *   1. mine_block_pow() produces a block that passes check_block() with
 *      check_pow=TRUE — i.e. the exact gate reducer_ingest_block() runs
 *      (reducer_ingest_service.c: check_block(pblock, out, params,
 *      true, true, true)). Before the fix this is impossible.
 *   2. The solved solution is a real Equihash answer (the verifier accepts
 *      it) AND the block hash is <= the regtest target.
 *   3. N=3 blocks can be mined as a chain (each building on the prior),
 *      modelling `generate 3` advancing the tip by 3, and each block's
 *      coinbase creates a spendable output of subsidy+fees (the UTXO that
 *      lands in the set once utxo_apply runs) — proving the new coinbase
 *      UTXO is present, value-correct, and at the right height.
 *
 * It runs in milliseconds: regtest Equihash (48,5) solves in << 1 ms and
 * the regtest target accepts roughly 1-in-16 solutions, so a block is
 * found in a few dozen nonce attempts.
 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include "domain/consensus/coinbase.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "validation/check_block.h"

#include <stdio.h>
#include <string.h>

/* Build a regtest block at `height` on top of `prev_hash` exactly the way
 * create_new_block() shapes it: one coinbase tx (subsidy, no fees, given
 * miner script), merkle root over that single tx, header fields filled,
 * nBits = the regtest powLimit compact (what GetNextWorkRequired hands the
 * first blocks). Returns false on any allocation/build failure. */
static bool build_regtest_block(struct block *blk, int height,
                                const struct uint256 *prev_hash,
                                const struct chain_params *cp,
                                int64_t *out_coinbase_value)
{
    block_init(blk);
    blk->vtx = calloc(1, sizeof(struct transaction));
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    /* A minimal, non-empty miner script (P2PKH-ish placeholder). */
    struct script miner_script;
    script_init(&miner_script);
    miner_script.data[0] = 0x76; /* OP_DUP    */
    miner_script.data[1] = 0xa9; /* OP_HASH160 */
    miner_script.data[2] = 0x14; /* push 20    */
    for (int i = 0; i < 20; i++)
        miner_script.data[3 + i] = (unsigned char)(0x10 + i);
    miner_script.data[23] = 0x88; /* OP_EQUALVERIFY */
    miner_script.data[24] = 0xac; /* OP_CHECKSIG    */
    miner_script.size = 25;

    int64_t subsidy = get_block_subsidy(height, &cp->consensus);
    struct domain_consensus_coinbase_inputs cb_in = {
        .n_height     = height,
        .subsidy      = subsidy,
        .total_fees   = 0,
        .miner_script = &miner_script,
        .params       = &cp->consensus,
    };
    struct zcl_result r = domain_consensus_coinbase_build(&cb_in, coinbase);
    if (!r.ok)
        return false;

    if (out_coinbase_value)
        *out_coinbase_value = subsidy;

    /* Merkle root over the single coinbase tx. */
    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);

    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1600000000u + (uint32_t)height;

    /* First-block work target: powLimit as a compact bits value, exactly
     * what GetNextWorkRequired returns before the averaging window fills. */
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);

    return true;
}

int test_regtest_generate(void);
int test_regtest_generate(void)
{
    int failures = 0;
    printf("\n=== regtest generate: mine valid PoW blocks through the "
           "reducer's consensus gate ===\n");

    /* The default test runner inits CHAIN_MAIN; switch to regtest for this
     * group and restore on the way out so the sequential runner is unaffected
     * (the parallel runner forks per group, so it is naturally isolated). */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    /* Sanity: regtest really is the small (48,5) parameter set. */
    {
        unsigned int n = chain_params_equihash_n(cp, 1);
        unsigned int k = chain_params_equihash_k(cp, 1);
        printf("regtest_generate: Equihash params are (48,5)... ");
        if (n == 48 && k == 5) printf("OK\n");
        else { printf("FAIL (got %u,%u)\n", n, k); failures++; }
    }

    /* Mine a chain of N blocks, each on top of the previous one, modelling
     * `generate N`. Genesis stands in as height-0 prev for block 1. */
    const int N = 3;
    struct uint256 prev_hash = cp->consensus.hashGenesisBlock;
    int64_t total_coinbase = 0;

    for (int i = 0; i < N; i++) {
        int height = i + 1;

        struct block blk;
        int64_t cb_value = 0;
        bool built = build_regtest_block(&blk, height, &prev_hash, cp,
                                         &cb_value);
        printf("regtest_generate: build block h%d... ", height);
        if (built) printf("OK (subsidy=%lld)\n", (long long)cb_value);
        else { printf("FAIL\n"); failures++; block_free(&blk); break; }

        /* THE FIX UNDER TEST: solve Equihash + PoW. */
        bool mined = mine_block_pow(&blk, height, cp, 0);
        printf("regtest_generate: mine_block_pow h%d (solve Equihash 48,5 "
               "+ nonce search)... ", height);
        if (mined) printf("OK\n");
        else { printf("FAIL (no PoW found)\n"); failures++; block_free(&blk); break; }

        /* (1) The solution must be a real Equihash witness AND the hash must
         * meet the target — verify both independently of mine_block_pow. */
        {
            struct equihash_params ep;
            equihash_params_init(&ep, 48, 5);
            struct blake2b_ctx st;
            equihash_initialise_state(&ep, &st);
            uint8_t le[4];
            le[0]=(uint8_t)((uint32_t)blk.header.nVersion & 0xff);
            le[1]=(uint8_t)(((uint32_t)blk.header.nVersion>>8)&0xff);
            le[2]=(uint8_t)(((uint32_t)blk.header.nVersion>>16)&0xff);
            le[3]=(uint8_t)(((uint32_t)blk.header.nVersion>>24)&0xff);
            blake2b_update(&st, le, 4);
            blake2b_update(&st, blk.header.hashPrevBlock.data, 32);
            blake2b_update(&st, blk.header.hashMerkleRoot.data, 32);
            blake2b_update(&st, blk.header.hashFinalSaplingRoot.data, 32);
            le[0]=(uint8_t)(blk.header.nTime&0xff);
            le[1]=(uint8_t)((blk.header.nTime>>8)&0xff);
            le[2]=(uint8_t)((blk.header.nTime>>16)&0xff);
            le[3]=(uint8_t)((blk.header.nTime>>24)&0xff);
            blake2b_update(&st, le, 4);
            le[0]=(uint8_t)(blk.header.nBits&0xff);
            le[1]=(uint8_t)((blk.header.nBits>>8)&0xff);
            le[2]=(uint8_t)((blk.header.nBits>>16)&0xff);
            le[3]=(uint8_t)((blk.header.nBits>>24)&0xff);
            blake2b_update(&st, le, 4);
            blake2b_update(&st, blk.header.nNonce.data, 32);

            bool eh_ok = equihash_is_valid_solution(&ep, &st,
                            blk.header.nSolution, blk.header.nSolutionSize);
            printf("regtest_generate: h%d solution is a valid Equihash "
                   "witness... ", height);
            if (eh_ok) printf("OK\n");
            else { printf("FAIL\n"); failures++; }

            struct uint256 hh;
            block_header_get_hash(&blk.header, &hh);
            struct arith_uint256 ha, ta;
            uint256_to_arith(&ha, &hh);
            arith_uint256_set_compact(&ta, blk.header.nBits, NULL, NULL);
            bool pow_ok = arith_uint256_compare(&ha, &ta) <= 0;
            printf("regtest_generate: h%d block hash <= target... ", height);
            if (pow_ok) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }

        /* (2) The mined block must pass the EXACT gate the reducer applies
         * at intake: check_block(check_pow=true, check_merkle=true,
         * check_size=true). This is reducer_ingest_block()'s first gate
         * verbatim. */
        {
            struct validation_state vs;
            validation_state_init(&vs);
            bool ok = check_block(&blk, &vs, cp, true, true, true);
            printf("regtest_generate: h%d passes reducer check_block"
                   "(pow=true)... ", height);
            if (ok) printf("OK\n");
            else {
                printf("FAIL (%s)\n",
                       vs.reject_reason[0] ? vs.reject_reason : "unknown");
                failures++;
            }
        }

        /* (3) The coinbase output is the spendable UTXO that utxo_apply will
         * add to the set: one vout carrying subsidy+fees, recorded at this
         * block's height. */
        {
            const struct transaction *cb = &blk.vtx[0];
            bool shape_ok = transaction_is_coinbase(cb) &&
                            cb->num_vout == 1 &&
                            cb->vout[0].value == cb_value &&
                            cb->vout[0].value > 0;
            printf("regtest_generate: h%d coinbase UTXO value=%lld correct... ",
                   height, (long long)cb->vout[0].value);
            if (shape_ok) { printf("OK\n"); total_coinbase += cb->vout[0].value; }
            else { printf("FAIL\n"); failures++; }
        }

        /* Chain forward: next block builds on this one's hash (tip advances). */
        block_header_get_hash(&blk.header, &prev_hash);
        block_free(&blk);
    }

    printf("regtest_generate: mined %d-block chain, total new coinbase "
           "value=%lld... %s\n", N, (long long)total_coinbase,
           (failures == 0 && total_coinbase > 0) ? "OK" : "see failures");
    if (total_coinbase <= 0 && failures == 0) failures++;

    /* Restore the runner's default chain. */
    chain_params_select(CHAIN_MAIN);

    printf("=== regtest generate test complete: %d failure(s) ===\n", failures);
    return failures;
}
