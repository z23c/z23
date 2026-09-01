/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * NET-NEW consensus edge-case tests for the block STRUCTURAL checks in
 * core/modules/validation/src/check_block.c (delegating to
 * domain/consensus/check_block). These exercise boundary values and
 * known historical attack patterns that the existing
 * test_domain_consensus_check_block.c does NOT cover:
 *
 *   1. Single-tx (coinbase-only) block — the merkle count==1 fast-path.
 *      The merkle root of a 1-tx block is the txid itself (no extra
 *      hashing). This is the most common real block shape and a
 *      distinct code path from the multi-tx merkle loop. We assert it
 *      ACCEPTS when header==txid and REJECTS "bad-txnmrklroot" when not.
 *
 *   2. CVE-2012-2459 (merkle malleability via duplicate-subtree padding)
 *      at DEEPER tree levels than the existing 2-leaf case:
 *        - 4 leaves where the final pair is an explicit duplicate
 *          ([A,B,C,C]) — the duplication happens at the base level of a
 *          2-level tree.
 *        - 6 leaves where the final pair is an explicit duplicate
 *          ([A,B,C,D,E,E]) — three base-level pairs, dup at the last.
 *      Both MUST be rejected "bad-txns-duplicate" dos=100.
 *
 *   3. CVE negative controls — block shapes that look superficially like
 *      a duplication but are LEGITIMATE odd-tree padding and MUST NOT be
 *      rejected. A false-positive mutation rejection would fork the
 *      chain by rejecting valid blocks:
 *        - 3 leaves [A,B,C]   (normal odd padding of a genuine leaf)
 *        - 5 leaves [A,B,C,D,E]
 *        - 6 leaves [A,B,C,D,E,F]  (all distinct)
 *
 *   4. Aggregate sigops boundary — the existing test only exercises the
 *      sigops-OK path. We pin the consensus boundary precisely:
 *        - total legacy sigops == MAX_BLOCK_SIGOPS (20000) -> ACCEPT
 *        - total legacy sigops == 20001                    -> REJECT
 *          "bad-blk-sigops" dos=100
 *      Each OP_CHECKSIG (0xac) byte counts as exactly one legacy sigop,
 *      so we lay down exactly N such bytes across vout scripts.
 *
 * Strategy mirrors test_domain_consensus_check_block.c: synthetic
 * in-process struct block, txids poked into the cached `hash` field for
 * deterministic merkle roots, the real pure domain consensus functions
 * invoked directly via the typed zcl_result API. No PoW, no contextual
 * checks, no network, no node process. Deterministic.
 */

#include "test/test_core.h"

#include "domain/consensus/check_block.h"
#include "bloom/merkle.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBE_CHECK(name, expr) do {                                  \
    printf("check_block_edge: %s... ", (name));                     \
    if ((expr)) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* A coinbase tx with a distinct, deterministic cached hash. */
static void cbe_coinbase_tx(struct transaction *tx, uint8_t marker)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = 1250000000;
    tx->vout[0].script_pub_key.size = 0;
    memset(tx->hash.data, 0, 32);
    tx->hash.data[0] = marker;
    tx->hash.data[31] = 0xa5;
}

/* A non-coinbase tx (non-null prevout) with a distinct cached hash. */
static void cbe_noncoinbase_tx(struct transaction *tx, uint8_t marker)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    memset(tx->vin[0].prevout.hash.data, 0xee, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = 500;
    tx->vout[0].script_pub_key.size = 0;
    memset(tx->hash.data, 0, 32);
    tx->hash.data[0] = marker;
    tx->hash.data[31] = 0x5a;
}

/* Build a block over the supplied txns and set the header merkle root to
 * the value actually computed from the txid list, so the merkle check
 * passes the equality gate and any verdict reflects the MUTATION flag
 * rather than a trivial header mismatch. Header otherwise zeroed. */
static void cbe_build_block(struct block *b,
                            struct transaction *txs, size_t n)
{
    block_init(b);
    b->vtx = txs;
    b->num_vtx = n;
    if (n > 0) {
        struct uint256 *ids = calloc(n, sizeof(struct uint256));
        for (size_t i = 0; i < n; i++) ids[i] = txs[i].hash;
        b->header.hashMerkleRoot = compute_merkle_root(ids, n);
        free(ids);
    } else {
        memset(&b->header.hashMerkleRoot, 0, sizeof(struct uint256));
    }
}

int test_check_block_edge(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;

    /* ================================================================
     * 1. Single-tx (coinbase-only) block — merkle count==1 fast-path.
     * ================================================================ */
    {
        struct transaction txs[1];
        cbe_coinbase_tx(&txs[0], 0x71);
        struct block b;
        cbe_build_block(&b, txs, 1);

        /* The merkle root of a 1-tx block IS the single txid. */
        CBE_CHECK("1-tx block: merkle root == sole txid",
                  uint256_eq(&b.header.hashMerkleRoot, &txs[0].hash));

        /* Merkle check accepts (no mutation possible with one leaf). */
        reason[0] = '\xff'; dos = -1;
        struct zcl_result rm =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("1-tx block: merkle -> OK, no mutation",
                  rm.ok && reason[0] == '\0' && dos == 0);

        /* size+coinbase accepts a lone coinbase. */
        reason[0] = '\xff'; dos = -1;
        struct zcl_result rs =
            domain_consensus_check_block_size_and_coinbase(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("1-tx block: size+coinbase -> OK",
                  rs.ok && reason[0] == '\0' && dos == 0);

        /* Now corrupt the header merkle root: a 1-tx block whose header
         * does not encode the sole txid must reject bad-txnmrklroot. */
        b.header.hashMerkleRoot.data[5] ^= 0x80;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result rmbad =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("1-tx block: corrupted header -> bad-txnmrklroot dos=100",
                  !rmbad.ok &&
                  rmbad.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNMRKLROOT &&
                  strcmp(reason, "bad-txnmrklroot") == 0 &&
                  dos == 100);

        for (size_t i = 0; i < 1; i++) transaction_free(&txs[i]);
    }

    /* ================================================================
     * 2. CVE-2012-2459 at deeper tree levels.
     * ================================================================ */

    /* 4 leaves, final pair an explicit duplicate: [A,B,C,C]. The merkle
     * code pads the last (even-positioned) pair with an identical leaf
     * at the base level of a 2-level tree, which the mutation detector
     * flags. Coinbase first, rest non-coinbase; tx[3].hash == tx[2].hash. */
    {
        struct transaction txs[4];
        cbe_coinbase_tx(&txs[0], 0x10);
        cbe_noncoinbase_tx(&txs[1], 0x11);
        cbe_noncoinbase_tx(&txs[2], 0x12);
        cbe_noncoinbase_tx(&txs[3], 0x13);
        txs[3].hash = txs[2].hash;   /* C,C as the final base-level pair */
        struct block b;
        cbe_build_block(&b, txs, 4);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("4-leaf [A,B,C,C] -> bad-txns-duplicate dos=100",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNS_DUP &&
                  strcmp(reason, "bad-txns-duplicate") == 0 &&
                  dos == 100);

        for (size_t i = 0; i < 4; i++) transaction_free(&txs[i]);
    }

    /* 6 leaves, final pair an explicit duplicate: [A,B,C,D,E,E]. Three
     * base-level pairs; the duplication is at the last. */
    {
        struct transaction txs[6];
        cbe_coinbase_tx(&txs[0], 0x20);
        cbe_noncoinbase_tx(&txs[1], 0x21);
        cbe_noncoinbase_tx(&txs[2], 0x22);
        cbe_noncoinbase_tx(&txs[3], 0x23);
        cbe_noncoinbase_tx(&txs[4], 0x24);
        cbe_noncoinbase_tx(&txs[5], 0x25);
        txs[5].hash = txs[4].hash;   /* E,E as the final base-level pair */
        struct block b;
        cbe_build_block(&b, txs, 6);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("6-leaf [A,B,C,D,E,E] -> bad-txns-duplicate dos=100",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNS_DUP &&
                  strcmp(reason, "bad-txns-duplicate") == 0 &&
                  dos == 100);

        for (size_t i = 0; i < 6; i++) transaction_free(&txs[i]);
    }

    /* ================================================================
     * 3. CVE negative controls — legitimate odd-tree padding MUST NOT
     *    be flagged as a duplication. A false-positive mutation reject
     *    would fork the chain by rejecting valid blocks.
     * ================================================================ */

    /* 3 leaves [A,B,C]: normal odd padding (the genuine last leaf C is
     * duplicated by the tree-walk, which is NOT a malleability flag). */
    {
        struct transaction txs[3];
        cbe_coinbase_tx(&txs[0], 0x30);
        cbe_noncoinbase_tx(&txs[1], 0x31);
        cbe_noncoinbase_tx(&txs[2], 0x32);
        struct block b;
        cbe_build_block(&b, txs, 3);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("3-leaf [A,B,C] distinct -> merkle OK (no false dup)",
                  r.ok && reason[0] == '\0' && dos == 0);

        for (size_t i = 0; i < 3; i++) transaction_free(&txs[i]);
    }

    /* 5 leaves [A,B,C,D,E] all distinct -> OK. */
    {
        struct transaction txs[5];
        cbe_coinbase_tx(&txs[0], 0x40);
        cbe_noncoinbase_tx(&txs[1], 0x41);
        cbe_noncoinbase_tx(&txs[2], 0x42);
        cbe_noncoinbase_tx(&txs[3], 0x43);
        cbe_noncoinbase_tx(&txs[4], 0x44);
        struct block b;
        cbe_build_block(&b, txs, 5);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("5-leaf [A,B,C,D,E] distinct -> merkle OK (no false dup)",
                  r.ok && reason[0] == '\0' && dos == 0);

        for (size_t i = 0; i < 5; i++) transaction_free(&txs[i]);
    }

    /* 6 leaves [A,B,C,D,E,F] all distinct -> OK (the even-count sibling
     * of the [A,B,C,D,E,E] positive case above). */
    {
        struct transaction txs[6];
        cbe_coinbase_tx(&txs[0], 0x50);
        cbe_noncoinbase_tx(&txs[1], 0x51);
        cbe_noncoinbase_tx(&txs[2], 0x52);
        cbe_noncoinbase_tx(&txs[3], 0x53);
        cbe_noncoinbase_tx(&txs[4], 0x54);
        cbe_noncoinbase_tx(&txs[5], 0x55);
        struct block b;
        cbe_build_block(&b, txs, 6);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("6-leaf [A,B,C,D,E,F] distinct -> merkle OK (no false dup)",
                  r.ok && reason[0] == '\0' && dos == 0);

        for (size_t i = 0; i < 6; i++) transaction_free(&txs[i]);
    }

    /* ================================================================
     * 4. Aggregate sigops boundary: MAX_BLOCK_SIGOPS == 20000.
     *    Each OP_CHECKSIG (0xac) byte counts as exactly one legacy
     *    sigop. MAX_SCRIPT_SIZE is 10000, so we spread the bytes across
     *    multiple vout scripts on a single coinbase tx.
     * ================================================================ */

    /* Helper: build a 1-tx coinbase block whose total legacy sigops is
     * exactly `total` by laying down `total` OP_CHECKSIG bytes split
     * across enough 10000-byte vout scripts. Returns the block + tx by
     * out-params; caller frees the tx. */
    #define OP_CHECKSIG_BYTE ((unsigned char)0xac)
    #define SIGOPS_PER_SCRIPT 10000u

    /* --- exactly 20000 sigops -> ACCEPT --- */
    {
        const unsigned int total = 20000u;          /* == limit */
        const size_t n_out = (total + SIGOPS_PER_SCRIPT - 1) / SIGOPS_PER_SCRIPT;
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, n_out);
        outpoint_set_null(&tx.vin[0].prevout);
        tx.vin[0].sequence = UINT32_MAX;
        unsigned int remaining = total;
        for (size_t o = 0; o < n_out; o++) {
            unsigned int here = remaining < SIGOPS_PER_SCRIPT
                                    ? remaining : SIGOPS_PER_SCRIPT;
            tx.vout[o].value = 0;
            tx.vout[o].script_pub_key.size = here;
            memset(tx.vout[o].script_pub_key.data, OP_CHECKSIG_BYTE, here);
            remaining -= here;
        }
        memset(tx.hash.data, 0, 32);
        tx.hash.data[0] = 0x60;

        struct block b;
        cbe_build_block(&b, &tx, 1);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_sigops(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("sigops == 20000 (limit) -> OK",
                  r.ok && reason[0] == '\0' && dos == 0);

        transaction_free(&tx);
    }

    /* --- exactly 20001 sigops -> REJECT bad-blk-sigops dos=100 --- */
    {
        const unsigned int total = 20001u;          /* limit + 1 */
        const size_t n_out = (total + SIGOPS_PER_SCRIPT - 1) / SIGOPS_PER_SCRIPT;
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, n_out);
        outpoint_set_null(&tx.vin[0].prevout);
        tx.vin[0].sequence = UINT32_MAX;
        unsigned int remaining = total;
        for (size_t o = 0; o < n_out; o++) {
            unsigned int here = remaining < SIGOPS_PER_SCRIPT
                                    ? remaining : SIGOPS_PER_SCRIPT;
            tx.vout[o].value = 0;
            tx.vout[o].script_pub_key.size = here;
            memset(tx.vout[o].script_pub_key.data, OP_CHECKSIG_BYTE, here);
            remaining -= here;
        }
        memset(tx.hash.data, 0, 32);
        tx.hash.data[0] = 0x61;

        struct block b;
        cbe_build_block(&b, &tx, 1);

        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_sigops(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("sigops == 20001 (over limit) -> bad-blk-sigops dos=100",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_BLK_SIGOPS &&
                  strcmp(reason, "bad-blk-sigops") == 0 &&
                  dos == 100);

        transaction_free(&tx);
    }

    return failures;
}
