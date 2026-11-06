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
#include "core/hash.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/safe_alloc.h"

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

/* Section 1: a coinbase-only block rides the merkle count==1 fast-path.
 * Returns the number of failed checks. */
static int cbe_check_single_tx_block(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;

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
    return failures;
}

/* Fill the leaf list of an n-leaf merkle case: tx[0] is the coinbase and
 * tx[1..n-1] are distinct non-coinbase txs, markers base..base+n-1. */
static void cbe_fill_merkle_leaves(struct transaction *txs, size_t n,
                                   uint8_t base)
{
    cbe_coinbase_tx(&txs[0], base);
    for (size_t i = 1; i < n; i++)
        cbe_noncoinbase_tx(&txs[i], (uint8_t)(base + i));
}

/* 4 leaves, final pair an explicit duplicate: [A,B,C,C]. The merkle
 * code pads the last (even-positioned) pair with an identical leaf
 * at the base level of a 2-level tree, which the mutation detector
 * flags. Coinbase first, rest non-coinbase; tx[3].hash == tx[2].hash. */
static int cbe_check_dup_4_leaf(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;
    struct transaction txs[4];
    cbe_fill_merkle_leaves(txs, 4, 0x10);
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
    return failures;
}

/* 6 leaves, final pair an explicit duplicate: [A,B,C,D,E,E]. Three
 * base-level pairs; the duplication is at the last. */
static int cbe_check_dup_6_leaf(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;
    struct transaction txs[6];
    cbe_fill_merkle_leaves(txs, 6, 0x20);
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
    return failures;
}

/* 3 leaves [A,B,C]: normal odd padding (the genuine last leaf C is
 * duplicated by the tree-walk, which is NOT a malleability flag). */
static int cbe_check_distinct_3_leaf(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;
    struct transaction txs[3];
    cbe_fill_merkle_leaves(txs, 3, 0x30);
    struct block b;
    cbe_build_block(&b, txs, 3);

    reason[0] = '\xff'; dos = -1;
    struct zcl_result r =
        domain_consensus_check_block_merkle_root(
            &b, reason, sizeof(reason), &dos);
    CBE_CHECK("3-leaf [A,B,C] distinct -> merkle OK (no false dup)",
              r.ok && reason[0] == '\0' && dos == 0);

    for (size_t i = 0; i < 3; i++) transaction_free(&txs[i]);
    return failures;
}

/* 5 leaves [A,B,C,D,E] all distinct -> OK. */
static int cbe_check_distinct_5_leaf(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;
    struct transaction txs[5];
    cbe_fill_merkle_leaves(txs, 5, 0x40);
    struct block b;
    cbe_build_block(&b, txs, 5);

    reason[0] = '\xff'; dos = -1;
    struct zcl_result r =
        domain_consensus_check_block_merkle_root(
            &b, reason, sizeof(reason), &dos);
    CBE_CHECK("5-leaf [A,B,C,D,E] distinct -> merkle OK (no false dup)",
              r.ok && reason[0] == '\0' && dos == 0);

    for (size_t i = 0; i < 5; i++) transaction_free(&txs[i]);
    return failures;
}

/* 6 leaves [A,B,C,D,E,F] all distinct -> OK (the even-count sibling
 * of the [A,B,C,D,E,E] positive case above). */
static int cbe_check_distinct_6_leaf(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;
    struct transaction txs[6];
    cbe_fill_merkle_leaves(txs, 6, 0x50);
    struct block b;
    cbe_build_block(&b, txs, 6);

    reason[0] = '\xff'; dos = -1;
    struct zcl_result r =
        domain_consensus_check_block_merkle_root(
            &b, reason, sizeof(reason), &dos);
    CBE_CHECK("6-leaf [A,B,C,D,E,F] distinct -> merkle OK (no false dup)",
              r.ok && reason[0] == '\0' && dos == 0);

    for (size_t i = 0; i < 6; i++) transaction_free(&txs[i]);
    return failures;
}

/* A valid multi-tx block stays valid when memory is short. The merkle check
 * works in the txid array it already owns, so it needs no scratch array, and a
 * scratch allocation that would fail cannot read as a bad merkle root with
 * dos=100 against the peer that sent the block. Stops short of a verdict when
 * the fault hook cannot be armed. */
static int cbe_check_merkle_no_scratch_alloc(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;
    struct transaction txs[3];
    cbe_fill_merkle_leaves(txs, 3, 0x70);
    struct block b;
    cbe_build_block(&b, txs, 3);

    zcl_alloc_fault_fail_next("merkle_level");
    bool armed = zcl_alloc_fault_armed_label() != NULL;
    CBE_CHECK("scratch allocation fault armed", armed);
    if (armed) {
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        CBE_CHECK("valid 3-leaf block, no scratch memory -> merkle OK",
                  r.ok && reason[0] == '\0' && dos == 0);
        CBE_CHECK("merkle check asked for no scratch allocation",
                  zcl_alloc_fault_armed_label() != NULL);
    }
    zcl_alloc_fault_clear();

    /* The array the check itself owns still reports a local failure, never a
     * verdict on the block: out-of-memory, dos=0. */
    zcl_alloc_fault_fail_next("domain_check_block_txids");
    reason[0] = '\xff'; dos = -1;
    struct zcl_result oom =
        domain_consensus_check_block_merkle_root(
            &b, reason, sizeof(reason), &dos);
    zcl_alloc_fault_clear();
    CBE_CHECK("txid array allocation fails -> out-of-memory dos=0",
              !oom.ok &&
              oom.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_OUT_OF_MEMORY &&
              strcmp(reason, "out-of-memory") == 0 && dos == 0);

    for (size_t i = 0; i < 3; i++) transaction_free(&txs[i]);
    return failures;
}

#define CBE_REF_LEAVES_MAX 40
/* The bound legacy reserves for its tree: leaves * 2 + 16. */
#define CBE_REF_NODES_MAX (CBE_REF_LEAVES_MAX * 2 + 16)

/* The merkle root and mutation flag as zclassicd computes them
 * (src/primitives/block.cpp, CBlock::BuildMerkleTree): an append-only array of
 * every node, walked level by level with an offset, hashing with hash256
 * directly. Shares no code with the production loop on purpose. */
static struct uint256 cbe_ref_merkle_root(const struct uint256 *ids, int count,
                                          bool *mutated_out)
{
    struct uint256 tree[CBE_REF_NODES_MAX];
    int tree_size = 0;
    for (int i = 0; i < count; i++)
        tree[tree_size++] = ids[i];

    int j = 0;
    bool mutated = false;
    for (int size = count; size > 1; size = (size + 1) / 2) {
        for (int i = 0; i < size; i += 2) {
            int i2 = (i + 1 < size - 1) ? i + 1 : size - 1;
            if (i2 == i + 1 && i2 + 1 == size &&
                memcmp(tree[j + i].data, tree[j + i2].data, 32) == 0) {
                /* Two identical hashes at the end of a level. */
                mutated = true;
            }
            unsigned char pair[64];
            memcpy(pair, tree[j + i].data, 32);
            memcpy(pair + 32, tree[j + i2].data, 32);
            hash256(pair, sizeof(pair), tree[tree_size++].data);
        }
        j += size;
    }
    *mutated_out = mutated;
    struct uint256 root;
    uint256_set_null(&root);
    if (tree_size > 0)
        root = tree[tree_size - 1];
    return root;
}

static struct uint256 cbe_ref_leaf(unsigned int seed)
{
    unsigned char in[2] = { (unsigned char)seed, 0xc5 };
    struct uint256 leaf;
    hash256(in, sizeof(in), leaf.data);
    return leaf;
}

/* Both production entry points against the reference, root and flag. Hands back
 * the reference's answer for a caller that also pins an expected one. */
static int cbe_merkle_agrees(const char *shape, const struct uint256 *ids,
                             int count, struct uint256 *ref_root,
                             bool *ref_mutated)
{
    struct uint256 scratch[CBE_REF_LEAVES_MAX];
    if (count > 0)
        memcpy(scratch, ids, (size_t)count * sizeof(scratch[0]));
    *ref_root = cbe_ref_merkle_root(ids, count, ref_mutated);
    bool copy_mut = !*ref_mutated, place_mut = !*ref_mutated;
    struct uint256 copy_root =
        compute_merkle_root_mutated(ids, (size_t)count, &copy_mut);
    struct uint256 place_root =
        merkle_root_mutated_in_place(scratch, (size_t)count, &place_mut);
    if (uint256_eq(ref_root, &copy_root) && uint256_eq(ref_root, &place_root) &&
        copy_mut == *ref_mutated && place_mut == *ref_mutated)
        return 0;
    printf("check_block_edge: %s n=%d differs from reference: root %d/%d "
           "flag ref=%d copy=%d place=%d\n", shape, count,
           uint256_eq(ref_root, &copy_root), uint256_eq(ref_root, &place_root),
           *ref_mutated, copy_mut, place_mut);
    return 1;
}

/* Every list length up to 40, as distinct leaves, with the trailing pair
 * repeated, with a repeated pair anywhere, and with a trailing sequence
 * repeated. */
static int cbe_check_merkle_reference_sweep(void)
{
    int failures = 0;
    struct uint256 ids[CBE_REF_LEAVES_MAX];
    struct uint256 root;
    bool flag;
    for (int n = 0; n <= CBE_REF_LEAVES_MAX; n++) {
        for (int i = 0; i < n; i++)
            ids[i] = cbe_ref_leaf((unsigned int)i);
        failures += cbe_merkle_agrees("distinct", ids, n, &root, &flag);
        if (flag) {
            printf("check_block_edge: reference flagged distinct n=%d\n", n);
            failures++;
        }

        for (int at = 0; at + 1 < n; at++) {
            struct uint256 kept = ids[at + 1];
            ids[at + 1] = ids[at];
            failures += cbe_merkle_agrees("repeated pair", ids, n, &root, &flag);
            ids[at + 1] = kept;
        }

        for (int tail = 1; tail <= n / 2; tail++) {
            for (int i = 0; i < tail; i++)
                ids[n - tail + i] = ids[n - 2 * tail + i];
            failures += cbe_merkle_agrees("repeated tail", ids, n, &root, &flag);
            for (int i = 0; i < tail; i++)
                ids[n - tail + i] = cbe_ref_leaf((unsigned int)(n - tail + i));
        }
    }
    CBE_CHECK("merkle root and flag match the legacy reference, 0..40 leaves",
              failures == 0);
    return failures;
}

/* A list and its mutated form share one root, and only the mutated form is
 * flagged. `l` holds the mutated form; its first `plain` leaves are the list. */
static int cbe_check_merkle_form(const char *name, const struct uint256 *l,
                                 int plain, int mutated_len)
{
    int failures = 0;
    struct uint256 root, mut_root;
    bool flag, mut_flag;
    int bad = cbe_merkle_agrees(name, l, plain, &root, &flag);
    bad += cbe_merkle_agrees(name, l, mutated_len, &mut_root, &mut_flag);
    CBE_CHECK(name, bad == 0 && !flag && mut_flag &&
                    uint256_eq(&root, &mut_root));
    return failures;
}

/* The two known forms by value. */
static int cbe_check_merkle_reference_named(void)
{
    struct uint256 l[8];
    for (unsigned int i = 0; i < 6; i++)
        l[i] = cbe_ref_leaf(0x40 + i);
    struct uint256 abcc[4] = { l[0], l[1], l[2], l[2] };
    int failures = cbe_check_merkle_form(
        "[A,B,C,C] flagged, same root as [A,B,C]", abcc, 3, 4);

    l[6] = l[4];
    l[7] = l[5];
    failures += cbe_check_merkle_form(
        "[1,2,3,4,5,6,5,6] flagged, same root as [1,2,3,4,5,6]", l, 6, 8);
    return failures;
}

/* Check the aggregate-sigops verdict for a 1-tx coinbase block carrying
 * exactly `total` legacy sigops. Returns the number of failed checks. */
static int cbe_check_sigops_total(unsigned int total, uint8_t marker,
                                  const char *desc, bool expect_reject)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;

    /* Helper: build a 1-tx coinbase block whose total legacy sigops is
     * exactly `total` by laying down `total` OP_CHECKSIG bytes split
     * across enough 10000-byte vout scripts. Returns the block + tx by
     * out-params; caller frees the tx. */
    #define OP_CHECKSIG_BYTE ((unsigned char)0xac)
    #define SIGOPS_PER_SCRIPT 10000u

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
    tx.hash.data[0] = marker;

    struct block b;
    cbe_build_block(&b, &tx, 1);

    reason[0] = '\xff'; dos = -1;
    struct zcl_result r =
        domain_consensus_check_block_sigops(
            &b, reason, sizeof(reason), &dos);
    if (expect_reject) {
        CBE_CHECK(desc,
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_BLK_SIGOPS &&
                  strcmp(reason, "bad-blk-sigops") == 0 &&
                  dos == 100);
    } else {
        CBE_CHECK(desc, r.ok && reason[0] == '\0' && dos == 0);
    }

    transaction_free(&tx);
    return failures;
}

int test_check_block_edge(void)
{
    int failures = 0;

    /* ================================================================
     * 1. Single-tx (coinbase-only) block — merkle count==1 fast-path.
     * ================================================================ */
    failures += cbe_check_single_tx_block();

    /* ================================================================
     * 2. CVE-2012-2459 at deeper tree levels.
     * ================================================================ */

    failures += cbe_check_dup_4_leaf();
    failures += cbe_check_dup_6_leaf();

    /* ================================================================
     * 3. CVE negative controls — legitimate odd-tree padding MUST NOT
     *    be flagged as a duplication. A false-positive mutation reject
     *    would fork the chain by rejecting valid blocks.
     * ================================================================ */

    failures += cbe_check_distinct_3_leaf();
    failures += cbe_check_distinct_5_leaf();
    failures += cbe_check_distinct_6_leaf();

    /* A local memory failure is not a verdict on the block. */
    failures += cbe_check_merkle_no_scratch_alloc();
    failures += cbe_check_merkle_reference_sweep();
    failures += cbe_check_merkle_reference_named();

    /* ================================================================
     * 4. Aggregate sigops boundary: MAX_BLOCK_SIGOPS == 20000.
     *    Each OP_CHECKSIG (0xac) byte counts as exactly one legacy
     *    sigop. MAX_SCRIPT_SIZE is 10000, so we spread the bytes across
     *    multiple vout scripts on a single coinbase tx.
     * ================================================================ */

    /* --- exactly 20000 sigops -> ACCEPT --- */
    {
        const unsigned int total = 20000u;          /* == limit */
        failures += cbe_check_sigops_total(
            total, 0x60, "sigops == 20000 (limit) -> OK", false);
    }

    /* --- exactly 20001 sigops -> REJECT bad-blk-sigops dos=100 --- */
    {
        const unsigned int total = 20001u;          /* limit + 1 */
        failures += cbe_check_sigops_total(
            total, 0x61,
            "sigops == 20001 (over limit) -> bad-blk-sigops dos=100",
            true);
    }

    return failures;
}
