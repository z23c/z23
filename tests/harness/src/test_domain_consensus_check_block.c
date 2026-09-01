/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/check_block.{c,h}.
 *
 * These tests pin the pure block STRUCTURAL checks (merkle root,
 * size+coinbase, sigops). They exercise the domain functions directly
 * via the typed zcl_result API, and — crucially — cross-check the
 * verdict against the legacy core/modules/validation/check_block::check_block()
 * wrapper on every representative block shape. The legacy wrapper now
 * delegates to the domain functions, so if the wrapper's reject_reason
 * ever drifts from "bad-blk-length" / "bad-cb-missing" /
 * "bad-cb-multiple" / "bad-txnmrklroot" / "bad-txns-duplicate" /
 * "bad-blk-sigops" (the byte-identical P2P-visible strings) this test
 * will shout.
 *
 * Block-construction strategy: synthetic struct block built in
 * process. No PoW or contextual checks are exercised here (those are
 * separate verdicts, separate tests). We call the domain functions
 * directly with `check_pow=false, check_merkle_root=true,
 * check_size_limits=true` to drive the legacy wrapper into the same
 * branches we test in the domain.
 */

#include "test/test_core.h"

#include "domain/consensus/check_block.h"
#include "validation/check_block.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "consensus/validation.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirror of the private DOMAIN_MAX_BLOCK_SIGOPS in
 * domain/consensus/src/check_block.c (== MAX_BLOCK_SIGOPS, 20000). The
 * CHECKDATASIG boundary KAT below builds blocks at exactly this value, so it
 * pins the constant: if the domain limit drifts, the 20000-OK / 20001-reject
 * assertions diverge and the test shouts. */
#define DOMAIN_MAX_BLOCK_SIGOPS_TEST 20000

#define DCB_CHECK(name, expr) do {                                  \
    printf("domain_consensus_check_block: %s... ", (name));         \
    if ((expr)) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* ---- synthetic block builders ---------------------------------- */

static void coinbase_tx(struct transaction *tx, uint8_t marker)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = 1250000000;
    tx->vout[0].script_pub_key.size = 0;
    /* Give each tx a distinct, deterministic hash so the merkle root
     * is non-trivially computable. We poke a marker byte into the
     * cached `hash` field. Real callers compute it via
     * transaction_compute_hash; here we just need uniqueness. */
    memset(tx->hash.data, 0, 32);
    tx->hash.data[0] = marker;
    tx->hash.data[31] = 0xa5;
}

static void noncoinbase_tx(struct transaction *tx, uint8_t marker)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    /* Non-null prevout makes transaction_is_coinbase return false. */
    memset(tx->vin[0].prevout.hash.data, 0xee, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = 500;
    tx->vout[0].script_pub_key.size = 0;
    memset(tx->hash.data, 0, 32);
    tx->hash.data[0] = marker;
    tx->hash.data[31] = 0x5a;
}

/* Build a non-coinbase tx whose output scripts contain exactly `total_ops`
 * top-level OP_CHECKDATASIG (0xba) opcodes — one single-byte sigop each —
 * spread across as many MAX_SCRIPT_SIZE outputs as needed. Used to drive the
 * block sigop tally to a precise value at the MAX_BLOCK_SIGOPS boundary. */
static void checkdatasig_tx(struct transaction *tx, uint8_t marker,
                            size_t total_ops)
{
    transaction_init(tx);
    size_t n_out = (total_ops + MAX_SCRIPT_SIZE - 1) / MAX_SCRIPT_SIZE;
    if (n_out == 0) n_out = 1;
    transaction_alloc(tx, 1, n_out);
    memset(tx->vin[0].prevout.hash.data, 0xee, 32);  /* non-null => not coinbase */
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    tx->vin[0].script_sig.size = 0;
    size_t remaining = total_ops;
    for (size_t i = 0; i < n_out; i++) {
        size_t s = remaining > MAX_SCRIPT_SIZE ? MAX_SCRIPT_SIZE : remaining;
        memset(tx->vout[i].script_pub_key.data, OP_CHECKDATASIG, s);
        tx->vout[i].script_pub_key.size = s;
        tx->vout[i].value = 1;
        remaining -= s;
    }
    memset(tx->hash.data, 0, 32);
    tx->hash.data[0] = marker;
    tx->hash.data[31] = 0xcd;
}

/* Build a block with the supplied txns and fix up the header's merkle
 * root so it matches the txid list. Header is otherwise zeroed; that
 * is fine because we never run PoW or contextual checks. */
static void build_block(struct block *b,
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

/* Compare the domain verdict to the legacy wrapper's reject_reason +
 * DoS score. The wrapper now DELEGATES to the domain, so this is the
 * regression seal that locks the extraction in. */
static bool cross_check_against_legacy(const struct block *b,
                                       const char *expect_reason,
                                       int expect_dos,
                                       bool expect_ok)
{
    struct validation_state st;
    validation_state_init(&st);
    /* check_pow=false (Equihash needs a real solution); merkle and
     * size_limits both ON so we route through the same paths the
     * domain functions own. */
    bool ok = check_block(b, &st, chain_params_get(), false, true, true);
    if (expect_ok) {
        if (!ok) {
            printf("\n  legacy wrapper unexpectedly REJECTED (reason=%s mode=%d)\n",
                   st.reject_reason, (int)st.mode);
            return false;
        }
        return true;
    }
    if (ok) {
        printf("\n  legacy wrapper unexpectedly ACCEPTED (expected reason=%s)\n",
               expect_reason);
        return false;
    }
    if (strcmp(st.reject_reason, expect_reason) != 0) {
        printf("\n  legacy reject_reason drift: got '%s' expected '%s'\n",
               st.reject_reason, expect_reason);
        return false;
    }
    if (st.dos != expect_dos) {
        printf("\n  legacy DoS drift: got %d expected %d (reason=%s)\n",
               st.dos, expect_dos, expect_reason);
        return false;
    }
    return true;
}

int test_domain_consensus_check_block(void)
{
    int failures = 0;
    char reason[DOMAIN_CHECK_BLOCK_REASON_MAX];
    int  dos;

    /* ---- null-arg contracts ---- */
    {
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(NULL, NULL, 0, NULL);
        DCB_CHECK("merkle_root: null block -> ERR_NULL_ARG",
                  !r.ok && r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_block_size_and_coinbase(NULL, NULL, 0, NULL);
        DCB_CHECK("size_and_coinbase: null block -> ERR_NULL_ARG",
                  !r.ok && r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_block_sigops(NULL, NULL, 0, NULL);
        DCB_CHECK("sigops: null block -> ERR_NULL_ARG",
                  !r.ok && r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_NULL_ARG);
    }

    /* ---- zero-txn block (bad-blk-length) ---- */
    {
        struct block b; block_init(&b);
        b.num_vtx = 0;
        b.vtx = NULL;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_size_and_coinbase(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("zero txns -> bad-blk-length",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_BLK_LENGTH &&
                  strcmp(reason, "bad-blk-length") == 0 &&
                  dos == 100);
        /* Regression seal: legacy wrapper must produce the same. */
        DCB_CHECK("legacy parity: zero txns -> bad-blk-length dos=100",
                  cross_check_against_legacy(&b, "bad-blk-length", 100, false));
    }

    /* ---- bad-cb-missing (first tx not a coinbase) ---- */
    {
        struct transaction txs[1];
        noncoinbase_tx(&txs[0], 0x01);
        struct block b;
        build_block(&b, txs, 1);
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_size_and_coinbase(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("non-coinbase first tx -> bad-cb-missing",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_CB_MISSING &&
                  strcmp(reason, "bad-cb-missing") == 0 &&
                  dos == 100);
        DCB_CHECK("legacy parity: bad-cb-missing dos=100",
                  cross_check_against_legacy(&b, "bad-cb-missing", 100, false));
        /* Don't free txs[0].vtx via block_free — caller owns the array. */
        for (size_t i = 0; i < 1; i++) transaction_free(&txs[i]);
    }

    /* ---- bad-cb-multiple ---- */
    {
        struct transaction txs[2];
        coinbase_tx(&txs[0], 0x10);
        coinbase_tx(&txs[1], 0x11);
        struct block b;
        build_block(&b, txs, 2);
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_size_and_coinbase(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("second coinbase -> bad-cb-multiple",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_CB_MULTIPLE &&
                  strcmp(reason, "bad-cb-multiple") == 0 &&
                  dos == 100);
        DCB_CHECK("legacy parity: bad-cb-multiple dos=100",
                  cross_check_against_legacy(&b, "bad-cb-multiple", 100, false));
        for (size_t i = 0; i < 2; i++) transaction_free(&txs[i]);
    }

    /* ---- bad-txnmrklroot (header merkle != computed) ---- */
    {
        struct transaction txs[2];
        coinbase_tx(&txs[0], 0x20);
        noncoinbase_tx(&txs[1], 0x21);
        struct block b;
        build_block(&b, txs, 2);
        /* Corrupt the header's merkle root: flip one bit. */
        b.header.hashMerkleRoot.data[0] ^= 0x01;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("corrupted merkle root -> bad-txnmrklroot",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNMRKLROOT &&
                  strcmp(reason, "bad-txnmrklroot") == 0 &&
                  dos == 100);
        DCB_CHECK("legacy parity: bad-txnmrklroot dos=100",
                  cross_check_against_legacy(&b, "bad-txnmrklroot", 100, false));
        for (size_t i = 0; i < 2; i++) transaction_free(&txs[i]);
    }

    /* ---- bad-txns-duplicate (CVE-2012-2459) ---------
     *
     * Trigger by building a tx list with an odd number of entries where
     * the final pair of leaves at any level are duplicates — but with
     * a special construction: a 3-leaf block where the last leaf is
     * identical to the second-to-last is itself NOT mutated (the
     * merkle code only flags when the duplication is INDUCED by the
     * uneven-tree-padding step). Simplest reliable trigger: a 2-leaf
     * block where both leaves carry the same hash. Then the in-tree
     * padding step duplicates the (already-duplicate) leaf to extend
     * the level, which the mutation detector catches. */
    {
        struct transaction txs[2];
        coinbase_tx(&txs[0], 0x30);
        noncoinbase_tx(&txs[1], 0x31);
        /* Force identical hashes. */
        txs[1].hash = txs[0].hash;
        struct block b;
        build_block(&b, txs, 2);
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("identical leaves -> bad-txns-duplicate",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNS_DUP &&
                  strcmp(reason, "bad-txns-duplicate") == 0 &&
                  dos == 100);
        DCB_CHECK("legacy parity: bad-txns-duplicate dos=100",
                  cross_check_against_legacy(&b, "bad-txns-duplicate", 100, false));
        for (size_t i = 0; i < 2; i++) transaction_free(&txs[i]);
    }

    /* ---- normal valid block: structural checks all pass ---- */
    {
        struct transaction txs[2];
        coinbase_tx(&txs[0], 0x40);
        noncoinbase_tx(&txs[1], 0x41);
        struct block b;
        build_block(&b, txs, 2);

        /* merkle ok */
        struct zcl_result rm =
            domain_consensus_check_block_merkle_root(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("valid block: merkle -> OK",
                  rm.ok && reason[0] == '\0' && dos == 0);

        /* size+coinbase ok */
        struct zcl_result rs =
            domain_consensus_check_block_size_and_coinbase(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("valid block: size+coinbase -> OK",
                  rs.ok && reason[0] == '\0' && dos == 0);

        /* sigops ok (txs have empty script_pub_key/script_sig => 0 sigops) */
        struct zcl_result rso =
            domain_consensus_check_block_sigops(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("valid block: sigops -> OK",
                  rso.ok && reason[0] == '\0' && dos == 0);

        /* No legacy-parity cross-check on the "accept" path: the
         * legacy wrapper additionally runs per-tx check_transaction,
         * which rejects our synthetic minimal coinbase on script-shape
         * grounds (bad-cb-length, owned by domain/consensus/tx_structural
         * — a separate extraction). The point of THIS test is the
         * structural-block verdicts; that the three domain functions
         * accept the block individually proves the structural layer
         * is correct. */

        for (size_t i = 0; i < 2; i++) transaction_free(&txs[i]);
    }

    /* ---- out_reject_reason / out_dos may be NULL ---- */
    {
        struct block b; block_init(&b);
        b.num_vtx = 0;
        b.vtx = NULL;
        struct zcl_result r =
            domain_consensus_check_block_size_and_coinbase(
                &b, NULL, 0, NULL);
        DCB_CHECK("size+coinbase: null out buffers handled",
                  !r.ok &&
                  r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_BLK_LENGTH);
    }

    /* ---- L1 LOCK-IN: no 2 MB serialized block-size cap ----------------
     *
     * Parity-audit round 2 (docs/work/parity-audit-round2-findings.md, L1):
     * domain_consensus_check_block_size_and_coinbase() bounds only the
     * tx-COUNT (num_vtx <= 2,000,000), never the SERIALIZED byte size.
     * zclassicd's CheckBlock rejects a block whose serialized size exceeds
     * GENEROUS_BLOCK_SIZE_LIMIT (2,000,000) with "bad-blk-length"
     * (main.cpp:4317). zcl23 has no such byte clause.
     *
     * THIS PIN ASSERTS THE CURRENT (LOOSENED) BEHAVIOR: a block whose
     * serialized size is well over 2,000,000 bytes — but whose num_vtx is a
     * tiny 2, far under the count cap — currently PASSES the size+coinbase
     * check (no bad-blk-length). When a future byte-size clause lands (after
     * the replay gate the doc requires), this assertion flips deliberately
     * and the new reject must be wired in. */
    {
        /* Build one non-coinbase tx with enough full-size (MAX_SCRIPT_SIZE)
         * output scripts to push the serialized block over 2,000,000 bytes.
         * Each output contributes ~MAX_SCRIPT_SIZE (10,000) script bytes plus
         * 8 value bytes plus the compact-size length prefix. 220 outputs ⇒
         * ~2.2 MB, comfortably over the 2 MB band. */
        const size_t n_out = 220;  /* 220 * ~10009 ≈ 2.20 MB > 2,000,000 */

        struct transaction txs[2];
        coinbase_tx(&txs[0], 0x80);

        transaction_init(&txs[1]);
        bool alloc_ok = transaction_alloc(&txs[1], 1, n_out);
        DCB_CHECK("L1: oversize tx alloc (1 vin / 220 vout)", alloc_ok);
        memset(txs[1].vin[0].prevout.hash.data, 0xee, 32); /* non-null => not coinbase */
        txs[1].vin[0].prevout.n = 0;
        txs[1].vin[0].sequence = UINT32_MAX;
        txs[1].vin[0].script_sig.size = 0;
        for (size_t i = 0; i < n_out; i++) {
            memset(txs[1].vout[i].script_pub_key.data, OP_NOP, MAX_SCRIPT_SIZE);
            txs[1].vout[i].script_pub_key.size = MAX_SCRIPT_SIZE;
            txs[1].vout[i].value = 1;
        }
        memset(txs[1].hash.data, 0, 32);
        txs[1].hash.data[0] = 0x81;
        txs[1].hash.data[31] = 0x1b;

        struct block b;
        build_block(&b, txs, 2);

        /* Prove the premise: the serialized block really is over 2 MB. */
        size_t cb_sz  = transaction_serialize_size(&txs[0]);
        size_t big_sz = transaction_serialize_size(&txs[1]);
        size_t total  = cb_sz + big_sz;  /* header + count prefix are tiny extra */
        DCB_CHECK("L1: synthetic block serializes > 2,000,000 bytes",
                  total > 2000000 && b.num_vtx == 2);

        /* num_vtx (2) is far under DOMAIN_GENEROUS_BLOCK_TXN_LIMIT (2,000,000),
         * so the ONLY cap in the predicate passes — the oversize block is
         * accepted today. */
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r_sz =
            domain_consensus_check_block_size_and_coinbase(
                &b, reason, sizeof(reason), &dos);
        DCB_CHECK("L1 PIN: >2MB block with num_vtx=2 currently ACCEPTED "
                  "(no serialized-size cap)",
                  r_sz.ok && reason[0] == '\0' && dos == 0);

        for (size_t i = 0; i < 2; i++) transaction_free(&txs[i]);
    }

    /* ---- CHECKDATASIG counts toward the block sigop limit (zclassicd parity) ----
     *
     * zclassicd counts OP_CHECKDATASIG/OP_CHECKDATASIGVERIFY toward
     * MAX_BLOCK_SIGOPS (its CheckBlock/ConnectBlock set the
     * SCRIPT_VERIFY_CHECKDATASIG_SIGOPS bit). c23 previously passed
     * SCRIPT_VERIFY_NONE so these opcodes counted 0 — an undercount that let a
     * block zclassicd rejects with bad-blk-sigops slip through. The limit is
     * strict '>' so exactly 20000 ops is accepted, 20001 rejected. Before the
     * fix, the 20001 case would (wrongly) return OK because the opcodes
     * counted 0 — so this case pins the corrected counting. */
    {
        char reason[64]; int dos;

        struct transaction at[1];
        checkdatasig_tx(&at[0], 0x70, DOMAIN_MAX_BLOCK_SIGOPS_TEST);
        struct block ba; build_block(&ba, at, 1);
        struct zcl_result r_at = domain_consensus_check_block_sigops(
            &ba, reason, sizeof(reason), &dos);
        DCB_CHECK("CHECKDATASIG == 20000 sigops: OK (at the limit)",
                  r_at.ok && dos == 0);
        transaction_free(&at[0]);

        struct transaction over[1];
        checkdatasig_tx(&over[0], 0x71, DOMAIN_MAX_BLOCK_SIGOPS_TEST + 1);
        struct block bo; build_block(&bo, over, 1);
        struct zcl_result r_over = domain_consensus_check_block_sigops(
            &bo, reason, sizeof(reason), &dos);
        DCB_CHECK("CHECKDATASIG == 20001 sigops: bad-blk-sigops (counted, was 0 pre-fix)",
                  !r_over.ok && strcmp(reason, "bad-blk-sigops") == 0 && dos == 100);
        transaction_free(&over[0]);
    }

    return failures;
}
