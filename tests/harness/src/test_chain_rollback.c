/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain rollback stress test — wave 8 new item.
 *
 * Strategy
 * --------
 * Build a synthetic chain of N coinbase-only blocks, apply each to
 * a fresh coins_view_cache via `update_coins`, and snapshot the
 * incremental UTXO commitment at every height. Then walk backward
 * via `disconnect_block` (coinbase-only undo is trivially empty)
 * and verify that the UTXO set after each disconnection matches the
 * snapshot recorded during the forward walk.
 *
 * Because `disconnect_block` manipulates the coins_map but does not
 * update the XOR commitment (that's done by update_coins at connect
 * time, not by the disconnect path), we test structural correctness
 * — after disconnecting block at height H, the coinbase tx at H is
 * absent from the cache and the coinbase txs at heights [0..H-1]
 * are still present. This proves the undo path is consistent.
 *
 * Separately, we test commitment consistency via `update_coins` +
 * manual `utxo_commitment_remove` (same as XOR-out), which covers
 * the XOR accumulator's roundtrip property.
 *
 * We also include a test with a non-coinbase spend to exercise the
 * full undo path (restore spent input via tx_undo).
 */

#include "test/test_core.h"
#include "validation/connect_block.h"
#include "validation/update_coins.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "coins/undo.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "script/script.h"
#include "bloom/merkle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

#define CR_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define NUM_BLOCKS 20

/* Build a coinbase transaction for `height`. Unique hash per height. */
static struct transaction make_coinbase(int height)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
    /* coinbase scriptSig: height-encoding (BIP34 style) */
    uint8_t sig[5];
    sig[0] = 4; /* push 4 bytes */
    sig[1] = (uint8_t)(height & 0xFF);
    sig[2] = (uint8_t)((height >> 8) & 0xFF);
    sig[3] = (uint8_t)((height >> 16) & 0xFF);
    sig[4] = (uint8_t)((height >> 24) & 0xFF);
    script_set(&tx.vin[0].script_sig, sig, 5);
    /* coinbase prevout is null (all-zeros hash, n=0xFFFFFFFF) */
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFF;
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
    tx.vout[0].value = 1000000000LL; /* 10 ZCL */
    uint8_t pk[] = {0x76, 0xa9, 0x14}; /* minimal P2PKH prefix */
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    transaction_compute_hash(&tx);
    return tx;
}

static void free_coinbase(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* Build a minimal block containing one coinbase tx. */
static void make_block(struct block *blk, int height,
                        const struct uint256 *prev_hash)
{
    memset(blk, 0, sizeof(*blk));
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
    blk->vtx[0] = make_coinbase(height);
    blk->header.nVersion = 4;
    if (prev_hash)
        blk->header.hashPrevBlock = *prev_hash;
    blk->header.nTime = 1000000 + (uint32_t)height * 150;
    blk->header.hashMerkleRoot =
        compute_merkle_root(&blk->vtx[0].hash, 1);
}

static void free_block(struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        free(blk->vtx[i].vin);
        free(blk->vtx[i].vout);
    }
    free(blk->vtx);
}

int test_chain_rollback(void)
{
    printf("\n=== chain rollback stress test ===\n");
    int failures = 0;

    /* ── 1. Forward: build N coinbase blocks, track commitment ─ */
    struct utxo_commitment snapshots[NUM_BLOCKS + 1];
    struct block blocks[NUM_BLOCKS];
    struct uint256 block_hashes[NUM_BLOCKS];
    struct block_index indices[NUM_BLOCKS];
    struct coins_view_cache cache;
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&cache, &null_view);

    /* Snapshot at height 0 (empty set) */
    snapshots[0] = cache.commitment;

    for (int h = 0; h < NUM_BLOCKS; h++) {
        struct uint256 prev;
        if (h == 0)
            uint256_set_null(&prev);
        else
            prev = block_hashes[h - 1];

        make_block(&blocks[h], h, &prev);
        block_header_get_hash(&blocks[h].header, &block_hashes[h]);

        /* Set up block_index */
        memset(&indices[h], 0, sizeof(indices[h]));
        indices[h].nHeight = h;
        indices[h].phashBlock = &block_hashes[h];
        if (h > 0) indices[h].pprev = &indices[h - 1];

        /* Apply coinbase to cache */
        update_coins(&blocks[h].vtx[0], &cache, h);

        /* Snapshot commitment at height h+1 */
        snapshots[h + 1] = cache.commitment;
    }

    CR_CHECK("cr: forward walk built 20 blocks",
             cache.commitment.count == NUM_BLOCKS);

    /* ── 2. Verify each height has a distinct commitment ──────── */
    {
        bool all_distinct = true;
        for (int h = 0; h < NUM_BLOCKS; h++) {
            if (utxo_commitment_equal(&snapshots[h], &snapshots[h + 1])) {
                all_distinct = false;
                break;
            }
        }
        CR_CHECK("cr: each height has distinct commitment", all_distinct);
    }

    /* ── 3. Backward: disconnect via disconnect_block ──────────── */
    {
        bool all_ok = true;
        for (int h = NUM_BLOCKS - 1; h >= 0; h--) {
            /* Coinbase-only: empty block_undo */
            struct block_undo bu;
            block_undo_init(&bu);

            struct validation_state vs;
            validation_state_init(&vs);

            bool ok = disconnect_block(&blocks[h], &vs, &indices[h],
                                        &cache, &bu);
            block_undo_free(&bu);
            if (!ok) { all_ok = false; break; }

            /* Coinbase tx should be gone from the cache */
            if (coins_view_cache_have_coins(&cache, &blocks[h].vtx[0].hash)) {
                all_ok = false;
                break;
            }
        }
        CR_CHECK("cr: disconnect_block succeeds for all 20 blocks", all_ok);
    }

    /* After disconnecting all blocks, no tx may be reachable via
     * have_coins.  The cache itself may retain DIRTY+pruned
     * tombstones pending a parent flush — that is the 
     * semantics of disconnect_block (connect_block.c:639) replacing
     * a bare erase with a pruned-entry write so the DELETE signal
     * propagates to the DIRTY-driven backing store.  The invariant
     * we care about is reachability, not raw cache_coins.size. */
    {
        bool all_unreachable = true;
        for (int h = 0; h < NUM_BLOCKS; h++) {
            if (coins_view_cache_have_coins(&cache, &blocks[h].vtx[0].hash)) {
                all_unreachable = false;
                break;
            }
        }
        CR_CHECK("cr: no tx reachable via have_coins after full rollback",
                 all_unreachable);
    }

    /* ── 4. Re-connect and verify commitment matches snapshots ─ */
    {
        struct coins_view_cache cache2;
        struct coins_view null_view2;
        memset(&null_view2, 0, sizeof(null_view2));
        coins_view_cache_init(&cache2, &null_view2);
        bool match = true;
        if (!utxo_commitment_equal(&cache2.commitment, &snapshots[0])) {
            match = false;
        }
        for (int h = 0; h < NUM_BLOCKS && match; h++) {
            update_coins(&blocks[h].vtx[0], &cache2, h);
            if (!utxo_commitment_equal(&cache2.commitment, &snapshots[h + 1]))
                match = false;
        }
        CR_CHECK("cr: re-connect matches original commitment snapshots", match);
        coins_view_cache_free(&cache2);
    }

    /* ── 5. XOR roundtrip: add then remove = identity ──────────── */
    {
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        for (int h = 0; h < NUM_BLOCKS; h++) {
            utxo_commitment_add(&uc,
                blocks[h].vtx[0].hash.data, 0,
                blocks[h].vtx[0].vout[0].value, h);
        }
        CR_CHECK("cr: XOR accumulator has count=20 after adds", uc.count == NUM_BLOCKS);

        for (int h = NUM_BLOCKS - 1; h >= 0; h--) {
            utxo_commitment_remove(&uc,
                blocks[h].vtx[0].hash.data, 0,
                blocks[h].vtx[0].vout[0].value, h);
        }
        struct utxo_commitment empty;
        utxo_commitment_init(&empty);
        CR_CHECK("cr: XOR roundtrip returns to empty set",
                 utxo_commitment_equal(&uc, &empty));
    }

    /* ── 6. Non-coinbase spend + undo roundtrip ────────────────── */
    {
        struct coins_view_cache cache3;
        struct coins_view null_view3;
        memset(&null_view3, 0, sizeof(null_view3));
        coins_view_cache_init(&cache3, &null_view3);

        /* Connect coinbase at h=0 */
        update_coins(&blocks[0].vtx[0], &cache3, 0);

        /* Build a tx that spends the coinbase output */
        struct transaction spend_tx;
        memset(&spend_tx, 0, sizeof(spend_tx));
        spend_tx.version = 1;
        spend_tx.num_vin = 1;
        spend_tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        spend_tx.vin[0].prevout.hash = blocks[0].vtx[0].hash;
        spend_tx.vin[0].prevout.n = 0;
        uint8_t sig[] = {0x48};
        script_set(&spend_tx.vin[0].script_sig, sig, 1);
        spend_tx.vin[0].sequence = 0xFFFFFFFF;
        spend_tx.num_vout = 1;
        spend_tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        spend_tx.vout[0].value = 999999000LL;
        uint8_t pk[] = {0x76, 0xa9, 0x14};
        script_set(&spend_tx.vout[0].script_pub_key, pk, 3);
        transaction_compute_hash(&spend_tx);

        /* Snapshot before spend */
        struct utxo_commitment before_spend = cache3.commitment;

        /* Apply spend with undo capture */
        struct tx_undo txundo;
        memset(&txundo, 0, sizeof(txundo));
        bool ok = update_coins_with_undo(&spend_tx, &cache3, &txundo, 1);
        CR_CHECK("cr: spend tx applied successfully", ok);

        /* Commitment changed */
        CR_CHECK("cr: commitment changed after spend",
                 !utxo_commitment_equal(&cache3.commitment, &before_spend));

        /* Build a block with the spend tx and disconnect it */
        struct block spend_blk;
        memset(&spend_blk, 0, sizeof(spend_blk));
        spend_blk.num_vtx = 2; /* coinbase + spend */

        struct transaction coinbase1 = make_coinbase(1);
        spend_blk.vtx = zcl_calloc(2, sizeof(struct transaction), "test_vtx");
        spend_blk.vtx[0] = coinbase1;
        spend_blk.vtx[1] = spend_tx;

        struct block_undo bu;
        block_undo_init(&bu);
        block_undo_alloc(&bu, 1); /* 1 non-coinbase tx */
        bu.vtxundo[0] = txundo;

        struct block_index bi;
        memset(&bi, 0, sizeof(bi));
        bi.nHeight = 1;
        bi.pprev = &indices[0];

        struct validation_state vs;
        validation_state_init(&vs);
        bool disc_ok = disconnect_block(&spend_blk, &vs, &bi,
                                         &cache3, &bu);
        CR_CHECK("cr: disconnect_block with spend tx succeeds", disc_ok);

        /* The coinbase from h=0 should still be in the cache
         * AND the spent output should be restored. */
        CR_CHECK("cr: original coinbase UTXO restored after disconnect",
                 coins_view_cache_have_coins(&cache3,
                                              &blocks[0].vtx[0].hash));

        /* Spend tx outputs should be gone */
        CR_CHECK("cr: spend tx outputs removed after disconnect",
                 !coins_view_cache_have_coins(&cache3, &spend_tx.hash));

        /* Cleanup */
        free(spend_blk.vtx);
        free_coinbase(&coinbase1);
        free(spend_tx.vin);
        free(spend_tx.vout);
        block_undo_free(&bu);
        coins_view_cache_free(&cache3);
    }

    /* ── Cleanup ───────────────────────────────────────────────── */
    coins_view_cache_free(&cache);
    for (int h = 0; h < NUM_BLOCKS; h++)
        free_block(&blocks[h]);

    printf("chain rollback stress test: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
