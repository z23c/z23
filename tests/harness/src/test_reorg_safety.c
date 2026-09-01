/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reorg safety test — wave 10 #1, the capstone test.
 *
 * Strategy
 * --------
 * Build two competing synthetic chains that fork from a common ancestor:
 *
 *   Genesis → A1 → A2 → ... → A50       (chain A, original tip)
 *                ↘ B1 → B2 → ... → B50  (chain B, more work)
 *
 * 1. Connect chain A (50 coinbase blocks) via update_coins.
 *
 * 2. Simulate reorg: disconnect A50..A1 via disconnect_block,
 *    then connect B1..B50 via update_coins.
 *
 * 3. Assert:
 *    - No UTXO loss: every B-chain coinbase is spendable
 *    - No orphan UTXOs: every disconnected A-chain coinbase is gone
 *    - CSR (chain_state_repository) accepts the reorged tip
 *    - recovery_policy allows the 49-block rollback
 *    - db_txn commit/rollback semantics hold during reorg
 *    - Reverse reorg restores chain A coins
 *    - Rapid back-and-forth reorgs preserve structural integrity
 *    - Non-coinbase spends undo correctly
 *
 * Note: disconnect_block does NOT update the XOR commitment counter
 * (see test_chain_rollback.c comments). We use cache_coins.size and
 * have_coins for structural correctness checks after disconnect.
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
#include "core/arith_uint256.h"
#include "script/script.h"
#include "bloom/merkle.h"
#include "services/chain_state_service.h"
#include "services/recovery_policy.h"
#include "models/db_txn.h"
#include "event/event.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include "util/safe_alloc.h"

#define CHAIN_LEN    50   /* blocks per chain (after genesis) */
#define FORK_HEIGHT  1    /* height where chain B diverges */

/* Pass/fail wrapper consistent with other test files. */
#define RG_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Helpers ─────────────────────────────────────────────── */

static struct transaction make_coinbase_seeded(int height, uint8_t seed)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "coinbase_vin");

    uint8_t sig[6];
    sig[0] = 4;
    sig[1] = (uint8_t)(height & 0xFF);
    sig[2] = (uint8_t)((height >> 8) & 0xFF);
    sig[3] = (uint8_t)((height >> 16) & 0xFF);
    sig[4] = (uint8_t)((height >> 24) & 0xFF);
    sig[5] = seed;
    script_set(&tx.vin[0].script_sig, sig, 6);

    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFF;
    tx.vin[0].sequence = 0xFFFFFFFF;

    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "coinbase_vout");
    tx.vout[0].value = 1000000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);

    transaction_compute_hash(&tx);
    return tx;
}

static void free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

static void make_block_seeded(struct block *blk, int height,
                               const struct uint256 *prev_hash,
                               uint8_t seed)
{
    memset(blk, 0, sizeof(*blk));
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "block_vtx");
    blk->vtx[0] = make_coinbase_seeded(height, seed);
    blk->header.nVersion = 4;
    if (prev_hash)
        blk->header.hashPrevBlock = *prev_hash;
    blk->header.nTime = 1000000 + (uint32_t)height * 150 + seed;
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

/* Disconnect chain blocks from `from` down to (not including) `to`. */
static bool disconnect_range(struct block *blocks, struct block_index *idx,
                              struct coins_view_cache *cache,
                              int from, int to)
{
    for (int h = from; h > to; h--) {
        struct block_undo bu;
        block_undo_init(&bu);
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = disconnect_block(&blocks[h], &vs, &idx[h], cache, &bu);
        block_undo_free(&bu);
        if (!ok) return false;
    }
    return true;
}

/* Connect chain coinbases from height `from` to `to` inclusive. */
static void connect_range(struct block *blocks,
                           struct coins_view_cache *cache,
                           int from, int to)
{
    for (int h = from; h <= to; h++)
        update_coins(&blocks[h].vtx[0], cache, h);
}

/* Check that all coinbases in [from..to] are present in cache. */
static bool all_coins_present(struct block *blocks,
                               struct coins_view_cache *cache,
                               int from, int to)
{
    for (int h = from; h <= to; h++) {
        if (!coins_view_cache_have_coins(cache, &blocks[h].vtx[0].hash))
            return false;
    }
    return true;
}

/* Check that no coinbases in [from..to] are present in cache. */
static bool no_coins_present(struct block *blocks,
                              struct coins_view_cache *cache,
                              int from, int to)
{
    for (int h = from; h <= to; h++) {
        if (coins_view_cache_have_coins(cache, &blocks[h].vtx[0].hash))
            return false;
    }
    return true;
}

/* ── Test implementation ─────────────────────────────────── */

int test_reorg_safety(void)
{
    printf("\n=== reorg safety test (50-block fork) ===\n");
    int failures = 0;

    /* ── Storage for both chains ─────────────────────────── */

    struct block   a_blocks[CHAIN_LEN + 1];
    struct uint256 a_hashes[CHAIN_LEN + 1];
    struct block_index a_idx[CHAIN_LEN + 1];

    struct block   b_blocks[CHAIN_LEN + 1];
    struct uint256 b_hashes[CHAIN_LEN + 1];
    struct block_index b_idx[CHAIN_LEN + 1];

    /* ── Build genesis (shared) ──────────────────────────── */

    make_block_seeded(&a_blocks[0], 0, NULL, 0x00);
    block_header_get_hash(&a_blocks[0].header, &a_hashes[0]);
    block_index_init(&a_idx[0]);
    a_idx[0].nHeight = 0;
    a_idx[0].phashBlock = &a_hashes[0];
    a_idx[0].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    a_idx[0].nTx = 1;
    a_idx[0].nChainTx = 1;
    arith_uint256_set_u64(&a_idx[0].nChainWork, 1);

    memset(&b_blocks[0], 0, sizeof(b_blocks[0]));
    b_hashes[0] = a_hashes[0];
    b_idx[0] = a_idx[0];
    b_idx[0].phashBlock = &b_hashes[0];

    /* ── UTXO cache ──────────────────────────────────────── */

    struct coins_view_cache cache;
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&cache, &null_view);

    update_coins(&a_blocks[0].vtx[0], &cache, 0);

    /* ── 1. Build chain A (50 blocks) ────────────────────── */

    for (int h = 1; h <= CHAIN_LEN; h++) {
        make_block_seeded(&a_blocks[h], h, &a_hashes[h - 1], 0x00);
        block_header_get_hash(&a_blocks[h].header, &a_hashes[h]);

        block_index_init(&a_idx[h]);
        a_idx[h].nHeight = h;
        a_idx[h].phashBlock = &a_hashes[h];
        a_idx[h].pprev = &a_idx[h - 1];
        a_idx[h].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        a_idx[h].nTx = 1;
        a_idx[h].nChainTx = a_idx[h - 1].nChainTx + 1;
        arith_uint256_set_u64(&a_idx[h].nChainWork, (uint64_t)(h + 1));

        update_coins(&a_blocks[h].vtx[0], &cache, h);
    }

    RG_CHECK("reorg: chain A built with 51 UTXOs",
             (int)cache.commitment.count == CHAIN_LEN + 1);

    RG_CHECK("reorg: all chain A coinbases present",
             all_coins_present(a_blocks, &cache, 0, CHAIN_LEN));

    /* ── 2. Build chain B (diverges at height 1) ─────────── */

    for (int h = 1; h <= CHAIN_LEN; h++) {
        const struct uint256 *prev = (h == 1) ? &a_hashes[0] : &b_hashes[h - 1];
        make_block_seeded(&b_blocks[h], h, prev, 0x80);
        block_header_get_hash(&b_blocks[h].header, &b_hashes[h]);

        block_index_init(&b_idx[h]);
        b_idx[h].nHeight = h;
        b_idx[h].phashBlock = &b_hashes[h];
        b_idx[h].pprev = (h == 1) ? &a_idx[0] : &b_idx[h - 1];
        b_idx[h].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        b_idx[h].nTx = 1;
        b_idx[h].nChainTx = b_idx[h].pprev->nChainTx + 1;
        arith_uint256_set_u64(&b_idx[h].nChainWork, (uint64_t)(h + 100));
    }

    RG_CHECK("reorg: chain B has more work than chain A",
             arith_uint256_compare(&b_idx[CHAIN_LEN].nChainWork,
                                    &a_idx[CHAIN_LEN].nChainWork) > 0);

    /* ── 3. recovery_policy allows 49-block rollback ─────── */

    {
        struct recovery_policy policy;
        policy_set_defaults(&policy);
        enum policy_decision d = policy_check_block_rollback(
            &policy, CHAIN_LEN, FORK_HEIGHT, "test_reorg_safety");
        RG_CHECK("reorg: recovery_policy allows 49-block rollback",
                 d == POLICY_ALLOW);
    }

    /* ── 4. Disconnect chain A (h=50..1) ─────────────────── */

    RG_CHECK("reorg: disconnect 50 chain-A blocks",
             disconnect_range(a_blocks, a_idx, &cache, CHAIN_LEN, 0));

    RG_CHECK("reorg: genesis coinbase survives disconnect",
             coins_view_cache_have_coins(&cache, &a_blocks[0].vtx[0].hash));

    RG_CHECK("reorg: no chain A orphan UTXOs after disconnect",
             no_coins_present(a_blocks, &cache, 1, CHAIN_LEN));

    /* After disconnect, cache should have only genesis (size ~1, may
     * include erased tombstones depending on hash map implementation,
     * but have_coins must return false for erased entries). */

    /* ── 5. Connect chain B (h=1..50) ────────────────────── */

    connect_range(b_blocks, &cache, 1, CHAIN_LEN);

    RG_CHECK("reorg: all chain B coinbases present (no UTXO loss)",
             all_coins_present(b_blocks, &cache, 1, CHAIN_LEN));

    RG_CHECK("reorg: no chain A orphan UTXOs remain",
             no_coins_present(a_blocks, &cache, 1, CHAIN_LEN));

    /* ── 6. CSR accepts the reorged tip ──────────────────── */

    {
        struct block_map bm;
        struct active_chain chain;
        struct block_index *header_tip = NULL;

        block_map_init(&bm);
        active_chain_init(&chain);

        block_map_insert(&bm, &a_hashes[0], &a_idx[0]);
        for (int h = 1; h <= CHAIN_LEN; h++)
            block_map_insert(&bm, &b_hashes[h], &b_idx[h]);

        active_chain_move_window_tip(&chain, &b_idx[CHAIN_LEN]);
        cache.hash_block = *b_idx[CHAIN_LEN].phashBlock;

        struct chain_state_repository csr;
        csr_init(&csr, &bm, &chain, &header_tip, &cache, NULL, NULL);

        struct chain_state_commit commit;
        memset(&commit, 0, sizeof(commit));
        commit.new_tip = &b_idx[CHAIN_LEN];
        commit.new_coins_best = *b_idx[CHAIN_LEN].phashBlock;
        commit.expected_utxo_count = -1;
        commit.update_header_tip = true;
        commit.wallet_scan_height = -1;
        commit.reason = "test_reorg_safety.chain_b_tip";

        enum csr_result r = csr_commit_tip(&csr, &commit);
        RG_CHECK("reorg: CSR accepts chain B tip commit", r == CSR_OK);

        csr_free(&csr);
        active_chain_free(&chain);
        block_map_free(&bm);
    }

    /* ── 7. db_txn scoped commit/rollback during reorg ───── */

    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        int rc = sqlite3_open(":memory:", &ndb.db);
        bool db_ok = (rc == SQLITE_OK);
        if (db_ok) {
            ndb.open = true;

            sqlite3_exec(ndb.db,
                "CREATE TABLE reorg_test(id INTEGER PRIMARY KEY, val TEXT)",
                NULL, NULL, NULL);

            /* Transaction that commits */
            {
                DB_TXN_SCOPE(txn, &ndb, "reorg_commit");
                db_ok = db_ok && (txn != NULL);
                if (txn) {
                    sqlite3_exec(ndb.db,
                        "INSERT INTO reorg_test VALUES(1, 'kept')",
                        NULL, NULL, NULL);
                    db_ok = db_ok && db_txn_commit(txn);
                }
            }

            /* Verify committed data persisted */
            if (db_ok) {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(ndb.db,
                    "SELECT val FROM reorg_test WHERE id=1", -1, &st, NULL);
                db_ok = db_ok && (sqlite3_step(st) == SQLITE_ROW);
                if (db_ok)
                    db_ok = db_ok &&
                        (strcmp((const char *)sqlite3_column_text(st, 0),
                                "kept") == 0);
                sqlite3_finalize(st);
            }

            /* Transaction that auto-rolls-back */
            {
                DB_TXN_SCOPE(txn2, &ndb, "reorg_rollback");
                db_ok = db_ok && (txn2 != NULL);
                if (txn2) {
                    sqlite3_exec(ndb.db,
                        "INSERT INTO reorg_test VALUES(2, 'vanish')",
                        NULL, NULL, NULL);
                }
            }

            /* Verify rolled-back data is gone */
            if (db_ok) {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(ndb.db,
                    "SELECT COUNT(*) FROM reorg_test WHERE id=2",
                    -1, &st, NULL);
                db_ok = db_ok && (sqlite3_step(st) == SQLITE_ROW);
                if (db_ok)
                    db_ok = db_ok && (sqlite3_column_int(st, 0) == 0);
                sqlite3_finalize(st);
            }

            sqlite3_close(ndb.db);
        }
        RG_CHECK("reorg: db_txn commit persists, auto-rollback reverts", db_ok);
    }

    /* ── 8. Reverse reorg: undo B, re-apply A ────────────── */

    RG_CHECK("reorg: disconnect 50 chain-B blocks",
             disconnect_range(b_blocks, b_idx, &cache, CHAIN_LEN, 0));

    /* After disconnecting B, only genesis remains structurally */
    RG_CHECK("reorg: genesis survives B disconnect",
             coins_view_cache_have_coins(&cache, &a_blocks[0].vtx[0].hash));

    RG_CHECK("reorg: no B coins after B disconnect",
             no_coins_present(b_blocks, &cache, 1, CHAIN_LEN));

    /* Re-apply chain A */
    connect_range(a_blocks, &cache, 1, CHAIN_LEN);

    RG_CHECK("reorg: all chain A coins restored after reverse reorg",
             all_coins_present(a_blocks, &cache, 0, CHAIN_LEN));

    RG_CHECK("reorg: no B orphans after reverse reorg",
             no_coins_present(b_blocks, &cache, 1, CHAIN_LEN));

    /* ── 9. Stress: 5 rapid back-and-forth reorg cycles ─── */

    {
        bool ok = true;
        for (int cycle = 0; cycle < 5 && ok; cycle++) {
            /* A → B */
            ok = ok && disconnect_range(a_blocks, a_idx, &cache, CHAIN_LEN, 0);
            if (ok) connect_range(b_blocks, &cache, 1, CHAIN_LEN);
            ok = ok && all_coins_present(b_blocks, &cache, 1, CHAIN_LEN);
            ok = ok && no_coins_present(a_blocks, &cache, 1, CHAIN_LEN);

            /* B → A */
            ok = ok && disconnect_range(b_blocks, b_idx, &cache, CHAIN_LEN, 0);
            if (ok) connect_range(a_blocks, &cache, 1, CHAIN_LEN);
            ok = ok && all_coins_present(a_blocks, &cache, 0, CHAIN_LEN);
            ok = ok && no_coins_present(b_blocks, &cache, 1, CHAIN_LEN);
        }
        RG_CHECK("reorg: 5 rapid reorg cycles preserve UTXO integrity", ok);
    }

    /* ── 10. recovery_policy rejects too-deep rollback ───── */

    {
        struct recovery_policy policy;
        policy_set_defaults(&policy);
        policy.max_block_rollback = 10;
        enum policy_decision d = policy_check_block_rollback(
            &policy, CHAIN_LEN, FORK_HEIGHT, "test_reorg_safety.deep");
        RG_CHECK("reorg: recovery_policy rejects rollback exceeding cap",
                 d == POLICY_REFUSE_TOO_LARGE);
    }

    /* ── 11. CSR rejects commit with mismatched coins hash ─ */

    {
        struct block_map bm;
        struct active_chain chain;
        struct block_index *header_tip = NULL;

        block_map_init(&bm);
        active_chain_init(&chain);

        block_map_insert(&bm, &a_hashes[0], &a_idx[0]);
        block_map_insert(&bm, &a_hashes[CHAIN_LEN], &a_idx[CHAIN_LEN]);
        active_chain_move_window_tip(&chain, &a_idx[CHAIN_LEN]);

        struct chain_state_repository csr;
        csr_init(&csr, &bm, &chain, &header_tip, &cache, NULL, NULL);

        struct uint256 wrong_hash;
        memset(&wrong_hash, 0xDE, sizeof(wrong_hash));
        cache.hash_block = wrong_hash;

        struct chain_state_commit bad;
        memset(&bad, 0, sizeof(bad));
        bad.new_tip = &a_idx[CHAIN_LEN];
        bad.new_coins_best = *a_idx[CHAIN_LEN].phashBlock;
        bad.expected_utxo_count = -1;
        bad.wallet_scan_height = -1;
        bad.reason = "test_reorg_safety.bad_hash";

        enum csr_result r = csr_commit_tip(&csr, &bad);
        RG_CHECK("reorg: CSR rejects mismatched coins hash", r != CSR_OK);

        csr_free(&csr);
        active_chain_free(&chain);
        block_map_free(&bm);
    }

    /* ── 12. Non-coinbase spend undo restores spent input ── */

    {
        struct coins_view_cache sc;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&sc, &nv);

        update_coins(&a_blocks[0].vtx[0], &sc, 0);

        /* Spend genesis coinbase */
        struct transaction spend;
        memset(&spend, 0, sizeof(spend));
        spend.version = 1;
        spend.num_vin = 1;
        spend.vin = zcl_calloc(1, sizeof(struct tx_in), "spend_vin");
        spend.vin[0].prevout.hash = a_blocks[0].vtx[0].hash;
        spend.vin[0].prevout.n = 0;
        uint8_t sig[] = {0x48};
        script_set(&spend.vin[0].script_sig, sig, 1);
        spend.vin[0].sequence = 0xFFFFFFFF;
        spend.num_vout = 1;
        spend.vout = zcl_calloc(1, sizeof(struct tx_out), "spend_vout");
        spend.vout[0].value = 999999000LL;
        uint8_t pk[] = {0x76, 0xa9, 0x14};
        script_set(&spend.vout[0].script_pub_key, pk, 3);
        transaction_compute_hash(&spend);

        struct tx_undo txundo;
        memset(&txundo, 0, sizeof(txundo));
        bool spend_ok = update_coins_with_undo(&spend, &sc, &txundo, 1);

        /* Block: coinbase + spend */
        struct transaction cb1 = make_coinbase_seeded(1, 0xCC);
        struct block sblk;
        memset(&sblk, 0, sizeof(sblk));
        sblk.num_vtx = 2;
        sblk.vtx = zcl_calloc(2, sizeof(struct transaction), "spend_block_vtx");
        sblk.vtx[0] = cb1;
        sblk.vtx[1] = spend;

        struct block_undo bu;
        block_undo_init(&bu);
        block_undo_alloc(&bu, 1);
        bu.vtxundo[0] = txundo;

        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 1;
        bi.pprev = &a_idx[0];

        struct validation_state vs;
        validation_state_init(&vs);
        spend_ok = spend_ok && disconnect_block(&sblk, &vs, &bi, &sc, &bu);

        /* Genesis coinbase restored */
        spend_ok = spend_ok &&
            coins_view_cache_have_coins(&sc, &a_blocks[0].vtx[0].hash);

        RG_CHECK("reorg: non-coinbase spend undo restores input", spend_ok);

        block_undo_free(&bu);
        free(sblk.vtx);
        free_tx(&cb1);
        free_tx(&spend);
        coins_view_cache_free(&sc);
    }

    /* ── 13. Commitment tracks correctly during forward walk ─ */

    {
        /* Fresh cache to verify commitment accuracy in connect path */
        struct coins_view_cache fc;
        struct coins_view fnv;
        memset(&fnv, 0, sizeof(fnv));
        coins_view_cache_init(&fc, &fnv);

        bool distinct = true;
        struct utxo_commitment prev_commit = fc.commitment;

        for (int h = 0; h <= CHAIN_LEN && distinct; h++) {
            update_coins(&a_blocks[h].vtx[0], &fc, h);
            if (utxo_commitment_equal(&fc.commitment, &prev_commit))
                distinct = false;
            prev_commit = fc.commitment;
        }
        RG_CHECK("reorg: each height has distinct commitment", distinct);
        RG_CHECK("reorg: forward commitment count matches",
                 (int)fc.commitment.count == CHAIN_LEN + 1);

        coins_view_cache_free(&fc);
    }

    /* ── 14. Partial reorg (disconnect 25 of 50) ─────────── */

    {
        struct coins_view_cache pc;
        struct coins_view pnv;
        memset(&pnv, 0, sizeof(pnv));
        coins_view_cache_init(&pc, &pnv);

        /* Build chain A */
        for (int h = 0; h <= CHAIN_LEN; h++)
            update_coins(&a_blocks[h].vtx[0], &pc, h);

        /* Disconnect top 25 blocks */
        bool ok = disconnect_range(a_blocks, a_idx, &pc, CHAIN_LEN, 25);
        ok = ok && all_coins_present(a_blocks, &pc, 0, 25);
        ok = ok && no_coins_present(a_blocks, &pc, 26, CHAIN_LEN);

        /* Connect 25 B blocks on top */
        for (int h = 26; h <= CHAIN_LEN; h++)
            update_coins(&b_blocks[h].vtx[0], &pc, h);

        ok = ok && all_coins_present(b_blocks, &pc, 26, CHAIN_LEN);
        ok = ok && all_coins_present(a_blocks, &pc, 0, 25);

        RG_CHECK("reorg: partial reorg (25 of 50) preserves lower chain", ok);

        coins_view_cache_free(&pc);
    }

    /* ── 15. 3-block chain: disconnect tip restores UTXO set ─ */

    {
        struct coins_view_cache tc;
        struct coins_view tnv;
        memset(&tnv, 0, sizeof(tnv));
        coins_view_cache_init(&tc, &tnv);

        /* Build 3-block chain: genesis → blk1 → blk2 */
        struct block tblks[3];
        struct uint256 thash[3];
        struct block_index tidx[3];

        for (int h = 0; h < 3; h++) {
            const struct uint256 *prev = h ? &thash[h - 1] : NULL;
            make_block_seeded(&tblks[h], h, prev, 0xDD);
            block_header_get_hash(&tblks[h].header, &thash[h]);
            block_index_init(&tidx[h]);
            tidx[h].nHeight = h;
            tidx[h].phashBlock = &thash[h];
            tidx[h].pprev = h ? &tidx[h - 1] : NULL;
            tidx[h].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            tidx[h].nTx = 1;
            tidx[h].nChainTx = (uint32_t)(h + 1);
            arith_uint256_set_u64(&tidx[h].nChainWork, (uint64_t)(h + 1));
            update_coins(&tblks[h].vtx[0], &tc, h);
        }

        /* All 3 coinbases exist */
        bool ok = true;
        for (int h = 0; h < 3; h++)
            ok = ok && coins_view_cache_have_coins(&tc, &tblks[h].vtx[0].hash);
        RG_CHECK("reorg: 3-block chain has all 3 coinbase UTXOs", ok);

        /* Disconnect tip (blk2) */
        struct block_undo bu2;
        block_undo_init(&bu2);
        struct validation_state vs2;
        validation_state_init(&vs2);
        ok = disconnect_block(&tblks[2], &vs2, &tidx[2], &tc, &bu2);
        block_undo_free(&bu2);
        RG_CHECK("reorg: disconnect tip of 3-block chain succeeds", ok);

        /* blk2 coinbase gone, blk0 and blk1 coinbases remain */
        ok = !coins_view_cache_have_coins(&tc, &tblks[2].vtx[0].hash);
        ok = ok && coins_view_cache_have_coins(&tc, &tblks[0].vtx[0].hash);
        ok = ok && coins_view_cache_have_coins(&tc, &tblks[1].vtx[0].hash);
        RG_CHECK("reorg: after disconnect tip, created outputs gone, prior UTXOs remain", ok);

        /* Disconnect blk1 */
        struct block_undo bu1;
        block_undo_init(&bu1);
        struct validation_state vs1;
        validation_state_init(&vs1);
        ok = disconnect_block(&tblks[1], &vs1, &tidx[1], &tc, &bu1);
        block_undo_free(&bu1);
        ok = ok && !coins_view_cache_have_coins(&tc, &tblks[1].vtx[0].hash);
        ok = ok && coins_view_cache_have_coins(&tc, &tblks[0].vtx[0].hash);
        RG_CHECK("reorg: after 2 disconnects, only genesis UTXO remains", ok);

        for (int h = 0; h < 3; h++)
            free_block(&tblks[h]);
        coins_view_cache_free(&tc);
    }

    /* ── Cleanup ─────────────────────────────────────────── */

    coins_view_cache_free(&cache);

    for (int h = 0; h <= CHAIN_LEN; h++)
        free_block(&a_blocks[h]);
    for (int h = 1; h <= CHAIN_LEN; h++)
        free_block(&b_blocks[h]);

    printf("=== reorg safety: %d failures ===\n", failures);
    return failures;
}
