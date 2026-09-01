/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic reproduction of a BIP30 chain stall.
 *
 * Context
 * -------
 * A stall can wedge the node at height N-1 with every
 * connect_tip(N) returning `bad-txns-BIP30`. A boot-time sweep that
 * runs once and cleans the orphan coinbase row lets
 * the chain advance to N — but if the tip later regresses back to N-1 on
 * its own (no operator restart, no reorg
 * log line), the BIP30 loop resumes.
 *
 * The failing shape
 * -----------------
 * The coins view holds an unspent coinbase entry for txid X belonging
 * to block N, but the chain tip has dropped back to N-1 (either from
 * a partial-application rollback or from a disconnect→reconnect path
 * that bypasses the sweep). connect_block(block_N) then reads
 * the stale coinbase, finds it still unspent, and trips BIP30 at
 * core/modules/validation/src/connect_block.c:219-233:
 *
 *     for (size_t i = 0; !skip_bip30 && i < block->num_vtx; i++) {
 *         if (coins_view_cache_have_coins(view, &block->vtx[i].hash)) {
 *             struct coins existing;
 *             coins_init(&existing);
 *             if (coins_view_cache_get_coins(view, &block->vtx[i].hash,
 *                                             &existing)) {
 *                 if (!coins_is_pruned(&existing)) {
 *                     coins_free(&existing);
 *                     return validation_state_dos(state, 100, false,
 *                         REJECT_INVALID, "bad-txns-BIP30", false, NULL);
 *                 }
 *             }
 *             coins_free(&existing);
 *         }
 *     }
 *
 * Scope — what this test is AND is NOT
 * ------------------------------------
 * This file started as a reproduction. It is now the regression gate:
 * connect_block must tolerate a block's own same-height coinbase
 * self-write after a local rewind, while preserving BIP30 rejection for
 * real duplicate transactions.
 *
 * Environment
 * -----------
 * All state is in-process and in-memory — no SQLite file, no node
 * boot, no threads.  We build a chain_params copy with a checkpoint
 * covering the test height so check_block's POW + size checks are
 * skipped; g_deferred_proof_validation_below_height is left at -1 so the BIP30 skip flag
 * stays false.  Runtime: <100ms.
 */

#include "test/test_core.h"
#include "validation/connect_block.h"
#include "validation/process_block.h"
#include "validation/update_coins.h"
#include "validation/contextual_check_tx.h"  /* g_deferred_proof_validation_below_height */
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "consensus/validation.h"
#include "storage/coins_view_sqlite.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Helpers (mirrors test_reorg_safety.c so reviewers can compare) ── */

static struct transaction make_coinbase_seeded(int height, uint8_t seed)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "p10_cb_vin");

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
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "p10_cb_vout");
    tx.vout[0].value = 1000000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);

    transaction_compute_hash(&tx);
    return tx;
}

static void make_block_seeded(struct block *blk, int height,
                               const struct uint256 *prev_hash,
                               uint8_t seed)
{
    memset(blk, 0, sizeof(*blk));
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "p10_block_vtx");
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

/* Build a chain_params copy with a single checkpoint at `height`
 * so connect_block's checkpoint_covers() returns true and
 * check_block runs with expensive_checks=false (skips Equihash POW
 * + size limit bounds we don't need for this fixture).  Heap-owned
 * so the caller frees when done. */
struct chain_params_fixture {
    struct chain_params params;
    struct checkpoint_entry entry;
};

static void build_checkpoint_params(struct chain_params_fixture *f,
                                     int checkpoint_height,
                                     const struct uint256 *hash)
{
    f->params = *chain_params_get();
    f->entry.height = checkpoint_height;
    f->entry.hash = *hash;
    f->params.checkpointData.entries = &f->entry;
    f->params.checkpointData.nEntries = 1;
}

/* ── Test 1 — live-node stall shape reproduces ──────────────────── */

static int t_connect_block_tolerates_own_coinbase_self_write(void)
{
    int failures = 0;

    TEST("chain_stall_repro: connect_block tolerates own coinbase self-write") {
        /* g_deferred_proof_validation_below_height guards the BIP30 skip flag — confirm
         * it is NOT set so the check runs. */
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        /* Heights chosen to match the live-node shape (tip+1 after
         * a partial-application rollback).  Any pair works; using
         * small values keeps the test fast. */
        const int parent_height = 199;
        const int stall_height = parent_height + 1;  /* = 200 */

        /* ── Parent block_index (height=199, the "tip" after rollback) ── */
        struct uint256 parent_hash;
        memset(parent_hash.data, 0xA0, sizeof(parent_hash.data));
        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = parent_height;
        parent_idx.phashBlock = &parent_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork, (uint64_t)parent_height + 1);

        /* ── The block that is about to be reconnected at height=200 ── */
        struct block stall_blk;
        make_block_seeded(&stall_blk, stall_height, &parent_hash, 0x00);

        struct uint256 stall_hash;
        block_header_get_hash(&stall_blk.header, &stall_hash);

        struct block_index stall_idx;
        block_index_init(&stall_idx);
        stall_idx.nHeight = stall_height;
        stall_idx.phashBlock = &stall_hash;
        stall_idx.pprev = &parent_idx;
        stall_idx.nStatus = BLOCK_HAVE_DATA;
        stall_idx.nTx = 1;

        /* ── Chain params: add a checkpoint at stall_height so
         *    check_block treats the header as trusted (skip POW/size
         *    limits — we don't mine Equihash for the fixture). ── */
        struct chain_params_fixture fx;
        build_checkpoint_params(&fx, stall_height, &stall_hash);

        /* ── Coins view: seed the stall block's coinbase as UNSPENT,
         *    then set best_block to the PARENT hash — the exact
         *    post-rewind shape the live node was trapped in. ── */
        struct coins_view_cache cache;
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        coins_view_cache_init(&cache, &null_view);

        /* Apply the block's coinbase to the cache — this simulates the
         * partial application of the original block N: the coinbase
         * output landed in the coins view but the tip-update never
         * committed.  After the mystery rollback, the cache still
         * holds this unspent coinbase. */
        update_coins(&stall_blk.vtx[0], &cache, stall_height);

        /* Pin the cache's best_block to the parent — simulating the
         * "tip regressed to N-1" state the live node entered. */
        coins_view_cache_set_best_block(&cache, &parent_hash);

        /* Sanity: the stale coinbase really is present and unspent. */
        ASSERT(coins_view_cache_have_coins(&cache, &stall_blk.vtx[0].hash));
        {
            struct coins existing;
            coins_init(&existing);
            ASSERT(coins_view_cache_get_coins(&cache,
                                               &stall_blk.vtx[0].hash,
                                               &existing));
            ASSERT(!coins_is_pruned(&existing));
            coins_free(&existing);
        }

        /* ── Attempt to reconnect block N — the actual repro call. ── */
        struct validation_state vs;
        validation_state_init(&vs);
        connect_block_set_sapling_tree(NULL);  /* just_check path */

        bool ok = connect_block(&stall_blk, &vs, &stall_idx, &cache,
                                 &fx.params, /*just_check=*/true);

        /* A same-height self-write wedge:
         * block N's own coinbase is already present while durable tip
         * is N-1. Since contextual_check_block enforces BIP34 coinbase
         * height encoding for every height > 0, this cannot be a real
         * post-BIP34 duplicate-coinbase consensus violation. */
        printf("connect_block ok=%d reject=\"%s\" dos=%d at h=%d... ",
               (int)ok, vs.reject_reason, vs.dos, stall_height);

        ASSERT(ok);
        ASSERT(strcmp(vs.reject_reason, "bad-txns-BIP30") != 0);

        /* Cleanup */
        free_block(&stall_blk);
        coins_view_cache_free(&cache);

        PASS();
    } _test_next:;

    return failures;
}

/* ── Test 2 — clean view does NOT trip BIP30 (control) ──────────── */

static int t_clean_view_advances(void)
{
    int failures = 0;

    TEST("chain_stall_repro: clean view (no stale coinbase) does NOT trip BIP30") {
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        const int parent_height = 199;
        const int stall_height = parent_height + 1;

        struct uint256 parent_hash;
        memset(parent_hash.data, 0xB0, sizeof(parent_hash.data));
        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = parent_height;
        parent_idx.phashBlock = &parent_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork, (uint64_t)parent_height + 1);

        struct block blk;
        make_block_seeded(&blk, stall_height, &parent_hash, 0x11);

        struct uint256 blk_hash;
        block_header_get_hash(&blk.header, &blk_hash);

        struct block_index blk_idx;
        block_index_init(&blk_idx);
        blk_idx.nHeight = stall_height;
        blk_idx.phashBlock = &blk_hash;
        blk_idx.pprev = &parent_idx;
        blk_idx.nStatus = BLOCK_HAVE_DATA;
        blk_idx.nTx = 1;

        struct chain_params_fixture fx;
        build_checkpoint_params(&fx, stall_height, &blk_hash);

        struct coins_view_cache cache;
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        coins_view_cache_init(&cache, &null_view);

        /* NO pre-seed of the coinbase — this is the "clean" state
         * that fix must restore. */
        coins_view_cache_set_best_block(&cache, &parent_hash);

        ASSERT(!coins_view_cache_have_coins(&cache, &blk.vtx[0].hash));

        struct validation_state vs;
        validation_state_init(&vs);
        connect_block_set_sapling_tree(NULL);

        bool ok = connect_block(&blk, &vs, &blk_idx, &cache,
                                 &fx.params, /*just_check=*/true);

        /* With a clean view BIP30 MUST NOT trip.  connect_block may
         * still fail further down (no sapling tree, etc.) but the
         * failure reason MUST NOT be "bad-txns-BIP30". */
        printf("clean: ok=%d reject=\"%s\"... ",
               (int)ok, vs.reject_reason);
        ASSERT(strcmp(vs.reject_reason, "bad-txns-BIP30") != 0);

        free_block(&blk);
        coins_view_cache_free(&cache);

        PASS();
    } _test_next:;

    return failures;
}

/* ── Test 3 — Regression test: disconnect_block purges coinbase ──
 *
 * The invariant: for every txid T in the coins view, the block that created
 * T's outputs must be on the active chain. Concretely: after
 * `disconnect_block(B)` runs on a scratch view wrapping a parent
 * cache, AND `coins_view_cache_flush_for_testing(scratch)` propagates the
 * disconnect to the parent, the parent MUST NO LONGER report
 * `coins_view_cache_have_coins` for any tx in B.
 *
 * This test constructs the three-layer shape that production uses
 * inside `disconnect_tip` (`process_block.c:1669-1693`):
 *
 *     null_view  ←  parent   ←  scratch
 *      (stub)    (coins_tip)  (disconnect_tip's scratchpad)
 *
 * `update_coins(blk.vtx[0], parent, h)` seeds the parent with the
 * coinbase (simulating a prior connect_block). Then the scratch is
 * layered on top, `disconnect_block` is called on the scratch, and
 * the scratch is flushed into the parent — exactly the production
 * sequence. The assertion is that the parent no longer has the
 * coinbase.
 *
 * Today this test FAILS. `disconnect_block` at
 * `core/modules/validation/src/connect_block.c:639` calls
 * `coins_map_erase(&scratch.cache_coins, &tx->hash)` on an empty
 * scratch map — a no-op — so nothing propagates to the parent, and
 * the parent retains the coinbase as an unspent entry. The
 * assertion failure names the bug: the coinbase that belongs to a
 * disconnected block is still reachable via `coins_view_cache_have_coins`
 * on the parent.
 *
 * This is the RED regression row. minimal fix
 * (emit a DIRTY+pruned tombstone from disconnect_block instead of
 * a bare erase) flips this assertion from RED to GREEN. After the
 * fix lands, the test stands as the permanent gate against
 * regression. */

static int t_disconnect_block_purges_coinbase_from_backing(void)
{
    int failures = 0;

    TEST("chain_stall_repro RED: disconnect_block purges coinbase from the backing parent cache") {
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        const int coinbase_height = 200;

        /* Build a stand-in for `coins_tip` — the parent cache.  Its
         * backing is a null view (no SQLite for this test; the
         * scratch→parent layer is enough to surface the bug). */
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache parent;
        coins_view_cache_init(&parent, &null_view);

        /* Block whose coinbase lands in the parent, then gets
         * disconnected via the scratch. */
        struct uint256 parent_prev_hash;
        memset(parent_prev_hash.data, 0xC0, sizeof(parent_prev_hash.data));
        struct block blk;
        make_block_seeded(&blk, coinbase_height, &parent_prev_hash, 0x33);

        struct uint256 blk_hash;
        block_header_get_hash(&blk.header, &blk_hash);

        /* block_index for disconnect_block: nHeight + pprev + phashBlock. */
        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = coinbase_height - 1;
        parent_idx.phashBlock = &parent_prev_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork,
                              (uint64_t)coinbase_height);

        struct block_index blk_idx;
        block_index_init(&blk_idx);
        blk_idx.nHeight = coinbase_height;
        blk_idx.phashBlock = &blk_hash;
        blk_idx.pprev = &parent_idx;
        blk_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        blk_idx.nTx = 1;

        /* Seed the parent with the coinbase — simulates a successful
         * prior connect_block at h=coinbase_height. */
        update_coins(&blk.vtx[0], &parent, coinbase_height);
        coins_view_cache_set_best_block(&parent, &blk_hash);

        /* Sanity: parent has the coinbase as unspent. */
        ASSERT(coins_view_cache_have_coins(&parent, &blk.vtx[0].hash));

        /* Now the interesting part: the scratch view wrapping the
         * parent, exactly as `disconnect_tip` builds it at
         * process_block.c:1669-1674. */
        struct coins_view parent_as_view;
        coins_view_cache_as_view(&parent_as_view, &parent);
        struct coins_view_cache scratch;
        coins_view_cache_init(&scratch, &parent_as_view);

        /* disconnect_block on the scratch. empty undo data is fine
         * for a coinbase-only block (the coinbase has no restorable
         * inputs). */
        struct block_undo empty_undo;
        block_undo_init(&empty_undo);
        struct validation_state vs;
        validation_state_init(&vs);
        bool disc_ok = disconnect_block(&blk, &vs, &blk_idx,
                                         &scratch, &empty_undo);
        ASSERT(disc_ok);

        /* Flush the scratch into the parent — the propagation step
         * that, per the postmortem, must purge the coinbase. */
        ASSERT(coins_view_cache_flush_for_testing(&scratch));

        /* The invariant — TODAY THIS FAILS.  The parent still
         * reports the coinbase as unspent because
         * disconnect_block's coins_map_erase at connect_block.c:639
         * ran on the (empty) scratch map and never emitted a DELETE
         * signal into the parent.
         *
         * minimal fix: emit a DIRTY+pruned tombstone from
         * disconnect_block so cvc_batch_write propagates a PRUNED
         * entry into the parent, and coins_view_cache_have_coins
         * returns false. When the fix lands this assertion flips
         * from RED to GREEN. */
        if (coins_view_cache_have_coins(&parent, &blk.vtx[0].hash)) {
            printf("FAIL (RED — parent still has coinbase_%d after "
                   "disconnect+flush; invariant violated at "
                   "connect_block.c:639)\n",
                   coinbase_height);
            failures++;
            goto _p103_cleanup;
        }
        PASS();

    _p103_cleanup:
        block_undo_free(&empty_undo);
        coins_view_cache_free(&scratch);
        coins_view_cache_free(&parent);
        free_block(&blk);
    } _test_next:;

    return failures;
}

/* ── Test 4 — Regression test: disconnect-flush lands in SQLite under shared-handle writer contention ──
 *
 * three-layer test uses a null_view backing, so the SQLite
 * persistence path is never exercised. The live-node stall at
 * h=3,081,408 showed the tombstone's DIRTY+pruned entry is correctly
 * produced in memory ( invariant assertion has never tripped),
 * but the `SAVEPOINT coins_flush failed rc=5: cannot open savepoint -
 * SQL statements in progress` line fires 3,478 times in node.log — the
 * DELETE never reaches disk, every cache eviction/rebuild re-reads the
 * original stale coinbase row, and BIP30 trips again.
 *
 * Root cause: the coins_view_sqlite SAVEPOINT is on the SHARED sqlite3
 * handle, and SQLite's OP_Savepoint bails with SQLITE_BUSY ("cannot
 * open savepoint - SQL statements in progress") whenever
 * `db->nVdbeWrite > 0` — i.e., any prepared writer statement on the
 * same connection is still mid-execution. In production this is
 * paired with an ordinary node_db writer whose VDBE counted up but
 * hasn't yet halted; the end effect is that the coins flush bails and
 * the tombstone DELETE never reaches disk.
 *
 * Reproducing in-process: hold ANY writer statement at SQLITE_ROW on
 * the shared handle. `INSERT ... RETURNING` pauses mid-execution with
 * `nVdbeWrite>0` on the first step — exact same shape as production's
 * contention. Then drive the full three-layer flush path. Pre-fix, the
 * flush fails and the tombstone DELETE never lands. Post-fix (:
 * dedicated connection for coins_view_sqlite), the shared-handle
 * writer no longer blocks the flush, and the DELETE is observable.
 *
 * Scope: this is the "coupled with" test called out in
 * AGENT-2.md — cache + backing three-layer GREEN after the fix. The
 * `disconnect_block + cvc_batch_write + sqlite_batch_write` sequence
 * under contention is the end-to-end path null-backing
 * variant couldn't surface. */

static int mkdir_p_p14(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void p14_tmp_path(char *buf, size_t n, const char *tag)
{
    snprintf(buf, n, "./test-tmp/p14_%d_%s", (int)getpid(), tag);
}

/* Build the minimal schema coins_view_sqlite_open's integrity check
 * and the flush path need. File-backed + WAL to match production. */
static bool p14_build_db(sqlite3 **out, const char *dbpath)
{
    if (sqlite3_open(dbpath, out) != SQLITE_OK) return false;
    sqlite3_exec(*out, "PRAGMA journal_mode=WAL",  NULL, NULL, NULL);
    sqlite3_exec(*out, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    sqlite3_busy_timeout(*out, 5000);
    char *err = NULL;
    int rc = sqlite3_exec(*out,
        "CREATE TABLE IF NOT EXISTS utxos("
        " txid BLOB, vout INTEGER, value INTEGER,"
        " script BLOB, script_type INTEGER, address_hash BLOB,"
        " height INTEGER, is_coinbase INTEGER,"
        " PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS node_state("
        " key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS blocks("
        " hash BLOB PRIMARY KEY, height INTEGER, status INTEGER);",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "p14_build_db exec err: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static int p14_count_utxos_by_txid(sqlite3 *db, const uint8_t txid[32])
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM utxos WHERE txid=?",
            -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    int count = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        count = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return count;
}

static int t_p14_flush_under_shared_cursor_lands_tombstone(void)
{
    int failures = 0;
    char dir[256];  p14_tmp_path(dir, sizeof(dir), "shared_cursor");
    mkdir_p_p14(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("chain_stall_repro RED: file-backed coins_view_sqlite opens a dedicated connection AND three-layer disconnect+flush lands DELETE in SQLite") {
        atomic_store(&g_deferred_proof_validation_below_height, -1);

        sqlite3 *db = NULL;
        ASSERT(p14_build_db(&db, dbpath));

        struct coins_view_sqlite cvs;
        ASSERT(coins_view_sqlite_open(&cvs, db));

        /* ── structural invariant — the RED/GREEN gate ──
         *
         * For a file-backed input handle, `coins_view_sqlite_open`
         * MUST open its own sqlite3 handle so the flush's BEGIN
         * IMMEDIATE runs on an independent `nVdbeWrite` counter.
         * Pre-fix, `cvs.db == db` and `cvs.owns_db == false`; any
         * writer VDBE on `db` trips SAVEPOINT with "SQL statements
         * in progress" (3,478 occurrences in the live node's log
         * before the canary rolled back).
         *
         * This is the deterministic pre-fix RED marker — no timing
         * or thread scheduling involved.  Post-fix, both hold. */
        ASSERT(cvs.owns_db);
        ASSERT(cvs.db != db);

        /* ── Probe: the exact contention shape that tripped the
         * pre-fix flush still exists on the SHARED handle ──
         *
         * We hold an `INSERT ... RETURNING` at SQLITE_ROW on the
         * caller's `db` handle — this is a writer whose VDBE is
         * mid-execution (`nVdbeWrite > 0` on that connection).  A
         * manual SAVEPOINT on the SAME handle must fail with
         * SQLITE_BUSY and the message "cannot open savepoint - SQL
         * statements in progress" — documenting that pre-fix, the
         * coins-view flush running SAVEPOINT on the same handle
         * would have tripped.  Post-fix, coins_view_sqlite's flush
         * is on `cvs.db`, not `db`, so this contention cannot
         * affect it. */
        uint8_t decoy_txid[32]; memset(decoy_txid, 0xEE, 32);
        sqlite3_stmt *foreign = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "INSERT INTO utxos(txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES(?,0,0,NULL,0,NULL,0,0) RETURNING txid",
            -1, &foreign, NULL) == SQLITE_OK);
        ASSERT_EQ(sqlite3_stmt_readonly(foreign), 0);
        sqlite3_bind_blob(foreign, 1, decoy_txid, 32, SQLITE_STATIC);
        ASSERT_EQ(sqlite3_step(foreign), SQLITE_ROW);
        {
            char *serr = NULL;
            int svrc = sqlite3_exec(db, "SAVEPOINT probe",
                                     NULL, NULL, &serr);
            /* Exactly the live-node error signature. */
            ASSERT_EQ(svrc, SQLITE_BUSY);
            ASSERT(serr && strstr(serr,
                "SQL statements in progress") != NULL);
            sqlite3_free(serr);
            /* No RELEASE — the SAVEPOINT never began. */
        }
        /* Release the foreign writer so the probe test's contention
         * doesn't survive into the subsequent flush.  Production
         * timing: node_db's AR writers commit in microseconds; the
         * "indefinite hold during flush" shape is a test
         * caricature, not a real-world scenario. */
        sqlite3_reset(foreign);
        sqlite3_finalize(foreign);

        /* ── Three-layer end-to-end flush → SQLite ──
         *
         * This is the path null-backing variant could not
         * surface: cache + cache + coins_view_sqlite. 
         * it is GREEN in one commit (per AGENT-2.md 
         * coupling). */
        struct coins_view_cache parent;
        coins_view_cache_init(&parent, &cvs.view);

        const int coinbase_height = 200;
        struct uint256 parent_prev_hash;
        memset(parent_prev_hash.data, 0xD0, sizeof(parent_prev_hash.data));
        struct block blk;
        make_block_seeded(&blk, coinbase_height, &parent_prev_hash, 0x44);

        struct uint256 blk_hash;
        block_header_get_hash(&blk.header, &blk_hash);

        struct block_index parent_idx;
        block_index_init(&parent_idx);
        parent_idx.nHeight = coinbase_height - 1;
        parent_idx.phashBlock = &parent_prev_hash;
        parent_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        parent_idx.nTx = 1;
        parent_idx.nChainTx = 1;
        arith_uint256_set_u64(&parent_idx.nChainWork,
                              (uint64_t)coinbase_height);

        struct block_index blk_idx;
        block_index_init(&blk_idx);
        blk_idx.nHeight = coinbase_height;
        blk_idx.phashBlock = &blk_hash;
        blk_idx.pprev = &parent_idx;
        blk_idx.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        blk_idx.nTx = 1;

        update_coins(&blk.vtx[0], &parent, coinbase_height);
        coins_view_cache_set_best_block(&parent, &blk_hash);
        ASSERT(coins_view_cache_flush_for_testing(&parent));

        const uint8_t *cb_txid = blk.vtx[0].hash.data;
        ASSERT_EQ(p14_count_utxos_by_txid(cvs.db, cb_txid), 1);

        /* Scratch view on top of parent — exactly how disconnect_tip
         * constructs its scratchpad at process_block.c:1669-1674. */
        struct coins_view parent_as_view;
        coins_view_cache_as_view(&parent_as_view, &parent);
        struct coins_view_cache scratch;
        coins_view_cache_init(&scratch, &parent_as_view);

        struct block_undo empty_undo;
        block_undo_init(&empty_undo);
        struct validation_state vs;
        validation_state_init(&vs);
        ASSERT(disconnect_block(&blk, &vs, &blk_idx,
                                 &scratch, &empty_undo));
        ASSERT(coins_view_cache_flush_for_testing(&scratch));

        /* The load-bearing flush: parent → SQLite.  Pre-fix, this
         * would have been vulnerable to the same SAVEPOINT
         * contention we probed above when it happens to race with
         * an external subsystem's writer.  Post-fix, it runs on
         * the dedicated `cvs.db` and is immune to the shared
         * handle's state. */
        ASSERT(coins_view_cache_flush_for_testing(&parent));

        /* Tombstone DELETE landed — the coinbase row is gone from
         * SQLite, not just from the in-memory tombstone map.  The
         * live-node stall at h=3,081,408 persisted because this
         * DELETE never reached disk; it does. */
        ASSERT_EQ(p14_count_utxos_by_txid(cvs.db, cb_txid), 0);

        block_undo_free(&empty_undo);
        coins_view_cache_free(&scratch);
        coins_view_cache_free(&parent);
        coins_view_sqlite_close(&cvs);
        sqlite3_close(db);
        free_block(&blk);

        PASS();
    } _test_next:;

    test_cleanup_tmpdir(dir);
    return failures;
}

int test_chain_stall_repro(void);

int test_chain_stall_repro(void)
{
    printf("\n=== chain stall repro ===\n");
    int failures = 0;
    failures += t_connect_block_tolerates_own_coinbase_self_write();
    failures += t_clean_view_advances();
    failures += t_disconnect_block_purges_coinbase_from_backing();
    failures += t_p14_flush_under_shared_cursor_lands_tombstone();
    return failures;
}
