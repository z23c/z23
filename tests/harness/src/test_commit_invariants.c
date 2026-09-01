/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_commit_invariants — the batch-commit conservation invariants
 * (jobs/reducer_commit_invariants.h): (a) coins row-count delta == created −
 * spent; (b) anchor set append-only/monotonic; (c) nullifier inserts unique.
 *
 * Two halves, exactly the task's test bar:
 *   (1) INJECT violations (duplicate nullifier, non-monotonic anchor, forged
 *       apply stats) via the module API on a hermetic store and assert verify()
 *       REFUSES the commit and raises the typed blocker naming the right height.
 *   (2) A GREEN end-to-end fold of a real mined regtest block through the
 *       batched utxo_apply drain, proving ZERO false positives + measuring the
 *       per-commit coins-count overhead.
 *
 *   make t ONLY=commit_invariants
 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "domain/consensus/coinbase.h"
#include "jobs/reducer_commit_invariants.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/header_admit_inbox.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define CI_CHECK(name, expr) do {                          \
    printf("commit_invariants: %s... ", (name));           \
    if ((expr)) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

static int ci_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* True iff the commit-invariant blocker is present AND its reason names the
 * given height + kind substring. */
static bool ci_blocker_names(int height, const char *kind_sub)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    char hneedle[32];
    snprintf(hneedle, sizeof(hneedle), "height=%d", height);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID) != 0)
            continue;
        bool h_ok = strstr(snaps[i].reason, hneedle) != NULL;
        bool k_ok = !kind_sub || strstr(snaps[i].reason, kind_sub) != NULL;
        if (!(h_ok && k_ok))
            printf("  >> blocker reason: %s\n", snaps[i].reason);
        return h_ok && k_ok;
    }
    return false;
}

/* One-coinbase regtest block, real merkle root, regtest powLimit nBits. */
static bool ci_build_regtest_block(struct block *blk, int height,
                                   const struct uint256 *prev_hash,
                                   const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "ci_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;
    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    struct script miner_script;
    script_init(&miner_script);
    miner_script.data[0] = 0x76;
    miner_script.data[1] = 0xa9;
    miner_script.data[2] = 0x14;
    for (int i = 0; i < 20; i++)
        miner_script.data[3 + i] = (unsigned char)(0x10 + i);
    miner_script.data[23] = 0x88;
    miner_script.data[24] = 0xac;
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

    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1600000000u + (uint32_t)height;
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return true;
}

static bool ci_seed_genesis_utxo_apply_row(sqlite3 *db)
{
    if (!db) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log "
        "(height,status,ok,spent_count,added_count,total_value_delta,applied_at) "
        "VALUES(0,'verified',1,0,0,0,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = (sqlite3_step(st) == SQLITE_DONE);  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* ── Part 1: direct-module violation injection (deterministic, hermetic) ── */
static int ci_part1_injection(void)
{
    int failures = 0;
    blocker_module_init();

    char dir[256];
    ci_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "commit_invariants", "inject");
    ci_mkdir_p(dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    CI_CHECK("inject: progress store opens", store_ok);
    if (!store_ok) { progress_store_close(); return failures; }
    sqlite3 *db = progress_store_db();
    CI_CHECK("inject: coins schema ensured", coins_kv_ensure_schema(db));
    CI_CHECK("inject: anchor schema ensured", anchor_kv_ensure_schema(db));
    CI_CHECK("inject: nullifier schema ensured", nullifier_kv_ensure_schema(db));

    /* (c) duplicate nullifier within a batch → refuse + blocker at the height. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        uint8_t nf[32];
        memset(nf, 0xC3, sizeof(nf));
        reducer_commit_invariants_batch_begin(db);
        reducer_commit_invariants_note_nullifier(5, nf, 0);
        reducer_commit_invariants_note_nullifier(5, nf, 0);  /* duplicate */
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(c) duplicate nullifier: verify REFUSES the commit", !ok);
        CI_CHECK("(c) duplicate nullifier: blocker names height=5 + kind",
                 ci_blocker_names(5, "nullifier_duplicate"));
    }

    /* (c) distinct nullifiers at the same height are NOT a duplicate. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        uint8_t nf1[32], nf2[32];
        memset(nf1, 0x11, sizeof(nf1));
        memset(nf2, 0x22, sizeof(nf2));
        reducer_commit_invariants_batch_begin(db);
        reducer_commit_invariants_note_nullifier(7, nf1, 0);
        reducer_commit_invariants_note_nullifier(7, nf2, 0);
        reducer_commit_invariants_note_nullifier(7, nf1, 1); /* diff pool = ok */
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(c) distinct nullifiers/pools: verify PASSES", ok);
        CI_CHECK("(c) distinct nullifiers: no blocker raised",
                 !blocker_exists(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID));
    }

    /* (b) non-monotonic anchor append → refuse + blocker at the height. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        reducer_commit_invariants_batch_begin(db);
        reducer_commit_invariants_note_anchor(10, ANCHOR_POOL_SAPLING);
        reducer_commit_invariants_note_anchor(9, ANCHOR_POOL_SAPLING); /* back */
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(b) non-monotonic anchor: verify REFUSES the commit", !ok);
        CI_CHECK("(b) non-monotonic anchor: blocker names height=9 + kind",
                 ci_blocker_names(9, "anchor_nonmonotonic"));
    }

    /* (b) strictly-increasing appends across pools PASS. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        reducer_commit_invariants_batch_begin(db);
        reducer_commit_invariants_note_anchor(11, ANCHOR_POOL_SPROUT);
        reducer_commit_invariants_note_anchor(12, ANCHOR_POOL_SPROUT);
        reducer_commit_invariants_note_anchor(11, ANCHOR_POOL_SAPLING); /* other pool */
        reducer_commit_invariants_note_anchor(13, ANCHOR_POOL_SAPLING);
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(b) monotonic appends across pools: verify PASSES", ok);
    }

    /* (a) forged apply stats: claim 5 created, author NONE → count mismatch. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        reducer_commit_invariants_batch_begin(db);
        reducer_commit_invariants_note_coins(3, /*added=*/5, /*spent=*/0);
        /* deliberately do NOT touch coins_kv — the stats are forged */
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(a) forged apply stats: verify REFUSES the commit", !ok);
        CI_CHECK("(a) forged apply stats: blocker names height=3 + kind",
                 ci_blocker_names(3, "coins_conservation"));
    }

    /* (a) honest apply stats: physically author 3 coins, claim +3 → PASS. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        reducer_commit_invariants_batch_begin(db);
        bool added = true;
        for (int i = 0; i < 3; i++) {
            uint8_t txid[32];
            memset(txid, 0xA0 + i, sizeof(txid));
            added = added && coins_kv_add(db, txid, 0, 1000 + i, 100, false,
                                          NULL, 0);
        }
        CI_CHECK("(a) honest path: 3 coins authored", added);
        reducer_commit_invariants_note_coins(4, /*added=*/3, /*spent=*/0);
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(a) honest apply stats: verify PASSES (delta==created)", ok);
        CI_CHECK("(a) honest apply stats: no blocker raised",
                 !blocker_exists(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID));
    }

    /* Replacement is an exact zero physical delta. A forged +1 claim must
     * refuse even though INSERT OR REPLACE itself succeeds. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        uint8_t txid[32];
        memset(txid, 0xA0, sizeof(txid)); /* already live above */
        reducer_commit_invariants_batch_begin(db);
        bool replaced = coins_kv_add(db, txid, 0, 7777, 101, false, NULL, 0);
        CI_CHECK("(a) replacement write succeeds", replaced);
        reducer_commit_invariants_note_coins(5, /*added=*/1, /*spent=*/0);
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(a) replacement collision: forged +1 REFUSES", !ok);
        CI_CHECK("(a) replacement collision: blocker names height=5 + kind",
                 ci_blocker_names(5, "coins_conservation"));
    }

    /* Deleting an absent row is likewise an exact zero physical delta. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        uint8_t absent[32];
        memset(absent, 0xDD, sizeof(absent));
        reducer_commit_invariants_batch_begin(db);
        bool deleted = coins_kv_spend(db, absent, 9);
        CI_CHECK("(a) absent DELETE retains no-op API success", deleted);
        reducer_commit_invariants_note_coins(6, /*added=*/0, /*spent=*/1);
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("(a) absent spend: forged -1 REFUSES", !ok);
        CI_CHECK("(a) absent spend: blocker names height=6 + kind",
                 ci_blocker_names(6, "coins_conservation"));
    }

    /* Reorg rebaseline: a noted reorg makes verify PASS even with a would-be
     * violation queued (the unwind's inverse math owns conservation). */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    {
        uint8_t nf[32];
        memset(nf, 0x5A, sizeof(nf));
        reducer_commit_invariants_batch_begin(db);
        reducer_commit_invariants_note_reorg();
        reducer_commit_invariants_note_nullifier(2, nf, 0);
        reducer_commit_invariants_note_nullifier(2, nf, 0); /* dup, but reorg */
        bool ok = reducer_commit_invariants_verify(db);
        CI_CHECK("reorg batch: verify PASSES (rebaselined)", ok);
        CI_CHECK("reorg batch: no blocker raised",
                 !blocker_exists(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID));
    }

    /* No open window: verify is a clean no-op pass. */
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    CI_CHECK("no window: verify PASSES (no-op)",
             reducer_commit_invariants_verify(db));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── Part 2: green end-to-end fold through the BATCHED utxo_apply drain ─── */
static int ci_part2_green_fold(void)
{
    int failures = 0;
    blocker_module_init();
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "commit_invariants", "green");
    ci_mkdir_p(dir);
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    ci_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    ci_mkdir_p(blocksdir);
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    CI_CHECK("green: progress store opens", store_ok);
    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    CI_CHECK("green: event log open", lg != NULL);
    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        SetDataDir(""); ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        return failures;
    }

    struct main_state ms;
    main_state_init(&ms);
    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis =
        chainstate_insert_block_index((struct chainstate *)&ms, &genesis_hash);
    if (genesis) {
        genesis->nHeight = 0;
        genesis->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        genesis->nTx = 1;
        genesis->nChainTx = 1;
        genesis->nChainWork = GetBlockProof(genesis);
        active_chain_move_window_tip(&ms.chain_active, genesis);
        ms.pindex_best_header = genesis;
    }

    bool stages_ok =
        header_admit_stage_init(&ms) &&
        validate_headers_stage_init(&ms) &&
        body_fetch_stage_init(&ms) &&
        body_persist_stage_init(&ms) &&
        script_validate_stage_init(&ms) &&
        proof_validate_stage_init(&ms) &&
        utxo_apply_stage_init(&ms) &&
        tip_finalize_stage_init(&ms);
    CI_CHECK("green: eight reducer stages init", stages_ok);
    CI_CHECK("green: genesis utxo row seeded",
             ci_seed_genesis_utxo_apply_row(progress_store_db()));
    CI_CHECK("green: genesis anchor seeded",
             tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    sqlite3 *db = progress_store_db();
    int64_t coins_before = coins_kv_count(db);

    if (stages_ok) {
        struct block blk1;
        bool built = ci_build_regtest_block(&blk1, 1, &genesis_hash, cp) &&
                     mine_block_pow(&blk1, 1, cp, 0);
        CI_CHECK("green: block 1 built + Equihash-mined", built);
        if (built) {
            struct uint256 h1;
            block_get_hash(&blk1, &h1);
            struct header_admit_msg m;
            memset(&m, 0, sizeof(m));
            m.hash = h1;
            m.has_header = true;
            m.header = blk1.header;
            m.height = -1;
            CI_CHECK("green: header pushed", mailbox_header_admit_push(&m));

            (void)header_admit_stage_drain(100);
            struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1);
            (void)validate_headers_stage_drain(100);

            bool persisted = false;
            if (bi1) {
                struct disk_block_pos pos;
                disk_block_pos_init(&pos);
                persisted = write_block_to_disk(&blk1, &pos, netdir,
                                                cp->pchMessageStart) &&
                            block_index_set_have_data_verified(bi1, &pos,
                                                               netdir);
            }
            CI_CHECK("green: body persisted", persisted);

            (void)body_fetch_stage_drain(100);
            (void)body_persist_stage_drain(100);
            (void)script_validate_stage_drain(100);
            (void)proof_validate_stage_drain(100);

            /* THE path under test: the BATCHED utxo_apply drain runs
             * batch_begin → step → verify → COMMIT. A false positive would
             * ROLLBACK and leave utxo_apply un-advanced + raise the blocker. */
            int adv = utxo_apply_stage_drain(100);
            CI_CHECK("green: batched utxo_apply drain advanced", adv >= 1);
            CI_CHECK("green: utxo_apply succeeded at height 1 (committed)",
                     utxo_apply_stage_succeeded_at(1));
            CI_CHECK("green: NO commit_invariant_violation blocker (zero "
                     "false positives)",
                     !blocker_exists(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID));

            int64_t coins_after = coins_kv_count(db);
            /* The coinbase adds exactly one spendable output. */
            CI_CHECK("green: coins conserved (+1 coinbase output)",
                     coins_before >= 0 && coins_after == coins_before + 1);

            int64_t count_us = reducer_commit_invariants_last_count_us();
            printf("commit_invariants: green: O(1) delta-read overhead "
                   "= %lld us (overlay inactive, no COUNT scan)\n",
                   (long long)count_us);

            block_free(&blk1);
        }
    }

    tip_finalize_stage_shutdown();
    utxo_apply_stage_shutdown();
    proof_validate_stage_shutdown();
    script_validate_stage_shutdown();
    body_persist_stage_shutdown();
    body_fetch_stage_shutdown();
    validate_headers_stage_shutdown();
    header_admit_stage_shutdown();
    event_log_close(lg);
    progress_store_close();
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(netdir);
    test_cleanup_tmpdir(dir);
    SetDataDir(""); ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    return failures;
}

int test_commit_invariants(void);
int test_commit_invariants(void)
{
    int failures = 0;
    failures += ci_part1_injection();
    failures += ci_part2_green_fold();
    blocker_clear(UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID);
    printf("=== commit invariants: %d failures ===\n", failures);
    return failures;
}
