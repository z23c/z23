/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_step_drain_harness — a DETERMINISTIC, single-stepped drive of the
 * eight-stage reducer pipeline for ONE self-mined regtest block with NO
 * successor (exactly the `generate 1` scenario). It calls each stage's step_once
 * ONE AT A TIME and asserts that stage's progress.kv log row + cursor, so the
 * exact stage that records a wrong ok=0 is pinpointed in-process — turning the
 * live, run-to-run-contradicting node diagnostics into a reproducible unit test.
 *
 * It runs the PRODUCTION step bodies with NO stubs: real Equihash mining
 * (mine_block_pow, regtest 48,5), real body write/read to disk, the identical
 * *_stage_step_once functions reducer_drain_all_stages calls. The only
 * difference from reducer_ingest_block is single-stepping with an assertion
 * between each stage instead of summing advance counts.
 *
 * Scaffolding (setup / block builder / genesis seed) is lifted from
 * test_reducer_forward_progress_gate.c. Process-globals → opt-in isolated run:
 *   make t ONLY=reducer_step_drain_harness
 */

#include "test/test_core.h"
#include "test/test_timing_budget.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "config/boot.h"       /* boot_mint_anchor_progress_log_tick_for_test */
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/chain_activation_service.h"
#include "services/header_admit_inbox.h"
#include "services/reducer_drain.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/progress_store.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/stage_helpers.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/accept_block_header.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"

#include <errno.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SD_CHECK(name, expr) do {                              \
    printf("reducer_step_drain_harness: %s... ", (name));      \
    if ((expr)) printf("OK\n");                                \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

static int sd_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* One-coinbase regtest block, real merkle root, regtest powLimit nBits.
 * Identical shape to rfp_build_regtest_block. */
static bool sd_build_regtest_block(struct block *blk, int height,
                                   const struct uint256 *prev_hash,
                                   const struct chain_params *cp,
                                   int64_t *out_coinbase_value)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "sd_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    struct script miner_script;
    script_init(&miner_script);
    miner_script.data[0] = 0x76; /* OP_DUP        */
    miner_script.data[1] = 0xa9; /* OP_HASH160    */
    miner_script.data[2] = 0x14; /* push 20       */
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

static bool sd_seed_genesis_utxo_apply_row(sqlite3 *db)
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

/* Generic "SELECT <col> FROM <table> WHERE height=?" -> int. Returns false if
 * no row / error. Idiom = tf_log_status_at (test_reducer_ingest_e2e.c). */
static bool sd_log_int(sqlite3 *db, const char *table, const char *col,
                       int height, int64_t *out)
{
    if (!db) return false;
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT %s FROM %s WHERE height=?", col, table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-sql-ok:test-readback
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {   // raw-sql-ok:test-readback
        *out = sqlite3_column_int64(st, 0);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* Read a TEXT column (status/source) into buf. */
static bool sd_log_text(sqlite3 *db, const char *table, const char *col,
                        int height, char *buf, size_t buflen)
{
    if (!db) return false;
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT %s FROM %s WHERE height=?", col, table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-sql-ok:test-readback
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {   // raw-sql-ok:test-readback
        const unsigned char *t = sqlite3_column_text(st, 0);
        snprintf(buf, buflen, "%s", t ? (const char *)t : "");
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* True iff NO "stage_spin_*" blocker is currently registered — the false-fire
 * assertion for the advance-or-blocker contract (a healthy fold must never name
 * a stage as spinning). */
static bool sd_no_stage_spin_blocker(void)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++)
        if (strncmp(snaps[i].id, "stage_spin_", 11) == 0)
            return false;
    return true;
}

int test_reducer_step_drain_harness(void);
int test_reducer_step_drain_harness(void)
{
    int failures = 0;

    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    /* The mainnet steady-tip authority close is a deliberately tiny shape:
     * H* trails the fully-applied active/best tip by exactly one and the only
     * finalize hold is the missing successor. Exercise each load-bearing
     * refusal independently so this can never become a generic jump helper. */
    {
        struct reducer_at_tip_authority_observation at = {
            .hstar = 99,
            .active_height = 100,
            .best_header_height = 100,
            .coins_applied_height = 101,
            .tip_finalize_cursor = 100,
            .active_hash_matches_best = true,
            .coins_applied_found = true,
            .utxo_apply_succeeded = true,
            .normal_lookahead_missing = true,
            .block_failed = false,
        };
        SD_CHECK("at-tip authority: exact normal-lookahead shape is ready",
                 reducer_at_tip_authority_ready(&at));
        at.hstar = 98;
        SD_CHECK("at-tip authority: multi-height H* jump refused",
                 !reducer_at_tip_authority_ready(&at));
        at.hstar = 99; at.best_header_height = 101;
        SD_CHECK("at-tip authority: header tip ahead refused",
                 !reducer_at_tip_authority_ready(&at));
        at.best_header_height = 100; at.active_hash_matches_best = false;
        SD_CHECK("at-tip authority: foreign best-header hash refused",
                 !reducer_at_tip_authority_ready(&at));
        at.active_hash_matches_best = true; at.coins_applied_height = 102;
        SD_CHECK("at-tip authority: coins frontier mismatch refused",
                 !reducer_at_tip_authority_ready(&at));
        at.coins_applied_height = 101; at.tip_finalize_cursor = 99;
        SD_CHECK("at-tip authority: finalize cursor mismatch refused",
                 !reducer_at_tip_authority_ready(&at));
        at.tip_finalize_cursor = 100; at.normal_lookahead_missing = false;
        SD_CHECK("at-tip authority: non-lookahead hold refused",
                 !reducer_at_tip_authority_ready(&at));
        at.normal_lookahead_missing = true; at.block_failed = true;
        SD_CHECK("at-tip authority: failed block refused",
                 !reducer_at_tip_authority_ready(&at));
        at.block_failed = false; at.utxo_apply_succeeded = false;
        SD_CHECK("at-tip authority: unapplied tip refused",
                 !reducer_at_tip_authority_ready(&at));
    }

    /* ── wf/foldpath-loud-errors: window-extend failure is now LOUD ────────
     * reducer_extend_window_to_candidate() used to (void)-discard the
     * active_chain_extend_window{,_have_data} result; a failed extend (alloc
     * failure only) is now counted + LOG_WARN'd. A FRESH chain has capacity==0
     * (active_chain_init), so the FIRST extend unconditionally attempts a
     * zcl_malloc("active_chain") grow (active_chain_grow_locked) — arming the
     * alloc-fault hook on that exact label forces the swallowed error to fire
     * deterministically, without touching the harness's real fold state below.
     * Synthetic block_index idiom mirrors mw_mk_idx in
     * test_most_work_selector.c. pindex_best_header stays NULL so the fallback
     * (most-work candidate) branch is exercised. */
    {
        struct main_state fault_ms;
        memset(&fault_ms, 0, sizeof(fault_ms));
        main_state_init(&fault_ms);

        struct uint256 *fh = zcl_malloc(sizeof(*fh), "sd_fault_hash");
        struct block_index *fcand =
            fh ? zcl_calloc(1, sizeof(*fcand), "sd_fault_bi") : NULL;
        bool fixture_ok = false;
        if (fh && fcand) {
            memset(fh, 0xAB, sizeof(*fh));
            fcand->nHeight = 0;
            fcand->phashBlock = fh;
            fcand->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
            fcand->nTx = 1;
            fcand->nChainTx = 1;
            arith_uint256_set_u64(&fcand->nChainWork, 1);
            fixture_ok = block_map_insert(&fault_ms.map_block_index, fh, fcand);
        }
        SD_CHECK("window-extend fault: fixture candidate inserted", fixture_ok);

        if (fixture_ok) {
            uint64_t before = reducer_window_extend_failure_count();

            zcl_alloc_fault_fail_next("active_chain");
            reducer_extend_window_to_candidate(&fault_ms, true);
            zcl_alloc_fault_clear();  /* belt-and-suspenders if unfired */

            SD_CHECK("window-extend fault: injected alloc fault is counted",
                     reducer_window_extend_failure_count() == before + 1);
            SD_CHECK("window-extend fault: failed extend leaves window untouched",
                     fault_ms.chain_active.height == -1);

            /* Healthy retry, identical inputs, no fault armed: must succeed AND
             * must NOT trip the failure counter (zero happy-path behavior
             * change — the (void)-vs-checked wrapper is a no-op on success). */
            reducer_extend_window_to_candidate(&fault_ms, true);
            SD_CHECK("window-extend healthy: counter does not increment",
                     reducer_window_extend_failure_count() == before + 1);
            SD_CHECK("window-extend healthy: window actually widened to cand",
                     fault_ms.chain_active.height == 0);

            /* With a best-header chain far above the window but H+1 still
             * body-missing, the fast path must stop after that single proof;
             * it cannot scan the remaining header band or consume an
             * active-chain grow allocation. Once H+1 receives data, the same
             * topology must immediately reactivate and expose it. */
            struct uint256 fh1, fh2;
            memset(&fh1, 0xBC, sizeof(fh1));
            memset(&fh2, 0xCD, sizeof(fh2));
            struct block_index fc1, fc2;
            memset(&fc1, 0, sizeof(fc1));
            memset(&fc2, 0, sizeof(fc2));
            fc1.nHeight = 1;
            fc1.phashBlock = &fh1;
            fc1.hashBlock = fh1;
            fc1.pprev = fcand;
            fc1.nStatus = BLOCK_VALID_TREE;
            fc2.nHeight = 2;
            fc2.phashBlock = &fh2;
            fc2.hashBlock = fh2;
            fc2.pprev = &fc1;
            fc2.nStatus = BLOCK_VALID_TREE;
            bool headers_ok =
                block_map_insert(&fault_ms.map_block_index, &fh1, &fc1) &&
                block_map_insert(&fault_ms.map_block_index, &fh2, &fc2);
            fault_ms.pindex_best_header = &fc2;
            SD_CHECK("window-extend H+1 gate: headers inserted", headers_ok);

            uint64_t fast_before =
                active_chain_extend_window_have_data_fast_count();
            zcl_alloc_fault_fail_next("active_chain");
            reducer_extend_window_to_candidate(&fault_ms, true);
            zcl_alloc_fault_clear();
            SD_CHECK("window-extend H+1 gate: missing body is a no-op",
                     fault_ms.chain_active.height == 0);
            SD_CHECK("window-extend H+1 gate: no futile band walk counted",
                     active_chain_extend_window_have_data_fast_count() ==
                         fast_before);

            fc1.nStatus |= BLOCK_HAVE_DATA;
            reducer_extend_window_to_candidate(&fault_ms, true);
            SD_CHECK("window-extend H+1 gate: body arrival reactivates",
                     fault_ms.chain_active.height == 1);
            SD_CHECK("window-extend H+1 gate: productive walk counted once",
                     active_chain_extend_window_have_data_fast_count() ==
                         fast_before + 1);

            /* One outer stage batch must perform one window exposure even
             * when many cursor steps call the shared helper. This is the
             * production 500-step catch-up shape. */
            sqlite3 *batch_db = NULL;
            bool batch_open = sqlite3_open(":memory:", &batch_db) == SQLITE_OK &&
                              stage_batch_begin(batch_db);
            SD_CHECK("window-extend batch cache: opens outer transaction",
                     batch_open);
            if (batch_open) {
                uint64_t attempts_before =
                    reducer_window_extend_attempt_count();
                reducer_extend_window_to_candidate(&fault_ms, true);
                reducer_extend_window_to_candidate(&fault_ms, true);
                reducer_extend_window_to_candidate(&fault_ms, true);
                SD_CHECK("window-extend batch cache: three steps attempt once",
                         reducer_window_extend_attempt_count() ==
                             attempts_before + 1);
                SD_CHECK("window-extend batch cache: no correctness failure",
                         reducer_window_extend_failure_count() == before + 1);
                (void)stage_batch_end(batch_db, false);
            }
            if (batch_db)
                sqlite3_close(batch_db);
        }

        main_state_free(&fault_ms);
        /* block_map_free does not free entry/hash blobs (process-lifetime by
         * design; see chainstate.c) — free them here like mw_free_idx does. */
        free(fcand);
        free(fh);
    }

    /* ── hermetic datadir + stores ─────────────────────────────────────── */
    char dir[256];
    sd_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "reducer_step_drain_harness", "main");
    sd_mkdir_p(dir);

    /* SetDataDir already clears the cache and populates cachedDataDirNet =
     * <dir>/regtest; do NOT ClearDataDirCache() here or GetDataDir falls back
     * to the shared default ~/.zclassic-c23/regtest and races other groups. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    sd_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    sd_mkdir_p(blocksdir);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    SD_CHECK("progress_store opens", store_ok);

    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    SD_CHECK("event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        SetDataDir(""); ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        printf("=== reducer step-drain harness: %d failures (setup) ===\n", failures);
        return failures;
    }


    struct main_state ms;
    main_state_init(&ms);

    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    SD_CHECK("genesis block_index inserted", genesis != NULL);
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
    SD_CHECK("all eight reducer stages init", stages_ok);
    SD_CHECK("seed genesis utxo_apply row",
             sd_seed_genesis_utxo_apply_row(progress_store_db()));
    SD_CHECK("tip_finalize anchor seed at genesis",
             tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    sqlite3 *db = progress_store_db();

    /* ── Mine ONE successor-less block (the `generate 1` scenario) ──────── */
    struct block blk1;
    int64_t cb_val = 0;
    bool built = stages_ok &&
                 sd_build_regtest_block(&blk1, 1, &genesis_hash, cp, &cb_val) &&
                 mine_block_pow(&blk1, 1, cp, 0);
    SD_CHECK("block 1 built + Equihash-mined", built);

    if (built) {
        struct uint256 h1;
        block_get_hash(&blk1, &h1);

        /* (1) Push the header EXACTLY like reducer_ingest_block: height=-1. */
        struct header_admit_msg m;
        memset(&m, 0, sizeof(m));
        m.hash = h1;
        m.has_header = true;
        m.header = blk1.header;
        m.height = -1;
        SD_CHECK("header pushed to admit inbox", mailbox_header_admit_push(&m));

        /* (2) Body-independent prefix: header_admit then validate_headers. */
        (void)header_admit_stage_drain(100);
        struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1);
        SD_CHECK("STEP header_admit: block_index for block 1 created", bi1 != NULL);
        SD_CHECK("STEP header_admit: best_header advanced to block 1 (L2.5)",
                 ms.pindex_best_header == bi1);

        (void)validate_headers_stage_drain(100);
        int64_t vh_ok = -1;
        bool vh_row = sd_log_int(db, "validate_headers_log", "ok", 1, &vh_ok);
        SD_CHECK("STEP validate_headers: row written ok=1 (header passes PoW)",
                 vh_row && vh_ok == 1);

        /* (3) Persist the body to disk + mark HAVE_DATA (reducer_persist step). */
        bool persisted = false;
        if (bi1) {
            struct disk_block_pos pos;
            disk_block_pos_init(&pos);
            persisted = write_block_to_disk(&blk1, &pos, netdir, cp->pchMessageStart) &&
                        block_index_set_have_data_verified(bi1, &pos, netdir);
        }
        SD_CHECK("STEP persist: body on disk + BLOCK_HAVE_DATA set",
                 persisted && bi1 && (bi1->nStatus & BLOCK_HAVE_DATA));

        /* (4) SINGLE-STEP the body-dependent stages, asserting each row. The
         * first stage to write ok=0 here is the bug. */
        (void)body_fetch_stage_step_once();
        int64_t bf_ok = -1; char bf_src[64] = {0};
        bool bf_row = sd_log_int(db, "body_fetch_log", "ok", 1, &bf_ok);
        (void)sd_log_text(db, "body_fetch_log", "source", 1, bf_src, sizeof(bf_src));
        SD_CHECK("STEP body_fetch: ok=1 source=disk (NOT skipped_invalid)",
                 bf_row && bf_ok == 1 && strcmp(bf_src, "disk") == 0);
        if (!(bf_row && bf_ok == 1))
            printf("  >> body_fetch row: found=%d ok=%lld source=%s\n",
                   (int)bf_row, (long long)bf_ok, bf_src);

        (void)body_persist_stage_step_once();
        int64_t bp_ok = -1; char bp_src[64] = {0};
        bool bp_row = sd_log_int(db, "body_persist_log", "ok", 1, &bp_ok);
        (void)sd_log_text(db, "body_persist_log", "source", 1, bp_src, sizeof(bp_src));
        SD_CHECK("STEP body_persist: ok=1 source=verified (NOT upstream_failed)",
                 bp_row && bp_ok == 1 && strcmp(bp_src, "verified") == 0);
        if (!(bp_row && bp_ok == 1))
            printf("  >> body_persist row: found=%d ok=%lld source=%s\n",
                   (int)bp_row, (long long)bp_ok, bp_src);

        (void)script_validate_stage_step_once();
        int64_t sv_ok = -1;
        bool sv_row = sd_log_int(db, "script_validate_log", "ok", 1, &sv_ok);
        SD_CHECK("STEP script_validate: ok=1 (coinbase-only, trivially valid)",
                 sv_row && sv_ok == 1);

        (void)proof_validate_stage_step_once();
        int64_t pv_ok = -1;
        bool pv_row = sd_log_int(db, "proof_validate_log", "ok", 1, &pv_ok);
        SD_CHECK("STEP proof_validate: ok=1 (no shielded proofs)",
                 pv_row && pv_ok == 1);

        (void)utxo_apply_stage_step_once();
        int64_t ua_ok = -1;
        bool ua_row = sd_log_int(db, "utxo_apply_log", "ok", 1, &ua_ok);
        SD_CHECK("STEP utxo_apply: ok=1 + succeeded_at(1) (coinbase added)",
                 ua_row && ua_ok == 1 && utxo_apply_stage_succeeded_at(1));

        /* Finalize block 1 the way reducer_ingest_block's L2 gate does, so the
         * single-stepped path lands a real tip at height 1. */
        (void)tip_finalize_stage_step_once();
        tip_finalize_stage_set_authoritative_tip(1, h1.data);
        SD_CHECK("single-stepped: tip advanced to height 1",
                 active_chain_height(&ms.chain_active) == 1);

        block_free(&blk1);
    }

    /* ── INTEGRATION: drive the REAL reducer_ingest_block on a SECOND
     * successor-less block (block 2 on top of the now-tip block 1). This is the
     * exact `generate` path — push(height=-1) + the two-drain sequence + the L2
     * finalize, all inside reducer_ingest_block — so if it diverges from the
     * single-stepped drive above, the bug is in the integration, not the
     * stages. ──────────────────────────────────────────────────────────── */
    if (stages_ok && active_chain_height(&ms.chain_active) == 1) {
        struct chain_activation_controller ctl;
        activation_controller_init(&ctl, &ms, NULL, cp, netdir);

        struct block_index *tip1 = active_chain_tip(&ms.chain_active);
        struct uint256 prev = tip1 && tip1->phashBlock ? *tip1->phashBlock
                                                        : genesis_hash;
        struct block blk2;
        int64_t cb2 = 0;
        bool built2 = sd_build_regtest_block(&blk2, 2, &prev, cp, &cb2) &&
                      mine_block_pow(&blk2, 2, cp, 0);
        SD_CHECK("block 2 built + mined (integration)", built2);

        if (built2) {
            int h_before = active_chain_height(&ms.chain_active);
            struct validation_state out;
            validation_state_init(&out);
            bool acc = reducer_ingest_block(&ctl, &blk2, REDUCER_SRC_MINED,
                                            true, &out);
            int h_after = active_chain_height(&ms.chain_active);
            SD_CHECK("INTEGRATION reducer_ingest_block(block 2) accepted", acc);
            SD_CHECK("INTEGRATION tip advanced 1 -> 2 via reducer_ingest_block",
                     h_after == 2);
            if (!acc || h_after != 2)
                printf("  >> integration: acc=%d h %d->%d reject=%s\n",
                       (int)acc, h_before, h_after,
                       out.reject_reason[0] ? out.reject_reason : "(none)");
            block_free(&blk2);
        }
        activation_controller_destroy(&ctl);
    }

    /* ── S1.4: mint-progress.log per-stage step-EWMA telemetry. -mint-anchor
     * producers run WITHOUT RPC, so dumpstate's stage_step_us_ewma() is
     * unreachable from them — this on-disk log line is the only offline
     * surface. Force one tick (throttle bypassed) after the eight stages
     * above have actually stepped, and assert the line names the slowest
     * stage + carries the full per-stage snapshot. start_us=0 keeps this
     * independent of GetTimeMicros/core/utiltime. ────────────────────────── */
    if (stages_ok) {
        char mint_log_path[512];
        snprintf(mint_log_path, sizeof(mint_log_path),
                "%s/mint-progress.log", dir);
        boot_mint_anchor_progress_log_tick_for_test(mint_log_path, 1, 2, 0,
                                                    /*force=*/true);

        FILE *mf = fopen(mint_log_path, "r");
        char line[512] = {0};
        char last_line[512] = {0};
        bool read_any = false;
        if (mf) {
            while (fgets(line, sizeof(line), mf)) {
                snprintf(last_line, sizeof(last_line), "%s", line);
                read_any = true;
            }
            fclose(mf);
        }
        SD_CHECK("mint-progress.log tick wrote a line", read_any);
        SD_CHECK("mint-progress.log line names the slowest stage (slow=)",
                 strstr(last_line, "slow=") != NULL);
        SD_CHECK("mint-progress.log line carries the 8-stage EWMA snapshot "
                 "(stages=[)",
                 strstr(last_line, "stages=[") != NULL);
    }

    /* ── teardown ──────────────────────────────────────────────────────── */
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

    printf("=== reducer step-drain harness: %d failures ===\n", failures);
    return failures;
}

/* ── Regression guard: regtest on-demand GENESIS SELF-SEED ────────────────────
 * The sibling harness above MANUALLY seeds the genesis anchor (the line the
 * import/snapshot/reindex paths run), so it cannot catch the regression where a
 * FRESH genesis-only regtest node fails to self-seed. Before the
 * fMineBlocksOnDemand-gated genesis-seed in reducer_ingest_block
 * (engine/reducer/services/src/reducer_ingest_service.c), the first `generate` on such a
 * node left utxo_apply unseeded (utx=-1) so the block never finalized
 * ("block-not-finalized-by-reducer", tip stuck at 0). This drives the REAL
 * reducer_ingest_block front door on an UNSEEDED genesis node (NO manual seed)
 * and asserts the ingest SELF-SEEDS genesis + advances the tip 0->1. If the fix
 * regresses, reducer_ingest_block(block 1) leaves the tip at 0 and this FAILS
 * loudly instead of silently regressing.
 * Hermetic in-process mirror of a copy-prove run (generate 5 -> 5,
 * rejects=0). */
int test_reducer_ondemand_genesis_seed(void);
int test_reducer_ondemand_genesis_seed(void)
{
    int failures = 0;

    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    SD_CHECK("regtest mines on demand (fMineBlocksOnDemand)",
             cp->fMineBlocksOnDemand);

    char dir[256];
    sd_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "reducer_ondemand_genesis_seed", "main");
    sd_mkdir_p(dir);
    /* SetDataDir already clears the cache and populates cachedDataDirNet =
     * <dir>/regtest; do NOT ClearDataDirCache() here or GetDataDir falls back
     * to the shared default ~/.zclassic-c23/regtest and races other groups. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    sd_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    sd_mkdir_p(blocksdir);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    SD_CHECK("progress_store opens", store_ok);
    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    SD_CHECK("event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        SetDataDir(""); ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        printf("=== reducer on-demand genesis-seed: %d failures (setup) ===\n",
               failures);
        return failures;
    }


    struct main_state ms;
    main_state_init(&ms);

    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    SD_CHECK("genesis block_index inserted", genesis != NULL);
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
    SD_CHECK("all eight reducer stages init", stages_ok);

    /* THE PRECONDITION that makes this a real guard: NOTHING seeded the genesis
     * anchor (no sd_seed_genesis_utxo_apply_row, no tip_finalize_stage_seed_anchor
     * — unlike the sibling harness). The cursor MUST be unseeded at genesis;
     * the fix is what seeds it from inside reducer_ingest_block. */
    SD_CHECK("precondition: tip is genesis (height 0)",
             active_chain_height(&ms.chain_active) == 0);
    SD_CHECK("precondition: tip_finalize cursor UNSEEDED (0)",
             tip_finalize_stage_cursor() == 0);

    if (stages_ok) {
        struct block blk1;
        int64_t cb_val = 0;
        bool built = sd_build_regtest_block(&blk1, 1, &genesis_hash, cp, &cb_val) &&
                     mine_block_pow(&blk1, 1, cp, 0);
        SD_CHECK("block 1 built + Equihash-mined", built);

        if (built) {
            struct chain_activation_controller ctl;
            activation_controller_init(&ctl, &ms, NULL, cp, netdir);
            struct validation_state out;
            validation_state_init(&out);

            int h_before = active_chain_height(&ms.chain_active);
            bool acc = reducer_ingest_block(&ctl, &blk1, REDUCER_SRC_MINED,
                                            true, &out);
            int h_after = active_chain_height(&ms.chain_active);

            SD_CHECK("reducer_ingest_block(block 1) accepted on UNSEEDED genesis",
                     acc);
            SD_CHECK("tip SELF-SEEDED + advanced 0 -> 1 (the fix; was utx=-1)",
                     h_after == 1);
            SD_CHECK("utxo_apply succeeded at height 1 (no utx=-1 reject)",
                     utxo_apply_stage_succeeded_at(1));
            SD_CHECK("tip_finalize cursor advanced past the genesis seed",
                     tip_finalize_stage_cursor() >= 1);
            if (!acc || h_after != 1)
                printf("  >> ondemand-seed: acc=%d h %d->%d reject=%s\n",
                       (int)acc, h_before, h_after,
                       out.reject_reason[0] ? out.reject_reason : "(none)");

            activation_controller_destroy(&ctl);
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

    printf("=== reducer on-demand genesis-seed: %d failures ===\n", failures);
    return failures;
}

/* ── Regression guard: MINT-FOLD LIVELOCK ────────────────────────
 * A single reducer_kick_unbudgeted call draining up to hard_cap(64) *
 * ZCL_REFOLD_DRAIN_BATCH(2000) = 128k blocks back-to-back with NO wall-clock
 * budget and NO frontier-progress check is unsafe. When the utxo_apply frontier is
 * WALLED at a low height (a bodiless/failed block) while header_admit /
 * validate_headers keeps advancing toward the mint ceiling, every round still
 * reports adv>0, so an unbudgeted kick can run for HOURS inside one call. The
 * boot_mint_anchor drive loop only logs progress and runs its 64-kick stall
 * detector BETWEEN kicks — so the process spins silently: no mint-progress.log
 * line, stall guard never runs — the tenacity doctrine's forbidden quiet stop.
 *
 * Scenario A (walled frontier): a synthetic header-only chain (no bodies) with
 * the mint ceiling armed and a small drain batch. One kick must RETURN having
 * NOT ground the whole upstream backlog (the frontier-stall convergence), so
 * the drive loop regains control. Then the drive loop's fail-closed reporter
 * must register the typed PERMANENT blocker `mint_fold.frontier_walled`
 * naming the walled stage (body_fetch here) with all eight cursors.
 *
 * Scenario B (healthy fold, no false-fire): one real mined regtest block
 * driven through the SAME reducer_kick_unbudgeted must still fold to the
 * ceiling (frontier advances; the new break must not truncate a healthy
 * fold), and a follow-up kick converges to 0. */

#include "config/boot.h"                /* boot_mint_anchor_report_frontier_walled */
#include "jobs/mint_fold_ceiling.h"     /* mint_fold_ceiling_set / _get */
#include "core/utiltime.h"              /* GetTimeMicros */
#include <stdlib.h>                     /* setenv / unsetenv */

static bool ml_stub_pass_validator(const struct block_index *bi,
                                   const char *datadir,
                                   char *out_reason, size_t out_reason_size,
                                   void *user)
{
    (void)bi; (void)datadir; (void)user;
    if (out_reason && out_reason_size) out_reason[0] = 0;
    return true;
}

#define ML_CHECK(name, expr) do {                              \
    printf("mint_fold_livelock: %s... ", (name));              \
    if ((expr)) printf("OK\n");                                \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

int test_mint_fold_livelock(void);
int test_mint_fold_livelock(void)
{
    int failures = 0;

    blocker_module_init();
    blocker_clear("mint_fold.frontier_walled");
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    /* ── Scenario A: walled frontier — the kick must return, not grind ──── */
    {
        enum { N = 64, BATCH = 4 };
        char dir[256];
        sd_mkdir_p("./test-tmp");
        test_fmt_tmpdir(dir, sizeof(dir), "mint_fold_livelock", "walled");
        sd_mkdir_p(dir);
        SetDataDir(dir);
        char netdir[512];
        GetDataDir(true, netdir, sizeof(netdir));
        sd_mkdir_p(netdir);

        progress_store_close();
        ML_CHECK("walled: progress store opens", progress_store_open(dir));

        struct main_state ms;
        main_state_init(&ms);

        /* Synthetic HEADER-ONLY chain: heights 0..N-1, hash-chained via pprev,
         * NO BLOCK_HAVE_DATA anywhere — body_fetch is walled at h=0 while
         * header_admit / validate_headers (stubbed validator: this guards the
         * DRAIN loop, not PoW) can march the whole backlog. */
        static struct block_index ml_blocks[N];
        static struct uint256     ml_hashes[N];
        for (int i = 0; i < N; i++) {
            block_index_init(&ml_blocks[i]);
            memset(&ml_hashes[i], 0, sizeof(ml_hashes[i]));
            ml_hashes[i].data[0] = (uint8_t)(i & 0xFF);
            ml_hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
            ml_hashes[i].data[2] = 0xA7;  /* tag distinct from other fixtures */
            ml_blocks[i].phashBlock = &ml_hashes[i];
            ml_blocks[i].hashBlock  = ml_hashes[i];
            ml_blocks[i].nHeight = i;
            ml_blocks[i].nVersion = 4;
            ml_blocks[i].nBits = 0x1f07ffff;
            if (i > 0) ml_blocks[i].pprev = &ml_blocks[i - 1];
        }
        active_chain_move_window_tip(&ms.chain_active, &ml_blocks[N - 1]);

        bool stages_ok =
            header_admit_stage_init(&ms) &&
            validate_headers_stage_init(&ms) &&
            body_fetch_stage_init(&ms) &&
            body_persist_stage_init(&ms) &&
            script_validate_stage_init(&ms) &&
            proof_validate_stage_init(&ms) &&
            utxo_apply_stage_init(&ms) &&
            tip_finalize_stage_init(&ms);
        ML_CHECK("walled: all eight stages init", stages_ok);
        validate_headers_stage_set_validator(ml_stub_pass_validator, NULL);

        /* Arm the mint context: ceiling at the synthetic tip (activates the
         * refold cadence) + a SMALL drain batch so one round cannot cover the
         * whole backlog (the regression signal below needs rounds << N). */
        setenv("ZCL_REFOLD_DRAIN_BATCH", "4", 1);
        mint_fold_ceiling_set(N - 1);

        struct chain_activation_controller ctl;
        activation_controller_init(&ctl, &ms, NULL, cp, netdir);

        uint64_t ua_before = utxo_apply_stage_cursor();
        struct reducer_drain_exit_stats des_before, des_after;
        reducer_drain_exit_stats_snapshot(&des_before);
        int64_t t0 = GetTimeMicros();
        int advanced = reducer_kick_unbudgeted(&ctl);
        int64_t elapsed_us = GetTimeMicros() - t0;
        reducer_drain_exit_stats_snapshot(&des_after);
        uint64_t ua_after = utxo_apply_stage_cursor();
        uint64_t ha_after = header_admit_stage_cursor();

        ML_CHECK("walled: kick advanced upstream work (adv>0)", advanced > 0);
        ML_CHECK("walled: frontier did NOT move (utxo_apply walled)",
                 ua_after == ua_before);
        /* Drain-exit telemetry (drive+fsync telemetry gap 1): the
         * frontier-stall break is deliberately bucketed into NEITHER
         * counter (see reducer_drain.c's doc comment) — it is a distinct
         * "walled fold" fact with its own dedicated signal
         * (mint_fold.frontier_walled below), not a throughput/convergence
         * one. This is the regression proof that a walled fold does NOT
         * masquerade as healthy convergence nor get misdiagnosed as an
         * IO/budget stall. */
        ML_CHECK("walled: frontier-stall break counts as NEITHER converged "
                 "nor budget",
                 des_after.exit_converged_total ==
                     des_before.exit_converged_total &&
                 des_after.exit_budget_total == des_before.exit_budget_total);
        ML_CHECK("walled: drain-exit stats record the round's own advances",
                 des_after.last_round_advances > 0);
        /* THE regression signal: with the frontier walled, the kick must
         * return at the first frontier-stalled round — one round admits at
         * most BATCH headers (+1 slack), nowhere near the N-header backlog.
         * Before the fix the kick ground the ENTIRE backlog (ha_after == N,
         * or hard_cap*batch rounds — hours at live scale) inside ONE call. */
        ML_CHECK("walled: kick returned after ONE round, backlog NOT ground",
                 ha_after <= (uint64_t)(2 * BATCH) && ha_after < (uint64_t)N);
        /* Wall ceiling scales with measured host load; nominal stays 60s. */
        struct test_budget kick_budget =
            test_budget_scale(UINT64_C(60LL * 1000 * 1000));
        ML_CHECK("walled: kick returned promptly (<60s wall clock)",
                 elapsed_us >= 0 &&
                 (uint64_t)elapsed_us < kick_budget.effective_us);
        if ((uint64_t)elapsed_us >= kick_budget.effective_us)
            printf("  >> walled TIMEOUT: elapsed=%lldus nominal_us=%llu "
                   "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
                   (long long)elapsed_us,
                   (unsigned long long)kick_budget.nominal_us,
                   (unsigned long long)kick_budget.effective_us,
                   kick_budget.factor,
                   (unsigned long long)kick_budget.calib_med_us);
        if (ha_after > (uint64_t)(2 * BATCH))
            printf("  >> walled: ha_after=%llu adv=%d elapsed=%lldus\n",
                   (unsigned long long)ha_after, advanced,
                   (long long)elapsed_us);

        /* False-fire proof: the walled frontier is a genuine wall (body_fetch
         * idle, utxo_apply idle), not a spin — the advance-or-blocker
         * reconciliation must NOT name any stage as spinning. header_admit /
         * validate_headers advance their OWN cursors (so they are progress, not
         * spin), and the frontier-stall break exits well before K rounds. */
        ML_CHECK("walled: no stage_spin_* blocker fired (no false-fire)",
                 sd_no_stage_spin_blocker());

        /* Fail-closed diagnosis: the drive loop's reporter must register the
         * typed PERMANENT blocker naming the walled stage with all cursors. */
        boot_mint_anchor_report_frontier_walled(progress_store_db(),
                                                (int32_t)ua_after - 1,
                                                N - 1, 64);
        ML_CHECK("walled: blocker mint_fold.frontier_walled registered",
                 blocker_exists("mint_fold.frontier_walled"));
        ML_CHECK("walled: blocker class is PERMANENT",
                 blocker_class_for("mint_fold.frontier_walled") ==
                     (int)BLOCKER_PERMANENT);
        {
            struct blocker_snapshot snaps[BLOCKER_CAP];
            int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
            bool found = false, wall_named = false, cursors_carried = false;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].id, "mint_fold.frontier_walled") != 0)
                    continue;
                found = true;
                wall_named = strstr(snaps[i].reason, "wall=body_fetch") != NULL;
                cursors_carried =
                    strstr(snaps[i].reason, "ha=") != NULL &&
                    strstr(snaps[i].reason, "ua=") != NULL &&
                    strstr(snaps[i].reason, "tf=") != NULL;
                if (!wall_named || !cursors_carried)
                    printf("  >> walled: blocker reason: %s\n",
                           snaps[i].reason);
            }
            ML_CHECK("walled: blocker names the walled stage (body_fetch)",
                     found && wall_named);
            ML_CHECK("walled: blocker reason carries the stage cursors",
                     found && cursors_carried);
        }

        /* teardown scenario A */
        mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);
        unsetenv("ZCL_REFOLD_DRAIN_BATCH");
        blocker_clear("mint_fold.frontier_walled");
        validate_headers_stage_set_validator(NULL, NULL);
        activation_controller_destroy(&ctl);
        tip_finalize_stage_shutdown();
        utxo_apply_stage_shutdown();
        proof_validate_stage_shutdown();
        script_validate_stage_shutdown();
        body_persist_stage_shutdown();
        body_fetch_stage_shutdown();
        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();
        test_cleanup_tmpdir(netdir);
        test_cleanup_tmpdir(dir);
        SetDataDir(""); ClearDataDirCache();
    }

    /* ── Scenario B: healthy one-block fold — no false-fire ─────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "mint_fold_livelock", "healthy");
        sd_mkdir_p(dir);
        SetDataDir(dir);
        char netdir[512];
        GetDataDir(true, netdir, sizeof(netdir));
        sd_mkdir_p(netdir);
        char blocksdir[640];
        snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
        sd_mkdir_p(blocksdir);

        progress_store_close();
        ML_CHECK("healthy: progress store opens", progress_store_open(dir));

        struct main_state ms;
        main_state_init(&ms);

        struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
        struct block_index *genesis = chainstate_insert_block_index(
            (struct chainstate *)&ms, &genesis_hash);
        ML_CHECK("healthy: genesis inserted", genesis != NULL);
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
        ML_CHECK("healthy: all eight stages init", stages_ok);
        ML_CHECK("healthy: genesis utxo row seeded",
                 sd_seed_genesis_utxo_apply_row(progress_store_db()));
        ML_CHECK("healthy: genesis anchor seeded",
                 tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

        struct block blk1;
        int64_t cb_val = 0;
        bool built = stages_ok &&
                     sd_build_regtest_block(&blk1, 1, &genesis_hash, cp,
                                            &cb_val) &&
                     mine_block_pow(&blk1, 1, cp, 0);
        ML_CHECK("healthy: block 1 built + mined", built);

        if (built) {
            struct uint256 h1;
            block_get_hash(&blk1, &h1);
            struct header_admit_msg m;
            memset(&m, 0, sizeof(m));
            m.hash = h1;
            m.has_header = true;
            m.header = blk1.header;
            m.height = -1;
            ML_CHECK("healthy: header pushed", mailbox_header_admit_push(&m));

            /* Header-first prefix (identical to the mint boot's admit), then
             * persist the body exactly like the harness above. */
            (void)header_admit_stage_drain(100);
            struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1);
            ML_CHECK("healthy: block 1 admitted", bi1 != NULL);
            bool persisted = false;
            if (bi1) {
                struct disk_block_pos pos;
                disk_block_pos_init(&pos);
                persisted = write_block_to_disk(&blk1, &pos, netdir,
                                                cp->pchMessageStart) &&
                            block_index_set_have_data_verified(bi1, &pos,
                                                               netdir);
            }
            ML_CHECK("healthy: body persisted", persisted);

            /* The mint context (ceiling at h=1) + the REAL unbudgeted kick.
             * The frontier-stall break must NOT truncate this healthy fold:
             * the kick folds block 1 through utxo_apply within the call. */
            mint_fold_ceiling_set(1);
            struct chain_activation_controller ctl;
            activation_controller_init(&ctl, &ms, NULL, cp, netdir);

            int advanced = reducer_kick_unbudgeted(&ctl);
            ML_CHECK("healthy: kick advanced (adv>0)", advanced > 0);
            ML_CHECK("healthy: utxo_apply folded block 1 (frontier moved)",
                     utxo_apply_stage_succeeded_at(1) &&
                     utxo_apply_stage_cursor() == 2);

            struct reducer_drain_exit_stats des_before, des_after;
            reducer_drain_exit_stats_snapshot(&des_before);
            int again = reducer_kick_unbudgeted(&ctl);
            reducer_drain_exit_stats_snapshot(&des_after);
            ML_CHECK("healthy: converged at the ceiling (second kick = 0)",
                     again == 0);
            /* Drain-exit telemetry (drive+fsync telemetry gap 1): a kick
             * that returns 0 (genuine convergence, no more work at the
             * ceiling) must land in exit_converged_total, NOT
             * exit_budget_total — the opposite of the walled-frontier
             * scenario above. */
            ML_CHECK("healthy: converged kick increments "
                     "exit_converged_total, not exit_budget_total",
                     des_after.exit_converged_total ==
                         des_before.exit_converged_total + 1 &&
                     des_after.exit_budget_total ==
                         des_before.exit_budget_total &&
                     des_after.last_round_advances == 0);

            /* False-fire proof (advance-or-blocker contract): a healthy fold
             * moves every advancing stage's own cursor, so the reconciliation
             * must NOT have named any stage as spinning. */
            ML_CHECK("healthy: no stage_spin_* blocker fired (no false-fire)",
                     sd_no_stage_spin_blocker());

            mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);
            activation_controller_destroy(&ctl);
            block_free(&blk1);
        }

        tip_finalize_stage_shutdown();
        utxo_apply_stage_shutdown();
        proof_validate_stage_shutdown();
        script_validate_stage_shutdown();
        body_persist_stage_shutdown();
        body_fetch_stage_shutdown();
        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();
        test_cleanup_tmpdir(blocksdir);
        test_cleanup_tmpdir(netdir);
        test_cleanup_tmpdir(dir);
        SetDataDir(""); ClearDataDirCache();
    }

    chain_params_select(CHAIN_MAIN);
    printf("=== mint-fold livelock guard: %d failures ===\n", failures);
    return failures;
}

/* ── Regression guard: ADVANCE-OR-BLOCKER contract (0.5) ──────────────────────
 * The drain core's per-round reconciliation: a stage that reports advances>0
 * while its OWN cursor never moves is, after K consecutive rounds, a named
 * "stage_spin_<name>" blocker (TRANSIENT, owner reducer_drain) carrying the
 * stage, round count, steps reported, and frozen cursor height — and cursor
 * movement clears it. This drives reducer_drain_spin_observe() directly (the
 * exact predicate the drain core applies per stage per round) with a synthetic
 * stub stage that reports advance=1 every round but leaves its cursor frozen,
 * so the contract is tested without spinning up the eight production stages. */
int test_reducer_drain_spin_contract(void);
int test_reducer_drain_spin_contract(void)
{
    int failures = 0;
    blocker_module_init();
    reducer_drain_spin_reset_for_testing();

    const int K = ZCL_STAGE_SPIN_ROUNDS_DEFAULT; /* compile-time default = 8 */
    const int idx = 0;
    const char *name = "teststage";
    const char *blk_id = "stage_spin_teststage";
    const uint64_t frozen = 100;

    /* Rounds 1..K-1: advance reported, cursor frozen — streak builds but has
     * NOT yet reached the threshold, so no blocker fires. */
    for (int r = 1; r < K; r++) {
        reducer_drain_spin_observe(idx, name, /*advance=*/1, frozen, frozen, K);
        char label[96];
        snprintf(label, sizeof(label),
                 "spin: no blocker before K (round %d/%d)", r, K);
        SD_CHECK(label, !blocker_exists(blk_id));
    }

    /* Round K: the K-th consecutive advance-yet-frozen round trips the blocker. */
    reducer_drain_spin_observe(idx, name, /*advance=*/1, frozen, frozen, K);
    SD_CHECK("spin: blocker stage_spin_teststage present at K rounds",
             blocker_exists(blk_id));
    SD_CHECK("spin: blocker class is TRANSIENT",
             blocker_class_for(blk_id) == (int)BLOCKER_TRANSIENT);

    /* Payload: names the stage, the round count, steps reported, frozen cursor,
     * and is owned by reducer_drain. */
    {
        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        bool found = false, has_stage = false, has_rounds = false,
             has_steps = false, has_height = false, owner_ok = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, blk_id) != 0)
                continue;
            found = true;
            has_stage  = strstr(snaps[i].reason, "stage=teststage") != NULL;
            has_rounds = strstr(snaps[i].reason, "consecutive drain rounds") != NULL;
            has_steps  = strstr(snaps[i].reason, "steps_reported=") != NULL;
            has_height = strstr(snaps[i].reason, "height 100") != NULL;
            owner_ok   = strcmp(snaps[i].owner_subsystem, "reducer_drain") == 0;
            if (!(has_stage && has_rounds && has_steps && has_height && owner_ok))
                printf("  >> spin: reason='%s' owner='%s'\n",
                       snaps[i].reason, snaps[i].owner_subsystem);
        }
        SD_CHECK("spin: payload names the stage", found && has_stage);
        SD_CHECK("spin: payload carries the round count", found && has_rounds);
        SD_CHECK("spin: payload carries steps_reported", found && has_steps);
        SD_CHECK("spin: payload carries the frozen cursor height",
                 found && has_height);
        SD_CHECK("spin: blocker owned by reducer_drain", found && owner_ok);
    }

    /* The dumpstate accessor reflects the streak while it stands. */
    {
        struct reducer_stage_spin_entry snap[REDUCER_DRAIN_NUM_STAGES];
        int m = reducer_drain_spin_snapshot(snap, REDUCER_DRAIN_NUM_STAGES);
        bool ok = (m >= 1) && snap[idx].rounds_frozen >= (uint32_t)K &&
                  snap[idx].steps_reported >= (uint64_t)K;
        SD_CHECK("spin: dumpstate accessor reports rounds_frozen>=K", ok);
    }

    /* Cursor movement clears the blocker and resets the streak. */
    reducer_drain_spin_observe(idx, name, /*advance=*/1, frozen, frozen + 1, K);
    SD_CHECK("spin: cursor movement clears the blocker",
             !blocker_exists(blk_id));
    {
        struct reducer_stage_spin_entry snap[REDUCER_DRAIN_NUM_STAGES];
        (void)reducer_drain_spin_snapshot(snap, REDUCER_DRAIN_NUM_STAGES);
        SD_CHECK("spin: streak reset after cursor movement",
                 snap[idx].rounds_frozen == 0);
    }

    reducer_drain_spin_reset_for_testing();
    printf("=== reducer drain spin contract: %d failures ===\n", failures);
    return failures;
}
