/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_matrix — the "we keep getting stuck" NEGATION (plan lane 2.2):
 * a boot (flag x datadir-state) matrix where EVERY cell terminates in a
 * NAMED terminal (preflight refusal / typed blocker id / anchor reached)
 * under a wall-clock budget. A timeout is scored as a test FAILURE, not a
 * skip — the whole point of this group is that a silent multi-hour grind
 * (a mint-fold livelock class) can never pass here quietly.
 *
 * Drives the REAL -mint-anchor entry functions in-process (no forked
 * binary): engine/composition/src/boot_mint_anchor_preflight.c's
 * boot_mint_anchor_preflight_run_all (the exact call engine/entry/main.c makes
 * before -mint-anchor is allowed to touch the datadir) and the same
 * reducer_kick_unbudgeted drive loop boot_mint_anchor_run uses. Reuses the
 * synthetic-datadir fixture idioms from test_mint_anchor_fresh_datadir.c
 * (scenarios a/b/c) and the hermetic-override idiom (point
 * ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR at a guaranteed-empty directory so a
 * dev box's real $HOME/.zclassic/blocks cannot make the test non-hermetic)
 * plus the skip/no-snapshot fixture-selection pattern from
 * test_chainstate_legacy_reader.c.
 *
 * Six highest-value cells:
 *
 *   1. -mint-anchor      x fresh (empty datadir)        -> preflight_refusal
 *   2. -mint-anchor      x headers-only (no bodies)      -> blocker_frontier_walled
 *   3. -mint-anchor      x imported+bodies               -> anchor_reached
 *   4. -mint-anchor-fast x fresh (empty datadir)         -> preflight_refusal
 *   5. preflight run-all x fresh, natural legacy source  -> preflight_refusal
 *   6. preflight run-all x fresh, EXPLICITLY EMPTY legacy
 *      source (ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR)     -> preflight_refusal
 *
 * -mint-anchor and -mint-anchor-fast share the SAME preflight gate
 * (engine/entry/main.c: `if (ctx.mint_anchor && !boot_mint_anchor_preflight_run_all(...))
 * return 1;` runs regardless of ctx.mint_anchor_fast — the fast/skip-crypto
 * toggle only changes what happens INSIDE a fold that reaches app_init, never
 * the preflight gate), so cells 1, 4, 5, 6 all exercise
 * boot_mint_anchor_preflight_run_all with different datadir/env shapes; cell
 * 4 additionally arms mint_skip_crypto to prove doing so does not change the
 * fresh-datadir terminal. Cells 2/3 exercise the post-preflight fold drive.
 *
 * Each cell records its (flag, datadir-state, terminal, elapsed, budget) into
 * a summary table printed at the end so the whole matrix reads as one glance.
 *
 * make t ONLY=boot_matrix
 */

#include "test/test_core.h"
#include "test/test_timing_budget.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "config/boot.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "domain/consensus/coinbase.h"
#include "json/json.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/chain_activation_service.h"
#include "services/header_admit_inbox.h"
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
#include "jobs/mint_fold_ceiling.h"
#include "jobs/mint_skip_crypto.h"
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BM_CHECK(name, expr) do {                              \
    printf("boot_matrix: %s... ", (name));                     \
    if ((expr)) printf("OK\n");                                \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

static int bm_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── shared JSON report helpers (same idiom as test_mint_anchor_fresh_datadir.c) */

static const struct json_value *bm_find_check(const struct json_value *report,
                                              const char *name)
{
    const struct json_value *checks = json_get(report, "checks");
    if (!checks)
        return NULL;
    for (size_t i = 0; i < json_size(checks); i++) {
        const struct json_value *row = json_at(checks, i);
        const struct json_value *row_name = row ? json_get(row, "name") : NULL;
        const char *n = row_name ? json_get_str(row_name) : NULL;
        if (n && strcmp(n, name) == 0)
            return row;
    }
    return NULL;
}

static bool bm_check_ok(const struct json_value *report, const char *name)
{
    const struct json_value *row = bm_find_check(report, name);
    const struct json_value *ok = row ? json_get(row, "ok") : NULL;
    return ok && json_get_bool(ok);
}

/* ── matrix summary table ─────────────────────────────────────────────── */

#define BM_MAX_CELLS 8

struct bm_cell_result {
    const char *flag;
    const char *datadir_state;
    const char *terminal;
    double      elapsed_s;
    bool        within_budget;
};

static struct bm_cell_result g_bm_results[BM_MAX_CELLS];
static int g_bm_num_results = 0;

static void bm_record(const char *flag, const char *datadir_state,
                      const char *terminal, int64_t elapsed_us,
                      int64_t budget_us)
{
    if (g_bm_num_results >= BM_MAX_CELLS)
        return;
    struct bm_cell_result *r = &g_bm_results[g_bm_num_results++];
    r->flag = flag;
    r->datadir_state = datadir_state;
    r->terminal = terminal;
    r->elapsed_s = (double)elapsed_us / 1e6;
    r->within_budget = elapsed_us < budget_us;
}

static void bm_print_matrix(void)
{
    printf("\n=== boot_matrix summary (flag x datadir-state -> named terminal) ===\n");
    for (int i = 0; i < g_bm_num_results; i++) {
        const struct bm_cell_result *r = &g_bm_results[i];
        printf("  [%-17s x %-22s] -> %-24s %7.2fs %s\n",
               r->flag, r->datadir_state, r->terminal, r->elapsed_s,
               r->within_budget ? "(budget OK)" : "(TIMEOUT)");
    }
    printf("=== %d/%d cells recorded ===\n", g_bm_num_results, BM_MAX_CELLS);
}

/* ── Cell 1: -mint-anchor x fresh (empty datadir) → preflight_refusal ────
 * Exercises the EXACT gate engine/entry/main.c runs before -mint-anchor touches the
 * datadir: `if (ctx.mint_anchor && !boot_mint_anchor_preflight_run_all(...))
 * return 1;`. Hermetic: point the legacy-blocks fallback at a guaranteed-
 * empty directory so a dev box's real $HOME/.zclassic/blocks cannot leak
 * into the verdict. */

#define BM_1_BUDGET_US (10ll * 1000 * 1000)  /* 10s: pure read-only checks */

static int bm_cell1_mint_anchor_fresh(void)
{
    int failures = 0;
    char dir[256];
    bm_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "boot_matrix", "1_mint_anchor_fresh");
    bm_mkdir_p(dir);

    char empty_legacy[300];
    snprintf(empty_legacy, sizeof(empty_legacy), "%s/empty-legacy", dir);
    bm_mkdir_p(empty_legacy);
    setenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR", empty_legacy, 1);

    struct json_value report;
    json_init(&report);

    int64_t t0 = GetTimeMicros();
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    int64_t elapsed_us = GetTimeMicros() - t0;
    unsetenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");

    /* Wall ceiling scales with measured host load; nominal stays 10s. */
    struct test_budget budget_1 = test_budget_scale((uint64_t)BM_1_BUDGET_US);
    BM_CHECK("(1) terminal reached under wall-clock budget (<10s)",
              (uint64_t)elapsed_us < budget_1.effective_us);
    if ((uint64_t)elapsed_us >= budget_1.effective_us)
        printf("  >> (1) TIMEOUT: elapsed=%lldus nominal_us=%llu "
               "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)budget_1.nominal_us,
               (unsigned long long)budget_1.effective_us,
               budget_1.factor,
               (unsigned long long)budget_1.calib_med_us);

    BM_CHECK("(1) named terminal = preflight_refusal (all_ok=false)", !all_ok);

    bm_record("-mint-anchor", "fresh", "preflight_refusal", elapsed_us,
              (int64_t)budget_1.effective_us);

    json_free(&report);
    rmdir(empty_legacy);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── shared stage-harness plumbing (lifted from test_mint_anchor_fresh_datadir.c
 * / test_mint_fold_livelock, itself from test_reducer_step_drain_harness.c) ── */

static bool bm_seed_genesis_utxo_apply_row(sqlite3 *db)
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

static bool bm_stub_pass_validator(const struct block_index *bi,
                                   const char *datadir,
                                   char *out_reason, size_t out_reason_size,
                                   void *user)
{
    (void)bi; (void)datadir; (void)user;
    if (out_reason && out_reason_size) out_reason[0] = 0;
    return true;
}

/* ── Cell 2: -mint-anchor x headers-only (no bodies) → blocker_frontier_walled
 * header_admit / validate_headers
 * can march the whole backlog while body_fetch is walled at h=0. A bounded
 * number of reducer_kick_unbudgeted calls must converge inside the budget,
 * then the fail-closed reporter registers the typed PERMANENT blocker. */

#define BM_2_BUDGET_US   (30ll * 1000 * 1000)  /* 30s: an unbounded grind can run HOURS */
#define BM_2_MAX_KICKS   8

static int bm_cell2_mint_anchor_headers_only(void)
{
    int failures = 0;
    enum { N = 64, BATCH = 4 };

    blocker_module_init();
    blocker_clear("mint_fold.frontier_walled");
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    bm_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "boot_matrix", "2_headers_only");
    bm_mkdir_p(dir);
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    bm_mkdir_p(netdir);

    progress_store_close();
    BM_CHECK("(2) progress store opens", progress_store_open(dir));

    struct main_state ms;
    main_state_init(&ms);

    /* Synthetic HEADER-ONLY chain: heights 0..N-1, hash-chained via pprev, NO
     * BLOCK_HAVE_DATA anywhere — mirrors an --importblockindex-style datadir
     * that has the legacy header chain but no fetched bodies yet. */
    static struct block_index bm_blocks[N];
    static struct uint256     bm_hashes[N];
    for (int i = 0; i < N; i++) {
        block_index_init(&bm_blocks[i]);
        memset(&bm_hashes[i], 0, sizeof(bm_hashes[i]));
        bm_hashes[i].data[0] = (uint8_t)(i & 0xFF);
        bm_hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
        bm_hashes[i].data[2] = 0xB4;  /* tag distinct from other fixtures */
        bm_blocks[i].phashBlock = &bm_hashes[i];
        bm_blocks[i].hashBlock  = bm_hashes[i];
        bm_blocks[i].nHeight = i;
        bm_blocks[i].nVersion = 4;
        bm_blocks[i].nBits = 0x1f07ffff;
        if (i > 0) bm_blocks[i].pprev = &bm_blocks[i - 1];
    }
    active_chain_move_window_tip(&ms.chain_active, &bm_blocks[N - 1]);

    bool stages_ok =
        header_admit_stage_init(&ms) &&
        validate_headers_stage_init(&ms) &&
        body_fetch_stage_init(&ms) &&
        body_persist_stage_init(&ms) &&
        script_validate_stage_init(&ms) &&
        proof_validate_stage_init(&ms) &&
        utxo_apply_stage_init(&ms) &&
        tip_finalize_stage_init(&ms);
    BM_CHECK("(2) all eight reducer stages init", stages_ok);
    validate_headers_stage_set_validator(bm_stub_pass_validator, NULL);

    char batch_str[16];
    snprintf(batch_str, sizeof(batch_str), "%d", BATCH);
    setenv("ZCL_REFOLD_DRAIN_BATCH", batch_str, 1);
    mint_fold_ceiling_set(N - 1);

    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, &ms, NULL, cp, netdir);

    uint64_t ua_before = utxo_apply_stage_cursor();
    uint64_t ua_prev = ua_before;
    int kicks_run = 0;
    bool frontier_converged = false;
    int64_t t0 = GetTimeMicros();
    for (; kicks_run < BM_2_MAX_KICKS; kicks_run++) {
        int advanced = reducer_kick_unbudgeted(&ctl);
        uint64_t ua_now = utxo_apply_stage_cursor();
        if (advanced == 0 || ua_now == ua_prev) {
            frontier_converged = true;
            kicks_run++;
            break;
        }
        ua_prev = ua_now;
    }
    int64_t elapsed_us = GetTimeMicros() - t0;
    uint64_t ua_after = utxo_apply_stage_cursor();
    uint64_t ha_after = header_admit_stage_cursor();

    /* Wall ceiling scales with measured host load; nominal stays 30s. */
    struct test_budget budget_2 = test_budget_scale((uint64_t)BM_2_BUDGET_US);
    BM_CHECK("(2) terminal reached under wall-clock budget (<30s)",
              (uint64_t)elapsed_us < budget_2.effective_us);
    if ((uint64_t)elapsed_us >= budget_2.effective_us)
        printf("  >> (2) TIMEOUT: elapsed=%lldus nominal_us=%llu "
               "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)budget_2.nominal_us,
               (unsigned long long)budget_2.effective_us,
               budget_2.factor,
               (unsigned long long)budget_2.calib_med_us);
    BM_CHECK("(2) frontier converged within a bounded number of kicks",
              frontier_converged && kicks_run <= BM_2_MAX_KICKS);
    BM_CHECK("(2) utxo_apply frontier did NOT reach the ceiling (walled)",
              ua_after == ua_before);
    BM_CHECK("(2) upstream backlog NOT ground (ha_after well under N)",
              ha_after < (uint64_t)N);

    boot_mint_anchor_report_frontier_walled(progress_store_db(),
                                            (int32_t)ua_after - 1, N - 1, 64);
    bool blocker_ok = blocker_exists("mint_fold.frontier_walled") &&
        blocker_class_for("mint_fold.frontier_walled") ==
            (int)BLOCKER_PERMANENT;
    BM_CHECK("(2) named terminal = blocker_frontier_walled, class PERMANENT",
              blocker_ok);

    bm_record("-mint-anchor", "headers-only",
              blocker_ok ? "blocker_frontier_walled" : "UNNAMED(BUG)",
              elapsed_us, (int64_t)budget_2.effective_us);

    /* teardown */
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
    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* One-coinbase regtest block, real merkle root, regtest powLimit nBits.
 * Identical shape to test_mint_anchor_fresh_datadir.c's mfd_build_regtest_block. */
static bool bm_build_regtest_block(struct block *blk, int height,
                                   const struct uint256 *prev_hash,
                                   const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "bm_vtx");
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
        miner_script.data[3 + i] = (unsigned char)(0x20 + i);
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

    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1700000000u + (uint32_t)height;

    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return true;
}

/* ── Cell 3: -mint-anchor x imported+bodies → anchor_reached ─────────────
 * The healthy-fold path: mirrors test_mint_anchor_fresh_datadir.c scenario
 * (c). Proves the frontier-stall break exercised by cell 2 does NOT
 * false-fire and truncate a datadir that actually has everything it needs —
 * the fold reaches the (tiny) ceiling and CONVERGES with no blocker. */

#define BM_3_BUDGET_US (15ll * 1000 * 1000)  /* 15s: one Equihash-mined block */

static int bm_cell3_mint_anchor_imported_bodies(void)
{
    int failures = 0;

    blocker_module_init();
    blocker_clear("mint_fold.frontier_walled");
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    bm_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "boot_matrix", "3_imported_bodies");
    bm_mkdir_p(dir);
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    bm_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    bm_mkdir_p(blocksdir);

    progress_store_close();
    BM_CHECK("(3) progress store opens", progress_store_open(dir));

    struct main_state ms;
    main_state_init(&ms);

    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    BM_CHECK("(3) genesis inserted", genesis != NULL);
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
    BM_CHECK("(3) all eight reducer stages init", stages_ok);
    BM_CHECK("(3) genesis utxo row seeded",
              bm_seed_genesis_utxo_apply_row(progress_store_db()));
    BM_CHECK("(3) genesis anchor seeded",
              tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    int64_t t0 = GetTimeMicros();
    bool terminal_is_anchor_reached = false;
    bool blocker_absent_at_end = false;

    struct block blk1;
    bool built = stages_ok &&
                 bm_build_regtest_block(&blk1, 1, &genesis_hash, cp) &&
                 mine_block_pow(&blk1, 1, cp, 0);
    BM_CHECK("(3) block 1 built + Equihash-mined", built);

    if (built) {
        struct uint256 h1;
        block_get_hash(&blk1, &h1);
        struct header_admit_msg m;
        memset(&m, 0, sizeof(m));
        m.hash = h1;
        m.has_header = true;
        m.header = blk1.header;
        m.height = -1;
        BM_CHECK("(3) header pushed", mailbox_header_admit_push(&m));

        (void)header_admit_stage_drain(100);
        struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1);
        BM_CHECK("(3) block 1 admitted", bi1 != NULL);

        bool persisted = false;
        if (bi1) {
            struct disk_block_pos pos;
            disk_block_pos_init(&pos);
            persisted = write_block_to_disk(&blk1, &pos, netdir,
                                            cp->pchMessageStart) &&
                        block_index_set_have_data_verified(bi1, &pos, netdir);
        }
        BM_CHECK("(3) body persisted (this datadir HAS its bodies)", persisted);

        mint_fold_ceiling_set(1);
        struct chain_activation_controller ctl;
        activation_controller_init(&ctl, &ms, NULL, cp, netdir);

        int advanced = reducer_kick_unbudgeted(&ctl);
        BM_CHECK("(3) kick advanced the fold (adv>0)", advanced > 0);
        terminal_is_anchor_reached =
            utxo_apply_stage_succeeded_at(1) &&
            utxo_apply_stage_cursor() == 2;
        BM_CHECK("(3) utxo_apply folded block 1 (frontier reached ceiling)",
                  terminal_is_anchor_reached);

        int again = reducer_kick_unbudgeted(&ctl);
        BM_CHECK("(3) converged at the ceiling (follow-up kick advances 0)",
                  again == 0);

        blocker_absent_at_end = !blocker_exists("mint_fold.frontier_walled");
        BM_CHECK("(3) NO frontier_walled blocker (no false-fire on a "
                  "healthy fold)", blocker_absent_at_end);

        mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);
        activation_controller_destroy(&ctl);
        block_free(&blk1);
    }

    int64_t elapsed_us = GetTimeMicros() - t0;
    /* Wall ceiling scales with measured host load; nominal stays 15s. */
    struct test_budget budget_3 = test_budget_scale((uint64_t)BM_3_BUDGET_US);
    BM_CHECK("(3) terminal reached under wall-clock budget (<15s)",
              (uint64_t)elapsed_us < budget_3.effective_us);
    if ((uint64_t)elapsed_us >= budget_3.effective_us)
        printf("  >> (3) TIMEOUT: elapsed=%lldus nominal_us=%llu "
               "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)budget_3.nominal_us,
               (unsigned long long)budget_3.effective_us,
               budget_3.factor,
               (unsigned long long)budget_3.calib_med_us);
    bool terminal_ok = terminal_is_anchor_reached && blocker_absent_at_end;
    BM_CHECK("(3) named terminal = anchor_reached, no blocker at end",
              terminal_ok);

    bm_record("-mint-anchor", "imported+bodies",
              terminal_ok ? "anchor_reached" : "UNNAMED(BUG)",
              elapsed_us, (int64_t)budget_3.effective_us);

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
    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* ── Cell 4: -mint-anchor-fast x fresh (empty datadir) → preflight_refusal
 * -mint-anchor-fast is honored ONLY together with -mint-anchor (engine/entry/main.c)
 * and shares the SAME preflight gate. Arm mint_skip_crypto the same way
 * boot_mint_anchor_reset does under ctx->mint_anchor, and prove doing so does
 * NOT change the fresh-datadir terminal — the toggle only affects the fold
 * driven AFTER app_init, which a refused preflight never reaches. */

#define BM_4_BUDGET_US (10ll * 1000 * 1000)  /* 10s: pure read-only checks */

static int bm_cell4_mint_anchor_fast_fresh(void)
{
    int failures = 0;
    char dir[256];
    bm_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "boot_matrix", "4_mint_anchor_fast_fresh");
    bm_mkdir_p(dir);

    char empty_legacy[300];
    snprintf(empty_legacy, sizeof(empty_legacy), "%s/empty-legacy", dir);
    bm_mkdir_p(empty_legacy);
    setenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR", empty_legacy, 1);

    mint_skip_crypto_set(true);
    BM_CHECK("(4) mint_skip_crypto armed (mirrors -mint-anchor-fast)",
              mint_skip_crypto_get());

    struct json_value report;
    json_init(&report);

    int64_t t0 = GetTimeMicros();
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    int64_t elapsed_us = GetTimeMicros() - t0;
    unsetenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");

    mint_skip_crypto_set(false);
    BM_CHECK("(4) mint_skip_crypto disarmed after cell (no leak to later cells)",
              !mint_skip_crypto_get());

    /* Wall ceiling scales with measured host load; nominal stays 10s. */
    struct test_budget budget_4 = test_budget_scale((uint64_t)BM_4_BUDGET_US);
    BM_CHECK("(4) terminal reached under wall-clock budget (<10s)",
              (uint64_t)elapsed_us < budget_4.effective_us);
    if ((uint64_t)elapsed_us >= budget_4.effective_us)
        printf("  >> (4) TIMEOUT: elapsed=%lldus nominal_us=%llu "
               "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)budget_4.nominal_us,
               (unsigned long long)budget_4.effective_us,
               budget_4.factor,
               (unsigned long long)budget_4.calib_med_us);
    BM_CHECK("(4) named terminal = preflight_refusal (all_ok=false, "
              "unaffected by the skip-crypto toggle)", !all_ok);

    bm_record("-mint-anchor-fast", "fresh", "preflight_refusal", elapsed_us,
              (int64_t)budget_4.effective_us);

    json_free(&report);
    rmdir(empty_legacy);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── Cell 5: preflight run-all x fresh, NATURAL legacy source → refusal ──
 * Deliberately does NOT override ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR — this
 * cell exercises the DEFAULT fallback path (a real $HOME/.zclassic/blocks on
 * a dev box, if any). The overall refusal is still hermetic on any machine:
 * legacy_block_index_covers_anchor ALWAYS fails on a fresh datadir with no
 * node.db, independent of whatever the legacy bodies check finds, so all_ok
 * is guaranteed false regardless of box state. */

#define BM_5_BUDGET_US (10ll * 1000 * 1000)  /* 10s: pure read-only checks */

static int bm_cell5_preflight_fresh_natural(void)
{
    int failures = 0;
    char dir[256];
    bm_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "boot_matrix", "5_preflight_fresh_natural");
    bm_mkdir_p(dir);

    unsetenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");

    struct json_value report;
    json_init(&report);

    int64_t t0 = GetTimeMicros();
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    int64_t elapsed_us = GetTimeMicros() - t0;

    /* Wall ceiling scales with measured host load; nominal stays 10s. */
    struct test_budget budget_5 = test_budget_scale((uint64_t)BM_5_BUDGET_US);
    BM_CHECK("(5) terminal reached under wall-clock budget (<10s)",
              (uint64_t)elapsed_us < budget_5.effective_us);
    if ((uint64_t)elapsed_us >= budget_5.effective_us)
        printf("  >> (5) TIMEOUT: elapsed=%lldus nominal_us=%llu "
               "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)budget_5.nominal_us,
               (unsigned long long)budget_5.effective_us,
               budget_5.factor,
               (unsigned long long)budget_5.calib_med_us);
    BM_CHECK("(5) named terminal = preflight_refusal (all_ok=false, "
              "guaranteed by legacy_block_index_covers_anchor alone)", !all_ok);
    BM_CHECK("(5) legacy_block_index_covers_anchor named+failed",
              bm_find_check(&report, "legacy_block_index_covers_anchor") &&
              !bm_check_ok(&report, "legacy_block_index_covers_anchor"));

    bm_record("preflight-run-all", "fresh(natural-src)", "preflight_refusal",
              elapsed_us, (int64_t)budget_5.effective_us);

    json_free(&report);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── Cell 6: preflight run-all x fresh, EXPLICITLY EMPTY legacy source ───
 * Forces both legacy_block_index_covers_anchor AND bodies_present_sampled to
 * fail in the SAME call, a composed hole that two separate single-check
 * failures across two separate runs (a FATAL, then later a silent stall)
 * would otherwise surface only individually. */

#define BM_6_BUDGET_US (10ll * 1000 * 1000)  /* 10s: pure read-only checks */

static int bm_cell6_preflight_fresh_empty_legacy(void)
{
    int failures = 0;
    char dir[256];
    bm_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "boot_matrix", "6_preflight_empty_legacy");
    bm_mkdir_p(dir);

    char empty_legacy[300];
    snprintf(empty_legacy, sizeof(empty_legacy), "%s/empty-legacy", dir);
    bm_mkdir_p(empty_legacy);
    setenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR", empty_legacy, 1);

    struct json_value report;
    json_init(&report);

    int64_t t0 = GetTimeMicros();
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    int64_t elapsed_us = GetTimeMicros() - t0;
    unsetenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");

    /* Wall ceiling scales with measured host load; nominal stays 10s. */
    struct test_budget budget_6 = test_budget_scale((uint64_t)BM_6_BUDGET_US);
    BM_CHECK("(6) terminal reached under wall-clock budget (<10s)",
              (uint64_t)elapsed_us < budget_6.effective_us);
    if ((uint64_t)elapsed_us >= budget_6.effective_us)
        printf("  >> (6) TIMEOUT: elapsed=%lldus nominal_us=%llu "
               "effective_us=%llu load_factor=%.2f calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)budget_6.nominal_us,
               (unsigned long long)budget_6.effective_us,
               budget_6.factor,
               (unsigned long long)budget_6.calib_med_us);
    BM_CHECK("(6) named terminal = preflight_refusal (all_ok=false)", !all_ok);
    BM_CHECK("(6) legacy_block_index_covers_anchor named+failed",
              bm_find_check(&report, "legacy_block_index_covers_anchor") &&
              !bm_check_ok(&report, "legacy_block_index_covers_anchor"));
    BM_CHECK("(6) bodies_present_sampled ALSO named+failed in the SAME call",
              bm_find_check(&report, "bodies_present_sampled") &&
              !bm_check_ok(&report, "bodies_present_sampled"));

    bm_record("preflight-run-all", "fresh+empty-legacy-src",
              "preflight_refusal", elapsed_us, (int64_t)budget_6.effective_us);

    json_free(&report);
    rmdir(empty_legacy);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_boot_matrix(void);
int test_boot_matrix(void)
{
    int failures = 0;
    printf("\n=== test_boot_matrix: every (flag x datadir-state) cell ends "
           "in a NAMED terminal under a wall-clock budget — a TIMEOUT is a "
           "FAILURE, never a skip ===\n");

    failures += bm_cell1_mint_anchor_fresh();
    failures += bm_cell2_mint_anchor_headers_only();
    failures += bm_cell3_mint_anchor_imported_bodies();
    failures += bm_cell4_mint_anchor_fast_fresh();
    failures += bm_cell5_preflight_fresh_natural();
    failures += bm_cell6_preflight_fresh_empty_legacy();

    bm_print_matrix();
    printf("=== test_boot_matrix complete: %d failure(s) ===\n", failures);
    return failures;
}
