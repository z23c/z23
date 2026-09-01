/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mint_anchor_fresh_datadir — the COMPOSITION test: a fresh datadir
 * driven through the
 * REAL -mint-anchor path (preflight -> reducer drive) must ALWAYS end in a
 * named terminal state, never a silent timeout/stall/FATAL-cascade. Each
 * scenario below wraps the drive in a wall-clock budget and asserts BOTH (1)
 * the budget was not exceeded and (2) the outcome is one of the states the
 * design allows for that scenario. A timeout is scored as a FAILURE, not a
 * skip — that is the whole point: this test catches a mint-fold livelock
 * (a silent multi-hour grind with zero progress-log output) because scenario
 * (b) below bounds the SAME walled-frontier shape to <30s wall clock.
 *
 * Reuses fixtures rather than inventing new synthesis, per plan:
 *   - engine/composition/src/boot_mint_anchor_preflight.c's boot_mint_anchor_preflight_run_all
 *     (unit-style direct call — no forked binary) for scenario (a), same
 *     pattern as test_mint_anchor_preflight.c's fresh-datadir case.
 *   - the header-only synthetic-chain + reducer_kick_unbudgeted +
 *     boot_mint_anchor_report_frontier_walled harness from
 *     test_mint_fold_livelock (test_reducer_step_drain_harness.c scenario A)
 *     for scenario (b).
 *   - the single-mined-block healthy-fold harness from test_mint_fold_livelock
 *     scenario B for scenario (c).
 *
 * Scenarios:
 *   (a) COMPLETELY fresh empty datadir: boot_mint_anchor_preflight_run_all
 *       refuses (all_ok=false) and names at least the legacy-block-index
 *       hole — terminal = "preflight_refusal".
 *   (b) Synthetic imported datadir: headers admitted, NO bodies. Driving the
 *       fold converges to a stalled frontier within a bounded number of
 *       kicks; the typed PERMANENT blocker mint_fold.frontier_walled is
 *       registered naming wall=body_fetch — terminal = "blocker_frontier_walled".
 *   (c) Synthetic datadir with headers+one body, ceiling=1: the healthy fold
 *       reaches the ceiling and CONVERGES (a follow-up kick advances
 *       nothing) with NO blocker registered — terminal = "anchor_reached".
 *
 * make t ONLY=mint_anchor_fresh_datadir
 */

#include "test/test_core.h"

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

#define MFD_CHECK(name, expr) do {                             \
    printf("mint_anchor_fresh_datadir: %s... ", (name));        \
    if ((expr)) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

static int mfd_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── shared JSON report helpers (same idiom as test_mint_anchor_preflight.c) */

static const struct json_value *mfd_find_check(const struct json_value *report,
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

static bool mfd_check_ok(const struct json_value *report, const char *name)
{
    const struct json_value *row = mfd_find_check(report, name);
    const struct json_value *ok = row ? json_get(row, "ok") : NULL;
    return ok && json_get_bool(ok);
}

/* ── Scenario (a): completely fresh empty datadir ─────────────────────────
 * Calls boot_mint_anchor_preflight_run_all DIRECTLY (unit-style, no forked
 * binary) — this IS the -mint-anchor entry path's first gate
 * (engine/composition/src/boot_mint_anchor.c calls this before any datadir mutation). */

#define MFD_A_BUDGET_US (10ll * 1000 * 1000)  /* 10s: pure read-only checks */

static int test_mfd_scenario_a_fresh_empty_preflight_refuses(void)
{
    int failures = 0;
    char dir[256];
    mfd_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_fresh_datadir", "a_empty");
    mfd_mkdir_p(dir);

    /* Hermetic: the bodies check falls back to the legacy zclassicd source
     * ($HOME/.zclassic/blocks), which exists on a dev box — point it at an
     * empty dir so "fresh" means fresh everywhere. */
    char empty_legacy[300];
    snprintf(empty_legacy, sizeof(empty_legacy), "%s/empty-legacy", dir);
    mfd_mkdir_p(empty_legacy);
    setenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR", empty_legacy, 1);

    struct json_value report;
    json_init(&report);

    int64_t t0 = GetTimeMicros();
    bool all_ok = boot_mint_anchor_preflight_run_all(dir, &report);
    int64_t elapsed_us = GetTimeMicros() - t0;
    unsetenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");

    MFD_CHECK("(a) terminal reached under wall-clock budget (<10s)",
              elapsed_us < MFD_A_BUDGET_US);
    if (elapsed_us >= MFD_A_BUDGET_US)
        printf("  >> (a) TIMEOUT: elapsed=%lldus budget=%lldus\n",
               (long long)elapsed_us, MFD_A_BUDGET_US);

    MFD_CHECK("(a) named terminal = preflight_refusal (all_ok=false)", !all_ok);
    MFD_CHECK("(a) report.all_ok field agrees (false)",
              json_get(&report, "all_ok") &&
              !json_get_bool(json_get(&report, "all_ok")));
    MFD_CHECK("(a) legacy_block_index_covers_anchor named+failed (the hole "
              "that used to surface as a bare FATAL on its own run)",
              mfd_find_check(&report, "legacy_block_index_covers_anchor") &&
              !mfd_check_ok(&report, "legacy_block_index_covers_anchor"));
    MFD_CHECK("(a) bodies_present_sampled ALSO named+failed in the SAME call "
              "(the hole that used to surface as a silent stall later)",
              mfd_find_check(&report, "bodies_present_sampled") &&
              !mfd_check_ok(&report, "bodies_present_sampled"));

    json_free(&report);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── shared stage-harness plumbing (lifted from test_mint_fold_livelock /
 * test_reducer_step_drain_harness.c) ─────────────────────────────────────── */

static bool mfd_seed_genesis_utxo_apply_row(sqlite3 *db)
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

static bool mfd_stub_pass_validator(const struct block_index *bi,
                                    const char *datadir,
                                    char *out_reason, size_t out_reason_size,
                                    void *user)
{
    (void)bi; (void)datadir; (void)user;
    if (out_reason && out_reason_size) out_reason[0] = 0;
    return true;
}

/* ── Scenario (b): synthetic imported datadir, headers-only, NO bodies ───
 * header_admit / validate_headers
 * can march the whole backlog while body_fetch is walled at h=0. A bounded
 * number of reducer_kick_unbudgeted calls must converge (frontier stops
 * moving) inside the wall-clock budget, then the drive loop's fail-closed
 * reporter must register the typed PERMANENT blocker naming the wall. */

#define MFD_B_BUDGET_US   (30ll * 1000 * 1000)  /* 30s: the incident ran HOURS */
#define MFD_B_MAX_KICKS   8

static int test_mfd_scenario_b_headers_no_bodies_walls_frontier(void)
{
    int failures = 0;
    enum { N = 64, BATCH = 4 };

    blocker_module_init();
    blocker_clear("mint_fold.frontier_walled");
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    mfd_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_fresh_datadir", "b_walled");
    mfd_mkdir_p(dir);
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    mfd_mkdir_p(netdir);

    progress_store_close();
    MFD_CHECK("(b) progress store opens", progress_store_open(dir));

    struct main_state ms;
    main_state_init(&ms);

    /* Synthetic HEADER-ONLY chain: heights 0..N-1, hash-chained via pprev, NO
     * BLOCK_HAVE_DATA anywhere — mirrors an --importblockindex-style datadir
     * that has the legacy header chain but no fetched bodies yet. */
    static struct block_index mfd_blocks[N];
    static struct uint256     mfd_hashes[N];
    for (int i = 0; i < N; i++) {
        block_index_init(&mfd_blocks[i]);
        memset(&mfd_hashes[i], 0, sizeof(mfd_hashes[i]));
        mfd_hashes[i].data[0] = (uint8_t)(i & 0xFF);
        mfd_hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
        mfd_hashes[i].data[2] = 0xE2;  /* tag distinct from other fixtures */
        mfd_blocks[i].phashBlock = &mfd_hashes[i];
        mfd_blocks[i].hashBlock  = mfd_hashes[i];
        mfd_blocks[i].nHeight = i;
        mfd_blocks[i].nVersion = 4;
        mfd_blocks[i].nBits = 0x1f07ffff;
        if (i > 0) mfd_blocks[i].pprev = &mfd_blocks[i - 1];
    }
    active_chain_move_window_tip(&ms.chain_active, &mfd_blocks[N - 1]);

    bool stages_ok =
        header_admit_stage_init(&ms) &&
        validate_headers_stage_init(&ms) &&
        body_fetch_stage_init(&ms) &&
        body_persist_stage_init(&ms) &&
        script_validate_stage_init(&ms) &&
        proof_validate_stage_init(&ms) &&
        utxo_apply_stage_init(&ms) &&
        tip_finalize_stage_init(&ms);
    MFD_CHECK("(b) all eight reducer stages init", stages_ok);
    validate_headers_stage_set_validator(mfd_stub_pass_validator, NULL);

    char batch_str[16];
    snprintf(batch_str, sizeof(batch_str), "%d", BATCH);
    setenv("ZCL_REFOLD_DRAIN_BATCH", batch_str, 1);
    mint_fold_ceiling_set(N - 1);

    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, &ms, NULL, cp, netdir);

    /* Drive a BOUNDED number of kicks — exactly what boot_mint_anchor's real
     * drive loop does between its own stall-detector checks — and time the
     * WHOLE loop. The regression this guards: before the fix, a single kick
     * could grind the entire upstream backlog (hours) with zero progress
     * output; here the frontier must stop moving well inside the budget. */
    uint64_t ua_before = utxo_apply_stage_cursor();
    uint64_t ua_prev = ua_before;
    int kicks_run = 0;
    bool frontier_converged = false;
    int64_t t0 = GetTimeMicros();
    for (; kicks_run < MFD_B_MAX_KICKS; kicks_run++) {
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

    MFD_CHECK("(b) terminal reached under wall-clock budget (<30s)",
              elapsed_us < MFD_B_BUDGET_US);
    if (elapsed_us >= MFD_B_BUDGET_US)
        printf("  >> (b) TIMEOUT: elapsed=%lldus budget=%lldus kicks=%d\n",
               (long long)elapsed_us, MFD_B_BUDGET_US, kicks_run);
    MFD_CHECK("(b) frontier converged within a bounded number of kicks",
              frontier_converged && kicks_run <= MFD_B_MAX_KICKS);
    MFD_CHECK("(b) utxo_apply frontier did NOT reach the ceiling (walled)",
              ua_after == ua_before);
    /* THE incident signal: header_admit must NOT have ground the entire N-
     * header backlog inside the bounded drive — nowhere near N. */
    MFD_CHECK("(b) upstream backlog NOT ground (ha_after well under N)",
              ha_after < (uint64_t)N);
    if (ha_after >= (uint64_t)N)
        printf("  >> (b) ha_after=%llu (N=%d) — backlog was ground\n",
               (unsigned long long)ha_after, N);

    /* Fail-closed diagnosis: exactly what the real drive loop does once its
     * own stall counter trips — register the typed PERMANENT blocker. */
    boot_mint_anchor_report_frontier_walled(progress_store_db(),
                                            (int32_t)ua_after - 1, N - 1, 64);
    MFD_CHECK("(b) named terminal = blocker_frontier_walled (registered)",
              blocker_exists("mint_fold.frontier_walled"));
    MFD_CHECK("(b) blocker class is PERMANENT (needs an operator, not a retry)",
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
                printf("  >> (b) blocker reason: %s\n", snaps[i].reason);
        }
        MFD_CHECK("(b) blocker names the exact walled stage (body_fetch)",
                  found && wall_named);
        MFD_CHECK("(b) blocker reason carries all eight stage cursors",
                  found && cursors_carried);
    }

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
 * Identical shape to test_reducer_step_drain_harness.c's sd_build_regtest_block. */
static bool mfd_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "mfd_vtx");
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

/* ── Scenario (c): synthetic datadir with headers+ONE body, tiny ceiling ──
 * The healthy-fold path: mirrors test_mint_fold_livelock scenario B. Proves
 * the frontier-stall break added for scenario (b) does NOT false-fire and
 * truncate a datadir that actually has everything it needs — the fold must
 * reach the (tiny) ceiling and CONVERGE with no blocker registered. */

#define MFD_C_BUDGET_US (15ll * 1000 * 1000)  /* 15s: one Equihash-mined block */

static int test_mfd_scenario_c_headers_and_bodies_reaches_ceiling(void)
{
    int failures = 0;

    blocker_module_init();
    blocker_clear("mint_fold.frontier_walled");
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    mfd_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "mint_anchor_fresh_datadir", "c_healthy");
    mfd_mkdir_p(dir);
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    mfd_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    mfd_mkdir_p(blocksdir);

    progress_store_close();
    MFD_CHECK("(c) progress store opens", progress_store_open(dir));

    struct main_state ms;
    main_state_init(&ms);

    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    MFD_CHECK("(c) genesis inserted", genesis != NULL);
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
    MFD_CHECK("(c) all eight reducer stages init", stages_ok);
    MFD_CHECK("(c) genesis utxo row seeded",
              mfd_seed_genesis_utxo_apply_row(progress_store_db()));
    MFD_CHECK("(c) genesis anchor seeded",
              tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    int64_t t0 = GetTimeMicros();
    bool terminal_is_anchor_reached = false;
    bool blocker_absent_at_end = false;

    struct block blk1;
    bool built = stages_ok &&
                 mfd_build_regtest_block(&blk1, 1, &genesis_hash, cp) &&
                 mine_block_pow(&blk1, 1, cp, 0);
    MFD_CHECK("(c) block 1 built + Equihash-mined", built);

    if (built) {
        struct uint256 h1;
        block_get_hash(&blk1, &h1);
        struct header_admit_msg m;
        memset(&m, 0, sizeof(m));
        m.hash = h1;
        m.has_header = true;
        m.header = blk1.header;
        m.height = -1;
        MFD_CHECK("(c) header pushed", mailbox_header_admit_push(&m));

        (void)header_admit_stage_drain(100);
        struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1);
        MFD_CHECK("(c) block 1 admitted", bi1 != NULL);

        bool persisted = false;
        if (bi1) {
            struct disk_block_pos pos;
            disk_block_pos_init(&pos);
            persisted = write_block_to_disk(&blk1, &pos, netdir,
                                            cp->pchMessageStart) &&
                        block_index_set_have_data_verified(bi1, &pos, netdir);
        }
        MFD_CHECK("(c) body persisted (this datadir HAS its bodies)", persisted);

        /* The real -mint-anchor drive: ceiling at h=1, drive via the SAME
         * reducer_kick_unbudgeted used in scenario (b). This datadir has
         * everything the fold needs, so it must reach the ceiling — the
         * scenario-(b) frontier-stall break must NOT truncate it. */
        mint_fold_ceiling_set(1);
        struct chain_activation_controller ctl;
        activation_controller_init(&ctl, &ms, NULL, cp, netdir);

        int advanced = reducer_kick_unbudgeted(&ctl);
        MFD_CHECK("(c) kick advanced the fold (adv>0)", advanced > 0);
        terminal_is_anchor_reached =
            utxo_apply_stage_succeeded_at(1) &&
            utxo_apply_stage_cursor() == 2;
        MFD_CHECK("(c) utxo_apply folded block 1 (frontier reached ceiling)",
                  terminal_is_anchor_reached);

        int again = reducer_kick_unbudgeted(&ctl);
        MFD_CHECK("(c) converged at the ceiling (follow-up kick advances 0)",
                  again == 0);

        blocker_absent_at_end = !blocker_exists("mint_fold.frontier_walled");
        MFD_CHECK("(c) NO frontier_walled blocker (no false-fire on a "
                  "healthy fold)", blocker_absent_at_end);

        mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);
        activation_controller_destroy(&ctl);
        block_free(&blk1);
    }

    int64_t elapsed_us = GetTimeMicros() - t0;
    MFD_CHECK("(c) terminal reached under wall-clock budget (<15s)",
              elapsed_us < MFD_C_BUDGET_US);
    if (elapsed_us >= MFD_C_BUDGET_US)
        printf("  >> (c) TIMEOUT: elapsed=%lldus budget=%lldus\n",
               (long long)elapsed_us, MFD_C_BUDGET_US);
    MFD_CHECK("(c) named terminal = anchor_reached, no blocker at end",
              terminal_is_anchor_reached && blocker_absent_at_end);

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

int test_mint_anchor_fresh_datadir(void);
int test_mint_anchor_fresh_datadir(void)
{
    int failures = 0;
    printf("\n=== test_mint_anchor_fresh_datadir: a fresh -mint-anchor "
           "datadir ALWAYS ends in a named terminal (never a silent "
           "timeout/stall) ===\n");

    failures += test_mfd_scenario_a_fresh_empty_preflight_refuses();
    failures += test_mfd_scenario_b_headers_no_bodies_walls_frontier();
    failures += test_mfd_scenario_c_headers_and_bodies_reaches_ceiling();

    printf("=== test_mint_anchor_fresh_datadir complete: %d failure(s) ===\n",
           failures);
    return failures;
}
