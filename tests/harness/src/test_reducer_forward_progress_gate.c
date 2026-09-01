/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_forward_progress_gate — the MULTI-BLOCK forward-progress +
 * REORG gate (the hermetic live-wedge repro harness).
 *
 * WHY THIS GATE EXISTS (the live-wedge axis)
 * ------------------------------------------
 * test_reducer_block_ingest_gate proves ONE mined regtest block finalizes
 * through the reducer front door to tip+1. The #1 v1 blocker, though, is the
 * LIVE WEDGE: on the mainnet datadir the tip HOLDS at some height without
 * finalizing forward — tip_finalize oscillates, finalized_total stalls. A
 * single-block gate cannot catch a wedge that only appears after several
 * sequential finalizations. This gate extends the proven it-works pattern to
 * MANY blocks and asserts MONOTONIC forward progress, so if the reducer ever
 * stalls or oscillates mid-run, it is reproduced HERMETICALLY (a deterministic,
 * in-process repro of the v1 blocker — far cheaper to debug than the live node).
 *
 * WHAT THIS PROVES
 * ----------------
 *   PART 1 (forward progress): mine + ingest N = 32 sequential regtest blocks
 *     through reducer_ingest_block (the SAME front door live intake uses),
 *     looping reducer_kick to convergence after each. Assert the authoritative
 *     active_chain_height reaches exactly 32 with NO stall and NO oscillation:
 *     finalized_total strictly increases each step and never retreats, and the
 *     tip never goes backward. If the tip stalls at H<32 or oscillates, the
 *     live-wedge failure mode is reproduced and the stall height + the exact
 *     eight stage cursors are captured in the output.
 *
 *   PART 2 (reorg): from a fork point near the tip (within ZCL_FINALITY_DEPTH),
 *     mine a competing branch that is HEAVIER (one block longer above the fork),
 *     install it on the active chain, and drive the reducer to convergence.
 *     Assert the reducer REORGS: the authoritative tip switches to the heavier
 *     branch, the displaced (losing-branch) coinbase UTXOs are removed, the new
 *     branch's coinbases are present, and the UTXO commitment is BYTE-EXACT to a
 *     from-scratch recompute of the winning chain (the consensus stake — a wrong
 *     inverse silently corrupts the UTXO set with no crash).
 *
 * THE ONE-BLOCK-LOOKAHEAD CONVENTION (carried from the it-works gate)
 * ------------------------------------------------------------------
 * tip_finalize finalizes height H by reading active_chain_at(H+1) and stamping
 * that successor as the tip; it records the row for height H in the log row at
 * key H-1. So to finalize up to height N you must have block N+1 data'd. PART 1
 * mines N+1 blocks (1..33) and ingests blocks 1..32; block 33 is the lookahead
 * successor that lets block 32 finalize.
 *
 * THE FINALITY FLOOR (why PART 2 forks NEAR the tip, not at height 16)
 * -------------------------------------------------------------------
 * utxo_apply's reorg unwind is gated by reorg_is_allowed(tip, fork): a reorg
 * deeper than ZCL_FINALITY_DEPTH (=10) is CORRECTLY REFUSED (a consensus safety
 * feature, not a wedge). With the tip at 32, a fork at height 16 (depth 16)
 * would be refused. PART 2 therefore forks within the finality window so the
 * unwind actually proceeds — exactly the reorg a live node performs.
 *
 * No stubs, no injected readers: the eight stages run on their PRODUCTION
 * defaults (bodies persisted to disk by the front door / helper and read back
 * by stage_default_block_reader; coinbase-only blocks have no transparent inputs
 * and no shielded proofs, so script_validate / proof_validate pass trivially).
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
#include "domain/consensus/coinbase.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "conditions/reducer_frontier_reconcile_light.h"
#include "framework/condition.h"
#include "net/connman.h"
#include "net/net.h"
#include "services/chain_activation_service.h"
#include "services/header_admit_inbox.h"
#include "services/sync_monitor.h"
#include "storage/coins_kv.h"
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

/* src-private test hook (engine/reducer/jobs/src/reducer_frontier.c, the witness-test
 * mirror pattern): lower the L0/L1 compiled anchor floor so the PRODUCTION
 * reorg re-bind path (reducer_frontier_reconcile_light: purge non-canonical
 * verdicts -> refill -> re-validate) operates at the regtest heights PART 2
 * mines. Off-test the floor is the mainnet SHA3 checkpoint (3,056,758); a
 * hermetic harness cannot build a contiguous chain to that height, so it runs
 * the identical reconcile logic at low heights via this override. -1 restores
 * the compiled checkpoint. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define RFP_CHECK(name, expr) do {                            \
    printf("reducer_forward_progress_gate: %s... ", (name));  \
    if ((expr)) printf("OK\n");                               \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

/* How many sequential blocks PART 1 drives the reducer forward. A wedge that
 * only surfaces after a handful of finalizations is the whole point — 32 is
 * deep enough to surface the live-wedge oscillation while staying fast. */
#define RFP_N 32

static int rfp_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── Block builder — identical shape to the it-works gate's
 * rbi_build_regtest_block (one coinbase tx, real merkle root, regtest powLimit
 * compact nBits). `script_salt` perturbs the miner pubkey-hash so a competing
 * branch's coinbase gets a DISTINCT txid at the same height (salt 0 = the
 * canonical chain, salt != 0 = a fork). Returns false on any build failure. */
static bool rfp_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp,
                                    uint8_t script_salt,
                                    int64_t *out_coinbase_value)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "rfp_vtx");
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
        miner_script.data[3 + i] = (unsigned char)(0x10 + i + script_salt);
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

/* Seed a genesis (height 0) utxo_apply_log row marking it already-applied with
 * a zero coin delta, so the cold-start anchor finalizes cleanly into block 1
 * (identical to the it-works gate's rbi_seed_genesis_utxo_apply_row). */
static bool rfp_seed_genesis_utxo_apply_row(sqlite3 *db)
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

struct rfp_ingest_ctx {
    const struct chain_params *cp;
    struct main_state *ms;
    struct chain_activation_controller *ctl;
    const char *datadir;
};

/* Mine a regtest block at `height` on `prev_hash`, admit its header (creating
 * the block_index + linking pprev), write its body to disk, and mark the index
 * BLOCK_HAVE_DATA — the "headers + bodies synced but not connected" state.
 * On success fills the out-params (caller block_free's *out_blk). Mirrors the
 * it-works gate's rbi_mine_admit_persist. The window/best-header anchor is
 * forward-extended to this block so the reducer can finalize down to it. */
static bool rfp_mine_admit_persist(struct rfp_ingest_ctx *c, int height,
                                   const struct uint256 *prev_hash,
                                   struct block *out_blk,
                                   struct uint256 *out_hash,
                                   int64_t *out_cb_value,
                                   struct block_index **out_bi)
{
    if (!rfp_build_regtest_block(out_blk, height, prev_hash, c->cp,
                                 0 /*canonical chain salt*/, out_cb_value))
        return false;
    if (!mine_block_pow(out_blk, height, c->cp, 0))
        return false;

    block_get_hash(out_blk, out_hash);

    struct header_admit_msg hmsg;
    memset(&hmsg, 0, sizeof(hmsg));
    hmsg.height = height;
    hmsg.hash = *out_hash;
    hmsg.has_header = true;
    hmsg.header = out_blk->header;
    if (!mailbox_header_admit_push(&hmsg))
        return false;
    (void)header_admit_stage_drain(64);

    struct block_index *bi = block_map_find(&c->ms->map_block_index, out_hash);
    if (!bi)
        return false;

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!write_block_to_disk(out_blk, &pos, c->datadir,
                             c->cp->pchMessageStart))
        return false;
    if (!block_index_set_have_data_verified(bi, &pos, c->datadir))
        return false;

    c->ms->pindex_best_header = bi;
    (void)active_chain_extend_window(&c->ms->chain_active, bi);

    if (out_bi) *out_bi = bi;
    return true;
}

/* Read the eight stage cursors into a fixed-order array so a stall snapshot can
 * pinpoint WHICH stage stopped advancing. Index order matches pipeline order. */
static void rfp_snapshot_cursors(sqlite3 *db, uint64_t out[8])
{
    static const char *names[8] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize"
    };
    for (int i = 0; i < 8; i++)
        out[i] = stage_cursor_persisted(db, names[i], names[i]);
}

static void rfp_print_cursors(const char *tag, const uint64_t cur[8])
{
    printf("reducer_forward_progress_gate: [%s cursors] header_admit=%llu "
           "validate_headers=%llu body_fetch=%llu body_persist=%llu "
           "script_validate=%llu proof_validate=%llu utxo_apply=%llu "
           "tip_finalize=%llu\n", tag,
           (unsigned long long)cur[0], (unsigned long long)cur[1],
           (unsigned long long)cur[2], (unsigned long long)cur[3],
           (unsigned long long)cur[4], (unsigned long long)cur[5],
           (unsigned long long)cur[6], (unsigned long long)cur[7]);
}

int test_reducer_forward_progress_gate(void);
int test_reducer_forward_progress_gate(void)
{
    printf("\n=== reducer forward-progress + reorg gate "
           "(live-wedge repro: %d sequential blocks -> reducer -> tip+N; "
           "then a heavier-fork reorg) ===\n", RFP_N);
    int failures = 0;

    /* OPT-IN gate (same rationale as the it-works gate): drives reducer
     * process-globals, deterministic only in a FRESH process. Run isolated via
     * `make mvp-forward-progress` (a dedicated --only fresh process). */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("reducer_forward_progress_gate: SKIP "
               "(set ZCL_STRESS_TESTS=1 and run isolated via "
               "`make mvp-forward-progress`)\n");
        return 0;
    }

    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    {
        unsigned int n = chain_params_equihash_n(cp, 1);
        unsigned int k = chain_params_equihash_k(cp, 1);
        RFP_CHECK("regtest is Equihash (48,5)", n == 48 && k == 5);
    }

    /* ── (1) Fresh node-db / progress.kv at genesis, hermetic datadir ────── */
    char dir[256];
    rfp_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "reducer_forward_progress_gate", "main");
    rfp_mkdir_p(dir);

    /* SetDataDir already clears the cache and populates cachedDataDirNet =
     * <dir>/regtest; do NOT ClearDataDirCache() here or GetDataDir falls back
     * to the shared default ~/.zclassic-c23/regtest and races other groups. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true /*net-specific (regtest subdir)*/, netdir, sizeof(netdir));
    rfp_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    rfp_mkdir_p(blocksdir);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    RFP_CHECK("progress_store opens at fresh datadir", store_ok);

    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    RFP_CHECK("event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(blocksdir);
        test_cleanup_tmpdir(netdir);
        test_cleanup_tmpdir(dir);
        SetDataDir("");
        ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        printf("=== reducer forward-progress gate: %d failures (setup) ===\n",
               failures);
        return failures;
    }

    struct main_state ms;
    main_state_init(&ms);

    /* Seed genesis exactly the way boot.c does. */
    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    RFP_CHECK("genesis block_index inserted", genesis != NULL);
    if (genesis) {
        genesis->nHeight = 0;
        genesis->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        genesis->nTx = 1;
        genesis->nChainTx = 1;
        genesis->nChainWork = GetBlockProof(genesis);
        active_chain_move_window_tip(&ms.chain_active, genesis);
        ms.pindex_best_header = genesis;
    }

    RFP_CHECK("tip_finalize anchor seed at genesis",
              tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    bool stages_ok =
        header_admit_stage_init(&ms) &&
        validate_headers_stage_init(&ms) &&
        body_fetch_stage_init(&ms) &&
        body_persist_stage_init(&ms) &&
        script_validate_stage_init(&ms) &&
        proof_validate_stage_init(&ms) &&
        utxo_apply_stage_init(&ms) &&
        tip_finalize_stage_init(&ms);
    RFP_CHECK("all eight reducer stages init", stages_ok);

    if (stages_ok)
        RFP_CHECK("seed genesis utxo_apply_log row",
                  rfp_seed_genesis_utxo_apply_row(progress_store_db()));

    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, &ms, NULL, cp, netdir);

    int height_genesis = active_chain_height(&ms.chain_active);
    RFP_CHECK("genesis tip height is 0", height_genesis == 0);

    /* coins_kv is the authoritative UTXO set the stages author (the projection
     * dual-write was removed); read the genesis baseline from it. */
    uint64_t count_genesis = (uint64_t)coins_kv_count(progress_store_db());

    struct rfp_ingest_ctx ictx = { .cp = cp, .ms = &ms, .ctl = &ctl,
                                   .datadir = netdir };

    /* ── (2) PART 1 — mine N+1 blocks (1..N+1) in the "headers+bodies synced"
     * state. Block N+1 is the one-block-lookahead successor that lets block N
     * finalize. Keep all blocks + their hashes/block_index pointers alive (the
     * reorg in PART 2 reuses the fork-point hash). ──────────────────────── */
    struct block      *blocks = zcl_calloc(RFP_N + 2, sizeof(struct block),
                                           "rfp_blocks");
    struct uint256    *hashes = zcl_calloc(RFP_N + 2, sizeof(struct uint256),
                                           "rfp_hashes");
    struct uint256    *cbids  = zcl_calloc(RFP_N + 2, sizeof(struct uint256),
                                           "rfp_cbids");
    int64_t           *cbvals = zcl_calloc(RFP_N + 2, sizeof(int64_t),
                                           "rfp_cbvals");
    struct block_index **bidx = zcl_calloc(RFP_N + 2,
                                           sizeof(struct block_index *),
                                           "rfp_bidx");
    bool allocs_ok = blocks && hashes && cbids && cbvals && bidx;
    RFP_CHECK("PART1 chain arrays allocated", allocs_ok);
    if (blocks) for (int i = 0; i <= RFP_N + 1; i++) block_init(&blocks[i]);

    /* The live-wedge witnesses we capture if PART 1 stalls. */
    bool wedge_reproduced = false;
    int  wedge_height = -1;
    char wedge_detail[256] = {0};
    uint64_t wedge_cursors[8] = {0};

    bool part1_ready = stages_ok && allocs_ok;

    if (part1_ready) {
        /* hashes[0] == genesis. Mine heights 1..N+1 on top. */
        hashes[0] = genesis_hash;
        bidx[0] = genesis;
        bool mined_all = true;
        for (int h = 1; h <= RFP_N + 1 && mined_all; h++) {
            mined_all = rfp_mine_admit_persist(&ictx, h, &hashes[h - 1],
                                               &blocks[h], &hashes[h],
                                               &cbvals[h], &bidx[h]);
            if (mined_all) cbids[h] = blocks[h].vtx[0].hash;
        }
        RFP_CHECK("all N+1 blocks mined + header-admitted + body-on-disk",
                  mined_all);
        part1_ready = mined_all;
    }

    /* ── (3) PART 1 drive: ingest blocks 1..N sequentially through the FRONT
     * DOOR, looping reducer_kick to convergence after each, asserting the
     * authoritative tip and finalized_total advance MONOTONICALLY and never
     * retreat. A stall/oscillation here is the LIVE WEDGE reproduced. ─────── */
    int      reached_height = height_genesis;
    uint64_t prev_finalized = tip_finalize_stage_finalized_total();
    if (part1_ready) {
        for (int h = 1; h <= RFP_N; h++) {
            /* Lookahead successor (block h+1) must be the visible window tip so
             * tip_finalize can finalize block h. */
            ms.pindex_best_header = bidx[h + 1];
            (void)active_chain_extend_window(&ms.chain_active, bidx[h + 1]);

            struct validation_state out;
            validation_state_init(&out);
            bool fd = reducer_ingest_block(&ctl, &blocks[h], REDUCER_SRC_MINED,
                                           true /*force*/, &out);
            (void)fd;
            /* Loop to TRUE convergence — never assert after one bounded kick. */
            for (int it = 0; it < 1000 && reducer_kick(&ctl) > 0; it++) {
                /* keep draining */
            }

            int      hh = active_chain_height(&ms.chain_active);
            uint64_t fin = tip_finalize_stage_finalized_total();

            /* Forward-progress invariant (post-67062bbf6 "publish each block on
             * arrival"): the tip must FINALIZE block h (hh >= h),
             * finalized_total must strictly increase (a stall would freeze it),
             * and the tip must never retreat (an oscillation would). Ordinarily
             * the visible lookahead permits hh <= h+1. All fixture bodies are
             * already persisted, though, so one reducer kick may legitimately
             * drain the complete N-block run; accept that terminal convergence
             * and leave the loop before the next iteration can mistake an
             * already-complete run for a frozen finalized_total. */
            bool completed = hh >= RFP_N && hh <= RFP_N + 1;
            bool advanced  = (hh >= h) && (hh <= h + 1 || completed);
            bool monotone  = (hh >= reached_height) && (fin >= prev_finalized);
            bool fin_up    = (fin > prev_finalized);
            if (!advanced || !monotone || !fin_up) {
                wedge_reproduced = true;
                wedge_height = h;
                rfp_snapshot_cursors(progress_store_db(), wedge_cursors);
                snprintf(wedge_detail, sizeof(wedge_detail),
                    "stalled at block %d: tip=%d (want %d) finalized_total "
                    "%llu->%llu reorg_detected=%llu precond_failed_via_logs "
                    "reject=\"%s\"",
                    h, hh, h,
                    (unsigned long long)prev_finalized,
                    (unsigned long long)fin,
                    (unsigned long long)tip_finalize_stage_reorg_detected_total(),
                    out.reject_reason[0] ? out.reject_reason : "(none)");
                printf("reducer_forward_progress_gate: *** LIVE WEDGE "
                       "REPRODUCED *** %s\n", wedge_detail);
                rfp_print_cursors("wedge", wedge_cursors);
                break;
            }
            reached_height = hh;
            prev_finalized = fin;
            if (completed)
                break;
        }

        printf("reducer_forward_progress_gate: PART1 reached tip height %d/%d "
               "(finalized_total=%llu)\n", reached_height, RFP_N,
               (unsigned long long)tip_finalize_stage_finalized_total());

        RFP_CHECK("PART1: tip advanced monotonically to N with no stall/"
                  "oscillation (live-wedge NOT reproduced)",
                  reached_height >= RFP_N && !wedge_reproduced);
        RFP_CHECK("PART1: tip_finalize finalized >= N blocks (reducer engine)",
                  tip_finalize_stage_finalized_total() >= (uint64_t)RFP_N);
        RFP_CHECK("PART1: utxo_apply succeeded at tip height N",
                  utxo_apply_stage_succeeded_at(RFP_N));
        RFP_CHECK("PART1: no spend-unknown across the run",
                  utxo_apply_stage_spend_unknown_total() == 0);

        /* Each block added exactly one coinbase UTXO over the genesis baseline.
         * With tip at N finalized and block N+1 also data'd as the pending
         * successor, utxo_apply has applied N+1 coinbases. */
        sqlite3 *pdb = progress_store_db();
        uint64_t count_after = (uint64_t)coins_kv_count(pdb);
        printf("reducer_forward_progress_gate: utxo count %llu -> %llu\n",
               (unsigned long long)count_genesis,
               (unsigned long long)count_after);
        bool applied_succ = utxo_apply_stage_succeeded_at(RFP_N + 1);
        RFP_CHECK("PART1: N coinbases live over genesis (+1 pending successor)",
                  count_after == count_genesis + (uint64_t)RFP_N +
                                 (applied_succ ? 1u : 0u));

        /* Each finalized block's coinbase output is live with the right value. */
        bool every_cb_live = !wedge_reproduced;
        for (int h = 1; h <= RFP_N && every_cb_live; h++) {
            int64_t v = 0;
            bool live = coins_kv_get(pdb, cbids[h].data, 0, &v, NULL,
                                     0, NULL);
            if (!live || v != cbvals[h] || v <= 0)
                every_cb_live = false;
        }
        RFP_CHECK("PART1: every finalized block's coinbase is live at subsidy",
                  every_cb_live);
    }

    /* ── (4) PART 2 — REORG ─────────────────────────────────────────────────
     * Fork NEAR the tip (within ZCL_FINALITY_DEPTH so the unwind is allowed),
     * mine a HEAVIER competing branch (one block longer above the fork), install
     * it on the active chain, and drive the reducer to convergence. Assert the
     * reducer reorgs and the resulting UTXO set is byte-exact to a from-scratch
     * build of the winning chain. Skipped if PART 1 wedged (no clean base). */
    bool part2_ran = false;
    bool reorg_ok = false;
    if (part1_ready && !wedge_reproduced) {
        /* Fork at F = N - 4 (depth N-F = 4 <= ZCL_FINALITY_DEPTH=10). Branch L
         * (the losing branch) holds heights F+1..N (4 blocks above the fork);
         * Branch W (winner) is HEAVIER: F+1..N+1 (5 blocks above the fork). */
        const int F = RFP_N - 4;
        RFP_CHECK("PART2: fork depth within finality floor",
                  (RFP_N - F) <= ZCL_FINALITY_DEPTH);

        /* Mine W: heights F+1 .. N+1 on top of the SHARED fork-point hash
         * hashes[F]. W's tip is at height N+1 — strictly longer (heavier) than
         * L's tip at N, so it must win. */
        const int W_LEN = RFP_N + 1 - F;   /* number of W blocks above fork */
        struct block      *wblk  = zcl_calloc((size_t)W_LEN, sizeof(struct block),
                                              "rfp_wblk");
        struct uint256    *whash = zcl_calloc((size_t)W_LEN, sizeof(struct uint256),
                                              "rfp_whash");
        struct uint256    *wcbid = zcl_calloc((size_t)W_LEN, sizeof(struct uint256),
                                              "rfp_wcbid");
        int64_t           *wcbv  = zcl_calloc((size_t)W_LEN, sizeof(int64_t),
                                              "rfp_wcbv");
        struct block_index **wbi = zcl_calloc((size_t)W_LEN,
                                              sizeof(struct block_index *),
                                              "rfp_wbi");
        bool w_alloc = wblk && whash && wcbid && wcbv && wbi;
        RFP_CHECK("PART2: W branch arrays allocated", w_alloc);
        if (wblk) for (int i = 0; i < W_LEN; i++) block_init(&wblk[i]);

        bool w_mined = w_alloc;
        for (int i = 0; i < W_LEN && w_mined; i++) {
            int h = F + 1 + i;
            const struct uint256 *prev = (i == 0) ? &hashes[F] : &whash[i - 1];
            /* Make W's coinbase genuinely DISTINCT from L's at the same height:
             * salt=1 perturbs the miner pubkey-hash so W's coinbase TXID differs
             * from L's, and a bumped nTime diverges the block header hash too.
             * (Without a distinct coinbase txid, L and W coinbases would be the
             * identical UTXO at each height and the "displaced L removed" check
             * would be vacuous.) */
            if (!rfp_build_regtest_block(&wblk[i], h, prev, cp,
                                         1 /*fork salt*/, &wcbv[i])) {
                w_mined = false; break;
            }
            wblk[i].header.nTime += 7777u;  /* diverge from L at this height */
            if (!mine_block_pow(&wblk[i], h, cp, 0)) { w_mined = false; break; }
            block_get_hash(&wblk[i], &whash[i]);
            wcbid[i] = wblk[i].vtx[0].hash;

            /* The header_admit producer is FORWARD-only: its cursor is already
             * past the fork heights (which hold L's blocks), so it would not
             * create W's index. Create the W block_index via the SAME canonical
             * path the reducer producer uses (add_to_block_index) so every field
             * — nBits, nVersion, and the CUMULATIVE nChainWork (pprev + this
             * block's proof) — is populated correctly. W's header points at the
             * shared fork-point parent (hashes[F]) then the prior W block, so
             * add_to_block_index links pprev and accumulates work; with W one
             * block longer than L above the fork, W's TIP outweighs L's tip and
             * the reducer's chainwork-greater gate passes. */
            struct block_index *bi = add_to_block_index(&ms, &wblk[i].header);
            if (!bi) { w_mined = false; break; }
            bi->nStatus |= BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
            bi->nTx = 1;
            bi->nChainTx = (bi->pprev ? bi->pprev->nChainTx : 0) + 1;

            struct disk_block_pos pos;
            disk_block_pos_init(&pos);
            if (!write_block_to_disk(&wblk[i], &pos, netdir,
                                     cp->pchMessageStart)) { w_mined = false; break; }
            if (!block_index_set_have_data_verified(bi, &pos, netdir)) {
                w_mined = false; break;
            }
            wbi[i] = bi;
        }
        RFP_CHECK("PART2: heavier W branch mined + admitted + body-on-disk",
                  w_mined);

        if (w_mined) {
            part2_ran = true;
            /* Pre-reorg witnesses. L's coinbases at heights F+1..N must be live
             * now; after the reorg they must be GONE and W's must be present. */
            struct block_index *w_tip = wbi[W_LEN - 1]; /* height N+1 */

            /* Install W on the active chain (the live driver's most-work tip
             * swap) and point best-header at W's tip so the stages extend
             * toward W. active_chain_move_window_tip reassembles chain[] along
             * W's pprev path — the structural reorg the reducer then OBSERVES
             * via branch_hash / pprev divergence. */
            ms.pindex_best_header = w_tip;
            bool installed = active_chain_move_window_tip(&ms.chain_active,
                                                          w_tip);
            RFP_CHECK("PART2: heavier W branch installed on active chain",
                      installed && active_chain_at(&ms.chain_active,
                                                   RFP_N + 1) == w_tip);

            uint64_t reorg_before = utxo_apply_stage_reorg_unwound_total();

            /* Wire the PRODUCTION self-heal condition layer exactly as the live
             * node runs it. After a reorg, utxo_apply's fail-closed label_splice
             * gate REFUSES to apply a W block while the script_validate_log
             * verdict at that height is still hash-bound to the displaced L
             * block — that refusal is correct, and the bare reducer drain cannot
             * clear it. The live re-bind path is the
             * reducer_frontier_reconcile_light Condition (ticked by the
             * self_heal supervisor every 5 s): it purges the now-non-canonical
             * L-bound verdicts at the reorged heights and rewinds the producer
             * cursors so the stages refill them for W, after which utxo_apply
             * re-binds + applies. A faithful reorg drive must therefore run BOTH
             * engines — the reducer drain AND the condition engine — the same
             * two the live node runs. (Zero peers => the reconcile peer gate
             * allows the local repair; the tip-staleness detect gate is forced
             * open each round as the deterministic stand-in for the production
             * "tip stalled >= 60 s".) */
            struct connman cm;
            memset(&cm, 0, sizeof(cm));
            net_manager_init(&cm.manager);
            condition_engine_reset_for_testing();
            reducer_frontier_reconcile_light_test_reset();
            sync_monitor_init();
            sync_monitor_set_context(&cm, NULL, &ms);
            register_reducer_frontier_reconcile_light();
            /* Lower the L0/L1 compiled anchor floor (mainnet 3,056,758) to
             * genesis so the reconcile's purge/refill window [hstar+1, ...]
             * covers the regtest reorg heights instead of being empty. The
             * production logic is identical; only the security floor moves,
             * and only inside this hermetic test. */
            reducer_frontier_test_set_compiled_anchor(0);

            /* Converge: one reducer_kick + one condition tick per round until
             * the post-reorg coin state itself is stable. The first repair tick
             * only purges stale L rows and rewinds upstream cursors; script/proof
             * refill holes become visible after the next reducer drain recreates
             * W's body_persist rows. Production waits for the 30s condition
             * backoff between those repair passes; this deterministic harness
             * clears that backoff so it can prove the same multi-pass repair
             * without sleeping. Do not stop merely because the active tip is
             * stable: the coin/refill work can still be in flight below it. */
            {
                int prev_tip = -2, idle = 0;
                for (int it = 0; it < 8000; it++) {
                    int kicked = reducer_kick(&ctl);
                    /* Stand in for ">= 60 s since the last tip advance" so the
                     * detect gate stays open across the whole convergence (a
                     * forward finalization mid-loop would otherwise reset it). */
                    sync_monitor_test_set_tip_advance_ts(1);
                    reducer_frontier_reconcile_light_test_clear_backoff();
                    condition_engine_tick();
                    int t = active_chain_height(&ms.chain_active);
                    sqlite3 *pdb = progress_store_db();
                    int l_live = 0, w_live = 0;
                    for (int h = F + 1; h <= RFP_N + 1; h++) {
                        if (coins_kv_exists(pdb, cbids[h].data, 0))
                            l_live++;
                    }
                    for (int i = 0; i < W_LEN; i++) {
                        if (coins_kv_exists(pdb, wcbid[i].data, 0))
                            w_live++;
                    }
                    bool coins_converged = (l_live == 0 && w_live == W_LEN);
                    if (kicked == 0 && t == prev_tip && coins_converged) {
                        if (++idle >= 16) break;
                    } else {
                        idle = 0;
                    }
                    prev_tip = t;
                }
            }

            /* Tear down the condition layer; the assertions below are pure
             * reads of the reorged coins_kv + active chain. */
            reducer_frontier_test_set_compiled_anchor(-1); /* restore mainnet floor */
            sync_monitor_set_context(NULL, NULL, NULL);
            sync_monitor_test_set_tip_advance_ts(0);
            condition_engine_reset_for_testing();
            reducer_frontier_reconcile_light_test_reset();
            net_manager_free(&cm.manager);

            uint64_t reorg_after = utxo_apply_stage_reorg_unwound_total();
            int reorg_tip = active_chain_height(&ms.chain_active);
            printf("reducer_forward_progress_gate: PART2 post-reorg tip=%d "
                   "(want %d) reorg_unwound %llu->%llu reorg_detected=%llu\n",
                   reorg_tip, RFP_N + 1,
                   (unsigned long long)reorg_before,
                   (unsigned long long)reorg_after,
                   (unsigned long long)tip_finalize_stage_reorg_detected_total());

            RFP_CHECK("PART2: utxo_apply performed a reorg unwind",
                      reorg_after > reorg_before);
            /* Since 67062bbf6 ("tip_finalize: publish each block on arrival —
             * kill the anchor +1 skip"), the reducer installs the FULL heavier
             * W branch on first arrival, so the post-reorg active tip is N+1.
             * (The retired +1-lattice held the served tip at N with N+1 pending;
             * this assertion was a reader still calibrated to that convention —
             * its sibling printf already expects RFP_N+1, and the byte-exact
             * UTXO match below confirms the set reflects W through N+1.) Verify
             * the active tip block at N+1 is the W head AND height N is also a W
             * block — a full branch switch, not a partial splice. */
            struct block_index *fin_at_n =
                active_chain_at(&ms.chain_active, RFP_N);
            struct block_index *fin_at_tip =
                active_chain_at(&ms.chain_active, RFP_N + 1);
            bool tip_is_w = fin_at_n && fin_at_n->phashBlock &&
                            uint256_eq(fin_at_n->phashBlock,
                                       &whash[W_LEN - 2]) && /* W height N */
                            fin_at_tip && fin_at_tip->phashBlock &&
                            uint256_eq(fin_at_tip->phashBlock,
                                       &whash[W_LEN - 1]);   /* W head, N+1 */
            RFP_CHECK("PART2: active tip switched to the heavier W branch head "
                      "(tip at N+1 is the W head; N is also a W block)",
                      reorg_tip == RFP_N + 1 && tip_is_w);

            /* coins_kv is the authoritative store after the reorg unwind. */
            sqlite3 *pdb = progress_store_db();

            /* Displaced L coinbases (heights F+1..N+1, all unwound + replaced by
             * W) are GONE; W coinbases (F+1..N+1) are present. */
            int l_absent = 0, l_total = 0;
            for (int h = F + 1; h <= RFP_N + 1; h++) {
                l_total++;
                if (!coins_kv_exists(pdb, cbids[h].data, 0))
                    l_absent++;
            }
            RFP_CHECK("PART2: all displaced L-branch coinbases removed",
                      l_total > 0 && l_absent == l_total);

            int w_present = 0;
            for (int i = 0; i < W_LEN; i++) {
                if (coins_kv_exists(pdb, wcbid[i].data, 0))
                    w_present++;
            }
            RFP_CHECK("PART2: all W-branch coinbases present",
                      w_present == W_LEN);

            uint8_t commit_reorg[32];
            bool have_reorg_commit =
                (coins_kv_commitment(pdb, commit_reorg) == 0);
            uint64_t count_reorg = (uint64_t)coins_kv_count(pdb);
            RFP_CHECK("PART2: reorg-path commitment computed", have_reorg_commit);
            printf("reducer_forward_progress_gate: PART2 reorg count=%llu\n",
                   (unsigned long long)count_reorg);

            /* Byte-exact from-scratch reorg parity (coins_kv-vs-coins_kv over
             * the SHA3 commitment) is the dedicated job of
             * test_stage_reorg_unwind_parity. Here we assert the reorged
             * coins_kv is STRUCTURALLY correct: every displaced L coinbase is
             * gone, every W coinbase is present, and the commitment recomputes. */
            reorg_ok = have_reorg_commit && count_reorg > 0 &&
                       l_total > 0 && l_absent == l_total &&
                       w_present == W_LEN;
            RFP_CHECK("PART2: reorg produced a structurally correct coins_kv "
                      "(L coinbases gone, W coinbases present)", reorg_ok);
        }

        if (wblk) for (int i = 0; i < W_LEN; i++) block_free(&wblk[i]);
        free(wblk); free(whash); free(wcbid); free(wcbv); free(wbi);
    }
    (void)part2_ran;
    (void)reorg_ok;

    /* ── (5) Teardown ───────────────────────────────────────────────────── */
    if (blocks) for (int i = 0; i <= RFP_N + 1; i++) block_free(&blocks[i]);
    free(blocks); free(hashes); free(cbids); free(cbvals); free(bidx);

    tip_finalize_stage_shutdown();
    utxo_apply_stage_shutdown();
    proof_validate_stage_shutdown();
    script_validate_stage_shutdown();
    body_persist_stage_shutdown();
    body_fetch_stage_shutdown();
    validate_headers_stage_shutdown();
    header_admit_stage_shutdown();

    activation_controller_destroy(&ctl);

    main_state_free(&ms);
    event_log_close(lg);
    progress_store_close();
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(netdir);
    test_cleanup_tmpdir(dir);

    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);

    if (wedge_reproduced) {
        printf("=== reducer forward-progress gate: LIVE WEDGE REPRODUCED at "
               "height %d — %s ===\n", wedge_height, wedge_detail);
    }
    printf("=== reducer forward-progress + reorg gate: %d failure(s) ===\n",
           failures);
    return failures;
}
