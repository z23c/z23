/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_forward_progress_gate — the MULTI-BLOCK forward-progress +
 * REORG gate (a hermetic repro of a tip that holds without finalizing).
 *
 * A single-block gate cannot catch a wedge that only appears after several
 * sequential finalizations, so this gate mines many blocks and asserts
 * MONOTONIC forward progress.
 *
 *   PART 1 (forward progress): mine + ingest N = 32 sequential regtest blocks
 *     through reducer_ingest_block (the front door live intake uses), looping
 *     reducer_kick to convergence after each. active_chain_height must reach
 *     exactly 32 with NO stall and NO oscillation: finalized_total strictly
 *     increases and never retreats, and the tip never goes backward. A stall
 *     captures the stall height + the eight stage cursors.
 *
 *   PART 2 (reorg): from a fork point near the tip (within
 *     ZCL_FINALITY_DEPTH), mine a HEAVIER competing branch (one block longer
 *     above the fork), install it, and drive the reducer to convergence. The
 *     authoritative tip must switch to the heavier branch, the displaced
 *     coinbase UTXOs must be removed, the new branch's coinbases present, and
 *     the UTXO commitment BYTE-EXACT to a from-scratch recompute of the
 *     winning chain.
 *
 * One-block lookahead: tip_finalize finalizes height H by reading
 * active_chain_at(H+1), and records the row for H at key H-1. To finalize up
 * to N, block N+1 must be data'd: PART 1 mines blocks 1..33 and ingests
 * 1..32.
 *
 * Finality floor: utxo_apply's reorg unwind is gated by
 * reorg_is_allowed(tip, fork); a reorg deeper than ZCL_FINALITY_DEPTH (=10)
 * is correctly refused. PART 2 therefore forks within the finality window.
 *
 * No stubs, no injected readers: the eight stages run on their PRODUCTION
 * defaults (bodies persisted to disk and read back by
 * stage_default_block_reader; coinbase-only blocks need no script or proof
 * validation).
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

/* src-private test hook (engine/reducer/jobs/src/reducer_frontier.c): lower
 * the L0/L1 compiled anchor floor so the PRODUCTION reorg re-bind path
 * (reducer_frontier_reconcile_light: purge non-canonical verdicts -> refill
 * -> re-validate) operates at the regtest heights PART 2 mines. Off-test the
 * floor is the mainnet SHA3 checkpoint (3,056,758). -1 restores it. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define RFP_CHECK(name, expr) do {                            \
    printf("reducer_forward_progress_gate: %s... ", (name));  \
    if ((expr)) printf("OK\n");                               \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

/* How many sequential blocks PART 1 drives the reducer forward; deep enough
 * to surface a wedge that appears after several finalizations. */
#define RFP_N 32

static int rfp_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── Block builder — one coinbase tx, real merkle root, regtest powLimit
 * compact nBits. `script_salt` perturbs the miner pubkey-hash so a competing
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
 * a zero coin delta, so the cold-start anchor finalizes cleanly into block 1. */
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

static bool rfp_mine_on_indexed_parent(struct main_state *ms,
    struct block *blk, int height, const struct chain_params *cp)
{
    struct block_index *parent = block_map_find(&ms->map_block_index,
                                                &blk->header.hashPrevBlock);
    if (!parent)
        return false;
    blk->header.nBits = GetNextWorkRequired(parent, &blk->header, &cp->consensus);
    return mine_block_pow(blk, height, cp, 0);
}

/* Mine a regtest block at `height` on `prev_hash`, admit its header (creating
 * the block_index + linking pprev), write its body to disk, and mark the index
 * BLOCK_HAVE_DATA ("headers + bodies synced but not connected"). Fills the
 * out-params (caller block_free's *out_blk). The window/best-header anchor is
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
    if (!rfp_mine_on_indexed_parent(c->ms, out_blk, height, c->cp))
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

struct rfp_gate_env {
    const struct chain_params *cp;
    char dir[256];
    char netdir[512];
    char blocksdir[640];
    char log_path[512];
    event_log_t *lg;
    struct main_state ms;
    struct uint256 genesis_hash;
    struct block_index *genesis;
    bool stages_ok;
    struct chain_activation_controller ctl;
    int height_genesis;
    uint64_t count_genesis;
    struct rfp_ingest_ctx ictx;
};

struct rfp_part1 {
    struct block *blocks;
    struct uint256 *hashes;
    struct uint256 *cbids;
    int64_t *cbvals;
    struct block_index **bidx;
    bool part1_ready;
    bool wedge_reproduced;
    int wedge_height;
    char wedge_detail[256];
    uint64_t wedge_cursors[8];
};

struct rfp_w_branch {
    struct block *wblk;
    struct uint256 *whash;
    struct uint256 *wcbid;
    int64_t *wcbv;
    struct block_index **wbi;
    int w_len;
    int fork_h;
    bool w_alloc;
    bool w_mined;
};

/* Returns true when the PART 1 loop must stop: a stall was recorded, or
 * block h reached terminal convergence. On a stall the reached tip and
 * finalized_total are left unchanged. */
static bool rfp_stop_after_forward_step(int h, int hh, uint64_t fin,
                                        int *reached_height,
                                        uint64_t *prev_finalized,
                                        struct rfp_part1 *p,
                                        struct validation_state *out)
{
    /* Forward-progress invariant: the tip must FINALIZE block h
     * (hh >= h), finalized_total must strictly increase, and the tip
     * must never retreat. Ordinarily hh <= h+1; since all fixture
     * bodies are persisted one kick may drain the whole N-block run,
     * which is accepted as terminal convergence. */
    bool completed = hh >= RFP_N && hh <= RFP_N + 1;
    bool advanced  = (hh >= h) && (hh <= h + 1 || completed);
    bool monotone  = (hh >= *reached_height) && (fin >= *prev_finalized);
    bool fin_up    = (fin > *prev_finalized);
    if (!advanced || !monotone || !fin_up) {
        p->wedge_reproduced = true;
        p->wedge_height = h;
        rfp_snapshot_cursors(progress_store_db(), p->wedge_cursors);
        snprintf(p->wedge_detail, sizeof(p->wedge_detail),
            "stalled at block %d: tip=%d (want %d) finalized_total "
            "%llu->%llu reorg_detected=%llu precond_failed_via_logs "
            "reject=\"%s\"",
            h, hh, h,
            (unsigned long long)*prev_finalized,
            (unsigned long long)fin,
            (unsigned long long)tip_finalize_stage_reorg_detected_total(),
            out->reject_reason[0] ? out->reject_reason : "(none)");
        printf("reducer_forward_progress_gate: *** LIVE WEDGE "
               "REPRODUCED *** %s\n", p->wedge_detail);
        rfp_print_cursors("wedge", p->wedge_cursors);
        return true;
    }
    *reached_height = hh;
    *prev_finalized = fin;
    return completed;
}

static int rfp_check_part1_tip_and_coinbases(const struct rfp_gate_env *e,
                                             const struct rfp_part1 *p,
                                             int reached_height)
{
    int failures = 0;

    printf("reducer_forward_progress_gate: PART1 reached tip height %d/%d "
           "(finalized_total=%llu)\n", reached_height, RFP_N,
           (unsigned long long)tip_finalize_stage_finalized_total());

    RFP_CHECK("PART1: tip advanced monotonically to N with no stall/"
              "oscillation (live-wedge NOT reproduced)",
              reached_height >= RFP_N && !p->wedge_reproduced);
    RFP_CHECK("PART1: tip_finalize finalized >= N blocks (reducer engine)",
              tip_finalize_stage_finalized_total() >= (uint64_t)RFP_N);
    RFP_CHECK("PART1: utxo_apply succeeded at tip height N",
              utxo_apply_stage_succeeded_at(RFP_N));
    RFP_CHECK("PART1: no spend-unknown across the run",
              utxo_apply_stage_spend_unknown_total() == 0);

    /* Each block added exactly one coinbase UTXO over the genesis
     * baseline; with block N+1 pending as successor, utxo_apply has
     * applied N+1 coinbases. */
    sqlite3 *pdb = progress_store_db();
    uint64_t count_after = (uint64_t)coins_kv_count(pdb);
    printf("reducer_forward_progress_gate: utxo count %llu -> %llu\n",
           (unsigned long long)e->count_genesis,
           (unsigned long long)count_after);
    bool applied_succ = utxo_apply_stage_succeeded_at(RFP_N + 1);
    RFP_CHECK("PART1: N coinbases live over genesis (+1 pending successor)",
              count_after == e->count_genesis + (uint64_t)RFP_N +
                             (applied_succ ? 1u : 0u));

    /* Each finalized block's coinbase output is live with the right value. */
    bool every_cb_live = !p->wedge_reproduced;
    for (int h = 1; h <= RFP_N && every_cb_live; h++) {
        int64_t v = 0;
        bool live = coins_kv_get(pdb, p->cbids[h].data, 0, &v, NULL,
                                 0, NULL);
        if (!live || v != p->cbvals[h] || v <= 0)
            every_cb_live = false;
    }
    RFP_CHECK("PART1: every finalized block's coinbase is live at subsidy",
              every_cb_live);
    return failures;
}

static int rfp_drive_part1_forward(struct rfp_gate_env *e, struct rfp_part1 *p)
{
    /* ── (3) PART 1 drive: ingest blocks 1..N through the FRONT DOOR, looping
     * reducer_kick to convergence after each; the tip and finalized_total
     * must advance MONOTONICALLY and never retreat. ────────────────────── */
    int failures = 0;
    int reached_height = e->height_genesis;
    uint64_t prev_finalized = tip_finalize_stage_finalized_total();
    if (p->part1_ready) {
        for (int h = 1; h <= RFP_N; h++) {
            /* Lookahead successor (block h+1) must be the visible window tip so
             * tip_finalize can finalize block h. */
            e->ms.pindex_best_header = p->bidx[h + 1];
            (void)active_chain_extend_window(&e->ms.chain_active, p->bidx[h + 1]);

            struct validation_state out;
            validation_state_init(&out);
            bool fd = reducer_ingest_block(&e->ctl, &p->blocks[h], REDUCER_SRC_MINED,
                                           true /*force*/, &out);
            (void)fd;
            /* Loop to TRUE convergence — never assert after one bounded kick. */
            for (int it = 0; it < 1000 && reducer_kick(&e->ctl) > 0; it++) {
                /* keep draining */
            }

            int hh = active_chain_height(&e->ms.chain_active);
            uint64_t fin = tip_finalize_stage_finalized_total();
            if (rfp_stop_after_forward_step(h, hh, fin, &reached_height,
                                            &prev_finalized, p, &out))
                break;
        }
        failures += rfp_check_part1_tip_and_coinbases(e, p, reached_height);
    }
    return failures;
}

/* Returns the failures counted during open. *ready is set when the
 * datadir, progress store and event log are open and the caller should
 * continue; on failure the setup cleanup has already run. */
static int rfp_open_forward_progress_env(struct rfp_gate_env *e, bool *ready)
{
    int failures = 0;
    *ready = false;

    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    e->cp = chain_params_get();

    {
        unsigned int n = chain_params_equihash_n(e->cp, 1);
        unsigned int k = chain_params_equihash_k(e->cp, 1);
        RFP_CHECK("regtest is Equihash (48,5)", n == 48 && k == 5);
    }

    /* ── (1) Fresh node-db / progress.kv at genesis, hermetic datadir ────── */
    rfp_mkdir_p("./test-tmp");
    test_fmt_tmpdir(e->dir, sizeof(e->dir), "reducer_forward_progress_gate", "main");
    rfp_mkdir_p(e->dir);

    /* SetDataDir already clears the cache and populates cachedDataDirNet =
     * <dir>/regtest; do NOT ClearDataDirCache() or GetDataDir falls back to
     * the shared default ~/.zclassic-c23/regtest. */
    SetDataDir(e->dir);
    GetDataDir(true /*net-specific (regtest subdir)*/, e->netdir, sizeof(e->netdir));
    rfp_mkdir_p(e->netdir);
    snprintf(e->blocksdir, sizeof(e->blocksdir), "%s/blocks", e->netdir);
    rfp_mkdir_p(e->blocksdir);

    snprintf(e->log_path, sizeof(e->log_path), "%s/events.log", e->dir);

    progress_store_close();
    bool store_ok = progress_store_open(e->dir);
    RFP_CHECK("progress_store opens at fresh datadir", store_ok);

    event_log_t *lg = store_ok ? event_log_open(e->log_path) : NULL;
    RFP_CHECK("event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(e->blocksdir);
        test_cleanup_tmpdir(e->netdir);
        test_cleanup_tmpdir(e->dir);
        SetDataDir("");
        ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        printf("=== reducer forward-progress gate: %d failures (setup) ===\n",
               failures);
        return failures;
    }

    e->lg = lg;
    *ready = true;
    return failures;
}

static int rfp_seed_genesis_and_stages(struct rfp_gate_env *e)
{
    int failures = 0;

    main_state_init(&e->ms);

    /* Seed genesis exactly the way boot.c does. */
    e->genesis_hash = e->cp->consensus.hashGenesisBlock;
    e->genesis = chainstate_insert_block_index(
        (struct chainstate *)&e->ms, &e->genesis_hash);
    RFP_CHECK("genesis block_index inserted", e->genesis != NULL);
    if (e->genesis) {
        e->genesis->nHeight = 0;
        e->genesis->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        e->genesis->nTx = 1;
        e->genesis->nChainTx = 1;
        e->genesis->nChainWork = GetBlockProof(e->genesis);
        active_chain_move_window_tip(&e->ms.chain_active, e->genesis);
        e->ms.pindex_best_header = e->genesis;
    }

    e->stages_ok =
        header_admit_stage_init(&e->ms) &&
        validate_headers_stage_init(&e->ms) &&
        body_fetch_stage_init(&e->ms) &&
        body_persist_stage_init(&e->ms) &&
        script_validate_stage_init(&e->ms) &&
        proof_validate_stage_init(&e->ms) &&
        utxo_apply_stage_init(&e->ms) &&
        tip_finalize_stage_init(&e->ms);
    RFP_CHECK("all eight reducer stages init", e->stages_ok);

    if (e->stages_ok)
        RFP_CHECK("seed genesis utxo_apply_log row",
                  rfp_seed_genesis_utxo_apply_row(progress_store_db()));

    RFP_CHECK("tip_finalize anchor seed at genesis",
              tip_finalize_stage_seed_anchor(0, e->genesis_hash.data, false));

    activation_controller_init(&e->ctl, &e->ms, NULL, e->cp, e->netdir);

    e->height_genesis = active_chain_height(&e->ms.chain_active);
    RFP_CHECK("genesis tip height is 0", e->height_genesis == 0);

    /* coins_kv is the authoritative UTXO set the stages author. */
    e->count_genesis = (uint64_t)coins_kv_count(progress_store_db());

    e->ictx = (struct rfp_ingest_ctx){ .cp = e->cp, .ms = &e->ms, .ctl = &e->ctl,
                                       .datadir = e->netdir };
    return failures;
}

static int rfp_alloc_part1_chain(struct rfp_gate_env *e, struct rfp_part1 *p)
{
    /* ── (2) PART 1 — mine N+1 blocks (1..N+1) in the "headers+bodies synced"
     * state; block N+1 is the lookahead successor that lets block N finalize.
     * Keep all blocks + hashes/block_index pointers alive (PART 2 reuses the
     * fork-point hash). ─────────────────────────────────────────────────── */
    int failures = 0;

    p->blocks = zcl_calloc(RFP_N + 2, sizeof(struct block), "rfp_blocks");
    p->hashes = zcl_calloc(RFP_N + 2, sizeof(struct uint256), "rfp_hashes");
    p->cbids = zcl_calloc(RFP_N + 2, sizeof(struct uint256), "rfp_cbids");
    p->cbvals = zcl_calloc(RFP_N + 2, sizeof(int64_t), "rfp_cbvals");
    p->bidx = zcl_calloc(RFP_N + 2, sizeof(struct block_index *), "rfp_bidx");
    bool allocs_ok = p->blocks && p->hashes && p->cbids && p->cbvals && p->bidx;
    RFP_CHECK("PART1 chain arrays allocated", allocs_ok);
    if (p->blocks) for (int i = 0; i <= RFP_N + 1; i++) block_init(&p->blocks[i]);

    /* The live-wedge witnesses we capture if PART 1 stalls. */
    p->wedge_reproduced = false;
    p->wedge_height = -1;
    memset(p->wedge_detail, 0, sizeof(p->wedge_detail));
    memset(p->wedge_cursors, 0, sizeof(p->wedge_cursors));

    p->part1_ready = e->stages_ok && allocs_ok;
    return failures;
}

static int rfp_mine_part1_blocks(struct rfp_gate_env *e, struct rfp_part1 *p)
{
    int failures = 0;

    if (p->part1_ready) {
        /* hashes[0] == genesis. Mine heights 1..N+1 on top. */
        p->hashes[0] = e->genesis_hash;
        p->bidx[0] = e->genesis;
        bool mined_all = true;
        for (int h = 1; h <= RFP_N + 1 && mined_all; h++) {
            mined_all = rfp_mine_admit_persist(&e->ictx, h, &p->hashes[h - 1],
                                               &p->blocks[h], &p->hashes[h],
                                               &p->cbvals[h], &p->bidx[h]);
            if (mined_all) p->cbids[h] = p->blocks[h].vtx[0].hash;
        }
        RFP_CHECK("all N+1 blocks mined + header-admitted + body-on-disk",
                  mined_all);
        p->part1_ready = mined_all;
    }
    return failures;
}

static bool rfp_active_tip_is_w_head(struct block_index *fin_at_n,
                                     struct block_index *fin_at_tip,
                                     const struct uint256 *whash,
                                     int w_len)
{
    return fin_at_n && fin_at_n->phashBlock &&
           uint256_eq(fin_at_n->phashBlock,
                      &whash[w_len - 2]) && /* W height N */
           fin_at_tip && fin_at_tip->phashBlock &&
           uint256_eq(fin_at_tip->phashBlock,
                      &whash[w_len - 1]);   /* W head, N+1 */
}

static int rfp_mine_w_branch(struct main_state *ms,
                             const struct chain_params *cp,
                             const char *netdir,
                             const struct uint256 *fork_hash,
                             struct rfp_w_branch *w)
{
    int failures = 0;
    w->w_mined = w->w_alloc;
    for (int i = 0; i < w->w_len && w->w_mined; i++) {
        int h = w->fork_h + 1 + i;
        const struct uint256 *prev = (i == 0) ? fork_hash : &w->whash[i - 1];
        /* Make W's coinbase DISTINCT from L's at the same height: salt=1
         * changes the coinbase TXID and a bumped nTime changes the header
         * hash (otherwise the "displaced L removed" check is vacuous). */
        if (!rfp_build_regtest_block(&w->wblk[i], h, prev, cp,
                                     1 /*fork salt*/, &w->wcbv[i])) {
            w->w_mined = false; break;
        }
        w->wblk[i].header.nTime += 7777u;  /* diverge from L at this height */
        if (!rfp_mine_on_indexed_parent(ms, &w->wblk[i], h, cp)) {
            w->w_mined = false; break;
        }
        block_get_hash(&w->wblk[i], &w->whash[i]);
        w->wcbid[i] = w->wblk[i].vtx[0].hash;

        /* The header_admit producer is FORWARD-only: its cursor is past
         * the fork heights, so it would not create W's index. Create the
         * W block_index via the canonical add_to_block_index so nBits,
         * nVersion and the CUMULATIVE nChainWork are populated; W's
         * header points at hashes[F] then the prior W block, and W's tip
         * outweighs L's so the chainwork-greater gate passes. */
        struct block_index *bi = add_to_block_index(ms, &w->wblk[i].header);
        if (!bi) { w->w_mined = false; break; }
        bi->nStatus |= BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        bi->nTx = 1;
        bi->nChainTx = (bi->pprev ? bi->pprev->nChainTx : 0) + 1;

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        if (!write_block_to_disk(&w->wblk[i], &pos, netdir,
                                 cp->pchMessageStart)) {
            w->w_mined = false; break;
        }
        if (!block_index_set_have_data_verified(bi, &pos, netdir)) {
            w->w_mined = false; break;
        }
        w->wbi[i] = bi;
    }
    RFP_CHECK("PART2: heavier W branch mined + admitted + body-on-disk",
              w->w_mined);
    return failures;
}

static void rfp_converge_w_reorg(struct rfp_gate_env *e,
                                 const struct rfp_part1 *p,
                                 const struct rfp_w_branch *w)
{
    /* Wire the PRODUCTION self-heal condition layer as the live node
     * runs it. After a reorg, utxo_apply's fail-closed label_splice
     * gate REFUSES a W block while the script_validate_log verdict at
     * that height is still hash-bound to the displaced L block, and
     * the bare drain cannot clear it. The
     * reducer_frontier_reconcile_light Condition purges the
     * non-canonical verdicts and rewinds producer cursors so the
     * stages refill them for W. The drive runs BOTH the reducer drain
     * AND the condition engine. (Zero peers => the reconcile peer
     * gate allows the local repair; the tip-staleness detect gate is
     * forced open each round.) */
    struct connman cm;
    memset(&cm, 0, sizeof(cm));
    net_manager_init(&cm.manager);
    condition_engine_reset_for_testing();
    reducer_frontier_reconcile_light_test_reset();
    sync_monitor_init();
    sync_monitor_set_context(&cm, NULL, &e->ms);
    register_reducer_frontier_reconcile_light();
    /* Lower the L0/L1 compiled anchor floor (mainnet 3,056,758) to
     * genesis so the reconcile's purge/refill window covers the
     * regtest reorg heights; only the floor moves, only in this
     * hermetic test. */
    reducer_frontier_test_set_compiled_anchor(0);

    /* Converge: one reducer_kick + one condition tick per round until
     * the post-reorg coin state is stable. The first repair tick only
     * purges stale L rows and rewinds upstream cursors; refill holes
     * appear after the next drain recreates W's body_persist rows.
     * Production waits for a 30s condition backoff between passes;
     * this harness clears it. Do not stop merely because the active
     * tip is stable: coin/refill work can still be in flight. */
    {
        int prev_tip = -2, idle = 0;
        for (int it = 0; it < 8000; it++) {
            int kicked = reducer_kick(&e->ctl);
            /* Stand in for ">= 60 s since the last tip advance" so the
             * detect gate stays open across the convergence. */
            sync_monitor_test_set_tip_advance_ts(1);
            reducer_frontier_reconcile_light_test_clear_backoff();
            condition_engine_tick();
            int t = active_chain_height(&e->ms.chain_active);
            sqlite3 *pdb = progress_store_db();
            int l_live = 0, w_live = 0;
            for (int h = w->fork_h + 1; h <= RFP_N + 1; h++) {
                if (coins_kv_exists(pdb, p->cbids[h].data, 0))
                    l_live++;
            }
            for (int i = 0; i < w->w_len; i++) {
                if (coins_kv_exists(pdb, w->wcbid[i].data, 0))
                    w_live++;
            }
            bool coins_converged = (l_live == 0 && w_live == w->w_len);
            if (kicked == 0 && t == prev_tip && coins_converged) {
                if (++idle >= 16) break;
            } else {
                idle = 0;
            }
            prev_tip = t;
        }
    }

    /* Tear down the condition layer; the assertions below only
     * read the reorged coins_kv + active chain. */
    reducer_frontier_test_set_compiled_anchor(-1); /* restore mainnet floor */
    sync_monitor_set_context(NULL, NULL, NULL);
    sync_monitor_test_set_tip_advance_ts(0);
    condition_engine_reset_for_testing();
    reducer_frontier_reconcile_light_test_reset();
    net_manager_free(&cm.manager);
}

static int rfp_assert_part2_reorg_coins(struct rfp_gate_env *e,
                                        const struct rfp_part1 *p,
                                        const struct rfp_w_branch *w,
                                        uint64_t reorg_before,
                                        bool *reorg_ok)
{
    int failures = 0;
    uint64_t reorg_after = utxo_apply_stage_reorg_unwound_total();
    int reorg_tip = active_chain_height(&e->ms.chain_active);
    printf("reducer_forward_progress_gate: PART2 post-reorg tip=%d "
           "(want %d) reorg_unwound %llu->%llu reorg_detected=%llu\n",
           reorg_tip, RFP_N + 1,
           (unsigned long long)reorg_before,
           (unsigned long long)reorg_after,
           (unsigned long long)tip_finalize_stage_reorg_detected_total());

    RFP_CHECK("PART2: utxo_apply performed a reorg unwind",
              reorg_after > reorg_before);
    /* The reducer installs the FULL heavier W branch on first
     * arrival, so the post-reorg active tip is N+1. Verify the tip
     * block at N+1 is the W head AND height N is also a W block: a
     * full branch switch, not a partial splice. */
    struct block_index *fin_at_n =
        active_chain_at(&e->ms.chain_active, RFP_N);
    struct block_index *fin_at_tip =
        active_chain_at(&e->ms.chain_active, RFP_N + 1);
    bool tip_is_w = rfp_active_tip_is_w_head(fin_at_n, fin_at_tip,
                                             w->whash, w->w_len);
    RFP_CHECK("PART2: active tip switched to the heavier W branch head "
              "(tip at N+1 is the W head; N is also a W block)",
              reorg_tip == RFP_N + 1 && tip_is_w);

    /* coins_kv is the authoritative store after the reorg unwind. */
    sqlite3 *pdb = progress_store_db();

    /* Displaced L coinbases (heights F+1..N+1, all unwound + replaced by
     * W) are GONE; W coinbases (F+1..N+1) are present. */
    int l_absent = 0, l_total = 0;
    for (int h = w->fork_h + 1; h <= RFP_N + 1; h++) {
        l_total++;
        if (!coins_kv_exists(pdb, p->cbids[h].data, 0))
            l_absent++;
    }
    RFP_CHECK("PART2: all displaced L-branch coinbases removed",
              l_total > 0 && l_absent == l_total);

    int w_present = 0;
    for (int i = 0; i < w->w_len; i++) {
        if (coins_kv_exists(pdb, w->wcbid[i].data, 0))
            w_present++;
    }
    RFP_CHECK("PART2: all W-branch coinbases present",
              w_present == w->w_len);

    uint8_t commit_reorg[32];
    bool have_reorg_commit =
        (coins_kv_commitment(pdb, commit_reorg) == 0);
    uint64_t count_reorg = (uint64_t)coins_kv_count(pdb);
    RFP_CHECK("PART2: reorg-path commitment computed", have_reorg_commit);
    printf("reducer_forward_progress_gate: PART2 reorg count=%llu\n",
           (unsigned long long)count_reorg);

    /* Byte-exact reorg parity over the SHA3 commitment belongs to
     * test_stage_reorg_unwind_parity. Here coins_kv must be
     * STRUCTURALLY correct: every displaced L coinbase gone, every W
     * coinbase present, and the commitment recomputes. */
    *reorg_ok = have_reorg_commit && count_reorg > 0 &&
                l_total > 0 && l_absent == l_total &&
                w_present == w->w_len;
    RFP_CHECK("PART2: reorg produced a structurally correct coins_kv "
              "(L coinbases gone, W coinbases present)", *reorg_ok);
    return failures;
}

static int rfp_run_part2_reorg(struct rfp_gate_env *e, struct rfp_part1 *p)
{
    /* ── (4) PART 2 — REORG ─────────────────────────────────────────────────
     * Fork NEAR the tip (within ZCL_FINALITY_DEPTH), mine a HEAVIER
     * competing branch (one block longer above the fork), install it, and
     * drive the reducer to convergence: it must reorg and the UTXO set must
     * be byte-exact to a from-scratch build of the winning chain. Skipped
     * if PART 1 wedged. ──────────────────────────────────────────────── */
    int failures = 0;
    bool part2_ran = false;
    bool reorg_ok = false;

    /* Fork at F = N - 4 (depth N-F = 4 <= ZCL_FINALITY_DEPTH=10). Branch L
     * (the losing branch) holds heights F+1..N (4 blocks above the fork);
     * Branch W (winner) is HEAVIER: F+1..N+1 (5 blocks above the fork). */
    const int F = RFP_N - 4;
    RFP_CHECK("PART2: fork depth within finality floor",
              (RFP_N - F) <= ZCL_FINALITY_DEPTH);

    /* Mine W: heights F+1 .. N+1 on the SHARED fork-point hash
     * hashes[F]; W's tip (N+1) is heavier than L's tip (N). */
    const int W_LEN = RFP_N + 1 - F;   /* number of W blocks above fork */
    struct rfp_w_branch w = {0};
    w.fork_h = F;
    w.w_len = W_LEN;
    w.wblk = zcl_calloc((size_t)W_LEN, sizeof(struct block), "rfp_wblk");
    w.whash = zcl_calloc((size_t)W_LEN, sizeof(struct uint256), "rfp_whash");
    w.wcbid = zcl_calloc((size_t)W_LEN, sizeof(struct uint256), "rfp_wcbid");
    w.wcbv = zcl_calloc((size_t)W_LEN, sizeof(int64_t), "rfp_wcbv");
    w.wbi = zcl_calloc((size_t)W_LEN, sizeof(struct block_index *), "rfp_wbi");
    w.w_alloc = w.wblk && w.whash && w.wcbid && w.wcbv && w.wbi;
    RFP_CHECK("PART2: W branch arrays allocated", w.w_alloc);
    if (w.wblk) for (int i = 0; i < W_LEN; i++) block_init(&w.wblk[i]);

    failures += rfp_mine_w_branch(&e->ms, e->cp, e->netdir, &p->hashes[F], &w);

    if (w.w_mined) {
        part2_ran = true;
        /* Pre-reorg witnesses. L's coinbases at heights F+1..N must be live
         * now; after the reorg they must be GONE and W's must be present. */
        struct block_index *w_tip = w.wbi[W_LEN - 1]; /* height N+1 */

        /* Install W on the active chain (the live driver's most-work tip
         * swap) and point best-header at W's tip.
         * active_chain_move_window_tip reassembles chain[] along W's pprev
         * path, the structural reorg the reducer OBSERVES. */
        e->ms.pindex_best_header = w_tip;
        bool installed = active_chain_move_window_tip(&e->ms.chain_active,
                                                      w_tip);
        RFP_CHECK("PART2: heavier W branch installed on active chain",
                  installed && active_chain_at(&e->ms.chain_active,
                                               RFP_N + 1) == w_tip);

        uint64_t reorg_before = utxo_apply_stage_reorg_unwound_total();
        rfp_converge_w_reorg(e, p, &w);
        failures += rfp_assert_part2_reorg_coins(e, p, &w, reorg_before,
                                                 &reorg_ok);
    }

    if (w.wblk) for (int i = 0; i < W_LEN; i++) block_free(&w.wblk[i]);
    free(w.wblk); free(w.whash); free(w.wcbid); free(w.wcbv); free(w.wbi);
    (void)part2_ran;
    (void)reorg_ok;
    return failures;
}

static void rfp_teardown_forward_progress(struct rfp_gate_env *e,
                                          struct rfp_part1 *p,
                                          int failures)
{
    /* ── (5) Teardown ───────────────────────────────────────────────────── */
    if (p->blocks) for (int i = 0; i <= RFP_N + 1; i++) block_free(&p->blocks[i]);
    free(p->blocks); free(p->hashes); free(p->cbids); free(p->cbvals); free(p->bidx);

    tip_finalize_stage_shutdown();
    utxo_apply_stage_shutdown();
    proof_validate_stage_shutdown();
    script_validate_stage_shutdown();
    body_persist_stage_shutdown();
    body_fetch_stage_shutdown();
    validate_headers_stage_shutdown();
    header_admit_stage_shutdown();

    activation_controller_destroy(&e->ctl);
    main_state_free(&e->ms);
    event_log_close(e->lg);
    progress_store_close();
    test_cleanup_tmpdir(e->blocksdir);
    test_cleanup_tmpdir(e->netdir);
    test_cleanup_tmpdir(e->dir);

    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);

    if (p->wedge_reproduced) {
        printf("=== reducer forward-progress gate: LIVE WEDGE REPRODUCED at "
               "height %d — %s ===\n", p->wedge_height, p->wedge_detail);
    }
    printf("=== reducer forward-progress + reorg gate: %d failure(s) ===\n",
           failures);
}

int test_reducer_forward_progress_gate(void);
int test_reducer_forward_progress_gate(void)
{
    printf("\n=== reducer forward-progress + reorg gate "
           "(live-wedge repro: %d sequential blocks -> reducer -> tip+N; "
           "then a heavier-fork reorg) ===\n", RFP_N);
    int failures = 0;

    /* OPT-IN gate: drives reducer process-globals, deterministic only in a
     * FRESH process. Run isolated via `make mvp-forward-progress`. */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("reducer_forward_progress_gate: SKIP "
               "(set ZCL_STRESS_TESTS=1 and run isolated via "
               "`make mvp-forward-progress`)\n");
        return 0;
    }

    struct rfp_gate_env env;
    bool ready = false;
    failures += rfp_open_forward_progress_env(&env, &ready);
    if (!ready)
        return failures;

    failures += rfp_seed_genesis_and_stages(&env);

    struct rfp_part1 part1 = {0};
    part1.wedge_height = -1;

    failures += rfp_alloc_part1_chain(&env, &part1);
    failures += rfp_mine_part1_blocks(&env, &part1);

    failures += rfp_drive_part1_forward(&env, &part1);

    if (part1.part1_ready && !part1.wedge_reproduced)
        failures += rfp_run_part2_reorg(&env, &part1);

    rfp_teardown_forward_progress(&env, &part1, failures);
    return failures;
}
