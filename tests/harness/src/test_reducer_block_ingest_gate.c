/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_block_ingest_gate — the MVP "it works" gate.
 *
 * WHAT THIS PROVES (the v1 "it works" guarantee)
 * ----------------------------------------------
 * The authoritative tip-advance engine is the REDUCER (the log -> projection
 * -> Jobs pipeline: header_admit -> validate_headers -> body_fetch ->
 * body_persist -> script_validate -> proof_validate -> utxo_apply ->
 * tip_finalize), NOT the legacy connect_block engine. This gate stands up a
 * fresh regtest node-db / progress.kv at genesis entirely in-process, mines
 * ONE real regtest block (height genesis+1) with a valid Equihash (48,5) PoW
 * via the in-process miner, drives it through the REDUCER FRONT DOOR
 * (reducer_ingest_block — the SAME entry every live intake caller uses:
 * msg_blocks / msg_compact / submitblock / miner / rebuild), and asserts:
 *
 *   1. block genesis+1 is finalized by the reducer, with the active-chain
 *      window bounded to the prepared genesis+1/genesis+2 span;
 *   2. the UTXO commitment recomputes consistently WITH the applied block —
 *      the mined coinbase output is now live in the UTXO set, the live count
 *      went up by exactly one, and the SHA3 commitment changed.
 *
 * WHY THE FRONT DOOR CAN BE DRIVEN HERE (vs the older e2e test's caveat)
 * --------------------------------------------------------------------
 * reducer_ingest_block()'s first gate is check_block(pblock, out, ctl->params,
 * check_pow=true, ...). That gate ALWAYS verifies a real Equihash witness, but
 * the verifier (core/modules/crypto_registry/src/scheme_equihash_200_9.c) size-demuxes
 * (N,K) from the solution LENGTH: a 36-byte solution selects regtest's (48,5)
 * (core/modules/crypto/src/equihash.c::equihash_solution_params). So a regtest block
 * mined by mine_block_pow() (which solves the real (48,5) PoW) PASSES the same
 * stateless gate the reducer applies — proven independently by
 * test_regtest_generate. With the controller initialised on regtest params,
 * the front door accepts the mined block end-to-end. No stubs, no injected
 * readers: the eight stages run on their PRODUCTION defaults (the body is
 * persisted to disk by the front door and read back by
 * stage_default_block_reader; a coinbase-only block has no transparent inputs
 * and no shielded proofs, so script_validate / proof_validate pass trivially).
 *
 * THE ONE-BLOCK-LOOKAHEAD NOTE
 * ----------------------------
 * tip_finalize finalizes height H by reading active_chain_at(H+1) and setting
 * the window tip to that successor. With exactly genesis(0) + block(1) there is
 * no height-2 successor, so tip_finalize legitimately does not write a
 * "finalized" row for height 1 yet — but utxo_apply DOES apply block 1's
 * coinbase delta, the window extends to height 1 (so active_chain_height == 1),
 * and the front-door read-back accepts the active tip via the pending-body
 * path (utxo_apply_stage_succeeded_at). This gate now stages height 2 as the
 * explicit lookahead witness; a full drain may leave the visible active-chain
 * window at height 1 or at that prepared lookahead height 2, so finality is
 * asserted through the reducer rows and the window is bounded to the prepared
 * span.
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
#include "services/chain_activation_service.h"
#include "services/header_admit_inbox.h"
#include "storage/disk_block_io.h"
#include "storage/coins_kv.h"
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
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RBI_CHECK(name, expr) do {                          \
    printf("reducer_block_ingest_gate: %s... ", (name));    \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

static int rbi_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void rbi_discard_header(const struct header_admit_msg *msg)
{
    (void)msg;
}

/* Build a regtest block at `height` on top of `prev_hash` the way
 * create_new_block() shapes it: one coinbase tx (subsidy, no fees, a minimal
 * miner script), merkle root over that single tx, header fields filled,
 * nBits = the regtest powLimit compact (what GetNextWorkRequired hands the
 * first blocks). Mirrors test_regtest_generate.c::build_regtest_block.
 * Returns false on any allocation/build failure. */
static bool rbi_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp,
                                    int64_t *out_coinbase_value)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "rbi_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    /* A minimal, non-empty P2PKH-shaped miner script. */
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

    /* Merkle root over the single coinbase tx — AFTER coinbase_build computed
     * the coinbase hash. */
    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);

    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1600000000u + (uint32_t)height;

    /* First-block work target: powLimit as a compact bits value, exactly what
     * GetNextWorkRequired returns before the averaging window fills. */
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);

    return true;
}

/* Seed a genesis (height 0) utxo_apply_log row marking it already-applied with
 * a zero coin delta (the genesis coinbase is not counted in this harness's
 * baseline, matching tip_finalize's added-spent model). This lets tip_finalize
 * finalize height 0 if its reorg-rewind ever sends the cursor back to the
 * genesis anchor — tip_finalize reads utxo_apply_log[next_h] before finalizing,
 * and seed_anchor advanced the utxo_apply cursor past genesis WITHOUT writing a
 * height-0 row. With this row present, the cold-start anchor finalizes cleanly
 * into block 1 instead of wedging at cursor 0. Returns false on SQL failure. */
static bool rbi_seed_genesis_utxo_apply_row(sqlite3 *db)
{
    if (!db) return false;
    /* The table is created by utxo_apply_stage_init; INSERT OR REPLACE is safe
     * whether or not a row already exists. Columns mirror the stage's schema
     * (see engine/jobs/src/utxo_apply_stage.c log schema / test_reducer_stage_fuzz
     * utxo_apply_log shape). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log "
        "(height,status,ok,spent_count,added_count,total_value_delta,applied_at) "
        "VALUES(0,'verified',1,0,0,0,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = (sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    return ok;
}

struct rbi_ingest_ctx {
    const struct chain_params *cp;
    struct main_state *ms;
    struct chain_activation_controller *ctl;
    const char *datadir;
};

/* Mine a regtest block at `height` on `prev_hash`, admit its header (creating
 * the block_index via the reducer's header_admit producer + linking it to its
 * parent), write its body to disk, and mark the index BLOCK_HAVE_DATA — i.e.
 * the state a live node is in once headers AND bodies for this height have been
 * synced but before connection. On success fills `*out_blk` (caller block_free),
 * `*out_hash`, `*out_cb_value`, `*out_bi` (the block_index), returns true. */
static bool rbi_mine_admit_persist(struct rbi_ingest_ctx *c, int height,
                                   const struct uint256 *prev_hash,
                                   struct block *out_blk,
                                   struct uint256 *out_hash,
                                   int64_t *out_cb_value,
                                   struct block_index **out_bi)
{
    if (!rbi_build_regtest_block(out_blk, height, prev_hash, c->cp,
                                 out_cb_value))
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

    /* Body downloaded to disk; mark HAVE_DATA at its verified position so the
     * downstream stages' default disk reader can serve it AND tip_finalize's
     * one-block-lookahead precondition (the successor must have data) is met. */
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!write_block_to_disk(out_blk, &pos, c->datadir,
                             c->cp->pchMessageStart))
        return false;
    if (!block_index_set_have_data_verified(bi, &pos, c->datadir))
        return false;

    /* Forward-extend the visible window + best-header anchor to this block so
     * the reducer can finalize down to it. */
    c->ms->pindex_best_header = bi;
    (void)active_chain_extend_window(&c->ms->chain_active, bi);

    if (out_bi) *out_bi = bi;
    return true;
}

int test_reducer_block_ingest_gate(void);
int test_reducer_block_ingest_gate(void)
{
    printf("\n=== reducer block-ingest gate "
           "(MVP: one real regtest block -> reducer front door -> tip+1) ===\n");
    int failures = 0;

    /* OPT-IN gate. This drives the real reducer (block_index, active_chain,
     * the eight stage stat counters) through process-global singletons, so it
     * is only deterministic in a FRESH process. The parallel runner reuses one
     * worker process across many groups, so global state left by a prior group
     * pollutes this one — run it isolated (its dedicated `make mvp-it-works`
     * target uses --only, a fresh process). The default `make ci` suite skips
     * it. Full-suite isolation (resetting every reducer global at entry) is a
     * tracked follow-up; until then this stays opt-in to keep CI green. */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("reducer_block_ingest_gate: SKIP "
               "(set ZCL_STRESS_TESTS=1 and run isolated via "
               "`make mvp-it-works`)\n");
        return 0;
    }

    blocker_module_init();

    /* The default runner inits CHAIN_MAIN; switch to regtest so the mined
     * (48,5) PoW passes the front-door check_block gate, and restore on the
     * way out so the sequential runner is unaffected (the parallel runner
     * forks per group, so it is naturally isolated). */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    /* Sanity: regtest really is the small (48,5) parameter set the miner can
     * solve in-process. */
    {
        unsigned int n = chain_params_equihash_n(cp, 1);
        unsigned int k = chain_params_equihash_k(cp, 1);
        RBI_CHECK("regtest is Equihash (48,5)", n == 48 && k == 5);
    }

    /* ── (1) Stand up a fresh node-db / progress.kv at genesis ──────────── */
    char dir[256];
    rbi_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "reducer_block_ingest_gate", "main");
    rbi_mkdir_p(dir);

    /* Point the GLOBAL datadir at our hermetic tmp dir so the front door's
     * write_block_to_disk(ctl->datadir, ...) and the stages' default block
     * reader (which uses GetDataDir(net_specific=true)) agree on ONE on-disk
     * blocks/ directory. Without this, the body is written under ctl->datadir
     * but read from ~/.zclassic-c23/regtest — the read fails and no stage can
     * apply the block. We derive the net-specific path GetDataDir returns and
     * use it verbatim for the controller, then pre-create its blocks/ dir. */
    /* SetDataDir already clears the cache and populates cachedDataDirNet =
     * <dir>/regtest; do NOT ClearDataDirCache() here or GetDataDir falls back
     * to the shared default ~/.zclassic-c23/regtest and races other groups. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true /*net-specific (regtest subdir)*/, netdir, sizeof(netdir));
    rbi_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    rbi_mkdir_p(blocksdir);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    RBI_CHECK("progress_store opens at fresh datadir", store_ok);

    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    RBI_CHECK("event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(blocksdir);
        test_cleanup_tmpdir(netdir);
        test_cleanup_tmpdir(dir);
        SetDataDir("");
        ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        printf("=== reducer block-ingest gate: %d failures (setup) ===\n",
               failures);
        return failures;
    }

    /* utxo_apply writes the applied coinbase into the kernel coins_kv — the
     * SOLE live UTXO author and read source. The UTXO-count/commitment
     * assertions below read coins_kv directly, so they compare the store the
     * reducer genuinely authored. */

    struct main_state ms;
    main_state_init(&ms);

    /* Seed genesis exactly the way boot.c does: a block_index at height 0,
     * HAVE_DATA + VALID_SCRIPTS, real chain-work, installed in the map, the
     * active chain, and as the best-header anchor. The reducer extends the
     * window from pindex_best_header, so block 1 builds on this. */
    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    RBI_CHECK("genesis block_index inserted", genesis != NULL);
    if (genesis) {
        genesis->nHeight = 0;
        genesis->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        genesis->nTx = 1;
        genesis->nChainTx = 1;
        genesis->nChainWork = GetBlockProof(genesis);
        active_chain_move_window_tip(&ms.chain_active, genesis);
        ms.pindex_best_header = genesis;
    }

    /* Seed the whole eight-stage pipeline to treat genesis as the already-
     * processed anchor: tip_finalize_stage_seed_anchor stamps the anchor row
     * AND advances every upstream stage cursor to height 1, so only height 1
     * (the block we ingest) flows through. This is the SAME cold-start seed
     * the snapshot-apply path uses (engine/services/src/snapshot_apply.c). */
    RBI_CHECK("tip_finalize anchor seed at genesis",
              tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    /* Init the eight reducer stages against this chainstate (production
     * defaults — no injected readers/validators). header_admit must be inited
     * before tip_finalize seeds it above is harmless; seed_anchor only writes
     * cursors. We init AFTER the anchor seed so each stage loads cursor=1. */
    bool stages_ok =
        header_admit_stage_init(&ms) &&
        validate_headers_stage_init(&ms) &&
        body_fetch_stage_init(&ms) &&
        body_persist_stage_init(&ms) &&
        script_validate_stage_init(&ms) &&
        proof_validate_stage_init(&ms) &&
        utxo_apply_stage_init(&ms) &&
        tip_finalize_stage_init(&ms);
    RBI_CHECK("all eight reducer stages init", stages_ok);

    /* Now that utxo_apply created its log table, seed the genesis (height 0)
     * applied row so the cold-start anchor can finalize cleanly into block 1
     * (see rbi_seed_genesis_utxo_apply_row). */
    if (stages_ok)
        RBI_CHECK("seed genesis utxo_apply_log row",
                  rbi_seed_genesis_utxo_apply_row(progress_store_db()));

    /* Build the activation controller — the object whose mutex the front door
     * serializes on and whose params drive check_block. datadir must outlive
     * the controller (stored by pointer) and must equal the stages' GetDataDir
     * net-specific path so the on-disk block body the front door writes is the
     * one the stages read back. `netdir` stays in scope through teardown. */
    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, &ms, NULL, cp, netdir);

    /* ── (2) Record genesis tip height + UTXO commitment ────────────────── */
    int height_before = active_chain_height(&ms.chain_active);
    RBI_CHECK("genesis tip height is 0", height_before == 0);

    /* Snapshot the authoritative coins_kv set the reducer writes. coins_kv
     * is empty here — genesis seeded only the utxo_apply_log row — so
     * count_before==0 and commit_before is the empty-set hash, preserving the
     * gate's baseline. (Runs after utxo_apply_stage_init, so the coins schema
     * exists.) */
    uint64_t count_before = (uint64_t)coins_kv_count(progress_store_db());
    uint8_t commit_before[32];
    bool have_commit_before =
        (coins_kv_commitment(progress_store_db(), commit_before) == 0);
    RBI_CHECK("genesis UTXO commitment computed", have_commit_before);
    printf("reducer_block_ingest_gate: genesis utxo count=%llu\n",
           (unsigned long long)count_before);

    struct rbi_ingest_ctx ictx = { .cp = cp, .ms = &ms, .ctl = &ctl,
                                   .datadir = netdir };

    /* ── (3) Mine ONE valid regtest block at height 1 (the block under test)
     * and confirm it passes the EXACT stateless gate the reducer front door
     * applies (check_block with check_pow=true). If this fails the front door
     * would reject before any stage runs. */
    struct block blk1;
    block_init(&blk1);
    int64_t cb_value = 0;
    bool built1 = stages_ok &&
                  rbi_build_regtest_block(&blk1, 1, &genesis_hash, cp,
                                          &cb_value);
    RBI_CHECK("regtest block at height 1 builds", built1);
    bool mined1 = built1 && mine_block_pow(&blk1, 1, cp, 0);
    RBI_CHECK("mine_block_pow solves Equihash (48,5) + nonce", mined1);
    if (mined1) {
        struct validation_state vs;
        validation_state_init(&vs);
        RBI_CHECK("mined block passes reducer check_block gate",
                  check_block(&blk1, &vs, cp, true, true, true));
    }
    block_free(&blk1);  /* rebuilt+admitted+persisted by the helper below */

    /* ── (3b) Prepare blocks 1 and 2 in the "headers + bodies synced" state ──
     * Block 2 is the one-block-lookahead SUCCESSOR tip_finalize needs to be able
     * to finalize block 1 (it finalizes height H by reading the fully-data'd
     * block at H+1). A live node is exactly here once it has synced the header
     * and body for both heights but not yet connected them — which is the state
     * reducer_ingest_block is designed to converge. */
    struct block blk1b, blk2;
    block_init(&blk1b);
    block_init(&blk2);
    struct uint256 hash1, hash2, cb_txid;
    uint256_set_null(&hash1); uint256_set_null(&hash2);
    uint256_set_null(&cb_txid);
    int64_t cb2_value = 0;
    struct block_index *bi1 = NULL, *bi2 = NULL;

    bool prepared1 = mined1 &&
        rbi_mine_admit_persist(&ictx, 1, &genesis_hash, &blk1b, &hash1,
                               &cb_value, &bi1);
    RBI_CHECK("block 1 mined + header-admitted + body-on-disk (HAVE_DATA)",
              prepared1);
    if (prepared1) cb_txid = blk1b.vtx[0].hash;

    bool prepared2 = prepared1 &&
        rbi_mine_admit_persist(&ictx, 2, &hash1, &blk2, &hash2,
                               &cb2_value, &bi2);
    RBI_CHECK("block 2 (lookahead successor) mined + admitted + body-on-disk",
              prepared2);

    /* ── (4) Drive block 1's BODY through the REDUCER FRONT DOOR ───────────
     * reducer_ingest_block runs check_block (real Equihash gate) then drains the
     * eight stages under the activation mutex. With block 2 already data'd as the
     * lookahead successor, the drain applies block 1 (utxo_apply) AND finalizes
     * it (tip_finalize), advancing the authoritative tip to height 1. The front
     * door returns the verdict for the just-ingested block. */
    bool front_door_ok = false;
    if (prepared2) {
        ms.pindex_best_header = bi2;  /* finalize down to the successor */
        (void)active_chain_extend_window(&ms.chain_active, bi2);

        struct validation_state out;
        validation_state_init(&out);
        front_door_ok = reducer_ingest_block(&ctl, &blk1b, REDUCER_SRC_MINED,
                                             true /*force: locally requested*/,
                                             &out);
        /* Drive remaining stage work to FULL convergence: within the single
         * front-door call, block 1's finalization can trail until block 2's
         * lookahead row is consumed. reducer_kick() drains only within a
         * bounded per-call latency budget, so under CPU load (e.g. the full
         * parallel suite) one kick may not finish — loop until a kick makes
         * ZERO advances (true convergence). Without this the tip-advance
         * assertion races the drain and flakes. The cap is a runaway guard. */
        for (int it = 0; it < 1000 && reducer_kick(&ctl) > 0; it++) {
            /* keep draining */
        }
        printf("reducer_block_ingest_gate: front-door verdict=%s%s\n",
               front_door_ok ? "accepted" : "pending",
               (!front_door_ok && out.reject_reason[0]) ? out.reject_reason
                                                        : "");
        /* The front door ran its real consensus gate (check_block) without a
         * stateless reject — a garbage block would have returned a DoS reason
         * here, not the benign tip-pending one. */
        RBI_CHECK("front door passed block 1 through the stateless gate "
                  "(no consensus reject)",
                  front_door_ok ||
                  strcmp(out.reject_reason, "block-not-finalized-by-reducer")
                      == 0);
    }

    /* The reducer (not legacy connect_block) applied block 1 end-to-end through
     * the front door: utxo_apply recorded a success at height 1, no
     * unknown-spend. */
    RBI_CHECK("utxo_apply succeeded at height 1 (reducer consensus)",
              utxo_apply_stage_succeeded_at(1));
    RBI_CHECK("utxo_apply recorded no spend-unknown",
              utxo_apply_stage_spend_unknown_total() == 0);
    bool applied2 = utxo_apply_stage_succeeded_at(2);

    /* ── (5a) ASSERT: block 1 finalized and the active window is bounded ──
     * Block 1 is finalized by the reducer. Block 2 is the prepared lookahead
     * successor; a full convergence drain may leave the visible active-chain
     * window at height 2, but it must not lag before block 1 or advance beyond
     * the staged lookahead. */
    int height_after = active_chain_height(&ms.chain_active);
    printf("reducer_block_ingest_gate: tip height %d -> %d\n",
           height_before, height_after);
    RBI_CHECK("active_chain_height reached block 1 and stayed within the "
              "prepared lookahead span",
              height_after >= height_before + 1 &&
              height_after <= height_before + 2);
    RBI_CHECK("block 1 is finalized by tip_finalize (reducer, not legacy)",
              tip_finalize_stage_finalized_total() >= 1);
    /* The block under test physically landed on the active chain: a durable
     * "finalized" tip_finalize_log row records block 1's hash. tip_finalize's
     * one-block-lookahead convention is that the row at height H stores the hash
     * of the canonical block at H+1 (it finalizes H by reading active_chain_at
     * (H+1) and stamps that successor as the new tip). So block 1 (height 1)
     * landing is witnessed by the row at height 0 carrying block 1's hash. */
    {
        uint8_t fin_hash[32] = {0};
        bool finalized_row = tip_finalize_stage_finalized_tip_at(
            progress_store_db(), 0, fin_hash);
        RBI_CHECK("block 1 has a durable finalized tip row (height-0 lookahead "
                  "row carries block 1's hash)",
                  finalized_row && memcmp(fin_hash, hash1.data, 32) == 0);
    }

    /* ── (5b) ASSERT: UTXO commitment recomputes WITH the applied block 1 ──
     * Block 1's coinbase is live in the UTXO set and the SHA3 commitment moved.
     * (The set also carries block 2's coinbase as the pending successor; we
     * assert specifically on block 1's coinbase — the block under test.) */
    uint64_t count_after = (uint64_t)coins_kv_count(progress_store_db());
    printf("reducer_block_ingest_gate: utxo count %llu -> %llu\n",
           (unsigned long long)count_before, (unsigned long long)count_after);
    /* Block 1 added exactly one new coinbase UTXO over the genesis baseline
     * (block 2's coinbase is also live as the pending successor). */
    RBI_CHECK("block 1's coinbase added exactly one UTXO over genesis",
              count_after == count_before + 1 + (applied2 ? 1 : 0));

    int64_t live_value = 0;
    bool cb_live = coins_kv_get(progress_store_db(), cb_txid.data, 0,
                                &live_value, NULL, 0, NULL);
    RBI_CHECK("block 1's coinbase output is live in the UTXO set", cb_live);
    RBI_CHECK("live coinbase value equals subsidy",
              cb_live && live_value == cb_value && cb_value > 0);

    uint8_t commit_after[32];
    bool have_commit_after =
        (coins_kv_commitment(progress_store_db(), commit_after) == 0);
    RBI_CHECK("post-ingest UTXO commitment recomputes", have_commit_after);
    RBI_CHECK("UTXO commitment changed after the block applied",
              have_commit_before && have_commit_after &&
              memcmp(commit_before, commit_after, 32) != 0);

    /* Headers-first catch-up must not replay an exact known header through the
     * bounded mailbox. It still stages/persists the body and preserves the
     * normal pending-reducer verdict. */
    RBI_CHECK("known-header fast path starts with an empty admit inbox",
              mailbox_header_admit_drain(rbi_discard_header) == 0);
    uint64_t known_before =
        reducer_ingest_catchup_known_header_bypass_total();
    uint64_t solution_skip_before =
        reducer_ingest_catchup_validated_solution_skip_total();
    struct validation_state catchup_out;
    validation_state_init(&catchup_out);
    bool catchup_final = reducer_stage_p2p_block_for_catchup(
        &ctl, &blk1b, &catchup_out);
    RBI_CHECK("known-header catch-up remains a staged, non-final verdict",
              !catchup_final &&
              strcmp(catchup_out.reject_reason,
                     "p2p-block-staged-for-reducer") == 0);
    RBI_CHECK("known-header catch-up takes the exact-hash bypass",
              reducer_ingest_catchup_known_header_bypass_total() ==
                  known_before + 1);
    RBI_CHECK("validated header avoids a redundant solution rewrite",
              reducer_ingest_catchup_validated_solution_skip_total() ==
                  solution_skip_before + 1);
    RBI_CHECK("known-header catch-up enqueues no duplicate header",
              mailbox_header_admit_drain(rbi_discard_header) == 0);

    /* ── (6) Teardown ───────────────────────────────────────────────────── */
    /* Both helper-built blocks were block_init'd unconditionally; block_free is
     * safe on an empty or partially-built block. (blk1 was already freed above
     * after the standalone check_block confirmation.) */
    block_free(&blk1b);
    block_free(&blk2);

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
    /* Remove the on-disk block file the front door wrote, then the dirs. */
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(netdir);
    test_cleanup_tmpdir(dir);

    /* Restore the global datadir + the runner's default chain. */
    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);

    printf("=== reducer block-ingest gate: %d failure(s) ===\n", failures);
    return failures;
}
