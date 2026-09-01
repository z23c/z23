/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_rederive_range — the universal re-derive primitive
 * (docs/work/fail-safe-architecture.md §0c), proven end-to-end on a REAL fold.
 *
 * Folds three real Equihash-mined regtest blocks to a tip, then damages a
 * mid-chain RANGE of the durable stage logs with the three birth shapes the
 * primitive must absorb without a bespoke detector:
 *   - a STALE verdict (script_validate_log h=2 forced ok=0),
 *   - a ROWLESS hole (proof_validate_log h=2 deleted),
 * both left BELOW the stage cursors (the exact "state at h contradicts the
 * fold/log contract" class). It then:
 *   1. calls stage_rederive_range(2,3) and asserts the rewind: the stale suffix
 *      rows are deleted, every body-dependent cursor is lowered to 2, coins are
 *      inverse-rewound to 2, and header authority (validate_headers) is
 *      untouched — cursors contiguous, no stale suffix survives;
 *   2. calls it AGAIN and asserts idempotency (a second call is a clean no-op);
 *   3. re-drives the forward fold and asserts BYTE-IDENTICAL re-derivation:
 *      the stale ok=0 becomes ok=1, the rowless hole is refilled ok=1, coins
 *      re-apply, and a downstream consumer (utxo_apply) advances back to tip.
 *
 * Scaffolding (datadir/stores/block builder/genesis seed) mirrors
 * test_reducer_step_drain_harness.c — production step bodies, no stubs. */

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
#include "services/header_admit_inbox.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/stage_rederive_range.h"
#include "jobs/created_outputs_index.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define SR_CHECK(name, expr) do {                          \
    printf("stage_rederive_range: %s... ", (name));        \
    if ((expr)) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* Lane-A1 reorg-unwind transaction mechanics (src-private header
 * engine/reducer/jobs/src/reducer_frontier_replay_tx.h — forward-declared here, matching
 * the house pattern for src-private stage primitives under test). */
bool reducer_frontier_replay_stale_script_tx(
    sqlite3 *db, struct main_state *ms, int height, int replay_first,
    int script_cursor, int proof_cursor, int utxo_cursor, int tip_cursor,
    int backfill_top, bool rewind_headers);
bool reducer_frontier_replay_backfill_created_outputs_projection(
    struct main_state *ms, int replay_first, int backfill_top);
void reducer_frontier_replay_tx_commit_seqs(uint64_t *kernel_out,
                                            uint64_t *projection_out);

static int sr_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* One-coinbase regtest block (identical shape to sd_build_regtest_block). */
static bool sr_build_block(struct block *blk, int height,
                           const struct uint256 *prev_hash,
                           const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "sr_vtx");
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

static bool sr_seed_genesis_utxo_apply_row(sqlite3 *db)
{
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

/* SELECT <col> FROM <table> WHERE height=? -> int (false if no row/error). */
static bool sr_log_int(sqlite3 *db, const char *table, const char *col,
                       int height, int64_t *out)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT %s FROM %s WHERE height=?", col, table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-sql-ok:test-readback
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:test-readback
        *out = sqlite3_column_int64(st, 0);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

static bool sr_has_row(sqlite3 *db, const char *table, int height)
{
    int64_t dummy = 0;
    return sr_log_int(db, table, "height", height, &dummy);
}

/* Highest height present in a stage log (-1 if empty). */
static int sr_max_height(sqlite3 *db, const char *table)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COALESCE(MAX(height),-1) FROM %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -2;  // raw-sql-ok:test-readback
    int v = -2;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int sr_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name=?",
                           -1, &st, NULL) != SQLITE_OK)
        return -2;  // raw-sql-ok:test-readback
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int v = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int sr_coins_applied(sqlite3 *db)
{
    int32_t v = -1;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &v, &found) || !found)
        return -1;
    return (int)v;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);  // raw-sql-ok:test-seed
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* created_outputs row count over [lo,hi] inclusive (-1 on error). */
static int sr_co_count_range(sqlite3 *db, int lo, int hi)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM created_outputs WHERE height BETWEEN ? AND ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;  // raw-sql-ok:test-readback
    sqlite3_bind_int(st, 1, lo);
    sqlite3_bind_int(st, 2, hi);
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* Fold ONE mined block through the eight stages (single-stepped, production
 * bodies). Returns the block hash for chaining; sets *ok=false on any failure. */
static struct uint256 sr_fold_one(struct main_state *ms,
                                  const struct chain_params *cp,
                                  const char *netdir, int height,
                                  const struct uint256 *prev, bool *ok)
{
    struct uint256 hash;
    uint256_set_null(&hash);
    struct block blk;
    if (!sr_build_block(&blk, height, prev, cp) ||
        !mine_block_pow(&blk, height, cp, 0)) {
        *ok = false;
        return hash;
    }
    block_get_hash(&blk, &hash);

    struct header_admit_msg m;
    memset(&m, 0, sizeof(m));
    m.hash = hash;
    m.has_header = true;
    m.header = blk.header;
    m.height = -1;
    if (!mailbox_header_admit_push(&m)) { *ok = false; block_free(&blk); return hash; }

    (void)header_admit_stage_drain(100);
    struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
    if (!bi) { *ok = false; block_free(&blk); return hash; }
    (void)validate_headers_stage_drain(100);

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    bool persisted = write_block_to_disk(&blk, &pos, netdir, cp->pchMessageStart) &&
                     block_index_set_have_data_verified(bi, &pos, netdir);
    if (!persisted) { *ok = false; block_free(&blk); return hash; }

    (void)body_fetch_stage_step_once();
    (void)body_persist_stage_step_once();
    (void)script_validate_stage_step_once();
    (void)proof_validate_stage_step_once();
    (void)utxo_apply_stage_step_once();
    (void)tip_finalize_stage_step_once();
    tip_finalize_stage_set_authoritative_tip(height, hash.data);

    block_free(&blk);
    return hash;
}

/* Drive the body-dependent stages forward across [lo, hi] after a rewind. Each
 * round folds one height across the pipeline in stage order. */
static void sr_redrive(int lo, int hi)
{
    for (int h = lo; h <= hi; h++) {
        (void)body_fetch_stage_step_once();
        (void)body_persist_stage_step_once();
        (void)script_validate_stage_step_once();
        (void)proof_validate_stage_step_once();
        (void)utxo_apply_stage_step_once();
        (void)tip_finalize_stage_step_once();
    }
}

int test_stage_rederive_range(void);
int test_stage_rederive_range(void)
{
    int failures = 0;

    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    sr_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "stage_rederive_range", "main");
    sr_mkdir_p(dir);
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    sr_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    sr_mkdir_p(blocksdir);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    projection_store_close();
    bool store_ok = progress_store_open(dir);
    SR_CHECK("progress_store opens", store_ok);
    /* Wave A2 split: the created_outputs backfill (TX2) runs on the projection
     * handle — open it so the projection commit is exercised. */
    SR_CHECK("projection_store opens", !store_ok || projection_store_open(dir));
    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    SR_CHECK("event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        projection_store_close();
        progress_store_close();
        SetDataDir(""); ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        printf("=== stage_rederive_range: %d failures (setup) ===\n", failures);
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
    SR_CHECK("genesis inserted", genesis != NULL);

    bool stages_ok =
        header_admit_stage_init(&ms) &&
        validate_headers_stage_init(&ms) &&
        body_fetch_stage_init(&ms) &&
        body_persist_stage_init(&ms) &&
        script_validate_stage_init(&ms) &&
        proof_validate_stage_init(&ms) &&
        utxo_apply_stage_init(&ms) &&
        tip_finalize_stage_init(&ms);
    SR_CHECK("all eight stages init", stages_ok);
    SR_CHECK("genesis utxo row seeded",
             sr_seed_genesis_utxo_apply_row(progress_store_db()));
    SR_CHECK("genesis anchor seeded",
             tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    sqlite3 *db = progress_store_db();

    /* ── Fold three real blocks to tip 3 ──────────────────────────────── */
    const int TIP = 3;
    struct uint256 prev = genesis_hash;
    bool fold_ok = stages_ok && genesis;
    for (int h = 1; h <= TIP && fold_ok; h++)
        prev = sr_fold_one(&ms, cp, netdir, h, &prev, &fold_ok);
    SR_CHECK("three blocks folded", fold_ok);
    SR_CHECK("tip at height 3", active_chain_height(&ms.chain_active) == TIP);
    SR_CHECK("utxo_apply cursor at 4 (next-to-apply past tip)",
             sr_cursor(db, "utxo_apply") == TIP + 1);
    SR_CHECK("coins applied frontier at 4", sr_coins_applied(db) == TIP + 1);

    if (!fold_ok || active_chain_height(&ms.chain_active) != TIP)
        goto teardown;

    /* ── Damage a mid-chain RANGE [2,3]: a STALE verdict + a ROWLESS hole ── */
    {
        sqlite3_stmt *st = NULL;
        (void)sqlite3_prepare_v2(db,
            "UPDATE script_validate_log SET ok=0, status='stale_test' "
            "WHERE height=2", -1, &st, NULL);
        (void)sqlite3_step(st);  // raw-sql-ok:test-seed
        sqlite3_finalize(st);
        st = NULL;
        (void)sqlite3_prepare_v2(db,
            "DELETE FROM proof_validate_log WHERE height=2", -1, &st, NULL);
        (void)sqlite3_step(st);  // raw-sql-ok:test-seed
        sqlite3_finalize(st);
    }
    {
        int64_t sv = -1;
        bool stale = sr_log_int(db, "script_validate_log", "ok", 2, &sv) && sv == 0;
        SR_CHECK("precondition: script_validate h=2 forced STALE ok=0", stale);
        SR_CHECK("precondition: proof_validate h=2 is a ROWLESS hole",
                 !sr_has_row(db, "proof_validate_log", 2));
        SR_CHECK("precondition: cursors still ahead (stale rows below cursor)",
                 sr_cursor(db, "script_validate") == TIP + 1 &&
                 sr_cursor(db, "proof_validate") == TIP + 1);
    }

    /* ── (1) Re-derive the range [2,3] ────────────────────────────────── */
    struct stage_rederive_range_result rr;
    bool called = stage_rederive_range(db, &ms, 2, 3, &rr);
    SR_CHECK("stage_rederive_range returned true (no store error)", called);
    SR_CHECK("result: committed (ok) + rewound + coins_rewound, no refusal",
             rr.ok && rr.rewound && rr.coins_rewound && !rr.refused_no_inverse);
    SR_CHECK("result: coins frontier before was 4", rr.coins_frontier_before == TIP + 1);

    /* Rewind assertions: stale suffix deleted, cursors lowered + contiguous. */
    SR_CHECK("rewind: script_validate suffix [2,] deleted",
             !sr_has_row(db, "script_validate_log", 2) &&
             !sr_has_row(db, "script_validate_log", 3));
    SR_CHECK("rewind: proof_validate suffix [2,] deleted",
             !sr_has_row(db, "proof_validate_log", 2) &&
             !sr_has_row(db, "proof_validate_log", 3));
    SR_CHECK("rewind: utxo_apply suffix [2,] deleted",
             !sr_has_row(db, "utxo_apply_log", 2) &&
             !sr_has_row(db, "utxo_apply_log", 3));
    SR_CHECK("rewind: coins frontier inverse-rewound to 2",
             sr_coins_applied(db) == 2);
    SR_CHECK("rewind: body_fetch cursor lowered to 2",
             sr_cursor(db, "body_fetch") == 2);
    SR_CHECK("rewind: body_persist cursor lowered to 2",
             sr_cursor(db, "body_persist") == 2);
    SR_CHECK("rewind: script_validate cursor lowered to 2",
             sr_cursor(db, "script_validate") == 2);
    SR_CHECK("rewind: proof_validate cursor lowered to 2",
             sr_cursor(db, "proof_validate") == 2);
    SR_CHECK("rewind: utxo_apply cursor lowered to 2",
             sr_cursor(db, "utxo_apply") == 2);
    SR_CHECK("rewind: tip_finalize cursor lowered to 2",
             sr_cursor(db, "tip_finalize") == 2);
    /* Contiguity: no rederived-stage row survives at/above its cursor. */
    SR_CHECK("contiguity: no script_validate row >= cursor 2",
             sr_max_height(db, "script_validate_log") < 2);
    SR_CHECK("contiguity: no utxo_apply row >= cursor 2",
             sr_max_height(db, "utxo_apply_log") < 2);
    /* Header authority preserved: validate_headers untouched by the re-derive. */
    SR_CHECK("header authority: validate_headers cursor UNCHANGED at 4",
             sr_cursor(db, "validate_headers") == TIP + 1);
    SR_CHECK("header authority: validate_headers rows [2,3] intact",
             sr_has_row(db, "validate_headers_log", 2) &&
             sr_has_row(db, "validate_headers_log", 3));
    /* Served-floor invariant: tip_finalize_log ROWS preserved (cursor-only). */
    SR_CHECK("served-floor: tip_finalize_log rows [2,3] preserved (not deleted)",
             sr_has_row(db, "tip_finalize_log", 2) &&
             sr_has_row(db, "tip_finalize_log", 3));

    /* ── (2) Idempotency: a second call on the rewound state is a no-op ── */
    struct stage_rederive_range_result rr2;
    bool called2 = stage_rederive_range(db, &ms, 2, 3, &rr2);
    SR_CHECK("idempotent: second call returns ok, nothing rewound",
             called2 && rr2.ok && !rr2.rewound && rr2.cursors_rewound == 0 &&
             !rr2.coins_rewound);
    SR_CHECK("idempotent: cursors unchanged after second call",
             sr_cursor(db, "utxo_apply") == 2 && sr_cursor(db, "tip_finalize") == 2);

    /* ── (3) Re-fold: byte-identical re-derivation + downstream advance ── */
    sr_redrive(2, TIP);
    {
        int64_t sv = -1, pv = -1, ua = -1;
        SR_CHECK("re-derive: script_validate h=2 recomputed ok=1 (was stale 0)",
                 sr_log_int(db, "script_validate_log", "ok", 2, &sv) && sv == 1);
        SR_CHECK("re-derive: proof_validate h=2 refilled ok=1 (was rowless)",
                 sr_log_int(db, "proof_validate_log", "ok", 2, &pv) && pv == 1);
        SR_CHECK("re-derive: utxo_apply h=2 re-applied ok=1",
                 sr_log_int(db, "utxo_apply_log", "ok", 2, &ua) && ua == 1 &&
                 utxo_apply_stage_succeeded_at(2));
        SR_CHECK("re-derive: utxo_apply h=3 re-applied ok=1",
                 utxo_apply_stage_succeeded_at(3));
    }
    SR_CHECK("downstream consumer advanced: utxo_apply cursor back to 4",
             sr_cursor(db, "utxo_apply") == TIP + 1);
    SR_CHECK("downstream consumer advanced: coins frontier back to 4",
             sr_coins_applied(db) == TIP + 1);

    /* ── Lane A1: reducer_frontier stale-script rewind = kernel(TX1) then
     * projection(TX2); crash between them still converges ─────────────────
     * reducer_frontier_replay_stale_script_tx now commits the KERNEL rewind
     * (coins/cursors/logs) in TX1 BEFORE the created_outputs backfill in TX2.
     * The state is back at tip 4 (a clean, never-crashed control). We capture
     * the control coins commitment, drive the reducer_frontier rewind of
     * [2,3] directly, assert (case 3) TX2 committed strictly AFTER TX1, then
     * (case 2) simulate a crash between TX1 and TX2 by deleting the span's
     * created_outputs (as if TX2 never committed AND the surviving body_persist
     * rows were absent) and re-fold — the coins commitment must return to the
     * control. Proof that the created_outputs projection is NOT load-bearing
     * for the kernel result; prevout resolution's coins_kv fallback is covered
     * by test_stage_repair_coin_backfill / test_script_validate_stage. */
    {
        int ctrl_coins = coins_kv_count(db);
        int ctrl_applied = sr_coins_applied(db);

        uint64_t k0 = 0, p0 = 0;
        reducer_frontier_replay_tx_commit_seqs(&k0, &p0);

        progress_store_tx_lock();
        bool tx_ok = reducer_frontier_replay_stale_script_tx(
            db, &ms, /*height*/2, /*replay_first*/2, /*script_cursor*/TIP + 1,
            /*proof_cursor*/TIP + 1, /*utxo_cursor*/TIP + 1,
            /*tip_cursor*/TIP + 1, /*backfill_top*/TIP, /*rewind_headers*/false);
        progress_store_tx_unlock();
        SR_CHECK("A1: stale_script_tx kernel TX1 ok", tx_ok);
        /* Wave A2 (D4): TX2 is now a SEPARATE projection-store call the driver
         * makes AFTER releasing the kernel lock (LOCK ORDER LAW). */
        bool bf_ok = reducer_frontier_replay_backfill_created_outputs_projection(
            &ms, /*replay_first*/2, /*backfill_top*/TIP);
        SR_CHECK("A1: created_outputs backfill (projection TX2) ok", bf_ok);

        uint64_t k1 = 0, p1 = 0;
        reducer_frontier_replay_tx_commit_seqs(&k1, &p1);
        /* case 3 — ordering: both advanced this repair, and the projection
         * commit carries a strictly greater sequence than the kernel commit
         * (TX2 never precedes TX1). */
        SR_CHECK("A1 ordering: kernel commit advanced", k1 > k0);
        SR_CHECK("A1 ordering: projection commit advanced", p1 > p0);
        SR_CHECK("A1 ordering: projection seq > kernel seq (TX2 after TX1)",
                 p1 > k1);

        /* Kernel rewind landed: coins/cursors at replay_first=2, header
         * authority untouched. */
        SR_CHECK("A1 rewind: coins frontier inverse-rewound to 2",
                 sr_coins_applied(db) == 2);
        SR_CHECK("A1 rewind: kernel cursors lowered to 2",
                 sr_cursor(db, "script_validate") == 2 &&
                 sr_cursor(db, "proof_validate") == 2 &&
                 sr_cursor(db, "utxo_apply") == 2 &&
                 sr_cursor(db, "tip_finalize") == 2);
        SR_CHECK("A1 rewind: validate_headers authority UNCHANGED at 4",
                 sr_cursor(db, "validate_headers") == TIP + 1);

        /* case 2 — crash between TX1 and TX2: drop the span's created_outputs
         * (TX2's effect) so the forward re-fold cannot rely on it. */
        (void)created_outputs_index_ensure_schema(db);
        SR_CHECK("A1 crash-sim: delete created_outputs [2,3] (TX2 skipped)",
                 exec_sql(db,
                          "DELETE FROM created_outputs WHERE height BETWEEN 2 AND 3") &&
                 sr_co_count_range(db, 2, 3) == 0);

        /* Forward re-fold from replay_first — must converge to the control. */
        sr_redrive(2, TIP);
        SR_CHECK("A1 converge: utxo_apply h=2 re-applied ok=1",
                 utxo_apply_stage_succeeded_at(2));
        SR_CHECK("A1 converge: utxo_apply h=3 re-applied ok=1",
                 utxo_apply_stage_succeeded_at(3));
        SR_CHECK("A1 converge: utxo_apply cursor back to 4",
                 sr_cursor(db, "utxo_apply") == TIP + 1);
        SR_CHECK("A1 converge: coins commitment == never-crashed control",
                 coins_kv_count(db) == ctrl_coins &&
                 sr_coins_applied(db) == ctrl_applied);
    }

teardown:
    tip_finalize_stage_shutdown();
    utxo_apply_stage_shutdown();
    proof_validate_stage_shutdown();
    script_validate_stage_shutdown();
    body_persist_stage_shutdown();
    body_fetch_stage_shutdown();
    validate_headers_stage_shutdown();
    header_admit_stage_shutdown();
    event_log_close(lg);
    projection_store_close();
    progress_store_close();
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(netdir);
    test_cleanup_tmpdir(dir);
    SetDataDir(""); ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);

    printf("=== stage_rederive_range: %d failures ===\n", failures);
    return failures;
}
