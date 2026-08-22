/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_repair_script_refill — FIX-2 script/proof missing-row refill.
 *
 * Covers both invocations of the shared scan+clamp core split across
 * app/jobs/src/stage_repair_reducer_frontier_refill_scan.c and
 * app/jobs/src/stage_repair_reducer_frontier_refill.c:
 *   - FIX-2b (post-refusal, inside reconcile_refill_cursors, reached through
 *     the full reconcile_light pipeline): a rowless script+proof hole at
 *     h0 == coins_applied clamps script/proof/tip_finalize to h0 and deletes
 *     nothing (T1).
 *   - FIX-2a (pre-refusal export stage_reducer_frontier_try_unapplied_hole_
 *     clamp, called directly until the orchestrator call site lands): bounds
 *     arithmetic [max(hstar+1, coins_applied), min(cursor-1, sweep_top)],
 *     positive clamp + negative (real tear below the frontier → zero writes).
 *   - The coins floor: a hole strictly below coins_applied is replay domain
 *     (WARN, no clamp), and an ok=0 row at the pin is a real verdict (no
 *     refill hole at all).
 *   - utxo_apply cursor byte-identical before/after EVERY path.
 *   - Drain-harness part (regtest, real Equihash + real stage step bodies,
 *     the test_reducer_step_drain_harness.c pattern): after the FIX-2b clamp
 *     the production script/proof/utxo stages refill the hole (INSERT OR
 *     REPLACE) and re-advance coins to the tip.
 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/header_admit_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/script_validate_stage.h"
#include "jobs/stage_repair.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/validate_headers_stage.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/header_admit_inbox.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Internal exports from the private reducer-frontier repair translation units
 * (declared in stage_repair_reducer_frontier_internal.h, which only
 * app/jobs/src includes) — local prototypes, kept in sync by the linker. */
extern bool stage_reducer_frontier_try_unapplied_hole_clamp(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out,
    bool *handled);
struct main_state;
extern bool stage_reducer_frontier_reconcile_refill_cursors(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out);

#define SRF_CHECK(name, expr) do { \
    printf("stage_repair_script_refill: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

/* The compiled-anchor floor is now NETWORK-DERIVED (genesis on regtest/testnet,
 * the mainnet SHA3 checkpoint on mainnet). This fixture deliberately mixes
 * regtest PARAMS (equihash 48,5, datadir) with MAINNET HEIGHTS (rows at A+1..),
 * so it must pin the floor to the mainnet anchor A explicitly rather than
 * relying on regtest inheriting it. The test entry sets the override to A and
 * restores -1 (production default) on exit. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* ── Part A fixture: synthetic progress.kv at the mainnet trusted anchor
 *    (the test_reducer_frontier_reconcile_light.c pattern). ─────────────── */

struct srf_fixture {
    char dir[256];
    struct main_state ms;
    struct uint256 hashes[4];
    struct block_index *idx[4];
};

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool seed_schema(sqlite3 *db)
{
    return
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            "parent_hash BLOB, admitted_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB, source TEXT,"
            "bytes INTEGER, fetched_at INTEGER, ok INTEGER,"
            "fail_reason TEXT)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "tip_hash BLOB)");
}

static bool seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool seed_all_cursors(sqlite3 *db, int cursor)
{
    return seed_cursor(db, "validate_headers", cursor) &&
           seed_cursor(db, "body_fetch", cursor) &&
           seed_cursor(db, "body_persist", cursor) &&
           seed_cursor(db, "script_validate", cursor) &&
           seed_cursor(db, "proof_validate", cursor) &&
           seed_cursor(db, "utxo_apply", cursor) &&
           seed_cursor(db, "tip_finalize", cursor);
}

static bool put_header_admit(sqlite3 *db, int height,
                             const struct uint256 *hash,
                             const struct uint256 *parent_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    if (parent_hash)
        sqlite3_bind_blob(st, 3, parent_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 3);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool put_body_fetch_ok(sqlite3 *db, int height,
                              const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO body_fetch_log"
            "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
            "VALUES(?,?,'disk',0,1,1,NULL)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool put_hash_log(sqlite3 *db, const char *table, const char *hash_col,
                         int height, int ok_flag, const struct uint256 *hash)
{
    char sql[192];
    if (strcmp(table, "validate_headers_log") == 0) {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,ok,%s) VALUES(?,?,?)",
                 table, hash_col);
    } else {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok,%s) "
                 "VALUES(?,'verified',?,?)",
                 table, hash_col);
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool put_simple_log(sqlite3 *db, const char *table, int height,
                           int ok_flag)
{
    char sql[160];
    if (strcmp(table, "body_persist_log") == 0) {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,source,ok) "
                 "VALUES(?,'fixture',?)",
                 table);
    } else {
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok) "
                 "VALUES(?,'verified',?)",
                 table);
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool put_tip_log(sqlite3 *db, int height, int ok_flag,
                        const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,tip_hash) VALUES(?,'finalized',?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool put_upstream_ok(sqlite3 *db, int height,
                            const struct uint256 *hash)
{
    sqlite3_stmt *delta = NULL;
    bool ok = put_hash_log(db, "validate_headers_log", "hash", height, 1,
                           hash) &&
              put_hash_log(db, "script_validate_log", "block_hash", height,
                           1, hash) &&
              put_simple_log(db, "body_persist_log", height, 1) &&
              put_hash_log(db, "proof_validate_log", "block_hash", height,
                           1, hash) &&
              put_simple_log(db, "utxo_apply_log", height, 1) &&
              sqlite3_prepare_v2(db,
                  "INSERT OR REPLACE INTO utxo_apply_delta"
                  "(height,branch_hash,spent_blob,added_blob) "
                  "VALUES(?,?,X'',X'')", -1, &delta, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int(delta, 1, height);
        sqlite3_bind_blob(delta, 2, hash->data, 32, SQLITE_STATIC);
        ok = sqlite3_step(delta) == SQLITE_DONE; // raw-sql-ok:test-seed
    }
    sqlite3_finalize(delta);
    return ok;
}

static bool delete_height(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE height=?", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool seed_coins_applied(sqlite3 *db, int64_t height)
{
    uint8_t blob[8];
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)((uint64_t)height >> (8 * i));

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, sizeof(blob), SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok) return false;
    /* Stamp full coins_kv proven-authority so compute_hstar honors the baked
     * TRUSTED_ANCHOR floor (these fixtures model a seeded datadir whose H*
     * clamps at the anchor with coins leading it). The phantom-anchor guard in
     * compute_hstar otherwise drops the floor to 0 when the store is not proven
     * authority — correct for a fresh datadir, wrong here. */
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {  // raw-sql-ok:test-seed
        sqlite3_free(err);
        return false;
    }
    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static int cursor_value(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

/* Total rows across every reducer log — the "no log row is ever deleted"
 * invariant witness. */
static int64_t total_log_rows(sqlite3 *db)
{
    static const char *const tables[] = {
        "header_admit_log", "validate_headers_log", "body_fetch_log",
        "body_persist_log", "script_validate_log", "proof_validate_log",
        "utxo_apply_log", "tip_finalize_log",
    };
    int64_t total = 0;
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[96];
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", tables[i]);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) != SQLITE_ROW) {  // raw-sql-ok:test-readback
            sqlite3_finalize(st);
            return -1;
        }
        total += sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return total;
}

static struct block_index *insert_index(struct main_state *ms,
                                        struct uint256 *hash,
                                        int height,
                                        struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = (uint8_t)((height >> 16) & 0xff);
    hash->data[31] = 0x5c;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    /* VALID_SCRIPTS and no HAVE_DATA: the block-index flag reconcile pass
     * has nothing to set or clear, so cursor assertions stay isolated. */
    bi->nStatus = BLOCK_VALID_SCRIPTS;
    bi->nFile = -1;
    bi->nDataPos = 0;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height - A + 1));
    return bi;
}

static bool setup_fixture(struct srf_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir),
                     "stage_repair_script_refill", tag);
    if (!progress_store_open(fx->dir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!seed_schema(db))
        return false;
    if (!seed_all_cursors(db, A + 4))
        return false;

    main_state_init(&fx->ms);
    fx->idx[1] = insert_index(&fx->ms, &fx->hashes[1], A + 1, NULL);
    fx->idx[2] = insert_index(&fx->ms, &fx->hashes[2], A + 2, fx->idx[1]);
    fx->idx[3] = insert_index(&fx->ms, &fx->hashes[3], A + 3, fx->idx[2]);
    if (!fx->idx[1] || !fx->idx[2] || !fx->idx[3])
        return false;

    if (!put_header_admit(db, A + 1, &fx->hashes[1], NULL) ||
        !put_header_admit(db, A + 2, &fx->hashes[2], &fx->hashes[1]) ||
        !put_header_admit(db, A + 3, &fx->hashes[3], &fx->hashes[2]))
        return false;

    for (int i = 1; i <= 3; i++) {
        if (!put_upstream_ok(db, A + i, &fx->hashes[i]) ||
            !put_body_fetch_ok(db, A + i, &fx->hashes[i]))
            return false;
    }
    if (!put_tip_log(db, A + 1, 1, &fx->hashes[1]))
        return false;
    if (!seed_coins_applied(db, A + 2))
        return false;
    return true;
}

static void teardown_fixture(struct srf_fixture *fx)
{
    main_state_free(&fx->ms);
    progress_store_close();
    test_cleanup_tmpdir(fx->dir);
}

/* Init a hand-built reconcile result for DIRECT calls into the refill core
 * (mirrors reducer_frontier_reconcile_light_impl's local init: -1 sentinels
 * so the validate/body refill paths no-op unless explicitly armed). */
static void rr_init_direct(struct stage_reducer_frontier_reconcile_result *rr,
                           int hstar, int sweep_top, int coins_applied)
{
    memset(rr, 0, sizeof(*rr));
    rr->hstar = hstar;
    rr->sweep_top = sweep_top;
    rr->coins_applied_found = true;
    rr->coins_applied_height = coins_applied;
    rr->tip_finalize_cursor_before = -1;
    rr->tip_finalize_cursor_after = -1;
    rr->validate_headers_cursor_before = -1;
    rr->validate_headers_cursor_after = -1;
    rr->body_fetch_cursor_before = -1;
    rr->body_fetch_cursor_after = -1;
    rr->body_persist_cursor_before = -1;
    rr->body_persist_cursor_after = -1;
    rr->lowest_have_data_cleared = -1;
    rr->lowest_validate_headers_refill_hole = -1;
    rr->lowest_validate_headers_hash_split = -1;
    rr->lowest_body_fetch_refill_hole = -1;
    rr->lowest_body_persist_refill_hole = -1;
}

/* ── Part B helpers: regtest drain harness (test_reducer_step_drain_harness.c
 *    pattern — real Equihash, real stage step bodies, no stubs). ─────────── */

static int srf_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool srf_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "srf_vtx");
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

static bool srf_seed_genesis_utxo_apply_row(sqlite3 *db)
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

static bool srf_log_ok_at(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT ok FROM %s WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        ok = sqlite3_column_int(st, 0) == 1;
    sqlite3_finalize(st);
    return ok;
}

static int run_drain_harness_refill(void)
{
    int failures = 0;

    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    srf_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "stage_repair_script_refill", "drain");
    srf_mkdir_p(dir);

    /* SetDataDir already clears the cache and populates cachedDataDirNet =
     * <dir>/regtest; do NOT ClearDataDirCache() here or GetDataDir falls back
     * to the shared default ~/.zclassic-c23/regtest and races other groups. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    srf_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    srf_mkdir_p(blocksdir);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    SRF_CHECK("drain: progress_store opens", store_ok);

    event_log_t *lg = store_ok ? event_log_open(log_path) : NULL;
    SRF_CHECK("drain: event log opens", lg != NULL);

    if (!store_ok || !lg) {
        if (lg) event_log_close(lg);
        progress_store_close();
        SetDataDir(""); ClearDataDirCache();
        chain_params_select(CHAIN_MAIN);
        return failures + 1;
    }

    struct main_state ms;
    main_state_init(&ms);

    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&ms, &genesis_hash);
    SRF_CHECK("drain: genesis block_index inserted", genesis != NULL);
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
    SRF_CHECK("drain: all eight reducer stages init", stages_ok);
    SRF_CHECK("drain: seed genesis utxo_apply row",
              srf_seed_genesis_utxo_apply_row(progress_store_db()));
    SRF_CHECK("drain: tip_finalize anchor seed at genesis",
              tip_finalize_stage_seed_anchor(0, genesis_hash.data, false));

    sqlite3 *db = progress_store_db();

    /* Mine + admit + persist blocks 1..3 (chained, coinbase-only). */
    struct uint256 prev = genesis_hash;
    bool chain_built = stages_ok;
    for (int h = 1; chain_built && h <= 3; h++) {
        struct block blk;
        chain_built = srf_build_regtest_block(&blk, h, &prev, cp) &&
                      mine_block_pow(&blk, h, cp, 0);
        if (!chain_built) {
            block_free(&blk);
            break;
        }

        struct uint256 bh;
        block_get_hash(&blk, &bh);

        struct header_admit_msg m;
        memset(&m, 0, sizeof(m));
        m.hash = bh;
        m.has_header = true;
        m.header = blk.header;
        m.height = -1;
        chain_built = mailbox_header_admit_push(&m);
        (void)header_admit_stage_drain(10);

        struct block_index *bi = block_map_find(&ms.map_block_index, &bh);
        if (chain_built && bi) {
            struct disk_block_pos pos;
            disk_block_pos_init(&pos);
            chain_built =
                write_block_to_disk(&blk, &pos, netdir,
                                    cp->pchMessageStart) &&
                block_index_set_have_data_verified(bi, &pos, netdir);
        } else {
            chain_built = false;
        }
        prev = bh;
        block_free(&blk);
    }
    SRF_CHECK("drain: blocks 1..3 mined + admitted + persisted", chain_built);

    /* First pass: script/proof walk all three; utxo applies ONLY block 1 —
     * the live shape (script/proof cursors ahead, coins frontier behind). */
    (void)validate_headers_stage_drain(100);
    (void)body_fetch_stage_drain(100);
    (void)body_persist_stage_drain(100);
    (void)script_validate_stage_drain(100);
    (void)proof_validate_stage_drain(100);
    for (int i = 0; i < 3 && !utxo_apply_stage_succeeded_at(1); i++)
        (void)utxo_apply_stage_step_once();
    (void)tip_finalize_stage_step_once();

    int32_t coins = -1;
    bool coins_found = false;
    SRF_CHECK("drain: coins frontier readable",
              coins_kv_get_applied_height(db, &coins, &coins_found));
    SRF_CHECK("drain: first pass — script/proof at 4, coins at 2",
              cursor_value(db, "script_validate") == 4 &&
              cursor_value(db, "proof_validate") == 4 &&
              cursor_value(db, "utxo_apply") == 2 &&
              coins_found && coins == 2 &&
              srf_log_ok_at(db, "script_validate_log", 2) &&
              srf_log_ok_at(db, "proof_validate_log", 2));

    /* Simulate the bulldozed rowless hole at h=2 == coins_applied. */
    SRF_CHECK("drain: punch rowless script+proof hole at h=2",
              delete_height(db, "script_validate_log", 2) &&
              delete_height(db, "proof_validate_log", 2));

    int utxo_before = cursor_value(db, "utxo_apply");
    int tip_before = cursor_value(db, "tip_finalize");
    int64_t rows_before = total_log_rows(db);

    struct stage_reducer_frontier_reconcile_result rr;
    rr_init_direct(&rr, 1, 3, 2);
    rr.validate_headers_cursor_before = cursor_value(db, "validate_headers");
    rr.validate_headers_cursor_after = rr.validate_headers_cursor_before;
    rr.body_fetch_cursor_before = cursor_value(db, "body_fetch");
    rr.body_fetch_cursor_after = rr.body_fetch_cursor_before;
    rr.body_persist_cursor_before = cursor_value(db, "body_persist");
    rr.body_persist_cursor_after = rr.body_persist_cursor_before;

    SRF_CHECK("drain: FIX-2b reconcile_refill_cursors succeeds",
              stage_reducer_frontier_reconcile_refill_cursors(db, NULL, true,
                                                              &rr));
    SRF_CHECK("drain: FIX-2b clamps script+proof to the hole",
              rr.clamped_script_validate &&
              rr.clamped_proof_validate &&
              rr.lowest_script_validate_refill_hole == 2 &&
              cursor_value(db, "script_validate") == 2 &&
              cursor_value(db, "proof_validate") == 2 &&
              !rr.clamped_validate_headers &&
              !rr.clamped_body_fetch &&
              !rr.clamped_body_persist);
    SRF_CHECK("drain: utxo/tip cursors untouched, no rows deleted",
              cursor_value(db, "utxo_apply") == utxo_before &&
              cursor_value(db, "tip_finalize") == tip_before &&
              total_log_rows(db) == rows_before);

    /* Production stages refill the hole (INSERT OR REPLACE) and coins
     * re-advance to the tip — the un-deadlock FIX-2 exists for. */
    (void)script_validate_stage_drain(100);
    (void)proof_validate_stage_drain(100);
    (void)utxo_apply_stage_drain(100);

    coins = -1;
    coins_found = false;
    SRF_CHECK("drain: refill rewrote the hole and coins re-advanced",
              srf_log_ok_at(db, "script_validate_log", 2) &&
              srf_log_ok_at(db, "proof_validate_log", 2) &&
              srf_log_ok_at(db, "utxo_apply_log", 2) &&
              srf_log_ok_at(db, "utxo_apply_log", 3) &&
              cursor_value(db, "script_validate") == 4 &&
              cursor_value(db, "proof_validate") == 4 &&
              cursor_value(db, "utxo_apply") == 4 &&
              coins_kv_get_applied_height(db, &coins, &coins_found) &&
              coins_found && coins == 4);

    /* teardown (drain-harness order) */
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
    main_state_free(&ms);
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(netdir);
    test_cleanup_tmpdir(dir);
    SetDataDir(""); ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    return failures;
}

int test_stage_repair_script_refill(void);
int test_stage_repair_script_refill(void)
{
    printf("\n=== stage_repair_script_refill tests ===\n");
    int failures = 0;

    /* Pin the (now network-derived) compiled-anchor floor to the mainnet
     * anchor A: every fixture below seeds rows at A+1.. and asserts hstar==A+1,
     * which requires the floor to sit at A even though the drain harness runs
     * under regtest params. Restored to -1 (production default) before return. */
    reducer_frontier_test_set_compiled_anchor(A);

    /* T1 (synthetic): rowless script+proof hole at h0 == coins_applied,
     * cursors at N > h0 — FIX-2b (via the full reconcile_light pipeline)
     * clamps script/proof/tip_finalize to h0 and deletes nothing. */
    {
        struct srf_fixture fx;
        SRF_CHECK("T1: setup fixture", setup_fixture(&fx, "t1_refill"));
        sqlite3 *db = progress_store_db();

        SRF_CHECK("T1: punch rowless hole at h0 = coins_applied",
                  delete_height(db, "script_validate_log", A + 2) &&
                  delete_height(db, "proof_validate_log", A + 2) &&
                  delete_height(db, "utxo_apply_log", A + 2) &&
                  delete_height(db, "utxo_apply_log", A + 3) &&
                  seed_cursor(db, "utxo_apply", A + 2));

        int64_t rows_before = total_log_rows(db);

        struct stage_reducer_frontier_reconcile_result dry;
        SRF_CHECK("T1: dry-run succeeds",
                  stage_reducer_frontier_reconcile_light_needed(
                      db, &fx.ms, &dry));
        SRF_CHECK("T1: dry-run detects + plans the clamp, no DB writes",
                  dry.hstar == A + 1 &&
                  !dry.refused_coin_tear &&
                  dry.lowest_script_validate_refill_hole == A + 2 &&
                  dry.lowest_proof_validate_refill_hole == -1 &&
                  dry.clamped_script_validate &&
                  dry.clamped_proof_validate &&
                  dry.script_validate_cursor_before == A + 4 &&
                  dry.script_validate_cursor_after == A + 2 &&
                  dry.proof_validate_cursor_before == A + 4 &&
                  dry.proof_validate_cursor_after == A + 2 &&
                  !dry.pre_refusal_unapplied_clamp &&
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "tip_finalize") == A + 4);

        struct stage_reducer_frontier_reconcile_result rr;
        SRF_CHECK("T1: apply succeeds",
                  stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        SRF_CHECK("T1: clamps script/proof/tip_finalize to the hole",
                  rr.repaired &&
                  rr.clamped_script_validate &&
                  rr.clamped_proof_validate &&
                  rr.clamped_tip_finalize &&
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 2 &&
                  /* OWN-frame (task #31, corrected): served tip = A+2,
                   * backed by the intact transition row at A+1 and coins
                   * applied through A+1 (coins_applied A+2, NEXT-frame) —
                   * the same height the forward step rests at. */
                  cursor_value(db, "tip_finalize") == A + 2 &&
                  cursor_value(db, "validate_headers") == A + 4 &&
                  cursor_value(db, "body_fetch") == A + 4 &&
                  cursor_value(db, "body_persist") == A + 4);
        SRF_CHECK("T1: utxo_apply cursor untouched, no log rows deleted",
                  cursor_value(db, "utxo_apply") == A + 2 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* FIX-2a positive (direct call): refused coin tear pending, rowless
     * script holes at A+1 (below coins → replay domain, OUT of bounds) and
     * A+2 (== coins_applied → in bounds) — bounds arithmetic picks only the
     * unapplied one, clamps, clears the refusal, claims the tick. */
    {
        struct srf_fixture fx;
        SRF_CHECK("2a+: setup fixture", setup_fixture(&fx, "t2a_clamp"));
        sqlite3 *db = progress_store_db();

        SRF_CHECK("2a+: punch script holes at A+1 (applied) and A+2",
                  delete_height(db, "script_validate_log", A + 1) &&
                  delete_height(db, "script_validate_log", A + 2));

        int64_t rows_before = total_log_rows(db);
        struct stage_reducer_frontier_reconcile_result rr;
        rr_init_direct(&rr, A, A + 3, A + 2);
        rr.refused_coin_tear = true;

        bool handled = false;
        SRF_CHECK("2a+: try_unapplied_hole_clamp succeeds",
                  stage_reducer_frontier_try_unapplied_hole_clamp(
                      db, true, &rr, &handled));
        SRF_CHECK("2a+: clamps only the unapplied hole and claims the tick",
                  handled &&
                  rr.pre_refusal_unapplied_clamp &&
                  !rr.refused_coin_tear &&
                  rr.repaired &&
                  rr.clamped_script_validate &&
                  rr.lowest_script_validate_refill_hole == A + 2 &&
                  rr.script_validate_cursor_before == A + 4 &&
                  rr.script_validate_cursor_after == A + 2 &&
                  !rr.clamped_proof_validate &&
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 4);
        SRF_CHECK("2a+: utxo/tip untouched, no rows deleted",
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  cursor_value(db, "tip_finalize") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* FIX-2a negative: REAL coin tear — the only hole is strictly below the
     * coins frontier (already applied). Bounds exclude it: handled stays
     * false, the refusal stands, ZERO cursor writes, ZERO row writes. */
    {
        struct srf_fixture fx;
        SRF_CHECK("2a-: setup fixture", setup_fixture(&fx, "t2a_tear"));
        sqlite3 *db = progress_store_db();

        SRF_CHECK("2a-: punch script hole at A+1 only (below coins=A+2)",
                  delete_height(db, "script_validate_log", A + 1));

        int64_t rows_before = total_log_rows(db);
        struct stage_reducer_frontier_reconcile_result rr;
        rr_init_direct(&rr, A, A + 3, A + 2);
        rr.refused_coin_tear = true;

        bool handled = false;
        SRF_CHECK("2a-: try_unapplied_hole_clamp succeeds",
                  stage_reducer_frontier_try_unapplied_hole_clamp(
                      db, true, &rr, &handled));
        SRF_CHECK("2a-: refusal stands, zero writes",
                  !handled &&
                  rr.refused_coin_tear &&
                  !rr.pre_refusal_unapplied_clamp &&
                  !rr.clamped_script_validate &&
                  !rr.clamped_proof_validate &&
                  rr.lowest_script_validate_refill_hole == -1 &&
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  cursor_value(db, "tip_finalize") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* Coins floor (direct FIX-2b): a hole strictly below coins_applied is
     * DETECTED but the clamp is refused ("replay domain" WARN) — the
     * stale-script replay owns it, not the forward refill. */
    {
        struct srf_fixture fx;
        SRF_CHECK("floor: setup fixture", setup_fixture(&fx, "t_floor"));
        sqlite3 *db = progress_store_db();

        SRF_CHECK("floor: hole at A+2 below coins frontier A+3",
                  delete_height(db, "script_validate_log", A + 2) &&
                  seed_coins_applied(db, A + 3));

        int64_t rows_before = total_log_rows(db);
        struct stage_reducer_frontier_reconcile_result rr;
        rr_init_direct(&rr, A + 1, A + 3, A + 3);

        SRF_CHECK("floor: reconcile_refill_cursors succeeds",
                  stage_reducer_frontier_reconcile_refill_cursors(
                      db, NULL, true, &rr));
        SRF_CHECK("floor: hole detected but clamp refused (replay domain)",
                  rr.lowest_script_validate_refill_hole == A + 2 &&
                  !rr.clamped_script_validate &&
                  !rr.clamped_proof_validate &&
                  rr.script_validate_cursor_after == A + 4 &&
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* ok=0 row at the pin: a real failed verdict is NOT a refill hole —
     * the scans require the row to be MISSING. Zero clamps, zero writes. */
    {
        struct srf_fixture fx;
        SRF_CHECK("ok0: setup fixture", setup_fixture(&fx, "t_ok0"));
        sqlite3 *db = progress_store_db();

        SRF_CHECK("ok0: real ok=0 script verdict at the pin",
                  put_hash_log(db, "script_validate_log", "block_hash",
                               A + 2, 0, &fx.hashes[2]));

        int64_t rows_before = total_log_rows(db);
        struct stage_reducer_frontier_reconcile_result rr;
        SRF_CHECK("ok0: reconcile_light succeeds",
                  stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        SRF_CHECK("ok0: verdict respected — no script/proof clamp",
                  rr.hstar == A + 1 &&
                  rr.lowest_script_validate_refill_hole == -1 &&
                  rr.lowest_proof_validate_refill_hole == -1 &&
                  !rr.clamped_script_validate &&
                  !rr.clamped_proof_validate &&
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* Drain harness: production stages refill + re-advance after the clamp.
     * Runs with the override still pinned to A (its fixture is at mainnet
     * heights too). */
    failures += run_drain_harness_refill();

    reducer_frontier_test_set_compiled_anchor(-1); /* restore production floor */

    printf("stage_repair_script_refill: %d failures\n", failures);
    return failures;
}
