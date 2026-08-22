/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "conditions/reducer_frontier_reconcile_light.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "core/arith_uint256.h"
#include "domain/consensus/coinbase.h"
#include "framework/condition.h"
#include "mining/miner.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_repair_coin_backfill.h"
#include "json/json.h"
#include "net/net.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/sync_monitor.h"
#include "storage/anchor_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define RFRL_CHECK(name, expr) do { \
    printf("reducer_frontier_reconcile_light: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* src-private ZCL_TESTING hooks mirrored from
 * reducer_frontier_reconcile_light.c (the test_reducer_reconcile_witness.c
 * pattern — not in the public header). */
int reducer_frontier_reconcile_light_test_bypass_warns(void);
int reducer_frontier_reconcile_light_test_gate_suppress_warns(void);
bool stage_reducer_frontier_purge_noncanonical(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out);
/* Label-splice re-bind arm (internal to app/jobs) + the pure remedy-decision
 * hook (internal to app/conditions), forward-declared for the tests below. */
bool stage_reducer_frontier_try_label_splice_rebind(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out,
    bool *mutated);
enum condition_remedy_result
reducer_frontier_reconcile_light_test_remedy_outcome(
    const struct stage_reducer_frontier_reconcile_result *rr);

struct rfrl_fixture {
    char dir[256];
    struct main_state ms;
    struct uint256 hashes[4];
    struct block_index *idx[4];
};

static int rfrl_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0)
        return 0;
    if (errno == EEXIST)
        return 0;
    return -1;
}

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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_script_status(sqlite3 *db, int height, int ok_flag,
                              const char *status,
                              const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log"
            "(height,status,ok,block_hash) VALUES(?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_flag);
    sqlite3_bind_blob(st, 4, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_proof_status(sqlite3 *db, int height, int ok_flag,
                             const char *status,
                             const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO proof_validate_log"
            "(height,status,ok,block_hash) VALUES(?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_flag);
    sqlite3_bind_blob(st, 4, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* An ok=1/status='verified' proof or script verdict row with a NULL block_hash
 * — the pre-stamping label_splice residue the re-bind arm targets. */
static bool put_verdict_null_hash(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO %s(height,status,ok,block_hash) "
             "VALUES(?,'verified',1,NULL)",
             table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Count ok=1 rows with a NULL block_hash in [first, end_exclusive). */
static int count_null_block_hash(sqlite3 *db, const char *table, int first,
                                 int end_exclusive)
{
    char sql[192];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM %s WHERE height >= ? AND height < ? "
             "AND ok=1 AND block_hash IS NULL",
             table);
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, first);
        sqlite3_bind_int(st, 2, end_exclusive);
        if (sqlite3_step(st) == SQLITE_ROW)
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

static bool put_utxo_delta(sqlite3 *db, int height,
                           const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_sapling_anchor_residue(sqlite3 *db, int height,
                                        const struct uint256 *root)
{
    if (!anchor_kv_ensure_schema(db))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO sapling_anchors(anchor,height,tree) "
            "VALUES(?,?,x'')", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, root->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static int count_range(sqlite3 *db, const char *table, int first,
                       int end_exclusive)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM %s WHERE height >= ? AND height < ?",
             table);
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, first);
        sqlite3_bind_int(st, 2, end_exclusive);
        if (sqlite3_step(st) == SQLITE_ROW)
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool rfrl_build_regtest_block(struct block *blk, int height,
                                     const struct uint256 *prev_hash,
                                     const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "rfrl_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    struct script miner_script;
    script_init(&miner_script);
    miner_script.data[0] = 0x76; /* OP_DUP */
    miner_script.data[1] = 0xa9; /* OP_HASH160 */
    miner_script.data[2] = 0x14; /* push 20 */
    for (int i = 0; i < 20; i++)
        miner_script.data[3 + i] = (unsigned char)(0x20 + i);
    miner_script.data[23] = 0x88; /* OP_EQUALVERIFY */
    miner_script.data[24] = 0xac; /* OP_CHECKSIG */
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

static bool put_upstream_ok(sqlite3 *db, int height,
                            const struct uint256 *hash)
{
    return put_hash_log(db, "validate_headers_log", "hash", height, 1, hash) &&
           put_hash_log(db, "script_validate_log", "block_hash", height, 1,
                        hash) &&
           put_simple_log(db, "body_persist_log", height, 1) &&
           put_hash_log(db, "proof_validate_log", "block_hash", height, 1,
                        hash) &&
           put_simple_log(db, "utxo_apply_log", height, 1) &&
           put_utxo_delta(db, height, hash);
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
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    /* Stamp full coins_kv proven-authority so compute_hstar treats the baked
     * TRUSTED_ANCHOR as a REAL finality floor (these reconcile fixtures model a
     * seeded datadir whose H* clamps at the anchor and whose coins lead it).
     * compute_hstar's phantom-anchor guard otherwise drops the floor to 0 when
     * the store is not proven authority — correct for a fresh datadir, wrong
     * here. Needs all three rungs: applied_height above, the migration stamp,
     * and a non-empty `coins` table. */
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {
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
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static struct block_index *insert_index(struct main_state *ms,
                                        struct uint256 *hash,
                                        int height,
                                        struct block_index *prev,
                                        unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = (uint8_t)((height >> 16) & 0xff);
    hash->data[31] = 0x7b;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = status;
    bi->nFile = -1;
    bi->nDataPos = 0;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height - A + 1));
    return bi;
}

static bool make_fixture_block_readable(struct rfrl_fixture *fx, int slot)
{
    if (!fx || slot <= 0 || slot >= 4 || !fx->idx[slot] ||
        !fx->idx[slot]->pprev || !fx->idx[slot]->pprev->phashBlock)
        return false;

    chain_params_select(CHAIN_REGTEST);
    reducer_frontier_test_set_compiled_anchor(A);
    const struct chain_params *cp = chain_params_get();
    if (!cp)
        return false;

    SetDataDir(fx->dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    if (rfrl_mkdir_p(netdir) != 0)
        return false;
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    if (rfrl_mkdir_p(blocksdir) != 0)
        return false;

    struct block blk;
    bool ok = rfrl_build_regtest_block(
        &blk, fx->idx[slot]->nHeight, fx->idx[slot]->pprev->phashBlock, cp);
    if (ok)
        ok = mine_block_pow(&blk, fx->idx[slot]->nHeight, cp, 0);

    struct uint256 block_hash;
    if (ok) {
        block_get_hash(&blk, &block_hash);
        fx->hashes[slot] = block_hash;
        fx->idx[slot]->hashBlock = block_hash;
        fx->idx[slot]->phashBlock = &fx->idx[slot]->hashBlock;

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        ok = write_block_to_disk(&blk, &pos, netdir, cp->pchMessageStart) &&
             block_index_set_have_data_verified(fx->idx[slot], &pos, netdir);
    }
    block_free(&blk);
    if (!ok)
        return false;

    sqlite3 *db = progress_store_db();
    const struct uint256 *parent_hash = fx->idx[slot]->pprev->phashBlock;
    return put_header_admit(db, fx->idx[slot]->nHeight, &fx->hashes[slot],
                            parent_hash) &&
           put_hash_log(db, "validate_headers_log", "hash",
                        fx->idx[slot]->nHeight, 1, &fx->hashes[slot]) &&
           put_body_fetch_ok(db, fx->idx[slot]->nHeight, &fx->hashes[slot]) &&
           put_hash_log(db, "script_validate_log", "block_hash",
                        fx->idx[slot]->nHeight, 1, &fx->hashes[slot]) &&
           put_hash_log(db, "proof_validate_log", "block_hash",
                        fx->idx[slot]->nHeight, 1, &fx->hashes[slot]) &&
           put_utxo_delta(db, fx->idx[slot]->nHeight, &fx->hashes[slot]) &&
           active_chain_move_window_tip(&fx->ms.chain_active, fx->idx[3]);
}

static bool setup_fixture(struct rfrl_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir),
                     "reducer_frontier_reconcile_light", tag);
    if (!progress_store_open(fx->dir))
        return false;
    /* progress.kv is closed+reopened per fixture; drop the dry-run detect memo
     * so a reused db pointer + reset total_changes cannot wrongly hit a prior
     * fixture's cached result (production never reopens, so this is test-only). */
    stage_reducer_frontier_reset_detect_memo_for_testing();
    if (!seed_schema(progress_store_db()))
        return false;
    if (!seed_all_cursors(progress_store_db(), A + 4))
        return false;

    main_state_init(&fx->ms);
    fx->idx[1] = insert_index(&fx->ms, &fx->hashes[1], A + 1, NULL,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    fx->idx[2] = insert_index(&fx->ms, &fx->hashes[2], A + 2,
                              fx->idx[1], BLOCK_HAVE_DATA);
    fx->idx[3] = insert_index(&fx->ms, &fx->hashes[3], A + 3,
                              fx->idx[2],
                              BLOCK_VALID_TREE | BLOCK_HAVE_DATA |
                              BLOCK_FAILED_VALID);
    if (!fx->idx[1] || !fx->idx[2] || !fx->idx[3])
        return false;

    if (!put_header_admit(progress_store_db(), A + 1, &fx->hashes[1], NULL) ||
        !put_header_admit(progress_store_db(), A + 2, &fx->hashes[2],
                          &fx->hashes[1]) ||
        !put_header_admit(progress_store_db(), A + 3, &fx->hashes[3],
                          &fx->hashes[2]))
        return false;

    if (!put_upstream_ok(progress_store_db(), A + 1, &fx->hashes[1]) ||
        !put_upstream_ok(progress_store_db(), A + 2, &fx->hashes[2]) ||
        !put_upstream_ok(progress_store_db(), A + 3, &fx->hashes[3]))
        return false;
    if (!put_tip_log(progress_store_db(), A + 1, 1, &fx->hashes[1]))
        return false;
    if (!seed_coins_applied(progress_store_db(), A + 2))
        return false;
    return true;
}

static void teardown_fixture(struct rfrl_fixture *fx)
{
    main_state_free(&fx->ms);
    progress_store_close();
    SetDataDir("");
    ClearDataDirCache();
    reducer_frontier_test_set_compiled_anchor(-1);
    chain_params_select(CHAIN_MAIN);
    test_rm_rf_recursive(fx->dir);
}

static const struct json_value *rfrl_json_condition(
    const struct json_value *root,
    const char *name)
{
    const struct json_value *conditions = json_get(root, "conditions");
    if (!conditions || !name)
        return NULL;
    for (size_t i = 0; i < json_size(conditions); i++) {
        const struct json_value *cond = json_at(conditions, i);
        const struct json_value *n = json_get(cond, "name");
        if (n && strcmp(json_get_str(n), name) == 0)
            return cond;
    }
    return NULL;
}

/* Cross-thread lock probe: acquires + releases the progress lock from a
 * second thread. A refusal path that leaks the (recursive) lock is invisible
 * to the calling thread; the probe's join hangs the test binary instead. */
static void *progress_lock_probe(void *arg)
{
    progress_store_tx_lock();
    progress_store_tx_unlock();
    *(bool *)arg = true;
    return NULL;
}

struct active_chain_lock_probe_arg {
    struct active_chain *chain;
    bool probed;
};

static void *active_chain_lock_probe(void *arg)
{
    struct active_chain_lock_probe_arg *a = arg;
    if (zcl_mutex_trylock(&a->chain->write_lock)) {
        zcl_mutex_unlock(&a->chain->write_lock);
        a->probed = true;
    }
    return NULL;
}

static int cursor_value(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

int test_reducer_frontier_reconcile_light(void);
int test_reducer_frontier_reconcile_light(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== reducer_frontier_reconcile_light tests ===\n");
    int failures = 0;

    {
        /* Mirror reducer_frontier_reconcile_light_impl's init for the
         * -1-sentinel refill-hole fields the classifiers read: a plain
         * memset(0) reads as a refill hole at height 0. */
        struct stage_reducer_frontier_reconcile_result zero;
        memset(&zero, 0, sizeof(zero));
        zero.lowest_validate_headers_refill_hole = -1;
        zero.lowest_body_fetch_refill_hole = -1;
        zero.lowest_body_persist_refill_hole = -1;
        zero.lowest_script_validate_refill_hole = -1;
        zero.lowest_proof_validate_refill_hole = -1;
        zero.label_splice_rebind_lowest = -1;  /* -1 sentinel = no re-bind */

        struct stage_reducer_frontier_reconcile_result rr = zero;
        RFRL_CHECK("result helpers: clean baseline",
                   !stage_reducer_frontier_result_has_coin_repair_evidence(&rr) &&
                   !stage_reducer_frontier_result_has_row_residue_evidence(&rr) &&
                   !stage_reducer_frontier_result_has_refill_hole_evidence(&rr) &&
                   !stage_reducer_frontier_result_has_gate_loudness_evidence(&rr) &&
                   stage_reducer_frontier_result_is_memo_clean(&rr));

        rr = zero;
        rr.coin_backfill_attempted = true;
        RFRL_CHECK("result helpers: coin repair evidence",
                   stage_reducer_frontier_result_has_coin_repair_evidence(&rr) &&
                   !stage_reducer_frontier_result_has_row_residue_evidence(&rr) &&
                   stage_reducer_frontier_result_has_gate_loudness_evidence(&rr) &&
                   !stage_reducer_frontier_result_is_memo_clean(&rr));

        rr = zero;
        rr.noncanonical_found = 1;
        RFRL_CHECK("result helpers: row residue evidence",
                   !stage_reducer_frontier_result_has_coin_repair_evidence(&rr) &&
                   stage_reducer_frontier_result_has_row_residue_evidence(&rr) &&
                   stage_reducer_frontier_result_has_gate_loudness_evidence(&rr) &&
                   !stage_reducer_frontier_result_is_memo_clean(&rr));

        rr = zero;
        rr.lowest_script_validate_refill_hole = A + 2;
        RFRL_CHECK("result helpers: refill hole evidence",
                   !stage_reducer_frontier_result_has_coin_repair_evidence(&rr) &&
                   !stage_reducer_frontier_result_has_row_residue_evidence(&rr) &&
                   stage_reducer_frontier_result_has_refill_hole_evidence(&rr) &&
                   stage_reducer_frontier_result_has_gate_loudness_evidence(&rr) &&
                   !stage_reducer_frontier_result_is_memo_clean(&rr));

        rr = zero;
        rr.refused_coin_tear = true;
        RFRL_CHECK("result helpers: coin tear bypass separate",
                   !stage_reducer_frontier_result_has_gate_loudness_evidence(&rr) &&
                   !stage_reducer_frontier_result_is_memo_clean(&rr));

        rr = zero;
        rr.repaired = true;
        RFRL_CHECK("result helpers: repaired is not memo-clean",
                   !stage_reducer_frontier_result_has_gate_loudness_evidence(&rr) &&
                   !stage_reducer_frontier_result_is_memo_clean(&rr));
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup dry-run/apply fixture",
                   setup_fixture(&fx, "apply"));

        sqlite3 *db = progress_store_db();
        unsigned before2 = fx.idx[2]->nStatus;
        unsigned before3 = fx.idx[3]->nStatus;

        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("dry-run succeeds",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry));
        RFRL_CHECK("dry-run reports repair",
                   dry.repaired && dry.hstar == A + 1 &&
                   dry.sweep_top == A + 3 &&
                   dry.lowest_have_data_cleared == A + 2 &&
                   dry.lowest_validate_headers_refill_hole == -1 &&
                   dry.lowest_body_fetch_refill_hole == A + 2 &&
                   dry.lowest_body_persist_refill_hole == -1 &&
                   dry.validate_headers_cursor_before == A + 4 &&
                   dry.validate_headers_cursor_after == A + 4 &&
                   dry.body_fetch_cursor_before == A + 4 &&
                   dry.body_fetch_cursor_after == A + 2 &&
                   dry.clamped_body_fetch &&
                   !dry.clamped_body_persist &&
                   /* OWN-frame (task #31): clamp band [hstar, hstar+1]
                    * capped at coins_applied = min(A+2, A+2) = A+2 —
                    * the served-tip ceiling the step itself rests at. */
                   dry.tip_finalize_cursor_after == A + 2);
        RFRL_CHECK("dry-run does not mutate",
                   fx.idx[2]->nStatus == before2 &&
                   fx.idx[3]->nStatus == before3 &&
                   cursor_value(db, "validate_headers") == A + 4 &&
                   cursor_value(db, "body_fetch") == A + 4 &&
                   cursor_value(db, "body_persist") == A + 4 &&
                   cursor_value(db, "tip_finalize") == A + 4);

        struct stage_reducer_frontier_reconcile_result applied;
        RFRL_CHECK("apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &applied));
        RFRL_CHECK("apply clamps body_fetch and tip_finalize",
                   cursor_value(db, "tip_finalize") == A + 2 &&
                   cursor_value(db, "validate_headers") == A + 4 &&
                   cursor_value(db, "body_fetch") == A + 2 &&
                   cursor_value(db, "body_persist") == A + 4 &&
                   cursor_value(db, "utxo_apply") == A + 4 &&
                   applied.clamped_body_fetch &&
                   !applied.clamped_body_persist &&
                   applied.clamped_tip_finalize);
        RFRL_CHECK("script bits restored",
                   (fx.idx[2]->nStatus & BLOCK_VALID_MASK) ==
                       BLOCK_VALID_SCRIPTS &&
                   (fx.idx[3]->nStatus & BLOCK_VALID_MASK) ==
                       BLOCK_VALID_SCRIPTS &&
                   applied.scripts_set == 2);
        RFRL_CHECK("unreadable HAVE_DATA cleared",
                   (fx.idx[2]->nStatus & BLOCK_HAVE_DATA) == 0 &&
                   (fx.idx[3]->nStatus & BLOCK_HAVE_DATA) == 0 &&
                   applied.have_data_cleared == 2);
        RFRL_CHECK("proved stale failure mask cleared",
                   (fx.idx[3]->nStatus & BLOCK_FAILED_MASK) == 0 &&
                   applied.failed_mask_cleared == 1);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("failed-mask proof split: setup",
                   setup_fixture(&fx, "failed_mask_proof_split"));
        sqlite3 *db = progress_store_db();
        struct uint256 fork = fx.hashes[3];
        fork.data[31] ^= 0x5au;
        RFRL_CHECK("failed-mask proof split: seed forked proof receipt",
                   put_hash_log(db, "proof_validate_log", "block_hash",
                                A + 3, 1, &fork));
        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("failed-mask proof split: reconcile completes",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("failed-mask proof split: failure evidence retained",
                   (fx.idx[3]->nStatus & BLOCK_FAILED_MASK) != 0 &&
                   rr.failed_mask_cleared == 0);
        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("failed-mask UTXO split: setup",
                   setup_fixture(&fx, "failed_mask_utxo_split"));
        sqlite3 *db = progress_store_db();
        struct uint256 fork = fx.hashes[3];
        fork.data[31] ^= 0xa5u;
        RFRL_CHECK("failed-mask UTXO split: seed forked delta receipt",
                   put_utxo_delta(db, A + 3, &fork));
        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("failed-mask UTXO split: reconcile completes",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("failed-mask UTXO split: failure evidence retained",
                   (fx.idx[3]->nStatus & BLOCK_FAILED_MASK) != 0 &&
                   rr.failed_mask_cleared == 0);
        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup validate-refill-hole fixture",
                   setup_fixture(&fx, "validate_refill_hole"));
        sqlite3 *db = progress_store_db();

        fx.idx[2]->nStatus = BLOCK_VALID_SCRIPTS;
        fx.idx[3]->nStatus = BLOCK_VALID_SCRIPTS;
        RFRL_CHECK("validate-refill-hole: seed later body_fetch row",
                   put_body_fetch_ok(db, A + 3, &fx.hashes[3]));
        RFRL_CHECK("validate-refill-hole: delete reducer rows at hole",
                   delete_height(db, "validate_headers_log", A + 2) &&
                   delete_height(db, "body_fetch_log", A + 2) &&
                   delete_height(db, "body_persist_log", A + 2) &&
                   delete_height(db, "script_validate_log", A + 2) &&
                   delete_height(db, "proof_validate_log", A + 2) &&
                   delete_height(db, "utxo_apply_log", A + 2));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("validate-refill-hole: apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("validate-refill-hole: clamps upstream refill cursors",
                   rr.lowest_validate_headers_refill_hole == A + 2 &&
                   rr.lowest_body_fetch_refill_hole == -1 &&
                   rr.lowest_body_persist_refill_hole == -1 &&
                   rr.clamped_validate_headers &&
                   rr.clamped_body_fetch &&
                   rr.clamped_body_persist &&
                   cursor_value(db, "validate_headers") == A + 2 &&
                   cursor_value(db, "body_fetch") == A + 2 &&
                   cursor_value(db, "body_persist") == A + 2 &&
                   /* tip_finalize is OWN-frame: served tip = A+2, backed by
                    * the intact transition row at A+1 and coins applied
                    * through A+1 (coins_applied A+2, NEXT-frame). */
                   cursor_value(db, "tip_finalize") == A + 2);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup validate-hash-split fixture",
                   setup_fixture(&fx, "validate_hash_split"));
        sqlite3 *db = progress_store_db();

        struct uint256 stale = fx.hashes[2];
        stale.data[0] ^= 0x5a;
        RFRL_CHECK("validate-hash-split: seed stale validate hash",
                   put_hash_log(db, "validate_headers_log", "hash",
                                A + 2, 1, &stale));
        RFRL_CHECK("validate-hash-split: seed coins above split hstar",
                   seed_coins_applied(db, A + 3));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("validate-hash-split: apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        /* New coin-tear semantics: a stale validate hash with utxo_apply SOLID
         * is NOT a coin tear (coins track utxo_apply's own log, not the
         * hash-split-pinned H*). The split still caps H* and must be healed,
         * but now via the downstream refill rather than the dead tear-gated
         * pre-refusal clamp — it re-walks validate_headers AND its dependent
         * cursors (body_fetch, tip_finalize) back to the split height A+2 to
         * re-derive the column; body_persist already holds its rows so it is
         * not clamped. No coin-tear refusal is involved. */
        RFRL_CHECK("validate-hash-split: downstream refill heals the split",
                   rr.repaired &&
                   !rr.refused_coin_tear &&
                   rr.lowest_validate_headers_hash_split == A + 2 &&
                   rr.lowest_validate_headers_refill_hole == -1 &&
                   rr.clamped_validate_headers &&
                   cursor_value(db, "validate_headers") == A + 2 &&
                   cursor_value(db, "body_fetch") == A + 2 &&
                   cursor_value(db, "body_persist") == A + 4 &&
                   cursor_value(db, "tip_finalize") == A + 2);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup body-refill-hole fixture",
                   setup_fixture(&fx, "body_refill_hole"));
        sqlite3 *db = progress_store_db();

        fx.idx[2]->nStatus = BLOCK_VALID_SCRIPTS;
        fx.idx[3]->nStatus = BLOCK_VALID_SCRIPTS;
        RFRL_CHECK("body-refill-hole: seed body_fetch rows around hole",
                   put_body_fetch_ok(db, A + 1, &fx.hashes[1]) &&
                   put_body_fetch_ok(db, A + 3, &fx.hashes[3]));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("body-refill-hole: apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("body-refill-hole: clamps to missing body_fetch row",
                   rr.lowest_have_data_cleared == -1 &&
                   rr.lowest_validate_headers_refill_hole == -1 &&
                   rr.lowest_body_fetch_refill_hole == A + 2 &&
                   rr.lowest_body_persist_refill_hole == -1 &&
                   rr.clamped_body_fetch &&
                   !rr.clamped_body_persist &&
                   cursor_value(db, "body_fetch") == A + 2);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup coin-tear fixture",
                   setup_fixture(&fx, "cointear"));
        sqlite3 *db = progress_store_db();
        /* REAL coin tear: a HOLE in utxo_apply's OWN ok=1 log below the coins
         * frontier. Mark utxo_apply ok=0 at A+2 (status='verified', so neither
         * the value_overflow nor stale_script replays — which key on
         * status='value_overflow'/'internal_error' in script_validate — engage)
         * so utxo_apply's contiguous prefix stops at A+1, then seed coins above
         * it at A+3. coins_applied(A+3) > utxo_apply_contig(A+1)+1 is a genuine
         * tear: coins applied above utxo_apply's own solid log. (Pre-fix this
         * test relied on tip_finalize lagging at A+1 to push coins past the
         * global MIN H* — a FALSE positive the new ua_contig compare ignores.)
         * tipfin_backfill's G3 refuses on the ok=0 utxo_apply row, so the tear
         * survives every pre-refusal repair and the L1 refusal stands. */
        RFRL_CHECK("seed real utxo_apply hole below coins frontier",
                   put_simple_log(db, "utxo_apply_log", A + 2, 0) &&
                   seed_coins_applied(db, A + 3));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("coin-tear detect call succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("coin-tear refused without mutation",
                   rr.refused_coin_tear &&
                   cursor_value(db, "tip_finalize") == A + 4 &&
                   (fx.idx[2]->nStatus & BLOCK_VALID_MASK) == 0);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup served-floor fixture",
                   setup_fixture(&fx, "served_floor"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("seed served floor above hstar without contiguous prefix",
                   put_tip_log(db, A + 3, 1, &fx.hashes[3]));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("served-floor apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("served-floor cannot override coins cap",
                   rr.hstar == A + 1 &&
                   rr.served_floor == A + 3 &&
                   rr.coins_applied_height == A + 2 &&
                   /* OWN-frame: served tip capped at coins_applied's own
                    * frame (coins_applied A+2 is NEXT-frame => applied
                    * through A+1 => can serve the transition row at A+1,
                    * i.e. served tip A+2). */
                   rr.tip_finalize_cursor_after == A + 2 &&
                   cursor_value(db, "tip_finalize") == A + 2 &&
                   rr.clamped_tip_finalize);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup coin-lag fixture",
                   setup_fixture(&fx, "coin_lag"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("seed contiguous hstar above coins_applied",
                   put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                   put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                   seed_coins_applied(db, A + 3));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("coin-lag apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("coin-lag caps tip_finalize at coins_applied",
                   rr.hstar == A + 3 &&
                   rr.coins_applied_height == A + 3 &&
                   /* OWN-frame: hstar allows served A+3..A+4 but coins
                    * (NEXT-frame A+3 => applied through A+2 => transition
                    * rows provable through A+2) cap the served-tip claim
                    * at A+3 — exactly where the step itself rests. */
                   rr.tip_finalize_cursor_after == A + 3 &&
                   cursor_value(db, "tip_finalize") == A + 3 &&
                   rr.clamped_tip_finalize);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup deep-coin-lag fixture",
                   setup_fixture(&fx, "deep_coin_lag"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("seed hstar above a deeply lagging coins frontier",
                   put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                   put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                   seed_coins_applied(db, A + 1));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("deep-coin-lag apply succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("deep-coin-lag refuses anchor-breaking tip clamp",
                   rr.hstar == A + 3 &&
                   rr.coins_applied_height == A + 1 &&
                   !rr.clamped_tip_finalize &&
                   rr.tip_finalize_cursor_after == A + 4 &&
                   cursor_value(db, "tip_finalize") == A + 4);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup unknown-coin fixture",
                   setup_fixture(&fx, "unknown"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("unknown-coin: active chain installs",
                   active_chain_move_window_tip(&fx.ms.chain_active,
                                                fx.idx[3]));
        RFRL_CHECK("unknown-coin: seed noncanonical script row",
                   put_script_status(db, A + 2, 0, "contextual_invalid",
                                     &fx.hashes[3]));
        RFRL_CHECK("unknown-coin: remove durable frontier authority",
                   exec_sql(db, "DELETE FROM progress_meta "
                                "WHERE key='coins_applied_height'"));
        struct stage_reducer_frontier_reconcile_result purge;
        memset(&purge, 0, sizeof(purge));
        purge.hstar = A + 1;
        purge.sweep_top = A + 2;
        purge.coins_applied_found = false;
        purge.coins_applied_height = -1;
        purge.lowest_noncanonical = -1;
        RFRL_CHECK("unknown-coin: direct purge detects but refuses",
                   stage_reducer_frontier_purge_noncanonical(db, &fx.ms, true,
                                                             &purge) &&
                   purge.noncanonical_found >= 1 &&
                   purge.noncanonical_purged == 0);
        RFRL_CHECK("unknown-coin: direct purge leaves rows intact",
                   count_range(db, "script_validate_log", A + 2, A + 3) == 1 &&
                   count_range(db, "body_persist_log", A + 2, A + 3) == 1 &&
                   count_range(db, "proof_validate_log", A + 2, A + 3) == 1);
        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("unknown-coin call succeeds",
                   stage_reducer_frontier_reconcile_light(
                       db, &fx.ms, &rr));
        RFRL_CHECK("unknown-coin refused without mutation",
                   rr.refused_coin_unknown &&
                   rr.noncanonical_purged == 0 &&
                   cursor_value(db, "tip_finalize") == A + 4 &&
                   (fx.idx[2]->nStatus & BLOCK_VALID_MASK) == 0);
        RFRL_CHECK("unknown-coin leaves purge evidence rows intact",
                   count_range(db, "script_validate_log", A + 2, A + 3) == 1 &&
                   count_range(db, "body_persist_log", A + 2, A + 3) == 1 &&
                   count_range(db, "proof_validate_log", A + 2, A + 3) == 1);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup zero-peer condition fixture",
                   setup_fixture(&fx, "zero_peer_condition"));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        sqlite3 *db = progress_store_db();
        /* STEP 4: the cursor-desync repair runs and clamps the cursors, but a
         * cursor clamp does NOT advance the provable frontier H*
         * (reducer_frontier_compute_hstar stays at A+1, still pinned by
         * tip_finalize). The H*-only witness therefore must NOT clear on cursor
         * churn — it stays active with one accrued attempt. (Pre-STEP-4 the
         * any-cursor-change clear-edge false-greened here; that edge is gone.) */
        bool ok = got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 1 &&
                  cursor_value(db, "body_fetch") == A + 2 &&
                  cursor_value(db, "tip_finalize") == A + 2 &&
                  snap.currently_active &&
                  snap.attempts == 1 &&
                  snap.last_outcome == COND_REMEDY_UNWITNESSED &&
                  snap.cleared_count == 0 &&
                  !snap.operator_needed_emitted;

        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            rfrl_json_condition(&dump, "reducer_frontier_reconcile_light");
        const struct json_value *detail = json_get(cond, "detail");
        ok = ok && detail != NULL;
        ok = ok &&
             json_get_int(json_get(detail, "hstar_at_detect")) == A + 1;
        ok = ok &&
             json_get_int(json_get(detail, "sweep_top_at_detect")) == A + 3;
        ok = ok &&
             json_get_int(json_get(
                 detail, "body_fetch_cursor_at_detect")) == A + 4;
        ok = ok &&
             json_get_int(json_get(
                 detail, "tip_finalize_cursor_at_detect")) == A + 4;
        ok = ok &&
             json_get_int(json_get(
                 detail, "coin_backfill_scan_present_at_detect")) == 0;
        ok = ok &&
             json_get_int(json_get(
                 detail, "tipfin_backfill_present_at_detect")) == 0;
        ok = ok && json_get_int(json_get(detail, "remedy_calls")) == 1;
        ok = ok && json_get_bool(json_get(
                     detail, "last_reconcile_seen"));
        ok = ok && strcmp(json_get_str(json_get(
                     detail, "last_reconcile_phase")), "remedy") == 0;
        ok = ok && !json_get_bool(json_get(
                     detail, "last_reconcile_refused_coin_tear"));
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_hstar")) == A + 1;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_body_fetch_cursor_before"))
                     == A + 4;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_body_fetch_cursor_after"))
                     == A + 2;
        ok = ok && !json_get_bool(json_get(
                     detail, "last_reconcile_clamped_script_validate"));
        ok = ok && !json_get_bool(json_get(
                     detail, "last_reconcile_clamped_proof_validate"));
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_script_validate_cursor_before"))
                     == A + 4;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_script_validate_cursor_after"))
                     == A + 4;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_proof_validate_cursor_before"))
                     == A + 4;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_proof_validate_cursor_after"))
                     == A + 4;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_lowest_script_validate_hash_split"))
                     == -1;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_lowest_script_validate_refill_hole"))
                     == -1;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_lowest_proof_validate_refill_hole"))
                     == -1;
        ok = ok && !json_get_bool(json_get(
                     detail, "last_reconcile_pre_refusal_unapplied_clamp"));
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_tip_finalize_cursor_before"))
                     == A + 4;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_tip_finalize_cursor_after"))
                     == A + 2;
        json_free(&dump);

        /* A second tick must still NOT false-clear: with H* unchanged the
         * witness stays false, so the condition remains active and un-cleared,
         * and a single bounded attempt does not page the operator. (Whether the
         * now-clamped symptom re-detects is irrelevant to the contract under
         * test — only that cursor churn never witnesses a clear.) */
        condition_engine_tick();
        got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        ok = ok && got &&
             snap.currently_active &&
             snap.cleared_count == 0 &&
             !snap.operator_needed_emitted;
        RFRL_CHECK("zero-peer cursor repair does not false-clear "
                   "(H*-only witness)", ok);

        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup coin-tear condition fixture",
                   setup_fixture(&fx, "cointear_condition"));
        sqlite3 *db = progress_store_db();
        /* REAL coin tear (same shape as the detect-path coin-tear case above):
         * a utxo_apply ok=0 hole at A+2 caps utxo_apply's own contiguous prefix
         * at A+1 while coins_applied sits at A+3, so
         * coins_applied > utxo_apply_contig+1 holds. The earlier seed leaned on
         * tip_finalize lagging at A+1 (a FALSE tear the new ua_contig compare
         * no longer escalates); this is a genuine hole below the cursor that
         * survives every pre-refusal repair, so the Condition still escalates
         * to operator_needed without mutating any cursor or block flag. */
        RFRL_CHECK("coin-tear condition: seed real utxo_apply hole",
                   put_simple_log(db, "utxo_apply_log", A + 2, 0) &&
                   seed_coins_applied(db, A + 3));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        for (int i = 0; i < 5; i++) {
            reducer_frontier_reconcile_light_test_clear_backoff();
            condition_engine_tick();
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        bool ok = got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 5 &&
                  snap.currently_active &&
                  snap.attempts >= 5 &&
                  snap.last_outcome == COND_REMEDY_FAILED &&
                  snap.operator_needed_emitted &&
                  cursor_value(db, "tip_finalize") == A + 4 &&
                  cursor_value(db, "body_fetch") == A + 4 &&
                  (fx.idx[2]->nStatus & BLOCK_VALID_MASK) == 0;

        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            rfrl_json_condition(&dump, "reducer_frontier_reconcile_light");
        const struct json_value *detail = json_get(cond, "detail");
        ok = ok && detail != NULL;
        ok = ok && json_get_bool(json_get(
                     detail, "last_reconcile_seen"));
        ok = ok && strcmp(json_get_str(json_get(
                     detail, "last_reconcile_phase")), "remedy") == 0;
        ok = ok && json_get_bool(json_get(
                     detail, "last_reconcile_refused_coin_tear"));
        ok = ok && !json_get_bool(json_get(
                     detail, "last_reconcile_refused_coin_unknown"));
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_coins_applied_height"))
                     == A + 3;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_tipfin_backfill_refused_reason"))
                     == STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_tipfin_backfill_refused_height"))
                     == A + 2;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_tipfin_backfill_refused_log"))
                     == STAGE_REPAIR_TIPFIN_LOG_UTXO_APPLY;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_tip_finalize_cursor_before"))
                     == A + 4;
        json_free(&dump);

        RFRL_CHECK("coin-tear condition escalates without mutation", ok);

        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    {
        /* Stale-script replay refusal (TOCTOU fix): the hole's preconditions
         * pass but the block is unreadable (fixture nFile == -1), so the
         * replay refuses AFTER the cursor snapshot — on a path that now runs
         * under the progress lock held from snapshot to rewind COMMIT. The
         * probe thread proves every traversed refusal path released it. */
        struct rfrl_fixture fx;
        RFRL_CHECK("setup stale-script fixture",
                   setup_fixture(&fx, "stale_script"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("stale-script: seed internal_error hole below cursor",
                   put_script_status(db, A + 2, 0, "internal_error",
                                     &fx.hashes[2]));

        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("stale-script: dry-run succeeds",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry));
        RFRL_CHECK("stale-script: dry-run reports the hole without mutation",
                   dry.repaired &&
                   dry.stale_script_repair_height == A + 2 &&
                   !dry.stale_script_repaired &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "utxo_apply") == A + 4);

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("stale-script: apply succeeds",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("stale-script: unreadable block refuses without rewind",
                   rr.stale_script_repair_height == A + 2 &&
                   !rr.stale_script_repaired &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "proof_validate") == A + 4 &&
                   cursor_value(db, "utxo_apply") == A + 4);

        bool probed = false;
        pthread_t probe;
        RFRL_CHECK("stale-script: probe thread starts",
                   pthread_create(&probe, NULL, progress_lock_probe,
                                  &probed) == 0);
        pthread_join(probe, NULL);
        RFRL_CHECK("stale-script: progress lock released on refusal", probed);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup readable stale-script fixture",
                   setup_fixture(&fx, "stale_script_readable"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("readable stale-script: canonical body is readable",
                   make_fixture_block_readable(&fx, 2));
        RFRL_CHECK("readable stale-script: seed one-body replay span",
                   seed_cursor(db, "body_persist", A + 3) &&
                   seed_cursor(db, "utxo_apply", A + 2) &&
                   put_script_status(db, A + 2, 0, "internal_error",
                                     &fx.hashes[2]));

        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("readable stale-script: dry-run succeeds",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry));
        RFRL_CHECK("readable stale-script: dry-run reports without mutation",
                   dry.repaired &&
                   !dry.refused_coin_tear &&
                   dry.hstar == A + 1 &&
                   dry.stale_script_repair_height == A + 2 &&
                   dry.stale_script_backfill_first == A + 2 &&
                   dry.stale_script_backfill_last == A + 2 &&
                   !dry.stale_script_repaired &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "proof_validate") == A + 4 &&
                   cursor_value(db, "utxo_apply") == A + 2);

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("readable stale-script: apply succeeds",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("readable stale-script: production replay rewinds rows",
                   rr.stale_script_repair_attempted &&
                   rr.stale_script_repaired &&
                   rr.stale_script_repair_height == A + 2 &&
                   rr.stale_script_cursor_before == A + 4 &&
                   rr.stale_script_cursor_after == A + 2 &&
                   rr.stale_script_backfill_first == A + 2 &&
                   rr.stale_script_backfill_last == A + 2 &&
                   !rr.stale_script_repair_genuinely_invalid &&
                   !rr.refused_coin_tear &&
                   cursor_value(db, "script_validate") == A + 2 &&
                   cursor_value(db, "proof_validate") == A + 2 &&
                   cursor_value(db, "tip_finalize") == A + 2 &&
                   cursor_value(db, "utxo_apply") == A + 2 &&
                   cursor_value(db, "body_persist") == A + 3 &&
                   count_range(db, "script_validate_log", A + 2, A + 4) == 0 &&
                   count_range(db, "proof_validate_log", A + 2, A + 4) == 0 &&
                   count_range(db, "validate_headers_log", A + 2, A + 4) == 2);

        teardown_fixture(&fx);
    }

    {
        struct rfrl_fixture fx;
        RFRL_CHECK("setup readable stale-proof fixture",
                   setup_fixture(&fx, "stale_proof_readable"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("readable stale-proof: canonical body is readable",
                   make_fixture_block_readable(&fx, 2));
        RFRL_CHECK("readable stale-proof: seed proof-only internal_error",
                   seed_cursor(db, "utxo_apply", A + 2) &&
                   put_script_status(db, A + 2, 1, "verified",
                                     &fx.hashes[2]) &&
                   put_proof_status(db, A + 2, 0, "internal_error",
                                    &fx.hashes[2]));

        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("readable stale-proof: dry-run succeeds",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry));
        RFRL_CHECK("readable stale-proof: dry-run reports without mutation",
                   dry.repaired &&
                   !dry.refused_coin_tear &&
                   dry.hstar == A + 1 &&
                   dry.stale_script_repair_attempted &&
                   dry.stale_script_repair_height == A + 2 &&
                   dry.stale_script_cursor_before == A + 4 &&
                   dry.stale_script_cursor_after == A + 4 &&
                   !dry.stale_script_repaired &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "proof_validate") == A + 4 &&
                   cursor_value(db, "utxo_apply") == A + 2);

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("readable stale-proof: apply succeeds",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("readable stale-proof: production replay rewinds proof only",
                   rr.stale_script_repair_attempted &&
                   rr.stale_script_repaired &&
                   rr.stale_script_repair_height == A + 2 &&
                   rr.stale_script_cursor_before == A + 4 &&
                   rr.stale_script_cursor_after == A + 2 &&
                   rr.stale_script_utxo_cursor_before == A + 2 &&
                   !rr.refused_coin_tear &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "proof_validate") == A + 2 &&
                   cursor_value(db, "tip_finalize") == A + 2 &&
                   cursor_value(db, "utxo_apply") == A + 2 &&
                   count_range(db, "proof_validate_log", A + 2, A + 4) == 0 &&
                   count_range(db, "script_validate_log", A + 2, A + 4) == 2);

        teardown_fixture(&fx);
    }

    {
        /* Dispatcher-order pin: a lower stale-script transient owns the shared
         * stale_script_* result fields even when a higher script-side
         * validate/script hash_split is also present. The hash-split probe may
         * remain observable through its own fields, but it must not overwrite
         * the lower repair height that the replay ladder will address first. */
        struct rfrl_fixture fx;
        RFRL_CHECK("setup stale-script + higher hash-split fixture",
                   setup_fixture(&fx, "stale_script_before_split"));
        sqlite3 *db = progress_store_db();

        struct uint256 stale = fx.hashes[3];
        stale.data[0] ^= 0x5a;
        RFRL_CHECK("stale-script+split: seed lower stale script and higher split",
                   put_script_status(db, A + 2, 0, "internal_error",
                                     &fx.hashes[2]) &&
                   put_hash_log(db, "script_validate_log", "block_hash",
                                A + 3, 1, &stale));

        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("stale-script+split: dry-run succeeds",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry));
        RFRL_CHECK("stale-script+split: lower stale-script hole keeps ownership",
                   dry.repaired &&
                   dry.stale_script_repair_height == A + 2 &&
                   dry.stale_script_cursor_before == A + 4 &&
                   dry.stale_script_cursor_after == A + 4 &&
                   (dry.lowest_script_validate_hash_split < 0 ||
                    dry.stale_script_repair_height <
                        dry.lowest_script_validate_hash_split) &&
                   !dry.stale_script_repaired &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "proof_validate") == A + 4);

        teardown_fixture(&fx);
    }

    {
        /* A coin-backfill refusal must be terminal for the current L1 pass:
         * the missing coin owns the prevout_unresolved hole. Falling through
         * to ordinary cursor repair lets a harmless body/tip clamp report
         * `repaired` even though the blocker is still unresolved, which is the
         * live soak shape this test pins. */
        struct rfrl_fixture fx;
        RFRL_CHECK("setup coin-backfill terminal refusal fixture",
                   setup_fixture(&fx, "coin_backfill_terminal"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("coin-backfill terminal: seed prevout hole below cursor",
                   put_script_status(db, A + 2, 0, "prevout_unresolved",
                                     &fx.hashes[2]));

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("coin-backfill terminal: apply succeeds",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("coin-backfill terminal: refusal does not fall through",
                   rr.coin_backfill_attempted &&
                   rr.coin_backfill_status != COIN_BACKFILL_NOT_APPLICABLE &&
                   !rr.repaired &&
                   !rr.clamped_body_fetch &&
                   !rr.clamped_tip_finalize &&
                   cursor_value(db, "body_fetch") == A + 4 &&
                   cursor_value(db, "tip_finalize") == A + 4 &&
                   cursor_value(db, "script_validate") == A + 4 &&
                   cursor_value(db, "utxo_apply") == A + 4);

        teardown_fixture(&fx);
    }

    {
        /* A coin-backfill refusal is a named, actionable self-heal failure,
         * not a quiet no-op. The fixture block is intentionally unreadable
         * (nFile == -1), so the prevout_unresolved hole refuses through the
         * backfill ladder and the condition must report FAILED rather than
         * SKIP. */
        struct rfrl_fixture fx;
        RFRL_CHECK("setup coin-backfill refusal condition fixture",
                   setup_fixture(&fx, "coin_backfill_refusal"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("coin-backfill refusal: seed prevout hole below cursor",
                   put_script_status(db, A + 2, 0, "prevout_unresolved",
                                     &fx.hashes[2]));
        RFRL_CHECK("coin-backfill refusal: pre-align benign cursors",
                   seed_cursor(db, "body_fetch", A + 2) &&
                   seed_cursor(db, "tip_finalize", A + 1));

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        bool ok = got &&
                  reducer_frontier_reconcile_light_test_remedy_calls() == 1 &&
                  snap.currently_active &&
                  snap.attempts == 1 &&
                  snap.last_outcome == COND_REMEDY_FAILED &&
                  !snap.operator_needed_emitted &&
                  cursor_value(db, "body_fetch") == A + 2 &&
                  cursor_value(db, "tip_finalize") == A + 1 &&
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4;
        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            rfrl_json_condition(&dump, "reducer_frontier_reconcile_light");
        const struct json_value *detail = json_get(cond, "detail");
        ok = ok && detail != NULL;
        ok = ok && json_get_bool(json_get(
                     detail, "last_reconcile_seen"));
        ok = ok && strcmp(json_get_str(json_get(
                     detail, "last_reconcile_phase")), "remedy") == 0;
        ok = ok && json_get_bool(json_get(
                     detail, "last_reconcile_coin_backfill_attempted"));
        ok = ok && !json_get_bool(json_get(
                     detail, "last_reconcile_repaired"));
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_coin_backfill_hole_height"))
                     == A + 2;
        ok = ok && json_get_int(json_get(
                     detail, "last_reconcile_coin_backfill_status")) > 0;
        ok = ok && strcmp(json_get_str(json_get(
                     detail,
                     "last_reconcile_coin_backfill_status_label")),
                     "not_applicable") != 0;
        json_free(&dump);
        RFRL_CHECK("coin-backfill refusal condition is failed, not skipped",
                   ok);

        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── non-canonical residue purge (the relabel-offset class) ──
     * Rows recorded for the WRONG block at their height (hash != the
     * canonical active-chain block) must be purged — including the false
     * ok=0 bad-cb-height verdicts no other repair touches — while a
     * GENUINE consensus reject (ok=0 with the canonical hash) survives. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("noncanon: setup fixture", setup_fixture(&fx, "noncanon"));
        sqlite3 *db = progress_store_db();

        RFRL_CHECK("noncanon: active chain installs",
                   active_chain_move_window_tip(&fx.ms.chain_active,
                                                fx.idx[3]));

        /* Stale row at A+2: recorded with A+3's hash (a relabel wrote the
         * wrong block's verdict here). False ok=0, like bad-cb-height. */
        RFRL_CHECK("noncanon: seed stale script row",
                   put_script_status(db, A + 2, 0, "contextual_invalid",
                                     &fx.hashes[3]));
        /* Genuine reject at A+3: ok=0 but hash IS canonical — kept. */
        RFRL_CHECK("noncanon: seed genuine reject",
                   put_script_status(db, A + 3, 0, "contextual_invalid",
                                     &fx.hashes[3]));

        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("noncanon: dry-run succeeds",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry));
        RFRL_CHECK("noncanon: dry-run finds, does not purge",
                   dry.noncanonical_found >= 1 &&
                   dry.noncanonical_purged == 0 &&
                   dry.lowest_noncanonical == A + 2);

        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("noncanon: apply succeeds",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        RFRL_CHECK("noncanon: apply purges the stale row",
                   rr.noncanonical_purged >= 1 && rr.repaired);

        sqlite3_stmt *st = NULL;
        int stale_left = -1, genuine_left = -1, vh_left = -1;
        if (sqlite3_prepare_v2(db,
                "SELECT "
                " (SELECT COUNT(*) FROM script_validate_log WHERE height=?),"
                " (SELECT COUNT(*) FROM script_validate_log WHERE height=?),"
                " (SELECT COUNT(*) FROM validate_headers_log WHERE height=?)",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, A + 2);
            sqlite3_bind_int(st, 2, A + 3);
            sqlite3_bind_int(st, 3, A + 2);
            if (sqlite3_step(st) == SQLITE_ROW) {
                stale_left = sqlite3_column_int(st, 0);
                genuine_left = sqlite3_column_int(st, 1);
                vh_left = sqlite3_column_int(st, 2);
            }
        }
        sqlite3_finalize(st);
        RFRL_CHECK("noncanon: stale gone, genuine + canonical rows kept",
                   stale_left == 0 && genuine_left == 1 && vh_left == 1);

        int dep_left = -1;
        if (sqlite3_prepare_v2(db,
                "SELECT (SELECT COUNT(*) FROM proof_validate_log "
                "WHERE height=?) + (SELECT COUNT(*) FROM body_persist_log "
                "WHERE height=?)",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, A + 2);
            sqlite3_bind_int(st, 2, A + 2);
            if (sqlite3_step(st) == SQLITE_ROW)
                dep_left = sqlite3_column_int(st, 0);
        }
        sqlite3_finalize(st);
        RFRL_CHECK("noncanon: hashless downstream rows purged transitively",
                   dep_left == 0);

        bool progress_probed = false;
        pthread_t progress_probe;
        bool progress_probe_started =
            pthread_create(&progress_probe, NULL, progress_lock_probe,
                           &progress_probed) == 0;
        RFRL_CHECK("noncanon: progress lock probe starts",
                   progress_probe_started);
        if (progress_probe_started) {
            pthread_join(progress_probe, NULL);
            RFRL_CHECK("noncanon: progress lock released",
                       progress_probed);
        }

        struct active_chain_lock_probe_arg chain_probe_arg = {
            .chain = &fx.ms.chain_active,
            .probed = false,
        };
        pthread_t chain_probe;
        bool chain_probe_started =
            pthread_create(&chain_probe, NULL, active_chain_lock_probe,
                           &chain_probe_arg) == 0;
        RFRL_CHECK("noncanon: active-chain lock probe starts",
                   chain_probe_started);
        if (chain_probe_started) {
            pthread_join(chain_probe, NULL);
            RFRL_CHECK("noncanon: active-chain lock released",
                       chain_probe_arg.probed);
        }

        teardown_fixture(&fx);
    }

    /* Non-canonical evidence below the known coins frontier is replay-domain,
     * not purge-domain. Deleting it creates a rowless hole below coins where
     * forward refills intentionally refuse to run. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("noncanon-below-coins: setup fixture",
                   setup_fixture(&fx, "noncanon_below_coins"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("noncanon-below-coins: active chain installs",
                   active_chain_move_window_tip(&fx.ms.chain_active,
                                                fx.idx[3]));
        RFRL_CHECK("noncanon-below-coins: seed coins above stale row",
                   seed_coins_applied(db, A + 3));
        RFRL_CHECK("noncanon-below-coins: seed stale script row",
                   put_script_status(db, A + 2, 0, "contextual_invalid",
                                     &fx.hashes[3]));

        struct stage_reducer_frontier_reconcile_result rr;
        memset(&rr, 0, sizeof(rr));
        rr.hstar = A + 1;
        rr.sweep_top = A + 2;
        rr.coins_applied_found = true;
        rr.coins_applied_height = A + 3;
        rr.lowest_noncanonical = -1;
        RFRL_CHECK("noncanon-below-coins: direct purge succeeds",
                   stage_reducer_frontier_purge_noncanonical(db, &fx.ms, true,
                                                             &rr));
        RFRL_CHECK("noncanon-below-coins: evidence is not purged",
                   rr.noncanonical_found >= 1 &&
                   rr.noncanonical_purged == 0 &&
                   count_range(db, "script_validate_log", A + 2, A + 3) == 1 &&
                   count_range(db, "body_persist_log", A + 2, A + 3) == 1 &&
                   count_range(db, "proof_validate_log", A + 2, A + 3) == 1);

        teardown_fixture(&fx);
    }

    /* A mixed-fork UTXO suffix must be removed as one kernel unit.  The
     * pre-lock result deliberately carries a stale coin frontier to reproduce
     * the live race: purge must re-read the durable frontier under its lock,
     * clamp there, and remove future log/delta/anchor state. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("noncanon-utxo-suffix: setup fixture",
                   setup_fixture(&fx, "noncanon_utxo_suffix"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("noncanon-utxo-suffix: active chain installs",
                   active_chain_move_window_tip(&fx.ms.chain_active,
                                                fx.idx[3]));
        struct uint256 fork = fx.hashes[3];
        fork.data[31] ^= 0x6du;
        RFRL_CHECK("noncanon-utxo-suffix: seed mixed fork and anchors",
                   put_utxo_delta(db, A + 3, &fork) &&
                   put_sapling_anchor_residue(db, A + 1, &fx.hashes[1]) &&
                   put_sapling_anchor_residue(db, A + 3, &fork));

        struct stage_reducer_frontier_reconcile_result rr;
        memset(&rr, 0, sizeof(rr));
        rr.hstar = A + 1;
        rr.sweep_top = A + 3;
        rr.coins_applied_found = true;
        rr.coins_applied_height = A + 1; /* stale pre-lock snapshot */
        rr.lowest_noncanonical = -1;
        RFRL_CHECK("noncanon-utxo-suffix: direct purge succeeds",
                   stage_reducer_frontier_purge_noncanonical(db, &fx.ms, true,
                                                             &rr));
        RFRL_CHECK("noncanon-utxo-suffix: live frontier wins stale snapshot",
                   rr.coins_applied_found &&
                   rr.coins_applied_height == A + 2 &&
                   cursor_value(db, "utxo_apply") == A + 2);
        RFRL_CHECK("noncanon-utxo-suffix: abandoned kernel suffix removed",
                   count_range(db, "utxo_apply_log", A + 2, A + 4) == 0 &&
                   count_range(db, "utxo_apply_delta", A + 2, A + 4) == 0 &&
                   count_range(db, "sapling_anchors", A + 2, A + 4) == 0 &&
                   count_range(db, "sapling_anchors", A + 1, A + 2) == 1);

        teardown_fixture(&fx);
    }

    /* ── P3: peer-gate BYPASS for internal re-derivations ──
     * A rowless script_validate_log + proof_validate_log hole below the
     * cursors (noncanonical-purge residue) re-derives from local persisted
     * state alone, so
     * peers-present-but-none-ahead must NOT suppress the healer. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("refill bypass: setup fixture",
                   setup_fixture(&fx, "refill_bypass"));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("refill bypass: delete script+proof rows at the hole",
                   delete_height(db, "script_validate_log", A + 2) &&
                   delete_height(db, "proof_validate_log", A + 2));

        /* One peer, NOT ahead: services=0 keeps connman_max_peer_height at
         * -1 while node_count=1, so peer_lag_allows_repair returns false —
         * pre-P3 the whole detect was discarded here every 5 s. */
        struct connman cm;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memset(&p1, 0, sizeof(p1));
        p1.id = 1;
        p1.starting_height = A + 1;
        p1.state = PEER_ACTIVE;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        RFRL_CHECK("refill bypass: detect fires with no peer ahead and the "
                   "remedy clamps script/proof cursors to the hole",
                   got &&
                   reducer_frontier_reconcile_light_test_remedy_calls() == 1 &&
                   snap.currently_active &&
                   cursor_value(db, "script_validate") == A + 2 &&
                   cursor_value(db, "proof_validate") == A + 2);
        RFRL_CHECK("refill bypass: transition WARN exactly once, no "
                   "suppression WARN",
                   reducer_frontier_reconcile_light_test_bypass_warns() == 1 &&
                   reducer_frontier_reconcile_light_test_gate_suppress_warns()
                       == 0);

        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── P3: gate PRESERVED for plain cursor churn (no repair evidence) ──
     * Same peer state (present, not ahead) with every refill hole absent and
     * no tear/residue: the tip_finalize clamp alone is not peer-independent
     * evidence, so detect stays suppressed — silently (no evidence to name,
     * so no WARN either). */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("churn suppress: setup fixture",
                   setup_fixture(&fx, "churn_suppress"));
        sqlite3 *db = progress_store_db();
        /* Fill body_fetch_log A+1..A+3 so no body_fetch refill hole exists;
         * the dry-run still reports repaired via the tip_finalize clamp and
         * the unreadable-HAVE_DATA flag sweep. */
        RFRL_CHECK("churn suppress: fill body_fetch rows",
                   put_body_fetch_ok(db, A + 1, &fx.hashes[1]) &&
                   put_body_fetch_ok(db, A + 2, &fx.hashes[2]) &&
                   put_body_fetch_ok(db, A + 3, &fx.hashes[3]));

        struct connman cm;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memset(&p1, 0, sizeof(p1));
        p1.id = 1;
        p1.starting_height = A + 1;
        p1.state = PEER_ACTIVE;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();
        reducer_frontier_reconcile_light_test_clear_backoff();
        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        RFRL_CHECK("churn suppress: gate holds, remedy never runs, silent",
                   got &&
                   reducer_frontier_reconcile_light_test_remedy_calls() == 0 &&
                   !snap.currently_active &&
                   reducer_frontier_reconcile_light_test_bypass_warns() == 0 &&
                   reducer_frontier_reconcile_light_test_gate_suppress_warns()
                       == 0);
        RFRL_CHECK("churn suppress: no mutation while suppressed",
                   cursor_value(db, "tip_finalize") == A + 4 &&
                   cursor_value(db, "body_fetch") == A + 4);

        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── P3: LOUD suppression — actionable evidence discarded at the gate
     * must WARN (throttled), never silently idle. The default fixture's
     * empty body_fetch_log reports lowest_body_fetch_refill_hole=A+2, which
     * is actionable but NOT in the internal-rederivation bypass list
     * (re-fetching a body needs a peer to serve it), so the gate suppresses
     * it and the suppression must be named in node.log. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("loud suppress: setup fixture",
                   setup_fixture(&fx, "loud_suppress"));
        sqlite3 *db = progress_store_db();

        struct connman cm;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memset(&p1, 0, sizeof(p1));
        p1.id = 1;
        p1.starting_height = A + 1;
        p1.state = PEER_ACTIVE;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        RFRL_CHECK("loud suppress: gate suppresses but WARNs once",
                   got &&
                   !snap.currently_active &&
                   reducer_frontier_reconcile_light_test_remedy_calls() == 0 &&
                   reducer_frontier_reconcile_light_test_bypass_warns() == 0 &&
                   reducer_frontier_reconcile_light_test_gate_suppress_warns()
                       == 1);

        reducer_frontier_reconcile_light_test_clear_backoff();
        condition_engine_tick();
        RFRL_CHECK("loud suppress: WARN throttled on the next tick",
                   reducer_frontier_reconcile_light_test_remedy_calls() == 0 &&
                   reducer_frontier_reconcile_light_test_gate_suppress_warns()
                       == 1);
        RFRL_CHECK("loud suppress: no mutation while suppressed",
                   cursor_value(db, "body_fetch") == A + 4 &&
                   cursor_value(db, "tip_finalize") == A + 4);

        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── F6: the peer gate compares the PROVABLE tip (H*), not the download
     * tip ───────────────────────────────────────────────────────────────────
     * The common wedge: the fold is stalled below the header tip, so the
     * download tip (active_chain_height) already sits at/above the peers' static
     * handshake starting_height while H* lags well behind. A block-serving peer
     * whose starting_height is AHEAD of H* but BEHIND the download tip is real
     * evidence the local provable tip is stale — the repair must be admitted.
     * The old download-tip comparison suppressed it (peer "not ahead"); the H*
     * comparison admits it. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("F6: setup fixture", setup_fixture(&fx, "f6_hstar_gate"));
        sqlite3 *db = progress_store_db();
        /* Download tip at A+3 (active_chain_height) while H* stays pinned at
         * A+1 (tip_finalize ok=1 only at A+1). */
        RFRL_CHECK("F6: active chain tip at A+3",
                   active_chain_move_window_tip(&fx.ms.chain_active,
                                                fx.idx[3]));

        /* One block-serving peer whose starting_height (A+2) is ABOVE H* (A+1)
         * but BELOW the download tip (A+3). */
        struct connman cm;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memset(&p1, 0, sizeof(p1));
        p1.id = 1;
        p1.starting_height = A + 2;
        p1.state = PEER_HANDSHAKE_COMPLETE;
        p1.services = NODE_NETWORK;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        sync_monitor_init();
        sync_monitor_set_context(&cm, NULL, &fx.ms);
        sync_monitor_test_set_tip_advance_ts(1);
        register_reducer_frontier_reconcile_light();

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "reducer_frontier_reconcile_light", &snap);
        RFRL_CHECK("F6: peer ahead of H* (not the download tip) admits the "
                   "repair — remedy runs and clamps tip_finalize to H*+1",
                   got &&
                   reducer_frontier_reconcile_light_test_remedy_calls() == 1 &&
                   snap.currently_active &&
                   cursor_value(db, "tip_finalize") == A + 2);
        /* Admitted via the H* peer-lag path, not the tear/refill bypass. */
        RFRL_CHECK("F6: no tear/refill bypass WARN (plain peer-ahead admit)",
                   reducer_frontier_reconcile_light_test_bypass_warns() == 0);

        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        sync_monitor_set_context(NULL, NULL, NULL);
        sync_monitor_test_set_tip_advance_ts(0);
        condition_engine_reset_for_testing();
        reducer_frontier_reconcile_light_test_reset();
        net_manager_free(&cm.manager);
        teardown_fixture(&fx);
    }

    /* ── Label-splice re-bind (direct arm): deep NULL-block_hash suffix ──
     * Models today's live wedge — proof/script cursors at N+164, an ok=1/
     * NULL-block_hash suffix over (N, N+163], utxo_apply at N+1, tip_finalize N.
     * The arm rewinds ONLY the proof/script VALIDATION cursors to the lowest
     * NULL (floored at MIN(utxo_apply, tip_finalize)) and deletes the NULL
     * suffix. Deep span (163) exceeds the small block_rollback cap (100),
     * proving the larger validation-rebind cap is what admits it. Pure
     * progress-store arm — no main_state needed. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir),
                         "reducer_frontier_reconcile_light", "rebind_direct");
        RFRL_CHECK("rebind-direct: store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        RFRL_CHECK("rebind-direct: schema", seed_schema(db));

        const int N = 1000;          /* anchor-free height */
        const int SPAN = 163;        /* NULL suffix over (N, N+163] */
        const int pv = N + SPAN + 1; /* proof/script cursor = N+164 */

        /* Row at N is hashed (below the consumer floor) — must NOT be touched. */
        struct uint256 hN; memset(&hN, 0, sizeof(hN)); hN.data[0] = 0x11;
        RFRL_CHECK("rebind-direct: hashed row at N (below floor)",
                   put_hash_log(db, "proof_validate_log", "block_hash",
                                N, 1, &hN) &&
                   put_hash_log(db, "script_validate_log", "block_hash",
                                N, 1, &hN));
        bool seeded = true;
        for (int h = N + 1; h <= N + SPAN; h++)
            seeded = seeded &&
                     put_verdict_null_hash(db, "proof_validate_log", h) &&
                     put_verdict_null_hash(db, "script_validate_log", h);
        RFRL_CHECK("rebind-direct: NULL suffix seeded", seeded);
        RFRL_CHECK("rebind-direct: cursors seeded",
                   seed_cursor(db, "proof_validate", pv) &&
                   seed_cursor(db, "script_validate", pv) &&
                   seed_cursor(db, "utxo_apply", N + 1) &&
                   seed_cursor(db, "tip_finalize", N));

        /* Dry-run: reports the pending re-bind, mutates NOTHING. */
        {
            struct stage_reducer_frontier_reconcile_result rr;
            memset(&rr, 0, sizeof(rr));
            rr.hstar = N;
            rr.label_splice_rebind_lowest = -1;
            bool mutated = true;
            RFRL_CHECK("rebind-direct: dry-run returns ok",
                       stage_reducer_frontier_try_label_splice_rebind(
                           db, false, &rr, &mutated));
            RFRL_CHECK("rebind-direct: dry-run detects N+1, no mutation",
                       !mutated && rr.label_splice_rebind_lowest == N + 1 &&
                       rr.label_splice_rebound == 0 &&
                       cursor_value(db, "proof_validate") == pv &&
                       cursor_value(db, "script_validate") == pv &&
                       count_null_block_hash(db, "proof_validate_log",
                                             N + 1, pv) == SPAN);
        }

        /* Cap gate: a small validation cap refuses the 163-deep rewind. */
        {
            setenv("ZCL_MAX_VALIDATION_REBIND", "100", 1);
            struct stage_reducer_frontier_reconcile_result rr;
            memset(&rr, 0, sizeof(rr));
            rr.hstar = N;
            rr.label_splice_rebind_lowest = -1;
            bool mutated = true;
            RFRL_CHECK("rebind-direct: cap=100 returns ok",
                       stage_reducer_frontier_try_label_splice_rebind(
                           db, true, &rr, &mutated));
            RFRL_CHECK("rebind-direct: cap=100 REFUSES 163-deep rewind",
                       !mutated && rr.label_splice_rebound == 0 &&
                       cursor_value(db, "proof_validate") == pv &&
                       count_null_block_hash(db, "proof_validate_log",
                                             N + 1, pv) == SPAN);
            unsetenv("ZCL_MAX_VALIDATION_REBIND");
        }

        /* Apply: default cap (4096) admits the 163-deep rewind of BOTH cursors. */
        {
            struct stage_reducer_frontier_reconcile_result rr;
            memset(&rr, 0, sizeof(rr));
            rr.hstar = N;
            rr.label_splice_rebind_lowest = -1;
            rr.label_splice_proof_rewound_to = -1;
            rr.label_splice_script_rewound_to = -1;
            bool mutated = false;
            RFRL_CHECK("rebind-direct: apply returns ok",
                       stage_reducer_frontier_try_label_splice_rebind(
                           db, true, &rr, &mutated));
            RFRL_CHECK("rebind-direct: apply re-bound BOTH cursors to N+1",
                       mutated && rr.label_splice_rebound == 2 &&
                       rr.label_splice_proof_rewound_to == N + 1 &&
                       rr.label_splice_script_rewound_to == N + 1 &&
                       cursor_value(db, "proof_validate") == N + 1 &&
                       cursor_value(db, "script_validate") == N + 1);
            RFRL_CHECK("rebind-direct: NULL suffix deleted, floor row kept, "
                       "utxo_apply/tip_finalize untouched",
                       count_null_block_hash(db, "proof_validate_log",
                                             N + 1, pv) == 0 &&
                       count_null_block_hash(db, "script_validate_log",
                                             N + 1, pv) == 0 &&
                       count_range(db, "proof_validate_log", N, N + 1) == 1 &&
                       count_range(db, "script_validate_log", N, N + 1) == 1 &&
                       cursor_value(db, "utxo_apply") == N + 1 &&
                       cursor_value(db, "tip_finalize") == N);
        }

        progress_store_close();
        test_rm_rf_recursive(dir);
    }

    /* ── Label-splice re-bind (WIRING via the public reconcile entry) ──
     * The impl must CALL the arm. Seed a NULL-block_hash proof/script suffix at
     * the utxo_apply frontier; the ONLY thing that rewinds the proof/script
     * VALIDATION cursors is the re-bind arm, so on main (arm unwired) they stay
     * at A+4 — this is the RED assertion. */
    {
        struct rfrl_fixture fx;
        RFRL_CHECK("rebind-wire: setup", setup_fixture(&fx, "rebind_wire"));
        sqlite3 *db = progress_store_db();

        /* utxo_apply STUCK at A+2 (its log ok=1 only through A+1); proof/script
         * validated ahead to A+4 with a NULL-block_hash suffix at A+2, A+3.
         * active window tip pinned at A+1 (== hstar) so the noncanonical purge
         * scans empty, exactly like the live wedge. */
        RFRL_CHECK("rebind-wire: shape the wedge",
                   delete_height(db, "utxo_apply_log", A + 2) &&
                   delete_height(db, "utxo_apply_log", A + 3) &&
                   delete_height(db, "utxo_apply_delta", A + 2) &&
                   delete_height(db, "utxo_apply_delta", A + 3) &&
                   put_verdict_null_hash(db, "proof_validate_log", A + 2) &&
                   put_verdict_null_hash(db, "proof_validate_log", A + 3) &&
                   put_verdict_null_hash(db, "script_validate_log", A + 2) &&
                   put_verdict_null_hash(db, "script_validate_log", A + 3) &&
                   seed_cursor(db, "utxo_apply", A + 2) &&
                   seed_cursor(db, "tip_finalize", A + 2) &&
                   seed_coins_applied(db, A + 2) &&
                   active_chain_move_window_tip(&fx.ms.chain_active, fx.idx[1]));

        /* Dry-run detect sees the pending re-bind (activates the Condition). */
        struct stage_reducer_frontier_reconcile_result dry;
        RFRL_CHECK("rebind-wire: dry-run detects re-bind pending",
                   stage_reducer_frontier_reconcile_light_needed(
                       db, &fx.ms, &dry) &&
                   dry.label_splice_rebind_lowest == A + 2 &&
                   dry.hstar == A + 1 &&
                   cursor_value(db, "proof_validate") == A + 4 &&
                   count_null_block_hash(db, "proof_validate_log",
                                         A + 2, A + 4) == 2);

        /* Apply: the wired impl runs the arm — proof/script cursors rewind and
         * the NULL suffix is deleted. On main (arm unwired) these stay at A+4. */
        struct stage_reducer_frontier_reconcile_result rr;
        RFRL_CHECK("rebind-wire: apply runs the arm (RED->GREEN)",
                   stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr) &&
                   rr.label_splice_rebound == 2 &&
                   cursor_value(db, "proof_validate") == A + 2 &&
                   cursor_value(db, "script_validate") == A + 2 &&
                   count_null_block_hash(db, "proof_validate_log",
                                         A + 2, A + 4) == 0 &&
                   count_null_block_hash(db, "script_validate_log",
                                         A + 2, A + 4) == 0 &&
                   /* utxo_apply cursor NEVER touched by the arm. */
                   cursor_value(db, "utxo_apply") == A + 2);

        teardown_fixture(&fx);
    }

    /* ── Conflation regression: a fired re-bind outranks a coin_backfill refusal
     * The remedy decision (rfrl_remedy_outcome) is a PURE function of the
     * result. A successful label_splice re-bind must report OK even when an
     * unrelated coin_backfill owner-refusal is set at a later height. The
     * control (no re-bind) proves the coin refusal alone WOULD fail the remedy
     * — the exact masking the live node hit. */
    {
        struct stage_reducer_frontier_reconcile_result rr;
        memset(&rr, 0, sizeof(rr));
        rr.coin_backfill_attempted = true;
        rr.coin_backfill_owner_refused = true;
        rr.coin_backfill_hole_height = A + 900;
        RFRL_CHECK("conflation: coin refusal alone -> FAILED (control)",
                   reducer_frontier_reconcile_light_test_remedy_outcome(&rr) ==
                       COND_REMEDY_FAILED);

        rr.label_splice_rebound = 2;
        rr.label_splice_rebind_lowest = A + 2;
        rr.repaired = true;
        RFRL_CHECK("conflation: re-bind + coin refusal -> OK (re-bind wins)",
                   reducer_frontier_reconcile_light_test_remedy_outcome(&rr) ==
                       COND_REMEDY_OK);
    }

    printf("reducer_frontier_reconcile_light: %d failures\n", failures);
    return failures;
}
