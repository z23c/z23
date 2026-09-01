/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stall_totality_matrix — the F4 stall-totality matrix
 * (docs/work/fail-safe-architecture.md §4 item 4: "synthesize every stall
 * kind on a fixture, assert H* climbs or rung-3 arms; pin the 3166989
 * shape as regression").
 *
 * One case per stall KIND. Each case synthesizes the durable progress.kv
 * shape that births the stall, then drives the REAL escalation ladder
 * (sticky_escalator_note_stall -> retry -> targeted_rederive — the same
 * rung sequence a live stall takes) and asserts the repair surface either
 * ADVANCES the frontier (cursors clamp to the hole / stale rows re-derived
 * from the body) or ESCALATES (the rung honestly advances) — never a
 * silent hold. Every case asserts BOTH the durable effect (cursor/log
 * values via SQL) and the escalator surface (rung + armed).
 *
 *   K1  — rowless script/proof hole below the cursors at the coins
 *         frontier: the regression pin for the shape where a
 *         purge deletes committed while both cursors stayed above the
 *         hole, stage_repair_reducer_frontier_purge.c:88-94). Cure under
 *         test: the refill clamps script/proof cursors to the hole.
 *   K1b — rowless script/proof hole STRICTLY BELOW the coins frontier:
 *         the refill refuses the clamp (replay domain,
 *         stage_repair_reducer_frontier_refill.c:385-391) and the replay
 *         detectors match only EXISTING ok=0 rows
 *         (reducer_frontier_replay.c:73-104), so the shape is owned by
 *         ESCALATION. The totality contract is the dichotomy itself:
 *         cursors clamp to the hole OR the rung advances.
 *   K2  — stale ok=0 verdict with the canonical body present and readable
 *         on disk: the stale-script replay re-derives from the body —
 *         deletes the stale rows and rewinds script/proof/tip cursors in
 *         ONE transaction (reducer_frontier_replay_tx.c).
 *   K3  — non-canonical relabeled rows above a reorg point: the purge
 *         deletes them AND clamps the script/proof cursors in the SAME
 *         transaction (the co-commit cure); a genuine consensus
 *         reject (ok=0 whose hash IS canonical) survives untouched.
 *   K4  — tip_finalize cursor stranded above the coins frontier: clamped
 *         into the [H*, coins_applied] serving band; nothing else
 *         moves and no row is deleted.
 *   K5  — hash_split: a stored ok=1 validate verdict whose hash disagrees
 *         with the canonical verdict at the same height; the validate
 *         cursor clamps to the split height so the column re-derives.
 *   K6  — fully consistent store: the honest no-op — the rung must
 *         ADVANCE (escalate to the next rung), with zero writes.
 *
 * Fixture is the test_sticky_escalator.c pattern (synthetic progress.kv
 * rows at the mainnet trusted anchor A; the ladder driven through the
 * sticky_escalator_test_drive seam). K2 borrows the mined-regtest-block
 * helper from test_reducer_frontier_reconcile_light.c so the canonical
 * body is genuinely present, PoW-mined and hash-verified on disk — the
 * replay re-derives with the SAME validation code, no shortcut flags
 * (consensus parity untouched). */

#include "platform/time_compat.h"
#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "storage/boot_auto_refold.h"
#include "storage/disk_block_io.h"
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

#define STM_CHECK(name, expr) do { \
    printf("stall_totality_matrix: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

/* The compiled-anchor floor is network-derived; the fixtures seed rows at
 * MAINNET heights (A+1..) so the floor is pinned to the mainnet anchor A for
 * compute_hstar (the test_sticky_escalator.c pattern). Restored to -1
 * (production default) before return. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* ── Fixture: synthetic progress.kv at the mainnet trusted anchor ───────── */

struct stm_fixture {
    char dir[256];
    struct main_state ms;
    struct uint256 hashes[4];
    struct block_index *idx[4];
};

static int stm_mkdir_p(const char *p)
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

/* Script verdict with an explicit status (the replay/purge discriminator). */
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

static bool put_utxo_log(sqlite3 *db, int height, int ok_flag,
                         const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
            "VALUES(?,'verified',?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
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
    return put_hash_log(db, "validate_headers_log", "hash", height, 1, hash) &&
           put_hash_log(db, "script_validate_log", "block_hash", height, 1,
                        hash) &&
           put_simple_log(db, "body_persist_log", height, 1) &&
           put_hash_log(db, "proof_validate_log", "block_hash", height, 1,
                        hash) &&
           put_utxo_log(db, height, 1, hash);
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
     * TRUSTED_ANCHOR floor (the fixture models a seeded datadir whose H*
     * clamps at the anchor — the test_sticky_escalator.c rationale). */
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
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

/* Total rows across every reducer log — the "no log row is ever deleted"
 * invariant witness for clamp-only repairs. */
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
    hash->data[31] = 0x57;

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

static bool setup_fixture(struct stm_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "stall_totality", tag);
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

static void teardown_fixture(struct stm_fixture *fx)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    sticky_escalator_test_reset();
    stage_reducer_frontier_reset_detect_memo_for_testing();
    main_state_free(&fx->ms);
    progress_store_close();
    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    test_cleanup_tmpdir(fx->dir);
}

/* ── K2 helper: a REAL canonical body on disk (the rfrl fixture) ─────────
 * Mines a regtest coinbase-only block at fx->idx[slot]'s height, writes it
 * to the fixture datadir, hash-verifies HAVE_DATA on the index entry, and
 * re-seeds the per-height log rows with the real hash. Full validation
 * code paths, no shortcuts — the replay under test re-derives with the
 * production pipeline. */
static bool build_regtest_block(struct block *blk, int height,
                                const struct uint256 *prev_hash,
                                const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "stm_vtx");
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

static bool make_fixture_block_readable(struct stm_fixture *fx, int slot)
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
    if (stm_mkdir_p(netdir) != 0)
        return false;
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    if (stm_mkdir_p(blocksdir) != 0)
        return false;

    struct block blk;
    bool ok = build_regtest_block(
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
           put_utxo_log(db, fx->idx[slot]->nHeight, 1,
                        &fx->hashes[slot]) &&
           active_chain_move_window_tip(&fx->ms.chain_active, fx->idx[3]);
}

/* ── The shared ladder drive ─────────────────────────────────────────────
 * Arms the ladder for `cause` and drives it through the retry window into
 * targeted_rederive, then dispatches the rederive rung once. Returns the
 * rung AFTER that dispatch — TARGETED_REDERIVE means the rung repaired and
 * HOLDS while the stages consume the clamp; RESNAPSHOT means the rung
 * found nothing actionable and the ladder honestly advanced. *out_t0 gets
 * the wall clock the injected drive times are anchored on (note_stall
 * stamps the rung-entered clock with the REAL wall time; injected tip 0
 * never satisfies the progress margin). STICKY_RUNG_COUNT = a rung
 * sequencing failure (loud FAIL in the caller's check). */
static enum sticky_rung arm_and_run_rederive(struct stm_fixture *fx,
                                             const char *cause,
                                             int64_t *out_t0)
{
    sync_monitor_set_context(NULL, NULL, &fx->ms);
    sticky_escalator_test_reset();
    stage_reducer_frontier_reset_detect_memo_for_testing();

    sticky_escalator_note_stall(cause);
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    if (out_t0)
        *out_t0 = t0;
    if (!sticky_escalator_test_armed())
        return STICKY_RUNG_COUNT;
    if (sticky_escalator_test_drive(0, t0 + 1) != STICKY_RUNG_RETRY)
        return STICKY_RUNG_COUNT;
    if (sticky_escalator_test_drive(0, t0 + 31) !=
            STICKY_RUNG_TARGETED_REDERIVE)
        return STICKY_RUNG_COUNT;
    return sticky_escalator_test_drive(0, t0 + 32);
}

/* Provable-tip H* over the fixture's progress.kv logs — the MIN-fold the node
 * serves as getblockcount. Used to prove a repair CLIMBS H* (not merely returns
 * true): a rowless hole caps it below the hole; the re-fold the repair unblocks
 * lifts it past. Re-entrant-safe lock (compute_hstar re-takes it internally). */
static int32_t stm_compute_hstar(sqlite3 *db)
{
    int32_t h = -1, served = -1;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, &h, &served);
    progress_store_tx_unlock();
    return ok ? h : -1;
}

int test_stall_totality_matrix(void);
int test_stall_totality_matrix(void)
{
    printf("\n=== stall_totality_matrix tests ===\n");
    int failures = 0;

    blocker_module_init();
    /* Pin the network-derived compiled-anchor floor to the mainnet anchor A:
     * the fixtures seed rows at A+1.. (the sticky_escalator test rationale). */
    reducer_frontier_test_set_compiled_anchor(A);

    /* K1 — THE 3166989 REGRESSION PIN: rowless script+proof hole below the
     * cursors at the coins frontier. Repair = clamp both cursors to the
     * hole so the forward stages re-derive from persisted bodies; the rung
     * holds while they consume it. */
    {
        struct stm_fixture fx;
        STM_CHECK("K1: setup fixture", setup_fixture(&fx, "k1_hole"));
        sqlite3 *db = progress_store_db();

        STM_CHECK("K1: punch rowless script+proof hole below the cursors",
                  delete_height(db, "script_validate_log", A + 2) &&
                  delete_height(db, "proof_validate_log", A + 2));
        int64_t rows_before = total_log_rows(db);

        STM_CHECK("K1: rederive repairs and HOLDS the rung",
                  arm_and_run_rederive(&fx, "k1_rowless_hole", NULL) ==
                      STICKY_RUNG_TARGETED_REDERIVE &&
                  sticky_escalator_test_armed());
        STM_CHECK("K1: script/proof cursors clamp to the hole",
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 2);
        STM_CHECK("K1: tip_finalize clamps to the coins-backed served tip",
                  cursor_value(db, "tip_finalize") == A + 2);
        STM_CHECK("K1: unrelated cursors untouched + no log rows deleted",
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  cursor_value(db, "validate_headers") == A + 4 &&
                  cursor_value(db, "body_fetch") == A + 4 &&
                  cursor_value(db, "body_persist") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* K1b — rowless hole STRICTLY BELOW the coins frontier: the refill
     * refuses the clamp (refill.c:385-391, replay domain) and the replay
     * detectors need an existing ok=0 row (replay.c:73-104), so today the
     * shape is owned by ESCALATION. The totality contract is the
     * dichotomy: cursors clamp to the hole OR the rung advances within its
     * bounded window — never a silent forever-hold. */
    {
        struct stm_fixture fx;
        STM_CHECK("K1b: setup fixture", setup_fixture(&fx, "k1b_below"));
        sqlite3 *db = progress_store_db();

        STM_CHECK("K1b: punch hole strictly below the coins frontier",
                  delete_height(db, "script_validate_log", A + 2) &&
                  delete_height(db, "proof_validate_log", A + 2) &&
                  seed_coins_applied(db, A + 3));

        int64_t t0 = 0;
        enum sticky_rung after_dispatch =
            arm_and_run_rederive(&fx, "k1b_below_coins", &t0);
        STM_CHECK("K1b: rederive dispatch is bounded (hold or advance)",
                  after_dispatch == STICKY_RUNG_TARGETED_REDERIVE ||
                  after_dispatch == STICKY_RUNG_RESNAPSHOT);
        /* Lapse the rederive witness window with no H* progress: a held
         * rung must hand off to the next rung, not spin. */
        enum sticky_rung after_window =
            sticky_escalator_test_drive(0, t0 + 31 + 61);
        STM_CHECK("K1b: repaired-or-escalated dichotomy",
                  cursor_value(db, "script_validate") == A + 2 ||
                  after_window >= STICKY_RUNG_RESNAPSHOT);
        STM_CHECK("K1b: ladder still armed (episode clears only on H* climb)",
                  sticky_escalator_test_armed());

        teardown_fixture(&fx);
    }

    /* K2 — stale ok=0 verdict with the canonical body present: the
     * stale-script replay re-derives from the PoW-mined on-disk body,
     * deleting the stale rows and rewinding script/proof/tip cursors in
     * one transaction. */
    {
        struct stm_fixture fx;
        STM_CHECK("K2: setup fixture", setup_fixture(&fx, "k2_stale_ok0"));
        sqlite3 *db = progress_store_db();

        STM_CHECK("K2: canonical body mined + readable on disk",
                  make_fixture_block_readable(&fx, 2));
        STM_CHECK("K2: seed stale ok=0 verdict at the readable height",
                  seed_cursor(db, "body_persist", A + 3) &&
                  seed_cursor(db, "utxo_apply", A + 2) &&
                  put_script_status(db, A + 2, 0, "internal_error",
                                    &fx.hashes[2]));

        STM_CHECK("K2: rederive repairs and HOLDS the rung",
                  arm_and_run_rederive(&fx, "k2_stale_verdict", NULL) ==
                      STICKY_RUNG_TARGETED_REDERIVE &&
                  sticky_escalator_test_armed());
        STM_CHECK("K2: stale script/proof rows deleted for the re-fold",
                  count_range(db, "script_validate_log", A + 2, A + 4) == 0 &&
                  count_range(db, "proof_validate_log", A + 2, A + 4) == 0 &&
                  count_range(db, "validate_headers_log", A + 2, A + 4) == 2);
        STM_CHECK("K2: cursors rewound to the repair height in one tx",
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 2 &&
                  cursor_value(db, "tip_finalize") == A + 2 &&
                  cursor_value(db, "utxo_apply") == A + 2 &&
                  cursor_value(db, "body_persist") == A + 3);

        teardown_fixture(&fx);
    }

    /* K3 — non-canonical relabeled rows above a reorg point: the purge
     * deletes the residue (plus its hashless downstream rows) and clamps
     * the script/proof cursors in the SAME transaction; a genuine
     * consensus reject at the canonical hash survives. */
    {
        struct stm_fixture fx;
        STM_CHECK("K3: setup fixture", setup_fixture(&fx, "k3_noncanon"));
        sqlite3 *db = progress_store_db();

        STM_CHECK("K3: active chain installs",
                  active_chain_move_window_tip(&fx.ms.chain_active,
                                               fx.idx[3]));
        /* Relabel residue at A+2: the verdict was recorded for A+3's block
         * (false ok=0, the bad-cb-height class). Genuine reject at A+3:
         * ok=0 but the hash IS canonical — parity says it stays. */
        STM_CHECK("K3: seed relabel residue + genuine reject",
                  put_script_status(db, A + 2, 0, "contextual_invalid",
                                    &fx.hashes[3]) &&
                  put_script_status(db, A + 3, 0, "contextual_invalid",
                                    &fx.hashes[3]));

        STM_CHECK("K3: rederive repairs and HOLDS the rung",
                  arm_and_run_rederive(&fx, "k3_noncanonical", NULL) ==
                      STICKY_RUNG_TARGETED_REDERIVE &&
                  sticky_escalator_test_armed());
        STM_CHECK("K3: residue purged, genuine reject + canonical rows kept",
                  count_range(db, "script_validate_log", A + 2, A + 3) == 0 &&
                  count_range(db, "script_validate_log", A + 3, A + 4) == 1 &&
                  count_range(db, "validate_headers_log", A + 2, A + 3) == 1);
        STM_CHECK("K3: hashless downstream rows purged transitively",
                  count_range(db, "proof_validate_log", A + 2, A + 3) == 0 &&
                  count_range(db, "body_persist_log", A + 2, A + 3) == 0);
        STM_CHECK("K3: script/proof cursors clamped with the deletes",
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 2);
        STM_CHECK("K3: coins writer untouched, tip_finalize at the "
                  "coins-backed served tip",
                  cursor_value(db, "tip_finalize") == A + 2 &&
                  cursor_value(db, "utxo_apply") == A + 4);

        teardown_fixture(&fx);
    }

    /* K4 — tip_finalize cursor stranded above the coins frontier: clamped
     * into the [H*, coins_applied] serving band. Clamp-only: no
     * other cursor moves, no row is touched. */
    {
        struct stm_fixture fx;
        STM_CHECK("K4: setup fixture", setup_fixture(&fx, "k4_tip_cursor"));
        sqlite3 *db = progress_store_db();

        /* Contiguous ok=1 frontier through A+3 with coins applied through
         * A+2 (NEXT-frame A+3), tip cursor stranded at A+4. */
        STM_CHECK("K4: seed contiguous frontier + stranded tip cursor",
                  put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                  put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                  seed_coins_applied(db, A + 3));
        int64_t rows_before = total_log_rows(db);

        STM_CHECK("K4: rederive repairs and HOLDS the rung",
                  arm_and_run_rederive(&fx, "k4_tip_above_coins", NULL) ==
                      STICKY_RUNG_TARGETED_REDERIVE &&
                  sticky_escalator_test_armed());
        STM_CHECK("K4: tip_finalize clamps to the coins_applied cap",
                  cursor_value(db, "tip_finalize") == A + 3);
        STM_CHECK("K4: clamp-only — every other cursor + row untouched",
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  cursor_value(db, "validate_headers") == A + 4 &&
                  cursor_value(db, "body_fetch") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* K5 — hash_split: an ok=1 validate verdict whose stored hash
     * disagrees with the canonical verdict at the same height. The
     * validate cursor clamps to the split height so the column re-derives
     * the canonical header; no row is deleted by the clamp. */
    {
        struct stm_fixture fx;
        STM_CHECK("K5: setup fixture", setup_fixture(&fx, "k5_hash_split"));
        sqlite3 *db = progress_store_db();

        struct uint256 stale = fx.hashes[2];
        stale.data[0] ^= 0x5a;
        STM_CHECK("K5: seed split validate verdict + coins above it",
                  put_hash_log(db, "validate_headers_log", "hash",
                               A + 2, 1, &stale) &&
                  seed_coins_applied(db, A + 3));
        int64_t rows_before = total_log_rows(db);

        STM_CHECK("K5: rederive repairs and HOLDS the rung",
                  arm_and_run_rederive(&fx, "k5_hash_split", NULL) ==
                      STICKY_RUNG_TARGETED_REDERIVE &&
                  sticky_escalator_test_armed());
        STM_CHECK("K5: validate cursor clamps to the split height",
                  cursor_value(db, "validate_headers") == A + 2);
        STM_CHECK("K5: served tip re-capped at the split",
                  cursor_value(db, "tip_finalize") == A + 2);
        STM_CHECK("K5: downstream rows intact, no row deleted",
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "body_persist") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* K6 — fully consistent store: nothing actionable. The rung reports
     * the honest no-op and the ladder ADVANCES to the next rung; zero
     * cursor writes, zero row deletes. */
    {
        struct stm_fixture fx;
        STM_CHECK("K6: setup fixture", setup_fixture(&fx, "k6_clean"));
        sqlite3 *db = progress_store_db();

        /* Complete the tip column, move coins one above H*, and park the
         * OWN-frame tip_finalize cursor AT H* (A+3, the served tip) so
         * every cursor already equals its reconcile target. */
        STM_CHECK("K6: complete tip rows + coins frontier + served cursor",
                  put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                  put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                  seed_coins_applied(db, A + 4) &&
                  seed_cursor(db, "tip_finalize", A + 3));
        int64_t rows_before = total_log_rows(db);

        STM_CHECK("K6: no-op rederive honestly ADVANCES the ladder",
                  arm_and_run_rederive(&fx, "k6_clean_store", NULL) ==
                      STICKY_RUNG_RESNAPSHOT &&
                  sticky_escalator_test_armed());
        STM_CHECK("K6: zero cursor writes + no log rows deleted",
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4 &&
                  cursor_value(db, "utxo_apply") == A + 4 &&
                  cursor_value(db, "validate_headers") == A + 4 &&
                  cursor_value(db, "body_fetch") == A + 4 &&
                  cursor_value(db, "body_persist") == A + 4 &&
                  cursor_value(db, "tip_finalize") == A + 3 &&
                  total_log_rows(db) == rows_before);

        teardown_fixture(&fx);
    }

    /* ── A3: ROW-ABSENT (rowless-page) shapes — the fourth detector match
     * (fail-safe-architecture.md §4 item 0a). The three pre-existing replay
     * detectors all require an EXISTING row (ok=0 status hole, ok=1 wrong-hash
     * split, ok=0 proof internal_error); the refill clamps rowless holes AT OR
     * ABOVE the coins frontier but REFUSES those strictly below it
     * (refill.c:385-391) — so a purely rowless span below the frontier fell
     * through to escalation (the live 3166989 gap). K7/K8/K9 pin the new
     * absent_script_hole detector that closes it by routing the ROWLESS hole to
     * the SAME stale_script_replay_tx. ──────────────────────────────────── */

    /* K7 — ROW-ABSENT verdict below the cursor with the canonical body present:
     * the detector re-derives from the PoW-mined on-disk body (deletes the stale
     * span rows, rewinds script/proof/tip cursors in ONE tx), and H* CLIMBS once
     * the unblocked stages re-fold. */
    {
        struct stm_fixture fx;
        STM_CHECK("K7: setup fixture", setup_fixture(&fx, "k7_absent_row"));
        sqlite3 *db = progress_store_db();

        STM_CHECK("K7: canonical body mined + readable on disk",
                  make_fixture_block_readable(&fx, 2));
        STM_CHECK("K7: delete verdict rows -> a ROWLESS hole below the cursor",
                  seed_cursor(db, "body_persist", A + 3) &&
                  seed_cursor(db, "utxo_apply", A + 2) &&
                  delete_height(db, "script_validate_log", A + 2) &&
                  delete_height(db, "proof_validate_log", A + 2));

        int32_t hstar_before = stm_compute_hstar(db);
        STM_CHECK("K7: H* is capped below the rowless hole before repair",
                  hstar_before == A + 1);

        STM_CHECK("K7: rederive repairs the ROW-ABSENT hole and HOLDS the rung",
                  arm_and_run_rederive(&fx, "k7_absent_verdict_row", NULL) ==
                      STICKY_RUNG_TARGETED_REDERIVE &&
                  sticky_escalator_test_armed());
        STM_CHECK("K7: stale span rows deleted, validate kept (no header rewind)",
                  count_range(db, "script_validate_log", A + 2, A + 4) == 0 &&
                  count_range(db, "proof_validate_log", A + 2, A + 4) == 0 &&
                  count_range(db, "validate_headers_log", A + 2, A + 4) == 2);
        STM_CHECK("K7: script/proof/tip/utxo cursors rewound to the hole",
                  cursor_value(db, "script_validate") == A + 2 &&
                  cursor_value(db, "proof_validate") == A + 2 &&
                  cursor_value(db, "tip_finalize") == A + 2 &&
                  cursor_value(db, "utxo_apply") == A + 2 &&
                  cursor_value(db, "body_persist") == A + 3);

        /* Simulate the forward fold the rewind unblocked, then H* CLIMBS past
         * the old cap (proves the repair enables progress, not just returns). */
        STM_CHECK("K7: simulate the unblocked re-fold over the rewound span",
                  put_upstream_ok(db, A + 2, &fx.hashes[2]) &&
                  put_upstream_ok(db, A + 3, &fx.hashes[3]) &&
                  put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                  put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                  seed_coins_applied(db, A + 4) &&
                  seed_all_cursors(db, A + 4));
        int32_t hstar_after = stm_compute_hstar(db);
        STM_CHECK("K7: H* CLIMBS after the re-fold (not merely repair==true)",
                  hstar_after == A + 3 && hstar_after > hstar_before);

        teardown_fixture(&fx);
    }

    /* K8 — ROW-ABSENT hole STRICTLY BELOW the coins frontier: the exact class
     * the refill REFUSES ("replay domain", refill.c:385-391) and the three
     * row-requiring detectors miss — the live 3166989 gap. The new detector now
     * OWNS it: the reconcile dry-run reports the hole height with NO false coin
     * tear, routing it to the replay instead of escalation. Detection pin; the
     * coins-rewinding heal is the same stale_script_replay_tx K2/K7 exercise. */
    {
        struct stm_fixture fx;
        STM_CHECK("K8: setup fixture",
                  setup_fixture(&fx, "k8_below_coins_absent"));
        sqlite3 *db = progress_store_db();
        stage_reducer_frontier_reset_detect_memo_for_testing();

        STM_CHECK("K8: rowless hole at A+2 with coins applied ABOVE it (A+3)",
                  delete_height(db, "script_validate_log", A + 2) &&
                  delete_height(db, "proof_validate_log", A + 2) &&
                  seed_coins_applied(db, A + 3));

        struct stage_reducer_frontier_reconcile_result dry;
        STM_CHECK("K8: reconcile dry-run succeeds",
                  stage_reducer_frontier_reconcile_light_needed(db, &fx.ms,
                                                                &dry));
        STM_CHECK("K8: below-coins rowless hole DETECTED + owned by the replay",
                  dry.repaired &&
                  dry.stale_script_repair_height == A + 2 &&
                  !dry.refused_coin_tear);

        teardown_fixture(&fx);
    }

    /* K9 — ROW-ABSENT hole below the coins frontier whose canonical body is NOT
     * on disk: the detector MATCHES (the class is no longer invisible) but the
     * replay HONESTLY DEFERS (cannot read the body) and the ladder ESCALATES —
     * no fake heal, no crash-loop, no cursor rewind on an unreadable body. */
    {
        struct stm_fixture fx;
        STM_CHECK("K9: setup fixture",
                  setup_fixture(&fx, "k9_absent_no_body"));
        sqlite3 *db = progress_store_db();
        stage_reducer_frontier_reset_detect_memo_for_testing();

        STM_CHECK("K9: rowless hole below coins frontier, no body on disk",
                  delete_height(db, "script_validate_log", A + 2) &&
                  delete_height(db, "proof_validate_log", A + 2) &&
                  seed_coins_applied(db, A + 3));

        struct stage_reducer_frontier_reconcile_result dry;
        STM_CHECK("K9: dry-run DETECTS the rowless hole",
                  stage_reducer_frontier_reconcile_light_needed(db, &fx.ms,
                                                                &dry) &&
                  dry.stale_script_repair_height == A + 2);

        /* APPLY: the detector matched (height set) but HONESTLY DEFERRED — the
         * canonical body is unreadable, so it never rewinds a cursor or writes a
         * verdict for the rowless hole (stale_script_repaired stays false). Any
         * incidental tip_finalize clamp is a separate, legitimate repair; it does
         * NOT fake-fill the hole. */
        struct stage_reducer_frontier_reconcile_result rr;
        STM_CHECK("K9: apply pass succeeds",
                  stage_reducer_frontier_reconcile_light(db, &fx.ms, &rr));
        STM_CHECK("K9: detector matched but honestly DEFERRED (no fake heal)",
                  rr.stale_script_repair_height == A + 2 &&
                  !rr.stale_script_repaired);
        STM_CHECK("K9: rowless hole NOT filled + script/proof cursors not rewound",
                  count_range(db, "script_validate_log", A + 2, A + 3) == 0 &&
                  count_range(db, "proof_validate_log", A + 2, A + 3) == 0 &&
                  cursor_value(db, "script_validate") == A + 4 &&
                  cursor_value(db, "proof_validate") == A + 4);

        /* The ladder still engages its always-terminating rung and stays armed —
         * a deferred rowless hole is handed forward, never a crash-loop. */
        STM_CHECK("K9: ladder engages the terminating rung + stays armed",
                  arm_and_run_rederive(&fx, "k9_absent_no_body", NULL) !=
                      STICKY_RUNG_COUNT &&
                  sticky_escalator_test_armed());

        teardown_fixture(&fx);
    }

    /* ── A1: RUNG-3 REAL — runtime refold-from-anchor as the escalator's
     * TERMINAL rung (fail-safe-architecture.md §1 rung 3 / §4 item 5). The
     * shallower rungs fail-forward on a clean fixture; the deepest rung
     * (STICKY_RUNG_REFOLD_FROM_ANCHOR) ARMS a durable one-shot
     * boot_auto_refold_request + requests a self-respawn (both suppressed
     * in-test) so the fresh boot runs the SAME boot_refold_from_anchor_reset —
     * automatic end-to-end, honestly named ("armed", never a fake "done"). The
     * live coins re-seed + H* climb from the anchor is the copy-prove fixture
     * run (orchestrator-owned); here we pin the ARM and the no-artifact blocker.
     * R1/R2 drive the REAL ladder to the deepest rung. ──────────────────── */

    /* R1 — an anchor artifact is reachable: the rung ARMS a durable refold and
     * HOLDS (PROGRESSING) for the restart to consume it. */
    {
        struct stm_fixture fx;
        STM_CHECK("R1: setup fixture", setup_fixture(&fx, "r1_refold_arm"));
        sqlite3 *db = progress_store_db();
        STM_CHECK("R1: complete a clean store (shallower rungs find nothing)",
                  put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                  put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                  seed_coins_applied(db, A + 4) &&
                  seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        sticky_escalator_set_datadir(fx.dir);
        sticky_escalator_test_set_suppress_refold_restart(true);
        sticky_escalator_test_set_refold_artifact_available(1); /* present */
        stage_reducer_frontier_reset_detect_memo_for_testing();
        boot_auto_refold_clear(fx.dir);

        sticky_escalator_note_stall("r1_force_refold");
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        enum sticky_rung r = STICKY_RUNG_RETRY;
        int64_t last = t0 + 1;
        for (int i = 0; i < 40 && r != STICKY_RUNG_REFOLD_FROM_ANCHOR; i++) {
            last = t0 + 1 + (int64_t)i * 4000;
            r = sticky_escalator_test_drive(0, last);
        }
        STM_CHECK("R1: ladder fails-forward to the DEEPEST refold rung",
                  r == STICKY_RUNG_REFOLD_FROM_ANCHOR);
        /* Entering a rung != dispatching it: one more drive WITHIN the rung
         * window runs the refold action (arms + would self-respawn) and HOLDS. */
        r = sticky_escalator_test_drive(0, last + 10);
        STM_CHECK("R1: refold rung holds after arming",
                  r == STICKY_RUNG_REFOLD_FROM_ANCHOR &&
                  sticky_escalator_test_armed());
        int32_t anchor = -1;
        int count = -1;
        STM_CHECK("R1: rung ARMED a durable refold-from-anchor request",
                  boot_auto_refold_pending(fx.dir) &&
                  boot_auto_refold_status(fx.dir, &anchor, &count) &&
                  anchor == A && count == 0);

        boot_auto_refold_clear(fx.dir);
        teardown_fixture(&fx);
    }

    /* R2 — NO anchor artifact reachable: the rung must NOT arm a doomed refold
     * (boot_refold_from_anchor_reset FATAL-refuses an unproven set). It names
     * exactly the missing clue as a typed blocker (detective doctrine) and the
     * ladder stays armed + auto-terminating — never a crash-loop. */
    {
        struct stm_fixture fx;
        STM_CHECK("R2: setup fixture", setup_fixture(&fx, "r2_no_artifact"));
        sqlite3 *db = progress_store_db();
        STM_CHECK("R2: complete a clean store",
                  put_tip_log(db, A + 2, 1, &fx.hashes[2]) &&
                  put_tip_log(db, A + 3, 1, &fx.hashes[3]) &&
                  seed_coins_applied(db, A + 4) &&
                  seed_cursor(db, "tip_finalize", A + 3));

        sync_monitor_set_context(NULL, NULL, &fx.ms);
        sticky_escalator_test_reset();
        sticky_escalator_set_datadir(fx.dir);
        sticky_escalator_test_set_suppress_refold_restart(true);
        sticky_escalator_test_set_refold_artifact_available(0); /* absent */
        stage_reducer_frontier_reset_detect_memo_for_testing();
        boot_auto_refold_clear(fx.dir);

        sticky_escalator_note_stall("r2_no_artifact");
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        enum sticky_rung r = STICKY_RUNG_RETRY;
        int64_t last = t0 + 1;
        for (int i = 0; i < 40 && r != STICKY_RUNG_REFOLD_FROM_ANCHOR; i++) {
            last = t0 + 1 + (int64_t)i * 4000;
            r = sticky_escalator_test_drive(0, last);
        }
        STM_CHECK("R2: ladder reaches the deepest refold rung",
                  r == STICKY_RUNG_REFOLD_FROM_ANCHOR);
        /* Dispatch the refold rung: no artifact -> names the blocker + FAILED
         * (deepest rung exhausted -> cycles, never arms a doomed refold). */
        (void)sticky_escalator_test_drive(0, last + 10);
        STM_CHECK("R2: no artifact -> typed blocker named, NOT armed",
                  blocker_exists("sticky_escalator.refold_no_anchor_artifact") &&
                  !boot_auto_refold_pending(fx.dir));
        /* Drive past the re-arm cooldown: the ladder re-cycles, never latches a
         * terminal give-up, never crashes. */
        (void)sticky_escalator_test_drive(0, last + 10 +
                                          STICKY_REARM_COOLDOWN_SECS + 5);
        STM_CHECK("R2: ladder stays armed (auto-terminating, no crash-loop)",
                  sticky_escalator_test_armed());

        boot_auto_refold_clear(fx.dir);
        teardown_fixture(&fx);
    }

    reducer_frontier_test_set_compiled_anchor(-1); /* restore production floor */

    printf("stall_totality_matrix: %d failures\n", failures);
    return failures;
}
