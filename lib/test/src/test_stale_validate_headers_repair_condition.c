/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "models/database.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "net/download.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

#define SVHR_CHECK(name, expr) do { \
    printf("stale_validate_headers_repair: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_stale_validate_headers_repair(void);
void stale_validate_headers_repair_test_reset(void);
int stale_validate_headers_repair_test_remedy_calls(void);
void stale_validate_headers_repair_test_clear_backoff(void);
void stale_validate_headers_repair_test_set_hstar_override(int height);
int stale_validate_headers_repair_test_repair_target(sqlite3 *db);
void reducer_frontier_test_set_compiled_anchor(int32_t height);
void stale_validate_headers_repair_test_set_peer_count(int n);
void stale_validate_headers_repair_test_set_node_db(struct node_db *ndb);
int stale_validate_headers_repair_test_quarantine_escalations(void);

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
            "fail_reason TEXT, validated_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, source TEXT NOT NULL,"
            "bytes INTEGER NOT NULL DEFAULT 0, fetched_at INTEGER NOT NULL,"
            "ok INTEGER NOT NULL, fail_reason TEXT)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER,"
            "persisted_at INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER, "
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER,"
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)");
}

/* Stamp coins_kv proven-authority (the 3 rungs coins_kv_is_proven_authority
 * checks) so compute_hstar honors the (overridden) anchor floor. The new
 * phantom-anchor guard in compute_hstar drops the floor to 0 when the store is
 * NOT proven authority — correct for a fresh datadir, but these condition
 * fixtures model a seeded datadir whose H* sits at the overridden anchor. Raw
 * SQL (this TU has no coins_kv.h); progress_meta is created by the store open.
 * Returns false on any SQLite error. */
static bool seed_proven_authority(sqlite3 *db, int64_t applied_height)
{
    if (!exec_sql(db, "CREATE TABLE IF NOT EXISTS progress_meta "
                      "(key TEXT PRIMARY KEY, value BLOB)") ||
        !exec_sql(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB)") ||
        !exec_sql(db, "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00')"))
        return false;
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, ah, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
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

static bool seed_cursors(sqlite3 *db, int validate_cursor,
                         int downstream_cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    static const char *const names[] = {
        "validate_headers",
        "body_fetch",
        "body_persist",
        "script_validate",
        "proof_validate",
        "utxo_apply",
        "tip_finalize",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_text(st, 1, names[i], -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 2, i == 0 ? validate_cursor : downstream_cursor);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
    }
    sqlite3_finalize(st);
    return true;
}

static bool seed_poison_rows(sqlite3 *db, int height, const char *vh_reason,
                             int vh_ok)
{
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),%d,%s,1);"
        "INSERT OR REPLACE INTO body_fetch_log"
        "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
        "VALUES(%d,zeroblob(32),'skipped_invalid',0,1,0,"
        "'header_validation_failed');"
        "INSERT OR REPLACE INTO body_persist_log"
        "(height,source,ok,persisted_at) "
        "VALUES(%d,'upstream_failed',0,1);"
        "INSERT OR REPLACE INTO script_validate_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO utxo_apply_delta"
        "(height,branch_hash,spent_blob,added_blob) "
        "VALUES(%d,zeroblob(32),X'',X'');"
        "INSERT OR REPLACE INTO tip_finalize_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);",
        height, vh_ok, vh_reason ? vh_reason : "NULL",
        height, height, height, height, height, height, height);
    return exec_sql(db, sql);
}

/* Seed an ok=1 tip_finalize_log row at `height` so active_chain_height
 * (MAX(height) FROM tip_finalize_log WHERE ok=1) reads >= height — the
 * un-fakeable forward-tip signal the W2 witness keys on. */
static bool seed_finalized_tip(sqlite3 *db, int height)
{
    char sql[256];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO tip_finalize_log(height,status,ok) "
        "VALUES(%d,'finalized',1)", height);
    return exec_sql(db, sql);
}

static bool seed_reducer_success(sqlite3 *db, int height)
{
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO header_admit_log"
        "(height,hash,parent_hash,admitted_at) "
        "VALUES(%d,zeroblob(32),zeroblob(32),1);"
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),1,NULL,1);"
        "INSERT OR REPLACE INTO body_persist_log"
        "(height,source,ok,persisted_at) VALUES(%d,'test',1,1);"
        "INSERT OR REPLACE INTO script_validate_log"
        "(height,status,ok,block_hash) "
        "VALUES(%d,'verified',1,zeroblob(32));"
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok,block_hash) "
        "VALUES(%d,'verified',1,zeroblob(32));"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height,status,ok) VALUES(%d,'verified',1);"
        "INSERT OR REPLACE INTO utxo_apply_delta"
        "(height,branch_hash,spent_blob,added_blob) "
        "VALUES(%d,zeroblob(32),X'',X'');"
        "INSERT OR REPLACE INTO tip_finalize_log"
        "(height,status,ok) VALUES(%d,'finalized',1);",
        height, height, height, height, height, height, height, height);
    return exec_sql(db, sql);
}

static int cursor_for(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int out = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

static bool row_exists(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static bool validate_ok_row_exists(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok FROM validate_headers_log WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW)
        ok = sqlite3_column_int(st, 0) == 1;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_repair_header_hash(sqlite3 *db, int height,
                                    struct uint256 *out_hash)
{
    struct block_header h;
    block_header_init(&h);
    h.nVersion = 4;
    h.hashPrevBlock.data[0] = (uint8_t)(height - 1);
    h.hashPrevBlock.data[1] = 0xA7;
    h.hashMerkleRoot.data[0] = (uint8_t)height;
    h.hashMerkleRoot.data[1] = 0xB8;
    h.hashFinalSaplingRoot.data[0] = (uint8_t)height;
    h.hashFinalSaplingRoot.data[1] = 0xC9;
    h.nTime = 1700000000u + (uint32_t)height;
    h.nBits = 0x1f07ffff;
    h.nNonce.data[0] = (uint8_t)height;
    h.nNonce.data[1] = 0xDA;
    h.nSolutionSize = 32;
    for (size_t i = 0; i < h.nSolutionSize; i++)
        h.nSolution[i] = (uint8_t)(height + (int)i);

    struct uint256 hash;
    block_header_get_hash(&h, &hash);
    if (out_hash)
        *out_hash = hash;
    return stage_repair_header_solution_save(db, height, &hash, &h);
}

static bool seed_repair_header(sqlite3 *db, int height)
{
    return seed_repair_header_hash(db, height, NULL);
}

/* Open an in-memory node_db with a `blocks` table holding ONE poisoned row
 * keyed by `canon` — arbitrary header fields that do NOT hash-bind to `canon`,
 * so the runtime quarantine's block_row_verify() returns HASH_BIND_MISMATCH and
 * authorizes the purge. Returns false on any SQLite error. */
static bool seed_poisoned_node_db(struct node_db *ndb, const struct uint256 *canon)
{
    memset(ndb, 0, sizeof(*ndb));
    if (sqlite3_open(":memory:", &ndb->db) != SQLITE_OK)
        return false;
    ndb->open = true;
    if (sqlite3_exec(ndb->db,
            "CREATE TABLE blocks("
            "hash BLOB PRIMARY KEY,height INTEGER NOT NULL,"
            "prev_hash BLOB NOT NULL,version INTEGER NOT NULL,"
            "merkle_root BLOB NOT NULL,time INTEGER NOT NULL,"
            "bits INTEGER NOT NULL,nonce BLOB NOT NULL,"
            "solution BLOB NOT NULL,chain_work BLOB NOT NULL,"
            "status INTEGER NOT NULL DEFAULT 0,"
            "file_num INTEGER,data_pos INTEGER,undo_pos INTEGER,"
            "num_tx INTEGER NOT NULL DEFAULT 0,"
            "sapling_root BLOB,sprout_root BLOB,"
            "sapling_value INTEGER DEFAULT 0,"
            "sprout_value INTEGER DEFAULT 0)",
            NULL, NULL, NULL) != SQLITE_OK)
        return false;

    uint8_t z32[32] = {0}, m32[32], n32[32], sol[32];
    memset(m32, 0x22, sizeof(m32));   /* arbitrary merkle → header hash != canon */
    memset(n32, 0x33, sizeof(n32));
    memset(sol, 0x11, sizeof(sol));

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,"
            "time,bits,nonce,solution,chain_work,status,file_num,data_pos,"
            "undo_pos,num_tx,sapling_root,sprout_root,sapling_value,"
            "sprout_value) VALUES(?,2,?,4,?,12345,?,?,?,?,3,0,0,0,1,?,?,0,0)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_blob(s, 1, canon->data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 2, z32, 32, SQLITE_TRANSIENT);          /* prev_hash */
    sqlite3_bind_blob(s, 3, m32, 32, SQLITE_TRANSIENT);          /* merkle_root */
    sqlite3_bind_int64(s, 4, 0x1f07ffff);                        /* bits */
    sqlite3_bind_blob(s, 5, n32, 32, SQLITE_TRANSIENT);          /* nonce */
    sqlite3_bind_blob(s, 6, sol, 32, SQLITE_TRANSIENT);          /* solution */
    sqlite3_bind_blob(s, 7, z32, 32, SQLITE_TRANSIENT);          /* chain_work */
    sqlite3_bind_blob(s, 8, z32, 32, SQLITE_TRANSIENT);          /* sapling_root */
    sqlite3_bind_blob(s, 9, z32, 32, SQLITE_TRANSIENT);          /* sprout_root */
    bool ok = (sqlite3_step(s) == SQLITE_DONE);
    sqlite3_finalize(s);
    return ok;
}

static int node_db_block_count(struct node_db *ndb)
{
    if (!ndb->db)
        return -1;
    sqlite3_stmt *c = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT COUNT(*) FROM blocks",
                           -1, &c, NULL) != SQLITE_OK || !c)
        return -1;
    int n = -1;
    if (sqlite3_step(c) == SQLITE_ROW)
        n = sqlite3_column_int(c, 0);
    sqlite3_finalize(c);
    return n;
}

static void setup_main_state(struct main_state *ms,
                             struct block_index blocks[2],
                             struct uint256 hashes[2])
{
    main_state_init(ms);
    for (int i = 0; i < 2; i++) {
        block_index_init(&blocks[i]);
        memset(&hashes[i], 0, sizeof(hashes[i]));
        hashes[i].data[0] = (uint8_t)i;
        hashes[i].data[1] = 0xA7;
        blocks[i].phashBlock = &hashes[i];
        blocks[i].nHeight = i;
        blocks[i].nStatus = BLOCK_VALID_TREE;
        if (i > 0)
            blocks[i].pprev = &blocks[i - 1];
    }
    active_chain_move_window_tip(&ms->chain_active, &blocks[1]);
    ms->pindex_best_header = &blocks[1];
}


/* Copy the active header_repair_no_source blocker, if any. */
static bool svhr_no_source_blocker(struct blocker_snapshot *out)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "header_repair_no_source") == 0) {
            *out = snaps[i];
            return true;
        }
    }
    return false;
}

static bool setup_condition_case(const char *tag, char *dir, size_t dir_n,
                                 struct main_state *ms,
                                 struct block_index blocks[2],
                                 struct uint256 hashes[2])
{
    condition_engine_reset_for_testing();
    stale_validate_headers_repair_test_reset();
    reducer_frontier_test_set_compiled_anchor(1);
    test_make_tmpdir(dir, dir_n, "stale_vh_repair", tag);
    if (!progress_store_open(dir))
        return false;
    setup_main_state(ms, blocks, hashes);
    condition_engine_set_main_state(ms);
    register_stale_validate_headers_repair();
    /* Anchor floor was overridden to 1 above. applied_height is the NEXT
     * height, so coverage through the overridden anchor is represented by 2. */
    return seed_schema(progress_store_db()) &&
           seed_proven_authority(progress_store_db(), 2);
}

static void teardown_condition_case(const char *dir, struct main_state *ms)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    condition_engine_set_main_state(NULL);
    main_state_free(ms);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    reducer_frontier_test_set_compiled_anchor(-1);
    condition_engine_reset_for_testing();
}

static bool svhr_queue_has_exact(struct download_manager *dm, int height,
                                 const struct uint256 *hash)
{
    return dm && hash && dm->queue_len == 1 &&
           dm->queue_heights[0] == height &&
           uint256_eq(&dm->queue[0], hash);
}

int test_stale_validate_headers_repair_condition(void)
{
    printf("\n=== stale_validate_headers_repair condition tests ===\n");
    int failures = 0;

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("downstream", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(db, 2, "NULL", 1);

        condition_engine_tick();

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        /* W2: the witness is now H*-ONLY. The rewind deleted the downstream
         * poison + rewound cursors but did NOT advance the reducer frontier,
         * so the
         * condition stays ACTIVE (was ==0 under the old poison-gone witness
         * shortcut — this flip IS the regression proof). */
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && cursor_for(db, "validate_headers") == 5;
        ok = ok && cursor_for(db, "body_fetch") == 2;
        ok = ok && validate_ok_row_exists(db, 2);
        ok = ok && !row_exists(db, "body_fetch_log", 2);
        /* tip_finalize_log rows MUST survive a downstream rewind — doctrine
         * forbids deleting them. The cursor is rewound; the (ok=0) row stays. */
        ok = ok && row_exists(db, "tip_finalize_log", 2);
        SVHR_CHECK("stale downstream poison rewinds downstream, preserves "
                   "tip_finalize_log, stays active until H* advances", ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("solutionless_no_header", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);

        condition_engine_tick();

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && cursor_for(db, "validate_headers") == 5;
        ok = ok && cursor_for(db, "body_fetch") == 5;
        ok = ok && row_exists(db, "validate_headers_log", 2);
        ok = ok && row_exists(db, "body_fetch_log", 2);
        SVHR_CHECK("solutionless poison without repair header stays active", ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("solutionless_probe_fail_refetch",
                                       dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        blocks[1].nStatus |= BLOCK_HAVE_DATA;
        ok = ok && seed_cursors(db, 5, 5);
        stale_validate_headers_repair_test_set_hstar_override(0);
        ok = ok && seed_poison_rows(
            db, 1, "'no-header-solution-backfill-required'", 0);

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "stale_validate_headers_repair", &snap);

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        ok = ok && got && snap.last_outcome == COND_REMEDY_SKIP;
        ok = ok && (blocks[1].nStatus & BLOCK_HAVE_DATA) == 0;
        ok = ok && condition_engine_get_active_count() == 1;
        SVHR_CHECK("header-probe failure falls back to P2P refetch instead "
                   "of failed remedy",
                   ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("solutionless_with_header", dir,
                                       sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);
        ok = ok && seed_repair_header(db, 2);

        condition_engine_tick();

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        /* NON-DESTRUCTIVE defer: when the repair header is available, the remedy
         * no longer poison_rewinds a SOLUTIONLESS frontier. validate_headers
         * self-heals the ok=0 row forward via recheck_failed_rows (060a5cb4c),
         * so the remedy returns SKIP and PRESERVES all forward progress: the
         * validate_headers + downstream cursors are NOT rewound and the log rows
         * survive. The condition stays ACTIVE because H* did NOT advance;
         * the honest reducer-frontier
         * witness governs the clear. A destructive rewind here would delete the
         * forward validate work and re-starve the recheck — the churn that
         * produced the 5x-unwitnessed → operator_needed loop. */
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && cursor_for(db, "validate_headers") == 5;
        ok = ok && cursor_for(db, "body_fetch") == 5;
        ok = ok && row_exists(db, "validate_headers_log", 2);
        ok = ok && row_exists(db, "body_fetch_log", 2);
        ok = ok && row_exists(db, "tip_finalize_log", 2);
        SVHR_CHECK("solutionless poison WITH repair header defers to "
                   "non-destructive recheck (no rewind, progress preserved, "
                   "stays active until H* advances)",
                   ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("hash_mismatch", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'header-source-hash-mismatch'", 0);

        condition_engine_tick();

        ok = ok && stage_repair_header_solution_poison_mode(
                         db, 2) ==
                     STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH;
        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && cursor_for(db, "validate_headers") == 5;
        ok = ok && cursor_for(db, "body_fetch") == 5;
        ok = ok && row_exists(db, "validate_headers_log", 2);
        ok = ok && row_exists(db, "body_fetch_log", 2);
        SVHR_CHECK("header-source hash mismatch activates validate-header "
                   "repair without destructive rewind",
                   ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[3];
        struct uint256 hashes[3];
        struct uint256 repair_hash = {0};
        bool ok = setup_condition_case("hash_mismatch_correct_header_pinned",
                                       dir, sizeof(dir), &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'header-source-hash-mismatch'", 0);
        ok = ok && seed_repair_header_hash(db, 2, &repair_hash);

        block_index_init(&blocks[2]);
        hashes[2] = repair_hash;
        blocks[2].phashBlock = &hashes[2];
        blocks[2].nHeight = 2;
        blocks[2].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        blocks[2].pprev = &blocks[1];
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &blocks[2]);
        ms.pindex_best_header = &blocks[2];

        for (int i = 0; i < 5; i++) {
            stale_validate_headers_repair_test_clear_backoff();
            condition_engine_tick();
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "stale_validate_headers_repair", &snap);

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 5;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && condition_engine_get_unresolved_count() == 1;
        ok = ok && got && snap.attempts >= 5;
        ok = ok && got && snap.operator_needed_emitted;
        ok = ok && row_exists(db, "validate_headers_log", 2);
        SVHR_CHECK("correct repair header with pinned H* remains diagnosable "
                   "and pages",
                   ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("served_above_hstar", dir,
                                       sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 9, 9);
        ok = ok && seed_poison_rows(
            db, 2, "'header-source-hash-mismatch'", 0);
        ok = ok && seed_finalized_tip(db, 8);

        condition_engine_tick();

        ok = ok && active_chain_height(&ms.chain_active) == 8;
        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && row_exists(db, "tip_finalize_log", 8);
        ok = ok && row_exists(db, "tip_finalize_log", 2);
        SVHR_CHECK("served tip above H* does not hide or witness-clear the "
                   "repairable validate frontier",
                   ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("scan_below_hstar", dir,
                                       sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 10, 1);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);
        ok = ok && seed_repair_header(db, 2);
        stale_validate_headers_repair_test_set_hstar_override(8);

        ok = ok && stale_validate_headers_repair_test_repair_target(db) == 2;
        condition_engine_tick();

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && cursor_for(db, "validate_headers") == 10;
        ok = ok && cursor_for(db, "body_fetch") == 1;
        ok = ok && row_exists(db, "validate_headers_log", 2);
        ok = ok && row_exists(db, "body_fetch_log", 2);
        SVHR_CHECK("repairable validate scan below H* is targeted before "
                   "H*+1 and does not self-clear while poison remains",
                   ok);
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("invalid", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(db, 2, "'invalid-solution'", 0);

        condition_engine_tick();

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 0;
        ok = ok && cursor_for(db, "validate_headers") == 5;
        ok = ok && cursor_for(db, "body_fetch") == 5;
        ok = ok && row_exists(db, "body_fetch_log", 2);
        SVHR_CHECK("consensus-invalid skip is not repaired", ok);
        teardown_condition_case(dir, &ms);
    }

    /* ── W2 NEW1: a non-advancing remedy escalates to EV_OPERATOR_NEEDED ──
     * Model a frontier that never advances: the pipeline keeps re-poisoning it
     * (solutionless) and the remedy keeps running but H* never moves. Under
     * the honest witness this accrues attempts to max_attempts=5
     * and pages the operator (the Law-7 lie is ended) — REGARDLESS of whether
     * the remedy was the (now non-destructive) SKIP-defer or a destructive
     * rewind: every due remedy increments the attempt counter (condition.c),
     * and a witness that never sees forward tip movement never clears it.
     *
     * We re-seed the solutionless poison + a repair header before each tick
     * (the pipeline regenerates the poison live) and clear the wall-clock
     * backoff between ticks (no injectable clock). The tip is held frozen at
     * 1 (target=2), so the witness stays false the whole time. With canon
     * unavailable here (height 2 is not on the seeded 2-block chain) detect
     * does not deactivate, so the remedy runs each tick and accrues attempts. */
    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("escalation", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);

        for (int i = 0; i < 5; i++) {
            /* Pipeline re-poisons the frontier; repair header stays available
             * so the remedy runs the rewind (no network probe). */
            ok = ok && seed_poison_rows(
                db, 2, "'no-header-solution-backfill-required'", 0);
            ok = ok && seed_repair_header(db, 2);
            stale_validate_headers_repair_test_clear_backoff();
            condition_engine_tick();
        }

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "stale_validate_headers_repair", &snap);

        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 5;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && condition_engine_get_unresolved_count() == 1;
        ok = ok && got && snap.attempts >= 5;
        ok = ok && got && snap.operator_needed_emitted;
        SVHR_CHECK("non-advancing remedy escalates to EV_OPERATOR_NEEDED "
                   "(witness never lies cleared)", ok);
        teardown_condition_case(dir, &ms);
    }

    /* ── W2 NEW2: a remedy that ADVANCES H* clears ───────────────────────
     * The honest witness's sole success predicate is reducer-frontier
     * movement. After the remedy, we publish a full success-checked reducer
     * row at target; the next tick witnesses H* >= target, clears the
     * condition, and does NOT re-run the remedy. */
    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("happy_clear", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);
        ok = ok && seed_repair_header(db, 2);

        /* Tick 1: remedy runs, H* frozen → witness false → still active. */
        condition_engine_tick();
        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;

        /* Publish a real success-checked reducer row at target=2 → H* moves. */
        ok = ok && seed_reducer_success(db, 2);

        /* Tick 2: witness now true (H*>=target) → cleared,
         * remedy NOT re-run. Clear backoff so a remedy WOULD run if the
         * witness hadn't cleared — proving the clear, not the backoff. */
        stale_validate_headers_repair_test_clear_backoff();
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
        SVHR_CHECK("forward reducer frontier advance witnesses the clear "
                   "(remedy not re-run)", ok);
        teardown_condition_case(dir, &ms);
    }

    /* ── Lane B3: at ladder EXHAUSTION on a non-advancing validate poison whose
     * durable `blocks` row is itself poisoned, the remedy escalates ONCE to the
     * runtime row quarantine (purging the poisoned row); a SECOND exhaustion at
     * the same height (reached via the first cooldown re-arm) does NOT re-fire —
     * the once-per-height bookkeeping survives the re-arm and there is no delete
     * loop. Faithful end-to-end: a real seeded node_db is injected so the helper
     * genuinely deletes the poisoned row and bumps the runtime counter. ─────── */
    {
        chain_params_select(CHAIN_MAIN);  /* block_row_verify needs cp != NULL */

        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("b3_row_quarantine", dir, sizeof(dir),
                                       &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();

        /* Extend to a 3-block chain so target=2 (H*+1) is ON the active chain
         * and canon = active_chain_at(2) is non-NULL (the escalation needs a
         * frontier hash to address). */
        struct block_index block2;
        struct uint256 hash2;
        block_index_init(&block2);
        memset(&hash2, 0, sizeof(hash2));
        hash2.data[0] = 2;
        hash2.data[1] = 0xA7;
        block2.phashBlock = &hash2;
        block2.nHeight = 2;
        block2.nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        block2.pprev = &blocks[1];
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &block2);
        ms.pindex_best_header = &block2;

        /* Seed the durable poisoned `blocks` row keyed by canon (hash2) and
         * inject the handle; force 0 peers so cure_request_peer_refetch takes
         * the deterministic no-peers branch. */
        struct node_db ndb;
        ok = ok && seed_poisoned_node_db(&ndb, &hash2);
        stale_validate_headers_repair_test_set_node_db(&ndb);
        stale_validate_headers_repair_test_set_peer_count(0);

        /* Solutionless poison at 2, NO repair header → the remedy falls through
         * to the P2P fallback (where the escalation lives) every tick. */
        ok = ok && seed_cursors(db, 5, 5);

        int64_t rq_before = stage_repair_runtime_row_quarantined();

        /* Ticks 1-5: climb to the first exhaustion → escalation fires ONCE. */
        for (int i = 0; i < 5; i++) {
            ok = ok && seed_poison_rows(
                db, 2, "'no-header-solution-backfill-required'", 0);
            stale_validate_headers_repair_test_clear_backoff();
            condition_engine_tick();
        }

        int esc_after_first = stale_validate_headers_repair_test_quarantine_escalations();
        int64_t rq_after_first = stage_repair_runtime_row_quarantined();
        int rows_after_first = node_db_block_count(&ndb);

        ok = ok && esc_after_first == 1;
        ok = ok && (rq_after_first - rq_before) == 1;   /* poisoned row purged */
        ok = ok && rows_after_first == 0;               /* gone from `blocks` */

        /* Ticks 6-10: the first cooldown re-arm (last_cooldown==0) resets the
         * ladder, so a SECOND exhaustion is reached at the SAME height. The
         * once-per-height set (which SURVIVED the re-arm) blocks a re-fire: no
         * new escalation, no second delete. */
        for (int i = 0; i < 5; i++) {
            ok = ok && seed_poison_rows(
                db, 2, "'no-header-solution-backfill-required'", 0);
            stale_validate_headers_repair_test_clear_backoff();
            condition_engine_tick();
        }

        int esc_after_second = stale_validate_headers_repair_test_quarantine_escalations();
        int64_t rq_after_second = stage_repair_runtime_row_quarantined();

        ok = ok && esc_after_second == 1;               /* still exactly once */
        ok = ok && (rq_after_second - rq_before) == 1;  /* no re-delete */

        SVHR_CHECK("B3 exhaustion escalates to runtime row quarantine EXACTLY "
                   "ONCE; second exhaustion at same height does not re-delete "
                   "(bookkeeping survives cooldown re-arm)", ok);

        stale_validate_headers_repair_test_set_node_db(NULL);
        if (ndb.db) sqlite3_close(ndb.db);
        teardown_condition_case(dir, &ms);
    }

    /* ── A refusal must name the cause that actually held ────────────────────
     * cure_request_peer_refetch() returns -1 when the repair target has no
     * best-header authority agreeing with the visible active chain: there is
     * no exact block_index entry or hash to request, so the network was never
     * asked. That
     * -1 used to fall into the caller's `peers <= 0` test and be reported as
     * "no connected peer can serve a P2P getdata re-fetch".
     *
     * Measured on a real wiped-datadir C3 run (2026-08-20, node.log line
     * 126894): "no durable repair header h=3193025 via oracle AND no peers
     * (peers=-1)" while the node was connected to 127.0.0.1:8033 and accepting
     * headers from it for the next four minutes. The fold sat at H*=3,193,024
     * and the blocker sent the recovery ladder looking for peers that were
     * already there.
     *
     * The cases below hold peers at 5 and distinguish usable exact H*+1
     * authority from absent or disagreeing authority. Refusal must NOT claim
     * peer. ───────────────────────────────────────────────────────────────── */
    /* Exact C3 shape: H*+1 is absent from the active window but is a
     * nonfailed child of the visible tip on best-header ancestry. */
    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[3];
        struct uint256 hashes[3];
        struct download_manager dm;
        bool ok = setup_condition_case("hstar_next_best_header_refetch", dir,
                                       sizeof(dir), &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();

        block_index_init(&blocks[2]);
        memset(&hashes[2], 0, sizeof(hashes[2]));
        hashes[2].data[0] = 2;
        hashes[2].data[1] = 0xB8;
        blocks[2].phashBlock = &hashes[2];
        blocks[2].nHeight = 2;
        blocks[2].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        blocks[2].pprev = &blocks[1];
        ms.pindex_best_header = &blocks[2];

        dl_init(&dm);
        sync_monitor_init();
        sync_monitor_set_context(NULL, &dm, &ms);
        stale_validate_headers_repair_test_set_peer_count(5);
        struct zcl_result exact_mismatch =
            sync_monitor_queue_best_header_body(
                2, &hashes[1], "test:stale_validate_exact_mismatch");
        ok = ok && !exact_mismatch.ok && exact_mismatch.code == -6;
        ok = ok && dm.queue_len == 0;
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);

        blocker_clear("header_repair_no_source");
        stale_validate_headers_repair_test_clear_backoff();
        condition_engine_tick();

        struct blocker_snapshot bs;
        ok = ok && !svhr_no_source_blocker(&bs);
        ok = ok && (blocks[2].nStatus & BLOCK_HAVE_DATA) == 0;
        ok = ok && svhr_queue_has_exact(&dm, 2, &hashes[2]);
        ok = ok && condition_engine_get_active_count() == 1;
        SVHR_CHECK("H*+1 best-header child is hash-bound and queued with "
                   "peers, without a false no-source blocker", ok);

        sync_monitor_set_context(NULL, NULL, NULL);
        dl_free(&dm);
        teardown_condition_case(dir, &ms);
    }

    /* A best-header block on a sibling of the visible active tip is not an
     * authority for H*+1. It must remain data-flagged and unqueued. */
    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[3];
        struct uint256 hashes[3];
        struct block_index sibling_parent;
        struct uint256 sibling_hash;
        struct download_manager dm;
        bool ok = setup_condition_case("best_header_parent_disagrees", dir,
                                       sizeof(dir), &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();

        block_index_init(&sibling_parent);
        memset(&sibling_hash, 0, sizeof(sibling_hash));
        sibling_hash.data[0] = 1;
        sibling_hash.data[1] = 0xCC;
        sibling_parent.phashBlock = &sibling_hash;
        sibling_parent.nHeight = 1;
        sibling_parent.nStatus = BLOCK_VALID_TREE;
        sibling_parent.pprev = &blocks[0];
        block_index_init(&blocks[2]);
        memset(&hashes[2], 0, sizeof(hashes[2]));
        hashes[2].data[0] = 2;
        hashes[2].data[1] = 0xCC;
        blocks[2].phashBlock = &hashes[2];
        blocks[2].nHeight = 2;
        blocks[2].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        blocks[2].pprev = &sibling_parent;
        ms.pindex_best_header = &blocks[2];

        dl_init(&dm);
        sync_monitor_init();
        sync_monitor_set_context(NULL, &dm, &ms);
        stale_validate_headers_repair_test_set_peer_count(5);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);

        blocker_clear("header_repair_no_source");
        stale_validate_headers_repair_test_clear_backoff();
        condition_engine_tick();

        struct blocker_snapshot bs;
        ok = ok && svhr_no_source_blocker(&bs);
        ok = ok && (blocks[2].nStatus & BLOCK_HAVE_DATA) != 0;
        ok = ok && dm.queue_len == 0;
        SVHR_CHECK("best-header child whose parent disagrees with the visible "
                   "tip fails closed with zero queue", ok);

        sync_monitor_set_context(NULL, NULL, NULL);
        dl_free(&dm);
        blocker_clear("header_repair_no_source");
        teardown_condition_case(dir, &ms);
    }

    /* Missing visible-parent publication also refuses, even when best-header
     * ancestry itself is well-linked. */
    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[3];
        struct uint256 hashes[3];
        struct download_manager dm;
        bool ok = setup_condition_case("best_header_visible_parent_absent", dir,
                                       sizeof(dir), &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();

        block_index_init(&blocks[2]);
        memset(&hashes[2], 0, sizeof(hashes[2]));
        hashes[2].data[0] = 2;
        hashes[2].data[1] = 0xDD;
        blocks[2].phashBlock = &hashes[2];
        blocks[2].nHeight = 2;
        blocks[2].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        blocks[2].pprev = &blocks[1];
        ms.pindex_best_header = &blocks[2];
        active_chain_free(&ms.chain_active);
        active_chain_init(&ms.chain_active);

        dl_init(&dm);
        sync_monitor_init();
        sync_monitor_set_context(NULL, &dm, &ms);
        stale_validate_headers_repair_test_set_peer_count(5);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);

        blocker_clear("header_repair_no_source");
        stale_validate_headers_repair_test_clear_backoff();
        condition_engine_tick();

        struct blocker_snapshot bs;
        ok = ok && svhr_no_source_blocker(&bs);
        ok = ok && (blocks[2].nStatus & BLOCK_HAVE_DATA) != 0;
        ok = ok && dm.queue_len == 0;
        SVHR_CHECK("missing visible parent fails closed with zero queue", ok);

        sync_monitor_set_context(NULL, NULL, NULL);
        dl_free(&dm);
        blocker_clear("header_repair_no_source");
        teardown_condition_case(dir, &ms);
    }

    {
        char dir[256];
        struct main_state ms;
        struct block_index blocks[2];
        struct uint256 hashes[2];
        bool ok = setup_condition_case("refusal_names_true_cause", dir,
                                       sizeof(dir), &ms, blocks, hashes);
        sqlite3 *db = progress_store_db();

        /* Best-header tip stays at height 1 — target 2 has no ancestor. */
        stale_validate_headers_repair_test_set_peer_count(5);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_poison_rows(
            db, 2, "'no-header-solution-backfill-required'", 0);

        blocker_clear("header_repair_no_source");
        stale_validate_headers_repair_test_clear_backoff();
        condition_engine_tick();

        struct blocker_snapshot bs;
        bool raised = svhr_no_source_blocker(&bs);
        ok = ok && raised;
        /* The lie this regression exists to prevent. */
        ok = ok && raised &&
             strstr(bs.reason, "no connected peer can serve") == NULL;
        /* The cause that actually held, and the peer count that was really
         * there — both readable straight off the blocker. */
        ok = ok && raised &&
             strstr(bs.reason, "no best-header ancestor") != NULL;
        ok = ok && raised && strstr(bs.reason, "5 peer(s) connected") != NULL;

        SVHR_CHECK("missing best-header authority is named as such, not as "
                   "\"no connected peer\", and carries the real peer count",
                   ok);

        blocker_clear("header_repair_no_source");
        teardown_condition_case(dir, &ms);
    }

    return failures;
}
