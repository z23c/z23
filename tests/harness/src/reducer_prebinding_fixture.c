/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Build durable prebinding frontier fixtures for recovery tests. */
#include "test/reducer_prebinding_fixture.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include <stdio.h>
#include <string.h>

bool rf_fixture_build_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor ("
        "  name TEXT PRIMARY KEY,"
        "  cursor INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_reducer_frontier] schema: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}
bool rf_fixture_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET "
            "cursor=excluded.cursor, updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}
bool rf_fixture_put_utxo_delta(sqlite3 *db, int32_t h,
                           const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool rf_prebinding_schema(sqlite3 *db)
{
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,parent_hash BLOB,"
        "admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,ok INTEGER NOT NULL,"
        "fail_reason TEXT,validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS script_validate_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "tx_count INTEGER NOT NULL,input_count INTEGER NOT NULL,"
        "first_failure_txid BLOB,first_failure_vin INTEGER,"
        "first_failure_serror INTEGER,validated_at INTEGER NOT NULL,"
        "block_hash BLOB,source_epoch_digest BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log("
        "height INTEGER PRIMARY KEY,source TEXT NOT NULL,ok INTEGER NOT NULL,"
        "persisted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "sapling_spends_total INTEGER NOT NULL,"
        "sapling_outputs_total INTEGER NOT NULL,"
        "sprout_joinsplits_total INTEGER NOT NULL,block_hash BLOB,"
        "source_epoch_digest BLOB,first_failure_txid BLOB,"
        "first_failure_proof_type TEXT,validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "spent_count INTEGER NOT NULL,added_count INTEGER NOT NULL,"
        "total_value_delta INTEGER NOT NULL,first_failure_kind TEXT,"
        "first_failure_detail BLOB,applied_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta("
        "height INTEGER PRIMARY KEY,branch_hash BLOB NOT NULL,"
        "spent_blob BLOB NOT NULL,added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "work_delta_high INTEGER NOT NULL,work_delta_low INTEGER NOT NULL,"
        "utxo_size_after INTEGER NOT NULL,reorg_depth INTEGER NOT NULL,"
        "finalized_at INTEGER NOT NULL,tip_hash BLOB);", NULL, NULL, NULL) == SQLITE_OK;
}


bool rf_fixture_insert(sqlite3 *db, const char *sql, int height, const uint8_t hash[32])
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int(stmt, 1, height) == SQLITE_OK;
    if (hash) ok = ok && sqlite3_bind_blob(stmt, 2, hash, 32, SQLITE_STATIC) == SQLITE_OK;
    ok = ok && sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    return sqlite3_finalize(stmt) == SQLITE_OK && ok;
}
static bool rf_prebinding_anchor(sqlite3 *db, const uint8_t hash[32])
{
    return rf_fixture_insert(db, "INSERT INTO tip_finalize_log(height,status,ok,work_delta_high,"
        "work_delta_low,utxo_size_after,reorg_depth,finalized_at,tip_hash) "
        "VALUES(?1,'anchor',1,0,0,0,0,0,?2)", 1, hash);
}
static bool rf_prebinding_rows(sqlite3 *db, const uint8_t served[32], const uint8_t coins[32])
{
    return rf_fixture_set_cursor(db, "validate_headers", 3) && rf_fixture_set_cursor(db, "script_validate", 2) &&
        rf_fixture_set_cursor(db, "body_persist", 2) && rf_fixture_set_cursor(db, "proof_validate", 2) &&
        rf_fixture_set_cursor(db, "utxo_apply", 3) && rf_fixture_set_cursor(db, "tip_finalize", 1) &&
        rf_fixture_insert(db, "INSERT INTO validate_headers_log(height,hash,ok,validated_at) "
            "VALUES(?1,?2,1,0)", 2, coins) &&
        rf_fixture_insert(db, "INSERT INTO utxo_apply_log(height,status,ok,spent_count,added_count,"
            "total_value_delta,applied_at) VALUES(?1,'verified',1,0,0,0,0)", 2, NULL) &&
        rf_fixture_put_utxo_delta(db, 2, coins) && rf_prebinding_anchor(db, served);
}
/* Seed a private prebinding fixture: served H*=1, proven coins through 2. */
bool test_reducer_prebinding_seed(sqlite3 *db, struct block_index *genesis, const uint8_t served[32], const uint8_t coins[32]);
bool test_reducer_prebinding_seed(sqlite3 *db, struct block_index *genesis, const uint8_t served[32], const uint8_t coins[32])
{
    const uint8_t one = 1, txid[32] = {1}; uint8_t applied[8] = {3};
    if (!db || !genesis || !served || !coins || !rf_prebinding_schema(db) || !rf_fixture_build_schema(db) || !coins_kv_ensure_schema(db)) return false;
    reducer_frontier_provable_tip_reset(); tip_finalize_stage_test_reset();
    tip_finalize_stage_warm_authority_caches(db, genesis, "prebinding-fixture");
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = coins_kv_add(db, txid, 0, 1, 1, false, NULL, 0) &&
        progress_meta_set_in_tx(db, COINS_APPLIED_HEIGHT_KEY, applied, sizeof(applied)) &&
        progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1) &&
        rf_prebinding_rows(db, served, coins);
    if (sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) return false;
    return ok;
}

bool test_reducer_prebinding_anchor(sqlite3 *db, const uint8_t *hash);
bool test_reducer_prebinding_anchor(sqlite3 *db, const uint8_t *hash)
{
    if (sqlite3_exec(db, "DELETE FROM tip_finalize_log WHERE height=1", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    return !hash || rf_prebinding_anchor(db, hash);
}
