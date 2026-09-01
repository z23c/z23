/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Error-path tests for wallet_sqlite_open_r.  Every error code that
 * the open path can produce must carry a distinct non-empty message.
 * Plan: WALLET_PERSISTENCE_PLAN.md §8.1 / AGENT_2_WALLET_SQLITE.md D5. */

#include "test/test_core.h"
#include "wallet/wallet_sqlite.h"
#include "util/result.h"
#include <string.h>

static int test_null_sqlite_returns_null_arg(void)
{
    int failures = 0;
    TEST("wallet_sqlite_open_r: NULL db → WSQL_NULL_ARG with non-empty message") {
        struct wallet_sqlite ws;
        memset(&ws, 0, sizeof(ws));
        struct zcl_result r = wallet_sqlite_open_r(&ws, NULL);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_NULL_ARG);
        ASSERT(r.message[0] != '\0');
        ASSERT(r.source_file != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_null_ws_returns_null_arg(void)
{
    int failures = 0;
    TEST("wallet_sqlite_open_r: NULL ws → WSQL_NULL_ARG") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        struct zcl_result r = wallet_sqlite_open_r(NULL, db);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_NULL_ARG);
        ASSERT(r.message[0] != '\0');
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_missing_watch_only_is_schema_missing(void)
{
    int failures = 0;
    TEST("wallet_sqlite_open_r: missing wallet_watch_only → WSQL_SCHEMA_MISSING") {
        /* This is the exact failure mode that produced the 0.4 ZCL
         * loss: pre-existing DB that never learned about the newer
         * wallet_watch_only table.  The open path must now name the
         * missing table explicitly rather than returning a bare
         * false with no breadcrumbs. */
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        /* Create every wallet table EXCEPT wallet_watch_only. */
        const char *partial =
            "CREATE TABLE wallet_keys ("
            "  pubkey_hash BLOB PRIMARY KEY,"
            "  pubkey BLOB NOT NULL,"
            "  privkey BLOB NOT NULL,"
            "  compressed INTEGER NOT NULL DEFAULT 1,"
            "  created_at INTEGER NOT NULL DEFAULT 0);"
            "CREATE TABLE wallet_keypool ("
            "  pubkey_hash BLOB PRIMARY KEY,"
            "  generation INTEGER NOT NULL UNIQUE);"
            "CREATE TABLE wallet_sapling_keys ("
            "  ivk BLOB PRIMARY KEY,xsk BLOB NOT NULL,xfvk BLOB NOT NULL,"
            "  diversifier BLOB NOT NULL,pk_d BLOB NOT NULL,"
            "  child_index INTEGER NOT NULL,"
            "  address TEXT NOT NULL DEFAULT '');"
            "CREATE TABLE wallet_scripts ("
            "  script_hash BLOB PRIMARY KEY,"
            "  redeem_script BLOB NOT NULL);"
            "CREATE TABLE wallet_seed ("
            "  id INTEGER PRIMARY KEY CHECK(id=1),"
            "  seed BLOB NOT NULL,next_child INTEGER NOT NULL DEFAULT 0);"
            "CREATE TABLE wallet_transactions ("
            "  txid BLOB PRIMARY KEY,raw_tx BLOB NOT NULL,"
            "  block_hash BLOB,block_height INTEGER,"
            "  time_received INTEGER NOT NULL,"
            "  from_me INTEGER NOT NULL DEFAULT 0,fee INTEGER);";
        ASSERT(sqlite3_exec(db, partial, NULL, NULL, NULL) == SQLITE_OK);

        struct wallet_sqlite ws;
        memset(&ws, 0, sizeof(ws));
        struct zcl_result r = wallet_sqlite_open_r(&ws, db);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_SCHEMA_MISSING);
        ASSERT(strstr(r.message, "wallet_watch_only") != NULL);

        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_missing_wallet_keys_is_schema_missing(void)
{
    int failures = 0;
    TEST("wallet_sqlite_open_r: missing wallet_keys → WSQL_SCHEMA_MISSING naming wallet_keys") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        /* Totally empty DB — not even wallet_keys exists. */
        struct wallet_sqlite ws;
        memset(&ws, 0, sizeof(ws));
        struct zcl_result r = wallet_sqlite_open_r(&ws, db);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_SCHEMA_MISSING);
        /* Must identify which table is missing. */
        ASSERT(strstr(r.message, "wallet_keys") != NULL);
        ASSERT(r.source_file != NULL);
        ASSERT(r.source_line > 0);

        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_closed_db_prepare_fail(void)
{
    int failures = 0;
    TEST("wallet_sqlite_open_r: closed db handle → prepare failure, non-empty msg") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        sqlite3_close(db);
        /* Reusing a closed handle is undefined by SQLite, but in
         * practice sqlite3_prepare_v2 misbehaves safely.  What we
         * require is that we don't silently succeed. */
        struct wallet_sqlite ws;
        memset(&ws, 0, sizeof(ws));
        struct zcl_result r = wallet_sqlite_open_r(&ws, db);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_PREPARE_FAIL ||
               r.code == WSQL_SCHEMA_MISSING);
        ASSERT(r.message[0] != '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_self_test_on_unopened_ws(void)
{
    int failures = 0;
    TEST("wallet_sqlite_self_test: unopened ws → WSQL_DB_NOT_OPEN") {
        struct wallet_sqlite ws;
        memset(&ws, 0, sizeof(ws));
        struct zcl_result r = wallet_sqlite_self_test(&ws);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_DB_NOT_OPEN);
        ASSERT(r.message[0] != '\0');
        PASS();
    } _test_next:;
    return failures;
}

int test_wallet_sqlite_open_errors(void)
{
    int failures = 0;
    failures += test_null_sqlite_returns_null_arg();
    failures += test_null_ws_returns_null_arg();
    failures += test_missing_watch_only_is_schema_missing();
    failures += test_missing_wallet_keys_is_schema_missing();
    failures += test_closed_db_prepare_fail();
    failures += test_self_test_on_unopened_ws();
    return failures;
}
