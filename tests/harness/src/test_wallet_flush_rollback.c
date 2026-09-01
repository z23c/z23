/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: a wallet flusher that
 * ignores per-writer rc and COMMITs even when a mid-flush write has
 * failed silently persists partial state.  That is the bug class
 * that can make funds unspendable.
 *
 * These tests inject a SQLite trigger that aborts INSERTs to
 * wallet_transactions and then ask the flusher to persist a wallet
 * that contains both keys and a transaction.  The flusher must:
 *   1. return !ok
 *   2. ROLLBACK — no keys AND no tx land on disk
 * We also verify the converse (clean flush commits everything).
 */

#include "test/test_core.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "keys/key.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same baseline schema as test_wallet_persistence_cycle.c — keep in
 * sync with the wallet_* CREATE statements in
 * engine/models/src/database.c SCHEMA[] so this fixture mirrors prod. */
static const char *k_flush_schema =
    "CREATE TABLE wallet_keys ("
    "  pubkey_hash BLOB PRIMARY KEY,"
    "  pubkey BLOB NOT NULL,"
    "  privkey BLOB NOT NULL,"
    "  compressed INTEGER NOT NULL DEFAULT 1,"
    "  created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE wallet_keypool ("
    "  pubkey_hash BLOB PRIMARY KEY,generation INTEGER NOT NULL UNIQUE);"
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
    "  from_me INTEGER NOT NULL DEFAULT 0,fee INTEGER);"
    "CREATE TABLE wallet_watch_only ("
    "  address_hash BLOB PRIMARY KEY,"
    "  address TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE node_state ("
    "  key TEXT PRIMARY KEY,value BLOB);";

/* Trigger that aborts any insert into wallet_transactions — stands
 * in for a real SQLITE_IOERR mid-flush.  The failure surfaces as
 * SQLITE_CONSTRAINT at sqlite3_step(), which is exactly the shape
 * of error the flusher must roll back on. */
static const char *k_fail_tx_trigger =
    "CREATE TRIGGER fail_tx_insert BEFORE INSERT ON wallet_transactions"
    " BEGIN SELECT RAISE(ABORT, 'injected tx-write failure'); END;";

static sqlite3 *open_flush_db(bool install_tx_trigger)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
    if (sqlite3_exec(db, k_flush_schema, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    if (install_tx_trigger &&
        sqlite3_exec(db, k_fail_tx_trigger, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static void make_key(struct privkey *key, struct pubkey *pk, uint8_t seed)
{
    privkey_init(key);
    memset(key->vch, seed, 32);
    key->vch[0] = seed;
    key->vch[1] = (uint8_t)(seed ^ 0xAA);
    key->vch[31] = (uint8_t)(seed + 1);
    key->fValid = true;
    key->fCompressed = true;
    privkey_get_pubkey(key, pk);
}

static struct wallet *alloc_wallet_t(void)
{
    struct wallet *w = zcl_calloc(1, sizeof(struct wallet), "flush_rollback_w");
    if (w) {
        keystore_init(&w->keystore);
        sapling_keystore_init(&w->sapling_keys);
        zcl_mutex_init(&w->cs);
    }
    return w;
}

static void free_wallet_t(struct wallet *w)
{
    if (!w) return;
    keystore_free(&w->keystore);
    free(w);
}

/* Fake-populate one wallet_tx slot so the flusher has something to
 * try to write; the trigger will abort the INSERT. */
static void seed_wallet_tx(struct wallet *w)
{
    struct wallet_tx *wtx = &w->map_wallet[0];
    memset(wtx, 0, sizeof(*wtx));
    transaction_init(&wtx->tx);
    /* A non-zero hash is enough; the trigger aborts before content
     * is touched.  The transaction_serialize call in the wrapper
     * still runs, so the tx must be a validly-initialised struct. */
    for (int i = 0; i < 32; i++) wtx->tx.hash.data[i] = (uint8_t)(0xA0 + i);
    wtx->time_received = 1713000000;
    wtx->from_me = true;
    wtx->used = true;
}

/* Count rows in a named table. */
static int count_rows(sqlite3 *db, const char *table)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (sqlite3_step(s) == SQLITE_ROW)
            n = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    return n;
}

/* ── Test 1: clean flush persists all state ────────────────────── */

static int test_flush_clean_commits_everything(void)
{
    int failures = 0;
    TEST("flush_rollback: clean flush commits keys and tx") {
        unsetenv("ZCL_WALLET_PASSPHRASE");
        sqlite3 *db = open_flush_db(/*install_tx_trigger=*/false);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct wallet *w = alloc_wallet_t();
        ASSERT(w);

        struct privkey k;
        struct pubkey pk;
        make_key(&k, &pk, 0x41);
        ASSERT(keystore_add_key(&w->keystore, &k));

        seed_wallet_tx(w);

        struct zcl_result r = wallet_sqlite_flush_r(&ws, w);
        ASSERT(r.ok);
        ASSERT_EQ(count_rows(db, "wallet_keys"), 1);
        ASSERT_EQ(count_rows(db, "wallet_transactions"), 1);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet_t(w);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Test 2: mid-flush write failure rolls back entire txn ─────── */

static int test_flush_tx_write_failure_rolls_back(void)
{
    int failures = 0;
    TEST("flush_rollback: injected tx-write failure rolls back keys too") {
        unsetenv("ZCL_WALLET_PASSPHRASE");
        sqlite3 *db = open_flush_db(/*install_tx_trigger=*/true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct wallet *w = alloc_wallet_t();
        ASSERT(w);

        /* Two fresh keys that would normally land on disk. */
        struct privkey k0, k1;
        struct pubkey pk0, pk1;
        make_key(&k0, &pk0, 0x51);
        make_key(&k1, &pk1, 0x52);
        ASSERT(keystore_add_key(&w->keystore, &k0));
        ASSERT(keystore_add_key(&w->keystore, &k1));

        /* Seed one tx so the flusher hits the trigger. */
        seed_wallet_tx(w);

        struct zcl_result r = wallet_sqlite_flush_r(&ws, w);
        /* The flusher must surface the failure. */
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_WRITE_FAIL);
        ASSERT(r.message[0] != '\0');

        /* The rollback must have undone BOTH the tx write attempt AND
         * any earlier key writes — otherwise partial state persists
         * and the keystore_count != row_count detector would fire on
         * next boot. */
        ASSERT_EQ(count_rows(db, "wallet_keys"), 0);
        ASSERT_EQ(count_rows(db, "wallet_transactions"), 0);

        /* get_health should show the mismatch between the in-memory
         * keystore (2 keys) and the rolled-back on-disk row count
         * (0) — this is the exact invariant that boot.c STATE F
         * relies on to detect divergence. */
        struct wallet_sqlite_health h =
            wallet_sqlite_get_health(&ws, (int)w->keystore.num_keys);
        ASSERT(h.row_count == 0);
        ASSERT(h.keystore_count == 2);
        ASSERT(h.mismatch);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet_t(w);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Test 3: legacy bool wrapper propagates the rollback ───────── */

static int test_flush_bool_wrapper_returns_false(void)
{
    int failures = 0;
    TEST("flush_rollback: bool wrapper returns false on injected failure") {
        unsetenv("ZCL_WALLET_PASSPHRASE");
        sqlite3 *db = open_flush_db(/*install_tx_trigger=*/true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct wallet *w = alloc_wallet_t();
        ASSERT(w);

        struct privkey k;
        struct pubkey pk;
        make_key(&k, &pk, 0x61);
        ASSERT(keystore_add_key(&w->keystore, &k));

        seed_wallet_tx(w);

        /* The legacy wrapper used to unconditionally return true even
         * on failure — that's the "silent-error" pattern callers
         * like wallet_controller.c guard on with `if (!...)`. */
        ASSERT(!wallet_sqlite_flush(&ws, w));

        ASSERT_EQ(count_rows(db, "wallet_keys"), 0);
        ASSERT_EQ(count_rows(db, "wallet_transactions"), 0);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet_t(w);
        PASS();
    } _test_next:;
    return failures;
}

int test_wallet_flush_rollback(void)
{
    int failures = 0;
    failures += test_flush_clean_commits_everything();
    failures += test_flush_tx_write_failure_rolls_back();
    failures += test_flush_bool_wrapper_returns_false();
    return failures;
}
