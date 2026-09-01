/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for watch-only address support: keystore, wallet_is_mine,
 * wallet_is_watch_only, wallet_sqlite persistence. */

#include "test/test_core.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/wallet_sqlite.h"
#include "script/standard.h"
#include "keys/key.h"
#include "support/cleanse.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util/safe_alloc.h"

/* ── keystore_add_watch_only_id ──────────────────────────── */

static int test_add_watch_only_id(void)
{
    int failures = 0;
    TEST("watch-only: add by key_id and have_watch_only") {
        struct basic_keystore *ks = zcl_calloc(1, sizeof(*ks), "test_keystore");
        ASSERT(ks);
        keystore_init(ks);

        struct key_id kid;
        memset(&kid, 0xAB, sizeof(kid));

        ASSERT(!keystore_have_watch_only(ks, &kid));
        ASSERT(keystore_add_watch_only_id(ks, &kid));
        ASSERT(keystore_have_watch_only(ks, &kid));
        ASSERT_EQ(ks->num_watching, (size_t)1);

        keystore_free(ks);
        free(ks);
        PASS();
    } _test_next:;
    return failures;
}

static int test_add_watch_only_id_dedup(void)
{
    int failures = 0;
    TEST("watch-only: add same key_id twice is idempotent") {
        struct basic_keystore *ks = zcl_calloc(1, sizeof(*ks), "test_keystore");
        ASSERT(ks);
        keystore_init(ks);

        struct key_id kid;
        memset(&kid, 0xCD, sizeof(kid));

        ASSERT(keystore_add_watch_only_id(ks, &kid));
        ASSERT(keystore_add_watch_only_id(ks, &kid));
        ASSERT_EQ(ks->num_watching, (size_t)1);

        keystore_free(ks);
        free(ks);
        PASS();
    } _test_next:;
    return failures;
}

static int test_add_watch_only_with_pubkey(void)
{
    int failures = 0;
    TEST("watch-only: add by pubkey, then have_watch_only works") {
        struct basic_keystore *ks = zcl_calloc(1, sizeof(*ks), "test_keystore");
        ASSERT(ks);
        keystore_init(ks);

        struct privkey sk;
        privkey_init(&sk);
        privkey_make_new(&sk, true);
        struct pubkey pk;
        privkey_get_pubkey(&sk, &pk);

        struct key_id kid = pubkey_get_id(&pk);

        ASSERT(keystore_add_watch_only(ks, &pk));
        ASSERT(keystore_have_watch_only(ks, &kid));

        memory_cleanse(sk.vch, 32);
        keystore_free(ks);
        free(ks);
        PASS();
    } _test_next:;
    return failures;
}

static int test_remove_watch_only(void)
{
    int failures = 0;
    TEST("watch-only: remove works") {
        struct basic_keystore *ks = zcl_calloc(1, sizeof(*ks), "test_keystore");
        ASSERT(ks);
        keystore_init(ks);

        struct key_id kid;
        memset(&kid, 0xEF, sizeof(kid));

        ASSERT(keystore_add_watch_only_id(ks, &kid));
        ASSERT(keystore_have_watch_only(ks, &kid));
        ASSERT(keystore_remove_watch_only(ks, &kid));
        ASSERT(!keystore_have_watch_only(ks, &kid));

        keystore_free(ks);
        free(ks);
        PASS();
    } _test_next:;
    return failures;
}

/* ── wallet_is_mine / wallet_is_watch_only ───────────────── */

static int test_wallet_is_mine_watch_only(void)
{
    int failures = 0;
    TEST("watch-only: wallet_is_mine returns true for watch-only output") {
        struct wallet *w = zcl_calloc(1, sizeof(*w), "test_wallet");
        ASSERT(w);
        wallet_init(w);

        struct privkey sk;
        privkey_init(&sk);
        privkey_make_new(&sk, true);
        struct pubkey pk;
        privkey_get_pubkey(&sk, &pk);
        struct key_id kid = pubkey_get_id(&pk);

        keystore_add_watch_only_id(&w->keystore, &kid);

        struct script spk;
        script_init(&spk);
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        dest.id.key = kid;
        script_for_destination(&spk, &dest);

        struct tx_out txout;
        memset(&txout, 0, sizeof(txout));
        txout.value = 100000;
        txout.script_pub_key = spk;

        ASSERT(wallet_is_mine(w, &txout));
        ASSERT(wallet_is_watch_only(w, &txout));

        memory_cleanse(sk.vch, 32);
        wallet_free(w);
        free(w);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wallet_is_watch_only_false_for_full_key(void)
{
    int failures = 0;
    TEST("watch-only: wallet_is_watch_only false when we have private key") {
        struct wallet *w = zcl_calloc(1, sizeof(*w), "test_wallet");
        ASSERT(w);
        wallet_init(w);

        struct privkey sk;
        privkey_init(&sk);
        privkey_make_new(&sk, true);

        keystore_add_key(&w->keystore, &sk);

        struct pubkey pk;
        privkey_get_pubkey(&sk, &pk);
        struct key_id kid = pubkey_get_id(&pk);

        struct script spk;
        script_init(&spk);
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        dest.id.key = kid;
        script_for_destination(&spk, &dest);

        struct tx_out txout;
        memset(&txout, 0, sizeof(txout));
        txout.value = 100000;
        txout.script_pub_key = spk;

        ASSERT(wallet_is_mine(w, &txout));
        ASSERT(!wallet_is_watch_only(w, &txout));

        memory_cleanse(sk.vch, 32);
        wallet_free(w);
        free(w);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wallet_is_mine_false_for_unknown(void)
{
    int failures = 0;
    TEST("watch-only: wallet_is_mine false for unknown address") {
        struct wallet *w = zcl_calloc(1, sizeof(*w), "test_wallet");
        ASSERT(w);
        wallet_init(w);

        struct key_id kid;
        memset(&kid, 0x77, sizeof(kid));

        struct script spk;
        script_init(&spk);
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        dest.id.key = kid;
        script_for_destination(&spk, &dest);

        struct tx_out txout;
        memset(&txout, 0, sizeof(txout));
        txout.value = 100000;
        txout.script_pub_key = spk;

        ASSERT(!wallet_is_mine(w, &txout));
        ASSERT(!wallet_is_watch_only(w, &txout));

        wallet_free(w);
        free(w);
        PASS();
    } _test_next:;
    return failures;
}

/* ── SQLite persistence ──────────────────────────────────── */

static const char *k_schema =
    "CREATE TABLE wallet_watch_only ("
    "  address_hash BLOB PRIMARY KEY,"
    "  address TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE wallet_keys (pubkey_hash BLOB PRIMARY KEY,"
    " pubkey BLOB NOT NULL, privkey BLOB NOT NULL,"
    " compressed INTEGER NOT NULL DEFAULT 1,"
    " created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE wallet_keypool (pubkey_hash BLOB PRIMARY KEY,"
    " generation INTEGER NOT NULL UNIQUE);"
    "CREATE TABLE wallet_transactions (txid BLOB PRIMARY KEY,"
    " raw_tx BLOB NOT NULL, block_hash BLOB,"
    " block_height INTEGER, time_received INTEGER NOT NULL,"
    " from_me INTEGER NOT NULL DEFAULT 0, fee INTEGER);"
    "CREATE TABLE wallet_seed (id INTEGER PRIMARY KEY CHECK(id=1),"
    " seed BLOB NOT NULL, next_child INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE wallet_sapling_keys (ivk BLOB PRIMARY KEY,"
    " xsk BLOB NOT NULL, xfvk BLOB NOT NULL,"
    " diversifier BLOB NOT NULL, pk_d BLOB NOT NULL,"
    " child_index INTEGER NOT NULL, address TEXT NOT NULL DEFAULT '');"
    "CREATE TABLE wallet_scripts (script_hash BLOB PRIMARY KEY,"
    " redeem_script BLOB NOT NULL);"
    "CREATE TABLE node_state (key TEXT PRIMARY KEY, value BLOB);";

static int test_sqlite_round_trip(void)
{
    int failures = 0;
    TEST("watch-only: SQLite write and read round-trips") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(sqlite3_exec(db, k_schema, NULL, NULL, NULL) == SQLITE_OK);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        uint8_t hash1[20], hash2[20];
        memset(hash1, 0x11, 20);
        memset(hash2, 0x22, 20);
        ASSERT(wallet_sqlite_write_watch_only(&ws, hash1, "t1TestAddr111"));
        ASSERT(wallet_sqlite_write_watch_only(&ws, hash2, "t1TestAddr222"));

        struct wallet *w = zcl_calloc(1, sizeof(*w), "test_wallet");
        ASSERT(w);
        wallet_init(w);
        ASSERT(wallet_sqlite_read_watch_only(&ws, w));

        struct key_id kid1, kid2, kid_missing;
        memcpy(kid1.id.data, hash1, 20);
        memcpy(kid2.id.data, hash2, 20);
        memset(kid_missing.id.data, 0x33, 20);

        ASSERT(keystore_have_watch_only(&w->keystore, &kid1));
        ASSERT(keystore_have_watch_only(&w->keystore, &kid2));
        ASSERT(!keystore_have_watch_only(&w->keystore, &kid_missing));
        ASSERT_EQ(w->keystore.num_watching, (size_t)2);

        wallet_free(w);
        free(w);
        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sqlite_overwrite(void)
{
    int failures = 0;
    TEST("watch-only: SQLite write same hash overwrites (no dup)") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(sqlite3_exec(db, k_schema, NULL, NULL, NULL) == SQLITE_OK);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        uint8_t hash[20];
        memset(hash, 0xAA, 20);
        ASSERT(wallet_sqlite_write_watch_only(&ws, hash, "t1First"));
        ASSERT(wallet_sqlite_write_watch_only(&ws, hash, "t1Second"));

        sqlite3_stmt *s;
        sqlite3_prepare_v2(db,
            "SELECT count(*) FROM wallet_watch_only", -1, &s, NULL);
        sqlite3_step(s);
        int count = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        ASSERT_EQ(count, 1);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────── */

int test_watch_only(void);

int test_watch_only(void)
{
    int failures = 0;
    printf("\n=== watch-only address tests ===\n");

    failures += test_add_watch_only_id();
    failures += test_add_watch_only_id_dedup();
    failures += test_add_watch_only_with_pubkey();
    failures += test_remove_watch_only();
    failures += test_wallet_is_mine_watch_only();
    failures += test_wallet_is_watch_only_false_for_full_key();
    failures += test_wallet_is_mine_false_for_unknown();
    failures += test_sqlite_round_trip();
    failures += test_sqlite_overwrite();

    printf("%d passed, %d failed\n",
           9 - failures, failures);
    return failures;
}
