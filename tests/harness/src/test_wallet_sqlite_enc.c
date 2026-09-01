/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Integration tests for wallet_sqlite encryption — wave 8 live wallet
 * encryption integration.
 *
 * Exercises the wallet_sqlite read/write paths with explicit runtime unlock
 * and lock transitions to verify:
 *   (1) plaintext round-trip still works (backward compat)
 *   (2) encrypted round-trip works when passphrase is set
 *   (3) encrypted blobs are unreadable without passphrase
 *   (4) mixed plaintext+encrypted DB reads cleanly
 *   (5) seed and sapling key encryption/decryption
 *
 * Each test opens a fresh in-memory SQLite DB, creates the schema,
 * and operates through the wallet_sqlite API. */

#include "test/test_core.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite_key_crypto.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"   /* MAX_SAPLING_KEYS (break-park regression) */
#include "keys/key.h"
#include "models/database.h"       /* node_db (scrub reader assertions) */
#include "models/wallet_key.h"     /* db_wallet_key_each / count */
#include "support/cleanse.h"
#include "util/result.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* ── Helpers ─────────────────────────────────────────────────── */

static const char k_schema[] =
    "CREATE TABLE wallet_keys("
    "pubkey_hash BLOB PRIMARY KEY,"
    "pubkey BLOB,privkey BLOB,compressed INT,created_at INT);"
    "CREATE TABLE wallet_keypool("
    "pubkey_hash BLOB PRIMARY KEY,generation INTEGER NOT NULL UNIQUE);"
    "CREATE TABLE wallet_key_encryption("
    "id INTEGER PRIMARY KEY CHECK(id=1),wrapped_dek BLOB NOT NULL);"
    "CREATE TABLE wallet_sapling_keys("
    "ivk BLOB PRIMARY KEY,xsk BLOB,xfvk BLOB,"
    "diversifier BLOB,pk_d BLOB,child_index INT,address TEXT);"
    "CREATE TABLE wallet_seed("
    "id INTEGER PRIMARY KEY CHECK(id=1),seed BLOB,next_child INT);"
    "CREATE TABLE wallet_transactions("
    "txid BLOB PRIMARY KEY,raw_tx BLOB,block_hash BLOB,"
    "block_height INT,time_received INT,from_me INT,fee INT);"
    "CREATE TABLE wallet_scripts("
    "script_hash BLOB PRIMARY KEY,redeem_script BLOB);"
    "CREATE TABLE wallet_watch_only("
    "address_hash BLOB PRIMARY KEY,address TEXT,created_at INT);"
    "CREATE TABLE node_state(key TEXT PRIMARY KEY,value BLOB);";

static sqlite3 *open_mem_db(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
    if (sqlite3_exec(db, k_schema, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

/* Set or clear the explicit test unlock register. Environment variables must
 * never auto-unlock an encrypted live wallet. */
static void set_passphrase(const char *pass)
{
    wallet_lock_reset_for_test();
    if (pass)
        ZCL_IGNORE_RESULT(wallet_lock_unlock(NULL, NULL, pass),
                          "fixed test passphrases satisfy unlock policy");
}

/* Make a deterministic private key for testing. */
static void make_test_key(struct privkey *key, struct pubkey *pk, uint8_t seed)
{
    privkey_init(key);
    memset(key->vch, seed, 32);
    /* Ensure it's a valid secp256k1 scalar — tweak byte 0 to avoid
     * the rare all-same-byte edge cases. */
    key->vch[0] = seed;
    key->vch[1] = (uint8_t)(seed ^ 0xAA);
    key->fValid = true;
    key->fCompressed = true;
    privkey_get_pubkey(key, pk);
}

/* Allocate a wallet for reading keys back. */
static struct wallet *alloc_wallet(void)
{
    struct wallet *w = zcl_calloc(1, sizeof(struct wallet), "test_wallet");
    if (w) {
        /* Production wallet_init() does this; a zeroed mutex is only valid
         * on POSIX (PTHREAD_MUTEX_INITIALIZER), Windows CRITICAL_SECTION
         * must be initialized before EnterCriticalSection. */
        zcl_mutex_init(&w->cs);
        keystore_init(&w->keystore);
        sapling_keystore_init(&w->sapling_keys);
    }
    return w;
}

static void free_wallet(struct wallet *w)
{
    if (!w) return;
    keystore_free(&w->keystore);
    zcl_mutex_destroy(&w->cs);
    free(w);
}

/* db_wallet_key_each callback state for the scrub reader assertions. */
static int g_each_seen;
static uint8_t g_each_pkh[8][20];

static void scrub_count_each_cb(const struct db_wallet_key *key, void *ctx)
{
    (void)ctx;
    if (g_each_seen < 8)
        memcpy(g_each_pkh[g_each_seen], key->pubkey_hash, 20);
    g_each_seen++;
}

/* ── Tests ───────────────────────────────────────────────────── */

static int test_plaintext_roundtrip(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: plaintext key roundtrip (no passphrase)") {
        set_passphrase(NULL);
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x42);
        ASSERT(wallet_sqlite_write_key(&ws, &pk, &key));

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        ASSERT(w->keystore.num_keys == 1);

        /* Verify the key matches. */
        struct key_id kid = pubkey_get_id(&pk);
        struct privkey got;
        privkey_init(&got);
        ASSERT(keystore_get_key(&w->keystore, &kid, &got));
        ASSERT(memcmp(got.vch, key.vch, 32) == 0);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_encrypted_roundtrip(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: encrypted key roundtrip") {
        set_passphrase("test-passphrase-42");
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x55);
        ASSERT(wallet_sqlite_write_key(&ws, &pk, &key));

        /* Read it back — same passphrase should decrypt. */
        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        ASSERT(w->keystore.num_keys == 1);

        struct key_id kid = pubkey_get_id(&pk);
        struct privkey got;
        privkey_init(&got);
        ASSERT(keystore_get_key(&w->keystore, &kid, &got));
        ASSERT(memcmp(got.vch, key.vch, 32) == 0);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        set_passphrase(NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_encrypted_unreadable_without_pass(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: encrypted key unreadable without passphrase") {
        set_passphrase("my-secret-phrase");
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x77);
        ASSERT(wallet_sqlite_write_key(&ws, &pk, &key));

        /* Remove passphrase — the read skips the authenticated envelope. */
        set_passphrase(NULL);

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        /* Key should be skipped — no keys loaded. */
        ASSERT(w->keystore.num_keys == 0);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wrong_passphrase_fails(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: wrong passphrase skips key") {
        set_passphrase("correct-phrase");
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x88);
        ASSERT(wallet_sqlite_write_key(&ws, &pk, &key));

        /* Change passphrase — GCM tag should fail. */
        set_passphrase("wrong-phrase");

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        ASSERT(w->keystore.num_keys == 0);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        set_passphrase(NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_mixed_plaintext_and_encrypted(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: mixed plaintext + encrypted keys both read") {
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        /* Write key A without encryption. */
        set_passphrase(NULL);
        struct privkey kA;
        struct pubkey pA;
        make_test_key(&kA, &pA, 0x11);
        ASSERT(wallet_sqlite_write_key(&ws, &pA, &kA));

        /* Write key B with encryption. */
        set_passphrase("mix-test");
        struct privkey kB;
        struct pubkey pB;
        make_test_key(&kB, &pB, 0x22);
        ASSERT(wallet_sqlite_write_key(&ws, &pB, &kB));

        /* Read with passphrase set — both should load. */
        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        ASSERT(w->keystore.num_keys == 2);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        set_passphrase(NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_encrypted_roundtrip(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: seed encrypts/decrypts correctly") {
        set_passphrase("seed-pass");
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        uint8_t seed[32];
        memset(seed, 0xAB, 32);
        ASSERT(wallet_sqlite_write_sapling_seed(&ws, seed));

        uint8_t got[32];
        memset(got, 0, 32);
        ASSERT(wallet_sqlite_read_sapling_seed(&ws, got));
        ASSERT(memcmp(seed, got, 32) == 0);

        /* Without passphrase, should fail. */
        set_passphrase(NULL);
        uint8_t bad[32];
        ASSERT(!wallet_sqlite_read_sapling_seed(&ws, bad));

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_plaintext_still_works(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: plaintext seed still readable") {
        set_passphrase(NULL);
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        uint8_t seed[32];
        memset(seed, 0xCD, 32);
        ASSERT(wallet_sqlite_write_sapling_seed(&ws, seed));

        uint8_t got[32];
        memset(got, 0, 32);
        ASSERT(wallet_sqlite_read_sapling_seed(&ws, got));
        ASSERT(memcmp(seed, got, 32) == 0);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* Regression: the sapling-seed read/write paths must NEVER leave the cached
 * stmt_seed_read cursor parked on a row. A cached SELECT stepped to SQLITE_ROW
 * and not reset keeps an implicit read transaction (WAL snapshot) open on the
 * shared node.db connection; on the live node every subsequent write on that
 * handle (wallet flush BEGIN IMMEDIATE, node_db state_set, catchup COMMIT) then
 * failed forever with SQLITE_BUSY_SNAPSHOT ("database is locked"). Assert the
 * connection returns to SQLITE_TXN_NONE after each seed op, on both the
 * row-found and no-row paths, encrypted and plaintext. */
static int test_seed_ops_leave_no_open_txn(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: seed read/write leave no open read txn") {
        set_passphrase(NULL);
        sqlite3 *db = open_mem_db();
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        /* No-row read: table empty -> false, and no cursor left open. */
        uint8_t got[32];
        memset(got, 0, 32);
        ASSERT(!wallet_sqlite_read_sapling_seed(&ws, got));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* Write path reads next_child via stmt_seed_read first. */
        uint8_t seed[32];
        memset(seed, 0xEE, 32);
        ASSERT(wallet_sqlite_write_sapling_seed(&ws, seed));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* Row-found read: the historically leaky path. */
        ASSERT(wallet_sqlite_read_sapling_seed(&ws, got));
        ASSERT(memcmp(seed, got, 32) == 0);
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* Same, encrypted envelope. */
        set_passphrase("leak-pass");
        memset(seed, 0x11, 32);
        ASSERT(wallet_sqlite_write_sapling_seed(&ws, seed));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);
        ASSERT(wallet_sqlite_read_sapling_seed(&ws, got));
        ASSERT(memcmp(seed, got, 32) == 0);
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);
        set_passphrase(NULL);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* Regression (Program O4e — wallet cached-stmt audit): every cached `_read`
 * SELECT must sqlite3_reset its cursor on EVERY exit path (row-found, no-row,
 * loop break, mid-iteration error). A cached SELECT left parked on SQLITE_ROW
 * keeps an implicit WAL read transaction open on the shared node.db
 * connection; every later write on that handle then fails forever with
 * SQLITE_BUSY_SNAPSHOT. read_single_key parked on the row after a successful
 * lookup, and read_sapling_keys parked when its loop broke at
 * MAX_SAPLING_KEYS — both now reset unconditionally. This asserts the
 * connection returns to SQLITE_TXN_NONE after each cached read. */
static int test_read_ops_leave_no_open_txn(void)
{
    int failures = 0;
    TEST("wallet_sqlite: cached reads leave no open read txn") {
        set_passphrase(NULL);
        sqlite3 *db = open_mem_db();
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        /* single-key read — the historically ROW-parked path. */
        struct privkey k;
        struct pubkey pk;
        make_test_key(&k, &pk, 0x5A);
        ASSERT(wallet_sqlite_write_key(&ws, &pk, &k));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        struct privkey out;
        ASSERT(wallet_sqlite_read_single_key(&ws, &pk, &out).ok);
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* no-row lookup for an absent key must still reset. */
        struct privkey k2;
        struct pubkey pk2;
        make_test_key(&k2, &pk2, 0x77);
        ASSERT(!wallet_sqlite_read_single_key(&ws, &pk2, &out).ok);
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        struct wallet *w = alloc_wallet();
        ASSERT(w);

        /* multi-row key loader. */
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* scripts / watch-only loop readers (rows inserted via direct SQL to
         * avoid pulling script/uint160 construction into this test). */
        {
            sqlite3_stmt *ins = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "INSERT INTO wallet_scripts(script_hash,redeem_script)"
                " VALUES(?,?)", -1, &ins, NULL) == SQLITE_OK);
            uint8_t sh[20];
            memset(sh, 0xA1, sizeof(sh));
            uint8_t redeem[4] = { 0x51, 0x52, 0x53, 0x54 };
            sqlite3_bind_blob(ins, 1, sh, sizeof(sh), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 2, redeem, sizeof(redeem), SQLITE_STATIC);
            ASSERT(sqlite3_step(ins) == SQLITE_DONE);
            sqlite3_finalize(ins);
        }
        ASSERT(wallet_sqlite_read_scripts(&ws, w));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        {
            sqlite3_stmt *ins = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "INSERT INTO wallet_watch_only(address_hash,address,created_at)"
                " VALUES(?,?,0)", -1, &ins, NULL) == SQLITE_OK);
            uint8_t ah[20];
            memset(ah, 0xB2, sizeof(ah));
            sqlite3_bind_blob(ins, 1, ah, sizeof(ah), SQLITE_STATIC);
            sqlite3_bind_text(ins, 2, "zWatchAddr", -1, SQLITE_STATIC);
            ASSERT(sqlite3_step(ins) == SQLITE_DONE);
            sqlite3_finalize(ins);
        }
        ASSERT(wallet_sqlite_read_watch_only(&ws, w));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* scan-height read (already correct — regression floor). */
        ASSERT(wallet_sqlite_write_scan_height(&ws, 12345));
        int h = 0;
        ASSERT(wallet_sqlite_read_scan_height(&ws, &h) && h == 12345);
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* transactions loop reader (dummy rows; undecodable blobs are skipped
         * but the reader must still reach DONE and reset). */
        for (int i = 0; i < 3; i++) {
            sqlite3_stmt *ins = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "INSERT INTO wallet_transactions"
                "(txid,raw_tx,block_hash,block_height,time_received,from_me,fee)"
                " VALUES(?,?,?,0,0,0,0)", -1, &ins, NULL) == SQLITE_OK);
            uint8_t txid[32];
            memset(txid, (uint8_t)(0xC0 + i), sizeof(txid));
            uint8_t raw[16];
            memset(raw, 0x00, sizeof(raw));
            uint8_t bh[32];
            memset(bh, 0, sizeof(bh));
            sqlite3_bind_blob(ins, 1, txid, sizeof(txid), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 2, raw, sizeof(raw), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 3, bh, sizeof(bh), SQLITE_STATIC);
            ASSERT(sqlite3_step(ins) == SQLITE_DONE);
            sqlite3_finalize(ins);
        }
        ASSERT(wallet_sqlite_read_txs(&ws, w));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        /* sapling loader — insert MAX_SAPLING_KEYS+1 well-formed rows so the
         * loop BREAKS at the cap, exiting PARKED on a row pre-fix. */
        for (int i = 0; i < MAX_SAPLING_KEYS + 1; i++) {
            sqlite3_stmt *ins = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "INSERT INTO wallet_sapling_keys"
                "(ivk,xsk,xfvk,diversifier,pk_d,child_index,address)"
                " VALUES(?,?,?,?,?,?,'')", -1, &ins, NULL) == SQLITE_OK);
            uint8_t ivk[32];
            memset(ivk, 0, sizeof(ivk));
            ivk[0] = (uint8_t)i;         /* unique PRIMARY KEY across [0,256] */
            ivk[1] = (uint8_t)(i >> 8);
            uint8_t big[256];
            memset(big, 0x33, sizeof(big)); /* >= sizeof(zip32_xsk / _xfvk) */
            uint8_t div[11];
            memset(div, 0x44, sizeof(div));
            uint8_t pkd[32];
            memset(pkd, 0x55, sizeof(pkd));
            sqlite3_bind_blob(ins, 1, ivk, sizeof(ivk), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 2, big, sizeof(big), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 3, big, sizeof(big), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 4, div, sizeof(div), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 5, pkd, sizeof(pkd), SQLITE_STATIC);
            sqlite3_bind_int(ins, 6, i);
            ASSERT(sqlite3_step(ins) == SQLITE_DONE);
            sqlite3_finalize(ins);
        }
        ASSERT(wallet_sqlite_read_sapling_keys(&ws, w));
        ASSERT(sqlite3_txn_state(db, NULL) == SQLITE_TXN_NONE);

        free_wallet(w);
        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* Runtime unlock/lock drives at-rest encryption via the wallet_lock register
 * (not just the env var): unlock encrypts writes, a full unlock into a wallet
 * reloads decrypted keys, lock wipes them, and a wrong passphrase fails
 * cleanly with no partial reload. */
static int test_runtime_unlock_lock_reload(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: runtime unlock encrypts, reloads, locks, wrong-pass clean") {
        wallet_lock_reset_for_test();
        set_passphrase(NULL);   /* drive purely through the runtime register */

        /* Unlock caches the passphrase; subsequent writes encrypt at rest. */
        ASSERT(wallet_lock_unlock(NULL, NULL, "runtime-pass").ok);

        sqlite3 *db = open_mem_db();
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey k1, k2;
        struct pubkey p1, p2;
        make_test_key(&k1, &p1, 0x11);
        make_test_key(&k2, &p2, 0x22);
        ASSERT(wallet_sqlite_write_key(&ws, &p1, &k1));
        ASSERT(wallet_sqlite_write_key(&ws, &p2, &k2));

        /* On-disk bytes are a WKD1 envelope, never the raw scalar. */
        sqlite3_stmt *st = NULL;
        ASSERT(sqlite3_prepare_v2(db, "SELECT privkey FROM wallet_keys LIMIT 1",
                                  -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW);
        const void *blob = sqlite3_column_blob(st, 0);
        int blen = sqlite3_column_bytes(st, 0);
        ASSERT(blob && blen >= 4 && memcmp(blob, "WKD1", 4) == 0);
        /* Portable "raw key absent" scan (avoids glibc-specific memmem). */
        bool raw_present = false;
        if (blob && blen >= 32) {
            const unsigned char *b = blob;
            for (int i = 0; i + 32 <= blen; i++)
                if (memcmp(b + i, k1.vch, 32) == 0) { raw_present = true; break; }
        }
        ASSERT(!raw_present);
        sqlite3_finalize(st);

        /* Full unlock into a wallet reloads the decrypted keys. */
        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_lock_unlock(w, &ws, "runtime-pass").ok);
        ASSERT(w->keystore.num_keys == 2);
        ASSERT(wallet_lock_encrypted_at_rest());
        ASSERT(wallet_lock_is_unlocked());

        /* Lock wipes resident spending keys and re-locks the register. */
        wallet_lock_lock(w);
        ASSERT(w->keystore.num_keys == 0);
        ASSERT(!wallet_lock_is_unlocked());
        struct privkey locked_read;
        privkey_init(&locked_read);
        ASSERT(!wallet_sqlite_read_single_key(
            &ws, &p1, &locked_read).ok);

        /* Wrong passphrase: typed failure, no partial reload, still locked. */
        struct zcl_result bad = wallet_lock_unlock(w, &ws, "WRONG");
        ASSERT(!bad.ok);
        ASSERT(bad.code == WLK_WRONG_PASS);
        ASSERT(w->keystore.num_keys == 0);
        ASSERT(!wallet_lock_is_unlocked());

        /* Correct passphrase reloads again. */
        ASSERT(wallet_lock_unlock(w, &ws, "runtime-pass").ok);
        ASSERT(w->keystore.num_keys == 2);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        wallet_lock_reset_for_test();
        set_passphrase(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* Boot-time plaintext scrub (wallet_sqlite_scrub_plaintext_r): with a
 * passphrase configured, every plaintext secret row — including rows the
 * in-memory wallet never loaded, like the removed mirror writer's stale
 * plantings — is wrapped IN PLACE; transparent keys use WKD1 while Sapling
 * keys and the seed retain WKS1 compatibility. Nothing is deleted. Assert
 * all three secret columns are envelopes after the
 * scrub, the decrypting read path still returns the original bytes, the
 * diagnostic reader (db_wallet_key_each) still sees the rows, and a
 * second scrub is a no-op. */
static int test_scrub_upgrades_plaintext_rows(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: scrub wraps plaintext rows into envelopes") {
        wallet_lock_reset_for_test();
        set_passphrase(NULL);
        sqlite3 *db = open_mem_db();
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        /* Plant PLAINTEXT rows (mirror-era / pre-encryption state). */
        struct privkey k1, k2;
        struct pubkey p1, p2;
        make_test_key(&k1, &p1, 0x31);
        make_test_key(&k2, &p2, 0x32);
        ASSERT(wallet_sqlite_write_key(&ws, &p1, &k1));
        ASSERT(wallet_sqlite_write_key(&ws, &p2, &k2));

        struct sapling_key_entry e;
        memset(&e, 0, sizeof(e));
        memset(e.ivk, 0x91, 32);
        memset(&e.xsk, 0x92, sizeof(e.xsk));
        memset(&e.xfvk, 0x93, sizeof(e.xfvk));
        memset(e.diversifier, 0x94, 11);
        memset(e.pk_d, 0x95, 32);
        e.child_index = 0;
        e.used = true;
        ASSERT(wallet_sqlite_write_sapling_key(&ws, 0, &e));

        uint8_t seed[32];
        memset(seed, 0x96, 32);
        ASSERT(wallet_sqlite_write_sapling_seed(&ws, seed));

        /* Sanity: without a passphrase the rows sit raw on disk. */
        {
            sqlite3_stmt *st = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "SELECT privkey FROM wallet_keys LIMIT 1",
                -1, &st, NULL) == SQLITE_OK);
            ASSERT(sqlite3_step(st) == SQLITE_ROW);
            const void *blob = sqlite3_column_blob(st, 0);
            ASSERT(blob && sqlite3_column_bytes(st, 0) == 32);
            ASSERT(memcmp(blob, "WKS1", 4) != 0);
            sqlite3_finalize(st);
        }

        /* Operator sets a passphrase and boots — the scrub fires. */
        set_passphrase("scrub-pass");
        ASSERT(wallet_sqlite_scrub_plaintext_r(&ws).ok);

        /* Every secret column is now its domain's authenticated envelope. */
        static const char *k_cols[] = {
            "SELECT privkey FROM wallet_keys",
            "SELECT xsk FROM wallet_sapling_keys",
            "SELECT seed FROM wallet_seed",
        };
        static const char *k_magic[] = { "WKD1", "WKS1", "WKS1" };
        int envelope_rows = 0;
        for (size_t q = 0; q < sizeof(k_cols) / sizeof(k_cols[0]); q++) {
            sqlite3_stmt *st = NULL;
            ASSERT(sqlite3_prepare_v2(db, k_cols[q], -1, &st, NULL)
                   == SQLITE_OK);
            while (sqlite3_step(st) == SQLITE_ROW) {
                const void *blob = sqlite3_column_blob(st, 0);
                int blen = sqlite3_column_bytes(st, 0);
                ASSERT(blob && blen > 60);
                ASSERT(memcmp(blob, k_magic[q], 4) == 0);
                envelope_rows++;
            }
            sqlite3_finalize(st);
        }
        ASSERT(envelope_rows == 4); /* 2 keys + 1 sapling + 1 seed */

        /* The decrypting read path still returns the original bytes. */
        struct wallet *w = alloc_wallet();
        ASSERT(w);
        ASSERT(wallet_sqlite_read_keys(&ws, w));
        ASSERT(w->keystore.num_keys == 2);
        struct key_id kid1 = pubkey_get_id(&p1);
        struct privkey got;
        privkey_init(&got);
        ASSERT(keystore_get_key(&w->keystore, &kid1, &got));
        ASSERT(memcmp(got.vch, k1.vch, 32) == 0);

        uint8_t got_seed[32];
        ASSERT(wallet_sqlite_read_sapling_seed(&ws, got_seed));
        ASSERT(memcmp(got_seed, seed, 32) == 0);

        /* The diagnostic reader still sees the rows (pubkey_hash intact). */
        {
            struct node_db ndb;
            memset(&ndb, 0, sizeof(ndb));
            ndb.db = db;
            ndb.open = true;
            g_each_seen = 0;
            memset(g_each_pkh, 0, sizeof(g_each_pkh));
            int n = db_wallet_key_each(&ndb, scrub_count_each_cb, NULL);
            ASSERT(n == 2);
            ASSERT(g_each_seen == 2);
            bool kid1_seen = false;
            for (int i = 0; i < g_each_seen; i++)
                if (memcmp(g_each_pkh[i], kid1.id.data, 20) == 0)
                    kid1_seen = true;
            ASSERT(kid1_seen);
        }

        /* Idempotent: a second scrub upgrades nothing and succeeds. */
        ASSERT(wallet_sqlite_scrub_plaintext_r(&ws).ok);
        ASSERT(db_wallet_key_count(&(struct node_db){
                   .db = db, .open = true }) == 2);

        wallet_sqlite_close(&ws);
        free_wallet(w);
        sqlite3_close(db);
        set_passphrase(NULL);
        wallet_lock_reset_for_test();
        PASS();
    } _test_next:;
    return failures;
}

static int test_scrub_noop_without_passphrase(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: scrub is a no-op without a passphrase") {
        wallet_lock_reset_for_test();
        set_passphrase(NULL);
        sqlite3 *db = open_mem_db();
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey k1;
        struct pubkey p1;
        make_test_key(&k1, &p1, 0x41);
        ASSERT(wallet_sqlite_write_key(&ws, &p1, &k1));
        uint8_t seed[32];
        memset(seed, 0x42, 32);
        ASSERT(wallet_sqlite_write_sapling_seed(&ws, seed));

        /* No passphrase: raw 32-byte rows are the legitimate format. */
        ASSERT(wallet_sqlite_scrub_plaintext_r(&ws).ok);

        sqlite3_stmt *st = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "SELECT privkey FROM wallet_keys LIMIT 1",
            -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW);
        const void *blob = sqlite3_column_blob(st, 0);
        ASSERT(blob && sqlite3_column_bytes(st, 0) == 32);
        ASSERT(memcmp(blob, k1.vch, 32) == 0);
        sqlite3_finalize(st);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        wallet_lock_reset_for_test();
        PASS();
    } _test_next:;
    return failures;
}

static int test_legacy_wks1_migrates_and_restarts(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: legacy WKS1 key migrates to WKD1 and restarts") {
        set_passphrase("legacy-migration-pass");
        sqlite3 *db = open_mem_db();
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x61);
        struct key_id kid = pubkey_get_id(&pk);
        uint8_t legacy[WKS_HEADER_LEN + 32];
        size_t legacy_len = 0;
        ASSERT(wks_encrypt(key.vch, 32, "legacy-migration-pass",
                           WKS_MIN_ITERS, legacy, sizeof(legacy),
                           &legacy_len));
        sqlite3_stmt *ins = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed) "
            "VALUES(?1,?2,?3,1)", -1, &ins, NULL) == SQLITE_OK);
        sqlite3_bind_blob(ins, 1, kid.id.data, 20, SQLITE_STATIC);
        sqlite3_bind_blob(ins, 2, pk.vch, (int)pk.size, SQLITE_STATIC);
        sqlite3_bind_blob(ins, 3, legacy, (int)legacy_len, SQLITE_STATIC);
        ASSERT(sqlite3_step(ins) == SQLITE_DONE);
        sqlite3_finalize(ins);
        memory_cleanse(legacy, sizeof(legacy));

        struct wallet *before = alloc_wallet();
        ASSERT(before);
        ASSERT(wallet_sqlite_read_keys(&ws, before));
        ASSERT(before->keystore.num_keys == 1);

        ASSERT(wallet_sqlite_migrate_transparent_keys_r(&ws, before).ok);
        ASSERT(wallet_sqlite_scrub_plaintext_r(&ws).ok);
        free_wallet(before);
        sqlite3_stmt *sel = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "SELECT privkey FROM wallet_keys WHERE pubkey_hash=?1",
            -1, &sel, NULL) == SQLITE_OK);
        sqlite3_bind_blob(sel, 1, kid.id.data, 20, SQLITE_STATIC);
        ASSERT(sqlite3_step(sel) == SQLITE_ROW);
        const void *blob = sqlite3_column_blob(sel, 0);
        int blob_len = sqlite3_column_bytes(sel, 0);
        ASSERT(wallet_sqlite_key_is_envelope(blob, (size_t)blob_len));
        sqlite3_finalize(sel);

        wallet_sqlite_close(&ws);
        set_passphrase("legacy-migration-pass");
        ASSERT(wallet_sqlite_open(&ws, db));
        struct wallet *after = alloc_wallet();
        ASSERT(after);
        ASSERT(wallet_sqlite_read_keys(&ws, after));
        ASSERT(after->keystore.num_keys == 1);
        struct privkey got;
        privkey_init(&got);
        ASSERT(keystore_get_key(&after->keystore, &kid, &got));
        ASSERT(memcmp(got.vch, key.vch, 32) == 0);

        wallet_sqlite_close(&ws);
        free_wallet(after);
        sqlite3_close(db);
        set_passphrase(NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wkd1_batch_and_row_swap_authentication(void)
{
    int failures = 0;
    TEST("wallet_sqlite_enc: WKD1 batch shares one wrapper and rejects row swap") {
        set_passphrase("batch-envelope-pass");
        sqlite3 *db = open_mem_db();
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open(&ws, db));

        struct privkey keys[10];
        struct pubkey pubs[10];
        struct key_id ids[10];
        for (size_t i = 0; i < 10; i++) {
            make_test_key(&keys[i], &pubs[i], (uint8_t)(0x70 + i));
            ids[i] = pubkey_get_id(&pubs[i]);
            ASSERT(wallet_sqlite_write_key(&ws, &pubs[i], &keys[i]));
        }

        sqlite3_stmt *count = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "SELECT count(*) FROM wallet_key_encryption WHERE id=1",
            -1, &count, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(count) == SQLITE_ROW);
        ASSERT(sqlite3_column_int(count, 0) == 1);
        sqlite3_finalize(count);

        uint8_t envelopes[2][WSQL_KEY_ENVELOPE_OVERHEAD + 32];
        size_t envelope_lens[2] = {0};
        for (size_t i = 0; i < 2; i++) {
            sqlite3_stmt *sel = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "SELECT privkey FROM wallet_keys WHERE pubkey_hash=?1",
                -1, &sel, NULL) == SQLITE_OK);
            sqlite3_bind_blob(sel, 1, ids[i].id.data, 20, SQLITE_STATIC);
            ASSERT(sqlite3_step(sel) == SQLITE_ROW);
            int n = sqlite3_column_bytes(sel, 0);
            const void *blob = sqlite3_column_blob(sel, 0);
            ASSERT(blob && n == (int)sizeof(envelopes[i]));
            memcpy(envelopes[i], blob, (size_t)n);
            envelope_lens[i] = (size_t)n;
            sqlite3_finalize(sel);
        }
        ASSERT(envelope_lens[0] == envelope_lens[1]);

        for (size_t i = 0; i < 2; i++) {
            sqlite3_stmt *upd = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "UPDATE wallet_keys SET privkey=?1 WHERE pubkey_hash=?2",
                -1, &upd, NULL) == SQLITE_OK);
            sqlite3_bind_blob(upd, 1, envelopes[1 - i],
                              (int)envelope_lens[1 - i], SQLITE_STATIC);
            sqlite3_bind_blob(upd, 2, ids[i].id.data, 20, SQLITE_STATIC);
            ASSERT(sqlite3_step(upd) == SQLITE_DONE);
            sqlite3_finalize(upd);
        }

        struct privkey swapped;
        privkey_init(&swapped);
        ASSERT(!wallet_sqlite_read_single_key(&ws, &pubs[0], &swapped).ok);
        ASSERT(!wallet_sqlite_read_single_key(&ws, &pubs[1], &swapped).ok);

        memory_cleanse(envelopes, sizeof(envelopes));
        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        set_passphrase(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────────── */

int test_wallet_sqlite_enc(void);

int test_wallet_sqlite_enc(void)
{
    int failures = 0;

    /* Start from a clean lock state; tests opt in through explicit unlock. */
    wallet_lock_reset_for_test();

    failures += test_plaintext_roundtrip();
    failures += test_encrypted_roundtrip();
    failures += test_encrypted_unreadable_without_pass();
    failures += test_wrong_passphrase_fails();
    failures += test_mixed_plaintext_and_encrypted();
    failures += test_seed_encrypted_roundtrip();
    failures += test_seed_plaintext_still_works();
    failures += test_seed_ops_leave_no_open_txn();
    failures += test_read_ops_leave_no_open_txn();
    failures += test_runtime_unlock_lock_reload();
    failures += test_scrub_upgrades_plaintext_rows();
    failures += test_scrub_noop_without_passphrase();
    failures += test_legacy_wks1_migrates_and_restarts();
    failures += test_wkd1_batch_and_row_swap_authentication();

    /* Cleanup: scrub the test unlock register. */
    set_passphrase(NULL);
    wallet_lock_reset_for_test();
    return failures;
}
