/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Round-trip tests for wallet_sqlite: open, write, close, reopen,
 * read, confirm keys survived.  This is the regression test for
 * the silent-open bug (see WALLET_PERSISTENCE_PLAN.md §2) at the
 * service layer — Agent 3's spec_e2e_wallet_restart covers the
 * same ground through a real forked daemon.
 *
 * Also exercises wallet_sqlite_self_test, invariant rejection in
 * wallet_sqlite_write_key_r, and wallet_sqlite_get_health. */

#include "test/test_core.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "keys/key.h"
#include "util/result.h"
#include "support/cleanse.h"
#include "util/ar_step_readonly.h"
#include "util/safe_alloc.h"
#include "platform/time_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

/* Minimal schema mirroring the production tables wallet_sqlite.c
 * prepares statements against.  wallet_watch_only is included —
 * omitting it was the original bug. */
static const char *k_full_schema =
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
    "  from_me INTEGER NOT NULL DEFAULT 0,fee INTEGER);"
    "CREATE TABLE wallet_watch_only ("
    "  address_hash BLOB PRIMARY KEY,"
    "  address TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE node_state ("
    "  key TEXT PRIMARY KEY,value BLOB);";

static sqlite3 *open_fixture_db(const char *path, bool apply_schema)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return NULL;
    if (apply_schema &&
        sqlite3_exec(db, k_full_schema, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static void make_test_key(struct privkey *key, struct pubkey *pk, uint8_t seed)
{
    privkey_init(key);
    /* Fill with a pattern that definitely isn't all-zero and isn't
     * a trivial scalar.  Two tweaked bytes ensure uniqueness across
     * seeds. */
    memset(key->vch, seed, 32);
    key->vch[0] = seed;
    key->vch[1] = (uint8_t)(seed ^ 0xAA);
    key->vch[31] = (uint8_t)(seed + 1);
    key->fValid = true;
    key->fCompressed = true;
    privkey_get_pubkey(key, pk);
}

static struct wallet *alloc_wallet(void)
{
    struct wallet *w = zcl_calloc(1, sizeof(struct wallet), "test_wallet");
    if (w) {
        keystore_init(&w->keystore);
        sapling_keystore_init(&w->sapling_keys);
        zcl_mutex_init(&w->cs);
    }
    return w;
}

static void free_wallet(struct wallet *w)
{
    if (!w) return;
    keystore_free(&w->keystore);
    free(w);
}

/* Make the tests deterministic by wiping any env that would change
 * the encrypted-at-rest path.  Individual tests can set it later. */
static void clear_passphrase(void)
{
    unsetenv("ZCL_WALLET_PASSPHRASE");
}

/* ── Tests ─────────────────────────────────────────────────────── */

static int test_open_empty_schema_ok(void)
{
    int failures = 0;
    TEST("wallet_persistence: open() on empty schema returns ZCL_OK") {
        clear_passphrase();
        sqlite3 *db = open_fixture_db(":memory:", true);
        ASSERT(db);

        struct wallet_sqlite ws;
        struct zcl_result r = wallet_sqlite_open_r(&ws, db);
        ASSERT(r.ok);
        ASSERT(r.code == 0);
        ASSERT(ws.open);

        struct wallet_sqlite_health h = wallet_sqlite_get_health(&ws, 0);
        ASSERT(h.open);
        ASSERT(h.row_count == 0);
        ASSERT(!h.mismatch);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_self_test_passes(void)
{
    int failures = 0;
    TEST("wallet_persistence: self_test round-trips through node_state") {
        clear_passphrase();
        sqlite3 *db = open_fixture_db(":memory:", true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct zcl_result r = wallet_sqlite_self_test(&ws);
        ASSERT(r.ok);
        ASSERT(ws.canary_ok);
        ASSERT(ws.canary_last_ok_ts > 0);

        /* Second call must also pass — probe is replaced each time. */
        r = wallet_sqlite_self_test(&ws);
        ASSERT(r.ok);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_write_then_reopen_preserves_keys(void)
{
    int failures = 0;
    TEST("wallet_persistence: 3 keys survive close + reopen") {
        clear_passphrase();

        /* Use a file DB so we can actually close and reopen. */
        char path[64];
        snprintf(path, sizeof(path),
                 "./test-tmp/wallet_persist_%d.db", (int)getpid());
        mkdir("./test-tmp", 0755);
        unlink(path);

        sqlite3 *db = open_fixture_db(path, true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct privkey keys[3];
        struct pubkey pks[3];
        for (int i = 0; i < 3; i++) {
            make_test_key(&keys[i], &pks[i], (uint8_t)(0x10 + i));
            struct zcl_result r =
                wallet_sqlite_write_key_r(&ws, &pks[i], &keys[i]);
            ASSERT(r.ok);
        }

        struct wallet_sqlite_health h = wallet_sqlite_get_health(&ws, 3);
        ASSERT(h.row_count == 3);
        ASSERT(!h.mismatch);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);

        /* Reopen and verify keys load back. */
        db = open_fixture_db(path, false);
        ASSERT(db);

        struct wallet_sqlite ws2;
        ASSERT(wallet_sqlite_open_r(&ws2, db).ok);

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        struct zcl_result r = wallet_sqlite_read_keys_r(&ws2, w);
        ASSERT(r.ok);
        ASSERT(w->keystore.num_keys == 3);

        /* Every written private key must be retrievable by pubkey. */
        for (int i = 0; i < 3; i++) {
            struct privkey got;
            privkey_init(&got);
            struct zcl_result rr =
                wallet_sqlite_read_single_key(&ws2, &pks[i], &got);
            ASSERT(rr.ok);
            ASSERT(memcmp(got.vch, keys[i].vch, 32) == 0);
            memory_cleanse(got.vch, 32);
        }

        wallet_sqlite_close(&ws2);
        sqlite3_close(db);
        free_wallet(w);
        unlink(path);

        PASS();
    } _test_next:;
    return failures;
}

static int test_keypool_membership_survives_restart(void)
{
    int failures = 0;
    TEST("wallet_persistence: unused keypool membership survives restart") {
        clear_passphrase();
        char path[80];
        snprintf(path, sizeof(path),
                 "./test-tmp/wallet_keypool_%d.db", (int)getpid());
        mkdir("./test-tmp", 0755);
        unlink(path);

        sqlite3 *db = open_fixture_db(path, true);
        ASSERT(db);
        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);
        struct wallet *before = alloc_wallet();
        ASSERT(before);
        ASSERT(wallet_top_up_key_pool(before, 3));
        int64_t ceiling = wallet_key_pool_generation_ceiling(before);
        ASSERT(wallet_sqlite_flush_r(&ws, before).ok);
        wallet_key_pool_mark_persisted_through(before, ceiling);
        ASSERT(wallet_key_pool_persisted_size(before) == 3);

        struct pubkey consumed;
        ASSERT(wallet_get_key_from_pool(before, &consumed));
        ASSERT(wallet_sqlite_flush_transactions_r(&ws, before).ok);
        ASSERT(before->key_pool_size == 2);
        free_wallet(before);
        wallet_sqlite_close(&ws);
        sqlite3_close(db);

        db = open_fixture_db(path, false);
        ASSERT(db);
        struct wallet_sqlite reopened;
        ASSERT(wallet_sqlite_open_r(&reopened, db).ok);
        struct wallet *after = alloc_wallet();
        ASSERT(after);
        ASSERT(wallet_sqlite_read_keys_r(&reopened, after).ok);
        ASSERT(wallet_sqlite_read_keypool_r(&reopened, after).ok);
        ASSERT(after->key_pool_size == 2);
        ASSERT(wallet_key_pool_persisted_size(after) == 2);
        ASSERT(wallet_get_key_from_pool(after, &consumed));
        ASSERT(wallet_get_key_from_pool(after, &consumed));
        ASSERT(!wallet_get_key_from_pool(after, &consumed));

        free_wallet(after);
        wallet_sqlite_close(&reopened);
        sqlite3_close(db);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* Regression for the SQLITE_BUSY key-persistence failure: when a concurrent
 * connection holds the node.db WAL write lock, wallet_sqlite_flush_r must
 * retry BEGIN IMMEDIATE and fail CLEANLY (no partial/corrupt state, no crash)
 * rather than silently strand keys; once the lock frees, the same flush must
 * succeed and durably persist. Deterministic: the holder is released between
 * the two flush calls (no threads, no timing assertions). */
static int test_flush_retries_under_write_lock(void)
{
    int failures = 0;
    TEST("wallet_persistence: flush retries under a held WAL write lock") {
        clear_passphrase();

        char path[80];
        snprintf(path, sizeof(path),
                 "./test-tmp/wallet_lock_%d.db", (int)getpid());
        mkdir("./test-tmp", 0755);
        unlink(path);

        /* Wallet connection: WAL + a short busy_timeout so the four bounded
         * retries resolve quickly when the lock is genuinely held. */
        sqlite3 *db = open_fixture_db(path, true);
        ASSERT(db);
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
        sqlite3_busy_timeout(db, 100);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x5A);
        ASSERT(keystore_add_key(&w->keystore, &key));

        /* Second connection holds the WAL write lock. */
        sqlite3 *holder = NULL;
        ASSERT(sqlite3_open(path, &holder) == SQLITE_OK);
        sqlite3_busy_timeout(holder, 0);
        ASSERT(sqlite3_exec(holder, "BEGIN IMMEDIATE", NULL, NULL, NULL)
               == SQLITE_OK);
        ASSERT(sqlite3_exec(holder,
               "INSERT INTO node_state(key,value) VALUES('lock',x'00')",
               NULL, NULL, NULL) == SQLITE_OK);

        /* Flush loses the lock race: it must fail cleanly, not corrupt. */
        struct zcl_result busy = wallet_sqlite_flush_r(&ws, w);
        ASSERT(!busy.ok);

        /* Release the lock; the retry contract says the next flush wins. */
        ASSERT(sqlite3_exec(holder, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
        sqlite3_close(holder);

        struct zcl_result ok = wallet_sqlite_flush_r(&ws, w);
        ASSERT(ok.ok);

        /* The key is now durably persisted. */
        struct privkey got;
        privkey_init(&got);
        ASSERT(wallet_sqlite_read_single_key(&ws, &pk, &got).ok);
        ASSERT(memcmp(got.vch, key.vch, 32) == 0);
        memory_cleanse(got.vch, 32);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet(w);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* Regression for the 2026-08-02 store-pay failure: the wallet shares ONE
 * FULLMUTEX connection with every other node.db writer (wallet_sqlite wraps
 * g_node_db.db; db_service's query_db IS node_db->db), so a competing job
 * mid-transaction on the SAME connection fails the flush's BEGIN IMMEDIATE
 * with SQLITE_ERROR "cannot start a transaction within a transaction" —
 * outside the BUSY family. The flush must treat it as transient contention
 * (bounded retry, then a CLEAN failure — no crash, no partial state) and,
 * once the competing COMMIT restores autocommit, succeed and persist.
 * Deterministic: the competing tx is held and released by this thread
 * between the two flushes. */
static int test_flush_retries_under_same_connection_tx(void)
{
    int failures = 0;
    TEST("wallet_persistence: flush retries under a same-connection open tx") {
        clear_passphrase();

        char path[80];
        snprintf(path, sizeof(path),
                 "./test-tmp/wallet_sametx_%d.db", (int)getpid());
        mkdir("./test-tmp", 0755);
        unlink(path);

        sqlite3 *db = open_fixture_db(path, true);
        ASSERT(db);
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
        sqlite3_busy_timeout(db, 100);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x3D);
        ASSERT(keystore_add_key(&w->keystore, &key));

        /* The competing writer opens its tx on the SAME connection — the
         * db-service-job shape (BEGIN now, COMMIT after its work). */
        ASSERT(sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
               == SQLITE_OK);
        ASSERT(sqlite3_get_autocommit(db) == 0);

        /* Flush contends: it must fail cleanly after the time-budgeted
         * retries, never crash and never write partial state. Shrink the
         * production 30 s budget to 2500 ms so the test runs fast, and
         * assert the wait actually TRACKS the budget — the pre-budget
         * 8-attempt cap exhausted in ~810 ms of backoff here, which is
         * exactly the C5 PAY-stage race (a sustained db-service job stream
         * outlasted the cap and stranded the pre-broadcast change key). */
        wallet_sqlite_flush_set_begin_budget_ms(2500);
        int64_t t0 = platform_time_monotonic_ms();
        struct zcl_result busy = wallet_sqlite_flush_r(&ws, w);
        int64_t waited_ms = platform_time_monotonic_ms() - t0;
        wallet_sqlite_flush_set_begin_budget_ms(0); /* restore production */
        ASSERT(!busy.ok);
        ASSERT(waited_ms >= 2000); /* budget governs, not the old 8-cap */
        ASSERT(waited_ms < 6000);  /* and it still bounds the wait */

        /* Competing writer commits; the next flush must win and persist. */
        ASSERT(sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
        ASSERT(sqlite3_get_autocommit(db) == 1);

        struct zcl_result ok = wallet_sqlite_flush_r(&ws, w);
        ASSERT(ok.ok);

        struct privkey got;
        privkey_init(&got);
        ASSERT(wallet_sqlite_read_single_key(&ws, &pk, &got).ok);
        ASSERT(memcmp(got.vch, key.vch, 32) == 0);
        memory_cleanse(got.vch, 32);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet(w);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

static int test_flush_resets_cached_read_cursors(void)
{
    int failures = 0;
    TEST("wallet_persistence: flush resets cached read cursors before BEGIN") {
        clear_passphrase();

        char path[96];
        snprintf(path, sizeof(path),
                 "./test-tmp/wallet_cursor_%d.db", (int)getpid());
        mkdir("./test-tmp", 0755);
        unlink(path);

        sqlite3 *db = open_fixture_db(path, true);
        ASSERT(db);
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct privkey persisted_key;
        struct pubkey persisted_pk;
        make_test_key(&persisted_key, &persisted_pk, 0x41);
        ASSERT(wallet_sqlite_write_key_r(&ws, &persisted_pk,
                                         &persisted_key).ok);

        sqlite3_reset(ws.stmt_key_read);
        ASSERT(AR_STEP_ROW_READONLY(ws.stmt_key_read) == SQLITE_ROW);

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        struct privkey new_key;
        struct pubkey new_pk;
        make_test_key(&new_key, &new_pk, 0x42);
        ASSERT(keystore_add_key(&w->keystore, &persisted_key));
        ASSERT(keystore_add_key(&w->keystore, &new_key));

        struct zcl_result r = wallet_sqlite_flush_r(&ws, w);
        ASSERT(r.ok);

        struct wallet_sqlite_health h = wallet_sqlite_get_health(&ws, 2);
        ASSERT(h.row_count == 2);
        ASSERT(!h.mismatch);

        struct privkey got;
        privkey_init(&got);
        ASSERT(wallet_sqlite_read_single_key(&ws, &new_pk, &got).ok);
        ASSERT(memcmp(got.vch, new_key.vch, 32) == 0);
        memory_cleanse(got.vch, 32);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet(w);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* Holder thread: grab the WAL write lock on a second connection, hold it for
 * `hold_ms`, then release. Used by test_flush_waits_out_transient_lock to
 * reproduce a background node.db writer (catch-up / store / evidence) that
 * holds the single WAL write lock across a window longer than the wallet
 * flush's OLD 4-attempt budget. */
struct lock_holder_args {
    char path[128];
    int  hold_ms;
    int  acquired; /* set once BEGIN IMMEDIATE succeeds */
};

static void *lock_holder_thread(void *arg)
{
    struct lock_holder_args *a = arg;
    sqlite3 *holder = NULL;
    if (sqlite3_open(a->path, &holder) != SQLITE_OK) return NULL;
    sqlite3_busy_timeout(holder, 0);
    if (sqlite3_exec(holder, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_exec(holder, "INSERT INTO node_state(key,value) VALUES('h',x'00')",
                     NULL, NULL, NULL) == SQLITE_OK) {
        __atomic_store_n(&a->acquired, 1, __ATOMIC_SEQ_CST);
        platform_sleep_ms(a->hold_ms);
        sqlite3_exec(holder, "COMMIT", NULL, NULL, NULL);
    }
    sqlite3_close(holder);
    return NULL;
}

/* Regression for the wallet-persistence P0 (node.db write-lock starvation):
 * a background node.db writer holds the single WAL write lock for a window
 * that exceeds the flush's OLD fixed 4-attempt budget. The hardened flush
 * (WALLET_FLUSH_BEGIN_MAX_ATTEMPTS + inter-attempt backoff + statement reset)
 * must wait it out on the SAME flush call and durably persist the key —
 * never strand it in RAM. The hold (500 ms) exceeds ~4×busy_timeout(100 ms)
 * = ~400 ms yet stays well under the new ~8×(100 ms)+backoff budget, so this
 * asserts the enlarged tolerance without a tight timing race. */
static int test_flush_waits_out_transient_lock(void)
{
    int failures = 0;
    TEST("wallet_persistence: flush waits out a transient held WAL write lock") {
        clear_passphrase();

        char path[128];
        snprintf(path, sizeof(path),
                 "./test-tmp/wallet_transient_%d.db", (int)getpid());
        mkdir("./test-tmp", 0755);
        unlink(path);

        sqlite3 *db = open_fixture_db(path, true);
        ASSERT(db);
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
        sqlite3_busy_timeout(db, 100);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct wallet *w = alloc_wallet();
        ASSERT(w);
        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x7C);
        ASSERT(keystore_add_key(&w->keystore, &key));

        struct lock_holder_args ha;
        memset(&ha, 0, sizeof(ha));
        snprintf(ha.path, sizeof(ha.path), "%s", path);
        ha.hold_ms = 500;
        pthread_t th;
        ASSERT(pthread_create(&th, NULL, lock_holder_thread, &ha) == 0);

        /* Wait until the holder actually owns the write lock, so the flush
         * genuinely contends (bounded spin, not a fixed sleep). */
        for (int i = 0; i < 200 &&
             !__atomic_load_n(&ha.acquired, __ATOMIC_SEQ_CST); i++)
            platform_sleep_ms(1);
        ASSERT(__atomic_load_n(&ha.acquired, __ATOMIC_SEQ_CST) == 1);

        /* Single flush call: it must retry across the 500 ms hold and win. */
        struct zcl_result ok = wallet_sqlite_flush_r(&ws, w);
        ASSERT(ok.ok);

        pthread_join(th, NULL);

        struct privkey got;
        privkey_init(&got);
        ASSERT(wallet_sqlite_read_single_key(&ws, &pk, &got).ok);
        ASSERT(memcmp(got.vch, key.vch, 32) == 0);
        memory_cleanse(got.vch, 32);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet(w);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

static int test_read_single_key_not_found(void)
{
    int failures = 0;
    TEST("wallet_persistence: read_single_key returns WSQL_READ_FAIL for unknown pubkey") {
        clear_passphrase();
        sqlite3 *db = open_fixture_db(":memory:", true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x77);

        struct privkey got;
        privkey_init(&got);
        struct zcl_result r = wallet_sqlite_read_single_key(&ws, &pk, &got);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_READ_FAIL);
        ASSERT(r.message[0] != '\0');

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_transaction_flush_skips_key_rewrite(void)
{
    int failures = 0;
    TEST("wallet_persistence: transaction-only flush leaves durable keys untouched") {
        clear_passphrase();
        sqlite3 *db = open_fixture_db(":memory:", true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);
        struct wallet *w = alloc_wallet();
        ASSERT(w);

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x6D);
        ASSERT(keystore_add_key(&w->keystore, &key));
        ASSERT(wallet_sqlite_flush_r(&ws, w).ok);

        /* Any attempt to replay the immutable key INSERT now aborts.  The hot
         * transaction durability path must still commit its wallet tx. */
        ASSERT(sqlite3_exec(db,
            "CREATE TRIGGER reject_key_rewrite BEFORE INSERT ON wallet_keys "
            "BEGIN SELECT RAISE(ABORT,'key rewrite'); END",
            NULL, NULL, NULL) == SQLITE_OK);
        struct wallet_tx *wtx = &w->map_wallet[0];
        memset(wtx, 0, sizeof(*wtx));
        transaction_init(&wtx->tx);
        wtx->tx.hash.data[0] = 0xA5;
        wtx->time_received = 1713000000;
        wtx->from_me = true;
        wtx->used = true;
        w->num_wallet_tx = 1;

        ASSERT(wallet_sqlite_flush_transactions_r(&ws, w).ok);
        sqlite3_stmt *count = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM wallet_transactions", -1,
            &count, NULL) == SQLITE_OK);
        ASSERT(AR_STEP_ROW_READONLY(count) == SQLITE_ROW);
        ASSERT(sqlite3_column_int(count, 0) == 1);
        sqlite3_finalize(count);

        /* Prove the trigger was armed rather than silently ineffective. */
        ASSERT(!wallet_sqlite_flush_r(&ws, w).ok);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        free_wallet(w);
        PASS();
    } _test_next:;
    return failures;
}

static int test_delete_key_roundtrip(void)
{
    int failures = 0;
    TEST("wallet_persistence: delete_key_r removes persisted key") {
        clear_passphrase();
        sqlite3 *db = open_fixture_db(":memory:", true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct privkey key;
        struct pubkey pk;
        make_test_key(&key, &pk, 0x88);
        ASSERT(wallet_sqlite_write_key_r(&ws, &pk, &key).ok);

        struct privkey got;
        privkey_init(&got);
        ASSERT(wallet_sqlite_read_single_key(&ws, &pk, &got).ok);
        memory_cleanse(got.vch, 32);

        struct zcl_result r = wallet_sqlite_delete_key_r(&ws, &pk);
        ASSERT(r.ok);

        privkey_init(&got);
        r = wallet_sqlite_read_single_key(&ws, &pk, &got);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_READ_FAIL);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_write_key_invariants(void)
{
    int failures = 0;
    TEST("wallet_persistence: write_key_r rejects invalid pubkey/privkey") {
        clear_passphrase();
        sqlite3 *db = open_fixture_db(":memory:", true);
        ASSERT(db);

        struct wallet_sqlite ws;
        ASSERT(wallet_sqlite_open_r(&ws, db).ok);

        struct privkey good_key;
        struct pubkey good_pk;
        make_test_key(&good_key, &good_pk, 0x33);

        /* invariant: NULL pubkey */
        struct zcl_result r = wallet_sqlite_write_key_r(&ws, NULL, &good_key);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_INVARIANT_PUBKEY);

        /* invariant: NULL privkey */
        r = wallet_sqlite_write_key_r(&ws, &good_pk, NULL);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_INVARIANT_PRIVKEY);

        /* invariant: fValid false */
        struct privkey bad;
        privkey_init(&bad);
        memcpy(bad.vch, good_key.vch, 32);
        bad.fValid = false;
        bad.fCompressed = true;
        r = wallet_sqlite_write_key_r(&ws, &good_pk, &bad);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_INVARIANT_PRIVKEY);

        /* invariant: all-zero privkey */
        struct privkey zero;
        privkey_init(&zero);
        memset(zero.vch, 0, 32);
        zero.fValid = true;
        zero.fCompressed = true;
        r = wallet_sqlite_write_key_r(&ws, &good_pk, &zero);
        ASSERT(!r.ok);
        ASSERT(r.code == WSQL_INVARIANT_PRIVKEY);

        /* Good write still works. */
        r = wallet_sqlite_write_key_r(&ws, &good_pk, &good_key);
        ASSERT(r.ok);

        wallet_sqlite_close(&ws);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_health_snapshot_without_open(void)
{
    int failures = 0;
    TEST("wallet_persistence: get_health handles closed handle") {
        struct wallet_sqlite ws;
        memset(&ws, 0, sizeof(ws));
        struct wallet_sqlite_health h = wallet_sqlite_get_health(&ws, 7);
        ASSERT(!h.open);
        ASSERT(h.row_count == 0);
        ASSERT(h.keystore_count == 7);
        ASSERT(h.mismatch);  /* 0 != 7 */
        PASS();
    } _test_next:;
    return failures;
}

/* Locate <root>/engine/composition/src/boot.c by walking up from the test binary
 * (<root>/build/bin/<name>) until a directory holding both the Makefile
 * and engine/composition/src/boot.c appears. Returns a malloc'd file buffer (caller
 * frees) or NULL if not found — in which case the test SKIPs rather than
 * failing, so a standalone test_zcl built outside the repo tree still
 * passes. */
static char *read_boot_c(void)
{
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0 || n >= (ssize_t)sizeof(exe) - 1)
        return NULL;
    exe[n] = '\0';

    char boot_path[PATH_MAX] = {0};
    for (int depth = 0; depth < 6; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';

        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/Makefile", exe)
                >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(probe, sizeof(probe), "%s/engine/composition/src/boot.c", exe)
                >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;
        snprintf(boot_path, sizeof(boot_path), "%s", probe);
        break;
    }
    if (!boot_path[0]) return NULL;

    FILE *f = fopen(boot_path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = zcl_malloc((size_t)sz + 1, "boot.c");
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

/* Regression for the wallet-persistence boot-ordering bug: the wallet
 * load/open block MUST run AFTER node.db is opened, otherwise
 * g_node_db.open is false when wallet_sqlite_open_r is reached, the
 * persistence layer never attaches, and every imported key / shielded
 * note is RAM-only and vanishes on restart. We pin the ordering at the
 * source level: in engine/composition/src/boot.c the node_db_sync_init(&g_node_db
 * call must appear BEFORE the wallet block's wallet_sqlite_open_r(
 * &g_wallet_sqlite call. */
static int test_boot_opens_node_db_before_wallet(void)
{
    int failures = 0;
    TEST("wallet_persistence: boot opens node.db before wallet_sqlite_open_r") {
        char *src = read_boot_c();
        if (!src) {
            /* Not in a repo tree (standalone test_zcl) — skip, don't fail. */
            PASS();
            goto _test_next;
        }

        const char *db_open = strstr(src, "node_db_sync_init(&g_node_db");
        const char *wallet_open =
            strstr(src, "wallet_sqlite_open_r(&g_wallet_sqlite");

        ASSERT(db_open != NULL);     /* the only node.db opener must exist */
        ASSERT(wallet_open != NULL); /* the wallet attach must exist */
        /* The opener must come first in the boot flow. */
        ASSERT(db_open < wallet_open);

        free(src);
        PASS();
    } _test_next:;
    return failures;
}

int test_wallet_persistence_cycle(void)
{
    int failures = 0;
    failures += test_boot_opens_node_db_before_wallet();
    failures += test_open_empty_schema_ok();
    failures += test_self_test_passes();
    failures += test_write_then_reopen_preserves_keys();
    failures += test_keypool_membership_survives_restart();
    failures += test_flush_retries_under_write_lock();
    failures += test_flush_retries_under_same_connection_tx();
    failures += test_flush_waits_out_transient_lock();
    failures += test_flush_resets_cached_read_cursors();
    failures += test_transaction_flush_skips_key_rewrite();
    failures += test_read_single_key_not_found();
    failures += test_delete_key_roundtrip();
    failures += test_write_key_invariants();
    failures += test_health_snapshot_without_open();
    return failures;
}
