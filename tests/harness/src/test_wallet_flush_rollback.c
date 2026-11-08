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
#include "config/boot_wallet_cutover_publish.h"
#include "config/boot_wallet_cutover_replay.h"
#include "controllers/wallet_helpers.h"
#include "services/wallet_private_relay.h"
#include "storage/coins_kv.h"
#include "storage/coins_kv_read_snapshot.h"
#include "storage/shielded_pool_kv.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "core/serialize.h"
#include "models/database.h"
#include "models/ar_after_commit.h"
#include "models/wallet_tx.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "script/standard.h"
#include "keys/key.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pthread.h>
#include <time.h>
#endif

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
        ASSERT(sqlite3_exec(db, "UPDATE wallet_transactions SET fee=42", NULL, NULL, NULL) == SQLITE_OK);
        ASSERT(wallet_sqlite_flush_r(&ws, w).ok);
        sqlite3_stmt *fee = NULL;
        ASSERT(sqlite3_prepare_v2(db, "SELECT fee FROM wallet_transactions", -1, &fee, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(fee) == SQLITE_ROW && sqlite3_column_int(fee, 0) == 42);
        sqlite3_finalize(fee);

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

static int wfr_deny_commit(void *arg, int action, const char *a, const char *b,
                           const char *c, const char *d)
{
    (void)arg; (void)b; (void)c; (void)d;
    return action == SQLITE_TRANSACTION && a && strcmp(a, "COMMIT") == 0 ? SQLITE_DENY : SQLITE_OK;
}

struct wfr_fixture {
    char dir[256], path[320], before[4096];
    sqlite3 *db;
    struct wallet_sqlite ws;
    struct wallet *w;
    struct wallet_cutover_binding b;
    uint8_t scan_identity[32];
};

static bool wfr_snapshot_secrets(sqlite3 *db, char *out, size_t cap)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT hex(privkey)||(SELECT hex(redeem_script) FROM wallet_scripts LIMIT 1) FROM wallet_keys LIMIT 1";
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_text(s, 0);
    if (ok) snprintf(out, cap, "%s", sqlite3_column_text(s, 0));
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool wfr_cutover_setup(struct wfr_fixture *f, int fault)
{
    test_make_tmpdir(f->dir, sizeof(f->dir), "cutover_flush", "db");
    snprintf(f->path, sizeof(f->path), "%s/node.db", f->dir);
    if (sqlite3_open(f->path, &f->db) != SQLITE_OK ||
        sqlite3_exec(f->db, k_flush_schema, NULL, NULL, NULL) != SQLITE_OK ||
        !wallet_sqlite_open_r(&f->ws, f->db).ok || !(f->w=alloc_wallet_t())) return false;
    struct privkey key; struct pubkey pub;
    make_key(&key, &pub, 0x41);
    struct script script; script_init(&script); script_push_op(&script, OP_1);
    if (!keystore_add_key(&f->w->keystore, &key) || !keystore_add_cscript(&f->w->keystore, &script) ||
        !wallet_sqlite_flush_r(&f->ws, f->w).ok ||
        !wfr_snapshot_secrets(f->db, f->before, sizeof(f->before))) return false;
    f->b = (struct wallet_cutover_binding){.old_generation_present=true, .old_generation=1,
        .old_height=10, .target_height=20};
    if (fault >= 9) { f->b.old_generation_present = false; f->b.old_generation = 0; }
    f->b.old_hash[0]=1; f->b.target_hash[0]=2; f->b.artifact_digest[0]=3;
    f->w->scan_retry.pending=true; f->w->scan_retry.from=5; f->w->scan_retry.since=123;
    f->w->best_block_height=10;
    snprintf(f->w->scan_retry.blocker, sizeof(f->w->scan_retry.blocker), "CUTOVER");
    if (!wallet_readiness_initialize(f->w, WALLET_READINESS_PENDING, true, fault >= 9 ? 1 : 2) ||
        !wallet_sqlite_cutover_prepare(&f->ws, f->w, &f->b)) return false;
    f->w->best_block_height=20; seed_wallet_tx(f->w);
    if (!wallet_scan_identity(f->w, f->scan_identity)) return false;
    return true;
}

static bool wfr_cutover_unsaved(struct wfr_fixture *f, int fault)
{
    if (fault == 6) { struct privkey extra; struct pubkey p; make_key(&extra, &p, 0x52);
        if (!keystore_add_key(&f->w->keystore, &extra)) return false; }
    if (fault == 7) { struct script extra; script_init(&extra); script_push_op(&extra, OP_2);
        if (!keystore_add_cscript(&f->w->keystore, &extra)) return false; }
    if (fault == 11) { struct key_id id = {0}; id.id.data[0] = 0x55;
        if (!keystore_add_watch_only_id(&f->w->keystore, &id)) return false; }
    if (fault == 12) f->w->readiness.epoch = UINT64_MAX;
    if (fault == 14) f->w->keystore.scripts[0].redeem_script.data[0] ^= 1;
    if (fault == 13) { f->w->sapling_keys.num_keys = 1;
        f->w->sapling_keys.keys[0].used = true; f->w->sapling_keys.keys[0].ivk[0] = 1; }
    return true;
}

static bool wfr_cutover_success(int fault) { return fault == 0 || fault == 9; }

static bool wfr_cutover_begin(struct wfr_fixture *f, int fault)
{
    if (!wfr_cutover_unsaved(f, fault)) return false;
    if ((fault == 6 || fault == 7) && !wallet_scan_identity(f->w, f->scan_identity)) return false;
    if (fault == 1 && sqlite3_exec(f->db, k_fail_tx_trigger, NULL, NULL, NULL) != SQLITE_OK) return false;
    if (fault == 2 && sqlite3_exec(f->db, "CREATE TRIGGER fail_fence BEFORE DELETE ON node_state WHEN old.key=\x27wallet_cutover_binding\x27 BEGIN SELECT RAISE(ABORT, \x27injected\x27); END", NULL, NULL, NULL) != SQLITE_OK) return false;
    if (sqlite3_exec(f->db, fault == 8 ? "BEGIN" : "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    if (fault == 3) sqlite3_set_authorizer(f->db, wfr_deny_commit, NULL);
    return true;
}

static bool wfr_refuse_completion(void *ctx, struct wallet *w, sqlite3 *db)
{
    bool *called = ctx;
    *called = w != NULL && db != NULL;
    return false;
}

static bool wfr_cutover_attempt(struct wfr_fixture *f, int fault)
{
    if (!wfr_cutover_begin(f, fault)) return false;
    struct wallet_cutover_binding expected=f->b;
    if (fault == 4) expected.target_hash[0] ^= 1;
    bool called = false;
    struct zcl_result r = fault == 15 ?
        wallet_sqlite_cutover_complete_checked_in_open_tx_r(&f->ws, f->w, &expected, true, 1, 20, f->scan_identity, wfr_refuse_completion, &called) :
        wallet_sqlite_cutover_complete_flush_in_open_tx_r(&f->ws, f->w, &expected, fault != 10, fault >= 9 ? 1 : (fault == 5 ? 3 : 2), 20, f->scan_identity);
    sqlite3_set_authorizer(f->db, NULL, NULL);
    bool success = wfr_cutover_success(fault);
    struct wallet_readiness ready = wallet_readiness_get(f->w);
    return (fault != 15 || called) && r.ok == success && sqlite3_get_autocommit(f->db) &&
        f->w->scan_retry.pending != success &&
        ready.state == (success ? WALLET_READINESS_READY : WALLET_READINESS_PENDING) &&
        ready.epoch == (fault == 12 ? UINT64_MAX : (success ? 2 : 1));
}

static bool wfr_binding_exact(const struct wallet_cutover_binding *a,
                              const struct wallet_cutover_binding *b)
{
    return a->old_generation_present == b->old_generation_present &&
        a->old_generation == b->old_generation && a->old_height == b->old_height &&
        a->target_height == b->target_height && memcmp(a->old_hash, b->old_hash, 32) == 0 &&
        memcmp(a->target_hash, b->target_hash, 32) == 0 &&
        memcmp(a->artifact_digest, b->artifact_digest, 32) == 0;
}

static bool wfr_fence_after_reopen(struct wfr_fixture *f, bool success)
{
    struct wallet_cutover_binding got;
    struct wallet_scan_marker marker;
    enum wallet_cutover_status status = wallet_sqlite_cutover_read(&f->ws, &got);
    bool marker_present = wallet_sqlite_read_scan_marker(&f->ws, &marker);
    if (success) return status == WALLET_CUTOVER_ABSENT && !marker_present;
    return status == WALLET_CUTOVER_PENDING && wfr_binding_exact(&got, &f->b) &&
        marker_present && marker.from == 5 && marker.depth_height == 10 &&
        marker.since == 123 && strcmp(marker.blocker, "CUTOVER") == 0;
}

static bool wfr_cutover_reopen(struct wfr_fixture *f, int fault)
{
    wallet_sqlite_close(&f->ws); sqlite3_close(f->db); f->db=NULL;
    if (sqlite3_open(f->path, &f->db) != SQLITE_OK || !wallet_sqlite_open_r(&f->ws, f->db).ok) return false;
    int scan=0; char after[4096];
    bool success = wfr_cutover_success(fault);
    return wfr_fence_after_reopen(f, success) &&
        count_rows(f->db, "wallet_transactions") == (success ? 1 : 0) &&
        wallet_sqlite_read_scan_height(&f->ws, &scan) && scan == (success ? 20 : 4) &&
        wfr_snapshot_secrets(f->db, after, sizeof(after)) && strcmp(f->before, after) == 0;
}

static bool wfr_cutover_one(int fault)
{
    struct wfr_fixture f = {0};
    bool ok = wfr_cutover_setup(&f, fault) && wfr_cutover_attempt(&f, fault) && wfr_cutover_reopen(&f, fault);
    if (f.ws.open) wallet_sqlite_close(&f.ws);
    if (f.db) sqlite3_close(f.db);
    free_wallet_t(f.w); test_rm_rf(f.dir);
    return ok;
}

static bool wfr_fee_survives_cutover(void)
{
    struct wfr_fixture f = {0};
    bool ok = wfr_cutover_setup(&f, 0);
    if (ok) ok = wallet_sqlite_write_tx(&f.ws, &f.w->map_wallet[0]);
    if (ok) ok = sqlite3_exec(f.db, "UPDATE wallet_transactions SET fee=42", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = wfr_cutover_attempt(&f, 0) && wfr_cutover_reopen(&f, 0);
    sqlite3_stmt *stmt = NULL;
    if (ok) ok = sqlite3_prepare_v2(f.db, "SELECT fee FROM wallet_transactions", -1, &stmt, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 42;
    sqlite3_finalize(stmt);
    if (f.ws.open) wallet_sqlite_close(&f.ws);
    if (f.db) sqlite3_close(f.db);
    free_wallet_t(f.w); test_rm_rf(f.dir);
    return ok;
}

struct wfr_height_resolver { bool fail_second; int calls; };
static bool wfr_resolve_height(void *ctx, const uint8_t hash[32], int *height)
{
    struct wfr_height_resolver *r = ctx;
    r->calls++;
    if (r->fail_second && r->calls == 2) return false;
    if (hash[0] == 0x31) *height = 7;
    else if (hash[0] == 0x32) *height = 9;
    else return false;
    return true;
}

static bool wfr_height_state(sqlite3 *db, const char *key, int32_t value)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO node_state(key,value) VALUES(?,?)", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, &value, sizeof(value), SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s); return ok;
}

static int wfr_height_row(sqlite3 *db, int first)
{
    sqlite3_stmt *s = NULL; int height = -1;
    if (sqlite3_prepare_v2(db, "SELECT block_height FROM wallet_transactions WHERE substr(block_hash,1,1)=?", -1, &s, NULL) == SQLITE_OK) {
        uint8_t b = (uint8_t)first;
        if (sqlite3_bind_blob(s, 1, &b, 1, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
            height = sqlite3_column_int(s, 0);
    }
    sqlite3_finalize(s); return height;
}

static bool wfr_height_prepare(struct wfr_fixture *f)
{
    if (!wfr_cutover_setup(f, 0)) return false;
    f->w->map_wallet[0].hash_block.data[0] = 0x31;
    transaction_compute_hash(&f->w->map_wallet[0].tx);
    f->w->map_wallet[0].confirms = 8;
    f->w->map_wallet[1] = f->w->map_wallet[0];
    f->w->map_wallet[1].tx.lock_time = 1;
    transaction_compute_hash(&f->w->map_wallet[1].tx);
    f->w->map_wallet[1].hash_block.data[0] = 0x32;
    f->w->map_wallet[1].confirms = 9;
    f->w->map_wallet[2] = f->w->map_wallet[0];
    f->w->map_wallet[2].tx.lock_time = 2;
    transaction_compute_hash(&f->w->map_wallet[2].tx);
    memset(&f->w->map_wallet[2].hash_block, 0, sizeof(f->w->map_wallet[2].hash_block));
    f->w->map_wallet[2].confirms = 0;
    f->w->num_wallet_tx = 3;
    return wallet_sqlite_write_tx(&f->ws, &f->w->map_wallet[0]) &&
        wallet_sqlite_write_tx(&f->ws, &f->w->map_wallet[1]) &&
        wallet_sqlite_write_tx(&f->ws, &f->w->map_wallet[2]) &&
        wfr_height_state(f->db, "schema_version", 88) &&
        wfr_height_state(f->db, "schema_compat_floor", 87);
}

static bool wfr_height_legacy_reload(struct wfr_fixture *f)
{
    struct wallet *loaded = alloc_wallet_t();
    if (!loaded) return false;
    bool ok = wallet_sqlite_read_txs(&f->ws, loaded) && loaded->num_wallet_tx == 3 &&
        loaded->map_wallet[0].confirms == 8 && loaded->map_wallet[1].confirms == 9;
    free_wallet_t(loaded);
    return ok;
}

static bool wfr_height_ambiguous(struct wfr_fixture *f)
{
    if (sqlite3_exec(f->db, "UPDATE wallet_transactions SET block_hash=zeroblob(32) WHERE substr(block_hash,1,1)=x'32'", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(f->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    struct wfr_height_resolver resolver = {0};
    bool refused = !wallet_sqlite_activate_height_v2_in_open_tx(&f->ws, 20, wfr_resolve_height, &resolver);
    bool rolled = sqlite3_exec(f->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    return refused && rolled && wallet_sqlite_write_tx(&f->ws, &f->w->map_wallet[1]);
}

static bool wfr_height_restore_raw(struct wfr_fixture *f)
{
    struct byte_stream bs; stream_init(&bs, 256);
    bool ok = transaction_serialize(&f->w->map_wallet[1].tx, &bs);
    sqlite3_stmt *s = NULL;
    if (ok) ok = sqlite3_prepare_v2(f->db, "UPDATE wallet_transactions SET raw_tx=? WHERE txid=?", -1, &s, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_blob(s, 1, bs.data, (int)bs.size, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, f->w->map_wallet[1].tx.hash.data, 32, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(f->db) == 1;
    sqlite3_finalize(s); stream_free(&bs); return ok;
}

static bool wfr_height_reject_partial(struct wfr_fixture *f, struct wallet *loaded)
{
    if (sqlite3_exec(f->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool refused = !wallet_sqlite_read_txs(&f->ws, loaded) && loaded->num_wallet_tx == 0 &&
        !sqlite3_get_autocommit(f->db);
    bool rolled = sqlite3_exec(f->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    if (!refused || !rolled || sqlite3_exec(f->db, "UPDATE wallet_transactions SET raw_tx=x'00' WHERE substr(block_hash,1,1)=x'32'", NULL, NULL, NULL) != SQLITE_OK) return false;
    refused = !wallet_sqlite_read_txs(&f->ws, loaded) && loaded->num_wallet_tx == 0;
    return wfr_height_restore_raw(f) && refused;
}

static bool wfr_height_refusal(struct wfr_fixture *f)
{
    struct wfr_height_resolver resolver = {.fail_second = true};
    if (sqlite3_exec(f->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool refused = !wallet_sqlite_activate_height_v2_in_open_tx(&f->ws, 20, wfr_resolve_height, &resolver);
    bool rolled = sqlite3_exec(f->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    int ref = -1;
    return refused && rolled && resolver.calls == 2 && wfr_height_row(f->db, 0x31) == 8 &&
        wfr_height_row(f->db, 0x32) == 9 && wallet_sqlite_height_encoding(&f->ws, &ref) == WALLET_HEIGHT_LEGACY;
}

static bool wfr_height_activate(struct wfr_fixture *f)
{
    struct wfr_height_resolver resolver = {0};
    if (sqlite3_exec(f->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = wallet_sqlite_activate_height_v2_in_open_tx(&f->ws, 20, wfr_resolve_height, &resolver);
    int rc = sqlite3_exec(f->db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    return ok && rc == SQLITE_OK && resolver.calls == 2 &&
        wfr_height_row(f->db, 0x31) == 7 && wfr_height_row(f->db, 0x32) == 9;
}

static bool wfr_height_loaded_check(struct wfr_fixture *f, struct wallet *loaded)
{
    bool ok = wfr_height_reject_partial(f, loaded) && wallet_sqlite_read_txs(&f->ws, loaded) &&
        wallet_sqlite_read_scan_state_checked(&f->ws, loaded) == WALLET_SCAN_STATE_OK &&
        loaded->best_block_height == 20 && loaded->num_wallet_tx == 3 &&
        loaded->map_wallet[0].confirms == 14 && loaded->map_wallet[1].confirms == 12;
    if (ok) { wallet_advance_confirmations(loaded, 21); ok = wallet_sqlite_flush_transactions_r(&f->ws, loaded).ok; }
    return ok;
}

static bool wfr_height_reopen(struct wfr_fixture *f)
{
    if (sqlite3_exec(f->db, "UPDATE wallet_transactions SET block_height=NULL WHERE block_hash=zeroblob(32)", NULL, NULL, NULL) != SQLITE_OK) return false;
    wallet_sqlite_close(&f->ws); sqlite3_close(f->db); f->db = NULL;
    if (sqlite3_open(f->path, &f->db) != SQLITE_OK || !wallet_sqlite_open_r(&f->ws, f->db).ok) return false;
    struct wallet *loaded = alloc_wallet_t();
    if (!loaded) return false;
    bool ok = wfr_height_loaded_check(f, loaded);
    int reference = -1;
    if (ok) ok = wallet_sqlite_height_encoding(&f->ws, &reference) == WALLET_HEIGHT_V2 && reference == 21 &&
        wfr_height_row(f->db, 0x31) == 7 && wfr_height_row(f->db, 0x32) == 9;
    free_wallet_t(loaded);
    return ok;
}

struct wfr_release_fault { const char *name; bool denied; };
static int wfr_deny_snapshot_release(void *opaque, int action, const char *op,
                                     const char *name, const char *db, const char *trigger)
{
    (void)db; (void)trigger;
    struct wfr_release_fault *fault = opaque;
    if (!fault->denied && action == SQLITE_SAVEPOINT && op && name &&
        strcmp(op, "RELEASE") == 0 && strcmp(name, fault->name) == 0) {
        fault->denied = true;
        return SQLITE_DENY;
    }
    return SQLITE_OK;
}

static bool wfr_snapshot_fault_read(struct wfr_fixture *f, struct wallet *loaded, bool scan)
{
    struct wfr_release_fault fault = {.name = scan ? "wallet_scan_snapshot" : "wallet_v2_snapshot"};
    loaded->best_block_height = 123;
    if (sqlite3_set_authorizer(f->db, wfr_deny_snapshot_release, &fault) != SQLITE_OK) return false;
    bool refused = scan ? wallet_sqlite_read_scan_state_checked(&f->ws, loaded) == WALLET_SCAN_STATE_ERROR :
                          !wallet_sqlite_read_txs(&f->ws, loaded);
    bool cleared = sqlite3_set_authorizer(f->db, NULL, NULL) == SQLITE_OK;
    return cleared && refused && fault.denied && sqlite3_get_autocommit(f->db) &&
        loaded->best_block_height == 123 && loaded->num_wallet_tx == 0;
}

static bool wfr_snapshot_reopen_verify(struct wfr_fixture *f, struct wallet *loaded)
{
    wallet_sqlite_close(&f->ws);
    if (sqlite3_close(f->db) != SQLITE_OK) return false;
    f->db = NULL;
    if (sqlite3_open(f->path, &f->db) != SQLITE_OK || !wallet_sqlite_open_r(&f->ws, f->db).ok) return false;
    return wallet_sqlite_read_txs(&f->ws, loaded) &&
        wallet_sqlite_read_scan_state_checked(&f->ws, loaded) == WALLET_SCAN_STATE_OK &&
        loaded->best_block_height == 20 && loaded->num_wallet_tx == 3 &&
        loaded->map_wallet[0].confirms == 14 && loaded->map_wallet[1].confirms == 12;
}

static bool wfr_snapshot_release_case(bool scan)
{
    struct wfr_fixture f = {0};
    struct wallet *loaded = alloc_wallet_t();
    bool ok = loaded && wfr_height_prepare(&f) && wfr_height_activate(&f) &&
        wfr_snapshot_fault_read(&f, loaded, scan) && wfr_snapshot_reopen_verify(&f, loaded);
    if (f.ws.open) wallet_sqlite_close(&f.ws);
    if (f.db) sqlite3_close(f.db);
    free_wallet_t(loaded); free_wallet_t(f.w); test_rm_rf(f.dir);
    return ok;
}

static bool wfr_height_v2_fixture(void)
{
    struct wfr_fixture f = {0};
    bool ok = wfr_height_prepare(&f) && wfr_height_legacy_reload(&f) && wfr_height_ambiguous(&f) && wfr_height_refusal(&f) && wfr_height_activate(&f) && wfr_height_reopen(&f);
    if (ok) ok = sqlite3_exec(f.db, "DELETE FROM node_state WHERE key='wallet_height_encoding_v2'", NULL, NULL, NULL) == SQLITE_OK;
    int ref = 0;
    if (ok) ok = wallet_sqlite_height_encoding(&f.ws, &ref) == WALLET_HEIGHT_ERROR;
    if (f.ws.open) wallet_sqlite_close(&f.ws);
    if (f.db) sqlite3_close(f.db);
    free_wallet_t(f.w); test_rm_rf(f.dir);
    return ok;
}

static bool wfr_scan_checked_fixture(void)
{
    sqlite3 *db = open_flush_db(false);
    struct wallet_sqlite ws = {0};
    struct wallet *w = alloc_wallet_t();
    bool ok = db && w && wallet_sqlite_open_r(&ws, db).ok;
    if (ok) ok = wallet_sqlite_read_scan_state_checked(&ws, w) == WALLET_SCAN_STATE_ABSENT;
    if (ok) ok = sqlite3_exec(db, "INSERT INTO node_state(key,value) VALUES('wallet_scan_incomplete','from=invalid')", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) { w->best_block_height = 42; ok = wallet_sqlite_read_scan_state_checked(&ws, w) == WALLET_SCAN_STATE_ERROR && w->best_block_height == 42; }
    if (ok) ok = sqlite3_exec(db, "DELETE FROM node_state WHERE key='wallet_scan_incomplete'", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_write_scan_height(&ws, -1) && wallet_sqlite_read_scan_state_checked(&ws, w) == WALLET_SCAN_STATE_OK &&
        w->best_block_height == -1;
    if (ok) ok = sqlite3_exec(db, "DROP TABLE wallet_transactions", NULL, NULL, NULL) == SQLITE_OK &&
        !wallet_sqlite_read_txs(&ws, w);
    if (ws.open) wallet_sqlite_close(&ws);
    if (db) sqlite3_close(db);
    free_wallet_t(w);
    return ok;
}

static bool wfr_invalid_depth_refused(struct wallet_sqlite *ws, struct wallet *reader, const char *marker)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ws->db, "UPDATE node_state SET value=? WHERE key='wallet_scan_incomplete'",
                           -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(stmt, 1, marker, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(ws->db) == 1;
    if (sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    reader->best_block_height = 42;
    int floor = -1;
    struct wallet_cutover_binding binding;
    return ok && wallet_sqlite_read_scan_state_checked(ws, reader) == WALLET_SCAN_STATE_ERROR &&
        reader->best_block_height == 42 &&
        wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_MALFORMED &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_MALFORMED;
}

static bool wfr_unscanned_loaded(struct wallet_sqlite *ws, struct wallet *reader,
                                 const struct wallet_cutover_binding *expected)
{
    struct wallet_cutover_binding actual;
    int floor = -1;
    return wallet_sqlite_read_scan_state_checked(ws, reader) == WALLET_SCAN_STATE_OK &&
        reader->best_block_height == -1 && reader->scan_retry.pending && reader->scan_retry.from == 0 &&
        wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == 0 &&
        wallet_sqlite_cutover_read(ws, &actual) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(expected, &actual);
}

static bool wfr_unscanned_cutover_roundtrip(void)
{
    sqlite3 *db = open_flush_db(false);
    struct wallet_sqlite ws = {0};
    struct wallet *writer = alloc_wallet_t(), *reader = alloc_wallet_t();
    bool ok = db && writer && reader && wallet_sqlite_open_r(&ws, db).ok;
    if (ok) {
        writer->best_block_height = -1;
        writer->scan_retry.pending = true;
        writer->scan_retry.from = 0;
        snprintf(writer->scan_retry.blocker, sizeof(writer->scan_retry.blocker), "WALLET_CUTOVER_PENDING");
        struct wallet_cutover_binding expected = {.old_height = -1, .target_height = 3309900};
        ok = wallet_sqlite_cutover_prepare(&ws, writer, &expected) &&
            wfr_unscanned_loaded(&ws, reader, &expected);
    }
    if (ok) ok = wfr_invalid_depth_refused(&ws, reader, "from=0 depth=-2 since=0 blocker=WALLET_CUTOVER_PENDING");
    if (ok) ok = wfr_invalid_depth_refused(&ws, reader, "from=0 depth=bad since=0 blocker=WALLET_CUTOVER_PENDING");
    if (ws.open) wallet_sqlite_close(&ws);
    if (db) sqlite3_close(db);
    free_wallet_t(writer); free_wallet_t(reader);
    return ok;
}

struct wfr_tracked_ctx {
    struct db_wallet_utxo_cutover_delivery delivery;
    bool endpoint_ok;
    int mode;
};

static bool wfr_tracked_resolve(void *ctx, const uint8_t hash[32], int *height)
{
    (void)ctx;
    if (hash[0] == 0x31) *height = 7;
    else if (hash[0] == 0x32) *height = 9;
    else if (hash[0] == 9) *height = 10;
    else if (hash[0] == 2) *height = 20;
    else return false;
    return true;
}

static bool wfr_tracked_reference(void *ctx, int height, const uint8_t hash[32])
{
    (void)ctx;
    return (height == 10 && hash[0] == 9) || (height == 20 && hash[0] == 2);
}

static bool wfr_fail_tx_resolver(void *ctx, const uint8_t hash[32], int *height)
{
    return hash[0] != 0x31 && wfr_tracked_resolve(ctx, hash, height);
}
static bool wfr_stale_reference(void *ctx, int height, const uint8_t hash[32])
{
    int *calls = ctx;
    return (*calls)++ == 0 && wfr_tracked_reference(NULL, height, hash);
}
static bool wfr_fail_after_first_row(void *ctx, const uint8_t hash[32], int *height)
{
    int *seen = ctx;
    if (hash[0] == 0x31) (*seen)++;
    if (hash[0] == 0x32) return false;
    return wfr_tracked_resolve(NULL, hash, height);
}

static bool wfr_bound_legacy_intact(struct wfr_fixture *f)
{
    int reference = -1; struct wallet_cutover_binding out;
    return wallet_sqlite_height_encoding(&f->ws, &reference) == WALLET_HEIGHT_LEGACY &&
        wallet_sqlite_cutover_read(&f->ws, &out) == WALLET_CUTOVER_ABSENT &&
        wfr_height_row(f->db, 0x31) == 4 && f->w->map_wallet[0].confirms == 4 &&
        f->w->best_block_height == 10 && f->w->scan_retry.from == 5 &&
        f->w->scan_retry.since == 123 && !strcmp(f->w->scan_retry.blocker, "CUTOVER");
}

static bool wfr_bound_partial_rollback(struct wfr_fixture *f)
{
    if (sqlite3_exec(f->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    f->w->map_wallet[1] = f->w->map_wallet[0];
    f->w->map_wallet[1].tx.lock_time++;
    transaction_compute_hash(&f->w->map_wallet[1].tx);
    f->w->map_wallet[1].hash_block.data[0] = 0x32;
    f->w->map_wallet[1].confirms = 2; f->w->num_wallet_tx = 2;
    int seen = 0; const uint8_t reference[32] = {9};
    bool ok = wallet_sqlite_write_tx(&f->ws, &f->w->map_wallet[1]) &&
        !wallet_sqlite_cutover_prepare_bound(&f->ws, f->w, &f->b, 10, reference,
            wfr_fail_after_first_row, wfr_tracked_reference, &seen) && seen == 1 &&
        wfr_height_row(f->db, 0x31) == 4 && wfr_height_row(f->db, 0x32) == 2;
    if (sqlite3_exec(f->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) ok = false;
    memset(&f->w->map_wallet[1], 0, sizeof(f->w->map_wallet[1])); f->w->num_wallet_tx = 1;
    return ok && wfr_bound_legacy_intact(f);
}

static bool wfr_bound_prepare_failures(struct wfr_fixture *f)
{
    const uint8_t reference[32] = {9};
    if (!wfr_bound_partial_rollback(f)) return false;
    if (wallet_sqlite_cutover_prepare_bound_preserving_cursor(&f->ws, f->w, &f->b, 10, reference,
        wfr_fail_tx_resolver, wfr_tracked_reference, NULL) || !wfr_bound_legacy_intact(f)) return false;
    int calls = 0;
    if (wallet_sqlite_cutover_prepare_bound_preserving_cursor(&f->ws, f->w, &f->b, 10, reference,
        wfr_tracked_resolve, wfr_stale_reference, &calls) || !wfr_bound_legacy_intact(f)) return false;
    if (sqlite3_set_authorizer(f->db, wfr_deny_commit, NULL) != SQLITE_OK) return false;
    bool refused = !wallet_sqlite_cutover_prepare_bound_preserving_cursor(&f->ws, f->w, &f->b, 10, reference,
        wfr_tracked_resolve, wfr_tracked_reference, NULL);
    if (sqlite3_set_authorizer(f->db, NULL, NULL) != SQLITE_OK) return false;
    return refused && sqlite3_get_autocommit(f->db) && wfr_bound_legacy_intact(f);
}

static bool wfr_bound_prepared_reopen(const struct wfr_fixture *f)
{
    sqlite3 *db = NULL; struct wallet_sqlite ws = {0}; struct wallet *w = alloc_wallet_t();
    if (!w || sqlite3_open(f->path, &db) != SQLITE_OK) { free_wallet_t(w); if (db) sqlite3_close(db); return false; }
    bool ok = wallet_sqlite_open_r(&ws, db).ok && wallet_sqlite_read_txs(&ws, w) &&
        w->num_wallet_tx == 1 && w->best_block_height == 10 && w->map_wallet[0].confirms == 4;
    if (ws.open) wallet_sqlite_close(&ws);
    free_wallet_t(w);
    return sqlite3_close(db) == SQLITE_OK && ok;
}

static bool wfr_tracked_endpoint(void *ctx, int height, const uint8_t hash[32])
{
    struct wfr_tracked_ctx *c = ctx;
    return c->endpoint_ok && height == 20 && hash[0] == 2;
}

static bool wfr_tracked_holds(void *ctx, struct wallet *wallet, sqlite3 *db)
{
    (void)ctx;
    return wallet && db;
}

static bool wfr_tracked_project(void *ctx, struct node_db *db, struct wallet *wallet,
                                struct wallet_cutover_v2_plan *plan)
{
    struct wfr_tracked_ctx *c = ctx;
    if (!plan->count) return false;
    uint8_t script[1] = {0x51};
    struct db_wallet_utxo u = {.value = 10, .height = 7, .script = script, .script_len = sizeof(script)};
    memcpy(u.txid, wallet->map_wallet[plan->entries[0].slot].tx.hash.data, 32);
    u.address_hash[0] = 5;
    if (db_wallet_utxo_cutover_merge(db, &u, &c->delivery) != DB_UTXO_CUTOVER_OK) return false;
    wallet_cutover_v2_plan_finish_spends(plan);
    if (c->mode == 2) c->endpoint_ok = false;
    if (c->mode == 6) { struct key_id extra = {0}; extra.id.data[0] = 99;
        if (!keystore_add_watch_only_id(&wallet->keystore, &extra)) return false; }
    return c->mode != 1;
}

static bool wfr_tracked_prepare_fence(struct wfr_fixture *f, bool bound)
{
    const uint8_t reference[32] = {9};
    if (bound && !wallet_sqlite_write_tx(&f->ws, &f->w->map_wallet[0])) return false;
    if (!wallet_readiness_initialize(f->w, WALLET_READINESS_PENDING, true, 2)) return false;
    if (bound && !wfr_bound_prepare_failures(f)) return false;
    bool prepared = bound ? wallet_sqlite_cutover_prepare_bound_preserving_cursor(&f->ws, f->w, &f->b,
        10, reference, wfr_tracked_resolve, wfr_tracked_reference, NULL) : wallet_sqlite_cutover_prepare(&f->ws, f->w, &f->b);
    return prepared && (!bound || wfr_bound_prepared_reopen(f));
}

static bool wfr_tracked_prepare(struct wfr_fixture *f, struct node_db *ndb, bool bound)
{
    test_make_tmpdir(f->dir, sizeof(f->dir), "wallet", "tracked_cutover");
    snprintf(f->path, sizeof(f->path), "%s/node.db", f->dir);
    if (!node_db_open(ndb, f->path)) return false;
    f->db = ndb->db;
    if (!wallet_sqlite_open_r(&f->ws, f->db).ok || !(f->w = alloc_wallet_t())) return false;
    struct privkey key; struct pubkey pub;
    make_key(&key, &pub, 0x41);
    if (!keystore_add_key(&f->w->keystore, &key) || !wallet_sqlite_flush_r(&f->ws, f->w).ok) return false;
    f->b = (struct wallet_cutover_binding){.old_generation_present = true, .old_generation = 1,
        .old_height = 10, .target_height = 20};
    if (bound) f->b.old_height = 12;
    f->b.old_hash[0] = 1; f->b.target_hash[0] = 2; f->b.artifact_digest[0] = 3;
    if (bound) { f->b.history_identity_present = true;
        f->b.snapshot_whole_sha3[0] = 0x51; f->b.history_manifest_root[0] = 0x62; }
    f->w->scan_retry.pending = true; f->w->scan_retry.from = 5; f->w->scan_retry.since = 123;
    f->w->best_block_height = 10;
    snprintf(f->w->scan_retry.blocker, sizeof(f->w->scan_retry.blocker), "CUTOVER");
    seed_wallet_tx(f->w); transaction_compute_hash(&f->w->map_wallet[0].tx);
    f->w->map_wallet[0].hash_block.data[0] = 0x31; f->w->map_wallet[0].confirms = bound ? 4 : 8;
    f->w->num_wallet_tx = 1;
    if (!wfr_tracked_prepare_fence(f, bound)) return false;
    return wallet_scan_identity(f->w, f->scan_identity);
}

static bool wfr_bound_mismatches(struct wallet_sqlite *ws, const struct wallet_cutover_binding *expected)
{
    for (unsigned i = 0; i < 10; ++i) {
        struct wallet_cutover_binding stale = *expected, observed;
        switch (i) {
        case 0: stale.old_generation++; break;
        case 1: stale.old_height++; break;
        case 2: stale.old_hash[0] ^= 1; break;
        case 3: stale.target_height++; break;
        case 4: stale.target_hash[0] ^= 1; break;
        case 5: stale.artifact_digest[0] ^= 1; break;
        case 6: stale.snapshot_whole_sha3[0] ^= 1; break;
        case 7: stale.history_manifest_root[0] ^= 1; break;
        case 8: stale.old_generation_present = !stale.old_generation_present; break;
        case 9: stale.history_identity_present = false; break;
        }
        if (wallet_sqlite_cutover_authority_read(ws, &stale, &observed) != WALLET_CUTOVER_AUTH_MISMATCH) return false;
    }
    return true;
}
static bool wfr_bound_authority(struct wallet_sqlite *ws, const struct wallet_cutover_binding *expected,
                                bool success)
{
    struct wallet_cutover_binding observed;
    enum wallet_cutover_authority_status want = success ?
        (expected->history_identity_present ? WALLET_CUTOVER_AUTH_COMPLETED : WALLET_CUTOVER_AUTH_ABSENT) :
        WALLET_CUTOVER_AUTH_PENDING;
    enum wallet_cutover_authority_status status = wallet_sqlite_cutover_authority_read(ws, expected, &observed);
    if (status != want) return false;
    if (want == WALLET_CUTOVER_AUTH_ABSENT) return true;
    if (!wallet_cutover_binding_equal(expected, &observed)) return false;
    struct wallet_cutover_binding alias = *expected;
    if (wallet_sqlite_cutover_authority_read(ws, &alias, &alias) != want ||
        !wallet_cutover_binding_equal(expected, &alias)) return false;
    if (success) {
        if (!wfr_bound_mismatches(ws, expected)) return false;
        if (wallet_sqlite_cutover_authority_read(ws, NULL, &observed) != WALLET_CUTOVER_AUTH_MISMATCH) return false;
    }
    return true;
}
static bool wfr_bound_reopen(const struct wfr_fixture *f, bool success)
{
    sqlite3 *db = NULL; struct wallet_sqlite ws = {0};
    if (sqlite3_open(f->path, &db) != SQLITE_OK) { if (db) sqlite3_close(db); return false; }
    bool ok = wallet_sqlite_open_r(&ws, db).ok && wfr_bound_authority(&ws, &f->b, success);
    if (ws.open) wallet_sqlite_close(&ws);
    return sqlite3_close(db) == SQLITE_OK && ok;
}

static bool wfr_tracked_state(struct wfr_fixture *f, bool success)
{
    struct wallet_cutover_binding binding;
    struct wallet_readiness ready = wallet_readiness_get(f->w);
    enum wallet_cutover_status status = wallet_sqlite_cutover_read(&f->ws, &binding);
    int count = count_rows(f->db, "wallet_utxos");
    return wfr_bound_authority(&f->ws, &f->b, success) &&
        wfr_bound_reopen(f, success) &&
        status == (success ? WALLET_CUTOVER_ABSENT : WALLET_CUTOVER_PENDING) &&
        ready.state == (success ? WALLET_READINESS_READY : WALLET_READINESS_PENDING) &&
        f->w->best_block_height == (success ? 20 : 10) &&
        f->w->map_wallet[0].confirms == (success ? 14 : (f->b.history_identity_present ? 4 : 8)) && count == (success ? 1 : 0);
}

#ifndef _WIN32
struct wfr_tx_gate {
    struct node_db *db;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool held, release;
};

static void *wfr_tx_gate_worker(void *arg)
{
    struct wfr_tx_gate *g = arg;
    zcl_mutex_lock(&g->db->state_mutex);
    pthread_mutex_lock(&g->mutex);
    g->held = true; pthread_cond_signal(&g->cond);
    while (!g->release) pthread_cond_wait(&g->cond, &g->mutex);
    pthread_mutex_unlock(&g->mutex);
    zcl_mutex_unlock(&g->db->state_mutex);
    return NULL;
}

static bool wfr_tracked_contention(struct wfr_fixture *f, struct node_db *ndb,
    struct wallet_cutover_v2_request *r, struct wallet_cutover_v2_plan *plan)
{
    struct wfr_tx_gate g = {.db = ndb};
    if (pthread_mutex_init(&g.mutex, NULL) != 0) return false;
    if (pthread_cond_init(&g.cond, NULL) != 0) { pthread_mutex_destroy(&g.mutex); return false; }
    pthread_t thread;
    if (pthread_create(&thread, NULL, wfr_tx_gate_worker, &g) != 0) {
        pthread_cond_destroy(&g.cond); pthread_mutex_destroy(&g.mutex); return false;
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline); deadline.tv_sec += 5;
    pthread_mutex_lock(&g.mutex);
    while (!g.held && pthread_cond_timedwait(&g.cond, &g.mutex, &deadline) == 0) {}
    bool held = g.held;
    pthread_mutex_unlock(&g.mutex);
    struct zcl_result result = {0};
    if (held) result = wallet_sqlite_cutover_complete_v2_in_open_tx_r(&f->ws, ndb, f->w, r, plan);
    bool untouched = held && !result.ok && result.code == WSQL_TXN_BEGIN_FAIL && !sqlite3_get_autocommit(f->db);
    pthread_mutex_lock(&g.mutex); g.release = true; pthread_cond_signal(&g.cond); pthread_mutex_unlock(&g.mutex);
    (void)pthread_join(thread, NULL);
    pthread_cond_destroy(&g.cond); pthread_mutex_destroy(&g.mutex);
    return node_db_rollback(ndb) && untouched;
}
#endif

static void wfr_foreign_hook(void *record, void *ctx)
{
    (void)record;
    int *fired = ctx;
    (*fired)++;
}

static bool wfr_tracked_result(struct wfr_fixture *f, struct node_db *ndb,
    struct wfr_tracked_ctx *ctx, struct zcl_result result, int mode)
{
    bool success = mode == 0;
    bool ok = result.ok == success && sqlite3_get_autocommit(f->db) &&
        wfr_tracked_state(f, success) && ctx->delivery.committed == success;
    if (ok && !success)
        ok = node_db_begin_immediate(ndb) && node_db_commit(ndb) && !ctx->delivery.committed;
    return ok;
}

static bool wfr_foreign_finish(struct wfr_fixture *f, struct node_db *ndb,
                               struct zcl_result result, const int *fired)
{
    return !result.ok && result.code == WSQL_TXN_BEGIN_FAIL && !sqlite3_get_autocommit(f->db) &&
        ar_after_commit_pending() == 1 && node_db_commit(ndb) && *fired == 1;
}

static bool wfr_tracked_run(struct wfr_fixture *f, struct node_db *ndb,
    struct wfr_tracked_ctx *ctx, struct wallet_cutover_v2_plan *plan,
    struct wallet_cutover_v2_request *r, int mode)
{
    if (mode == 4) r->project = NULL;
    if (mode == 5) r->reference_height = -1;
    bool ok = node_db_begin_immediate(ndb);
    int foreign_fired = 0; uint8_t token = 1;
    if (ok && mode == 8) ok = ar_after_commit_enqueue(wfr_foreign_hook, &foreign_fired, &token, sizeof(token));
    if (ok && mode == 3) ok = sqlite3_set_authorizer(f->db, wfr_deny_commit, NULL) == SQLITE_OK;
    struct zcl_result result = {0};
    if (ok) {
#ifndef _WIN32
        if (mode == 7) ok = wfr_tracked_contention(f, ndb, r, plan);
        else
#endif
            result = wallet_sqlite_cutover_complete_v2_in_open_tx_r(&f->ws, ndb, f->w, r, plan);
    }
    (void)sqlite3_set_authorizer(f->db, NULL, NULL);
    if (ok && mode == 8) ok = wfr_foreign_finish(f, ndb, result, &foreign_fired);
    return ok && wfr_tracked_result(f, ndb, ctx, result, mode);
}

static bool wfr_bound_completion_corruption(struct wfr_fixture *f)
{
    struct wallet_cutover_binding out;
    if (sqlite3_exec(f->db, "SAVEPOINT completed_corrupt", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_exec(f->db,
        "UPDATE node_state SET value=substr(value,1,114) WHERE key='wallet_cutover_completed'", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_authority_read(&f->ws, &f->b, &out) == WALLET_CUTOVER_AUTH_MALFORMED;
    return sqlite3_exec(f->db, "ROLLBACK TO completed_corrupt; RELEASE completed_corrupt", NULL, NULL, NULL) == SQLITE_OK && ok;
}
static bool wfr_bound_completion_contradiction(struct wfr_fixture *f)
{
    struct wallet_cutover_binding out;
    if (sqlite3_exec(f->db, "SAVEPOINT completed_mixed", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_exec(f->db,
        "INSERT INTO node_state(key,value) SELECT 'wallet_cutover_binding',value FROM node_state WHERE key='wallet_cutover_completed'",
        NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_authority_read(&f->ws, &f->b, &out) == WALLET_CUTOVER_AUTH_MALFORMED;
    return sqlite3_exec(f->db, "ROLLBACK TO completed_mixed; RELEASE completed_mixed", NULL, NULL, NULL) == SQLITE_OK && ok;
}

static bool wfr_bound_completion_floor(struct wfr_fixture *f)
{
    struct wallet_cutover_binding out;
    if (sqlite3_exec(f->db, "SAVEPOINT completed_floor", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_exec(f->db, "DELETE FROM node_state WHERE key='schema_compat_floor'", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_authority_read(&f->ws, &f->b, &out) == WALLET_CUTOVER_AUTH_MALFORMED;
    return sqlite3_exec(f->db, "ROLLBACK TO completed_floor; RELEASE completed_floor", NULL, NULL, NULL) == SQLITE_OK && ok;
}

static bool wfr_next_pending_rollback(struct wfr_fixture *f, const struct wallet_cutover_binding *next)
{
    struct wallet_cutover_binding out;
    if (sqlite3_exec(f->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = (next->history_identity_present ? wallet_sqlite_cutover_prepare_bound(&f->ws, f->w, next,
        20, f->b.target_hash, wfr_tracked_resolve, wfr_tracked_reference, NULL) : wallet_sqlite_cutover_prepare(&f->ws, f->w, next)) &&
        wallet_sqlite_cutover_authority_read(&f->ws, next, &out) == WALLET_CUTOVER_AUTH_PENDING;
    if (sqlite3_exec(f->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) return false;
    return ok && wallet_sqlite_cutover_authority_read(&f->ws, &f->b, &out) == WALLET_CUTOVER_AUTH_COMPLETED;
}

static bool wfr_bound_next_pending(struct wfr_fixture *f)
{
    struct wallet_cutover_binding next = f->b, out;
    int reference = -1;
    if (wallet_sqlite_height_encoding(&f->ws, &reference) != WALLET_HEIGHT_V2 || reference != 20) return false;
    next.target_hash[0] ^= 1;
    f->w->scan_retry.pending = true; f->w->scan_retry.from = 5; f->w->scan_retry.since = 123;
    snprintf(f->w->scan_retry.blocker, sizeof(f->w->scan_retry.blocker), "CUTOVER");
    if (!wfr_next_pending_rollback(f, &next) ||
        wallet_sqlite_height_encoding(&f->ws, &reference) != WALLET_HEIGHT_V2 || reference != 20) return false;
    next.history_identity_present = false;
    memset(next.snapshot_whole_sha3, 0, sizeof(next.snapshot_whole_sha3));
    memset(next.history_manifest_root, 0, sizeof(next.history_manifest_root));
    if (!wfr_next_pending_rollback(f, &next)) return false;
    if (sqlite3_exec(f->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = wallet_sqlite_cutover_prepare(&f->ws, f->w, &next) &&
        wallet_sqlite_cutover_authority_read(&f->ws, &next, &out) == WALLET_CUTOVER_AUTH_PENDING;
    if (sqlite3_exec(f->db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) return false;
    return ok && wallet_sqlite_cutover_authority_read(&f->ws, &f->b, &out) == WALLET_CUTOVER_AUTH_MISMATCH;
}

static bool wfr_bound_legacy_refusal(struct wfr_fixture *f)
{
    if (sqlite3_exec(f->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    struct zcl_result r = wallet_sqlite_cutover_complete_flush_in_open_tx_r(
        &f->ws, f->w, &f->b, true, 2, 20, f->scan_identity);
    return !r.ok && sqlite3_get_autocommit(f->db) && wfr_bound_authority(&f->ws, &f->b, false);
}

static bool wfr_tracked_one(int mode, bool bound)
{
    struct wfr_fixture f = {0}; struct node_db ndb = {0};
    struct wfr_tracked_ctx ctx = {.endpoint_ok = true, .mode = mode};
    struct wallet_cutover_v2_plan plan = {0};
    bool ok = wfr_tracked_prepare(&f, &ndb, bound) && wallet_cutover_v2_plan_init(&plan, 2);
    struct wallet_cutover_v2_request r = {.binding = &f.b, .generation_present = true, .generation = 2,
        .reference_height = 20, .resolve = wfr_tracked_resolve, .endpoint_current = wfr_tracked_endpoint,
        .chain_ctx = &ctx, .holds_valid = wfr_tracked_holds, .holds_ctx = &ctx,
        .project = wfr_tracked_project, .projection_ctx = &ctx};
    r.reference_hash[0] = 2; memcpy(r.scan_identity, f.scan_identity, 32);
    if (ok && bound) ok = wfr_bound_legacy_refusal(&f);
    if (ok) ok = wfr_tracked_run(&f, &ndb, &ctx, &plan, &r, mode);
    if (ok && bound && mode == 0) ok = wfr_bound_completion_corruption(&f) && wfr_bound_completion_contradiction(&f) && wfr_bound_completion_floor(&f) && wfr_bound_next_pending(&f);
    db_wallet_utxo_cutover_delivery_clear(&ctx.delivery);
    wallet_cutover_v2_plan_free(&plan);
    if (f.ws.open) wallet_sqlite_close(&f.ws);
    if (ndb.open) node_db_close(&ndb);
    free_wallet_t(f.w); test_rm_rf(f.dir);
    return ok;
}

static bool wfr_tracked_fixture(void)
{
    for (int mode = 0; mode < 7; mode++) if (!wfr_tracked_one(mode, true)) { printf("bound tracked mode %d failed\n", mode); return false; }
    for (int mode = 0; mode < 7; mode++) if (!wfr_tracked_one(mode, false)) { printf("tracked mode %d failed\n", mode); return false; }
#ifndef _WIN32
    if (!wfr_tracked_one(7, false)) { printf("tracked contention failed\n"); return false; }
    if (!wfr_tracked_one(8, false)) { printf("tracked foreign hook failed\n"); return false; }
#endif
    return true;
}

struct wfr_projection_ctx {
    struct db_wallet_utxo_cutover_delivery delivery;
    struct db_wallet_utxo_cutover_projection projection;
    uint8_t active[32], inactive[32], funding[32];
    bool unknown;
    int mode;
};

static enum db_wallet_cutover_tx_class wfr_projection_class(void *opaque, const uint8_t id[32])
{
    struct wfr_projection_ctx *ctx = opaque;
    if (!memcmp(id, ctx->active, 32)) return ctx->unknown ? DB_CUTOVER_TX_UNKNOWN : DB_CUTOVER_TX_ACTIVE;
    if (!memcmp(id, ctx->inactive, 32)) return DB_CUTOVER_TX_INACTIVE;
    return DB_CUTOVER_TX_UNKNOWN;
}

static enum db_cutover_coin_verdict wfr_projection_coin(void *opaque, const uint8_t id[32],
    uint32_t vout, const struct tx_out *out, int height, bool coinbase)
{
    struct wfr_projection_ctx *ctx = opaque;
    if (memcmp(id, ctx->funding, 32) || vout > 2 || out->value != (int64_t)(100 * (vout + 1)) ||
        height != 7 || coinbase) return DB_CUTOVER_COIN_UNKNOWN;
    if (ctx->mode == 4 && vout == 2) return DB_CUTOVER_COIN_UNKNOWN;
    if ((ctx->mode == 3 || ctx->mode == 6) && vout == 1) return DB_CUTOVER_COIN_SPENT;
    return DB_CUTOVER_COIN_UNSPENT;
}

static bool wfr_projection_add_tx(struct wallet *w, struct transaction *tx, bool confirmed)
{
    struct wallet_tx row = {.tx = *tx, .used = true, .time_received = 123};
    if (confirmed) { row.hash_block.data[0] = 0x31; row.confirms = 8; }
    return wallet_add_to_wallet(w, &row);
}

static bool wfr_projection_transactions(struct wfr_fixture *f, struct wfr_projection_ctx *ctx)
{
    transaction_free(&f->w->map_wallet[0].tx);
    memset(&f->w->map_wallet[0], 0, sizeof(f->w->map_wallet[0])); f->w->num_wallet_tx = 0;
    struct key_id watch = {0}; watch.id.data[0] = 0x77;
    if (!keystore_add_watch_only_id(&f->w->keystore, &watch) ||
        !wallet_sqlite_write_watch_only(&f->ws, watch.id.data, "")) return false;
    struct tx_destination mine = {.type = DEST_KEY_ID, .id.key = f->w->keystore.keys[0].keyid};
    struct tx_destination watched = {.type = DEST_KEY_ID, .id.key = watch};
    struct transaction funding, active, inactive;
    transaction_init(&funding); transaction_init(&active); transaction_init(&inactive);
    bool ok = transaction_alloc(&funding, 1, 3) && transaction_alloc(&active, 1, 0) && transaction_alloc(&inactive, 1, 0);
    if (ok) {
        funding.vin[0].prevout.hash.data[0] = 0x42; funding.vin[0].prevout.n = 0;
        funding.vout[0].value = 100; funding.vout[1].value = 200; funding.vout[2].value = 300;
        script_for_destination(&funding.vout[0].script_pub_key, &mine);
        script_for_destination(&funding.vout[1].script_pub_key, &mine);
        script_for_destination(&funding.vout[2].script_pub_key, &watched);
        transaction_compute_hash(&funding);
        memcpy(ctx->funding, funding.hash.data, 32);
        active.vin[0].prevout.hash = funding.hash; active.vin[0].prevout.n = 0; active.lock_time = 1;
        inactive.vin[0].prevout.hash = funding.hash; inactive.vin[0].prevout.n = 1; inactive.lock_time = 2;
        transaction_compute_hash(&active); transaction_compute_hash(&inactive);
        memcpy(ctx->active, active.hash.data, 32); memcpy(ctx->inactive, inactive.hash.data, 32);
        ok = wfr_projection_add_tx(f->w, &funding, true) && wfr_projection_add_tx(f->w, &active, false) &&
             wfr_projection_add_tx(f->w, &inactive, false) && wallet_scan_identity(f->w, f->scan_identity);
    }
    transaction_free(&funding); transaction_free(&active); transaction_free(&inactive);
    return ok;
}

static bool wfr_projection_seed_hold(struct wfr_fixture *f, struct node_db *ndb,
                                     const struct wfr_projection_ctx *ctx, bool rogue)
{
    const struct wallet_tx *funding = &f->w->map_wallet[0];
    const struct tx_out *out = &funding->tx.vout[0];
    struct db_wallet_utxo row = {.vout = 0, .value = out->value, .height = 6,
        .script = (uint8_t *)out->script_pub_key.data, .script_len = out->script_pub_key.size};
    memcpy(row.txid, funding->tx.hash.data, 32);
    memcpy(row.address_hash, f->w->keystore.keys[0].keyid.id.data, 20);
    if (!db_wallet_utxo_save(ndb, &row) || !db_wallet_utxo_mark_spent(ndb, row.txid, 0, ctx->active, 0)) return false;
    if (!rogue) return true;
    row.txid[0] ^= 0x40;
    return db_wallet_utxo_save(ndb, &row);
}

static bool wfr_projection_rows(struct node_db *ndb, const struct wfr_fixture *f,
                                const struct wfr_projection_ctx *ctx)
{
    struct db_wallet_utxo first = {0}, second = {0}, watched = {0};
    const uint8_t *id = f->w->map_wallet[0].tx.hash.data;
    bool ok = db_wallet_utxo_find(ndb, id, 0, &first) && db_wallet_utxo_find(ndb, id, 1, &second) &&
        !db_wallet_utxo_find(ndb, id, 2, &watched) && first.height == 7 && first.is_spent &&
        !memcmp(first.spent_txid, ctx->active, 32) && second.height == 7 &&
        (ctx->mode == 6 ? (second.is_spent && !memcmp(second.spent_txid, ctx->inactive, 32)) : !second.is_spent);
    db_wallet_utxo_free(&first); db_wallet_utxo_free(&second); db_wallet_utxo_free(&watched);
    return ok;
}

static bool wfr_projection_ram_result(struct wfr_fixture *f, bool success, int mode)
{
    return wallet_readiness_get(f->w).state == (success ? WALLET_READINESS_READY : WALLET_READINESS_PENDING) &&
        f->w->best_block_height == (success ? 20 : 10) && f->w->map_wallet[0].confirms == (success ? 14 : 8) &&
        wallet_is_outpoint_spent(f->w, &f->w->map_wallet[0].tx.hash, 0) == success &&
        wallet_is_outpoint_spent(f->w, &f->w->map_wallet[0].tx.hash, 1) == (!success || mode == 6);
}

static bool wfr_projection_result(struct wfr_fixture *f, struct node_db *ndb,
    struct wfr_projection_ctx *ctx, struct zcl_result result, int mode)
{
    bool success = mode == 0 || mode == 6;
    bool ok = result.ok == success && sqlite3_get_autocommit(f->db) &&
        ctx->delivery.committed == success && wfr_projection_ram_result(f, success, mode);
    if (ok && success) ok = wfr_projection_rows(ndb, f, ctx);
    if (ok && !success) ok = count_rows(f->db, "wallet_utxos") == (mode == 2 ? 2 : 1);
    return ok;
}

static bool wfr_projection_one(int mode)
{
    struct wfr_fixture f = {0}; struct node_db ndb = {0};
    struct wfr_tracked_ctx auth = {.endpoint_ok = true};
    struct wfr_projection_ctx ctx = {.unknown = mode == 1, .mode = mode};
    struct wallet_cutover_v2_plan plan = {0};
    bool ok = wfr_tracked_prepare(&f, &ndb, false) && wfr_projection_transactions(&f, &ctx);
    if (ok) {
        wallet_mark_outpoint_spent(f.w, &f.w->map_wallet[0].tx.hash, 1);
        if (mode == 6) { f.w->map_wallet[2].hash_block.data[0] = 0x32; f.w->map_wallet[2].confirms = 4; }
        ok = wfr_projection_seed_hold(&f, &ndb, &ctx, mode == 2) && wallet_cutover_v2_plan_init(&plan, 3);
    }
    ctx.projection = (struct db_wallet_utxo_cutover_projection){.delivery = &ctx.delivery,
        .classify_unconfirmed = wfr_projection_class, .classify_ctx = &ctx,
        .reference_coin = wfr_projection_coin, .reference_coin_ctx = &ctx};
    struct wallet_cutover_v2_request r = {.binding = &f.b, .generation_present = true, .generation = 2,
        .reference_height = 20, .resolve = wfr_tracked_resolve, .endpoint_current = wfr_tracked_endpoint,
        .chain_ctx = &auth, .holds_valid = wfr_tracked_holds, .holds_ctx = &auth,
        .project = db_wallet_utxo_cutover_project, .projection_ctx = &ctx.projection};
    r.reference_hash[0] = 2; memcpy(r.scan_identity, f.scan_identity, 32);
    if (ok) ok = node_db_begin_immediate(&ndb);
    struct zcl_result result = {0};
    if (ok) result = wallet_sqlite_cutover_complete_v2_in_open_tx_r(&f.ws, &ndb, f.w, &r, &plan);
    if (ok) ok = wfr_projection_result(&f, &ndb, &ctx, result, mode);
    db_wallet_utxo_cutover_delivery_clear(&ctx.delivery); wallet_cutover_v2_plan_free(&plan);
    if (f.ws.open) wallet_sqlite_close(&f.ws);
    if (ndb.open) node_db_close(&ndb);
    free_wallet_t(f.w); test_rm_rf(f.dir); return ok;
}

static bool wfr_projection_fixture(void)
{
    for (int mode = 0; mode < 5; mode++)
        if (!wfr_projection_one(mode)) { printf("projection mode %d failed\\n", mode); return false; }
    if (!wfr_projection_one(6)) { printf("projection confirmed spend failed\n"); return false; }
    return true;
}

struct wfr_publish_fixture {
    struct wfr_fixture f;
    struct node_db db;
    struct main_state ms;
    bool ms_initialized, progress_open;
    struct block_index blocks[21];
    struct uint256 hashes[21];
    struct wpr *relay;
    struct wpr_pending_guard guard;
    struct coins_kv_read_snapshot *snapshot;
    struct coins_kv_read_snapshot_info info;
    struct wallet_cutover_v2_plan plan;
    struct db_wallet_utxo_cutover_delivery delivery;
    struct wallet_rpc_context ctx;
    struct boot_cutover_replay replay;
};

static bool wfr_publish_chain(struct wfr_publish_fixture *x)
{
    main_state_init(&x->ms);
    x->ms_initialized = true;
    for (int i = 0; i <= 20; i++) {
        x->hashes[i].data[0] = (uint8_t)(0x40 + i);
        if (i == 7) x->hashes[i].data[0] = 0x31;
        if (i == 20) x->hashes[i].data[0] = 2;
        struct block_index *p = &x->blocks[i];
        block_index_init(p); p->nHeight = i; p->hashBlock = x->hashes[i];
        p->phashBlock = &p->hashBlock;
        if (i) p->pprev = &x->blocks[i - 1];
        if (!block_map_insert(&x->ms.map_block_index, &x->hashes[i], p) ||
            !active_chain_install_tip_slot(&x->ms.chain_active, p)) return false;
    }
    return true;
}

static bool wfr_publish_wallet(struct wfr_publish_fixture *x)
{
    struct wallet *w = x->f.w;
    transaction_free(&w->map_wallet[0].tx);
    memset(&w->map_wallet[0], 0, sizeof(w->map_wallet[0])); w->num_wallet_tx = 0;
    struct transaction tx; transaction_init(&tx);
    if (!transaction_alloc(&tx, 1, 1)) return false;
    tx.vin[0].prevout.hash.data[0] = 0x42; tx.vin[0].prevout.n = 0;
    tx.vout[0].value = 123;
    struct tx_destination mine = {.type = DEST_KEY_ID, .id.key = w->keystore.keys[0].keyid};
    script_for_destination(&tx.vout[0].script_pub_key, &mine);
    transaction_compute_hash(&tx);
    bool ok = wfr_projection_add_tx(w, &tx, true) && wallet_scan_identity(w, x->f.scan_identity);
    transaction_free(&tx);
    return ok;
}

static bool wfr_publish_pool_known(struct coins_kv_read_snapshot *snapshot)
{
    int64_t sprout = -1, sapling = -1;
    bool found = false;
    return coins_kv_read_snapshot_shielded_pool(snapshot, 20, &sprout, &sapling, &found) &&
        found && sprout == 0 && sapling == 0;
}

static bool wfr_publish_coins(struct wfr_publish_fixture *x, bool mismatch)
{
    if (!progress_store_open(x->f.dir)) return false;
    x->progress_open = true;
    sqlite3 *db = progress_store_db();
    const struct transaction *tx = &x->f.w->map_wallet[0].tx;
    const struct tx_out *out = &tx->vout[0];
    /* This synthetic chain has no shielded transfers at its reference tip. */
    bool ok = coins_kv_ensure_schema(db) && shielded_pool_kv_ensure_schema(db) &&
        shielded_pool_kv_put(db, 20, 0, 0) &&
        coins_kv_add(db, tx->hash.data, 0, out->value + (mismatch ? 1 : 0), 7, false,
                     out->script_pub_key.data, out->script_pub_key.size) &&
        coins_kv_mark_migration_complete(db) &&
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_set_applied_height_in_tx(db, 21) &&
        coins_kv_bump_authority_generation_in_tx(db) && coins_kv_bump_authority_generation_in_tx(db) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) { (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); return false; }
    x->snapshot = coins_kv_read_snapshot_open(&x->info);
    return x->snapshot && wfr_publish_pool_known(x->snapshot);
}

static bool wfr_publish_guard(struct wfr_publish_fixture *x, bool mismatch)
{
    x->relay = calloc(1, sizeof(*x->relay));
    if (!x->relay) return false;
    wpr_init(x->relay);
    struct wpr_env env = {.wallet = x->f.w, .node_db = mismatch ? NULL : &x->db,
                          .main_state = &x->ms, .datadir = x->f.dir};
    wpr_configure(x->relay, WPR_MODE_PUBLIC, &env);
    struct wpr_pending_record record; size_t count = 0;
    enum wpr_pending_read_status status = wpr_pending_proof_begin(x->relay, &x->guard, &record, 1, &count);
    return (status == WPR_PENDING_ABSENT || status == WPR_PENDING_OK) && count == 0;
}

static bool wfr_publish_setup(struct wfr_publish_fixture *x, int mode)
{
    if (!wfr_tracked_prepare(&x->f, &x->db, false) || !wfr_publish_chain(x) ||
        !wfr_publish_wallet(x) || !wfr_publish_coins(x, mode == 2) ||
        !wallet_cutover_v2_plan_init(&x->plan, 1) || !wfr_publish_guard(x, mode == 3)) return false;
    x->ctx = (struct wallet_rpc_context){.wallet = x->f.w, .wallet_db = &x->f.ws,
        .node_db = &x->db, .main_state = &x->ms, .datadir = x->f.dir};
    x->replay.ctx = &x->ctx; x->replay.binding = x->f.b;
    x->replay.readiness = wallet_readiness_get(x->f.w);
    x->replay.endpoint.height = 20; x->replay.endpoint.hash = x->hashes[20];
    x->replay.endpoint.root = x->blocks[20].hashFinalSaplingRoot;
    x->replay.phase = BOOT_CUTOVER_DONE;
    memcpy(x->replay.identity, x->f.scan_identity, 32);
    if (mode == 1) x->info.applied_height--;
    return true;
}

static void wfr_publish_close(struct wfr_publish_fixture *x)
{
    if (x->guard.relay) wpr_pending_proof_end(&x->guard);
    db_wallet_utxo_cutover_delivery_clear(&x->delivery);
    wallet_cutover_v2_plan_free(&x->plan);
    if (x->snapshot) coins_kv_read_snapshot_abort(x->snapshot);
    if (x->progress_open) progress_store_close();
    if (x->relay) { wpr_free(x->relay); free(x->relay); }
    if (x->ms_initialized) main_state_free(&x->ms);
    if (x->f.ws.open) wallet_sqlite_close(&x->f.ws);
    if (x->db.open) node_db_close(&x->db);
    free_wallet_t(x->f.w);
    test_rm_rf(x->f.dir);
}

static bool wfr_publish_value(struct wfr_publish_fixture *x)
{
    struct db_wallet_utxo row = {0};
    const struct transaction *tx = &x->f.w->map_wallet[0].tx;
    bool ok = db_wallet_utxo_find(&x->db, tx->hash.data, 0, &row) &&
        row.value == 123 && row.height == 7 && !row.is_spent && !row.is_coinbase &&
        row.script_len == tx->vout[0].script_pub_key.size &&
        !memcmp(row.script, tx->vout[0].script_pub_key.data, row.script_len) &&
        x->f.w->best_block_height == 20;
    db_wallet_utxo_free(&row);
    return ok;
}

static bool wfr_publish_one(int mode)
{
    struct wfr_publish_fixture *x = calloc(1, sizeof(*x));
    if (!x) return false;
    bool ok = wfr_publish_setup(x, mode);
    if (!ok) printf("publish mode %d setup failed\n", mode);
    bool committed = ok && boot_wallet_cutover_publish(&x->replay, &x->guard,
        x->snapshot, &x->info, &x->plan, &x->delivery);
    struct wallet_cutover_binding binding;
    bool expected = mode == 0;
    ok = ok && committed == expected && sqlite3_get_autocommit(x->db.db) &&
        wallet_readiness_get(x->f.w).state == (expected ? WALLET_READINESS_READY : WALLET_READINESS_PENDING) &&
        wallet_sqlite_cutover_read(&x->f.ws, &binding) == (expected ? WALLET_CUTOVER_ABSENT : WALLET_CUTOVER_PENDING) &&
        count_rows(x->db.db, "wallet_utxos") == (expected ? 1 : 0);
    if (ok && expected) ok = wfr_publish_value(x);
    wfr_publish_close(x); free(x);
    return ok;
}

static bool wfr_publish_fixture(void)
{
    for (int mode = 0; mode < 4; mode++)
        if (!wfr_publish_one(mode)) { printf("publish mode %d failed\n", mode); return false; }
    return true;
}

static int test_cutover_flush_atomic(void)
{
    int failures = 0;
    TEST("cutover flush: disk reopen preserves fence on failures and keys/scripts always") {
        ASSERT(wfr_fee_survives_cutover());
        ASSERT(wfr_height_v2_fixture());
        ASSERT(wfr_snapshot_release_case(false));
        ASSERT(wfr_snapshot_release_case(true));
        ASSERT(wfr_scan_checked_fixture());
        ASSERT(wfr_unscanned_cutover_roundtrip());
        ASSERT(wfr_tracked_fixture());
        ASSERT(wfr_projection_fixture());
        ASSERT(wfr_publish_fixture());
        for (int fault=0; fault <= 15; fault++) {
            if (!wfr_cutover_one(fault)) { printf("case %d ", fault); ASSERT(false); }
        }
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
    failures += test_cutover_flush_atomic();
    return failures;
}
