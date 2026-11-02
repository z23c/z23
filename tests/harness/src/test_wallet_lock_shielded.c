/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_lock_shielded: locking an encrypted wallet cleanses the Sapling
 * seed, master key and every spending key, keeps the viewing material, and
 * never lets a locked wallet mint a replacement seed.
 *
 * Every fixture is an in-memory SQLite database with throwaway keys. Nothing
 * here touches a datadir, a running node, or a real wallet. The expected
 * secrets are held in the fixture, so each check compares live memory with
 * what the wallet stored. */

#include "test/test_core.h"
#include "config/boot_cursor_state.h"
#include "config/boot_internal.h"
#include "config/boot_wallet_phrase.h"
#include "chain/chain.h"
#include "controllers/wallet_scan.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "wallet/bip44.h"
#include "wallet/hd_keychain.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shielded_internal.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "sapling/constants.h"
#include "sapling/sapling.h"
#include "sapling/zip32.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <pthread.h>
#ifdef __linux__
#include <unistd.h>
#endif
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WLS_PASS "wls-fixture-passphrase"
#define WLS_KEYS 3
#define WLS_VALUE ((uint64_t)125000000)
#define WLS_DUMP_CAP 65536
#define WLS_JOIN_SECONDS 10

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

struct wls_fixture {
    sqlite3 *db;
    struct wallet_sqlite ws;
    struct wallet *w;
    struct sapling_key_entry orig[WLS_KEYS];
    uint8_t seed[32];
    struct privkey tkey;
    struct pubkey tpub;
    struct rpc_table *tbl;
    char saved_iters[32];
    bool had_iters;
};

/* ── Small helpers ───────────────────────────────────────────────── */

/* The two readings below exist only on the locked-boot build; they are the
 * single place the group touches fields introduced by the lock change. */
static size_t wls_unscannable(const struct wallet *w)
{
    return w->sapling_keys.num_unscannable;
}

static int wls_sealed_rows(void)
{
    return wallet_sqlite_read_keys_locked_count();
}

static bool wls_locked(void)
{
    return !wallet_lock_is_unlocked();
}

/* The autolock timer is registry-owned (NULL out_tid), so a bounded join_all
 * reaps it. Joining orders the timer's wipe before every secret inspection
 * that follows; false means a registered thread outlived the bound. */
static bool wls_join_timers(void)
{
    return thread_registry_join_all(WLS_JOIN_SECONDS) == 0;
}

static bool wls_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i] != 0)
            return false;
    return true;
}

static struct wallet *wls_alloc_wallet(void)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "wls_wallet");
    if (w)
        wallet_init(w);
    return w;
}

static void wls_free_wallet(struct wallet *w)
{
    if (!w)
        return;
    wallet_free(w);
    free(w);
}

static const char *wls_str(const struct json_value *v)
{
    const char *s = json_get_str(v);
    return s ? s : "";
}

/* True when the live Sapling keystore holds no secret at all. */
static bool wls_secrets_absent(const struct wallet *w)
{
    const struct sapling_keystore *sks = &w->sapling_keys;
    if (sks->has_seed || !wls_zero(sks->seed, sizeof(sks->seed)) ||
        !wls_zero(&sks->master_xsk, sizeof(sks->master_xsk)))
        return false;
    for (size_t i = 0; i < sks->num_keys; i++)
        if (!wls_zero(&sks->keys[i].xsk, sizeof(sks->keys[i].xsk)))
            return false;
    return true;
}

/* The transparent key is owned but holds no private key: sealed. */
static bool wls_transparent_sealed(struct wallet *w, const struct pubkey *pub,
                                   size_t want_entries)
{
    struct key_id kid = pubkey_get_id(pub);
    struct privkey got;
    privkey_init(&got);
    return w->keystore.num_keys == want_entries &&
           keystore_have_key(&w->keystore, &kid) &&
           !keystore_get_key(&w->keystore, &kid, &got) &&
           wls_zero(got.vch, sizeof(got.vch));
}

/* The transparent key is owned and its private key is resident. */
static bool wls_transparent_open(struct wallet *w, const struct pubkey *pub)
{
    struct key_id kid = pubkey_get_id(pub);
    struct privkey got;
    privkey_init(&got);
    bool ok = keystore_get_key(&w->keystore, &kid, &got) && got.fValid;
    memory_cleanse(&got, sizeof(got));
    return ok;
}

/* True when every viewing field of every entry equals the fixture's. */
static bool wls_viewing_intact(const struct wls_fixture *f,
                               const struct wallet *w, size_t want_keys)
{
    const struct sapling_keystore *sks = &w->sapling_keys;
    if (sks->num_keys != want_keys)
        return false;
    for (size_t i = 0; i < want_keys; i++) {
        const struct sapling_key_entry *e = sapling_keystore_find_by_ivk(
            sks, f->orig[i].ivk);
        if (!e || memcmp(e->xfvk.fvk.ak, f->orig[i].xfvk.fvk.ak, 32) != 0 ||
            memcmp(e->xfvk.fvk.nk, f->orig[i].xfvk.fvk.nk, 32) != 0 ||
            memcmp(e->diversifier, f->orig[i].diversifier, 11) != 0 ||
            memcmp(e->pk_d, f->orig[i].pk_d, 32) != 0)
            return false;
    }
    return true;
}

/* True when every spending key and the seed equal the fixture's. */
static bool wls_secrets_restored(const struct wls_fixture *f,
                                 const struct wallet *w)
{
    const struct sapling_keystore *sks = &w->sapling_keys;
    if (!sks->has_seed || memcmp(sks->seed, f->seed, 32) != 0)
        return false;
    for (size_t i = 0; i < WLS_KEYS; i++) {
        const struct sapling_key_entry *e = sapling_keystore_find_by_ivk(
            sks, f->orig[i].ivk);
        if (!e || memcmp(&e->xsk, &f->orig[i].xsk, sizeof(e->xsk)) != 0)
            return false;
    }
    return true;
}

/* No ivk appears twice. */
static bool wls_no_duplicates(const struct wallet *w)
{
    const struct sapling_keystore *sks = &w->sapling_keys;
    for (size_t i = 0; i < sks->num_keys; i++)
        for (size_t j = i + 1; j < sks->num_keys; j++)
            if (memcmp(sks->keys[i].ivk, sks->keys[j].ivk, 32) == 0)
                return false;
    return true;
}

/* Concatenate the seed row and every Sapling key row, in key order. */
static size_t wls_dump_rows(sqlite3 *db, uint8_t *buf, size_t cap)
{
    static const char *const queries[] = {
        "SELECT seed,next_child FROM wallet_seed ORDER BY id",
        "SELECT ivk,xsk,xfvk,diversifier,pk_d,child_index "
        "FROM wallet_sapling_keys ORDER BY ivk",
        "SELECT pubkey_hash,pubkey,privkey FROM wallet_keys "
        "ORDER BY pubkey_hash",
        "SELECT wrapped_dek FROM wallet_key_encryption",
    };
    size_t used = 0;
    for (size_t q = 0; q < sizeof(queries) / sizeof(queries[0]); q++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, queries[q], -1, &st, NULL) != SQLITE_OK)
            return 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            for (int c = 0; c < sqlite3_column_count(st); c++) {
                int n = sqlite3_column_bytes(st, c);
                const void *p = sqlite3_column_blob(st, c);
                if (p && n > 0 && used + (size_t)n <= cap) {
                    memcpy(buf + used, p, (size_t)n);
                    used += (size_t)n;
                }
            }
        }
        sqlite3_finalize(st);
    }
    return used;
}

/* ── Fixture ─────────────────────────────────────────────────────── */

static bool wls_open_db(struct wls_fixture *f)
{
    if (sqlite3_open(":memory:", &f->db) != SQLITE_OK)
        return false;
    if (sqlite3_exec(f->db, k_schema, NULL, NULL, NULL) != SQLITE_OK)
        return false;
    return wallet_sqlite_open_r(&f->ws, f->db).ok;
}

/* Build WLS_KEYS Sapling entries from a fixed seed and store them, with the
 * seed and optionally one transparent key, under the registered state. */
static bool wls_store_wallet(struct wls_fixture *f, bool with_transparent)
{
    struct wallet *src = wls_alloc_wallet();
    if (!src)
        return false;
    memset(f->seed, 0x37, sizeof(f->seed));
    bool ok = sapling_keystore_set_seed(&src->sapling_keys, f->seed);
    for (size_t i = 0; ok && i < WLS_KEYS; i++) {
        uint8_t d[ZC_DIVERSIFIER_SIZE], pk[32];
        ok = sapling_keystore_new_address(&src->sapling_keys, d, pk);
    }
    ok = ok && src->sapling_keys.num_keys == WLS_KEYS &&
         wallet_sqlite_write_sapling_seed(&f->ws, f->seed);
    for (size_t i = 0; ok && i < WLS_KEYS; i++) {
        f->orig[i] = src->sapling_keys.keys[i];
        ok = wallet_sqlite_write_sapling_key(&f->ws, f->orig[i].child_index,
                                             &f->orig[i]);
    }
    if (ok && with_transparent) {
        privkey_init(&f->tkey);
        memset(f->tkey.vch, 0x4c, 32);
        f->tkey.vch[1] = 0x99;
        f->tkey.fValid = true;
        f->tkey.fCompressed = true;
        ok = privkey_get_pubkey(&f->tkey, &f->tpub) &&
             wallet_sqlite_write_key_r(&f->ws, &f->tpub, &f->tkey).ok;
    }
    wls_free_wallet(src);
    return ok;
}

static void wls_register_rpc(struct wls_fixture *f)
{
    f->tbl = zcl_calloc(1, sizeof(*f->tbl), "wls_rpc_table");
    if (!f->tbl)
        return;
    rpc_table_init(f->tbl);
    register_wallet_rpc_commands(f->tbl);
    char status[32];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();
}

/* Open the database and store the wallet. `encrypted` wraps every secret
 * under WLS_PASS; otherwise the rows are plaintext. */
static bool wls_provision(struct wls_fixture *f, bool encrypted,
                          bool with_transparent)
{
    memset(f, 0, sizeof(*f));
    const char *old = getenv("ZCL_WALLET_KDF_ITERS");
    f->had_iters = old != NULL;
    if (old)
        snprintf(f->saved_iters, sizeof(f->saved_iters), "%s", old);
    char iters[16];
    snprintf(iters, sizeof(iters), "%u", (unsigned)WKS_MIN_ITERS);
    setenv("ZCL_WALLET_KDF_ITERS", iters, 1);

    wallet_lock_reset_for_test();
    if (encrypted &&
        !wallet_lock_unlock(NULL, NULL, WLS_PASS).ok)
        return false;
    if (!wls_open_db(f) || !wls_store_wallet(f, with_transparent))
        return false;
    wls_register_rpc(f);
    return f->tbl != NULL;
}

/* A new process: load the stored wallet under the current lock state. */
static bool wls_boot(struct wls_fixture *f)
{
    wls_free_wallet(f->w);
    f->w = wls_alloc_wallet();
    if (!f->w)
        return false;
    bool ok = wallet_sqlite_read_keys_r(&f->ws, f->w).ok;
    ok = wallet_sqlite_read_sapling_keys(&f->ws, f->w) && ok;
    rpc_wallet_set_state(f->w, NULL, NULL, &f->ws, NULL, NULL);
    return ok;
}

/* Restart without a passphrase, as the node does with none configured. */
static bool wls_boot_locked(struct wls_fixture *f)
{
    wallet_lock_reset_for_test();
    return wls_boot(f);
}

static void wls_teardown(struct wls_fixture *f)
{
    wls_free_wallet(f->w);
    f->w = NULL;
    free(f->tbl);
    f->tbl = NULL;
    wallet_sqlite_close(&f->ws);
    if (f->db)
        sqlite3_close(f->db);
    f->db = NULL;
    wallet_lock_reset_for_test();
    if (f->had_iters)
        setenv("ZCL_WALLET_KDF_ITERS", f->saved_iters, 1);
    else
        unsetenv("ZCL_WALLET_KDF_ITERS");
}

/* ── Notes ───────────────────────────────────────────────────────── */

/* Encrypt a note of WLS_VALUE to fixture entry `idx`. */
static bool wls_build_tx(struct transaction *tx, const struct wls_fixture *f,
                         size_t idx)
{
    uint8_t ovk[32];
    memset(ovk, 0x5a, sizeof(ovk));
    uint8_t cv[32], cm[32], epk[32];
    uint8_t enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE];
    uint8_t out[ZC_SAPLING_OUTCIPHERTEXT_SIZE];
    uint8_t proof[GROTH_PROOF_SIZE];
    memset(proof, 0, sizeof(proof));
    transaction_init(tx);
    if (!sapling_build_output_description(ovk, f->orig[idx].diversifier,
                                          f->orig[idx].pk_d, WLS_VALUE, NULL,
                                          cv, cm, epk, enc, out, proof, NULL))
        return false;
    tx->version = 4;
    tx->overwintered = true;
    tx->value_balance = -(int64_t)WLS_VALUE;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "wls_output");
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return false;
    }
    tx->num_shielded_output = 1;
    struct output_description *od = &tx->v_shielded_output[0];
    memcpy(od->cv.data, cv, 32);
    memcpy(od->cm.data, cm, 32);
    memcpy(od->ephemeral_key.data, epk, 32);
    memcpy(od->enc_ciphertext, enc, sizeof(enc));
    memcpy(od->out_ciphertext, out, sizeof(out));
    memcpy(od->zkproof, proof, sizeof(proof));
    return true;
}

/* Receive a note for entry `idx`; returns how many notes were found. */
static int wls_receive(struct wls_fixture *f, size_t idx, uint8_t tag)
{
    struct transaction tx;
    if (!wls_build_tx(&tx, f, idx))
        return -1;
    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    txid.data[0] = tag;
    int found = wallet_try_sapling_decrypt(f->w, &tx, &txid);
    transaction_free(&tx);
    return found;
}

/* The nullifier the spending key gives the note, at the position-0
 * placeholder the receive path stores. */
static bool wls_expected_nf(const struct wls_fixture *f, size_t idx,
                            const struct sapling_received_note *n,
                            uint8_t nf[32])
{
    uint8_t ak[32], nk[32];
    sapling_ask_to_ak(f->orig[idx].xsk.expsk.ask, ak);
    sapling_nsk_to_nk(f->orig[idx].xsk.expsk.nsk, nk);
    return sapling_compute_nf(n->diversifier, n->pk_d, n->value, n->rcm, ak,
                              nk, 0, nf);
}

/* ── RPC ─────────────────────────────────────────────────────────── */

static void wls_rpc(struct wls_fixture *f, const char *method,
                    const char *arg, struct json_value *result)
{
    struct json_value params, value;
    json_init(&params);
    json_set_array(&params);
    if (arg) {
        json_init(&value);
        json_set_str(&value, arg);
        (void)json_push_back(&params, &value);
        json_free(&value);
    }
    json_init(result);
    (void)rpc_table_execute(f->tbl, method, &params, result);
    json_free(&params);
}

static bool wls_address(const struct wls_fixture *f, size_t idx, char *out,
                        size_t out_size)
{
    const struct chain_params *cp = chain_params_get();
    return sapling_encode_payment_address(
        f->orig[idx].diversifier, f->orig[idx].pk_d,
        cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], out, out_size);
}

static bool wls_rpc_refused_as_locked(struct wls_fixture *f,
                                      const char *method, const char *arg)
{
    struct json_value r;
    wls_rpc(f, method, arg, &r);
    const char *s = wls_str(&r);
    bool locked = strstr(s, "locked") != NULL &&
                  strstr(s, "secret-extended-key") == NULL;
    json_free(&r);
    return locked;
}

/* ── Tests ───────────────────────────────────────────────────────── */

static int test_lock_cleanses_memory(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: lock cleanses seed, master key and every xsk") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(!wls_zero(&f.w->sapling_keys.master_xsk,
                         sizeof(f.w->sapling_keys.master_xsk)));

        wallet_lock_lock(f.w);
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(wls_viewing_intact(&f, f.w, WLS_KEYS));
        for (size_t i = 0; i < WLS_KEYS; i++)
            ASSERT(sapling_keystore_find_by_address(
                &f.w->sapling_keys, f.orig[i].diversifier, f.orig[i].pk_d));
        ASSERT(wls_transparent_sealed(f.w, &f.tpub, 1));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_timeout_and_refusal_paths_cleanse(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: timeout and refused-timeout locks cleanse") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        ASSERT(wls_secrets_restored(&f, f.w));

        /* A refused timeout locks before it refuses. */
        ASSERT(!wallet_lock_arm_timeout(f.w, 0).ok);
        ASSERT(wls_secrets_absent(f.w));

        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(wallet_lock_arm_timeout(f.w, 1).ok);
        struct timespec nap = { .tv_sec = 2, .tv_nsec = 500000000L };
        while (nanosleep(&nap, &nap) != 0) { /* retry interrupted sleep */ }
        ASSERT(wls_join_timers());
        ASSERT(wls_locked());
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(wls_viewing_intact(&f, f.w, WLS_KEYS));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_unlock_cycles_are_idempotent(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: lock/unlock cycles keep keys and balance") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(wls_receive(&f, 1, 0x71) == 1);
        ASSERT(wallet_get_sapling_balance(f.w) == (int64_t)WLS_VALUE);
        for (int cycle = 0; cycle < 20; cycle++) {
            wallet_lock_lock(f.w);
            ASSERT(wls_secrets_absent(f.w));
            ASSERT(wls_transparent_sealed(f.w, &f.tpub, 1));
            ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
            ASSERT(wallet_get_sapling_balance(f.w) == (int64_t)WLS_VALUE);
            ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
            ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
            ASSERT(wls_no_duplicates(f.w));
            ASSERT(wls_secrets_restored(&f, f.w));
            ASSERT(wls_transparent_open(f.w, &f.tpub));
            ASSERT(wls_viewing_intact(&f, f.w, WLS_KEYS));
            ASSERT(wallet_get_sapling_balance(f.w) == (int64_t)WLS_VALUE);
        }
        {
            uint8_t d[ZC_DIVERSIFIER_SIZE], pk[32];
            ASSERT(sapling_keystore_new_address(&f.w->sapling_keys, d, pk));
            ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS + 1);
        }
        ASSERT(f.w->num_sapling_notes == 1);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_unlock_alone_does_not_duplicate(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: repeated unlock of a loaded wallet adds no entries") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        for (int i = 0; i < 3; i++) {
            ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
            ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
            ASSERT(wls_no_duplicates(f.w));
        }
        struct json_value r;
        wls_rpc(&f, "z_listaddresses", NULL, &r);
        ASSERT(json_size(&r) == WLS_KEYS);
        json_free(&r);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_exports_refuse_while_locked(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: every key export refuses while locked") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        char zaddr[128], taddr[64];
        ASSERT(wls_address(&f, 0, zaddr, sizeof(zaddr)));
        ASSERT(wallet_pubkey_to_addr(&f.tpub, taddr, sizeof(taddr)));

        struct json_value r;
        wls_rpc(&f, "z_exportkey", zaddr, &r);
        ASSERT(strncmp(wls_str(&r), "secret-extended-key-", 20) == 0);
        json_free(&r);
        wls_rpc(&f, "dumpprivkey", taddr, &r);
        ASSERT(wls_str(&r)[0] != '\0' && strstr(wls_str(&r), "locked") == NULL);
        json_free(&r);

        wallet_lock_lock(f.w);
        ASSERT(wls_rpc_refused_as_locked(&f, "z_exportkey", zaddr));
        ASSERT(wls_rpc_refused_as_locked(&f, "z_exportviewingkey", zaddr));
        ASSERT(wls_rpc_refused_as_locked(&f, "dumpprivkey", taddr));
        ASSERT(wls_secrets_absent(f.w));

        /* The same refusal after a restart with no passphrase. */
        ASSERT(wls_boot_locked(&f));
        ASSERT(wls_rpc_refused_as_locked(&f, "z_exportkey", zaddr));
        ASSERT(wls_rpc_refused_as_locked(&f, "z_exportviewingkey", zaddr));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* Count the mutations a locked wallet should refuse that succeeded. */
static int wls_locked_mutations_that_succeed(struct wls_fixture *f)
{
    struct wallet *w = f->w;
    int ok = 0;
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk[32];
    uint8_t other[32];
    memset(other, 0xee, sizeof(other));
    struct zip32_xsk foreign;
    zip32_xsk_master(&foreign, other, sizeof(other));
    char addr[128];
    struct pubkey fresh;

    ok += sapling_keystore_new_address(&w->sapling_keys, d, pk);
    ok += sapling_keystore_generate_seed(&w->sapling_keys);
    ok += sapling_keystore_set_seed(&w->sapling_keys, other);
    ok += sapling_keystore_import_xsk(&w->sapling_keys, &foreign);
    ok += wallet_get_new_address(w, addr, sizeof(addr));
    ok += wallet_top_up_key_pool(w, 5);
    ok += wallet_generate_new_key(w, &fresh);
    memory_cleanse(&foreign, sizeof(foreign));

    struct json_value r;
    wls_rpc(f, "z_getnewaddress", NULL, &r);
    ok += strncmp(wls_str(&r), "zs", 2) == 0;
    json_free(&r);
    boot_wallet_adopt_seed_if_it_governs(w);
    return ok;
}

static int test_locked_wallet_never_replaces_the_seed(void)
{
    int failures = 0;
    struct wls_fixture f;
    static uint8_t before[WLS_DUMP_CAP], after[WLS_DUMP_CAP];
    TEST("wallet_lock_shielded: locked wallet cannot mint or replace a seed") {
        ASSERT(wls_provision(&f, true, true));
        size_t n_before = wls_dump_rows(f.db, before, sizeof(before));
        ASSERT(n_before > 0);

        /* Locked in-process. */
        ASSERT(wls_boot(&f));
        wallet_lock_lock(f.w);
        ASSERT(wls_locked_mutations_that_succeed(&f) == 0);
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        (void)wallet_sqlite_flush_r(&f.ws, f.w);
        ASSERT(wls_dump_rows(f.db, after, sizeof(after)) == n_before);
        ASSERT(memcmp(before, after, n_before) == 0);

        /* Locked at boot. */
        ASSERT(wls_boot_locked(&f));
        ASSERT(wls_locked_mutations_that_succeed(&f) == 0);
        ASSERT(!f.w->sapling_keys.has_seed);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        (void)wallet_sqlite_flush_r(&f.ws, f.w);
        ASSERT(wls_dump_rows(f.db, after, sizeof(after)) == n_before);
        ASSERT(memcmp(before, after, n_before) == 0);

        /* The stored seed still opens with the passphrase. */
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wls_secrets_restored(&f, f.w));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_locked_boot_scans_and_computes_nullifiers(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: locked boot finds a note and its nullifier") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot_locked(&f));
        ASSERT(wls_transparent_sealed(f.w, &f.tpub, 1));
        ASSERT(wls_sealed_rows() == 1);
        ASSERT(wls_locked());
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(wls_viewing_intact(&f, f.w, WLS_KEYS));

        ASSERT(wls_receive(&f, 2, 0x72) == 1);
        ASSERT(f.w->num_sapling_notes == 1);
        ASSERT(wallet_get_sapling_balance(f.w) == (int64_t)WLS_VALUE);
        uint8_t nf[32];
        ASSERT(wls_expected_nf(&f, 2, &f.w->sapling_notes[0], nf));
        ASSERT(memcmp(nf, f.w->sapling_notes[0].nf, 32) == 0);

        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(f.w->keystore.num_keys == 1);
        ASSERT(wls_transparent_open(f.w, &f.tpub));
        ASSERT(wallet_get_sapling_balance(f.w) == (int64_t)WLS_VALUE);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_row_without_viewing_key_is_reported(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a row with no stored xfvk is reported") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(sqlite3_exec(f.db,
            "UPDATE wallet_sapling_keys SET xfvk=NULL WHERE child_index=1",
            NULL, NULL, NULL) == SQLITE_OK);
        ASSERT(wls_boot_locked(&f));
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS - 1);
        ASSERT(wls_unscannable(f.w) == 1);
        ASSERT(wls_receive(&f, 1, 0x73) == 0);
        ASSERT(wls_receive(&f, 0, 0x74) == 1);

        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(wls_unscannable(f.w) == 0);
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(wls_receive(&f, 1, 0x75) == 1);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wrong_passphrase_keeps_shielded_wallet_locked(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: wrong passphrase leaves a shielded-only wallet locked") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot_locked(&f));
        ASSERT(!wallet_lock_unlock(f.w, &f.ws, "not-the-passphrase").ok);
        ASSERT(wls_locked());
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wls_secrets_restored(&f, f.w));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* While the unlock reads the Sapling rows the wallet must not report unlocked. */
struct wls_unlock_probe {
    struct wls_fixture *f;
    int reads;
    int saw_unlocked;
};

static int wls_probe_unlocked_during_reload(void *ctx)
{
    struct wls_unlock_probe *p = ctx;
    if (!sqlite3_stmt_busy(p->f->ws.stmt_zkey_read))
        return 0;
    p->reads++;
    if (wallet_lock_is_unlocked() || !wls_locked())
        p->saw_unlocked++;
    return 0;
}

static int test_wallet_is_not_unlocked_before_its_keys_are_loaded(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a wallet reports locked until an unlock has loaded its keys") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot_locked(&f));
        struct wls_unlock_probe p = { .f = &f };
        sqlite3_progress_handler(f.db, 1, wls_probe_unlocked_during_reload, &p);
        struct zcl_result u = wallet_lock_unlock(f.w, &f.ws, WLS_PASS);
        sqlite3_progress_handler(f.db, 0, NULL, NULL);
        ASSERT(u.ok);
        ASSERT(p.reads > 0);
        ASSERT(p.saw_unlocked == 0);
        ASSERT(wallet_lock_is_unlocked() && !wls_locked());
        ASSERT(wls_secrets_restored(&f, f.w));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lock_during_send_cannot_sign_with_wiped_key(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a send that meets the lock refuses") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        const struct sapling_key_entry *key = sapling_keystore_find_by_address(
            &f.w->sapling_keys, f.orig[0].diversifier, f.orig[0].pk_d);
        ASSERT(key);

        uint8_t zd[1][11], zp[1][32], zm[1][512];
        int64_t za[1] = { 1000 };
        bool zh[1] = { false };
        memcpy(zd[0], f.orig[1].diversifier, 11);
        memcpy(zp[0], f.orig[1].pk_d, 32);
        memset(zm, 0, sizeof(zm));
        struct wallet_rpc_context *ctx = wallet_rpc_context_current();
        const struct chain_params *cp = chain_params_get();
        struct json_value r;

        /* Unlocked: the send gets past the key and stops at the missing node
         * database. */
        json_init(&r);
        ASSERT(!z_sendmany_shielded(ctx, cp, key, 1000, NULL, NULL, 0,
                                    (const uint8_t (*)[11])zd,
                                    (const uint8_t (*)[32])zp, za,
                                    (const uint8_t (*)[512])zm, zh, 1, 0, NULL,
                                    &r));
        ASSERT(strstr(wls_str(&r), "locked") == NULL);
        json_free(&r);

        /* The lock fires while the caller still holds the keystore pointer. */
        wallet_lock_lock(f.w);
        json_init(&r);
        ASSERT(!z_sendmany_shielded(ctx, cp, key, 1000, NULL, NULL, 0,
                                    (const uint8_t (*)[11])zd,
                                    (const uint8_t (*)[32])zp, za,
                                    (const uint8_t (*)[512])zm, zh, 1, 0, NULL,
                                    &r));
        ASSERT(strstr(wls_str(&r), "locked") != NULL);
        json_free(&r);
        ASSERT(wls_secrets_absent(f.w));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_plaintext_wallet_is_unchanged(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a plaintext wallet behaves as before") {
        ASSERT(wls_provision(&f, false, false));
        ASSERT(wls_boot(&f));
        ASSERT(!wallet_lock_encrypted_at_rest());
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(wls_unscannable(f.w) == 0);

        wallet_lock_lock(f.w);
        ASSERT(wallet_lock_is_unlocked());
        ASSERT(wls_secrets_restored(&f, f.w));

        uint8_t d[ZC_DIVERSIFIER_SIZE], pk[32];
        ASSERT(sapling_keystore_new_address(&f.w->sapling_keys, d, pk));
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS + 1);
        char zaddr[128];
        ASSERT(wls_address(&f, 0, zaddr, sizeof(zaddr)));
        struct json_value r;
        wls_rpc(&f, "z_exportkey", zaddr, &r);
        ASSERT(strncmp(wls_str(&r), "secret-extended-key-", 20) == 0);
        json_free(&r);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Sealed boot, HD, read errors, wrong passphrase, races ───────── */

static bool wls_hd_key(const uint8_t seed[32], uint32_t index,
                       struct privkey *key, struct pubkey *pub)
{
    struct ext_key master;
    privkey_init(key);
    bool ok = hd_master_from_seed(&master, seed, 32) &&
              bip44_derive_keypair(&master, key, pub, 0, BIP44_EXTERNAL,
                                   index);
    memory_cleanse(&master, sizeof(master));
    return ok;
}

static bool wls_seed_projection(struct node_db *ndb, const struct pubkey *pub)
{
    static const uint8_t raw_tx[2] = { 0x01, 0x02 };
    static const uint8_t script[3] = { 0x76, 0xa9, 0x14 };
    struct key_id kid = pubkey_get_id(pub);
    struct db_wallet_tx tx;
    struct db_wallet_utxo utxo;
    memset(&tx, 0, sizeof(tx));
    memset(&utxo, 0, sizeof(utxo));
    memset(tx.txid, 0x61, sizeof(tx.txid));
    tx.raw_tx = (uint8_t *)raw_tx;
    tx.raw_tx_len = sizeof(raw_tx);
    tx.time_received = 1;
    memcpy(utxo.txid, tx.txid, sizeof(utxo.txid));
    memcpy(utxo.address_hash, kid.id.data, 20);
    utxo.value = 777;
    utxo.script = (uint8_t *)script;
    utxo.script_len = sizeof(script);
    utxo.height = 1;
    return db_wallet_tx_save(ndb, &tx) && db_wallet_utxo_save(ndb, &utxo);
}

static int test_sealed_boot_keeps_wallet_records(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a sealed boot keeps the wallet records") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        uint64_t fp_open = wallet_scan_keyset_fp(f.w);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, ":memory:"));
        ASSERT(wls_seed_projection(&ndb, &f.tpub));
        ASSERT(node_db_state_set_int(&ndb, BOOT_CUR_WALLET, 5));
        ASSERT(node_db_state_set_int(&ndb, BOOT_CUR_WALLET_KS,
                                     (int64_t)fp_open));

        ASSERT(wls_boot_locked(&f));
        /* Sealed is not a changed key set. */
        ASSERT(wallet_scan_keyset_fp(f.w) == fp_open);
        struct active_chain chain;
        active_chain_init(&chain);
        ASSERT(boot_cursor_scan_wallet(&ndb, &chain, f.w, "/nonexistent", 5)
               == 0);
        active_chain_free(&chain);
        ASSERT(db_wallet_tx_count(&ndb) == 1);
        ASSERT(db_wallet_utxo_balance(&ndb) == 777);
        int64_t cursor = -1, fp = 0;
        ASSERT(node_db_state_get_int(&ndb, BOOT_CUR_WALLET, &cursor));
        ASSERT(node_db_state_get_int(&ndb, BOOT_CUR_WALLET_KS, &fp));
        ASSERT(cursor == 5 && (uint64_t)fp == fp_open);

        /* The output script still resolves to a key the wallet owns, so a
         * receipt arriving while sealed is recorded. */
        struct key_id kid = pubkey_get_id(&f.tpub);
        ASSERT(keystore_have_key(&f.w->keystore, &kid));
        node_db_close(&ndb);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hd_master_follows_lock_and_unlock(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: the HD master is cleansed and restored") {
        ASSERT(wls_provision(&f, true, false));
        struct privkey k0, k1;
        struct pubkey p0, p1, fresh;
        ASSERT(wls_hd_key(f.seed, 0, &k0, &p0) && wls_hd_key(f.seed, 1, &k1, &p1));
        ASSERT(wallet_sqlite_write_key_r(&f.ws, &p0, &k0).ok);
        ASSERT(wls_boot(&f));
        boot_wallet_adopt_seed_if_it_governs(f.w);
        ASSERT(wallet_has_hd(f.w) && f.w->master_key.key.fValid);

        wallet_lock_lock(f.w);
        ASSERT(wls_zero(&f.w->master_key, sizeof(f.w->master_key)));
        ASSERT(!wallet_generate_new_key(f.w, &fresh));
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(f.w->master_key.key.fValid);
        ASSERT(wallet_generate_new_key(f.w, &fresh));
        ASSERT(pubkey_get_id(&fresh).id.data[0] == pubkey_get_id(&p1).id.data[0]);
        ASSERT(memcmp(pubkey_get_id(&fresh).id.data,
                      pubkey_get_id(&p1).id.data, 20) == 0);
        memory_cleanse(&k0, sizeof(k0));
        memory_cleanse(&k1, sizeof(k1));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_unlock_after_locked_boot_adopts_the_seed(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: unlock after a locked boot derives from the phrase") {
        ASSERT(wls_provision(&f, true, false));
        struct privkey k0, k1;
        struct pubkey p0, p1, fresh;
        ASSERT(wls_hd_key(f.seed, 0, &k0, &p0) && wls_hd_key(f.seed, 1, &k1, &p1));
        ASSERT(wallet_sqlite_write_key_r(&f.ws, &p0, &k0).ok);

        ASSERT(wls_boot_locked(&f));
        boot_wallet_adopt_seed_if_it_governs(f.w);
        ASSERT(!wallet_has_hd(f.w));
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wallet_has_hd(f.w));
        ASSERT(wallet_generate_new_key(f.w, &fresh));
        ASSERT(memcmp(pubkey_get_id(&fresh).id.data,
                      pubkey_get_id(&p1).id.data, 20) == 0);
        memory_cleanse(&k0, sizeof(k0));
        memory_cleanse(&k1, sizeof(k1));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int wls_seed_read_busy(void *ctx)
{
    struct wallet_sqlite *ws = ctx;
    return sqlite3_stmt_busy(ws->stmt_seed_read) ? 1 : 0;
}

static int test_seed_read_error_never_reads_as_absent(void)
{
    int failures = 0;
    struct wls_fixture f;
    static uint8_t before[WLS_DUMP_CAP], after[WLS_DUMP_CAP];
    TEST("wallet_lock_shielded: a seed read error keeps the wallet locked") {
        ASSERT(wls_provision(&f, true, true));
        size_t n_before = wls_dump_rows(f.db, before, sizeof(before));
        ASSERT(wls_boot(&f));
        wallet_lock_lock(f.w);

        uint8_t seed[32];
        sqlite3_progress_handler(f.db, 1, wls_seed_read_busy, &f.ws);
        ASSERT(wallet_sqlite_sapling_seed_state(&f.ws, seed) ==
               WALLET_SEED_UNREADABLE);
        struct zcl_result u = wallet_lock_unlock(f.w, &f.ws, WLS_PASS);
        sqlite3_progress_handler(f.db, 0, NULL, NULL);
        ASSERT(!u.ok);
        ASSERT(wls_locked());
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(wls_locked_mutations_that_succeed(&f) == 0);
        (void)wallet_sqlite_flush_r(&f.ws, f.w);
        ASSERT(wls_dump_rows(f.db, after, sizeof(after)) == n_before);
        ASSERT(memcmp(before, after, n_before) == 0);

        /* The writer is the second line: it never stores a different seed. */
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        uint8_t other[32];
        memset(other, 0x55, sizeof(other));
        ASSERT(!wallet_sqlite_write_sapling_seed(&f.ws, other));
        ASSERT(wls_dump_rows(f.db, after, sizeof(after)) == n_before);
        ASSERT(memcmp(before, after, n_before) == 0);
        /* The same seed is accepted (re-wrapped under a fresh salt). */
        ASSERT(wallet_sqlite_write_sapling_seed(&f.ws, f.seed));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static bool wls_foreign_key_string(char *out, size_t cap, uint8_t tag)
{
    uint8_t material[32];
    memset(material, tag, sizeof(material));
    struct zip32_xsk xsk;
    zip32_xsk_master(&xsk, material, sizeof(material));
    const struct chain_params *cp = chain_params_get();
    bool ok = sapling_encode_extended_spending_key(
        &xsk, cp->bech32HRPs[BECH32_SAPLING_EXTENDED_SPEND_KEY], out, cap);
    memory_cleanse(&xsk, sizeof(xsk));
    return ok;
}

static int test_wrong_passphrase_while_unlocked_changes_nothing(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a wrong passphrase leaves an unlocked wallet intact") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(!wallet_lock_unlock(f.w, &f.ws, "typo-passphrase").ok);
        ASSERT(wallet_lock_is_unlocked());
        ASSERT(wls_transparent_open(f.w, &f.tpub));
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(!f.w->sapling_keys.locked);

        char key[512];
        struct json_value r;
        ASSERT(wls_foreign_key_string(key, sizeof(key), 0x21));
        wls_rpc(&f, "z_importkey", key, &r);
        ASSERT(strstr(wls_str(&r), "Error") == NULL);
        json_free(&r);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS + 1);

        /* An import into a keystore holding no secrets is an error, never a
         * success that added nothing. */
        sapling_keystore_wipe_secrets(&f.w->sapling_keys);
        ASSERT(wls_foreign_key_string(key, sizeof(key), 0x22));
        wls_rpc(&f, "z_importkey", key, &r);
        ASSERT(strstr(wls_str(&r), "locked") != NULL);
        json_free(&r);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS + 1);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

struct wls_midlock {
    struct wls_fixture *f;
    pthread_t th;
    bool started;
    bool ran_during_unlock;
    atomic_bool lock_done;
    atomic_int tid;
};

static void *wls_lock_once(void *arg)
{
    struct wls_midlock *m = arg;
#ifdef __linux__
    char self[64];
    ssize_t len = readlink("/proc/thread-self", self, sizeof(self) - 1);
    const char *slash = NULL;
    if (len > 0) {
        self[len] = 0;
        slash = strrchr(self, '/');
    }
    atomic_store(&m->tid, slash ? atoi(slash + 1) : 0);
#endif
    wallet_lock_lock(m->f->w);
    atomic_store(&m->lock_done, true);
    return NULL;
}

/* While the unlock reads the Sapling rows, another thread asks to lock. */
static int wls_lock_mid_reload(void *ctx)
{
    struct wls_midlock *m = ctx;
    if (m->started && atomic_load(&m->lock_done) &&
        sqlite3_stmt_busy(m->f->ws.stmt_zkey_read))
        m->ran_during_unlock = true;
    if (m->started || !sqlite3_stmt_busy(m->f->ws.stmt_zkey_read))
        return 0;
    m->started = true;
    if (pthread_create(&m->th, NULL, wls_lock_once, m) != 0)
        m->started = false;
    struct timespec nap = { .tv_sec = 0, .tv_nsec = 50000000L };
    while (nanosleep(&nap, &nap) != 0) { /* retry interrupted sleep */ }
    return 0;
}

static int test_lock_waits_for_an_unlock_in_progress(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a lock during an unlock runs after it") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        wallet_lock_lock(f.w);
        struct wls_midlock m = { .f = &f };
        sqlite3_progress_handler(f.db, 1, wls_lock_mid_reload, &m);
        struct zcl_result u = wallet_lock_unlock(f.w, &f.ws, WLS_PASS);
        sqlite3_progress_handler(f.db, 0, NULL, NULL);
        ASSERT(m.started);
        ASSERT(!m.ran_during_unlock);
        ASSERT(u.ok);
        pthread_join(m.th, NULL);
        ASSERT(wls_locked());
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(wls_viewing_intact(&f, f.w, WLS_KEYS));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

struct wls_race {
    struct wls_fixture *f;
    int rounds;
};

static void *wls_race_locker(void *arg)
{
    struct wls_race *r = arg;
    for (int i = 0; i < r->rounds; i++)
        wallet_lock_lock(r->f->w);
    return NULL;
}

static void *wls_race_unlocker(void *arg)
{
    struct wls_race *r = arg;
    for (int i = 0; i < r->rounds; i++)
        (void)wallet_lock_unlock(r->f->w, &r->f->ws, WLS_PASS);
    return NULL;
}

static int test_concurrent_lock_and_unlock_stay_consistent(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: concurrent lock and unlock end consistent") {
        ASSERT(wls_provision(&f, true, true));
        struct privkey k0;
        struct pubkey p0;
        ASSERT(wls_hd_key(f.seed, 0, &k0, &p0));
        ASSERT(wallet_sqlite_write_key_r(&f.ws, &p0, &k0).ok);
        memory_cleanse(&k0, sizeof(k0));
        ASSERT(wls_boot(&f));
        boot_wallet_adopt_seed_if_it_governs(f.w);

        struct wls_race race = { .f = &f, .rounds = 150 };
        pthread_t locker, unlocker;
        ASSERT(pthread_create(&locker, NULL, wls_race_locker, &race) == 0);
        ASSERT(pthread_create(&unlocker, NULL, wls_race_unlocker, &race) == 0);
        pthread_join(locker, NULL);
        pthread_join(unlocker, NULL);

        if (wallet_lock_is_locked()) {
            ASSERT(wls_secrets_absent(f.w));
            ASSERT(wls_zero(&f.w->master_key, sizeof(f.w->master_key)));
        } else {
            ASSERT(wls_secrets_restored(&f, f.w));
            ASSERT(f.w->master_key.key.fValid);
        }
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wls_secrets_restored(&f, f.w));
        ASSERT(f.w->master_key.key.fValid);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(wls_no_duplicates(f.w));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sealed_flush_succeeds_and_writes_nothing_secret(void)
{
    int failures = 0;
    struct wls_fixture f;
    static uint8_t before[WLS_DUMP_CAP], after[WLS_DUMP_CAP];
    TEST("wallet_lock_shielded: a sealed flush is clean and changes no secret row") {
        ASSERT(wls_provision(&f, true, true));
        size_t n_before = wls_dump_rows(f.db, before, sizeof(before));
        ASSERT(wls_boot_locked(&f));
        struct zcl_result r = wallet_sqlite_flush_r(&f.ws, f.w);
        ASSERT(r.ok);
        ASSERT(wls_dump_rows(f.db, after, sizeof(after)) == n_before);
        ASSERT(memcmp(before, after, n_before) == 0);
        wallet_lock_lock(f.w);
        ASSERT(wallet_sqlite_flush_r(&f.ws, f.w).ok);
        ASSERT(wls_dump_rows(f.db, after, sizeof(after)) == n_before);
        ASSERT(memcmp(before, after, n_before) == 0);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* Flip one byte of a stored envelope so it no longer authenticates. */
static bool wls_tamper(struct wls_fixture *f, const char *select_sql,
                       const char *update_sql, int index_bind)
{
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(f->db, select_sql, -1, &sel, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_step(sel) == SQLITE_ROW;
    uint8_t blob[512];
    int n = ok ? sqlite3_column_bytes(sel, 0) : 0;
    ok = ok && n > 40 && (size_t)n <= sizeof(blob);
    if (ok) {
        memcpy(blob, sqlite3_column_blob(sel, 0), (size_t)n);
        blob[n - 1] ^= 0x01;
    }
    sqlite3_finalize(sel);
    sqlite3_stmt *upd = NULL;
    ok = ok && sqlite3_prepare_v2(f->db, update_sql, -1, &upd, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_blob(upd, 1, blob, n, SQLITE_TRANSIENT);
        if (index_bind >= 0)
            sqlite3_bind_int(upd, 2, index_bind);
        ok = sqlite3_step(upd) == SQLITE_DONE;
    }
    if (upd)
        sqlite3_finalize(upd);
    return ok;
}

static bool wls_tamper_key_row(struct wls_fixture *f, int child)
{
    char select_sql[96];
    snprintf(select_sql, sizeof(select_sql),
             "SELECT xsk FROM wallet_sapling_keys WHERE child_index=%d", child);
    return wls_tamper(f, select_sql,
        "UPDATE wallet_sapling_keys SET xsk=?1 WHERE child_index=?2", child);
}

static int test_one_damaged_row_does_not_block_the_rest(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: one damaged key row leaves the others usable") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_tamper_key_row(&f, 1));
        ASSERT(wls_boot_locked(&f));
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(f.w->sapling_keys.num_damaged == 1);
        ASSERT(!f.w->sapling_keys.locked);
        ASSERT(f.w->sapling_keys.has_seed);
        for (size_t i = 0; i < WLS_KEYS; i++) {
            const struct sapling_key_entry *e = sapling_keystore_find_by_ivk(
                &f.w->sapling_keys, f.orig[i].ivk);
            ASSERT(e);
            ASSERT(e->secret_wiped == (f.orig[i].child_index == 1));
        }
        uint8_t zd[1][11], zp[1][32], zm[1][512];
        int64_t za[1] = { 1000 };
        bool zh[1] = { false };
        memcpy(zd[0], f.orig[2].diversifier, 11);
        memcpy(zp[0], f.orig[2].pk_d, 32);
        memset(zm, 0, sizeof(zm));
        struct wallet_rpc_context *ctx = wallet_rpc_context_current();
        const struct chain_params *cp = chain_params_get();
        for (size_t i = 0; i < 2; i++) {
            const struct sapling_key_entry *key =
                sapling_keystore_find_by_ivk(&f.w->sapling_keys,
                                             f.orig[i].ivk);
            struct json_value r;
            json_init(&r);
            ASSERT(!z_sendmany_shielded(ctx, cp, key, 1000, NULL, NULL, 0,
                                        (const uint8_t (*)[11])zd,
                                        (const uint8_t (*)[32])zp, za,
                                        (const uint8_t (*)[512])zm, zh, 1, 0,
                                        NULL, &r));
            ASSERT((strstr(wls_str(&r), "decrypted") != NULL) == (i == 1));
            ASSERT(strstr(wls_str(&r), "wallet is locked") == NULL);
            json_free(&r);
        }
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_unlock_refuses_only_when_nothing_decrypts(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: unlock refuses only when no sealed row opens") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_tamper(&f, "SELECT seed FROM wallet_seed WHERE id=1",
                          "UPDATE wallet_seed SET seed=?1 WHERE id=1", -1));
        ASSERT(wls_boot_locked(&f));
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(f.w->sapling_keys.num_keys == WLS_KEYS);
        ASSERT(f.w->sapling_keys.num_damaged == 0);
        ASSERT(!f.w->sapling_keys.has_seed && f.w->sapling_keys.locked);
        ASSERT(wls_locked_mutations_that_succeed(&f) == 0);

        for (int c = 0; c < WLS_KEYS; c++)
            ASSERT(wls_tamper_key_row(&f, c));
        ASSERT(wls_boot_locked(&f));
        ASSERT(!wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wls_locked());
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_export_guard_covers_the_lock_to_wipe_window(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: z_exportkey refuses between lock and wipe") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        char zaddr[128];
        ASSERT(wls_address(&f, 0, zaddr, sizeof(zaddr)));

        /* The passphrase is gone but the secrets are still resident: the
         * state a lock leaves until its wipe completes. */
        wallet_lock_flip_after_unlock_checks_for_test(1);
        ASSERT(wallet_lock_is_unlocked());
        ASSERT(wls_locked());
        ASSERT(!f.w->sapling_keys.keys[0].secret_wiped);
        ASSERT(wls_rpc_refused_as_locked(&f, "z_exportkey", zaddr));
        wls_teardown(&f);

        /* Plaintext Sapling rows in a wallet that is encrypted elsewhere keep
         * their secrets resident after a passphrase-less boot. */
        ASSERT(wls_provision(&f, false, false));
        wallet_lock_note_encrypted_at_rest();
        ASSERT(wls_boot(&f));
        ASSERT(wls_locked());
        ASSERT(!f.w->sapling_keys.keys[0].secret_wiped);
        ASSERT(wls_rpc_refused_as_locked(&f, "z_exportkey", zaddr));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int wls_count_rows(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int test_failed_encryption_never_writes_plaintext(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a failed encryption writes no plaintext secret") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(sqlite3_exec(f.db, "DELETE FROM wallet_seed;"
                            "DELETE FROM wallet_sapling_keys;",
                            NULL, NULL, NULL) == SQLITE_OK);
        ASSERT(wallet_lock_effective_passphrase() != NULL);
        zcl_alloc_fault_fail_nth("wallet_encrypt_buf", 1);
        ASSERT(!wallet_sqlite_write_sapling_seed(&f.ws, f.seed));
        zcl_alloc_fault_clear();
        ASSERT(wls_count_rows(f.db, "SELECT count(*) FROM wallet_seed") == 0);
        zcl_alloc_fault_fail_nth("wallet_encrypt_buf", 1);
        ASSERT(!wallet_sqlite_write_sapling_key(
            &f.ws, f.orig[0].child_index, &f.orig[0]));
        zcl_alloc_fault_clear();
        ASSERT(wls_count_rows(
                   f.db, "SELECT count(*) FROM wallet_sapling_keys") == 0);
        ASSERT(wallet_sqlite_write_sapling_seed(&f.ws, f.seed));
        ASSERT(wls_count_rows(f.db, "SELECT count(*) FROM wallet_seed "
                              "WHERE length(seed) > 32") == 1);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* A lock thread started from inside the first statement step of a call, so the
 * lock lands while that call waits on the database. */
static int wls_lock_mid_check(void *ctx)
{
    struct wls_midlock *m = ctx;
    if (m->started) {
        if (atomic_load(&m->lock_done))
            m->ran_during_unlock = true;
        return 0;
    }
    m->started = true;
    if (pthread_create(&m->th, NULL, wls_lock_once, m) != 0)
        m->started = false;
    /* Give the lock up to five seconds to finish; a blocked lock is then seen
     * as not done, without a fixed nap that a loaded host could outlast. */
    struct timespec tick = { .tv_sec = 0, .tv_nsec = 10000000L };
    for (int i = 0; i < 500 && !atomic_load(&m->lock_done); i++)
        nanosleep(&tick, NULL);
    return 0;
}

/* A transparent key minted in RAM, not yet flushed. */
static bool wls_mint_unstored_transparent(struct wls_fixture *f)
{
    struct privkey k;
    struct pubkey pub;
    privkey_init(&k);
    memset(k.vch, 0x5d, 32);
    k.vch[2] = 0x21;
    k.fValid = true;
    k.fCompressed = true;
    return privkey_get_pubkey(&k, &pub) &&
           keystore_add_key(&f->w->keystore, &k);
}

/* A Sapling address minted in RAM, not yet flushed. */
static bool wls_mint_unstored_sapling(struct wls_fixture *f)
{
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk[32];
    return sapling_keystore_new_address(&f->w->sapling_keys, d, pk);
}

/* The import-from reload helper; its header cannot be included beside the
 * shielded internals. */
bool wallet_rescan_reload_from_store(struct wallet *w, struct wallet_sqlite *db);

typedef bool (*wls_mint_fn)(struct wls_fixture *f);

/* Mint one unstored entry, lock (before the flush, or while it waits for the
 * database), then flush. Reports whether the flush succeeded. */
static bool wls_flush_after_mint(wls_mint_fn mint, bool lock_in_flush,
                                 bool *ok)
{
    struct wls_fixture f;
    bool ready = wls_provision(&f, true, true) && wls_boot(&f) && mint(&f);
    if (ready && !lock_in_flush)
        wallet_lock_lock(f.w);
    struct wls_midlock m = { .f = &f };
    if (ready && lock_in_flush)
        sqlite3_progress_handler(f.db, 1, wls_lock_mid_check, &m);
    *ok = ready && wallet_sqlite_flush_r(&f.ws, f.w).ok;
    sqlite3_progress_handler(f.db, 0, NULL, NULL);
    if (m.started)
        pthread_join(m.th, NULL);
    bool locked = wls_locked();
    /* Transactions-only flushes stay available: a send whose proof outlives
     * the unlock window must still record its transaction. */
    bool txs_ok = ready && wallet_sqlite_flush_transactions_r(&f.ws, f.w).ok;
    wls_teardown(&f);
    return ready && locked && txs_ok && (!lock_in_flush || m.started);
}

static int test_flush_refuses_a_sealed_transparent_key_without_a_row(void)
{
    int failures = 0;
    bool ok = true;
    TEST("wallet_lock_shielded: a sealed transparent key without a row fails the flush") {
        ASSERT(wls_flush_after_mint(wls_mint_unstored_transparent, false, &ok));
        ASSERT(!ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_flush_refuses_a_sealed_sapling_address_without_a_row(void)
{
    int failures = 0;
    bool ok = true;
    TEST("wallet_lock_shielded: a sealed Sapling address without a row fails the flush") {
        ASSERT(wls_flush_after_mint(wls_mint_unstored_sapling, false, &ok));
        ASSERT(!ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lock_while_flush_waits_cannot_hide_an_unstored_key(void)
{
    int failures = 0;
    bool ok = true;
    TEST("wallet_lock_shielded: a lock while the flush waits cannot hide an unstored key") {
        ASSERT(wls_flush_after_mint(wls_mint_unstored_transparent, true, &ok));
        ASSERT(!ok);
        ASSERT(wls_flush_after_mint(wls_mint_unstored_sapling, true, &ok));
        ASSERT(!ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_flush_of_stored_sealed_keys_still_succeeds(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a flushed key stays flushable after a lock") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(wls_mint_unstored_transparent(&f));
        ASSERT(wls_mint_unstored_sapling(&f));
        ASSERT(wallet_sqlite_flush_r(&f.ws, f.w).ok);
        wallet_lock_lock(f.w);
        ASSERT(wallet_sqlite_flush_r(&f.ws, f.w).ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* Live entries: a removed key stays in the array, marked unused. */
static size_t wls_used_keys(const struct wallet *w)
{
    size_t n = 0;
    for (size_t i = 0; i < w->keystore.num_keys; i++)
        n += w->keystore.keys[i].used ? 1 : 0;
    return n;
}

static int test_refused_keypool_refill_leaves_no_unstored_key(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a refill refused by a lock discards its keys") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        size_t keys = wls_used_keys(f.w);
        struct wls_midlock m = { .f = &f };
        sqlite3_progress_handler(f.db, 1, wls_lock_mid_check, &m);
        struct json_value r;
        wls_rpc(&f, "keypoolrefill", "5", &r);
        sqlite3_progress_handler(f.db, 0, NULL, NULL);
        json_free(&r);
        ASSERT(m.started);
        pthread_join(m.th, NULL);
        ASSERT(wls_locked());
        ASSERT(f.w->key_pool_size == 0);
        ASSERT(wls_used_keys(f.w) == keys);
        ASSERT(wallet_sqlite_flush_r(&f.ws, f.w).ok);
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wallet_sqlite_flush_r(&f.ws, f.w).ok);
        ASSERT(f.w->key_pool_size == 0);
        ASSERT(wls_used_keys(f.w) == keys);
        ASSERT(wls_boot(&f));
        ASSERT(wallet_sqlite_read_keypool_r(&f.ws, f.w).ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* Reload the stored keys while another thread locks. via_import selects the
 * import-from call site over the lock module entry point. */
static bool wls_reload_while_locking(bool via_import)
{
    struct wls_fixture f;
    if (!wls_provision(&f, true, false) || !wls_boot(&f))
        return false;
    struct wls_midlock m = { .f = &f };
    sqlite3_progress_handler(f.db, 1, wls_lock_mid_reload, &m);
    bool ok = via_import
        ? wallet_rescan_reload_from_store(f.w, &f.ws)
        : wallet_lock_reload_keys(f.w, &f.ws).ok;
    sqlite3_progress_handler(f.db, 0, NULL, NULL);
    bool started = m.started;
    if (started)
        pthread_join(m.th, NULL);
    bool held = started && !m.ran_during_unlock && ok;
    bool sealed = wls_locked() && wls_secrets_absent(f.w);
    wls_teardown(&f);
    return held && sealed;
}

static int test_reload_cannot_undo_a_lock(void)
{
    int failures = 0;
    TEST("wallet_lock_shielded: a key reload runs under the transition mutex") {
        ASSERT(wls_reload_while_locking(false));
        PASS();
    } _test_next:;
    return failures;
}

static int test_import_from_reloads_under_the_transition_mutex(void)
{
    int failures = 0;
    TEST("wallet_lock_shielded: import-from reloads under the transition mutex") {
        ASSERT(wls_reload_while_locking(true));
        PASS();
    } _test_next:;
    return failures;
}

static int test_wrong_passphrase_does_not_hold_off_a_lock(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a passphrase check does not block a lock") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        struct wls_midlock m = { .f = &f };
        sqlite3_progress_handler(f.db, 1, wls_lock_mid_check, &m);
        struct zcl_result r = wallet_lock_unlock(f.w, &f.ws, "not the passphrase");
        sqlite3_progress_handler(f.db, 0, NULL, NULL);
        ASSERT(m.started);
        ASSERT(!r.ok);
        pthread_join(m.th, NULL);
        ASSERT(m.ran_during_unlock);
        ASSERT(wls_locked());
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_locked_boot_is_not_reported_as_plaintext(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: only clear key rows read as plaintext at rest") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot_locked(&f));
        ASSERT(!boot_wallet_keys_plaintext_at_rest(1));
        wls_teardown(&f);
        ASSERT(wls_provision(&f, false, true));
        ASSERT(wls_boot(&f));
        ASSERT(boot_wallet_keys_plaintext_at_rest(1));
        ASSERT(!boot_wallet_keys_plaintext_at_rest(0));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* After a refused mint or flush: nothing unstored is left behind, the next
 * full flush works once unlocked, and a restart reads the key pool back. */
static bool wls_pool_clean_and_restartable(struct wls_fixture *f,
                                           size_t keys_before)
{
    if (f->w->key_pool_size != 0 || wls_used_keys(f->w) != keys_before)
        return false;
    if (!wallet_lock_unlock(f->w, &f->ws, WLS_PASS).ok ||
        !wallet_sqlite_flush_r(&f->ws, f->w).ok)
        return false;
    return wls_boot(f) &&
           wallet_sqlite_read_keypool_r(&f->ws, f->w).ok &&
           f->w->key_pool_size == 0;
}

static int test_transactions_flush_writes_only_stored_pool_entries(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a transactions-only flush never names an unstored key") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        ASSERT(wallet_top_up_key_pool(f.w, 3));
        ASSERT(f.w->key_pool_size == 3);
        wallet_lock_lock(f.w);
        ASSERT(wallet_lock_unlock(f.w, &f.ws, WLS_PASS).ok);
        ASSERT(wallet_sqlite_flush_transactions_r(&f.ws, f.w).ok);
        ASSERT(wls_boot(&f));
        ASSERT(wallet_sqlite_read_keypool_r(&f.ws, f.w).ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_refill_refused_at_the_mint_discards_its_keys(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a keypoolrefill refused at the mint discards its keys") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        size_t keys = wls_used_keys(f.w);
        ASSERT(wallet_top_up_key_pool(f.w, 3));
        wallet_lock_lock(f.w);
        struct json_value r;
        wls_rpc(&f, "keypoolrefill", "5", &r);
        json_free(&r);
        ASSERT(wls_pool_clean_and_restartable(&f, keys));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_getnewaddress_topup_refused_at_the_mint_discards_its_keys(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a getnewaddress top-up refused at the mint discards its keys") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        ASSERT(!wallet_has_hd(f.w));
        size_t keys = wls_used_keys(f.w);
        ASSERT(wallet_top_up_key_pool(f.w, 3));
        wallet_lock_lock(f.w);
        struct json_value r;
        wls_rpc(&f, "getnewaddress", NULL, &r);
        json_free(&r);
        ASSERT(wls_pool_clean_and_restartable(&f, keys));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_getnewaddress_topup_refused_at_the_flush_discards_its_keys(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a getnewaddress top-up refused at the flush discards its keys") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        ASSERT(!wallet_has_hd(f.w));
        size_t keys = wls_used_keys(f.w);
        struct wls_midlock m = { .f = &f };
        sqlite3_progress_handler(f.db, 1, wls_lock_mid_check, &m);
        struct json_value r;
        wls_rpc(&f, "getnewaddress", NULL, &r);
        sqlite3_progress_handler(f.db, 0, NULL, NULL);
        json_free(&r);
        ASSERT(m.started);
        pthread_join(m.th, NULL);
        ASSERT(wls_locked());
        ASSERT(wls_pool_clean_and_restartable(&f, keys));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* A send whose proof outlives the unlock window records its transaction
 * through the pre-relay durability boundary even while a never-stored sealed
 * key exists. */
static int test_send_past_the_timer_still_persists(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: the pre-relay flush works after the timer locks") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(wls_mint_unstored_transparent(&f));
        wallet_lock_lock(f.w);
        ASSERT(!wallet_sqlite_flush_r(&f.ws, f.w).ok);
        struct tx_mempool *pool = zcl_calloc(1, 4096, "wls_mempool");
        ASSERT(pool != NULL);
        struct wallet_rpc_context ctx = {
            .wallet = f.w, .wallet_db = &f.ws, .mempool = pool,
        };
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        bool ok = wallet_persist_commit_before_relay(&ctx, &wtx).ok;
        free(pool);
        ASSERT(ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* Sleep for `ms` milliseconds; a real thread race has no injected clock. */
static void wls_nap_ms(long ms)
{
    struct timespec nap = { .tv_sec = 0, .tv_nsec = ms * 1000000L };
    while (nanosleep(&nap, &nap) != 0) { /* real-clock: waits on a real thread; no injected clock exists */ }
}

/* True when the transparent key `kid` is held and sealed. */
static bool wls_key_sealed(struct wallet *w, const struct key_id *kid)
{
    bool sealed = false;
    zcl_mutex_lock(&w->keystore.cs);
    for (size_t i = 0; i < w->keystore.num_keys; i++)
        if (w->keystore.keys[i].used &&
            memcmp(w->keystore.keys[i].keyid.id.data, kid->id.data, 20) == 0)
            sealed = w->keystore.keys[i].sealed;
    zcl_mutex_unlock(&w->keystore.cs);
    return sealed;
}

/* Wait until the lock thread has run as far as it can and sleeps on a mutex.
 * Linux reads the thread state; elsewhere a fixed wait stands in. */
static bool wls_wait_until_blocked(struct wls_midlock *m)
{
#ifdef __linux__
    for (int i = 0; i < 5000; i++) {
        int tid = atomic_load(&m->tid);
        char path[64], buf[256];
        if (tid != 0) {
            snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
            FILE *fp = fopen(path, "r");
            size_t n = fp ? fread(buf, 1, sizeof(buf) - 1, fp) : 0;
            if (fp)
                fclose(fp);
            buf[n] = 0;
            const char *state = strrchr(buf, ')');
            if (state && state[1] == ' ' && state[2] == 'S')
                return true;
        }
        wls_nap_ms(1);
    }
    return false;
#else
    (void)m;
    wls_nap_ms(2000);
    return true;
#endif
}

/* A mint that passed its lock check holds w->cs while it adds a key. The
 * test stands in for it: a lock lands, the seal has to wait for w->cs, and
 * only then does the key arrive. The seal must still cover that key, the
 * flush must refuse a key without a row, and the pool must read back after a
 * restart. */
static int test_lock_waits_for_a_mint_holding_the_wallet_mutex(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a lock during a mint seals the key it adds") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        struct privkey held;
        privkey_init(&held);
        memset(held.vch, 0x3c, 32);
        held.vch[4] = 0x11;
        held.fValid = true;
        held.fCompressed = true;
        struct pubkey held_pub;
        struct key_id held_kid;
        ASSERT(keystore_add_key(&f.w->keystore, &held));
        ASSERT(privkey_get_pubkey(&held, &held_pub));
        held_kid = pubkey_get_id(&held_pub);
        ASSERT(wallet_sqlite_write_key_r(&f.ws, &held_pub, &held).ok);
        size_t keys = wls_used_keys(f.w);
        struct wls_midlock m = { .f = &f };
        zcl_mutex_lock(&f.w->cs);
        ASSERT(pthread_create(&m.th, NULL, wls_lock_once, &m) == 0);
        /* Wait for the published lock, then for the lock thread to run as far
         * as it can. With the seal under w->cs the held key is still
         * unsealed at that point; a seal outside w->cs has sealed it. */
        for (int i = 0; i < 5000 && !wls_locked(); i++)
            wls_nap_ms(1);
        bool blocked = wls_locked() && wls_wait_until_blocked(&m);
        bool held_sealed = wls_key_sealed(f.w, &held_kid);
        bool added = blocked && wls_mint_unstored_transparent(&f);
        zcl_mutex_unlock(&f.w->cs);
        pthread_join(m.th, NULL);
        ASSERT(blocked && added);
        ASSERT(!held_sealed);
        ASSERT(wls_secrets_absent(f.w));
        ASSERT(f.w->keystore.keys[f.w->keystore.num_keys - 1].sealed);
        /* The refill that minted it: one pool entry, no stored row. */
        struct key_id kid = f.w->keystore.keys[f.w->keystore.num_keys - 1].keyid;
        f.w->key_pool[0].keyid = kid;
        f.w->key_pool[0].persisted = false;
        f.w->key_pool_size = 1;
        ASSERT(!wallet_sqlite_flush_r(&f.ws, f.w).ok);
        wallet_key_pool_discard_unpersisted(f.w);
        ASSERT(wls_pool_clean_and_restartable(&f, keys));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* Publish the lock without wiping the fixture wallet: the lock runs on a
 * stand-in wallet. This is the state between the published lock and the wipe
 * that the timer and a lock request pass through. */
static void wls_publish_lock_only(void)
{
    struct wallet *other = wls_alloc_wallet();
    if (!other)
        return;
    wallet_lock_lock(other);
    wls_free_wallet(other);
}

/* importprivkey stored the row, then the lock was published, then the
 * keystore refused the key. A key the wallet already held keeps its row; a
 * key this import introduced loses it. */
static int test_refused_reimport_keeps_the_existing_key_row(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a refused re-import keeps the row of a held key") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        struct privkey k;
        struct pubkey pub;
        privkey_init(&k);
        memset(k.vch, 0x52, 32);
        k.vch[6] = 0x33;
        k.fValid = true;
        k.fCompressed = true;
        ASSERT(privkey_get_pubkey(&k, &pub));
        ASSERT(keystore_add_key(&f.w->keystore, &k));
        ASSERT(wallet_sqlite_write_key_r(&f.ws, &pub, &k).ok);
        int rows = wls_count_rows(f.db, "SELECT COUNT(*) FROM wallet_keys");
        ASSERT(rows > 0);
        wls_publish_lock_only();
        struct wallet_rpc_context ctx = { .wallet = f.w, .wallet_db = &f.ws };
        struct zcl_result r = wallet_import_key_commit(&ctx, &pub, &k, true);
        ASSERT(!r.ok);
        ASSERT(strstr(r.message, "locked") != NULL);
        ASSERT(wls_count_rows(f.db, "SELECT COUNT(*) FROM wallet_keys") == rows);
        /* A key this import introduced is rolled back. */
        r = wallet_import_key_commit(&ctx, &pub, &k, false);
        ASSERT(!r.ok);
        ASSERT(wls_count_rows(f.db, "SELECT COUNT(*) FROM wallet_keys") == rows - 1);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* z_importkey: a refused import is a success only when the key is held. */
static int test_refused_sapling_import_is_never_reported_as_added(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a refused z_importkey reports the true reason") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        struct wallet_rpc_context ctx = { .wallet = f.w, .wallet_db = &f.ws };
        uint8_t material[32];
        memset(material, 0x44, sizeof(material));
        struct zip32_xsk fresh;
        zip32_xsk_master(&fresh, material, sizeof(material));
        struct json_value r;
        json_init(&r);
        /* Lock published after the RPC checks: the import is refused. */
        wls_publish_lock_only();
        ASSERT(!wallet_shielded_import_refused(&ctx, &fresh, true, &r));
        ASSERT(strstr(wls_str(&r), "locked") != NULL);
        json_free(&r);
        wls_teardown(&f);
        /* A full keystore is not a duplicate either. */
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ctx.wallet = f.w;
        ctx.wallet_db = &f.ws;
        size_t kept = f.w->sapling_keys.num_keys;
        f.w->sapling_keys.num_keys = MAX_SAPLING_KEYS;
        json_init(&r);
        ASSERT(!wallet_shielded_import_refused(&ctx, &fresh, true, &r));
        ASSERT(strstr(wls_str(&r), "full") != NULL);
        json_free(&r);
        f.w->sapling_keys.num_keys = kept;
        /* A key the wallet holds is reported as already present. */
        struct zip32_xsk held = f.w->sapling_keys.keys[0].xsk;
        json_init(&r);
        ASSERT(wallet_shielded_import_refused(&ctx, &held, true, &r));
        json_free(&r);
        json_init(&r);
        ASSERT(!wallet_shielded_import_refused(&ctx, &held, false, &r));
        ASSERT(strstr(wls_str(&r), "already exists") != NULL);
        json_free(&r);
        memory_cleanse(&held, sizeof(held));
        memory_cleanse(&fresh, sizeof(fresh));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sapling_mint_and_import_refuse_once_the_lock_is_published(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a Sapling mint or import after the published lock is refused") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        size_t n = f.w->sapling_keys.num_keys;
        wls_publish_lock_only();
        ASSERT(wls_locked());
        ASSERT(!f.w->sapling_keys.locked);
        uint8_t d[ZC_DIVERSIFIER_SIZE], pk[32];
        ASSERT(!sapling_keystore_new_address(&f.w->sapling_keys, d, pk));
        uint8_t material[32];
        memset(material, 0x31, sizeof(material));
        struct zip32_xsk xsk;
        zip32_xsk_master(&xsk, material, sizeof(material));
        ASSERT(!sapling_keystore_import_xsk(&f.w->sapling_keys, &xsk));
        memory_cleanse(&xsk, sizeof(xsk));
        ASSERT(f.w->sapling_keys.num_keys == n);
        /* A scratch keystore that only derives public values is not the
         * wallet's keystore and keeps working under a published lock. */
        struct sapling_keystore *scratch = zcl_calloc(1, sizeof(*scratch), "wls_scratch");
        ASSERT(scratch != NULL);
        sapling_keystore_init(scratch);
        bool scratch_ok = sapling_keystore_set_seed(scratch, f.seed) &&
                          sapling_keystore_new_address(scratch, d, pk);
        sapling_keystore_free(scratch);
        free(scratch);
        ASSERT(scratch_ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_locked_flush_needs_a_row_for_an_unwiped_sapling_entry(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a locked flush refuses an unwiped Sapling entry without a row") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(wls_mint_unstored_sapling(&f));
        wls_publish_lock_only();
        ASSERT(!wallet_sqlite_flush_r(&f.ws, f.w).ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_locked_flush_needs_the_sapling_seed_row(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a locked flush refuses a held Sapling seed without a row") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        ASSERT(f.w->sapling_keys.has_seed);
        ASSERT(sqlite3_exec(f.db, "DELETE FROM wallet_seed", NULL, NULL,
                            NULL) == SQLITE_OK);
        wls_publish_lock_only();
        ASSERT(!wallet_sqlite_flush_r(&f.ws, f.w).ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_import_key_refuses_once_the_lock_is_published(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a transparent key import after the published lock is refused") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        size_t keys = wls_used_keys(f.w);
        wls_publish_lock_only();
        struct privkey k;
        privkey_init(&k);
        memset(k.vch, 0x4b, 32);
        k.vch[5] = 0x29;
        k.fValid = true;
        k.fCompressed = true;
        ASSERT(!wallet_import_key(f.w, &k));
        ASSERT(wls_used_keys(f.w) == keys);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_legacy_key_add_rechecks_the_lock_under_the_wallet_mutex(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a legacy key added after a lock is refused") {
        ASSERT(wls_provision(&f, true, false));
        ASSERT(wls_boot(&f));
        ASSERT(!wallet_has_hd(f.w));
        size_t keys = wls_used_keys(f.w);
        wallet_lock_lock(f.w);
        struct privkey k;
        privkey_init(&k);
        memset(k.vch, 0x6e, 32);
        k.vch[3] = 0x17;
        k.fValid = true;
        k.fCompressed = true;
        ASSERT(!wallet_add_generated_key(f.w, &k));
        ASSERT(wls_used_keys(f.w) == keys);
        ASSERT(wls_secrets_absent(f.w));
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_locked_flush_refuses_an_unsealed_key_without_a_row(void)
{
    int failures = 0;
    struct wls_fixture f;
    TEST("wallet_lock_shielded: a locked flush refuses an unsealed key without a row") {
        ASSERT(wls_provision(&f, true, true));
        ASSERT(wls_boot(&f));
        wallet_lock_lock(f.w);
        ASSERT(wls_mint_unstored_transparent(&f));
        ASSERT(!wallet_sqlite_flush_r(&f.ws, f.w).ok);
        wls_teardown(&f);
        PASS();
    } _test_next:;
    return failures;
}

int test_wallet_lock_shielded(void);
int test_wallet_lock_shielded(void)
{
    int failures = 0;
    printf("\n=== wallet_lock_shielded ===\n");
    failures += test_lock_cleanses_memory();
    failures += test_timeout_and_refusal_paths_cleanse();
    failures += test_unlock_cycles_are_idempotent();
    failures += test_unlock_alone_does_not_duplicate();
    failures += test_exports_refuse_while_locked();
    failures += test_locked_wallet_never_replaces_the_seed();
    failures += test_locked_boot_scans_and_computes_nullifiers();
    failures += test_row_without_viewing_key_is_reported();
    failures += test_wrong_passphrase_keeps_shielded_wallet_locked();
    failures += test_wallet_is_not_unlocked_before_its_keys_are_loaded();
    failures += test_lock_during_send_cannot_sign_with_wiped_key();
    failures += test_plaintext_wallet_is_unchanged();
    failures += test_sealed_boot_keeps_wallet_records();
    failures += test_hd_master_follows_lock_and_unlock();
    failures += test_unlock_after_locked_boot_adopts_the_seed();
    failures += test_seed_read_error_never_reads_as_absent();
    failures += test_wrong_passphrase_while_unlocked_changes_nothing();
    failures += test_lock_waits_for_an_unlock_in_progress();
    failures += test_concurrent_lock_and_unlock_stay_consistent();
    failures += test_sealed_flush_succeeds_and_writes_nothing_secret();
    failures += test_one_damaged_row_does_not_block_the_rest();
    failures += test_unlock_refuses_only_when_nothing_decrypts();
    failures += test_export_guard_covers_the_lock_to_wipe_window();
    failures += test_failed_encryption_never_writes_plaintext();
    failures += test_flush_refuses_a_sealed_transparent_key_without_a_row();
    failures += test_flush_refuses_a_sealed_sapling_address_without_a_row();
    failures += test_lock_while_flush_waits_cannot_hide_an_unstored_key();
    failures += test_flush_of_stored_sealed_keys_still_succeeds();
    failures += test_refused_keypool_refill_leaves_no_unstored_key();
    failures += test_transactions_flush_writes_only_stored_pool_entries();
    failures += test_refill_refused_at_the_mint_discards_its_keys();
    failures += test_getnewaddress_topup_refused_at_the_mint_discards_its_keys();
    failures += test_getnewaddress_topup_refused_at_the_flush_discards_its_keys();
    failures += test_send_past_the_timer_still_persists();
    failures += test_reload_cannot_undo_a_lock();
    failures += test_import_from_reloads_under_the_transition_mutex();
    failures += test_wrong_passphrase_does_not_hold_off_a_lock();
    failures += test_locked_boot_is_not_reported_as_plaintext();
    failures += test_lock_waits_for_a_mint_holding_the_wallet_mutex();
    failures += test_legacy_key_add_rechecks_the_lock_under_the_wallet_mutex();
    failures += test_locked_flush_refuses_an_unsealed_key_without_a_row();
    failures += test_sapling_mint_and_import_refuse_once_the_lock_is_published();
    failures += test_locked_flush_needs_a_row_for_an_unwiped_sapling_entry();
    failures += test_locked_flush_needs_the_sapling_seed_row();
    failures += test_import_key_refuses_once_the_lock_is_published();
    failures += test_refused_reimport_keeps_the_existing_key_row();
    failures += test_refused_sapling_import_is_never_reported_as_added();
    wallet_lock_reset_for_test();
    return failures;
}
