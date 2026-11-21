/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared helpers for wallet spec tests.
 * Include ONCE per spec file — provides GET, POST, has, not_has. */

#ifndef ZCL_TEST_SPEC_HELPERS_H
#define ZCL_TEST_SPEC_HELPERS_H

#include "test/spec.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "models/database.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* From test_helpers.c via the spec runner link; declared here instead of
 * including test_core.h, whose unit-test PASS macro collides with the
 * spec framework's PASS in every file that includes this header. */
void test_make_tmpdir(char *buf, size_t n, const char *prefix,
                      const char *tag);
int test_rm_rf_recursive(const char *path);

/* Seed a throwaway node.db holding one shielded address so QR stories
 * exercise the real address-bearing render; the wallet-less render these
 * specs otherwise drive has no address to encode by design. Restores
 * nothing: callers re-run wallet_view_init(NULL) and test_rm_rf_recursive. */
__attribute__((unused))
static int seed_shielded_wallet(char *dir, size_t cap)
{
    test_make_tmpdir(dir, cap, "spec_qr", "wallet");
    char path[1024];
    sqlite3 *db = NULL;
    char *err = NULL;
    int rc = -1;
    if (snprintf(path, sizeof path, "%s/node.db", dir) >= (int)sizeof path)
        goto out;
    if (sqlite3_open(path, &db) != SQLITE_OK)
        goto out;
    if (sqlite3_exec(db,
            "CREATE TABLE wallet_sapling_keys (address TEXT);"
            "INSERT INTO wallet_sapling_keys (address) VALUES "
            "('zs1spec8v5k9duemlt7g5xwgcp9yq3d7q0u9y7t2nv6d4c5e8wqzxy3rl8m0a7q3f');",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        goto out;
    }
    rc = 0;
out:
    sqlite3_close(db);
    if (rc != 0)
        test_rm_rf_recursive(dir);
    return rc;
}

struct spec_wallet_fixture {
    char dir[256];
    const char *previous_dir;
    int balance_dirty;
    time_t shield_pending_since;
    char shield_opid[128];
    int64_t shield_pending_amount;
    bool sync_enabled;
};

/* A real, isolated schema with one synthetic spendable transparent output. */
__attribute__((unused))
static bool spec_wallet_fixture_open(struct spec_wallet_fixture *f)
{
    if (!f) return false;
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dir, sizeof(f->dir), "spec", "wallet");
    char path[320];
    int n = snprintf(path, sizeof(path), "%s/node.db", f->dir);
    if (!f->dir[0] || n < 0 || (size_t)n >= sizeof(path)) return false;
    struct node_db db = {0};
    bool ok = node_db_open(&db, path);
    if (ok) ok = node_db_exec(&db,
        "CREATE TABLE mempool_entries(txid BLOB PRIMARY KEY, fee INTEGER, size INTEGER, time_added INTEGER)");
    if (ok) ok = node_db_exec(&db,
        "INSERT INTO wallet_utxos(txid,vout,value,address_hash,script,height,is_coinbase)"
        " VALUES(zeroblob(32),0,100000000,zeroblob(20),zeroblob(1),1,0)");
    if (db.open) node_db_close(&db);
    if (!ok) { test_rm_rf_recursive(f->dir); return false; }
    f->previous_dir = g_wv_datadir;
    f->balance_dirty = g_balance_dirty;
    f->shield_pending_since = g_shield_pending_since;
    memcpy(f->shield_opid, g_shield_opid, sizeof(f->shield_opid));
    f->shield_pending_amount = g_shield_pending_amount;
    f->sync_enabled = g_sync_enabled;
    g_sync_enabled = false;
    wallet_view_init(f->dir);
    return true;
}

__attribute__((unused))
static void spec_wallet_fixture_close(struct spec_wallet_fixture *f)
{
    if (!f) return;
    wallet_view_init(f->previous_dir);
    g_balance_dirty = f->balance_dirty;
    g_shield_pending_since = f->shield_pending_since;
    memcpy(g_shield_opid, f->shield_opid, sizeof(g_shield_opid));
    g_shield_pending_amount = f->shield_pending_amount;
    g_sync_enabled = f->sync_enabled;
    test_rm_rf_recursive(f->dir);
}


static uint8_t _resp[131072];

__attribute__((unused))
static size_t GET(const char *path) {
    memset(_resp, 0, sizeof(_resp));
    return wallet_view_handle_request("GET", path, NULL, 0,
                                       _resp, sizeof(_resp));
}

__attribute__((unused))
static size_t POST(const char *path, const char *body) {
    memset(_resp, 0, sizeof(_resp));
    return wallet_view_handle_request("POST", path,
        (const uint8_t *)body, body ? strlen(body) : 0,
        _resp, sizeof(_resp));
}

/* Does the rendered page contain this text? */
__attribute__((unused))
static bool has(const char *needle) {
    return strstr((char *)_resp, needle) != NULL;
}

/* Is the response a valid 200 HTML page? */
__attribute__((unused))
static bool is_200(void) {
    return has("HTTP/1.1 200 OK") && has("text/html");
}

/* Is the page in loading state (no DB)? */
__attribute__((unused))
static bool is_loading(void) {
    return has("Wallet Loading");
}

#endif
