/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: differential test of the wallet txid -> slot index against the
 * linear reference scan: adds, erases, reorg disconnects, a restore from a
 * fixture database, present and absent lookups, table-full behaviour, and a
 * lookup micro-benchmark. Fixed seed, no wall clock in the sequence. */

#include "test/test_core.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define UNIVERSE 300u
#define STEPS 6000u

static const char *k_schema =
    "CREATE TABLE wallet_keys (pubkey_hash BLOB PRIMARY KEY, pubkey BLOB NOT NULL,"
    " privkey BLOB NOT NULL, compressed INTEGER NOT NULL DEFAULT 1,"
    " created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE wallet_keypool (pubkey_hash BLOB PRIMARY KEY, generation INTEGER NOT NULL UNIQUE);"
    "CREATE TABLE wallet_sapling_keys (ivk BLOB PRIMARY KEY, xsk BLOB NOT NULL, xfvk BLOB NOT NULL,"
    " diversifier BLOB NOT NULL, pk_d BLOB NOT NULL, child_index INTEGER NOT NULL,"
    " address TEXT NOT NULL DEFAULT '');"
    "CREATE TABLE wallet_scripts (script_hash BLOB PRIMARY KEY, redeem_script BLOB NOT NULL);"
    "CREATE TABLE wallet_seed (id INTEGER PRIMARY KEY CHECK(id=1), seed BLOB NOT NULL,"
    " next_child INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE wallet_transactions (txid BLOB PRIMARY KEY, raw_tx BLOB NOT NULL,"
    " block_hash BLOB, block_height INTEGER, time_received INTEGER NOT NULL,"
    " from_me INTEGER NOT NULL DEFAULT 0, fee INTEGER);"
    "CREATE TABLE wallet_watch_only (address_hash BLOB PRIMARY KEY, address TEXT NOT NULL,"
    " created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE node_state (key TEXT PRIMARY KEY, value BLOB);";

struct txi_fixture {
    struct wallet *w;
    struct transaction txs[UNIVERSE];
    uint32_t rng;
    size_t compared, wrong;
};

static uint32_t txi_rand(struct txi_fixture *f)
{
    f->rng ^= f->rng << 13; f->rng ^= f->rng >> 17; f->rng ^= f->rng << 5;
    return f->rng;
}

static void txi_make(struct transaction *tx, uint32_t id)
{
    transaction_init(tx);
    tx->lock_time = id + 1;
    transaction_compute_hash(tx);
}

static void txi_same(struct txi_fixture *f, struct wallet *w, unsigned id)
{
    size_t a = wallet_find_slot_indexed(w, &f->txs[id].hash);
    size_t b = wallet_find_slot_scan(w, &f->txs[id].hash);
    f->compared++;
    if (a != b) f->wrong++;
}

static void txi_sweep(struct txi_fixture *f, struct wallet *w)
{
    for (unsigned id = 0; id < UNIVERSE; id++) txi_same(f, w, id);
}

static void txi_add(struct txi_fixture *f, struct wallet *w, unsigned id)
{
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    wtx.tx = f->txs[id];
    wtx.used = true;
    wtx.time_received = 1700000000 + (int64_t)id;
    (void)wallet_add_to_wallet(w, &wtx);
}

static void txi_run(struct txi_fixture *f, struct wallet *w, unsigned steps)
{
    for (unsigned s = 0; s < steps; s++) {
        unsigned id = txi_rand(f) % UNIVERSE, op = txi_rand(f) % 5;
        if (op <= 1) txi_add(f, w, id);
        else if (op == 2) (void)wallet_disconnect_transaction(w, &f->txs[id], false);
        else if (op == 3) (void)wallet_disconnect_transaction(w, &f->txs[id], true);
        txi_same(f, w, id);
        txi_same(f, w, txi_rand(f) % UNIVERSE);
        if (s % 97 == 0) txi_sweep(f, w);
    }
    txi_sweep(f, w);
}

static bool txi_same_members(struct txi_fixture *f, struct wallet *b)
{
    txi_sweep(f, b);
    for (unsigned id = 0; id < UNIVERSE; id++)
        if ((wallet_find_slot_indexed(f->w, &f->txs[id].hash) < MAX_WALLET_TX) !=
            (wallet_find_slot_indexed(b, &f->txs[id].hash) < MAX_WALLET_TX)) return false;
    return true;
}

static bool txi_open_fixture_db(sqlite3 **db, struct wallet_sqlite *ws)
{
    memset(ws, 0, sizeof(*ws));
    return sqlite3_open(":memory:", db) == SQLITE_OK &&
        sqlite3_exec(*db, k_schema, NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_open_r(ws, *db).ok;
}

static bool txi_restore(struct txi_fixture *f, struct wallet **out)
{
    sqlite3 *db = NULL;
    struct wallet_sqlite ws;
    bool ok = txi_open_fixture_db(&db, &ws);
    for (size_t i = 0; ok && i < MAX_WALLET_TX; i++)
        if (f->w->map_wallet[i].used) ok = wallet_sqlite_write_tx(&ws, &f->w->map_wallet[i]);
    struct wallet *b = zcl_calloc(1, sizeof(*b), "txi_restore_wallet");
    if (b) wallet_init_zeroed(b);
    ok = ok && b && wallet_sqlite_read_txs(&ws, b) &&
         b->num_wallet_tx == f->w->num_wallet_tx && b->num_wallet_tx > 0 &&
         txi_same_members(f, b);
    if (ws.open) wallet_sqlite_close(&ws);
    if (db) sqlite3_close(db);
    *out = b;
    return ok;
}

static bool txi_table_full(void)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "txi_full_wallet");
    if (!w) return false;
    wallet_init_zeroed(w);
    bool ok = true;
    /* Fill every slot directly (adding 65,536 through the API is quadratic in
     * the free-slot scan), then re-derive the index. */
    for (uint32_t i = 0; i < MAX_WALLET_TX; i++) {
        transaction_init(&w->map_wallet[i].tx);
        w->map_wallet[i].tx.hash.data[0] = (uint8_t)(i + 1);
        w->map_wallet[i].tx.hash.data[1] = (uint8_t)((i + 1) >> 8);
        w->map_wallet[i].tx.hash.data[2] = (uint8_t)(((i + 1) >> 16) | 0x80);
        w->map_wallet[i].used = true;
    }
    w->num_wallet_tx = MAX_WALLET_TX;
    wallet_tx_index_rebuild_locked(w);
    struct wallet_tx extra;
    memset(&extra, 0, sizeof(extra));
    txi_make(&extra.tx, 900000);
    extra.used = true;
    bool refused = !wallet_add_to_wallet(w, &extra);
    bool absent = wallet_find_slot_indexed(w, &extra.tx.hash) == MAX_WALLET_TX &&
                  wallet_find_slot_scan(w, &extra.tx.hash) == MAX_WALLET_TX;
    struct uint256 probe = w->map_wallet[4321].tx.hash;
    size_t a = wallet_find_slot_indexed(w, &probe);
    bool present = a == wallet_find_slot_scan(w, &probe) && a == 4321;
    wallet_free(w);
    free(w);
    return ok && refused && absent && present;
}

static bool txi_duplicates(struct txi_fixture *f)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "txi_dup_wallet");
    if (!w) return false;
    wallet_init_zeroed(w);
    for (size_t s = 50; s <= 52; s++) {
        w->map_wallet[s].used = true;
        w->map_wallet[s].tx.hash = f->txs[7].hash;
    }
    wallet_tx_index_rebuild_locked(w);
    bool ok = wallet_find_slot_indexed(w, &f->txs[7].hash) == 50 &&
              wallet_find_slot_scan(w, &f->txs[7].hash) == 50;
    for (size_t s = 50; s <= 52; s++) w->map_wallet[s].used = false;
    free(w);
    return ok;
}

static double txi_ns_per_lookup(struct wallet *w, struct txi_fixture *f, bool indexed,
                                size_t *sink)
{
    const unsigned n = 10000;
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (unsigned i = 0; i < n; i++)
        *sink += indexed ? wallet_find_slot_indexed(w, &f->txs[i % UNIVERSE].hash)
                         : wallet_find_slot_scan(w, &f->txs[i % UNIVERSE].hash);
    clock_gettime(CLOCK_MONOTONIC, &b);
    return ((double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec)) / n;
}

static bool txi_benchmark(struct txi_fixture *f)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "txi_bench_wallet");
    if (!w) return false;
    wallet_init_zeroed(w);
    for (unsigned id = 0; id < 6; id++) txi_add(f, w, id);
    size_t sink = 0;
    double scan = txi_ns_per_lookup(w, f, false, &sink);
    double idx = txi_ns_per_lookup(w, f, true, &sink);
    /* ids 0..5 are present; 294 of every 300 lookups are absent. */
    printf("(10000 lookups, 6 used slots: scan %.0f ns, index %.0f ns, ratio %.0fx, %zu) ",
           scan, idx, scan / (idx > 0.5 ? idx : 0.5), sink % 10);
    wallet_free(w);
    free(w);
    return idx * 10.0 < scan;
}

static int txi_report(const char *name, bool ok)
{
    printf("%s\n", ok ? "OK" : "FAIL");
    (void)name;
    return ok ? 0 : 1;
}

int test_wallet_tx_index_checks(void);
int test_wallet_tx_index_checks(void)
{
    struct txi_fixture *f = zcl_calloc(1, sizeof(*f), "txi_fixture");
    struct wallet *restored = NULL;
    int failures = 0;
    if (!f) return 1;
    f->rng = 0x2545F491u;
    for (unsigned i = 0; i < UNIVERSE; i++) txi_make(&f->txs[i], i);
    f->w = zcl_calloc(1, sizeof(*f->w), "txi_wallet");
    if (!f->w) { free(f); return 1; }
    wallet_init_zeroed(f->w);
    wallet_tx_index_set_check_for_test(false);

    printf("wallet tx index equals linear scan over a random sequence... ");
    txi_run(f, f->w, STEPS);
    printf("(%zu compared, %zu used) ", f->compared, f->w->num_wallet_tx);
    failures += txi_report("random", f->wrong == 0 && f->compared > STEPS &&
                                         f->w->num_wallet_tx > 0);
    printf("wallet tx index after restore from a fixture database... ");
    bool ok = txi_restore(f, &restored) && f->wrong == 0;
    if (ok) { txi_run(f, restored, STEPS / 2); ok = f->wrong == 0; }
    failures += txi_report("restore", ok);
    printf("wallet tx index with duplicate txids returns the lowest slot... ");
    failures += txi_report("duplicates", txi_duplicates(f));
    printf("wallet tx index with a full table... ");
    failures += txi_report("full", txi_table_full());
    printf("wallet tx index absent-txid lookups beat the scan... ");
    failures += txi_report("bench", txi_benchmark(f));
    wallet_tx_index_set_check_for_test(true);
    printf("wallet tx index checked mode saw no disagreement... ");
    failures += txi_report("checked", wallet_tx_index_mismatches_for_test() == 0);

    if (restored) { wallet_free(restored); free(restored); }
    wallet_free(f->w);
    free(f->w);
    for (unsigned i = 0; i < UNIVERSE; i++) transaction_free(&f->txs[i]);
    free(f);
    return failures;
}
