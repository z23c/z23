/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for the §3 boot-wedge fix: commitment-validated
 * reconciliation of a STALE coins_best_block anchor
 * (coins_view_sqlite.c: coins_reconcile_stale_anchor, reached from the
 * boot tip-consistency gate before the strict FATAL).
 *
 * The wedge: the coins anchor pointer gets reset far below the real
 * applied UTXO frontier (live incident: anchor → height 200 while the
 * `utxos` table held millions of rows), so the gate sees the UTXO set
 * "ahead of tip" and FATAL-halts, crash-looping the node.
 *
 * The fix heals the anchor ONLY under cryptographic proof — a stored
 * height-stamped SHA3 commitment that recompute-matches the live `utxos`
 * table — and otherwise preserves the FATAL. These tests assert BOTH
 * directions: a proven-intact set heals (boot continues), and every
 * un-proven shape (no commitment, torn set, commitment below the live
 * frontier) is refused so the gate is never weakened.
 *
 * Like test_coins_view_atomicity.c, the fixtures build a minimal node.db
 * directly so the logic is exercised deterministically without a live
 * chain. The reconcile function is static, so it is driven through the
 * public coins_view_sqlite_open() entry point.
 */

#include "test/test_core.h"
#include "storage/coins_view_sqlite.h"
#include "coins/utxo_commitment.h"
#include "models/database.h"
#include "config/boot_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int car_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void car_path(char *buf, size_t n, const char *tag)
{
    snprintf(buf, n, "./test-tmp/car_%d_%s", (int)getpid(), tag);
}

static bool car_build_min_db(sqlite3 **out, const char *dbpath)
{
    if (sqlite3_open(dbpath, out) != SQLITE_OK) return false;
    char *err = NULL;
    int rc = sqlite3_exec(*out,
        "CREATE TABLE IF NOT EXISTS utxos("
        " txid BLOB, vout INTEGER, value INTEGER,"
        " script BLOB, script_type INTEGER, address_hash BLOB,"
        " height INTEGER, is_coinbase INTEGER,"
        " PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS node_state("
        " key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS blocks("
        " hash BLOB PRIMARY KEY, height INTEGER, status INTEGER);",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "car_build_min_db exec err: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Seed a UTXO row whose txid is `txid_byte` repeated 32x and vout `vout`,
 * so distinct (txid_byte,vout) pairs are distinct rows. */
static void car_seed_utxo(sqlite3 *db, int height, uint8_t txid_byte, int vout)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(db,
        "INSERT INTO utxos(txid,vout,value,script,script_type,"
        " address_hash,height,is_coinbase) VALUES(?,?,1000,NULL,0,NULL,?,0)",
        -1, &s, NULL);
    uint8_t txid[32];
    memset(txid, txid_byte, 32);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, vout);
    sqlite3_bind_int(s, 3, height);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

static void car_set_anchor(sqlite3 *db, const uint8_t hash[32])
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('coins_best_block',?)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash, 32, SQLITE_STATIC);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

static void car_seed_block(sqlite3 *db, const uint8_t hash[32], int height)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(db,
        "INSERT INTO blocks(hash,height,status) VALUES(?,?,3)",
        -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

/* Read back the stored coins_best_block blob; returns true + fills out[32]. */
static bool car_get_anchor(sqlite3 *db, uint8_t out[32])
{
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM node_state WHERE key='coins_best_block'",
            -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW &&
            sqlite3_column_bytes(s, 0) == 32) {
            memcpy(out, sqlite3_column_blob(s, 0), 32);
            ok = true;
        }
        sqlite3_finalize(s);
    }
    return ok;
}

/* Seed a small UTXO set spanning heights 100..frontier_h, a stale anchor
 * at height 200, and the frontier block. Returns the frontier block hash
 * in frontier_hash[32]. The commitment is NOT saved here — callers decide. */
static void car_seed_wedge(sqlite3 *db, int frontier_h, uint8_t frontier_hash[32])
{
    car_seed_utxo(db, 100, 0x11, 0);
    car_seed_utxo(db, 150, 0x22, 0);
    car_seed_utxo(db, 200, 0x33, 0);
    car_seed_utxo(db, 200, 0x33, 1);
    car_seed_utxo(db, frontier_h, 0x44, 0);

    /* Stale anchor: coins_best_block → a block at height 200. */
    uint8_t stale[32]; memset(stale, 0xAB, 32);
    car_seed_block(db, stale, 200);
    car_set_anchor(db, stale);

    /* The true frontier block (where the heal must re-point the anchor). */
    memset(frontier_hash, 0xCD, 32);
    car_seed_block(db, frontier_hash, frontier_h);
}

/* CASE 1 — proven-intact set: stale anchor heals to the committed height. */
static int test_coins_anchor_reconcile_heals_on_valid_commitment(void)
{
    int failures = 0;
    char dir[256]; car_path(dir, sizeof(dir), "heal"); car_mkdir_p(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("car: stale anchor + matching SHA3 commitment -> healed, anchor re-pointed") {
        sqlite3 *db = NULL;
        ASSERT(car_build_min_db(&db, dbpath));
        const int FRONTIER = 500;
        uint8_t frontier_hash[32];
        car_seed_wedge(db, FRONTIER, frontier_hash);

        /* Store a trusted commitment over the (intact) set at the frontier. */
        uint8_t cmt[32]; uint64_t count = 0;
        utxo_commitment_sha3_compute(db, cmt, &count);
        ASSERT(count == 5);
        ASSERT(utxo_commitment_sha3_save(db, cmt, FRONTIER, count));

        /* Open the coins view: the gate sees UTXOs ahead of the stale
         * anchor, calls reconcile, the recompute matches -> heal -> accept. */
        struct coins_view_sqlite cvs;
        ASSERT(coins_view_sqlite_open(&cvs, db));   /* healed, boot continues */

        /* The anchor must now point at the verified frontier block. */
        uint8_t now[32];
        ASSERT(car_get_anchor(db, now));
        ASSERT(memcmp(now, frontier_hash, 32) == 0);

        coins_view_sqlite_close(&cvs);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 2 — no stored commitment (the live datadir shape): MUST refuse. */
static int test_coins_anchor_reconcile_refuses_without_commitment(void)
{
    int failures = 0;
    char dir[256]; car_path(dir, sizeof(dir), "nocmt"); car_mkdir_p(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("car: stale anchor + NO commitment -> refused (FATAL preserved)") {
        sqlite3 *db = NULL;
        ASSERT(car_build_min_db(&db, dbpath));
        uint8_t frontier_hash[32];
        car_seed_wedge(db, 500, frontier_hash);
        /* deliberately store NO utxo_sha3 commitment */

        struct coins_view_sqlite cvs;
        bool opened = coins_view_sqlite_open(&cvs, db);
        ASSERT(!opened);   /* cannot prove the set -> refuse */

        /* The anchor must be UNCHANGED (still the stale height-200 block). */
        uint8_t now[32], stale[32]; memset(stale, 0xAB, 32);
        ASSERT(car_get_anchor(db, now));
        ASSERT(memcmp(now, stale, 32) == 0);

        sqlite3_close(db);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 3 — torn set: a dropped spend (lower-height row removed, MAX(height)
 * unchanged) makes the recompute MISMATCH the stored commitment -> refuse.
 * This is the consensus-safety case: a double-spendable set is NOT healed. */
static int test_coins_anchor_reconcile_refuses_torn_set(void)
{
    int failures = 0;
    char dir[256]; car_path(dir, sizeof(dir), "torn"); car_mkdir_p(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("car: stale anchor + commitment but TORN set -> refused (no silent heal)") {
        sqlite3 *db = NULL;
        ASSERT(car_build_min_db(&db, dbpath));
        const int FRONTIER = 500;
        uint8_t frontier_hash[32];
        car_seed_wedge(db, FRONTIER, frontier_hash);

        /* Commit the intact set, THEN drop a low-height row (simulating a
         * lost spend). MAX(utxos.height) stays at FRONTIER, so the gate
         * still routes to reconcile, but the recompute no longer matches. */
        uint8_t cmt[32]; uint64_t count = 0;
        utxo_commitment_sha3_compute(db, cmt, &count);
        ASSERT(utxo_commitment_sha3_save(db, cmt, FRONTIER, count));
        ASSERT(sqlite3_exec(db, "DELETE FROM utxos WHERE height=100",
                            NULL, NULL, NULL) == SQLITE_OK);

        struct coins_view_sqlite cvs;
        bool opened = coins_view_sqlite_open(&cvs, db);
        ASSERT(!opened);   /* commitment mismatch -> refuse */

        sqlite3_close(db);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 4 — commitment below the live frontier: cannot justify advancing the
 * anchor past un-committed rows -> refuse. */
static int test_coins_anchor_reconcile_refuses_commitment_below_frontier(void)
{
    int failures = 0;
    char dir[256]; car_path(dir, sizeof(dir), "below"); car_mkdir_p(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("car: commitment height below live UTXO frontier -> refused") {
        sqlite3 *db = NULL;
        ASSERT(car_build_min_db(&db, dbpath));
        const int FRONTIER = 500;
        uint8_t frontier_hash[32];
        car_seed_wedge(db, FRONTIER, frontier_hash);

        /* Store a commitment stamped at height 400 (< frontier 500), even
         * though its hash matches the full table — the height guard must
         * refuse because rows exist above the committed height. */
        uint8_t cmt[32]; uint64_t count = 0;
        utxo_commitment_sha3_compute(db, cmt, &count);
        ASSERT(utxo_commitment_sha3_save(db, cmt, 400, count));

        struct coins_view_sqlite cvs;
        bool opened = coins_view_sqlite_open(&cvs, db);
        ASSERT(!opened);   /* commitment does not cover the frontier -> refuse */

        sqlite3_close(db);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 5 — the -reindex-chainstate pre-gate wipe (subsection B): clearing the
 * coins state lets the boot integrity gate pass so the rebuild can run. Drives
 * the shared helper boot_index_clear_coins_state() directly over a real
 * node_db, asserting the utxos table and all three coins-state keys are gone. */
static int car_state_key_count(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL; int n = -1;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM node_state WHERE key IN "
            "('coins_best_block','utxo_commitment','utxo_sha3')",
            -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) n = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    return n;
}

static int test_reindex_clear_coins_state(void)
{
    int failures = 0;
    char dir[256]; car_path(dir, sizeof(dir), "wipe"); car_mkdir_p(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("car: boot_index_clear_coins_state wipes utxos + anchor + commitments") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT(node_db_exec(&ndb,
            "INSERT INTO utxos(txid,vout,value,script,script_type,"
            "address_hash,height,is_coinbase) "
            "VALUES(x'1111',0,1000,x'00',0,NULL,500,0)"));
        ASSERT(node_db_exec(&ndb, "INSERT OR REPLACE INTO node_state(key,value)"
            " VALUES('coins_best_block',x'abcd')"));
        ASSERT(node_db_exec(&ndb, "INSERT OR REPLACE INTO node_state(key,value)"
            " VALUES('utxo_sha3',x'01')"));
        ASSERT(node_db_exec(&ndb, "INSERT OR REPLACE INTO node_state(key,value)"
            " VALUES('utxo_commitment',x'02')"));
        ASSERT(car_state_key_count(&ndb) == 3);

        ASSERT(boot_index_clear_coins_state(&ndb));

        sqlite3_stmt *s = NULL; int rows = -1;
        ASSERT(sqlite3_prepare_v2(ndb.db, "SELECT COUNT(*) FROM utxos",
                                  -1, &s, NULL) == SQLITE_OK);
        if (sqlite3_step(s) == SQLITE_ROW) rows = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        ASSERT(rows == 0);                       /* UTXO set cleared */
        ASSERT(car_state_key_count(&ndb) == 0);  /* anchor + commitments gone */

        node_db_close(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 6 — the heal is DURABLE/idempotent: after it re-points the anchor, a
 * second open passes via the normal tip-OK path (not reconcile) and the anchor
 * stays put. Proves the full self-heal loop a real boot would take. */
static int test_coins_anchor_reconcile_heal_is_durable(void)
{
    int failures = 0;
    char dir[256]; car_path(dir, sizeof(dir), "durable"); car_mkdir_p(dir);
    char dbpath[512]; snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("car: heal is durable — second open passes without re-healing") {
        sqlite3 *db = NULL;
        ASSERT(car_build_min_db(&db, dbpath));
        const int FRONTIER = 500;
        uint8_t frontier_hash[32];
        car_seed_wedge(db, FRONTIER, frontier_hash);
        uint8_t cmt[32]; uint64_t count = 0;
        utxo_commitment_sha3_compute(db, cmt, &count);
        ASSERT(utxo_commitment_sha3_save(db, cmt, FRONTIER, count));

        struct coins_view_sqlite cvs;
        ASSERT(coins_view_sqlite_open(&cvs, db));     /* first open heals */
        coins_view_sqlite_close(&cvs);

        struct coins_view_sqlite cvs2;
        ASSERT(coins_view_sqlite_open(&cvs2, db));    /* second open: clean */
        uint8_t now[32];
        ASSERT(car_get_anchor(db, now));
        ASSERT(memcmp(now, frontier_hash, 32) == 0);  /* anchor unchanged */
        coins_view_sqlite_close(&cvs2);

        sqlite3_close(db);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_coins_anchor_reconcile_all(void)
{
    int failures = 0;
    failures += test_coins_anchor_reconcile_heals_on_valid_commitment();
    failures += test_coins_anchor_reconcile_refuses_without_commitment();
    failures += test_coins_anchor_reconcile_refuses_torn_set();
    failures += test_coins_anchor_reconcile_refuses_commitment_below_frontier();
    failures += test_reindex_clear_coins_state();
    failures += test_coins_anchor_reconcile_heal_is_durable();
    return failures;
}
