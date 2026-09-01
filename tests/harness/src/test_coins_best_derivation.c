/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wave-2 regression tests for THE coins-best derivation
 * (reducer_frontier_derive_coins_best) and the derived boot gate in
 * coins_view_sqlite_check_tip_consistency.
 *
 * Doctrine under test (docs/TENACITY.md I1/I2): the coins-best fact has ONE
 * authoritative encoding — coins_kv's co-committed coins_applied_height in
 * progress.kv plus the durable stage logs. The node_state 'coins_best_block'
 * key and the node.db `utxos` mirror are CACHES: rebuildable, never believed
 * over the derivation, never guess-reconciled.
 *
 * Two suites:
 *   1. Derivation unit tests on a throwaway sqlite handle carrying the REAL
 *      progress.kv schema (same fixture style as test_reducer_frontier.c).
 *   2. The drift test — "the cache lies, the machine does not care": a
 *      scratch datadir whose node_state anchor is GARBAGE and whose mirror
 *      holds orphan rows above the frontier must (a) derive correctly,
 *      (b) PASS the boot gate with ZERO mutations (no guess-repair, no
 *      auto-rewind), and (c) still FATAL on the legacy branch once
 *      coins_applied_height is deleted (legacy datadirs keep their gate). */

#include "test/test_core.h"

#include "jobs/reducer_frontier.h"
#include "storage/coins_kv.h"
#include "storage/coins_view_sqlite.h"
#include "storage/progress_store.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── shared fixture helpers ─────────────────────────────────────────── */

/* Production progress.kv log/cursor schema subset the derivation touches. */
static bool cbd_build_progress_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor ("
        "  name TEXT PRIMARY KEY, cursor INTEGER);"
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[cbd] schema: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Write coins_applied_height as the production little-endian int64 blob. */
static bool cbd_set_applied(sqlite3 *db, int64_t applied)
{
    uint8_t blob[8];
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)((uint64_t)applied >> (8 * i));
    return progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY,
                             blob, sizeof(blob));
}

/* Make coins_kv the PROVEN authority on this handle (the other two rungs of
 * coins_kv_is_proven_authority): one live coin row + the migration stamp. */
static bool cbd_mark_canonical(sqlite3 *db)
{
    if (!coins_kv_ensure_schema(db))
        return false;
    uint8_t txid[32];
    memset(txid, 0x77, 32);
    if (!coins_kv_add(db, txid, 0, 1000LL, 1, false, NULL, 0))
        return false;
    uint8_t one = 1;
    return progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
}

static void cbd_hash(uint8_t out[32], int32_t h, uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = tag;
}

static bool cbd_put_tip_finalize(sqlite3 *db, int32_t h, int ok,
                                 const uint8_t hash[32], const char *status)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log(height,status,ok,tip_hash)"
            " VALUES(?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_text(st, 2, status ? status : "ok", -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok);
    if (hash) sqlite3_bind_blob(st, 4, hash, 32, SQLITE_STATIC);
    else      sqlite3_bind_null(st, 4);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool cbd_put_validate_headers(sqlite3 *db, int32_t h, int ok,
                                     const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok)"
            " VALUES(?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

/* ── Suite 1: derivation unit tests (throwaway handle) ──────────────── */

#define CBD_H ((int32_t)3142976)

static int cbd_unit_absent_key(void)
{
    int failures = 0;
    TEST("cbd: absent coins_applied_height -> found=false, success") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = true, found = true;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(!found);
        ASSERT(!hf);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* The RED rung: coins_applied_height present but coins_kv NOT the proven
 * authority (no migration stamp / empty set — e.g. a legacy datadir whose
 * frontier was cursor-backfilled while the coins still live only in the
 * node.db mirror) must NOT count as canonical: found=false, success. */
static int cbd_unit_unproven_authority(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: applied present but authority unproven -> found=false") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(coins_kv_ensure_schema(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));

        /* (a) no migration stamp, empty set. */
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = true, found = true;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(!found && !hf);

        /* (b) rows but still no migration stamp (the bdsr RED-2 class). */
        uint8_t txid[32];
        memset(txid, 0x78, 32);
        ASSERT(coins_kv_add(db, txid, 0, 1000LL, 1, false, NULL, 0));
        hf = true; found = true;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(!found && !hf);

        /* (c) stamp set -> NOW canonical. */
        uint8_t one = 1;
        ASSERT(progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                 &one, 1));
        hf = true; found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found && height == H && !hf);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* PRODUCTION write convention (tip_finalize_stage.c step_finalize): the
 * "finalized" ok=1 row at height X stores the LOOKAHEAD hash(X+1) — the
 * step binds new_tip = active_chain_at(X+1) into the row at X. Only
 * status='anchor' seed rows store the block's OWN hash (row X -> hash(X)).
 * The derivation must therefore find hash(h) in the finalized row at h-1,
 * NEVER in the raw row at h (whose blob is hash(h+1) — the off-by-one this
 * suite regression-pins). */
static int cbd_unit_finalized_rung(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: production finalized rows (row X -> hash X+1) -> derived "
         "hash is hash(H), not hash(H+1)") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(cbd_mark_canonical(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));
        uint8_t want[32], succ[32];
        cbd_hash(want, H, 0x11);       /* hash of block H   */
        cbd_hash(succ, H + 1, 0x12);   /* hash of block H+1 */
        /* Fully-caught-up production shape: finalized row at H-1 carries
         * hash(H); finalized row at H carries hash(H+1). NO validate_headers
         * row, so ONLY the tip_finalize witness can resolve. */
        ASSERT(cbd_put_tip_finalize(db, H - 1, 1, want, "finalized"));
        ASSERT(cbd_put_tip_finalize(db, H, 1, succ, "finalized"));
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = false, found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found);
        ASSERT(height == H);
        ASSERT(hf);
        ASSERT(memcmp(hash, want, 32) == 0);   /* hash(H)        */
        ASSERT(memcmp(hash, succ, 32) != 0);   /* NEVER hash(H+1) */
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* The ANCHOR convention: a status='anchor' seed row at H carries the block's
 * OWN hash(H) and is the valid witness AT h. An anchor at h-1 carries
 * hash(h-1) and must NOT be misread as hash(h). */
static int cbd_unit_anchor_rung(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: anchor row at H witnesses hash(H); anchor at H-1 does NOT") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(cbd_mark_canonical(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));

        /* (a) only an anchor at H-1 (carries hash(H-1)): no witness for h=H,
         * so hash_found=false while the height stays authoritative. */
        uint8_t prev_own[32];
        cbd_hash(prev_own, H - 1, 0x21);
        ASSERT(cbd_put_tip_finalize(db, H - 1, 1, prev_own, "anchor"));
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = true, found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found && height == H);
        ASSERT(!hf);

        /* (b) anchor at H (carries hash(H)): the witness. */
        uint8_t want[32];
        cbd_hash(want, H, 0x22);
        ASSERT(cbd_put_tip_finalize(db, H, 1, want, "anchor"));
        hf = false; found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found && height == H);
        ASSERT(hf);
        ASSERT(memcmp(hash, want, 32) == 0);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int cbd_unit_pipeline_window(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: empty tip_finalize window at frontier -> validate_headers "
         "hash (the 2026-06-11 wave2-proof fixture shape)") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(cbd_mark_canonical(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));
        /* tip_finalize has NOT reached the frontier: no ok=1 rows at H-1/H
         * (only a non-witnessing ok=0 row, hash NULL, like a real
         * reorg_detected entry). validate_headers_log supplies hash(H). */
        ASSERT(cbd_put_tip_finalize(db, H - 1, 0, NULL, "reorg_detected"));
        uint8_t want[32];
        cbd_hash(want, H, 0x33);
        ASSERT(cbd_put_validate_headers(db, H, 1, want));
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = false, found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found);
        ASSERT(height == H);
        ASSERT(hf);
        ASSERT(memcmp(hash, want, 32) == 0);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* Cross-log identity guard: when BOTH witnesses resolve they must byte-agree;
 * a mismatch withholds the hash (hash_found=false) instead of guessing —
 * the height stays authoritative either way. */
static int cbd_unit_cross_log_guard(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: cross-log agreement -> hash; mismatch -> hash withheld") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(cbd_mark_canonical(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));
        uint8_t want[32];
        cbd_hash(want, H, 0x41);
        ASSERT(cbd_put_tip_finalize(db, H - 1, 1, want, "finalized"));
        ASSERT(cbd_put_validate_headers(db, H, 1, want));

        /* (a) both witnesses agree -> hash resolved. */
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = false, found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found && height == H && hf);
        ASSERT(memcmp(hash, want, 32) == 0);

        /* (b) validate_headers now claims a DIFFERENT block at H (stale
         * finalized row across a reorg): don't guess — hash withheld,
         * success, height stands. */
        uint8_t other[32];
        cbd_hash(other, H, 0x42);
        ASSERT(cbd_put_validate_headers(db, H, 1, other));
        hf = true; found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found && height == H);
        ASSERT(!hf);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int cbd_unit_no_hash_rung(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: neither log row -> hash_found=false, height authoritative") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(cbd_mark_canonical(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = true, found = false;
        ASSERT(reducer_frontier_derive_coins_best(db, &height, hash,
                                                  &hf, &found));
        ASSERT(found);
        ASSERT(height == H);
        ASSERT(!hf);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int cbd_unit_recursive_lock(void)
{
    int failures = 0;
    const int32_t H = CBD_H;
    TEST("cbd: recursive-lock smoke — callable under progress_store_tx_lock") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);
        ASSERT(cbd_build_progress_schema(db));
        ASSERT(cbd_mark_canonical(db));
        ASSERT(cbd_set_applied(db, (int64_t)H + 1));
        uint8_t want[32];
        cbd_hash(want, H, 0x44);
        /* Production convention: the finalized row at H-1 carries hash(H). */
        ASSERT(cbd_put_tip_finalize(db, H - 1, 1, want, "finalized"));
        progress_store_tx_lock();
        int32_t height = -2;
        uint8_t hash[32];
        bool hf = false, found = false;
        bool ok = reducer_frontier_derive_coins_best(db, &height, hash,
                                                     &hf, &found);
        progress_store_tx_unlock();
        ASSERT(ok);
        ASSERT(found && height == H && hf);
        ASSERT(memcmp(hash, want, 32) == 0);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Suite 2: the drift test — the cache lies, the machine doesn't care ──
 *
 * Uses the SINGLETON progress store (the boot gate reads progress_store_db())
 * plus a minimal node.db, exactly like test_coins_anchor_reconcile.c. */

static int cbd_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool cbd_build_min_node_db(sqlite3 **out, const char *dbpath)
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
        fprintf(stderr, "[cbd] node.db schema: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static void cbd_seed_utxo(sqlite3 *db, int height, uint8_t txid_byte, int vout)
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

static int64_t cbd_utxo_rowcount(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM utxos",
                           -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW)
            n = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    return n;
}

static bool cbd_get_anchor(sqlite3 *db, uint8_t out[32])
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

static int cbd_drift_test(void)
{
    int failures = 0;
    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/cbd_%d_drift", (int)getpid());
    cbd_mkdir_p("./test-tmp");
    cbd_mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("cbd drift: garbage cache + orphan mirror rows -> gate PASSES, "
         "derivation wins, ZERO mutations; legacy FATAL preserved") {
        const int32_t H = 500;

        /* Singleton progress store on the scratch dir (the gate reads it).
         * Close any store a prior test left open (safe when none is). */
        progress_store_close();
        ASSERT(progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        ASSERT(pdb != NULL);
        ASSERT(cbd_build_progress_schema(pdb));
        ASSERT(cbd_mark_canonical(pdb));
        ASSERT(cbd_set_applied(pdb, (int64_t)H + 1));
        uint8_t want[32];
        cbd_hash(want, H, 0x55);
        /* Production conventions: finalized row at H-1 carries hash(H);
         * finalized row at H carries hash(H+1); validate_headers carries
         * the block's own hash at H. Both witnesses agree on hash(H). */
        ASSERT(cbd_put_tip_finalize(pdb, H - 1, 1, want, "finalized"));
        uint8_t succ[32];
        cbd_hash(succ, H + 1, 0x56);
        ASSERT(cbd_put_tip_finalize(pdb, H, 1, succ, "finalized"));
        uint8_t vh[32];
        cbd_hash(vh, H, 0x55);
        ASSERT(cbd_put_validate_headers(pdb, H, 1, vh));

        /* node.db: a WRONG anchor blob + orphan mirror rows ABOVE H — the
         * exact shape the legacy gate FATALs / auto-rewinds on. */
        sqlite3 *db = NULL;
        ASSERT(cbd_build_min_node_db(&db, dbpath));
        cbd_seed_utxo(db, 100, 0x11, 0);
        cbd_seed_utxo(db, H, 0x22, 0);
        cbd_seed_utxo(db, H + 5, 0x33, 0);   /* orphan rows above frontier */
        cbd_seed_utxo(db, H + 5, 0x33, 1);
        uint8_t garbage[32];
        memset(garbage, 0xEE, 32);           /* hash of NO block anywhere */
        {
            sqlite3_stmt *s = NULL;
            ASSERT(sqlite3_prepare_v2(db,
                "INSERT OR REPLACE INTO node_state(key,value) "
                "VALUES('coins_best_block',?)", -1, &s, NULL) == SQLITE_OK);
            sqlite3_bind_blob(s, 1, garbage, 32, SQLITE_STATIC);
            ASSERT(sqlite3_step(s) == SQLITE_DONE);
            sqlite3_finalize(s);
        }
        int64_t rows_before = cbd_utxo_rowcount(db);
        ASSERT(rows_before == 4);

        /* (a) the derivation returns the correct height + hash */
        {
            int32_t height = -2;
            uint8_t hash[32];
            bool hf = false, found = false;
            ASSERT(reducer_frontier_derive_coins_best(pdb, &height, hash,
                                                      &hf, &found));
            ASSERT(found && height == H && hf);
            ASSERT(memcmp(hash, want, 32) == 0);
        }

        /* (b) the boot gate PASSES (open succeeds — no FATAL branch) */
        struct coins_view_sqlite cvs;
        ASSERT(coins_view_sqlite_open(&cvs, db));
        coins_view_sqlite_close(&cvs);

        /* (c) ZERO mutations: the lying cache still lies (no guess-repair
         * wrote it) and the orphan mirror rows survive (no auto-rewind
         * DELETE fired). The caches are diagnostics now, not decisions. */
        uint8_t now[32];
        ASSERT(cbd_get_anchor(db, now));
        ASSERT(memcmp(now, garbage, 32) == 0);
        ASSERT(cbd_utxo_rowcount(db) == rows_before);

        /* (d) legacy branch preserved: delete coins_applied_height and the
         * strict legacy gate must refuse this shape again (garbage anchor
         * unresolvable + rows above it -> WARN path resolves tip_height<0
         * => "continuing"; force the FATAL shape by clearing the anchor:
         * utxos present + no anchor = the orphan-UTXO MISMATCH FATAL). */
        ASSERT(progress_meta_delete(pdb, COINS_APPLIED_HEIGHT_KEY));
        {
            char *err = NULL;
            ASSERT(sqlite3_exec(db,
                "DELETE FROM node_state WHERE key='coins_best_block'",
                NULL, NULL, &err) == SQLITE_OK);
            (void)err;
        }
        struct coins_view_sqlite cvs2;
        ASSERT(!coins_view_sqlite_open(&cvs2, db));

        sqlite3_close(db);
        progress_store_close();
        PASS();
    } _test_next:;

    test_cleanup_tmpdir(dir);
    return failures;
}

int test_coins_best_derivation(void)
{
    int failures = 0;
    failures += cbd_unit_absent_key();
    failures += cbd_unit_unproven_authority();
    failures += cbd_unit_finalized_rung();
    failures += cbd_unit_anchor_rung();
    failures += cbd_unit_pipeline_window();
    failures += cbd_unit_cross_log_guard();
    failures += cbd_unit_no_hash_rung();
    failures += cbd_unit_recursive_lock();
    failures += cbd_drift_test();
    return failures;
}
