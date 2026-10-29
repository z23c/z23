/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for sync integrity and audit features:
 *   - SHA3 UTXO checkpoint verification logic
 *   - UTXO count sanity check logic
 *   - XOR commitment save/load/compare roundtrip
 *   - bg_hash_verification_service state machine
 *   - Stall recovery window expansion */

#include "test/test_core.h"
#include "net/net.h"
#include "coins/utxo_commitment.h"
#include "chain/checkpoints.h"
#include "services/authority_projection_audit.h"
#include "services/authority_projection_pair.h"
#include "services/bg_validation_service.h"
#include "services/bg_hash_verification_service.h"
#include "sync/sync_planner.h"
#include "services/utxo_recovery_service.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "validation/main_state.h"
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

/* ── Helper: open in-memory SQLite with node_state + utxos tables ── */

static sqlite3 *open_test_db(void)
{
    sqlite3 *db = NULL;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE node_state (key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE utxos ("
        "  txid BLOB, vout INT, value INT, script BLOB,"
        "  script_type INT, address_hash BLOB, height INT, is_coinbase INT);",
        NULL, NULL, NULL);
    return db;
}

/* ── SHA3 UTXO checkpoint tests ──────────────────────────────────── */

static int test_integrity_sha3_checkpoint_exists(void)
{
    int failures = 0;

    TEST("integrity: SHA3 UTXO checkpoint is available") {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        ASSERT(cp->height > 0);
        ASSERT(cp->utxo_count > 0);
        ASSERT(cp->total_supply > 0);

        /* SHA3 hash should not be all-zero */
        uint8_t zero[32] = {0};
        ASSERT(memcmp(cp->sha3_hash, zero, 32) != 0);
        ASSERT(memcmp(cp->block_hash, zero, 32) != 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_sha3_empty_db(void)
{
    int failures = 0;

    TEST("integrity: SHA3 of empty UTXO set is deterministic") {
        sqlite3 *db = open_test_db();
        uint8_t hash1[32], hash2[32];
        uint64_t count1 = 0, count2 = 0;

        utxo_commitment_sha3_compute(db, hash1, &count1);
        utxo_commitment_sha3_compute(db, hash2, &count2);

        ASSERT(count1 == 0);
        ASSERT(count2 == 0);
        ASSERT(memcmp(hash1, hash2, 32) == 0);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_sha3_deterministic_with_data(void)
{
    int failures = 0;

    TEST("integrity: SHA3 is deterministic over same UTXO set") {
        sqlite3 *db = open_test_db();

        /* Insert two UTXOs */
        uint8_t txid1[32] = {0}, txid2[32] = {0};
        txid1[0] = 0x11;
        txid2[0] = 0x22;
        sqlite3_stmt *ins = NULL;
        sqlite3_prepare_v2(db,
            "INSERT INTO utxos (txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES (?, ?, ?, X'76A914', 1, X'00', ?, 0)",
            -1, &ins, NULL);

        sqlite3_bind_blob(ins, 1, txid1, 32, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, 0);
        sqlite3_bind_int64(ins, 3, 50000000);
        sqlite3_bind_int(ins, 4, 100);
        sqlite3_step(ins);
        sqlite3_reset(ins);

        sqlite3_bind_blob(ins, 1, txid2, 32, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, 1);
        sqlite3_bind_int64(ins, 3, 25000000);
        sqlite3_bind_int(ins, 4, 200);
        sqlite3_step(ins);
        sqlite3_finalize(ins);

        uint8_t hash1[32], hash2[32];
        uint64_t count1 = 0, count2 = 0;
        utxo_commitment_sha3_compute(db, hash1, &count1);
        utxo_commitment_sha3_compute(db, hash2, &count2);

        ASSERT(count1 == 2);
        ASSERT(count2 == 2);
        ASSERT(memcmp(hash1, hash2, 32) == 0);

        /* Different from empty set */
        sqlite3 *db2 = open_test_db();
        uint8_t empty_hash[32];
        uint64_t empty_count = 0;
        utxo_commitment_sha3_compute(db2, empty_hash, &empty_count);
        ASSERT(memcmp(hash1, empty_hash, 32) != 0);

        sqlite3_close(db2);
        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_sha3_save_load_roundtrip(void)
{
    int failures = 0;

    TEST("integrity: SHA3 save/load roundtrip preserves data") {
        sqlite3 *db = open_test_db();
        uint8_t hash[32];
        memset(hash, 0xAB, 32);

        ASSERT(utxo_commitment_sha3_save(db, hash, 3056758, 1350000));

        uint8_t loaded[32] = {0};
        int32_t height = 0;
        uint64_t count = 0;
        ASSERT(utxo_commitment_sha3_load(db, loaded, &height, &count));
        ASSERT(memcmp(hash, loaded, 32) == 0);
        ASSERT(height == 3056758);
        ASSERT(count == 1350000);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── XOR commitment save/load/compare tests ──────────────────────── */

static int test_integrity_xor_save_load_roundtrip(void)
{
    int failures = 0;

    TEST("integrity: XOR commitment save/load roundtrip") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x77, 32);
        utxo_commitment_add(&uc, txid, 3, 42000000, 999);

        ASSERT(utxo_commitment_save_checkpoint(db, &uc));

        struct utxo_commitment loaded;
        ASSERT(utxo_commitment_load_checkpoint(db, &loaded));
        ASSERT(utxo_commitment_equal(&uc, &loaded));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_load_missing(void)
{
    int failures = 0;

    TEST("integrity: XOR load returns false when no checkpoint saved") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        ASSERT(!utxo_commitment_load_checkpoint(db, &uc));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Height-tracked checkpoint (UTXO_COMMITMENT_HEIGHT_KEY) ─────────
 * utxo_mirror_delta_apply / mirror_rebuild_from_coins_kv stamp a covering
 * height with the checkpoint so utxo_commitment_boot_check_and_refresh can
 * skip its O(n) `utxos` scan when the stamp is trustworthy. */

static int test_integrity_xor_at_height_roundtrip(void)
{
    int failures = 0;

    TEST("integrity: XOR checkpoint save/load AT a covering height") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x55, 32);
        utxo_commitment_add(&uc, txid, 1, 7000000, 500);

        ASSERT(utxo_commitment_save_checkpoint_at_height(db, &uc, 500));

        struct utxo_commitment loaded;
        int32_t h = -1;
        ASSERT(utxo_commitment_load_checkpoint_at_height(db, &loaded, &h));
        ASSERT(utxo_commitment_equal(&uc, &loaded));
        ASSERT(h == 500);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_plain_save_clears_height(void)
{
    int failures = 0;

    TEST("integrity: plain save_checkpoint clears a prior height stamp") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x66, 32);
        utxo_commitment_add(&uc, txid, 0, 1000, 10);

        /* Stamp a height, then overwrite via the PLAIN (no covering-height
         * claim) save — the load_checkpoint_at_height reader must now
         * refuse to trust ANY height (even the stale one), because a
         * downstream incremental maintainer folding deltas on top of a
         * height that doesn't actually describe this blob would silently
         * corrupt the accumulator (see utxo_mirror_delta_apply). */
        ASSERT(utxo_commitment_save_checkpoint_at_height(db, &uc, 500));
        ASSERT(utxo_commitment_save_checkpoint(db, &uc));

        struct utxo_commitment loaded;
        int32_t h = -1;
        ASSERT(!utxo_commitment_load_checkpoint_at_height(db, &loaded, &h));
        /* The blob itself is still intact via the plain loader. */
        ASSERT(utxo_commitment_load_checkpoint(db, &loaded));
        ASSERT(utxo_commitment_equal(&uc, &loaded));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_boot_check_fast_path_no_scan(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh fast path skips the O(n) scan "
         "when the height stamp matches") {
        sqlite3 *db = open_test_db();

        /* A checkpoint claiming h=200, but the `utxos` TABLE itself is
         * empty/wrong — if the fast path actually recomputed, it would
         * disagree and refresh. It must NOT recompute at all when the
         * stamp matches mirror_height, so the (deliberately wrong-vs-table)
         * saved digest survives untouched. */
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x77, 32);
        utxo_commitment_add(&uc, txid, 2, 42, 199);
        ASSERT(utxo_commitment_save_checkpoint_at_height(db, &uc, 200));

        struct utxo_commitment computed;
        bool refreshed = true;
        ASSERT(utxo_commitment_boot_check_and_refresh(db, 200, &computed, &refreshed));
        ASSERT(!refreshed);
        ASSERT(utxo_commitment_equal(&computed, &uc));

        /* The on-disk checkpoint must be BYTE-IDENTICAL to before — a fast
         * path that touched it would defeat the whole point. */
        struct utxo_commitment still_saved;
        ASSERT(utxo_commitment_load_checkpoint(db, &still_saved));
        ASSERT(utxo_commitment_equal(&still_saved, &uc));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_boot_check_slow_path_refreshes(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh slow path recomputes + "
         "re-stamps on a genuine mismatch") {
        sqlite3 *db = open_test_db();

        /* Stale checkpoint: no height stamp at all (plain save), and it
         * disagrees with the live `utxos` table below. */
        struct utxo_commitment stale;
        utxo_commitment_init(&stale);
        uint8_t stale_txid[32];
        memset(stale_txid, 0x88, 32);
        utxo_commitment_add(&stale, stale_txid, 0, 1, 1);
        ASSERT(utxo_commitment_save_checkpoint(db, &stale));

        sqlite3_exec(db,
            "INSERT INTO utxos (txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES (X'9900000000000000000000000000000000000000000000000000000000000000',"
            " 0, 500000, X'76A914', 1, X'00', 300, 0)",
            NULL, NULL, NULL);

        struct utxo_commitment computed;
        bool refreshed = false;
        ASSERT(utxo_commitment_boot_check_and_refresh(db, 300, &computed, &refreshed));
        ASSERT(refreshed);

        struct utxo_commitment ground_truth;
        utxo_commitment_compute_db(db, &ground_truth);
        ASSERT(utxo_commitment_equal(&computed, &ground_truth));

        /* Re-stamped at the asserted mirror_height (300) — a subsequent
         * incremental maintainer can now trust it as a baseline. */
        struct utxo_commitment restamped;
        int32_t h = -1;
        ASSERT(utxo_commitment_load_checkpoint_at_height(db, &restamped, &h));
        ASSERT(h == 300);
        ASSERT(utxo_commitment_equal(&restamped, &ground_truth));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_verify_db_match(void)
{
    int failures = 0;

    TEST("integrity: XOR verify_db matches compute_db for same data") {
        sqlite3 *db = open_test_db();

        /* Insert a UTXO */
        sqlite3_exec(db,
            "INSERT INTO utxos (txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES (X'DEAD000000000000000000000000000000000000000000000000000000000000',"
            " 0, 100000, X'76A914', 1, X'00', 50, 0)",
            NULL, NULL, NULL);

        struct utxo_commitment computed;
        utxo_commitment_compute_db(db, &computed);
        ASSERT(computed.count > 0);

        /* Verify should pass against itself */
        ASSERT(utxo_commitment_verify_db(db, &computed));

        /* Verify should fail against a wrong commitment */
        struct utxo_commitment wrong;
        utxo_commitment_init(&wrong);
        ASSERT(!utxo_commitment_verify_db(db, &wrong));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Characterization: boot_check_and_refresh branches ───────────── */

static void seed_utxo_row(sqlite3 *db, const char *table, uint8_t tag,
                          uint32_t vout, int64_t value, int32_t height)
{
    uint8_t txid[32];
    memset(txid, tag, 32);
    char sql[96];
    snprintf(sql, sizeof(sql),
             "INSERT INTO %s (txid, vout, value, height) VALUES (?, ?, ?, ?)",
             table);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 2, vout);
    sqlite3_bind_int64(s, 3, value);
    sqlite3_bind_int64(s, 4, height);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

static int test_integrity_xor_boot_check_null_and_empty(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh refuses a NULL db; with no "
         "checkpoint stored it returns true and writes nothing") {
        struct utxo_commitment computed = {0};
        bool refreshed = true;
        ASSERT(!utxo_commitment_boot_check_and_refresh(NULL, 200, &computed, &refreshed));
        ASSERT(!refreshed);
        ASSERT(computed.count == 0);

        sqlite3 *db = open_test_db();
        seed_utxo_row(db, "utxos", 0x11, 0, 100, 5);
        computed.count = 77;
        refreshed = true;
        ASSERT(utxo_commitment_boot_check_and_refresh(db, 10, &computed, &refreshed));
        ASSERT(!refreshed);
        ASSERT(computed.count == 77); /* out_computed left as the caller set it */
        struct utxo_commitment none = {0};
        ASSERT(!utxo_commitment_load_checkpoint(db, &none));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_boot_check_refresh_paths(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh refresh paths: plain save at "
         "mirror_height -1, stamp-height mismatch, accurate unstamped kept") {
        /* Stale, unstamped checkpoint, mirror_height -1: refresh via the plain
         * save (no stamp), NULL out params accepted. */
        {
            sqlite3 *db = open_test_db();
            struct utxo_commitment stale = {0};
            uint8_t stale_txid[32];
            memset(stale_txid, 0x88, 32);
            utxo_commitment_add(&stale, stale_txid, 0, 1, 1);
            ASSERT(utxo_commitment_save_checkpoint(db, &stale));
            seed_utxo_row(db, "utxos", 0x99, 0, 500000, 300);

            ASSERT(utxo_commitment_boot_check_and_refresh(db, -1, NULL, NULL));
            struct utxo_commitment ground_truth = {0};
            utxo_commitment_compute_db(db, &ground_truth);
            struct utxo_commitment saved = {0};
            ASSERT(utxo_commitment_load_checkpoint(db, &saved));
            ASSERT(utxo_commitment_equal(&saved, &ground_truth));
            int32_t h = -1;
            ASSERT(!utxo_commitment_load_checkpoint_at_height(db, &saved, &h));
            sqlite3_close(db);
        }

        /* Stamped at 200, asked about 201: no fast path, recompute over the
         * empty utxos table and re-stamp at 201. */
        {
            sqlite3 *db = open_test_db();
            struct utxo_commitment stamped = {0};
            uint8_t txid[32];
            memset(txid, 0xAA, 32);
            utxo_commitment_add(&stamped, txid, 0, 1, 1);
            ASSERT(utxo_commitment_save_checkpoint_at_height(db, &stamped, 200));

            struct utxo_commitment computed = {0};
            bool refreshed = false;
            ASSERT(utxo_commitment_boot_check_and_refresh(db, 201, &computed, &refreshed));
            ASSERT(refreshed);
            ASSERT(computed.count == 0);
            struct utxo_commitment restamped = {0};
            int32_t h = -1;
            ASSERT(utxo_commitment_load_checkpoint_at_height(db, &restamped, &h));
            ASSERT(h == 201);
            ASSERT(restamped.count == 0);
            sqlite3_close(db);
        }

        /* Accurate but unstamped: kept as is, not restamped. */
        {
            sqlite3 *db = open_test_db();
            seed_utxo_row(db, "utxos", 0x44, 1, 700, 20);
            struct utxo_commitment ground_truth = {0};
            utxo_commitment_compute_db(db, &ground_truth);
            ASSERT(utxo_commitment_save_checkpoint(db, &ground_truth));

            struct utxo_commitment computed = {0};
            bool refreshed = true;
            ASSERT(utxo_commitment_boot_check_and_refresh(db, 300, &computed, &refreshed));
            ASSERT(!refreshed);
            ASSERT(utxo_commitment_equal(&computed, &ground_truth));
            struct utxo_commitment after = {0};
            int32_t h = -1;
            ASSERT(!utxo_commitment_load_checkpoint_at_height(db, &after, &h));
            sqlite3_close(db);
        }
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_boot_check_save_failure(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh reports a failed refresh save "
         "as false, for the stamped and the plain save") {
        sqlite3 *db = open_test_db();
        struct utxo_commitment stale = {0};
        uint8_t stale_txid[32];
        memset(stale_txid, 0xBB, 32);
        utxo_commitment_add(&stale, stale_txid, 0, 1, 1);
        ASSERT(utxo_commitment_save_checkpoint(db, &stale));
        seed_utxo_row(db, "utxos", 0xCC, 0, 900, 400);

        struct utxo_commitment ground_truth = {0};
        utxo_commitment_compute_db(db, &ground_truth);

        /* Block every node_state insert; the SELECT-side loader still works. */
        ASSERT(sqlite3_exec(db,
            "CREATE TRIGGER block_node_state_write BEFORE INSERT ON node_state "
            "BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
            NULL, NULL, NULL) == SQLITE_OK);

        struct utxo_commitment computed = {0};
        bool refreshed = true;
        ASSERT(!utxo_commitment_boot_check_and_refresh(db, 400, &computed, &refreshed));
        ASSERT(!refreshed);
        ASSERT(utxo_commitment_equal(&computed, &ground_truth));
        ASSERT(!utxo_commitment_boot_check_and_refresh(db, -1, NULL, &refreshed));
        ASSERT(!refreshed);

        /* The stale blob is still what is stored. */
        struct utxo_commitment still = {0};
        ASSERT(utxo_commitment_load_checkpoint(db, &still));
        ASSERT(utxo_commitment_equal(&still, &stale));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Characterization: compute_range (bounded keyspace window) ───── */

/* Three valid 32-byte txids (tags 0x11 < 0x22 < 0x33) plus one 1-byte txid
 * that sorts last: compute_range counts it toward the SQL LIMIT but skips
 * it (sqlite3_column_bytes < 32), so it never adds a row. */
static void seed_range_fixture(sqlite3 *db)
{
    seed_utxo_row(db, "utxos", 0x11, 0, 100, 5);
    seed_utxo_row(db, "utxos", 0x22, 1, 200, 9);
    seed_utxo_row(db, "utxos", 0x33, 2, 300, 7);
    sqlite3_exec(db,
        "INSERT INTO utxos (txid, vout, value, height) VALUES (X'FF', 0, 1, 1)",
        NULL, NULL, NULL);
}

static int test_integrity_range_refuses_bad_args(void)
{
    int failures = 0;

    TEST("integrity: compute_range refuses NULL db/out/txid, max_rows <= 0, "
         "any table other than coins/utxos, and an absent table") {
        sqlite3 *db = open_test_db();
        seed_range_fixture(db);
        uint8_t lo[32] = {0};
        struct utxo_commitment out = {0};
        size_t rows = 99;
        int32_t mn = 0;
        int32_t mx = 0;

        ASSERT(!utxo_commitment_compute_range(NULL, "utxos", lo, 10,
                                              &out, &rows, &mn, &mx, NULL));
        ASSERT(rows == 0);
        ASSERT(mn == INT32_MAX);
        ASSERT(mx == INT32_MIN);
        ASSERT(!utxo_commitment_compute_range(db, "utxos", lo, 10,
                                              NULL, &rows, &mn, &mx, NULL));
        ASSERT(!utxo_commitment_compute_range(db, "utxos", NULL, 10,
                                              &out, &rows, &mn, &mx, NULL));
        ASSERT(!utxo_commitment_compute_range(db, "utxos", lo, 0,
                                              &out, &rows, &mn, &mx, NULL));
        ASSERT(!utxo_commitment_compute_range(db, "utxos", lo, -1,
                                              &out, &rows, &mn, &mx, NULL));
        ASSERT(!utxo_commitment_compute_range(db, NULL, lo, 10,
                                              &out, &rows, NULL, NULL, NULL));
        ASSERT(!utxo_commitment_compute_range(db, "node_state", lo, 10,
                                              &out, &rows, NULL, NULL, NULL));
        ASSERT(!utxo_commitment_compute_range(db, "UTXOS", lo, 10,
                                              &out, &rows, NULL, NULL, NULL));
        ASSERT(!utxo_commitment_compute_range(db, "utxos;DROP TABLE utxos", lo, 10,
                                              &out, &rows, NULL, NULL, NULL));
        ASSERT(rows == 0);
        ASSERT(out.count == 0);

        /* `coins` is allowed but absent from this schema: prepare fails. */
        ASSERT(!utxo_commitment_compute_range(db, "coins", lo, 10,
                                              &out, &rows, NULL, NULL, NULL));
        ASSERT(rows == 0);
        ASSERT(out.count == 0);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_range_windows(void)
{
    int failures = 0;

    TEST("integrity: compute_range windows: full keyspace, max_rows cap, "
         "inclusive txid_lo, short-txid-only window, empty table") {
        sqlite3 *db = open_test_db();
        seed_range_fixture(db);
        uint8_t tag11[32];
        uint8_t tag22[32];
        uint8_t tag33[32];
        memset(tag11, 0x11, 32);
        memset(tag22, 0x22, 32);
        memset(tag33, 0x33, 32);
        uint8_t lo[32] = {0};
        uint8_t last[32] = {0};
        struct utxo_commitment out = {0};
        size_t rows = 0;
        int32_t mn = 0;
        int32_t mx = 0;

        /* Full keyspace: matches compute_db; the short txid is skipped. */
        ASSERT(utxo_commitment_compute_range(db, "utxos", lo, 100,
                                             &out, &rows, &mn, &mx, last));
        ASSERT(rows == 3);
        ASSERT(out.count == 3);
        ASSERT(mn == 5);
        ASSERT(mx == 9);
        ASSERT(memcmp(last, tag33, 32) == 0);
        struct utxo_commitment full = {0};
        utxo_commitment_compute_db(db, &full);
        ASSERT(utxo_commitment_equal(&out, &full));

        /* NULL rows/min/max/last outputs are accepted. */
        struct utxo_commitment bare = {0};
        ASSERT(utxo_commitment_compute_range(db, "utxos", lo, 100,
                                             &bare, NULL, NULL, NULL, NULL));
        ASSERT(utxo_commitment_equal(&bare, &full));

        /* max_rows cap keeps the first two rows in txid order. */
        ASSERT(utxo_commitment_compute_range(db, "utxos", lo, 2,
                                             &out, &rows, &mn, &mx, last));
        ASSERT(rows == 2);
        ASSERT(mn == 5);
        ASSERT(mx == 9);
        ASSERT(memcmp(last, tag22, 32) == 0);
        struct utxo_commitment expect = {0};
        utxo_commitment_add(&expect, tag11, 0, 100, 5);
        utxo_commitment_add(&expect, tag22, 1, 200, 9);
        ASSERT(utxo_commitment_equal(&out, &expect));

        /* txid_lo = 0x22.. is inclusive: rows 0x22 and 0x33 only. */
        memset(lo, 0x22, 32);
        ASSERT(utxo_commitment_compute_range(db, "utxos", lo, 10,
                                             &out, &rows, &mn, &mx, last));
        ASSERT(rows == 2);
        ASSERT(out.count == 2);
        ASSERT(mn == 7);
        ASSERT(mx == 9);
        ASSERT(memcmp(last, tag33, 32) == 0);

        /* Only the short txid is in window: zero rows, last_txid untouched. */
        memset(lo, 0x44, 32);
        memset(last, 0xCD, 32);
        ASSERT(utxo_commitment_compute_range(db, "utxos", lo, 10,
                                             &out, &rows, &mn, &mx, last));
        ASSERT(rows == 0);
        ASSERT(out.count == 0);
        ASSERT(mn == INT32_MAX);
        ASSERT(mx == INT32_MIN);
        ASSERT(last[0] == 0xCD && last[31] == 0xCD);

        /* Empty table: a valid zero-row success, same sentinel behaviour. */
        sqlite3 *empty = open_test_db();
        memset(lo, 0, 32);
        ASSERT(utxo_commitment_compute_range(empty, "utxos", lo, 10,
                                             &out, &rows, &mn, &mx, last));
        ASSERT(rows == 0);
        ASSERT(out.count == 0);
        ASSERT(mn == INT32_MAX);
        ASSERT(mx == INT32_MIN);
        ASSERT(last[0] == 0xCD);
        sqlite3_close(empty);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_range_coins_table(void)
{
    int failures = 0;

    TEST("integrity: compute_range accepts the coins table with the same "
         "hash-and-fold") {
        sqlite3 *db = open_test_db();
        ASSERT(sqlite3_exec(db,
            "CREATE TABLE coins (txid BLOB, vout INT, value INT, height INT,"
            " PRIMARY KEY (txid, vout));",
            NULL, NULL, NULL) == SQLITE_OK);
        seed_utxo_row(db, "coins", 0x55, 3, 1, 42);

        uint8_t lo[32] = {0};
        uint8_t last[32] = {0};
        struct utxo_commitment out = {0};
        size_t rows = 0;
        int32_t mn = 0;
        int32_t mx = 0;
        ASSERT(utxo_commitment_compute_range(db, "coins", lo, 10,
                                             &out, &rows, &mn, &mx, last));
        ASSERT(rows == 1);
        ASSERT(mn == 42);
        ASSERT(mx == 42);
        uint8_t tag55[32];
        memset(tag55, 0x55, 32);
        ASSERT(memcmp(last, tag55, 32) == 0);
        struct utxo_commitment expect = {0};
        utxo_commitment_add(&expect, tag55, 3, 1, 42);
        ASSERT(utxo_commitment_equal(&out, &expect));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── UTXO count sanity check tests ───────────────────────────────── */

static int test_integrity_utxo_count_check(void)
{
    int failures = 0;

    TEST("integrity: UTXO count sanity check logic") {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (!cp) { PASS(); goto _test_next; }

        /* Simulate count within 10% — should be OK */
        uint64_t good_count = cp->utxo_count;
        double ratio = (double)good_count / (double)cp->utxo_count;
        ASSERT(ratio >= 0.9 && ratio <= 1.1);

        /* Count off by 20% — should trigger warning */
        uint64_t warn_count = (uint64_t)(cp->utxo_count * 0.8);
        ratio = (double)warn_count / (double)cp->utxo_count;
        ASSERT(ratio < 0.9);
        struct utxo_count_check_result warn =
            utxo_recovery_classify_count_check(
                cp->height, cp->height, cp->utxo_count, warn_count);
        ASSERT(warn.level == UTXO_COUNT_CHECK_WARNING);

        /* Count off by 60% — should trigger critical */
        uint64_t crit_count = (uint64_t)(cp->utxo_count * 0.4);
        ratio = (double)crit_count / (double)cp->utxo_count;
        ASSERT(ratio < 0.5);
        struct utxo_count_check_result crit =
            utxo_recovery_classify_count_check(
                cp->height, cp->height, cp->utxo_count, crit_count);
        ASSERT(crit.level == UTXO_COUNT_CHECK_CRITICAL);

        /* Far past the checkpoint, current UTXO count can legitimately
         * drift; the operator needs a stale-reference diagnostic, not a
         * corruption warning. */
        struct utxo_count_check_result stale =
            utxo_recovery_classify_count_check(
                cp->height + 10000, cp->height, cp->utxo_count, warn_count);
        ASSERT(stale.level == UTXO_COUNT_CHECK_INFO_STALE_REFERENCE);

        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_mismatch_policy(void)
{
    int failures = 0;

    TEST("integrity: XOR mismatch classifier splits stale vs corruption") {
        /* Growth past the checkpoint = the set advanced while tracking
         * was frozen (bulk import): stale, refresh — never a candidate. */
        ASSERT(!utxo_recovery_xor_mismatch_is_corruption_candidate(42, 43));
        ASSERT(!utxo_recovery_xor_mismatch_is_corruption_candidate(
            1000000, 1300000));
        /* Equal counts with a differing accumulator (callers only invoke
         * this on a mismatch) = same cardinality, different contents:
         * the clearest corruption signature. */
        ASSERT(utxo_recovery_xor_mismatch_is_corruption_candidate(42, 42));
        /* Shrink below the checkpoint = rows vanished: a
         * silent keyspace-tail truncation class. */
        ASSERT(utxo_recovery_xor_mismatch_is_corruption_candidate(43, 42));
        ASSERT(utxo_recovery_xor_mismatch_is_corruption_candidate(
            1300000, 900000));
        PASS();
    } _test_next:;

    return failures;
}

/* ── bg_hash_verification_service tests ──────────────────────────── */

static int test_integrity_bg_hash_verify_init(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify initializes to idle state") {
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, NULL, NULL, "/tmp", NULL);

        ASSERT(!svc.thread_started);
        ASSERT(!atomic_load(&svc.stop_requested));

        struct bg_hash_verify_progress p = bg_hash_verify_get_progress(&svc);
        ASSERT(p.state == BG_HASH_VERIFY_IDLE);
        ASSERT(p.verified_height == 0);
        ASSERT(p.chain_height == 0);
        ASSERT(p.mismatches == 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_owns_datadir(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify owns the caller's datadir bytes") {
        /* Boot resolves the datadir into a stack buffer; the worker must copy it. */
        char caller_path[512];
        snprintf(caller_path, sizeof(caller_path), "%s", "/tmp");
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, NULL, NULL, caller_path, NULL);
        memset(caller_path, 0xA5, sizeof(caller_path));
        ASSERT(svc.datadir == svc.datadir_storage);
        ASSERT_STR_EQ(svc.datadir, "/tmp");

        /* No datadir => refuse, rather than walk every height, read nothing,
         * and publish "0 mismatches". */
        char oversized[sizeof(svc.datadir_storage) + 1u];
        memset(oversized, 'x', sizeof(oversized) - 1u);
        oversized[sizeof(oversized) - 1u] = '\0';
        struct main_state ms;
        main_state_init(&ms);
        bg_hash_verify_init(&svc, &ms, NULL, oversized, NULL);
        ASSERT(svc.datadir == NULL);
        ASSERT(svc.datadir_storage[0] == '\0');
        ASSERT(!bg_hash_verify_start(&svc).ok);
        ASSERT(!svc.thread_started);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_state_names(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify state names are correct") {
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_IDLE), "idle");
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_RUNNING), "running");
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_COMPLETE), "complete");
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_FAILED), "failed");
        ASSERT_STR_EQ(bg_hash_verify_state_name(99), "unknown");
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_no_start_without_ms(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify refuses to start without main_state") {
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, NULL, NULL, "/tmp", NULL);

        ASSERT(!bg_hash_verify_start(&svc).ok);
        ASSERT(!svc.thread_started);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_supervisor_contract(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify registers a chain supervisor contract") {
        bool ok = true;
        supervisor_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, &ms, NULL, "/tmp", NULL);

        struct zcl_result r = bg_hash_verify_start(&svc);
        ok = ok && r.ok;
        if (r.ok) {
            struct supervisor_snapshot snaps[SUPERVISOR_CAP];
            int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
            const struct supervisor_snapshot *hash = NULL;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].name, "chain.bg_hash_verify") == 0) {
                    hash = &snaps[i];
                    break;
                }
            }
            ok = ok && hash != NULL;
            if (hash)
                ok = ok && hash->period_secs == 0;
            bg_hash_verify_stop(&svc);
            ok = ok && supervisor_child_count_total() == 0;
        }

        main_state_free(&ms);
        supervisor_reset_for_testing();
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_validation_supervisor_contract(void)
{
    int failures = 0;

    TEST("integrity: bg_validation registers a chain supervisor contract") {
        bool ok = true;
        supervisor_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        struct bg_validation_service svc;
        bg_validation_init(&svc, &ms, NULL, "/tmp", NULL);

        ok = ok && bg_validation_start(&svc);
        if (ok) {
            struct supervisor_snapshot snaps[SUPERVISOR_CAP];
            int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
            const struct supervisor_snapshot *valid = NULL;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].name, "chain.bg_validation") == 0) {
                    valid = &snaps[i];
                    break;
                }
            }
            ok = ok && valid != NULL;
            if (valid)
                ok = ok && valid->period_secs == 0;
            bg_validation_stop(&svc);
            ok = ok && supervisor_child_count_total() == 0;
        }

        main_state_free(&ms);
        supervisor_reset_for_testing();
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Stall recovery window expansion tests ───────────────────────── */

static int test_integrity_stall_recovery_plan(void)
{
    int failures = 0;

    TEST("integrity: stall recovery plans getheaders action") {
        struct sync_getheaders_action action;
        struct sync_stall_recovery recovery;

        memset(&action, 0, sizeof(action));
        memset(&recovery, 0, sizeof(recovery));

        /* No recovery → no action */
        syncsvc_plan_recovery_getheaders(&action, &recovery, NULL);
        ASSERT(!action.should_send);

        /* Active recovery → should send */
        recovery.should_recover = true;
        syncsvc_plan_recovery_getheaders(&action, &recovery, NULL);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP);

        /* With tip parent request */
        struct block_index tip, parent;
        memset(&tip, 0, sizeof(tip));
        memset(&parent, 0, sizeof(parent));
        tip.pprev = &parent;
        recovery.should_request_tip_parent = true;
        syncsvc_plan_recovery_getheaders(&action, &recovery, &tip);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP_PARENT);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_stall_recovery_anchor(void)
{
    int failures = 0;

    TEST("integrity: stall recovery anchor selection") {
        struct sync_stall_recovery recovery;
        memset(&recovery, 0, sizeof(recovery));

        /* Not recovering → TIP */
        ASSERT(syncsvc_recovery_header_anchor(&recovery, NULL) ==
               SYNC_HEADER_REQUEST_TIP);

        /* Recovering without tip parent → TIP */
        recovery.should_recover = true;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, NULL) ==
               SYNC_HEADER_REQUEST_TIP);

        /* Recovering with tip parent → TIP_PARENT */
        struct block_index tip, parent;
        memset(&tip, 0, sizeof(tip));
        memset(&parent, 0, sizeof(parent));
        tip.pprev = &parent;
        recovery.should_request_tip_parent = true;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, &tip) ==
               SYNC_HEADER_REQUEST_TIP_PARENT);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_valid_block_at_tip(void)
{
    int failures = 0;

    TEST("integrity: valid block triggers AT_TIP when headers caught up") {
        struct sync_block_acceptance result;
        struct p2p_node node;

        memset(&node, 0, sizeof(node));
        node.starting_height = 1000;
        node.state = PEER_SYNCING_BLOCKS;

        /* Not yet at peer tip */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 999, 1500, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.reached_peer_tip);

        /* At peer tip, headers caught up */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 1000, 1001, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(result.should_set_sync_state);
        ASSERT(result.next_sync_state == SYNC_AT_TIP);
        ASSERT(result.should_update_peer_state);
        ASSERT(result.next_peer_state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_progress_snapshot(void)
{
    int failures = 0;

    TEST("integrity: progress snapshot collects sync metrics") {
        struct sync_progress_snapshot snap;

        syncsvc_collect_progress(&snap, NULL, SYNC_BLOCKS_DOWNLOAD,
                                 500, 1000, 0, 0);
        ASSERT(snap.sync_state == SYNC_BLOCKS_DOWNLOAD);
        ASSERT(snap.chain_height == 500);
        ASSERT(snap.header_height == 1000);
        ASSERT(snap.should_log_progress);

        /* AT_TIP should not log progress */
        syncsvc_collect_progress(&snap, NULL, SYNC_AT_TIP,
                                 1000, 1000, 0, 0);
        ASSERT(!snap.should_log_progress);

        /* AT_TIP with stale tip */
        syncsvc_collect_progress(&snap, NULL, SYNC_AT_TIP,
                                 1000, 1000, 100, 800);
        ASSERT(snap.tip_stale);
        ASSERT(snap.tip_stale_seconds == 700);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Registration ─────────────────────────────────────────────────── */

/* ── Authority(coins)-vs-projection(utxos) redundant cross-check ─────── */

/* Find the named blocker in the process registry; copy its reason. */
static bool find_blocker_reason(const char *id, char *reason_out, size_t cap)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, id) == 0) {
            if (reason_out && cap)
                snprintf(reason_out, cap, "%s", snaps[i].reason);
            return true;
        }
    }
    return false;
}

static int test_integrity_ap_audit_match_no_fire(void)
{
    int failures = 0;

    TEST("integrity: ap-audit matching authority/projection does NOT fire") {
        ap_audit_reset_for_test();

        uint8_t root[32];
        for (int i = 0; i < 32; i++) root[i] = (uint8_t)(i * 7 + 1);

        struct ap_audit_inputs in;
        memset(&in, 0, sizeof(in));
        in.comparable = true;
        in.height = 3176325;
        memcpy(in.auth_root, root, 32);
        memcpy(in.proj_root, root, 32);
        in.auth_count = 1300000;
        in.proj_count = 1300000;

        struct ap_audit_verdict v;
        ap_audit_evaluate(&in, &v);
        ASSERT(!v.violated);

        /* Even repeated clean verdicts must never raise the blocker. */
        ASSERT(!ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                       in.proj_count, in.auth_root,
                                       in.proj_root));
        ASSERT(!ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                       in.proj_count, in.auth_root,
                                       in.proj_root));
        ASSERT(!find_blocker_reason("authority_projection_divergence",
                                    NULL, 0));

        /* A non-comparable input (heights disagreed / moved mid-scan) is a
         * clean no-violation, never a false fire. */
        struct ap_audit_inputs nc = in;
        nc.comparable = false;
        nc.auth_count = 42; /* would differ, but not comparable */
        struct ap_audit_verdict vnc;
        ap_audit_evaluate(&nc, &vnc);
        ASSERT(!vnc.violated);

        ap_audit_reset_for_test();
        PASS();
    } _test_next:;
    return failures;
}

/* ── authority_projection_pair: pure pair-identity contract ─────────── */

static struct ap_pair_identity pair_id(int64_t h, uint8_t hash_byte, uint64_t gen)
{
    struct ap_pair_identity id = { .applied_height = h, .generation = gen,
                                   .read_ok = true };
    if (hash_byte != 0) {
        id.has_tip_hash = true;
        memset(id.tip_hash, hash_byte, sizeof id.tip_hash);
    }
    return id;
}

struct pair_case {
    const char *name;
    struct ap_pair_identity id[4]; /* auth_before, proj_before, auth_after, proj_after */
    int null_idx;                  /* -1: none, else the argument passed as NULL */
    enum ap_pair_verdict want;
};

static int test_integrity_ap_pair_check_table(void)
{
    int failures = 0;
    struct ap_pair_identity a = pair_id(100, 0xAA, 7);
    struct ap_pair_identity bad = a;
    bad.read_ok = false;
    struct ap_pair_identity ovl = a;
    ovl.overlay_active = true;
    struct ap_pair_identity changed_hash = pair_id(100, 0xBB, 7);   /* same height+gen, new hash */
    struct ap_pair_identity gen = pair_id(100, 0xAA, 8);
    struct ap_pair_identity mov = pair_id(101, 0xAA, 7);
    struct ap_pair_identity h99 = pair_id(99, 0xAA, 7);
    struct ap_pair_identity nohash = pair_id(100, 0, 7);
    struct ap_pair_identity reorg = pair_id(100, 0xCC, 7);
    struct ap_pair_identity h99nohash = pair_id(99, 0, 7);
    struct ap_pair_identity zero_hash = nohash;
    zero_hash.has_tip_hash = true; /* present bytes, not an absent hash */
    const struct pair_case cases[] = {
        { "all equal with hashes", {a, a, a, a}, -1, AP_PAIR_COMPARABLE },
        { "stable unequal side-local generations", {a, gen, a, gen}, -1, AP_PAIR_COMPARABLE },
        { "present zero hash", {zero_hash, zero_hash, zero_hash, zero_hash}, -1,
          AP_PAIR_COMPARABLE },
        { "present zero hash versus absent", {zero_hash, nohash, zero_hash, nohash}, -1,
          AP_PAIR_BRANCH_UNKNOWN },
        /* A hidden A->B->A with unchanged/reused generation has these same
         * endpoints. Only the caller's producer guarantees can exclude it. */
        { "ABA limitation: indistinguishable endpoints", {a, a, a, a}, -1,
          AP_PAIR_COMPARABLE },

        { "read_ok false auth_before", {bad, a, a, a}, -1, AP_PAIR_READ_ERROR },
        { "read_ok false proj_before", {a, bad, a, a}, -1, AP_PAIR_READ_ERROR },
        { "read_ok false auth_after", {a, a, bad, a}, -1, AP_PAIR_READ_ERROR },
        { "read_ok false proj_after", {a, a, a, bad}, -1, AP_PAIR_READ_ERROR },
        { "NULL auth_before", {a, a, a, a}, 0, AP_PAIR_READ_ERROR },
        { "NULL proj_before", {a, a, a, a}, 1, AP_PAIR_READ_ERROR },
        { "NULL auth_after", {a, a, a, a}, 2, AP_PAIR_READ_ERROR },
        { "NULL proj_after", {a, a, a, a}, 3, AP_PAIR_READ_ERROR },
        { "overlay active", {a, ovl, a, a}, -1, AP_PAIR_OVERLAY_ACTIVE },
        { "authority final hash changed", {a, a, changed_hash, a}, -1, AP_PAIR_MOVED },
        { "projection final hash changed", {a, a, a, changed_hash}, -1, AP_PAIR_MOVED },
        { "generation bump", {a, a, a, gen}, -1, AP_PAIR_MOVED },
        { "height moved", {a, a, mov, a}, -1, AP_PAIR_MOVED },
        { "hash appeared mid-window", {a, nohash, a, a}, -1, AP_PAIR_MOVED },
        { "hash disappeared mid-window", {a, a, a, nohash}, -1, AP_PAIR_MOVED },
        { "height mismatch", {a, h99, a, h99}, -1, AP_PAIR_HEIGHT_MISMATCH },
        { "projection lacks hash", {a, nohash, a, nohash}, -1, AP_PAIR_BRANCH_UNKNOWN },
        { "authority lacks hash", {nohash, a, nohash, a}, -1, AP_PAIR_BRANCH_UNKNOWN },
        { "equal height different hash", {a, reorg, a, reorg}, -1, AP_PAIR_BRANCH_MISMATCH },
        { "overlay beats height mismatch", {ovl, h99, ovl, h99}, -1, AP_PAIR_OVERLAY_ACTIVE },
        { "read error beats overlay", {bad, ovl, a, a}, -1, AP_PAIR_READ_ERROR },
        { "moved beats branch unknown", {a, nohash, changed_hash, nohash}, -1, AP_PAIR_MOVED },
        { "moved beats height mismatch", {a, h99, mov, h99}, -1, AP_PAIR_MOVED },
        { "height mismatch beats branch unknown", {a, h99nohash, a, h99nohash}, -1,
          AP_PAIR_HEIGHT_MISMATCH },
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const struct pair_case *c = &cases[i];
        TEST(c->name) {
            const struct ap_pair_identity *p[4];
            for (int k = 0; k < 4; k++)
                p[k] = (k == c->null_idx) ? NULL : &c->id[k];
            enum ap_pair_verdict got = ap_pair_check(p[0], p[1], p[2], p[3]);
            ASSERT_EQ((int)got, (int)c->want);
            PASS();
        } _test_next:;
    }
    return failures;
}

static int test_integrity_ap_pair_verdict_names(void)
{
    int failures = 0;
    TEST("integrity: ap-pair verdict names") {
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_COMPARABLE), "comparable");
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_READ_ERROR), "read_error");
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_OVERLAY_ACTIVE), "overlay_active");
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_HEIGHT_MISMATCH), "height_mismatch");
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_BRANCH_UNKNOWN), "branch_unknown");
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_BRANCH_MISMATCH), "branch_mismatch");
        ASSERT_STR_EQ(ap_pair_verdict_name(AP_PAIR_MOVED), "moved");
        ASSERT_STR_EQ(ap_pair_verdict_name((enum ap_pair_verdict)99), "unknown");
        ASSERT_STR_EQ(ap_pair_verdict_name((enum ap_pair_verdict)-1), "unknown");
        PASS();
    } _test_next:;
    return failures;
}

static int test_integrity_ap_audit_divergence_fires(void)
{
    int failures = 0;

    TEST("integrity: ap-audit planted divergence raises blocker w/ both roots") {
        ap_audit_reset_for_test();

        uint8_t auth_root[32], proj_root[32];
        for (int i = 0; i < 32; i++) {
            auth_root[i] = (uint8_t)(i + 1);   /* authority */
            proj_root[i] = (uint8_t)(0xF0 + i); /* projection — different */
        }
        char auth_hex[65] = {0}, proj_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            snprintf(auth_hex + i * 2, 3, "%02x", auth_root[i]);
            snprintf(proj_hex + i * 2, 3, "%02x", proj_root[i]);
        }

        struct ap_audit_inputs in;
        memset(&in, 0, sizeof(in));
        in.comparable = true;
        in.height = 3176326;
        memcpy(in.auth_root, auth_root, 32);
        memcpy(in.proj_root, proj_root, 32);
        in.auth_count = 1300001;
        in.proj_count = 1300000; /* also a count mismatch */

        struct ap_audit_verdict v;
        ap_audit_evaluate(&in, &v);
        ASSERT(v.violated);
        ASSERT(v.root_mismatch);
        ASSERT(v.count_mismatch);

        /* First confirmation sample: streak=1 — must NOT raise yet. */
        bool raised1 = ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                              in.proj_count, in.auth_root,
                                              in.proj_root);
        ASSERT(!raised1);
        ASSERT(!find_blocker_reason("authority_projection_divergence", NULL, 0));

        /* Second consecutive sample: streak=2 — raises the PERMANENT blocker. */
        bool raised2 = ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                              in.proj_count, in.auth_root,
                                              in.proj_root);
        ASSERT(raised2);

        char reason[BLOCKER_REASON_MAX];
        ASSERT(find_blocker_reason("authority_projection_divergence",
                                   reason, sizeof(reason)));
        /* The alarm names BOTH roots + the height. */
        ASSERT(strstr(reason, auth_hex) != NULL);
        ASSERT(strstr(reason, proj_hex) != NULL);
        ASSERT(strstr(reason, "3176326") != NULL);

        /* A subsequent clean pass self-clears the latch. */
        struct ap_audit_verdict clean;
        memset(&clean, 0, sizeof(clean));
        ASSERT(!ap_audit_apply_verdict(&clean, in.height, in.auth_count,
                                       in.auth_count, in.auth_root,
                                       in.auth_root));
        ASSERT(!find_blocker_reason("authority_projection_divergence", NULL, 0));

        ap_audit_reset_for_test();
        PASS();
    } _test_next:;
    return failures;
}

int test_integrity(void)
{
    int failures = 0;

    /* SHA3 UTXO checkpoint verification */
    failures += test_integrity_sha3_checkpoint_exists();
    failures += test_integrity_sha3_empty_db();
    failures += test_integrity_sha3_deterministic_with_data();
    failures += test_integrity_sha3_save_load_roundtrip();

    /* XOR commitment persistence */
    failures += test_integrity_xor_save_load_roundtrip();
    failures += test_integrity_xor_load_missing();
    failures += test_integrity_xor_at_height_roundtrip();
    failures += test_integrity_xor_plain_save_clears_height();
    failures += test_integrity_xor_boot_check_fast_path_no_scan();
    failures += test_integrity_xor_boot_check_slow_path_refreshes();
    failures += test_integrity_xor_verify_db_match();
    failures += test_integrity_xor_boot_check_null_and_empty();
    failures += test_integrity_xor_boot_check_refresh_paths();
    failures += test_integrity_xor_boot_check_save_failure();
    failures += test_integrity_range_refuses_bad_args();
    failures += test_integrity_range_windows();
    failures += test_integrity_range_coins_table();

    /* UTXO count sanity check */
    failures += test_integrity_utxo_count_check();

    /* XOR mismatch stale-vs-corruption classifier */
    failures += test_integrity_xor_mismatch_policy();

    /* bg_hash_verification_service */
    failures += test_integrity_bg_hash_verify_init();
    failures += test_integrity_bg_hash_verify_owns_datadir();
    failures += test_integrity_bg_hash_verify_state_names();
    failures += test_integrity_bg_hash_verify_no_start_without_ms();
    failures += test_integrity_bg_hash_verify_supervisor_contract();
    failures += test_integrity_bg_validation_supervisor_contract();

    /* Redundant authority(coins)-vs-projection(utxos) cross-check */
    failures += test_integrity_ap_audit_match_no_fire();
    failures += test_integrity_ap_audit_divergence_fires();
    failures += test_integrity_ap_pair_check_table();
    failures += test_integrity_ap_pair_verdict_names();

    /* Stall recovery and sync integrity */
    failures += test_integrity_stall_recovery_plan();
    failures += test_integrity_stall_recovery_anchor();
    failures += test_integrity_valid_block_at_tip();
    failures += test_integrity_progress_snapshot();

    return failures;
}
