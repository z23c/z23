/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: prove coins_kv export reads one WAL generation and rejects malformed rows. */
#include "test/test_core.h"

#include "storage/coins_kv.h"
#include "storage/coins_kv_read_snapshot.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CKRS_CHECK(name, expression) do {                                \
    if (expression) printf("  coins_kv_read_snapshot: %s... OK\n", name); \
    else {                                                               \
        printf("  coins_kv_read_snapshot: %s... FAIL\n", name);          \
        failures++;                                                      \
    }                                                                    \
} while (0)

static bool ckrs_set_frontier(sqlite3 *db, int32_t applied)
{
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool ok = coins_kv_set_applied_height_in_tx(db, applied) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok)
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return ok;
}

static bool ckrs_add(sqlite3 *db, uint8_t tag, uint32_t vout, int64_t value,
                     int32_t height)
{
    uint8_t txid[32] = {0};
    uint8_t script[2] = {0x51, tag};
    txid[0] = tag;
    txid[31] = 0xa5;
    return coins_kv_add(db, txid, vout, value, height, false,
                        script, sizeof(script));
}

static bool ckrs_commit_newer_wal_generation(sqlite3 *db)
{
    return sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
           ckrs_add(db, 0x20, 0, 200, 11) &&
           coins_kv_set_applied_height_in_tx(db, 12) &&
           coins_kv_bump_authority_generation_in_tx(db) &&
           sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
}

static enum coins_kv_read_snapshot_step ckrs_next_step_or_error(
    struct coins_kv_read_snapshot *snap,
    struct coins_kv_read_snapshot_row *row)
{
    return snap ? coins_kv_read_snapshot_next(snap, row)
                : COINS_KV_READ_SNAPSHOT_ERROR;
}

static int ckrs_count_rows(struct coins_kv_read_snapshot *snap,
                           struct coins_kv_read_snapshot_row *row,
                           enum coins_kv_read_snapshot_step *step)
{
    int rows = 0;
    while (snap && (*step = coins_kv_read_snapshot_next(snap, row)) ==
                       COINS_KV_READ_SNAPSHOT_ROW)
        rows++;
    return rows;
}

static bool ckrs_second_snapshot_saw_new_generation(
    const struct coins_kv_read_snapshot *snap,
    const struct coins_kv_read_snapshot_info *info,
    int rows, enum coins_kv_read_snapshot_step step)
{
    return snap && info->applied_height == 12 && rows == 2 &&
           info->authority_generation == 1 &&
           step == COINS_KV_READ_SNAPSHOT_DONE;
}

static bool ckrs_insert_malformed_row(sqlite3 *db)
{
    uint8_t bad_txid[31] = {0x30};
    sqlite3_stmt *insert = NULL;
    bool malformed_inserted = sqlite3_prepare_v2(
        db, "INSERT INTO coins(txid,vout,value,height,is_coinbase,script) "
            "VALUES(?,0,1,11,0,X'51')", -1, &insert, NULL) == SQLITE_OK;
    if (malformed_inserted) {
        malformed_inserted = sqlite3_bind_blob(insert, 1, bad_txid,
                                                sizeof(bad_txid), SQLITE_STATIC) == SQLITE_OK &&
                             sqlite3_step(insert) == SQLITE_DONE;
    }
    sqlite3_finalize(insert);
    return malformed_inserted;
}

static bool ckrs_scan_until_error(struct coins_kv_read_snapshot *snap,
                                  struct coins_kv_read_snapshot_row *row)
{
    while (snap) {
        enum coins_kv_read_snapshot_step step = coins_kv_read_snapshot_next(snap, row);
        if (step == COINS_KV_READ_SNAPSHOT_ERROR)
            return true;
        if (step == COINS_KV_READ_SNAPSHOT_DONE)
            return false;
    }
    return false;
}

/* ---- boundary and malformed-row cases, run on the same open store ---- */

#define CKRS_Z30 "0000000000" "0000000000" "0000000000"
#define CKRS_TX(tag) "X'" tag CKRS_Z30 CKRS_Z30 "a5'"
#define CKRS_MAX_MONEY "2100000000000000"

static bool ckrs_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

struct ckrs_case {
    const char *name;
    const char *txid;
    const char *vout;
    const char *value;
    const char *height;
    const char *coinbase;
    const char *script;
};

static bool ckrs_put_case(sqlite3 *db, const struct ckrs_case *c)
{
    char sql[512];
    int n = snprintf(sql, sizeof(sql),
                     "INSERT INTO coins(txid,vout,value,height,is_coinbase,script)"
                     " VALUES(%s,%s,%s,%s,%s,%s)",
                     c->txid, c->vout, c->value, c->height, c->coinbase,
                     c->script);
    return n > 0 && (size_t)n < sizeof(sql) && ckrs_exec(db, sql);
}

static bool ckrs_row_key_is(const struct coins_kv_read_snapshot_row *r,
                            uint8_t tag, uint32_t vout)
{
    bool middle_zero = true;
    for (int i = 1; i < 31; i++)
        middle_zero = middle_zero && r->txid[i] == 0;
    return r->txid[0] == tag && r->txid[31] == 0xa5 && middle_zero &&
           r->vout == vout;
}

static bool ckrs_row_meta_is(const struct coins_kv_read_snapshot_row *r,
                             int64_t value, int32_t height, bool coinbase,
                             size_t script_len)
{
    bool script_ok = script_len == 0 ? r->script == NULL : r->script != NULL;
    return r->value == value && r->height == height &&
           r->is_coinbase == coinbase && r->script_len == script_len &&
           script_ok;
}

static bool ckrs_expect_row(struct coins_kv_read_snapshot *snap,
                            struct coins_kv_read_snapshot_row *row,
                            uint8_t tag, uint32_t vout, int64_t value,
                            int32_t height, bool coinbase, size_t script_len)
{
    return coins_kv_read_snapshot_next(snap, row) ==
               COINS_KV_READ_SNAPSHOT_ROW &&
           ckrs_row_key_is(row, tag, vout) &&
           ckrs_row_meta_is(row, value, height, coinbase, script_len);
}

static bool ckrs_script_all_zero(const uint8_t *script, size_t len)
{
    bool zero = script != NULL;
    for (size_t i = 0; zero && i < len; i++)
        zero = script[i] == 0;
    return zero;
}

static bool ckrs_row_cleared(const struct coins_kv_read_snapshot_row *r)
{
    return r->txid[0] == 0 && r->txid[31] == 0 && r->vout == 0 &&
           r->value == 0 && r->script == NULL && r->script_len == 0 &&
           r->height == 0 && !r->is_coinbase;
}

static bool ckrs_seed_boundary_rows(sqlite3 *db)
{
    static const struct ckrs_case rows[] = {
        {"r0", CKRS_TX("00"), "1", "5", "3", "0", "X''"},
        {"r1", CKRS_TX("01"), "4294967295", CKRS_MAX_MONEY, "0", "1",
         "X'5152'"},
        {"r2", CKRS_TX("02"), "7", "0", "20", "0", "X''"},
        {"r3", CKRS_TX("03"), "9", "1", "19", "1", "zeroblob(10000)"},
    };
    bool ok = ckrs_exec(db, "DELETE FROM coins") && ckrs_set_frontier(db, 21);
    for (size_t i = 0; ok && i < sizeof(rows) / sizeof(rows[0]); i++)
        ok = ckrs_put_case(db, &rows[i]);
    return ok;
}

/* Every boundary value that must read as good: vout UINT32_MAX, value
 * MAX_MONEY and 0, height 0 and applied-1, both coinbase flags, empty and
 * MAX_SCRIPT_SIZE scripts (empty after a non-empty one must publish NULL). */
static bool ckrs_boundary_rows_read_exact(
    struct coins_kv_read_snapshot *snap,
    struct coins_kv_read_snapshot_row *row)
{
    static const uint8_t r1_script[2] = {0x51, 0x52};
    bool ok = ckrs_expect_row(snap, row, 0x00, 1, 5, 3, false, 0);
    ok = ok && ckrs_expect_row(snap, row, 0x01, UINT32_MAX, 2100000000000000LL,
                               0, true, 2) &&
         memcmp(row->script, r1_script, 2) == 0;
    ok = ok && ckrs_expect_row(snap, row, 0x02, 7, 0, 20, false, 0);
    ok = ok && ckrs_expect_row(snap, row, 0x03, 9, 1, 19, true, 10000) &&
         ckrs_script_all_zero(row->script, 10000);
    return ok;
}

static int ckrs_check_boundary_rows(sqlite3 *db)
{
    int failures = 0;
    bool seeded = ckrs_seed_boundary_rows(db);
    CKRS_CHECK("boundary rows seeded", seeded);
    if (!seeded)
        return failures;
    struct coins_kv_read_snapshot_info info = {0};
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("boundary snapshot opens at frontier 21",
               snap && info.applied_height == 21);
    if (!snap)
        return failures;
    struct coins_kv_read_snapshot_row row;
    memset(&row, 0, sizeof(row));
    CKRS_CHECK("boundary rows read back exactly",
               ckrs_boundary_rows_read_exact(snap, &row));
    memset(&row, 0xff, sizeof(row));
    CKRS_CHECK("DONE zeroes the row",
               coins_kv_read_snapshot_next(snap, &row) ==
                   COINS_KV_READ_SNAPSHOT_DONE && ckrs_row_cleared(&row));
    CKRS_CHECK("next after DONE is an error",
               coins_kv_read_snapshot_next(snap, &row) ==
                   COINS_KV_READ_SNAPSHOT_ERROR);
    CKRS_CHECK("boundary snapshot finishes", coins_kv_read_snapshot_finish(snap));
    return failures;
}

static int ckrs_check_early_finish(sqlite3 *db)
{
    int failures = 0;
    (void)db;
    struct coins_kv_read_snapshot_info info = {0};
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    struct coins_kv_read_snapshot_row row;
    bool one = snap && coins_kv_read_snapshot_next(snap, &row) ==
                           COINS_KV_READ_SNAPSHOT_ROW;
    CKRS_CHECK("one row read before finishing", one);
    CKRS_CHECK("finish before DONE is refused",
               snap && !coins_kv_read_snapshot_finish(snap));
    CKRS_CHECK("finish(NULL) is refused", !coins_kv_read_snapshot_finish(NULL));
    coins_kv_read_snapshot_abort(NULL);
    CKRS_CHECK("open(NULL) is refused", coins_kv_read_snapshot_open(NULL) == NULL);
    return failures;
}

/* One malformed row sorted before a good one: the first next() must fail,
 * the failure must stick (the good row after it is never delivered), the row
 * must be zeroed, and finish() must refuse the incomplete traversal. */
static int ckrs_check_bad_case(sqlite3 *db, const struct ckrs_case *c)
{
    int failures = 0;
    static const struct ckrs_case good = {
        "good", CKRS_TX("20"), "0", "1", "1", "0", "X'51'"};
    bool seeded = ckrs_exec(db, "DELETE FROM coins") &&
                  ckrs_put_case(db, c) && ckrs_put_case(db, &good);
    if (!seeded) {
        printf("  coins_kv_read_snapshot: %s seed... FAIL\n", c->name);
        return 1;
    }
    struct coins_kv_read_snapshot_info info = {0};
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    struct coins_kv_read_snapshot_row row;
    memset(&row, 0xff, sizeof(row));
    bool first = snap && coins_kv_read_snapshot_next(snap, &row) ==
                             COINS_KV_READ_SNAPSHOT_ERROR;
    bool zeroed = ckrs_row_cleared(&row);
    bool sticky = snap && coins_kv_read_snapshot_next(snap, &row) ==
                              COINS_KV_READ_SNAPSHOT_ERROR;
    bool refused = snap && !coins_kv_read_snapshot_finish(snap);
    CKRS_CHECK(c->name, first && zeroed && sticky && refused);
    return failures;
}

static int ckrs_check_bad_rows(sqlite3 *db)
{
    static const struct ckrs_case bad[] = {
        {"vout above UINT32_MAX refused", CKRS_TX("10"), "4294967296", "1", "1", "0", "X'51'"},
        {"negative vout refused", CKRS_TX("10"), "-1", "1", "1", "0", "X'51'"},
        {"value above MAX_MONEY refused", CKRS_TX("10"), "0", "2100000000000001", "1", "0", "X'51'"},
        {"negative value refused", CKRS_TX("10"), "0", "-1", "1", "0", "X'51'"},
        {"height equal to frontier refused", CKRS_TX("10"), "0", "1", "21", "0", "X'51'"},
        {"negative height refused", CKRS_TX("10"), "0", "1", "-1", "0", "X'51'"},
        {"coinbase flag 2 refused", CKRS_TX("10"), "0", "1", "1", "2", "X'51'"},
        {"negative coinbase flag refused", CKRS_TX("10"), "0", "1", "1", "-1", "X'51'"},
        {"script above MAX_SCRIPT_SIZE refused", CKRS_TX("10"), "0", "1", "1", "0", "zeroblob(10001)"},
        {"text vout refused", CKRS_TX("10"), "'x'", "1", "1", "0", "X'51'"},
        {"text value refused", CKRS_TX("10"), "0", "'x'", "1", "0", "X'51'"},
        {"text height refused", CKRS_TX("10"), "0", "1", "'x'", "0", "X'51'"},
        {"text coinbase flag refused", CKRS_TX("10"), "0", "1", "1", "'x'", "X'51'"},
        {"text script refused", CKRS_TX("10"), "0", "1", "1", "0", "'abc'"},
        {"text txid refused", "'12345678901234567890123456789012'", "0", "1", "1", "0", "X'51'"},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        failures += ckrs_check_bad_case(db, &bad[i]);
    return failures;
}

/* Frontier 1 is the smallest good frontier (one row at height 0); frontier 0
 * is not an authority and must leave the caller's info zeroed. */
static int ckrs_check_frontier_edges(sqlite3 *db)
{
    int failures = 0;
    static const struct ckrs_case row0 = {
        "row0", CKRS_TX("05"), "0", "0", "0", "0", "X'51'"};
    bool seeded = ckrs_exec(db, "DELETE FROM coins") &&
                  ckrs_put_case(db, &row0) && ckrs_set_frontier(db, 1);
    CKRS_CHECK("frontier-1 fixture seeded", seeded);
    if (!seeded)
        return failures;
    struct coins_kv_read_snapshot_info info = {0};
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    struct coins_kv_read_snapshot_row row;
    CKRS_CHECK("frontier 1 opens and reads the height-0 row",
               snap && info.applied_height == 1 &&
                   ckrs_expect_row(snap, &row, 0x05, 0, 0, 0, false, 1));
    if (snap)
        coins_kv_read_snapshot_abort(snap);
    CKRS_CHECK("frontier 0 set", ckrs_set_frontier(db, 0));
    memset(&info, 0xff, sizeof(info));
    snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("frontier 0 is refused and info zeroed",
               snap == NULL && info.applied_height == 0 &&
                   info.authority_generation == 0);
    if (snap)
        coins_kv_read_snapshot_abort(snap);
    return failures;
}

static int ckrs_validation_tests(sqlite3 *db)
{
    int failures = 0;
    failures += ckrs_check_boundary_rows(db);
    failures += ckrs_check_early_finish(db);
    failures += ckrs_check_bad_rows(db);
    failures += ckrs_check_frontier_edges(db);
    return failures;
}

int test_coins_kv_read_snapshot(void);
int test_coins_kv_read_snapshot(void)
{
    printf("\n=== coins_kv_read_snapshot tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "coins_kv_read_snapshot", "main");

    CKRS_CHECK("progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    CKRS_CHECK("coins schema exists", db && coins_kv_ensure_schema(db));
    CKRS_CHECK("initial row added", ckrs_add(db, 0x10, 0, 100, 5));
    CKRS_CHECK("frontier 11 committed", ckrs_set_frontier(db, 11));
    CKRS_CHECK("authority stamped", coins_kv_mark_migration_complete(db));

    struct coins_kv_read_snapshot_info first_info;
    struct coins_kv_read_snapshot *first =
        coins_kv_read_snapshot_open(&first_info);
    CKRS_CHECK("first snapshot opens at frontier 11",
               first && first_info.applied_height == 11);

    progress_store_tx_lock();
    bool writer_ok = ckrs_commit_newer_wal_generation(db);
    if (!writer_ok)
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    CKRS_CHECK("writer commits a newer WAL generation", writer_ok);

    struct coins_kv_read_snapshot_row row;
    enum coins_kv_read_snapshot_step step = ckrs_next_step_or_error(first, &row);
    CKRS_CHECK("pinned snapshot sees original row", step == COINS_KV_READ_SNAPSHOT_ROW &&
               row.txid[0] == 0x10 && row.value == 100 &&
               first_info.authority_generation == 0);
    step = ckrs_next_step_or_error(first, &row);
    CKRS_CHECK("pinned snapshot excludes newer row",
               step == COINS_KV_READ_SNAPSHOT_DONE);
    CKRS_CHECK("completed snapshot finishes", first &&
               coins_kv_read_snapshot_finish(first));

    struct coins_kv_read_snapshot_info second_info;
    struct coins_kv_read_snapshot *second =
        coins_kv_read_snapshot_open(&second_info);
    int second_rows = ckrs_count_rows(second, &row, &step);
    CKRS_CHECK("next snapshot sees new frontier and both rows",
               ckrs_second_snapshot_saw_new_generation(
                   second, &second_info, second_rows, step));
    CKRS_CHECK("second snapshot finishes", second &&
               coins_kv_read_snapshot_finish(second));

    bool malformed_inserted = ckrs_insert_malformed_row(db);
    CKRS_CHECK("malformed authority row injected", malformed_inserted);

    struct coins_kv_read_snapshot_info malformed_info;
    struct coins_kv_read_snapshot *malformed =
        coins_kv_read_snapshot_open(&malformed_info);
    bool refused = ckrs_scan_until_error(malformed, &row);
    CKRS_CHECK("malformed txid row is refused", refused);
    if (malformed)
        coins_kv_read_snapshot_abort(malformed);

    if (db)
        failures += ckrs_validation_tests(db);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
