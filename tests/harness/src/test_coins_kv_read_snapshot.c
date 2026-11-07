/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: prove coins_kv export reads one WAL generation and rejects malformed rows. */
#include "test/test_core.h"
#include "config/boot_wallet_cutover_coins.h"
#include "wallet/wallet.h"
#include "script/standard.h"
#include "util/safe_alloc.h"
#include <limits.h>
#include <stdlib.h>

#include "storage/coins_kv.h"
#include "storage/coins_kv_read_snapshot.h"
#include "storage/shielded_pool_kv.h"
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

#ifdef ZCL_TESTING
void coins_kv_read_snapshot_test_authorizer(struct coins_kv_read_snapshot *,
    int (*)(void *, int, const char *, const char *, const char *, const char *));
static int ckrs_deny_read(void *ctx, int action, const char *a, const char *b,
                          const char *c, const char *d)
{
    (void)ctx; (void)a; (void)b; (void)c; (void)d;
    return action == SQLITE_READ ? SQLITE_DENY : SQLITE_OK;
}
#endif

static int ckrs_point_reopen_cases(void)
{
    int failures = 0;
    struct coins_kv_read_snapshot_info info;
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    uint8_t key[32] = {0x33}; key[31] = 0xa5;
    struct coins_kv_read_snapshot_row row;
    CKRS_CHECK("new snapshot sees committed point", snap &&
        coins_kv_read_snapshot_lookup(snap, key, 0, &row) == COINS_KV_LOOKUP_FOUND && row.value == 33);
#ifdef ZCL_TESTING
    if (snap) coins_kv_read_snapshot_test_authorizer(snap, ckrs_deny_read);
    memset(&row, 0xff, sizeof(row));
    CKRS_CHECK("database failure is error, not absent", snap &&
        coins_kv_read_snapshot_lookup(snap, key, 0, &row) == COINS_KV_LOOKUP_ERROR && ckrs_row_cleared(&row));
#endif
    if (snap) coins_kv_read_snapshot_abort(snap);
    return failures;
}

static int ckrs_point_cases(sqlite3 *db)
{
    int failures = 0;
    bool seeded = ckrs_seed_boundary_rows(db);
    struct coins_kv_read_snapshot_info info;
    struct coins_kv_read_snapshot *snap = seeded ? coins_kv_read_snapshot_open(&info) : NULL;
    uint8_t key[32] = {0x01}; key[31] = 0xa5;
    struct coins_kv_read_snapshot_row row;
    enum coins_kv_read_snapshot_lookup_result found = snap ?
        coins_kv_read_snapshot_lookup(snap, key, UINT32_MAX, &row) : COINS_KV_LOOKUP_ERROR;
    static const uint8_t script[2] = {0x51, 0x52};
    CKRS_CHECK("point returns exact maximum outpoint and complete value", found == COINS_KV_LOOKUP_FOUND &&
        ckrs_row_key_is(&row, 1, UINT32_MAX) && ckrs_row_meta_is(&row, 2100000000000000LL, 0, true, 2) &&
        memcmp(row.script, script, 2) == 0);
    memset(&row, 0xff, sizeof(row));
    CKRS_CHECK("missing point is absent and clears output", snap &&
        coins_kv_read_snapshot_lookup(snap, key, 0, &row) == COINS_KV_LOOKUP_ABSENT && ckrs_row_cleared(&row));
    key[0] = 0x33;
    CKRS_CHECK("writer commits new point", ckrs_add(db, 0x33, 0, 33, 3));
    CKRS_CHECK("pinned point excludes later commit", snap &&
        coins_kv_read_snapshot_lookup(snap, key, 0, &row) == COINS_KV_LOOKUP_ABSENT);
    CKRS_CHECK("point lookup does not advance traversal", snap &&
        coins_kv_read_snapshot_next(snap, &row) == COINS_KV_READ_SNAPSHOT_ROW && ckrs_row_key_is(&row, 0, 1));
    if (snap) coins_kv_read_snapshot_abort(snap);
    return failures + ckrs_point_reopen_cases();
}

static int ckrs_bad_point_cases(sqlite3 *db)
{
    static const struct ckrs_case bad[] = {
        {"negative value", CKRS_TX("10"), "0", "-1", "1", "0", "X'51'"},
        {"invalid height", CKRS_TX("10"), "0", "1", "21", "0", "X'51'"},
        {"invalid coinbase", CKRS_TX("10"), "0", "1", "1", "2", "X'51'"},
        {"oversized script", CKRS_TX("10"), "0", "1", "1", "0", "zeroblob(10001)"},
        {"text script", CKRS_TX("10"), "0", "1", "1", "0", "'x'"}
    };
    int failures = 0;
    uint8_t key[32] = {0x10}; key[31] = 0xa5;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bool seeded = ckrs_exec(db, "DELETE FROM coins") && ckrs_put_case(db, &bad[i]);
        struct coins_kv_read_snapshot_info info;
        struct coins_kv_read_snapshot *snap = seeded ? coins_kv_read_snapshot_open(&info) : NULL;
        struct coins_kv_read_snapshot_row row;
        memset(&row, 0xff, sizeof(row));
        CKRS_CHECK(bad[i].name, snap && coins_kv_read_snapshot_lookup(snap, key, 0, &row) ==
            COINS_KV_LOOKUP_ERROR && ckrs_row_cleared(&row));
        if (snap) coins_kv_read_snapshot_abort(snap);
    }
    return failures;
}

static int ckrs_validation_tests(sqlite3 *db)
{
    int failures = 0;
    failures += ckrs_point_cases(db);
    failures += ckrs_bad_point_cases(db);
    failures += ckrs_check_boundary_rows(db);
    failures += ckrs_check_early_finish(db);
    failures += ckrs_check_bad_rows(db);
    failures += ckrs_check_frontier_edges(db);
    return failures;
}

int test_coins_kv_read_snapshot(void);
static bool ckrs_cutover_resolve(void *ctx, const uint8_t hash[32], int *height)
{
    (void)ctx;
    if (hash[0] == 0x31) *height = 5;
    else if (hash[0] == 0x40) *height = 10;
    else if (hash[0] == 0x41) *height = 11;
    else return false;
    return true;
}

static bool ckrs_cutover_setup(sqlite3 *db, struct wallet *w, struct wallet_tx *tx)
{
    struct key_id id = {0}; id.id.data[0] = 9;
    if (!db || !w || !coins_kv_ensure_schema(db) || !coins_kv_mark_migration_complete(db) ||
        !ckrs_set_frontier(db, 11) || !keystore_add_watch_only_id(&w->keystore, &id) ||
        !transaction_alloc(&tx->tx, 0, 2)) return false;
    struct tx_destination dest = {.type = DEST_KEY_ID, .id.key = id};
    tx->tx.hash.data[0] = 0x22; tx->hash_block.data[0] = 0x31;
    script_for_destination(&tx->tx.vout[0].script_pub_key, &dest);
    tx->tx.vout[1].script_pub_key = tx->tx.vout[0].script_pub_key;
    tx->tx.vout[0].value = 100; tx->tx.vout[1].value = 200;
    return wallet_add_to_wallet(w, tx) && coins_kv_add(db, tx->tx.hash.data, 0, 100, 5,
        false, tx->tx.vout[0].script_pub_key.data, tx->tx.vout[0].script_pub_key.size);
}

static bool ckrs_cutover_write_newer(sqlite3 *db, const struct wallet_tx *tx)
{
    progress_store_tx_lock();
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_add(db, tx->tx.hash.data, 1, 201, 5, false,
                     tx->tx.vout[1].script_pub_key.data, tx->tx.vout[1].script_pub_key.size) &&
        coins_kv_set_applied_height_in_tx(db, 12) && coins_kv_bump_authority_generation_in_tx(db) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    return ok;
}

static int ckrs_cutover_check_pinned(struct wallet *w, const struct wallet_tx *tx,
    struct coins_kv_read_snapshot *snap, const struct coins_kv_read_snapshot_info *info,
    const uint8_t identity[32])
{
    int failures = 0;
    uint8_t ref[32] = {0x40};
    struct boot_cutover_coins *cache = NULL;
    enum boot_cutover_coins_status st = boot_cutover_coins_prepare(w, snap, info, 10, ref,
        info->authority_generation, identity, ckrs_cutover_resolve, NULL, &cache);
    CKRS_CHECK("watch-only outputs captured from pinned generation", st == BOOT_CUTOVER_COINS_OK && cache &&
        boot_cutover_coins_verdict(cache, tx->tx.hash.data, 0, &tx->tx.vout[0], 5, false) == DB_CUTOVER_COIN_UNSPENT &&
        boot_cutover_coins_verdict(cache, tx->tx.hash.data, 1, &tx->tx.vout[1], 5, false) == DB_CUTOVER_COIN_SPENT);
    CKRS_CHECK("identity and generation bind cache", boot_cutover_coins_matches(cache, 10, ref,
        info->authority_generation, identity) && !boot_cutover_coins_matches(cache, 10, ref,
        info->authority_generation + 1, identity));
    struct tx_out changed = tx->tx.vout[0]; changed.value++;
    CKRS_CHECK("mismatched output is unknown", boot_cutover_coins_verdict(cache, tx->tx.hash.data, 0,
        &changed, 5, false) == DB_CUTOVER_COIN_UNKNOWN);
    boot_cutover_coins_free(cache);
    return failures;
}

static int ckrs_cutover_check_heights(struct wallet *w, struct coins_kv_read_snapshot *snap,
    const struct coins_kv_read_snapshot_info *info, const uint8_t identity[32])
{
    int failures = 0;
    const uint8_t ref[32] = {0x40};
    struct boot_cutover_coins *cache = NULL;
    enum boot_cutover_coins_status st = boot_cutover_coins_prepare(w, snap, info, 11, ref,
        info->authority_generation, identity, ckrs_cutover_resolve, NULL, &cache);
    CKRS_CHECK("exclusive frontier rejects equal endpoint", st == BOOT_CUTOVER_COINS_INVALID && !cache);
    st = boot_cutover_coins_prepare(w, snap, info, INT_MAX, ref,
        info->authority_generation, identity, ckrs_cutover_resolve, NULL, &cache);
    CKRS_CHECK("maximum endpoint refuses overflow", st == BOOT_CUTOVER_COINS_INVALID && !cache);
    return failures;
}

static int ckrs_cutover_cache_fixture(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "cutover_coin_cache", "main");
    bool opened = progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    struct wallet *w = zcl_calloc(1, sizeof(*w), "cutover cache test wallet");
    struct wallet_tx tx = {0};
    if (w) wallet_init(w);
    bool ok = ckrs_cutover_setup(db, w, &tx);
    uint8_t identity[32] = {0}, ref[32] = {0x41};
    if (ok) ok = wallet_scan_identity(w, identity);
    struct coins_kv_read_snapshot_info info = {0};
    struct coins_kv_read_snapshot *snap = ok ? coins_kv_read_snapshot_open(&info) : NULL;
    CKRS_CHECK("cutover fixture opens pinned snapshot", snap != NULL);
    if (snap) {
        CKRS_CHECK("newer generation commits", ckrs_cutover_write_newer(db, &tx));
        failures += ckrs_cutover_check_pinned(w, &tx, snap, &info, identity);
        failures += ckrs_cutover_check_heights(w, snap, &info, identity);
        coins_kv_read_snapshot_abort(snap);
    }
    struct coins_kv_read_snapshot_info newer_info = {0};
    struct coins_kv_read_snapshot *newer = ok ? coins_kv_read_snapshot_open(&newer_info) : NULL;
    struct boot_cutover_coins *bad = NULL;
    enum boot_cutover_coins_status st = newer ? boot_cutover_coins_prepare(w, newer, &newer_info, 11, ref,
        newer_info.authority_generation, identity, ckrs_cutover_resolve, NULL, &bad) : BOOT_CUTOVER_COINS_ERROR;
    CKRS_CHECK("new snapshot rejects mismatched durable row", st == BOOT_CUTOVER_COINS_INVALID && !bad);
    boot_cutover_coins_free(bad);
    if (newer) coins_kv_read_snapshot_abort(newer);
    transaction_free(&tx.tx);
    if (w) { wallet_free(w); free(w); }
    if (opened) progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static bool ckrs_pool_expect(struct coins_kv_read_snapshot *snap, int32_t height,
                             bool expected_found, int64_t expected_sprout,
                             int64_t expected_sapling)
{
    int64_t sprout = 9, sapling = 9;
    bool found = true;
    return snap && coins_kv_read_snapshot_shielded_pool(snap, height, &sprout, &sapling, &found) &&
        found == expected_found && sprout == expected_sprout && sapling == expected_sapling;
}

static bool ckrs_pool_refused(struct coins_kv_read_snapshot *snap, int32_t height)
{
    int64_t sprout = 9, sapling = 9;
    bool found = true;
    return snap && !coins_kv_read_snapshot_shielded_pool(snap, height, &sprout, &sapling, &found) &&
        !found && sprout == 0 && sapling == 0;
}

static int ckrs_pool_pinned(sqlite3 *db)
{
    int failures = 0;
    struct coins_kv_read_snapshot_info info = {0};
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("pool snapshot opens", snap && info.applied_height == 11);
    CKRS_CHECK("missing pool is distinct from zero",
        ckrs_pool_expect(snap, 10, false, 0, 0));
    CKRS_CHECK("writer inserts known zero after pin",
        ckrs_exec(db, "INSERT INTO shielded_pool_totals VALUES(10,0,0)"));
    CKRS_CHECK("pinned snapshot still sees missing pool",
        ckrs_pool_expect(snap, 10, false, 0, 0));
    if (snap) coins_kv_read_snapshot_abort(snap);
    snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("new snapshot reads known zero",
        ckrs_pool_expect(snap, 10, true, 0, 0));
    CKRS_CHECK("writer updates pool after pin",
        ckrs_exec(db, "UPDATE shielded_pool_totals SET sprout=7,sapling=9 WHERE height=10"));
    CKRS_CHECK("pinned snapshot retains earlier zero",
        ckrs_pool_expect(snap, 10, true, 0, 0));
    if (snap) coins_kv_read_snapshot_abort(snap);
    snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("new snapshot reads updated totals",
        ckrs_pool_expect(snap, 10, true, 7, 9));
    if (snap) coins_kv_read_snapshot_abort(snap);
    return failures;
}

static int ckrs_pool_refusals(sqlite3 *db)
{
    int failures = 0;
    struct coins_kv_read_snapshot_info info = {0};
    CKRS_CHECK("malformed pool fixture", ckrs_exec(db,
        "UPDATE shielded_pool_totals SET sprout='bad' WHERE height=10"));
    struct coins_kv_read_snapshot *snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("malformed pool poisons and clears outputs",
        ckrs_pool_refused(snap, 10));
    struct coins_kv_read_snapshot_row row;
    CKRS_CHECK("poisoned pool snapshot refuses further reads",
        snap && coins_kv_read_snapshot_next(snap, &row) == COINS_KV_READ_SNAPSHOT_ERROR);
    if (snap) coins_kv_read_snapshot_abort(snap);
    CKRS_CHECK("negative pool fixture", ckrs_exec(db,
        "UPDATE shielded_pool_totals SET sprout=-1 WHERE height=10"));
    snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("negative pool is refused with cleared outputs",
        ckrs_pool_refused(snap, 10));
    if (snap) coins_kv_read_snapshot_abort(snap);
    CKRS_CHECK("restore valid pool totals", ckrs_exec(db,
        "UPDATE shielded_pool_totals SET sprout=7,sapling=9 WHERE height=10"));
    snap = coins_kv_read_snapshot_open(&info);
    CKRS_CHECK("valid pool reads before refusal injection", ckrs_pool_expect(snap, 10, true, 7, 9));
    if (snap) coins_kv_read_snapshot_abort(snap);
    snap = coins_kv_read_snapshot_open(&info);
#ifdef ZCL_TESTING
    if (snap) coins_kv_read_snapshot_test_authorizer(snap, ckrs_deny_read);
    CKRS_CHECK("database refusal poisons and clears outputs",
        ckrs_pool_refused(snap, 10));
    if (snap) coins_kv_read_snapshot_abort(snap);
    snap = coins_kv_read_snapshot_open(&info);
#endif
    CKRS_CHECK("wrong endpoint poisons and clears outputs",
        ckrs_pool_refused(snap, 9));
    if (snap) coins_kv_read_snapshot_abort(snap);
    return failures;
}

static int ckrs_pool_transaction_rows(sqlite3 *db)
{
    int failures = 0;
    int64_t a = -1, b = -1;
    bool found = true;
    CKRS_CHECK("transaction reader zero fixture",
        ckrs_exec(db, "UPDATE shielded_pool_totals SET sprout=0,sapling=0 WHERE height=10") &&
        coins_kv_read_transaction_shielded_pool(db, 10, &a, &b, &found) &&
        found && a == 0 && b == 0);
    CKRS_CHECK("transaction reader missing fixture",
        ckrs_exec(db, "DELETE FROM shielded_pool_totals WHERE height=10") &&
        coins_kv_read_transaction_shielded_pool(db, 10, &a, &b, &found) &&
        !found && a == 0 && b == 0);
    CKRS_CHECK("transaction reader malformed fixture",
        ckrs_exec(db, "INSERT INTO shielded_pool_totals VALUES(10,'bad',0)") &&
        !coins_kv_read_transaction_shielded_pool(db, 10, &a, &b, &found) &&
        !found && a == 0 && b == 0);
    CKRS_CHECK("transaction reader closes", ckrs_exec(db, "ROLLBACK"));
    return failures;
}

static int ckrs_pool_transaction(sqlite3 *db)
{
    int failures = 0;
    int64_t a = -1, b = -1;
    bool found = true;
    CKRS_CHECK("transaction reader refuses autocommit",
        !coins_kv_read_transaction_shielded_pool(db, 10, &a, &b, &found) &&
        a == 0 && b == 0 && !found);
    CKRS_CHECK("transaction reader begins", ckrs_exec(db, "BEGIN"));
    CKRS_CHECK("transaction reader sees exact row",
        coins_kv_read_transaction_shielded_pool(db, 10, &a, &b, &found) &&
        found && a == 7 && b == 9);
    CKRS_CHECK("transaction reader refuses wrong height",
        !coins_kv_read_transaction_shielded_pool(db, 9, &a, &b, &found) &&
        a == 0 && b == 0 && !found);
    failures += ckrs_pool_transaction_rows(db);
    return failures;
}

static int ckrs_pool_transaction_pinned(sqlite3 *writer)
{
    int failures = 0;
    int64_t a = -1, b = -1;
    bool found = false;
    sqlite3 *reader = progress_store_open_reader();
    CKRS_CHECK("transaction reader opens", reader != NULL);
    if (!reader) return failures;
    CKRS_CHECK("transaction reader pins generation",
        ckrs_exec(reader, "BEGIN") &&
        coins_kv_read_transaction_shielded_pool(reader, 10, &a, &b, &found) &&
        found && a == 7 && b == 9);
    CKRS_CHECK("writer changes pool after pin",
        ckrs_exec(writer, "UPDATE shielded_pool_totals SET sprout=12,sapling=13 WHERE height=10"));
    CKRS_CHECK("transaction reader retains pinned pool",
        coins_kv_read_transaction_shielded_pool(reader, 10, &a, &b, &found) &&
        found && a == 7 && b == 9);
    CKRS_CHECK("transaction reader ends", ckrs_exec(reader, "ROLLBACK"));
    CKRS_CHECK("transaction reader closes", sqlite3_close(reader) == SQLITE_OK);
    CKRS_CHECK("restore writer pool", ckrs_exec(writer,
        "UPDATE shielded_pool_totals SET sprout=7,sapling=9 WHERE height=10"));
    return failures;
}

static int ckrs_pool_fixture(void)
{
    int failures = 0; char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "pinned_shielded_pool", "main");
    bool opened = progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    bool ready = db && coins_kv_ensure_schema(db) && ckrs_add(db, 0x10, 0, 100, 5) &&
        coins_kv_mark_migration_complete(db) && ckrs_set_frontier(db, 11) &&
        shielded_pool_kv_ensure_schema(db);
    CKRS_CHECK("pool authority fixture ready", ready);
    if (ready) { failures += ckrs_pool_pinned(db); failures += ckrs_pool_refusals(db); failures += ckrs_pool_transaction(db); failures += ckrs_pool_transaction_pinned(db); }
    if (opened) progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

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
    failures += ckrs_cutover_cache_fixture();
    failures += ckrs_pool_fixture();
    return failures;
}
