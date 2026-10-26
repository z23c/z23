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

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
