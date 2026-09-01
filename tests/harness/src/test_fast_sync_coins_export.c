/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical coins_kv-to-fast-sync chunk export acceptance. */
#include "test/test_core.h"

#include "net/fast_sync.h"
#include "net/fast_sync_coins_export.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FSCE_CHECK(name, expression) do {                              \
    if (expression) printf("  fast_sync_coins_export: %s... OK\n", name); \
    else {                                                             \
        printf("  fast_sync_coins_export: %s... FAIL\n", name);       \
        failures++;                                                    \
    }                                                                  \
} while (0)

struct fsce_result {
    uint8_t root[32];
    uint8_t chunk_hashes[2][32];
    uint64_t count;
    uint32_t chunks;
    uint32_t chunk_sizes[2];
};

static void fsce_txid(uint8_t txid[32], uint32_t index)
{
    memset(txid, 0, 32);
    txid[0] = (uint8_t)(index >> 24);
    txid[1] = (uint8_t)(index >> 16);
    txid[2] = (uint8_t)(index >> 8);
    txid[3] = (uint8_t)index;
    txid[31] = 0xa5;
}

static bool fsce_set_frontier(sqlite3 *db, int32_t applied)
{
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool ok = coins_kv_set_applied_height_in_tx(db, applied) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok)
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return ok;
}

static bool fsce_add_row(sqlite3 *db, uint32_t index, size_t script_len)
{
    uint8_t txid[32];
    uint8_t script[520];
    fsce_txid(txid, index);
    for (size_t i = 0; i < script_len; i++)
        script[i] = (uint8_t)(index + (uint32_t)i);
    return coins_kv_add(db, txid, index % 5, 1000 + (int64_t)index,
                        10 + (int32_t)(index % 100), (index & 1u) != 0,
                        script_len ? script : NULL, script_len);
}

static size_t fsce_script_len(uint32_t index)
{
    if (index == 0) return 0;
    if (index == 1) return 252;
    if (index == 2) return 253;
    if (index == 3) return 520;
    return 1;
}

static bool fsce_run_corpus(const char *tag, uint32_t rows, bool reverse,
                            struct fsce_result *out)
{
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "fast_sync_coins_export", tag);
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    bool ok = db && coins_kv_ensure_schema(db);
    for (uint32_t n = 0; ok && n < rows; n++) {
        uint32_t index = reverse ? rows - 1 - n : n;
        ok = fsce_add_row(db, index, fsce_script_len(index));
    }
    ok = ok && fsce_set_frontier(db, 200) &&
         coins_kv_mark_migration_complete(db);

    uint8_t expected_root[32] = {0};
    ok = ok && coins_kv_commitment(db, expected_root) == 0;
    struct fast_sync_coins_export_info info;
    struct fast_sync_coins_export *exporter = ok
        ? fast_sync_coins_export_open(&info) : NULL;
    ok = ok && exporter && info.applied_height == 200;

    struct utxo_chunk *chunk = zcl_calloc(
        1, sizeof(*chunk), "fast_sync_coins_export_chunk");
    struct fsce_result result = {0};
    enum fast_sync_coins_export_step step = FAST_SYNC_COINS_EXPORT_ERROR;
    while (ok && result.chunks < 2 &&
           (step = fast_sync_coins_export_next_chunk(
                exporter, chunk, result.chunk_hashes[result.chunks])) ==
                    FAST_SYNC_COINS_EXPORT_CHUNK) {
        result.chunk_sizes[result.chunks] = chunk->num_entries;
        result.chunks++;
    }
    if (ok && step == FAST_SYNC_COINS_EXPORT_CHUNK)
        step = fast_sync_coins_export_next_chunk(exporter, chunk,
                                                  (uint8_t[32]){0});
    bool finished = false;
    if (ok && step == FAST_SYNC_COINS_EXPORT_DONE) {
        finished = fast_sync_coins_export_finish(
            exporter, result.root, &result.count);
        exporter = NULL;
    }
    ok = ok && step == FAST_SYNC_COINS_EXPORT_DONE && finished &&
         result.count == rows && memcmp(result.root, expected_root, 32) == 0;
    if (!ok && exporter)
        fast_sync_coins_export_abort(exporter);
    free(chunk);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    if (ok)
        *out = result;
    return ok;
}

static bool fsce_oversize_refused(void)
{
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "fast_sync_coins_export", "oversize");
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    uint8_t txid[32];
    uint8_t script[521];
    fsce_txid(txid, 7);
    memset(script, 0x63, sizeof(script));
    bool ok = db && coins_kv_ensure_schema(db) &&
              coins_kv_add(db, txid, 0, 7000, 7, false,
                           script, sizeof(script)) &&
              fsce_set_frontier(db, 20) &&
              coins_kv_mark_migration_complete(db);
    struct fast_sync_coins_export_info info;
    struct fast_sync_coins_export *exporter = ok
        ? fast_sync_coins_export_open(&info) : NULL;
    struct utxo_chunk *chunk = zcl_calloc(
        1, sizeof(*chunk), "fast_sync_coins_export_oversize_chunk");
    uint8_t chunk_hash[32];
    enum fast_sync_coins_export_step step = exporter && chunk
        ? fast_sync_coins_export_next_chunk(exporter, chunk, chunk_hash)
        : FAST_SYNC_COINS_EXPORT_ERROR;
    uint8_t root[32];
    uint64_t count = UINT64_MAX;
    bool finish_refused = exporter &&
                          !fast_sync_coins_export_finish(exporter, root, &count);
    ok = ok && chunk && step == FAST_SYNC_COINS_EXPORT_ERROR &&
         chunk->num_entries == 0 && finish_refused && count == 0;
    free(chunk);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return ok;
}

int test_fast_sync_coins_export(void)
{
    printf("\n=== fast_sync_coins_export tests ===\n");
    int failures = 0;
    struct fsce_result r499, r500, r501_forward, r501_reverse;

    FSCE_CHECK("499 rows produce one 499-entry chunk",
               fsce_run_corpus("n499", 499, false, &r499) &&
               r499.chunks == 1 && r499.chunk_sizes[0] == 499);
    FSCE_CHECK("500 rows produce one exact-boundary chunk",
               fsce_run_corpus("n500", 500, false, &r500) &&
               r500.chunks == 1 && r500.chunk_sizes[0] == 500);
    FSCE_CHECK("501 rows produce 500 + 1 chunks with commitment parity",
               fsce_run_corpus("n501_forward", 501, false, &r501_forward) &&
               r501_forward.chunks == 2 &&
               r501_forward.chunk_sizes[0] == 500 &&
               r501_forward.chunk_sizes[1] == 1);
    FSCE_CHECK("reverse insertion produces identical root and chunk hashes",
               fsce_run_corpus("n501_reverse", 501, true, &r501_reverse) &&
               r501_reverse.count == r501_forward.count &&
               memcmp(r501_reverse.root, r501_forward.root, 32) == 0 &&
               memcmp(r501_reverse.chunk_hashes,
                      r501_forward.chunk_hashes,
                      sizeof(r501_reverse.chunk_hashes)) == 0);
    FSCE_CHECK("521-byte script is refused without truncation",
               fsce_oversize_refused());
    return failures;
}
