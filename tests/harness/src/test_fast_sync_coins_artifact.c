/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical fast-sync artifact publication acceptance. */
#include "test/test_core.h"

#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "net/fast_sync.h"
#include "net/fast_sync_coins_artifact.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FSCA_CHECK(name, expression) do {                                  \
    if (expression) printf("  fast_sync_coins_artifact: %s... OK\n", name); \
    else {                                                                 \
        printf("  fast_sync_coins_artifact: %s... FAIL\n", name);          \
        failures++;                                                        \
    }                                                                      \
} while (0)

static void fsca_txid(uint8_t txid[32], uint32_t index)
{
    memset(txid, 0, 32);
    txid[0] = (uint8_t)(index >> 24);
    txid[1] = (uint8_t)(index >> 16);
    txid[2] = (uint8_t)(index >> 8);
    txid[3] = (uint8_t)index;
    txid[31] = 0x5a;
}

static bool fsca_set_frontier(sqlite3 *db, int32_t applied)
{
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool ok = coins_kv_set_applied_height_in_tx(db, applied) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok)
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return ok;
}

static bool fsca_add_row(sqlite3 *db, uint32_t index, size_t script_len)
{
    uint8_t txid[32];
    uint8_t script[521];
    fsca_txid(txid, index);
    for (size_t i = 0; i < script_len; i++)
        script[i] = (uint8_t)(index + (uint32_t)i);
    return coins_kv_add(db, txid, index % 7u, 1000 + (int64_t)index,
                        10 + (int32_t)(index % 100u), (index & 1u) != 0,
                        script_len ? script : NULL, script_len);
}

static bool fsca_seed(sqlite3 *db, uint32_t rows, bool reverse,
                      size_t forced_script_len)
{
    bool ok = db && coins_kv_ensure_schema(db);
    for (uint32_t n = 0; ok && n < rows; n++) {
        uint32_t index = reverse ? rows - 1u - n : n;
        size_t script_len = forced_script_len
            ? forced_script_len
            : (index == 0 ? 0u : index == 1 ? 252u :
               index == 2 ? 253u : index == 3 ? 520u : 1u);
        ok = fsca_add_row(db, index, script_len);
    }
    return ok && fsca_set_frontier(db, 200) &&
           coins_kv_mark_migration_complete(db);
}

static uint8_t *fsca_read_file(const char *path, size_t *size_out)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > SIZE_MAX)
        return NULL;
    FILE *file = fopen(path, "rb");
    uint8_t *bytes = file
        ? zcl_malloc((size_t)st.st_size, "fast_sync_artifact_test_read")
        : NULL;
    bool ok = bytes && fread(bytes, 1, (size_t)st.st_size, file) ==
                       (size_t)st.st_size;
    if (file && fclose(file) != 0)
        ok = false;
    if (!ok) {
        free(bytes);
        return NULL;
    }
    *size_out = (size_t)st.st_size;
    return bytes;
}

static bool fsca_no_stage_files(const char *dir)
{
    DIR *stream = opendir(dir);
    if (!stream)
        return false;
    bool clean = true;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strstr(entry->d_name, ".z23-stage-") != NULL) {
            clean = false;
            break;
        }
    }
    closedir(stream);
    return clean;
}

static bool fsca_artifact_roundtrip(void)
{
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "fast_sync_coins_artifact", "roundtrip");
    snprintf(path, sizeof(path), "%s/snapshot.bin", dir);
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    uint64_t expected_generation = UINT64_MAX;
    bool ok = fsca_seed(db, 501, true, 0) &&
              coins_kv_get_authority_generation(db, &expected_generation);
    struct fast_sync_coins_artifact artifact = {0};
    enum fast_sync_coins_artifact_status status = ok
        ? fast_sync_coins_artifact_write(path, &artifact)
        : FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED;
    progress_store_close();

    uint8_t expected_merkle[32] = {0};
    if (status == FAST_SYNC_COINS_ARTIFACT_OK)
        fast_sync_merkle_root(
            (const uint8_t (*)[32])artifact.chunk_hashes,
            artifact.num_chunks, expected_merkle);
    size_t size = 0;
    uint8_t *bytes = status == FAST_SYNC_COINS_ARTIFACT_OK
        ? fsca_read_file(path, &size) : NULL;
    ok = ok && status == FAST_SYNC_COINS_ARTIFACT_OK && bytes &&
         artifact.applied_height == 200 &&
         artifact.authority_generation == expected_generation &&
         artifact.num_utxos == 501 && artifact.num_chunks == 2 &&
         artifact.chunk_size == SYNC_CHUNK_SIZE &&
         artifact.artifact_bytes == size &&
         memcmp(artifact.merkle_root, expected_merkle, 32) == 0;

    if (ok) {
        ok = fast_sync_publish_snapshot_cache(
            bytes, (int64_t)size, artifact.utxo_root, artifact.num_utxos);
        if (ok)
            bytes = NULL;
        struct utxo_chunk *chunk = zcl_calloc(
            1, sizeof(*chunk), "fast_sync_artifact_test_chunk");
        struct sha3_256_ctx decoded;
        sha3_256_init(&decoded);
        uint64_t decoded_count = 0;
        for (uint32_t ci = 0; ok && chunk && ci < artifact.num_chunks; ci++) {
            ok = fast_sync_serve_chunk(dir, ci, chunk) &&
                 chunk->chunk_index == ci &&
                 fast_sync_verify_chunk(chunk, artifact.chunk_hashes[ci]);
            for (uint32_t i = 0; ok && i < chunk->num_entries; i++) {
                utxo_commitment_sha3_write_record(
                    &decoded, chunk->entries[i].txid,
                    chunk->entries[i].vout, chunk->entries[i].value,
                    chunk->entries[i].script,
                    chunk->entries[i].script_len,
                    (uint32_t)chunk->entries[i].height,
                    (uint8_t)(chunk->entries[i].is_coinbase ? 1 : 0));
                decoded_count++;
            }
        }
        uint8_t decoded_root[32];
        sha3_256_finalize(&decoded, decoded_root);
        ok = ok && chunk && decoded_count == artifact.num_utxos &&
             memcmp(decoded_root, artifact.utxo_root, 32) == 0 &&
             !fast_sync_serve_chunk(dir, artifact.num_chunks, chunk);
        free(chunk);
        fast_sync_reset_snapshot_cache();
    }
    free(bytes);
    fast_sync_coins_artifact_free(&artifact);
    bool no_stage = fsca_no_stage_files(dir);
    test_cleanup_tmpdir(dir);
    return ok && no_stage;
}

static bool fsca_failure_preserves_destination(void)
{
    char dir[256], path[320], absent[320];
    test_make_tmpdir(dir, sizeof(dir), "fast_sync_coins_artifact", "failure");
    snprintf(path, sizeof(path), "%s/snapshot.bin", dir);
    snprintf(absent, sizeof(absent), "%s/absent.bin", dir);
    FILE *sentinel = fopen(path, "wb");
    bool ok = sentinel && fwrite("KEEP", 1, 4, sentinel) == 4 &&
              fclose(sentinel) == 0 && progress_store_open(dir);
    sqlite3 *db = ok ? progress_store_db() : NULL;
    ok = ok && fsca_seed(db, 1, false, 521);
    struct fast_sync_coins_artifact artifact = {0};
    enum fast_sync_coins_artifact_status status = ok
        ? fast_sync_coins_artifact_write(path, &artifact)
        : FAST_SYNC_COINS_ARTIFACT_OK;
    enum fast_sync_coins_artifact_status absent_status = ok
        ? fast_sync_coins_artifact_write(absent, &artifact)
        : FAST_SYNC_COINS_ARTIFACT_OK;
    progress_store_close();

    uint8_t kept[4] = {0};
    FILE *check = fopen(path, "rb");
    bool preserved = check && fread(kept, 1, sizeof(kept), check) ==
                                sizeof(kept) && fclose(check) == 0;
    ok = ok && status == FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED &&
         absent_status == FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED &&
         artifact.chunk_hashes == NULL && preserved &&
         memcmp(kept, "KEEP", 4) == 0 && access(absent, F_OK) != 0 &&
         fsca_no_stage_files(dir);
    fast_sync_coins_artifact_free(&artifact);
    test_cleanup_tmpdir(dir);
    return ok;
}

int test_fast_sync_coins_artifact(void)
{
    printf("\n=== fast_sync_coins_artifact tests ===\n");
    int failures = 0;
    FSCA_CHECK("501 canonical rows publish 500+1 cache-compatible chunks with exact manifest facts",
               fsca_artifact_roundtrip());
    FSCA_CHECK("export failure preserves an existing artifact and publishes no partial",
               fsca_failure_preserves_destination());
    return failures;
}
