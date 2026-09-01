/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File Transfer Controller — SHA3-verified chunk service.
 * Each block file is split into 50MB chunks, SHA3-256 hashed.
 * Chunks are served by hash over REST, RPC, and P2P. */

#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "controllers/blockchain_controller.h"
#include "controllers/file_controller.h"
#include "controllers/strong_params.h"
#include "config/boot_snapshot_offer.h"
#include "views/format_helpers.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <sqlite3.h>
#include <pthread.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct file_context {
    const char *datadir;
    struct file_manifest manifest;
    bool manifest_valid;
    pthread_mutex_t manifest_mutex;
};

static struct file_context g_file_ctx = {
    .manifest_mutex = PTHREAD_MUTEX_INITIALIZER,
};

static struct file_context *file_ctx(void)
{
    return &g_file_ctx;
}

static bool file_snapshot_state_allowed(void)
{
    return boot_snapshot_offer_state_is_sovereign(NULL, 0);
}

static bool file_snapshot_serving_allowed(const char *datadir)
{
    return boot_snapshot_offer_artifact_is_eligible(datadir, NULL, 0);
}

/* A manifest can outlive the state epoch that built it. Strip snapshot chunks
 * from caller-owned copies whenever trust is no longer sovereign, then rebuild
 * the aggregate byte count/root so REST/RPC never advertises stale authority. */
static void file_manifest_strip_snapshot(struct file_manifest *fm)
{
    if (!fm)
        return;
    uint32_t dst = 0;
    uint64_t total = 0;
    for (uint32_t src = 0; src < fm->num_chunks; src++) {
        if (fm->chunks[src].file_index == 254)
            continue;
        if (dst != src)
            fm->chunks[dst] = fm->chunks[src];
        total += fm->chunks[dst].size;
        dst++;
    }
    fm->num_chunks = dst;
    fm->total_bytes = total;
    struct sha3_256_ctx root;
    sha3_256_init(&root);
    for (uint32_t i = 0; i < fm->num_chunks; i++)
        sha3_256_write(&root, fm->chunks[i].sha3, sizeof(fm->chunks[i].sha3));
    sha3_256_finalize(&root, fm->root_hash);
}

static bool file_artifact_path(char *path, size_t path_size,
                               const char *datadir, uint8_t file_index)
{
    if (!path || !datadir || path_size == 0)
        LOG_FAIL("file", "artifact_path: NULL %s", !path ? "path" : !datadir ? "datadir" : "path_size=0");

    if (file_index == 254)
        snprintf(path, path_size, "%s/consensus_snapshot.db", datadir);
    else if (file_index == 253)
        snprintf(path, path_size, "%s/block_index.bin", datadir);
    else
        snprintf(path, path_size, "%s/blocks/blk%05d.dat",
                 datadir, file_index);

    return true;
}

static bool file_manifest_has_file_index(const struct file_manifest *fm,
                                         uint8_t file_index)
{
    if (!fm)
        LOG_FAIL("file", "manifest_has_file_index: NULL manifest");

    for (uint32_t i = 0; i < fm->num_chunks; i++) {
        if (fm->chunks[i].file_index == file_index)
            return true;
    }
    return false;
}

static bool file_artifact_exists(const char *datadir, uint8_t file_index,
                                 off_t min_size, struct stat *st_out)
{
    char path[576];
    struct stat st;

    if (!file_artifact_path(path, sizeof(path), datadir, file_index))
        LOG_FAIL("file", "artifact_exists: cannot build path for file_index=%u", (unsigned)file_index);
    if (stat(path, &st) != 0 || st.st_size < min_size)
        LOG_FAIL("file", "artifact_exists: %s missing or too small (min=%lld)", path, (long long)min_size);

    if (st_out)
        *st_out = st;
    return true;
}

static bool file_manifest_cache_has_required_exports(const struct file_manifest *fm,
                                                     const char *datadir)
{
    struct stat snap_st;
    bool snapshot_allowed = file_snapshot_serving_allowed(datadir);

    if (!snapshot_allowed && file_manifest_has_file_index(fm, 254)) {
        printf("file_manifest: cached consensus_snapshot.db is not sovereign; "
               "rebuilding without file_index=254\n");
        return false;
    }
    if (snapshot_allowed &&
        file_artifact_exists(datadir, 254, 1000000, &snap_st) &&
        !file_manifest_has_file_index(fm, 254)) {
        printf("file_manifest: consensus_snapshot.db exists but cached "
               "manifest omits file_index=254, rebuilding\n");
        return false;
    }

    return true;
}

static bool file_manifest_cache_inputs_are_fresh(const struct file_manifest *fm,
                                                 const char *datadir,
                                                 const struct stat *cache_st)
{
    if (!fm || !datadir || !cache_st)
        LOG_FAIL("file", "cache_inputs_fresh: NULL %s", !fm ? "fm" : !datadir ? "datadir" : "cache_st");

    for (uint32_t i = 0; i < fm->num_chunks; i++) {
        uint8_t file_index = fm->chunks[i].file_index;
        char path[576];
        struct stat st;

        if (file_index >= 253 &&
            !file_artifact_path(path, sizeof(path), datadir, file_index))
            LOG_FAIL("file", "cache_inputs_fresh: cannot build path for file_index=%u", (unsigned)file_index);
        if (file_index >= 253 &&
            stat(path, &st) == 0 &&
            st.st_mtime > cache_st->st_mtime) {
            printf("file_manifest: artifact file_index=%u modified after "
                   "cache, rebuilding\n", (unsigned)file_index);
            return false;
        }
    }

    return true;
}

void file_controller_init(const char *datadir)
{
    struct file_context *ctx = file_ctx();
    pthread_mutex_lock(&ctx->manifest_mutex);
    ctx->datadir = datadir;
    memset(&ctx->manifest, 0, sizeof(ctx->manifest));
    ctx->manifest_valid = false;
    pthread_mutex_unlock(&ctx->manifest_mutex);
}

bool file_controller_get_manifest_copy(struct file_manifest *out)
{
    struct file_context *ctx = file_ctx();

    if (!out)
        LOG_FAIL("file", "get_manifest_copy: NULL output pointer");

    pthread_mutex_lock(&ctx->manifest_mutex);
    if (ctx->manifest_valid)
        *out = ctx->manifest;
    else
        memset(out, 0, sizeof(*out));
    bool ok = ctx->manifest_valid;
    const char *datadir = ctx->datadir;
    pthread_mutex_unlock(&ctx->manifest_mutex);
    if (ok && !file_snapshot_serving_allowed(datadir))
        file_manifest_strip_snapshot(out);
    return ok;
}

bool file_controller_refresh_manifest(void)
{
    struct file_context *ctx = file_ctx();
    struct file_manifest manifest = {0};
    bool manifest_valid = false;

    pthread_mutex_lock(&ctx->manifest_mutex);
    const char *datadir = ctx->datadir;
    pthread_mutex_unlock(&ctx->manifest_mutex);

    if (!datadir) {
        pthread_mutex_lock(&ctx->manifest_mutex);
        ctx->manifest_valid = false;
        memset(&ctx->manifest, 0, sizeof(ctx->manifest));
        pthread_mutex_unlock(&ctx->manifest_mutex);
        LOG_FAIL("file", "refresh_manifest: datadir not configured");
    }

    manifest_valid = file_manifest_build(&manifest, datadir);

    pthread_mutex_lock(&ctx->manifest_mutex);
    ctx->manifest_valid = manifest_valid;
    if (manifest_valid)
        ctx->manifest = manifest;
    else
        memset(&ctx->manifest, 0, sizeof(ctx->manifest));
    pthread_mutex_unlock(&ctx->manifest_mutex);
    return manifest_valid;
}

void file_controller_get_manifest_status(struct file_manifest_status *out)
{
    struct file_context *ctx = file_ctx();
    struct file_manifest_status status = {0};

    if (!out)
        return;

    struct file_manifest serving_manifest = {0};
    pthread_mutex_lock(&ctx->manifest_mutex);
    status.datadir_configured = (ctx->datadir != NULL);
    status.manifest_valid = ctx->manifest_valid;
    if (ctx->manifest_valid) {
        serving_manifest = ctx->manifest;
    }
    const char *datadir = ctx->datadir;
    pthread_mutex_unlock(&ctx->manifest_mutex);

    if (status.manifest_valid) {
        if (!file_snapshot_serving_allowed(datadir))
            file_manifest_strip_snapshot(&serving_manifest);
        status.num_chunks = serving_manifest.num_chunks;
        status.total_bytes = serving_manifest.total_bytes;
        status.snapshot_served =
            file_manifest_has_file_index(&serving_manifest, 254);
        status.block_index_served =
            file_manifest_has_file_index(&serving_manifest, 253);
    }

    if (datadir) {
        status.snapshot_present = file_artifact_exists(datadir, 254, 1000000, NULL);
        status.block_index_present = file_artifact_exists(datadir, 253, 1000000, NULL);
    }

    *out = status;
}

/* ── Build manifest from block files ───────────────────────────── */

static bool hash_file_chunks(const char *path, uint8_t file_index,
                              struct file_manifest *fm)
{
    FILE *f = fopen(path, "rb");
    if (!f) LOG_FAIL("file", "hash_file_chunks: cannot open %s", path);

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) { fclose(f); return true; }

    uint8_t *buf = zcl_malloc(FILE_CHUNK_SIZE, "file chunk hash buf");
    if (!buf) { fclose(f); LOG_FAIL("file", "hash_file_chunks: alloc(%d) failed for %s", FILE_CHUNK_SIZE, path); }

    uint64_t offset = 0;
    while (offset < (uint64_t)file_size &&
           fm->num_chunks < FILE_MAX_CHUNKS) {
        uint32_t to_read = FILE_CHUNK_SIZE;
        if (offset + to_read > (uint64_t)file_size)
            to_read = (uint32_t)((uint64_t)file_size - offset);

        size_t got = fread(buf, 1, to_read, f);
        if (got != to_read) { free(buf); fclose(f); LOG_FAIL("file", "hash_file_chunks: short read at offset %llu in %s (got %zu, expected %u)", (unsigned long long)offset, path, got, to_read); }

        struct file_chunk *chunk = &fm->chunks[fm->num_chunks];
        chunk->offset = offset;
        chunk->size = to_read;
        chunk->file_index = file_index;

        /* SHA3-256 hash of chunk data */
        sha3_256(buf, to_read, chunk->sha3);

        fm->total_bytes += to_read;
        fm->num_chunks++;
        offset += to_read;
    }

    free(buf);
    fclose(f);
    return true;
}

/* Save manifest to disk for instant reload on restart */
static bool file_manifest_save(const struct file_manifest *fm,
                                const char *datadir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/file_manifest.bin", datadir);
    FILE *f = fopen(path, "wb");
    if (!f) LOG_FAIL("file", "manifest_save: cannot create %s", path);
    /* Write header: magic + num_chunks + total_bytes + root_hash */
    uint32_t magic = 0x464D414E; /* "FMAN" */
    /* A short fwrite silently corrupts the on-disk manifest; reject it. */
    if (fwrite(&magic, 4, 1, f) != 1 ||
        fwrite(&fm->num_chunks, 4, 1, f) != 1 ||
        fwrite(&fm->total_bytes, 8, 1, f) != 1 ||
        fwrite(fm->root_hash, 32, 1, f) != 1) {
        fclose(f); LOG_FAIL("file", "manifest_save: short header write to %s", path);
    }
    /* Write chunks */
    for (uint32_t i = 0; i < fm->num_chunks; i++) {
        if (fwrite(fm->chunks[i].sha3, 32, 1, f) != 1 ||
            fwrite(&fm->chunks[i].offset, 8, 1, f) != 1 ||
            fwrite(&fm->chunks[i].size, 4, 1, f) != 1 ||
            fwrite(&fm->chunks[i].file_index, 1, 1, f) != 1) {
            fclose(f); LOG_FAIL("file", "manifest_save: short chunk write to %s", path);
        }
    }
    fflush(f);
    platform_data_sync(fileno(f));
    fclose(f);
    return true;
}

/* Load cached manifest from disk — instant startup */
static bool file_manifest_load(struct file_manifest *fm,
                                const char *datadir)
{
    char path[512];
    struct stat cache_st;
    snprintf(path, sizeof(path), "%s/file_manifest.bin", datadir);
    FILE *f = fopen(path, "rb");
    if (!f) LOG_FAIL("file", "manifest_load: cannot open %s", path);
    memset(fm, 0, sizeof(*fm));
    uint32_t magic = 0;
    if (fread(&magic, 4, 1, f) != 1 || magic != 0x464D414E) {
        fclose(f); LOG_FAIL("file", "manifest_load: bad magic in %s (got 0x%08x)", path, magic);
    }
    /* A truncated cache leaves these fields uninitialized; a short fread must
     * fail loudly rather than run the bounds check and loop on garbage. */
    if (fread(&fm->num_chunks, 4, 1, f) != 1 ||
        fread(&fm->total_bytes, 8, 1, f) != 1 ||
        fread(fm->root_hash, 32, 1, f) != 1) {
        fclose(f); LOG_FAIL("file", "manifest_load: short header read from %s", path);
    }
    if (fm->num_chunks > FILE_MAX_CHUNKS) { fclose(f); LOG_FAIL("file", "manifest_load: num_chunks %u exceeds max %d", fm->num_chunks, FILE_MAX_CHUNKS); }
    for (uint32_t i = 0; i < fm->num_chunks; i++) {
        if (fread(fm->chunks[i].sha3, 32, 1, f) != 1 ||
            fread(&fm->chunks[i].offset, 8, 1, f) != 1 ||
            fread(&fm->chunks[i].size, 4, 1, f) != 1 ||
            fread(&fm->chunks[i].file_index, 1, 1, f) != 1) {
            fclose(f); LOG_FAIL("file", "manifest_load: short chunk read from %s (chunk %u of %u)", path, i, fm->num_chunks);
        }
    }
    fclose(f);

    if (!file_manifest_cache_has_required_exports(fm, datadir))
        LOG_FAIL("file", "manifest_load: cache missing required exports");

    /* Verify block files still match — check first AND last chunk.
     * The last chunk is most likely to be stale (active block file). */
    if (fm->num_chunks > 0) {
        uint8_t *data = NULL;
        uint32_t sz = 0;
        if (!file_chunk_read(&fm->chunks[0], datadir, &data, &sz)) {
            printf("file_manifest: first chunk stale, rebuilding\n");
            return false;
        }
        free(data);
        /* Also check last chunk — most likely to be stale */
        if (fm->num_chunks > 1) {
            data = NULL; sz = 0;
            if (!file_chunk_read(&fm->chunks[fm->num_chunks - 1],
                                  datadir, &data, &sz)) {
                printf("file_manifest: last chunk stale, rebuilding\n");
                return false;
            }
            free(data);
        }
        /* Check if any served input artifact changed after the cache. */
        if (stat(path, &cache_st) == 0) {
            uint8_t last_fi = fm->chunks[fm->num_chunks - 1].file_index;
            if (last_fi < 253) {
                char blk_path[576];
                struct stat blk_st;
                snprintf(blk_path, sizeof(blk_path),
                         "%s/blocks/blk%05d.dat", datadir, last_fi);
                if (stat(blk_path, &blk_st) == 0 &&
                    blk_st.st_mtime > cache_st.st_mtime) {
                    printf("file_manifest: blk%05d.dat modified after cache, "
                           "rebuilding\n", last_fi);
                    return false;
                }
            }
            if (!file_manifest_cache_inputs_are_fresh(fm, datadir, &cache_st))
                LOG_FAIL("file", "manifest_load: cache inputs are stale");
        }
    }
    printf("file_manifest: loaded cached manifest (%u chunks, %.1f GB)\n",
           fm->num_chunks,
           (double)fm->total_bytes / (1024.0*1024.0*1024.0));
    return true;
}

bool file_manifest_build(struct file_manifest *fm, const char *datadir)
{
    /* Try loading cached manifest first — instant startup */
    if (file_manifest_load(fm, datadir))
        return true;

    memset(fm, 0, sizeof(*fm));

    char blocks_dir[512];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);

    /* Count block files first to find the last one */
    int num_files = 0;
    for (int i = 0; i < 256; i++) {
        char path[576];
        snprintf(path, sizeof(path), "%s/blk%05d.dat", blocks_dir, i);
        struct stat st;
        if (stat(path, &st) != 0) break;
        num_files++;
    }

    /* Scan block files. Skip any file modified in the last hour —
     * the node may be actively appending blocks via P2P, which
     * changes the file after we hash it, causing SHA3 mismatches.
     * Only serve stable, immutable files. */
    int64_t cutoff = (int64_t)platform_time_wall_time_t() - 3600;
    for (int i = 0; i < num_files; i++) {
        char path[576];
        snprintf(path, sizeof(path), "%s/blk%05d.dat", blocks_dir, i);

        struct stat st;
        if (stat(path, &st) != 0) break;
        if (st.st_size == 0) continue;
        if ((int64_t)st.st_mtime > cutoff) {
            printf("file_manifest: skipping %s (modified %llds ago)\n",
                   path, (long long)((int64_t)platform_time_wall_time_t() - (int64_t)st.st_mtime));
            continue;
        }

        if (!hash_file_chunks(path, (uint8_t)i, fm))
            LOG_FAIL("file", "manifest_build: hash_file_chunks failed for %s", path);
    }

    /* Serve block_index.bin (flat file, ~409MB) as file_index=253.
     * Saves 116s LevelDB scan on first boot. Block index is safe to
     * transfer — it only contains PoW-verified header metadata. */
    {
        char flat_path[576];
        snprintf(flat_path, sizeof(flat_path), "%s/block_index.bin", datadir);
        struct stat flat_st;
        if (stat(flat_path, &flat_st) == 0 && flat_st.st_size > 1000000) {
            if ((int64_t)flat_st.st_mtime > cutoff) {
                printf("file_manifest: skipping block_index.bin "
                       "(modified %llds ago)\n",
                       (long long)((int64_t)platform_time_wall_time_t() -
                                   (int64_t)flat_st.st_mtime));
            } else {
                printf("file_manifest: adding block_index.bin (%.0f MB)\n",
                       (double)flat_st.st_size / (1024.0*1024.0));
                hash_file_chunks(flat_path, 253, fm);
            }
        }
    }

    /* Serve consensus snapshot as file_index=254 only from sovereign state.
     * SECURITY: node.db contains private wallet keys/txns.
     * We export ONLY public consensus tables (blocks, utxos,
     * addresses, chain_stats) into a separate snapshot file.
     * This file is SHA3-verified and safe to share with any peer. */
    {
        char snap_path[576];
        snprintf(snap_path, sizeof(snap_path),
                 "%s/consensus_snapshot.db", datadir);
        struct stat snap_st;
        if (file_snapshot_serving_allowed(datadir) &&
            stat(snap_path, &snap_st) == 0 && snap_st.st_size > 1000000) {
            printf("file_manifest: adding consensus_snapshot.db (%.0f MB)\n",
                   (double)snap_st.st_size / (1024.0*1024.0));
            hash_file_chunks(snap_path, 254, fm);
        }
    }

    if (fm->num_chunks == 0) LOG_FAIL("file", "manifest_build: no chunks found in %s", datadir);

    /* Compute root hash: SHA3-256 of all chunk hashes concatenated */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    for (uint32_t i = 0; i < fm->num_chunks; i++)
        sha3_256_write(&ctx, fm->chunks[i].sha3, 32);
    sha3_256_finalize(&ctx, fm->root_hash);

    /* Embed the current auxiliary MMR root as peer evidence. Receivers can
     * verify internal consistency with the advertised manifest/history; this
     * is not a ZClassic consensus or PoW commitment to file/state bytes. */
    {
        uint64_t leaves = 0;
        if (rpc_blockchain_mmr_snapshot(fm->mmr_root, &leaves, NULL) &&
            leaves > 0) {
            fm->chain_height = (int32_t)leaves;
        } else {
            memset(fm->mmr_root, 0, 32);
        }
    }

    printf("File manifest: %u chunks, %llu bytes, root=",
           fm->num_chunks, (unsigned long long)fm->total_bytes);
    for (int i = 0; i < 8; i++) printf("%02x", fm->root_hash[i]);
    printf("...\n");

    /* Cache to disk for instant reload on next restart */
    file_manifest_save(fm, datadir);

    return true;
}

const struct file_chunk *file_manifest_find(const struct file_manifest *fm,
                                             const uint8_t sha3[32])
{
    bool snapshot_allowed = file_snapshot_state_allowed();
    for (uint32_t i = 0; i < fm->num_chunks; i++) {
        if (fm->chunks[i].file_index == 254 && !snapshot_allowed)
            continue;
        if (memcmp(fm->chunks[i].sha3, sha3, 32) == 0)
            return &fm->chunks[i];
    }
    LOG_NULL("file", "manifest_find: chunk not found among %u chunks", fm->num_chunks);
}

bool file_chunk_read(const struct file_chunk *chunk, const char *datadir,
                     uint8_t **out, uint32_t *out_size)
{
    if (out)
        *out = NULL;
    if (out_size)
        *out_size = 0;
    if (!chunk || !datadir || !out || !out_size)
        LOG_FAIL("file", "chunk_read: invalid argument");
    if (chunk->file_index == 254 &&
        !file_snapshot_serving_allowed(datadir))
        LOG_FAIL("file", "chunk_read: consensus snapshot withheld because "
                          "full-state history is not sovereign");
    char path[576];
    if (!file_artifact_path(path, sizeof(path), datadir, chunk->file_index))
        LOG_FAIL("file", "chunk_read: cannot build path for file_index=%u", (unsigned)chunk->file_index);

    FILE *f = fopen(path, "rb");
    if (!f) LOG_FAIL("file", "chunk_read: cannot open %s", path);

    if (fseek(f, (long)chunk->offset, SEEK_SET) != 0) {
        fclose(f);
        LOG_FAIL("file", "chunk_read: fseek to offset %llu failed in %s", (unsigned long long)chunk->offset, path);
    }

    uint8_t *buf = zcl_malloc(chunk->size, "file chunk read buf");
    if (!buf) { fclose(f); LOG_FAIL("file", "chunk_read: alloc(%u) failed for %s", chunk->size, path); }

    size_t got = fread(buf, 1, chunk->size, f);
    fclose(f);

    if (got != chunk->size) { free(buf); LOG_FAIL("file", "chunk_read: short read in %s (got %zu, expected %u)", path, got, chunk->size); }

    /* Verify SHA3 hash matches manifest */
    uint8_t hash[32];
    sha3_256(buf, chunk->size, hash);
    if (memcmp(hash, chunk->sha3, 32) != 0) {
        LOG_WARN("file", "chunk_read: SHA3 mismatch for chunk at "
                "file=%d offset=%llu",
                chunk->file_index, (unsigned long long)chunk->offset);
        free(buf);
        return false;
    }

    *out = buf;
    *out_size = chunk->size;
    return true;
}

/* ── Consensus snapshot export ─────────────────────────────────── */
/* Exports ONLY public consensus tables from node.db.
 * NEVER exports: wallet_keys, wallet_utxos, wallet_sapling_keys,
 * wallet_sapling_notes, wallet_sapling_witnesses, node_state.
 * The exported file is safe to share with any peer. */

static bool rpc_getfilemanifest(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    struct file_manifest manifest;
    (void)params;
    RPC_HELP(help, result,
        "getfilemanifest\n"
        "\nReturn SHA3-verified file manifest for blockchain data.\n"
        "\nResult:\n"
        "  { root_hash, chain_height, total_bytes, num_chunks, chunks[] }\n");

    /* Build manifest on first call if not cached */
    if (!file_controller_get_manifest_copy(&manifest))
        file_controller_refresh_manifest();
    if (!file_controller_get_manifest_copy(&manifest)) {
        json_set_str(result, "error: no block files found");
        return true;
    }

    json_set_object(result);

    char root_hex[65];
    HexStr(manifest.root_hash, 32, false, root_hex, sizeof(root_hex));
    json_push_kv_str(result, "root_hash", root_hex);
    json_push_kv_int(result, "num_chunks", (int64_t)manifest.num_chunks);
    json_push_kv_int(result, "total_bytes", (int64_t)manifest.total_bytes);

    /* Chunk list */
    struct json_value chunks_arr = {0};
    json_set_array(&chunks_arr);
    for (uint32_t i = 0; i < manifest.num_chunks; i++) {
        struct json_value chunk_obj = {0};
        json_set_object(&chunk_obj);

        char hex[65];
        HexStr(manifest.chunks[i].sha3, 32, false, hex, sizeof(hex));
        json_push_kv_str(&chunk_obj, "sha3", hex);
        json_push_kv_int(&chunk_obj, "size",
                          (int64_t)manifest.chunks[i].size);
        json_push_kv_int(&chunk_obj, "file_index",
                          (int64_t)manifest.chunks[i].file_index);
        json_push_kv_int(&chunk_obj, "offset",
                          (int64_t)manifest.chunks[i].offset);

        json_push_back(&chunks_arr, &chunk_obj);
    }
    json_push_kv(result, "chunks", &chunks_arr);

    return true;
}

static bool rpc_getfilemanifeststatus(const struct json_value *params, bool help,
                                       struct json_value *result)
{
    struct file_manifest_status status;
    (void)params;
    RPC_HELP(help, result,
        "getfilemanifeststatus\n"
        "\nReturn current file manifest/export readiness summary.\n"
        "\nResult:\n"
        "  { datadir_configured, manifest_valid, snapshot_present,\n"
        "    snapshot_served, block_index_present, block_index_served,\n"
        "    num_chunks, total_bytes }\n");

    file_controller_get_manifest_status(&status);

    json_set_object(result);
    json_push_kv_bool(result, "datadir_configured", status.datadir_configured);
    json_push_kv_bool(result, "manifest_valid", status.manifest_valid);
    json_push_kv_bool(result, "snapshot_present", status.snapshot_present);
    json_push_kv_bool(result, "snapshot_served", status.snapshot_served);
    json_push_kv_bool(result, "block_index_present", status.block_index_present);
    json_push_kv_bool(result, "block_index_served", status.block_index_served);
    json_push_kv_int(result, "num_chunks", (int64_t)status.num_chunks);
    json_push_kv_int(result, "total_bytes", (int64_t)status.total_bytes);
    return true;
}

static bool rpc_getfilechunk(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct file_context *ctx = file_ctx();
    struct file_manifest manifest;
    const char *datadir;
    RPC_HELP(help, result,
        "getfilechunk \"sha3hash\"\n"
        "\nReturn a file chunk by its SHA3-256 hash.\n"
        "\nArguments:\n"
        "  1. sha3hash (string, required) — 64-char hex SHA3 hash\n"
        "\nResult: { size, sha3, data_hex } or error\n");

    if (!params || !file_controller_get_manifest_copy(&manifest)) {
        json_set_str(result, "error: file manifest not initialized");
        return true;
    }

    const struct json_value *arg0 = json_at(params, 0);
    const char *hex = arg0 ? json_get_str(arg0) : NULL;
    if (!zcl_is_hex_string(hex, 64)) {
        json_set_str(result, "error: sha3hash must be 64 hex chars");
        return true;
    }

    /* Parse hex → bytes */
    uint8_t sha3[32];
    if (ParseHex(hex, sha3, 32) != 32) {
        json_set_str(result, "error: invalid hex");
        return true;
    }

    const struct file_chunk *chunk = file_manifest_find(&manifest, sha3);
    if (!chunk) {
        json_set_str(result, "error: chunk not found");
        return true;
    }

    pthread_mutex_lock(&ctx->manifest_mutex);
    datadir = ctx->datadir;
    pthread_mutex_unlock(&ctx->manifest_mutex);

    uint8_t *data = NULL;
    uint32_t data_size = 0;
    if (!datadir || !file_chunk_read(chunk, datadir, &data, &data_size)) {
        json_set_str(result, "error: failed to read chunk from disk");
        return true;
    }

    json_set_object(result);
    json_push_kv_int(result, "size", (int64_t)data_size);
    json_push_kv_str(result, "sha3", hex);
    /* For large chunks, return size only — use REST API for data */
    json_push_kv_str(result, "download",
                      "use GET /api/files/<sha3hash> for raw data");

    free(data);
    return true;
}

void register_file_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "files", "getfilemanifest", rpc_getfilemanifest, true },
        { "files", "getfilemanifeststatus", rpc_getfilemanifeststatus, true },
        { "files", "getfilechunk",    rpc_getfilechunk,    true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
