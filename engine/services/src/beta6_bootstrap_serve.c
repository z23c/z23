/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Arm the beta6 bootstrap service and serve bounded chunks of its snapshot.
 *
 * Port of GetBootstrapSnapshotManifest + PreflightBootstrapSnapshotService +
 * ReadBootstrapSnapshotChunk (bootstrap.cpp:3722-3819, 4268-4426). The
 * manifest is built ONCE, when the flag arms the service, and cached; a
 * request path never hashes and never reads a whole file — every chunk is a
 * single bounded positioned read whose range the C++ validator has already
 * accepted.
 *
 * The serve directory is treated as immutable while armed: a chunk read
 * refuses when the file's size or mtime moved since the manifest was built,
 * which is what stops a half-written file from being served as if it had been
 * hashed (bootstrap.cpp:4362-4372).
 */
#include "services/beta6_bootstrap.h"

#include "platform/positioned_file.h"
#include "util/sync.h"

#include <stdio.h>
#include <string.h>

static zcl_mutex_t g_serve_lock;
static bool g_serve_lock_ready;
static bool g_armed;
static char g_source_dir[4096];
static struct beta6_bs_manifest g_manifest;

static void serve_lock_init_once(void)
{
    if (!g_serve_lock_ready) {
        zcl_mutex_init(&g_serve_lock);
        g_serve_lock_ready = true;
    }
}

/* Decide which manifest version this serve directory publishes, and fill the
 * anchor-derived header fields. A v2 self-snapshot ".meta" wins outright; a
 * ".anchor" copy publishes v1, upgraded to v3 when a ".blocktip" sidecar shows
 * the block bundle strictly extends past the anchor. */
static bool resolve_meta_manifest(const char *source_dir,
                                  struct beta6_bs_manifest *manifest)
{
    char path[4096];
    if (!beta6_bs_sidecar_path(source_dir, ".meta", path, sizeof(path)).ok)
        return false;  // raw-return-ok:no .meta path means this is not a v2 copy
    struct uint256 hash_block;
    struct uint256 hash_chainstate;
    int32_t height = -1;
    if (!beta6_bs_read_meta_sidecar(path, &height, &hash_block, &hash_chainstate).ok)
        return false;  // raw-return-ok:an absent .meta is the ordinary v1 anchor case
    manifest->version = 2;
    manifest->height = height;
    manifest->hash_block = hash_block;
    manifest->hash_chainstate = hash_chainstate;
    return true;
}

/* Which compiled anchor this copy belongs to. Unlike the C++
 * (ResolveServedAnchorFromMarker, bootstrap.cpp:1983-2009), a marker that
 * names NO compiled anchor is refused instead of silently falling back to the
 * primary: publishing the primary anchor's identity over a different copy's
 * bytes only wastes a client's whole multi-GiB download before it rejects. */
static struct zcl_result resolve_marked_anchor(const char *source_dir,
                                               const struct beta6_bs_anchor **out)
{
    char path[4096];
    struct zcl_result named = beta6_bs_sidecar_path(source_dir, ".anchor", path,
                                                    sizeof(path));
    if (!named.ok)
        return named;
    struct uint256 hash_block;
    int32_t height = -1;
    struct zcl_result marker =
        beta6_bs_read_height_hash_sidecar(path, &height, &hash_block);
    if (!marker.ok)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap source has no readable .anchor marker "
                       "beside %s: %s",
                       source_dir, marker.message);
    const struct beta6_bs_anchor *anchor = beta6_bs_find_anchor(height, &hash_block);
    if (!anchor)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap source .anchor names no compiled fast-sync "
                       "anchor: %s",
                       path);
    *out = anchor;
    return ZCL_OK;
}

static void apply_anchor(struct beta6_bs_manifest *manifest,
                         const struct beta6_bs_anchor *anchor)
{
    manifest->version = 1;
    manifest->height = anchor->height;
    manifest->hash_block = anchor->hash_block;
    manifest->hash_anchor_sha256 = anchor->hash_anchor_sha256;
    manifest->hash_anchor_sha3 = anchor->hash_anchor_sha3;
}

/* GROWABLE v3: keep the anchor as the pinned chainstate identity and publish
 * the extended block bundle's tip beside it. Emitted only when the bundle
 * strictly extends past the anchor and the anchor carries a commitment — the
 * exact gate the client's validator applies (bootstrap.cpp:4452-4482). */
static void apply_block_tip(const char *source_dir, struct beta6_bs_manifest *manifest,
                            const struct beta6_bs_anchor *anchor)
{
    char path[4096];
    if (!beta6_bs_sidecar_path(source_dir, ".blocktip", path, sizeof(path)).ok)
        return;
    struct uint256 hash_tip;
    int32_t tip_height = -1;
    if (!beta6_bs_read_height_hash_sidecar(path, &tip_height, &hash_tip).ok)
        return;
    if (tip_height <= anchor->height || uint256_is_null(&anchor->hash_chainstate))
        return;
    manifest->version = 3;
    manifest->hash_chainstate = anchor->hash_chainstate;
    manifest->block_tip_height = tip_height;
    manifest->hash_block_tip = hash_tip;
}

/* PreflightBootstrapSnapshotService: refuse to advertise a manifest we would
 * not accept ourselves. */
static struct zcl_result preflight_manifest(const struct beta6_bs_manifest *manifest)
{
    if (manifest->file_count == 0)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 bootstrap manifest has no files");
    uint64_t total = 0;
    for (size_t i = 0; i < manifest->file_count; i++) {
        const struct beta6_bs_file *file = &manifest->files[i];
        struct zcl_result safe = beta6_bs_check_data_path(file->path);
        if (!safe.ok)
            return safe;
        if (uint256_is_null(&file->sha256))
            return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                           "beta6 bootstrap manifest file is missing SHA-256: %s",
                           file->path);
        if (i > 0 && strcmp(manifest->files[i - 1].path, file->path) == 0)
            return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                           "beta6 bootstrap manifest has duplicate file path: %s",
                           file->path);
        total += file->size;
    }
    if (total != manifest->snapshot_bytes)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap manifest file sizes total %llu, not %llu",
                       (unsigned long long)total,
                       (unsigned long long)manifest->snapshot_bytes);
    return ZCL_OK;
}

static struct zcl_result build_manifest(const char *source_dir, const char *network,
                                        struct beta6_bs_manifest *manifest)
{
    beta6_bs_manifest_init(manifest);
    snprintf(manifest->network, sizeof(manifest->network), "%s", network);
    manifest->chunk_size = BETA6_BS_CHUNK_SIZE;

    if (!resolve_meta_manifest(source_dir, manifest)) {
        const struct beta6_bs_anchor *anchor = NULL;
        struct zcl_result marked = resolve_marked_anchor(source_dir, &anchor);
        if (!marked.ok)
            return marked;
        apply_anchor(manifest, anchor);
        apply_block_tip(source_dir, manifest, anchor);
    }
    struct zcl_result collected = beta6_bs_collect_files(source_dir, manifest);
    if (!collected.ok)
        return collected;
    struct zcl_result flown = preflight_manifest(manifest);
    if (!flown.ok)
        beta6_bs_manifest_free(manifest);
    return flown;
}

struct zcl_result beta6_bs_arm(const char *source_dir, const char *network)
{
    if (!source_dir || source_dir[0] == '\0')
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 bootstrap source directory is empty");
    if (source_dir[0] != '/')
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap source must be an ABSOLUTE path: %s", source_dir);
    if (strlen(source_dir) >= sizeof(g_source_dir))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap source path is too long: %s", source_dir);
    if (!network || network[0] == '\0')
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "beta6 bootstrap serve needs a network id");
    struct zcl_result present = beta6_bs_require_source_paths(source_dir);
    if (!present.ok)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap source is incomplete (needs blocks/, "
                       "blocks/index/ and chainstate/): %s",
                       present.message);

    struct beta6_bs_manifest built;
    struct zcl_result made = build_manifest(source_dir, network, &built);
    if (!made.ok)
        return made;

    serve_lock_init_once();
    LOCK(g_serve_lock);
    beta6_bs_manifest_free(&g_manifest);
    g_manifest = built;
    snprintf(g_source_dir, sizeof(g_source_dir), "%s", source_dir);
    g_armed = true;
    UNLOCK(g_serve_lock);
    return ZCL_OK;
}

void beta6_bs_disarm(void)
{
    serve_lock_init_once();
    LOCK(g_serve_lock);
    beta6_bs_manifest_free(&g_manifest);
    beta6_bs_manifest_init(&g_manifest);
    g_source_dir[0] = '\0';
    g_armed = false;
    UNLOCK(g_serve_lock);
}

struct zcl_result beta6_bs_status(void)
{
    if (!g_armed)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "the beta6 bootstrap snapshot service is not armed; set "
                       "-beta6-bootstrap-source");
    return ZCL_OK;
}

const char *beta6_bs_source_dir(void)
{
    return g_armed ? g_source_dir : "";
}

const struct beta6_bs_manifest *beta6_bs_manifest(void)
{
    return g_armed ? &g_manifest : NULL;
}

struct zcl_result beta6_bs_validate_chunk_range(uint64_t offset, uint64_t length,
                                                uint64_t file_size, uint64_t chunk_size,
                                                const char *label)
{
    if (chunk_size == 0)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "%s chunk size is zero", label);
    if (offset > file_size || length > file_size - offset)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "%s chunk range exceeds file size", label);
    if (offset % chunk_size != 0)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "%s chunk offset is not aligned", label);
    uint64_t remaining = file_size - offset;
    uint64_t expected = remaining < chunk_size ? remaining : chunk_size;
    if (length != expected)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "%s chunk length is not the expected size",
                       label);
    return ZCL_OK;
}

/* Open one manifest file and prove it is still the object that was hashed:
 * same size, same mtime. The open is confined beneath `root` and follows no
 * link at any component, so the manifest path cannot escape the serve tree;
 * the snapshot caller additionally requires a blocks//chainstate/ data path,
 * which a bare parameter file name is not. */
static struct zcl_result open_verified(const char *root,
                                       const struct beta6_bs_file *file,
                                       struct platform_positioned_file *out)
{
    platform_positioned_file_init(out);
    if (!platform_positioned_file_open_beneath(out, root, file->path))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "could not open beta6 bootstrap snapshot file: %s", file->path);
    struct platform_positioned_file_snapshot stamp;
    uint64_t size = 0;
    if (!platform_positioned_file_size(out, &size) ||
        !platform_positioned_file_snapshot(out, &stamp)) {
        platform_positioned_file_close(out);
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "could not stat beta6 bootstrap snapshot file: %s", file->path);
    }
    if (size != file->size || stamp.modified_seconds != file->mtime_seconds) {
        platform_positioned_file_close(out);
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap snapshot file changed after manifest "
                       "creation: %s",
                       file->path);
    }
    return ZCL_OK;
}

/* Shared bounded read for both the snapshot and the parameter serve paths. */
struct zcl_result beta6_bs_read_file_chunk(const char *root,
                                           const struct beta6_bs_file *file,
                                           const struct beta6_bs_chunk_request *request,
                                           const char *label, unsigned char *out,
                                           size_t out_capacity)
{
    struct zcl_result ranged = beta6_bs_validate_chunk_range(
        request->offset, request->length, file->size, BETA6_BS_CHUNK_SIZE, label);
    if (!ranged.ok)
        return ranged;
    if (out_capacity < request->length)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "%s chunk buffer is too small", label);

    struct platform_positioned_file handle;
    struct zcl_result opened = open_verified(root, file, &handle);
    if (!opened.ok)
        return opened;
    int64_t got = platform_positioned_file_read(&handle, out, request->length,
                                                request->offset);
    platform_positioned_file_close(&handle);
    if (got < 0 || (uint64_t)got != request->length)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "could not read the requested %s chunk",
                       label);
    return ZCL_OK;
}

struct zcl_result beta6_bs_read_chunk(const struct beta6_bs_chunk_request *request,
                                      unsigned char *out, size_t out_capacity)
{
    if (!request || !out)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap chunk read needs a request and a buffer");
    struct zcl_result armed = beta6_bs_status();
    if (!armed.ok)
        return armed;
    if (request->length == 0 || request->length > BETA6_BS_CHUNK_SIZE)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED, "invalid beta6 bootstrap chunk length %u",
                       (unsigned)request->length);
    if (request->file_index >= g_manifest.file_count)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 bootstrap chunk file index %u out of range (%zu served)",
                       (unsigned)request->file_index, g_manifest.file_count);
    struct zcl_result safe =
        beta6_bs_check_data_path(g_manifest.files[request->file_index].path);
    if (!safe.ok)
        return safe;
    return beta6_bs_read_file_chunk(g_source_dir, &g_manifest.files[request->file_index],
                                    request, "bootstrap", out, out_capacity);
}
