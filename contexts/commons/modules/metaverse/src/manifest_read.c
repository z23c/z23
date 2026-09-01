/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only helpers over the frozen <datadir>/zcode layout. See
 * metaverse_priv.h; the layout contract itself is vcs/package_store.h.
 *
 * Why this file exists rather than a store handle: vcs_package_store_open()
 * deletes leftover temps, commits staged packages, and GCs orphan CAS
 * objects. That is correct for the node and wrong for a read command, so
 * the projection reaches the same canonical bytes by path. The wires stay
 * authoritative — nothing here is a second truth, exactly as
 * contexts/commons/modules/vcs/package_index.c reads manifests/<root> directly. */

#include "metaverse_priv.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "metaverse/property_adapter.h"
#include "platform/positioned_file.h"
#include "platform/file_metadata.h"
#include "vcs/blob_store.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MV_LOG "metaverse.read"
#define MV_PATH_MAX 4400

struct mv_chunk_fingerprint {
    struct platform_positioned_file_snapshot snapshot;
    uint8_t hash[32];
};

static bool mv_snapshot_equal(
    const struct platform_positioned_file_snapshot *left,
    const struct platform_positioned_file_snapshot *right)
{
    return left->size == right->size && left->volume == right->volume &&
        left->file_low == right->file_low && left->file_high == right->file_high &&
        left->modified_seconds == right->modified_seconds &&
        left->modified_nanoseconds == right->modified_nanoseconds &&
        left->changed_seconds == right->changed_seconds &&
        left->changed_nanoseconds == right->changed_nanoseconds;
}

static bool mv_read_exact(const struct platform_positioned_file *file,
                          uint8_t *out, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        int64_t got = platform_positioned_file_read(
            file, out + offset, length - offset, offset);
        if (got <= 0)
            return false;
        offset += (size_t)got;
    }
    return true;
}

static size_t mv_expected_chunk(const struct vcs_package_file *file,
                                uint32_t chunk_index)
{
    uint64_t offset = (uint64_t)chunk_index * VCS_PACKAGE_CHUNK_BYTES;
    uint64_t remaining = file->size - offset;

    return remaining > VCS_PACKAGE_CHUNK_BYTES
               ? VCS_PACKAGE_CHUNK_BYTES
               : (size_t)remaining;
}

static bool mv_cas_path(const char *zcode_dir, const uint8_t hash[32],
                        char out[MV_PATH_MAX])
{
    char hex[65];
    int n;

    if (!zcode_dir || !hash || !out)
        return false;
    zcl_hex_encode(hash, 32, hex);
    (void)zcode_dir;
    n = snprintf(out, MV_PATH_MAX, "cas/sha3/%.2s/%s", hex, hex);
    return n >= 0 && (size_t)n < MV_PATH_MAX;
}

/* Name why a CAS coordinate could not be opened as possession bytes.
 * `relative` is a store-relative path as built by mv_cas_path(). Callers use
 * this only for the reported verification_gap; the refusal itself is decided
 * on the handle. */
static const char *mv_chunk_refusal_gap(const char *zcode_dir,
                                        const char *relative)
{
    char full[MV_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", zcode_dir, relative);

    if (n <= 0 || (size_t)n >= sizeof(full))
        return "cas_path_invalid";
    switch (platform_file_shape_read(full)) {
    case PLATFORM_FILE_SHAPE_MISSING:
        return "chunk_missing";
    case PLATFORM_FILE_SHAPE_SYMLINK:
        return "chunk_symlink";
    case PLATFORM_FILE_SHAPE_OTHER:
        return "chunk_not_regular";
    /* REGULAR lands here when the object became a plain file between the
     * refused open and this look, or when a component above it is what
     * actually blocked the open. Either way the coordinate was unreadable
     * to us, which is what we say. */
    default:
        return "chunk_unreadable";
    }
}

static void mv_verification_gap(struct mv_manifest_read *manifest,
                                const char *gap)
{
    if (manifest->verification_gap[0] == '\0')
        (void)snprintf(manifest->verification_gap,
                       sizeof(manifest->verification_gap), "%s", gap);
}

/* Read at most `cap` bytes of a file; a file larger than cap is a
 * rejection, not a truncated read. */
static enum mv_manifest_read_status mv_read_file(
    const char *root, const char *relative, size_t cap,
    uint8_t **out, size_t *out_len)
{
    uint8_t *buf;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    size_t len = 0;

    *out = NULL;
    *out_len = 0;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, root, relative)) {
        char full[MV_PATH_MAX];
        struct platform_file_metadata metadata;
        int n = snprintf(full, sizeof(full), "%s/%s", root, relative);
        enum platform_file_metadata_result result =
            n > 0 && (size_t)n < sizeof(full)
                ? platform_file_metadata_read(full, &metadata)
                : PLATFORM_FILE_METADATA_REFUSED;
        return result == PLATFORM_FILE_METADATA_MISSING
            ? MV_MANIFEST_READ_ABSENT : MV_MANIFEST_READ_INVALID;
    }
    if (cap == SIZE_MAX || !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return MV_MANIFEST_READ_IO_ERROR;
    }
    if (before.size == 0 || before.size > (uint64_t)cap) {
        platform_positioned_file_close(&file);
        return MV_MANIFEST_READ_INVALID;
    }
    len = (size_t)before.size;
    buf = zcl_malloc(len, "mv_read_file");
    if (!buf) {
        platform_positioned_file_close(&file);
        LOG_RETURN(MV_MANIFEST_READ_IO_ERROR, MV_LOG,
                   "read buffer of %zu bytes for %s", len, relative);
    }
    if (!mv_read_exact(&file, buf, len) ||
        !platform_positioned_file_snapshot(&file, &after)) {
        platform_positioned_file_close(&file);
        free(buf);
        return MV_MANIFEST_READ_IO_ERROR;
    }
    platform_positioned_file_close(&file);
    if (!mv_snapshot_equal(&before, &after)) {
        free(buf);
        return MV_MANIFEST_READ_INVALID;
    }
    *out = buf;
    *out_len = len;
    return MV_MANIFEST_READ_OK;
}

bool mv_manifest_is_blob(const struct vcs_package_manifest *m)
{
    const struct vcs_package_file *f;

    if (!m || m->count != 1u || !m->files)
        return false;
    f = &m->files[0];
    return f->path && strcmp(f->path, VCS_BLOB_PATH) == 0 &&
           f->mode == VCS_PACKAGE_MODE_FILE && f->chunk_count == 1u &&
           f->size > 0 && f->size <= (uint64_t)VCS_BLOB_MAX_BYTES;
}

void mv_manifest_free(struct mv_manifest_read *m)
{
    if (!m)
        return;
    vcs_package_manifest_free(&m->manifest);
    memset(m, 0, sizeof(*m));
}

const char *mv_manifest_read_status_name(enum mv_manifest_read_status status)
{
    switch (status) {
    case MV_MANIFEST_READ_OK:       return "ok";
    case MV_MANIFEST_READ_ABSENT:   return "absent";
    case MV_MANIFEST_READ_IO_ERROR: return "io_error";
    case MV_MANIFEST_READ_INVALID:  return "invalid";
    }
    return "invalid";
}

enum mv_manifest_read_status mv_manifest_read(
    const char *zcode_dir, const char *root_hex, struct mv_manifest_read *out)
{
    char path[MV_PATH_MAX];
    uint8_t name_root[32];
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum mv_manifest_read_status read_status;
    int n;

    if (!out)
        return MV_MANIFEST_READ_INVALID;
    memset(out, 0, sizeof(*out));
    if (!zcode_dir || !root_hex || !zcl_hex_decode_lower(root_hex, name_root, 32))
        return MV_MANIFEST_READ_INVALID;

    n = snprintf(path, sizeof(path), "manifests/%s", root_hex);
    if (n < 0 || (size_t)n >= sizeof(path))
        return MV_MANIFEST_READ_INVALID;
    read_status = mv_read_file(zcode_dir, path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                               &wire, &wire_len);
    if (read_status != MV_MANIFEST_READ_OK)
        return read_status;
    if (!vcs_package_manifest_parse(wire, wire_len, &out->manifest)) {
        free(wire);
        memset(out, 0, sizeof(*out));
        return MV_MANIFEST_READ_INVALID;
    }
    free(wire);

    /* Re-derive the root from the wire we just parsed. This is the whole
     * basis of the local_content_hash evidence grade: the filename is not
     * evidence of anything, the recomputed root is. */
    if (!vcs_package_manifest_root(&out->manifest, out->root)) {
        vcs_package_manifest_free(&out->manifest);
        memset(out, 0, sizeof(*out));
        return MV_MANIFEST_READ_INVALID;
    }
    out->root_matches_name = memcmp(out->root, name_root, 32) == 0;
    out->manifest_root_verified = out->root_matches_name;
    if (!out->root_matches_name)
        mv_verification_gap(out, "manifest_root_mismatch");

    out->file_count = (uint32_t)out->manifest.count;
    for (size_t i = 0; i < out->manifest.count; i++) {
        const struct vcs_package_file *f = &out->manifest.files[i];

        out->total_bytes += f->size;
        out->chunk_total += f->chunk_count;
    }
    return MV_MANIFEST_READ_OK;
}

static void mv_manifest_verify_possession_impl(
    const char *zcode_dir, struct mv_manifest_read *manifest,
    uint64_t byte_budget, uint32_t operation_budget,
#ifdef ZCL_TESTING
    mv_manifest_verify_test_hook hook, void *hook_context,
#endif
    uint64_t *bytes_used, uint32_t *operations_used)
{
    struct mv_chunk_fingerprint *fingerprints = NULL;
    uint32_t coordinate = 0;
    uint64_t used_bytes = 0;
    uint32_t used_operations = 0;

    if (bytes_used)
        *bytes_used = 0;
    if (operations_used)
        *operations_used = 0;
    if (!manifest)
        return;
    manifest->chunks_present = 0;
    manifest->chunks_verified = 0;
    manifest->bytes_verified = 0;
    manifest->verification_complete = false;
    if (!manifest->manifest_root_verified) {
        mv_verification_gap(manifest, "manifest_root_mismatch");
        return;
    }
    manifest->verification_gap[0] = '\0';
    if (!zcode_dir) {
        mv_verification_gap(manifest, "store_unavailable");
        return;
    }
    if (manifest->chunk_total == 0) {
        manifest->verification_complete = true;
        return;
    }
    fingerprints = zcl_calloc(manifest->chunk_total,
                              sizeof(*fingerprints),
                              "mv_chunk_fingerprints");
    if (!fingerprints) {
        mv_verification_gap(manifest, "allocation_failed");
        return;
    }

    for (size_t i = 0; i < manifest->manifest.count; i++) {
        const struct vcs_package_file *file = &manifest->manifest.files[i];

        for (uint32_t c = 0; c < file->chunk_count; c++, coordinate++) {
            const uint8_t *hash = file->chunk_hashes + (size_t)c * 32u;
            size_t expected = mv_expected_chunk(file, c);
            char path[MV_PATH_MAX];
            struct platform_positioned_file file_handle;
            struct platform_positioned_file_snapshot before, after;
            uint8_t *bytes = NULL;

            if (used_operations >= operation_budget) {
                mv_verification_gap(manifest, "operation_budget_exhausted");
                goto done;
            }
            if ((uint64_t)expected > byte_budget - used_bytes) {
                mv_verification_gap(manifest, "byte_budget_exhausted");
                goto done;
            }
            used_operations++;
            if (!mv_cas_path(zcode_dir, hash, path)) {
                mv_verification_gap(manifest, "cas_path_invalid");
                goto done;
            }
            platform_positioned_file_init(&file_handle);
            if (!platform_positioned_file_open_beneath(
                    &file_handle, zcode_dir, path)) {
                /* The refusal above is the fail-closed decision and it is
                 * already taken on the handle; this second, pathname-based
                 * look only NAMES it. open_beneath returns one bool for four
                 * different facts, and reporting a planted symlink or a
                 * directory as "chunk_missing" tells an operator to
                 * re-download when what actually happened is that something
                 * was substituted at the CAS coordinate. mv_read_file()
                 * above answers a coarser question -- absent or invalid --
                 * so it keeps only two of these four facts; this path needs
                 * all four. A race here can only mislabel a refusal that
                 * stands regardless. */
                mv_verification_gap(manifest,
                                    mv_chunk_refusal_gap(zcode_dir, path));
                goto done;
            }
            if (!platform_positioned_file_snapshot(&file_handle, &before)) {
                platform_positioned_file_close(&file_handle);
                mv_verification_gap(manifest, "chunk_stat_failed");
                goto done;
            }
            if (before.size != (uint64_t)expected) {
                platform_positioned_file_close(&file_handle);
                mv_verification_gap(manifest, "chunk_length_mismatch");
                goto done;
            }
            manifest->chunks_present++;
            bytes = zcl_malloc(expected, "mv_verify_chunk");
            if (!bytes) {
                platform_positioned_file_close(&file_handle);
                mv_verification_gap(manifest, "allocation_failed");
                goto done;
            }
            if (!mv_read_exact(&file_handle, bytes, expected)) {
                free(bytes);
                platform_positioned_file_close(&file_handle);
                used_bytes += expected;
                mv_verification_gap(manifest, "chunk_read_failed");
                goto done;
            }
            used_bytes += expected;
            if (!platform_positioned_file_snapshot(&file_handle, &after) ||
                !mv_snapshot_equal(&before, &after)) {
                free(bytes);
                platform_positioned_file_close(&file_handle);
                mv_verification_gap(manifest,
                                    "chunk_mutated_during_verification");
                goto done;
            }
            platform_positioned_file_close(&file_handle);
            if (!vcs_package_verify_chunk(file, c, bytes, expected)) {
                free(bytes);
                mv_verification_gap(manifest, "chunk_hash_mismatch");
                goto done;
            }
            free(bytes);
            fingerprints[coordinate].snapshot = after;
            memcpy(fingerprints[coordinate].hash, hash, 32);
            manifest->chunks_verified++;
            manifest->bytes_verified += expected;
#ifdef ZCL_TESTING
            if (hook)
                hook(hook_context, manifest->chunks_verified);
#endif
        }
    }

    /* Re-check every coordinate after the final hash. This closes the useful
     * race window: replacing an early chunk while later chunks are being
     * hashed cannot yield a completed possession claim. */
    for (coordinate = 0; coordinate < manifest->chunk_total; coordinate++) {
        char path[MV_PATH_MAX];
        struct platform_positioned_file file_handle;
        struct platform_positioned_file_snapshot status;
        const struct mv_chunk_fingerprint *fingerprint =
            &fingerprints[coordinate];

        if (used_operations >= operation_budget) {
            mv_verification_gap(manifest, "operation_budget_exhausted");
            goto done;
        }
        used_operations++;
        platform_positioned_file_init(&file_handle);
        bool unchanged = mv_cas_path(zcode_dir, fingerprint->hash, path) &&
            platform_positioned_file_open_beneath(
                &file_handle, zcode_dir, path) &&
            platform_positioned_file_snapshot(&file_handle, &status) &&
            mv_snapshot_equal(&status, &fingerprint->snapshot);
        platform_positioned_file_close(&file_handle);
        if (!unchanged) {
            mv_verification_gap(manifest,
                                "chunk_mutated_during_verification");
            goto done;
        }
    }
    manifest->verification_complete = true;

done:
    free(fingerprints);
    if (bytes_used)
        *bytes_used = used_bytes;
    if (operations_used)
        *operations_used = used_operations;
}

void mv_manifest_verify_possession(const char *zcode_dir,
                                   struct mv_manifest_read *manifest,
                                   uint64_t byte_budget,
                                   uint32_t operation_budget,
                                   uint64_t *bytes_used,
                                   uint32_t *operations_used)
{
    mv_manifest_verify_possession_impl(
        zcode_dir, manifest, byte_budget, operation_budget,
#ifdef ZCL_TESTING
        NULL, NULL,
#endif
        bytes_used, operations_used);
}

#ifdef ZCL_TESTING
void mv_manifest_verify_possession_test(
    const char *zcode_dir, struct mv_manifest_read *manifest,
    uint64_t byte_budget, uint32_t operation_budget,
    mv_manifest_verify_test_hook hook, void *hook_context,
    uint64_t *bytes_used, uint32_t *operations_used)
{
    mv_manifest_verify_possession_impl(
        zcode_dir, manifest, byte_budget, operation_budget, hook,
        hook_context, bytes_used, operations_used);
}
#endif

bool mv_store_enumerable(const char *zcode_dir, char *reason, size_t cap)
{
    char path[MV_PATH_MAX];
    DIR *dir;
    int n;

    if (reason && cap)
        reason[0] = '\0';
    if (!zcode_dir) {
        if (reason && cap)
            snprintf(reason, cap, "no content store directory was given");
        return false;
    }
    n = snprintf(path, sizeof(path), "%s/manifests", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        if (reason && cap)
            snprintf(reason, cap,
                     "content store path is longer than %zu bytes",
                     sizeof(path));
        return false;
    }
    dir = opendir(path);
    if (dir) {
        closedir(dir);
        return true;
    }
    /* Nothing published yet. An empty catalog is the true answer. */
    if (errno == ENOENT)
        return true;
    if (reason && cap)
        snprintf(reason, cap,
                 "the local content store exists but could not be read "
                 "(%s: %s) — this is not an empty catalog",
                 path, strerror(errno));
    return false;
}

bool mv_zcode_store_ready(const struct metaverse_adapter_ctx *ctx,
                          char *reason, size_t reason_cap)
{
    if (!ctx) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "no adapter context");
        return false;
    }
    return mv_store_enumerable(ctx->zcode_dir, reason, reason_cap);
}

static int mv_name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

bool mv_manifest_names(const char *zcode_dir, char (*out)[65],
                       size_t out_cap, size_t *written_out,
                       size_t *total_out, bool *truncated_out)
{
    char path[MV_PATH_MAX];
    char (*names)[65];
    size_t seen = 0;
    size_t written;
    bool truncated = false;
    DIR *dir;
    struct dirent *ent;
    int n;

    if (written_out)
        *written_out = 0;
    if (total_out)
        *total_out = 0;
    if (truncated_out)
        *truncated_out = false;
    if (!zcode_dir || !written_out || !total_out || !truncated_out ||
        (!out && out_cap > 0))
        return false;

    n = snprintf(path, sizeof(path), "%s/manifests", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    dir = opendir(path);
    if (!dir)
        return errno == ENOENT; /* no store yet: honestly empty */

    names = zcl_malloc(MV_MANIFEST_SCAN_MAX * sizeof(*names), "mv_names");
    if (!names) {
        closedir(dir);
        LOG_FAIL(MV_LOG, "manifest name buffer for %s", path);
    }
    errno = 0;
    while ((ent = readdir(dir)) != NULL) {
        uint8_t scratch[32];

        if (!zcl_hex_decode_lower(ent->d_name, scratch, 32))
            continue;
        if (seen == MV_MANIFEST_SCAN_MAX) {
            truncated = true;
            break;
        }
        memcpy(names[seen], ent->d_name, 64);
        names[seen][64] = '\0';
        seen++;
    }
    if (errno != 0) {
        closedir(dir);
        free(names);
        return false;
    }
    closedir(dir);

    /* Ascending name order: readdir order is filesystem-dependent, and a
     * catalog page that reshuffles between identical calls is unusable. */
    qsort(names, seen, sizeof(*names), mv_name_cmp);

    written = seen < out_cap ? seen : out_cap;
    for (size_t i = 0; i < written; i++)
        memcpy(out[i], names[i], 65);
    free(names);

    *written_out = written;
    *total_out = seen;
    *truncated_out = truncated || written < seen;
    return true;
}

bool mv_release_read_verified(const char *zcode_dir,
                             const char *release_id_hex,
                             struct vcs_package_release *out)
{
    char path[MV_PATH_MAX];
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int n;

    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!zcode_dir || !release_id_hex)
        return false;
    n = snprintf(path, sizeof(path), "releases/%s",
                 release_id_hex);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    if (mv_read_file(zcode_dir, path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                     &wire_len) != MV_MANIFEST_READ_OK)
        return false;
    if (vcs_package_release_parse(wire, wire_len, out) !=
        VCS_PACKAGE_RELEASE_OK) {
        free(wire);
        memset(out, 0, sizeof(*out));
        return false;
    }
    free(wire);

    /* Verified NOW, in this call. package_index deliberately does not
     * verify signatures ("publication did"), so a view that inherited the
     * index's word for it could not honestly claim local_signature. */
    if (vcs_package_release_verify(out) != VCS_PACKAGE_RELEASE_OK) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}
