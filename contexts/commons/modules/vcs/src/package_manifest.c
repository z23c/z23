/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_manifest — implementation. See vcs/package_manifest.h. */

#include "vcs/package_manifest.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include "vcs_priv.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t package_magic[8] = {
    'Z', 'C', 'L', 'P', 'K', 'G', '\r', '\n'
};
static const uint8_t file_hash_domain[] = VCS_PACKAGE_FILE_HASH_DOMAIN;
static const uint8_t root_hash_domain[] = VCS_PACKAGE_ROOT_HASH_DOMAIN;

static bool package_mode_valid(uint32_t mode)
{
    return mode == VCS_PACKAGE_MODE_FILE ||
           mode == VCS_PACKAGE_MODE_EXECUTABLE;
}

static bool package_path_byte_valid(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' ||
           c == '-' || c == '+' || c == '@';
}

static bool package_path_valid_n(const uint8_t *path, size_t len)
{
    if (!path || len == 0 || len > VCS_PACKAGE_PATH_MAX)
        return false;

    size_t segment_start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && path[i] != '/') {
            if (!package_path_byte_valid(path[i]))
                return false;
            continue;
        }

        size_t segment_len = i - segment_start;
        if (segment_len == 0 || segment_len > VCS_PACKAGE_PATH_SEGMENT_MAX)
            return false;
        if (segment_len == 1 && path[segment_start] == '.')
            return false;
        if (segment_len == 2 && path[segment_start] == '.' &&
            path[segment_start + 1] == '.')
            return false;
        segment_start = i + 1;
    }
    return true;
}

bool vcs_package_path_valid(const char *path)
{
    if (!path)
        return false;
    size_t len = 0;
    while (len <= VCS_PACKAGE_PATH_MAX && path[len] != '\0')
        len++;
    if (len > VCS_PACKAGE_PATH_MAX)
        return false;
    return package_path_valid_n((const uint8_t *)path, len);
}

static bool package_expected_chunks(uint64_t size, uint32_t *out)
{
    if (!out || size > VCS_PACKAGE_MAX_FILE_BYTES)
        return false;
    uint64_t count = size == 0 ? 0 :
        UINT64_C(1) + (size - UINT64_C(1)) / VCS_PACKAGE_CHUNK_BYTES;
    if (count > VCS_PACKAGE_MAX_CHUNKS_PER_FILE || count > UINT32_MAX)
        return false;
    *out = (uint32_t)count;
    return true;
}

static bool package_file_valid(const struct vcs_package_file *file)
{
    uint32_t expected = 0;
    if (!file || !file->path || !vcs_package_path_valid(file->path) ||
        !package_mode_valid(file->mode) ||
        !package_expected_chunks(file->size, &expected) ||
        file->chunk_count != expected)
        return false;
    return file->chunk_count == 0 || file->chunk_hashes != NULL;
}

void vcs_package_manifest_init(struct vcs_package_manifest *manifest)
{
    if (!manifest)
        return;
    manifest->files = NULL;
    manifest->count = 0;
    manifest->cap = 0;
}

void vcs_package_manifest_free(struct vcs_package_manifest *manifest)
{
    if (!manifest)
        return;
    for (size_t i = 0; i < manifest->count; i++) {
        free(manifest->files[i].path);
        free(manifest->files[i].chunk_hashes);
    }
    free(manifest->files);
    vcs_package_manifest_init(manifest);
}

static bool package_manifest_totals(const struct vcs_package_manifest *manifest,
                                    uint64_t *total_bytes,
                                    uint64_t *total_chunks)
{
    if (!manifest || !total_bytes || !total_chunks ||
        manifest->count > VCS_PACKAGE_MAX_FILES ||
        manifest->cap > VCS_PACKAGE_MAX_FILES || manifest->count > manifest->cap ||
        (manifest->count > 0 && !manifest->files))
        return false;

    uint64_t bytes = 0;
    uint64_t chunks = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_package_file *file = &manifest->files[i];
        if (!package_file_valid(file) ||
            file->size > VCS_PACKAGE_MAX_TOTAL_BYTES - bytes ||
            file->chunk_count > VCS_PACKAGE_MAX_TOTAL_CHUNKS - chunks)
            return false;
        bytes += file->size;
        chunks += file->chunk_count;
    }
    *total_bytes = bytes;
    *total_chunks = chunks;
    return true;
}

bool vcs_package_manifest_add(struct vcs_package_manifest *manifest,
                              const char *path, uint32_t mode, uint64_t size,
                              const uint8_t *chunk_hashes,
                              uint32_t chunk_count)
{
    uint32_t expected = 0;
    if (!manifest || !path)
        LOG_FAIL("vcs.package", "null package manifest/path");
    if (!vcs_package_path_valid(path))
        LOG_FAIL("vcs.package", "non-canonical package path");
    if (!package_mode_valid(mode))
        LOG_FAIL("vcs.package", "invalid package mode 0%o", mode);
    if (!package_expected_chunks(size, &expected) || expected != chunk_count)
        LOG_FAIL("vcs.package", "size/chunk count mismatch for %s", path);
    if (chunk_count > 0 && !chunk_hashes)
        LOG_FAIL("vcs.package", "missing chunk hashes for %s", path);
    if (manifest->count >= VCS_PACKAGE_MAX_FILES)
        LOG_FAIL("vcs.package", "package file limit exceeded");

    uint64_t total_bytes = 0;
    uint64_t total_chunks = 0;
    if (!package_manifest_totals(manifest, &total_bytes, &total_chunks) ||
        size > VCS_PACKAGE_MAX_TOTAL_BYTES - total_bytes ||
        chunk_count > VCS_PACKAGE_MAX_TOTAL_CHUNKS - total_chunks)
        LOG_FAIL("vcs.package", "package aggregate limit exceeded");

    size_t insert_at = 0;
    while (insert_at < manifest->count &&
           strcmp(manifest->files[insert_at].path, path) < 0)
        insert_at++;
    if (insert_at < manifest->count &&
        strcmp(manifest->files[insert_at].path, path) == 0)
        LOG_FAIL("vcs.package", "duplicate package path %s", path);

    if (manifest->count == manifest->cap) {
        size_t new_cap = manifest->cap ? manifest->cap * 2 : 16;
        if (new_cap > VCS_PACKAGE_MAX_FILES)
            new_cap = VCS_PACKAGE_MAX_FILES;
        if (new_cap < manifest->count ||
            new_cap > SIZE_MAX / sizeof(*manifest->files))
            LOG_FAIL("vcs.package", "package file capacity overflow");
        struct vcs_package_file *files = zcl_realloc(
            manifest->files, new_cap * sizeof(*files), "vcs_package_files");
        if (!files)
            LOG_FAIL("vcs.package", "alloc package files");
        manifest->files = files;
        manifest->cap = new_cap;
    }

    char *path_copy = zcl_strdup(path, "vcs_package_path");
    if (!path_copy)
        LOG_FAIL("vcs.package", "copy package path");
    uint8_t *hash_copy = NULL;
    if (chunk_count > 0) {
        size_t hash_bytes = (size_t)chunk_count * 32u;
        hash_copy = zcl_malloc(hash_bytes, "vcs_package_chunk_hashes");
        if (!hash_copy) {
            free(path_copy);
            LOG_FAIL("vcs.package", "copy package chunk hashes");
        }
        memcpy(hash_copy, chunk_hashes, hash_bytes);
    }

    if (insert_at < manifest->count) {
        memmove(&manifest->files[insert_at + 1],
                &manifest->files[insert_at],
                (manifest->count - insert_at) * sizeof(*manifest->files));
    }
    struct vcs_package_file *file = &manifest->files[insert_at];
    file->path = path_copy;
    file->mode = mode;
    file->size = size;
    file->chunk_count = chunk_count;
    file->chunk_hashes = hash_copy;
    manifest->count++;
    return true;
}

static int package_file_cmp(const void *a, const void *b)
{
    const struct vcs_package_file *fa = a;
    const struct vcs_package_file *fb = b;
    return strcmp(fa->path, fb->path);
}

static bool package_sorted_copy(const struct vcs_package_manifest *manifest,
                                struct vcs_package_file **out)
{
    *out = NULL;
    uint64_t total_bytes = 0;
    uint64_t total_chunks = 0;
    if (!package_manifest_totals(manifest, &total_bytes, &total_chunks))
        LOG_FAIL("vcs.package", "invalid package manifest");
    (void)total_bytes;
    (void)total_chunks;
    if (manifest->count == 0)
        return true;

    if (manifest->count > SIZE_MAX / sizeof(**out))
        LOG_FAIL("vcs.package", "package sort capacity overflow");
    struct vcs_package_file *copy = zcl_malloc(
        manifest->count * sizeof(*copy), "vcs_package_sorted_copy");
    if (!copy)
        LOG_FAIL("vcs.package", "alloc package sort copy");
    memcpy(copy, manifest->files, manifest->count * sizeof(*copy));
    qsort(copy, manifest->count, sizeof(*copy), package_file_cmp);
    for (size_t i = 1; i < manifest->count; i++) {
        if (strcmp(copy[i - 1].path, copy[i].path) == 0) {
            free(copy);
            LOG_FAIL("vcs.package", "duplicate path in package manifest");
        }
    }
    *out = copy;
    return true;
}

bool vcs_package_manifest_serialize(const struct vcs_package_manifest *manifest,
                                    uint8_t **out, size_t *out_len)
{
    if (!out || !out_len)
        LOG_FAIL("vcs.package", "null package serialization output");
    *out = NULL;
    *out_len = 0;
    if (!manifest)
        LOG_FAIL("vcs.package", "null package manifest");

    struct vcs_package_file *files = NULL;
    if (!package_sorted_copy(manifest, &files))
        return false;

    size_t total = VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES;
    for (size_t i = 0; i < manifest->count; i++) {
        size_t path_len = strlen(files[i].path);
        size_t hash_bytes = (size_t)files[i].chunk_count * 32u;
        size_t fixed = 2u + path_len + 4u + 8u + 4u;
        if (fixed > SIZE_MAX - hash_bytes || total > SIZE_MAX - fixed - hash_bytes) {
            free(files);
            LOG_FAIL("vcs.package", "package wire length overflow");
        }
        total += fixed + hash_bytes;
    }
    if (total > VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES) {
        free(files);
        LOG_FAIL("vcs.package", "package wire limit exceeded: %zu", total);
    }

    uint8_t *wire = zcl_malloc(total, "vcs_package_wire");
    if (!wire) {
        free(files);
        LOG_FAIL("vcs.package", "alloc package wire");
    }
    size_t off = 0;
    memcpy(wire + off, package_magic, sizeof(package_magic));
    off += sizeof(package_magic);
    vcs_wr_u16le(wire + off, VCS_PACKAGE_MANIFEST_VERSION);
    off += 2;
    vcs_wr_u32le(wire + off, VCS_PACKAGE_CHUNK_BYTES);
    off += 4;
    vcs_wr_u32le(wire + off, (uint32_t)manifest->count);
    off += 4;

    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_package_file *file = &files[i];
        size_t path_len = strlen(file->path);
        size_t hash_bytes = (size_t)file->chunk_count * 32u;
        vcs_wr_u16le(wire + off, (uint16_t)path_len);
        off += 2;
        memcpy(wire + off, file->path, path_len);
        off += path_len;
        vcs_wr_u32le(wire + off, file->mode);
        off += 4;
        vcs_wr_u64le(wire + off, file->size);
        off += 8;
        vcs_wr_u32le(wire + off, file->chunk_count);
        off += 4;
        if (hash_bytes > 0) {
            memcpy(wire + off, file->chunk_hashes, hash_bytes);
            off += hash_bytes;
        }
    }
    free(files);
    *out = wire;
    *out_len = off;
    return true;
}

static bool package_wire_has(size_t wire_len, size_t off, size_t need)
{
    return off <= wire_len && need <= wire_len - off;
}

bool vcs_package_manifest_parse(const uint8_t *wire, size_t wire_len,
                                struct vcs_package_manifest *out)
{
    if (!out)
        LOG_FAIL("vcs.package", "null package parse output");
    vcs_package_manifest_init(out);
    if (!wire || wire_len < VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES ||
        wire_len > VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES)
        LOG_FAIL("vcs.package", "invalid package wire length %zu", wire_len);

    size_t off = 0;
    const char *reject = NULL;
    if (memcmp(wire, package_magic, sizeof(package_magic)) != 0) {
        reject = "magic";
        goto rejected;
    }
    off += sizeof(package_magic);
    if (vcs_rd_u16le(wire + off) != VCS_PACKAGE_MANIFEST_VERSION) {
        reject = "version";
        goto rejected;
    }
    off += 2;
    if (vcs_rd_u32le(wire + off) != VCS_PACKAGE_CHUNK_BYTES) {
        reject = "chunk-size";
        goto rejected;
    }
    off += 4;
    uint32_t file_count = vcs_rd_u32le(wire + off);
    off += 4;
    if (file_count > VCS_PACKAGE_MAX_FILES) {
        reject = "file-count";
        goto rejected;
    }

    for (uint32_t i = 0; i < file_count; i++) {
        if (!package_wire_has(wire_len, off, 2)) {
            reject = "path-length-truncated";
            goto rejected;
        }
        uint16_t path_len = vcs_rd_u16le(wire + off);
        off += 2;
        if (!package_wire_has(wire_len, off, path_len) ||
            !package_path_valid_n(wire + off, path_len)) {
            reject = "path";
            goto rejected;
        }
        char path[VCS_PACKAGE_PATH_MAX + 1];
        memcpy(path, wire + off, path_len);
        path[path_len] = '\0';
        off += path_len;
        if (i > 0 && strcmp(out->files[i - 1].path, path) >= 0) {
            reject = "path-order-or-duplicate";
            goto rejected;
        }
        if (!package_wire_has(wire_len, off, 4u + 8u + 4u)) {
            reject = "file-metadata-truncated";
            goto rejected;
        }
        uint32_t mode = vcs_rd_u32le(wire + off);
        off += 4;
        uint64_t size = vcs_rd_u64le(wire + off);
        off += 8;
        uint32_t chunk_count = vcs_rd_u32le(wire + off);
        off += 4;

        uint32_t expected = 0;
        if (!package_mode_valid(mode) ||
            !package_expected_chunks(size, &expected) ||
            expected != chunk_count) {
            reject = "file-metadata";
            goto rejected;
        }
        size_t hash_bytes = (size_t)chunk_count * 32u;
        if (!package_wire_has(wire_len, off, hash_bytes)) {
            reject = "chunk-hashes-truncated";
            goto rejected;
        }
        if (!vcs_package_manifest_add(out, path, mode, size, wire + off,
                                      chunk_count)) {
            reject = "manifest-limits";
            goto rejected;
        }
        off += hash_bytes;
    }
    if (off != wire_len) {
        reject = "trailing-data";
        goto rejected;
    }
    return true;

rejected:
    vcs_package_manifest_free(out);
    LOG_FAIL("vcs.package", "package parse rejected %s at %zu/%zu",
             reject ? reject : "unknown", off, wire_len);
}

bool vcs_package_file_hash(const struct vcs_package_file *file,
                           uint8_t out[32])
{
    if (!out || !package_file_valid(file))
        LOG_FAIL("vcs.package", "invalid package file hash input");

    size_t path_len = strlen(file->path);
    uint8_t path_len_le[2];
    uint8_t mode_le[4];
    uint8_t size_le[8];
    uint8_t count_le[4];
    vcs_wr_u16le(path_len_le, (uint16_t)path_len);
    vcs_wr_u32le(mode_le, file->mode);
    vcs_wr_u64le(size_le, file->size);
    vcs_wr_u32le(count_le, file->chunk_count);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, file_hash_domain, sizeof(file_hash_domain));
    sha3_256_write(&ctx, path_len_le, sizeof(path_len_le));
    sha3_256_write(&ctx, (const uint8_t *)file->path, path_len);
    sha3_256_write(&ctx, mode_le, sizeof(mode_le));
    sha3_256_write(&ctx, size_le, sizeof(size_le));
    sha3_256_write(&ctx, count_le, sizeof(count_le));
    if (file->chunk_count > 0)
        sha3_256_write(&ctx, file->chunk_hashes,
                       (size_t)file->chunk_count * 32u);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool vcs_package_manifest_root(const struct vcs_package_manifest *manifest,
                               uint8_t out[32])
{
    if (!manifest || !out)
        LOG_FAIL("vcs.package", "null package root input");
    struct vcs_package_file *files = NULL;
    if (!package_sorted_copy(manifest, &files))
        return false;

    uint8_t version_le[2];
    uint8_t chunk_size_le[4];
    uint8_t count_le[4];
    vcs_wr_u16le(version_le, VCS_PACKAGE_MANIFEST_VERSION);
    vcs_wr_u32le(chunk_size_le, VCS_PACKAGE_CHUNK_BYTES);
    vcs_wr_u32le(count_le, (uint32_t)manifest->count);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, root_hash_domain, sizeof(root_hash_domain));
    sha3_256_write(&ctx, version_le, sizeof(version_le));
    sha3_256_write(&ctx, chunk_size_le, sizeof(chunk_size_le));
    sha3_256_write(&ctx, count_le, sizeof(count_le));
    bool ok = true;
    for (size_t i = 0; i < manifest->count; i++) {
        uint8_t file_hash[32];
        if (!vcs_package_file_hash(&files[i], file_hash)) {
            ok = false;
            break;
        }
        sha3_256_write(&ctx, file_hash, sizeof(file_hash));
    }
    if (ok)
        sha3_256_finalize(&ctx, out);
    free(files);
    if (!ok)
        LOG_FAIL("vcs.package", "package file hash failed");
    return true;
}

bool vcs_package_chunk_hash(const uint8_t *chunk, size_t chunk_len,
                            uint8_t out[32])
{
    if (!chunk || !out || chunk_len == 0 ||
        chunk_len > VCS_PACKAGE_CHUNK_BYTES)
        LOG_FAIL("vcs.package", "invalid package chunk length %zu", chunk_len);
    sha3_256(chunk, chunk_len, out);
    return true;
}

static bool package_hash_equal(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

bool vcs_package_verify_chunk(const struct vcs_package_file *file,
                              uint32_t chunk_index, const uint8_t *chunk,
                              size_t chunk_len)
{
    if (!package_file_valid(file) || chunk_index >= file->chunk_count || !chunk)
        LOG_FAIL("vcs.package", "invalid package chunk verification input");
    uint64_t chunk_offset = (uint64_t)chunk_index * VCS_PACKAGE_CHUNK_BYTES;
    uint64_t remaining = file->size - chunk_offset;
    size_t expected = remaining > VCS_PACKAGE_CHUNK_BYTES ?
        VCS_PACKAGE_CHUNK_BYTES : (size_t)remaining;
    if (chunk_len != expected)
        LOG_FAIL("vcs.package", "package chunk length mismatch");
    uint8_t actual[32];
    if (!vcs_package_chunk_hash(chunk, chunk_len, actual))
        return false;
    if (!package_hash_equal(actual, file->chunk_hashes +
                            (size_t)chunk_index * 32u))
        LOG_FAIL("vcs.package", "package chunk hash mismatch");
    return true;
}

bool vcs_package_verify_file(const struct vcs_package_file *file,
                             const uint8_t *bytes, size_t bytes_len)
{
    if (!package_file_valid(file) || file->size > SIZE_MAX ||
        bytes_len != (size_t)file->size || (bytes_len > 0 && !bytes))
        LOG_FAIL("vcs.package", "invalid package file verification input");
    for (uint32_t i = 0; i < file->chunk_count; i++) {
        size_t off = (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t remaining = bytes_len - off;
        size_t chunk_len = remaining > VCS_PACKAGE_CHUNK_BYTES ?
            VCS_PACKAGE_CHUNK_BYTES : remaining;
        if (!vcs_package_verify_chunk(file, i, bytes + off, chunk_len))
            return false;
    }
    return true;
}
