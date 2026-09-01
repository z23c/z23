/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared byte/chunk mechanics for content.v2 carriers. */

#include "vcs/package_content.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define CONTENT_LOG "vcs.package.content"

bool vcs_package_content_add_file(struct vcs_package_manifest *manifest,
                                  const char *path, uint32_t mode,
                                  const uint8_t *bytes, size_t bytes_len)
{
    if (!manifest || !path || (!bytes && bytes_len != 0) ||
        (uint64_t)bytes_len > VCS_PACKAGE_MAX_FILE_BYTES)
        LOG_FAIL(CONTENT_LOG, "invalid manifest file bytes");
    uint32_t chunks = bytes_len == 0 ? 0u :
        (uint32_t)(1u + (bytes_len - 1u) / VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *hashes = chunks == 0 ? NULL :
        zcl_malloc((size_t)chunks * 32u, "vcs.package.content_hashes");
    if (chunks != 0 && !hashes)
        return false;
    bool ok = true;
    for (uint32_t i = 0; ok && i < chunks; i++) {
        size_t offset = (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t take = bytes_len - offset;
        if (take > VCS_PACKAGE_CHUNK_BYTES)
            take = VCS_PACKAGE_CHUNK_BYTES;
        ok = vcs_package_chunk_hash(bytes + offset, take,
                                    hashes + (size_t)i * 32u);
    }
    ok = ok && vcs_package_manifest_add(manifest, path, mode, bytes_len,
                                        hashes, chunks);
    free(hashes);
    return ok;
}

enum vcs_package_store_result vcs_package_content_put_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, const uint8_t *bytes, size_t bytes_len)
{
    if (!store || !package_root || !path || (!bytes && bytes_len != 0))
        return VCS_PACKAGE_STORE_ERR_NULL;
    if ((uint64_t)bytes_len > VCS_PACKAGE_MAX_FILE_BYTES)
        return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
    uint32_t chunks = bytes_len == 0 ? 0u :
        (uint32_t)(1u + (bytes_len - 1u) / VCS_PACKAGE_CHUNK_BYTES);
    for (uint32_t i = 0; i < chunks; i++) {
        size_t offset = (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t take = bytes_len - offset;
        if (take > VCS_PACKAGE_CHUNK_BYTES)
            take = VCS_PACKAGE_CHUNK_BYTES;
        enum vcs_package_store_result stored = vcs_package_store_put_chunk(
            store, package_root, path, i, bytes + offset, take);
        if (stored != VCS_PACKAGE_STORE_OK)
            return stored;
    }
    return VCS_PACKAGE_STORE_OK;
}

enum vcs_package_store_result vcs_package_content_get_file_at(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_manifest *manifest, uint32_t file_index,
    uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!store || !package_root || !manifest || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, CONTENT_LOG,
                   "null content file read input");
    uint8_t derived[32];
    if (file_index >= manifest->count ||
        !vcs_package_manifest_root(manifest, derived) ||
        memcmp(derived, package_root, 32) != 0 ||
        manifest->files[file_index].size > SIZE_MAX)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_MANIFEST, CONTENT_LOG,
                   "content file manifest/root mismatch");
    const struct vcs_package_file *file = &manifest->files[file_index];
    size_t len = (size_t)file->size;
    uint8_t *bytes = zcl_malloc(len == 0 ? 1u : len,
                                "vcs.package.content_file");
    if (!bytes)
        return VCS_PACKAGE_STORE_ERR_ALLOC;
    size_t offset = 0;
    for (uint32_t i = 0; i < file->chunk_count; i++) {
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        enum vcs_package_store_result got = vcs_package_store_get_chunk_at(
            store, package_root, file_index, i, &chunk, &chunk_len);
        if (got != VCS_PACKAGE_STORE_OK ||
            !vcs_package_verify_chunk(file, i, chunk, chunk_len) ||
            chunk_len > len - offset) {
            free(chunk);
            free(bytes);
            LOG_RETURN(got == VCS_PACKAGE_STORE_OK
                           ? VCS_PACKAGE_STORE_ERR_CHUNK_HASH : got,
                       CONTENT_LOG, "content file chunk %u refused", i);
        }
        memcpy(bytes + offset, chunk, chunk_len);
        offset += chunk_len;
        free(chunk);
    }
    if (offset != len) {
        free(bytes);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_CHUNK_MISSING, CONTENT_LOG,
                   "content file length mismatch %zu/%zu", offset, len);
    }
    *out = bytes;
    *out_len = len;
    return VCS_PACKAGE_STORE_OK;
}
