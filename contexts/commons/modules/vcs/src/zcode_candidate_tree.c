/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Carry a complete ZVCS candidate tree as content.v2 files. */

#include "vcs/zcode_candidate_tree.h"

#include "vcs_priv.h"

#include "util/safe_alloc.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_task_authority.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct candidate_tree_blob {
    const struct vcs_entry *entry;
    uint8_t *bytes;
    size_t len;
};

const char *vcs_zcode_candidate_tree_result_string(
    enum vcs_zcode_candidate_tree_result result)
{
    switch (result) {
    case VCS_ZCODE_CANDIDATE_TREE_OK: return "ok";
    case VCS_ZCODE_CANDIDATE_TREE_NULL: return "null-argument";
    case VCS_ZCODE_CANDIDATE_TREE_AUTHORITY:
        return "candidate-tree-authority";
    case VCS_ZCODE_CANDIDATE_TREE_SHAPE: return "candidate-tree-shape";
    case VCS_ZCODE_CANDIDATE_TREE_LIMIT: return "candidate-tree-limit";
    case VCS_ZCODE_CANDIDATE_TREE_CAS: return "candidate-tree-cas";
    case VCS_ZCODE_CANDIDATE_TREE_STORE: return "candidate-tree-store";
    case VCS_ZCODE_CANDIDATE_TREE_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

static uint32_t candidate_tree_mode(uint32_t mode)
{
    return (mode & 0111u) != 0 ? VCS_PACKAGE_MODE_EXECUTABLE
                               : VCS_PACKAGE_MODE_FILE;
}

static bool candidate_tree_path(const char *path, char out[1035])
{
    size_t prefix = sizeof(VCS_ZCODE_CANDIDATE_TREE_PREFIX) - 1u;
    size_t len = path ? strlen(path) : 0;
    if (len == 0 || prefix + len > VCS_PACKAGE_PATH_MAX)
        return false;
    memcpy(out, VCS_ZCODE_CANDIDATE_TREE_PREFIX, prefix);
    memcpy(out + prefix, path, len + 1u);
    return vcs_package_path_valid(out);
}

static enum vcs_zcode_candidate_tree_result candidate_tree_load_blob(
    const char *repo_root, const struct vcs_entry *entry,
    uint8_t **bytes, size_t *len)
{
    *bytes = NULL; *len = 0;
    if (!S_ISREG(entry->mode) || entry->size > SIZE_MAX)
        return VCS_ZCODE_CANDIDATE_TREE_SHAPE;
    if (vcs_object_get(repo_root, entry->blob, VCS_TAG_BLOB,
                       bytes, len) != 0 || *len != (size_t)entry->size) {
        free(*bytes); *bytes = NULL; *len = 0;
        return VCS_ZCODE_CANDIDATE_TREE_CAS;
    }
    return VCS_ZCODE_CANDIDATE_TREE_OK;
}

static enum vcs_zcode_candidate_tree_result candidate_tree_add_entry(
    const char *repo_root, const struct vcs_entry *entry,
    struct vcs_package_manifest *manifest)
{
    char path[1035];
    if (!candidate_tree_path(entry->path, path))
        return VCS_ZCODE_CANDIDATE_TREE_SHAPE;
    uint8_t *bytes = NULL; size_t len = 0;
    enum vcs_zcode_candidate_tree_result result = candidate_tree_load_blob(
        repo_root, entry, &bytes, &len);
    if (result != VCS_ZCODE_CANDIDATE_TREE_OK) return result;
    if (result == VCS_ZCODE_CANDIDATE_TREE_OK &&
        !vcs_package_content_add_file(
            manifest, path, candidate_tree_mode(entry->mode), bytes, len))
        result = VCS_ZCODE_CANDIDATE_TREE_SHAPE;
    free(bytes);
    return result;
}

enum vcs_zcode_candidate_tree_result vcs_zcode_candidate_tree_add_manifest(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, uint64_t max_bytes,
    struct vcs_package_manifest *manifest, uint64_t *tree_bytes)
{
    if (!repo_root || !task || !candidate || !manifest || !tree_bytes)
        return VCS_ZCODE_CANDIDATE_TREE_NULL;
    *tree_bytes = 0;
    if (vcs_zcode_task_authority_validate_for_candidate(
            repo_root, task, candidate) != VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_CANDIDATE_TREE_AUTHORITY;
    struct vcs_manifest tree;
    if (!vcs_tree_load(repo_root, candidate->candidate_source_root, &tree))
        return VCS_ZCODE_CANDIDATE_TREE_CAS;
    enum vcs_zcode_candidate_tree_result result =
        tree.count > VCS_PACKAGE_MAX_FILES - manifest->count
            ? VCS_ZCODE_CANDIDATE_TREE_LIMIT
            : VCS_ZCODE_CANDIDATE_TREE_OK;
    uint64_t total = 0;
    for (size_t i = 0; result == VCS_ZCODE_CANDIDATE_TREE_OK &&
                         i < tree.count; i++) {
        if (UINT64_MAX - total < tree.entries[i].size ||
            total + tree.entries[i].size > max_bytes) {
            result = VCS_ZCODE_CANDIDATE_TREE_LIMIT;
            break;
        }
        result = candidate_tree_add_entry(repo_root, &tree.entries[i],
                                          manifest);
        total += tree.entries[i].size;
    }
    vcs_manifest_free(&tree);
    if (result == VCS_ZCODE_CANDIDATE_TREE_OK) *tree_bytes = total;
    return result;
}

static enum vcs_zcode_candidate_tree_result candidate_tree_put_blob(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *repo_root, const struct vcs_entry *entry)
{
    char path[1035]; uint8_t *bytes = NULL; size_t len = 0;
    if (!candidate_tree_path(entry->path, path))
        return VCS_ZCODE_CANDIDATE_TREE_SHAPE;
    enum vcs_zcode_candidate_tree_result result = candidate_tree_load_blob(
        repo_root, entry, &bytes, &len);
    if (result == VCS_ZCODE_CANDIDATE_TREE_OK &&
        vcs_package_content_put_file(
            store, package_root, path, bytes, len) != VCS_PACKAGE_STORE_OK)
        result = VCS_ZCODE_CANDIDATE_TREE_STORE;
    free(bytes);
    return result;
}

enum vcs_zcode_candidate_tree_result vcs_zcode_candidate_tree_put_chunks(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *repo_root, const struct vcs_zcode_candidate_v1 *candidate)
{
    if (!store || !package_root || !repo_root || !candidate)
        return VCS_ZCODE_CANDIDATE_TREE_NULL;
    struct vcs_manifest tree;
    if (!vcs_tree_load(repo_root, candidate->candidate_source_root, &tree))
        return VCS_ZCODE_CANDIDATE_TREE_CAS;
    enum vcs_zcode_candidate_tree_result result =
        VCS_ZCODE_CANDIDATE_TREE_OK;
    for (size_t i = 0; result == VCS_ZCODE_CANDIDATE_TREE_OK &&
                         i < tree.count; i++)
        result = candidate_tree_put_blob(store, package_root, repo_root,
                                         &tree.entries[i]);
    vcs_manifest_free(&tree);
    return result;
}

static int candidate_tree_package_index(
    const struct vcs_package_manifest *manifest, const char *path)
{
    size_t lo = 0, hi = manifest->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(manifest->files[mid].path, path);
        if (cmp == 0) return (int)mid;
        if (cmp < 0) lo = mid + 1u; else hi = mid;
    }
    return -1;
}

static enum vcs_zcode_candidate_tree_result candidate_tree_read_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_file *file, size_t file_index,
    uint8_t **bytes_out, size_t *len_out)
{
    if (file->size > SIZE_MAX) return VCS_ZCODE_CANDIDATE_TREE_LIMIT;
    size_t len = (size_t)file->size;
    uint8_t *bytes = len > 0
        ? zcl_malloc(len, "zcode.candidate_tree.import") : NULL;
    if (len > 0 && !bytes) return VCS_ZCODE_CANDIDATE_TREE_ALLOC;
    size_t written = 0;
    for (uint32_t i = 0; i < file->chunk_count; i++) {
        uint8_t *chunk = NULL; size_t chunk_len = 0;
        enum vcs_package_store_result got = vcs_package_store_get_chunk_at(
            store, package_root, (uint32_t)file_index, i,
            &chunk, &chunk_len);
        if (got != VCS_PACKAGE_STORE_OK ||
            !vcs_package_verify_chunk(file, i, chunk, chunk_len) ||
            chunk_len > len - written) {
            free(chunk); free(bytes);
            return VCS_ZCODE_CANDIDATE_TREE_STORE;
        }
        memcpy(bytes + written, chunk, chunk_len);
        written += chunk_len; free(chunk);
    }
    if (written != len) {
        free(bytes); return VCS_ZCODE_CANDIDATE_TREE_STORE;
    }
    *bytes_out = bytes; *len_out = len;
    return VCS_ZCODE_CANDIDATE_TREE_OK;
}

static void candidate_tree_blobs_free(struct candidate_tree_blob *blobs,
                                      size_t count)
{
    if (!blobs) return;
    for (size_t i = 0; i < count; i++) free(blobs[i].bytes);
    free(blobs);
}

static size_t candidate_tree_prefixed_count(
    const struct vcs_package_manifest *manifest)
{
    size_t count = 0;
    const size_t n = sizeof(VCS_ZCODE_CANDIDATE_TREE_PREFIX) - 1u;
    for (size_t i = 0; i < manifest->count; i++)
        if (strncmp(manifest->files[i].path,
                    VCS_ZCODE_CANDIDATE_TREE_PREFIX, n) == 0)
            count++;
    return count;
}

enum vcs_zcode_candidate_tree_result vcs_zcode_candidate_tree_import(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    if (!store || !package_root || !repo_root || !task || !candidate)
        return VCS_ZCODE_CANDIDATE_TREE_NULL;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_ZCODE_CANDIDATE_TREE_LIMIT;
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(
            store, package_root, &wire, &wire_len) != VCS_PACKAGE_STORE_OK)
        return VCS_ZCODE_CANDIDATE_TREE_STORE;
    struct vcs_package_manifest package;
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &package);
    free(wire);
    uint8_t root[32];
    if (!parsed || !vcs_package_manifest_root(&package, root) ||
        memcmp(root, package_root, 32) != 0) {
        if (parsed) vcs_package_manifest_free(&package);
        return VCS_ZCODE_CANDIDATE_TREE_AUTHORITY;
    }
    struct vcs_manifest tree;
    if (!vcs_tree_load(repo_root, candidate->candidate_source_root, &tree)) {
        vcs_package_manifest_free(&package);
        return VCS_ZCODE_CANDIDATE_TREE_CAS;
    }
    enum vcs_zcode_candidate_tree_result result =
        candidate_tree_prefixed_count(&package) == tree.count
            ? VCS_ZCODE_CANDIDATE_TREE_OK
            : VCS_ZCODE_CANDIDATE_TREE_AUTHORITY;
    uint64_t tree_bytes = 0;
    for (size_t i = 0; result == VCS_ZCODE_CANDIDATE_TREE_OK &&
                         i < tree.count; i++) {
        if (UINT64_MAX - tree_bytes < tree.entries[i].size ||
            tree_bytes + tree.entries[i].size > task->max_context_bytes)
            result = VCS_ZCODE_CANDIDATE_TREE_LIMIT;
        else
            tree_bytes += tree.entries[i].size;
    }
    struct candidate_tree_blob *blobs = result == VCS_ZCODE_CANDIDATE_TREE_OK
        ? zcl_calloc(tree.count, sizeof(*blobs),
                     "zcode.candidate_tree.blobs") : NULL;
    if (result == VCS_ZCODE_CANDIDATE_TREE_OK && tree.count > 0 && !blobs)
        result = VCS_ZCODE_CANDIDATE_TREE_ALLOC;
    for (size_t i = 0; result == VCS_ZCODE_CANDIDATE_TREE_OK &&
                         i < tree.count; i++) {
        char path[1035];
        if (!candidate_tree_path(tree.entries[i].path, path)) {
            result = VCS_ZCODE_CANDIDATE_TREE_SHAPE; break;
        }
        int index = candidate_tree_package_index(&package, path);
        if (index < 0) {
            result = VCS_ZCODE_CANDIDATE_TREE_AUTHORITY; break;
        }
        const struct vcs_package_file *file = &package.files[index];
        if (file->mode != candidate_tree_mode(tree.entries[i].mode) ||
            file->size != tree.entries[i].size) {
            result = VCS_ZCODE_CANDIDATE_TREE_AUTHORITY; break;
        }
        result = candidate_tree_read_file(
            store, package_root, file, (size_t)index,
            &blobs[i].bytes, &blobs[i].len);
        blobs[i].entry = &tree.entries[i];
        uint8_t hash[32];
        if (result == VCS_ZCODE_CANDIDATE_TREE_OK) {
            vcs_sha3_tag(VCS_TAG_BLOB, blobs[i].bytes, blobs[i].len, hash);
            if (memcmp(hash, tree.entries[i].blob, 32) != 0)
                result = VCS_ZCODE_CANDIDATE_TREE_AUTHORITY;
        }
    }
    if (result == VCS_ZCODE_CANDIDATE_TREE_OK &&
        !vcs_object_store_init(repo_root))
        result = VCS_ZCODE_CANDIDATE_TREE_CAS;
    for (size_t i = 0; result == VCS_ZCODE_CANDIDATE_TREE_OK &&
                         i < tree.count; i++) {
        uint8_t hash[32];
        if (!vcs_object_put(repo_root, blobs[i].bytes, blobs[i].len,
                            VCS_TAG_BLOB, hash) ||
            memcmp(hash, blobs[i].entry->blob, 32) != 0)
            result = VCS_ZCODE_CANDIDATE_TREE_CAS;
    }
    candidate_tree_blobs_free(blobs, tree.count);
    vcs_manifest_free(&tree); vcs_package_manifest_free(&package);
    return result;
}
