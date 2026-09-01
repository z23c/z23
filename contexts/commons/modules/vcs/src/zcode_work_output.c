/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Action-bound fixed-work output over the existing content.v2 swarm. */

#include "vcs/zcode_work_output.h"

#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

#include <stdlib.h>
#include <string.h>

const char *vcs_zcode_work_output_result_string(
    enum vcs_zcode_work_output_result result)
{
    switch (result) {
    case VCS_ZCODE_WORK_OUTPUT_OK: return "ok";
    case VCS_ZCODE_WORK_OUTPUT_NULL: return "null-argument";
    case VCS_ZCODE_WORK_OUTPUT_EMPTY: return "empty-output";
    case VCS_ZCODE_WORK_OUTPUT_LIMIT: return "output-too-large";
    case VCS_ZCODE_WORK_OUTPUT_STORE: return "store-refused";
    case VCS_ZCODE_WORK_OUTPUT_ABSENT: return "output-absent";
    case VCS_ZCODE_WORK_OUTPUT_SHAPE: return "output-shape-invalid";
    case VCS_ZCODE_WORK_OUTPUT_CORRUPT: return "output-corrupt";
    case VCS_ZCODE_WORK_OUTPUT_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

enum vcs_zcode_work_output_result vcs_zcode_work_output_put(
    struct vcs_package_store *store, const uint8_t action_root[32],
    const uint8_t *bytes, size_t len, uint8_t package_root[32])
{
    if (!store || !action_root || !bytes || !package_root)
        return VCS_ZCODE_WORK_OUTPUT_NULL;
    if (len == 0) return VCS_ZCODE_WORK_OUTPUT_EMPTY;
    if ((uint64_t)len + 32u > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES)
        return VCS_ZCODE_WORK_OUTPUT_LIMIT;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool built = vcs_package_content_add_file(
            &manifest, VCS_ZCODE_WORK_OUTPUT_ACTION_PATH,
            VCS_PACKAGE_MODE_FILE, action_root, 32) &&
        vcs_package_content_add_file(
            &manifest, VCS_ZCODE_WORK_OUTPUT_BYTES_PATH,
            VCS_PACKAGE_MODE_FILE, bytes, len);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    built = built && vcs_package_manifest_root(&manifest, package_root) &&
        vcs_package_manifest_serialize(&manifest, &wire, &wire_len);
    vcs_package_manifest_free(&manifest);
    if (!built) {
        free(wire);
        return VCS_ZCODE_WORK_OUTPUT_SHAPE;
    }
    uint8_t admitted[32];
    enum vcs_package_store_result stored = vcs_package_store_put_manifest(
        store, wire, wire_len, admitted);
    free(wire);
    if (stored != VCS_PACKAGE_STORE_OK ||
        memcmp(admitted, package_root, 32) != 0)
        return VCS_ZCODE_WORK_OUTPUT_STORE;
    if (vcs_package_content_put_file(
            store, package_root, VCS_ZCODE_WORK_OUTPUT_ACTION_PATH,
            action_root, 32) != VCS_PACKAGE_STORE_OK ||
        vcs_package_content_put_file(
            store, package_root, VCS_ZCODE_WORK_OUTPUT_BYTES_PATH,
            bytes, len) != VCS_PACKAGE_STORE_OK)
        return VCS_ZCODE_WORK_OUTPUT_STORE;
    return VCS_ZCODE_WORK_OUTPUT_OK;
}

static bool work_output_file_shape(const struct vcs_package_file *file,
                                   const char *path, uint64_t max_bytes)
{
    return file && file->path && strcmp(file->path, path) == 0 &&
        file->mode == VCS_PACKAGE_MODE_FILE && file->size > 0 &&
        file->size <= max_bytes && file->chunk_count ==
            (uint32_t)((file->size + VCS_PACKAGE_CHUNK_BYTES - 1u) /
                       VCS_PACKAGE_CHUNK_BYTES);
}

static enum vcs_zcode_work_output_result work_output_read_file(
    struct vcs_package_store *store, const uint8_t root[32],
    const struct vcs_package_manifest *manifest, uint32_t file_index,
    uint8_t **out, size_t *out_len)
{
    enum vcs_package_store_result got = vcs_package_content_get_file_at(
        store, root, manifest, file_index, out, out_len);
    if (got == VCS_PACKAGE_STORE_ERR_ALLOC)
        return VCS_ZCODE_WORK_OUTPUT_ALLOC;
    return got == VCS_PACKAGE_STORE_OK ? VCS_ZCODE_WORK_OUTPUT_OK
                                       : VCS_ZCODE_WORK_OUTPUT_CORRUPT;
}

enum vcs_zcode_work_output_result vcs_zcode_work_output_get(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t expected_action_root[32], uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!store || !package_root || !expected_action_root || !out || !out_len)
        return VCS_ZCODE_WORK_OUTPUT_NULL;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_ZCODE_WORK_OUTPUT_ABSENT;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(
            store, package_root, &wire, &wire_len) != VCS_PACKAGE_STORE_OK)
        return VCS_ZCODE_WORK_OUTPUT_ABSENT;
    struct vcs_package_manifest manifest;
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &manifest);
    free(wire);
    uint8_t derived[32];
    bool shape = parsed && manifest.count == 2u &&
        work_output_file_shape(&manifest.files[0],
                               VCS_ZCODE_WORK_OUTPUT_ACTION_PATH, 32u) &&
        manifest.files[0].size == 32u &&
        work_output_file_shape(
            &manifest.files[1], VCS_ZCODE_WORK_OUTPUT_BYTES_PATH,
            VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES - 32u) &&
        vcs_package_manifest_root(&manifest, derived) &&
        memcmp(derived, package_root, 32) == 0;
    if (!shape) {
        if (parsed) vcs_package_manifest_free(&manifest);
        return VCS_ZCODE_WORK_OUTPUT_SHAPE;
    }
    uint8_t *action = NULL;
    size_t action_len = 0;
    enum vcs_zcode_work_output_result result = work_output_read_file(
        store, package_root, &manifest, 0u, &action, &action_len);
    if (result == VCS_ZCODE_WORK_OUTPUT_OK &&
        (action_len != 32u ||
         memcmp(action, expected_action_root, 32) != 0))
        result = VCS_ZCODE_WORK_OUTPUT_CORRUPT;
    free(action);
    if (result == VCS_ZCODE_WORK_OUTPUT_OK)
        result = work_output_read_file(
            store, package_root, &manifest, 1u, out, out_len);
    vcs_package_manifest_free(&manifest);
    return result;
}
