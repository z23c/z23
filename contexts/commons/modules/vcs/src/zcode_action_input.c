/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Candidate-bound immutable inputs for fixed ZCODE actions. */

#include "vcs/zcode_action_input.h"

#include "base/bytes.h"
#include "vcs_priv.h"

#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_task_authority.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const uint8_t action_input_magic[8] = {
    'Z', 'C', 'A', 'C', 'T', 'I', '\r', '\n'
};

static const uint8_t package_action_input_magic[8] = {
    'Z', 'C', 'P', 'K', 'G', 'I', '\r', '\n'
};

const char *vcs_zcode_action_input_result_string(
    enum vcs_zcode_action_input_result result)
{
    switch (result) {
    case VCS_ZCODE_ACTION_INPUT_OK: return "ok";
    case VCS_ZCODE_ACTION_INPUT_NULL: return "null-argument";
    case VCS_ZCODE_ACTION_INPUT_SHAPE: return "noncanonical-action-input";
    case VCS_ZCODE_ACTION_INPUT_LIMIT: return "action-input-limit";
    case VCS_ZCODE_ACTION_INPUT_BINDING: return "candidate-input-mismatch";
    case VCS_ZCODE_ACTION_INPUT_CAS: return "candidate-input-cas-miss";
    case VCS_ZCODE_ACTION_INPUT_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

void vcs_zcode_action_input_init(struct vcs_zcode_action_input_v1 *input)
{
    if (!input) return;
    memset(input, 0, sizeof(*input));
    input->schema_version = VCS_ZCODE_ACTION_INPUT_VERSION;
}

void vcs_zcode_action_input_free(struct vcs_zcode_action_input_v1 *input)
{
    if (!input) return;
    free(input->path); free(input->payload);
    vcs_zcode_action_input_init(input);
}

static bool action_input_kind_valid(uint8_t kind)
{
    return kind == VCS_ZCODE_WORK_BUILD || kind == VCS_ZCODE_WORK_TEST ||
           kind == VCS_ZCODE_WORK_FUZZ;
}

static const struct vcs_entry *action_input_find(
    const struct vcs_manifest *manifest, const char *path)
{
    size_t lo = 0, hi = manifest->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(manifest->entries[mid].path, path);
        if (cmp == 0) return &manifest->entries[mid];
        if (cmp < 0) lo = mid + 1u; else hi = mid;
    }
    return NULL;
}

static bool action_input_entry_allowed(const struct vcs_entry *entry,
                                       uint8_t kind)
{
    if (!entry || !S_ISREG(entry->mode) || entry->size == 0 ||
        entry->size > VCS_BUILD_ARTIFACT_MAX_BYTES)
        return false;
    size_t len = strlen(entry->path);
    if (kind == VCS_ZCODE_WORK_BUILD)
        return len > 2u && strcmp(entry->path + len - 2u, ".i") == 0;
    return (entry->mode & 0111u) != 0;
}

static enum vcs_zcode_action_input_result action_input_shape(
    const struct vcs_zcode_action_input_v1 *input)
{
    if (!input || !input->path || !input->payload)
        return VCS_ZCODE_ACTION_INPUT_NULL;
    size_t path_len = strnlen(input->path, (size_t)UINT16_MAX + 1u);
    if (input->schema_version != VCS_ZCODE_ACTION_INPUT_VERSION ||
        !action_input_kind_valid(input->work_kind) || path_len == 0 ||
        path_len > UINT16_MAX || !vcs_package_path_valid(input->path) ||
        input->payload_len == 0 ||
        input->payload_len > VCS_BUILD_ARTIFACT_MAX_BYTES)
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    if (!zcl_bytes_any_set(input->task_root, 32) ||
        !zcl_bytes_any_set(input->candidate_root, 32) ||
        !zcl_bytes_any_set(input->candidate_source_root, 32) ||
        !zcl_bytes_any_set(input->dependency_lock_root, 32) ||
        !zcl_bytes_any_set(input->acceptance_tests_root, 32) ||
        !zcl_bytes_any_set(input->payload_blob_root, 32))
        return VCS_ZCODE_ACTION_INPUT_BINDING;
    uint8_t blob[32];
    vcs_sha3_tag(VCS_TAG_BLOB, input->payload, input->payload_len, blob);
    return memcmp(blob, input->payload_blob_root, 32) == 0
        ? VCS_ZCODE_ACTION_INPUT_OK : VCS_ZCODE_ACTION_INPUT_BINDING;
}

enum vcs_zcode_action_input_result vcs_zcode_action_input_derive_cas(
    const char *repo_root, const uint8_t task_root[32],
    const uint8_t candidate_root[32], const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, uint8_t work_kind,
    const char *candidate_path, struct vcs_zcode_action_input_v1 *out)
{
    if (!repo_root || !task_root || !candidate_root || !task || !candidate ||
        !candidate_path || !out)
        return VCS_ZCODE_ACTION_INPUT_NULL;
    vcs_zcode_action_input_init(out);
    if (!action_input_kind_valid(work_kind) ||
        !vcs_package_path_valid(candidate_path))
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    struct vcs_manifest manifest;
    if (!vcs_tree_load(repo_root, candidate->candidate_source_root,
                       &manifest))
        return VCS_ZCODE_ACTION_INPUT_CAS;
    const struct vcs_entry *entry = action_input_find(&manifest,
                                                       candidate_path);
    if (!action_input_entry_allowed(entry, work_kind)) {
        vcs_manifest_free(&manifest);
        return VCS_ZCODE_ACTION_INPUT_BINDING;
    }
    uint8_t *payload = NULL; size_t payload_len = 0;
    if (vcs_object_get(repo_root, entry->blob, VCS_TAG_BLOB,
                       &payload, &payload_len) != 0 ||
        payload_len != entry->size) {
        free(payload); vcs_manifest_free(&manifest);
        return VCS_ZCODE_ACTION_INPUT_CAS;
    }
    size_t path_len = strlen(candidate_path);
    char *path = zcl_malloc(path_len + 1u, "zcode.action_input.path");
    if (!path) {
        free(payload); vcs_manifest_free(&manifest);
        return VCS_ZCODE_ACTION_INPUT_ALLOC;
    }
    memcpy(path, candidate_path, path_len + 1u);
    out->work_kind = work_kind;
    memcpy(out->task_root, task_root, 32);
    memcpy(out->candidate_root, candidate_root, 32);
    memcpy(out->candidate_source_root,
           candidate->candidate_source_root, 32);
    memcpy(out->dependency_lock_root, task->dependency_lock_root, 32);
    memcpy(out->acceptance_tests_root, task->acceptance_tests_root, 32);
    memcpy(out->payload_blob_root, entry->blob, 32);
    out->path = path; out->payload = payload; out->payload_len = payload_len;
    vcs_manifest_free(&manifest);
    return action_input_shape(out);
}

enum vcs_zcode_action_input_result vcs_zcode_action_input_serialize(
    const struct vcs_zcode_action_input_v1 *input, uint8_t **wire,
    size_t *wire_len)
{
    if (!wire || !wire_len) return VCS_ZCODE_ACTION_INPUT_NULL;
    *wire = NULL; *wire_len = 0;
    enum vcs_zcode_action_input_result result = action_input_shape(input);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    size_t path_len = strlen(input->path);
    if (SIZE_MAX - VCS_ZCODE_ACTION_INPUT_HEADER_BYTES < path_len ||
        SIZE_MAX - VCS_ZCODE_ACTION_INPUT_HEADER_BYTES - path_len <
            input->payload_len)
        return VCS_ZCODE_ACTION_INPUT_LIMIT;
    size_t total = VCS_ZCODE_ACTION_INPUT_HEADER_BYTES + path_len +
                   input->payload_len;
    uint8_t *out = zcl_malloc(total, "zcode.action_input.wire");
    if (!out) return VCS_ZCODE_ACTION_INPUT_ALLOC;
    memcpy(out, action_input_magic, 8);
    vcs_wr_u16le(out + 8, VCS_ZCODE_ACTION_INPUT_VERSION);
    out[10] = input->work_kind; out[11] = 0;
    vcs_wr_u16le(out + 12, (uint16_t)path_len);
    vcs_wr_u16le(out + 14, 0);
    vcs_wr_u64le(out + 16, input->payload_len);
    size_t off = 24;
    memcpy(out + off, input->task_root, 32); off += 32;
    memcpy(out + off, input->candidate_root, 32); off += 32;
    memcpy(out + off, input->candidate_source_root, 32); off += 32;
    memcpy(out + off, input->dependency_lock_root, 32); off += 32;
    memcpy(out + off, input->acceptance_tests_root, 32); off += 32;
    memcpy(out + off, input->payload_blob_root, 32); off += 32;
    memcpy(out + off, input->path, path_len); off += path_len;
    memcpy(out + off, input->payload, input->payload_len);
    off += input->payload_len;
    if (off != total) { free(out); return VCS_ZCODE_ACTION_INPUT_SHAPE; }
    *wire = out; *wire_len = total;
    return VCS_ZCODE_ACTION_INPUT_OK;
}

enum vcs_zcode_action_input_result vcs_zcode_action_input_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_action_input_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_ACTION_INPUT_NULL;
    vcs_zcode_action_input_init(out);
    if (wire_len < VCS_ZCODE_ACTION_INPUT_HEADER_BYTES ||
        wire_len > VCS_BUILD_ARTIFACT_MAX_BYTES + UINT16_MAX +
                       VCS_ZCODE_ACTION_INPUT_HEADER_BYTES ||
        memcmp(wire, action_input_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_ACTION_INPUT_VERSION ||
        wire[11] != 0 || vcs_rd_u16le(wire + 14) != 0)
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    uint16_t path_len = vcs_rd_u16le(wire + 12);
    uint64_t payload_len = vcs_rd_u64le(wire + 16);
    if (path_len == 0 || payload_len == 0 || payload_len > SIZE_MAX ||
        (uint64_t)VCS_ZCODE_ACTION_INPUT_HEADER_BYTES + path_len +
            payload_len != wire_len)
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    size_t off = 24;
    out->work_kind = wire[10];
    memcpy(out->task_root, wire + off, 32); off += 32;
    memcpy(out->candidate_root, wire + off, 32); off += 32;
    memcpy(out->candidate_source_root, wire + off, 32); off += 32;
    memcpy(out->dependency_lock_root, wire + off, 32); off += 32;
    memcpy(out->acceptance_tests_root, wire + off, 32); off += 32;
    memcpy(out->payload_blob_root, wire + off, 32); off += 32;
    out->path = zcl_malloc((size_t)path_len + 1u,
                           "zcode.action_input.parse_path");
    out->payload = zcl_malloc((size_t)payload_len,
                              "zcode.action_input.parse_payload");
    if (!out->path || !out->payload) {
        vcs_zcode_action_input_free(out);
        return VCS_ZCODE_ACTION_INPUT_ALLOC;
    }
    memcpy(out->path, wire + off, path_len); out->path[path_len] = '\0';
    if (memchr(out->path, '\0', path_len) != NULL) {
        vcs_zcode_action_input_free(out);
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    }
    off += path_len; out->payload_len = (size_t)payload_len;
    memcpy(out->payload, wire + off, out->payload_len);
    enum vcs_zcode_action_input_result result = action_input_shape(out);
    if (result != VCS_ZCODE_ACTION_INPUT_OK)
        vcs_zcode_action_input_free(out);
    return result;
}

enum vcs_zcode_action_input_result vcs_zcode_action_input_root(
    const struct vcs_zcode_action_input_v1 *input, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_ACTION_INPUT_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_action_input_result result =
        vcs_zcode_action_input_serialize(input, &wire, &wire_len);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_ZCODE_ACTION_INPUT_ROOT_DOMAIN;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out); free(wire);
    return VCS_ZCODE_ACTION_INPUT_OK;
}

enum vcs_zcode_action_input_result
vcs_zcode_action_input_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_action_input_v1 *input,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    uint8_t expected_work_kind)
{
    if (!repo_root || !task || !candidate || !input || !task_root ||
        !candidate_root)
        return VCS_ZCODE_ACTION_INPUT_NULL;
    enum vcs_zcode_action_input_result result = action_input_shape(input);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    uint8_t checked_task[32], checked_candidate[32];
    if (vcs_zcode_task_root(task, checked_task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, checked_candidate) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(checked_task, task_root, 32) != 0 ||
        memcmp(checked_candidate, candidate_root, 32) != 0 ||
        input->work_kind != expected_work_kind ||
        memcmp(input->task_root, task_root, 32) != 0 ||
        memcmp(input->candidate_root, candidate_root, 32) != 0 ||
        memcmp(input->candidate_source_root,
               candidate->candidate_source_root, 32) != 0 ||
        memcmp(input->dependency_lock_root,
               task->dependency_lock_root, 32) != 0 ||
        memcmp(input->acceptance_tests_root,
               task->acceptance_tests_root, 32) != 0)
        return VCS_ZCODE_ACTION_INPUT_BINDING;
    if (vcs_zcode_task_authority_validate_for_candidate(
            repo_root, task, candidate) != VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    struct vcs_manifest manifest;
    if (!vcs_tree_load(repo_root, candidate->candidate_source_root,
                       &manifest))
        return VCS_ZCODE_ACTION_INPUT_CAS;
    const struct vcs_entry *entry = action_input_find(&manifest, input->path);
    bool valid = action_input_entry_allowed(entry, input->work_kind) &&
        entry->size == input->payload_len &&
        memcmp(entry->blob, input->payload_blob_root, 32) == 0;
    vcs_manifest_free(&manifest);
    return valid ? VCS_ZCODE_ACTION_INPUT_OK
                 : VCS_ZCODE_ACTION_INPUT_BINDING;
}

static enum vcs_zcode_action_input_result action_input_load_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t expected_work_kind, uint8_t **payload, size_t *payload_len)
{
    if (!repo_root || !input_root || !task || !candidate ||
        ((payload == NULL) != (payload_len == NULL)))
        return VCS_ZCODE_ACTION_INPUT_NULL;
    if (payload) { *payload = NULL; *payload_len = 0; }
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_object_load_raw(repo_root, input_root, &wire, &wire_len) != 0)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    struct vcs_zcode_action_input_v1 input;
    enum vcs_zcode_action_input_result result = vcs_zcode_action_input_parse(
        wire, wire_len, &input);
    free(wire);
    uint8_t checked[32], task_root[32], candidate_root[32];
    if (result == VCS_ZCODE_ACTION_INPUT_OK &&
        (vcs_zcode_action_input_root(&input, checked) !=
            VCS_ZCODE_ACTION_INPUT_OK ||
         memcmp(checked, input_root, 32) != 0 ||
         vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
         vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK))
        result = VCS_ZCODE_ACTION_INPUT_BINDING;
    if (result == VCS_ZCODE_ACTION_INPUT_OK)
        result = vcs_zcode_action_input_validate_for_candidate(
            repo_root, task, candidate, &input, task_root, candidate_root,
            expected_work_kind);
    if (result == VCS_ZCODE_ACTION_INPUT_OK && payload) {
        *payload = input.payload; *payload_len = input.payload_len;
        input.payload = NULL; input.payload_len = 0;
    }
    vcs_zcode_action_input_free(&input);
    return result;
}

enum vcs_zcode_action_input_result vcs_zcode_action_input_load_payload_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t expected_work_kind, uint8_t **payload, size_t *payload_len)
{
    if (!payload || !payload_len) return VCS_ZCODE_ACTION_INPUT_NULL;
    return action_input_load_cas(
        repo_root, input_root, task, candidate, expected_work_kind,
        payload, payload_len);
}

enum vcs_zcode_action_input_result vcs_zcode_action_input_verify_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t expected_work_kind)
{
    return action_input_load_cas(
        repo_root, input_root, task, candidate, expected_work_kind,
        NULL, NULL);
}

static enum vcs_zcode_action_input_result package_action_input_shape(
    const struct vcs_zcode_package_action_input_v1 *input)
{
    if (!input) return VCS_ZCODE_ACTION_INPUT_NULL;
    if (input->schema_version != VCS_ZCODE_PACKAGE_ACTION_INPUT_VERSION)
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    return zcl_bytes_any_set(input->task_root, 32) &&
           zcl_bytes_any_set(input->candidate_root, 32) &&
           zcl_bytes_any_set(input->candidate_source_root, 32) &&
           zcl_bytes_any_set(input->base_source_root, 32) &&
           zcl_bytes_any_set(input->dependency_lock_root, 32) &&
           zcl_bytes_any_set(input->acceptance_recipe_root, 32)
        ? VCS_ZCODE_ACTION_INPUT_OK : VCS_ZCODE_ACTION_INPUT_BINDING;
}

static enum vcs_zcode_action_input_result package_action_lock_target(
    const char *repo_root, const struct vcs_zcode_task_v1 *task)
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_object_load_raw(repo_root, task->dependency_lock_root,
                            &wire, &wire_len) != 0)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    struct vcs_package_lock lock;
    enum vcs_package_deps_error parsed =
        vcs_package_lock_parse(wire, wire_len, &lock);
    free(wire);
    if (parsed != VCS_PACKAGE_DEPS_OK || lock.count == 0)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    const struct vcs_package_lock_node *target = &lock.nodes[lock.count - 1u];
    /* The lock target is a package-release/content root. task.source_root is
     * the ZVCS structural tree captured for editing. They are intentionally
     * different address spaces; the task binds both exact roots while the
     * candidate authority check below proves recipe membership in the tree. */
    return target->depth == 0 && target->name[0] != '\0'
        ? VCS_ZCODE_ACTION_INPUT_OK : VCS_ZCODE_ACTION_INPUT_BINDING;
}

enum vcs_zcode_action_input_result vcs_zcode_package_action_input_derive(
    const char *repo_root, const uint8_t task_root[32],
    const uint8_t candidate_root[32], const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_package_action_input_v1 *out)
{
    if (!repo_root || !task_root || !candidate_root || !task || !candidate ||
        !out)
        return VCS_ZCODE_ACTION_INPUT_NULL;
    memset(out, 0, sizeof(*out));
    out->schema_version = VCS_ZCODE_PACKAGE_ACTION_INPUT_VERSION;
    memcpy(out->task_root, task_root, 32);
    memcpy(out->candidate_root, candidate_root, 32);
    memcpy(out->candidate_source_root, candidate->candidate_source_root, 32);
    memcpy(out->base_source_root, task->source_root, 32);
    memcpy(out->dependency_lock_root, task->dependency_lock_root, 32);
    memcpy(out->acceptance_recipe_root, task->acceptance_tests_root, 32);
    enum vcs_zcode_action_input_result result = package_action_input_shape(out);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    if (vcs_zcode_task_authority_validate_for_candidate(
            repo_root, task, candidate) != VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    return package_action_lock_target(repo_root, task);
}

enum vcs_zcode_action_input_result vcs_zcode_package_action_input_serialize(
    const struct vcs_zcode_package_action_input_v1 *input,
    uint8_t out[VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_ACTION_INPUT_NULL;
    enum vcs_zcode_action_input_result result = package_action_input_shape(input);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    memcpy(out, package_action_input_magic, 8);
    vcs_wr_u16le(out + 8, VCS_ZCODE_PACKAGE_ACTION_INPUT_VERSION);
    vcs_wr_u16le(out + 10, 0);
    size_t off = 12;
    memcpy(out + off, input->task_root, 32); off += 32;
    memcpy(out + off, input->candidate_root, 32); off += 32;
    memcpy(out + off, input->candidate_source_root, 32); off += 32;
    memcpy(out + off, input->base_source_root, 32); off += 32;
    memcpy(out + off, input->dependency_lock_root, 32); off += 32;
    memcpy(out + off, input->acceptance_recipe_root, 32); off += 32;
    return off == VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES
        ? VCS_ZCODE_ACTION_INPUT_OK : VCS_ZCODE_ACTION_INPUT_SHAPE;
}

enum vcs_zcode_action_input_result vcs_zcode_package_action_input_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_package_action_input_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_ACTION_INPUT_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES ||
        memcmp(wire, package_action_input_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_PACKAGE_ACTION_INPUT_VERSION ||
        vcs_rd_u16le(wire + 10) != 0)
        return VCS_ZCODE_ACTION_INPUT_SHAPE;
    out->schema_version = VCS_ZCODE_PACKAGE_ACTION_INPUT_VERSION;
    size_t off = 12;
    memcpy(out->task_root, wire + off, 32); off += 32;
    memcpy(out->candidate_root, wire + off, 32); off += 32;
    memcpy(out->candidate_source_root, wire + off, 32); off += 32;
    memcpy(out->base_source_root, wire + off, 32); off += 32;
    memcpy(out->dependency_lock_root, wire + off, 32); off += 32;
    memcpy(out->acceptance_recipe_root, wire + off, 32);
    return package_action_input_shape(out);
}

enum vcs_zcode_action_input_result vcs_zcode_package_action_input_root(
    const struct vcs_zcode_package_action_input_v1 *input, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_ACTION_INPUT_NULL;
    uint8_t wire[VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES];
    enum vcs_zcode_action_input_result result =
        vcs_zcode_package_action_input_serialize(input, wire);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_ZCODE_PACKAGE_ACTION_INPUT_ROOT_DOMAIN;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_ACTION_INPUT_OK;
}

enum vcs_zcode_action_input_result
vcs_zcode_package_action_input_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_package_action_input_v1 *input,
    const uint8_t task_root[32], const uint8_t candidate_root[32])
{
    if (!repo_root || !task || !candidate || !input || !task_root ||
        !candidate_root)
        return VCS_ZCODE_ACTION_INPUT_NULL;
    enum vcs_zcode_action_input_result result = package_action_input_shape(input);
    uint8_t checked_task[32], checked_candidate[32];
    if (result != VCS_ZCODE_ACTION_INPUT_OK) return result;
    if (vcs_zcode_task_root(task, checked_task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, checked_candidate) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(checked_task, task_root, 32) != 0 ||
        memcmp(checked_candidate, candidate_root, 32) != 0 ||
        memcmp(input->task_root, task_root, 32) != 0 ||
        memcmp(input->candidate_root, candidate_root, 32) != 0 ||
        memcmp(input->candidate_source_root,
               candidate->candidate_source_root, 32) != 0 ||
        memcmp(input->base_source_root, task->source_root, 32) != 0 ||
        memcmp(input->dependency_lock_root,
               task->dependency_lock_root, 32) != 0 ||
        memcmp(input->acceptance_recipe_root,
               task->acceptance_tests_root, 32) != 0)
        return VCS_ZCODE_ACTION_INPUT_BINDING;
    if (vcs_zcode_task_authority_validate_for_candidate(
            repo_root, task, candidate) != VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    return package_action_lock_target(repo_root, task);
}

enum vcs_zcode_action_input_result vcs_zcode_package_action_input_load_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_package_action_input_v1 *out)
{
    if (!repo_root || !input_root || !task || !candidate || !out)
        return VCS_ZCODE_ACTION_INPUT_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_object_load_raw(repo_root, input_root, &wire, &wire_len) != 0)
        return VCS_ZCODE_ACTION_INPUT_CAS;
    enum vcs_zcode_action_input_result result =
        vcs_zcode_package_action_input_parse(wire, wire_len, out);
    free(wire);
    uint8_t checked[32], task_root[32], candidate_root[32];
    if (result == VCS_ZCODE_ACTION_INPUT_OK &&
        (vcs_zcode_package_action_input_root(out, checked) !=
             VCS_ZCODE_ACTION_INPUT_OK ||
         memcmp(checked, input_root, 32) != 0 ||
         vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
         vcs_zcode_candidate_root(candidate, candidate_root) !=
             VCS_ZCODE_DEV_OK))
        result = VCS_ZCODE_ACTION_INPUT_BINDING;
    if (result == VCS_ZCODE_ACTION_INPUT_OK)
        result = vcs_zcode_package_action_input_validate_for_candidate(
            repo_root, task, candidate, out, task_root, candidate_root);
    if (result != VCS_ZCODE_ACTION_INPUT_OK) memset(out, 0, sizeof(*out));
    return result;
}
