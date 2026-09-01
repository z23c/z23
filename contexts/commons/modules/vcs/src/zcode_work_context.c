/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical content.v2 carrier for one fixed ZCODE build action. */

#include "vcs/zcode_work_context.h"

#include "base/bytes.h"
#include "vcs_priv.h"

#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_candidate_tree.h"
#include "vcs/zcode_task_authority_bundle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t context_magic[8] = {
    'Z', 'C', 'C', 'T', 'X', '\r', '\n', 0
};

const char *vcs_zcode_work_context_result_string(
    enum vcs_zcode_work_context_result result)
{
    switch (result) {
    case VCS_ZCODE_WORK_CONTEXT_OK: return "ok";
    case VCS_ZCODE_WORK_CONTEXT_NULL: return "null-argument";
    case VCS_ZCODE_WORK_CONTEXT_SHAPE: return "noncanonical-context";
    case VCS_ZCODE_WORK_CONTEXT_LIMIT: return "context-limit";
    case VCS_ZCODE_WORK_CONTEXT_STALE: return "stale-context";
    case VCS_ZCODE_WORK_CONTEXT_ACTION: return "action-mismatch";
    case VCS_ZCODE_WORK_CONTEXT_STORE: return "package-store-refused";
    case VCS_ZCODE_WORK_CONTEXT_ABSENT: return "context-absent";
    case VCS_ZCODE_WORK_CONTEXT_CORRUPT: return "context-corrupt";
    case VCS_ZCODE_WORK_CONTEXT_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

void vcs_zcode_work_context_init(struct vcs_zcode_work_context_v1 *context)
{
    if (context) memset(context, 0, sizeof(*context));
}

void vcs_zcode_work_context_free(struct vcs_zcode_work_context_v1 *context)
{
    if (!context) return;
    free(context->fixed_input);
    free(context->candidate_authority);
    free(context->task_authority);
    vcs_zcode_work_context_init(context);
}

enum vcs_zcode_candidate_bundle_result
vcs_zcode_work_context_import_authority(
    const char *repo_root, const struct vcs_zcode_work_context_v1 *context)
{
    if (!repo_root || !context)
        return VCS_ZCODE_CANDIDATE_BUNDLE_NULL;
    if (!context->candidate_authority ||
        context->candidate_authority_len == 0)
        return VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
    return vcs_zcode_candidate_bundle_import(
        repo_root, &context->task, &context->candidate,
        context->candidate_authority, context->candidate_authority_len);
}

static enum vcs_zcode_work_context_result context_validate(
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix)
{
    if (!context || !context->fixed_input ||
        ((context->candidate_authority == NULL) !=
         (context->candidate_authority_len == 0)) ||
        ((context->task_authority == NULL) !=
         (context->task_authority_len == 0)))
        return VCS_ZCODE_WORK_CONTEXT_NULL;
    size_t profile_len = strnlen(context->profile, sizeof(context->profile));
    if (!zcl_bytes_any_set(context->source_sha256, 32) || profile_len == 0 ||
        profile_len > VCS_ZCODE_WORK_CONTEXT_PROFILE_MAX)
        return VCS_ZCODE_WORK_CONTEXT_SHAPE;
    if (context->fixed_input_len == 0 ||
        SIZE_MAX - context->fixed_input_len <
            context->candidate_authority_len ||
        SIZE_MAX - context->fixed_input_len -
                context->candidate_authority_len <
            context->task_authority_len ||
        context->fixed_input_len + context->candidate_authority_len +
                context->task_authority_len >
            context->task.max_context_bytes ||
        context->fixed_input_len + context->candidate_authority_len +
                context->task_authority_len >
            VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES -
                VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES - profile_len)
        return VCS_ZCODE_WORK_CONTEXT_LIMIT;
    if (vcs_zcode_task_validate_at(&context->task, now_unix) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_validate_for_task(
            &context->task, &context->candidate, now_unix) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_validate(&context->proof_policy) !=
            VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_WORK_CONTEXT_STALE;
    uint8_t policy_root[32];
    if (vcs_zcode_proof_policy_root(&context->proof_policy, policy_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(policy_root, context->task.proof_policy_root, 32) != 0)
        return VCS_ZCODE_WORK_CONTEXT_STALE;
    return VCS_ZCODE_WORK_CONTEXT_OK;
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_action_root_for_kind(
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, uint8_t action_root[32], uint8_t input_root[32])
{
    if (!action_root || !input_root)
        return VCS_ZCODE_WORK_CONTEXT_NULL;
    enum vcs_zcode_work_context_result valid =
        context_validate(context, now_unix);
    if (valid != VCS_ZCODE_WORK_CONTEXT_OK) return valid;
    struct vcs_build_action_v1 action = {0};
    memcpy(action.source_sha256, context->source_sha256, 32);
    memcpy(action.source_cas_sha3, context->candidate.candidate_source_root,
           32);
    struct vcs_zcode_action_input_v1 bound_input;
    enum vcs_zcode_action_input_result parsed = vcs_zcode_action_input_parse(
        context->fixed_input, context->fixed_input_len, &bound_input);
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0) {
        struct vcs_zcode_package_action_input_v1 package_input;
        parsed = vcs_zcode_package_action_input_parse(
            context->fixed_input, context->fixed_input_len, &package_input);
        uint8_t task_root[32], candidate_root[32];
        bool binding = parsed == VCS_ZCODE_ACTION_INPUT_OK &&
            vcs_zcode_task_root(&context->task, task_root) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_candidate_root(&context->candidate, candidate_root) ==
                VCS_ZCODE_DEV_OK &&
            memcmp(package_input.task_root, task_root, 32) == 0 &&
            memcmp(package_input.candidate_root, candidate_root, 32) == 0 &&
            memcmp(package_input.candidate_source_root,
                   context->candidate.candidate_source_root, 32) == 0 &&
            memcmp(package_input.base_source_root,
                   context->task.source_root, 32) == 0 &&
            memcmp(package_input.dependency_lock_root,
                   context->task.dependency_lock_root, 32) == 0 &&
            memcmp(package_input.acceptance_recipe_root,
                   context->task.acceptance_tests_root, 32) == 0 &&
            vcs_zcode_package_action_input_root(
                &package_input, input_root) == VCS_ZCODE_ACTION_INPUT_OK;
        if (!binding) return VCS_ZCODE_WORK_CONTEXT_ACTION;
    } else if (parsed == VCS_ZCODE_ACTION_INPUT_OK) {
        uint8_t task_root[32], candidate_root[32];
        uint8_t expected_kind = vcs_build_action_v1_work_kind(kind);
        bool binding = expected_kind != 0 &&
            bound_input.work_kind == expected_kind &&
            vcs_zcode_task_root(&context->task, task_root) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_candidate_root(&context->candidate, candidate_root) ==
                VCS_ZCODE_DEV_OK &&
            memcmp(bound_input.task_root, task_root, 32) == 0 &&
            memcmp(bound_input.candidate_root, candidate_root, 32) == 0 &&
            memcmp(bound_input.candidate_source_root,
                   context->candidate.candidate_source_root, 32) == 0 &&
            memcmp(bound_input.dependency_lock_root,
                   context->task.dependency_lock_root, 32) == 0 &&
            memcmp(bound_input.acceptance_tests_root,
                   context->task.acceptance_tests_root, 32) == 0 &&
            vcs_zcode_action_input_root(&bound_input, input_root) ==
                VCS_ZCODE_ACTION_INPUT_OK;
        vcs_zcode_action_input_free(&bound_input);
        if (!binding) return VCS_ZCODE_WORK_CONTEXT_ACTION;
    } else {
        /* Legacy local contexts remain readable; the ZCODE worker refuses
         * their unbound bytes before execution. */
        sha3_256(context->fixed_input, context->fixed_input_len, input_root);
    }
    memcpy(action.input_root_sha3, input_root, 32);
    memcpy(action.toolchain_capsule_sha3,
           context->task.toolchain_capsule_root, 32);
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    if (!vcs_build_action_v1_descriptors(
            kind, &workdir, &output, &resource) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(
            kind, action.flags_sha3) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            kind, action.environment_sha3))
        return VCS_ZCODE_WORK_CONTEXT_ACTION;
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action.profile, sizeof(action.profile), "%s",
                   context->profile);
    (void)snprintf(action.virtual_workdir, sizeof(action.virtual_workdir),
                   "%s", workdir);
    (void)snprintf(action.declared_outputs, sizeof(action.declared_outputs),
                   "%s", output);
    (void)snprintf(action.resource_policy, sizeof(action.resource_policy),
                   "%s", resource);
    if (!vcs_build_action_v1_root_for_kind(kind, &action, action_root))
        return VCS_ZCODE_WORK_CONTEXT_ACTION;
    return VCS_ZCODE_WORK_CONTEXT_OK;
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_action_root(
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix,
    uint8_t action_root[32], uint8_t input_root[32])
{
    return vcs_zcode_work_context_action_root_for_kind(
        context, VCS_BUILD_ACTION_KIND_V1, now_unix, action_root,
        input_root);
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_serialize(
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix,
    uint8_t **out, size_t *out_len)
{
    if (!out || !out_len) return VCS_ZCODE_WORK_CONTEXT_NULL;
    *out = NULL; *out_len = 0;
    enum vcs_zcode_work_context_result valid =
        context_validate(context, now_unix);
    if (valid != VCS_ZCODE_WORK_CONTEXT_OK) return valid;
    size_t profile_len = strlen(context->profile);
    size_t total = VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES + profile_len +
                   context->fixed_input_len;
    uint8_t *wire = zcl_malloc(total, "zcode.work_context");
    if (!wire) return VCS_ZCODE_WORK_CONTEXT_ALLOC;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (vcs_zcode_task_serialize(&context->task, task_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(&context->candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_serialize(&context->proof_policy,
                                         policy_wire) != VCS_ZCODE_DEV_OK)
        goto reject;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, total);
    bool ok = zcl_codec_write_bytes(&writer, context_magic,
                                    sizeof(context_magic)) &&
        zcl_codec_write_u16le(&writer, VCS_ZCODE_WORK_CONTEXT_VERSION) &&
        zcl_codec_write_u16le(&writer, (uint16_t)profile_len) &&
        zcl_codec_write_u32le(&writer, 0) &&
        zcl_codec_write_u64le(&writer, context->fixed_input_len) &&
        zcl_codec_write_bytes(&writer, context->source_sha256, 32) &&
        zcl_codec_write_bytes(&writer, task_wire, sizeof(task_wire)) &&
        zcl_codec_write_bytes(&writer, candidate_wire,
                              sizeof(candidate_wire)) &&
        zcl_codec_write_bytes(&writer, policy_wire, sizeof(policy_wire)) &&
        zcl_codec_write_bytes(&writer, context->profile, profile_len) &&
        zcl_codec_write_bytes(&writer, context->fixed_input,
                              context->fixed_input_len);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) || written != total)
        goto reject;
    *out = wire; *out_len = total;
    return VCS_ZCODE_WORK_CONTEXT_OK;
reject:
    free(wire);
    return VCS_ZCODE_WORK_CONTEXT_SHAPE;
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_parse(
    const uint8_t *wire, size_t wire_len, int64_t now_unix,
    struct vcs_zcode_work_context_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_WORK_CONTEXT_NULL;
    vcs_zcode_work_context_init(out);
    if (wire_len < VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES ||
        wire_len > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES ||
        memcmp(wire, context_magic, sizeof(context_magic)) != 0)
        return VCS_ZCODE_WORK_CONTEXT_SHAPE;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire + sizeof(context_magic),
                          wire_len - sizeof(context_magic));
    uint16_t version, profile_len;
    uint32_t reserved;
    uint64_t input_len64;
    if (!zcl_codec_read_u16le(&reader, &version) ||
        !zcl_codec_read_u16le(&reader, &profile_len) ||
        !zcl_codec_read_u32le(&reader, &reserved) ||
        !zcl_codec_read_u64le(&reader, &input_len64) ||
        version != VCS_ZCODE_WORK_CONTEXT_VERSION || reserved != 0)
        return VCS_ZCODE_WORK_CONTEXT_SHAPE;
    if (profile_len == 0 || profile_len > VCS_ZCODE_WORK_CONTEXT_PROFILE_MAX ||
        input_len64 == 0 || input_len64 > SIZE_MAX ||
        (uint64_t)VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES + profile_len +
                input_len64 != wire_len)
        return VCS_ZCODE_WORK_CONTEXT_SHAPE;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (!zcl_codec_read_bytes(&reader, out->source_sha256, 32) ||
        !zcl_codec_read_bytes(&reader, task_wire, sizeof(task_wire)) ||
        !zcl_codec_read_bytes(&reader, candidate_wire,
                              sizeof(candidate_wire)) ||
        !zcl_codec_read_bytes(&reader, policy_wire, sizeof(policy_wire)) ||
        vcs_zcode_task_parse(task_wire, sizeof(task_wire),
                             &out->task) != VCS_ZCODE_DEV_OK)
        goto reject;
    if (vcs_zcode_candidate_parse(candidate_wire,
            sizeof(candidate_wire), &out->candidate) !=
            VCS_ZCODE_DEV_OK) goto reject;
    if (vcs_zcode_proof_policy_parse(policy_wire,
            sizeof(policy_wire), &out->proof_policy) !=
            VCS_ZCODE_DEV_OK) goto reject;
    uint16_t decoded_profile_len;
    if (!zcl_codec_read_bytes(&reader, out->profile, profile_len)) goto reject;
    decoded_profile_len = profile_len;
    out->profile[decoded_profile_len] = '\0';
    out->fixed_input_len = (size_t)input_len64;
    out->fixed_input = zcl_malloc(out->fixed_input_len,
                                   "zcode.work_context.input");
    if (!out->fixed_input) {
        vcs_zcode_work_context_free(out);
        return VCS_ZCODE_WORK_CONTEXT_ALLOC;
    }
    if (!zcl_codec_read_bytes(&reader, out->fixed_input,
                              out->fixed_input_len) ||
        !zcl_codec_reader_finish(&reader))
        goto reject;
    enum vcs_zcode_work_context_result valid =
        context_validate(out, now_unix);
    if (valid != VCS_ZCODE_WORK_CONTEXT_OK) {
        vcs_zcode_work_context_free(out);
        return valid;
    }
    return VCS_ZCODE_WORK_CONTEXT_OK;
reject:
    vcs_zcode_work_context_free(out);
    return VCS_ZCODE_WORK_CONTEXT_SHAPE;
}

static enum vcs_zcode_work_context_result context_put_for_kind(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, const char *repo_root, uint8_t package_root[32],
    uint8_t action_root[32])
{
    if (!store || !package_root || !action_root)
        return VCS_ZCODE_WORK_CONTEXT_NULL;
    uint8_t input_root[32];
    enum vcs_zcode_work_context_result result =
        vcs_zcode_work_context_action_root_for_kind(
            context, kind, now_unix, action_root, input_root);
    if (result != VCS_ZCODE_WORK_CONTEXT_OK) return result;
    uint8_t *wire = NULL; size_t wire_len = 0;
    result = vcs_zcode_work_context_serialize(context, now_unix, &wire,
                                              &wire_len);
    if (result != VCS_ZCODE_WORK_CONTEXT_OK) return result;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool built = vcs_package_content_add_file(
        &manifest, VCS_ZCODE_WORK_CONTEXT_PATH, VCS_PACKAGE_MODE_FILE,
        wire, wire_len);
    if (built && context->candidate_authority_len > 0)
        built = vcs_package_content_add_file(
            &manifest, VCS_ZCODE_CANDIDATE_BUNDLE_PATH,
            VCS_PACKAGE_MODE_FILE,
            context->candidate_authority, context->candidate_authority_len);
    if (built && context->task_authority_len > 0)
        built = vcs_package_content_add_file(
            &manifest, VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH,
            VCS_PACKAGE_MODE_FILE,
            context->task_authority, context->task_authority_len);
    enum vcs_zcode_candidate_tree_result tree_result =
        VCS_ZCODE_CANDIDATE_TREE_OK;
    if (built && repo_root) {
        uint64_t metadata_bytes = context->fixed_input_len +
            context->candidate_authority_len + context->task_authority_len;
        uint64_t remaining = context->task.max_context_bytes - metadata_bytes;
        uint64_t overhead = VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES +
                            strlen(context->profile);
        uint64_t store_remaining = VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES -
                                   overhead - metadata_bytes;
        if (remaining > store_remaining) remaining = store_remaining;
        uint64_t tree_bytes = 0;
        tree_result = vcs_zcode_candidate_tree_add_manifest(
            repo_root, &context->task, &context->candidate, remaining,
            &manifest, &tree_bytes);
        built = tree_result == VCS_ZCODE_CANDIDATE_TREE_OK;
    }
    uint8_t *manifest_wire = NULL; size_t manifest_len = 0;
    built = built && vcs_package_manifest_root(&manifest, package_root) &&
            vcs_package_manifest_serialize(&manifest, &manifest_wire,
                                           &manifest_len);
    vcs_package_manifest_free(&manifest);
    if (!built) {
        free(manifest_wire); free(wire);
        return tree_result == VCS_ZCODE_CANDIDATE_TREE_LIMIT
            ? VCS_ZCODE_WORK_CONTEXT_LIMIT : VCS_ZCODE_WORK_CONTEXT_SHAPE;
    }
    uint8_t admitted[32];
    enum vcs_package_store_result stored = vcs_package_store_put_manifest(
        store, manifest_wire, manifest_len, admitted);
    free(manifest_wire);
    if (stored != VCS_PACKAGE_STORE_OK ||
        memcmp(admitted, package_root, 32) != 0) {
        free(wire); return VCS_ZCODE_WORK_CONTEXT_STORE;
    }
    result = vcs_package_content_put_file(
                 store, package_root, VCS_ZCODE_WORK_CONTEXT_PATH,
                 wire, wire_len) == VCS_PACKAGE_STORE_OK
        ? VCS_ZCODE_WORK_CONTEXT_OK : VCS_ZCODE_WORK_CONTEXT_STORE;
    if (result == VCS_ZCODE_WORK_CONTEXT_OK &&
        context->candidate_authority_len > 0)
        result = vcs_package_content_put_file(
                     store, package_root, VCS_ZCODE_CANDIDATE_BUNDLE_PATH,
                     context->candidate_authority,
                     context->candidate_authority_len) ==
                         VCS_PACKAGE_STORE_OK
            ? VCS_ZCODE_WORK_CONTEXT_OK : VCS_ZCODE_WORK_CONTEXT_STORE;
    if (result == VCS_ZCODE_WORK_CONTEXT_OK &&
        context->task_authority_len > 0)
        result = vcs_package_content_put_file(
                     store, package_root,
                     VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH,
                     context->task_authority,
                     context->task_authority_len) == VCS_PACKAGE_STORE_OK
            ? VCS_ZCODE_WORK_CONTEXT_OK : VCS_ZCODE_WORK_CONTEXT_STORE;
    if (result == VCS_ZCODE_WORK_CONTEXT_OK && repo_root &&
        vcs_zcode_candidate_tree_put_chunks(
            store, package_root, repo_root, &context->candidate) !=
                VCS_ZCODE_CANDIDATE_TREE_OK)
        result = VCS_ZCODE_WORK_CONTEXT_STORE;
    free(wire);
    return result;
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_put_for_kind(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, uint8_t package_root[32], uint8_t action_root[32])
{
    return context_put_for_kind(store, context, kind, now_unix, NULL,
                                package_root, action_root);
}

enum vcs_zcode_work_context_result
vcs_zcode_work_context_put_for_kind_with_candidate(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, const char *repo_root, uint8_t package_root[32],
    uint8_t action_root[32])
{
    if (!repo_root) return VCS_ZCODE_WORK_CONTEXT_NULL;
    return context_put_for_kind(store, context, kind, now_unix, repo_root,
                                package_root, action_root);
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_put(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix,
    uint8_t package_root[32], uint8_t action_root[32])
{
    return vcs_zcode_work_context_put_for_kind(
        store, context, VCS_BUILD_ACTION_KIND_V1, now_unix, package_root,
        action_root);
}

static int context_manifest_file_index(
    const struct vcs_package_manifest *manifest, const char *path)
{
    for (size_t i = 0; i < manifest->count; i++)
        if (strcmp(manifest->files[i].path, path) == 0) return (int)i;
    return -1;
}

static size_t context_manifest_candidate_files(
    const struct vcs_package_manifest *manifest)
{
    const size_t prefix = sizeof(VCS_ZCODE_CANDIDATE_TREE_PREFIX) - 1u;
    size_t count = 0;
    for (size_t i = 0; i < manifest->count; i++)
        if (strncmp(manifest->files[i].path,
                    VCS_ZCODE_CANDIDATE_TREE_PREFIX, prefix) == 0 &&
            manifest->files[i].path[prefix] != '\0')
            count++;
    return count;
}

static enum vcs_zcode_work_context_result context_get_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_manifest *manifest, size_t file_index,
    uint8_t **out, size_t *out_len)
{
    const struct vcs_package_file *file = &manifest->files[file_index];
    if (file->mode != VCS_PACKAGE_MODE_FILE || file->size == 0 ||
        file->size > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES)
        return VCS_ZCODE_WORK_CONTEXT_CORRUPT;
    enum vcs_package_store_result got = vcs_package_content_get_file_at(
        store, package_root, manifest, (uint32_t)file_index, out, out_len);
    if (got == VCS_PACKAGE_STORE_ERR_ALLOC)
        return VCS_ZCODE_WORK_CONTEXT_ALLOC;
    return got == VCS_PACKAGE_STORE_OK ? VCS_ZCODE_WORK_CONTEXT_OK
                                       : VCS_ZCODE_WORK_CONTEXT_CORRUPT;
}

enum vcs_zcode_work_context_result vcs_zcode_work_context_get(
    struct vcs_package_store *store, const uint8_t package_root[32],
    int64_t now_unix, struct vcs_zcode_work_context_v1 *out)
{
    if (!store || !package_root || !out)
        return VCS_ZCODE_WORK_CONTEXT_NULL;
    vcs_zcode_work_context_init(out);
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_ZCODE_WORK_CONTEXT_ABSENT;
    uint8_t *manifest_wire = NULL; size_t manifest_len = 0;
    if (vcs_package_store_get_manifest_wire(
            store, package_root, &manifest_wire, &manifest_len) !=
            VCS_PACKAGE_STORE_OK)
        return VCS_ZCODE_WORK_CONTEXT_ABSENT;
    struct vcs_package_manifest manifest;
    bool parsed = vcs_package_manifest_parse(manifest_wire, manifest_len,
                                              &manifest);
    free(manifest_wire);
    uint8_t derived[32];
    int context_index = parsed ? context_manifest_file_index(
        &manifest, VCS_ZCODE_WORK_CONTEXT_PATH) : -1;
    int authority_index = parsed ? context_manifest_file_index(
        &manifest, VCS_ZCODE_CANDIDATE_BUNDLE_PATH) : -1;
    int task_authority_index = parsed ? context_manifest_file_index(
        &manifest, VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH) : -1;
    size_t known_files = 1u + (authority_index >= 0 ? 1u : 0u) +
        (task_authority_index >= 0 ? 1u : 0u) +
        (parsed ? context_manifest_candidate_files(&manifest) : 0u);
    if (!parsed || manifest.count < 1 ||
        context_index < 0 || manifest.count != known_files ||
        manifest.files[context_index].size <
            VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES ||
        !vcs_package_manifest_root(&manifest, derived) ||
        memcmp(derived, package_root, 32) != 0) {
        if (parsed) vcs_package_manifest_free(&manifest);
        return VCS_ZCODE_WORK_CONTEXT_CORRUPT;
    }
    uint8_t *wire = NULL, *authority = NULL, *task_authority = NULL;
    size_t wire_len = 0, authority_len = 0, task_authority_len = 0;
    enum vcs_zcode_work_context_result result = context_get_file(
        store, package_root, &manifest, (size_t)context_index,
        &wire, &wire_len);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK && authority_index >= 0)
        result = context_get_file(
            store, package_root, &manifest, (size_t)authority_index,
            &authority, &authority_len);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK && task_authority_index >= 0)
        result = context_get_file(
            store, package_root, &manifest, (size_t)task_authority_index,
            &task_authority, &task_authority_len);
    vcs_package_manifest_free(&manifest);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK)
        result = vcs_zcode_work_context_parse(wire, wire_len, now_unix, out);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK) {
        uint64_t overhead = VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES +
                            strlen(out->profile);
        if (status.total_bytes < overhead ||
            status.total_bytes - overhead > out->task.max_context_bytes)
            result = VCS_ZCODE_WORK_CONTEXT_LIMIT;
    }
    free(wire);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK) {
        out->candidate_authority = authority;
        out->candidate_authority_len = authority_len;
        authority = NULL;
        out->task_authority = task_authority;
        out->task_authority_len = task_authority_len;
        task_authority = NULL;
        result = context_validate(out, now_unix);
        if (result != VCS_ZCODE_WORK_CONTEXT_OK)
            vcs_zcode_work_context_free(out);
    }
    free(task_authority); free(authority);
    if (result != VCS_ZCODE_WORK_CONTEXT_OK)
        vcs_zcode_work_context_free(out);
    return result;
}

static enum vcs_zcode_work_context_result context_restore_authority(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *receiver_root,
    const struct vcs_zcode_work_context_v1 *context)
{
    if (!context->task_authority || context->task_authority_len == 0 ||
        vcs_zcode_task_authority_bundle_import(
            receiver_root, &context->task, context->task_authority,
            context->task_authority_len) != VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_WORK_CONTEXT_CORRUPT;
    if (vcs_zcode_work_context_import_authority(receiver_root, context) !=
            VCS_ZCODE_CANDIDATE_BUNDLE_OK ||
        vcs_zcode_candidate_tree_import(
            store, package_root, receiver_root, &context->task,
            &context->candidate) != VCS_ZCODE_CANDIDATE_TREE_OK)
        return VCS_ZCODE_WORK_CONTEXT_CORRUPT;
    return VCS_ZCODE_WORK_CONTEXT_OK;
}

static bool context_source_manifest_id(
    const char *receiver_root, const struct vcs_zcode_work_context_v1 *context,
    uint8_t source_manifest_id[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool loaded = vcs_object_load_raw(
        receiver_root, context->candidate.candidate_source_root,
        &wire, &wire_len) == 0 && wire_len > 0;
    if (loaded) vcs_source_manifest_id(wire, wire_len, source_manifest_id);
    free(wire);
    return loaded && memcmp(source_manifest_id, context->source_sha256, 32) == 0;
}

static bool context_addressed_exact(
    const char *receiver_root, const uint8_t root[32], const uint8_t *wire,
    size_t wire_len)
{
    uint8_t *stored = NULL;
    size_t stored_len = 0;
    bool exact = vcs_object_load_raw_bounded(
            receiver_root, root, wire_len, &stored, &stored_len) == 0 &&
        stored_len == wire_len &&
        (wire_len == 0 || memcmp(stored, wire, wire_len) == 0);
    free(stored);
    return exact;
}

static bool context_store_action_objects(
    const char *receiver_root, const struct vcs_zcode_work_context_v1 *context,
    const uint8_t input_root[32])
{
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    bool canonical = vcs_zcode_task_root(
            &context->task, task_root) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(&context->candidate, candidate_root) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(&context->proof_policy, policy_root) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_serialize(&context->task, task_wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_serialize(&context->candidate, candidate_wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_serialize(
            &context->proof_policy, policy_wire) == VCS_ZCODE_DEV_OK &&
        vcs_object_store_init(receiver_root);
    if (!canonical) return false;
    canonical = vcs_object_put_addressed_repair(
            receiver_root, task_root, task_wire, sizeof(task_wire), NULL) &&
        vcs_object_put_addressed_repair(
            receiver_root, candidate_root, candidate_wire,
            sizeof(candidate_wire), NULL) &&
        vcs_object_put_addressed_repair(
            receiver_root, policy_root, policy_wire,
            sizeof(policy_wire), NULL) &&
        vcs_object_put_addressed_repair(
            receiver_root, input_root, context->fixed_input,
            context->fixed_input_len, NULL);
    if (!canonical) return false;
    return context_addressed_exact(
            receiver_root, task_root, task_wire, sizeof(task_wire)) &&
        context_addressed_exact(
            receiver_root, candidate_root, candidate_wire,
            sizeof(candidate_wire)) &&
        context_addressed_exact(
            receiver_root, policy_root, policy_wire, sizeof(policy_wire)) &&
        context_addressed_exact(
            receiver_root, input_root, context->fixed_input,
            context->fixed_input_len);
}

static bool context_action_input_current(
    const char *receiver_root, const struct vcs_zcode_work_context_v1 *context,
    const char *kind, const uint8_t input_root[32])
{
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0) {
        struct vcs_zcode_package_action_input_v1 input;
        return vcs_zcode_package_action_input_load_cas(
            receiver_root, input_root, &context->task, &context->candidate,
            &input) == VCS_ZCODE_ACTION_INPUT_OK;
    }
    uint8_t work_kind = vcs_build_action_v1_work_kind(kind);
    return work_kind != 0 && vcs_zcode_action_input_verify_cas(
        receiver_root, input_root, &context->task, &context->candidate,
        work_kind) == VCS_ZCODE_ACTION_INPUT_OK;
}

enum vcs_zcode_work_context_result
vcs_zcode_work_context_restore_for_kind(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *receiver_root, const char *kind, int64_t now_unix,
    struct vcs_zcode_work_context_roots *roots)
{
    if (roots) memset(roots, 0, sizeof(*roots));
    if (!store || !package_root || !receiver_root || !receiver_root[0] ||
        !kind || !roots)
        return VCS_ZCODE_WORK_CONTEXT_NULL;
    struct vcs_zcode_work_context_v1 context;
    enum vcs_zcode_work_context_result result = vcs_zcode_work_context_get(
        store, package_root, now_unix, &context);
    if (result != VCS_ZCODE_WORK_CONTEXT_OK) return result;
    result = context_restore_authority(
        store, package_root, receiver_root, &context);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK &&
        !context_source_manifest_id(
            receiver_root, &context, roots->source_manifest_id))
        result = VCS_ZCODE_WORK_CONTEXT_ACTION;
    if (result == VCS_ZCODE_WORK_CONTEXT_OK)
        result = vcs_zcode_work_context_action_root_for_kind(
            &context, kind, now_unix, roots->action_root, roots->input_root);
    if (result == VCS_ZCODE_WORK_CONTEXT_OK &&
        !context_store_action_objects(
            receiver_root, &context, roots->input_root))
        result = VCS_ZCODE_WORK_CONTEXT_STORE;
    if (result == VCS_ZCODE_WORK_CONTEXT_OK &&
        !context_action_input_current(
            receiver_root, &context, kind, roots->input_root))
        result = VCS_ZCODE_WORK_CONTEXT_ACTION;
    if (result == VCS_ZCODE_WORK_CONTEXT_OK)
        memcpy(roots->source_root,
               context.candidate.candidate_source_root, 32);
    else
        memset(roots, 0, sizeof(*roots));
    vcs_zcode_work_context_free(&context);
    return result;
}
