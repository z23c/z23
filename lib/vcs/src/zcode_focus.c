/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical shared-focus and active-claim-set codecs. */
#include "vcs/zcode_focus.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t focus_magic[8] = {
    'Z', 'C', 'F', 'O', 'C', 'U', 'S', '\n'
};
static const uint8_t claim_set_magic[8] = {
    'Z', 'C', 'F', 'C', 'L', 'M', 'S', '\n'
};

static bool focus_status_valid(uint8_t status)
{
    return status >= ZCL_ONTOLOGY_PROVED &&
           status <= ZCL_ONTOLOGY_INCOMPLETE;
}

static void focus_hash(const char *domain, const uint8_t *wire,
                       size_t wire_len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1u);
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
}

static void focus_derived_root(const char *domain,
                               const uint8_t *bytes, size_t bytes_len,
                               uint8_t out[32])
{
    focus_hash(domain, bytes, bytes_len, out);
}

const char *vcs_zcode_focus_error_string(enum vcs_zcode_focus_error error)
{
    switch (error) {
    case VCS_ZCODE_FOCUS_OK: return "ok";
    case VCS_ZCODE_FOCUS_NULL: return "null-argument";
    case VCS_ZCODE_FOCUS_VERSION_ERROR: return "focus-version-invalid";
    case VCS_ZCODE_FOCUS_SHAPE: return "focus-shape-invalid";
    case VCS_ZCODE_FOCUS_ROOT_ZERO: return "focus-root-zero";
    case VCS_ZCODE_FOCUS_LIMIT: return "focus-limit-invalid";
    case VCS_ZCODE_FOCUS_ORDER: return "focus-order-invalid";
    case VCS_ZCODE_FOCUS_DUPLICATE: return "focus-duplicate-root";
    case VCS_ZCODE_FOCUS_BINDING: return "focus-binding-mismatch";
    case VCS_ZCODE_FOCUS_EXPIRED: return "focus-claim-expired";
    case VCS_ZCODE_FOCUS_ALLOC: return "focus-allocation-failed";
    }
    return "unknown-focus-error";
}

enum vcs_zcode_focus_error vcs_zcode_focus_validate(
    const struct vcs_zcode_focus_v1 *focus)
{
    if (!focus) return VCS_ZCODE_FOCUS_NULL;
    if (focus->schema_version != VCS_ZCODE_FOCUS_VERSION)
        return VCS_ZCODE_FOCUS_VERSION_ERROR;
    if (!focus_status_valid(focus->status) ||
        (focus->flags & ~VCS_ZCODE_FOCUS_CONTEXT_TRUNCATED) != 0 ||
        focus->reserved != 0 || focus->reserved_budget != 0)
        return VCS_ZCODE_FOCUS_SHAPE;
    if (focus->claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS ||
        focus->max_changed_files == 0 ||
        focus->max_changed_files > 4096 ||
        focus->max_patch_bytes == 0 ||
        focus->max_patch_bytes > VCS_ZCODE_TASK_MAX_PATCH_BYTES ||
        focus->max_context_bytes == 0 ||
        focus->max_context_bytes > VCS_ZCODE_TASK_MAX_CONTEXT_BYTES ||
        focus->max_cpu_seconds == 0 || focus->max_cpu_seconds > 3600 ||
        focus->max_memory_bytes < UINT64_C(1024) * 1024u ||
        focus->max_memory_bytes > VCS_ZCODE_TASK_MAX_MEMORY_BYTES ||
        focus->max_output_bytes == 0 ||
        focus->max_output_bytes > VCS_ZCODE_TASK_MAX_OUTPUT_BYTES)
        return VCS_ZCODE_FOCUS_LIMIT;
    const uint32_t required = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                              VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    if ((focus->capabilities & required) != required ||
        (focus->capabilities & ~VCS_ZCODE_TASK_CAP_V1_MASK) != 0)
        return VCS_ZCODE_FOCUS_SHAPE;
    const uint8_t *roots[] = {
        focus->task_root, focus->goal_root, focus->source_universe_root,
        focus->context_root, focus->story_graph_root, focus->claim_set_root,
        focus->required_evidence_root, focus->authority_limits_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_focus_serialize(
    const struct vcs_zcode_focus_v1 *focus,
    uint8_t out[VCS_ZCODE_FOCUS_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    enum vcs_zcode_focus_error error = vcs_zcode_focus_validate(focus);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_FOCUS_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, focus_magic, 8) &&
        zcl_codec_write_u16le(&writer, focus->schema_version) &&
        zcl_codec_write_u8(&writer, focus->status) &&
        zcl_codec_write_u8(&writer, focus->flags) &&
        zcl_codec_write_u16le(&writer, focus->claim_count) &&
        zcl_codec_write_u16le(&writer, focus->reserved) &&
        zcl_codec_write_u32le(&writer, focus->capabilities) &&
        zcl_codec_write_u32le(&writer, focus->max_changed_files) &&
        zcl_codec_write_u64le(&writer, focus->max_patch_bytes) &&
        zcl_codec_write_u64le(&writer, focus->max_context_bytes) &&
        zcl_codec_write_u32le(&writer, focus->max_cpu_seconds) &&
        zcl_codec_write_u32le(&writer, focus->reserved_budget) &&
        zcl_codec_write_u64le(&writer, focus->max_memory_bytes) &&
        zcl_codec_write_u64le(&writer, focus->max_output_bytes) &&
        zcl_codec_write_bytes(&writer, focus->task_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->goal_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->source_universe_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->context_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->story_graph_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->claim_set_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->required_evidence_root, 32) &&
        zcl_codec_write_bytes(&writer, focus->authority_limits_root, 32);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_FOCUS_WIRE_BYTES
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_SHAPE;
}

enum vcs_zcode_focus_error vcs_zcode_focus_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_focus_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_FOCUS_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_FOCUS_WIRE_BYTES)
        return VCS_ZCODE_FOCUS_SHAPE;
    struct zcl_codec_reader reader;
    uint8_t magic[8];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->status) &&
        zcl_codec_read_u8(&reader, &out->flags) &&
        zcl_codec_read_u16le(&reader, &out->claim_count) &&
        zcl_codec_read_u16le(&reader, &out->reserved) &&
        zcl_codec_read_u32le(&reader, &out->capabilities) &&
        zcl_codec_read_u32le(&reader, &out->max_changed_files) &&
        zcl_codec_read_u64le(&reader, &out->max_patch_bytes) &&
        zcl_codec_read_u64le(&reader, &out->max_context_bytes) &&
        zcl_codec_read_u32le(&reader, &out->max_cpu_seconds) &&
        zcl_codec_read_u32le(&reader, &out->reserved_budget) &&
        zcl_codec_read_u64le(&reader, &out->max_memory_bytes) &&
        zcl_codec_read_u64le(&reader, &out->max_output_bytes) &&
        zcl_codec_read_bytes(&reader, out->task_root, 32) &&
        zcl_codec_read_bytes(&reader, out->goal_root, 32) &&
        zcl_codec_read_bytes(&reader, out->source_universe_root, 32) &&
        zcl_codec_read_bytes(&reader, out->context_root, 32) &&
        zcl_codec_read_bytes(&reader, out->story_graph_root, 32) &&
        zcl_codec_read_bytes(&reader, out->claim_set_root, 32) &&
        zcl_codec_read_bytes(&reader, out->required_evidence_root, 32) &&
        zcl_codec_read_bytes(&reader, out->authority_limits_root, 32) &&
        zcl_codec_reader_finish(&reader) &&
        memcmp(magic, focus_magic, 8) == 0;
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_FOCUS_SHAPE;
    }
    return vcs_zcode_focus_validate(out);
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_set_serialize(
    const uint8_t (*claim_roots)[32], size_t claim_count,
    uint8_t **wire_out, size_t *wire_len)
{
    if (!wire_out || !wire_len || (claim_count > 0 && !claim_roots))
        return VCS_ZCODE_FOCUS_NULL;
    *wire_out = NULL;
    *wire_len = 0;
    if (claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS)
        return VCS_ZCODE_FOCUS_LIMIT;
    for (size_t i = 0; i < claim_count; i++) {
        if (!zcl_bytes_any_set(claim_roots[i], 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
        if (i > 0) {
            int order = memcmp(claim_roots[i - 1u], claim_roots[i], 32);
            if (order == 0) return VCS_ZCODE_FOCUS_DUPLICATE;
            if (order > 0) return VCS_ZCODE_FOCUS_ORDER;
        }
    }
    size_t total = VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES +
                   claim_count * 32u;
    uint8_t *wire = zcl_malloc(total, "zcode.focus.claim_set");
    if (!wire) return VCS_ZCODE_FOCUS_ALLOC;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, total);
    bool ok = zcl_codec_write_bytes(&writer, claim_set_magic, 8) &&
        zcl_codec_write_u16le(&writer, VCS_ZCODE_FOCUS_VERSION) &&
        zcl_codec_write_u16le(&writer, (uint16_t)claim_count);
    for (size_t i = 0; ok && i < claim_count; i++)
        ok = zcl_codec_write_bytes(&writer, claim_roots[i], 32);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != total) {
        free(wire);
        return VCS_ZCODE_FOCUS_SHAPE;
    }
    *wire_out = wire;
    *wire_len = total;
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_set_parse(
    const uint8_t *wire, size_t wire_len,
    uint8_t (*claim_roots)[32], size_t capacity, size_t *claim_count)
{
    if (!wire || !claim_count) return VCS_ZCODE_FOCUS_NULL;
    *claim_count = 0;
    if (wire_len < VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES ||
        wire_len > VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX)
        return VCS_ZCODE_FOCUS_SHAPE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint16_t version, count;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &version) &&
        zcl_codec_read_u16le(&reader, &count);
    if (!ok || memcmp(magic, claim_set_magic, 8) != 0 ||
        version != VCS_ZCODE_FOCUS_VERSION ||
        count > VCS_ZCODE_FOCUS_MAX_CLAIMS || count > capacity ||
        (count > 0 && !claim_roots) ||
        wire_len != VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES +
                    (size_t)count * 32u)
        return VCS_ZCODE_FOCUS_SHAPE;
    for (size_t i = 0; ok && i < count; i++)
        ok = zcl_codec_read_bytes(&reader, claim_roots[i], 32);
    if (!ok || !zcl_codec_reader_finish(&reader))
        return VCS_ZCODE_FOCUS_SHAPE;
    uint8_t *canonical = NULL; size_t canonical_len = 0;
    enum vcs_zcode_focus_error error = vcs_zcode_focus_claim_set_serialize(
        claim_roots, count, &canonical, &canonical_len);
    bool exact = error == VCS_ZCODE_FOCUS_OK && canonical_len == wire_len &&
                 memcmp(canonical, wire, wire_len) == 0;
    free(canonical);
    if (!exact) return error == VCS_ZCODE_FOCUS_OK
        ? VCS_ZCODE_FOCUS_SHAPE : error;
    *claim_count = count;
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_set_root(
    const uint8_t (*claim_roots)[32], size_t claim_count, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_focus_error error = vcs_zcode_focus_claim_set_serialize(
        claim_roots, claim_count, &wire, &wire_len);
    if (error == VCS_ZCODE_FOCUS_OK)
        focus_hash(VCS_ZCODE_FOCUS_CLAIM_SET_DOMAIN, wire, wire_len, out);
    free(wire);
    return error;
}

enum vcs_zcode_focus_error vcs_zcode_focus_situation_root(
    const struct vcs_zcode_focus_v1 *focus, uint8_t out[32])
{
    if (!focus || !out) return VCS_ZCODE_FOCUS_NULL;
    struct vcs_zcode_focus_v1 basis = *focus;
    basis.claim_count = 0;
    enum vcs_zcode_focus_error error = vcs_zcode_focus_claim_set_root(
        NULL, 0, basis.claim_set_root);
    uint8_t wire[VCS_ZCODE_FOCUS_WIRE_BYTES];
    if (error == VCS_ZCODE_FOCUS_OK)
        error = vcs_zcode_focus_serialize(&basis, wire);
    if (error == VCS_ZCODE_FOCUS_OK)
        focus_hash(VCS_ZCODE_FOCUS_SITUATION_DOMAIN, wire, sizeof(wire), out);
    return error;
}

enum vcs_zcode_focus_error vcs_zcode_focus_root(
    const struct vcs_zcode_focus_v1 *focus, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    uint8_t wire[VCS_ZCODE_FOCUS_WIRE_BYTES];
    enum vcs_zcode_focus_error error = vcs_zcode_focus_serialize(focus, wire);
    if (error == VCS_ZCODE_FOCUS_OK)
        focus_hash(VCS_ZCODE_FOCUS_DOMAIN, wire, sizeof(wire), out);
    return error;
}

enum vcs_zcode_focus_error vcs_zcode_focus_compose(
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    const uint8_t context_root[32], const uint8_t story_graph_root[32],
    enum zcl_ontology_status status, uint8_t flags,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    struct vcs_zcode_focus_v1 *out)
{
    if (!task || !task_root || !context_root || !story_graph_root || !out)
        return VCS_ZCODE_FOCUS_NULL;
    memset(out, 0, sizeof(*out));
    uint8_t derived_task[32];
    if (vcs_zcode_task_validate(task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, derived_task) != VCS_ZCODE_DEV_OK ||
        memcmp(derived_task, task_root, 32) != 0)
        return VCS_ZCODE_FOCUS_BINDING;
    if (!zcl_bytes_any_set(context_root, 32) ||
        !zcl_bytes_any_set(story_graph_root, 32))
        return VCS_ZCODE_FOCUS_ROOT_ZERO;
    out->schema_version = VCS_ZCODE_FOCUS_VERSION;
    out->status = (uint8_t)status;
    out->flags = flags;
    out->claim_count = (uint16_t)claim_count;
    out->capabilities = task->capabilities;
    out->max_changed_files = task->max_changed_files;
    out->max_patch_bytes = task->max_patch_bytes;
    out->max_context_bytes = task->max_context_bytes;
    out->max_cpu_seconds = task->max_cpu_seconds;
    out->max_memory_bytes = task->max_memory_bytes;
    out->max_output_bytes = task->max_output_bytes;
    memcpy(out->task_root, task_root, 32);
    memcpy(out->goal_root, task->goal_root, 32);
    memcpy(out->source_universe_root, task->source_root, 32);
    memcpy(out->context_root, context_root, 32);
    memcpy(out->story_graph_root, story_graph_root, 32);
    enum vcs_zcode_focus_error error = vcs_zcode_focus_claim_set_root(
        claim_roots, claim_count, out->claim_set_root);
    uint8_t evidence[64];
    memcpy(evidence, task->acceptance_tests_root, 32);
    memcpy(evidence + 32, task->proof_policy_root, 32);
    focus_derived_root("zcl.focus.required_evidence.v1", evidence,
                       sizeof(evidence), out->required_evidence_root);
    uint8_t authority[108];
    memcpy(authority, task->write_scope_root, 32);
    memcpy(authority + 32, task->model_policy_root, 32);
    memcpy(authority + 64, task_root, 32);
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, authority + 96, 12);
    bool encoded = zcl_codec_write_u32le(&writer, task->capabilities) &&
                   zcl_codec_write_u64le(
                       &writer, (uint64_t)task->expires_unix);
    size_t written = 0;
    encoded = encoded && zcl_codec_writer_finish(&writer, &written) &&
              written == 12;
    if (!encoded) return VCS_ZCODE_FOCUS_SHAPE;
    focus_derived_root("zcl.focus.authority_limits.v1", authority,
                       sizeof(authority), out->authority_limits_root);
    return error == VCS_ZCODE_FOCUS_OK ? vcs_zcode_focus_validate(out) : error;
}
