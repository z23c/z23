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

static enum vcs_zcode_focus_error focus_validate_limits(
    const struct vcs_zcode_focus_v1 *focus)
{
    if (focus->claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS ||
        focus->max_changed_files == 0 ||
        focus->max_changed_files > 4096 ||
        focus->max_patch_bytes == 0 ||
        focus->max_patch_bytes > VCS_ZCODE_TASK_MAX_PATCH_BYTES ||
        focus->max_context_bytes == 0 ||
        focus->max_context_bytes > VCS_ZCODE_TASK_MAX_CONTEXT_BYTES)
        return VCS_ZCODE_FOCUS_LIMIT;
    return VCS_ZCODE_FOCUS_OK;
}

static enum vcs_zcode_focus_error focus_validate_budget(
    const struct vcs_zcode_focus_v1 *focus)
{
    if (focus->max_cpu_seconds == 0 || focus->max_cpu_seconds > 3600 ||
        focus->max_memory_bytes < UINT64_C(1024) * 1024u ||
        focus->max_memory_bytes > VCS_ZCODE_TASK_MAX_MEMORY_BYTES ||
        focus->max_output_bytes == 0 ||
        focus->max_output_bytes > VCS_ZCODE_TASK_MAX_OUTPUT_BYTES)
        return VCS_ZCODE_FOCUS_LIMIT;
    return VCS_ZCODE_FOCUS_OK;
}

static enum vcs_zcode_focus_error focus_validate_capabilities(
    const struct vcs_zcode_focus_v1 *focus)
{
    const uint32_t required = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                              VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    if ((focus->capabilities & required) != required ||
        (focus->capabilities & ~VCS_ZCODE_TASK_CAP_V1_MASK) != 0)
        return VCS_ZCODE_FOCUS_SHAPE;
    return VCS_ZCODE_FOCUS_OK;
}

/* The eight 32-byte roots, in wire order, as byte offsets into the struct. */
#define FOCUS_ROOT_COUNT 8u
static const size_t focus_root_offsets[FOCUS_ROOT_COUNT] = {
    offsetof(struct vcs_zcode_focus_v1, task_root),
    offsetof(struct vcs_zcode_focus_v1, goal_root),
    offsetof(struct vcs_zcode_focus_v1, source_universe_root),
    offsetof(struct vcs_zcode_focus_v1, context_root),
    offsetof(struct vcs_zcode_focus_v1, story_graph_root),
    offsetof(struct vcs_zcode_focus_v1, claim_set_root),
    offsetof(struct vcs_zcode_focus_v1, required_evidence_root),
    offsetof(struct vcs_zcode_focus_v1, authority_limits_root),
};

static const uint8_t *focus_root_at(const struct vcs_zcode_focus_v1 *focus,
                                    size_t index)
{
    return (const uint8_t *)focus + focus_root_offsets[index];
}

static uint8_t *focus_root_at_mut(struct vcs_zcode_focus_v1 *out, size_t index)
{
    return (uint8_t *)out + focus_root_offsets[index];
}

static enum vcs_zcode_focus_error focus_validate_roots(
    const struct vcs_zcode_focus_v1 *focus)
{
    for (size_t i = 0; i < FOCUS_ROOT_COUNT; i++)
        if (!zcl_bytes_any_set(focus_root_at(focus, i), 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
    return VCS_ZCODE_FOCUS_OK;
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
    enum vcs_zcode_focus_error error = focus_validate_limits(focus);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    error = focus_validate_budget(focus);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    error = focus_validate_capabilities(focus);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    return focus_validate_roots(focus);
}

static bool focus_write_header(struct zcl_codec_writer *writer,
                               const struct vcs_zcode_focus_v1 *focus)
{
    return zcl_codec_write_bytes(writer, focus_magic, 8) &&
        zcl_codec_write_u16le(writer, focus->schema_version) &&
        zcl_codec_write_u8(writer, focus->status) &&
        zcl_codec_write_u8(writer, focus->flags) &&
        zcl_codec_write_u16le(writer, focus->claim_count) &&
        zcl_codec_write_u16le(writer, focus->reserved) &&
        zcl_codec_write_u32le(writer, focus->capabilities);
}

/* The seven budget fields in wire order; width is the integer size in bytes. */
#define FOCUS_LIMIT_COUNT 7u
struct focus_limit_field {
    size_t offset;
    size_t width;
};
static const struct focus_limit_field focus_limit_fields[FOCUS_LIMIT_COUNT] = {
    { offsetof(struct vcs_zcode_focus_v1, max_changed_files), 4 },
    { offsetof(struct vcs_zcode_focus_v1, max_patch_bytes), 8 },
    { offsetof(struct vcs_zcode_focus_v1, max_context_bytes), 8 },
    { offsetof(struct vcs_zcode_focus_v1, max_cpu_seconds), 4 },
    { offsetof(struct vcs_zcode_focus_v1, reserved_budget), 4 },
    { offsetof(struct vcs_zcode_focus_v1, max_memory_bytes), 8 },
    { offsetof(struct vcs_zcode_focus_v1, max_output_bytes), 8 },
};

static bool focus_write_limits(struct zcl_codec_writer *writer,
                               const struct vcs_zcode_focus_v1 *focus)
{
    for (size_t i = 0; i < FOCUS_LIMIT_COUNT; i++) {
        const struct focus_limit_field *field = &focus_limit_fields[i];
        const uint8_t *at = (const uint8_t *)focus + field->offset;
        bool ok = field->width == 4
            ? zcl_codec_write_u32le(writer, *(const uint32_t *)at)
            : zcl_codec_write_u64le(writer, *(const uint64_t *)at);
        if (!ok) return false;
    }
    return true;
}

static bool focus_write_roots(struct zcl_codec_writer *writer,
                              const struct vcs_zcode_focus_v1 *focus)
{
    for (size_t i = 0; i < FOCUS_ROOT_COUNT; i++)
        if (!zcl_codec_write_bytes(writer, focus_root_at(focus, i), 32))
            return false;
    return true;
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
    bool ok = focus_write_header(&writer, focus) &&
        focus_write_limits(&writer, focus) &&
        focus_write_roots(&writer, focus);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_FOCUS_WIRE_BYTES
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_SHAPE;
}

static bool focus_read_header(struct zcl_codec_reader *reader,
                              uint8_t magic[8],
                              struct vcs_zcode_focus_v1 *out)
{
    return zcl_codec_read_bytes(reader, magic, 8) &&
        zcl_codec_read_u16le(reader, &out->schema_version) &&
        zcl_codec_read_u8(reader, &out->status) &&
        zcl_codec_read_u8(reader, &out->flags) &&
        zcl_codec_read_u16le(reader, &out->claim_count) &&
        zcl_codec_read_u16le(reader, &out->reserved) &&
        zcl_codec_read_u32le(reader, &out->capabilities);
}

static bool focus_read_limits(struct zcl_codec_reader *reader,
                              struct vcs_zcode_focus_v1 *out)
{
    for (size_t i = 0; i < FOCUS_LIMIT_COUNT; i++) {
        const struct focus_limit_field *field = &focus_limit_fields[i];
        uint8_t *at = (uint8_t *)out + field->offset;
        bool ok = field->width == 4
            ? zcl_codec_read_u32le(reader, (uint32_t *)at)
            : zcl_codec_read_u64le(reader, (uint64_t *)at);
        if (!ok) return false;
    }
    return true;
}

static bool focus_read_roots(struct zcl_codec_reader *reader,
                             struct vcs_zcode_focus_v1 *out)
{
    for (size_t i = 0; i < FOCUS_ROOT_COUNT; i++)
        if (!zcl_codec_read_bytes(reader, focus_root_at_mut(out, i), 32))
            return false;
    return true;
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
    bool ok = focus_read_header(&reader, magic, out) &&
        focus_read_limits(&reader, out) &&
        focus_read_roots(&reader, out) &&
        zcl_codec_reader_finish(&reader) &&
        memcmp(magic, focus_magic, 8) == 0;
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_FOCUS_SHAPE;
    }
    return vcs_zcode_focus_validate(out);
}

static enum vcs_zcode_focus_error focus_claim_set_check(
    const uint8_t (*claim_roots)[32], size_t claim_count)
{
    for (size_t i = 0; i < claim_count; i++) {
        if (!zcl_bytes_any_set(claim_roots[i], 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
        if (i > 0) {
            int order = memcmp(claim_roots[i - 1u], claim_roots[i], 32);
            if (order == 0) return VCS_ZCODE_FOCUS_DUPLICATE;
            if (order > 0) return VCS_ZCODE_FOCUS_ORDER;
        }
    }
    return VCS_ZCODE_FOCUS_OK;
}

static enum vcs_zcode_focus_error focus_claim_set_encode(
    uint8_t *wire, size_t total,
    const uint8_t (*claim_roots)[32], size_t claim_count)
{
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, total);
    bool ok = zcl_codec_write_bytes(&writer, claim_set_magic, 8) &&
        zcl_codec_write_u16le(&writer, VCS_ZCODE_FOCUS_VERSION) &&
        zcl_codec_write_u16le(&writer, (uint16_t)claim_count);
    for (size_t i = 0; ok && i < claim_count; i++)
        ok = zcl_codec_write_bytes(&writer, claim_roots[i], 32);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != total)
        return VCS_ZCODE_FOCUS_SHAPE;
    return VCS_ZCODE_FOCUS_OK;
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
    enum vcs_zcode_focus_error error =
        focus_claim_set_check(claim_roots, claim_count);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    size_t total = VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES +
                   claim_count * 32u;
    uint8_t *wire = zcl_malloc(total, "zcode.focus.claim_set");
    if (!wire) return VCS_ZCODE_FOCUS_ALLOC;
    error = focus_claim_set_encode(wire, total, claim_roots, claim_count);
    if (error != VCS_ZCODE_FOCUS_OK) {
        free(wire);
        return error;
    }
    *wire_out = wire;
    *wire_len = total;
    return VCS_ZCODE_FOCUS_OK;
}

static bool focus_claim_set_read_header(struct zcl_codec_reader *reader,
                                        uint8_t magic[8], uint16_t *version,
                                        uint16_t *count)
{
    return zcl_codec_read_bytes(reader, magic, 8) &&
        zcl_codec_read_u16le(reader, version) &&
        zcl_codec_read_u16le(reader, count);
}

static enum vcs_zcode_focus_error focus_claim_set_check_header(
    bool ok, const uint8_t magic[8], uint16_t version, uint16_t count,
    size_t wire_len, size_t capacity, const uint8_t (*claim_roots)[32])
{
    if (!ok || memcmp(magic, claim_set_magic, 8) != 0 ||
        version != VCS_ZCODE_FOCUS_VERSION ||
        count > VCS_ZCODE_FOCUS_MAX_CLAIMS || count > capacity ||
        (count > 0 && !claim_roots) ||
        wire_len != VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES +
                    (size_t)count * 32u)
        return VCS_ZCODE_FOCUS_SHAPE;
    return VCS_ZCODE_FOCUS_OK;
}

static bool focus_claim_set_read_roots(struct zcl_codec_reader *reader,
                                       uint8_t (*claim_roots)[32],
                                       size_t count)
{
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++)
        ok = zcl_codec_read_bytes(reader, claim_roots[i], 32);
    return ok;
}

static enum vcs_zcode_focus_error focus_claim_set_canonical(
    const uint8_t *wire, size_t wire_len,
    const uint8_t (*claim_roots)[32], size_t count)
{
    uint8_t *canonical = NULL; size_t canonical_len = 0;
    enum vcs_zcode_focus_error error = vcs_zcode_focus_claim_set_serialize(
        claim_roots, count, &canonical, &canonical_len);
    bool exact = error == VCS_ZCODE_FOCUS_OK && canonical_len == wire_len &&
                 memcmp(canonical, wire, wire_len) == 0;
    free(canonical);
    if (!exact) return error == VCS_ZCODE_FOCUS_OK
        ? VCS_ZCODE_FOCUS_SHAPE : error;
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
    bool ok = focus_claim_set_read_header(&reader, magic, &version, &count);
    enum vcs_zcode_focus_error error = focus_claim_set_check_header(
        ok, magic, version, count, wire_len, capacity, claim_roots);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    ok = focus_claim_set_read_roots(&reader, claim_roots, count);
    if (!ok || !zcl_codec_reader_finish(&reader))
        return VCS_ZCODE_FOCUS_SHAPE;
    error = focus_claim_set_canonical(wire, wire_len, claim_roots, count);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
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

static enum vcs_zcode_focus_error focus_compose_check_task(
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32])
{
    uint8_t derived_task[32];
    if (vcs_zcode_task_validate(task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, derived_task) != VCS_ZCODE_DEV_OK ||
        memcmp(derived_task, task_root, 32) != 0)
        return VCS_ZCODE_FOCUS_BINDING;
    return VCS_ZCODE_FOCUS_OK;
}

static void focus_compose_evidence(const struct vcs_zcode_task_v1 *task,
                                   struct vcs_zcode_focus_v1 *out)
{
    uint8_t evidence[64];
    memcpy(evidence, task->acceptance_tests_root, 32);
    memcpy(evidence + 32, task->proof_policy_root, 32);
    focus_derived_root("zcl.focus.required_evidence.v1", evidence,
                       sizeof(evidence), out->required_evidence_root);
}

static enum vcs_zcode_focus_error focus_compose_authority(
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    struct vcs_zcode_focus_v1 *out)
{
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
    return VCS_ZCODE_FOCUS_OK;
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
    enum vcs_zcode_focus_error binding =
        focus_compose_check_task(task, task_root);
    if (binding != VCS_ZCODE_FOCUS_OK) return binding;
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
    focus_compose_evidence(task, out);
    enum vcs_zcode_focus_error authority =
        focus_compose_authority(task, task_root, out);
    if (authority != VCS_ZCODE_FOCUS_OK) return authority;
    return error == VCS_ZCODE_FOCUS_OK ? vcs_zcode_focus_validate(out) : error;
}

enum vcs_zcode_focus_error vcs_zcode_focus_validate_for_context(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_agent_context_v1 *context,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    bool require_complete)
{
    if (!focus || !task || !context)
        return VCS_ZCODE_FOCUS_NULL;
    uint8_t task_root[32], context_root[32];
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_agent_context_root(
            context, task->max_context_bytes, context_root) !=
            VCS_ZCODE_AGENT_CONTEXT_OK)
        return VCS_ZCODE_FOCUS_BINDING;
    enum vcs_zcode_agent_context_result context_result =
        vcs_zcode_agent_context_validate_for_task(
            context, task, task_root, focus->context_root, require_complete);
    if (context_result == VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE)
        return VCS_ZCODE_FOCUS_INCOMPLETE;
    if (context_result != VCS_ZCODE_AGENT_CONTEXT_OK ||
        memcmp(context_root, focus->context_root, 32) != 0)
        return VCS_ZCODE_FOCUS_BINDING;
    uint8_t flags = (context->flags & VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0
        ? VCS_ZCODE_FOCUS_CONTEXT_TRUNCATED : 0;
    struct vcs_zcode_focus_v1 expected;
    enum vcs_zcode_focus_error error = vcs_zcode_focus_compose(
        task, task_root, context_root, focus->story_graph_root,
        (enum zcl_ontology_status)focus->status, flags,
        claim_roots, claim_count, &expected);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    uint8_t received_root[32], expected_root[32];
    if (vcs_zcode_focus_root(focus, received_root) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_root(&expected, expected_root) != VCS_ZCODE_FOCUS_OK)
        return VCS_ZCODE_FOCUS_SHAPE;
    return memcmp(received_root, expected_root, 32) == 0
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_BINDING;
}
