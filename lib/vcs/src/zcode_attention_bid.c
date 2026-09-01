/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: immutable heuristic proposals and non-authoritative attention bids. */
#include "vcs/zcode_attention_bid.h"

#include "zcode_attention_internal.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t heuristic_magic[8] = {
    'Z', 'C', 'H', 'E', 'U', 'R', '1', '\n'
};
static const uint8_t attention_bid_magic[8] = {
    'Z', 'C', 'A', 'T', 'T', 'N', '1', '\n'
};

static bool root_is_zero(const uint8_t root[32])
{
    return !zcl_bytes_any_set(root, 32);
}

static bool memory_overlaps(const void *left, size_t left_size,
                            const void *right, size_t right_size)
{
    uintptr_t left_address = (uintptr_t)left;
    uintptr_t right_address = (uintptr_t)right;
    if (left_address > UINTPTR_MAX - left_size ||
        right_address > UINTPTR_MAX - right_size)
        return true;
    return left_address < right_address + right_size &&
           right_address < left_address + left_size;
}

static bool roots_are_sorted_unique(const uint8_t roots[][32], size_t count)
{
    for (size_t i = 1; i < count; i++) {
        if (memcmp(roots[i - 1], roots[i], 32) >= 0) return false;
    }
    return true;
}

static bool inactive_roots_are_zero(const uint8_t roots[][32], size_t count,
                                    size_t capacity)
{
    for (size_t i = count; i < capacity; i++) {
        if (!root_is_zero(roots[i])) return false;
    }
    return true;
}

static bool priority_valid(uint8_t priority_class)
{
    return priority_class >= VCS_ZCODE_ATTENTION_P0_SECURITY &&
           priority_class <= VCS_ZCODE_ATTENTION_P3_RESEARCH;
}

const char *vcs_zcode_attention_error_string(
    enum vcs_zcode_attention_error error)
{
    switch (error) {
    case VCS_ZCODE_ATTENTION_OK: return "ok";
    case VCS_ZCODE_ATTENTION_NULL: return "null";
    case VCS_ZCODE_ATTENTION_ALIAS: return "alias";
    case VCS_ZCODE_ATTENTION_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_ATTENTION_MAGIC: return "magic";
    case VCS_ZCODE_ATTENTION_VERSION: return "version";
    case VCS_ZCODE_ATTENTION_RESERVED: return "reserved";
    case VCS_ZCODE_ATTENTION_DERIVATION: return "derivation";
    case VCS_ZCODE_ATTENTION_COUNT: return "count";
    case VCS_ZCODE_ATTENTION_ORDER: return "order";
    case VCS_ZCODE_ATTENTION_ROOT: return "root";
    case VCS_ZCODE_ATTENTION_BUDGET: return "budget";
    case VCS_ZCODE_ATTENTION_PRIORITY: return "priority";
    case VCS_ZCODE_ATTENTION_METRIC: return "metric";
    case VCS_ZCODE_ATTENTION_BINDING: return "binding";
    case VCS_ZCODE_ATTENTION_DUPLICATE: return "duplicate";
    case VCS_ZCODE_ATTENTION_CAPACITY: return "capacity";
    case VCS_ZCODE_ATTENTION_CAS: return "cas";
    case VCS_ZCODE_ATTENTION_EVIDENCE: return "evidence";
    default: return "unknown";
    }
}

void vcs_zcode_heuristic_init(struct vcs_zcode_heuristic_v1 *heuristic)
{
    if (!heuristic) return;
    memset(heuristic, 0, sizeof(*heuristic));
    heuristic->schema_version = VCS_ZCODE_HEURISTIC_VERSION;
    heuristic->derivation = VCS_ZCODE_HEURISTIC_SEED;
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_validate(
    const struct vcs_zcode_heuristic_v1 *heuristic)
{
    if (!heuristic) return VCS_ZCODE_ATTENTION_NULL;
    if (heuristic->schema_version != VCS_ZCODE_HEURISTIC_VERSION)
        return VCS_ZCODE_ATTENTION_VERSION;
    if (heuristic->derivation < VCS_ZCODE_HEURISTIC_SEED ||
        heuristic->derivation > VCS_ZCODE_HEURISTIC_REPAIR)
        return VCS_ZCODE_ATTENTION_DERIVATION;
    if (heuristic->evaluator_count == 0 ||
        heuristic->evaluator_count > VCS_ZCODE_HEURISTIC_MAX_EVALUATORS ||
        heuristic->parent_count > VCS_ZCODE_HEURISTIC_MAX_PARENTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if ((heuristic->derivation == VCS_ZCODE_HEURISTIC_SEED &&
         heuristic->parent_count != 0) ||
        (heuristic->derivation == VCS_ZCODE_HEURISTIC_COMPOSE &&
         heuristic->parent_count < 2) ||
        (heuristic->derivation != VCS_ZCODE_HEURISTIC_SEED &&
         heuristic->derivation != VCS_ZCODE_HEURISTIC_COMPOSE &&
         heuristic->parent_count != 1))
        return VCS_ZCODE_ATTENTION_DERIVATION;
    const uint8_t *const roots[] = {
        heuristic->task_root, heuristic->source_root,
        heuristic->agent_context_root, heuristic->ontology_context_root,
        heuristic->applicability_root, heuristic->observed_features_root,
        heuristic->proposed_rule_root, heuristic->expected_effect_root,
        heuristic->proposal_input_root, heuristic->study_root,
        heuristic->preregistration_root, heuristic->provenance_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        if (root_is_zero(roots[i])) return VCS_ZCODE_ATTENTION_ROOT;
    }
    for (size_t i = 0; i < heuristic->evaluator_count; i++) {
        if (root_is_zero(heuristic->evaluator_roots[i]))
            return VCS_ZCODE_ATTENTION_ROOT;
    }
    for (size_t i = 0; i < heuristic->parent_count; i++) {
        if (root_is_zero(heuristic->parent_roots[i]))
            return VCS_ZCODE_ATTENTION_ROOT;
    }
    if (!roots_are_sorted_unique(heuristic->evaluator_roots,
                                 heuristic->evaluator_count) ||
        !roots_are_sorted_unique(heuristic->parent_roots,
                                 heuristic->parent_count))
        return VCS_ZCODE_ATTENTION_ORDER;
    if (!inactive_roots_are_zero(heuristic->evaluator_roots,
                                 heuristic->evaluator_count,
                                 VCS_ZCODE_HEURISTIC_MAX_EVALUATORS) ||
        !inactive_roots_are_zero(heuristic->parent_roots,
                                 heuristic->parent_count,
                                 VCS_ZCODE_HEURISTIC_MAX_PARENTS))
        return VCS_ZCODE_ATTENTION_RESERVED;
    if (heuristic->requested_cpu_seconds == 0 ||
        heuristic->requested_cpu_seconds >
            VCS_ZCODE_HEURISTIC_MAX_CPU_SECONDS ||
        heuristic->requested_processes == 0 ||
        heuristic->requested_processes >
            VCS_ZCODE_HEURISTIC_MAX_PROCESSES ||
        heuristic->requested_memory_bytes == 0 ||
        heuristic->requested_memory_bytes >
            VCS_ZCODE_HEURISTIC_MAX_MEMORY_BYTES ||
        heuristic->requested_context_bytes == 0 ||
        heuristic->requested_context_bytes >
            VCS_ZCODE_HEURISTIC_MAX_CONTEXT_BYTES ||
        heuristic->requested_output_bytes == 0 ||
        heuristic->requested_output_bytes >
            VCS_ZCODE_HEURISTIC_MAX_OUTPUT_BYTES)
        return VCS_ZCODE_ATTENTION_BUDGET;
    return VCS_ZCODE_ATTENTION_OK;
}

static bool heuristic_lineage_boundary_equal(
    const struct vcs_zcode_heuristic_v1 *left,
    const struct vcs_zcode_heuristic_v1 *right)
{
    return memcmp(left->task_root, right->task_root, 32) == 0 &&
        memcmp(left->source_root, right->source_root, 32) == 0 &&
        memcmp(left->agent_context_root,
               right->agent_context_root, 32) == 0 &&
        memcmp(left->ontology_context_root,
               right->ontology_context_root, 32) == 0 &&
        memcmp(left->study_root, right->study_root, 32) == 0 &&
        memcmp(left->preregistration_root,
               right->preregistration_root, 32) == 0 &&
        left->evaluator_count == right->evaluator_count &&
        memcmp(left->evaluator_roots, right->evaluator_roots,
               sizeof(left->evaluator_roots)) == 0;
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_validate_derivation(
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_validate(heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (parent_count != heuristic->parent_count)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (parent_count == 0)
        return heuristic->derivation == VCS_ZCODE_HEURISTIC_SEED
            ? VCS_ZCODE_ATTENTION_OK : VCS_ZCODE_ATTENTION_DERIVATION;
    if (!parents) return VCS_ZCODE_ATTENTION_NULL;

    for (size_t i = 0; i < parent_count; i++) {
        uint8_t parent_root[32];
        error = vcs_zcode_heuristic_validate(&parents[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        error = vcs_zcode_heuristic_root(&parents[i], parent_root);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (memcmp(parent_root, heuristic->parent_roots[i], 32) != 0 ||
            !heuristic_lineage_boundary_equal(heuristic, &parents[i]))
            return VCS_ZCODE_ATTENTION_BINDING;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_serialize(
    const struct vcs_zcode_heuristic_v1 *heuristic,
    uint8_t out[VCS_ZCODE_HEURISTIC_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_ATTENTION_NULL;
    if (!heuristic) {
        memset(out, 0, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
        return VCS_ZCODE_ATTENTION_NULL;
    }
    if (memory_overlaps(heuristic, sizeof(*heuristic), out,
                        VCS_ZCODE_HEURISTIC_WIRE_BYTES))
        return VCS_ZCODE_ATTENTION_ALIAS;
    memset(out, 0, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_validate(heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, heuristic_magic, 8) &&
        zcl_codec_write_u16le(&writer, heuristic->schema_version) &&
        zcl_codec_write_u8(&writer, heuristic->derivation) &&
        zcl_codec_write_u8(&writer, heuristic->evaluator_count) &&
        zcl_codec_write_u8(&writer, heuristic->parent_count) &&
        zcl_codec_write_bytes(&writer, (const uint8_t[3]){0}, 3);
#define WRITE_ROOT(field_) \
    do { ok = ok && zcl_codec_write_bytes(&writer, heuristic->field_, 32); } while (0)
    WRITE_ROOT(task_root);
    WRITE_ROOT(source_root);
    WRITE_ROOT(agent_context_root);
    WRITE_ROOT(ontology_context_root);
    WRITE_ROOT(applicability_root);
    WRITE_ROOT(observed_features_root);
    WRITE_ROOT(proposed_rule_root);
    WRITE_ROOT(expected_effect_root);
    WRITE_ROOT(proposal_input_root);
    WRITE_ROOT(study_root);
    WRITE_ROOT(preregistration_root);
    WRITE_ROOT(provenance_root);
#undef WRITE_ROOT
    for (size_t i = 0; i < VCS_ZCODE_HEURISTIC_MAX_EVALUATORS; i++)
        ok = ok && zcl_codec_write_bytes(&writer,
                                         heuristic->evaluator_roots[i], 32);
    for (size_t i = 0; i < VCS_ZCODE_HEURISTIC_MAX_PARENTS; i++)
        ok = ok && zcl_codec_write_bytes(&writer,
                                         heuristic->parent_roots[i], 32);
    ok = ok &&
        zcl_codec_write_u32le(&writer, heuristic->requested_cpu_seconds) &&
        zcl_codec_write_u32le(&writer, heuristic->requested_processes) &&
        zcl_codec_write_u64le(&writer, heuristic->requested_memory_bytes) &&
        zcl_codec_write_u64le(&writer, heuristic->requested_context_bytes) &&
        zcl_codec_write_u64le(&writer, heuristic->requested_output_bytes);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != VCS_ZCODE_HEURISTIC_WIRE_BYTES) {
        memset(out, 0, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
        return VCS_ZCODE_ATTENTION_WIRE_SIZE;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_heuristic_v1 *out)
{
    if (!out) return VCS_ZCODE_ATTENTION_NULL;
    if (!wire) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_NULL;
    }
    if (memory_overlaps(wire, wire_len, out, sizeof(*out)))
        return VCS_ZCODE_ATTENTION_ALIAS;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_HEURISTIC_WIRE_BYTES)
        return VCS_ZCODE_ATTENTION_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved[3];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->derivation) &&
        zcl_codec_read_u8(&reader, &out->evaluator_count) &&
        zcl_codec_read_u8(&reader, &out->parent_count) &&
        zcl_codec_read_bytes(&reader, reserved, 3);
#define READ_ROOT(field_) \
    do { ok = ok && zcl_codec_read_bytes(&reader, out->field_, 32); } while (0)
    READ_ROOT(task_root);
    READ_ROOT(source_root);
    READ_ROOT(agent_context_root);
    READ_ROOT(ontology_context_root);
    READ_ROOT(applicability_root);
    READ_ROOT(observed_features_root);
    READ_ROOT(proposed_rule_root);
    READ_ROOT(expected_effect_root);
    READ_ROOT(proposal_input_root);
    READ_ROOT(study_root);
    READ_ROOT(preregistration_root);
    READ_ROOT(provenance_root);
#undef READ_ROOT
    for (size_t i = 0; i < VCS_ZCODE_HEURISTIC_MAX_EVALUATORS; i++)
        ok = ok && zcl_codec_read_bytes(&reader, out->evaluator_roots[i], 32);
    for (size_t i = 0; i < VCS_ZCODE_HEURISTIC_MAX_PARENTS; i++)
        ok = ok && zcl_codec_read_bytes(&reader, out->parent_roots[i], 32);
    ok = ok &&
        zcl_codec_read_u32le(&reader, &out->requested_cpu_seconds) &&
        zcl_codec_read_u32le(&reader, &out->requested_processes) &&
        zcl_codec_read_u64le(&reader, &out->requested_memory_bytes) &&
        zcl_codec_read_u64le(&reader, &out->requested_context_bytes) &&
        zcl_codec_read_u64le(&reader, &out->requested_output_bytes) &&
        zcl_codec_reader_finish(&reader);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_WIRE_SIZE;
    }
    if (memcmp(magic, heuristic_magic, 8) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_MAGIC;
    }
    if (memcmp(reserved, (const uint8_t[3]){0}, 3) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_RESERVED;
    }
    enum vcs_zcode_attention_error error = vcs_zcode_heuristic_validate(out);
    if (error != VCS_ZCODE_ATTENTION_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_root(
    const struct vcs_zcode_heuristic_v1 *heuristic, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_ATTENTION_NULL;
    if (!heuristic) {
        memset(out, 0, 32);
        return VCS_ZCODE_ATTENTION_NULL;
    }
    if (memory_overlaps(heuristic, sizeof(*heuristic), out, 32))
        return VCS_ZCODE_ATTENTION_ALIAS;
    memset(out, 0, 32);
    uint8_t wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_serialize(heuristic, wire);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_HEURISTIC_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_ATTENTION_OK;
}

void vcs_zcode_attention_bid_init(struct vcs_zcode_attention_bid_v1 *bid)
{
    if (!bid) return;
    memset(bid, 0, sizeof(*bid));
    bid->schema_version = VCS_ZCODE_ATTENTION_BID_VERSION;
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate(
    const struct vcs_zcode_attention_bid_v1 *bid)
{
    if (!bid) return VCS_ZCODE_ATTENTION_NULL;
    if (bid->schema_version != VCS_ZCODE_ATTENTION_BID_VERSION)
        return VCS_ZCODE_ATTENTION_VERSION;
    if (!priority_valid(bid->priority_class))
        return VCS_ZCODE_ATTENTION_PRIORITY;
    const uint8_t *const required_roots[] = {
        bid->focus_root, bid->task_root, bid->source_root, bid->heuristic_root,
        bid->priority_policy_root, bid->bid_evaluator_root,
        bid->evidence_root,
    };
    for (size_t i = 0;
         i < sizeof(required_roots) / sizeof(required_roots[0]); i++) {
        if (root_is_zero(required_roots[i])) return VCS_ZCODE_ATTENTION_ROOT;
    }
    const uint16_t metrics[] = {
        bid->expected_user_value_bp, bid->information_gain_bp,
        bid->blocker_relief_bp, bid->reuse_potential_bp,
        bid->evidence_strength_bp, bid->risk_bp, bid->overlap_bp,
    };
    for (size_t i = 0; i < sizeof(metrics) / sizeof(metrics[0]); i++) {
        if (metrics[i] > VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX)
            return VCS_ZCODE_ATTENTION_METRIC;
    }
    if (bid->observed_metrics != VCS_ZCODE_ATTENTION_METRIC_REQUIRED)
        return VCS_ZCODE_ATTENTION_METRIC;
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error attention_bid_validate_binding(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_attention_bid_validate(bid);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    error = vcs_zcode_heuristic_validate(heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    uint8_t heuristic_root[32];
    error = vcs_zcode_heuristic_root(heuristic, heuristic_root);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (memcmp(bid->heuristic_root, heuristic_root, 32) != 0 ||
        memcmp(bid->task_root, heuristic->task_root, 32) != 0 ||
        memcmp(bid->source_root, heuristic->source_root, 32) != 0)
        return VCS_ZCODE_ATTENTION_BINDING;
    for (size_t i = 0; i < heuristic->evaluator_count; i++) {
        if (memcmp(bid->bid_evaluator_root,
                   heuristic->evaluator_roots[i], 32) == 0)
            return VCS_ZCODE_ATTENTION_OK;
    }
    return VCS_ZCODE_ATTENTION_BINDING;
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate_for_heuristic(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_validate(heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (heuristic->derivation != VCS_ZCODE_HEURISTIC_SEED)
        return VCS_ZCODE_ATTENTION_DERIVATION;
    return attention_bid_validate_binding(bid, heuristic);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_bid_validate_for_derivation(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_validate_derivation(
            heuristic, parents, parent_count);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (heuristic->derivation == VCS_ZCODE_HEURISTIC_SEED)
        return VCS_ZCODE_ATTENTION_DERIVATION;
    return attention_bid_validate_binding(bid, heuristic);
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate_for_focus(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_attention_bid_validate_for_heuristic(bid, heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    return vcs_zcode_attention_bid_validate_focus_binding(
        bid, heuristic, focus);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_bid_validate_focus_binding(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus)
{
    uint8_t focus_root[32];
    if (vcs_zcode_focus_root(focus, focus_root) != VCS_ZCODE_FOCUS_OK)
        return VCS_ZCODE_ATTENTION_BINDING;
    if (memcmp(bid->focus_root, focus_root, 32) != 0 ||
        memcmp(focus->task_root, heuristic->task_root, 32) != 0 ||
        memcmp(focus->source_universe_root,
               heuristic->source_root, 32) != 0 ||
        memcmp(focus->context_root,
               heuristic->agent_context_root, 32) != 0 ||
        memcmp(focus->story_graph_root,
               heuristic->ontology_context_root, 32) != 0 ||
        heuristic->requested_cpu_seconds > focus->max_cpu_seconds ||
        heuristic->requested_memory_bytes > focus->max_memory_bytes ||
        heuristic->requested_context_bytes > focus->max_context_bytes ||
        heuristic->requested_output_bytes > focus->max_output_bytes)
        return VCS_ZCODE_ATTENTION_BINDING;
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_serialize(
    const struct vcs_zcode_attention_bid_v1 *bid,
    uint8_t out[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_ATTENTION_NULL;
    if (!bid) {
        memset(out, 0, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES);
        return VCS_ZCODE_ATTENTION_NULL;
    }
    if (memory_overlaps(bid, sizeof(*bid), out,
                        VCS_ZCODE_ATTENTION_BID_WIRE_BYTES))
        return VCS_ZCODE_ATTENTION_ALIAS;
    memset(out, 0, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES);
    enum vcs_zcode_attention_error error =
        vcs_zcode_attention_bid_validate(bid);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, attention_bid_magic, 8) &&
        zcl_codec_write_u16le(&writer, bid->schema_version) &&
        zcl_codec_write_u8(&writer, bid->priority_class) &&
        zcl_codec_write_bytes(&writer, (const uint8_t[5]){0}, 5);
#define WRITE_ROOT(field_) \
    do { ok = ok && zcl_codec_write_bytes(&writer, bid->field_, 32); } while (0)
    WRITE_ROOT(focus_root);
    WRITE_ROOT(task_root);
    WRITE_ROOT(source_root);
    WRITE_ROOT(heuristic_root);
    WRITE_ROOT(priority_policy_root);
    WRITE_ROOT(bid_evaluator_root);
    WRITE_ROOT(evidence_root);
#undef WRITE_ROOT
    ok = ok &&
        zcl_codec_write_u16le(&writer, bid->expected_user_value_bp) &&
        zcl_codec_write_u16le(&writer, bid->information_gain_bp) &&
        zcl_codec_write_u16le(&writer, bid->blocker_relief_bp) &&
        zcl_codec_write_u16le(&writer, bid->reuse_potential_bp) &&
        zcl_codec_write_u16le(&writer, bid->evidence_strength_bp) &&
        zcl_codec_write_u16le(&writer, bid->risk_bp) &&
        zcl_codec_write_u16le(&writer, bid->overlap_bp) &&
        zcl_codec_write_u16le(&writer, bid->observed_metrics) &&
        zcl_codec_write_u64le(&writer, bid->expected_latency_us) &&
        zcl_codec_write_u64le(&writer, bid->expected_cost_milliunits);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != VCS_ZCODE_ATTENTION_BID_WIRE_BYTES) {
        memset(out, 0, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES);
        return VCS_ZCODE_ATTENTION_WIRE_SIZE;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_attention_bid_v1 *out)
{
    if (!out) return VCS_ZCODE_ATTENTION_NULL;
    if (!wire) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_NULL;
    }
    if (memory_overlaps(wire, wire_len, out, sizeof(*out)))
        return VCS_ZCODE_ATTENTION_ALIAS;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_ATTENTION_BID_WIRE_BYTES)
        return VCS_ZCODE_ATTENTION_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved[5];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->priority_class) &&
        zcl_codec_read_bytes(&reader, reserved, 5);
#define READ_ROOT(field_) \
    do { ok = ok && zcl_codec_read_bytes(&reader, out->field_, 32); } while (0)
    READ_ROOT(focus_root);
    READ_ROOT(task_root);
    READ_ROOT(source_root);
    READ_ROOT(heuristic_root);
    READ_ROOT(priority_policy_root);
    READ_ROOT(bid_evaluator_root);
    READ_ROOT(evidence_root);
#undef READ_ROOT
    ok = ok &&
        zcl_codec_read_u16le(&reader, &out->expected_user_value_bp) &&
        zcl_codec_read_u16le(&reader, &out->information_gain_bp) &&
        zcl_codec_read_u16le(&reader, &out->blocker_relief_bp) &&
        zcl_codec_read_u16le(&reader, &out->reuse_potential_bp) &&
        zcl_codec_read_u16le(&reader, &out->evidence_strength_bp) &&
        zcl_codec_read_u16le(&reader, &out->risk_bp) &&
        zcl_codec_read_u16le(&reader, &out->overlap_bp) &&
        zcl_codec_read_u16le(&reader, &out->observed_metrics) &&
        zcl_codec_read_u64le(&reader, &out->expected_latency_us) &&
        zcl_codec_read_u64le(&reader, &out->expected_cost_milliunits) &&
        zcl_codec_reader_finish(&reader);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_WIRE_SIZE;
    }
    if (memcmp(magic, attention_bid_magic, 8) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_MAGIC;
    }
    if (memcmp(reserved, (const uint8_t[5]){0}, 5) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_ATTENTION_RESERVED;
    }
    enum vcs_zcode_attention_error error =
        vcs_zcode_attention_bid_validate(out);
    if (error != VCS_ZCODE_ATTENTION_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_root(
    const struct vcs_zcode_attention_bid_v1 *bid, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_ATTENTION_NULL;
    if (!bid) {
        memset(out, 0, 32);
        return VCS_ZCODE_ATTENTION_NULL;
    }
    if (memory_overlaps(bid, sizeof(*bid), out, 32))
        return VCS_ZCODE_ATTENTION_ALIAS;
    memset(out, 0, 32);
    uint8_t wire[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES];
    enum vcs_zcode_attention_error error =
        vcs_zcode_attention_bid_serialize(bid, wire);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_ATTENTION_BID_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_ATTENTION_OK;
}

static bool heuristic_readback_exact(
    const char *workspace, const uint8_t expected_root[32],
    const uint8_t expected_wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES],
    struct vcs_zcode_heuristic_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t checked_root[32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, expected_root, VCS_ZCODE_HEURISTIC_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        wire_len == VCS_ZCODE_HEURISTIC_WIRE_BYTES &&
        memcmp(wire, expected_wire, VCS_ZCODE_HEURISTIC_WIRE_BYTES) == 0 &&
        vcs_zcode_heuristic_parse(wire, wire_len, out) ==
            VCS_ZCODE_ATTENTION_OK &&
        vcs_zcode_heuristic_root(out, checked_root) ==
            VCS_ZCODE_ATTENTION_OK &&
        memcmp(checked_root, expected_root, 32) == 0;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static bool heuristic_load_exact(
    const char *workspace, const uint8_t expected_root[32],
    struct vcs_zcode_heuristic_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t checked_root[32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, expected_root, VCS_ZCODE_HEURISTIC_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        wire_len == VCS_ZCODE_HEURISTIC_WIRE_BYTES &&
        vcs_zcode_heuristic_parse(wire, wire_len, out) ==
            VCS_ZCODE_ATTENTION_OK &&
        vcs_zcode_heuristic_root(out, checked_root) ==
            VCS_ZCODE_ATTENTION_OK &&
        memcmp(checked_root, expected_root, 32) == 0;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static bool bid_readback_exact(
    const char *workspace, const uint8_t expected_root[32],
    const uint8_t expected_wire[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES],
    struct vcs_zcode_attention_bid_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t checked_root[32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, expected_root, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        wire_len == VCS_ZCODE_ATTENTION_BID_WIRE_BYTES &&
        memcmp(wire, expected_wire, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES) == 0 &&
        vcs_zcode_attention_bid_parse(wire, wire_len, out) ==
            VCS_ZCODE_ATTENTION_OK &&
        vcs_zcode_attention_bid_root(out, checked_root) ==
            VCS_ZCODE_ATTENTION_OK &&
        memcmp(checked_root, expected_root, 32) == 0;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

enum vcs_zcode_attention_error vcs_zcode_attention_store_pair(
    const char *workspace,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_attention_bid_v1 *bid,
    uint8_t heuristic_root_out[32], uint8_t bid_root_out[32])
{
    size_t workspace_bytes = workspace ? strlen(workspace) + 1u : 0u;
    bool alias = heuristic_root_out && bid_root_out &&
            memory_overlaps(heuristic_root_out, 32, bid_root_out, 32);
    alias = alias || (heuristic_root_out && heuristic &&
            memory_overlaps(heuristic_root_out, 32, heuristic,
                            sizeof(*heuristic))) ||
        (heuristic_root_out && bid &&
            memory_overlaps(heuristic_root_out, 32, bid, sizeof(*bid))) ||
        (heuristic_root_out && workspace &&
            memory_overlaps(heuristic_root_out, 32, workspace,
                            workspace_bytes)) ||
        (bid_root_out && heuristic &&
            memory_overlaps(bid_root_out, 32, heuristic,
                            sizeof(*heuristic))) ||
        (bid_root_out && bid &&
            memory_overlaps(bid_root_out, 32, bid, sizeof(*bid))) ||
        (bid_root_out && workspace &&
            memory_overlaps(bid_root_out, 32, workspace, workspace_bytes));
    if (alias)
        return VCS_ZCODE_ATTENTION_ALIAS;
    if (!heuristic_root_out || !bid_root_out || !workspace || !heuristic ||
        !bid) {
        if (heuristic_root_out) memset(heuristic_root_out, 0, 32);
        if (bid_root_out) memset(bid_root_out, 0, 32);
        return VCS_ZCODE_ATTENTION_NULL;
    }
    memset(heuristic_root_out, 0, 32);
    memset(bid_root_out, 0, 32);

    enum vcs_zcode_attention_error error = vcs_zcode_heuristic_validate(
        heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    struct vcs_zcode_heuristic_v1
        parents[VCS_ZCODE_HEURISTIC_MAX_PARENTS];
    memset(parents, 0, sizeof(parents));
    for (size_t i = 0; i < heuristic->parent_count; i++) {
        if (!heuristic_load_exact(
                workspace, heuristic->parent_roots[i], &parents[i]))
            return VCS_ZCODE_ATTENTION_CAS;
    }
    if (heuristic->derivation == VCS_ZCODE_HEURISTIC_SEED) {
        error = vcs_zcode_attention_bid_validate_for_heuristic(
            bid, heuristic);
    } else {
        error = vcs_zcode_attention_bid_validate_for_derivation(
            bid, heuristic, parents, heuristic->parent_count);
    }
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    uint8_t heuristic_wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
    uint8_t bid_wire[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES];
    uint8_t heuristic_root[32], bid_root[32];
    error = vcs_zcode_heuristic_serialize(heuristic, heuristic_wire);
    if (error == VCS_ZCODE_ATTENTION_OK)
        error = vcs_zcode_attention_bid_serialize(bid, bid_wire);
    if (error == VCS_ZCODE_ATTENTION_OK)
        error = vcs_zcode_heuristic_root(heuristic, heuristic_root);
    if (error == VCS_ZCODE_ATTENTION_OK)
        error = vcs_zcode_attention_bid_root(bid, bid_root);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    if (!vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(
            workspace, heuristic_root, heuristic_wire,
            sizeof(heuristic_wire)))
        return VCS_ZCODE_ATTENTION_CAS;
    struct vcs_zcode_heuristic_v1 checked_heuristic;
    if (!heuristic_readback_exact(
            workspace, heuristic_root, heuristic_wire, &checked_heuristic))
        return VCS_ZCODE_ATTENTION_CAS;

    if (!vcs_object_put_addressed(
            workspace, bid_root, bid_wire, sizeof(bid_wire)))
        return VCS_ZCODE_ATTENTION_CAS;
    struct vcs_zcode_attention_bid_v1 checked_bid;
    if (!bid_readback_exact(workspace, bid_root, bid_wire, &checked_bid))
        return VCS_ZCODE_ATTENTION_CAS;
    if (checked_heuristic.derivation == VCS_ZCODE_HEURISTIC_SEED) {
        error = vcs_zcode_attention_bid_validate_for_heuristic(
            &checked_bid, &checked_heuristic);
    } else {
        error = vcs_zcode_attention_bid_validate_for_derivation(
            &checked_bid, &checked_heuristic, parents,
            checked_heuristic.parent_count);
    }
    if (error != VCS_ZCODE_ATTENTION_OK) return VCS_ZCODE_ATTENTION_CAS;

    memcpy(heuristic_root_out, heuristic_root, 32);
    memcpy(bid_root_out, bid_root, 32);
    return VCS_ZCODE_ATTENTION_OK;
}
