/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: immutable heuristic proposals and non-authoritative attention bids. */
#include "vcs/zcode_attention_bid.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"

#include <stdbool.h>
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
         heuristic->parent_count == 0))
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
        bid->task_root, bid->source_root, bid->heuristic_root,
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

enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate_for_heuristic(
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

static bool bid_dominates(const struct vcs_zcode_attention_bid_v1 *left,
                          const struct vcs_zcode_attention_bid_v1 *right)
{
    bool no_worse =
        left->expected_user_value_bp >= right->expected_user_value_bp &&
        left->information_gain_bp >= right->information_gain_bp &&
        left->blocker_relief_bp >= right->blocker_relief_bp &&
        left->reuse_potential_bp >= right->reuse_potential_bp &&
        left->evidence_strength_bp >= right->evidence_strength_bp &&
        left->risk_bp <= right->risk_bp &&
        left->overlap_bp <= right->overlap_bp &&
        left->expected_latency_us <= right->expected_latency_us &&
        left->expected_cost_milliunits <= right->expected_cost_milliunits;
    bool strictly_better =
        left->expected_user_value_bp > right->expected_user_value_bp ||
        left->information_gain_bp > right->information_gain_bp ||
        left->blocker_relief_bp > right->blocker_relief_bp ||
        left->reuse_potential_bp > right->reuse_potential_bp ||
        left->evidence_strength_bp > right->evidence_strength_bp ||
        left->risk_bp < right->risk_bp ||
        left->overlap_bp < right->overlap_bp ||
        left->expected_latency_us < right->expected_latency_us ||
        left->expected_cost_milliunits < right->expected_cost_milliunits;
    return no_worse && strictly_better;
}

static bool bid_subject_equal(
    const struct vcs_zcode_attention_bid_v1 *left,
    const struct vcs_zcode_attention_bid_v1 *right)
{
    return memcmp(left->task_root, right->task_root, 32) == 0 &&
        memcmp(left->source_root, right->source_root, 32) == 0 &&
        memcmp(left->heuristic_root, right->heuristic_root, 32) == 0 &&
        memcmp(left->priority_policy_root,
               right->priority_policy_root, 32) == 0 &&
        memcmp(left->bid_evaluator_root,
               right->bid_evaluator_root, 32) == 0 &&
        memcmp(left->evidence_root, right->evidence_root, 32) == 0;
}

enum vcs_zcode_attention_error vcs_zcode_attention_frontier_project(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_frontier_report *report)
{
    if (!query || !report ||
        (bid_count != 0 && (!bids || !heuristics)) ||
        (out_capacity != 0 && !out_indices))
        return VCS_ZCODE_ATTENTION_NULL;
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        return VCS_ZCODE_ATTENTION_COUNT;
    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    index_span *= sizeof(*out_indices);
    if ((bid_count != 0 &&
         (memory_overlaps(report, sizeof(*report), bids,
                          bid_count * sizeof(*bids)) ||
          memory_overlaps(report, sizeof(*report), heuristics,
                          bid_count * sizeof(*heuristics)) ||
          (out_capacity != 0 &&
           (memory_overlaps(out_indices, index_span, bids,
                            bid_count * sizeof(*bids)) ||
            memory_overlaps(out_indices, index_span, heuristics,
                            bid_count * sizeof(*heuristics)))))) ||
        memory_overlaps(report, sizeof(*report), query, sizeof(*query)) ||
        (out_capacity != 0 &&
         (memory_overlaps(out_indices, index_span, query, sizeof(*query)) ||
          memory_overlaps(out_indices, index_span, report,
                          sizeof(*report)))))
        return VCS_ZCODE_ATTENTION_ALIAS;
    struct vcs_zcode_attention_frontier_report result = {
        .input_count = bid_count,
    };
    const uint8_t *const query_roots[] = {
        query->task_root, query->source_root, query->priority_policy_root,
        query->bid_evaluator_root,
    };
    if (!priority_valid(query->priority_class))
        return VCS_ZCODE_ATTENTION_PRIORITY;
    for (size_t i = 0;
         i < sizeof(query_roots) / sizeof(query_roots[0]); i++) {
        if (root_is_zero(query_roots[i])) return VCS_ZCODE_ATTENTION_ROOT;
    }

    uint8_t roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {{0}};
    bool in_class[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    bool dominated[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    for (size_t i = 0; i < bid_count; i++) {
        enum vcs_zcode_attention_error error =
            vcs_zcode_attention_bid_validate_for_heuristic(
                &bids[i], &heuristics[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (memcmp(bids[i].task_root, query->task_root, 32) != 0 ||
            memcmp(bids[i].source_root, query->source_root, 32) != 0 ||
            memcmp(bids[i].priority_policy_root,
                   query->priority_policy_root, 32) != 0 ||
            memcmp(bids[i].bid_evaluator_root,
                   query->bid_evaluator_root, 32) != 0)
            return VCS_ZCODE_ATTENTION_BINDING;
        error = vcs_zcode_attention_bid_root(&bids[i], roots[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(roots[i], roots[j], 32) == 0 ||
                bid_subject_equal(&bids[i], &bids[j]))
                return VCS_ZCODE_ATTENTION_DUPLICATE;
        }
        in_class[i] = bids[i].priority_class == query->priority_class;
        if (in_class[i]) result.class_candidate_count++;
    }
    for (size_t i = 0; i < bid_count; i++) {
        if (!in_class[i]) continue;
        for (size_t j = 0; j < bid_count; j++) {
            if (i != j && in_class[j] && bid_dominates(&bids[j], &bids[i])) {
                dominated[i] = true;
                break;
            }
        }
        if (!dominated[i]) result.frontier_count++;
    }
    if (out_capacity < result.frontier_count) {
        *report = result;
        return VCS_ZCODE_ATTENTION_CAPACITY;
    }
    for (size_t i = 0; i < bid_count; i++) {
        if (!in_class[i] || dominated[i]) continue;
        size_t position = result.returned_count;
        while (position > 0 &&
               memcmp(roots[i], roots[out_indices[position - 1]], 32) < 0) {
            out_indices[position] = out_indices[position - 1];
            position--;
        }
        out_indices[position] = i;
        result.returned_count++;
    }
    *report = result;
    return VCS_ZCODE_ATTENTION_OK;
}
