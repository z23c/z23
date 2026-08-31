/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Encode and verify bounded semantic-duplicate candidate evidence. */

#include "codeindex/codeindex_semantic_candidate.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

static const uint8_t semantic_magic[8] = {
    'Z', 'C', 'S', 'E', 'M', 'C', '1', 0,
};
static const char semantic_domain[] = "zcl.code_semantic_candidate.v1";

_Static_assert(ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED == 0 &&
                   ZCL_CODE_SEMANTIC_EVIDENCE_MATCH == 1 &&
                   ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH == 2 &&
                   ZCL_CODE_SEMANTIC_EVIDENCE_INCOMPLETE == 3 &&
                   ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE == 1 &&
                   ZCL_CODE_SEMANTIC_VERDICT_MISMATCH == 2 &&
                   ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE == 3 &&
                   ZCL_CODE_SEMANTIC_VECTOR_ABSENT == 0 &&
                   ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT == 1,
               "semantic-candidate wire enums are append-only");
_Static_assert(ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES ==
                   8 + 8 + 8 + 4 * 4 + 15 * 32,
               "semantic-candidate wire size drift");

static bool root_present(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static bool ranges_overlap(const void *a, size_t a_len,
                           const void *b, size_t b_len)
{
    uintptr_t a_start, a_end, b_start, b_end;
    if (!a || !b || a_len == 0 || b_len == 0) return false;
    a_start = (uintptr_t)a;
    b_start = (uintptr_t)b;
    if (a_len > UINTPTR_MAX - a_start || b_len > UINTPTR_MAX - b_start)
        return true;
    a_end = a_start + a_len;
    b_end = b_start + b_len;
    return a_start < b_end && b_start < a_end;
}

static bool evidence_state_valid(uint8_t state)
{
    return state <= ZCL_CODE_SEMANTIC_EVIDENCE_INCOMPLETE;
}

static bool verdict_valid(uint8_t verdict)
{
    return verdict >= ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE &&
           verdict <= ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE;
}

static enum zcl_code_semantic_candidate_error evidence_root_valid(
    uint8_t state, const uint8_t root[32])
{
    bool present = root_present(root);
    if ((state == ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED && present) ||
        (state != ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED && !present))
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE;
    return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
}

static enum zcl_code_semantic_candidate_error behavior_samples_valid(
    uint8_t state, uint32_t left, uint32_t right)
{
    switch (state) {
    case ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED:
        return left == 0 && right == 0
                   ? ZCL_CODE_SEMANTIC_CANDIDATE_OK
                   : ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES;
    case ZCL_CODE_SEMANTIC_EVIDENCE_MATCH:
        return left >= ZCL_CODE_SEMANTIC_MIN_DISTINCT &&
                       right >= ZCL_CODE_SEMANTIC_MIN_DISTINCT
                   ? ZCL_CODE_SEMANTIC_CANDIDATE_OK
                   : ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES;
    case ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH:
        return left != 0 && right != 0
                   ? ZCL_CODE_SEMANTIC_CANDIDATE_OK
                   : ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES;
    case ZCL_CODE_SEMANTIC_EVIDENCE_INCOMPLETE:
        return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
    default:
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM;
    }
}

enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_derive_verdict(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t *verdict)
{
    if (!verdict)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    *verdict = 0;
    if (!candidate) return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    const uint8_t states[] = {
        candidate->syntax_shape, candidate->graph_depth1,
        candidate->behavior_a, candidate->behavior_b,
    };
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
        if (!evidence_state_valid(states[i]))
            return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM;
    enum zcl_code_semantic_candidate_error error = behavior_samples_valid(
        candidate->behavior_a, candidate->behavior_a_left_distinct,
        candidate->behavior_a_right_distinct);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    error = behavior_samples_valid(
        candidate->behavior_b, candidate->behavior_b_left_distinct,
        candidate->behavior_b_right_distinct);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
        if (states[i] == ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH) {
            *verdict = ZCL_CODE_SEMANTIC_VERDICT_MISMATCH;
            return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
        }
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
        if (states[i] == ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED ||
            states[i] == ZCL_CODE_SEMANTIC_EVIDENCE_INCOMPLETE) {
            *verdict = ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE;
            return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
        }
    *verdict = ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE;
    return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
}

enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_validate(
    const struct zcl_code_semantic_candidate_v1 *candidate)
{
    uint8_t derived = 0;
    enum zcl_code_semantic_candidate_error error;
    if (!candidate) return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    if (candidate->schema_version != ZCL_CODE_SEMANTIC_CANDIDATE_VERSION)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERSION;
    if (!verdict_valid(candidate->verdict) ||
        candidate->vector_hint > ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM;
    error = zcl_code_semantic_candidate_v1_derive_verdict(candidate, &derived);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    if (candidate->flags != 0 || candidate->reserved != 0 ||
        candidate->reserved_word != 0)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS;
    const uint8_t *mandatory_roots[] = {
        candidate->source_root, candidate->universe_root,
        candidate->ontology_root, candidate->context_root,
        candidate->left_subject_root, candidate->right_subject_root,
        candidate->left_concept_card_root,
        candidate->right_concept_card_root,
        candidate->extractor_profile_root, candidate->proof_needed_root,
    };
    for (size_t i = 0;
         i < sizeof(mandatory_roots) / sizeof(mandatory_roots[0]); i++)
        if (!root_present(mandatory_roots[i]))
            return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_ZERO;
    if (memcmp(candidate->left_subject_root, candidate->right_subject_root,
               32) >= 0)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ORDER;
    error = evidence_root_valid(candidate->syntax_shape,
                                candidate->syntax_evidence_root);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    error = evidence_root_valid(candidate->graph_depth1,
                                candidate->graph_evidence_root);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    error = evidence_root_valid(candidate->behavior_a,
                                candidate->behavior_a_evidence_root);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    error = evidence_root_valid(candidate->behavior_b,
                                candidate->behavior_b_evidence_root);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    if (candidate->behavior_a != ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED &&
        candidate->behavior_b != ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED &&
        memcmp(candidate->behavior_a_evidence_root,
               candidate->behavior_b_evidence_root, 32) == 0)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_CHANNEL_ALIAS;
    if ((candidate->vector_hint == ZCL_CODE_SEMANTIC_VECTOR_ABSENT &&
         root_present(candidate->vector_hint_root)) ||
        (candidate->vector_hint == ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT &&
         !root_present(candidate->vector_hint_root)))
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE;
    if (candidate->verdict != derived)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERDICT;
    return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
}

static size_t roots_encode(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t *out, size_t off)
{
    const uint8_t *roots[] = {
        candidate->source_root,
        candidate->universe_root, candidate->ontology_root,
        candidate->context_root, candidate->left_subject_root,
        candidate->right_subject_root, candidate->left_concept_card_root,
        candidate->right_concept_card_root, candidate->syntax_evidence_root,
        candidate->graph_evidence_root, candidate->behavior_a_evidence_root,
        candidate->behavior_b_evidence_root,
        candidate->extractor_profile_root, candidate->vector_hint_root,
        candidate->proof_needed_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(out + off, roots[i], 32);
        off += 32;
    }
    return off;
}

static size_t roots_parse(struct zcl_code_semantic_candidate_v1 *out,
                          const uint8_t *wire, size_t off)
{
    uint8_t *roots[] = {
        out->source_root, out->universe_root, out->ontology_root,
        out->context_root, out->left_subject_root, out->right_subject_root,
        out->left_concept_card_root, out->right_concept_card_root,
        out->syntax_evidence_root, out->graph_evidence_root,
        out->behavior_a_evidence_root, out->behavior_b_evidence_root,
        out->extractor_profile_root, out->vector_hint_root,
        out->proof_needed_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(roots[i], wire + off, 32);
        off += 32;
    }
    return off;
}

enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_encode(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t out[ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES])
{
    size_t off = 0;
    if (!out) return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    if (candidate && ranges_overlap(candidate, sizeof(*candidate), out,
                                    ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES))
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP;
    enum zcl_code_semantic_candidate_error error =
        zcl_code_semantic_candidate_v1_validate(candidate);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) {
        memset(out, 0, ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES);
        return error;
    }
    memcpy(out + off, semantic_magic, sizeof(semantic_magic));
    off += sizeof(semantic_magic);
    zcl_write_u16_le(out + off, candidate->schema_version); off += 2;
    out[off++] = candidate->verdict;
    out[off++] = candidate->syntax_shape;
    out[off++] = candidate->graph_depth1;
    out[off++] = candidate->behavior_a;
    out[off++] = candidate->behavior_b;
    out[off++] = candidate->vector_hint;
    zcl_write_u16_le(out + off, candidate->flags); off += 2;
    zcl_write_u16_le(out + off, candidate->reserved); off += 2;
    zcl_write_u32_le(out + off, candidate->reserved_word); off += 4;
    zcl_write_u32_le(out + off, candidate->behavior_a_left_distinct); off += 4;
    zcl_write_u32_le(out + off, candidate->behavior_a_right_distinct); off += 4;
    zcl_write_u32_le(out + off, candidate->behavior_b_left_distinct); off += 4;
    zcl_write_u32_le(out + off, candidate->behavior_b_right_distinct); off += 4;
    off = roots_encode(candidate, out, off);
    return off == ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES
               ? ZCL_CODE_SEMANTIC_CANDIDATE_OK
               : ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE;
}

enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_semantic_candidate_v1 *out)
{
    size_t off;
    if (!out) return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    if (!wire) {
        memset(out, 0, sizeof(*out));
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    }
    if (ranges_overlap(wire, wire_len, out, sizeof(*out)))
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP;
    memset(out, 0, sizeof(*out));
    if (wire_len != ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE;
    if (memcmp(wire, semantic_magic, sizeof(semantic_magic)) != 0)
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_MAGIC;
    off = sizeof(semantic_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->verdict = wire[off++];
    out->syntax_shape = wire[off++];
    out->graph_depth1 = wire[off++];
    out->behavior_a = wire[off++];
    out->behavior_b = wire[off++];
    out->vector_hint = wire[off++];
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    out->reserved_word = zcl_read_u32_le(wire + off); off += 4;
    out->behavior_a_left_distinct = zcl_read_u32_le(wire + off); off += 4;
    out->behavior_a_right_distinct = zcl_read_u32_le(wire + off); off += 4;
    out->behavior_b_left_distinct = zcl_read_u32_le(wire + off); off += 4;
    out->behavior_b_right_distinct = zcl_read_u32_le(wire + off); off += 4;
    off = roots_parse(out, wire, off);
    enum zcl_code_semantic_candidate_error error =
        off == wire_len ? zcl_code_semantic_candidate_v1_validate(out)
                        : ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE;
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_root(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t out[32])
{
    struct sha3_256_ctx sha;
    struct zcl_code_semantic_candidate_v1 core;
    uint8_t wire[ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES];
    if (!out) return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    if (candidate && ranges_overlap(candidate, sizeof(*candidate), out, 32))
        return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP;
    memset(out, 0, 32);
    if (!candidate) return ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL;
    enum zcl_code_semantic_candidate_error error =
        zcl_code_semantic_candidate_v1_validate(candidate);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    core = *candidate;
    core.vector_hint = ZCL_CODE_SEMANTIC_VECTOR_ABSENT;
    memset(core.vector_hint_root, 0, sizeof(core.vector_hint_root));
    error = zcl_code_semantic_candidate_v1_encode(&core, wire);
    if (error != ZCL_CODE_SEMANTIC_CANDIDATE_OK) return error;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)semantic_domain,
                   sizeof(semantic_domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return ZCL_CODE_SEMANTIC_CANDIDATE_OK;
}

const char *zcl_code_semantic_candidate_error_string(
    enum zcl_code_semantic_candidate_error error)
{
    switch (error) {
    case ZCL_CODE_SEMANTIC_CANDIDATE_OK: return "ok";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL: return "null";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERSION: return "version";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM: return "enum";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS: return "flags";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_ZERO: return "root_zero";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE: return "root_presence";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ORDER: return "order";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES: return "samples";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERDICT: return "verdict";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE: return "wire_size";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_MAGIC: return "wire_magic";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP: return "overlap";
    case ZCL_CODE_SEMANTIC_CANDIDATE_ERR_CHANNEL_ALIAS:
        return "channel_alias";
    }
    return "unknown";
}

const char *zcl_code_semantic_verdict_string(uint8_t verdict)
{
    switch (verdict) {
    case ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE: return "CANDIDATE";
    case ZCL_CODE_SEMANTIC_VERDICT_MISMATCH: return "MISMATCH";
    case ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE: return "INCOMPLETE";
    default: return "UNKNOWN";
    }
}
