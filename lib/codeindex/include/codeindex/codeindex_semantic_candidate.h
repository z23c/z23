/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical bounded evidence candidates for possible semantic code
 * duplication, without consolidation or source-mutation authority. */
#ifndef ZCL_CODEINDEX_SEMANTIC_CANDIDATE_H
#define ZCL_CODEINDEX_SEMANTIC_CANDIDATE_H

#include <stddef.h>
#include <stdint.h>

enum {
    ZCL_CODE_SEMANTIC_CANDIDATE_VERSION = 1,
    ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES = 520,
    ZCL_CODE_SEMANTIC_MIN_DISTINCT = 3,
};

/* Immutable wire values. UNOBSERVED has no evidence root. INCOMPLETE binds a
 * concrete truncation/refusal receipt that still cannot support comparison. */
enum zcl_code_semantic_evidence_state {
    ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED = 0,
    ZCL_CODE_SEMANTIC_EVIDENCE_MATCH = 1,
    ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH = 2,
    ZCL_CODE_SEMANTIC_EVIDENCE_INCOMPLETE = 3,
};

enum zcl_code_semantic_verdict {
    /* Finite observations agree. This is not equivalence, merge permission,
     * deletion permission, source acceptance, or review approval. */
    ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE = 1,
    ZCL_CODE_SEMANTIC_VERDICT_MISMATCH = 2,
    ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE = 3,
};

enum zcl_code_semantic_vector_state {
    ZCL_CODE_SEMANTIC_VECTOR_ABSENT = 0,
    /* Ordering hint only. It never participates in verdict derivation. */
    ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT = 1,
};

enum zcl_code_semantic_candidate_error {
    ZCL_CODE_SEMANTIC_CANDIDATE_OK = 0,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL = 1,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERSION = 2,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM = 3,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS = 4,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_ZERO = 5,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE = 6,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ORDER = 7,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES = 8,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERDICT = 9,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE = 10,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_MAGIC = 11,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP = 12,
    ZCL_CODE_SEMANTIC_CANDIDATE_ERR_CHANNEL_ALIAS = 13,
};

struct zcl_code_semantic_candidate_v1 {
    uint16_t schema_version;
    uint8_t verdict;
    uint8_t syntax_shape;
    uint8_t graph_depth1;
    uint8_t behavior_a;
    uint8_t behavior_b;
    uint8_t vector_hint;
    uint16_t flags;
    uint16_t reserved;
    uint32_t reserved_word;
    uint32_t behavior_a_left_distinct;
    uint32_t behavior_a_right_distinct;
    uint32_t behavior_b_left_distinct;
    uint32_t behavior_b_right_distinct;

    /* Reusable evidence identity is independent of the task that requested
     * it. A separately verified ZCode work receipt may bind this object's
     * root as output_root without changing the evidence identity. */
    uint8_t source_root[32];
    uint8_t universe_root[32];
    uint8_t ontology_root[32];
    uint8_t context_root[32];

    /* Strict ascending subject order gives one identity for an unordered
     * pair. Evidence roots bind exact child receipts, not truth by fiat. */
    uint8_t left_subject_root[32];
    uint8_t right_subject_root[32];
    uint8_t left_concept_card_root[32];
    uint8_t right_concept_card_root[32];
    uint8_t syntax_evidence_root[32];
    uint8_t graph_evidence_root[32];
    uint8_t behavior_a_evidence_root[32];
    uint8_t behavior_b_evidence_root[32];
    uint8_t extractor_profile_root[32];
    uint8_t vector_hint_root[32];
    uint8_t proof_needed_root[32];
};

/* MISMATCH dominates because one complete contradictory observation rules out
 * a duplicate candidate. Otherwise any absent/incomplete mandatory channel
 * yields INCOMPLETE; only four complete matches yield CANDIDATE. vector_hint
 * and vector_hint_root are deliberately not read. Behavior sample floors are
 * enforced here as well as by full structural validation. */
enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_derive_verdict(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t *verdict);

/* Structural validation proves canonical bytes, bindings, and verdict
 * derivation only. It does not independently replay child evidence. */
enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_validate(
    const struct zcl_code_semantic_candidate_v1 *candidate);
enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_encode(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t out[ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES]);
enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_semantic_candidate_v1 *out);
/* Core evidence identity: the optional MODEL_HINT envelope is validated but
 * normalized out, so ranking hints cannot fork task/action output identity. */
enum zcl_code_semantic_candidate_error
zcl_code_semantic_candidate_v1_root(
    const struct zcl_code_semantic_candidate_v1 *candidate,
    uint8_t out[32]);

const char *zcl_code_semantic_candidate_error_string(
    enum zcl_code_semantic_candidate_error error);
const char *zcl_code_semantic_verdict_string(uint8_t verdict);

#endif /* ZCL_CODEINDEX_SEMANTIC_CANDIDATE_H */
