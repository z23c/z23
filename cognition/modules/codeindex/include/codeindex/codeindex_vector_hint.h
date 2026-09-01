/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical, bounded MODEL_HINT objects for exact code concept cards
 * and optional signed-int8 retrieval vectors. */
#ifndef ZCL_CODEINDEX_VECTOR_HINT_H
#define ZCL_CODEINDEX_VECTOR_HINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_ontology_manifest_inputs_v1;
struct zcl_ontology_manifest_v1;
struct zcl_source_universe_v1;

enum {
    ZCL_CODE_CONCEPT_CARD_VERSION = 1,
    ZCL_CODE_EMBEDDING_PROFILE_VERSION = 1,
    ZCL_CODE_EMBEDDING_SEGMENT_VERSION = 1,
    ZCL_CODE_CONCEPT_CARD_WIRE_BYTES = 272,
    ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES = 344,
    ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES = 304,
    ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES = 96,
    ZCL_CODE_EMBEDDING_DIMENSION_MAX = 4096,
    ZCL_CODE_EMBEDDING_SEGMENT_WIRE_MAX = 64u * 1024u * 1024u,
};

/* These immutable wire values are append-only. Renumbering changes roots. */
enum zcl_code_concept_card_kind {
    ZCL_CODE_CONCEPT_CARD_PACKAGE = 1,
    ZCL_CODE_CONCEPT_CARD_COMPONENT = 2,
    ZCL_CODE_CONCEPT_CARD_API = 3,
    ZCL_CODE_CONCEPT_CARD_CONFIGURED_ENTITY = 4,
    ZCL_CODE_CONCEPT_CARD_USAGE_NEIGHBORHOOD = 5,
    ZCL_CODE_CONCEPT_CARD_INVARIANT = 6,
    ZCL_CODE_CONCEPT_CARD_TEST = 7,
    ZCL_CODE_CONCEPT_CARD_ACCEPTED_TELEMETRY = 8,
};

enum zcl_code_hint_evidence_kind {
    /* A candidate-ordering hint only. It cannot prove identity, truth,
     * completeness, compatibility, ownership, authority, calls or permission,
     * and cannot omit a mandatory proof or test. */
    ZCL_CODE_HINT_EVIDENCE_MODEL_HINT = 1,
};

enum zcl_code_concept_evidence_kind {
    /* The card contains only roots of exact ontology-derived facts. */
    ZCL_CODE_CONCEPT_EVIDENCE_EXACT_ROOTS = 1,
};

enum zcl_code_embedding_metric {
    ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT = 1,
};

enum zcl_code_embedding_quantizer {
    ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8 = 1,
};

enum zcl_code_vector_hint_error {
    ZCL_CODE_VECTOR_HINT_OK = 0,
    ZCL_CODE_VECTOR_HINT_ERR_NULL = 1,
    ZCL_CODE_VECTOR_HINT_ERR_VERSION = 2,
    ZCL_CODE_VECTOR_HINT_ERR_ENUM = 3,
    ZCL_CODE_VECTOR_HINT_ERR_FLAGS = 4,
    ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO = 5,
    ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE = 6,
    ZCL_CODE_VECTOR_HINT_ERR_WIRE_MAGIC = 7,
    ZCL_CODE_VECTOR_HINT_ERR_LIMIT = 8,
    ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW = 9,
    ZCL_CODE_VECTOR_HINT_ERR_ORDER = 10,
    ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT = 11,
    ZCL_CODE_VECTOR_HINT_ERR_CAPACITY = 12,
    ZCL_CODE_VECTOR_HINT_ERR_OVERLAP = 13,
    ZCL_CODE_VECTOR_HINT_ERR_PROFILE_BINDING = 14,
    ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING = 15,
    ZCL_CODE_VECTOR_HINT_ERR_CARD_SET_ROOT = 16,
    ZCL_CODE_VECTOR_HINT_ERR_SCRATCH = 17,
};

struct zcl_code_concept_card_v1 {
    uint16_t schema_version;
    uint8_t kind;
    uint8_t evidence_kind;
    uint16_t flags;
    uint16_t reserved;
    uint8_t source_root[32];
    uint8_t universe_root[32];
    uint8_t ontology_root[32];
    uint8_t context_root[32];
    uint8_t subject_root[32];
    uint8_t fact_manifest_root[32];
    uint8_t coverage_root[32];
    uint8_t extractor_root[32];
};

struct zcl_code_embedding_profile_v1 {
    uint16_t schema_version;
    uint8_t evidence_kind;
    uint8_t metric;
    uint8_t quantizer;
    uint8_t reserved_byte;
    uint16_t flags;
    uint32_t dimension;
    uint32_t reserved;
    uint8_t projection_root[32];
    uint8_t tokenizer_root[32];
    uint8_t preprocessing_root[32];
    uint8_t model_root[32];
    uint8_t weights_root[32];
    uint8_t license_root[32];
    uint8_t rights_root[32];
    uint8_t accepted_runner_root[32];
    uint8_t accepted_action_root[32];
    uint8_t reproducibility_root[32];
};

struct zcl_code_embedding_vector_v1 {
    uint8_t entity_root[32];
    uint8_t concept_card_root[32];
    uint8_t span_root[32];
    /* Exactly segment.dimension signed bytes. For parsed segments this borrows
     * the input wire and remains valid only while that wire remains alive. */
    const int8_t *values;
};

struct zcl_code_embedding_segment_v1 {
    uint16_t schema_version;
    uint8_t evidence_kind;
    uint8_t metric;
    uint8_t quantizer;
    uint8_t reserved_byte;
    uint16_t flags;
    uint32_t dimension;
    uint32_t reserved;
    uint64_t vector_count;
    uint64_t row_bytes;
    uint64_t payload_bytes;
    uint8_t corpus_root[32];
    uint8_t source_root[32];
    uint8_t universe_root[32];
    uint8_t concept_card_set_root[32];
    uint8_t context_root[32];
    uint8_t coverage_root[32];
    uint8_t profile_root[32];
    uint8_t payload_root[32];
    const struct zcl_code_embedding_vector_v1 *vectors;
};

/* Structural canonical codecs only. Parse/validate/root do not accept a model,
 * authorize source access or publication, establish any semantic claim, or
 * locally accept the rights/policy roots carried by an object. Input and
 * output ranges must not overlap. Parsed vector values borrow the input wire;
 * vector_storage must therefore remain separate from that wire. */
enum zcl_code_vector_hint_error zcl_code_concept_card_v1_validate(
    const struct zcl_code_concept_card_v1 *card);
enum zcl_code_vector_hint_error zcl_code_concept_card_v1_encode(
    const struct zcl_code_concept_card_v1 *card,
    uint8_t out[ZCL_CODE_CONCEPT_CARD_WIRE_BYTES]);
enum zcl_code_vector_hint_error zcl_code_concept_card_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_concept_card_v1 *out);
enum zcl_code_vector_hint_error zcl_code_concept_card_v1_root(
    const struct zcl_code_concept_card_v1 *card, uint8_t out[32]);
/* Rederives the accepted ontology manifest and exact child-set roots carried by
 * a card. Structural validation alone deliberately cannot establish these
 * facts from nonzero hashes. */
enum zcl_code_vector_hint_error zcl_code_concept_card_v1_validate_ontology(
    const struct zcl_code_concept_card_v1 *card,
    const struct zcl_ontology_manifest_v1 *manifest,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_manifest_inputs_v1 *inputs);

enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_validate(
    const struct zcl_code_embedding_profile_v1 *profile);
enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_encode(
    const struct zcl_code_embedding_profile_v1 *profile,
    uint8_t out[ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES]);
enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_embedding_profile_v1 *out);
enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_root(
    const struct zcl_code_embedding_profile_v1 *profile, uint8_t out[32]);

enum zcl_code_vector_hint_error zcl_code_embedding_payload_v1_root(
    uint32_t dimension,
    const struct zcl_code_embedding_vector_v1 *vectors,
    uint64_t vector_count, uint8_t out[32]);
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_wire_size(
    const struct zcl_code_embedding_segment_v1 *segment, size_t *out);
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_validate(
    const struct zcl_code_embedding_segment_v1 *segment);
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_validate_profile(
    const struct zcl_code_embedding_segment_v1 *segment,
    const struct zcl_code_embedding_profile_v1 *profile);
/* Exact cross-binding for a structurally valid vector proposal. cards must be
 * in strict canonical-card-root order and there must be exactly one unique
 * card per row. Multiple cards may name one entity; a future ranker must group
 * those rows by entity before any candidate cap or RRF contribution. This
 * function does not infer ontology fact membership from nonzero roots. */
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_validate_cards(
    const struct zcl_code_embedding_segment_v1 *segment,
    const struct zcl_code_embedding_profile_v1 *profile,
    const struct zcl_code_concept_card_v1 *cards, size_t card_count,
    uint8_t (*root_scratch)[32], size_t scratch_capacity);
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_encode(
    const struct zcl_code_embedding_segment_v1 *segment,
    uint8_t *out, size_t out_cap, size_t *out_len);
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_embedding_segment_v1 *out,
    struct zcl_code_embedding_vector_v1 *vector_storage,
    size_t vector_capacity, size_t *required_vectors);
enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_root(
    const struct zcl_code_embedding_segment_v1 *segment, uint8_t out[32]);

const char *zcl_code_vector_hint_error_string(
    enum zcl_code_vector_hint_error error);

#endif /* ZCL_CODEINDEX_VECTOR_HINT_H */
