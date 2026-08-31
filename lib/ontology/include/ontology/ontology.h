/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded IO-free contextual ontology and source-universe contracts. */
#ifndef ZCL_ONTOLOGY_ONTOLOGY_H
#define ZCL_ONTOLOGY_ONTOLOGY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    ZCL_SOURCE_UNIVERSE_VERSION = 1,
    ZCL_ONTOLOGY_OBJECT_VERSION = 1,
    ZCL_ONTOLOGY_MAX_ARITY = 4,
    ZCL_ONTOLOGY_MAX_IMPORTS = 16,
    ZCL_ONTOLOGY_MAX_CONTEXTS = ZCL_ONTOLOGY_MAX_IMPORTS + 1,
    ZCL_ONTOLOGY_MAX_COVERAGE = ZCL_ONTOLOGY_MAX_CONTEXTS,
    ZCL_SOURCE_COVER_GOVERNED = 1u << 0,
    ZCL_SOURCE_COVER_GENERATED = 1u << 1,
    ZCL_SOURCE_COVER_VENDOR = 1u << 2,
    ZCL_SOURCE_COVER_METADATA = 1u << 3,
    ZCL_SOURCE_COVER_PUBLISHABLE = 1u << 4,
    ZCL_SOURCE_COVER_CONSENSUS = 1u << 5,
    ZCL_SOURCE_COVER_INDEXED = 1u << 6,
    ZCL_SOURCE_COVER_ALL = (1u << 7) - 1u,
};

struct zcl_source_universe_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    uint32_t coverage_mask;
    uint64_t governed_path_count;
    uint64_t total_bytes;
    uint8_t source_manifest_root[32];
    uint8_t governed_paths_root[32];
    uint8_t generated_paths_root[32];
    uint8_t vendor_paths_root[32];
    uint8_t metadata_paths_root[32];
    uint8_t publishable_paths_root[32];
    uint8_t consensus_seal_root[32];
    uint8_t indexed_paths_root[32];
};

enum zcl_ontology_world {
    ZCL_ONTOLOGY_OPEN_WORLD = 1,
    ZCL_ONTOLOGY_CLOSED_WORLD = 2,
};

enum zcl_ontology_tier {
    ZCL_ONTOLOGY_TIER_EXACT = 1,
    ZCL_ONTOLOGY_TIER_HORN = 2,
    ZCL_ONTOLOGY_TIER_GOAL = 3,
};

struct zcl_ontology_predicate_v1 {
    uint16_t schema_version;
    uint8_t arity;
    uint8_t world;
    uint8_t execution_tier;
    uint8_t explicit_negation;
    uint16_t reserved;
    uint32_t coverage_required;
    uint8_t term_root[32];
    uint8_t argument_type_roots[ZCL_ONTOLOGY_MAX_ARITY][32];
};

enum zcl_ontology_context_kind {
    ZCL_ONTOLOGY_CONTEXT_CORPUS = 1,
    ZCL_ONTOLOGY_CONTEXT_BUILD = 2,
    ZCL_ONTOLOGY_CONTEXT_WORKSPACE = 3,
    ZCL_ONTOLOGY_CONTEXT_RUNTIME = 4,
    ZCL_ONTOLOGY_CONTEXT_TASK = 5,
};

struct zcl_ontology_context_v1 {
    uint16_t schema_version;
    uint8_t kind;
    uint8_t reserved;
    uint8_t universe_root[32];
    uint8_t subject_root[32];
    uint8_t import_manifest_root[32];
    uint8_t policy_root[32];
};

enum zcl_ontology_polarity {
    ZCL_ONTOLOGY_POSITIVE = 1,
    ZCL_ONTOLOGY_NEGATIVE = 2,
};

struct zcl_ontology_assertion_v1 {
    uint16_t schema_version;
    uint8_t arity;
    uint8_t polarity;
    uint8_t context_root[32];
    uint8_t predicate_root[32];
    uint8_t argument_roots[ZCL_ONTOLOGY_MAX_ARITY][32];
    uint8_t evidence_root[32];
};

struct zcl_ontology_coverage_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    uint32_t complete_mask;
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t evidence_root[32];
};

enum zcl_ontology_status {
    ZCL_ONTOLOGY_PROVED = 1,
    ZCL_ONTOLOGY_DISPROVED = 2,
    ZCL_ONTOLOGY_BOTH = 3,
    ZCL_ONTOLOGY_UNKNOWN = 4,
    ZCL_ONTOLOGY_INCOMPLETE = 5,
};

struct zcl_ontology_query_v1 {
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t predicate_root[32];
    uint8_t arity;
    uint8_t argument_roots[ZCL_ONTOLOGY_MAX_ARITY][32];
    const uint8_t (*import_context_roots)[32];
    size_t import_count;
    const struct zcl_ontology_context_v1 *contexts;
    size_t context_count;
    const struct zcl_ontology_assertion_v1 *assertions;
    size_t assertion_count;
    size_t fact_budget;
    const struct zcl_ontology_coverage_v1 *coverage;
    size_t coverage_count;
};

struct zcl_ontology_result_v1 {
    enum zcl_ontology_status status;
    bool observed_positive;
    bool observed_negative;
    bool complete;
    size_t facts_examined;
    uint32_t missing_coverage_mask;
    const char *truncation_reason;
};

bool zcl_source_universe_v1_root(
    const struct zcl_source_universe_v1 *universe, uint8_t out[32]);
bool zcl_ontology_predicate_v1_root(
    const struct zcl_ontology_predicate_v1 *predicate, uint8_t out[32]);
bool zcl_ontology_context_v1_root(
    const struct zcl_ontology_context_v1 *context, uint8_t out[32]);
bool zcl_ontology_assertion_v1_root(
    const struct zcl_ontology_assertion_v1 *assertion, uint8_t out[32]);
bool zcl_ontology_import_manifest_v1_root(
    const uint8_t universe_root[32], const uint8_t (*imports)[32],
    size_t import_count, uint8_t out[32]);
bool zcl_ontology_coverage_v1_root(
    const struct zcl_ontology_coverage_v1 *coverage, uint8_t out[32]);
bool zcl_ontology_evaluate_atom_v1(
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_predicate_v1 *predicate,
    const struct zcl_ontology_query_v1 *query,
    struct zcl_ontology_result_v1 *out);

#endif
