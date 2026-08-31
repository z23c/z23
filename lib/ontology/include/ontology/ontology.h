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
    ZCL_ONTOLOGY_MAX_FORMULA_NODES = 128,
    ZCL_ONTOLOGY_MAX_VARIABLES = 16,
    ZCL_ONTOLOGY_MAX_DOMAINS =
        ZCL_ONTOLOGY_MAX_VARIABLES * ZCL_ONTOLOGY_MAX_CONTEXTS,
    ZCL_ONTOLOGY_MAX_DOMAIN_VALUES = 64,
    ZCL_ONTOLOGY_MAX_PREDICATES = 64,
    ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES = 32768,
    ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES = 528,
    ZCL_SOURCE_COVER_GOVERNED = 1u << 0,
    ZCL_SOURCE_COVER_GENERATED = 1u << 1,
    ZCL_SOURCE_COVER_VENDOR = 1u << 2,
    ZCL_SOURCE_COVER_METADATA = 1u << 3,
    ZCL_SOURCE_COVER_PUBLISHABLE = 1u << 4,
    ZCL_SOURCE_COVER_CONSENSUS = 1u << 5,
    ZCL_SOURCE_COVER_INDEXED = 1u << 6,
    ZCL_SOURCE_COVER_ALL = (1u << 7) - 1u,
};

enum zcl_ontology_term_kind {
    ZCL_ONTOLOGY_TERM_ENTITY = 1,
    ZCL_ONTOLOGY_TERM_TYPE = 2,
    ZCL_ONTOLOGY_TERM_PREDICATE = 3,
    ZCL_ONTOLOGY_TERM_CONTEXT = 4,
    ZCL_ONTOLOGY_TERM_LITERAL = 5,
};

struct zcl_ontology_term_v1 {
    uint16_t schema_version;
    uint8_t kind;
    uint8_t reserved;
    uint8_t vocabulary_root[32];
    /* Within a validated manifest, this is the identity_root of a canonical
     * ZCL_ONTOLOGY_TERM_TYPE member; values use identity_root similarly. */
    uint8_t type_root[32];
    uint8_t identity_root[32];
    uint8_t lexical_root[32];
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

struct zcl_ontology_domain_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t type_root[32];
    uint8_t coverage_evidence_root[32];
    uint64_t value_count;
    const uint8_t (*value_roots)[32];
};

enum zcl_ontology_formula_term_kind {
    ZCL_ONTOLOGY_FORMULA_CONSTANT = 1,
    ZCL_ONTOLOGY_FORMULA_VARIABLE = 2,
};

struct zcl_ontology_formula_term_v1 {
    uint8_t kind;
    uint8_t variable;
    uint16_t reserved;
    uint8_t type_root[32];
    uint8_t value_root[32];
};

enum zcl_ontology_formula_op {
    ZCL_ONTOLOGY_FORMULA_ATOM = 1,
    ZCL_ONTOLOGY_FORMULA_EQUAL = 2,
    ZCL_ONTOLOGY_FORMULA_AND = 3,
    ZCL_ONTOLOGY_FORMULA_OR = 4,
    ZCL_ONTOLOGY_FORMULA_NOT = 5,
    ZCL_ONTOLOGY_FORMULA_IMPLIES = 6,
    ZCL_ONTOLOGY_FORMULA_FORALL = 7,
    ZCL_ONTOLOGY_FORMULA_EXISTS = 8,
};

struct zcl_ontology_formula_node_v1 {
    uint8_t op;
    uint8_t arity;
    uint8_t variable;
    uint8_t reserved;
    uint32_t left;
    uint32_t right;
    uint8_t predicate_root[32];
    uint8_t quantified_type_root[32];
    struct zcl_ontology_formula_term_v1 terms[ZCL_ONTOLOGY_MAX_ARITY];
};

struct zcl_ontology_formula_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    uint32_t node_count;
    uint32_t root_index;
    uint8_t variable_count;
    uint8_t reserved_bytes[7];
    const struct zcl_ontology_formula_node_v1 *nodes;
};

struct zcl_ontology_budget_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    uint64_t memory_limit_bytes;
    uint64_t fact_limit;
    uint64_t step_limit;
    uint64_t recursion_limit;
    uint64_t derivation_limit;
    uint64_t time_limit_us;
};

typedef uint64_t (*zcl_ontology_elapsed_us_fn)(void *context);

struct zcl_ontology_evaluator;

struct zcl_ontology_formula_query_v1 {
    uint8_t universe_root[32];
    uint8_t context_root[32];
    const uint8_t (*import_context_roots)[32];
    size_t import_count;
    const struct zcl_ontology_context_v1 *contexts;
    size_t context_count;
    const struct zcl_ontology_predicate_v1 *predicates;
    size_t predicate_count;
    const struct zcl_ontology_assertion_v1 *assertions;
    size_t assertion_count;
    const struct zcl_ontology_coverage_v1 *coverage;
    size_t coverage_count;
    const struct zcl_ontology_domain_v1 *domains;
    size_t domain_count;
    const struct zcl_ontology_budget_v1 *budget;
    zcl_ontology_elapsed_us_fn elapsed_us;
    void *elapsed_context;
};

enum zcl_ontology_status {
    ZCL_ONTOLOGY_PROVED = 1,
    ZCL_ONTOLOGY_DISPROVED = 2,
    ZCL_ONTOLOGY_BOTH = 3,
    ZCL_ONTOLOGY_UNKNOWN = 4,
    ZCL_ONTOLOGY_INCOMPLETE = 5,
};

enum zcl_ontology_incomplete_reason {
    ZCL_ONTOLOGY_REASON_NONE = 0,
    ZCL_ONTOLOGY_REASON_FACT_BUDGET = 1,
    ZCL_ONTOLOGY_REASON_STEP_BUDGET = 2,
    ZCL_ONTOLOGY_REASON_RECURSION_BUDGET = 3,
    ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET = 4,
    ZCL_ONTOLOGY_REASON_MEMORY_BUDGET = 5,
    ZCL_ONTOLOGY_REASON_TIME_BUDGET = 6,
    ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING = 7,
    ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED = 8,
    ZCL_ONTOLOGY_REASON_PREDICATE_MISSING = 9,
    ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID = 10,
    ZCL_ONTOLOGY_REASON_PREDICATE_ARITY = 11,
    ZCL_ONTOLOGY_REASON_PREDICATE_TYPE = 12,
    ZCL_ONTOLOGY_REASON_PREDICATE_TIER = 13,
    ZCL_ONTOLOGY_REASON_ASSERTION_INVALID = 14,
    ZCL_ONTOLOGY_REASON_COVERAGE_MISSING = 15,
    ZCL_ONTOLOGY_REASON_DOMAIN_MISSING = 16,
    ZCL_ONTOLOGY_REASON_DOMAIN_INVALID = 17,
    ZCL_ONTOLOGY_REASON_DOMAIN_CONTEXT = 18,
    ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID = 19,
    ZCL_ONTOLOGY_REASON_VARIABLE_UNBOUND = 20,
    ZCL_ONTOLOGY_REASON_FORMULA_EVIDENCE = 21,
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
    uint64_t facts_examined;
    uint64_t steps_taken;
    uint64_t derivations_produced;
    uint32_t max_recursion_depth;
    uint32_t missing_coverage_mask;
    enum zcl_ontology_incomplete_reason incomplete_reason;
    const char *truncation_reason;
};

struct zcl_ontology_derivation_v1 {
    uint16_t schema_version;
    uint8_t status;
    uint8_t observed_positive;
    uint8_t observed_negative;
    uint8_t complete;
    uint8_t incomplete_reason;
    uint8_t reserved_byte;
    uint16_t reserved;
    uint32_t missing_coverage_mask;
    uint64_t facts_examined;
    uint64_t steps_taken;
    uint64_t derivations_produced;
    uint32_t max_recursion_depth;
    uint32_t parent_count;
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t formula_root[32];
    uint8_t budget_root[32];
    uint8_t evidence_manifest_root[32];
    uint8_t parent_manifest_root[32];
    uint8_t evaluator_root[32];
};

enum zcl_ontology_object_kind {
    ZCL_ONTOLOGY_OBJECT_TERM = 1,
    ZCL_ONTOLOGY_OBJECT_PREDICATE = 2,
    ZCL_ONTOLOGY_OBJECT_FORMULA = 3,
    ZCL_ONTOLOGY_OBJECT_RULE = 4,
    ZCL_ONTOLOGY_OBJECT_CONTEXT = 5,
    ZCL_ONTOLOGY_OBJECT_ASSERTION = 6,
    ZCL_ONTOLOGY_OBJECT_COVERAGE = 7,
    ZCL_ONTOLOGY_OBJECT_DOMAIN = 8,
    ZCL_ONTOLOGY_OBJECT_GAP = 9,
};

struct zcl_ontology_manifest_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint32_t reserved;
    uint64_t term_count;
    uint64_t predicate_count;
    uint64_t formula_count;
    uint64_t rule_count;
    uint64_t context_count;
    uint64_t assertion_count;
    uint64_t coverage_count;
    uint64_t domain_count;
    uint64_t gap_count;
    uint8_t source_root[32];
    uint8_t universe_root[32];
    uint8_t vocabulary_root[32];
    uint8_t term_set_root[32];
    uint8_t predicate_set_root[32];
    uint8_t formula_set_root[32];
    uint8_t rule_set_root[32];
    uint8_t context_set_root[32];
    uint8_t assertion_set_root[32];
    uint8_t coverage_set_root[32];
    uint8_t domain_set_root[32];
    uint8_t extractor_root[32];
    uint8_t policy_root[32];
    uint8_t gap_set_root[32];
};

struct zcl_ontology_manifest_inputs_v1 {
    const struct zcl_ontology_term_v1 *terms;
    size_t term_count;
    const struct zcl_ontology_predicate_v1 *predicates;
    size_t predicate_count;
    const struct zcl_ontology_formula_v1 *formulas;
    size_t formula_count;
    const struct zcl_ontology_context_v1 *contexts;
    size_t context_count;
    const struct zcl_ontology_assertion_v1 *assertions;
    size_t assertion_count;
    const struct zcl_ontology_coverage_v1 *coverage;
    size_t coverage_count;
    const struct zcl_ontology_domain_v1 *domains;
    size_t domain_count;
};

bool zcl_source_universe_v1_root(
    const struct zcl_source_universe_v1 *universe, uint8_t out[32]);
bool zcl_ontology_term_v1_root(
    const struct zcl_ontology_term_v1 *term, uint8_t out[32]);
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
bool zcl_ontology_domain_v1_root(
    const struct zcl_ontology_domain_v1 *domain, uint8_t out[32]);
bool zcl_ontology_formula_v1_root(
    const struct zcl_ontology_formula_v1 *formula, uint8_t out[32]);
bool zcl_ontology_budget_v1_root(
    const struct zcl_ontology_budget_v1 *budget, uint8_t out[32]);
bool zcl_ontology_derivation_v1_root(
    const struct zcl_ontology_derivation_v1 *derivation, uint8_t out[32]);
/* Builds a typed-set identity from roots that the caller has already
 * verified. This helper does not itself establish any child's object kind;
 * manifest validation below rederives roots from canonical child objects. */
bool zcl_ontology_object_set_v1_root(
    enum zcl_ontology_object_kind kind, const uint8_t (*roots)[32],
    size_t count, uint8_t out[32]);
bool zcl_ontology_manifest_v1_encode(
    const struct zcl_ontology_manifest_v1 *manifest, uint8_t *out,
    size_t out_size);
bool zcl_ontology_manifest_v1_decode(
    const uint8_t *wire, size_t wire_size,
    struct zcl_ontology_manifest_v1 *out);
bool zcl_ontology_manifest_v1_root(
    const struct zcl_ontology_manifest_v1 *manifest, uint8_t out[32]);
/* Validation rederives every supported child root and cross-reference.
 * Nonempty RULE and GAP sets refuse until their canonical codecs land. */
bool zcl_ontology_manifest_v1_validate(
    const struct zcl_ontology_manifest_v1 *manifest,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_manifest_inputs_v1 *inputs);
bool zcl_ontology_evaluator_init_v1(
    void *storage, size_t storage_size,
    struct zcl_ontology_evaluator **out_evaluator);
size_t zcl_ontology_evaluator_alignment_v1(void);
bool zcl_ontology_evaluate_formula_v1(
    struct zcl_ontology_evaluator *evaluator,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_formula_v1 *formula,
    const struct zcl_ontology_formula_query_v1 *query,
    struct zcl_ontology_result_v1 *out);
bool zcl_ontology_evaluate_atom_v1(
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_predicate_v1 *predicate,
    const struct zcl_ontology_query_v1 *query,
    struct zcl_ontology_result_v1 *out);

#endif
