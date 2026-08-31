/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Deterministic built-in ontology taxonomy vocabulary. */
#ifndef ZCL_ONTOLOGY_ONTOLOGY_VOCABULARY_H
#define ZCL_ONTOLOGY_ONTOLOGY_VOCABULARY_H

#include "ontology/ontology.h"

enum {
    ZCL_ONTOLOGY_VOCABULARY_VERSION = 1,
    ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT = 4,
    ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT = 2,
    ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT = 2,
    ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT = 2,
    ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT = 8,
};

enum zcl_ontology_vocabulary_rule {
    ZCL_ONTOLOGY_VOCABULARY_GENLS_TRANSITIVITY = 0,
    ZCL_ONTOLOGY_VOCABULARY_ISA_INHERITANCE = 1,
};

/* Pointer-free caller-owned storage. terms, predicates, formula_roots, rules,
 * and rule_roots are each in strict ascending canonical-root order. The rule
 * node blocks remain in the semantic enum order above; formula_order maps a
 * canonical formula slot to its node block. No stored object contains names. */
struct zcl_ontology_vocabulary_v1 {
    uint16_t schema_version;
    uint16_t reserved;
    uint8_t vocabulary_root[32];
    uint8_t evidence_root[32];
    uint8_t universe_root[32];
    uint8_t context_root[32];
    uint8_t ontology_object_identity_root[32];
    uint8_t ontology_type_identity_root[32];
    uint8_t isa_predicate_root[32];
    uint8_t genls_predicate_root[32];
    struct zcl_ontology_term_v1
        terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT];
    struct zcl_ontology_predicate_v1
        predicates[ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT];
    struct zcl_ontology_formula_node_v1
        rule_nodes[ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT]
                  [ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT];
    uint8_t formula_order[ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT];
    uint8_t reserved_bytes[6];
    uint8_t formula_roots[ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT][32];
    struct zcl_ontology_horn_rule_v1
        rules[ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT];
    uint8_t rule_roots[ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT][32];
};

/* Builds the exact built-in vocabulary and its two context-bound Horn rules.
 * The source universe must be complete and the context must name its root.
 * No allocation, IO, global mutation, or implicit reflexivity occurs. */
bool zcl_ontology_vocabulary_v1_build(
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context,
    struct zcl_ontology_vocabulary_v1 *out);

/* Reconstruct one canonical formula view in ascending formula-root order.
 * out->nodes borrows vocabulary storage and remains valid for its lifetime. */
bool zcl_ontology_vocabulary_v1_formula_at(
    const struct zcl_ontology_vocabulary_v1 *vocabulary, size_t index,
    struct zcl_ontology_formula_v1 *out);

/* Rederives the exact built-in object and validates both rules through the
 * canonical Horn admission API. Extra or altered taxonomy is rejected. */
bool zcl_ontology_vocabulary_v1_validate(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context);

#endif /* ZCL_ONTOLOGY_ONTOLOGY_VOCABULARY_H */
