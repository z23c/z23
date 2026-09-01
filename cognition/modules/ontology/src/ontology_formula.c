/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical finite formulas and a bounded paraconsistent evaluator. */
#include "ontology/ontology.h"
#include "ontology_internal.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <string.h>

static_assert(sizeof(struct zcl_ontology_evaluator) <=
              ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES,
              "ontology evaluator storage contract is too small");

struct ontology_truth {
    bool positive;
    bool negative;
    bool complete;
};

struct ontology_eval_runtime {
    struct zcl_ontology_evaluator *evaluator;
    const struct zcl_ontology_formula_query_v1 *query;
    struct zcl_ontology_result_v1 *result;
    uint64_t started_us;
    enum zcl_ontology_incomplete_reason reason;
    enum zcl_ontology_incomplete_reason soft_reason;
};

static const char *formula_reason_string(
    enum zcl_ontology_incomplete_reason reason)
{
    switch (reason) {
    case ZCL_ONTOLOGY_REASON_FACT_BUDGET:
        return "fact_budget_exhausted";
    case ZCL_ONTOLOGY_REASON_STEP_BUDGET:
        return "step_budget_exhausted";
    case ZCL_ONTOLOGY_REASON_RECURSION_BUDGET:
        return "recursion_budget_exhausted";
    case ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET:
        return "derivation_budget_exhausted";
    case ZCL_ONTOLOGY_REASON_MEMORY_BUDGET:
        return "memory_budget_exhausted";
    case ZCL_ONTOLOGY_REASON_TIME_BUDGET:
        return "time_budget_exhausted";
    case ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING:
        return "time_source_missing";
    case ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED:
        return "time_source_regressed";
    case ZCL_ONTOLOGY_REASON_PREDICATE_MISSING:
        return "predicate_missing";
    case ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID:
        return "invalid_predicate_registry";
    case ZCL_ONTOLOGY_REASON_PREDICATE_ARITY:
        return "predicate_arity_mismatch";
    case ZCL_ONTOLOGY_REASON_PREDICATE_TYPE:
        return "predicate_type_mismatch";
    case ZCL_ONTOLOGY_REASON_PREDICATE_TIER:
        return "predicate_tier_unsupported";
    case ZCL_ONTOLOGY_REASON_ASSERTION_INVALID:
        return "invalid_assertion";
    case ZCL_ONTOLOGY_REASON_COVERAGE_MISSING:
        return "missing_coverage";
    case ZCL_ONTOLOGY_REASON_DOMAIN_MISSING:
        return "domain_missing";
    case ZCL_ONTOLOGY_REASON_DOMAIN_INVALID:
        return "invalid_domain";
    case ZCL_ONTOLOGY_REASON_DOMAIN_CONTEXT:
        return "domain_context_mismatch";
    case ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID:
        return "invalid_domain_registry";
    case ZCL_ONTOLOGY_REASON_VARIABLE_UNBOUND:
        return "variable_unbound";
    case ZCL_ONTOLOGY_REASON_FORMULA_EVIDENCE:
        return "formula_evidence_incomplete";
    case ZCL_ONTOLOGY_REASON_EXPLICIT_NEGATION_UNSUPPORTED:
        return "explicit_negation_unsupported";
    case ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED:
        return "enumeration_evidence_unverified";
    case ZCL_ONTOLOGY_REASON_TYPE_EVIDENCE_UNVERIFIED:
        return "type_evidence_unverified";
    case ZCL_ONTOLOGY_REASON_MANIFEST_INVALID:
        return "manifest_invalid";
    case ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID:
        return "horn_query_invalid";
    case ZCL_ONTOLOGY_REASON_HORN_CONTEXT_UNSUPPORTED:
        return "horn_imported_context_rule_unsupported";
    case ZCL_ONTOLOGY_REASON_NONE:
        break;
    }
    return "unknown_incomplete_reason";
}

static bool formula_nonzero(const uint8_t root[32])
{
    return root && zcl_bytes_any_set(root, 32);
}

static bool formula_zero(const uint8_t root[32])
{
    return root && !zcl_bytes_any_set(root, 32);
}

static void formula_hash_start(struct sha3_256_ctx *sha, const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1u);
}

static void formula_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t wire[2];
    zcl_write_u16_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void formula_hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t wire[4];
    zcl_write_u32_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void formula_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t wire[8];
    zcl_write_u64_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

bool zcl_ontology_term_v1_root(
    const struct zcl_ontology_term_v1 *term, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!term || !out ||
        term->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        term->kind < ZCL_ONTOLOGY_TERM_ENTITY ||
        term->kind > ZCL_ONTOLOGY_TERM_LITERAL || term->reserved != 0 ||
        !formula_nonzero(term->vocabulary_root) ||
        !formula_nonzero(term->type_root) ||
        !formula_nonzero(term->identity_root) ||
        !formula_nonzero(term->lexical_root))
        return false;
    struct sha3_256_ctx sha;
    formula_hash_start(&sha, "zcl.ontology_term.v1");
    formula_hash_u16(&sha, term->schema_version);
    sha3_256_write(&sha, &term->kind, 1);
    sha3_256_write(&sha, &term->reserved, 1);
    sha3_256_write(&sha, term->vocabulary_root, 32);
    sha3_256_write(&sha, term->type_root, 32);
    sha3_256_write(&sha, term->identity_root, 32);
    sha3_256_write(&sha, term->lexical_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

bool zcl_ontology_domain_v1_root(
    const struct zcl_ontology_domain_v1 *domain, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!domain || !out ||
        domain->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        domain->reserved != 0 ||
        domain->value_count > ZCL_ONTOLOGY_MAX_DOMAIN_VALUES ||
        (domain->value_count != 0 && !domain->value_roots) ||
        !formula_nonzero(domain->universe_root) ||
        !formula_nonzero(domain->context_root) ||
        !formula_nonzero(domain->type_root) ||
        !formula_nonzero(domain->coverage_evidence_root))
        return false;
    for (uint64_t i = 0; i < domain->value_count; i++) {
        if (!formula_nonzero(domain->value_roots[i]) ||
            (i != 0 && memcmp(domain->value_roots[i - 1u],
                              domain->value_roots[i], 32) >= 0))
            return false;
    }
    struct sha3_256_ctx sha;
    formula_hash_start(&sha, "zcl.ontology_domain.v1");
    formula_hash_u16(&sha, domain->schema_version);
    formula_hash_u16(&sha, domain->reserved);
    sha3_256_write(&sha, domain->universe_root, 32);
    sha3_256_write(&sha, domain->context_root, 32);
    sha3_256_write(&sha, domain->type_root, 32);
    sha3_256_write(&sha, domain->coverage_evidence_root, 32);
    formula_hash_u64(&sha, domain->value_count);
    for (uint64_t i = 0; i < domain->value_count; i++)
        sha3_256_write(&sha, domain->value_roots[i], 32);
    sha3_256_finalize(&sha, out);
    return true;
}

static bool formula_term_zero(
    const struct zcl_ontology_formula_term_v1 *term)
{
    return term->kind == 0 && term->variable == 0 && term->reserved == 0 &&
           formula_zero(term->type_root) && formula_zero(term->value_root);
}

static bool formula_term_shape_valid(
    const struct zcl_ontology_formula_term_v1 *term, uint8_t variable_count)
{
    if (!term || term->reserved != 0 || !formula_nonzero(term->type_root))
        return false;
    if (term->kind == ZCL_ONTOLOGY_FORMULA_CONSTANT)
        return term->variable == 0 && formula_nonzero(term->value_root);
    if (term->kind == ZCL_ONTOLOGY_FORMULA_VARIABLE)
        return term->variable < variable_count &&
               formula_zero(term->value_root);
    return false;
}

static bool formula_node_terms_zero(
    const struct zcl_ontology_formula_node_v1 *node)
{
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if (!formula_term_zero(&node->terms[i])) return false;
    return true;
}

static bool formula_node_shape_valid(
    const struct zcl_ontology_formula_v1 *formula, uint32_t index,
    uint16_t parents[ZCL_ONTOLOGY_MAX_FORMULA_NODES])
{
    const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[index];
    uint32_t none = formula->node_count;
    if (node->op < ZCL_ONTOLOGY_FORMULA_ATOM ||
        node->op > ZCL_ONTOLOGY_FORMULA_EXISTS || node->reserved != 0)
        return false;
    if (node->op == ZCL_ONTOLOGY_FORMULA_ATOM) {
        if (node->arity > ZCL_ONTOLOGY_MAX_ARITY || node->variable != 0 ||
            node->left != none || node->right != none ||
            !formula_nonzero(node->predicate_root) ||
            !formula_zero(node->quantified_type_root))
            return false;
        for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++) {
            if (i < node->arity) {
                if (!formula_term_shape_valid(&node->terms[i],
                                              formula->variable_count))
                    return false;
            } else if (!formula_term_zero(&node->terms[i])) {
                return false;
            }
        }
        return true;
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_EQUAL) {
        if (node->arity != 2 || node->variable != 0 || node->left != none ||
            node->right != none || !formula_zero(node->predicate_root) ||
            !formula_zero(node->quantified_type_root))
            return false;
        if (!formula_term_shape_valid(&node->terms[0],
                                      formula->variable_count) ||
            !formula_term_shape_valid(&node->terms[1],
                                      formula->variable_count) ||
            memcmp(node->terms[0].type_root,
                   node->terms[1].type_root, 32) != 0)
            return false;
        for (size_t i = 2; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
            if (!formula_term_zero(&node->terms[i])) return false;
        return true;
    }
    if (node->arity != 0 || !formula_zero(node->predicate_root) ||
        !formula_node_terms_zero(node))
        return false;
    if (node->op == ZCL_ONTOLOGY_FORMULA_NOT) {
        if (node->variable != 0 || node->left >= index ||
            node->right != none ||
            !formula_zero(node->quantified_type_root))
            return false;
        parents[node->left]++;
        return parents[node->left] == 1;
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_AND ||
        node->op == ZCL_ONTOLOGY_FORMULA_OR ||
        node->op == ZCL_ONTOLOGY_FORMULA_IMPLIES) {
        if (node->variable != 0 || node->left >= index ||
            node->right >= index || node->left == node->right ||
            !formula_zero(node->quantified_type_root))
            return false;
        parents[node->left]++;
        parents[node->right]++;
        return parents[node->left] == 1 && parents[node->right] == 1;
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_FORALL ||
        node->op == ZCL_ONTOLOGY_FORMULA_EXISTS) {
        if (node->variable >= formula->variable_count || node->left >= index ||
            node->right != none ||
            !formula_nonzero(node->quantified_type_root))
            return false;
        parents[node->left]++;
        return parents[node->left] == 1;
    }
    return false;
}

static bool formula_scope_valid(
    const struct zcl_ontology_formula_v1 *formula, uint32_t index,
    bool bound[ZCL_ONTOLOGY_MAX_VARIABLES],
    uint8_t bound_types[ZCL_ONTOLOGY_MAX_VARIABLES][32],
    uint8_t binder_counts[ZCL_ONTOLOGY_MAX_VARIABLES])
{
    const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[index];
    if (node->op == ZCL_ONTOLOGY_FORMULA_ATOM ||
        node->op == ZCL_ONTOLOGY_FORMULA_EQUAL) {
        for (size_t i = 0; i < node->arity; i++) {
            const struct zcl_ontology_formula_term_v1 *term = &node->terms[i];
            if (term->kind == ZCL_ONTOLOGY_FORMULA_VARIABLE &&
                (!bound[term->variable] ||
                 memcmp(bound_types[term->variable], term->type_root, 32)))
                return false;
        }
        return true;
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_NOT)
        return formula_scope_valid(formula, node->left, bound, bound_types,
                                   binder_counts);
    if (node->op == ZCL_ONTOLOGY_FORMULA_AND ||
        node->op == ZCL_ONTOLOGY_FORMULA_OR ||
        node->op == ZCL_ONTOLOGY_FORMULA_IMPLIES)
        return formula_scope_valid(formula, node->left, bound, bound_types,
                                   binder_counts) &&
               formula_scope_valid(formula, node->right, bound, bound_types,
                                   binder_counts);
    if (bound[node->variable] || binder_counts[node->variable] != 0)
        return false;
    binder_counts[node->variable] = 1;
    bound[node->variable] = true;
    memcpy(bound_types[node->variable], node->quantified_type_root, 32);
    bool valid = formula_scope_valid(formula, node->left, bound, bound_types,
                                     binder_counts);
    bound[node->variable] = false;
    memset(bound_types[node->variable], 0, 32);
    return valid;
}

static bool formula_shape_valid(const struct zcl_ontology_formula_v1 *formula)
{
    if (!formula ||
        formula->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        formula->reserved != 0 || formula->node_count == 0 ||
        formula->node_count > ZCL_ONTOLOGY_MAX_FORMULA_NODES ||
        formula->root_index != formula->node_count - 1u ||
        formula->variable_count > ZCL_ONTOLOGY_MAX_VARIABLES ||
        !formula->nodes)
        return false;
    for (size_t i = 0; i < sizeof(formula->reserved_bytes); i++)
        if (formula->reserved_bytes[i] != 0) return false;
    uint16_t parents[ZCL_ONTOLOGY_MAX_FORMULA_NODES] = {0};
    for (uint32_t i = 0; i < formula->node_count; i++)
        if (!formula_node_shape_valid(formula, i, parents)) return false;
    for (uint32_t i = 0; i < formula->node_count; i++) {
        uint16_t expected = i == formula->root_index ? 0 : 1;
        if (parents[i] != expected) return false;
    }
    bool bound[ZCL_ONTOLOGY_MAX_VARIABLES] = {0};
    uint8_t bound_types[ZCL_ONTOLOGY_MAX_VARIABLES][32] = {{0}};
    uint8_t binder_counts[ZCL_ONTOLOGY_MAX_VARIABLES] = {0};
    if (!formula_scope_valid(formula, formula->root_index, bound,
                             bound_types, binder_counts))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_VARIABLES; i++) {
        uint8_t expected = i < formula->variable_count ? 1 : 0;
        if (binder_counts[i] != expected) return false;
    }
    return true;
}

bool zcl_ontology_formula_v1_root(
    const struct zcl_ontology_formula_v1 *formula, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out || !formula_shape_valid(formula)) return false;
    struct sha3_256_ctx sha;
    formula_hash_start(&sha, "zcl.ontology_formula.v1");
    formula_hash_u16(&sha, formula->schema_version);
    formula_hash_u16(&sha, formula->reserved);
    formula_hash_u32(&sha, formula->node_count);
    formula_hash_u32(&sha, formula->root_index);
    sha3_256_write(&sha, &formula->variable_count, 1);
    sha3_256_write(&sha, formula->reserved_bytes,
                   sizeof(formula->reserved_bytes));
    for (uint32_t i = 0; i < formula->node_count; i++) {
        const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[i];
        const uint8_t fields[] = {
            node->op, node->arity, node->variable, node->reserved,
        };
        sha3_256_write(&sha, fields, sizeof(fields));
        formula_hash_u32(&sha, node->left);
        formula_hash_u32(&sha, node->right);
        sha3_256_write(&sha, node->predicate_root, 32);
        sha3_256_write(&sha, node->quantified_type_root, 32);
        for (size_t j = 0; j < ZCL_ONTOLOGY_MAX_ARITY; j++) {
            const struct zcl_ontology_formula_term_v1 *term = &node->terms[j];
            const uint8_t term_fields[] = {term->kind, term->variable};
            sha3_256_write(&sha, term_fields, sizeof(term_fields));
            formula_hash_u16(&sha, term->reserved);
            sha3_256_write(&sha, term->type_root, 32);
            sha3_256_write(&sha, term->value_root, 32);
        }
    }
    sha3_256_finalize(&sha, out);
    return true;
}

bool zcl_ontology_budget_v1_root(
    const struct zcl_ontology_budget_v1 *budget, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!budget || !out ||
        budget->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        budget->reserved != 0)
        return false;
    struct sha3_256_ctx sha;
    formula_hash_start(&sha, "zcl.ontology_budget.v1");
    formula_hash_u16(&sha, budget->schema_version);
    formula_hash_u16(&sha, budget->reserved);
    formula_hash_u64(&sha, budget->memory_limit_bytes);
    formula_hash_u64(&sha, budget->fact_limit);
    formula_hash_u64(&sha, budget->step_limit);
    formula_hash_u64(&sha, budget->recursion_limit);
    formula_hash_u64(&sha, budget->derivation_limit);
    formula_hash_u64(&sha, budget->time_limit_us);
    sha3_256_finalize(&sha, out);
    return true;
}

static bool derivation_status_valid(
    const struct zcl_ontology_derivation_v1 *derivation)
{
    bool positive = derivation->observed_positive != 0;
    bool negative = derivation->observed_negative != 0;
    if (derivation->status == ZCL_ONTOLOGY_INCOMPLETE)
        return derivation->complete == 0 &&
               derivation->incomplete_reason > ZCL_ONTOLOGY_REASON_NONE &&
               derivation->incomplete_reason <=
                   ZCL_ONTOLOGY_REASON_TYPE_EVIDENCE_UNVERIFIED;
    if (derivation->complete == 0 ||
        derivation->incomplete_reason != ZCL_ONTOLOGY_REASON_NONE)
        return false;
    if (derivation->status == ZCL_ONTOLOGY_PROVED)
        return positive && !negative;
    if (derivation->status == ZCL_ONTOLOGY_DISPROVED)
        return !positive && negative;
    if (derivation->status == ZCL_ONTOLOGY_BOTH)
        return positive && negative;
    if (derivation->status == ZCL_ONTOLOGY_UNKNOWN)
        return !positive && !negative;
    return false;
}

static bool derivation_zero_work_reason_valid(uint8_t reason)
{
    return reason == ZCL_ONTOLOGY_REASON_MEMORY_BUDGET ||
           reason == ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING ||
           reason == ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID ||
           reason == ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID ||
           reason == ZCL_ONTOLOGY_REASON_RECURSION_BUDGET;
}

static bool derivation_pre_step_reason_valid(uint8_t reason)
{
    return reason == ZCL_ONTOLOGY_REASON_STEP_BUDGET ||
           reason == ZCL_ONTOLOGY_REASON_TIME_BUDGET ||
           reason == ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED;
}

static bool derivation_counters_valid(
    const struct zcl_ontology_derivation_v1 *derivation)
{
    if (derivation->derivations_produced > derivation->steps_taken)
        return false;
    if (derivation->status != ZCL_ONTOLOGY_INCOMPLETE)
        return derivation->steps_taken != 0 &&
               derivation->derivations_produced != 0 &&
               derivation->max_recursion_depth != 0;
    if (derivation->steps_taken == 0) {
        if (derivation->derivations_produced != 0) return false;
        if (derivation->max_recursion_depth == 0)
            return derivation_zero_work_reason_valid(
                derivation->incomplete_reason);
        return derivation_pre_step_reason_valid(
            derivation->incomplete_reason);
    }
    if (derivation->max_recursion_depth == 0) return false;
    if (derivation->derivations_produced == 0)
        return derivation->incomplete_reason ==
               ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET;
    return true;
}

bool zcl_ontology_derivation_v1_root(
    const struct zcl_ontology_derivation_v1 *derivation, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!derivation || !out ||
        derivation->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        derivation->reserved_byte != 0 || derivation->reserved != 0 ||
        derivation->observed_positive > 1 ||
        derivation->observed_negative > 1 || derivation->complete > 1 ||
        !derivation_status_valid(derivation) ||
        (derivation->missing_coverage_mask & ~ZCL_SOURCE_COVER_ALL) != 0 ||
        (derivation->status != ZCL_ONTOLOGY_INCOMPLETE &&
         derivation->missing_coverage_mask != 0) ||
        !derivation_counters_valid(derivation) ||
        (derivation->missing_coverage_mask != 0 &&
         derivation->incomplete_reason !=
             ZCL_ONTOLOGY_REASON_COVERAGE_MISSING &&
         derivation->incomplete_reason !=
             ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED) ||
        !formula_nonzero(derivation->universe_root) ||
        !formula_nonzero(derivation->context_root) ||
        !formula_nonzero(derivation->formula_root) ||
        !formula_nonzero(derivation->budget_root) ||
        !formula_nonzero(derivation->evidence_manifest_root) ||
        !formula_nonzero(derivation->evaluator_root) ||
        ((derivation->parent_count == 0) !=
         formula_zero(derivation->parent_manifest_root)))
        return false;
    struct sha3_256_ctx sha;
    formula_hash_start(&sha, "zcl.ontology_derivation.v1");
    formula_hash_u16(&sha, derivation->schema_version);
    const uint8_t fields[] = {
        derivation->status, derivation->observed_positive,
        derivation->observed_negative, derivation->complete,
        derivation->incomplete_reason, derivation->reserved_byte,
    };
    sha3_256_write(&sha, fields, sizeof(fields));
    formula_hash_u16(&sha, derivation->reserved);
    formula_hash_u32(&sha, derivation->missing_coverage_mask);
    formula_hash_u64(&sha, derivation->facts_examined);
    formula_hash_u64(&sha, derivation->steps_taken);
    formula_hash_u64(&sha, derivation->derivations_produced);
    formula_hash_u32(&sha, derivation->max_recursion_depth);
    formula_hash_u32(&sha, derivation->parent_count);
    sha3_256_write(&sha, derivation->universe_root, 32);
    sha3_256_write(&sha, derivation->context_root, 32);
    sha3_256_write(&sha, derivation->formula_root, 32);
    sha3_256_write(&sha, derivation->budget_root, 32);
    sha3_256_write(&sha, derivation->evidence_manifest_root, 32);
    sha3_256_write(&sha, derivation->parent_manifest_root, 32);
    sha3_256_write(&sha, derivation->evaluator_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

static bool horn_derivation_reason_valid(uint8_t reason)
{
    switch (reason) {
    case ZCL_ONTOLOGY_REASON_FACT_BUDGET:
    case ZCL_ONTOLOGY_REASON_STEP_BUDGET:
    case ZCL_ONTOLOGY_REASON_RECURSION_BUDGET:
    case ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET:
    case ZCL_ONTOLOGY_REASON_MEMORY_BUDGET:
    case ZCL_ONTOLOGY_REASON_TIME_BUDGET:
    case ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING:
    case ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED:
    case ZCL_ONTOLOGY_REASON_PREDICATE_MISSING:
    case ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID:
    case ZCL_ONTOLOGY_REASON_VARIABLE_UNBOUND:
    case ZCL_ONTOLOGY_REASON_MANIFEST_INVALID:
    case ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID:
    case ZCL_ONTOLOGY_REASON_HORN_CONTEXT_UNSUPPORTED:
        return true;
    case ZCL_ONTOLOGY_REASON_NONE:
    case ZCL_ONTOLOGY_REASON_PREDICATE_ARITY:
    case ZCL_ONTOLOGY_REASON_PREDICATE_TYPE:
    case ZCL_ONTOLOGY_REASON_PREDICATE_TIER:
    case ZCL_ONTOLOGY_REASON_ASSERTION_INVALID:
    case ZCL_ONTOLOGY_REASON_COVERAGE_MISSING:
    case ZCL_ONTOLOGY_REASON_DOMAIN_MISSING:
    case ZCL_ONTOLOGY_REASON_DOMAIN_INVALID:
    case ZCL_ONTOLOGY_REASON_DOMAIN_CONTEXT:
    case ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID:
    case ZCL_ONTOLOGY_REASON_FORMULA_EVIDENCE:
    case ZCL_ONTOLOGY_REASON_EXPLICIT_NEGATION_UNSUPPORTED:
    case ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED:
    case ZCL_ONTOLOGY_REASON_TYPE_EVIDENCE_UNVERIFIED:
        return false;
    }
    return false;
}

static bool horn_derivation_status_valid(
    const struct zcl_ontology_horn_derivation_v1 *derivation)
{
    bool positive = derivation->observed_positive != 0;
    bool negative = derivation->observed_negative != 0;
    if (derivation->status == ZCL_ONTOLOGY_INCOMPLETE)
        return derivation->complete == 0 &&
               horn_derivation_reason_valid(derivation->incomplete_reason);
    if (derivation->complete == 0 ||
        derivation->incomplete_reason != ZCL_ONTOLOGY_REASON_NONE)
        return false;
    if (derivation->status == ZCL_ONTOLOGY_PROVED)
        return positive && !negative;
    if (derivation->status == ZCL_ONTOLOGY_DISPROVED)
        return !positive && negative;
    if (derivation->status == ZCL_ONTOLOGY_BOTH)
        return positive && negative;
    if (derivation->status == ZCL_ONTOLOGY_UNKNOWN)
        return !positive && !negative;
    return false;
}

static bool horn_derivation_counters_valid(
    const struct zcl_ontology_horn_derivation_v1 *derivation)
{
    if (derivation->facts_examined > derivation->steps_taken ||
        derivation->derivations_produced > derivation->steps_taken ||
        (derivation->derivations_produced != 0 &&
         derivation->max_recursion_depth == 0))
        return false;
    if (derivation->status != ZCL_ONTOLOGY_INCOMPLETE)
        return derivation->steps_taken != 0;
    return true;
}

static bool formula_ranges_overlap(
    const void *left, size_t left_size, const void *right, size_t right_size)
{
    if (!left || !right || left_size == 0 || right_size == 0) return false;
    uintptr_t left_begin = (uintptr_t)left;
    uintptr_t right_begin = (uintptr_t)right;
    if (left_size > UINTPTR_MAX - left_begin ||
        right_size > UINTPTR_MAX - right_begin)
        return true;
    return left_begin < right_begin + right_size &&
           right_begin < left_begin + left_size;
}

bool zcl_ontology_horn_derivation_v1_root(
    const struct zcl_ontology_horn_derivation_v1 *derivation,
    uint8_t out[32])
{
    if (!derivation || !out || formula_ranges_overlap(
            derivation, sizeof(*derivation), out, 32))
        return false;
    memset(out, 0, 32);
    if (
        derivation->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        derivation->reserved_byte != 0 || derivation->reserved != 0 ||
        derivation->observed_positive > 1 ||
        derivation->observed_negative > 1 || derivation->complete > 1 ||
        !horn_derivation_status_valid(derivation) ||
        (derivation->missing_coverage_mask & ~ZCL_SOURCE_COVER_ALL) != 0 ||
        (derivation->status != ZCL_ONTOLOGY_INCOMPLETE &&
         derivation->missing_coverage_mask != 0) ||
        !horn_derivation_counters_valid(derivation) ||
        (derivation->missing_coverage_mask != 0 &&
         derivation->incomplete_reason !=
             ZCL_ONTOLOGY_REASON_COVERAGE_MISSING &&
         derivation->incomplete_reason !=
             ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED) ||
        !formula_nonzero(derivation->universe_root) ||
        !formula_nonzero(derivation->context_root) ||
        !formula_nonzero(derivation->query_root) ||
        !formula_nonzero(derivation->budget_root) ||
        !formula_nonzero(derivation->evidence_manifest_root) ||
        !formula_nonzero(derivation->evaluator_root) ||
        ((derivation->parent_count == 0) !=
         formula_zero(derivation->parent_manifest_root)))
        return false;
    struct sha3_256_ctx sha;
    formula_hash_start(&sha, "zcl.ontology_horn_derivation.v1");
    formula_hash_u16(&sha, derivation->schema_version);
    const uint8_t fields[] = {
        derivation->status, derivation->observed_positive,
        derivation->observed_negative, derivation->complete,
        derivation->incomplete_reason, derivation->reserved_byte,
    };
    sha3_256_write(&sha, fields, sizeof(fields));
    formula_hash_u16(&sha, derivation->reserved);
    formula_hash_u32(&sha, derivation->missing_coverage_mask);
    formula_hash_u64(&sha, derivation->facts_examined);
    formula_hash_u64(&sha, derivation->steps_taken);
    formula_hash_u64(&sha, derivation->derivations_produced);
    formula_hash_u32(&sha, derivation->max_recursion_depth);
    formula_hash_u32(&sha, derivation->parent_count);
    sha3_256_write(&sha, derivation->universe_root, 32);
    sha3_256_write(&sha, derivation->context_root, 32);
    sha3_256_write(&sha, derivation->query_root, 32);
    sha3_256_write(&sha, derivation->budget_root, 32);
    sha3_256_write(&sha, derivation->evidence_manifest_root, 32);
    sha3_256_write(&sha, derivation->parent_manifest_root, 32);
    sha3_256_write(&sha, derivation->evaluator_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

bool zcl_ontology_evaluator_init_v1(
    void *storage, size_t storage_size,
    struct zcl_ontology_evaluator **out_evaluator)
{
    if (!out_evaluator) return false;
    uintptr_t storage_begin = (uintptr_t)storage;
    uintptr_t output_begin = (uintptr_t)out_evaluator;
    if (storage &&
        (storage_size > UINTPTR_MAX - storage_begin ||
         sizeof(*out_evaluator) > UINTPTR_MAX - output_begin ||
         (storage_begin < output_begin + sizeof(*out_evaluator) &&
          output_begin < storage_begin + storage_size)))
        return false;
    *out_evaluator = NULL;
    if (!storage ||
        storage_size < ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES ||
        (uintptr_t)storage % _Alignof(struct zcl_ontology_evaluator) != 0)
        return false;
    memset(storage, 0, sizeof(struct zcl_ontology_evaluator));
    struct zcl_ontology_evaluator *evaluator = storage;
    evaluator->magic = ZCL_ONTOLOGY_EVALUATOR_MAGIC;
    *out_evaluator = evaluator;
    return true;
}

size_t zcl_ontology_evaluator_alignment_v1(void)
{
    return _Alignof(struct zcl_ontology_evaluator);
}

static void runtime_fail(struct ontology_eval_runtime *runtime,
                         enum zcl_ontology_incomplete_reason reason)
{
    if (runtime->reason == ZCL_ONTOLOGY_REASON_NONE)
        runtime->reason = reason;
}

static void runtime_note_incomplete(
    struct ontology_eval_runtime *runtime,
    enum zcl_ontology_incomplete_reason reason)
{
    if (runtime->soft_reason == ZCL_ONTOLOGY_REASON_NONE)
        runtime->soft_reason = reason;
}

static bool runtime_time_available(struct ontology_eval_runtime *runtime)
{
    uint64_t now = runtime->query->elapsed_us(
        runtime->query->elapsed_context);
    if (now < runtime->started_us) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED);
        return false;
    }
    if (now - runtime->started_us >= runtime->query->budget->time_limit_us) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_TIME_BUDGET);
        return false;
    }
    return true;
}

static bool runtime_step(struct ontology_eval_runtime *runtime)
{
    if (runtime->reason) return false;
    if (!runtime_time_available(runtime)) return false;
    if (runtime->result->steps_taken >= runtime->query->budget->step_limit) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_STEP_BUDGET);
        return false;
    }
    runtime->result->steps_taken++;
    return true;
}

static bool runtime_derivation(struct ontology_eval_runtime *runtime)
{
    if (runtime->result->derivations_produced >=
        runtime->query->budget->derivation_limit) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET);
        return false;
    }
    runtime->result->derivations_produced++;
    return true;
}

static bool formula_context_visible(
    const struct zcl_ontology_formula_query_v1 *query,
    const uint8_t context_root[32])
{
    if (memcmp(query->context_root, context_root, 32) == 0) return true;
    for (size_t i = 0; i < query->import_count; i++)
        if (memcmp(query->import_context_roots[i], context_root, 32) == 0)
            return true;
    return false;
}

static bool formula_contexts_bound(
    const struct zcl_ontology_formula_query_v1 *query,
    const uint8_t universe_root[32])
{
    uint8_t imports_root[32];
    if (!query->contexts || query->context_count == 0 ||
        query->context_count > ZCL_ONTOLOGY_MAX_CONTEXTS ||
        query->import_count > ZCL_ONTOLOGY_MAX_IMPORTS ||
        (query->import_count && !query->import_context_roots) ||
        memcmp(query->universe_root, universe_root, 32) != 0 ||
        !zcl_ontology_import_manifest_v1_root(
            universe_root, query->import_context_roots,
            query->import_count, imports_root))
        return false;
    for (size_t wanted = 0; wanted <= query->import_count; wanted++) {
        const uint8_t *root = wanted == 0 ? query->context_root :
            query->import_context_roots[wanted - 1u];
        bool found = false;
        for (size_t i = 0; i < query->context_count; i++) {
            uint8_t actual[32];
            if (zcl_ontology_context_v1_root(&query->contexts[i], actual) &&
                memcmp(actual, root, 32) == 0 &&
                memcmp(query->contexts[i].universe_root,
                       universe_root, 32) == 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    for (size_t i = 0; i < query->context_count; i++) {
        uint8_t actual[32];
        if (zcl_ontology_context_v1_root(&query->contexts[i], actual) &&
            memcmp(actual, query->context_root, 32) == 0 &&
            memcmp(query->contexts[i].import_manifest_root,
                   imports_root, 32) == 0)
            return true;
    }
    return false;
}

static bool formula_coverage_declared_for_all_contexts(
    const struct zcl_ontology_formula_query_v1 *query, uint32_t required)
{
    for (size_t wanted = 0; wanted <= query->import_count; wanted++) {
        const uint8_t *context = wanted == 0 ? query->context_root :
            query->import_context_roots[wanted - 1u];
        bool declared = false;
        for (size_t i = 0; i < query->coverage_count; i++) {
            uint8_t ignored[32];
            if (zcl_ontology_coverage_v1_root(&query->coverage[i], ignored) &&
                memcmp(query->coverage[i].universe_root,
                       query->universe_root, 32) == 0 &&
                memcmp(query->coverage[i].context_root, context, 32) == 0 &&
                (query->coverage[i].complete_mask & required) == required) {
                declared = true;
                break;
            }
        }
        if (!declared) return false;
    }
    return true;
}

static const struct zcl_ontology_predicate_v1 *formula_predicate(
    struct ontology_eval_runtime *runtime, const uint8_t root[32])
{
    for (size_t i = 0; i < runtime->query->predicate_count; i++) {
        if (memcmp(runtime->evaluator->predicate_roots[i], root, 32) == 0)
            return &runtime->query->predicates[i];
    }
    runtime_fail(runtime, ZCL_ONTOLOGY_REASON_PREDICATE_MISSING);
    return NULL;
}

static bool formula_predicate_registry_valid(
    struct ontology_eval_runtime *runtime)
{
    for (size_t i = 0; i < runtime->query->predicate_count; i++) {
        if (!runtime_step(runtime)) return false;
        if (!zcl_ontology_predicate_v1_root(
                &runtime->query->predicates[i],
                runtime->evaluator->predicate_roots[i])) {
            runtime_fail(runtime,
                         ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID);
            return false;
        }
        for (size_t j = 0; j < i; j++) {
            if (memcmp(runtime->evaluator->predicate_roots[j],
                       runtime->evaluator->predicate_roots[i], 32) == 0) {
                runtime_fail(runtime,
                             ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID);
                return false;
            }
        }
    }
    return true;
}

static const uint8_t *formula_visible_context_at(
    const struct zcl_ontology_formula_query_v1 *query, size_t index)
{
    return index == 0 ? query->context_root :
        query->import_context_roots[index - 1u];
}

static int formula_domain_key_compare(
    const struct zcl_ontology_domain_v1 *left,
    const struct zcl_ontology_domain_v1 *right)
{
    int compared = memcmp(left->type_root, right->type_root, 32);
    return compared != 0 ? compared :
        memcmp(left->context_root, right->context_root, 32);
}

static bool formula_domain_registry_valid(
    struct ontology_eval_runtime *runtime)
{
    for (size_t i = 0; i < runtime->query->domain_count; i++) {
        const struct zcl_ontology_domain_v1 *domain =
            &runtime->query->domains[i];
        uint8_t ignored[32];
        if (!runtime_step(runtime)) return false;
        if (!zcl_ontology_domain_v1_root(domain, ignored) ||
            memcmp(domain->universe_root,
                   runtime->query->universe_root, 32) != 0 ||
            !formula_context_visible(runtime->query, domain->context_root) ||
            (i != 0 && formula_domain_key_compare(
                           &runtime->query->domains[i - 1u], domain) >= 0)) {
            runtime_fail(runtime,
                         ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID);
            return false;
        }
    }
    return true;
}

static bool formula_working_set_add(
    uint64_t *total, uint64_t count, uint64_t element_size)
{
    if (!total || element_size == 0 ||
        count > UINT64_MAX / element_size)
        return false;
    uint64_t bytes = count * element_size;
    if (*total > UINT64_MAX - bytes) return false;
    *total += bytes;
    return true;
}

static bool formula_working_set_add_size(
    uint64_t *total, size_t count, size_t element_size)
{
    uint64_t count64 = (uint64_t)count;
    uint64_t element64 = (uint64_t)element_size;
    if ((size_t)count64 != count || (size_t)element64 != element_size)
        return false;
    return formula_working_set_add(total, count64, element64);
}

static bool formula_working_set_bytes(
    const struct zcl_ontology_formula_v1 *formula,
    const struct zcl_ontology_formula_query_v1 *query, uint64_t *out)
{
    if (!formula || !query || !out) return false;
    uint64_t total = ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES;
    if (!formula_working_set_add(
            &total, formula->node_count,
            sizeof(struct zcl_ontology_formula_node_v1)) ||
        !formula_working_set_add_size(
            &total, query->predicate_count,
            sizeof(struct zcl_ontology_predicate_v1)) ||
        !formula_working_set_add_size(
            &total, query->assertion_count,
            sizeof(struct zcl_ontology_assertion_v1)) ||
        !formula_working_set_add_size(
            &total, query->context_count,
            sizeof(struct zcl_ontology_context_v1)) ||
        !formula_working_set_add_size(
            &total, query->coverage_count,
            sizeof(struct zcl_ontology_coverage_v1)) ||
        !formula_working_set_add_size(
            &total, query->domain_count,
            sizeof(struct zcl_ontology_domain_v1)) ||
        !formula_working_set_add_size(
            &total, query->import_count, sizeof(uint8_t[32])))
        return false;
    for (size_t i = 0; i < query->domain_count; i++)
        if (!formula_working_set_add(
                &total, query->domains[i].value_count,
                sizeof(uint8_t[32])))
            return false;
    *out = total;
    return true;
}

static const struct zcl_ontology_domain_v1 *formula_domain_for_context(
    struct ontology_eval_runtime *runtime, const uint8_t type_root[32],
    const uint8_t context_root[32])
{
    for (size_t i = 0; i < runtime->query->domain_count; i++) {
        const struct zcl_ontology_domain_v1 *domain =
            &runtime->query->domains[i];
        if (memcmp(domain->type_root, type_root, 32) == 0 &&
            memcmp(domain->context_root, context_root, 32) == 0)
            return domain;
    }
    runtime_fail(runtime, ZCL_ONTOLOGY_REASON_DOMAIN_MISSING);
    return NULL;
}

static const uint8_t *formula_resolve_term(
    struct ontology_eval_runtime *runtime,
    const struct zcl_ontology_formula_term_v1 *term)
{
    if (term->kind == ZCL_ONTOLOGY_FORMULA_CONSTANT) {
        runtime_note_incomplete(
            runtime, ZCL_ONTOLOGY_REASON_TYPE_EVIDENCE_UNVERIFIED);
        return term->value_root;
    }
    if (!runtime->evaluator->bound[term->variable]) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_VARIABLE_UNBOUND);
        return NULL;
    }
    return runtime->evaluator->bindings[term->variable];
}

static struct ontology_truth formula_eval_atom(
    struct ontology_eval_runtime *runtime,
    const struct zcl_ontology_formula_node_v1 *node)
{
    struct ontology_truth truth = {.complete = false};
    const struct zcl_ontology_predicate_v1 *predicate =
        formula_predicate(runtime, node->predicate_root);
    if (!predicate) return truth;
    if (predicate->arity != node->arity) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_PREDICATE_ARITY);
        return truth;
    }
    for (size_t i = 0; i < node->arity; i++) {
        if (memcmp(predicate->argument_type_roots[i],
                   node->terms[i].type_root, 32) != 0) {
            runtime_fail(runtime, ZCL_ONTOLOGY_REASON_PREDICATE_TYPE);
            return truth;
        }
    }
    if (predicate->execution_tier != ZCL_ONTOLOGY_TIER_EXACT) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_PREDICATE_TIER);
        return truth;
    }
    uint8_t arguments[ZCL_ONTOLOGY_MAX_ARITY][32] = {{0}};
    for (size_t i = 0; i < node->arity; i++) {
        const uint8_t *resolved = formula_resolve_term(runtime,
                                                       &node->terms[i]);
        if (!resolved) return truth;
        memcpy(arguments[i], resolved, 32);
    }
    for (size_t i = 0; i < runtime->query->assertion_count; i++) {
        if (runtime->result->facts_examined >=
            runtime->query->budget->fact_limit) {
            runtime_fail(runtime, ZCL_ONTOLOGY_REASON_FACT_BUDGET);
            return truth;
        }
        if (!runtime_step(runtime)) return truth;
        runtime->result->facts_examined++;
        const struct zcl_ontology_assertion_v1 *assertion =
            &runtime->query->assertions[i];
        uint8_t ignored[32];
        if (!zcl_ontology_assertion_v1_root(assertion, ignored)) {
            runtime_fail(runtime, ZCL_ONTOLOGY_REASON_ASSERTION_INVALID);
            return truth;
        }
        if (assertion->arity != node->arity ||
            !formula_context_visible(runtime->query,
                                     assertion->context_root) ||
            memcmp(assertion->predicate_root, node->predicate_root, 32) ||
            memcmp(assertion->argument_roots, arguments,
                   sizeof(arguments)))
            continue;
        if (assertion->polarity == ZCL_ONTOLOGY_NEGATIVE &&
            predicate->explicit_negation == 0) {
            runtime_fail(
                runtime,
                ZCL_ONTOLOGY_REASON_EXPLICIT_NEGATION_UNSUPPORTED);
            return truth;
        }
        if (assertion->polarity == ZCL_ONTOLOGY_POSITIVE)
            truth.positive = true;
        if (assertion->polarity == ZCL_ONTOLOGY_NEGATIVE)
            truth.negative = true;
    }
    truth.complete = true;
    if (!truth.positive && !truth.negative &&
        predicate->world == ZCL_ONTOLOGY_CLOSED_WORLD) {
        runtime->result->missing_coverage_mask |=
            predicate->coverage_required;
        if (!formula_coverage_declared_for_all_contexts(
                runtime->query, predicate->coverage_required)) {
            runtime_fail(runtime, ZCL_ONTOLOGY_REASON_COVERAGE_MISSING);
            truth.complete = false;
        } else {
            runtime_note_incomplete(
                runtime,
                ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED);
            truth.complete = false;
        }
    }
    return truth;
}

static struct ontology_truth formula_eval_node(
    struct ontology_eval_runtime *runtime,
    const struct zcl_ontology_formula_v1 *formula, uint32_t index,
    uint32_t depth)
{
    struct ontology_truth unavailable = {.complete = false};
    if (runtime->reason) return unavailable;
    if (depth > runtime->query->budget->recursion_limit) {
        runtime_fail(runtime, ZCL_ONTOLOGY_REASON_RECURSION_BUDGET);
        return unavailable;
    }
    if (depth > runtime->result->max_recursion_depth)
        runtime->result->max_recursion_depth = depth;
    if (!runtime_step(runtime) || !runtime_derivation(runtime))
        return unavailable;
    const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[index];
    if (node->op == ZCL_ONTOLOGY_FORMULA_ATOM)
        return formula_eval_atom(runtime, node);
    if (node->op == ZCL_ONTOLOGY_FORMULA_EQUAL) {
        const uint8_t *left = formula_resolve_term(runtime, &node->terms[0]);
        const uint8_t *right = formula_resolve_term(runtime, &node->terms[1]);
        if (!left || !right) return unavailable;
        bool equal = memcmp(left, right, 32) == 0;
        return (struct ontology_truth){
            .positive = equal, .negative = !equal, .complete = true,
        };
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_NOT) {
        struct ontology_truth child = formula_eval_node(
            runtime, formula, node->left, depth + 1u);
        return (struct ontology_truth){
            .positive = child.negative, .negative = child.positive,
            .complete = child.complete,
        };
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_AND ||
        node->op == ZCL_ONTOLOGY_FORMULA_OR ||
        node->op == ZCL_ONTOLOGY_FORMULA_IMPLIES) {
        struct ontology_truth left = formula_eval_node(
            runtime, formula, node->left, depth + 1u);
        struct ontology_truth right = formula_eval_node(
            runtime, formula, node->right, depth + 1u);
        struct ontology_truth combined = {
            .complete = left.complete && right.complete,
        };
        if (node->op == ZCL_ONTOLOGY_FORMULA_AND) {
            combined.positive = left.positive && right.positive;
            combined.negative = left.negative || right.negative;
        } else if (node->op == ZCL_ONTOLOGY_FORMULA_OR) {
            combined.positive = left.positive || right.positive;
            combined.negative = left.negative && right.negative;
        } else {
            combined.positive = left.negative || right.positive;
            combined.negative = left.positive && right.negative;
        }
        return combined;
    }
    struct ontology_truth aggregate = {
        .positive = node->op == ZCL_ONTOLOGY_FORMULA_FORALL,
        .negative = node->op == ZCL_ONTOLOGY_FORMULA_EXISTS,
        .complete = true,
    };
    runtime->evaluator->bound[node->variable] = true;
    uint64_t examined = 0, expected = 0;
    size_t visible_count = runtime->query->import_count + 1u;
    bool enumeration_unverified = false;
    for (size_t context_index = 0; context_index < visible_count;
         context_index++) {
        const uint8_t *context_root = formula_visible_context_at(
            runtime->query, context_index);
        const struct zcl_ontology_domain_v1 *domain =
            formula_domain_for_context(runtime, node->quantified_type_root,
                                       context_root);
        if (!domain) {
            aggregate.complete = false;
            break;
        }
        enumeration_unverified = true;
        expected += domain->value_count;
        for (uint64_t i = 0; i < domain->value_count; i++) {
            if (!runtime_step(runtime)) {
                aggregate.complete = false;
                break;
            }
            memcpy(runtime->evaluator->bindings[node->variable],
                   domain->value_roots[i], 32);
            struct ontology_truth child = formula_eval_node(
                runtime, formula, node->left, depth + 1u);
            examined++;
            aggregate.complete = aggregate.complete && child.complete;
            if (node->op == ZCL_ONTOLOGY_FORMULA_FORALL) {
                aggregate.positive = aggregate.positive && child.positive;
                aggregate.negative = aggregate.negative || child.negative;
            } else {
                aggregate.positive = aggregate.positive || child.positive;
                aggregate.negative = aggregate.negative && child.negative;
            }
            if (runtime->reason) break;
        }
        if (runtime->reason) break;
    }
    runtime->evaluator->bound[node->variable] = false;
    memset(runtime->evaluator->bindings[node->variable], 0, 32);
    if (examined != expected || runtime->reason) aggregate.complete = false;
    if (enumeration_unverified) {
        aggregate.complete = false;
        runtime_note_incomplete(
            runtime,
            ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED);
    }
    if (!aggregate.complete) {
        if (node->op == ZCL_ONTOLOGY_FORMULA_FORALL)
            aggregate.positive = false;
        else
            aggregate.negative = false;
    }
    return aggregate;
}

static void formula_finish_result(struct ontology_eval_runtime *runtime,
                                  struct ontology_truth truth)
{
    struct zcl_ontology_result_v1 *result = runtime->result;
    result->observed_positive = truth.positive;
    result->observed_negative = truth.negative;
    if (runtime->reason || runtime->soft_reason || !truth.complete) {
        result->status = ZCL_ONTOLOGY_INCOMPLETE;
        result->complete = false;
        enum zcl_ontology_incomplete_reason reason = runtime->reason;
        if (reason == ZCL_ONTOLOGY_REASON_NONE)
            reason = runtime->soft_reason;
        if (reason == ZCL_ONTOLOGY_REASON_NONE)
            reason = ZCL_ONTOLOGY_REASON_FORMULA_EVIDENCE;
        result->incomplete_reason = reason;
        result->truncation_reason = formula_reason_string(reason);
        return;
    }
    if (truth.positive && truth.negative)
        result->status = ZCL_ONTOLOGY_BOTH;
    else if (truth.positive)
        result->status = ZCL_ONTOLOGY_PROVED;
    else if (truth.negative)
        result->status = ZCL_ONTOLOGY_DISPROVED;
    else
        result->status = ZCL_ONTOLOGY_UNKNOWN;
    result->complete = true;
}

bool zcl_ontology_evaluate_formula_v1(
    struct zcl_ontology_evaluator *evaluator,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_formula_v1 *formula,
    const struct zcl_ontology_formula_query_v1 *query,
    struct zcl_ontology_result_v1 *out)
{
    uint8_t universe_root[32], formula_root[32], budget_root[32];
    uint64_t working_set_bytes = 0;
    if (out) memset(out, 0, sizeof(*out));
    if (!evaluator || evaluator->magic != ZCL_ONTOLOGY_EVALUATOR_MAGIC ||
        !out || !query || !query->budget ||
        !zcl_source_universe_v1_root(universe, universe_root) ||
        !zcl_ontology_formula_v1_root(formula, formula_root) ||
        !zcl_ontology_budget_v1_root(query->budget, budget_root) ||
        query->predicate_count > ZCL_ONTOLOGY_MAX_PREDICATES ||
        (query->predicate_count && !query->predicates) ||
        (query->assertion_count && !query->assertions) ||
        query->coverage_count > ZCL_ONTOLOGY_MAX_COVERAGE ||
        (query->coverage_count && !query->coverage) ||
        query->domain_count > ZCL_ONTOLOGY_MAX_DOMAINS ||
        (query->domain_count && !query->domains) ||
        !formula_contexts_bound(query, universe_root))
        return false;
    memset(evaluator->bound, 0, sizeof(evaluator->bound));
    memset(evaluator->bindings, 0, sizeof(evaluator->bindings));
    memset(evaluator->predicate_roots, 0,
           sizeof(evaluator->predicate_roots));
    if (!query->elapsed_us) {
        out->status = ZCL_ONTOLOGY_INCOMPLETE;
        out->incomplete_reason = ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING;
        out->truncation_reason = formula_reason_string(
            out->incomplete_reason);
        return true;
    }
    struct ontology_eval_runtime runtime = {
        .evaluator = evaluator, .query = query, .result = out,
        .started_us = query->elapsed_us(query->elapsed_context),
    };
    if (!formula_working_set_bytes(formula, query, &working_set_bytes) ||
        query->budget->memory_limit_bytes < working_set_bytes) {
        runtime_fail(&runtime, ZCL_ONTOLOGY_REASON_MEMORY_BUDGET);
        formula_finish_result(&runtime,
                              (struct ontology_truth){.complete = false});
        return true;
    }
    if (!formula_predicate_registry_valid(&runtime) ||
        !formula_domain_registry_valid(&runtime)) {
        formula_finish_result(&runtime,
                              (struct ontology_truth){.complete = false});
        return true;
    }
    struct ontology_truth truth = formula_eval_node(
        &runtime, formula, formula->root_index, 1);
    formula_finish_result(&runtime, truth);
    return true;
}
