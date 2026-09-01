/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Manifest-bound, bounded, paraconsistent Horn fixed-point inference. */
#include "ontology/ontology.h"
#include "ontology_internal.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <string.h>

struct horn_runtime {
    struct zcl_ontology_evaluator *evaluator;
    const struct zcl_source_universe_v1 *universe;
    const struct zcl_ontology_horn_query_v1 *query;
    struct zcl_ontology_result_v1 *result;
    uint64_t started_us;
    enum zcl_ontology_incomplete_reason reason;
    enum zcl_ontology_incomplete_reason soft_reason;
};

static const char *horn_reason_string(
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
    case ZCL_ONTOLOGY_REASON_MANIFEST_INVALID:
        return "manifest_invalid";
    case ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID:
        return "horn_query_invalid";
    case ZCL_ONTOLOGY_REASON_HORN_CONTEXT_UNSUPPORTED:
        return "horn_imported_context_rule_unsupported";
    case ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID:
    case ZCL_ONTOLOGY_REASON_PREDICATE_ARITY:
    case ZCL_ONTOLOGY_REASON_PREDICATE_TYPE:
    case ZCL_ONTOLOGY_REASON_PREDICATE_TIER:
    case ZCL_ONTOLOGY_REASON_ASSERTION_INVALID:
    case ZCL_ONTOLOGY_REASON_COVERAGE_MISSING:
    case ZCL_ONTOLOGY_REASON_DOMAIN_MISSING:
    case ZCL_ONTOLOGY_REASON_DOMAIN_INVALID:
    case ZCL_ONTOLOGY_REASON_DOMAIN_CONTEXT:
    case ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID:
    case ZCL_ONTOLOGY_REASON_VARIABLE_UNBOUND:
    case ZCL_ONTOLOGY_REASON_FORMULA_EVIDENCE:
    case ZCL_ONTOLOGY_REASON_EXPLICIT_NEGATION_UNSUPPORTED:
    case ZCL_ONTOLOGY_REASON_ENUMERATION_EVIDENCE_UNVERIFIED:
    case ZCL_ONTOLOGY_REASON_TYPE_EVIDENCE_UNVERIFIED:
    case ZCL_ONTOLOGY_REASON_NONE:
        break;
    }
    return "horn_evidence_incomplete";
}

static bool horn_nonzero(const uint8_t root[32])
{
    return root && zcl_bytes_any_set(root, 32);
}

static bool horn_ranges_overlap(const void *left, size_t left_size,
                                const void *right, size_t right_size)
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

static void horn_fail(struct horn_runtime *runtime,
                      enum zcl_ontology_incomplete_reason reason)
{
    if (runtime->reason == ZCL_ONTOLOGY_REASON_NONE)
        runtime->reason = reason;
}

static void horn_note_incomplete(
    struct horn_runtime *runtime,
    enum zcl_ontology_incomplete_reason reason)
{
    if (runtime->soft_reason == ZCL_ONTOLOGY_REASON_NONE)
        runtime->soft_reason = reason;
}

static bool horn_time_available(struct horn_runtime *runtime)
{
    uint64_t now = runtime->query->elapsed_us(
        runtime->query->elapsed_context);
    if (now < runtime->started_us) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED);
        return false;
    }
    if (now - runtime->started_us >= runtime->query->budget->time_limit_us) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_TIME_BUDGET);
        return false;
    }
    return true;
}

static bool horn_step(struct horn_runtime *runtime)
{
    if (runtime->reason != ZCL_ONTOLOGY_REASON_NONE) return false;
    if (!horn_time_available(runtime)) return false;
    if (runtime->result->steps_taken >=
        runtime->query->budget->step_limit) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_STEP_BUDGET);
        return false;
    }
    runtime->result->steps_taken++;
    return true;
}

static bool horn_fact_examined(struct horn_runtime *runtime)
{
    if (runtime->result->facts_examined >=
        runtime->query->budget->fact_limit) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_FACT_BUDGET);
        return false;
    }
    if (!horn_step(runtime)) return false;
    runtime->result->facts_examined++;
    return true;
}

static bool horn_derivation(struct horn_runtime *runtime)
{
    if (runtime->result->derivations_produced >=
        runtime->query->budget->derivation_limit) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET);
        return false;
    }
    runtime->result->derivations_produced++;
    return true;
}

static bool horn_context_visible(
    const struct zcl_ontology_horn_query_v1 *query,
    const uint8_t context_root[32])
{
    if (memcmp(query->context_root, context_root, 32) == 0) return true;
    for (size_t i = 0; i < query->import_count; i++)
        if (memcmp(query->import_context_roots[i], context_root, 32) == 0)
            return true;
    return false;
}

static bool horn_contexts_bound(
    const struct zcl_ontology_horn_query_v1 *query,
    const struct zcl_ontology_manifest_inputs_v1 *inputs)
{
    uint8_t imports_root[32];
    if (!zcl_ontology_import_manifest_v1_root(
            query->universe_root, query->import_context_roots,
            query->import_count, imports_root))
        return false;
    bool primary_bound = false;
    for (size_t wanted = 0; wanted <= query->import_count; wanted++) {
        const uint8_t *wanted_root = wanted == 0 ? query->context_root :
            query->import_context_roots[wanted - 1u];
        bool found = false;
        for (size_t i = 0; i < inputs->context_count; i++) {
            uint8_t actual[32];
            if (!zcl_ontology_context_v1_root(&inputs->contexts[i], actual) ||
                memcmp(actual, wanted_root, 32) != 0)
                continue;
            found = true;
            if (wanted == 0 && memcmp(
                    inputs->contexts[i].import_manifest_root,
                    imports_root, 32) == 0)
                primary_bound = true;
            break;
        }
        if (!found) return false;
    }
    return primary_bound;
}

static bool horn_add_bytes(uint64_t *total, size_t count, size_t size)
{
    uint64_t count64 = (uint64_t)count;
    uint64_t size64 = (uint64_t)size;
    if ((size_t)count64 != count || (size_t)size64 != size ||
        (size64 != 0 && count64 > UINT64_MAX / size64))
        return false;
    uint64_t bytes = count64 * size64;
    if (*total > UINT64_MAX - bytes) return false;
    *total += bytes;
    return true;
}

static bool horn_working_set_bytes(
    const struct zcl_ontology_horn_query_v1 *query, uint64_t *out)
{
    const struct zcl_ontology_manifest_inputs_v1 *inputs = query->inputs;
    uint64_t total = ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES;
    if (!horn_add_bytes(&total, inputs->term_count,
                        sizeof(*inputs->terms)) ||
        !horn_add_bytes(&total, inputs->predicate_count,
                        sizeof(*inputs->predicates)) ||
        !horn_add_bytes(&total, inputs->formula_count,
                        sizeof(*inputs->formulas)) ||
        !horn_add_bytes(&total, inputs->rule_count,
                        sizeof(*inputs->rules)) ||
        !horn_add_bytes(&total, inputs->context_count,
                        sizeof(*inputs->contexts)) ||
        !horn_add_bytes(&total, inputs->assertion_count,
                        sizeof(*inputs->assertions)) ||
        !horn_add_bytes(&total, inputs->coverage_count,
                        sizeof(*inputs->coverage)) ||
        !horn_add_bytes(&total, inputs->domain_count,
                        sizeof(*inputs->domains)) ||
        !horn_add_bytes(&total, query->import_count,
                        sizeof(*query->import_context_roots)))
        return false;
    for (size_t i = 0; i < inputs->formula_count; i++)
        if (!horn_add_bytes(&total, inputs->formulas[i].node_count,
                            sizeof(*inputs->formulas[i].nodes)))
            return false;
    for (size_t i = 0; i < inputs->domain_count; i++) {
        uint64_t count = inputs->domains[i].value_count;
        if (count > SIZE_MAX ||
            !horn_add_bytes(&total, (size_t)count, sizeof(uint8_t[32])))
            return false;
    }
    *out = total;
    return true;
}

static bool horn_input_bounds_valid(
    const struct zcl_ontology_manifest_inputs_v1 *inputs)
{
    return inputs &&
           inputs->term_count <= ZCL_ONTOLOGY_MAX_HORN_TERMS &&
           (inputs->term_count == 0 || inputs->terms) &&
           inputs->predicate_count <= ZCL_ONTOLOGY_MAX_PREDICATES &&
           (inputs->predicate_count == 0 || inputs->predicates) &&
           inputs->formula_count <= ZCL_ONTOLOGY_MAX_HORN_FORMULAS &&
           (inputs->formula_count == 0 || inputs->formulas) &&
           inputs->rule_count <= ZCL_ONTOLOGY_MAX_HORN_RULES &&
           (inputs->rule_count == 0 || inputs->rules) &&
           inputs->context_count <= ZCL_ONTOLOGY_MAX_CONTEXTS &&
           (inputs->context_count == 0 || inputs->contexts) &&
           inputs->assertion_count <= ZCL_ONTOLOGY_MAX_HORN_FACTS &&
           (inputs->assertion_count == 0 || inputs->assertions) &&
           inputs->coverage_count <= ZCL_ONTOLOGY_MAX_COVERAGE &&
           (inputs->coverage_count == 0 || inputs->coverage) &&
           inputs->domain_count <= ZCL_ONTOLOGY_MAX_DOMAINS &&
           (inputs->domain_count == 0 || inputs->domains);
}

static bool horn_cost_add(uint64_t *total, uint64_t add)
{
    if (*total > UINT64_MAX - add) return false;
    *total += add;
    return true;
}

static bool horn_cost_multiply_add(
    uint64_t *total, uint64_t left, uint64_t right)
{
    if (right != 0 && left > UINT64_MAX / right) return false;
    return horn_cost_add(total, left * right);
}

static bool horn_admission_cost(
    const struct zcl_ontology_horn_query_v1 *query, uint64_t *out)
{
    const struct zcl_ontology_manifest_inputs_v1 *inputs =
        query->inputs;
    uint64_t terms = inputs->term_count;
    uint64_t predicates = inputs->predicate_count;
    uint64_t contexts = inputs->context_count;
    uint64_t cost = 1;
    if (!horn_cost_multiply_add(&cost, terms, terms + 2u) ||
        !horn_cost_multiply_add(
            &cost, predicates, predicates + 5u * terms + 2u) ||
        !horn_cost_multiply_add(
            &cost, inputs->assertion_count,
            contexts + predicates + ZCL_ONTOLOGY_MAX_ARITY * terms + 2u) ||
        !horn_cost_multiply_add(
            &cost, inputs->coverage_count, contexts + 2u))
        return false;
    uint64_t formula_nodes = 0;
    for (size_t i = 0; i < inputs->formula_count; i++)
        if (!horn_cost_add(&formula_nodes,
                           inputs->formulas[i].node_count))
            return false;
    if (!horn_cost_multiply_add(
            &cost, formula_nodes,
            predicates + 8u * terms + 2u) ||
        !horn_cost_multiply_add(
            &cost, inputs->rule_count,
            inputs->formula_count + contexts + predicates * predicates +
                formula_nodes + 2u))
        return false;
    for (size_t i = 0; i < inputs->domain_count; i++)
        if (!horn_cost_add(&cost, contexts + terms + 2u) ||
            !horn_cost_multiply_add(
                &cost, inputs->domains[i].value_count, terms))
            return false;
    if (!horn_cost_add(&cost, query->import_count + 1u)) return false;
    *out = cost;
    return true;
}

static bool horn_admission_charge(struct horn_runtime *runtime)
{
    uint64_t cost = 0;
    if (!horn_admission_cost(runtime->query, &cost)) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_STEP_BUDGET);
        return false;
    }
    if (!horn_time_available(runtime)) return false;
    if (runtime->result->steps_taken >
        runtime->query->budget->step_limit ||
        cost > runtime->query->budget->step_limit -
                   runtime->result->steps_taken) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_STEP_BUDGET);
        return false;
    }
    runtime->result->steps_taken += cost;
    return horn_time_available(runtime);
}

static const struct zcl_ontology_predicate_v1 *horn_predicate_find(
    struct horn_runtime *runtime, const uint8_t root[32])
{
    const struct zcl_ontology_manifest_inputs_v1 *inputs =
        runtime->query->inputs;
    for (size_t i = 0; i < inputs->predicate_count; i++)
        if (memcmp(runtime->evaluator->predicate_roots[i], root, 32) == 0)
            return &inputs->predicates[i];
    return NULL;
}

static const struct zcl_ontology_formula_v1 *horn_formula_find(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t root[32])
{
    for (size_t i = 0; i < inputs->formula_count; i++) {
        uint8_t actual[32];
        if (zcl_ontology_formula_v1_root(&inputs->formulas[i], actual) &&
            memcmp(actual, root, 32) == 0)
            return &inputs->formulas[i];
    }
    return NULL;
}

static const struct zcl_ontology_term_v1 *horn_term_find(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t identity_root[32])
{
    for (size_t i = 0; i < inputs->term_count; i++)
        if (memcmp(inputs->terms[i].identity_root, identity_root, 32) == 0)
            return &inputs->terms[i];
    return NULL;
}

static bool horn_fact_equal(const struct zcl_ontology_horn_fact *left,
                            const struct zcl_ontology_horn_fact *right)
{
    return left->arity == right->arity &&
           left->polarity == right->polarity &&
           memcmp(left->context_root, right->context_root, 32) == 0 &&
           memcmp(left->predicate_root, right->predicate_root, 32) == 0 &&
           memcmp(left->argument_roots, right->argument_roots,
                  sizeof(left->argument_roots)) == 0;
}

static bool horn_fact_add(struct horn_runtime *runtime,
                          const struct zcl_ontology_horn_fact *fact,
                          bool derived, bool *added)
{
    *added = false;
    for (size_t i = 0; i < runtime->evaluator->horn_fact_count; i++)
        if (horn_fact_equal(&runtime->evaluator->horn_facts[i], fact))
            return true;
    if (runtime->evaluator->horn_fact_count >=
        ZCL_ONTOLOGY_MAX_HORN_FACTS) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_MEMORY_BUDGET);
        return false;
    }
    if (derived && !horn_derivation(runtime)) return false;
    runtime->evaluator->horn_facts[
        runtime->evaluator->horn_fact_count++] = *fact;
    if (fact->arity == runtime->query->arity &&
        memcmp(fact->predicate_root,
               runtime->query->predicate_root, 32) == 0 &&
        memcmp(fact->argument_roots,
               runtime->query->argument_roots,
               sizeof(fact->argument_roots)) == 0) {
        if (fact->polarity == ZCL_ONTOLOGY_POSITIVE)
            runtime->result->observed_positive = true;
        if (fact->polarity == ZCL_ONTOLOGY_NEGATIVE)
            runtime->result->observed_negative = true;
    }
    *added = true;
    return true;
}

static bool horn_load_assertions(struct horn_runtime *runtime)
{
    const struct zcl_ontology_manifest_inputs_v1 *inputs =
        runtime->query->inputs;
    runtime->evaluator->horn_fact_count = 0;
    memset(runtime->evaluator->horn_facts, 0,
           sizeof(runtime->evaluator->horn_facts));
    for (size_t i = 0; i < inputs->assertion_count; i++) {
        if (!horn_fact_examined(runtime)) return false;
        const struct zcl_ontology_assertion_v1 *assertion =
            &inputs->assertions[i];
        if (!horn_context_visible(runtime->query,
                                  assertion->context_root))
            continue;
        struct zcl_ontology_horn_fact fact = {
            .arity = assertion->arity,
            .polarity = assertion->polarity,
        };
        memcpy(fact.context_root, assertion->context_root, 32);
        memcpy(fact.predicate_root, assertion->predicate_root, 32);
        memcpy(fact.argument_roots, assertion->argument_roots,
               sizeof(fact.argument_roots));
        bool added = false;
        if (!horn_fact_add(runtime, &fact, false, &added)) return false;
    }
    return true;
}

static bool horn_atom_matches_fact(
    struct horn_runtime *runtime,
    const struct zcl_ontology_formula_node_v1 *atom,
    const struct zcl_ontology_horn_fact *fact, uint8_t polarity,
    uint8_t newly_bound[ZCL_ONTOLOGY_MAX_ARITY], size_t *new_count)
{
    *new_count = 0;
    if (fact->polarity != polarity || fact->arity != atom->arity ||
        memcmp(fact->predicate_root, atom->predicate_root, 32) != 0)
        return false;
    for (size_t i = 0; i < atom->arity; i++) {
        uint8_t variable = atom->terms[i].variable;
        if (runtime->evaluator->bound[variable]) {
            if (memcmp(runtime->evaluator->bindings[variable],
                       fact->argument_roots[i], 32) != 0)
                goto mismatch;
        } else {
            runtime->evaluator->bound[variable] = true;
            memcpy(runtime->evaluator->bindings[variable],
                   fact->argument_roots[i], 32);
            newly_bound[(*new_count)++] = variable;
        }
    }
    return true;

mismatch:
    for (size_t i = 0; i < *new_count; i++) {
        uint8_t variable = newly_bound[i];
        runtime->evaluator->bound[variable] = false;
        memset(runtime->evaluator->bindings[variable], 0, 32);
    }
    *new_count = 0;
    return false;
}

static void horn_unbind(struct zcl_ontology_evaluator *evaluator,
                        const uint8_t *variables, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        evaluator->bound[variables[i]] = false;
        memset(evaluator->bindings[variables[i]], 0, 32);
    }
}

static bool horn_constraint_atom(
    struct horn_runtime *runtime,
    const struct zcl_ontology_formula_node_v1 *atom, uint8_t polarity,
    bool *matched)
{
    *matched = false;
    for (size_t i = 0; i < runtime->evaluator->horn_fact_count; i++) {
        const struct zcl_ontology_horn_fact *fact =
            &runtime->evaluator->horn_facts[i];
        if (!horn_fact_examined(runtime)) return false;
        if (fact->polarity != polarity || fact->arity != atom->arity ||
            memcmp(fact->predicate_root, atom->predicate_root, 32) != 0)
            continue;
        bool same = true;
        for (size_t argument = 0; argument < atom->arity; argument++) {
            uint8_t variable = atom->terms[argument].variable;
            if (!runtime->evaluator->bound[variable] ||
                memcmp(runtime->evaluator->bindings[variable],
                       fact->argument_roots[argument], 32) != 0) {
                same = false;
                break;
            }
        }
        if (same) {
            *matched = true;
            return true;
        }
    }
    return true;
}

static bool horn_constraints_match(
    struct horn_runtime *runtime,
    const struct zcl_ontology_formula_v1 *formula,
    const uint32_t *constraints, size_t constraint_count, bool *matched)
{
    *matched = false;
    for (size_t i = 0; i < constraint_count; i++) {
        const struct zcl_ontology_formula_node_v1 *node =
            &formula->nodes[constraints[i]];
        if (node->op == ZCL_ONTOLOGY_FORMULA_EQUAL) {
            uint8_t left = node->terms[0].variable;
            uint8_t right = node->terms[1].variable;
            if (!runtime->evaluator->bound[left] ||
                !runtime->evaluator->bound[right] ||
                memcmp(runtime->evaluator->bindings[left],
                       runtime->evaluator->bindings[right], 32) != 0)
                return true;
            continue;
        }
        const struct zcl_ontology_formula_node_v1 *atom =
            &formula->nodes[node->left];
        bool atom_matched = false;
        if (!horn_constraint_atom(
                runtime, atom, ZCL_ONTOLOGY_NEGATIVE, &atom_matched))
            return false;
        if (!atom_matched) return true;
    }
    *matched = true;
    return true;
}

static bool horn_derive_head(
    struct horn_runtime *runtime,
    const struct zcl_ontology_formula_v1 *formula, uint32_t head_index,
    bool *added)
{
    uint8_t polarity = ZCL_ONTOLOGY_POSITIVE;
    const struct zcl_ontology_formula_node_v1 *head =
        &formula->nodes[head_index];
    if (head->op == ZCL_ONTOLOGY_FORMULA_NOT) {
        polarity = ZCL_ONTOLOGY_NEGATIVE;
        head = &formula->nodes[head->left];
    }
    struct zcl_ontology_horn_fact fact = {
        .arity = head->arity,
        .polarity = polarity,
    };
    memcpy(fact.context_root, runtime->query->context_root, 32);
    memcpy(fact.predicate_root, head->predicate_root, 32);
    for (size_t i = 0; i < head->arity; i++) {
        uint8_t variable = head->terms[i].variable;
        if (!runtime->evaluator->bound[variable]) {
            horn_fail(runtime, ZCL_ONTOLOGY_REASON_VARIABLE_UNBOUND);
            return false;
        }
        memcpy(fact.argument_roots[i],
               runtime->evaluator->bindings[variable], 32);
    }
    return horn_fact_add(runtime, &fact, true, added);
}

static bool horn_match_positive(
    struct horn_runtime *runtime,
    const struct zcl_ontology_formula_v1 *formula,
    const uint32_t *positive, size_t positive_count, size_t position,
    const uint32_t *constraints, size_t constraint_count,
    uint32_t head_index, uint32_t depth, bool *changed)
{
    if (depth > runtime->query->budget->recursion_limit) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_RECURSION_BUDGET);
        return false;
    }
    if (depth > runtime->result->max_recursion_depth)
        runtime->result->max_recursion_depth = depth;
    if (!horn_step(runtime)) return false;
    if (position == positive_count) {
        bool matched = false;
        if (!horn_constraints_match(
                runtime, formula, constraints, constraint_count, &matched))
            return false;
        if (!matched) return true;
        bool added = false;
        if (!horn_derive_head(runtime, formula, head_index, &added))
            return false;
        *changed = *changed || added;
        return true;
    }
    const struct zcl_ontology_formula_node_v1 *atom =
        &formula->nodes[positive[position]];
    size_t fact_count = runtime->evaluator->horn_fact_count;
    for (size_t i = 0; i < fact_count; i++) {
        const struct zcl_ontology_horn_fact *fact =
            &runtime->evaluator->horn_facts[i];
        if (!horn_fact_examined(runtime)) return false;
        uint8_t newly_bound[ZCL_ONTOLOGY_MAX_ARITY] = {0};
        size_t new_count = 0;
        bool matched = horn_atom_matches_fact(
            runtime, atom, fact, ZCL_ONTOLOGY_POSITIVE,
            newly_bound, &new_count);
        if (matched && !horn_match_positive(
                runtime, formula, positive, positive_count, position + 1u,
                constraints, constraint_count, head_index, depth + 1u,
                changed)) {
            horn_unbind(runtime->evaluator, newly_bound, new_count);
            return false;
        }
        horn_unbind(runtime->evaluator, newly_bound, new_count);
    }
    return true;
}

static bool horn_collect_body(
    const struct zcl_ontology_formula_v1 *formula, uint32_t index,
    uint32_t positive[ZCL_ONTOLOGY_MAX_FORMULA_NODES], size_t *positive_count,
    uint32_t constraints[ZCL_ONTOLOGY_MAX_FORMULA_NODES],
    size_t *constraint_count)
{
    const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[index];
    if (node->op == ZCL_ONTOLOGY_FORMULA_AND)
        return horn_collect_body(
                   formula, node->left, positive, positive_count,
                   constraints, constraint_count) &&
               horn_collect_body(
                   formula, node->right, positive, positive_count,
                   constraints, constraint_count);
    if (node->op == ZCL_ONTOLOGY_FORMULA_ATOM) {
        positive[(*positive_count)++] = index;
        return true;
    }
    if (node->op == ZCL_ONTOLOGY_FORMULA_EQUAL ||
        node->op == ZCL_ONTOLOGY_FORMULA_NOT) {
        constraints[(*constraint_count)++] = index;
        return true;
    }
    return false;
}

static bool horn_apply_rule(
    struct horn_runtime *runtime,
    const struct zcl_ontology_horn_rule_v1 *rule, bool *changed)
{
    const struct zcl_ontology_formula_v1 *formula = horn_formula_find(
        runtime->query->inputs, rule->formula_root);
    if (!formula) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_MANIFEST_INVALID);
        return false;
    }
    uint32_t index = formula->root_index;
    while (formula->nodes[index].op == ZCL_ONTOLOGY_FORMULA_FORALL)
        index = formula->nodes[index].left;
    const struct zcl_ontology_formula_node_v1 *implication =
        &formula->nodes[index];
    uint32_t positive[ZCL_ONTOLOGY_MAX_FORMULA_NODES] = {0};
    uint32_t constraints[ZCL_ONTOLOGY_MAX_FORMULA_NODES] = {0};
    size_t positive_count = 0, constraint_count = 0;
    if (implication->op != ZCL_ONTOLOGY_FORMULA_IMPLIES ||
        !horn_collect_body(
            formula, implication->left, positive, &positive_count,
            constraints, &constraint_count) || positive_count == 0) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_MANIFEST_INVALID);
        return false;
    }
    memset(runtime->evaluator->bound, 0,
           sizeof(runtime->evaluator->bound));
    memset(runtime->evaluator->bindings, 0,
           sizeof(runtime->evaluator->bindings));
    return horn_match_positive(
        runtime, formula, positive, positive_count, 0,
        constraints, constraint_count, implication->right, 1, changed);
}

static bool horn_saturate(struct horn_runtime *runtime)
{
    const struct zcl_ontology_manifest_inputs_v1 *inputs =
        runtime->query->inputs;
    bool changed;
    do {
        changed = false;
        for (size_t i = 0; i < inputs->rule_count; i++) {
            const struct zcl_ontology_horn_rule_v1 *rule =
                &inputs->rules[i];
            if (memcmp(rule->context_root,
                       runtime->query->context_root, 32) != 0) {
                if (horn_context_visible(runtime->query,
                                         rule->context_root))
                    horn_note_incomplete(
                        runtime,
                        ZCL_ONTOLOGY_REASON_HORN_CONTEXT_UNSUPPORTED);
                continue;
            }
            if (!horn_step(runtime) ||
                !horn_apply_rule(runtime, rule, &changed))
                return false;
        }
    } while (changed);
    return true;
}

static void horn_finish(struct horn_runtime *runtime)
{
    struct zcl_ontology_result_v1 *result = runtime->result;
    enum zcl_ontology_incomplete_reason reason = runtime->reason;
    if (reason == ZCL_ONTOLOGY_REASON_NONE)
        reason = runtime->soft_reason;
    if (reason != ZCL_ONTOLOGY_REASON_NONE) {
        result->status = ZCL_ONTOLOGY_INCOMPLETE;
        result->complete = false;
        result->incomplete_reason = reason;
        result->truncation_reason = horn_reason_string(reason);
        return;
    }
    if (result->observed_positive && result->observed_negative)
        result->status = ZCL_ONTOLOGY_BOTH;
    else if (result->observed_positive)
        result->status = ZCL_ONTOLOGY_PROVED;
    else if (result->observed_negative)
        result->status = ZCL_ONTOLOGY_DISPROVED;
    else
        result->status = ZCL_ONTOLOGY_UNKNOWN;
    result->complete = true;
}

static bool horn_query_shape_valid(
    const struct zcl_ontology_horn_query_v1 *query)
{
    if (!query || query->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        query->reserved != 0 || query->arity > ZCL_ONTOLOGY_MAX_ARITY ||
        !horn_nonzero(query->universe_root) ||
        !horn_nonzero(query->context_root) ||
        !horn_nonzero(query->predicate_root) ||
        query->import_count > ZCL_ONTOLOGY_MAX_IMPORTS ||
        (query->import_count != 0 && !query->import_context_roots) ||
        !query->manifest || !query->inputs || !query->budget)
        return false;
    for (size_t i = 0; i < sizeof(query->reserved_bytes); i++)
        if (query->reserved_bytes[i] != 0) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if ((i < query->arity) != horn_nonzero(query->argument_roots[i]))
            return false;
    return true;
}

static void horn_query_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t wire[2];
    zcl_write_u16_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void horn_query_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t wire[8];
    zcl_write_u64_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

bool zcl_ontology_horn_query_v1_root(
    const struct zcl_ontology_horn_query_v1 *query, uint8_t out[32])
{
    size_t import_bytes = query && query->import_context_roots ?
        (query->import_count <= ZCL_ONTOLOGY_MAX_IMPORTS ?
             query->import_count * sizeof(*query->import_context_roots) :
             sizeof(*query->import_context_roots)) : 0;
    if (!out || (query &&
        (horn_ranges_overlap(query, sizeof(*query), out, 32) ||
         horn_ranges_overlap(query->manifest, sizeof(*query->manifest),
                             out, 32) ||
         horn_ranges_overlap(query->budget, sizeof(*query->budget),
                             out, 32) ||
         horn_ranges_overlap(query->import_context_roots, import_bytes,
                             out, 32))))
        return false;
    memset(out, 0, 32);
    if (!horn_query_shape_valid(query)) return false;
    uint8_t manifest_root[32], budget_root[32], imports_root[32];
    if (!zcl_ontology_manifest_v1_root(query->manifest, manifest_root) ||
        !zcl_ontology_budget_v1_root(query->budget, budget_root) ||
        !zcl_ontology_import_manifest_v1_root(
            query->universe_root, query->import_context_roots,
            query->import_count, imports_root))
        return false;
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.ontology_horn_query.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    horn_query_hash_u16(&sha, query->schema_version);
    horn_query_hash_u16(&sha, query->reserved);
    sha3_256_write(&sha, query->universe_root, 32);
    sha3_256_write(&sha, query->context_root, 32);
    sha3_256_write(&sha, query->predicate_root, 32);
    sha3_256_write(&sha, &query->arity, 1);
    sha3_256_write(&sha, query->reserved_bytes,
                   sizeof(query->reserved_bytes));
    sha3_256_write(&sha, &query->argument_roots[0][0],
                   sizeof(query->argument_roots));
    horn_query_hash_u64(&sha, (uint64_t)query->import_count);
    sha3_256_write(&sha, imports_root, 32);
    sha3_256_write(&sha, manifest_root, 32);
    sha3_256_write(&sha, budget_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

static bool horn_target_valid(struct horn_runtime *runtime)
{
    const struct zcl_ontology_predicate_v1 *predicate =
        horn_predicate_find(runtime, runtime->query->predicate_root);
    if (!predicate) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_PREDICATE_MISSING);
        return false;
    }
    if (predicate->arity != runtime->query->arity ||
        predicate->execution_tier != ZCL_ONTOLOGY_TIER_HORN) {
        horn_fail(runtime, ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
        return false;
    }
    for (size_t i = 0; i < predicate->arity; i++) {
        const struct zcl_ontology_term_v1 *term = horn_term_find(
            runtime->query->inputs, runtime->query->argument_roots[i]);
        if (!term || memcmp(term->type_root,
                            predicate->argument_type_roots[i], 32) != 0) {
            horn_fail(runtime, ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
            return false;
        }
    }
    return true;
}

bool zcl_ontology_evaluate_horn_v1(
    struct zcl_ontology_evaluator *evaluator,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_horn_query_v1 *query,
    struct zcl_ontology_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!evaluator || evaluator->magic != ZCL_ONTOLOGY_EVALUATOR_MAGIC)
        return false;
    struct horn_runtime runtime = {
        .evaluator = evaluator,
        .universe = universe,
        .query = query,
        .result = out,
    };
    evaluator->horn_fact_count = 0;
    if (!horn_query_shape_valid(query) || !horn_input_bounds_valid(
            query ? query->inputs : NULL)) {
        horn_fail(&runtime, ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
        horn_finish(&runtime);
        return true;
    }
    uint8_t universe_root[32], budget_root[32];
    if (!zcl_source_universe_v1_root(universe, universe_root) ||
        !zcl_ontology_budget_v1_root(query->budget, budget_root) ||
        memcmp(universe_root, query->universe_root, 32) != 0) {
        horn_fail(&runtime, ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
        horn_finish(&runtime);
        return true;
    }
    if (!query->elapsed_us) {
        horn_fail(&runtime, ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING);
        horn_finish(&runtime);
        return true;
    }
    runtime.started_us = query->elapsed_us(query->elapsed_context);
    uint64_t working_set = 0;
    if (!horn_working_set_bytes(query, &working_set) ||
        query->budget->memory_limit_bytes < working_set) {
        horn_fail(&runtime, ZCL_ONTOLOGY_REASON_MEMORY_BUDGET);
        horn_finish(&runtime);
        return true;
    }
    if (!horn_admission_charge(&runtime)) {
        horn_finish(&runtime);
        return true;
    }
    if (!zcl_ontology_manifest_v1_validate(
            query->manifest, universe, query->inputs)) {
        horn_fail(&runtime, ZCL_ONTOLOGY_REASON_MANIFEST_INVALID);
        horn_finish(&runtime);
        return true;
    }
    if (!horn_time_available(&runtime)) {
        horn_finish(&runtime);
        return true;
    }
    if (!horn_contexts_bound(query, query->inputs)) {
        horn_fail(&runtime, ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
        horn_finish(&runtime);
        return true;
    }
    memset(evaluator->predicate_roots, 0,
           sizeof(evaluator->predicate_roots));
    for (size_t i = 0; i < query->inputs->predicate_count; i++) {
        if (!horn_step(&runtime)) {
            horn_finish(&runtime);
            return true;
        }
        if (!zcl_ontology_predicate_v1_root(
                &query->inputs->predicates[i],
                evaluator->predicate_roots[i])) {
            horn_fail(&runtime,
                      ZCL_ONTOLOGY_REASON_PREDICATE_REGISTRY_INVALID);
            horn_finish(&runtime);
            return true;
        }
    }
    if (!horn_step(&runtime) || !horn_target_valid(&runtime)) {
        horn_finish(&runtime);
        return true;
    }
    if (!horn_load_assertions(&runtime)) {
        horn_finish(&runtime);
        return true;
    }
    (void)horn_saturate(&runtime);
    if (runtime.reason == ZCL_ONTOLOGY_REASON_NONE)
        (void)horn_time_available(&runtime);
    horn_finish(&runtime);
    return true;
}
