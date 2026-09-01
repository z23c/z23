/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical, range-restricted Horn-rule admission without evaluation. */
#include "ontology/ontology.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <string.h>

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

static bool horn_rule_shape_valid(
    const struct zcl_ontology_horn_rule_v1 *rule)
{
    return rule &&
           rule->schema_version == ZCL_ONTOLOGY_OBJECT_VERSION &&
           (rule->head_polarity == ZCL_ONTOLOGY_POSITIVE ||
            rule->head_polarity == ZCL_ONTOLOGY_NEGATIVE) &&
           rule->reserved == 0 &&
           rule->quantified_variable_count <= ZCL_ONTOLOGY_MAX_VARIABLES &&
           rule->body_clause_count != 0 &&
           rule->body_clause_count <= ZCL_ONTOLOGY_MAX_FORMULA_NODES &&
           horn_nonzero(rule->universe_root) &&
           horn_nonzero(rule->context_root) &&
           horn_nonzero(rule->formula_root) &&
           horn_nonzero(rule->evidence_root);
}

static void horn_put_u16(uint8_t *wire, size_t *offset, uint16_t value)
{
    zcl_write_u16_le(wire + *offset, value);
    *offset += 2u;
}

static uint16_t horn_get_u16(const uint8_t *wire, size_t *offset)
{
    uint16_t value = zcl_read_u16_le(wire + *offset);
    *offset += 2u;
    return value;
}

static void horn_put_root(uint8_t *wire, size_t *offset,
                          const uint8_t root[32])
{
    memcpy(wire + *offset, root, 32);
    *offset += 32u;
}

static void horn_get_root(const uint8_t *wire, size_t *offset,
                          uint8_t root[32])
{
    memcpy(root, wire + *offset, 32);
    *offset += 32u;
}

bool zcl_ontology_horn_rule_v1_encode(
    const struct zcl_ontology_horn_rule_v1 *rule, uint8_t *out,
    size_t out_size)
{
    if (!rule || !out || out_size != ZCL_ONTOLOGY_HORN_RULE_WIRE_BYTES ||
        horn_ranges_overlap(rule, sizeof(*rule), out, out_size))
        return false;
    memset(out, 0, out_size);
    if (!horn_rule_shape_valid(rule)) return false;
    size_t offset = 0;
    horn_put_u16(out, &offset, rule->schema_version);
    out[offset++] = rule->head_polarity;
    out[offset++] = rule->reserved;
    horn_put_u16(out, &offset, rule->quantified_variable_count);
    horn_put_u16(out, &offset, rule->body_clause_count);
    horn_put_root(out, &offset, rule->universe_root);
    horn_put_root(out, &offset, rule->context_root);
    horn_put_root(out, &offset, rule->formula_root);
    horn_put_root(out, &offset, rule->evidence_root);
    return offset == out_size;
}

bool zcl_ontology_horn_rule_v1_decode(
    const uint8_t *wire, size_t wire_size,
    struct zcl_ontology_horn_rule_v1 *out)
{
    if (!out) return false;
    if (wire && horn_ranges_overlap(wire, wire_size, out, sizeof(*out)))
        return false;
    memset(out, 0, sizeof(*out));
    if (!wire || wire_size != ZCL_ONTOLOGY_HORN_RULE_WIRE_BYTES) return false;
    size_t offset = 0;
    out->schema_version = horn_get_u16(wire, &offset);
    out->head_polarity = wire[offset++];
    out->reserved = wire[offset++];
    out->quantified_variable_count = horn_get_u16(wire, &offset);
    out->body_clause_count = horn_get_u16(wire, &offset);
    horn_get_root(wire, &offset, out->universe_root);
    horn_get_root(wire, &offset, out->context_root);
    horn_get_root(wire, &offset, out->formula_root);
    horn_get_root(wire, &offset, out->evidence_root);
    if (offset != wire_size || !horn_rule_shape_valid(out)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}

bool zcl_ontology_horn_rule_v1_root(
    const struct zcl_ontology_horn_rule_v1 *rule, uint8_t out[32])
{
    uint8_t wire[ZCL_ONTOLOGY_HORN_RULE_WIRE_BYTES];
    if (!rule || !out || horn_ranges_overlap(rule, sizeof(*rule), out, 32))
        return false;
    memset(out, 0, 32);
    if (!zcl_ontology_horn_rule_v1_encode(rule, wire, sizeof(wire)))
        return false;
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.ontology_horn_rule.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return true;
}

struct horn_registry {
    const struct zcl_ontology_predicate_v1 *predicates;
    size_t count;
    uint8_t roots[ZCL_ONTOLOGY_MAX_PREDICATES][32];
};

static bool horn_registry_init(
    struct horn_registry *registry,
    const struct zcl_ontology_predicate_v1 *predicates, size_t count)
{
    if (!registry || count > ZCL_ONTOLOGY_MAX_PREDICATES ||
        (count != 0 && !predicates))
        return false;
    memset(registry, 0, sizeof(*registry));
    registry->predicates = predicates;
    registry->count = count;
    for (size_t i = 0; i < count; i++) {
        if (!zcl_ontology_predicate_v1_root(
                &predicates[i], registry->roots[i]))
            return false;
        for (size_t j = 0; j < i; j++)
            if (memcmp(registry->roots[j], registry->roots[i], 32) == 0)
                return false;
    }
    return true;
}

static const struct zcl_ontology_predicate_v1 *horn_predicate_find(
    const struct horn_registry *registry, const uint8_t root[32])
{
    for (size_t i = 0; i < registry->count; i++)
        if (memcmp(registry->roots[i], root, 32) == 0)
            return &registry->predicates[i];
    return NULL;
}

static bool horn_atom_valid(
    const struct zcl_ontology_formula_node_v1 *node,
    const struct horn_registry *registry, bool head, bool negative,
    bool positive_range[ZCL_ONTOLOGY_MAX_VARIABLES],
    bool *saw_positive_body_atom)
{
    const struct zcl_ontology_predicate_v1 *predicate =
        horn_predicate_find(registry, node->predicate_root);
    if (!predicate || predicate->arity != node->arity ||
        (head && predicate->execution_tier != ZCL_ONTOLOGY_TIER_HORN) ||
        (!head && predicate->execution_tier != ZCL_ONTOLOGY_TIER_EXACT &&
         predicate->execution_tier != ZCL_ONTOLOGY_TIER_HORN) ||
        (!head && predicate->world == ZCL_ONTOLOGY_CLOSED_WORLD) ||
        (negative && predicate->explicit_negation != 1))
        return false;
    if (!head && !negative && saw_positive_body_atom)
        *saw_positive_body_atom = true;
    for (size_t i = 0; i < node->arity; i++) {
        /* Structural Horn admission has no term manifest. Constants would let
         * a caller self-declare an arbitrary value/type pair, so executable
         * rules remain variable-only until manifest-bound admission supplies
         * the canonical term registry. */
        if (node->terms[i].kind != ZCL_ONTOLOGY_FORMULA_VARIABLE)
            return false;
        if (memcmp(predicate->argument_type_roots[i],
                   node->terms[i].type_root, 32) != 0)
            return false;
        if (!head && !negative && positive_range &&
            node->terms[i].kind == ZCL_ONTOLOGY_FORMULA_VARIABLE)
            positive_range[node->terms[i].variable] = true;
    }
    return true;
}

static bool horn_body_valid(
    const struct zcl_ontology_formula_v1 *formula, uint32_t index,
    const struct horn_registry *registry,
    bool positive_range[ZCL_ONTOLOGY_MAX_VARIABLES], uint16_t *clause_count,
    bool *saw_positive_body_atom)
{
    const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[index];
    if (node->op == ZCL_ONTOLOGY_FORMULA_AND)
        return horn_body_valid(formula, node->left, registry, positive_range,
                               clause_count, saw_positive_body_atom) &&
               horn_body_valid(formula, node->right, registry, positive_range,
                               clause_count, saw_positive_body_atom);
    if (*clause_count == UINT16_MAX) return false;
    (*clause_count)++;
    if (node->op == ZCL_ONTOLOGY_FORMULA_ATOM)
        return horn_atom_valid(node, registry, false, false, positive_range,
                               saw_positive_body_atom);
    if (node->op == ZCL_ONTOLOGY_FORMULA_EQUAL)
        return node->terms[0].kind == ZCL_ONTOLOGY_FORMULA_VARIABLE &&
               node->terms[1].kind == ZCL_ONTOLOGY_FORMULA_VARIABLE;
    if (node->op == ZCL_ONTOLOGY_FORMULA_NOT) {
        const struct zcl_ontology_formula_node_v1 *child =
            &formula->nodes[node->left];
        return child->op == ZCL_ONTOLOGY_FORMULA_ATOM &&
               horn_atom_valid(child, registry, false, true, positive_range,
                               saw_positive_body_atom);
    }
    return false;
}

static bool horn_head_valid(
    const struct zcl_ontology_formula_v1 *formula, uint32_t index,
    const struct horn_registry *registry, uint8_t *polarity)
{
    const struct zcl_ontology_formula_node_v1 *node = &formula->nodes[index];
    bool negative = false;
    if (node->op == ZCL_ONTOLOGY_FORMULA_NOT) {
        negative = true;
        node = &formula->nodes[node->left];
    }
    if (node->op != ZCL_ONTOLOGY_FORMULA_ATOM ||
        !horn_atom_valid(node, registry, true, negative, NULL, NULL))
        return false;
    *polarity = negative ? ZCL_ONTOLOGY_NEGATIVE : ZCL_ONTOLOGY_POSITIVE;
    return true;
}

bool zcl_ontology_horn_rule_v1_validate(
    const struct zcl_ontology_horn_rule_v1 *rule,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context,
    const struct zcl_ontology_formula_v1 *formula,
    const struct zcl_ontology_predicate_v1 *predicates,
    size_t predicate_count)
{
    uint8_t universe_root[32], context_root[32], formula_root[32];
    struct horn_registry registry;
    if (!horn_rule_shape_valid(rule) ||
        !zcl_source_universe_v1_root(universe, universe_root) ||
        !zcl_ontology_context_v1_root(context, context_root) ||
        !zcl_ontology_formula_v1_root(formula, formula_root) ||
        memcmp(context->universe_root, universe_root, 32) != 0 ||
        memcmp(rule->universe_root, universe_root, 32) != 0 ||
        memcmp(rule->context_root, context_root, 32) != 0 ||
        memcmp(rule->formula_root, formula_root, 32) != 0 ||
        !horn_registry_init(&registry, predicates, predicate_count))
        return false;

    uint32_t index = formula->root_index;
    uint16_t quantified = 0;
    while (formula->nodes[index].op == ZCL_ONTOLOGY_FORMULA_FORALL) {
        if (quantified == UINT16_MAX) return false;
        quantified++;
        index = formula->nodes[index].left;
    }
    if (quantified != formula->variable_count ||
        quantified != rule->quantified_variable_count ||
        formula->nodes[index].op != ZCL_ONTOLOGY_FORMULA_IMPLIES)
        return false;

    const struct zcl_ontology_formula_node_v1 *implication =
        &formula->nodes[index];
    bool positive_range[ZCL_ONTOLOGY_MAX_VARIABLES] = {0};
    uint16_t body_clauses = 0;
    uint8_t head_polarity = 0;
    bool saw_positive_body_atom = false;
    if (!horn_body_valid(formula, implication->left, &registry,
                         positive_range, &body_clauses,
                         &saw_positive_body_atom) ||
        !saw_positive_body_atom ||
        !horn_head_valid(formula, implication->right, &registry,
                         &head_polarity) ||
        body_clauses != rule->body_clause_count ||
        head_polarity != rule->head_polarity)
        return false;
    for (uint16_t variable = 0; variable < quantified; variable++)
        if (!positive_range[variable]) return false;
    return true;
}
