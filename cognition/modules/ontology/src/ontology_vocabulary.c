/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Deterministic built-in ontology taxonomy vocabulary. */
#include "ontology/ontology_vocabulary.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <string.h>

static const char vocabulary_name[] = "zcl.builtin_taxonomy.v1";
static const char object_name[] = "ontology_object";
static const char type_name[] = "ontology_type";
static const char isa_name[] = "isa";
static const char genls_name[] = "genls";

static void vocabulary_hash_start(struct sha3_256_ctx *sha,
                                  const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1u);
}

static void vocabulary_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t wire[2];
    zcl_write_u16_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void vocabulary_root(uint8_t out[32])
{
    struct sha3_256_ctx sha;
    vocabulary_hash_start(&sha, "zcl.ontology_vocabulary.v1");
    vocabulary_hash_u16(&sha, ZCL_ONTOLOGY_VOCABULARY_VERSION);
    sha3_256_write(&sha, (const uint8_t *)vocabulary_name,
                   sizeof(vocabulary_name));
    sha3_256_finalize(&sha, out);
}

static void vocabulary_lexical_root(const char *name, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    vocabulary_hash_start(&sha, "zcl.ontology_lexical.v1");
    sha3_256_write(&sha, (const uint8_t *)name, strlen(name) + 1u);
    sha3_256_finalize(&sha, out);
}

static void vocabulary_identity_root(const uint8_t vocabulary[32],
                                     uint8_t kind,
                                     const uint8_t lexical[32],
                                     uint8_t out[32])
{
    struct sha3_256_ctx sha;
    vocabulary_hash_start(&sha, "zcl.ontology_identity.v1");
    sha3_256_write(&sha, vocabulary, 32);
    sha3_256_write(&sha, &kind, 1);
    sha3_256_write(&sha, lexical, 32);
    sha3_256_finalize(&sha, out);
}

static void vocabulary_evidence_root(
    const struct zcl_ontology_vocabulary_v1 *vocabulary, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    vocabulary_hash_start(&sha, "zcl.ontology_vocabulary_evidence.v1");
    vocabulary_hash_u16(&sha, ZCL_ONTOLOGY_VOCABULARY_VERSION);
    sha3_256_write(&sha, (const uint8_t *)vocabulary_name,
                   sizeof(vocabulary_name));
    sha3_256_write(&sha, vocabulary->vocabulary_root, 32);
    sha3_256_write(&sha, vocabulary->universe_root, 32);
    sha3_256_write(&sha, vocabulary->context_root, 32);
    vocabulary_hash_u16(&sha, ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT);
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++)
        sha3_256_write(&sha, vocabulary->formula_roots[i], 32);
    sha3_256_finalize(&sha, out);
}

static bool vocabulary_root_equal(const uint8_t left[32],
                                  const uint8_t right[32])
{
    return memcmp(left, right, 32) == 0;
}

static bool vocabulary_term_equal(const struct zcl_ontology_term_v1 *left,
                                  const struct zcl_ontology_term_v1 *right)
{
    return left->schema_version == right->schema_version &&
           left->kind == right->kind && left->reserved == right->reserved &&
           vocabulary_root_equal(left->vocabulary_root,
                                 right->vocabulary_root) &&
           vocabulary_root_equal(left->type_root, right->type_root) &&
           vocabulary_root_equal(left->identity_root, right->identity_root) &&
           vocabulary_root_equal(left->lexical_root, right->lexical_root);
}

static bool vocabulary_predicate_equal(
    const struct zcl_ontology_predicate_v1 *left,
    const struct zcl_ontology_predicate_v1 *right)
{
    if (left->schema_version != right->schema_version ||
        left->arity != right->arity || left->world != right->world ||
        left->execution_tier != right->execution_tier ||
        left->explicit_negation != right->explicit_negation ||
        left->reserved != right->reserved ||
        left->coverage_required != right->coverage_required ||
        !vocabulary_root_equal(left->term_root, right->term_root))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if (!vocabulary_root_equal(left->argument_type_roots[i],
                                   right->argument_type_roots[i]))
            return false;
    return true;
}

static bool vocabulary_formula_term_equal(
    const struct zcl_ontology_formula_term_v1 *left,
    const struct zcl_ontology_formula_term_v1 *right)
{
    return left->kind == right->kind &&
           left->variable == right->variable &&
           left->reserved == right->reserved &&
           vocabulary_root_equal(left->type_root, right->type_root) &&
           vocabulary_root_equal(left->value_root, right->value_root);
}

static bool vocabulary_formula_node_equal(
    const struct zcl_ontology_formula_node_v1 *left,
    const struct zcl_ontology_formula_node_v1 *right)
{
    if (left->op != right->op || left->arity != right->arity ||
        left->variable != right->variable ||
        left->reserved != right->reserved || left->left != right->left ||
        left->right != right->right ||
        !vocabulary_root_equal(left->predicate_root,
                               right->predicate_root) ||
        !vocabulary_root_equal(left->quantified_type_root,
                               right->quantified_type_root))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if (!vocabulary_formula_term_equal(&left->terms[i],
                                           &right->terms[i]))
            return false;
    return true;
}

static bool vocabulary_rule_equal(
    const struct zcl_ontology_horn_rule_v1 *left,
    const struct zcl_ontology_horn_rule_v1 *right)
{
    return left->schema_version == right->schema_version &&
           left->head_polarity == right->head_polarity &&
           left->reserved == right->reserved &&
           left->quantified_variable_count ==
               right->quantified_variable_count &&
           left->body_clause_count == right->body_clause_count &&
           vocabulary_root_equal(left->universe_root,
                                 right->universe_root) &&
           vocabulary_root_equal(left->context_root, right->context_root) &&
           vocabulary_root_equal(left->formula_root, right->formula_root) &&
           vocabulary_root_equal(left->evidence_root, right->evidence_root);
}

static bool vocabulary_equal(
    const struct zcl_ontology_vocabulary_v1 *left,
    const struct zcl_ontology_vocabulary_v1 *right)
{
    if (left->schema_version != right->schema_version ||
        left->reserved != right->reserved ||
        !vocabulary_root_equal(left->vocabulary_root,
                               right->vocabulary_root) ||
        !vocabulary_root_equal(left->evidence_root, right->evidence_root) ||
        !vocabulary_root_equal(left->universe_root, right->universe_root) ||
        !vocabulary_root_equal(left->context_root, right->context_root) ||
        !vocabulary_root_equal(left->ontology_object_identity_root,
                               right->ontology_object_identity_root) ||
        !vocabulary_root_equal(left->ontology_type_identity_root,
                               right->ontology_type_identity_root) ||
        !vocabulary_root_equal(left->isa_predicate_root,
                               right->isa_predicate_root) ||
        !vocabulary_root_equal(left->genls_predicate_root,
                               right->genls_predicate_root))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++)
        if (!vocabulary_term_equal(&left->terms[i], &right->terms[i]))
            return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++)
        if (!vocabulary_predicate_equal(&left->predicates[i],
                                        &right->predicates[i]))
            return false;
    for (size_t rule = 0; rule < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT;
         rule++) {
        for (size_t node = 0;
             node < ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT; node++)
            if (!vocabulary_formula_node_equal(
                    &left->rule_nodes[rule][node],
                    &right->rule_nodes[rule][node]))
                return false;
    }
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++) {
        if (left->formula_order[i] != right->formula_order[i] ||
            !vocabulary_root_equal(left->formula_roots[i],
                                   right->formula_roots[i]))
            return false;
    }
    for (size_t i = 0; i < sizeof(left->reserved_bytes); i++)
        if (left->reserved_bytes[i] != right->reserved_bytes[i]) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++)
        if (!vocabulary_rule_equal(&left->rules[i], &right->rules[i]) ||
            !vocabulary_root_equal(left->rule_roots[i],
                                   right->rule_roots[i]))
            return false;
    return true;
}

static bool vocabulary_ranges_overlap(const void *left, size_t left_size,
                                      const void *right, size_t right_size)
{
    uintptr_t left_start = (uintptr_t)left;
    uintptr_t right_start = (uintptr_t)right;
    if (left_size == 0 || right_size == 0) return false;
    if (left_start <= right_start)
        return right_start - left_start < left_size;
    return left_start - right_start < right_size;
}

static void vocabulary_term(
    struct zcl_ontology_term_v1 *term, uint8_t kind,
    const uint8_t vocabulary[32], const uint8_t type[32], const char *name)
{
    memset(term, 0, sizeof(*term));
    term->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    term->kind = kind;
    memcpy(term->vocabulary_root, vocabulary, 32);
    memcpy(term->type_root, type, 32);
    vocabulary_lexical_root(name, term->lexical_root);
    vocabulary_identity_root(vocabulary, kind, term->lexical_root,
                             term->identity_root);
}

static bool vocabulary_sort_terms(
    struct zcl_ontology_term_v1 terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT])
{
    uint8_t roots[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT][32];
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++)
        if (!zcl_ontology_term_v1_root(&terms[i], roots[i])) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++) {
        for (size_t j = i + 1u;
             j < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; j++) {
            int order = memcmp(roots[i], roots[j], 32);
            if (order == 0) return false;
            if (order > 0) {
                struct zcl_ontology_term_v1 term = terms[i];
                uint8_t root[32];
                terms[i] = terms[j]; terms[j] = term;
                memcpy(root, roots[i], 32);
                memcpy(roots[i], roots[j], 32);
                memcpy(roots[j], root, 32);
            }
        }
    }
    return true;
}

static void vocabulary_predicate(
    struct zcl_ontology_predicate_v1 *predicate,
    const uint8_t term_root[32], const uint8_t left_type[32],
    const uint8_t right_type[32])
{
    memset(predicate, 0, sizeof(*predicate));
    predicate->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    predicate->arity = 2;
    predicate->world = ZCL_ONTOLOGY_OPEN_WORLD;
    predicate->execution_tier = ZCL_ONTOLOGY_TIER_HORN;
    predicate->explicit_negation = 1;
    memcpy(predicate->term_root, term_root, 32);
    memcpy(predicate->argument_type_roots[0], left_type, 32);
    memcpy(predicate->argument_type_roots[1], right_type, 32);
}

static bool vocabulary_sort_predicates(
    struct zcl_ontology_predicate_v1
        predicates[ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT])
{
    uint8_t roots[ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT][32];
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++)
        if (!zcl_ontology_predicate_v1_root(&predicates[i], roots[i]))
            return false;
    int order = memcmp(roots[0], roots[1], 32);
    if (order == 0) return false;
    if (order > 0) {
        struct zcl_ontology_predicate_v1 predicate = predicates[0];
        predicates[0] = predicates[1]; predicates[1] = predicate;
    }
    return true;
}

static void vocabulary_node(
    struct zcl_ontology_formula_node_v1 *node, uint8_t op)
{
    memset(node, 0, sizeof(*node));
    node->op = op;
    node->left = ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT;
    node->right = ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT;
}

static void vocabulary_variable(
    struct zcl_ontology_formula_term_v1 *term, uint8_t variable,
    const uint8_t object_type[32])
{
    term->kind = ZCL_ONTOLOGY_FORMULA_VARIABLE;
    term->variable = variable;
    memcpy(term->type_root, object_type, 32);
}

static void vocabulary_atom(
    struct zcl_ontology_formula_node_v1 *node,
    const uint8_t predicate_root[32], uint8_t left, uint8_t right,
    const uint8_t left_type[32], const uint8_t right_type[32])
{
    vocabulary_node(node, ZCL_ONTOLOGY_FORMULA_ATOM);
    node->arity = 2;
    memcpy(node->predicate_root, predicate_root, 32);
    vocabulary_variable(&node->terms[0], left, left_type);
    vocabulary_variable(&node->terms[1], right, right_type);
}

static void vocabulary_binary(
    struct zcl_ontology_formula_node_v1 *node, uint8_t op,
    uint32_t left, uint32_t right)
{
    vocabulary_node(node, op);
    node->left = left;
    node->right = right;
}

static void vocabulary_forall(
    struct zcl_ontology_formula_node_v1 *node, uint8_t variable,
    uint32_t child, const uint8_t object_type[32])
{
    vocabulary_node(node, ZCL_ONTOLOGY_FORMULA_FORALL);
    node->variable = variable;
    node->left = child;
    memcpy(node->quantified_type_root, object_type, 32);
}

static void vocabulary_rule_nodes(
    struct zcl_ontology_formula_node_v1
        nodes[ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT],
    enum zcl_ontology_vocabulary_rule rule,
    const uint8_t isa[32], const uint8_t genls[32],
    const uint8_t object_type[32], const uint8_t ontology_type[32])
{
    if (rule == ZCL_ONTOLOGY_VOCABULARY_GENLS_TRANSITIVITY) {
        vocabulary_atom(&nodes[0], genls, 0, 1, ontology_type,
                        ontology_type);
        vocabulary_atom(&nodes[1], genls, 1, 2, ontology_type,
                        ontology_type);
        vocabulary_atom(&nodes[3], genls, 0, 2, ontology_type,
                        ontology_type);
    } else {
        vocabulary_atom(&nodes[0], isa, 0, 1, object_type,
                        ontology_type);
        vocabulary_atom(&nodes[1], genls, 1, 2, ontology_type,
                        ontology_type);
        vocabulary_atom(&nodes[3], isa, 0, 2, object_type,
                        ontology_type);
    }
    vocabulary_binary(&nodes[2], ZCL_ONTOLOGY_FORMULA_AND, 0, 1);
    vocabulary_binary(&nodes[4], ZCL_ONTOLOGY_FORMULA_IMPLIES, 2, 3);
    vocabulary_forall(&nodes[5], 2, 4, ontology_type);
    vocabulary_forall(&nodes[6], 1, 5, ontology_type);
    vocabulary_forall(&nodes[7], 0, 6,
                      rule == ZCL_ONTOLOGY_VOCABULARY_GENLS_TRANSITIVITY
                          ? ontology_type : object_type);
}

static void vocabulary_formula(
    const struct zcl_ontology_formula_node_v1 *nodes,
    struct zcl_ontology_formula_v1 *formula)
{
    memset(formula, 0, sizeof(*formula));
    formula->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    formula->node_count = ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT;
    formula->root_index = ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT - 1u;
    formula->variable_count = 3;
    formula->nodes = nodes;
}

static bool vocabulary_formula_raw(
    const struct zcl_ontology_vocabulary_v1 *vocabulary, size_t index,
    struct zcl_ontology_formula_v1 *out)
{
    if (!vocabulary || !out ||
        index >= ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT ||
        vocabulary->formula_order[index] >=
            ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT)
        return false;
    vocabulary_formula(
        vocabulary->rule_nodes[vocabulary->formula_order[index]], out);
    uint8_t root[32];
    return zcl_ontology_formula_v1_root(out, root) &&
           memcmp(root, vocabulary->formula_roots[index], 32) == 0;
}

static bool vocabulary_sort_formulas(
    struct zcl_ontology_vocabulary_v1 *vocabulary,
    const uint8_t semantic_roots[ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT][32])
{
    uint8_t first = 0, second = 1;
    int order = memcmp(semantic_roots[first], semantic_roots[second], 32);
    if (order == 0) return false;
    if (order > 0) { first = 1; second = 0; }
    vocabulary->formula_order[0] = first;
    vocabulary->formula_order[1] = second;
    memcpy(vocabulary->formula_roots[0], semantic_roots[first], 32);
    memcpy(vocabulary->formula_roots[1], semantic_roots[second], 32);
    return true;
}

static bool vocabulary_sort_rules(
    struct zcl_ontology_vocabulary_v1 *vocabulary,
    struct zcl_ontology_horn_rule_v1
        semantic[ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT])
{
    uint8_t roots[ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT][32];
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++)
        if (!zcl_ontology_horn_rule_v1_root(&semantic[i], roots[i]))
            return false;
    uint8_t first = 0, second = 1;
    int order = memcmp(roots[first], roots[second], 32);
    if (order == 0) return false;
    if (order > 0) { first = 1; second = 0; }
    vocabulary->rules[0] = semantic[first];
    vocabulary->rules[1] = semantic[second];
    memcpy(vocabulary->rule_roots[0], roots[first], 32);
    memcpy(vocabulary->rule_roots[1], roots[second], 32);
    return true;
}

static bool vocabulary_horn_valid(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context)
{
    for (size_t rule = 0; rule < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT;
         rule++) {
        bool found = false;
        for (size_t formula = 0;
             formula < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; formula++) {
            if (memcmp(vocabulary->rules[rule].formula_root,
                       vocabulary->formula_roots[formula], 32) != 0)
                continue;
            struct zcl_ontology_formula_v1 view;
            if (!vocabulary_formula_raw(vocabulary, formula, &view) ||
                !zcl_ontology_horn_rule_v1_validate(
                    &vocabulary->rules[rule], universe, context, &view,
                    vocabulary->predicates,
                    ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT))
                return false;
            found = true;
            break;
        }
        if (!found) return false;
    }
    return true;
}

static bool vocabulary_construct(
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context,
    struct zcl_ontology_vocabulary_v1 *out)
{
    memset(out, 0, sizeof(*out));
    out->schema_version = ZCL_ONTOLOGY_VOCABULARY_VERSION;
    if (!zcl_source_universe_v1_root(universe, out->universe_root) ||
        !zcl_ontology_context_v1_root(context, out->context_root) ||
        memcmp(context->universe_root, out->universe_root, 32) != 0)
        return false;
    vocabulary_root(out->vocabulary_root);

    struct zcl_ontology_term_v1
        semantic_terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT];
    uint8_t object_lexical[32], type_lexical[32];
    vocabulary_lexical_root(type_name, type_lexical);
    vocabulary_identity_root(out->vocabulary_root, ZCL_ONTOLOGY_TERM_TYPE,
                             type_lexical,
                             out->ontology_type_identity_root);
    vocabulary_lexical_root(object_name, object_lexical);
    vocabulary_identity_root(out->vocabulary_root, ZCL_ONTOLOGY_TERM_TYPE,
                             object_lexical,
                             out->ontology_object_identity_root);
    vocabulary_term(&semantic_terms[0], ZCL_ONTOLOGY_TERM_TYPE,
                    out->vocabulary_root,
                    out->ontology_type_identity_root, type_name);
    vocabulary_term(&semantic_terms[1], ZCL_ONTOLOGY_TERM_TYPE,
                    out->vocabulary_root,
                    out->ontology_type_identity_root, object_name);
    vocabulary_term(&semantic_terms[2], ZCL_ONTOLOGY_TERM_PREDICATE,
                    out->vocabulary_root,
                    out->ontology_object_identity_root, isa_name);
    vocabulary_term(&semantic_terms[3], ZCL_ONTOLOGY_TERM_PREDICATE,
                    out->vocabulary_root,
                    out->ontology_object_identity_root, genls_name);
    memcpy(out->terms, semantic_terms, sizeof(semantic_terms));
    if (!vocabulary_sort_terms(out->terms)) return false;

    uint8_t term_roots[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT][32];
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++)
        if (!zcl_ontology_term_v1_root(&semantic_terms[i], term_roots[i]))
            return false;
    struct zcl_ontology_predicate_v1 semantic_predicates[2];
    vocabulary_predicate(&semantic_predicates[0], term_roots[2],
                         out->ontology_object_identity_root,
                         out->ontology_type_identity_root);
    vocabulary_predicate(&semantic_predicates[1], term_roots[3],
                         out->ontology_type_identity_root,
                         out->ontology_type_identity_root);
    if (!zcl_ontology_predicate_v1_root(
            &semantic_predicates[0], out->isa_predicate_root) ||
        !zcl_ontology_predicate_v1_root(
            &semantic_predicates[1], out->genls_predicate_root))
        return false;
    memcpy(out->predicates, semantic_predicates,
           sizeof(semantic_predicates));
    if (!vocabulary_sort_predicates(out->predicates)) return false;

    uint8_t semantic_formula_roots[2][32];
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++) {
        vocabulary_rule_nodes(out->rule_nodes[i],
            (enum zcl_ontology_vocabulary_rule)i,
            out->isa_predicate_root, out->genls_predicate_root,
            out->ontology_object_identity_root,
            out->ontology_type_identity_root);
        struct zcl_ontology_formula_v1 formula;
        vocabulary_formula(out->rule_nodes[i], &formula);
        if (!zcl_ontology_formula_v1_root(
                &formula, semantic_formula_roots[i]))
            return false;
    }
    if (!vocabulary_sort_formulas(out, semantic_formula_roots)) return false;
    vocabulary_evidence_root(out, out->evidence_root);

    struct zcl_ontology_horn_rule_v1 semantic_rules[2] = {0};
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++) {
        semantic_rules[i].schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
        semantic_rules[i].head_polarity = ZCL_ONTOLOGY_POSITIVE;
        semantic_rules[i].quantified_variable_count = 3;
        semantic_rules[i].body_clause_count = 2;
        memcpy(semantic_rules[i].universe_root, out->universe_root, 32);
        memcpy(semantic_rules[i].context_root, out->context_root, 32);
        memcpy(semantic_rules[i].formula_root,
               semantic_formula_roots[i], 32);
        memcpy(semantic_rules[i].evidence_root, out->evidence_root, 32);
    }
    return vocabulary_sort_rules(out, semantic_rules) &&
           vocabulary_horn_valid(out, universe, context);
}

bool zcl_ontology_vocabulary_v1_build(
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context,
    struct zcl_ontology_vocabulary_v1 *out)
{
    if (!out) return false;
    struct zcl_ontology_vocabulary_v1 built;
    if (!universe || !context ||
        !vocabulary_construct(universe, context, &built)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    memcpy(out, &built, sizeof(*out));
    return true;
}

bool zcl_ontology_vocabulary_v1_formula_at(
    const struct zcl_ontology_vocabulary_v1 *vocabulary, size_t index,
    struct zcl_ontology_formula_v1 *out)
{
    if (!out) return false;
    if (vocabulary && vocabulary_ranges_overlap(
            vocabulary, sizeof(*vocabulary), out, sizeof(*out)))
        return false;
    memset(out, 0, sizeof(*out));
    if (!vocabulary ||
        vocabulary->schema_version != ZCL_ONTOLOGY_VOCABULARY_VERSION ||
        vocabulary->reserved != 0)
        return false;
    for (size_t i = 0; i < sizeof(vocabulary->reserved_bytes); i++)
        if (vocabulary->reserved_bytes[i] != 0) return false;
    struct zcl_ontology_formula_v1 view;
    if (!vocabulary_formula_raw(vocabulary, index, &view)) return false;
    *out = view;
    return true;
}

bool zcl_ontology_vocabulary_v1_validate(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context)
{
    if (!vocabulary || !universe || !context) return false;
    struct zcl_ontology_vocabulary_v1 expected;
    return vocabulary_construct(universe, context, &expected) &&
           vocabulary_equal(vocabulary, &expected) &&
           vocabulary_horn_valid(vocabulary, universe, context);
}
