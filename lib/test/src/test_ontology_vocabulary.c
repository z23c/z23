/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical and born-red built-in ontology taxonomy contracts. */
#include "test/test_core.h"

#include "ontology/ontology_vocabulary.h"

#include <string.h>

static void tv_root(uint8_t out[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i);
}

static bool tv_fixture(struct zcl_source_universe_v1 *universe,
                       struct zcl_ontology_context_v1 *context)
{
    memset(universe, 0, sizeof(*universe));
    universe->schema_version = ZCL_SOURCE_UNIVERSE_VERSION;
    universe->coverage_mask = ZCL_SOURCE_COVER_ALL;
    universe->governed_path_count = 7;
    universe->total_bytes = 4096;
    tv_root(universe->source_manifest_root, 0x01);
    tv_root(universe->governed_paths_root, 0x21);
    tv_root(universe->generated_paths_root, 0x41);
    tv_root(universe->vendor_paths_root, 0x61);
    tv_root(universe->metadata_paths_root, 0x81);
    tv_root(universe->publishable_paths_root, 0xa1);
    tv_root(universe->consensus_seal_root, 0xc1);
    tv_root(universe->indexed_paths_root, 0xe1);
    uint8_t universe_root[32], imports_root[32];
    if (!zcl_source_universe_v1_root(universe, universe_root) ||
        !zcl_ontology_import_manifest_v1_root(
            universe_root, NULL, 0, imports_root))
        return false;
    memset(context, 0, sizeof(*context));
    context->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    context->kind = ZCL_ONTOLOGY_CONTEXT_CORPUS;
    memcpy(context->universe_root, universe_root, 32);
    memcpy(context->import_manifest_root, imports_root, 32);
    tv_root(context->subject_root, 0x17);
    tv_root(context->policy_root, 0x57);
    return true;
}

static bool tv_hex_equal(const uint8_t root[32], const char *hex)
{
    uint8_t expected[32];
    test_hex_to_bytes(hex, expected, 32);
    return memcmp(root, expected, 32) == 0;
}

static bool tv_root_equal(const uint8_t left[32], const uint8_t right[32])
{
    return memcmp(left, right, 32) == 0;
}

static bool tv_root_zero(const uint8_t root[32])
{
    for (size_t i = 0; i < 32; i++)
        if (root[i] != 0) return false;
    return true;
}

static bool tv_formula_term_zero(
    const struct zcl_ontology_formula_term_v1 *term)
{
    return term->kind == 0 && term->variable == 0 && term->reserved == 0 &&
           tv_root_zero(term->type_root) && tv_root_zero(term->value_root);
}

static bool tv_formula_node_zero(
    const struct zcl_ontology_formula_node_v1 *node)
{
    if (node->op != 0 || node->arity != 0 || node->variable != 0 ||
        node->reserved != 0 || node->left != 0 || node->right != 0 ||
        !tv_root_zero(node->predicate_root) ||
        !tv_root_zero(node->quantified_type_root))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if (!tv_formula_term_zero(&node->terms[i])) return false;
    return true;
}

static bool tv_formula_zero(const struct zcl_ontology_formula_v1 *formula)
{
    if (formula->schema_version != 0 || formula->reserved != 0 ||
        formula->node_count != 0 || formula->root_index != 0 ||
        formula->variable_count != 0 || formula->nodes != NULL)
        return false;
    for (size_t i = 0; i < sizeof(formula->reserved_bytes); i++)
        if (formula->reserved_bytes[i] != 0) return false;
    return true;
}

static bool tv_term_zero(const struct zcl_ontology_term_v1 *term)
{
    return term->schema_version == 0 && term->kind == 0 &&
           term->reserved == 0 && tv_root_zero(term->vocabulary_root) &&
           tv_root_zero(term->type_root) &&
           tv_root_zero(term->identity_root) &&
           tv_root_zero(term->lexical_root);
}

static bool tv_predicate_zero(
    const struct zcl_ontology_predicate_v1 *predicate)
{
    if (predicate->schema_version != 0 || predicate->arity != 0 ||
        predicate->world != 0 || predicate->execution_tier != 0 ||
        predicate->explicit_negation != 0 || predicate->reserved != 0 ||
        predicate->coverage_required != 0 ||
        !tv_root_zero(predicate->term_root))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if (!tv_root_zero(predicate->argument_type_roots[i])) return false;
    return true;
}

static bool tv_rule_zero(const struct zcl_ontology_horn_rule_v1 *rule)
{
    return rule->schema_version == 0 && rule->head_polarity == 0 &&
           rule->reserved == 0 && rule->quantified_variable_count == 0 &&
           rule->body_clause_count == 0 &&
           tv_root_zero(rule->universe_root) &&
           tv_root_zero(rule->context_root) &&
           tv_root_zero(rule->formula_root) &&
           tv_root_zero(rule->evidence_root);
}

static bool tv_vocabulary_zero(
    const struct zcl_ontology_vocabulary_v1 *vocabulary)
{
    if (vocabulary->schema_version != 0 || vocabulary->reserved != 0 ||
        !tv_root_zero(vocabulary->vocabulary_root) ||
        !tv_root_zero(vocabulary->evidence_root) ||
        !tv_root_zero(vocabulary->universe_root) ||
        !tv_root_zero(vocabulary->context_root) ||
        !tv_root_zero(vocabulary->ontology_object_identity_root) ||
        !tv_root_zero(vocabulary->ontology_type_identity_root) ||
        !tv_root_zero(vocabulary->isa_predicate_root) ||
        !tv_root_zero(vocabulary->genls_predicate_root))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++)
        if (!tv_term_zero(&vocabulary->terms[i])) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++)
        if (!tv_predicate_zero(&vocabulary->predicates[i])) return false;
    for (size_t rule = 0; rule < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT;
         rule++) {
        for (size_t node = 0;
             node < ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT; node++)
            if (!tv_formula_node_zero(
                    &vocabulary->rule_nodes[rule][node]))
                return false;
    }
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++) {
        if (vocabulary->formula_order[i] != 0 ||
            !tv_root_zero(vocabulary->formula_roots[i]))
            return false;
    }
    for (size_t i = 0; i < sizeof(vocabulary->reserved_bytes); i++)
        if (vocabulary->reserved_bytes[i] != 0) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++)
        if (!tv_rule_zero(&vocabulary->rules[i]) ||
            !tv_root_zero(vocabulary->rule_roots[i]))
            return false;
    return true;
}

static const struct zcl_ontology_term_v1 *tv_term_for_root(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const uint8_t root[32])
{
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++) {
        uint8_t actual[32];
        if (zcl_ontology_term_v1_root(&vocabulary->terms[i], actual) &&
            tv_root_equal(actual, root))
            return &vocabulary->terms[i];
    }
    return NULL;
}

static struct zcl_ontology_predicate_v1 *tv_predicate_for_root(
    struct zcl_ontology_vocabulary_v1 *vocabulary, const uint8_t root[32])
{
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++) {
        uint8_t actual[32];
        if (zcl_ontology_predicate_v1_root(
                &vocabulary->predicates[i], actual) &&
            tv_root_equal(actual, root))
            return &vocabulary->predicates[i];
    }
    return NULL;
}

static const struct zcl_ontology_predicate_v1 *tv_const_predicate_for_root(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const uint8_t root[32])
{
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++) {
        uint8_t actual[32];
        if (zcl_ontology_predicate_v1_root(
                &vocabulary->predicates[i], actual) &&
            tv_root_equal(actual, root))
            return &vocabulary->predicates[i];
    }
    return NULL;
}

static bool tv_formula_for_rule(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const struct zcl_ontology_horn_rule_v1 *rule,
    struct zcl_ontology_formula_v1 *formula)
{
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++) {
        if (tv_root_equal(vocabulary->formula_roots[i],
                          rule->formula_root))
            return zcl_ontology_vocabulary_v1_formula_at(
                vocabulary, i, formula);
    }
    return false;
}

static bool tv_horn_valid(
    const struct zcl_ontology_vocabulary_v1 *vocabulary,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_context_v1 *context)
{
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++) {
        struct zcl_ontology_formula_v1 formula;
        if (!tv_formula_for_rule(vocabulary, &vocabulary->rules[i],
                                 &formula) ||
            !zcl_ontology_horn_rule_v1_validate(
                &vocabulary->rules[i], universe, context, &formula,
                vocabulary->predicates,
                ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT))
            return false;
    }
    return true;
}

static bool tv_roots_sorted(const uint8_t (*roots)[32], size_t count)
{
    for (size_t i = 1; i < count; i++)
        if (memcmp(roots[i - 1u], roots[i], 32) >= 0) return false;
    return true;
}

static int test_ontology_vocabulary_canonical(void)
{
    int failures = 0;
    TEST_CASE("built-in ontology vocabulary is canonical and contextual") {
        struct zcl_source_universe_v1 universe;
        struct zcl_ontology_context_v1 context;
        struct zcl_ontology_vocabulary_v1 left, right;
        ASSERT(tv_fixture(&universe, &context));
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &universe, &context, &left));
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &universe, &context, &right));
        ASSERT(zcl_ontology_vocabulary_v1_validate(
            &left, &universe, &context));
        ASSERT(zcl_ontology_vocabulary_v1_validate(
            &right, &universe, &context));
        ASSERT(tv_horn_valid(&left, &universe, &context));

        ASSERT(left.schema_version == right.schema_version);
        ASSERT(left.reserved == right.reserved);
        ASSERT(tv_root_equal(left.vocabulary_root, right.vocabulary_root));
        ASSERT(tv_root_equal(left.evidence_root, right.evidence_root));
        ASSERT(tv_root_equal(left.universe_root, right.universe_root));
        ASSERT(tv_root_equal(left.context_root, right.context_root));
        ASSERT(tv_root_equal(left.ontology_object_identity_root,
                             right.ontology_object_identity_root));
        ASSERT(tv_root_equal(left.ontology_type_identity_root,
                             right.ontology_type_identity_root));
        ASSERT(tv_root_equal(left.isa_predicate_root,
                             right.isa_predicate_root));
        ASSERT(tv_root_equal(left.genls_predicate_root,
                             right.genls_predicate_root));

        ASSERT(tv_hex_equal(
            left.vocabulary_root,
            "90d49d40afaf24faac36481d8e55fe9f0ab60072a744b6442f8c322895c8d080"));
        ASSERT(tv_hex_equal(
            left.ontology_object_identity_root,
            "1c78cf74aaa8bd4b0e3b6441f2edbc558d3b459930e1d2d9e998bdb69b8ae16b"));
        ASSERT(tv_hex_equal(
            left.ontology_type_identity_root,
            "004049acc4b4e836f26c9ab880ec51df42f53b538cf0938c2f2f49982f8b887b"));

        uint8_t term_roots[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT][32];
        uint8_t predicate_roots[ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT][32];
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++) {
            uint8_t right_root[32];
            ASSERT(zcl_ontology_term_v1_root(
                &left.terms[i], term_roots[i]));
            ASSERT(zcl_ontology_term_v1_root(
                &right.terms[i], right_root));
            ASSERT(tv_root_equal(term_roots[i], right_root));
        }
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++) {
            uint8_t right_root[32];
            ASSERT(zcl_ontology_predicate_v1_root(
                &left.predicates[i], predicate_roots[i]));
            ASSERT(zcl_ontology_predicate_v1_root(
                &right.predicates[i], right_root));
            ASSERT(tv_root_equal(predicate_roots[i], right_root));
        }
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++) {
            ASSERT(left.formula_order[i] == right.formula_order[i]);
            ASSERT(tv_root_equal(left.formula_roots[i],
                                 right.formula_roots[i]));
        }
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++)
            ASSERT(tv_root_equal(left.rule_roots[i], right.rule_roots[i]));
        ASSERT(tv_roots_sorted(term_roots,
                               ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT));
        ASSERT(tv_roots_sorted(predicate_roots,
                               ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT));
        ASSERT(tv_roots_sorted(left.formula_roots,
                               ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT));
        ASSERT(tv_roots_sorted(left.rule_roots,
                               ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT));

        const struct zcl_ontology_term_v1 *object = NULL, *type = NULL;
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++)
            if (tv_root_equal(left.terms[i].identity_root,
                              left.ontology_object_identity_root))
                object = &left.terms[i];
            else if (tv_root_equal(left.terms[i].identity_root,
                                   left.ontology_type_identity_root))
                type = &left.terms[i];
        ASSERT(object != NULL);
        ASSERT(type != NULL);
        ASSERT(object->kind == ZCL_ONTOLOGY_TERM_TYPE);
        ASSERT(type->kind == ZCL_ONTOLOGY_TERM_TYPE);
        ASSERT(tv_root_equal(type->type_root, type->identity_root));
        ASSERT(tv_root_equal(object->type_root, type->identity_root));
        ASSERT(tv_hex_equal(
            object->lexical_root,
            "528d08e1d2bd43fca232ade5473f0c62fc607e8d592e12cedd7e1900f847f1dc"));
        ASSERT(tv_hex_equal(
            type->lexical_root,
            "40fe09c68631ed941c44e721758bcacd10e8b7fdca003fd72794237dd48f5a57"));
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++) {
            const struct zcl_ontology_predicate_v1 *predicate =
                &left.predicates[i];
            uint8_t predicate_root[32];
            const struct zcl_ontology_term_v1 *term =
                tv_term_for_root(&left, predicate->term_root);
            ASSERT(term != NULL);
            ASSERT(zcl_ontology_predicate_v1_root(
                predicate, predicate_root));
            ASSERT(term->kind == ZCL_ONTOLOGY_TERM_PREDICATE);
            ASSERT(tv_root_equal(term->type_root,
                                 left.ontology_object_identity_root));
            ASSERT(predicate->arity == 2);
            ASSERT(predicate->world == ZCL_ONTOLOGY_OPEN_WORLD);
            ASSERT(predicate->execution_tier == ZCL_ONTOLOGY_TIER_HORN);
            ASSERT(predicate->explicit_negation == 1);
            ASSERT(predicate->coverage_required == 0);
            if (tv_root_equal(predicate_root, left.isa_predicate_root)) {
                ASSERT(tv_root_equal(predicate->argument_type_roots[0],
                                     left.ontology_object_identity_root));
                ASSERT(tv_root_equal(predicate->argument_type_roots[1],
                                     left.ontology_type_identity_root));
            } else {
                ASSERT(tv_root_equal(predicate_root,
                                     left.genls_predicate_root));
                ASSERT(tv_root_equal(predicate->argument_type_roots[0],
                                     left.ontology_type_identity_root));
                ASSERT(tv_root_equal(predicate->argument_type_roots[1],
                                     left.ontology_type_identity_root));
            }
        }
        for (size_t rule = 0;
             rule < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; rule++) {
            for (size_t node = 0;
                 node < ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT; node++) {
                const struct zcl_ontology_formula_node_v1 *candidate =
                    &left.rule_nodes[rule][node];
                if (candidate->op == ZCL_ONTOLOGY_FORMULA_ATOM) {
                    const struct zcl_ontology_predicate_v1 *predicate =
                        tv_const_predicate_for_root(
                            &left, candidate->predicate_root);
                    ASSERT(predicate != NULL);
                    ASSERT(candidate->arity == predicate->arity);
                    ASSERT(tv_root_equal(
                        candidate->terms[0].type_root,
                        predicate->argument_type_roots[0]));
                    ASSERT(tv_root_equal(
                        candidate->terms[1].type_root,
                        predicate->argument_type_roots[1]));
                    if (tv_root_equal(candidate->predicate_root,
                                      left.genls_predicate_root))
                        ASSERT(candidate->terms[0].variable !=
                               candidate->terms[1].variable);
                }
            }
        }
        ASSERT(tv_root_equal(
            left.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_GENLS_TRANSITIVITY][5]
                .quantified_type_root,
            left.ontology_type_identity_root));
        ASSERT(tv_root_equal(
            left.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_GENLS_TRANSITIVITY][6]
                .quantified_type_root,
            left.ontology_type_identity_root));
        ASSERT(tv_root_equal(
            left.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_GENLS_TRANSITIVITY][7]
                .quantified_type_root,
            left.ontology_type_identity_root));
        ASSERT(tv_root_equal(
            left.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_ISA_INHERITANCE][5]
                .quantified_type_root,
            left.ontology_type_identity_root));
        ASSERT(tv_root_equal(
            left.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_ISA_INHERITANCE][6]
                .quantified_type_root,
            left.ontology_type_identity_root));
        ASSERT(tv_root_equal(
            left.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_ISA_INHERITANCE][7]
                .quantified_type_root,
            left.ontology_object_identity_root));
    } TEST_END
    return failures;
}

static int test_ontology_vocabulary_binding(void)
{
    int failures = 0;
    TEST_CASE("built-in vocabulary binds universe and context") {
        struct zcl_source_universe_v1 universe, changed_universe;
        struct zcl_ontology_context_v1 context, changed_context;
        struct zcl_ontology_vocabulary_v1 base, changed, rejected;
        ASSERT(tv_fixture(&universe, &context));
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &universe, &context, &base));

        changed_context = context;
        changed_context.policy_root[0] ^= 1u;
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &universe, &changed_context, &changed));
        ASSERT(tv_root_equal(base.vocabulary_root, changed.vocabulary_root));
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++)
            ASSERT(tv_root_equal(base.formula_roots[i],
                                 changed.formula_roots[i]));
        ASSERT(!tv_root_equal(base.evidence_root, changed.evidence_root));
        bool rule_root_changed = false;
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT; i++)
            if (!tv_root_equal(base.rule_roots[i], changed.rule_roots[i]))
                rule_root_changed = true;
        ASSERT(rule_root_changed);

        changed_universe = universe;
        changed_universe.total_bytes++;
        uint8_t universe_root[32], imports_root[32];
        ASSERT(zcl_source_universe_v1_root(
            &changed_universe, universe_root));
        ASSERT(zcl_ontology_import_manifest_v1_root(
            universe_root, NULL, 0, imports_root));
        changed_context = context;
        memcpy(changed_context.universe_root, universe_root, 32);
        memcpy(changed_context.import_manifest_root, imports_root, 32);
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &changed_universe, &changed_context, &changed));
        ASSERT(tv_root_equal(base.vocabulary_root, changed.vocabulary_root));
        ASSERT(!tv_root_equal(base.evidence_root, changed.evidence_root));

        changed_context = context;
        changed_context.universe_root[0] ^= 1u;
        memset(&rejected, 0xa5, sizeof(rejected));
        ASSERT(!zcl_ontology_vocabulary_v1_build(
            &universe, &changed_context, &rejected));
        ASSERT(tv_vocabulary_zero(&rejected));
        changed_universe = universe;
        changed_universe.coverage_mask &= ~ZCL_SOURCE_COVER_VENDOR;
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &base, &changed_universe, &context));
    } TEST_END
    return failures;
}

static int test_ontology_vocabulary_formula_views(void)
{
    int failures = 0;
    TEST_CASE("formula views reject aliases and zero independent failures") {
        union {
            struct zcl_ontology_vocabulary_v1 vocabulary;
            struct zcl_ontology_formula_v1 formula;
        } overlap;
        struct zcl_source_universe_v1 universe;
        struct zcl_ontology_context_v1 context;
        struct zcl_ontology_formula_v1 rejected = {0};
        ASSERT(tv_fixture(&universe, &context));
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &universe, &context, &overlap.vocabulary));

        uint8_t vocabulary_root[32];
        memcpy(vocabulary_root, overlap.vocabulary.vocabulary_root, 32);
        ASSERT(!zcl_ontology_vocabulary_v1_formula_at(
            &overlap.vocabulary, 0, &overlap.formula));
        ASSERT(tv_root_equal(vocabulary_root,
                             overlap.vocabulary.vocabulary_root));
        ASSERT(zcl_ontology_vocabulary_v1_validate(
            &overlap.vocabulary, &universe, &context));

        rejected.schema_version = UINT16_MAX;
        rejected.reserved = UINT16_MAX;
        rejected.node_count = UINT32_MAX;
        rejected.root_index = UINT32_MAX;
        rejected.variable_count = UINT8_MAX;
        memset(rejected.reserved_bytes, 0xa5,
               sizeof(rejected.reserved_bytes));
        rejected.nodes = overlap.vocabulary.rule_nodes[0];
        ASSERT(!zcl_ontology_vocabulary_v1_formula_at(
            &overlap.vocabulary,
            ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT, &rejected));
        ASSERT(tv_formula_zero(&rejected));

        struct zcl_ontology_vocabulary_v1 changed = overlap.vocabulary;
        changed.formula_roots[0][0] ^= 1u;
        rejected.schema_version = UINT16_MAX;
        rejected.nodes = overlap.vocabulary.rule_nodes[0];
        ASSERT(!zcl_ontology_vocabulary_v1_formula_at(
            &changed, 0, &rejected));
        ASSERT(tv_formula_zero(&rejected));

        rejected.schema_version = UINT16_MAX;
        rejected.nodes = overlap.vocabulary.rule_nodes[0];
        ASSERT(!zcl_ontology_vocabulary_v1_formula_at(
            NULL, 0, &rejected));
        ASSERT(tv_formula_zero(&rejected));
    } TEST_END
    return failures;
}

static int test_ontology_vocabulary_barriers(void)
{
    int failures = 0;
    TEST_CASE("built-in taxonomy refuses type and tier drift") {
        struct zcl_source_universe_v1 universe;
        struct zcl_ontology_context_v1 context;
        struct zcl_ontology_vocabulary_v1 vocabulary, changed;
        ASSERT(tv_fixture(&universe, &context));
        ASSERT(zcl_ontology_vocabulary_v1_build(
            &universe, &context, &vocabulary));

        changed = vocabulary;
        struct zcl_ontology_predicate_v1 *isa = tv_predicate_for_root(
            &changed, vocabulary.isa_predicate_root);
        ASSERT(isa != NULL);
        isa->execution_tier = ZCL_ONTOLOGY_TIER_EXACT;
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &changed, &universe, &context));
        ASSERT(!tv_horn_valid(&changed, &universe, &context));

        changed = vocabulary;
        isa = tv_predicate_for_root(&changed, vocabulary.isa_predicate_root);
        ASSERT(isa != NULL);
        tv_root(isa->argument_type_roots[0], 0x33);
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &changed, &universe, &context));
        ASSERT(!tv_horn_valid(&changed, &universe, &context));

        changed = vocabulary;
        struct zcl_ontology_predicate_v1 *genls = tv_predicate_for_root(
            &changed, vocabulary.genls_predicate_root);
        ASSERT(genls != NULL);
        memcpy(genls->argument_type_roots[0],
               vocabulary.ontology_object_identity_root, 32);
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &changed, &universe, &context));
        ASSERT(!tv_horn_valid(&changed, &universe, &context));

        changed = vocabulary;
        bool object_changed = false;
        for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++) {
            if (!tv_root_equal(changed.terms[i].identity_root,
                               vocabulary.ontology_object_identity_root))
                continue;
            memcpy(changed.terms[i].type_root,
                   vocabulary.ontology_object_identity_root, 32);
            object_changed = true;
            break;
        }
        ASSERT(object_changed);
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &changed, &universe, &context));

        changed = vocabulary;
        memcpy(changed.rule_nodes[ZCL_ONTOLOGY_VOCABULARY_ISA_INHERITANCE]
                                 [7].quantified_type_root,
               vocabulary.ontology_type_identity_root, 32);
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &changed, &universe, &context));
        ASSERT(!tv_horn_valid(&changed, &universe, &context));

        changed = vocabulary;
        changed.rules[0].context_root[0] ^= 1u;
        ASSERT(!zcl_ontology_vocabulary_v1_validate(
            &changed, &universe, &context));
        ASSERT(!tv_horn_valid(&changed, &universe, &context));
    } TEST_END
    return failures;
}

int test_ontology_vocabulary(void)
{
    int failures = 0;
    failures += test_ontology_vocabulary_canonical();
    failures += test_ontology_vocabulary_binding();
    failures += test_ontology_vocabulary_formula_views();
    failures += test_ontology_vocabulary_barriers();
    return failures;
}
