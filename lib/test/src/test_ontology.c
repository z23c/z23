/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Born-red contracts for contextual, paraconsistent ontology truth. */
#include "test/test_core.h"
#include "ontology/ontology.h"
#include "base/hex.h"

#include <string.h>

static void root(uint8_t out[32], uint8_t value) { memset(out, value, 32); }

struct ontology_fake_clock {
    uint64_t now_us;
    uint64_t advance_us;
};

static uint64_t ontology_fake_elapsed_us(void *opaque)
{
    struct ontology_fake_clock *clock = opaque;
    uint64_t now = clock->now_us;
    clock->now_us += clock->advance_us;
    return now;
}

static void formula_node_init(struct zcl_ontology_formula_node_v1 *node,
                              uint8_t op, uint32_t node_count)
{
    memset(node, 0, sizeof(*node));
    node->op = op;
    node->left = node_count;
    node->right = node_count;
}

static void formula_variable(
    struct zcl_ontology_formula_term_v1 *term, uint8_t variable,
    const uint8_t type_root[32])
{
    memset(term, 0, sizeof(*term));
    term->kind = ZCL_ONTOLOGY_FORMULA_VARIABLE;
    term->variable = variable;
    memcpy(term->type_root, type_root, 32);
}

static void formula_constant(
    struct zcl_ontology_formula_term_v1 *term,
    const uint8_t type_root[32], const uint8_t value_root[32])
{
    memset(term, 0, sizeof(*term));
    term->kind = ZCL_ONTOLOGY_FORMULA_CONSTANT;
    memcpy(term->type_root, type_root, 32);
    memcpy(term->value_root, value_root, 32);
}

static void formula_assertion(
    struct zcl_ontology_assertion_v1 *assertion,
    const uint8_t context_root[32], const uint8_t predicate_root[32],
    const uint8_t value_root[32], uint8_t polarity, uint8_t evidence)
{
    memset(assertion, 0, sizeof(*assertion));
    assertion->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    assertion->arity = 1;
    assertion->polarity = polarity;
    memcpy(assertion->context_root, context_root, 32);
    memcpy(assertion->predicate_root, predicate_root, 32);
    memcpy(assertion->argument_roots[0], value_root, 32);
    root(assertion->evidence_root, evidence);
}

static bool ontology_terms_sort(
    struct zcl_ontology_term_v1 *terms, size_t count,
    uint8_t (*sorted_roots)[32])
{
    if (!terms || !sorted_roots) return false;
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1u; j < count; j++) {
            uint8_t left[32], right[32];
            if (!zcl_ontology_term_v1_root(&terms[i], left) ||
                !zcl_ontology_term_v1_root(&terms[j], right))
                return false;
            if (memcmp(left, right, 32) > 0) {
                struct zcl_ontology_term_v1 swap = terms[i];
                terms[i] = terms[j];
                terms[j] = swap;
            }
        }
    }
    for (size_t i = 0; i < count; i++)
        if (!zcl_ontology_term_v1_root(&terms[i], sorted_roots[i]))
            return false;
    return true;
}

static int test_ontology_four_valued_calculus(void)
{
    int failures = 0;
    struct zcl_source_universe_v1 universe = {
        .schema_version = 1, .coverage_mask = ZCL_SOURCE_COVER_ALL,
        .governed_path_count = 3, .total_bytes = 64,
    };
    root(universe.source_manifest_root, 1);
    root(universe.governed_paths_root, 2);
    root(universe.generated_paths_root, 3);
    root(universe.vendor_paths_root, 4);
    root(universe.metadata_paths_root, 5);
    root(universe.publishable_paths_root, 6);
    root(universe.consensus_seal_root, 7);
    root(universe.indexed_paths_root, 8);
    uint8_t universe_root[32], imports_root[32], context_root[32];
    ASSERT(zcl_source_universe_v1_root(&universe, universe_root));
    ASSERT(zcl_ontology_import_manifest_v1_root(
        universe_root, NULL, 0, imports_root));
    struct zcl_ontology_context_v1 context = {
        .schema_version = 1, .kind = ZCL_ONTOLOGY_CONTEXT_CORPUS,
    };
    memcpy(context.universe_root, universe_root, 32);
    memcpy(context.import_manifest_root, imports_root, 32);
    root(context.subject_root, 9); root(context.policy_root, 10);
    ASSERT(zcl_ontology_context_v1_root(&context, context_root));

    uint8_t entity_type[32], value_a[32], value_b[32];
    root(entity_type, 11); root(value_a, 12); root(value_b, 13);
    struct zcl_ontology_predicate_v1 predicates[2] = {0};
    uint8_t predicate_roots[2][32];
    for (size_t i = 0; i < 2; i++) {
        predicates[i].schema_version = 1;
        predicates[i].arity = 1;
        predicates[i].world = ZCL_ONTOLOGY_OPEN_WORLD;
        predicates[i].execution_tier = ZCL_ONTOLOGY_TIER_EXACT;
        predicates[i].explicit_negation = 1;
        root(predicates[i].term_root, (uint8_t)(20u + i));
        memcpy(predicates[i].argument_type_roots[0], entity_type, 32);
        ASSERT(zcl_ontology_predicate_v1_root(
            &predicates[i], predicate_roots[i]));
    }
    struct zcl_ontology_assertion_v1 prototypes[4];
    formula_assertion(&prototypes[0], context_root, predicate_roots[0],
                      value_a, ZCL_ONTOLOGY_POSITIVE, 30);
    formula_assertion(&prototypes[1], context_root, predicate_roots[0],
                      value_a, ZCL_ONTOLOGY_NEGATIVE, 31);
    formula_assertion(&prototypes[2], context_root, predicate_roots[1],
                      value_a, ZCL_ONTOLOGY_POSITIVE, 32);
    formula_assertion(&prototypes[3], context_root, predicate_roots[1],
                      value_a, ZCL_ONTOLOGY_NEGATIVE, 33);

    struct zcl_ontology_budget_v1 budget = {
        .schema_version = 1,
        .memory_limit_bytes = ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES,
        .fact_limit = 64, .step_limit = 256, .recursion_limit = 8,
        .derivation_limit = 64, .time_limit_us = 1000,
    };
    struct ontology_fake_clock clock = {0};
    struct zcl_ontology_formula_query_v1 query = {
        .contexts = &context, .context_count = 1,
        .predicates = predicates, .predicate_count = 2,
        .budget = &budget, .elapsed_us = ontology_fake_elapsed_us,
        .elapsed_context = &clock,
    };
    memcpy(query.universe_root, universe_root, 32);
    memcpy(query.context_root, context_root, 32);
    union {
        max_align_t alignment;
        uint8_t bytes[ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES +
                      sizeof(max_align_t)];
    } storage;
    struct zcl_ontology_evaluator *evaluator = NULL;
    ASSERT(zcl_ontology_evaluator_init_v1(
        storage.bytes, sizeof(storage.bytes), &evaluator));

    TEST("ontology: connectives implement complete four-valued truth tables") {
        static const uint8_t operations[3] = {
            ZCL_ONTOLOGY_FORMULA_AND,
            ZCL_ONTOLOGY_FORMULA_OR,
            ZCL_ONTOLOGY_FORMULA_IMPLIES,
        };
        static const uint8_t expected[3][4][4] = {
            {
                {ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_UNKNOWN,
                 ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_DISPROVED},
                {ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_BOTH},
                {ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_DISPROVED,
                 ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_DISPROVED},
                {ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_BOTH,
                 ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_BOTH},
            },
            {
                {ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED},
                {ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_PROVED},
                {ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_BOTH},
                {ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_BOTH, ZCL_ONTOLOGY_BOTH},
            },
            {
                {ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED},
                {ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_DISPROVED, ZCL_ONTOLOGY_BOTH},
                {ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_PROVED},
                {ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_PROVED,
                 ZCL_ONTOLOGY_BOTH, ZCL_ONTOLOGY_BOTH},
            },
        };
        struct zcl_ontology_formula_node_v1 nodes[3];
        struct zcl_ontology_formula_v1 formula = {
            .schema_version = 1, .node_count = 3, .root_index = 2,
            .nodes = nodes,
        };
        struct zcl_ontology_assertion_v1 facts[4];
        struct zcl_ontology_result_v1 result;
        uint8_t formula_root[32];
        for (size_t operation = 0; operation < 3; operation++) {
            for (size_t i = 0; i < 3; i++)
                formula_node_init(&nodes[i], 0, 3);
            nodes[0].op = ZCL_ONTOLOGY_FORMULA_ATOM;
            nodes[0].arity = 1;
            memcpy(nodes[0].predicate_root, predicate_roots[0], 32);
            formula_constant(&nodes[0].terms[0], entity_type, value_a);
            nodes[1].op = ZCL_ONTOLOGY_FORMULA_ATOM;
            nodes[1].arity = 1;
            memcpy(nodes[1].predicate_root, predicate_roots[1], 32);
            formula_constant(&nodes[1].terms[0], entity_type, value_a);
            nodes[2].op = operations[operation];
            nodes[2].left = 0; nodes[2].right = 1;
            ASSERT(zcl_ontology_formula_v1_root(&formula, formula_root));
            for (uint8_t left = 0; left < 4; left++) {
                for (uint8_t right = 0; right < 4; right++) {
                    size_t fact_count = 0;
                    if (left & 1u) facts[fact_count++] = prototypes[0];
                    if (left & 2u) facts[fact_count++] = prototypes[1];
                    if (right & 1u) facts[fact_count++] = prototypes[2];
                    if (right & 2u) facts[fact_count++] = prototypes[3];
                    query.assertions = fact_count ? facts : NULL;
                    query.assertion_count = fact_count;
                    ASSERT(zcl_ontology_evaluate_formula_v1(
                        evaluator, &universe, &formula, &query, &result));
                    ASSERT(result.complete);
                    ASSERT(result.status == expected[operation][left][right]);
                }
            }
        }

        for (size_t i = 0; i < 2; i++)
            formula_node_init(&nodes[i], 0, 2);
        formula.node_count = 2; formula.root_index = 1;
        nodes[0].op = ZCL_ONTOLOGY_FORMULA_ATOM;
        nodes[0].arity = 1;
        memcpy(nodes[0].predicate_root, predicate_roots[0], 32);
        formula_constant(&nodes[0].terms[0], entity_type, value_a);
        nodes[1].op = ZCL_ONTOLOGY_FORMULA_NOT; nodes[1].left = 0;
        static const uint8_t not_expected[4] = {
            ZCL_ONTOLOGY_UNKNOWN, ZCL_ONTOLOGY_DISPROVED,
            ZCL_ONTOLOGY_PROVED, ZCL_ONTOLOGY_BOTH,
        };
        for (uint8_t state = 0; state < 4; state++) {
            size_t fact_count = 0;
            if (state & 1u) facts[fact_count++] = prototypes[0];
            if (state & 2u) facts[fact_count++] = prototypes[1];
            query.assertions = fact_count ? facts : NULL;
            query.assertion_count = fact_count;
            ASSERT(zcl_ontology_evaluate_formula_v1(
                evaluator, &universe, &formula, &query, &result));
            ASSERT(result.complete && result.status == not_expected[state]);
        }

        formula_node_init(&nodes[0], ZCL_ONTOLOGY_FORMULA_EQUAL, 1);
        formula.node_count = 1; formula.root_index = 0;
        nodes[0].arity = 2;
        formula_constant(&nodes[0].terms[0], entity_type, value_a);
        formula_constant(&nodes[0].terms[1], entity_type, value_a);
        query.assertions = NULL; query.assertion_count = 0;
        ASSERT(zcl_ontology_formula_v1_root(&formula, formula_root));
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_PROVED);
        memcpy(nodes[0].terms[1].value_root, value_b, 32);
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_DISPROVED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ontology_manifest_codec(void)
{
    int failures = 0;
    struct zcl_source_universe_v1 universe = {
        .schema_version = 1, .coverage_mask = ZCL_SOURCE_COVER_ALL,
        .governed_path_count = 5, .total_bytes = 80,
    };
    root(universe.source_manifest_root, 1);
    root(universe.governed_paths_root, 2);
    root(universe.generated_paths_root, 3);
    root(universe.vendor_paths_root, 4);
    root(universe.metadata_paths_root, 5);
    root(universe.publishable_paths_root, 6);
    root(universe.consensus_seal_root, 7);
    root(universe.indexed_paths_root, 8);
    uint8_t universe_root[32];
    ASSERT(zcl_source_universe_v1_root(&universe, universe_root));
    struct zcl_ontology_manifest_v1 manifest = {
        .schema_version = ZCL_ONTOLOGY_OBJECT_VERSION,
    };
    memcpy(manifest.source_root, universe.source_manifest_root, 32);
    memcpy(manifest.universe_root, universe_root, 32);
    root(manifest.vocabulary_root, 20);
    root(manifest.extractor_root, 21);
    root(manifest.policy_root, 22);
    uint8_t *set_roots[] = {
        manifest.term_set_root, manifest.predicate_set_root,
        manifest.formula_set_root, manifest.rule_set_root,
        manifest.context_set_root, manifest.assertion_set_root,
        manifest.coverage_set_root, manifest.domain_set_root,
        manifest.gap_set_root,
    };
    for (uint8_t kind = ZCL_ONTOLOGY_OBJECT_TERM;
         kind <= ZCL_ONTOLOGY_OBJECT_GAP; kind++)
        ASSERT(zcl_ontology_object_set_v1_root(
            (enum zcl_ontology_object_kind)kind, NULL, 0,
            set_roots[kind - 1u]));
    static const char *const empty_set_kats[] = {
        "e0845481eca6a4f46d1af383357bcc7d3dac752d06a774ac0cd3860ea44c2d3a",
        "8b2ea0d5211ce8ba406f84de53769bf3355577a348195031596671be4c9eb351",
        "fba2520486f5a3de2e574d245c02339e9d93fd563bf586a37d265a483da7b332",
        "e27688ca850857781bf41b03e6bca3eb810666313d4620194dba7195d7228be8",
        "2592f793157cc158961f4cf548c6a889107c0584999e7d0dbcd2794940adbdc6",
        "0d7da02b0a746a7f5c01c476a62b1d44fd364f5d069b92adbba60f4ea412b0d4",
        "d920aed6ee2af808d22cad2d95e88585b9521a13bb1a483cd7397fcba4ad715d",
        "bacc313b3efc35d5f49702620355dfc503e41ee1b10526ee0a78ef077d2911e1",
        "f87df0a96bd480548e1a86888cf00effe48afe26b7982c00e6d5db53a9a4d7b8",
    };
    for (size_t i = 0; i < sizeof(set_roots) / sizeof(set_roots[0]); i++) {
        char empty_root_hex[65];
        zcl_hex_encode(set_roots[i], 32, empty_root_hex);
        ASSERT_STR_EQ(empty_root_hex, empty_set_kats[i]);
    }
    struct zcl_ontology_manifest_inputs_v1 inputs = {0};

    TEST("ontology: manifest codec binds exact typed sets and source universe") {
        ASSERT(zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));
        for (size_t i = 1; i < sizeof(set_roots) / sizeof(set_roots[0]); i++)
            ASSERT(memcmp(set_roots[0], set_roots[i], 32) != 0);

        uint8_t wire[ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES];
        uint8_t wire_again[ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES];
        uint8_t manifest_root[32];
        char manifest_root_hex[65];
        struct zcl_ontology_manifest_v1 parsed;
        ASSERT(zcl_ontology_manifest_v1_encode(
            &manifest, wire, sizeof(wire)));
        ASSERT(zcl_ontology_manifest_v1_decode(
            wire, sizeof(wire), &parsed));
        ASSERT(zcl_ontology_manifest_v1_encode(
            &parsed, wire_again, sizeof(wire_again)));
        ASSERT(memcmp(wire, wire_again, sizeof(wire)) == 0);
        ASSERT(zcl_ontology_manifest_v1_root(&manifest, manifest_root));
        zcl_hex_encode(manifest_root, sizeof(manifest_root), manifest_root_hex);
        ASSERT_STR_EQ(manifest_root_hex,
            "d28f740ef6c7091cce30ea9aabb15ea6638845efc7a29b67ee695387c5682ed8");

        uint8_t meta_type[32], argument_type[32], argument[32];
        root(meta_type, 40); root(argument_type, 41); root(argument, 42);
        struct zcl_ontology_term_v1 child_terms[4] = {0};
        for (size_t i = 0; i < 4; i++) {
            child_terms[i].schema_version = 1;
            memcpy(child_terms[i].vocabulary_root,
                   manifest.vocabulary_root, 32);
            root(child_terms[i].lexical_root, (uint8_t)(50u + i));
        }
        child_terms[0].kind = ZCL_ONTOLOGY_TERM_TYPE;
        memcpy(child_terms[0].type_root, meta_type, 32);
        memcpy(child_terms[0].identity_root, meta_type, 32);
        child_terms[1].kind = ZCL_ONTOLOGY_TERM_TYPE;
        memcpy(child_terms[1].type_root, meta_type, 32);
        memcpy(child_terms[1].identity_root, argument_type, 32);
        child_terms[2].kind = ZCL_ONTOLOGY_TERM_PREDICATE;
        memcpy(child_terms[2].type_root, meta_type, 32);
        root(child_terms[2].identity_root, 43);
        child_terms[3].kind = ZCL_ONTOLOGY_TERM_ENTITY;
        memcpy(child_terms[3].type_root, argument_type, 32);
        memcpy(child_terms[3].identity_root, argument, 32);
        uint8_t child_predicate_term_root[32];
        ASSERT(zcl_ontology_term_v1_root(
            &child_terms[2], child_predicate_term_root));
        uint8_t child_term_roots[4][32];
        ASSERT(ontology_terms_sort(child_terms, 4, child_term_roots));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM, child_term_roots, 4,
            manifest.term_set_root));
        manifest.term_count = 4;
        inputs.terms = child_terms; inputs.term_count = 4;

        struct zcl_ontology_predicate_v1 child_predicate = {
            .schema_version = 1, .arity = 1,
            .world = ZCL_ONTOLOGY_OPEN_WORLD,
            .execution_tier = ZCL_ONTOLOGY_TIER_EXACT,
            .explicit_negation = 1,
        };
        memcpy(child_predicate.term_root, child_predicate_term_root, 32);
        memcpy(child_predicate.argument_type_roots[0], argument_type, 32);
        uint8_t child_predicate_root[32];
        ASSERT(zcl_ontology_predicate_v1_root(
            &child_predicate, child_predicate_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_PREDICATE,
            (const uint8_t (*)[32])&child_predicate_root, 1,
            manifest.predicate_set_root));
        manifest.predicate_count = 1;
        inputs.predicates = &child_predicate; inputs.predicate_count = 1;

        uint8_t empty_imports[32];
        ASSERT(zcl_ontology_import_manifest_v1_root(
            universe_root, NULL, 0, empty_imports));
        struct zcl_ontology_context_v1 child_context = {
            .schema_version = 1, .kind = ZCL_ONTOLOGY_CONTEXT_CORPUS,
        };
        memcpy(child_context.universe_root, universe_root, 32);
        memcpy(child_context.import_manifest_root, empty_imports, 32);
        root(child_context.subject_root, 45); root(child_context.policy_root, 46);
        uint8_t child_context_root[32];
        ASSERT(zcl_ontology_context_v1_root(
            &child_context, child_context_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONTEXT,
            (const uint8_t (*)[32])&child_context_root, 1,
            manifest.context_set_root));
        manifest.context_count = 1;
        inputs.contexts = &child_context; inputs.context_count = 1;

        struct zcl_ontology_assertion_v1 child_assertion = {
            .schema_version = 1, .arity = 1,
            .polarity = ZCL_ONTOLOGY_POSITIVE,
        };
        memcpy(child_assertion.context_root, child_context_root, 32);
        memcpy(child_assertion.predicate_root, child_predicate_root, 32);
        memcpy(child_assertion.argument_roots[0], argument, 32);
        root(child_assertion.evidence_root, 47);
        uint8_t child_assertion_root[32];
        ASSERT(zcl_ontology_assertion_v1_root(
            &child_assertion, child_assertion_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_ASSERTION,
            (const uint8_t (*)[32])&child_assertion_root, 1,
            manifest.assertion_set_root));
        manifest.assertion_count = 1;
        inputs.assertions = &child_assertion; inputs.assertion_count = 1;

        struct zcl_ontology_coverage_v1 child_coverage = {
            .schema_version = 1,
            .complete_mask = ZCL_SOURCE_COVER_INDEXED,
        };
        memcpy(child_coverage.universe_root, universe_root, 32);
        memcpy(child_coverage.context_root, child_context_root, 32);
        root(child_coverage.evidence_root, 48);
        uint8_t child_coverage_root[32];
        ASSERT(zcl_ontology_coverage_v1_root(
            &child_coverage, child_coverage_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_COVERAGE,
            (const uint8_t (*)[32])&child_coverage_root, 1,
            manifest.coverage_set_root));
        manifest.coverage_count = 1;
        inputs.coverage = &child_coverage; inputs.coverage_count = 1;

        uint8_t domain_values[1][32]; memcpy(domain_values[0], argument, 32);
        struct zcl_ontology_domain_v1 child_domain = {
            .schema_version = 1, .value_count = 1,
            .value_roots = domain_values,
        };
        memcpy(child_domain.universe_root, universe_root, 32);
        memcpy(child_domain.context_root, child_context_root, 32);
        memcpy(child_domain.type_root, argument_type, 32);
        root(child_domain.coverage_evidence_root, 49);
        uint8_t child_domain_root[32];
        ASSERT(zcl_ontology_domain_v1_root(&child_domain, child_domain_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_DOMAIN,
            (const uint8_t (*)[32])&child_domain_root, 1,
            manifest.domain_set_root));
        manifest.domain_count = 1;
        inputs.domains = &child_domain; inputs.domain_count = 1;

        struct zcl_ontology_formula_node_v1 child_node;
        formula_node_init(&child_node, ZCL_ONTOLOGY_FORMULA_ATOM, 1);
        child_node.arity = 1;
        memcpy(child_node.predicate_root, child_predicate_root, 32);
        formula_constant(&child_node.terms[0], argument_type, argument);
        struct zcl_ontology_formula_v1 child_formula = {
            .schema_version = 1, .node_count = 1, .nodes = &child_node,
        };
        uint8_t child_formula_root[32];
        ASSERT(zcl_ontology_formula_v1_root(
            &child_formula, child_formula_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA,
            (const uint8_t (*)[32])&child_formula_root, 1,
            manifest.formula_set_root));
        manifest.formula_count = 1;
        inputs.formulas = &child_formula; inputs.formula_count = 1;
        ASSERT(zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));

        child_terms[0].vocabulary_root[0] ^= 1u;
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));
        child_terms[0].vocabulary_root[0] ^= 1u;
        child_node.predicate_root[0] ^= 1u;
        ASSERT(zcl_ontology_formula_v1_root(
            &child_formula, child_formula_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA,
            (const uint8_t (*)[32])&child_formula_root, 1,
            manifest.formula_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));
        child_node.predicate_root[0] ^= 1u;
        ASSERT(zcl_ontology_formula_v1_root(
            &child_formula, child_formula_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA,
            (const uint8_t (*)[32])&child_formula_root, 1,
            manifest.formula_set_root));
        memcpy(child_node.terms[0].type_root, meta_type, 32);
        ASSERT(zcl_ontology_formula_v1_root(
            &child_formula, child_formula_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA,
            (const uint8_t (*)[32])&child_formula_root, 1,
            manifest.formula_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));
        memcpy(child_node.terms[0].type_root, argument_type, 32);
        ASSERT(zcl_ontology_formula_v1_root(
            &child_formula, child_formula_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA,
            (const uint8_t (*)[32])&child_formula_root, 1,
            manifest.formula_set_root));
        child_assertion.arity = 0;
        memset(child_assertion.argument_roots[0], 0, 32);
        ASSERT(zcl_ontology_assertion_v1_root(
            &child_assertion, child_assertion_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_ASSERTION,
            (const uint8_t (*)[32])&child_assertion_root, 1,
            manifest.assertion_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));
        child_assertion.arity = 1;
        memcpy(child_assertion.argument_roots[0], argument, 32);
        ASSERT(zcl_ontology_assertion_v1_root(
            &child_assertion, child_assertion_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_ASSERTION,
            (const uint8_t (*)[32])&child_assertion_root, 1,
            manifest.assertion_set_root));
        uint8_t unregistered_type[32]; root(unregistered_type, 90);
        memcpy(child_domain.type_root, unregistered_type, 32);
        ASSERT(zcl_ontology_domain_v1_root(&child_domain, child_domain_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_DOMAIN,
            (const uint8_t (*)[32])&child_domain_root, 1,
            manifest.domain_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &manifest, &universe, &inputs));

        uint8_t object_roots[2][32];
        root(object_roots[0], 50); root(object_roots[1], 51);
        uint8_t swap[32]; memcpy(swap, object_roots[0], 32);
        memcpy(object_roots[0], object_roots[1], 32);
        memcpy(object_roots[1], swap, 32);
        ASSERT(!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM, object_roots, 2, manifest_root));
        memcpy(object_roots[1], object_roots[0], 32);
        ASSERT(!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM, object_roots, 2, manifest_root));
        memset(object_roots[0], 0, 32);
        ASSERT(!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM, object_roots, 1, manifest_root));
        ASSERT(!zcl_ontology_object_set_v1_root(
            (enum zcl_ontology_object_kind)0, NULL, 0, manifest_root));
        ASSERT(!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM, NULL, 1, manifest_root));

        inputs = (struct zcl_ontology_manifest_inputs_v1){0};
        struct zcl_ontology_manifest_v1 changed = parsed;
        changed.term_count = 1;
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &changed, &universe, &inputs));
        changed = parsed; changed.source_root[0] ^= 1u;
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &changed, &universe, &inputs));
        changed = parsed; changed.universe_root[0] ^= 1u;
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &changed, &universe, &inputs));
        changed = parsed; changed.schema_version++;
        ASSERT(!zcl_ontology_manifest_v1_encode(
            &changed, wire_again, sizeof(wire_again)));
        changed = parsed; changed.flags = 1;
        ASSERT(!zcl_ontology_manifest_v1_encode(
            &changed, wire_again, sizeof(wire_again)));
        changed = parsed; memset(changed.extractor_root, 0, 32);
        ASSERT(!zcl_ontology_manifest_v1_root(&changed, manifest_root));
        ASSERT(!zcl_ontology_manifest_v1_encode(
            &parsed, wire_again, sizeof(wire_again) - 1u));

        struct zcl_ontology_manifest_v1 zero = {0};
        memset(&parsed, 0xa5, sizeof(parsed));
        ASSERT(!zcl_ontology_manifest_v1_decode(
            wire, sizeof(wire) - 1u, &parsed));
        ASSERT(parsed.schema_version == zero.schema_version);
        uint8_t trailing[ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES + 1u];
        memcpy(trailing, wire, sizeof(wire)); trailing[sizeof(wire)] = 0;
        ASSERT(!zcl_ontology_manifest_v1_decode(
            trailing, sizeof(trailing), &parsed));
        wire[0] = 2;
        ASSERT(!zcl_ontology_manifest_v1_decode(
            wire, sizeof(wire), &parsed));
        PASS();
    } _test_next:;
    return failures;
}

static int test_ontology_formula_language(void)
{
    int failures = 0;
    struct zcl_source_universe_v1 universe = {
        .schema_version = 1, .coverage_mask = ZCL_SOURCE_COVER_ALL,
        .governed_path_count = 9, .total_bytes = 123,
    };
    root(universe.source_manifest_root, 1);
    root(universe.governed_paths_root, 2);
    root(universe.generated_paths_root, 3);
    root(universe.vendor_paths_root, 4);
    root(universe.metadata_paths_root, 5);
    root(universe.publishable_paths_root, 6);
    root(universe.consensus_seal_root, 7);
    root(universe.indexed_paths_root, 8);
    uint8_t universe_root[32], imports_root[32], context_root[32];
    ASSERT(zcl_source_universe_v1_root(&universe, universe_root));
    ASSERT(zcl_ontology_import_manifest_v1_root(
        universe_root, NULL, 0, imports_root));
    struct zcl_ontology_context_v1 context = {
        .schema_version = 1, .kind = ZCL_ONTOLOGY_CONTEXT_CORPUS,
    };
    memcpy(context.universe_root, universe_root, 32);
    memcpy(context.import_manifest_root, imports_root, 32);
    root(context.subject_root, 11); root(context.policy_root, 12);
    ASSERT(zcl_ontology_context_v1_root(&context, context_root));

    uint8_t entity_type[32]; root(entity_type, 20);
    struct zcl_ontology_term_v1 term = {
        .schema_version = 1, .kind = ZCL_ONTOLOGY_TERM_ENTITY,
    };
    root(term.vocabulary_root, 21); memcpy(term.type_root, entity_type, 32);
    root(term.identity_root, 22); root(term.lexical_root, 23);
    uint8_t term_root[32]; ASSERT(zcl_ontology_term_v1_root(&term, term_root));

    struct zcl_ontology_predicate_v1 predicates[2] = {0};
    uint8_t predicate_roots[2][32];
    for (size_t i = 0; i < 2; i++) {
        predicates[i].schema_version = 1;
        predicates[i].arity = 1;
        predicates[i].world = ZCL_ONTOLOGY_OPEN_WORLD;
        predicates[i].execution_tier = ZCL_ONTOLOGY_TIER_EXACT;
        predicates[i].explicit_negation = 1;
        root(predicates[i].term_root, (uint8_t)(30 + i));
        memcpy(predicates[i].argument_type_roots[0], entity_type, 32);
        ASSERT(zcl_ontology_predicate_v1_root(
            &predicates[i], predicate_roots[i]));
    }

    uint8_t values[2][32]; root(values[0], 40); root(values[1], 41);
    struct zcl_ontology_domain_v1 domain = {
        .schema_version = 1, .value_count = 2, .value_roots = values,
    };
    memcpy(domain.universe_root, universe_root, 32);
    memcpy(domain.context_root, context_root, 32);
    memcpy(domain.type_root, entity_type, 32);
    root(domain.coverage_evidence_root, 42);
    uint8_t domain_root[32];
    ASSERT(zcl_ontology_domain_v1_root(&domain, domain_root));

    struct zcl_ontology_assertion_v1 facts[4] = {0};
    for (size_t i = 0; i < 4; i++) {
        facts[i].schema_version = 1;
        facts[i].arity = 1;
        memcpy(facts[i].context_root, context_root, 32);
        root(facts[i].evidence_root, (uint8_t)(50 + i));
    }
    /* P(a), P(b), explicit-not-Q(a), Q(b). */
    memcpy(facts[0].predicate_root, predicate_roots[0], 32);
    memcpy(facts[0].argument_roots[0], values[0], 32);
    facts[0].polarity = ZCL_ONTOLOGY_POSITIVE;
    memcpy(facts[1].predicate_root, predicate_roots[0], 32);
    memcpy(facts[1].argument_roots[0], values[1], 32);
    facts[1].polarity = ZCL_ONTOLOGY_POSITIVE;
    memcpy(facts[2].predicate_root, predicate_roots[1], 32);
    memcpy(facts[2].argument_roots[0], values[0], 32);
    facts[2].polarity = ZCL_ONTOLOGY_NEGATIVE;
    memcpy(facts[3].predicate_root, predicate_roots[1], 32);
    memcpy(facts[3].argument_roots[0], values[1], 32);
    facts[3].polarity = ZCL_ONTOLOGY_POSITIVE;

    enum { FORMULA_NODES = 5 };
    struct zcl_ontology_formula_node_v1 nodes[FORMULA_NODES];
    for (size_t i = 0; i < FORMULA_NODES; i++)
        formula_node_init(&nodes[i], 0, FORMULA_NODES);
    nodes[0].op = ZCL_ONTOLOGY_FORMULA_ATOM; nodes[0].arity = 1;
    memcpy(nodes[0].predicate_root, predicate_roots[0], 32);
    formula_variable(&nodes[0].terms[0], 0, entity_type);
    nodes[1].op = ZCL_ONTOLOGY_FORMULA_ATOM; nodes[1].arity = 1;
    memcpy(nodes[1].predicate_root, predicate_roots[1], 32);
    formula_variable(&nodes[1].terms[0], 0, entity_type);
    nodes[2].op = ZCL_ONTOLOGY_FORMULA_NOT; nodes[2].left = 1;
    nodes[3].op = ZCL_ONTOLOGY_FORMULA_AND;
    nodes[3].left = 0; nodes[3].right = 2;
    nodes[4].op = ZCL_ONTOLOGY_FORMULA_EXISTS;
    nodes[4].left = 3; nodes[4].variable = 0;
    memcpy(nodes[4].quantified_type_root, entity_type, 32);
    struct zcl_ontology_formula_v1 formula = {
        .schema_version = 1, .node_count = FORMULA_NODES,
        .root_index = FORMULA_NODES - 1, .variable_count = 1,
        .nodes = nodes,
    };
    uint8_t formula_root[32];
    ASSERT(zcl_ontology_formula_v1_root(&formula, formula_root));
    char formula_root_hex[65];
    zcl_hex_encode(formula_root, sizeof(formula_root), formula_root_hex);
    ASSERT_STR_EQ(formula_root_hex,
        "d668c929dfdb52d3a71c33dffce63ac44256aaf0df09d3b6e6d916fd24310914");

    struct zcl_ontology_budget_v1 budget = {
        .schema_version = 1,
        .memory_limit_bytes = ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES,
        .fact_limit = 64, .step_limit = 128, .recursion_limit = 16,
        .derivation_limit = 64, .time_limit_us = 1000,
    };
    uint8_t budget_root[32];
    ASSERT(zcl_ontology_budget_v1_root(&budget, budget_root));
    struct ontology_fake_clock clock = {0};
    struct zcl_ontology_formula_query_v1 query = {
        .contexts = &context, .context_count = 1,
        .predicates = predicates, .predicate_count = 2,
        .assertions = facts, .assertion_count = 4,
        .domains = &domain, .domain_count = 1,
        .budget = &budget, .elapsed_us = ontology_fake_elapsed_us,
        .elapsed_context = &clock,
    };
    memcpy(query.universe_root, universe_root, 32);
    memcpy(query.context_root, context_root, 32);
    union {
        max_align_t alignment;
        uint8_t bytes[ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES];
    } storage;
    struct zcl_ontology_evaluator *evaluator = NULL;
    ASSERT(zcl_ontology_evaluator_init_v1(
        storage.bytes, sizeof(storage.bytes), &evaluator));
    struct zcl_ontology_result_v1 result;

    TEST("ontology: quantified formulas are canonical, bounded, and paraconsistent") {
        size_t evaluator_alignment = zcl_ontology_evaluator_alignment_v1();
        ASSERT(evaluator_alignment != 0);
        ASSERT(!zcl_ontology_evaluator_init_v1(
            NULL, ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES, &evaluator));
        ASSERT(evaluator == NULL);
        ASSERT(!zcl_ontology_evaluator_init_v1(
            storage.bytes, ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES - 1u,
            &evaluator));
        ASSERT(evaluator == NULL);
        ASSERT(!zcl_ontology_evaluator_init_v1(
            storage.bytes + 1u, ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES,
            &evaluator));
        ASSERT(evaluator == NULL);
        ASSERT(!zcl_ontology_evaluator_init_v1(
            storage.bytes, ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES,
            (struct zcl_ontology_evaluator **)(void *)storage.bytes));
        ASSERT(!zcl_ontology_evaluator_init_v1(
            storage.bytes, ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES, NULL));
        ASSERT(zcl_ontology_evaluator_init_v1(
            storage.bytes, ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES,
            &evaluator));

        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_PROVED && result.complete);
        ASSERT(result.observed_positive && !result.observed_negative);
        ASSERT(result.facts_examined == 16);
        /* forall x. P(x) and not Q(x) is disproved by b. */
        nodes[4].op = ZCL_ONTOLOGY_FORMULA_FORALL;
        ASSERT(zcl_ontology_formula_v1_root(&formula, formula_root));
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_DISPROVED && result.complete);
        ASSERT(!result.observed_positive && result.observed_negative);
        nodes[4].op = ZCL_ONTOLOGY_FORMULA_EXISTS;

        /* Every independently enforced resource dimension fails incomplete. */
        budget.fact_limit = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE && !result.complete);
        ASSERT(strcmp(result.truncation_reason, "fact_budget_exhausted") == 0);
        budget.fact_limit = 64; budget.step_limit = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason, "step_budget_exhausted") == 0);
        budget.step_limit = 128; budget.recursion_limit = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason,
                      "recursion_budget_exhausted") == 0);
        budget.recursion_limit = 16; budget.derivation_limit = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason,
                      "derivation_budget_exhausted") == 0);
        budget.derivation_limit = 64;
        budget.memory_limit_bytes = ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES - 1u;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason,
                      "memory_budget_exhausted") == 0);
        budget.memory_limit_bytes = ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES;
        clock.now_us = 0; clock.advance_us = 2; budget.time_limit_us = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason,
                      "time_budget_exhausted") == 0);
        clock.now_us = 0; clock.advance_us = 0; budget.time_limit_us = 1000;
        query.elapsed_us = NULL;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING);
        query.elapsed_us = ontology_fake_elapsed_us;
        clock.now_us = UINT64_MAX; clock.advance_us = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED);
        clock.now_us = 0; clock.advance_us = 0; budget.time_limit_us = 0;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_TIME_BUDGET);
        budget.time_limit_us = 1000;

        /* A missing exact predicate never becomes an unknown truth claim. */
        query.predicate_count = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason, "predicate_missing") == 0);
        query.predicate_count = 2;

        /* Quantifier domains are exact, sorted, and coverage-bearing. */
        struct zcl_ontology_domain_v1 malformed_domain = domain;
        malformed_domain.value_count = ZCL_ONTOLOGY_MAX_DOMAIN_VALUES + 1u;
        ASSERT(!zcl_ontology_domain_v1_root(&malformed_domain, domain_root));
        malformed_domain = domain; malformed_domain.value_roots = NULL;
        ASSERT(!zcl_ontology_domain_v1_root(&malformed_domain, domain_root));
        uint8_t unsorted_values[2][32];
        memcpy(unsorted_values[0], values[1], 32);
        memcpy(unsorted_values[1], values[0], 32);
        malformed_domain = domain; malformed_domain.value_roots = unsorted_values;
        ASSERT(!zcl_ontology_domain_v1_root(&malformed_domain, domain_root));
        memcpy(unsorted_values[0], values[0], 32);
        memcpy(unsorted_values[1], values[0], 32);
        ASSERT(!zcl_ontology_domain_v1_root(&malformed_domain, domain_root));
        struct zcl_ontology_domain_v1 empty_domain = domain;
        empty_domain.value_count = 0; empty_domain.value_roots = NULL;
        ASSERT(zcl_ontology_domain_v1_root(&empty_domain, domain_root));
        query.domains = &empty_domain;
        nodes[4].op = ZCL_ONTOLOGY_FORMULA_EXISTS;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_DISPROVED);
        nodes[4].op = ZCL_ONTOLOGY_FORMULA_FORALL;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_PROVED);
        nodes[4].op = ZCL_ONTOLOGY_FORMULA_EXISTS;
        query.domains = NULL; query.domain_count = 0;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &formula, &query, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_DOMAIN_MISSING);
        query.domains = &domain; query.domain_count = 1;

        /* Forward edges and unbound variables cannot mint formula identity. */
        nodes[3].left = 4;
        ASSERT(!zcl_ontology_formula_v1_root(&formula, formula_root));
        nodes[3].left = 0;
        nodes[4].variable = 1;
        ASSERT(!zcl_ontology_formula_v1_root(&formula, formula_root));
        nodes[4].variable = 0;
        ASSERT(zcl_ontology_formula_v1_root(&formula, formula_root));
        nodes[0].terms[0].type_root[0] ^= 1u;
        ASSERT(!zcl_ontology_formula_v1_root(&formula, formula_root));
        nodes[0].terms[0].type_root[0] ^= 1u;
        formula.variable_count = 2;
        ASSERT(!zcl_ontology_formula_v1_root(&formula, formula_root));
        formula.variable_count = 1;
        ASSERT(zcl_ontology_formula_v1_root(&formula, formula_root));

        struct zcl_ontology_derivation_v1 derivation = {
            .schema_version = 1, .status = ZCL_ONTOLOGY_PROVED,
            .observed_positive = 1, .complete = 1,
            .facts_examined = 16, .steps_taken = 32,
            .derivations_produced = 9, .max_recursion_depth = 5,
        };
        memcpy(derivation.universe_root, universe_root, 32);
        memcpy(derivation.context_root, context_root, 32);
        memcpy(derivation.formula_root, formula_root, 32);
        memcpy(derivation.budget_root, budget_root, 32);
        root(derivation.evidence_manifest_root, 60);
        root(derivation.evaluator_root, 61);
        uint8_t derivation_root[32];
        ASSERT(zcl_ontology_derivation_v1_root(
            &derivation, derivation_root));
        uint8_t complete_derivation_root[32];
        memcpy(complete_derivation_root, derivation_root, 32);
        derivation.complete = 0;
        derivation.status = ZCL_ONTOLOGY_INCOMPLETE;
        derivation.incomplete_reason = ZCL_ONTOLOGY_REASON_TIME_BUDGET;
        ASSERT(zcl_ontology_derivation_v1_root(
            &derivation, derivation_root));
        ASSERT(memcmp(complete_derivation_root, derivation_root, 32) != 0);
        uint8_t incomplete_derivation_root[32];
        memcpy(incomplete_derivation_root, derivation_root, 32);
        derivation.incomplete_reason = ZCL_ONTOLOGY_REASON_MEMORY_BUDGET;
        ASSERT(zcl_ontology_derivation_v1_root(
            &derivation, derivation_root));
        ASSERT(memcmp(incomplete_derivation_root, derivation_root, 32) != 0);
        derivation.missing_coverage_mask = UINT32_MAX;
        ASSERT(!zcl_ontology_derivation_v1_root(
            &derivation, derivation_root));

        /* Every imported context supplies its own canonical finite domain. */
        struct zcl_ontology_context_v1 imported_contexts[2] = {
            {0}, context,
        };
        imported_contexts[0] = context;
        root(imported_contexts[0].subject_root, 70);
        root(imported_contexts[0].policy_root, 71);
        ASSERT(zcl_ontology_import_manifest_v1_root(
            universe_root, (const uint8_t (*)[32])&context_root, 1,
            imported_contexts[0].import_manifest_root));
        uint8_t importing_context_root[32];
        ASSERT(zcl_ontology_context_v1_root(
            &imported_contexts[0], importing_context_root));
        struct zcl_ontology_domain_v1 imported_domains[2] = {
            empty_domain, empty_domain,
        };
        memcpy(imported_domains[0].context_root, importing_context_root, 32);
        memcpy(imported_domains[1].context_root, context_root, 32);
        root(imported_domains[0].coverage_evidence_root, 72);
        root(imported_domains[1].coverage_evidence_root, 73);
        if (memcmp(imported_domains[0].context_root,
                   imported_domains[1].context_root, 32) > 0) {
            struct zcl_ontology_domain_v1 swap = imported_domains[0];
            imported_domains[0] = imported_domains[1];
            imported_domains[1] = swap;
        }
        struct zcl_ontology_formula_node_v1 imported_nodes[2];
        for (size_t i = 0; i < 2; i++)
            formula_node_init(&imported_nodes[i], 0, 2);
        imported_nodes[0].op = ZCL_ONTOLOGY_FORMULA_EQUAL;
        imported_nodes[0].arity = 2;
        formula_variable(&imported_nodes[0].terms[0], 0, entity_type);
        formula_variable(&imported_nodes[0].terms[1], 0, entity_type);
        imported_nodes[1].op = ZCL_ONTOLOGY_FORMULA_FORALL;
        imported_nodes[1].left = 0; imported_nodes[1].variable = 0;
        memcpy(imported_nodes[1].quantified_type_root, entity_type, 32);
        struct zcl_ontology_formula_v1 imported_formula = {
            .schema_version = 1, .node_count = 2, .root_index = 1,
            .variable_count = 1, .nodes = imported_nodes,
        };
        ASSERT(zcl_ontology_formula_v1_root(
            &imported_formula, formula_root));
        struct zcl_ontology_formula_query_v1 imported_query = query;
        memcpy(imported_query.context_root, importing_context_root, 32);
        imported_query.import_context_roots =
            (const uint8_t (*)[32])&context_root;
        imported_query.import_count = 1;
        imported_query.contexts = imported_contexts;
        imported_query.context_count = 2;
        imported_query.predicates = NULL;
        imported_query.predicate_count = 0;
        imported_query.assertions = NULL;
        imported_query.assertion_count = 0;
        imported_query.domains = imported_domains;
        imported_query.domain_count = 2;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &imported_formula, &imported_query,
            &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_PROVED);
        struct zcl_ontology_domain_v1 primary_domain = empty_domain;
        memcpy(primary_domain.context_root, importing_context_root, 32);
        root(primary_domain.coverage_evidence_root, 74);
        imported_query.domains = &primary_domain;
        imported_query.domain_count = 1;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &imported_formula, &imported_query,
            &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_DOMAIN_MISSING);
        imported_domains[1] = imported_domains[0];
        imported_query.domains = imported_domains;
        imported_query.domain_count = 2;
        ASSERT(zcl_ontology_evaluate_formula_v1(
            evaluator, &universe, &imported_formula, &imported_query,
            &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_DOMAIN_REGISTRY_INVALID);
        PASS();
    } _test_next:;
    return failures;
}

int test_ontology(void)
{
    int failures = 0;
    struct zcl_source_universe_v1 u = {
        .schema_version = 1, .coverage_mask = ZCL_SOURCE_COVER_ALL,
        .governed_path_count = 7, .total_bytes = 99,
    };
    root(u.source_manifest_root, 1); root(u.governed_paths_root, 2);
    root(u.generated_paths_root, 3); root(u.vendor_paths_root, 4);
    root(u.metadata_paths_root, 5); root(u.publishable_paths_root, 6);
    root(u.consensus_seal_root, 7); root(u.indexed_paths_root, 8);
    struct zcl_ontology_predicate_v1 p = {
        .schema_version = 1, .arity = 1, .world = ZCL_ONTOLOGY_OPEN_WORLD,
        .execution_tier = ZCL_ONTOLOGY_TIER_EXACT, .explicit_negation = 1,
        .coverage_required = ZCL_SOURCE_COVER_INDEXED,
    };
    root(p.term_root, 9); root(p.argument_type_roots[0], 10);
    uint8_t ur[32], pr[32];
    ASSERT(zcl_source_universe_v1_root(&u, ur));
    ASSERT(zcl_ontology_predicate_v1_root(&p, pr));
    struct zcl_ontology_context_v1 contexts[3] = {0};
    uint8_t empty_imports[32];
    ASSERT(zcl_ontology_import_manifest_v1_root(ur, NULL, 0, empty_imports));
    for (size_t i = 0; i < 3; i++) {
        contexts[i].schema_version = 1;
        contexts[i].kind = i == 2 ? ZCL_ONTOLOGY_CONTEXT_BUILD
                                  : ZCL_ONTOLOGY_CONTEXT_CORPUS;
        memcpy(contexts[i].universe_root, ur, 32);
        root(contexts[i].subject_root, (uint8_t)(11 + i));
        root(contexts[i].policy_root, (uint8_t)(16 + i));
        memcpy(contexts[i].import_manifest_root, empty_imports, 32);
    }
    uint8_t here[32], foreign[32], importing[32], arg[32];
    ASSERT(zcl_ontology_context_v1_root(&contexts[0], here));
    ASSERT(zcl_ontology_context_v1_root(&contexts[1], foreign));
    ASSERT(zcl_ontology_import_manifest_v1_root(
        ur, (const uint8_t (*)[32])&foreign, 1,
        contexts[2].import_manifest_root));
    ASSERT(zcl_ontology_context_v1_root(&contexts[2], importing));
    root(arg, 13);
    struct zcl_ontology_assertion_v1 facts[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        facts[i].schema_version = 1; facts[i].arity = 1;
        memcpy(facts[i].predicate_root, pr, 32);
        memcpy(facts[i].argument_roots[0], arg, 32); root(facts[i].evidence_root, (uint8_t)(20 + i));
    }
    facts[0].polarity = ZCL_ONTOLOGY_POSITIVE; memcpy(facts[0].context_root, here, 32);
    facts[1].polarity = ZCL_ONTOLOGY_NEGATIVE; memcpy(facts[1].context_root, here, 32);
    facts[2].polarity = ZCL_ONTOLOGY_POSITIVE; memcpy(facts[2].context_root, foreign, 32);
    struct zcl_ontology_query_v1 q = {
        .arity = 1, .assertions = facts, .assertion_count = 2, .fact_budget = 2,
        .contexts = contexts, .context_count = 3,
    };
    memcpy(q.universe_root, ur, 32); memcpy(q.context_root, here, 32);
    memcpy(q.predicate_root, pr, 32);
    memcpy(q.argument_roots[0], arg, 32);
    struct zcl_ontology_result_v1 result;

    TEST("ontology: contextual four-valued truth fails closed under budgets") {
        char hex[65];
        zcl_hex_encode(ur, 32, hex);
        ASSERT(strcmp(hex, "5ac273a11dd688e410cdd8a75f731c4fd55452902903bb8e6db77a9b8e4579b0") == 0);
        zcl_hex_encode(pr, 32, hex);
        ASSERT(strcmp(hex, "074718a2890f5c95cba70f02ced4ff98c8bba41257b047336f2ab8169c1f4242") == 0);
        zcl_hex_encode(here, 32, hex);
        ASSERT(strcmp(hex, "db1f284062b7f1aae9e8eeb495ce789cb94e18c169223a3eafbd210a036f324e") == 0);
        uint8_t changed[32];
        contexts[0].policy_root[0] ^= 1u;
        ASSERT(zcl_ontology_context_v1_root(&contexts[0], changed));
        ASSERT(memcmp(changed, here, 32) != 0);
        contexts[0].policy_root[0] ^= 1u;
        /* Contradictions remain visible and do not explode. */
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_BOTH && result.complete);
        ASSERT(result.observed_positive && result.observed_negative);
        /* Foreign contexts remain invisible until explicitly imported. */
        q.assertions = &facts[2]; q.assertion_count = 1; q.fact_budget = 1;
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_UNKNOWN);
        q.import_context_roots = (const uint8_t (*)[32])&foreign;
        q.import_count = 1;
        memcpy(q.context_root, importing, 32);
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_PROVED);
        memcpy(q.context_root, here, 32);
        q.import_context_roots = NULL; q.import_count = 0;
        contexts[1].universe_root[0] ^= 1u;
        q.import_context_roots = (const uint8_t (*)[32])&foreign;
        q.import_count = 1;
        memcpy(q.context_root, importing, 32);
        ASSERT(!zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        contexts[1].universe_root[0] ^= 1u;
        memcpy(q.context_root, here, 32);
        q.import_context_roots = NULL; q.import_count = 0;
        /* Closed-world absence is a fact only under proved coverage. */
        q.assertion_count = 0; q.assertions = NULL; q.fact_budget = 0;
        p.world = ZCL_ONTOLOGY_CLOSED_WORLD;
        ASSERT(zcl_ontology_predicate_v1_root(&p, pr));
        memcpy(q.predicate_root, pr, 32);
        q.coverage = NULL; q.coverage_count = 0;
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE && !result.complete);
        ASSERT(result.missing_coverage_mask == ZCL_SOURCE_COVER_INDEXED);
        struct zcl_ontology_coverage_v1 coverage = {
            .schema_version = 1, .complete_mask = ZCL_SOURCE_COVER_INDEXED,
        };
        memcpy(coverage.universe_root, ur, 32);
        memcpy(coverage.context_root, here, 32);
        root(coverage.evidence_root, 30);
        q.coverage = &coverage; q.coverage_count = 1;
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_DISPROVED && result.complete);
        q.coverage = NULL;
        ASSERT(!zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        q.coverage = &coverage;
        q.argument_roots[1][0] = 1;
        ASSERT(!zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        q.argument_roots[1][0] = 0;
        q.context_count = ZCL_ONTOLOGY_MAX_CONTEXTS + 1u;
        ASSERT(!zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        q.context_count = 3;
        q.coverage_count = ZCL_ONTOLOGY_MAX_COVERAGE + 1u;
        ASSERT(!zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        q.coverage_count = 1;
        memset(coverage.evidence_root, 0, sizeof(coverage.evidence_root));
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        root(coverage.evidence_root, 30);
        /* Budget exhaustion retains observations but refuses completeness. */
        p.world = ZCL_ONTOLOGY_OPEN_WORLD;
        ASSERT(zcl_ontology_predicate_v1_root(&p, pr));
        memcpy(q.predicate_root, pr, 32);
        memcpy(facts[0].predicate_root, pr, 32);
        memcpy(facts[1].predicate_root, pr, 32);
        q.assertions = facts; q.assertion_count = 2; q.fact_budget = 1;
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE && !result.complete);
        ASSERT(result.observed_positive && !result.observed_negative);
        ASSERT(strcmp(result.truncation_reason, "fact_budget_exhausted") == 0);
        memset(facts[0].evidence_root, 0, sizeof(facts[0].evidence_root));
        q.assertion_count = 1; q.fact_budget = 1;
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason, "invalid_assertion") == 0);
        p.execution_tier = ZCL_ONTOLOGY_TIER_HORN;
        ASSERT(zcl_ontology_predicate_v1_root(&p, pr));
        memcpy(q.predicate_root, pr, 32);
        ASSERT(zcl_ontology_evaluate_atom_v1(&u, &p, &q, &result));
        ASSERT(result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(strcmp(result.truncation_reason,
                      "predicate_tier_unsupported") == 0);
        /* A partial source census cannot mint the universe root. */
        ASSERT(zcl_source_universe_v1_root(&u, ur));
        u.coverage_mask &= ~ZCL_SOURCE_COVER_VENDOR;
        ASSERT(!zcl_source_universe_v1_root(&u, ur));
        PASS();
    } _test_next:;
    failures += test_ontology_formula_language();
    failures += test_ontology_four_valued_calculus();
    failures += test_ontology_manifest_codec();
    return failures;
}
