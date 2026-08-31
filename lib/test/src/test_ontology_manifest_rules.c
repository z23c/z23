/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove ontology manifests admit only exact contextual Horn rules. */
#include "test/test_core.h"

#include "ontology/ontology_vocabulary.h"

#include <string.h>

struct manifest_rule_fixture {
    struct zcl_source_universe_v1 universe;
    struct zcl_ontology_context_v1 context;
    struct zcl_ontology_vocabulary_v1 vocabulary;
    struct zcl_ontology_formula_v1 formula;
    struct zcl_ontology_formula_node_v1
        formula_nodes[ZCL_ONTOLOGY_VOCABULARY_RULE_NODE_COUNT];
    struct zcl_ontology_predicate_v1 predicates[3];
    struct zcl_ontology_manifest_v1 manifest;
    struct zcl_ontology_manifest_inputs_v1 inputs;
};

static void manifest_rule_test_root(uint8_t out[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i);
}

static bool manifest_rule_member_roots(
    const struct zcl_ontology_term_v1 *terms, size_t count,
    uint8_t (*roots)[32])
{
    for (size_t i = 0; i < count; i++)
        if (!zcl_ontology_term_v1_root(&terms[i], roots[i])) return false;
    return true;
}

static bool manifest_rule_predicate_roots(
    const struct zcl_ontology_predicate_v1 *predicates, size_t count,
    uint8_t (*roots)[32])
{
    for (size_t i = 0; i < count; i++)
        if (!zcl_ontology_predicate_v1_root(
                &predicates[i], roots[i])) return false;
    return true;
}

static bool manifest_rule_formula_set(struct manifest_rule_fixture *fixture)
{
    uint8_t root[1][32];
    return zcl_ontology_formula_v1_root(&fixture->formula, root[0]) &&
           zcl_ontology_object_set_v1_root(
               ZCL_ONTOLOGY_OBJECT_FORMULA, root, 1,
               fixture->manifest.formula_set_root);
}

static bool manifest_rule_rule_set(struct manifest_rule_fixture *fixture)
{
    uint8_t root[1][32];
    return zcl_ontology_horn_rule_v1_root(
               &fixture->vocabulary.rules[0], root[0]) &&
           zcl_ontology_object_set_v1_root(
               ZCL_ONTOLOGY_OBJECT_RULE, root, 1,
               fixture->manifest.rule_set_root);
}

static bool manifest_rule_context_set(struct manifest_rule_fixture *fixture)
{
    uint8_t root[1][32];
    return zcl_ontology_context_v1_root(&fixture->context, root[0]) &&
           zcl_ontology_object_set_v1_root(
               ZCL_ONTOLOGY_OBJECT_CONTEXT, root, 1,
               fixture->manifest.context_set_root);
}

static bool manifest_rule_fixture_init(struct manifest_rule_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->universe.schema_version = ZCL_SOURCE_UNIVERSE_VERSION;
    fixture->universe.coverage_mask = ZCL_SOURCE_COVER_ALL;
    fixture->universe.governed_path_count = 11;
    fixture->universe.total_bytes = 8192;
    manifest_rule_test_root(fixture->universe.source_manifest_root, 0x01);
    manifest_rule_test_root(fixture->universe.governed_paths_root, 0x21);
    manifest_rule_test_root(fixture->universe.generated_paths_root, 0x41);
    manifest_rule_test_root(fixture->universe.vendor_paths_root, 0x61);
    manifest_rule_test_root(fixture->universe.metadata_paths_root, 0x81);
    manifest_rule_test_root(fixture->universe.publishable_paths_root, 0xa1);
    manifest_rule_test_root(fixture->universe.consensus_seal_root, 0xc1);
    manifest_rule_test_root(fixture->universe.indexed_paths_root, 0xe1);

    uint8_t universe_root[32], imports_root[32], context_root[1][32];
    if (!zcl_source_universe_v1_root(&fixture->universe, universe_root) ||
        !zcl_ontology_import_manifest_v1_root(
            universe_root, NULL, 0, imports_root))
        return false;
    fixture->context.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->context.kind = ZCL_ONTOLOGY_CONTEXT_CORPUS;
    memcpy(fixture->context.universe_root, universe_root, 32);
    memcpy(fixture->context.import_manifest_root, imports_root, 32);
    manifest_rule_test_root(fixture->context.subject_root, 0x17);
    manifest_rule_test_root(fixture->context.policy_root, 0x57);
    if (!zcl_ontology_context_v1_root(
            &fixture->context, context_root[0]) ||
        !zcl_ontology_vocabulary_v1_build(
            &fixture->universe, &fixture->context, &fixture->vocabulary))
        return false;

    bool found_formula = false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++) {
        if (memcmp(fixture->vocabulary.formula_roots[i],
                   fixture->vocabulary.rules[0].formula_root, 32) == 0) {
            if (!zcl_ontology_vocabulary_v1_formula_at(
                    &fixture->vocabulary, i, &fixture->formula))
                return false;
            for (uint32_t node = 0; node < fixture->formula.node_count; node++)
                fixture->formula_nodes[node] = fixture->formula.nodes[node];
            fixture->formula.nodes = fixture->formula_nodes;
            found_formula = true;
            break;
        }
    }
    if (!found_formula) return false;

    fixture->manifest.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->manifest.term_count = ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT;
    fixture->manifest.predicate_count =
        ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT;
    fixture->manifest.formula_count = 1;
    fixture->manifest.rule_count = 1;
    fixture->manifest.context_count = 1;
    memcpy(fixture->manifest.source_root,
           fixture->universe.source_manifest_root, 32);
    memcpy(fixture->manifest.universe_root, universe_root, 32);
    memcpy(fixture->manifest.vocabulary_root,
           fixture->vocabulary.vocabulary_root, 32);
    manifest_rule_test_root(fixture->manifest.extractor_root, 0x31);
    manifest_rule_test_root(fixture->manifest.policy_root, 0x71);

    uint8_t term_roots[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT][32];
    uint8_t predicate_roots[ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT][32];
    if (!manifest_rule_member_roots(
            fixture->vocabulary.terms,
            ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT, term_roots) ||
        !manifest_rule_predicate_roots(
            fixture->vocabulary.predicates,
            ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT, predicate_roots) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM, term_roots,
            ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT,
            fixture->manifest.term_set_root) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_PREDICATE, predicate_roots,
            ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT,
            fixture->manifest.predicate_set_root) ||
        !manifest_rule_formula_set(fixture) ||
        !manifest_rule_rule_set(fixture) ||
        !manifest_rule_context_set(fixture) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_ASSERTION, NULL, 0,
            fixture->manifest.assertion_set_root) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_COVERAGE, NULL, 0,
            fixture->manifest.coverage_set_root) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_DOMAIN, NULL, 0,
            fixture->manifest.domain_set_root) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_GAP, NULL, 0,
            fixture->manifest.gap_set_root))
        return false;

    fixture->inputs.terms = fixture->vocabulary.terms;
    fixture->inputs.term_count = ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT;
    fixture->inputs.predicates = fixture->vocabulary.predicates;
    fixture->inputs.predicate_count =
        ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT;
    fixture->inputs.formulas = &fixture->formula;
    fixture->inputs.formula_count = 1;
    fixture->inputs.rules = &fixture->vocabulary.rules[0];
    fixture->inputs.rule_count = 1;
    fixture->inputs.contexts = &fixture->context;
    fixture->inputs.context_count = 1;
    return true;
}

static bool manifest_rule_sort_predicates(
    struct zcl_ontology_predicate_v1 *predicates, size_t count,
    uint8_t (*roots)[32])
{
    if (!manifest_rule_predicate_roots(predicates, count, roots)) return false;
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1u; j < count; j++) {
            int order = memcmp(roots[i], roots[j], 32);
            if (order == 0) return false;
            if (order > 0) {
                struct zcl_ontology_predicate_v1 swap = predicates[i];
                uint8_t root_swap[32];
                predicates[i] = predicates[j];
                predicates[j] = swap;
                memcpy(root_swap, roots[i], 32);
                memcpy(roots[i], roots[j], 32);
                memcpy(roots[j], root_swap, 32);
            }
        }
    }
    return true;
}

int test_ontology_manifest_rules(void)
{
    int failures = 0;
    TEST("ontology_manifest_rules: exact contextual Horn children only") {
        struct manifest_rule_fixture fixture;
        ASSERT(manifest_rule_fixture_init(&fixture));
        ASSERT(zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));

        uint8_t concept_card[1][32], concept_set_root[32];
        manifest_rule_test_root(concept_card[0], 0x39);
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONCEPT_CARD, concept_card, 1,
            concept_set_root));

        ASSERT(manifest_rule_fixture_init(&fixture));
        fixture.inputs.formulas = NULL;
        fixture.inputs.formula_count = 0;
        fixture.manifest.formula_count = 0;
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA, NULL, 0,
            fixture.manifest.formula_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));

        ASSERT(manifest_rule_fixture_init(&fixture));
        fixture.formula_nodes[0].terms[0].variable =
            (uint8_t)((fixture.formula_nodes[0].terms[0].variable + 1u) % 3u);
        ASSERT(manifest_rule_formula_set(&fixture));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));

        ASSERT(manifest_rule_fixture_init(&fixture));
        fixture.inputs.contexts = NULL;
        fixture.inputs.context_count = 0;
        fixture.manifest.context_count = 0;
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONTEXT, NULL, 0,
            fixture.manifest.context_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));

        ASSERT(manifest_rule_fixture_init(&fixture));
        fixture.context.subject_root[0] ^= 1u;
        ASSERT(manifest_rule_context_set(&fixture));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));

        ASSERT(manifest_rule_fixture_init(&fixture));
        fixture.vocabulary.rules[0].universe_root[0] ^= 1u;
        ASSERT(manifest_rule_rule_set(&fixture));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));

        ASSERT(manifest_rule_fixture_init(&fixture));
        for (size_t i = 0;
             i < ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT; i++)
            fixture.predicates[i] = fixture.vocabulary.predicates[i];
        fixture.predicates[2] = fixture.predicates[0];
        fixture.predicates[2].coverage_required = ZCL_SOURCE_COVER_INDEXED;
        uint8_t predicate_roots[3][32];
        ASSERT(manifest_rule_sort_predicates(
            fixture.predicates, 3, predicate_roots));
        fixture.inputs.predicates = fixture.predicates;
        fixture.inputs.predicate_count = 3;
        fixture.manifest.predicate_count = 3;
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_PREDICATE, predicate_roots, 3,
            fixture.manifest.predicate_set_root));
        ASSERT(!zcl_ontology_manifest_v1_validate(
            &fixture.manifest, &fixture.universe, &fixture.inputs));
        PASS();
    } _test_next:;
    return failures;
}
