/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Born-red contracts for manifest-bound Horn fixed-point inference. */
#include "test/test_core.h"

#include "ontology/ontology_vocabulary.h"

#include <string.h>

enum {
    HORN_FIXTURE_TERM_COUNT = ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 4,
    HORN_FIXTURE_ASSERTION_COUNT = 5,
    HORN_FIXTURE_CONTEXT_COUNT = 2,
};

struct horn_test_clock {
    uint64_t now_us;
    uint64_t advance_us;
};

struct horn_fixture {
    struct zcl_source_universe_v1 universe;
    uint8_t universe_root[32];
    struct zcl_ontology_context_v1 primary_context;
    struct zcl_ontology_context_v1 foreign_context;
    uint8_t primary_context_root[32];
    uint8_t foreign_context_root[32];
    uint8_t imports[1][32];
    struct zcl_ontology_vocabulary_v1 vocabulary;
    struct zcl_ontology_term_v1 terms[HORN_FIXTURE_TERM_COUNT];
    struct zcl_ontology_formula_v1
        formulas[ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT];
    struct zcl_ontology_context_v1 contexts[HORN_FIXTURE_CONTEXT_COUNT];
    struct zcl_ontology_assertion_v1
        assertions[HORN_FIXTURE_ASSERTION_COUNT];
    struct zcl_ontology_manifest_v1 manifest;
    struct zcl_ontology_manifest_inputs_v1 inputs;
    uint8_t type_a[32];
    uint8_t type_b[32];
    uint8_t type_c[32];
    uint8_t entity_x[32];
};

static void horn_root(uint8_t out[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i);
}

static uint64_t horn_elapsed_us(void *opaque)
{
    struct horn_test_clock *clock = opaque;
    uint64_t now = clock->now_us;
    clock->now_us += clock->advance_us;
    return now;
}

static bool horn_term_sort(struct zcl_ontology_term_v1 *values, size_t count)
{
    uint8_t left[32], right[32];
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1u; j < count; j++) {
            if (!zcl_ontology_term_v1_root(&values[i], left) ||
                !zcl_ontology_term_v1_root(&values[j], right))
                return false;
            if (memcmp(left, right, 32) > 0) {
                struct zcl_ontology_term_v1 swap = values[i];
                values[i] = values[j];
                values[j] = swap;
            }
        }
    }
    return true;
}

static bool horn_context_sort(
    struct zcl_ontology_context_v1 *values, size_t count)
{
    uint8_t left[32], right[32];
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1u; j < count; j++) {
            if (!zcl_ontology_context_v1_root(&values[i], left) ||
                !zcl_ontology_context_v1_root(&values[j], right))
                return false;
            if (memcmp(left, right, 32) > 0) {
                struct zcl_ontology_context_v1 swap = values[i];
                values[i] = values[j];
                values[j] = swap;
            }
        }
    }
    return true;
}

static bool horn_assertion_sort(
    struct zcl_ontology_assertion_v1 *values, size_t count)
{
    uint8_t left[32], right[32];
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1u; j < count; j++) {
            if (!zcl_ontology_assertion_v1_root(&values[i], left) ||
                !zcl_ontology_assertion_v1_root(&values[j], right))
                return false;
            if (memcmp(left, right, 32) > 0) {
                struct zcl_ontology_assertion_v1 swap = values[i];
                values[i] = values[j];
                values[j] = swap;
            }
        }
    }
    return true;
}

static bool horn_member_roots(
    enum zcl_ontology_object_kind kind, const void *members, size_t count,
    size_t member_size, uint8_t (*roots)[32])
{
    const uint8_t *bytes = members;
    for (size_t i = 0; i < count; i++) {
        const void *member = bytes + i * member_size;
        bool ok = false;
        if (kind == ZCL_ONTOLOGY_OBJECT_TERM)
            ok = zcl_ontology_term_v1_root(member, roots[i]);
        else if (kind == ZCL_ONTOLOGY_OBJECT_PREDICATE)
            ok = zcl_ontology_predicate_v1_root(member, roots[i]);
        else if (kind == ZCL_ONTOLOGY_OBJECT_FORMULA)
            ok = zcl_ontology_formula_v1_root(member, roots[i]);
        else if (kind == ZCL_ONTOLOGY_OBJECT_RULE)
            ok = zcl_ontology_horn_rule_v1_root(member, roots[i]);
        else if (kind == ZCL_ONTOLOGY_OBJECT_CONTEXT)
            ok = zcl_ontology_context_v1_root(member, roots[i]);
        else if (kind == ZCL_ONTOLOGY_OBJECT_ASSERTION)
            ok = zcl_ontology_assertion_v1_root(member, roots[i]);
        if (!ok || (i != 0 && memcmp(roots[i - 1u], roots[i], 32) >= 0))
            return false;
    }
    return true;
}

static void horn_term_init(
    struct zcl_ontology_term_v1 *term, uint8_t kind,
    const uint8_t vocabulary_root[32], const uint8_t type_root[32],
    uint8_t identity_seed, uint8_t lexical_seed)
{
    memset(term, 0, sizeof(*term));
    term->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    term->kind = kind;
    memcpy(term->vocabulary_root, vocabulary_root, 32);
    memcpy(term->type_root, type_root, 32);
    horn_root(term->identity_root, identity_seed);
    horn_root(term->lexical_root, lexical_seed);
}

static void horn_assertion_init(
    struct zcl_ontology_assertion_v1 *assertion,
    const uint8_t context_root[32], const uint8_t predicate_root[32],
    const uint8_t left[32], const uint8_t right[32], uint8_t polarity,
    uint8_t evidence_seed)
{
    memset(assertion, 0, sizeof(*assertion));
    assertion->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    assertion->arity = 2;
    assertion->polarity = polarity;
    memcpy(assertion->context_root, context_root, 32);
    memcpy(assertion->predicate_root, predicate_root, 32);
    memcpy(assertion->argument_roots[0], left, 32);
    memcpy(assertion->argument_roots[1], right, 32);
    horn_root(assertion->evidence_root, evidence_seed);
}

static bool horn_manifest_set(
    enum zcl_ontology_object_kind kind, const void *members, size_t count,
    size_t member_size, uint8_t out[32])
{
    uint8_t roots[ZCL_ONTOLOGY_MAX_HORN_TERMS][32];
    if (count > ZCL_ONTOLOGY_MAX_HORN_TERMS ||
        (count != 0 && !horn_member_roots(
            kind, members, count, member_size, roots)))
        return false;
    return zcl_ontology_object_set_v1_root(
        kind, count ? roots : NULL, count, out);
}

static bool horn_fixture_init(struct horn_fixture *fixture, bool imported)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->universe.schema_version = ZCL_SOURCE_UNIVERSE_VERSION;
    fixture->universe.coverage_mask = ZCL_SOURCE_COVER_ALL;
    fixture->universe.governed_path_count = 17;
    fixture->universe.total_bytes = 8192;
    horn_root(fixture->universe.source_manifest_root, 0x01);
    horn_root(fixture->universe.governed_paths_root, 0x11);
    horn_root(fixture->universe.generated_paths_root, 0x21);
    horn_root(fixture->universe.vendor_paths_root, 0x31);
    horn_root(fixture->universe.metadata_paths_root, 0x41);
    horn_root(fixture->universe.publishable_paths_root, 0x51);
    horn_root(fixture->universe.consensus_seal_root, 0x61);
    horn_root(fixture->universe.indexed_paths_root, 0x71);
    if (!zcl_source_universe_v1_root(
            &fixture->universe, fixture->universe_root))
        return false;

    uint8_t empty_imports_root[32];
    if (!zcl_ontology_import_manifest_v1_root(
            fixture->universe_root, NULL, 0, empty_imports_root))
        return false;
    fixture->foreign_context.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->foreign_context.kind = ZCL_ONTOLOGY_CONTEXT_CORPUS;
    memcpy(fixture->foreign_context.universe_root,
           fixture->universe_root, 32);
    memcpy(fixture->foreign_context.import_manifest_root,
           empty_imports_root, 32);
    horn_root(fixture->foreign_context.subject_root, 0x81);
    horn_root(fixture->foreign_context.policy_root, 0x91);
    if (!zcl_ontology_context_v1_root(
            &fixture->foreign_context, fixture->foreign_context_root))
        return false;
    memcpy(fixture->imports[0], fixture->foreign_context_root, 32);

    uint8_t primary_imports_root[32];
    if (!zcl_ontology_import_manifest_v1_root(
            fixture->universe_root,
            imported ? fixture->imports : NULL, imported ? 1u : 0u,
            primary_imports_root))
        return false;
    fixture->primary_context.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->primary_context.kind = ZCL_ONTOLOGY_CONTEXT_CORPUS;
    memcpy(fixture->primary_context.universe_root,
           fixture->universe_root, 32);
    memcpy(fixture->primary_context.import_manifest_root,
           primary_imports_root, 32);
    horn_root(fixture->primary_context.subject_root, 0xa1);
    horn_root(fixture->primary_context.policy_root, 0xb1);
    if (!zcl_ontology_context_v1_root(
            &fixture->primary_context, fixture->primary_context_root) ||
        !zcl_ontology_vocabulary_v1_build(
            &fixture->universe, &fixture->primary_context,
            &fixture->vocabulary))
        return false;

    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT; i++)
        fixture->terms[i] = fixture->vocabulary.terms[i];
    horn_term_init(
        &fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT],
        ZCL_ONTOLOGY_TERM_TYPE, fixture->vocabulary.vocabulary_root,
        fixture->vocabulary.ontology_type_identity_root, 0xc1, 0xc2);
    horn_term_init(
        &fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 1u],
        ZCL_ONTOLOGY_TERM_TYPE, fixture->vocabulary.vocabulary_root,
        fixture->vocabulary.ontology_type_identity_root, 0xd1, 0xd2);
    horn_term_init(
        &fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 2u],
        ZCL_ONTOLOGY_TERM_TYPE, fixture->vocabulary.vocabulary_root,
        fixture->vocabulary.ontology_type_identity_root, 0xe1, 0xe2);
    horn_term_init(
        &fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 3u],
        ZCL_ONTOLOGY_TERM_ENTITY, fixture->vocabulary.vocabulary_root,
        fixture->vocabulary.ontology_object_identity_root, 0xf1, 0xf2);
    memcpy(fixture->type_a,
           fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT].identity_root,
           32);
    memcpy(fixture->type_b,
           fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 1u]
               .identity_root, 32);
    memcpy(fixture->type_c,
           fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 2u]
               .identity_root, 32);
    memcpy(fixture->entity_x,
           fixture->terms[ZCL_ONTOLOGY_VOCABULARY_TERM_COUNT + 3u]
               .identity_root, 32);
    if (!horn_term_sort(fixture->terms, HORN_FIXTURE_TERM_COUNT))
        return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT; i++)
        if (!zcl_ontology_vocabulary_v1_formula_at(
                &fixture->vocabulary, i, &fixture->formulas[i]))
            return false;

    fixture->contexts[0] = fixture->primary_context;
    fixture->contexts[1] = fixture->foreign_context;
    if (!horn_context_sort(fixture->contexts, HORN_FIXTURE_CONTEXT_COUNT))
        return false;
    horn_assertion_init(
        &fixture->assertions[0], fixture->primary_context_root,
        fixture->vocabulary.genls_predicate_root,
        fixture->type_a, fixture->type_b, ZCL_ONTOLOGY_POSITIVE, 0x12);
    horn_assertion_init(
        &fixture->assertions[1], fixture->foreign_context_root,
        fixture->vocabulary.genls_predicate_root,
        fixture->type_b, fixture->type_c, ZCL_ONTOLOGY_POSITIVE, 0x22);
    horn_assertion_init(
        &fixture->assertions[2], fixture->primary_context_root,
        fixture->vocabulary.isa_predicate_root,
        fixture->entity_x, fixture->type_a, ZCL_ONTOLOGY_POSITIVE, 0x32);
    horn_assertion_init(
        &fixture->assertions[3], fixture->primary_context_root,
        fixture->vocabulary.isa_predicate_root,
        fixture->entity_x, fixture->type_c, ZCL_ONTOLOGY_NEGATIVE, 0x42);
    horn_assertion_init(
        &fixture->assertions[4], fixture->primary_context_root,
        fixture->vocabulary.genls_predicate_root,
        fixture->type_c, fixture->type_b, ZCL_ONTOLOGY_POSITIVE, 0x52);
    if (!horn_assertion_sort(
            fixture->assertions, HORN_FIXTURE_ASSERTION_COUNT))
        return false;

    fixture->inputs.terms = fixture->terms;
    fixture->inputs.term_count = HORN_FIXTURE_TERM_COUNT;
    fixture->inputs.predicates = fixture->vocabulary.predicates;
    fixture->inputs.predicate_count =
        ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT;
    fixture->inputs.formulas = fixture->formulas;
    fixture->inputs.formula_count =
        ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT;
    fixture->inputs.rules = fixture->vocabulary.rules;
    fixture->inputs.rule_count = ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT;
    fixture->inputs.contexts = fixture->contexts;
    fixture->inputs.context_count = HORN_FIXTURE_CONTEXT_COUNT;
    fixture->inputs.assertions = fixture->assertions;
    fixture->inputs.assertion_count = HORN_FIXTURE_ASSERTION_COUNT;

    fixture->manifest.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->manifest.term_count = HORN_FIXTURE_TERM_COUNT;
    fixture->manifest.predicate_count =
        ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT;
    fixture->manifest.formula_count =
        ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT;
    fixture->manifest.rule_count = ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT;
    fixture->manifest.context_count = HORN_FIXTURE_CONTEXT_COUNT;
    fixture->manifest.assertion_count = HORN_FIXTURE_ASSERTION_COUNT;
    memcpy(fixture->manifest.source_root,
           fixture->universe.source_manifest_root, 32);
    memcpy(fixture->manifest.universe_root, fixture->universe_root, 32);
    memcpy(fixture->manifest.vocabulary_root,
           fixture->vocabulary.vocabulary_root, 32);
    horn_root(fixture->manifest.extractor_root, 0x13);
    horn_root(fixture->manifest.policy_root, 0x23);
    if (!horn_manifest_set(
            ZCL_ONTOLOGY_OBJECT_TERM, fixture->terms,
            HORN_FIXTURE_TERM_COUNT, sizeof(fixture->terms[0]),
            fixture->manifest.term_set_root) ||
        !horn_manifest_set(
            ZCL_ONTOLOGY_OBJECT_PREDICATE, fixture->vocabulary.predicates,
            ZCL_ONTOLOGY_VOCABULARY_PREDICATE_COUNT,
            sizeof(fixture->vocabulary.predicates[0]),
            fixture->manifest.predicate_set_root) ||
        !horn_manifest_set(
            ZCL_ONTOLOGY_OBJECT_FORMULA, fixture->formulas,
            ZCL_ONTOLOGY_VOCABULARY_FORMULA_COUNT,
            sizeof(fixture->formulas[0]), fixture->manifest.formula_set_root) ||
        !horn_manifest_set(
            ZCL_ONTOLOGY_OBJECT_RULE, fixture->vocabulary.rules,
            ZCL_ONTOLOGY_VOCABULARY_RULE_COUNT,
            sizeof(fixture->vocabulary.rules[0]),
            fixture->manifest.rule_set_root) ||
        !horn_manifest_set(
            ZCL_ONTOLOGY_OBJECT_CONTEXT, fixture->contexts,
            HORN_FIXTURE_CONTEXT_COUNT, sizeof(fixture->contexts[0]),
            fixture->manifest.context_set_root) ||
        !horn_manifest_set(
            ZCL_ONTOLOGY_OBJECT_ASSERTION, fixture->assertions,
            HORN_FIXTURE_ASSERTION_COUNT, sizeof(fixture->assertions[0]),
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
    return zcl_ontology_manifest_v1_validate(
        &fixture->manifest, &fixture->universe, &fixture->inputs);
}

static void horn_query_init(
    struct zcl_ontology_horn_query_v1 *query,
    const struct horn_fixture *fixture, bool imported,
    const uint8_t predicate_root[32], const uint8_t left[32],
    const uint8_t right[32], const struct zcl_ontology_budget_v1 *budget,
    struct horn_test_clock *clock)
{
    memset(query, 0, sizeof(*query));
    query->schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    memcpy(query->universe_root, fixture->universe_root, 32);
    memcpy(query->context_root, fixture->primary_context_root, 32);
    memcpy(query->predicate_root, predicate_root, 32);
    query->arity = 2;
    memcpy(query->argument_roots[0], left, 32);
    memcpy(query->argument_roots[1], right, 32);
    query->import_context_roots = imported ? fixture->imports : NULL;
    query->import_count = imported ? 1u : 0u;
    query->manifest = &fixture->manifest;
    query->inputs = &fixture->inputs;
    query->budget = budget;
    query->elapsed_us = horn_elapsed_us;
    query->elapsed_context = clock;
}

static bool horn_result_derivation_root(
    const struct zcl_ontology_horn_query_v1 *query,
    const struct zcl_ontology_result_v1 *result, uint8_t out[32])
{
    uint8_t query_root[32], budget_root[32], manifest_root[32];
    if (!zcl_ontology_horn_query_v1_root(query, query_root) ||
        !zcl_ontology_budget_v1_root(query->budget, budget_root) ||
        !zcl_ontology_manifest_v1_root(query->manifest, manifest_root))
        return false;
    struct zcl_ontology_horn_derivation_v1 derivation = {
        .schema_version = ZCL_ONTOLOGY_OBJECT_VERSION,
        .status = result->status,
        .observed_positive = result->observed_positive,
        .observed_negative = result->observed_negative,
        .complete = result->complete,
        .incomplete_reason = result->incomplete_reason,
        .missing_coverage_mask = result->missing_coverage_mask,
        .facts_examined = result->facts_examined,
        .steps_taken = result->steps_taken,
        .derivations_produced = result->derivations_produced,
        .max_recursion_depth = result->max_recursion_depth,
    };
    memcpy(derivation.universe_root, query->universe_root, 32);
    memcpy(derivation.context_root, query->context_root, 32);
    memcpy(derivation.query_root, query_root, 32);
    memcpy(derivation.budget_root, budget_root, 32);
    memcpy(derivation.evidence_manifest_root, manifest_root, 32);
    horn_root(derivation.evaluator_root, 0x63);
    if (!zcl_ontology_horn_derivation_v1_root(&derivation, out))
        return false;
    uint8_t query_before[32];
    memcpy(query_before, derivation.query_root, 32);
    if (zcl_ontology_horn_derivation_v1_root(
            &derivation, derivation.query_root) ||
        memcmp(query_before, derivation.query_root, 32) != 0)
        return false;
    uint64_t facts_before = derivation.facts_examined;
    derivation.facts_examined = derivation.steps_taken + 1u;
    if (zcl_ontology_horn_derivation_v1_root(&derivation, query_root))
        return false;
    derivation.facts_examined = facts_before;
    uint8_t reason_before = derivation.incomplete_reason;
    uint8_t status_before = derivation.status;
    uint8_t complete_before = derivation.complete;
    derivation.status = ZCL_ONTOLOGY_INCOMPLETE;
    derivation.complete = 0;
    derivation.incomplete_reason = ZCL_ONTOLOGY_REASON_DOMAIN_MISSING;
    if (zcl_ontology_horn_derivation_v1_root(&derivation, query_root))
        return false;
    derivation.status = status_before;
    derivation.complete = complete_before;
    derivation.incomplete_reason = reason_before;
    return true;
}

static int test_ontology_horn_fixed_point(void)
{
    int failures = 0;
    TEST_CASE("ontology Horn: ISA and genls saturate without explosion") {
        struct horn_fixture isolated, imported;
        ASSERT(horn_fixture_init(&isolated, false));
        ASSERT(horn_fixture_init(&imported, true));
        struct zcl_ontology_budget_v1 budget = {
            .schema_version = ZCL_ONTOLOGY_OBJECT_VERSION,
            .memory_limit_bytes = 1u << 20,
            .fact_limit = 4096,
            .step_limit = 16384,
            .recursion_limit = 32,
            .derivation_limit = 1024,
            .time_limit_us = 1000000,
        };
        struct horn_test_clock clock = {0};
        union {
            max_align_t alignment;
            uint8_t bytes[ZCL_ONTOLOGY_EVALUATOR_STORAGE_BYTES];
        } storage;
        struct zcl_ontology_evaluator *evaluator = NULL;
        ASSERT(zcl_ontology_evaluator_init_v1(
            storage.bytes, sizeof(storage.bytes), &evaluator));
        struct zcl_ontology_horn_query_v1 query;
        struct zcl_ontology_result_v1 result;

        horn_query_init(
            &query, &isolated, false,
            isolated.vocabulary.isa_predicate_root,
            isolated.entity_x, isolated.type_c, &budget, &clock);
        uint8_t query_root[32], query_root_again[32];
        ASSERT(zcl_ontology_horn_query_v1_root(&query, query_root));
        ASSERT(zcl_ontology_horn_query_v1_root(&query, query_root_again));
        ASSERT(memcmp(query_root, query_root_again, 32) == 0);
        query.argument_roots[1][0] ^= 1u;
        ASSERT(zcl_ontology_horn_query_v1_root(&query, query_root_again));
        ASSERT(memcmp(query_root, query_root_again, 32) != 0);
        query.argument_roots[1][0] ^= 1u;
        ASSERT(!zcl_ontology_horn_query_v1_root(
            &query, query.universe_root));
        ASSERT(memcmp(query.universe_root, isolated.universe_root, 32) == 0);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &isolated.universe, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_DISPROVED);
        ASSERT(!result.observed_positive && result.observed_negative);

        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.isa_predicate_root,
            imported.entity_x, imported.type_c, &budget, &clock);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_BOTH);
        ASSERT(result.observed_positive && result.observed_negative);
        ASSERT(result.derivations_produced == 6);

        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.genls_predicate_root,
            imported.type_a, imported.type_c, &budget, &clock);
        ASSERT(zcl_ontology_horn_query_v1_root(&query, query_root));
        uint8_t import_before[32];
        memcpy(import_before, imported.imports[0], 32);
        ASSERT(!zcl_ontology_horn_query_v1_root(
            &query, imported.imports[0]));
        ASSERT(memcmp(import_before, imported.imports[0], 32) == 0);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_PROVED);
        ASSERT(result.observed_positive && !result.observed_negative);

        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.genls_predicate_root,
            imported.type_c, imported.type_a, &budget, &clock);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(!result.observed_positive && !result.observed_negative);

        uint64_t stable_facts = result.facts_examined;
        uint64_t stable_steps = result.steps_taken;
        uint64_t stable_derivations = result.derivations_produced;
        uint32_t stable_depth = result.max_recursion_depth;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_UNKNOWN);
        ASSERT(result.facts_examined == stable_facts);
        ASSERT(result.steps_taken == stable_steps);
        ASSERT(result.derivations_produced == stable_derivations);
        ASSERT(result.max_recursion_depth == stable_depth);

        struct horn_fixture direct;
        ASSERT(horn_fixture_init(&direct, false));
        direct.inputs.formulas = NULL;
        direct.inputs.formula_count = 0;
        direct.inputs.rules = NULL;
        direct.inputs.rule_count = 0;
        direct.manifest.formula_count = 0;
        direct.manifest.rule_count = 0;
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_FORMULA, NULL, 0,
            direct.manifest.formula_set_root));
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_RULE, NULL, 0,
            direct.manifest.rule_set_root));
        ASSERT(zcl_ontology_manifest_v1_validate(
            &direct.manifest, &direct.universe, &direct.inputs));
        struct zcl_ontology_budget_v1 direct_budget = budget;
        horn_query_init(
            &query, &direct, false,
            direct.vocabulary.genls_predicate_root,
            direct.type_a, direct.type_b, &direct_budget, &clock);
        ASSERT(zcl_ontology_horn_query_v1_root(&query, query_root));
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &direct.universe, &query, &result));
        ASSERT(result.complete && result.status == ZCL_ONTOLOGY_PROVED);
        ASSERT(result.observed_positive && !result.observed_negative);
        ASSERT(result.derivations_produced == 0);
        ASSERT(result.max_recursion_depth == 0);
        uint8_t direct_derivation_root[32];
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        direct_budget.fact_limit = 0;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &direct.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_FACT_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));
        direct_budget.fact_limit = 4096;
        direct_budget.step_limit = 0;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &direct.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_STEP_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        budget.fact_limit = 1;
        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.isa_predicate_root,
            imported.entity_x, imported.type_c, &budget, &clock);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_FACT_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        budget.fact_limit = 4096;
        budget.step_limit = 1;
        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.isa_predicate_root,
            imported.entity_x, imported.type_c, &budget, &clock);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_STEP_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        budget.step_limit = 16384;
        budget.derivation_limit = 0;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_DERIVATION_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        budget.derivation_limit = 1024;
        budget.recursion_limit = 0;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_RECURSION_BUDGET);
        ASSERT(result.observed_negative);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        budget.recursion_limit = 32;
        budget.memory_limit_bytes = 1;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_MEMORY_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        budget.memory_limit_bytes = 1u << 20;
        budget.time_limit_us = 1;
        clock.now_us = 0;
        clock.advance_us = 1;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason == ZCL_ONTOLOGY_REASON_TIME_BUDGET);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));
        clock.now_us = 2;
        clock.advance_us = UINT64_MAX;
        budget.time_limit_us = UINT64_MAX;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_TIME_SOURCE_REGRESSED);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));
        clock.now_us = 0;
        clock.advance_us = 0;
        budget.time_limit_us = 1000000;

        query.elapsed_us = NULL;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_TIME_SOURCE_MISSING);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.isa_predicate_root,
            imported.entity_x, imported.type_c, &budget, &clock);
        horn_root(query.predicate_root, 0x77);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_PREDICATE_MISSING);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        horn_query_init(
            &query, &imported, false,
            imported.vocabulary.isa_predicate_root,
            imported.entity_x, imported.type_c, &budget, &clock);
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        horn_query_init(
            &query, &imported, true,
            imported.vocabulary.isa_predicate_root,
            imported.entity_x, imported.type_c, &budget, &clock);
        struct zcl_ontology_manifest_inputs_v1 bad_inputs = imported.inputs;
        bad_inputs.assertions = NULL;
        query.inputs = &bad_inputs;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_HORN_QUERY_INVALID);
        query.inputs = &imported.inputs;
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));

        struct zcl_ontology_manifest_v1 changed = imported.manifest;
        changed.rule_set_root[0] ^= 1u;
        query.manifest = &changed;
        ASSERT(zcl_ontology_evaluate_horn_v1(
            evaluator, &imported.universe, &query, &result));
        ASSERT(!result.complete && result.status == ZCL_ONTOLOGY_INCOMPLETE);
        ASSERT(result.incomplete_reason ==
               ZCL_ONTOLOGY_REASON_MANIFEST_INVALID);
        ASSERT(horn_result_derivation_root(
            &query, &result, direct_derivation_root));
        PASS();
    } TEST_END
    return failures;
}

int test_ontology_horn_evaluator(void)
{
    return test_ontology_horn_fixed_point();
}
