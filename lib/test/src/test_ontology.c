/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Born-red contracts for contextual, paraconsistent ontology truth. */
#include "test/test_core.h"
#include "ontology/ontology.h"
#include "base/hex.h"

#include <string.h>

static void root(uint8_t out[32], uint8_t value) { memset(out, value, 32); }

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
    return failures;
}
