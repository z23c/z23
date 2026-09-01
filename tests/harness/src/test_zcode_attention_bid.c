/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: immutable heuristic and Pareto attention-bid contracts. */
#include "vcs/zcode_attention_bid.h"

#include "test/test_core.h"
#include "vcs/vcs_object.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AB_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                     \
        printf("  zcode_attention_bid: %s... OK\n", (name_));             \
    } else {                                                               \
        printf("  zcode_attention_bid: %s... FAIL\n", (name_));           \
        failures++;                                                        \
    }                                                                      \
} while (0)

static void ab_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static void ab_valid_heuristic(struct vcs_zcode_heuristic_v1 *heuristic,
                               uint8_t tag)
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 2;
    ab_root(heuristic->task_root, 1);
    ab_root(heuristic->source_root, 2);
    ab_root(heuristic->agent_context_root, 3);
    ab_root(heuristic->ontology_context_root, 4);
    ab_root(heuristic->applicability_root, 5);
    ab_root(heuristic->observed_features_root, 6);
    ab_root(heuristic->proposed_rule_root, tag);
    ab_root(heuristic->expected_effect_root, 8);
    ab_root(heuristic->proposal_input_root, 12);
    ab_root(heuristic->study_root, 13);
    ab_root(heuristic->preregistration_root, 14);
    ab_root(heuristic->provenance_root, 9);
    ab_root(heuristic->evaluator_roots[0], 5);
    ab_root(heuristic->evaluator_roots[1], 11);
    heuristic->requested_cpu_seconds = 60;
    heuristic->requested_processes = 2;
    heuristic->requested_memory_bytes = 16u * 1024u * 1024u;
    heuristic->requested_context_bytes = 64u * 1024u;
    heuristic->requested_output_bytes = 1024u * 1024u;
}

static void ab_derived_heuristic(
    struct vcs_zcode_heuristic_v1 *child,
    const struct vcs_zcode_heuristic_v1 *parent, uint8_t tag)
{
    *child = *parent;
    child->derivation = VCS_ZCODE_HEURISTIC_SPECIALIZE;
    child->parent_count = 1;
    ab_root(child->proposed_rule_root, tag);
    ab_root(child->proposal_input_root, (uint8_t)(tag + 1u));
    ab_root(child->provenance_root, (uint8_t)(tag + 2u));
    (void)vcs_zcode_heuristic_root(parent, child->parent_roots[0]);
}

static void ab_order_two_parents(
    struct vcs_zcode_heuristic_v1 parents[2])
{
    uint8_t roots[2][32];
    (void)vcs_zcode_heuristic_root(&parents[0], roots[0]);
    (void)vcs_zcode_heuristic_root(&parents[1], roots[1]);
    if (memcmp(roots[0], roots[1], 32) > 0) {
        struct vcs_zcode_heuristic_v1 swap = parents[0];
        parents[0] = parents[1];
        parents[1] = swap;
    }
}

static void ab_composed_heuristic(
    struct vcs_zcode_heuristic_v1 *child,
    const struct vcs_zcode_heuristic_v1 parents[2], uint8_t tag)
{
    *child = parents[0];
    child->derivation = VCS_ZCODE_HEURISTIC_COMPOSE;
    child->parent_count = 2;
    ab_root(child->proposed_rule_root, tag);
    ab_root(child->proposal_input_root, (uint8_t)(tag + 1u));
    ab_root(child->provenance_root, (uint8_t)(tag + 2u));
    (void)vcs_zcode_heuristic_root(&parents[0], child->parent_roots[0]);
    (void)vcs_zcode_heuristic_root(&parents[1], child->parent_roots[1]);
}

static void ab_valid_focus(struct vcs_zcode_focus_v1 *focus)
{
    memset(focus, 0, sizeof(*focus));
    focus->schema_version = VCS_ZCODE_FOCUS_VERSION;
    focus->status = ZCL_ONTOLOGY_PROVED;
    focus->capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                          VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    focus->max_changed_files = 8;
    focus->max_patch_bytes = 65536;
    focus->max_context_bytes = 128u * 1024u;
    focus->max_cpu_seconds = 120;
    focus->max_memory_bytes = 32u * 1024u * 1024u;
    focus->max_output_bytes = 2u * 1024u * 1024u;
    ab_root(focus->task_root, 1);
    ab_root(focus->goal_root, 20);
    ab_root(focus->source_universe_root, 2);
    ab_root(focus->context_root, 3);
    ab_root(focus->story_graph_root, 4);
    (void)vcs_zcode_focus_claim_set_root(NULL, 0, focus->claim_set_root);
    ab_root(focus->required_evidence_root, 21);
    ab_root(focus->authority_limits_root, 22);
}

static void ab_valid_bid(struct vcs_zcode_attention_bid_v1 *bid,
                         const struct vcs_zcode_heuristic_v1 *heuristic)
{
    vcs_zcode_attention_bid_init(bid);
    bid->priority_class = VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY;
    struct vcs_zcode_focus_v1 focus;
    ab_valid_focus(&focus);
    (void)vcs_zcode_focus_root(&focus, bid->focus_root);
    ab_root(bid->task_root, 1);
    ab_root(bid->source_root, 2);
    (void)vcs_zcode_heuristic_root(heuristic, bid->heuristic_root);
    ab_root(bid->priority_policy_root, 4);
    ab_root(bid->bid_evaluator_root, 5);
    ab_root(bid->evidence_root, 6);
    bid->expected_user_value_bp = 7000;
    bid->information_gain_bp = 6000;
    bid->blocker_relief_bp = 5000;
    bid->reuse_potential_bp = 4000;
    bid->evidence_strength_bp = 3000;
    bid->risk_bp = 2000;
    bid->overlap_bp = 1000;
    bid->observed_metrics = VCS_ZCODE_ATTENTION_METRIC_REQUIRED;
    bid->expected_latency_us = 1000000;
    bid->expected_cost_milliunits = 100;
}

static void ab_query(struct vcs_zcode_attention_frontier_query *query,
                     uint8_t priority_class)
{
    memset(query, 0, sizeof(*query));
    struct vcs_zcode_focus_v1 focus;
    ab_valid_focus(&focus);
    (void)vcs_zcode_focus_root(&focus, query->focus_root);
    ab_root(query->task_root, 1);
    ab_root(query->source_root, 2);
    ab_root(query->priority_policy_root, 4);
    ab_root(query->bid_evaluator_root, 5);
    query->priority_class = priority_class;
}

static bool ab_roots_equal(const struct vcs_zcode_attention_bid_v1 *left,
                           const struct vcs_zcode_attention_bid_v1 *right)
{
    uint8_t left_root[32], right_root[32];
    return vcs_zcode_attention_bid_root(left, left_root) ==
               VCS_ZCODE_ATTENTION_OK &&
           vcs_zcode_attention_bid_root(right, right_root) ==
               VCS_ZCODE_ATTENTION_OK &&
           memcmp(left_root, right_root, 32) == 0;
}

static bool ab_all_zero(const uint8_t *bytes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

static void ab_improve_axis(struct vcs_zcode_attention_bid_v1 *bid,
                            size_t axis)
{
    switch (axis) {
    case 0: bid->expected_user_value_bp++; break;
    case 1: bid->information_gain_bp++; break;
    case 2: bid->blocker_relief_bp++; break;
    case 3: bid->reuse_potential_bp++; break;
    case 4: bid->evidence_strength_bp++; break;
    case 5: bid->risk_bp--; break;
    case 6: bid->overlap_bp--; break;
    case 7: bid->expected_latency_us--; break;
    case 8: bid->expected_cost_milliunits--; break;
    default: break;
    }
}

int test_zcode_attention_bid(void)
{
    int failures = 0;
    struct vcs_zcode_heuristic_v1 heuristic, parsed_heuristic;
    uint8_t heuristic_wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
    uint8_t heuristic_root[32], changed_root[32];
    ab_valid_heuristic(&heuristic, 7);
    AB_CHECK("heuristic-valid",
             vcs_zcode_heuristic_validate(&heuristic) ==
                 VCS_ZCODE_ATTENTION_OK);
    AB_CHECK("heuristic-exact-wire",
             vcs_zcode_heuristic_serialize(&heuristic, heuristic_wire) ==
                 VCS_ZCODE_ATTENTION_OK &&
             memcmp(heuristic_wire, "ZCHEUR1\n", 8) == 0);
    AB_CHECK("heuristic-round-trip",
             vcs_zcode_heuristic_parse(heuristic_wire,
                                       sizeof(heuristic_wire),
                                       &parsed_heuristic) ==
                 VCS_ZCODE_ATTENTION_OK &&
             parsed_heuristic.evaluator_count == 2 &&
             parsed_heuristic.parent_count == 0 &&
             memcmp(parsed_heuristic.proposed_rule_root,
                    heuristic.proposed_rule_root, 32) == 0);
    AB_CHECK("heuristic-root",
             vcs_zcode_heuristic_root(&heuristic, heuristic_root) ==
                 VCS_ZCODE_ATTENTION_OK);
    parsed_heuristic.proposed_rule_root[0]++;
    AB_CHECK("heuristic-root-commits-rule",
             vcs_zcode_heuristic_root(&parsed_heuristic, changed_root) ==
                 VCS_ZCODE_ATTENTION_OK &&
             memcmp(heuristic_root, changed_root, 32) != 0);

    uint8_t saved = heuristic_wire[13];
    heuristic_wire[13] = 1;
    AB_CHECK("heuristic-reserved-refusal",
             vcs_zcode_heuristic_parse(heuristic_wire,
                                       sizeof(heuristic_wire),
                                       &parsed_heuristic) ==
                 VCS_ZCODE_ATTENTION_RESERVED);
    heuristic_wire[13] = saved;
    heuristic_wire[0] ^= 1u;
    AB_CHECK("heuristic-magic-refusal",
             vcs_zcode_heuristic_parse(heuristic_wire,
                                       sizeof(heuristic_wire),
                                       &parsed_heuristic) ==
                 VCS_ZCODE_ATTENTION_MAGIC);

    struct vcs_zcode_heuristic_v1 invalid = heuristic;
    invalid.evaluator_roots[1][0] = 4;
    AB_CHECK("heuristic-evaluator-order-refusal",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_ORDER);
    invalid = heuristic;
    ab_root(invalid.evaluator_roots[2], 12);
    AB_CHECK("heuristic-inactive-root-refusal",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_RESERVED);
    invalid = heuristic;
    invalid.derivation = VCS_ZCODE_HEURISTIC_SPECIALIZE;
    AB_CHECK("derived-heuristic-needs-parent",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_DERIVATION);
    invalid = heuristic;
    invalid.derivation = VCS_ZCODE_HEURISTIC_COMPOSE;
    invalid.parent_count = 1;
    ab_root(invalid.parent_roots[0], 20);
    AB_CHECK("compose-needs-two-parents",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_DERIVATION);
    invalid.parent_count = 2;
    ab_root(invalid.parent_roots[1], 21);
    AB_CHECK("compose-valid",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_OK);

    struct vcs_zcode_heuristic_v1 derived;
    ab_derived_heuristic(&derived, &heuristic, 30);
    AB_CHECK("seed-lineage-has-no-parents",
             vcs_zcode_heuristic_validate_derivation(
                 &heuristic, NULL, 0) == VCS_ZCODE_ATTENTION_OK);
    AB_CHECK("derived-lineage-resolves-exact-parent",
             vcs_zcode_heuristic_validate_derivation(
                 &derived, &heuristic, 1) == VCS_ZCODE_ATTENTION_OK);
    struct vcs_zcode_attention_bid_v1 derived_bid;
    ab_valid_bid(&derived_bid, &derived);
    AB_CHECK("unresolved-derived-bid-refuses-seed-seam",
             vcs_zcode_attention_bid_validate_for_heuristic(
                 &derived_bid, &derived) ==
                 VCS_ZCODE_ATTENTION_DERIVATION);
    AB_CHECK("derived-bid-requires-exact-lineage-seam",
             vcs_zcode_attention_bid_validate_for_derivation(
                 &derived_bid, &derived, &heuristic, 1) ==
                 VCS_ZCODE_ATTENTION_OK);
    struct vcs_zcode_attention_frontier_query derived_query;
    struct vcs_zcode_attention_frontier_report derived_report;
    size_t derived_selected = 777;
    ab_query(&derived_query, VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY);
    AB_CHECK("frontier-refuses-unresolved-derived-heuristic",
             vcs_zcode_attention_frontier_project(
                 &derived_bid, 1, &derived, &derived_query,
                 &derived_selected, 1, &derived_report) ==
                 VCS_ZCODE_ATTENTION_DERIVATION &&
             derived_selected == 777);
    AB_CHECK("derived-lineage-requires-parent-object",
             vcs_zcode_heuristic_validate_derivation(
                 &derived, NULL, 1) == VCS_ZCODE_ATTENTION_NULL);
    AB_CHECK("derived-lineage-count-refusal",
             vcs_zcode_heuristic_validate_derivation(
                 &derived, &heuristic, 0) == VCS_ZCODE_ATTENTION_COUNT);
    struct vcs_zcode_heuristic_v1 changed_derived = derived;
    changed_derived.parent_roots[0][0] ^= 1u;
    AB_CHECK("derived-lineage-root-mismatch-refusal",
             vcs_zcode_heuristic_validate_derivation(
                 &changed_derived, &heuristic, 1) ==
                 VCS_ZCODE_ATTENTION_BINDING);

    uint8_t *const frozen_lineage_roots[] = {
        derived.task_root, derived.source_root,
        derived.agent_context_root, derived.ontology_context_root,
        derived.study_root, derived.preregistration_root,
        derived.evaluator_roots[1],
    };
    bool all_lineage_mutations_refused = true;
    for (size_t i = 0;
         i < sizeof(frozen_lineage_roots) /
             sizeof(frozen_lineage_roots[0]); i++) {
        frozen_lineage_roots[i][0] ^= 1u;
        if (vcs_zcode_heuristic_validate_derivation(
                &derived, &heuristic, 1) !=
            VCS_ZCODE_ATTENTION_BINDING)
            all_lineage_mutations_refused = false;
        frozen_lineage_roots[i][0] ^= 1u;
    }
    AB_CHECK("derived-lineage-freezes-evaluation-boundary",
             all_lineage_mutations_refused);

    struct vcs_zcode_heuristic_v1 compose_parents[2], composed;
    ab_valid_heuristic(&compose_parents[0], 40);
    ab_valid_heuristic(&compose_parents[1], 41);
    ab_order_two_parents(compose_parents);
    ab_composed_heuristic(&composed, compose_parents, 42);
    AB_CHECK("compose-lineage-resolves-canonical-parent-set",
             vcs_zcode_heuristic_validate_derivation(
                 &composed, compose_parents, 2) ==
                 VCS_ZCODE_ATTENTION_OK);
    struct vcs_zcode_heuristic_v1 reversed_parents[2] = {
        compose_parents[1], compose_parents[0]
    };
    AB_CHECK("compose-lineage-parent-order-refusal",
             vcs_zcode_heuristic_validate_derivation(
                 &composed, reversed_parents, 2) ==
                 VCS_ZCODE_ATTENTION_BINDING);
    compose_parents[1].study_root[0] ^= 1u;
    ab_order_two_parents(compose_parents);
    ab_composed_heuristic(&composed, compose_parents, 43);
    AB_CHECK("compose-lineage-policy-disagreement-refusal",
             vcs_zcode_heuristic_validate_derivation(
                 &composed, compose_parents, 2) ==
                 VCS_ZCODE_ATTENTION_BINDING);
    invalid = heuristic;
    invalid.derivation = VCS_ZCODE_HEURISTIC_REPAIR;
    invalid.parent_count = 2;
    ab_root(invalid.parent_roots[0], 20);
    ab_root(invalid.parent_roots[1], 21);
    AB_CHECK("non-compose-derivation-has-one-parent",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_DERIVATION);

    invalid = heuristic;
    invalid.requested_context_bytes =
        VCS_ZCODE_HEURISTIC_MAX_CONTEXT_BYTES + 1u;
    AB_CHECK("heuristic-budget-refusal",
             vcs_zcode_heuristic_validate(&invalid) ==
                 VCS_ZCODE_ATTENTION_BUDGET);
    uint8_t stale_heuristic_wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
    memset(stale_heuristic_wire, 0xa5, sizeof(stale_heuristic_wire));
    invalid = heuristic;
    invalid.schema_version++;
    AB_CHECK("failed-heuristic-serialization-zeroes-output",
             vcs_zcode_heuristic_serialize(
                 &invalid, stale_heuristic_wire) ==
                 VCS_ZCODE_ATTENTION_VERSION &&
             ab_all_zero(stale_heuristic_wire,
                         sizeof(stale_heuristic_wire)));
    memset(stale_heuristic_wire, 0xa5, sizeof(stale_heuristic_wire));
    AB_CHECK("null-heuristic-serialization-zeroes-output",
             vcs_zcode_heuristic_serialize(
                 NULL, stale_heuristic_wire) == VCS_ZCODE_ATTENTION_NULL &&
             ab_all_zero(stale_heuristic_wire,
                         sizeof(stale_heuristic_wire)));
    memset(&parsed_heuristic, 0xa5, sizeof(parsed_heuristic));
    AB_CHECK("null-heuristic-parse-zeroes-output",
             vcs_zcode_heuristic_parse(
                 NULL, VCS_ZCODE_HEURISTIC_WIRE_BYTES,
                 &parsed_heuristic) == VCS_ZCODE_ATTENTION_NULL &&
             ab_all_zero((const uint8_t *)&parsed_heuristic,
                         sizeof(parsed_heuristic)));
    memset(changed_root, 0xa5, sizeof(changed_root));
    AB_CHECK("null-heuristic-root-zeroes-output",
             vcs_zcode_heuristic_root(NULL, changed_root) ==
                 VCS_ZCODE_ATTENTION_NULL &&
             ab_all_zero(changed_root, sizeof(changed_root)));
    AB_CHECK("heuristic-root-alias-refusal",
             vcs_zcode_heuristic_root(&heuristic, heuristic.task_root) ==
                 VCS_ZCODE_ATTENTION_ALIAS);
    AB_CHECK("heuristic-short-and-trailing-refusal",
             vcs_zcode_heuristic_parse(
                 heuristic_wire, VCS_ZCODE_HEURISTIC_WIRE_BYTES - 1,
                 &parsed_heuristic) == VCS_ZCODE_ATTENTION_WIRE_SIZE &&
             vcs_zcode_heuristic_parse(
                 heuristic_wire, VCS_ZCODE_HEURISTIC_WIRE_BYTES + 1,
                 &parsed_heuristic) == VCS_ZCODE_ATTENTION_WIRE_SIZE);
    union {
        struct vcs_zcode_heuristic_v1 object;
        uint8_t wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
    } heuristic_alias;
    heuristic_alias.object = heuristic;
    AB_CHECK("heuristic-serialize-alias-refusal",
             vcs_zcode_heuristic_serialize(
                 &heuristic_alias.object, heuristic_alias.wire) ==
                 VCS_ZCODE_ATTENTION_ALIAS);
    (void)vcs_zcode_heuristic_serialize(&heuristic, heuristic_alias.wire);
    AB_CHECK("heuristic-parse-alias-refusal",
             vcs_zcode_heuristic_parse(
                 heuristic_alias.wire, sizeof(heuristic_alias.wire),
                 &heuristic_alias.object) == VCS_ZCODE_ATTENTION_ALIAS);

    struct vcs_zcode_attention_bid_v1 bid, parsed_bid;
    uint8_t bid_wire[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES];
    ab_valid_bid(&bid, &heuristic);
    AB_CHECK("attention-bid-valid",
             vcs_zcode_attention_bid_validate(&bid) ==
                 VCS_ZCODE_ATTENTION_OK);
    AB_CHECK("attention-bid-heuristic-binding",
             vcs_zcode_attention_bid_validate_for_heuristic(
                 &bid, &heuristic) == VCS_ZCODE_ATTENTION_OK);
    struct vcs_zcode_focus_v1 focus;
    ab_valid_focus(&focus);
    AB_CHECK("attention-bid-focus-binding",
             vcs_zcode_attention_bid_validate_for_focus(
                 &bid, &heuristic, &focus) == VCS_ZCODE_ATTENTION_OK);
    AB_CHECK("attention-bid-exact-wire",
             vcs_zcode_attention_bid_serialize(&bid, bid_wire) ==
                 VCS_ZCODE_ATTENTION_OK &&
             memcmp(bid_wire, "ZCATTN1\n", 8) == 0);
    AB_CHECK("attention-bid-round-trip",
             vcs_zcode_attention_bid_parse(bid_wire, sizeof(bid_wire),
                                           &parsed_bid) ==
                 VCS_ZCODE_ATTENTION_OK &&
             ab_roots_equal(&bid, &parsed_bid));
    uint8_t kat_bid_root[32];
    (void)vcs_zcode_attention_bid_root(&bid, kat_bid_root);
    static const uint8_t expected_heuristic_root[32] = {
        0x26, 0x64, 0x92, 0x9f, 0xa7, 0x56, 0xb1, 0x26,
        0xd2, 0x4b, 0xa9, 0x63, 0x27, 0x18, 0x93, 0xc1,
        0xaf, 0xa0, 0x66, 0x49, 0x9f, 0x62, 0xd5, 0xc6,
        0x7a, 0xe5, 0x16, 0x6a, 0xe9, 0x76, 0xa0, 0x9a,
    };
    static const uint8_t expected_bid_root[32] = {
        0x74, 0xed, 0x73, 0x3a, 0x3f, 0x0f, 0x00, 0x8c,
        0x8f, 0xbd, 0x9b, 0x87, 0x7a, 0x34, 0x6e, 0xd6,
        0x20, 0x53, 0x04, 0x90, 0x87, 0x90, 0x57, 0xce,
        0x95, 0xfd, 0xec, 0x11, 0x5e, 0x1b, 0x88, 0x20,
    };
    AB_CHECK("frozen-wire-root-kats",
             memcmp(heuristic_root, expected_heuristic_root, 32) == 0 &&
             memcmp(kat_bid_root, expected_bid_root, 32) == 0);
    bid_wire[11] = 1;
    AB_CHECK("attention-bid-reserved-refusal",
             vcs_zcode_attention_bid_parse(bid_wire, sizeof(bid_wire),
                                           &parsed_bid) ==
                 VCS_ZCODE_ATTENTION_RESERVED);
    ab_valid_bid(&bid, &heuristic);
    bid.observed_metrics &=
        (uint16_t)~VCS_ZCODE_ATTENTION_METRIC_RISK;
    AB_CHECK("unknown-metric-refusal",
             vcs_zcode_attention_bid_validate(&bid) ==
                 VCS_ZCODE_ATTENTION_METRIC);
    ab_valid_bid(&bid, &heuristic);
    bid.overlap_bp = VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX + 1u;
    AB_CHECK("metric-bound-refusal",
             vcs_zcode_attention_bid_validate(&bid) ==
                 VCS_ZCODE_ATTENTION_METRIC);

    ab_valid_bid(&bid, &heuristic);
    struct vcs_zcode_heuristic_v1 mismatched = heuristic;
    mismatched.proposed_rule_root[0]++;
    AB_CHECK("heuristic-root-mismatch-refusal",
             vcs_zcode_attention_bid_validate_for_heuristic(
                 &bid, &mismatched) == VCS_ZCODE_ATTENTION_BINDING);
    mismatched = heuristic;
    mismatched.source_root[0]++;
    (void)vcs_zcode_heuristic_root(&mismatched, bid.heuristic_root);
    AB_CHECK("heuristic-source-mismatch-refusal",
             vcs_zcode_attention_bid_validate_for_heuristic(
                 &bid, &mismatched) == VCS_ZCODE_ATTENTION_BINDING);
    ab_valid_bid(&bid, &heuristic);
    focus.claim_set_root[0]++;
    AB_CHECK("changed-focus-claim-set-refusal",
             vcs_zcode_attention_bid_validate_for_focus(
                 &bid, &heuristic, &focus) ==
                 VCS_ZCODE_ATTENTION_BINDING);
    ab_valid_focus(&focus);
    focus.max_context_bytes = heuristic.requested_context_bytes - 1u;
    (void)vcs_zcode_focus_root(&focus, bid.focus_root);
    AB_CHECK("focus-budget-refusal",
             vcs_zcode_attention_bid_validate_for_focus(
                 &bid, &heuristic, &focus) ==
                 VCS_ZCODE_ATTENTION_BINDING);
    ab_valid_bid(&bid, &heuristic);
    ab_root(bid.bid_evaluator_root, 10);
    AB_CHECK("unauthorized-evaluator-refusal",
             vcs_zcode_attention_bid_validate_for_heuristic(
                 &bid, &heuristic) == VCS_ZCODE_ATTENTION_BINDING);

    uint8_t stale_wire[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES];
    memset(stale_wire, 0xa5, sizeof(stale_wire));
    ab_valid_bid(&bid, &heuristic);
    bid.schema_version++;
    AB_CHECK("failed-serialization-zeroes-output",
             vcs_zcode_attention_bid_serialize(&bid, stale_wire) ==
                 VCS_ZCODE_ATTENTION_VERSION &&
             ab_all_zero(stale_wire, sizeof(stale_wire)));
    memset(stale_wire, 0xa5, sizeof(stale_wire));
    AB_CHECK("null-bid-serialization-zeroes-output",
             vcs_zcode_attention_bid_serialize(NULL, stale_wire) ==
                 VCS_ZCODE_ATTENTION_NULL &&
             ab_all_zero(stale_wire, sizeof(stale_wire)));
    memset(&parsed_bid, 0xa5, sizeof(parsed_bid));
    AB_CHECK("null-bid-parse-zeroes-output",
             vcs_zcode_attention_bid_parse(
                 NULL, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES,
                 &parsed_bid) == VCS_ZCODE_ATTENTION_NULL &&
             ab_all_zero((const uint8_t *)&parsed_bid,
                         sizeof(parsed_bid)));
    memset(kat_bid_root, 0xa5, sizeof(kat_bid_root));
    AB_CHECK("null-bid-root-zeroes-output",
             vcs_zcode_attention_bid_root(NULL, kat_bid_root) ==
                 VCS_ZCODE_ATTENTION_NULL &&
             ab_all_zero(kat_bid_root, sizeof(kat_bid_root)));
    ab_valid_bid(&bid, &heuristic);
    AB_CHECK("bid-root-alias-refusal",
             vcs_zcode_attention_bid_root(&bid, bid.task_root) ==
                 VCS_ZCODE_ATTENTION_ALIAS);
    union {
        struct vcs_zcode_attention_bid_v1 object;
        uint8_t wire[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES];
    } bid_alias;
    bid_alias.object = bid;
    AB_CHECK("bid-serialize-alias-refusal",
             vcs_zcode_attention_bid_serialize(
                 &bid_alias.object, bid_alias.wire) ==
                 VCS_ZCODE_ATTENTION_ALIAS);
    (void)vcs_zcode_attention_bid_serialize(&bid, bid_alias.wire);
    AB_CHECK("bid-parse-alias-refusal",
             vcs_zcode_attention_bid_parse(
                 bid_alias.wire, sizeof(bid_alias.wire),
                 &bid_alias.object) == VCS_ZCODE_ATTENTION_ALIAS);
    AB_CHECK("bid-short-and-trailing-refusal",
             vcs_zcode_attention_bid_parse(
                 bid_wire, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES - 1,
                 &parsed_bid) == VCS_ZCODE_ATTENTION_WIRE_SIZE &&
             vcs_zcode_attention_bid_parse(
                 bid_wire, VCS_ZCODE_ATTENTION_BID_WIRE_BYTES + 1,
                 &parsed_bid) == VCS_ZCODE_ATTENTION_WIRE_SIZE);

    char store_workspace[512];
    test_make_tmpdir(store_workspace, sizeof(store_workspace),
                     "zcode_attention", "store_pair");
    uint8_t stored_heuristic_root[32], stored_bid_root[32];
    ab_valid_heuristic(&heuristic, 7);
    ab_valid_bid(&bid, &heuristic);
    bool stored_once = vcs_zcode_attention_store_pair(
        store_workspace, &heuristic, &bid,
        stored_heuristic_root, stored_bid_root) == VCS_ZCODE_ATTENTION_OK;
    uint8_t first_heuristic_root[32], first_bid_root[32];
    memcpy(first_heuristic_root, stored_heuristic_root, 32);
    memcpy(first_bid_root, stored_bid_root, 32);
    uint8_t *stored_heuristic_wire = NULL, *stored_bid_wire = NULL;
    size_t stored_heuristic_len = 0, stored_bid_len = 0;
    bool stored_exact = stored_once &&
        vcs_object_load_raw_bounded(
            store_workspace, stored_heuristic_root,
            VCS_ZCODE_HEURISTIC_WIRE_BYTES, &stored_heuristic_wire,
            &stored_heuristic_len) == 0 &&
        vcs_object_load_raw_bounded(
            store_workspace, stored_bid_root,
            VCS_ZCODE_ATTENTION_BID_WIRE_BYTES, &stored_bid_wire,
            &stored_bid_len) == 0 &&
        stored_heuristic_len == VCS_ZCODE_HEURISTIC_WIRE_BYTES &&
        stored_bid_len == VCS_ZCODE_ATTENTION_BID_WIRE_BYTES;
    AB_CHECK("store-pair-canonical-cas-readback", stored_exact);
    free(stored_bid_wire);
    free(stored_heuristic_wire);

    memset(stored_heuristic_root, 0xa5, sizeof(stored_heuristic_root));
    memset(stored_bid_root, 0xa5, sizeof(stored_bid_root));
    AB_CHECK("store-pair-idempotent",
             vcs_zcode_attention_store_pair(
                 store_workspace, &heuristic, &bid,
                 stored_heuristic_root, stored_bid_root) ==
                     VCS_ZCODE_ATTENTION_OK &&
             memcmp(stored_heuristic_root, first_heuristic_root, 32) == 0 &&
             memcmp(stored_bid_root, first_bid_root, 32) == 0);

    ab_derived_heuristic(&derived, &heuristic, 50);
    ab_valid_bid(&bid, &derived);
    memset(stored_heuristic_root, 0xa5, sizeof(stored_heuristic_root));
    memset(stored_bid_root, 0xa5, sizeof(stored_bid_root));
    AB_CHECK("store-pair-derived-resolves-cas-parent",
             vcs_zcode_attention_store_pair(
                 store_workspace, &derived, &bid,
                 stored_heuristic_root, stored_bid_root) ==
                     VCS_ZCODE_ATTENTION_OK &&
             !ab_all_zero(stored_heuristic_root,
                          sizeof(stored_heuristic_root)) &&
             !ab_all_zero(stored_bid_root, sizeof(stored_bid_root)));

    char missing_parent_workspace[512];
    test_make_tmpdir(missing_parent_workspace,
                     sizeof(missing_parent_workspace),
                     "zcode_attention", "missing_parent");
    memset(stored_heuristic_root, 0xa5, sizeof(stored_heuristic_root));
    memset(stored_bid_root, 0xa5, sizeof(stored_bid_root));
    AB_CHECK("store-pair-derived-missing-parent-refusal",
             vcs_zcode_attention_store_pair(
                 missing_parent_workspace, &derived, &bid,
                 stored_heuristic_root, stored_bid_root) ==
                     VCS_ZCODE_ATTENTION_CAS &&
             ab_all_zero(stored_heuristic_root,
                         sizeof(stored_heuristic_root)) &&
             ab_all_zero(stored_bid_root, sizeof(stored_bid_root)));
    (void)test_rm_rf_recursive(missing_parent_workspace);

    struct vcs_zcode_heuristic_v1 changed_evaluator = derived;
    changed_evaluator.evaluator_roots[1][0]++;
    ab_valid_bid(&bid, &changed_evaluator);
    memset(stored_heuristic_root, 0xa5, sizeof(stored_heuristic_root));
    memset(stored_bid_root, 0xa5, sizeof(stored_bid_root));
    AB_CHECK("store-pair-derived-evaluator-change-refusal",
             vcs_zcode_attention_store_pair(
                 store_workspace, &changed_evaluator, &bid,
                 stored_heuristic_root, stored_bid_root) ==
                     VCS_ZCODE_ATTENTION_BINDING &&
             ab_all_zero(stored_heuristic_root,
                         sizeof(stored_heuristic_root)) &&
             ab_all_zero(stored_bid_root, sizeof(stored_bid_root)));

    ab_valid_bid(&bid, &heuristic);
    struct vcs_zcode_attention_bid_v1 mismatched_store_bid = bid;
    mismatched_store_bid.source_root[0]++;
    memset(stored_heuristic_root, 0xa5, sizeof(stored_heuristic_root));
    memset(stored_bid_root, 0xa5, sizeof(stored_bid_root));
    AB_CHECK("store-pair-binding-failure-zeroes-roots",
             vcs_zcode_attention_store_pair(
                 store_workspace, &heuristic, &mismatched_store_bid,
                 stored_heuristic_root, stored_bid_root) ==
                     VCS_ZCODE_ATTENTION_BINDING &&
             ab_all_zero(stored_heuristic_root,
                         sizeof(stored_heuristic_root)) &&
             ab_all_zero(stored_bid_root, sizeof(stored_bid_root)));
    uint8_t heuristic_before_alias[32];
    memcpy(heuristic_before_alias, heuristic.task_root, 32);
    AB_CHECK("store-pair-output-alias-refusal-is-nondestructive",
             vcs_zcode_attention_store_pair(
                 store_workspace, &heuristic, &bid, heuristic.task_root,
                 stored_bid_root) == VCS_ZCODE_ATTENTION_ALIAS &&
             memcmp(heuristic.task_root, heuristic_before_alias, 32) == 0);
    AB_CHECK("store-pair-null-output-cannot-mask-input-alias",
             vcs_zcode_attention_store_pair(
                 store_workspace, &heuristic, &bid, heuristic.task_root,
                 NULL) == VCS_ZCODE_ATTENTION_ALIAS &&
             memcmp(heuristic.task_root, heuristic_before_alias, 32) == 0);
    AB_CHECK("store-pair-null-workspace-cannot-mask-input-alias",
             vcs_zcode_attention_store_pair(
                 NULL, &heuristic, &bid, heuristic.task_root,
                 stored_bid_root) == VCS_ZCODE_ATTENTION_ALIAS &&
             memcmp(heuristic.task_root, heuristic_before_alias, 32) == 0);
    (void)test_rm_rf_recursive(store_workspace);

    char corrupt_workspace[512];
    test_make_tmpdir(corrupt_workspace, sizeof(corrupt_workspace),
                     "zcode_attention", "corrupt_pair");
    uint8_t corrupt_wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
    (void)vcs_zcode_heuristic_serialize(&heuristic, corrupt_wire);
    corrupt_wire[16] ^= 1u;
    (void)vcs_zcode_heuristic_root(&heuristic, first_heuristic_root);
    bool corrupt_filed = vcs_object_store_init(corrupt_workspace) &&
        vcs_object_put_addressed(
            corrupt_workspace, first_heuristic_root, corrupt_wire,
            sizeof(corrupt_wire));
    memset(stored_heuristic_root, 0xa5, sizeof(stored_heuristic_root));
    memset(stored_bid_root, 0xa5, sizeof(stored_bid_root));
    AB_CHECK("store-pair-corrupt-preexisting-refusal",
             corrupt_filed && vcs_zcode_attention_store_pair(
                 corrupt_workspace, &heuristic, &bid,
                 stored_heuristic_root, stored_bid_root) ==
                     VCS_ZCODE_ATTENTION_CAS &&
             ab_all_zero(stored_heuristic_root,
                         sizeof(stored_heuristic_root)) &&
             ab_all_zero(stored_bid_root, sizeof(stored_bid_root)));
    (void)test_rm_rf_recursive(corrupt_workspace);

    struct vcs_zcode_heuristic_v1 heuristics[6];
    struct vcs_zcode_attention_bid_v1 bids[6];
    for (size_t i = 0; i < 6; i++) {
        ab_valid_heuristic(&heuristics[i], (uint8_t)(40 + i));
        ab_valid_bid(&bids[i], &heuristics[i]);
    }

    bids[1].expected_user_value_bp--;
    bids[1].information_gain_bp--;
    bids[1].blocker_relief_bp--;
    bids[1].reuse_potential_bp--;
    bids[1].evidence_strength_bp--;
    bids[1].risk_bp++;
    bids[1].overlap_bp++;
    bids[1].expected_latency_us++;
    bids[1].expected_cost_milliunits++;
    bids[2].expected_user_value_bp--;
    bids[2].information_gain_bp++;
    bids[4].priority_class = VCS_ZCODE_ATTENTION_P0_SECURITY;
    bids[4].expected_user_value_bp = 10000;
    bids[4].information_gain_bp = 10000;
    bids[5].expected_user_value_bp--;
    bids[5].information_gain_bp--;
    bids[5].blocker_relief_bp--;
    bids[5].reuse_potential_bp--;
    bids[5].evidence_strength_bp--;
    bids[5].risk_bp++;
    bids[5].overlap_bp++;
    bids[5].expected_latency_us++;
    bids[5].expected_cost_milliunits++;

    struct vcs_zcode_attention_frontier_query query;
    struct vcs_zcode_attention_frontier_report report;
    size_t selected[6] = {0};
    ab_query(&query, VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY);
    AB_CHECK("pareto-frontier-preserves-tradeoffs-and-equals",
             vcs_zcode_attention_frontier_project(
                 bids, 6, heuristics, &query, selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             report.input_count == 6 && report.class_candidate_count == 5 &&
             report.frontier_count == 3 && report.returned_count == 3);
    bool has_zero = false, has_two = false, has_three = false;
    for (size_t i = 0; i < report.returned_count; i++) {
        has_zero = has_zero || selected[i] == 0;
        has_two = has_two || selected[i] == 2;
        has_three = has_three || selected[i] == 3;
    }
    AB_CHECK("dominated-bids-excluded",
             has_zero && has_two && has_three);

    size_t untouched = 777;
    AB_CHECK("frontier-capacity-is-atomic",
             vcs_zcode_attention_frontier_project(
                 bids, 6, heuristics, &query, &untouched, 1, &report) ==
                 VCS_ZCODE_ATTENTION_CAPACITY &&
             report.frontier_count == 3 && report.returned_count == 0 &&
             untouched == 777);
    ab_query(&query, VCS_ZCODE_ATTENTION_P0_SECURITY);
    AB_CHECK("priority-classes-are-isolated",
             vcs_zcode_attention_frontier_project(
                 bids, 6, heuristics, &query, selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             report.class_candidate_count == 1 &&
             report.frontier_count == 1 &&
             selected[0] == 4);

    ab_query(&query, VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY);
    bool baseline_again = vcs_zcode_attention_frontier_project(
        bids, 6, heuristics, &query, selected, 6, &report) ==
        VCS_ZCODE_ATTENTION_OK;
    struct vcs_zcode_attention_bid_v1 permuted[6] = {
        bids[5], bids[3], bids[1], bids[4], bids[2], bids[0]
    };
    struct vcs_zcode_heuristic_v1 permuted_heuristics[6] = {
        heuristics[5], heuristics[3], heuristics[1], heuristics[4],
        heuristics[2], heuristics[0]
    };
    size_t permuted_selected[6] = {0};
    AB_CHECK("frontier-input-permutation",
             baseline_again && vcs_zcode_attention_frontier_project(
                 permuted, 6, permuted_heuristics, &query,
                 permuted_selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             report.frontier_count == 3 &&
             ab_roots_equal(&bids[selected[0]],
                            &permuted[permuted_selected[0]]) &&
             ab_roots_equal(&bids[selected[1]],
                            &permuted[permuted_selected[1]]) &&
             ab_roots_equal(&bids[selected[2]],
                            &permuted[permuted_selected[2]]));
    struct vcs_zcode_attention_bid_v1 duplicate[2] = {bids[0], bids[0]};
    struct vcs_zcode_heuristic_v1 duplicate_heuristics[2] = {
        heuristics[0], heuristics[0]
    };
    AB_CHECK("duplicate-bid-refusal",
             vcs_zcode_attention_frontier_project(
                 duplicate, 2, duplicate_heuristics, &query,
                 selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_DUPLICATE);
    duplicate[1] = bids[2];
    duplicate_heuristics[1] = heuristics[2];
    duplicate[1].source_root[0]++;
    AB_CHECK("exact-source-binding-refusal",
             vcs_zcode_attention_frontier_project(
                 duplicate, 2, duplicate_heuristics, &query,
                 selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_BINDING);

    duplicate[0] = bids[0];
    duplicate[1] = bids[0];
    duplicate_heuristics[1] = heuristics[0];
    duplicate[1].expected_user_value_bp--;
    AB_CHECK("conflicting-metrics-for-same-evidence-refusal",
             vcs_zcode_attention_frontier_project(
                 duplicate, 2, duplicate_heuristics, &query,
                 selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_DUPLICATE);

    duplicate[0] = bids[0];
    duplicate[1] = bids[0];
    duplicate_heuristics[1] = heuristics[0];
    duplicate[1].evidence_root[0] ^= 1u;
    duplicate[1].expected_user_value_bp++;
    duplicate[1].information_gain_bp--;
    AB_CHECK("multiple-evidence-generations-for-one-candidate-refuse",
             vcs_zcode_attention_frontier_project(
                 duplicate, 2, duplicate_heuristics, &query,
                 selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_DUPLICATE);

    struct vcs_zcode_attention_frontier_report empty_report = {0};
    AB_CHECK("empty-frontier",
             vcs_zcode_attention_frontier_project(
                 NULL, 0, NULL, &query, NULL, 0, &empty_report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             empty_report.input_count == 0 &&
             empty_report.frontier_count == 0);
    AB_CHECK("frontier-count-bound",
             vcs_zcode_attention_frontier_project(
                 bids, VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS + 1u,
                 heuristics, &query, selected, 6, &report) ==
                 VCS_ZCODE_ATTENTION_COUNT);

    struct vcs_zcode_heuristic_v1 axis_heuristics[2];
    struct vcs_zcode_attention_bid_v1 axis_bids[2];
    size_t axis_selected[2];
    bool all_axis_directions = true;
    for (size_t axis = 0; axis < 9; axis++) {
        ab_valid_heuristic(&axis_heuristics[0], 100);
        ab_valid_heuristic(&axis_heuristics[1], 101);
        ab_valid_bid(&axis_bids[0], &axis_heuristics[0]);
        ab_valid_bid(&axis_bids[1], &axis_heuristics[1]);
        ab_improve_axis(&axis_bids[1], axis);
        if (vcs_zcode_attention_frontier_project(
                axis_bids, 2, axis_heuristics, &query,
                axis_selected, 2, &report) != VCS_ZCODE_ATTENTION_OK ||
            report.frontier_count != 1 || axis_selected[0] != 1)
            all_axis_directions = false;
    }
    AB_CHECK("all-nine-pareto-axis-directions", all_axis_directions);

    struct vcs_zcode_heuristic_v1 auto_heuristics[4];
    struct vcs_zcode_attention_bid_v1 auto_bids[4];
    for (size_t i = 0; i < 4; i++) {
        ab_valid_heuristic(&auto_heuristics[i], (uint8_t)(110 + i));
        ab_valid_bid(&auto_bids[i], &auto_heuristics[i]);
        auto_bids[i].priority_class =
            (uint8_t)(VCS_ZCODE_ATTENTION_P0_SECURITY + i);
    }
    /* A lower-priority bid may look better on every metric and still cannot
     * displace P0. Hard class ordering runs before optimization. */
    auto_bids[0].expected_user_value_bp = 0;
    auto_bids[0].information_gain_bp = 0;
    auto_bids[0].blocker_relief_bp = 0;
    auto_bids[0].reuse_potential_bp = 0;
    auto_bids[0].evidence_strength_bp = 0;
    auto_bids[0].risk_bp = VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[0].overlap_bp = VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[0].expected_latency_us = UINT64_MAX;
    auto_bids[0].expected_cost_milliunits = UINT64_MAX;
    auto_bids[3].expected_user_value_bp =
        VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[3].information_gain_bp =
        VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[3].blocker_relief_bp =
        VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[3].reuse_potential_bp =
        VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[3].evidence_strength_bp =
        VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX;
    auto_bids[3].risk_bp = 0;
    auto_bids[3].overlap_bp = 0;
    auto_bids[3].expected_latency_us = 0;
    auto_bids[3].expected_cost_milliunits = 0;

    struct vcs_zcode_attention_frontier_query auto_query;
    ab_query(&auto_query, VCS_ZCODE_ATTENTION_PRIORITY_AUTO);
    size_t auto_selected[4] = {0};
    struct vcs_zcode_attention_choice_report choice_report;
    AB_CHECK("automatic-choice-enforces-hard-priority",
             vcs_zcode_attention_frontier_choose(
                 auto_bids, 4, auto_heuristics, &auto_query,
                 auto_selected, 4, &choice_report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             choice_report.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P0_SECURITY &&
             choice_report.frontier.class_candidate_count == 1 &&
             choice_report.frontier.frontier_count == 1 &&
             auto_selected[0] == 0);

    auto_bids[0].priority_class = VCS_ZCODE_ATTENTION_P3_RESEARCH;
    AB_CHECK("removing-last-p0-reveals-p1",
             vcs_zcode_attention_frontier_choose(
                 auto_bids, 4, auto_heuristics, &auto_query,
                 auto_selected, 4, &choice_report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             choice_report.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P1_USER_JOURNEY &&
             choice_report.frontier.class_candidate_count == 1 &&
             auto_selected[0] == 1);
    uint8_t selected_before_lower[32], selected_after_lower[32];
    (void)vcs_zcode_attention_bid_root(
        &auto_bids[auto_selected[0]], selected_before_lower);
    auto_bids[3].expected_user_value_bp--;
    bool lower_unchanged = vcs_zcode_attention_frontier_choose(
        auto_bids, 4, auto_heuristics, &auto_query,
        auto_selected, 4, &choice_report) == VCS_ZCODE_ATTENTION_OK;
    if (lower_unchanged)
        (void)vcs_zcode_attention_bid_root(
            &auto_bids[auto_selected[0]], selected_after_lower);
    AB_CHECK("lower-class-change-cannot-move-frontier",
             lower_unchanged && memcmp(selected_before_lower,
                                        selected_after_lower, 32) == 0);
    struct vcs_zcode_attention_bid_v1 auto_permuted[4] = {
        auto_bids[3], auto_bids[2], auto_bids[1], auto_bids[0]
    };
    struct vcs_zcode_heuristic_v1 auto_permuted_heuristics[4] = {
        auto_heuristics[3], auto_heuristics[2], auto_heuristics[1],
        auto_heuristics[0]
    };
    bool auto_permutation = vcs_zcode_attention_frontier_choose(
        auto_permuted, 4, auto_permuted_heuristics, &auto_query,
        auto_selected, 4, &choice_report) == VCS_ZCODE_ATTENTION_OK;
    if (auto_permutation)
        (void)vcs_zcode_attention_bid_root(
            &auto_permuted[auto_selected[0]], selected_after_lower);
    AB_CHECK("automatic-choice-input-permutation",
             auto_permutation && choice_report.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P1_USER_JOURNEY &&
             memcmp(selected_before_lower, selected_after_lower, 32) == 0);

    size_t auto_untouched = 777;
    AB_CHECK("automatic-choice-capacity-is-atomic",
             vcs_zcode_attention_frontier_choose(
                 auto_bids, 4, auto_heuristics, &auto_query,
                 &auto_untouched, 0, &choice_report) ==
                 VCS_ZCODE_ATTENTION_CAPACITY &&
             choice_report.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P1_USER_JOURNEY &&
             choice_report.frontier.returned_count == 0 &&
             auto_untouched == 777);
    auto_query.priority_class = VCS_ZCODE_ATTENTION_P1_USER_JOURNEY;
    AB_CHECK("automatic-choice-refuses-caller-selected-class",
             vcs_zcode_attention_frontier_choose(
                 auto_bids, 4, auto_heuristics, &auto_query,
                 auto_selected, 4, &choice_report) ==
                 VCS_ZCODE_ATTENTION_PRIORITY);
    auto_query.priority_class = VCS_ZCODE_ATTENTION_PRIORITY_AUTO;
    union {
        struct vcs_zcode_attention_frontier_query query;
        struct vcs_zcode_attention_choice_report report;
    } auto_alias;
    auto_alias.query = auto_query;
    AB_CHECK("automatic-choice-query-output-alias-refusal",
             vcs_zcode_attention_frontier_choose(
                 auto_bids, 4, auto_heuristics, &auto_alias.query,
                 auto_selected, 4, &auto_alias.report) ==
                 VCS_ZCODE_ATTENTION_ALIAS);
    struct vcs_zcode_attention_choice_report auto_empty = {0};
    AB_CHECK("automatic-empty-choice-has-no-selected-class",
             vcs_zcode_attention_frontier_choose(
                 NULL, 0, NULL, &auto_query, NULL, 0, &auto_empty) ==
                 VCS_ZCODE_ATTENTION_OK &&
             auto_empty.frontier.input_count == 0 &&
             auto_empty.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_PRIORITY_AUTO);

    return failures;
}
