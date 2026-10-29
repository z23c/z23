/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: mixed seed/derived attention selection and evidence tests. */
#include "vcs/zcode_attention_verified.h"

#include "crypto/ed25519.h"
#include "test/test_core.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define AL_CHECK(name_, expression_) do {                                \
    if (expression_) {                                                   \
        printf("  zcode_attention_lineage: %s... OK\n", (name_));    \
    } else {                                                             \
        printf("  zcode_attention_lineage: %s... FAIL\n", (name_));  \
        failures++;                                                      \
    }                                                                    \
} while (0)

static void al_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static void al_seed(struct vcs_zcode_heuristic_v1 *heuristic, uint8_t tag)
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 1;
    al_root(heuristic->task_root, 1);
    al_root(heuristic->source_root, 2);
    al_root(heuristic->agent_context_root, 3);
    al_root(heuristic->ontology_context_root, 4);
    al_root(heuristic->applicability_root, 5);
    al_root(heuristic->observed_features_root, 6);
    al_root(heuristic->proposed_rule_root, tag);
    al_root(heuristic->expected_effect_root, 8);
    al_root(heuristic->proposal_input_root, 9);
    al_root(heuristic->study_root, 10);
    al_root(heuristic->preregistration_root, 11);
    al_root(heuristic->provenance_root, 12);
    al_root(heuristic->evaluator_roots[0], 5);
    heuristic->requested_cpu_seconds = 60;
    heuristic->requested_processes = 2;
    heuristic->requested_memory_bytes = 16u * 1024u * 1024u;
    heuristic->requested_context_bytes = 64u * 1024u;
    heuristic->requested_output_bytes = 1024u * 1024u;
}

static void al_specialize(
    struct vcs_zcode_heuristic_v1 *child,
    const struct vcs_zcode_heuristic_v1 *parent, uint8_t tag)
{
    *child = *parent;
    child->derivation = VCS_ZCODE_HEURISTIC_SPECIALIZE;
    child->parent_count = 1;
    al_root(child->proposed_rule_root, tag);
    al_root(child->proposal_input_root, (uint8_t)(tag + 1u));
    al_root(child->provenance_root, (uint8_t)(tag + 2u));
    (void)vcs_zcode_heuristic_root(parent, child->parent_roots[0]);
}

static void al_order_two(struct vcs_zcode_heuristic_v1 parents[2])
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

static void al_compose(
    struct vcs_zcode_heuristic_v1 *child,
    const struct vcs_zcode_heuristic_v1 parents[2], uint8_t tag)
{
    *child = parents[0];
    child->derivation = VCS_ZCODE_HEURISTIC_COMPOSE;
    child->parent_count = 2;
    al_root(child->proposed_rule_root, tag);
    al_root(child->proposal_input_root, (uint8_t)(tag + 1u));
    al_root(child->provenance_root, (uint8_t)(tag + 2u));
    (void)vcs_zcode_heuristic_root(&parents[0], child->parent_roots[0]);
    (void)vcs_zcode_heuristic_root(&parents[1], child->parent_roots[1]);
}

static void al_focus(struct vcs_zcode_focus_v1 *focus)
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
    al_root(focus->task_root, 1);
    al_root(focus->goal_root, 20);
    al_root(focus->source_universe_root, 2);
    al_root(focus->context_root, 3);
    al_root(focus->story_graph_root, 4);
    (void)vcs_zcode_focus_claim_set_root(NULL, 0, focus->claim_set_root);
    al_root(focus->required_evidence_root, 21);
    al_root(focus->authority_limits_root, 22);
}

static void al_bid(
    struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus, uint8_t evidence_tag)
{
    vcs_zcode_attention_bid_init(bid);
    bid->priority_class = VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY;
    (void)vcs_zcode_focus_root(focus, bid->focus_root);
    memcpy(bid->task_root, focus->task_root, 32);
    memcpy(bid->source_root, focus->source_universe_root, 32);
    (void)vcs_zcode_heuristic_root(heuristic, bid->heuristic_root);
    al_root(bid->priority_policy_root, 4);
    al_root(bid->bid_evaluator_root, 5);
    al_root(bid->evidence_root, evidence_tag);
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

static void al_query(struct vcs_zcode_attention_frontier_query *query,
                     const struct vcs_zcode_focus_v1 *focus,
                     uint8_t priority)
{
    memset(query, 0, sizeof(*query));
    (void)vcs_zcode_focus_root(focus, query->focus_root);
    memcpy(query->task_root, focus->task_root, 32);
    memcpy(query->source_root, focus->source_universe_root, 32);
    al_root(query->priority_policy_root, 4);
    al_root(query->bid_evaluator_root, 5);
    query->priority_class = priority;
}

static bool al_statement(
    struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    const struct vcs_zcode_science_relation_set_v1 empty_relations = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    memset(statement, 0, sizeof(*statement));
    statement->schema_version = VCS_ZCODE_SCIENCE_STATEMENT_VERSION;
    statement->profile = VCS_ZCODE_SCIENCE_PROFILE_RESULT;
    statement->access = VCS_ZCODE_SCIENCE_ACCESS_PUBLIC;
    statement->privacy = VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC;
    statement->redistribution = VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED;
    statement->authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_ASSERTED;
    if (vcs_zcode_heuristic_root(heuristic, statement->subject_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_attention_bid_root(bid, statement->predicate_body_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_focus_root(focus, statement->input_root) !=
            VCS_ZCODE_FOCUS_OK)
        return false;
    memcpy(statement->provenance_root, bid->evidence_root, 32);
    memcpy(statement->activity_root, bid->bid_evaluator_root, 32);
    al_root(statement->profile_schema_root, 30);
    al_root(statement->authorship_assertion_root, 31);
    al_root(statement->license_root, 32);
    al_root(statement->access_policy_root, 33);
    al_root(statement->privacy_policy_root, 34);
    al_root(statement->external_identifiers_root, 35);
    al_root(statement->citations_root, 36);
    if (vcs_zcode_science_relation_set_root(
            &empty_relations, statement->relations_root) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    statement->observed_unix = 1;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
           VCS_ZCODE_SCIENCE_OK;
}

static bool al_selected_roots(
    const struct vcs_zcode_attention_bid_v1 *bids, const size_t *selected,
    size_t count, uint8_t roots[3][32])
{
    if (count > 3) return false;
    for (size_t i = 0; i < count; i++) {
        if (vcs_zcode_attention_bid_root(
                &bids[selected[i]], roots[i]) != VCS_ZCODE_ATTENTION_OK)
            return false;
    }
    return true;
}

struct al_fixture {
    struct vcs_zcode_focus_v1 focus;
    struct vcs_zcode_heuristic_v1 heuristics[3], parents[3];
    struct vcs_zcode_heuristic_v1 wrong_parents[3];
    struct vcs_zcode_attention_bid_v1 bids[3];
    struct vcs_zcode_attention_bid_v1 priority_bids[3];
    struct vcs_zcode_attention_frontier_query query;
    struct vcs_zcode_attention_frontier_query auto_query;
    struct vcs_zcode_attention_frontier_report report;
    struct vcs_zcode_attention_verified_report verified_report;
    size_t selected[3];
    uint8_t baseline_roots[3][32];
    bool mixed_ok;
    uint8_t secret[32], pubkey[32];
    struct vcs_zcode_science_statement_v1 statements[3];
    bool statements_ok;
};

static void al_setup(struct al_fixture *fx)
{
    struct vcs_zcode_heuristic_v1 compose_parents[2];
    memset(fx, 0, sizeof(*fx));
    al_focus(&fx->focus);
    al_seed(&fx->heuristics[0], 40);
    al_seed(&fx->parents[0], 41);
    al_specialize(&fx->heuristics[1], &fx->parents[0], 42);
    al_seed(&compose_parents[0], 43);
    al_seed(&compose_parents[1], 44);
    al_order_two(compose_parents);
    fx->parents[1] = compose_parents[0];
    fx->parents[2] = compose_parents[1];
    al_compose(&fx->heuristics[2], compose_parents, 45);
    for (size_t i = 0; i < 3; i++)
        al_bid(&fx->bids[i], &fx->heuristics[i], &fx->focus,
               (uint8_t)(50u + i));
    al_query(&fx->query, &fx->focus, VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY);
    for (size_t i = 0; i < 3; i++)
        fx->selected[i] = SIZE_MAX;
    al_query(&fx->auto_query, &fx->focus, VCS_ZCODE_ATTENTION_PRIORITY_AUTO);
    memcpy(fx->priority_bids, fx->bids, sizeof(fx->bids));
    fx->priority_bids[1].priority_class = VCS_ZCODE_ATTENTION_P1_USER_JOURNEY;
    memcpy(fx->wrong_parents, fx->parents, sizeof(fx->parents));
    fx->wrong_parents[2].proposed_rule_root[0] ^= 1u;
}

static int al_check_layouts(struct al_fixture *fx)
{
    int failures = 0;
    AL_CHECK("packed-layout-0-1-2",
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 3, &fx->query,
                 fx->selected, 3, &fx->report) == VCS_ZCODE_ATTENTION_OK);
    AL_CHECK("empty-and-all-seed-layouts",
             vcs_zcode_attention_frontier_project_with_lineage(
                 NULL, 0, NULL, NULL, 0, &fx->query,
                 fx->selected, 3, &fx->report) == VCS_ZCODE_ATTENTION_OK &&
             vcs_zcode_attention_frontier_project_with_lineage(
                 &fx->bids[0], 1, &fx->heuristics[0], NULL, 0, &fx->query,
                 fx->selected, 3, &fx->report) ==
                 VCS_ZCODE_ATTENTION_OK);
    return failures;
}

static int al_check_derived_focus(struct al_fixture *fx)
{
    int failures = 0;
    AL_CHECK("derived-focus-positive",
             vcs_zcode_attention_bid_validate_for_focus_with_lineage(
                 &fx->bids[1], &fx->heuristics[1], &fx->parents[0], 1,
                 &fx->focus) == VCS_ZCODE_ATTENTION_OK &&
             vcs_zcode_attention_bid_validate_for_focus_with_lineage(
                 &fx->bids[2], &fx->heuristics[2], &fx->parents[1], 2,
                 &fx->focus) == VCS_ZCODE_ATTENTION_OK);
    AL_CHECK("legacy-focus-remains-seed-only",
             vcs_zcode_attention_bid_validate_for_focus(
                 &fx->bids[1], &fx->heuristics[1], &fx->focus) ==
                 VCS_ZCODE_ATTENTION_DERIVATION);
    return failures;
}

static int al_check_refusals(struct al_fixture *fx)
{
    int failures = 0;
    struct vcs_zcode_heuristic_v1 swapped_parents[3] = {
        fx->parents[0], fx->parents[2], fx->parents[1]
    };
    AL_CHECK("packed-layout-short-long-null-refusal",
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 2, &fx->query,
                 fx->selected, 3, &fx->report) ==
                 VCS_ZCODE_ATTENTION_COUNT &&
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 4, &fx->query,
                 fx->selected, 3, &fx->report) ==
                 VCS_ZCODE_ATTENTION_COUNT &&
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, NULL, 3, &fx->query,
                 fx->selected, 3, &fx->report) ==
                 VCS_ZCODE_ATTENTION_NULL &&
             vcs_zcode_attention_frontier_project_with_lineage(
                 &fx->bids[0], 1, &fx->heuristics[0], fx->parents, 0,
                 &fx->query, fx->selected, 3, &fx->report) ==
                 VCS_ZCODE_ATTENTION_COUNT &&
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, SIZE_MAX,
                 &fx->query, fx->selected, 3, &fx->report) ==
                 VCS_ZCODE_ATTENTION_COUNT);
    AL_CHECK("swapped-compose-parent-order-refusal",
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, swapped_parents, 3, &fx->query,
                 fx->selected, 3, &fx->report) == VCS_ZCODE_ATTENTION_BINDING);
    return failures;
}

static int al_check_lineage_scope(struct al_fixture *fx)
{
    int failures = 0;
    struct vcs_zcode_heuristic_v1 unresolved_parent = fx->parents[0];
    unresolved_parent.derivation = VCS_ZCODE_HEURISTIC_REPAIR;
    unresolved_parent.parent_count = 1;
    al_root(unresolved_parent.parent_roots[0], 90);
    al_root(unresolved_parent.proposed_rule_root, 91);
    struct vcs_zcode_heuristic_v1 grandchild;
    struct vcs_zcode_attention_bid_v1 grandchild_bid;
    al_specialize(&grandchild, &unresolved_parent, 92);
    al_bid(&grandchild_bid, &grandchild, &fx->focus, 93);
    AL_CHECK("lineage-scope-is-exactly-one-hop",
             vcs_zcode_attention_bid_validate_for_focus_with_lineage(
                 &grandchild_bid, &grandchild, &unresolved_parent, 1,
                 &fx->focus) == VCS_ZCODE_ATTENTION_OK);
    return failures;
}

static int al_check_mixed_frontier(struct al_fixture *fx)
{
    int failures = 0;
    fx->mixed_ok = vcs_zcode_attention_frontier_project_with_lineage(
        fx->bids, 3, fx->heuristics, fx->parents, 3, &fx->query,
        fx->selected, 3, &fx->report) == VCS_ZCODE_ATTENTION_OK;
    AL_CHECK("mixed-seed-derived-frontier",
             fx->mixed_ok && fx->report.input_count == 3 &&
             fx->report.class_candidate_count == 3 &&
             fx->report.frontier_count == 3 && fx->report.returned_count == 3 &&
             al_selected_roots(fx->bids, fx->selected, 3, fx->baseline_roots));
    return failures;
}

static int al_check_hard_priority(struct al_fixture *fx)
{
    int failures = 0;
    struct vcs_zcode_attention_choice_report choice;
    AL_CHECK("derived-hard-priority-before-pareto",
             vcs_zcode_attention_frontier_choose_with_lineage(
                 fx->priority_bids, 3, fx->heuristics, fx->parents, 3,
                 &fx->auto_query, fx->selected, 3, &choice) ==
                 VCS_ZCODE_ATTENTION_OK &&
             choice.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P1_USER_JOURNEY &&
             choice.frontier.frontier_count == 1 && fx->selected[0] == 1);
    return failures;
}

static int al_check_wrong_batch(struct al_fixture *fx)
{
    int failures = 0;
    struct vcs_zcode_attention_choice_report untouched_choice;
    memset(&untouched_choice, 0xa5, sizeof(untouched_choice));
    struct vcs_zcode_attention_choice_report choice_before =
        untouched_choice;
    size_t untouched_index = 777;
    AL_CHECK("invalid-lower-row-fails-whole-batch",
             vcs_zcode_attention_frontier_choose_with_lineage(
                 fx->priority_bids, 3, fx->heuristics, fx->wrong_parents, 3,
                 &fx->auto_query, &untouched_index, 1,
                 &untouched_choice) == VCS_ZCODE_ATTENTION_BINDING &&
             untouched_index == 777 &&
             memcmp(&untouched_choice, &choice_before,
                    sizeof(untouched_choice)) == 0);
    return failures;
}

static int al_check_capacity_alias(struct al_fixture *fx)
{
    int failures = 0;
    size_t capacity_indices[2] = {777, 888};
    AL_CHECK("mixed-capacity-is-atomic",
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 3, &fx->query,
                 capacity_indices, 2, &fx->report) ==
                 VCS_ZCODE_ATTENTION_CAPACITY &&
             fx->report.frontier_count == 3 && fx->report.returned_count == 0 &&
             capacity_indices[0] == 777 && capacity_indices[1] == 888);
    struct vcs_zcode_heuristic_v1 first_parent_before = fx->parents[0];
    AL_CHECK("packed-parent-output-alias-refusal",
             vcs_zcode_attention_frontier_project_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 3, &fx->query,
                 (size_t *)&fx->parents[0], 1, &fx->report) ==
                 VCS_ZCODE_ATTENTION_ALIAS &&
             memcmp(&fx->parents[0], &first_parent_before,
                    sizeof(first_parent_before)) == 0);
    return failures;
}

static size_t al_permuted_rows(
    const struct al_fixture *fx, const uint8_t permutation[3],
    struct vcs_zcode_heuristic_v1 perm_heuristics[3],
    struct vcs_zcode_heuristic_v1 perm_parents[3],
    struct vcs_zcode_attention_bid_v1 perm_bids[3])
{
    size_t parent_cursor = 0;
    for (size_t row = 0; row < 3; row++) {
        size_t source = permutation[row];
        perm_heuristics[row] = fx->heuristics[source];
        perm_bids[row] = fx->bids[source];
        if (source == 1) {
            perm_parents[parent_cursor++] = fx->parents[0];
        } else if (source == 2) {
            perm_parents[parent_cursor++] = fx->parents[1];
            perm_parents[parent_cursor++] = fx->parents[2];
        }
    }
    return parent_cursor;
}

static int al_check_permutations(struct al_fixture *fx)
{
    int failures = 0;
    static const uint8_t permutations[6][3] = {
        {0, 1, 2}, {0, 2, 1}, {1, 0, 2},
        {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
    };
    bool all_permutations_equal = fx->mixed_ok;
    for (size_t permutation = 0; permutation < 6; permutation++) {
        struct vcs_zcode_heuristic_v1 perm_heuristics[3], perm_parents[3];
        struct vcs_zcode_attention_bid_v1 perm_bids[3];
        size_t perm_selected[3] = {SIZE_MAX, SIZE_MAX, SIZE_MAX};
        uint8_t perm_roots[3][32] = {{0}};
        size_t parent_cursor = al_permuted_rows(
            fx, permutations[permutation], perm_heuristics, perm_parents,
            perm_bids);
        if (parent_cursor != 3 ||
            vcs_zcode_attention_frontier_project_with_lineage(
                perm_bids, 3, perm_heuristics, perm_parents, 3,
                &fx->query, perm_selected, 3, &fx->report) !=
                    VCS_ZCODE_ATTENTION_OK ||
            fx->report.returned_count != 3 ||
            !al_selected_roots(
                perm_bids, perm_selected, 3, perm_roots) ||
            memcmp(perm_roots, fx->baseline_roots, sizeof(perm_roots)) != 0)
            all_permutations_equal = false;
    }
    AL_CHECK("all-six-row-permutations-repack-lineage",
             all_permutations_equal);
    return failures;
}

static void al_sign_statements(struct al_fixture *fx)
{
    uint8_t seed[32];
    al_root(seed, 80);
    ed25519_keypair(fx->pubkey, fx->secret, seed);
    fx->statements_ok = true;
    for (size_t i = 0; i < 3; i++) {
        fx->statements_ok = fx->statements_ok && al_statement(
            &fx->statements[i], &fx->bids[i], &fx->heuristics[i], &fx->focus,
            fx->secret, fx->pubkey);
    }
}

static int al_check_signed_derived(struct al_fixture *fx)
{
    int failures = 0;
    AL_CHECK("signed-derived-statement-positive",
             fx->statements_ok &&
             vcs_zcode_attention_bid_verify_statement_with_lineage(
                 &fx->bids[1], &fx->heuristics[1], &fx->parents[0], 1,
                 &fx->focus, &fx->statements[1], fx->pubkey) ==
                 VCS_ZCODE_ATTENTION_OK);
    return failures;
}

static int al_check_verified_frontier(struct al_fixture *fx)
{
    int failures = 0;
    AL_CHECK("mixed-verified-frontier-positive",
             fx->statements_ok &&
             vcs_zcode_attention_frontier_next_verified_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 3, fx->statements,
                 &fx->focus, fx->bids[0].priority_policy_root,
                 fx->bids[0].bid_evaluator_root, fx->pubkey, fx->selected, 3,
                 &fx->verified_report) == VCS_ZCODE_ATTENTION_OK &&
             fx->verified_report.verified_count == 3 &&
             fx->verified_report.choice.frontier.frontier_count == 3);
    size_t verified_capacity_indices[2] = {777, 888};
    AL_CHECK("mixed-verified-capacity-is-atomic",
             vcs_zcode_attention_frontier_next_verified_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 3, fx->statements,
                 &fx->focus, fx->bids[0].priority_policy_root,
                 fx->bids[0].bid_evaluator_root, fx->pubkey,
                 verified_capacity_indices, 2,
                 &fx->verified_report) == VCS_ZCODE_ATTENTION_CAPACITY &&
             fx->verified_report.verified_count == 3 &&
             fx->verified_report.choice.frontier.frontier_count == 3 &&
             fx->verified_report.choice.frontier.returned_count == 0 &&
             verified_capacity_indices[0] == 777 &&
             verified_capacity_indices[1] == 888);
    return failures;
}

static int al_check_verified_alias_and_batch(struct al_fixture *fx)
{
    int failures = 0;
    struct vcs_zcode_heuristic_v1 first_parent_before = fx->parents[0];
    AL_CHECK("verified-parent-output-alias-refusal",
             vcs_zcode_attention_frontier_next_verified_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->parents, 3, fx->statements,
                 &fx->focus, fx->bids[0].priority_policy_root,
                 fx->bids[0].bid_evaluator_root, fx->pubkey,
                 (size_t *)&fx->parents[0], 1,
                 &fx->verified_report) == VCS_ZCODE_ATTENTION_ALIAS &&
             memcmp(&fx->parents[0], &first_parent_before,
                    sizeof(first_parent_before)) == 0);
    struct vcs_zcode_attention_verified_report untouched_verified;
    memset(&untouched_verified, 0xa5, sizeof(untouched_verified));
    struct vcs_zcode_attention_verified_report verified_before =
        untouched_verified;
    size_t untouched_index = 777;
    AL_CHECK("verified-wrong-parent-is-atomic",
             vcs_zcode_attention_frontier_next_verified_with_lineage(
                 fx->bids, 3, fx->heuristics, fx->wrong_parents, 3,
                 fx->statements, &fx->focus, fx->bids[0].priority_policy_root,
                 fx->bids[0].bid_evaluator_root, fx->pubkey,
                 &untouched_index, 1, &untouched_verified) ==
                     VCS_ZCODE_ATTENTION_BINDING &&
             untouched_index == 777 &&
             memcmp(&untouched_verified, &verified_before,
                    sizeof(verified_before)) == 0);
    return failures;
}

static int al_check_ranked_evidence(struct al_fixture *fx)
{
    int failures = 0;
    struct vcs_zcode_attention_bid_v1 ranked_bids[3] = {
        fx->bids[0], fx->bids[1], fx->bids[2]
    };
    ranked_bids[1].priority_class = VCS_ZCODE_ATTENTION_P1_USER_JOURNEY;
    ranked_bids[2].priority_class = VCS_ZCODE_ATTENTION_P3_RESEARCH;
    struct vcs_zcode_science_statement_v1 ranked_statements[3];
    bool ranked_statements_ok = true;
    for (size_t i = 0; i < 3; i++) {
        ranked_statements_ok = ranked_statements_ok && al_statement(
            &ranked_statements[i], &ranked_bids[i], &fx->heuristics[i],
            &fx->focus, fx->secret, fx->pubkey);
    }
    ranked_statements[2].signature[0] ^= 1u;
    struct vcs_zcode_attention_verified_report untouched_verified;
    memset(&untouched_verified, 0xa5, sizeof(untouched_verified));
    struct vcs_zcode_attention_verified_report verified_before =
        untouched_verified;
    size_t untouched_index = 777;
    AL_CHECK("invalid-lower-priority-evidence-fails-whole-batch",
             ranked_statements_ok &&
             vcs_zcode_attention_frontier_next_verified_with_lineage(
                 ranked_bids, 3, fx->heuristics, fx->parents, 3,
                 ranked_statements, &fx->focus,
                 fx->bids[0].priority_policy_root,
                 fx->bids[0].bid_evaluator_root, fx->pubkey,
                 &untouched_index, 1, &untouched_verified) ==
                     VCS_ZCODE_ATTENTION_EVIDENCE &&
             untouched_index == 777 &&
             memcmp(&untouched_verified, &verified_before,
                    sizeof(verified_before)) == 0);
    return failures;
}

int test_zcode_attention_lineage(void)
{
    int failures = 0;
    struct al_fixture fx;
    al_setup(&fx);
    failures += al_check_layouts(&fx);
    failures += al_check_derived_focus(&fx);
    failures += al_check_refusals(&fx);
    failures += al_check_lineage_scope(&fx);
    failures += al_check_mixed_frontier(&fx);
    failures += al_check_hard_priority(&fx);
    failures += al_check_wrong_batch(&fx);
    failures += al_check_capacity_alias(&fx);
    failures += al_check_permutations(&fx);
    al_sign_statements(&fx);
    failures += al_check_signed_derived(&fx);
    failures += al_check_verified_frontier(&fx);
    failures += al_check_verified_alias_and_batch(&fx);
    failures += al_check_ranked_evidence(&fx);
    return failures;
}
