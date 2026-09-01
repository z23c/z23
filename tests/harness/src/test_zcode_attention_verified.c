/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove evaluator-attributed automatic attention selection. */
#include "vcs/zcode_attention_verified.h"

#include "crypto/ed25519.h"
#include "test/test_core.h"

#include <stdio.h>
#include <string.h>

#define AV_CHECK(name_, expression_) do {                                 \
    if (expression_) {                                                    \
        printf("  zcode_attention_verified: %s... OK\n", (name_));    \
    } else {                                                              \
        printf("  zcode_attention_verified: %s... FAIL\n", (name_));  \
        failures++;                                                       \
    }                                                                     \
} while (0)

static void av_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static void av_heuristic(struct vcs_zcode_heuristic_v1 *heuristic,
                         uint8_t tag)
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 1;
    av_root(heuristic->task_root, 1);
    av_root(heuristic->source_root, 2);
    av_root(heuristic->agent_context_root, 3);
    av_root(heuristic->ontology_context_root, 4);
    av_root(heuristic->applicability_root, 5);
    av_root(heuristic->observed_features_root, 6);
    av_root(heuristic->proposed_rule_root, tag);
    av_root(heuristic->expected_effect_root, 8);
    av_root(heuristic->proposal_input_root, 9);
    av_root(heuristic->study_root, 10);
    av_root(heuristic->preregistration_root, 11);
    av_root(heuristic->provenance_root, 12);
    av_root(heuristic->evaluator_roots[0], 5);
    heuristic->requested_cpu_seconds = 60;
    heuristic->requested_processes = 2;
    heuristic->requested_memory_bytes = 16u * 1024u * 1024u;
    heuristic->requested_context_bytes = 64u * 1024u;
    heuristic->requested_output_bytes = 1024u * 1024u;
}

static void av_focus(struct vcs_zcode_focus_v1 *focus)
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
    av_root(focus->task_root, 1);
    av_root(focus->goal_root, 20);
    av_root(focus->source_universe_root, 2);
    av_root(focus->context_root, 3);
    av_root(focus->story_graph_root, 4);
    (void)vcs_zcode_focus_claim_set_root(NULL, 0, focus->claim_set_root);
    av_root(focus->required_evidence_root, 21);
    av_root(focus->authority_limits_root, 22);
}

static void av_bid(struct vcs_zcode_attention_bid_v1 *bid,
                   const struct vcs_zcode_heuristic_v1 *heuristic,
                   const struct vcs_zcode_focus_v1 *focus,
                   uint8_t priority, uint8_t tag)
{
    vcs_zcode_attention_bid_init(bid);
    bid->priority_class = priority;
    (void)vcs_zcode_focus_root(focus, bid->focus_root);
    memcpy(bid->task_root, focus->task_root, 32);
    memcpy(bid->source_root, focus->source_universe_root, 32);
    (void)vcs_zcode_heuristic_root(heuristic, bid->heuristic_root);
    av_root(bid->priority_policy_root, 4);
    av_root(bid->bid_evaluator_root, 5);
    av_root(bid->evidence_root, tag);
    bid->expected_user_value_bp = (uint16_t)(3000u + tag);
    bid->information_gain_bp = 4000;
    bid->blocker_relief_bp = 5000;
    bid->reuse_potential_bp = 6000;
    bid->evidence_strength_bp = 7000;
    bid->risk_bp = 2000;
    bid->overlap_bp = 1000;
    bid->observed_metrics = VCS_ZCODE_ATTENTION_METRIC_REQUIRED;
    bid->expected_latency_us = UINT64_C(1000000);
    bid->expected_cost_milliunits = 100;
}

static bool av_statement(
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
    av_root(statement->profile_schema_root, 30);
    av_root(statement->authorship_assertion_root, 31);
    av_root(statement->license_root, 32);
    av_root(statement->access_policy_root, 33);
    av_root(statement->privacy_policy_root, 34);
    av_root(statement->external_identifiers_root, 35);
    av_root(statement->citations_root, 36);
    if (vcs_zcode_science_relation_set_root(
            &empty_relations, statement->relations_root) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    statement->observed_unix = 1;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
           VCS_ZCODE_SCIENCE_OK;
}

int test_zcode_attention_verified(void)
{
    int failures = 0;
    struct vcs_zcode_focus_v1 focus;
    struct vcs_zcode_heuristic_v1 heuristics[4];
    struct vcs_zcode_attention_bid_v1 bids[4];
    struct vcs_zcode_science_statement_v1 statements[4];
    const uint8_t priorities[4] = {
        VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY,
        VCS_ZCODE_ATTENTION_P1_USER_JOURNEY,
        VCS_ZCODE_ATTENTION_P3_RESEARCH,
        VCS_ZCODE_ATTENTION_P0_SECURITY,
    };
    uint8_t seed[32], secret[32], pubkey[32], wrong_signer[32];
    uint8_t policy_root[32], evaluator_root[32];
    av_root(seed, 40);
    ed25519_keypair(pubkey, secret, seed);
    av_root(wrong_signer, 41);
    av_root(policy_root, 4);
    av_root(evaluator_root, 5);
    av_focus(&focus);
    bool fixtures_ok = true;
    for (size_t i = 0; i < 4; i++) {
        av_heuristic(&heuristics[i], (uint8_t)(50u + i));
        av_bid(&bids[i], &heuristics[i], &focus, priorities[i],
               (uint8_t)(60u + i));
        fixtures_ok = fixtures_ok &&
            av_statement(&statements[i], &bids[i], &heuristics[i],
                         &focus, secret, pubkey);
    }
    AV_CHECK("fixtures-seal", fixtures_ok);
    for (size_t i = 0; i < 4; i++) {
        AV_CHECK("exact-statement-binding",
                 vcs_zcode_attention_bid_verify_statement(
                     &bids[i], &heuristics[i], &focus, &statements[i],
                     pubkey) == VCS_ZCODE_ATTENTION_OK);
    }

    struct vcs_zcode_heuristic_v1 unresolved_derived = heuristics[0];
    unresolved_derived.derivation = VCS_ZCODE_HEURISTIC_REPAIR;
    unresolved_derived.parent_count = 1;
    av_root(unresolved_derived.proposed_rule_root, 70);
    av_root(unresolved_derived.proposal_input_root, 71);
    av_root(unresolved_derived.provenance_root, 72);
    (void)vcs_zcode_heuristic_root(
        &heuristics[0], unresolved_derived.parent_roots[0]);
    struct vcs_zcode_attention_bid_v1 unresolved_bid;
    struct vcs_zcode_science_statement_v1 unresolved_statement;
    av_bid(&unresolved_bid, &unresolved_derived, &focus,
           VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY, 73);
    bool unresolved_statement_ok = av_statement(
        &unresolved_statement, &unresolved_bid, &unresolved_derived,
        &focus, secret, pubkey);
    AV_CHECK("verified-seam-refuses-unresolved-derived-heuristic",
             unresolved_statement_ok &&
             vcs_zcode_attention_bid_verify_statement(
                 &unresolved_bid, &unresolved_derived, &focus,
                 &unresolved_statement, pubkey) ==
                 VCS_ZCODE_ATTENTION_DERIVATION);

    size_t indices[4] = {SIZE_MAX, SIZE_MAX, SIZE_MAX, SIZE_MAX};
    struct vcs_zcode_attention_verified_report report;
    AV_CHECK("hard-p0-before-superior-lower-priority",
             vcs_zcode_attention_frontier_next_verified(
                 bids, 4, heuristics, statements, &focus, policy_root,
                 evaluator_root, pubkey, indices, 4, &report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             report.verified_count == 4 &&
             report.choice.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P0_SECURITY &&
             report.choice.frontier.frontier_count == 1 && indices[0] == 3);
    AV_CHECK("removing-p0-reveals-p1",
             vcs_zcode_attention_frontier_next_verified(
                 bids, 3, heuristics, statements, &focus, policy_root,
                 evaluator_root, pubkey, indices, 4, &report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             report.choice.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_P1_USER_JOURNEY && indices[0] == 1);

    struct vcs_zcode_attention_bid_v1 generation_bids[2] = {
        bids[0], bids[0]
    };
    struct vcs_zcode_heuristic_v1 generation_heuristics[2] = {
        heuristics[0], heuristics[0]
    };
    struct vcs_zcode_science_statement_v1 generation_statements[2] = {
        statements[0], statements[0]
    };
    generation_bids[1].evidence_root[0] ^= 1u;
    generation_bids[1].expected_user_value_bp++;
    generation_bids[1].information_gain_bp--;
    bool generation_statement_ok = av_statement(
        &generation_statements[1], &generation_bids[1],
        &generation_heuristics[1], &focus, secret, pubkey);
    AV_CHECK("signed-evidence-cannot-duplicate-one-logical-candidate",
             generation_statement_ok &&
             vcs_zcode_attention_frontier_next_verified(
                 generation_bids, 2, generation_heuristics,
                 generation_statements, &focus, policy_root,
                 evaluator_root, pubkey, indices, 4, &report) ==
                 VCS_ZCODE_ATTENTION_DUPLICATE);

    struct vcs_zcode_attention_bid_v1 changed_bid = bids[3];
    changed_bid.expected_user_value_bp++;
    AV_CHECK("signed-result-commits-every-score",
             vcs_zcode_attention_bid_verify_statement(
                 &changed_bid, &heuristics[3], &focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    changed_bid = bids[3];
    changed_bid.priority_class = VCS_ZCODE_ATTENTION_P3_RESEARCH;
    AV_CHECK("signed-result-commits-priority-class",
             vcs_zcode_attention_bid_verify_statement(
                 &changed_bid, &heuristics[3], &focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    changed_bid = bids[3];
    changed_bid.priority_policy_root[0] ^= 1u;
    AV_CHECK("signed-result-commits-priority-policy",
             vcs_zcode_attention_bid_verify_statement(
                 &changed_bid, &heuristics[3], &focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    changed_bid = bids[3];
    changed_bid.evidence_root[0] ^= 1u;
    AV_CHECK("signed-result-commits-evidence",
             vcs_zcode_attention_bid_verify_statement(
                 &changed_bid, &heuristics[3], &focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    changed_bid = bids[3];
    changed_bid.bid_evaluator_root[0] ^= 1u;
    AV_CHECK("signed-result-commits-evaluator",
             vcs_zcode_attention_bid_verify_statement(
                 &changed_bid, &heuristics[3], &focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    struct vcs_zcode_focus_v1 changed_focus = focus;
    changed_focus.claim_set_root[0] ^= 1u;
    AV_CHECK("signed-result-commits-focus",
             vcs_zcode_attention_bid_verify_statement(
                 &bids[3], &heuristics[3], &changed_focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    struct vcs_zcode_heuristic_v1 changed_heuristic = heuristics[3];
    changed_heuristic.proposed_rule_root[0] ^= 1u;
    AV_CHECK("signed-result-commits-heuristic",
             vcs_zcode_attention_bid_verify_statement(
                 &bids[3], &changed_heuristic, &focus, &statements[3],
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    AV_CHECK("wrong-local-signer-refuses",
             vcs_zcode_attention_bid_verify_statement(
                 &bids[3], &heuristics[3], &focus, &statements[3],
                 wrong_signer) == VCS_ZCODE_ATTENTION_EVIDENCE);
    struct vcs_zcode_science_statement_v1 changed_statement = statements[3];
    changed_statement.signature[0] ^= 1u;
    AV_CHECK("tampered-signature-refuses",
             vcs_zcode_attention_bid_verify_statement(
                 &bids[3], &heuristics[3], &focus, &changed_statement,
                 pubkey) == VCS_ZCODE_ATTENTION_EVIDENCE);
    changed_statement = statements[3];
    changed_statement.subject_root[0] ^= 1u;
    AV_CHECK("rebound-subject-reseals",
             vcs_zcode_science_statement_seal(
                 &changed_statement, secret, pubkey) ==
                 VCS_ZCODE_SCIENCE_OK);
    AV_CHECK("signed-wrong-subject-refuses",
             vcs_zcode_attention_bid_verify_statement(
                 &bids[3], &heuristics[3], &focus, &changed_statement,
                 pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    changed_statement = statements[3];
    changed_statement.profile = VCS_ZCODE_SCIENCE_PROFILE_OBSERVATION;
    AV_CHECK("non-result-fixture-reseals",
             vcs_zcode_science_statement_seal(
                 &changed_statement, secret, pubkey) ==
                 VCS_ZCODE_SCIENCE_OK);
    AV_CHECK("signed-non-result-is-incomplete",
             vcs_zcode_attention_bid_verify_statement(
                 &bids[3], &heuristics[3], &focus, &changed_statement,
                 pubkey) == VCS_ZCODE_ATTENTION_EVIDENCE);

    struct vcs_zcode_attention_bid_v1 capacity_bids[4];
    struct vcs_zcode_science_statement_v1 capacity_statements[4];
    memcpy(capacity_bids, bids, sizeof(bids));
    memcpy(capacity_statements, statements, sizeof(statements));
    capacity_bids[0].priority_class = VCS_ZCODE_ATTENTION_P0_SECURITY;
    capacity_bids[0].expected_user_value_bp = 9000;
    capacity_bids[0].expected_cost_milliunits = 900;
    capacity_bids[3].expected_user_value_bp = 1000;
    capacity_bids[3].expected_cost_milliunits = 10;
    AV_CHECK("capacity-fixtures-reseal",
             av_statement(&capacity_statements[0], &capacity_bids[0],
                          &heuristics[0], &focus, secret, pubkey) &&
             av_statement(&capacity_statements[3], &capacity_bids[3],
                          &heuristics[3], &focus, secret, pubkey));
    indices[0] = SIZE_MAX;
    AV_CHECK("capacity-is-atomic-and-reports-need",
             vcs_zcode_attention_frontier_next_verified(
                 capacity_bids, 4, heuristics, capacity_statements, &focus,
                 policy_root, evaluator_root, pubkey, indices, 1, &report) ==
                 VCS_ZCODE_ATTENTION_CAPACITY &&
             report.verified_count == 4 &&
             report.choice.frontier.frontier_count == 2 &&
             report.choice.frontier.returned_count == 0 &&
             indices[0] == SIZE_MAX);

    changed_statement = statements[1];
    changed_statement.signature[0] ^= 1u;
    struct vcs_zcode_science_statement_v1 invalid_statements[4];
    memcpy(invalid_statements, statements, sizeof(statements));
    invalid_statements[1] = changed_statement;
    memset(&report, 0xa5, sizeof(report));
    struct vcs_zcode_attention_verified_report report_before = report;
    indices[0] = SIZE_MAX;
    AV_CHECK("one-unverified-row-fails-closed",
             vcs_zcode_attention_frontier_next_verified(
                 bids, 4, heuristics, invalid_statements, &focus,
                 policy_root, evaluator_root, pubkey, indices, 4, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &report_before, sizeof(report)) == 0 &&
             indices[0] == SIZE_MAX);
    AV_CHECK("empty-set-is-explicit",
             vcs_zcode_attention_frontier_next_verified(
                 NULL, 0, NULL, NULL, &focus, policy_root, evaluator_root,
                 pubkey, NULL, 0, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.verified_count == 0 &&
             report.choice.frontier.input_count == 0 &&
             report.choice.selected_priority_class ==
                 VCS_ZCODE_ATTENTION_PRIORITY_AUTO);
    AV_CHECK("error-string-evidence",
             strcmp(vcs_zcode_attention_error_string(
                        VCS_ZCODE_ATTENTION_EVIDENCE), "evidence") == 0);
    return failures;
}
