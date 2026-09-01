/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove exact retrieval observations compose with attention evidence. */
#include "retrieval/retrieval_experiment.h"
#include "vcs/zcode_attention_verified.h"

#include "crypto/ed25519.h"
#include "test/test_core.h"

#include <stdio.h>
#include <string.h>

#define RAE_CHECK(name_, expression_) do {                                \
    if (expression_) {                                                    \
        printf("  retrieval_attention_evidence: %s... OK\n", (name_)); \
    } else {                                                              \
        printf("  retrieval_attention_evidence: %s... FAIL\n", (name_)); \
        failures++;                                                       \
    }                                                                     \
} while (0)

static void rae_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static bool rae_retrieval_observation(
    struct zcl_retrieval_experiment_eval_report *report,
    uint8_t proposal_root[32], uint8_t candidate_root[32],
    uint8_t source_root[32], uint8_t projection_root[32],
    uint8_t evaluator_root[32])
{
    const struct zcl_retrieval_ranked_file bm25[5] = {
        {"cognition/modules/retrieval/src/retrieval.c", 100u, false, true},
        {"cognition/modules/retrieval/src/retrieval_eval.c", 80u, true, true},
        {"tests/harness/src/test_retrieval.c", 60u, true, true},
        {"contexts/wallet/models/src/wallet.c", 40u, false, true},
        {"platform/modules/base/src/safe_alloc.c", 20u, false, true},
    };
    const struct zcl_retrieval_ranked_file parent[5] = {
        {"cognition/modules/retrieval/src/retrieval_eval.c", 80u, true, true},
        {"tests/harness/src/test_retrieval.c", 60u, true, true},
        {"cognition/modules/retrieval/src/retrieval.c", 100u, false, true},
        {"contexts/wallet/models/src/wallet.c", 40u, false, true},
        {"platform/modules/base/src/safe_alloc.c", 20u, false, true},
    };
    const char *const relevant[] = {
        "cognition/modules/retrieval/src/retrieval_eval.c",
    };
    const struct zcl_retrieval_experiment_eval_task task = {
        .task_id = "retrieval-observation",
        .query = "exact retrieval evaluation evidence",
        .relevant_paths = relevant,
        .relevant_count = 1u,
        .bm25 = bm25,
        .bm25_count = 5u,
        .bm25_complete = true,
        .parent = parent,
        .parent_count = 5u,
        .parent_complete = true,
    };
    if (zcl_retrieval_experiment_evaluate(&task, 1u, 0u, report) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;
    struct zcl_retrieval_ranked_file candidate[5];
    struct zcl_retrieval_experiment_report projection_report;
    if (zcl_retrieval_experiment_project(
            bm25, 5u, true, parent, 5u, true, 0u,
            candidate, 5u, &projection_report) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        !zcl_retrieval_ranked_files_root(candidate, 5u, true, candidate_root))
        return false;
    uint8_t bm25_root[32], parent_root[32], study_root[32], prereg_root[32];
    if (!zcl_retrieval_ranked_files_root(bm25, 5u, true, bm25_root) ||
        !zcl_retrieval_ranked_files_root(parent, 5u, true, parent_root))
        return false;
    rae_root(source_root, 1u);
    rae_root(projection_root, 2u);
    rae_root(study_root, 3u);
    rae_root(prereg_root, 4u);
    rae_root(evaluator_root, 5u);
    return zcl_retrieval_experiment_proposal_input_root(
        source_root, projection_root, task.task_id, task.query,
        bm25_root, parent_root, 0u, study_root, prereg_root,
        evaluator_root, proposal_root);
}

static void rae_focus(struct vcs_zcode_focus_v1 *focus,
                      const uint8_t source_root[32])
{
    memset(focus, 0, sizeof(*focus));
    focus->schema_version = VCS_ZCODE_FOCUS_VERSION;
    focus->status = ZCL_ONTOLOGY_PROVED;
    focus->capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                          VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    focus->max_changed_files = 4u;
    focus->max_patch_bytes = 32768u;
    focus->max_context_bytes = 65536u;
    focus->max_cpu_seconds = 120u;
    focus->max_memory_bytes = 32u * 1024u * 1024u;
    focus->max_output_bytes = 1024u * 1024u;
    rae_root(focus->task_root, 10u);
    rae_root(focus->goal_root, 11u);
    memcpy(focus->source_universe_root, source_root, 32u);
    rae_root(focus->context_root, 12u);
    rae_root(focus->story_graph_root, 13u);
    (void)vcs_zcode_focus_claim_set_root(NULL, 0, focus->claim_set_root);
    rae_root(focus->required_evidence_root, 14u);
    rae_root(focus->authority_limits_root, 15u);
}

static bool rae_statement(
    struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    const struct vcs_zcode_science_relation_set_v1 relations = {
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
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_science_relation_set_root(
            &relations, statement->relations_root) != VCS_ZCODE_SCIENCE_OK)
        return false;
    memcpy(statement->provenance_root, bid->evidence_root, 32u);
    memcpy(statement->activity_root, bid->bid_evaluator_root, 32u);
    for (uint8_t tag = 20u; tag < 27u; tag++) {
        uint8_t *root = tag == 20u ? statement->profile_schema_root :
            tag == 21u ? statement->authorship_assertion_root :
            tag == 22u ? statement->license_root :
            tag == 23u ? statement->access_policy_root :
            tag == 24u ? statement->privacy_policy_root :
            tag == 25u ? statement->external_identifiers_root :
                         statement->citations_root;
        rae_root(root, tag);
    }
    statement->observed_unix = 1;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
        VCS_ZCODE_SCIENCE_OK;
}

int test_retrieval_attention_evidence(void)
{
    int failures = 0;
    struct zcl_retrieval_experiment_eval_report report;
    uint8_t proposal_root[32], candidate_root[32], source_root[32];
    uint8_t projection_root[32], evaluator_root[32];
    bool observed = rae_retrieval_observation(
        &report, proposal_root, candidate_root, source_root,
        projection_root, evaluator_root);
    RAE_CHECK("maintained-evaluator-observation", observed &&
              report.metrics.tasks == 1u &&
              report.top20_membership_preserved &&
              report.full_retained_set_preserved &&
              report.context_ceiling_preserved);

    struct vcs_zcode_focus_v1 focus;
    rae_focus(&focus, source_root);
    struct vcs_zcode_heuristic_v1 heuristic;
    vcs_zcode_heuristic_init(&heuristic);
    heuristic.evaluator_count = 1u;
    memcpy(heuristic.task_root, focus.task_root, 32u);
    memcpy(heuristic.source_root, source_root, 32u);
    memcpy(heuristic.agent_context_root, focus.context_root, 32u);
    memcpy(heuristic.ontology_context_root, focus.story_graph_root, 32u);
    rae_root(heuristic.applicability_root, 30u);
    memcpy(heuristic.observed_features_root, projection_root, 32u);
    memcpy(heuristic.proposed_rule_root, proposal_root, 32u);
    memcpy(heuristic.expected_effect_root, candidate_root, 32u);
    memcpy(heuristic.proposal_input_root, proposal_root, 32u);
    rae_root(heuristic.study_root, 3u);
    rae_root(heuristic.preregistration_root, 4u);
    rae_root(heuristic.provenance_root, 31u);
    memcpy(heuristic.evaluator_roots[0], evaluator_root, 32u);
    heuristic.requested_cpu_seconds = 60u;
    heuristic.requested_processes = 2u;
    heuristic.requested_memory_bytes = 16u * 1024u * 1024u;
    heuristic.requested_context_bytes = 32768u;
    heuristic.requested_output_bytes = 65536u;
    uint8_t heuristic_root[32], evaluation_input_root[32];
    bool heuristic_ok = vcs_zcode_heuristic_root(
        &heuristic, heuristic_root) == VCS_ZCODE_ATTENTION_OK;
    rae_root(evaluation_input_root, 32u);

    struct zcl_retrieval_experiment_eval_result_v1 result, parsed;
    uint8_t result_root[32], parsed_root[32];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_eval_result_init(
            &result, &report, heuristic_root, proposal_root,
            evaluation_input_root, evaluator_root);
    uint8_t wire[ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES];
    bool result_ok = heuristic_ok &&
        error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_experiment_eval_result_serialize(&result, wire) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_experiment_eval_result_parse(
            wire, sizeof(wire), &parsed) == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_experiment_eval_result_root(&result, result_root) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_experiment_eval_result_root(&parsed, parsed_root) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK;
    RAE_CHECK("canonical-result-roundtrip", result_ok &&
              memcmp(&result, &parsed, sizeof(result)) == 0 &&
              memcmp(result_root, parsed_root, 32u) == 0 &&
              memcmp(wire, "ZCRXEV1\n", 8u) == 0);
    RAE_CHECK("exact-four-root-binding",
              zcl_retrieval_experiment_eval_result_verify_binding(
                  &result, heuristic_root, proposal_root,
                  evaluation_input_root, evaluator_root, result_root) ==
                  ZCL_RETRIEVAL_EXPERIMENT_OK);

    struct vcs_zcode_attention_bid_v1 bid;
    vcs_zcode_attention_bid_init(&bid);
    bid.priority_class = VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY;
    (void)vcs_zcode_focus_root(&focus, bid.focus_root);
    memcpy(bid.task_root, focus.task_root, 32u);
    memcpy(bid.source_root, source_root, 32u);
    memcpy(bid.heuristic_root, heuristic_root, 32u);
    rae_root(bid.priority_policy_root, 33u);
    memcpy(bid.bid_evaluator_root, evaluator_root, 32u);
    memcpy(bid.evidence_root, result_root, 32u);
    bid.expected_user_value_bp = 5000u;
    bid.information_gain_bp = 7000u;
    bid.blocker_relief_bp = 4000u;
    bid.reuse_potential_bp = 6000u;
    bid.evidence_strength_bp = 3000u;
    bid.risk_bp = 2000u;
    bid.overlap_bp = 1000u;
    bid.observed_metrics = VCS_ZCODE_ATTENTION_METRIC_REQUIRED;
    bid.expected_latency_us = 1000000u;
    bid.expected_cost_milliunits = 100u;
    uint8_t seed[32], secret[32], pubkey[32];
    rae_root(seed, 40u);
    ed25519_keypair(pubkey, secret, seed);
    struct vcs_zcode_science_statement_v1 statement;
    bool statement_ok = rae_statement(
        &statement, &bid, &heuristic, &focus, secret, pubkey);
    size_t selected = SIZE_MAX;
    struct vcs_zcode_attention_verified_report attention_report;
    RAE_CHECK("retrieval-result-enters-signed-proposal-frontier",
              statement_ok &&
              vcs_zcode_attention_frontier_next_verified(
                  &bid, 1u, &heuristic, &statement, &focus,
                  bid.priority_policy_root, evaluator_root, pubkey,
                  &selected, 1u, &attention_report) ==
                  VCS_ZCODE_ATTENTION_OK && selected == 0u &&
              attention_report.verified_count == 1u &&
              attention_report.choice.frontier.frontier_count == 1u);

    struct zcl_retrieval_experiment_eval_result_v1 changed = result;
    changed.evaluation_input_root[0] ^= 1u;
    RAE_CHECK("changed-evaluation-input-invalidates-bid-evidence",
              zcl_retrieval_experiment_eval_result_verify_binding(
                  &changed, heuristic_root, proposal_root,
                  evaluation_input_root, evaluator_root, result_root) ==
                  ZCL_RETRIEVAL_EXPERIMENT_BINDING);
    changed = result;
    changed.flags &= (uint16_t)~(
        ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED |
        ZCL_RETRIEVAL_EVAL_RESULT_RETAINED_SET_PRESERVED |
        ZCL_RETRIEVAL_EVAL_RESULT_CONTEXT_CEILING_PRESERVED);
    RAE_CHECK("failed-guards-remain-valid-negative-observations",
              zcl_retrieval_experiment_eval_result_validate(&changed) ==
                  ZCL_RETRIEVAL_EXPERIMENT_OK);
    changed = result;
    changed.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE;
    changed.recall_at_5_bp = 1u;
    RAE_CHECK("unavailable-metric-cannot-carry-a-score",
              zcl_retrieval_experiment_eval_result_validate(&changed) ==
                  ZCL_RETRIEVAL_EXPERIMENT_EVALUATION);
    changed = result;
    changed.flags |= ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE;
    changed.unique_files_at_5 = 3u;
    changed.wrong_scope_files_at_5 = 1u;
    changed.wrong_scope_at_5_bp = 3334u;
    RAE_CHECK("wrong-scope-arithmetic-is-canonical",
              zcl_retrieval_experiment_eval_result_validate(&changed) ==
                  ZCL_RETRIEVAL_EXPERIMENT_EVALUATION);
    memset(&parsed, 0xa5, sizeof(parsed));
    RAE_CHECK("short-wire-clears-parse-output",
              zcl_retrieval_experiment_eval_result_parse(
                  wire, sizeof(wire) - 1u, &parsed) ==
                  ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE &&
              memcmp(&parsed,
                     &(struct zcl_retrieval_experiment_eval_result_v1){0},
                     sizeof(parsed)) == 0);
    struct zcl_retrieval_experiment_eval_report inconsistent = report;
    inconsistent.metrics.approximate_tokens_at_5++;
    RAE_CHECK("derived-token-count-cannot-drift",
              zcl_retrieval_experiment_eval_result_init(
                  &changed, &inconsistent, heuristic_root, proposal_root,
                  evaluation_input_root, evaluator_root) ==
                  ZCL_RETRIEVAL_EXPERIMENT_EVALUATION);
    return failures;
}
