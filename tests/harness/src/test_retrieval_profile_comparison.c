/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove retrieval comparison is bound to exact specialization. */
#include "services/zcode_retrieval_profile_comparison_service.h"

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RPC_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                      \
        printf("  retrieval_profile_comparison: %s... OK\n", (name_));   \
    } else {                                                                \
        printf("  retrieval_profile_comparison: %s... FAIL\n", (name_)); \
        failures++;                                                         \
    }                                                                       \
} while (0)

struct rpc_fixture {
    struct zcl_retrieval_comparison_policy_v1 policy;
    struct vcs_zcode_heuristic_v1 parent, child;
    struct zcl_retrieval_experiment_eval_result_v1 parent_result, child_result;
    uint8_t policy_root[32], parent_root[32], child_root[32];
    uint8_t parent_result_root[32], child_result_root[32];
};

static void rpc_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static void rpc_heuristic_base(struct vcs_zcode_heuristic_v1 *heuristic)
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 2u;
    rpc_root(heuristic->task_root, 0x10u);
    rpc_root(heuristic->source_root, 0x11u);
    rpc_root(heuristic->agent_context_root, 0x12u);
    rpc_root(heuristic->ontology_context_root, 0x13u);
    rpc_root(heuristic->applicability_root, 0x14u);
    rpc_root(heuristic->observed_features_root, 0x15u);
    rpc_root(heuristic->proposed_rule_root, 0x16u);
    rpc_root(heuristic->expected_effect_root, 0x17u);
    rpc_root(heuristic->proposal_input_root, 0x18u);
    rpc_root(heuristic->study_root, 0x19u);
    rpc_root(heuristic->provenance_root, 0x1au);
    rpc_root(heuristic->evaluator_roots[0], 0x40u);
    rpc_root(heuristic->evaluator_roots[1], 0x50u);
    heuristic->requested_cpu_seconds = 30u;
    heuristic->requested_processes = 1u;
    heuristic->requested_memory_bytes = 1024u * 1024u;
    heuristic->requested_context_bytes = 4096u;
    heuristic->requested_output_bytes = 4096u;
}

static void rpc_result_base(
    struct zcl_retrieval_experiment_eval_result_v1 *result,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    uint32_t recall_at_5_bp)
{
    memset(result, 0, sizeof(*result));
    result->schema_version = ZCL_RETRIEVAL_EVAL_RESULT_VERSION;
    result->flags = ZCL_RETRIEVAL_EVAL_RESULT_FLAGS_ALL;
    result->tasks = 2u;
    result->recall_at_5_bp = recall_at_5_bp;
    result->recall_at_20_bp = 6000u;
    result->mrr_bp = 4000u;
    result->wrong_scope_at_5_bp = 2500u;
    result->unique_files_at_5 = 4u;
    result->wrong_scope_files_at_5 = 1u;
    result->changed_positions_at_5 = 2u;
    result->context_bytes_at_5 = 100u;
    memcpy(result->subject_root, heuristic->task_root, 32u);
    memcpy(result->proposal_input_root, heuristic->proposal_input_root, 32u);
    memcpy(result->evaluation_input_root,
           policy->evaluation_input_root, 32u);
    memcpy(result->evaluator_root, policy->evaluator_root, 32u);
}

static bool rpc_fixture_init(struct rpc_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->policy.schema_version = ZCL_RETRIEVAL_COMPARISON_POLICY_VERSION;
    fixture->policy.metric = ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP;
    fixture->policy.direction =
        ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST;
    fixture->policy.required_guards = ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL;
    fixture->policy.threshold_bp = 100u;
    fixture->policy.expected_tasks = 2u;
    rpc_root(fixture->policy.evaluation_input_root, 0x60u);
    rpc_root(fixture->policy.evaluator_root, 0x50u);
    if (zcl_retrieval_comparison_policy_root(
            &fixture->policy, fixture->policy_root) !=
            ZCL_RETRIEVAL_COMPARISON_OK)
        return false;

    rpc_heuristic_base(&fixture->parent);
    memcpy(fixture->parent.preregistration_root, fixture->policy_root, 32u);
    if (vcs_zcode_heuristic_root(&fixture->parent, fixture->parent_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return false;
    fixture->child = fixture->parent;
    fixture->child.derivation = VCS_ZCODE_HEURISTIC_SPECIALIZE;
    fixture->child.parent_count = 1u;
    memcpy(fixture->child.parent_roots[0], fixture->parent_root, 32u);
    rpc_root(fixture->child.observed_features_root, 0x25u);
    rpc_root(fixture->child.proposed_rule_root, 0x26u);
    rpc_root(fixture->child.expected_effect_root, 0x27u);
    rpc_root(fixture->child.proposal_input_root, 0x28u);
    rpc_root(fixture->child.provenance_root, 0x29u);
    if (vcs_zcode_heuristic_validate_derivation(
            &fixture->child, &fixture->parent, 1u) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_heuristic_root(&fixture->child, fixture->child_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return false;

    rpc_result_base(&fixture->parent_result, &fixture->parent,
                    &fixture->policy, 5000u);
    rpc_result_base(&fixture->child_result, &fixture->child,
                    &fixture->policy, 5100u);
    memcpy(fixture->parent_result.subject_root, fixture->parent_root, 32u);
    memcpy(fixture->child_result.subject_root, fixture->child_root, 32u);
    return zcl_retrieval_experiment_eval_result_root(
               &fixture->parent_result, fixture->parent_result_root) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK &&
           zcl_retrieval_experiment_eval_result_root(
               &fixture->child_result, fixture->child_result_root) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static struct zcode_retrieval_profile_comparison_request rpc_request(
    const struct rpc_fixture *fixture)
{
    struct zcode_retrieval_profile_comparison_request request = {
        .parent_heuristic = &fixture->parent,
        .child_heuristic = &fixture->child,
        .policy = &fixture->policy,
        .parent_result = &fixture->parent_result,
        .child_result = &fixture->child_result,
    };
    memcpy(request.expected_task_root, fixture->parent.task_root, 32u);
    memcpy(request.expected_source_root, fixture->parent.source_root, 32u);
    memcpy(request.expected_policy_root, fixture->policy_root, 32u);
    memcpy(request.parent_result_root, fixture->parent_result_root, 32u);
    memcpy(request.child_result_root, fixture->child_result_root, 32u);
    return request;
}

static bool rpc_refresh_results(struct rpc_fixture *fixture)
{
    return zcl_retrieval_experiment_eval_result_root(
               &fixture->parent_result, fixture->parent_result_root) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK &&
           zcl_retrieval_experiment_eval_result_root(
               &fixture->child_result, fixture->child_result_root) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rpc_refuses_atomically(
    const struct rpc_fixture *fixture,
    enum zcode_retrieval_profile_comparison_error expected)
{
    struct zcode_retrieval_profile_comparison_request request =
        rpc_request(fixture);
    struct zcode_retrieval_profile_comparison_report report, before;
    memset(&report, 0xa5, sizeof(report));
    before = report;
    return zcode_retrieval_profile_comparison_observe(&request, &report) ==
               expected && memcmp(&report, &before, sizeof(report)) == 0;
}

static int case_exact_specialization(void)
{
    int failures = 0;
    struct rpc_fixture fixture;
    struct zcode_retrieval_profile_comparison_report report;
    bool ready = rpc_fixture_init(&fixture);
    struct zcode_retrieval_profile_comparison_request request =
        rpc_request(&fixture);
    bool observed = ready && zcode_retrieval_profile_comparison_observe(
        &request, &report) == ZCODE_RETRIEVAL_PROFILE_COMPARISON_OK;
    RPC_CHECK("immediate SPECIALIZE lineage is observed",
              observed && fixture.child.derivation ==
                  VCS_ZCODE_HEURISTIC_SPECIALIZE &&
              fixture.child.parent_count == 1u &&
              memcmp(fixture.child.parent_roots[0],
                     fixture.parent_root, 32u) == 0 &&
              vcs_zcode_heuristic_validate_derivation(
                  &fixture.child, &fixture.parent, 1u) ==
                  VCS_ZCODE_ATTENTION_OK);
    RPC_CHECK("both heuristic and proposal roots are exact",
              observed && memcmp(report.parent_heuristic_root,
                                 fixture.parent_root, 32u) == 0 &&
              memcmp(report.child_heuristic_root,
                     fixture.child_root, 32u) == 0 &&
              memcmp(fixture.parent_result.proposal_input_root,
                     fixture.parent.proposal_input_root, 32u) == 0 &&
              memcmp(fixture.child_result.proposal_input_root,
                     fixture.child.proposal_input_root, 32u) == 0);
    RPC_CHECK("policy task source and study joins remain frozen",
              observed && memcmp(report.observation.policy_root,
                                 fixture.policy_root, 32u) == 0 &&
              memcmp(fixture.parent.preregistration_root,
                     fixture.policy_root, 32u) == 0 &&
              memcmp(fixture.child.preregistration_root,
                     fixture.policy_root, 32u) == 0 &&
              memcmp(fixture.parent.task_root, fixture.child.task_root, 32u) == 0 &&
              memcmp(fixture.parent.source_root, fixture.child.source_root, 32u) == 0 &&
              memcmp(fixture.parent.study_root, fixture.child.study_root, 32u) == 0);
    RPC_CHECK("policy evaluator is a member of both frozen evaluator sets",
              observed && memcmp(fixture.policy.evaluator_root,
                                 fixture.parent.evaluator_roots[1], 32u) == 0 &&
              memcmp(fixture.policy.evaluator_root,
                     fixture.child.evaluator_roots[1], 32u) == 0 &&
              memcmp(fixture.policy.evaluator_root,
                     fixture.parent_result.evaluator_root, 32u) == 0 &&
              memcmp(fixture.policy.evaluator_root,
                     fixture.child_result.evaluator_root, 32u) == 0 &&
              report.observation.status ==
                  ZCL_RETRIEVAL_COMPARISON_SATISFIED);
    return failures;
}

static int case_atomic_refusals(void)
{
    int failures = 0;
    struct rpc_fixture base, changed;
    bool ready = rpc_fixture_init(&base);
    changed = base;
    rpc_root(changed.parent_result.subject_root, 0xa1u);
    rpc_root(changed.child_result.subject_root, 0xa2u);
    rpc_root(changed.parent_result.proposal_input_root, 0xa3u);
    rpc_root(changed.child_result.proposal_input_root, 0xa4u);
    RPC_CHECK("arbitrary distinct arm tags are refused atomically",
              ready && rpc_refresh_results(&changed) &&
              rpc_refuses_atomically(
                  &changed, ZCODE_RETRIEVAL_PROFILE_COMPARISON_OBSERVATION));

    changed = base;
    changed.policy.threshold_bp++;
    RPC_CHECK("post-hoc policy substitution is refused atomically",
              rpc_refuses_atomically(
                  &changed, ZCODE_RETRIEVAL_PROFILE_COMPARISON_BINDING));

    changed = base;
    changed.child.expected_effect_root[0] ^= 1u;
    RPC_CHECK("stale child generation result is refused atomically",
              vcs_zcode_heuristic_validate_derivation(
                  &changed.child, &changed.parent, 1u) ==
                  VCS_ZCODE_ATTENTION_OK &&
              rpc_refuses_atomically(
                  &changed, ZCODE_RETRIEVAL_PROFILE_COMPARISON_OBSERVATION));

    changed = base;
    changed.parent.provenance_root[0] ^= 1u;
    RPC_CHECK("wrong immediate parent is refused atomically",
              vcs_zcode_heuristic_validate(&changed.parent) ==
                  VCS_ZCODE_ATTENTION_OK &&
              rpc_refuses_atomically(
                  &changed, ZCODE_RETRIEVAL_PROFILE_COMPARISON_LINEAGE));

    changed = base;
    rpc_root(changed.child_result.proposal_input_root, 0xb0u);
    RPC_CHECK("wrong proposal root is refused atomically",
              rpc_refresh_results(&changed) &&
              rpc_refuses_atomically(
                  &changed, ZCODE_RETRIEVAL_PROFILE_COMPARISON_OBSERVATION));
    return failures;
}

int test_retrieval_profile_comparison(void)
{
    int failures = case_exact_specialization() + case_atomic_refusals();
    printf("retrieval_profile_comparison: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
