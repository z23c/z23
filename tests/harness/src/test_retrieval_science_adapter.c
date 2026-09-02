/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the pure retrieval-to-science adapter and its boundaries. */
#include "services/zcode_retrieval_science_adapter_service.h"

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RSA_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                       \
        printf("  retrieval_science_adapter: %s... OK\n", (name_));       \
    } else {                                                                \
        printf("  retrieval_science_adapter: %s... FAIL\n", (name_));     \
        failures++;                                                         \
    }                                                                       \
} while (0)

struct rsa_fixture {
    struct zcl_retrieval_profile_v1 parent_profile, child_profile;
    struct zcl_retrieval_feature_snapshot_v1 snapshot;
    struct zcl_retrieval_feature_row_v1 rows[5];
    struct vcs_zcode_heuristic_v1 parent_heuristic, child_heuristic;
    struct zcl_retrieval_comparison_policy_v2 comparison_policy;
    struct vcs_zcode_environment_policy_v1 environment_policy;
    struct vcs_zcode_hardware_profile_v1 hardware_profile;
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    const char *relevant[1];
    uint8_t source_root[32], projection_root[32], evaluator_root[32];
    uint8_t workload_root[32], comparison_policy_root[32];
    uint8_t environment_policy_root[32], study_root[32], task_root[32];
    uint8_t candidate_root[32], parent_heuristic_root[32];
};

static void rsa_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static bool rsa_profile_projection(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct rsa_fixture *fixture,
    struct zcl_retrieval_profile_report *report)
{
    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    return zcl_retrieval_profile_project(
        profile, &fixture->snapshot, fixture->rows, indices,
        ZCL_RETRIEVAL_EVAL_RANK_MAX, report) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rsa_proposal_root(
    const struct rsa_fixture *fixture, const uint8_t profile_root[32],
    const uint8_t snapshot_root[32], const uint8_t ranking_root[32],
    uint8_t out[32])
{
    return zcl_retrieval_profile_proposal_input_root(
        fixture->source_root, fixture->snapshot.source_root,
        fixture->snapshot.codeindex_root, "science_pair",
        "find the exact target", fixture->snapshot.baseline_ranking_root,
        profile_root, snapshot_root, ranking_root, fixture->study_root,
        fixture->comparison_policy_root, fixture->evaluator_root, out);
}

static void rsa_heuristic_common(
    struct vcs_zcode_heuristic_v1 *heuristic,
    const struct rsa_fixture *fixture, const uint8_t snapshot_root[32])
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 1u;
    memcpy(heuristic->task_root, fixture->task_root, 32u);
    memcpy(heuristic->source_root, fixture->source_root, 32u);
    rsa_root(heuristic->agent_context_root, 0x31u);
    rsa_root(heuristic->ontology_context_root, 0x32u);
    rsa_root(heuristic->applicability_root, 0x33u);
    memcpy(heuristic->observed_features_root, snapshot_root, 32u);
    memcpy(heuristic->study_root, fixture->study_root, 32u);
    memcpy(heuristic->preregistration_root,
           fixture->comparison_policy_root, 32u);
    rsa_root(heuristic->provenance_root, 0x34u);
    memcpy(heuristic->evaluator_roots[0], fixture->evaluator_root, 32u);
    heuristic->requested_cpu_seconds = 30u;
    heuristic->requested_processes = 1u;
    heuristic->requested_memory_bytes = 1024u * 1024u;
    heuristic->requested_context_bytes = 4096u;
    heuristic->requested_output_bytes = 4096u;
}

static bool rsa_refresh_heuristics(struct rsa_fixture *fixture)
{
    struct zcl_retrieval_profile_report parent_projection, child_projection;
    uint8_t parent_profile_root[32], child_profile_root[32], snapshot_root[32];
    if (!rsa_profile_projection(
            &fixture->parent_profile, fixture, &parent_projection) ||
        !rsa_profile_projection(
            &fixture->child_profile, fixture, &child_projection) ||
        zcl_retrieval_profile_root(
            &fixture->parent_profile, parent_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_root(
            &fixture->child_profile, child_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_feature_snapshot_root(
            &fixture->snapshot, fixture->rows, snapshot_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;

    rsa_heuristic_common(&fixture->parent_heuristic, fixture, snapshot_root);
    memcpy(fixture->parent_heuristic.proposed_rule_root,
           parent_profile_root, 32u);
    memcpy(fixture->parent_heuristic.expected_effect_root,
           parent_projection.candidate_ranking_root, 32u);
    if (!rsa_proposal_root(
            fixture, parent_profile_root, snapshot_root,
            parent_projection.candidate_ranking_root,
            fixture->parent_heuristic.proposal_input_root) ||
        vcs_zcode_heuristic_root(
            &fixture->parent_heuristic,
            fixture->parent_heuristic_root) != VCS_ZCODE_ATTENTION_OK)
        return false;

    fixture->child_heuristic = fixture->parent_heuristic;
    fixture->child_heuristic.derivation = VCS_ZCODE_HEURISTIC_SPECIALIZE;
    fixture->child_heuristic.parent_count = 1u;
    memcpy(fixture->child_heuristic.parent_roots[0],
           fixture->parent_heuristic_root, 32u);
    memcpy(fixture->child_heuristic.proposed_rule_root,
           child_profile_root, 32u);
    memcpy(fixture->child_heuristic.expected_effect_root,
           child_projection.candidate_ranking_root, 32u);
    rsa_root(fixture->child_heuristic.provenance_root, 0x35u);
    if (!rsa_proposal_root(
            fixture, child_profile_root, snapshot_root,
            child_projection.candidate_ranking_root,
            fixture->child_heuristic.proposal_input_root))
        return false;
    return vcs_zcode_heuristic_validate_derivation(
        &fixture->child_heuristic, &fixture->parent_heuristic, 1u) ==
        VCS_ZCODE_ATTENTION_OK;
}

static bool rsa_refresh_candidate(struct rsa_fixture *fixture)
{
    uint8_t child_heuristic_root[32];
    if (vcs_zcode_heuristic_root(
            &fixture->child_heuristic, child_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return false;
    memcpy(fixture->candidate.patch_root, child_heuristic_root, 32u);
    memcpy(fixture->candidate.candidate_source_root,
           fixture->source_root, 32u);
    return vcs_zcode_candidate_root(
        &fixture->candidate, fixture->candidate_root) == VCS_ZCODE_DEV_OK;
}

static bool rsa_fixture_init(struct rsa_fixture *fixture, uint8_t metric,
                             uint16_t threshold_bp)
{
    memset(fixture, 0, sizeof(*fixture));
    rsa_root(fixture->source_root, 0x12u);
    rsa_root(fixture->projection_root, 0x14u);
    rsa_root(fixture->evaluator_root, 0x16u);
    fixture->relevant[0] = "src/target.c";

    zcl_retrieval_profile_init(&fixture->parent_profile);
    fixture->parent_profile.feature_mask = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    fixture->parent_profile.weight_bp[
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES] = 100u;
    fixture->parent_profile.rerank_window = 5u;
    fixture->parent_profile.top_k = ZCL_RETRIEVAL_EXPERIMENT_TOP;
    fixture->parent_profile.context_byte_scale = 1u;
    fixture->child_profile = fixture->parent_profile;
    fixture->child_profile.context_byte_scale = 1000u;

    static const char *const paths[5] = {
        "src/target.c", "src/a.c", "src/b.c", "src/c.c", "src/d.c"};
    static const uint64_t bytes[5] = {500u, 100u, 200u, 300u, 400u};
    struct zcl_retrieval_ranked_file baseline[5];
    for (size_t i = 0; i < 5u; i++) {
        fixture->rows[i] = (struct zcl_retrieval_feature_row_v1){
            .path = paths[i],
            .context_bytes = bytes[i],
            .original_bm25_rank = (uint16_t)(i + 1u),
            .observed_features = ZCL_RETRIEVAL_FEATURE_BIT(
                ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES),
        };
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = paths[i], .context_bytes = bytes[i],
            .in_scope = false, .in_scope_available = false,
        };
    }
    fixture->snapshot.schema_version = ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION;
    fixture->snapshot.row_count = 5u;
    fixture->snapshot.ranking_complete = true;
    fixture->snapshot.available_features = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    memcpy(fixture->snapshot.source_root, fixture->source_root, 32u);
    memcpy(fixture->snapshot.codeindex_root,
           fixture->projection_root, 32u);
    rsa_root(fixture->snapshot.extractor_root, 0x17u);
    if (zcl_retrieval_query_root(
            "find the exact target", fixture->snapshot.query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        !zcl_retrieval_ranked_files_root(
            baseline, 5u, true,
            fixture->snapshot.baseline_ranking_root))
        return false;

    struct zcl_retrieval_evaluation_workload_task_v1 workload = {
        .task_id = "science_pair",
        .query = "find the exact target",
        .relevant_paths = fixture->relevant,
        .relevant_count = 1u,
    };
    if (zcl_retrieval_evaluation_workload_v2_root(
            &workload, 1u, fixture->source_root,
            fixture->projection_root, fixture->workload_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;
    fixture->comparison_policy =
        (struct zcl_retrieval_comparison_policy_v2){
            .schema_version = ZCL_RETRIEVAL_COMPARISON_POLICY_V2_VERSION,
            .metric = metric,
            .direction =
                metric == ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP
                    ? ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN
                    : ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
            .required_guards = ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL,
            .evaluation_kind =
                ZCL_RETRIEVAL_COMPARISON_DERIVED_PROFILE_PAIRED_V1,
            .threshold_bp = threshold_bp,
            .expected_tasks = 1u,
        };
    memcpy(fixture->comparison_policy.workload_root,
           fixture->workload_root, 32u);
    memcpy(fixture->comparison_policy.evaluator_root,
           fixture->evaluator_root, 32u);
    if (zcl_retrieval_comparison_policy_v2_root(
            &fixture->comparison_policy,
            fixture->comparison_policy_root) !=
            ZCL_RETRIEVAL_COMPARISON_OK)
        return false;

    fixture->environment_policy.schema_version =
        VCS_ZCODE_ENVIRONMENT_POLICY_VERSION;
    fixture->environment_policy.min_physical_cores = 2u;
    fixture->environment_policy.min_logical_cores = 4u;
    fixture->environment_policy.min_ram_mib = 1024u;
    if (vcs_zcode_environment_policy_v1_root(
            &fixture->environment_policy,
            fixture->environment_policy_root) != VCS_ZCODE_RECEIPT_OK)
        return false;

    fixture->study.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    rsa_root(fixture->study.hypothesis_root, 0x41u);
    rsa_root(fixture->study.null_hypothesis_root, 0x42u);
    memcpy(fixture->study.source_root, fixture->source_root, 32u);
    rsa_root(fixture->study.dependency_lock_root, 0x43u);
    rsa_root(fixture->study.toolchain_capsule_root, 0x44u);
    rsa_root(fixture->study.protocol_root, 0x45u);
    memcpy(fixture->study.workloads_root, fixture->workload_root, 32u);
    rsa_root(fixture->study.metrics_root, 0x46u);
    rsa_root(fixture->study.estimator_tolerance_root, 0x47u);
    memcpy(fixture->study.environment_policy_root,
           fixture->environment_policy_root, 32u);
    rsa_root(fixture->study.citations_root, 0x49u);
    memcpy(fixture->study.preregistration_policy_root,
           fixture->comparison_policy_root, 32u);
    fixture->study.required_reproductions = 1u;
    fixture->study.required_reviews = 1u;
    fixture->study.sequence = 1u;
    fixture->study.created_unix = 1000;
    fixture->study.expires_unix = 9000;
    if (vcs_zcode_study_spec_root(
            &fixture->study, fixture->study_root) != VCS_ZCODE_SCIENCE_OK)
        return false;

    fixture->task.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(fixture->task.source_root, fixture->source_root, 32u);
    memcpy(fixture->task.dependency_lock_root,
           fixture->study.dependency_lock_root, 32u);
    memcpy(fixture->task.toolchain_capsule_root,
           fixture->study.toolchain_capsule_root, 32u);
    rsa_root(fixture->task.write_scope_root, 0x51u);
    rsa_root(fixture->task.acceptance_tests_root, 0x52u);
    rsa_root(fixture->task.proof_policy_root, 0x53u);
    rsa_root(fixture->task.model_policy_root, 0x54u);
    memcpy(fixture->task.goal_root, fixture->study_root, 32u);
    fixture->task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    fixture->task.max_changed_files = 32u;
    fixture->task.max_patch_bytes = 1024u * 1024u;
    fixture->task.max_context_bytes = 2u * 1024u * 1024u;
    fixture->task.max_cpu_seconds = 120u;
    fixture->task.max_memory_bytes = UINT64_C(512) * 1024u * 1024u;
    fixture->task.max_output_bytes = UINT64_C(64) * 1024u * 1024u;
    fixture->task.expires_unix = fixture->study.expires_unix;
    if (vcs_zcode_task_root(&fixture->task, fixture->task_root) !=
            VCS_ZCODE_DEV_OK)
        return false;

    fixture->candidate.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(fixture->candidate.task_root, fixture->task_root, 32u);
    memcpy(fixture->candidate.base_source_root,
           fixture->source_root, 32u);
    rsa_root(fixture->candidate.adapter_policy_root, 0x63u);
    rsa_root(fixture->candidate.author_pubkey, 0x64u);
    fixture->candidate.sequence = 1u;
    fixture->candidate.created_unix = 1100;
    fixture->hardware_profile.schema_version =
        VCS_ZCODE_HARDWARE_PROFILE_VERSION;
    fixture->hardware_profile.physical_cores = 4u;
    fixture->hardware_profile.logical_cores = 8u;
    fixture->hardware_profile.ram_mib = 8192u;
    fixture->hardware_profile.captured_unix = 1150;
    return vcs_zcode_hardware_profile_validate(&fixture->hardware_profile) ==
               VCS_ZCODE_SCIENCE_OK &&
        rsa_refresh_heuristics(fixture) && rsa_refresh_candidate(fixture);
}

static struct zcode_retrieval_profile_pair_measure_request rsa_measurement(
    const struct rsa_fixture *fixture)
{
    struct zcode_retrieval_profile_pair_measure_request request = {
        .parent_profile = &fixture->parent_profile,
        .child_profile = &fixture->child_profile,
        .feature_snapshot = &fixture->snapshot,
        .feature_rows = fixture->rows,
        .parent_heuristic = &fixture->parent_heuristic,
        .child_heuristic = &fixture->child_heuristic,
        .policy = &fixture->comparison_policy,
        .study = &fixture->study,
        .task_id = "science_pair",
        .query = "find the exact target",
        .relevant_paths = fixture->relevant,
        .relevant_count = 1u,
        .workload_version = ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V2,
    };
    memcpy(request.expected_task_root, fixture->task_root, 32u);
    memcpy(request.expected_source_root, fixture->source_root, 32u);
    memcpy(request.expected_snapshot_source_root,
           fixture->snapshot.source_root, 32u);
    memcpy(request.expected_retrieval_projection_root,
           fixture->projection_root, 32u);
    memcpy(request.expected_study_root, fixture->study_root, 32u);
    memcpy(request.expected_policy_root,
           fixture->comparison_policy_root, 32u);
    memcpy(request.expected_evaluator_root, fixture->evaluator_root, 32u);
    return request;
}

static struct zcode_retrieval_science_result_request rsa_result_request(
    const struct rsa_fixture *fixture,
    const struct zcode_retrieval_profile_pair_measure_request *measurement,
    uint64_t result_sequence, uint8_t challenge_tag)
{
    struct zcode_retrieval_science_result_request request = {
        .measurement = measurement,
        .task = &fixture->task,
        .candidate = &fixture->candidate,
        .environment_policy = &fixture->environment_policy,
        .hardware_profile = &fixture->hardware_profile,
        .action_sequence = 7u,
        .result_sequence = result_sequence,
        .challenge_block_height = 100u,
        .started_unix = 1200,
        .finished_unix = 1201,
        .now_unix = 2000,
    };
    rsa_root(request.challenge_block_hash, challenge_tag);
    return request;
}

static bool rsa_result_refused_unchanged(
    const struct zcode_retrieval_science_result_request *request,
    enum zcode_retrieval_science_adapter_error expected)
{
    struct zcode_retrieval_science_result_bundle out, before;
    memset(&out, 0xa5, sizeof(out));
    before = out;
    return zcode_retrieval_science_result_compose(request, &out) == expected &&
        memcmp(&out, &before, sizeof(out)) == 0;
}

static bool rsa_reproduction_refused_unchanged(
    const struct zcode_retrieval_science_reproduction_request *request,
    enum zcode_retrieval_science_adapter_error expected)
{
    struct zcode_retrieval_science_reproduction_bundle out, before;
    memset(&out, 0xa5, sizeof(out));
    before = out;
    return zcode_retrieval_science_reproduction_compose(request, &out) ==
            expected &&
        memcmp(&out, &before, sizeof(out)) == 0;
}

static int rsa_case_result_compose(void)
{
    int failures = 0;
    struct rsa_fixture fixture;
    bool ready = rsa_fixture_init(
        &fixture, ZCL_RETRIEVAL_COMPARISON_MRR_BP, 100u);
    struct zcode_retrieval_profile_pair_measure_request measurement =
        rsa_measurement(&fixture);
    struct zcode_retrieval_science_result_request request =
        rsa_result_request(&fixture, &measurement, 1u, 0x71u);
    struct zcode_retrieval_science_result_bundle first, repeated;
    bool composed = ready && zcode_retrieval_science_result_compose(
            &request, &first) == ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK &&
        zcode_retrieval_science_result_compose(
            &request, &repeated) == ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
    RSA_CHECK("result composition is deterministic",
              composed && memcmp(first.result_wire, repeated.result_wire,
                                 sizeof(first.result_wire)) == 0 &&
              memcmp(first.observation_wire, repeated.observation_wire,
                     sizeof(first.observation_wire)) == 0 &&
              memcmp(first.result_root, repeated.result_root, 32u) == 0 &&
              memcmp(first.action_root, repeated.action_root, 32u) == 0);

    uint8_t observation_root[32], action_root[32], flags_root[32], env_root[32];
    struct zcl_retrieval_pair_observation_v1 parsed = {0};
    bool observation_exact = composed &&
        zcl_retrieval_pair_observation_parse(
            first.observation_wire, sizeof(first.observation_wire),
            &parsed) == ZCL_RETRIEVAL_PAIR_OBSERVATION_OK &&
        zcl_retrieval_pair_observation_verify(
            &parsed, &fixture.comparison_policy,
            &first.measurement.parent_result,
            &first.measurement.child_result) ==
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK &&
        zcl_retrieval_pair_observation_root(
            &parsed, observation_root) ==
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK &&
        memcmp(observation_root, first.observation_root, 32u) == 0;
    RSA_CHECK("observation wire verifies and re-roots exactly",
              observation_exact);
    struct zcl_retrieval_pair_observation_v1 stale_observation = parsed;
    stale_observation.snapshot_source_root[0] ^= 1u;
    RSA_CHECK("observation carrier refuses stale source generation",
              observation_exact &&
              zcl_retrieval_pair_observation_verify(
                  &stale_observation, &fixture.comparison_policy,
                  &first.measurement.parent_result,
                  &first.measurement.child_result) ==
                  ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING);

    bool action_exact = composed &&
        vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, flags_root) &&
        vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, env_root) &&
        vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &first.action, action_root) &&
        memcmp(action_root, first.action_root, 32u) == 0 &&
        memcmp(first.result.action_root, first.action_root, 32u) == 0 &&
        memcmp(first.action.flags_sha3, flags_root, 32u) == 0 &&
        memcmp(first.action.environment_sha3, env_root, 32u) == 0 &&
        memcmp(first.action.source_cas_sha3,
               fixture.candidate.candidate_source_root, 32u) == 0 &&
        memcmp(first.action.input_root_sha3,
               first.observation.evaluation_input_root, 32u) == 0 &&
        memcmp(first.action.toolchain_capsule_sha3,
               fixture.study.toolchain_capsule_root, 32u) == 0 &&
        strcmp(first.action.profile, "science") == 0;
    RSA_CHECK("fixed action is derived internally from exact inputs",
              action_exact);
    RSA_CHECK("satisfied comparison maps only to OBSERVED",
              composed && first.result.status ==
                  VCS_ZCODE_BENCHMARK_OBSERVED &&
              memcmp(first.result.raw_sample_root,
                     first.observation.evaluation_input_root, 32u) == 0 &&
              memcmp(first.result.evidence_root,
                     first.observation_root, 32u) == 0);
    struct zcode_retrieval_science_result_bundle alias_out, alias_before;
    memset(&alias_out, 0xa5, sizeof(alias_out));
    alias_before = alias_out;
    struct zcode_retrieval_profile_pair_measure_request alias_measure =
        measurement;
    alias_measure.query = (const char *)alias_out.observation_wire;
    struct zcode_retrieval_science_result_request alias_request = request;
    alias_request.measurement = &alias_measure;
    RSA_CHECK("nested output string alias refuses before scanning",
              zcode_retrieval_science_result_compose(
                  &alias_request, &alias_out) ==
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ALIAS &&
              memcmp(&alias_out, &alias_before, sizeof(alias_out)) == 0);
    return failures;
}

static int rsa_case_statuses_and_refusals(void)
{
    int failures = 0;
    struct rsa_fixture negative, incomplete;
    bool negative_ready = rsa_fixture_init(
        &negative, ZCL_RETRIEVAL_COMPARISON_MRR_BP, 9000u);
    bool incomplete_ready = rsa_fixture_init(
        &incomplete, ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP, 0u);
    struct zcode_retrieval_profile_pair_measure_request negative_measure =
        rsa_measurement(&negative);
    struct zcode_retrieval_profile_pair_measure_request incomplete_measure =
        rsa_measurement(&incomplete);
    struct zcode_retrieval_science_result_request negative_request =
        rsa_result_request(&negative, &negative_measure, 1u, 0x72u);
    struct zcode_retrieval_science_result_request incomplete_request =
        rsa_result_request(&incomplete, &incomplete_measure, 1u, 0x73u);
    struct zcode_retrieval_science_result_bundle negative_out, incomplete_out;
    struct zcode_retrieval_profile_pair_measure_request legacy_measure =
        negative_measure;
    legacy_measure.workload_version =
        ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V1;
    struct zcode_retrieval_science_result_request legacy_request =
        rsa_result_request(&negative, &legacy_measure, 1u, 0x70u);
    RSA_CHECK("science adapter refuses cyclic workload v1",
              negative_ready && rsa_result_refused_unchanged(
                  &legacy_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_PARAMETER));
    RSA_CHECK("known failed policy maps to NEGATIVE",
              negative_ready && zcode_retrieval_science_result_compose(
                  &negative_request, &negative_out) ==
                      ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK &&
              negative_out.result.status ==
                  VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT);
    RSA_CHECK("missing selected metric maps to NULL",
              incomplete_ready && zcode_retrieval_science_result_compose(
                  &incomplete_request, &incomplete_out) ==
                      ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK &&
              incomplete_out.result.status ==
                  VCS_ZCODE_BENCHMARK_NULL_RESULT);

    struct rsa_fixture stale;
    bool stale_ready = rsa_fixture_init(
        &stale, ZCL_RETRIEVAL_COMPARISON_MRR_BP, 100u);
    rsa_root(stale.snapshot.source_root, 0x19u);
    stale_ready = stale_ready && rsa_refresh_heuristics(&stale) &&
        rsa_refresh_candidate(&stale);
    struct zcode_retrieval_profile_pair_measure_request stale_measure =
        rsa_measurement(&stale);
    struct zcode_retrieval_science_result_request stale_request =
        rsa_result_request(&stale, &stale_measure, 1u, 0x74u);
    RSA_CHECK("stale snapshot source refuses atomically",
              stale_ready && rsa_result_refused_unchanged(
                  &stale_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING));

    struct rsa_fixture policy_bad = negative;
    policy_bad.comparison_policy.threshold_bp++;
    struct zcode_retrieval_profile_pair_measure_request policy_measure =
        rsa_measurement(&policy_bad);
    struct zcode_retrieval_science_result_request policy_request =
        rsa_result_request(&policy_bad, &policy_measure, 1u, 0x75u);
    RSA_CHECK("post-registration policy mutation refuses atomically",
              rsa_result_refused_unchanged(
                  &policy_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_MEASUREMENT));

    struct rsa_fixture environment_bad = negative;
    environment_bad.environment_policy.min_logical_cores = 9u;
    uint8_t changed_policy_root[32];
    bool environment_ready = vcs_zcode_environment_policy_v1_root(
        &environment_bad.environment_policy, changed_policy_root) ==
        VCS_ZCODE_RECEIPT_OK;
    memcpy(environment_bad.study.environment_policy_root,
           changed_policy_root, 32u);
    environment_ready = environment_ready &&
        vcs_zcode_study_spec_root(
            &environment_bad.study, environment_bad.study_root) ==
            VCS_ZCODE_SCIENCE_OK;
    memcpy(environment_bad.task.goal_root,
           environment_bad.study_root, 32u);
    environment_ready = environment_ready &&
        vcs_zcode_task_root(
            &environment_bad.task, environment_bad.task_root) ==
            VCS_ZCODE_DEV_OK;
    memcpy(environment_bad.candidate.task_root,
           environment_bad.task_root, 32u);
    environment_ready = environment_ready &&
        rsa_refresh_heuristics(&environment_bad) &&
        rsa_refresh_candidate(&environment_bad);
    struct zcode_retrieval_profile_pair_measure_request environment_measure =
        rsa_measurement(&environment_bad);
    struct zcode_retrieval_science_result_request environment_request =
        rsa_result_request(
            &environment_bad, &environment_measure, 1u, 0x76u);
    RSA_CHECK("environment policy rejection is atomic",
              environment_ready && rsa_result_refused_unchanged(
                  &environment_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ENVIRONMENT));

    struct rsa_fixture binding_bad = negative;
    rsa_root(binding_bad.candidate.base_source_root, 0x77u);
    bool binding_ready = vcs_zcode_candidate_root(
        &binding_bad.candidate, binding_bad.candidate_root) ==
        VCS_ZCODE_DEV_OK;
    struct zcode_retrieval_profile_pair_measure_request binding_measure =
        rsa_measurement(&binding_bad);
    struct zcode_retrieval_science_result_request binding_request =
        rsa_result_request(&binding_bad, &binding_measure, 1u, 0x78u);
    RSA_CHECK("candidate source boundary refuses atomically",
              binding_ready && rsa_result_refused_unchanged(
                  &binding_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING));

    struct rsa_fixture unrelated = negative;
    unrelated.candidate.patch_root[0] ^= 1u;
    bool unrelated_ready = vcs_zcode_candidate_root(
        &unrelated.candidate, unrelated.candidate_root) == VCS_ZCODE_DEV_OK;
    struct zcode_retrieval_profile_pair_measure_request unrelated_measure =
        rsa_measurement(&unrelated);
    struct zcode_retrieval_science_result_request unrelated_request =
        rsa_result_request(&unrelated, &unrelated_measure, 1u, 0x79u);
    RSA_CHECK("unrelated candidate cannot claim measured child",
              unrelated_ready && rsa_result_refused_unchanged(
                  &unrelated_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING));
    return failures;
}

static bool rsa_reproduction_request(
    struct rsa_fixture *fixture,
    struct zcode_retrieval_profile_pair_measure_request *original_measure,
    struct zcode_retrieval_profile_pair_measure_request *reproduced_measure,
    struct zcode_retrieval_science_reproduction_request *request,
    struct zcode_retrieval_science_result_bundle *original,
    struct zcode_retrieval_science_result_bundle *reproduced)
{
    *original_measure = rsa_measurement(fixture);
    *reproduced_measure = rsa_measurement(fixture);
    memset(request, 0, sizeof(*request));
    request->original = rsa_result_request(
        fixture, original_measure, 1u, 0x81u);
    request->reproduced = rsa_result_request(
        fixture, reproduced_measure, 2u, 0x82u);
    request->reproducer_pubkey[0] = 1u;
    request->reproduction_sequence = 1u;
    request->created_unix = 1300;
    request->now_unix = 2000;
    if (zcode_retrieval_science_result_compose(
            &request->original, original) !=
            ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK ||
        zcode_retrieval_science_result_compose(
            &request->reproduced, reproduced) !=
            ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK)
        return false;
    memcpy(request->expected_original_result_root,
           original->result_root, 32u);
    memcpy(request->expected_reproduced_result_root,
           reproduced->result_root, 32u);
    return true;
}

static int rsa_case_reproduction(void)
{
    int failures = 0;
    struct rsa_fixture fixture;
    struct zcode_retrieval_profile_pair_measure_request om = {0}, rm = {0};
    struct zcode_retrieval_science_reproduction_request request = {0};
    struct zcode_retrieval_science_result_bundle original = {0};
    struct zcode_retrieval_science_result_bundle reproduced = {0};
    bool ready = rsa_fixture_init(
            &fixture, ZCL_RETRIEVAL_COMPARISON_MRR_BP, 100u) &&
        rsa_reproduction_request(
            &fixture, &om, &rm, &request, &original, &reproduced);
    struct zcode_retrieval_science_reproduction_bundle out;
    bool composed = ready && zcode_retrieval_science_reproduction_compose(
        &request, &out) == ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
    uint8_t reproduction_root[32];
    RSA_CHECK("observed independent result maps to REPLICATED",
              composed && out.reproduction.verdict ==
                  VCS_ZCODE_REPRODUCTION_REPLICATED &&
              memcmp(out.reproduction.original_result_root,
                     original.result_root, 32u) == 0 &&
              memcmp(out.reproduction.reproduced_result_root,
                     reproduced.result_root, 32u) == 0 &&
              memcmp(out.reproduction.comparison_policy_root,
                     fixture.comparison_policy_root, 32u) == 0);
    RSA_CHECK("reproduction wire re-roots exactly",
              composed && vcs_zcode_reproduction_root(
                  &out.reproduction, reproduction_root) ==
                      VCS_ZCODE_SCIENCE_OK &&
              memcmp(reproduction_root, out.reproduction_root, 32u) == 0);

    struct rsa_fixture negative;
    struct zcode_retrieval_profile_pair_measure_request nom, nrm;
    struct zcode_retrieval_science_reproduction_request negative_request;
    struct zcode_retrieval_science_result_bundle no, nr;
    bool negative_ready = rsa_fixture_init(
            &negative, ZCL_RETRIEVAL_COMPARISON_MRR_BP, 9000u) &&
        rsa_reproduction_request(
            &negative, &nom, &nrm, &negative_request, &no, &nr);
    RSA_CHECK("negative original is anchor-ineligible atomically",
              negative_ready && rsa_reproduction_refused_unchanged(
                  &negative_request,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ANCHOR_INELIGIBLE));

    struct zcode_retrieval_science_reproduction_request wrong_root = request;
    wrong_root.expected_reproduced_result_root[0] ^= 1u;
    RSA_CHECK("wrong expected result root refuses atomically",
              rsa_reproduction_refused_unchanged(
                  &wrong_root,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING));

    struct zcode_retrieval_science_reproduction_request duplicate = request;
    duplicate.reproduced = duplicate.original;
    memcpy(duplicate.expected_reproduced_result_root,
           duplicate.expected_original_result_root, 32u);
    RSA_CHECK("identical original and reproduced roots refuse atomically",
              rsa_reproduction_refused_unchanged(
                  &duplicate,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING));

    struct zcode_retrieval_science_reproduction_request wrong_action = request;
    wrong_action.reproduced.action_sequence++;
    struct zcode_retrieval_science_result_bundle changed_action = {0};
    bool changed_ready = zcode_retrieval_science_result_compose(
        &wrong_action.reproduced, &changed_action) ==
        ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
    memcpy(wrong_action.expected_reproduced_result_root,
           changed_action.result_root, 32u);
    RSA_CHECK("changed reproduction action boundary refuses atomically",
              changed_ready && rsa_reproduction_refused_unchanged(
                  &wrong_action,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING));

    struct zcode_retrieval_science_reproduction_request early = request;
    early.created_unix = early.reproduced.finished_unix - 1;
    RSA_CHECK("pre-result reproduction time refuses atomically",
              rsa_reproduction_refused_unchanged(
                  &early,
                  ZCODE_RETRIEVAL_SCIENCE_ADAPTER_REPRODUCTION));
    return failures;
}

int test_retrieval_science_adapter(void)
{
    int failures = 0;
    failures += rsa_case_result_compose();
    failures += rsa_case_statuses_and_refusals();
    failures += rsa_case_reproduction();
    printf("retrieval_science_adapter: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
