/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure, evidence-bound retrieval measurements as science wires. */
#include "services/zcode_retrieval_science_adapter_service.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool rsa_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool rsa_overlaps(const void *left, size_t left_size,
                         const void *right, size_t right_size)
{
    uintptr_t l = (uintptr_t)left, r = (uintptr_t)right;
    if (left_size == 0 || right_size == 0) return false;
    if (l > UINTPTR_MAX - left_size || r > UINTPTR_MAX - right_size)
        return true;
    return l < r + right_size && r < l + left_size;
}

static bool rsa_text_length(const char *text, size_t maximum,
                            size_t *length_out)
{
    if (!text || !length_out) return false;
    size_t length = 0;
    while (length <= maximum && text[length]) length++;
    if (length == 0 || length > maximum) return false;
    *length_out = length;
    return true;
}

static bool rsa_result_reachable_overlaps(
    const struct zcode_retrieval_science_result_request *request,
    const void *output, size_t output_size)
{
    if (!request ||
        rsa_overlaps(output, output_size, request, sizeof(*request)))
        return true;
    const struct zcode_retrieval_profile_pair_measure_request *m =
        request->measurement;
    if (m && rsa_overlaps(output, output_size, m, sizeof(*m))) return true;
    if (!m) return false;
    const void *fixed[] = {
        request->task, request->candidate, request->environment_policy,
        request->hardware_profile, m->parent_profile, m->child_profile,
        m->feature_snapshot, m->parent_heuristic, m->child_heuristic,
        m->policy, m->study,
    };
    const size_t fixed_sizes[] = {
        sizeof(*request->task), sizeof(*request->candidate),
        sizeof(*request->environment_policy),
        sizeof(*request->hardware_profile), sizeof(*m->parent_profile),
        sizeof(*m->child_profile), sizeof(*m->feature_snapshot),
        sizeof(*m->parent_heuristic), sizeof(*m->child_heuristic),
        sizeof(*m->policy), sizeof(*m->study),
    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        if (fixed[i] &&
            rsa_overlaps(output, output_size, fixed[i], fixed_sizes[i]))
            return true;
    if (!request->task || !request->candidate ||
        !request->environment_policy || !request->hardware_profile ||
        !m->parent_profile || !m->child_profile || !m->feature_snapshot ||
        !m->feature_rows || !m->parent_heuristic || !m->child_heuristic ||
        !m->policy || !m->study || !m->task_id || !m->query ||
        !m->relevant_paths)
        return false;
    if (rsa_overlaps(output, output_size, m->feature_rows, 1u) ||
        rsa_overlaps(output, output_size, m->relevant_paths, 1u) ||
        rsa_overlaps(output, output_size, m->task_id, 1u) ||
        rsa_overlaps(output, output_size, m->query, 1u))
        return true;
    size_t row_count = m->feature_snapshot->row_count;
    if (row_count == 0 || row_count > ZCL_RETRIEVAL_EVAL_RANK_MAX ||
        m->relevant_count == 0 ||
        m->relevant_count > ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX)
        return false;
    if (rsa_overlaps(output, output_size, m->feature_rows,
                     row_count * sizeof(*m->feature_rows)) ||
        rsa_overlaps(output, output_size, m->relevant_paths,
                     m->relevant_count * sizeof(*m->relevant_paths)))
        return true;
    size_t task_id_length = 0, query_length = 0;
    if (!rsa_text_length(
            m->task_id, ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX,
            &task_id_length) ||
        !rsa_text_length(
            m->query, ZCL_RETRIEVAL_PAIRED_EVALUATION_QUERY_MAX,
            &query_length))
        return false;
    if (rsa_overlaps(output, output_size, m->task_id, task_id_length + 1u) ||
        rsa_overlaps(output, output_size, m->query, query_length + 1u))
        return true;
    for (size_t i = 0; i < row_count; i++) {
        const char *path = m->feature_rows[i].path;
        if (path && rsa_overlaps(output, output_size, path, 1u)) return true;
        size_t path_length = 0;
        if (!rsa_text_length(path, ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX,
                             &path_length))
            return false;
        if (rsa_overlaps(output, output_size, path, path_length + 1u))
            return true;
    }
    for (size_t i = 0; i < m->relevant_count; i++) {
        const char *path = m->relevant_paths[i];
        if (path && rsa_overlaps(output, output_size, path, 1u)) return true;
        size_t path_length = 0;
        if (!rsa_text_length(path, ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX,
                             &path_length))
            return false;
        if (rsa_overlaps(output, output_size, path, path_length + 1u))
            return true;
    }
    return false;
}

static enum zcode_retrieval_science_adapter_error rsa_boundary_roots(
    const struct zcode_retrieval_science_result_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *measurement,
    uint8_t study_root[32], uint8_t task_root[32], uint8_t candidate_root[32],
    uint8_t policy_root[32], uint8_t hardware_root[32])
{
    const struct zcode_retrieval_profile_pair_measure_request *m =
        request->measurement;
    if (vcs_zcode_study_spec_validate(m->study) != VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_study_spec_root(m->study, study_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        memcmp(study_root, m->expected_study_root, 32u) != 0)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_STUDY;
    if (vcs_zcode_task_validate(request->task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(request->task, task_root) != VCS_ZCODE_DEV_OK ||
        memcmp(task_root, m->expected_task_root, 32u) != 0)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_TASK;
    if (vcs_zcode_candidate_validate(request->candidate) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(request->candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_CANDIDATE;
    if (zcl_retrieval_comparison_policy_v2_root(m->policy, policy_root) !=
            ZCL_RETRIEVAL_COMPARISON_OK ||
        memcmp(policy_root, m->expected_policy_root, 32u) != 0)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_POLICY;
    uint8_t environment_policy_root[32];
    if (vcs_zcode_environment_policy_v1_validate(
            request->environment_policy) != VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_environment_policy_v1_root(
            request->environment_policy, environment_policy_root) !=
            VCS_ZCODE_RECEIPT_OK ||
        memcmp(environment_policy_root,
               m->study->environment_policy_root, 32u) != 0 ||
        vcs_zcode_hardware_profile_validate(request->hardware_profile) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_hardware_profile_root(
            request->hardware_profile, hardware_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        !vcs_zcode_environment_policy_v1_accepts(
            request->environment_policy, request->hardware_profile))
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ENVIRONMENT;
    if (memcmp(m->expected_source_root,
               m->expected_snapshot_source_root, 32u) != 0 ||
        memcmp(m->expected_source_root, m->study->source_root, 32u) != 0 ||
        memcmp(m->expected_source_root, request->task->source_root, 32u) != 0 ||
        memcmp(request->task->goal_root, study_root, 32u) != 0 ||
        memcmp(request->task->dependency_lock_root,
               m->study->dependency_lock_root, 32u) != 0 ||
        memcmp(request->task->toolchain_capsule_root,
               m->study->toolchain_capsule_root, 32u) != 0 ||
        memcmp(request->candidate->task_root, task_root, 32u) != 0 ||
        memcmp(request->candidate->base_source_root,
               request->task->source_root, 32u) != 0 ||
        memcmp(request->candidate->patch_root,
               measurement->child_heuristic_root, 32u) != 0 ||
        memcmp(request->candidate->candidate_source_root,
               m->expected_source_root, 32u) != 0 ||
        memcmp(m->study->preregistration_policy_root, policy_root, 32u) != 0 ||
        memcmp(measurement->comparison.observation.policy_root,
               policy_root, 32u) != 0)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING;
    return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
}

static enum zcode_retrieval_science_adapter_error rsa_action(
    const struct zcode_retrieval_science_result_request *request,
    const uint8_t evaluation_input_root[32],
    struct vcs_build_action_v1 *action,
    uint8_t action_root[32])
{
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_serialize(request->candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_CANDIDATE;
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    struct vcs_build_action_v1 result = {0};
    if (!vcs_build_action_v1_descriptors(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
            &workdir, &output, &resource) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, result.flags_sha3) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, result.environment_sha3))
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ACTION;
    vcs_source_manifest_id(candidate_wire, sizeof(candidate_wire),
                           result.source_sha256);
    memcpy(result.source_cas_sha3,
           request->candidate->candidate_source_root, 32u);
    memcpy(result.input_root_sha3, evaluation_input_root, 32u);
    memcpy(result.toolchain_capsule_sha3,
           request->measurement->study->toolchain_capsule_root, 32u);
    int n1 = snprintf(result.target, sizeof(result.target), "%s",
                      VCS_BUILD_TARGET_V1);
    int n2 = snprintf(result.profile, sizeof(result.profile), "%s", "science");
    int n3 = snprintf(result.virtual_workdir, sizeof(result.virtual_workdir),
                      "%s", workdir);
    int n4 = snprintf(result.declared_outputs, sizeof(result.declared_outputs),
                      "%s", output);
    int n5 = snprintf(result.resource_policy, sizeof(result.resource_policy),
                      "%s", resource);
    if (n1 <= 0 || (size_t)n1 >= sizeof(result.target) ||
        n2 <= 0 || (size_t)n2 >= sizeof(result.profile) ||
        n3 <= 0 || (size_t)n3 >= sizeof(result.virtual_workdir) ||
        n4 <= 0 || (size_t)n4 >= sizeof(result.declared_outputs) ||
        n5 <= 0 || (size_t)n5 >= sizeof(result.resource_policy))
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ACTION;
    result.sequence = request->action_sequence;
    uint8_t root[32];
    if (!vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &result, root))
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ACTION;
    *action = result;
    memcpy(action_root, root, 32u);
    return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
}

static bool rsa_status(uint8_t comparison_status, uint8_t *status)
{
    if (comparison_status == ZCL_RETRIEVAL_COMPARISON_SATISFIED)
        *status = VCS_ZCODE_BENCHMARK_OBSERVED;
    else if (comparison_status == ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED)
        *status = VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT;
    else if (comparison_status == ZCL_RETRIEVAL_COMPARISON_INCOMPLETE)
        *status = VCS_ZCODE_BENCHMARK_NULL_RESULT;
    else
        return false;
    return true;
}

static enum zcode_retrieval_science_adapter_error rsa_observation(
    const struct zcode_retrieval_science_result_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *measurement,
    const uint8_t study_root[32], const uint8_t task_root[32],
    const uint8_t candidate_root[32], const uint8_t action_root[32],
    struct zcl_retrieval_pair_observation_v1 *observation,
    uint8_t wire[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES],
    uint8_t root[32])
{
    const struct zcl_retrieval_comparison_report *comparison =
        &measurement->comparison.observation;
    struct zcl_retrieval_pair_observation_v1 result;
    zcl_retrieval_pair_observation_init(&result);
    result.comparison_status = (uint8_t)comparison->status;
    result.metric = comparison->metric;
    result.direction = comparison->direction;
    result.missing_arms = comparison->missing_arms;
    result.failed_guards = comparison->failed_guards;
    result.directional_delta_bp = comparison->directional_delta_bp;
    memcpy(result.study_root, study_root, 32u);
    memcpy(result.task_root, task_root, 32u);
    memcpy(result.candidate_root, candidate_root, 32u);
    memcpy(result.action_root, action_root, 32u);
    memcpy(result.source_root, request->measurement->expected_source_root, 32u);
    memcpy(result.snapshot_source_root,
           request->measurement->expected_snapshot_source_root, 32u);
    memcpy(result.retrieval_projection_root,
           request->measurement->expected_retrieval_projection_root, 32u);
    memcpy(result.feature_snapshot_root,
           measurement->feature_snapshot_root, 32u);
    memcpy(result.parent_heuristic_root,
           measurement->parent_heuristic_root, 32u);
    memcpy(result.child_heuristic_root,
           measurement->child_heuristic_root, 32u);
    memcpy(result.policy_root, comparison->policy_root, 32u);
    memcpy(result.evaluator_root,
           request->measurement->expected_evaluator_root, 32u);
    memcpy(result.workload_root,
           measurement->paired_evaluation.workload_root, 32u);
    memcpy(result.parent_arm_root,
           measurement->paired_evaluation.parent_arm_root, 32u);
    memcpy(result.child_arm_root,
           measurement->paired_evaluation.child_arm_root, 32u);
    memcpy(result.evaluation_input_root,
           measurement->paired_evaluation.evaluation_input_root, 32u);
    memcpy(result.parent_result_root, measurement->parent_result_root, 32u);
    memcpy(result.child_result_root, measurement->child_result_root, 32u);

    if (zcl_retrieval_pair_observation_validate(&result) !=
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK ||
        zcl_retrieval_pair_observation_verify(
            &result, request->measurement->policy,
            &measurement->parent_result, &measurement->child_result) !=
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK ||
        zcl_retrieval_pair_observation_serialize(&result, wire) !=
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK ||
        zcl_retrieval_pair_observation_root(&result, root) !=
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OBSERVATION;
    *observation = result;
    return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
}

enum zcode_retrieval_science_adapter_error
zcode_retrieval_science_result_compose(
    const struct zcode_retrieval_science_result_request *request,
    struct zcode_retrieval_science_result_bundle *out)
{
    if (!request || !out || !request->measurement || !request->task ||
        !request->candidate || !request->environment_policy ||
        !request->hardware_profile)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_NULL;
    if (request->measurement->workload_version !=
            ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V2 ||
        request->action_sequence == 0 || request->result_sequence == 0 ||
        request->challenge_block_height == 0 ||
        !rsa_root_any(request->challenge_block_hash) ||
        request->started_unix <= 0 ||
        request->finished_unix < request->started_unix ||
        request->finished_unix > request->now_unix)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_PARAMETER;

    if (rsa_result_reachable_overlaps(request, out, sizeof(*out)))
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ALIAS;
    struct zcode_retrieval_science_result_bundle result = {0};
    if (zcode_retrieval_profile_pair_measure(
            request->measurement, &result.measurement) !=
            ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_MEASUREMENT;

    uint8_t study_root[32], task_root[32], candidate_root[32];
    uint8_t policy_root[32], hardware_root[32];
    enum zcode_retrieval_science_adapter_error error = rsa_boundary_roots(
        request, &result.measurement, study_root, task_root, candidate_root,
        policy_root, hardware_root);
    if (error != ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK) return error;
    error = rsa_action(
        request, result.measurement.paired_evaluation.evaluation_input_root,
        &result.action, result.action_root);
    if (error != ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK) return error;

    if (zcl_retrieval_experiment_eval_result_serialize(
            &result.measurement.parent_result,
            result.parent_retrieval_result_wire) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_serialize(
            &result.measurement.child_result,
            result.child_retrieval_result_wire) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OBSERVATION;

    error = rsa_observation(
        request, &result.measurement, study_root, task_root, candidate_root,
        result.action_root, &result.observation, result.observation_wire,
        result.observation_root);
    if (error != ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK) return error;

    struct vcs_zcode_benchmark_result_v1 science = {
        .schema_version = VCS_ZCODE_SCIENCE_VERSION,
        .challenge_block_height = request->challenge_block_height,
        .sequence = request->result_sequence,
        .started_unix = request->started_unix,
        .finished_unix = request->finished_unix,
    };
    memcpy(science.study_root, study_root, 32u);
    memcpy(science.task_root, task_root, 32u);
    memcpy(science.candidate_root, candidate_root, 32u);
    memcpy(science.action_root, result.action_root, 32u);
    memcpy(science.achieved_environment_root, hardware_root, 32u);
    memcpy(science.raw_sample_root,
           result.measurement.paired_evaluation.evaluation_input_root, 32u);
    memcpy(science.evidence_root, result.observation_root, 32u);
    memcpy(science.challenge_block_hash, request->challenge_block_hash, 32u);
    if (!rsa_status(
            (uint8_t)result.measurement.comparison.observation.status,
            &science.status) ||
        vcs_zcode_benchmark_result_validate_for_study(
            request->measurement->study, request->task, request->candidate,
            &result.action, &science, request->now_unix) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_benchmark_result_serialize(
            &science, result.result_wire) != VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_benchmark_result_root(&science, result.result_root) !=
            VCS_ZCODE_SCIENCE_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_RESULT;
    result.result = science;
    *out = result;
    return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
}

static bool rsa_shared_boundary(
    const struct zcode_retrieval_science_result_bundle *original,
    const struct zcode_retrieval_science_result_bundle *reproduced)
{
    const struct zcl_retrieval_pair_observation_v1 *a =
        &original->observation;
    const struct zcl_retrieval_pair_observation_v1 *b =
        &reproduced->observation;
    const uint8_t *const left[] = {
        a->study_root, a->task_root, a->candidate_root, a->action_root,
        a->source_root, a->snapshot_source_root,
        a->retrieval_projection_root, a->feature_snapshot_root,
        a->parent_heuristic_root, a->child_heuristic_root,
        a->policy_root, a->evaluator_root, a->workload_root,
    };
    const uint8_t *const right[] = {
        b->study_root, b->task_root, b->candidate_root, b->action_root,
        b->source_root, b->snapshot_source_root,
        b->retrieval_projection_root, b->feature_snapshot_root,
        b->parent_heuristic_root, b->child_heuristic_root,
        b->policy_root, b->evaluator_root, b->workload_root,
    };
    for (size_t i = 0; i < sizeof(left) / sizeof(left[0]); i++)
        if (memcmp(left[i], right[i], 32u) != 0) return false;
    return true;
}

static bool rsa_reproduction_verdict(uint8_t status, uint8_t *verdict)
{
    if (status == VCS_ZCODE_BENCHMARK_OBSERVED)
        *verdict = VCS_ZCODE_REPRODUCTION_REPLICATED;
    else if (status == VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT)
        *verdict = VCS_ZCODE_REPRODUCTION_CONTRADICTED;
    else if (status == VCS_ZCODE_BENCHMARK_NULL_RESULT ||
             status == VCS_ZCODE_BENCHMARK_EXECUTION_FAILED)
        *verdict = VCS_ZCODE_REPRODUCTION_INCONCLUSIVE;
    else
        return false;
    return true;
}

enum zcode_retrieval_science_adapter_error
zcode_retrieval_science_reproduction_compose(
    const struct zcode_retrieval_science_reproduction_request *request,
    struct zcode_retrieval_science_reproduction_bundle *out)
{
    if (!request || !out)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_NULL;
    if (!rsa_root_any(request->expected_original_result_root) ||
        !rsa_root_any(request->expected_reproduced_result_root) ||
        !rsa_root_any(request->reproducer_pubkey) ||
        request->reproduction_sequence == 0 || request->created_unix <= 0 ||
        request->now_unix <= 0)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_PARAMETER;
    struct zcode_retrieval_science_reproduction_bundle result = {0};
    enum zcode_retrieval_science_adapter_error error =
        zcode_retrieval_science_result_compose(&request->original,
                                               &result.original);
    if (error != ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK) return error;
    error = zcode_retrieval_science_result_compose(&request->reproduced,
                                                   &result.reproduced);
    if (error != ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK) return error;
    if (rsa_overlaps(out, sizeof(*out), request, sizeof(*request)) ||
        rsa_result_reachable_overlaps(&request->original, out, sizeof(*out)) ||
        rsa_result_reachable_overlaps(&request->reproduced, out, sizeof(*out)))
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ALIAS;
    if (memcmp(result.original.result_root,
               request->expected_original_result_root, 32u) != 0 ||
        memcmp(result.reproduced.result_root,
               request->expected_reproduced_result_root, 32u) != 0 ||
        memcmp(result.original.result_root,
               result.reproduced.result_root, 32u) == 0 ||
        !rsa_shared_boundary(&result.original, &result.reproduced) ||
        memcmp(result.original.observation_root,
               result.reproduced.observation_root, 32u) != 0)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING;
    if (result.original.result.status != VCS_ZCODE_BENCHMARK_OBSERVED)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ANCHOR_INELIGIBLE;

    struct vcs_zcode_reproduction_v1 reproduction = {
        .schema_version = VCS_ZCODE_SCIENCE_VERSION,
        .sequence = request->reproduction_sequence,
        .created_unix = request->created_unix,
    };
    memcpy(reproduction.study_root,
           result.original.result.study_root, 32u);
    memcpy(reproduction.original_result_root,
           result.original.result_root, 32u);
    memcpy(reproduction.reproduced_result_root,
           result.reproduced.result_root, 32u);
    memcpy(reproduction.comparison_policy_root,
           result.original.observation.policy_root, 32u);
    memcpy(reproduction.original_environment_root,
           result.original.result.achieved_environment_root, 32u);
    memcpy(reproduction.reproduced_environment_root,
           result.reproduced.result.achieved_environment_root, 32u);
    memcpy(reproduction.reproducer_pubkey, request->reproducer_pubkey, 32u);
    if (!rsa_reproduction_verdict(
            result.reproduced.result.status, &reproduction.verdict) ||
        vcs_zcode_reproduction_validate_for_results(
            request->original.measurement->study,
            &result.original.result, &result.reproduced.result,
            &reproduction, request->now_unix) != VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_reproduction_serialize(
            &reproduction, result.reproduction_wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_reproduction_root(
            &reproduction, result.reproduction_root) !=
            VCS_ZCODE_SCIENCE_OK)
        return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_REPRODUCTION;
    result.reproduction = reproduction;
    *out = result;
    return ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
}

const char *zcode_retrieval_science_adapter_error_string(
    enum zcode_retrieval_science_adapter_error error)
{
    switch (error) {
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK: return "ok";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_NULL: return "null argument";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ALIAS:
        return "output aliases reachable input";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_PARAMETER:
        return "invalid run parameter";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_MEASUREMENT:
        return "retrieval pair measurement refused";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_STUDY: return "invalid study";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_TASK: return "invalid task";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_CANDIDATE:
        return "invalid candidate";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_POLICY: return "invalid policy";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ENVIRONMENT:
        return "environment policy refused profile";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ACTION:
        return "fixed benchmark action derivation failed";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OBSERVATION:
        return "retrieval observation composition failed";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_RESULT:
        return "science result composition failed";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_ANCHOR_INELIGIBLE:
        return "original result is not an observed anchor";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_BINDING:
        return "scientific boundary mismatch";
    case ZCODE_RETRIEVAL_SCIENCE_ADAPTER_REPRODUCTION:
        return "reproduction composition failed";
    }
    return "unknown retrieval science adapter error";
}
