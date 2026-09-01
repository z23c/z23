/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: derive and compare one exact retrieval-profile evaluation pair. */
#include "services/zcode_retrieval_profile_pair_measure_service.h"

#include "vcs/zcode_science.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool measure_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool measure_overlaps(const void *left, size_t left_size,
                             const void *right, size_t right_size)
{
    uintptr_t l = (uintptr_t)left, r = (uintptr_t)right;
    if (left_size == 0 || right_size == 0) return false;
    if (l > UINTPTR_MAX - left_size || r > UINTPTR_MAX - right_size)
        return true;
    return l < r + right_size && r < l + left_size;
}

static bool measure_text_length(const char *text, size_t maximum,
                                size_t *length_out)
{
    if (!text || !length_out) return false;
    size_t length = 0;
    while (length <= maximum && text[length]) length++;
    if (length == 0 || length > maximum) return false;
    *length_out = length;
    return true;
}

static bool measure_output_contains(
    const struct zcode_retrieval_profile_pair_measure_report *report,
    const void *input, size_t input_size)
{
    return measure_overlaps(report, sizeof(*report), input, input_size);
}

static bool measure_fixed_output_aliases(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *report)
{
    return measure_output_contains(
               report, request->parent_profile,
               sizeof(*request->parent_profile)) ||
        measure_output_contains(
               report, request->child_profile,
               sizeof(*request->child_profile)) ||
        measure_output_contains(
               report, request->feature_snapshot,
               sizeof(*request->feature_snapshot)) ||
        measure_output_contains(
               report, request->parent_heuristic,
               sizeof(*request->parent_heuristic)) ||
        measure_output_contains(
               report, request->child_heuristic,
               sizeof(*request->child_heuristic)) ||
        measure_output_contains(
               report, request->policy, sizeof(*request->policy)) ||
        measure_output_contains(
               report, request->study, sizeof(*request->study)) ||
        measure_output_contains(report, request->task_id, 1u) ||
        measure_output_contains(report, request->query, 1u) ||
        measure_output_contains(report, request->relevant_paths, 1u) ||
        measure_output_contains(report, request->feature_rows, 1u);
}

static bool measure_evaluator_member(
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const uint8_t evaluator_root[32])
{
    for (size_t i = 0; i < heuristic->evaluator_count; i++)
        if (memcmp(heuristic->evaluator_roots[i], evaluator_root, 32u) == 0)
            return true;
    return false;
}

static bool measure_boundary_equal(
    const struct vcs_zcode_heuristic_v1 *parent,
    const struct vcs_zcode_heuristic_v1 *child)
{
    return memcmp(parent->task_root, child->task_root, 32u) == 0 &&
        memcmp(parent->source_root, child->source_root, 32u) == 0 &&
        memcmp(parent->study_root, child->study_root, 32u) == 0 &&
        memcmp(parent->preregistration_root,
               child->preregistration_root, 32u) == 0 &&
        parent->evaluator_count == child->evaluator_count &&
        memcmp(parent->evaluator_roots, child->evaluator_roots,
               sizeof(parent->evaluator_roots)) == 0;
}

static enum zcode_retrieval_profile_pair_measure_error measure_project(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 *rows,
    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX],
    struct zcl_retrieval_profile_report *projection)
{
    enum zcl_retrieval_experiment_error error = zcl_retrieval_profile_project(
        profile, snapshot, rows, indices, ZCL_RETRIEVAL_EVAL_RANK_MAX,
        projection);
    if (error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_INCOMPLETE;
    return error == ZCL_RETRIEVAL_EXPERIMENT_OK
        ? ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK
        : ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PROFILE;
}

static bool measure_top20_preserved(
    const size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX], size_t row_count,
    bool ranking_complete)
{
    if (row_count < 20u && !ranking_complete) return false;
    size_t top = row_count < 20u ? row_count : 20u;
    for (size_t baseline = 0; baseline < top; baseline++) {
        bool found = false;
        for (size_t candidate = 0; candidate < top; candidate++)
            if (indices[candidate] == baseline) {
                found = true;
                break;
            }
        if (!found) return false;
    }
    return true;
}

static void measure_eval_report(
    const struct zcl_retrieval_eval_metrics *metrics,
    const struct zcl_retrieval_profile_report *projection,
    const size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX], size_t row_count,
    bool ranking_complete,
    struct zcl_retrieval_experiment_eval_report *report)
{
    *report = (struct zcl_retrieval_experiment_eval_report){
        .metrics = *metrics,
        .fallback_tasks = projection->used_baseline_fallback ? 1u : 0u,
        .top20_membership_preserved = measure_top20_preserved(
            indices, row_count, ranking_complete),
        .full_retained_set_preserved = projection->retained_set_preserved,
        .context_ceiling_preserved =
            projection->candidate_context_bytes_at_top <=
            projection->baseline_context_bytes_at_top,
    };
    size_t top = row_count < ZCL_RETRIEVAL_EXPERIMENT_TOP
        ? row_count : ZCL_RETRIEVAL_EXPERIMENT_TOP;
    for (size_t i = 0; i < top; i++)
        if (indices[i] != i) report->changed_positions_at_5++;
}

static bool measure_proposal_root(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const uint8_t profile_root[32], const uint8_t snapshot_root[32],
    const uint8_t candidate_root[32], uint8_t out[32])
{
    return zcl_retrieval_profile_proposal_input_root(
        request->expected_source_root,
        request->feature_snapshot->source_root,
        request->feature_snapshot->codeindex_root,
        request->task_id, request->query,
        request->feature_snapshot->baseline_ranking_root,
        profile_root, snapshot_root, candidate_root,
        request->expected_study_root, request->expected_policy_root,
        request->expected_evaluator_root, out);
}

enum zcode_retrieval_profile_pair_measure_error
zcode_retrieval_profile_pair_measure(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    struct zcode_retrieval_profile_pair_measure_report *report)
{
    if (!request || !report)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_NULL;
    if (measure_output_contains(report, request, sizeof(*request)))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    if (!request->parent_profile ||
        !request->child_profile || !request->feature_snapshot ||
        !request->feature_rows || !request->parent_heuristic ||
        !request->child_heuristic || !request->policy || !request->study ||
        !request->task_id || !request->query || !request->relevant_paths)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_NULL;
    if (measure_fixed_output_aliases(request, report))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    if (request->relevant_count == 0 ||
        request->relevant_count > ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER;
    if (measure_output_contains(
            report, request->relevant_paths,
            request->relevant_count * sizeof(*request->relevant_paths)))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    if (request->parent_profile->top_k != ZCL_RETRIEVAL_EXPERIMENT_TOP ||
        request->child_profile->top_k != ZCL_RETRIEVAL_EXPERIMENT_TOP)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER;
    size_t row_count = request->feature_snapshot->row_count;
    if (row_count == 0 || row_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT;
    if (measure_output_contains(
            report, request->feature_rows,
            row_count * sizeof(*request->feature_rows)))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    for (size_t i = 0; i < request->relevant_count; i++) {
        const char *path = request->relevant_paths[i];
        if (!path) return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER;
        if (measure_output_contains(report, path, 1u))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    }
    for (size_t i = 0; i < row_count; i++) {
        const char *path = request->feature_rows[i].path;
        if (!path) return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT;
        if (measure_output_contains(report, path, 1u))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    }
    size_t task_id_length = 0, query_length = 0;
    if (!measure_text_length(
            request->task_id,
            ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX, &task_id_length) ||
        !measure_text_length(
            request->query,
            ZCL_RETRIEVAL_PAIRED_EVALUATION_QUERY_MAX, &query_length))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER;
    if (measure_output_contains(
            report, request->task_id, task_id_length + 1u) ||
        measure_output_contains(report, request->query, query_length + 1u))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    for (size_t i = 0; i < request->relevant_count; i++) {
        size_t path_length = 0;
        if (!measure_text_length(
                request->relevant_paths[i],
                ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX,
                &path_length))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER;
        if (measure_output_contains(
                report, request->relevant_paths[i], path_length + 1u))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    }
    for (size_t i = 0; i < row_count; i++) {
        size_t path_length = 0;
        if (!measure_text_length(
                request->feature_rows[i].path,
                ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX,
                &path_length))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT;
        if (measure_output_contains(
                report, request->feature_rows[i].path, path_length + 1u))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS;
    }

    const uint8_t *roots[] = {
        request->expected_task_root, request->expected_source_root,
        request->expected_snapshot_source_root,
        request->expected_retrieval_projection_root,
        request->expected_study_root, request->expected_policy_root,
        request->expected_evaluator_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!measure_root_any(roots[i]))
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ROOT;

    struct zcode_retrieval_profile_pair_measure_report result = {0};
    uint8_t study_root[32];
    if (vcs_zcode_study_spec_root(request->study, study_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        memcmp(study_root, request->expected_study_root, 32u) != 0 ||
        memcmp(request->study->source_root,
               request->expected_source_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING;

    uint8_t parent_profile_root[32], child_profile_root[32], query_root[32];
    if (zcl_retrieval_profile_root(
            request->parent_profile, parent_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_root(
            request->child_profile, child_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PROFILE;
    if (memcmp(parent_profile_root, child_profile_root, 32u) == 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING;
    if (zcl_retrieval_query_root(request->query, query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        memcmp(query_root, request->feature_snapshot->query_root, 32u) != 0 ||
        memcmp(request->expected_snapshot_source_root,
               request->feature_snapshot->source_root, 32u) != 0 ||
        memcmp(request->expected_retrieval_projection_root,
               request->feature_snapshot->codeindex_root, 32u) != 0 ||
        zcl_retrieval_feature_snapshot_root(
            request->feature_snapshot, request->feature_rows,
            result.feature_snapshot_root) != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT;

    if (vcs_zcode_heuristic_root(
            request->parent_heuristic, result.parent_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_heuristic_root(
            request->child_heuristic, result.child_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_HEURISTIC;
    if (request->child_heuristic->derivation !=
            VCS_ZCODE_HEURISTIC_SPECIALIZE ||
        vcs_zcode_heuristic_validate_derivation(
            request->child_heuristic, request->parent_heuristic, 1u) !=
            VCS_ZCODE_ATTENTION_OK ||
        !measure_boundary_equal(request->parent_heuristic,
                                request->child_heuristic) ||
        memcmp(result.parent_heuristic_root,
               result.child_heuristic_root, 32u) == 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_LINEAGE;

    uint8_t policy_root[32];
    if (zcl_retrieval_comparison_policy_v2_root(
            request->policy, policy_root) != ZCL_RETRIEVAL_COMPARISON_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_POLICY;
    if (request->policy->evaluation_kind !=
            ZCL_RETRIEVAL_COMPARISON_DERIVED_PROFILE_PAIRED_V1 ||
        request->policy->expected_tasks != 1u ||
        memcmp(policy_root, request->expected_policy_root, 32u) != 0 ||
        memcmp(request->policy->evaluator_root,
               request->expected_evaluator_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->preregistration_root,
               request->expected_policy_root, 32u) != 0 ||
        memcmp(request->child_heuristic->preregistration_root,
               request->expected_policy_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_POLICY;
    if (memcmp(request->parent_heuristic->task_root,
               request->expected_task_root, 32u) != 0 ||
        memcmp(request->child_heuristic->task_root,
               request->expected_task_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->source_root,
               request->expected_source_root, 32u) != 0 ||
        memcmp(request->child_heuristic->source_root,
               request->expected_source_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->study_root,
               request->expected_study_root, 32u) != 0 ||
        memcmp(request->child_heuristic->study_root,
               request->expected_study_root, 32u) != 0 ||
        !measure_evaluator_member(request->parent_heuristic,
                                  request->expected_evaluator_root) ||
        !measure_evaluator_member(request->child_heuristic,
                                  request->expected_evaluator_root))
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING;

    size_t parent_indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    size_t child_indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    enum zcode_retrieval_profile_pair_measure_error error = measure_project(
        request->parent_profile, request->feature_snapshot,
        request->feature_rows, parent_indices, &result.parent_projection);
    if (error != ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK) return error;
    error = measure_project(
        request->child_profile, request->feature_snapshot,
        request->feature_rows, child_indices, &result.child_projection);
    if (error != ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK) return error;

    uint8_t parent_proposal_root[32], child_proposal_root[32];
    if (memcmp(request->parent_heuristic->proposed_rule_root,
               parent_profile_root, 32u) != 0 ||
        memcmp(request->child_heuristic->proposed_rule_root,
               child_profile_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->observed_features_root,
               result.feature_snapshot_root, 32u) != 0 ||
        memcmp(request->child_heuristic->observed_features_root,
               result.feature_snapshot_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->expected_effect_root,
               result.parent_projection.candidate_ranking_root, 32u) != 0 ||
        memcmp(request->child_heuristic->expected_effect_root,
               result.child_projection.candidate_ranking_root, 32u) != 0 ||
        !measure_proposal_root(
            request, parent_profile_root, result.feature_snapshot_root,
            result.parent_projection.candidate_ranking_root,
            parent_proposal_root) ||
        !measure_proposal_root(
            request, child_profile_root, result.feature_snapshot_root,
            result.child_projection.candidate_ranking_root,
            child_proposal_root) ||
        memcmp(parent_proposal_root,
               request->parent_heuristic->proposal_input_root, 32u) != 0 ||
        memcmp(child_proposal_root,
               request->child_heuristic->proposal_input_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING;

    struct zcl_retrieval_evaluation_workload_task_v1 workload = {
        .task_id = request->task_id,
        .query = request->query,
        .relevant_paths = request->relevant_paths,
        .relevant_count = request->relevant_count,
    };
    uint8_t workload_root[32];
    if (zcl_retrieval_evaluation_workload_root(
            &workload, 1u, request->expected_task_root,
            request->expected_source_root,
            request->expected_retrieval_projection_root,
            workload_root) != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_WORKLOAD;
    if (memcmp(workload_root, request->policy->workload_root, 32u) != 0 ||
        memcmp(request->study->workloads_root, workload_root, 32u) != 0 ||
        memcmp(request->study->preregistration_policy_root,
               request->expected_policy_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING;

    struct zcl_retrieval_ranked_file
        parent_ranked[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {{0}};
    struct zcl_retrieval_ranked_file
        child_ranked[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {{0}};
    for (size_t i = 0; i < row_count; i++) {
        if (parent_indices[i] >= row_count || child_indices[i] >= row_count)
            return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_EVALUATION;
        parent_ranked[i] = (struct zcl_retrieval_ranked_file){
            .path = request->feature_rows[parent_indices[i]].path,
            .context_bytes =
                request->feature_rows[parent_indices[i]].context_bytes,
            .in_scope = false,
            .in_scope_available = false,
        };
        child_ranked[i] = (struct zcl_retrieval_ranked_file){
            .path = request->feature_rows[child_indices[i]].path,
            .context_bytes =
                request->feature_rows[child_indices[i]].context_bytes,
            .in_scope = false,
            .in_scope_available = false,
        };
    }
    struct zcl_retrieval_paired_evaluation_task_v1 paired_task = {
        .task_id = request->task_id,
        .query = request->query,
        .relevant_paths = request->relevant_paths,
        .relevant_count = request->relevant_count,
        .parent_ranked = parent_ranked,
        .parent_count = row_count,
        .parent_complete = request->feature_snapshot->ranking_complete,
        .child_ranked = child_ranked,
        .child_count = row_count,
        .child_complete = request->feature_snapshot->ranking_complete,
    };
    if (zcl_retrieval_paired_evaluate(
            &paired_task, 1u, request->expected_task_root,
            request->expected_source_root,
            request->expected_retrieval_projection_root,
            &result.paired_evaluation) != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_EVALUATION;
    if (memcmp(result.paired_evaluation.workload_root,
               workload_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_EVALUATION;

    struct zcl_retrieval_experiment_eval_report parent_eval, child_eval;
    measure_eval_report(
        &result.paired_evaluation.parent_metrics, &result.parent_projection,
        parent_indices, row_count, request->feature_snapshot->ranking_complete,
        &parent_eval);
    measure_eval_report(
        &result.paired_evaluation.child_metrics, &result.child_projection,
        child_indices, row_count, request->feature_snapshot->ranking_complete,
        &child_eval);
    if (zcl_retrieval_experiment_eval_result_init(
            &result.parent_result, &parent_eval,
            result.parent_heuristic_root,
            request->parent_heuristic->proposal_input_root,
            result.paired_evaluation.evaluation_input_root,
            request->expected_evaluator_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_init(
            &result.child_result, &child_eval,
            result.child_heuristic_root,
            request->child_heuristic->proposal_input_root,
            result.paired_evaluation.evaluation_input_root,
            request->expected_evaluator_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_root(
            &result.parent_result, result.parent_result_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_root(
            &result.child_result, result.child_result_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_EVALUATION;

    struct zcl_retrieval_comparison_arm_binding parent_binding = {0};
    struct zcl_retrieval_comparison_arm_binding child_binding = {0};
    memcpy(parent_binding.subject_root, result.parent_heuristic_root, 32u);
    memcpy(parent_binding.proposal_input_root,
           request->parent_heuristic->proposal_input_root, 32u);
    memcpy(parent_binding.result_root, result.parent_result_root, 32u);
    memcpy(child_binding.subject_root, result.child_heuristic_root, 32u);
    memcpy(child_binding.proposal_input_root,
           request->child_heuristic->proposal_input_root, 32u);
    memcpy(child_binding.result_root, result.child_result_root, 32u);
    uint8_t evaluation_input_root[32];
    memcpy(evaluation_input_root,
           result.paired_evaluation.evaluation_input_root, 32u);
    if (zcl_retrieval_comparison_observe_v2(
            request->policy, request->expected_policy_root,
            &result.paired_evaluation, evaluation_input_root,
            &result.parent_result, &parent_binding,
            &result.child_result, &child_binding,
            &result.comparison) != ZCL_RETRIEVAL_COMPARISON_OK)
        return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_COMPARISON;
    *report = result;
    return ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK;
}

const char *zcode_retrieval_profile_pair_measure_error_string(
    enum zcode_retrieval_profile_pair_measure_error error)
{
    switch (error) {
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK: return "ok";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_NULL: return "null argument";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS:
        return "output aliases reachable input";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER:
        return "invalid bounded input";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ROOT:
        return "required root is zero";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PROFILE:
        return "profile projection refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT:
        return "feature snapshot refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_INCOMPLETE:
        return "required feature evidence is incomplete";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_HEURISTIC:
        return "heuristic refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_LINEAGE:
        return "immediate specialization lineage refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_POLICY:
        return "derived comparison policy refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_WORKLOAD:
        return "evaluation workload refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING:
        return "exact input binding mismatch";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_EVALUATION:
        return "derived paired evaluation refused";
    case ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_COMPARISON:
        return "derived comparison refused";
    }
    return "unknown retrieval profile pair measurement error";
}
