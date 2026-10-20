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

/* Working state shared by the measurement stages. */
struct pm_state {
    const struct zcode_retrieval_profile_pair_measure_request *request;
    struct zcode_retrieval_profile_pair_measure_report result;
    size_t row_count;
    uint8_t parent_profile_root[32];
    uint8_t child_profile_root[32];
    size_t parent_indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    size_t child_indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    uint8_t workload_root[32];
};

#define PM_ERR(name) ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_##name

static bool pm_request_incomplete(
    const struct zcode_retrieval_profile_pair_measure_request *request)
{
    return !request->parent_profile ||
        !request->child_profile || !request->feature_snapshot ||
        !request->feature_rows || !request->parent_heuristic ||
        !request->child_heuristic || !request->policy || !request->study ||
        !request->task_id || !request->query || !request->relevant_paths;
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_pointers(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *report)
{
    if (!request || !report) return PM_ERR(NULL);
    if (measure_output_contains(report, request, sizeof(*request)))
        return PM_ERR(ALIAS);
    if (pm_request_incomplete(request)) return PM_ERR(NULL);
    if (measure_fixed_output_aliases(request, report)) return PM_ERR(ALIAS);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_bounds(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *report,
    size_t *row_count_out)
{
    if (request->relevant_count == 0 ||
        request->relevant_count > ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX)
        return PM_ERR(PARAMETER);
    if (measure_output_contains(
            report, request->relevant_paths,
            request->relevant_count * sizeof(*request->relevant_paths)))
        return PM_ERR(ALIAS);
    if (request->parent_profile->top_k != ZCL_RETRIEVAL_EXPERIMENT_TOP ||
        request->child_profile->top_k != ZCL_RETRIEVAL_EXPERIMENT_TOP)
        return PM_ERR(PARAMETER);
    size_t row_count = request->feature_snapshot->row_count;
    if (row_count == 0 || row_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return PM_ERR(SNAPSHOT);
    if (measure_output_contains(
            report, request->feature_rows,
            row_count * sizeof(*request->feature_rows)))
        return PM_ERR(ALIAS);
    *row_count_out = row_count;
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_path_pointers(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *report,
    size_t row_count)
{
    for (size_t i = 0; i < request->relevant_count; i++) {
        const char *path = request->relevant_paths[i];
        if (!path) return PM_ERR(PARAMETER);
        if (measure_output_contains(report, path, 1u)) return PM_ERR(ALIAS);
    }
    for (size_t i = 0; i < row_count; i++) {
        const char *path = request->feature_rows[i].path;
        if (!path) return PM_ERR(SNAPSHOT);
        if (measure_output_contains(report, path, 1u)) return PM_ERR(ALIAS);
    }
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_text(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *report,
    size_t row_count)
{
    size_t task_id_length = 0, query_length = 0;
    if (!measure_text_length(
            request->task_id,
            ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX, &task_id_length) ||
        !measure_text_length(
            request->query,
            ZCL_RETRIEVAL_PAIRED_EVALUATION_QUERY_MAX, &query_length))
        return PM_ERR(PARAMETER);
    if (measure_output_contains(
            report, request->task_id, task_id_length + 1u) ||
        measure_output_contains(report, request->query, query_length + 1u))
        return PM_ERR(ALIAS);
    for (size_t i = 0; i < request->relevant_count; i++) {
        size_t path_length = 0;
        if (!measure_text_length(
                request->relevant_paths[i],
                ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX, &path_length))
            return PM_ERR(PARAMETER);
        if (measure_output_contains(
                report, request->relevant_paths[i], path_length + 1u))
            return PM_ERR(ALIAS);
    }
    for (size_t i = 0; i < row_count; i++) {
        size_t path_length = 0;
        if (!measure_text_length(
                request->feature_rows[i].path,
                ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX, &path_length))
            return PM_ERR(SNAPSHOT);
        if (measure_output_contains(
                report, request->feature_rows[i].path, path_length + 1u))
            return PM_ERR(ALIAS);
    }
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_roots(
    const struct zcode_retrieval_profile_pair_measure_request *request)
{
    const uint8_t *roots[] = {
        request->expected_task_root, request->expected_source_root,
        request->expected_snapshot_source_root,
        request->expected_retrieval_projection_root,
        request->expected_study_root, request->expected_policy_root,
        request->expected_evaluator_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!measure_root_any(roots[i])) return PM_ERR(ROOT);
    if (request->workload_version !=
            ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V1 &&
        request->workload_version !=
            ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V2)
        return PM_ERR(PARAMETER);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_validate_input(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    const struct zcode_retrieval_profile_pair_measure_report *report,
    size_t *row_count)
{
    enum zcode_retrieval_profile_pair_measure_error error =
        pm_check_pointers(request, report);
    if (error != PM_ERR(OK)) return error;
    error = pm_check_bounds(request, report, row_count);
    if (error != PM_ERR(OK)) return error;
    error = pm_check_path_pointers(request, report, *row_count);
    if (error != PM_ERR(OK)) return error;
    error = pm_check_text(request, report, *row_count);
    if (error != PM_ERR(OK)) return error;
    return pm_check_roots(request);
}

static enum zcode_retrieval_profile_pair_measure_error pm_bind_study(
    const struct zcode_retrieval_profile_pair_measure_request *request)
{
    uint8_t study_root[32];
    if (vcs_zcode_study_spec_root(request->study, study_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        memcmp(study_root, request->expected_study_root, 32u) != 0 ||
        memcmp(request->study->source_root,
               request->expected_source_root, 32u) != 0)
        return PM_ERR(BINDING);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_bind_profiles(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    uint8_t query_root[32];
    if (zcl_retrieval_profile_root(
            request->parent_profile, st->parent_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_root(
            request->child_profile, st->child_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return PM_ERR(PROFILE);
    if (memcmp(st->parent_profile_root, st->child_profile_root, 32u) == 0)
        return PM_ERR(BINDING);
    if (zcl_retrieval_query_root(request->query, query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        memcmp(query_root, request->feature_snapshot->query_root, 32u) != 0 ||
        memcmp(request->expected_snapshot_source_root,
               request->feature_snapshot->source_root, 32u) != 0 ||
        memcmp(request->expected_retrieval_projection_root,
               request->feature_snapshot->codeindex_root, 32u) != 0 ||
        zcl_retrieval_feature_snapshot_root(
            request->feature_snapshot, request->feature_rows,
            st->result.feature_snapshot_root) != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return PM_ERR(SNAPSHOT);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_lineage(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    if (vcs_zcode_heuristic_root(
            request->parent_heuristic, st->result.parent_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_heuristic_root(
            request->child_heuristic, st->result.child_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return PM_ERR(HEURISTIC);
    if (request->child_heuristic->derivation !=
            VCS_ZCODE_HEURISTIC_SPECIALIZE ||
        vcs_zcode_heuristic_validate_derivation(
            request->child_heuristic, request->parent_heuristic, 1u) !=
            VCS_ZCODE_ATTENTION_OK ||
        !measure_boundary_equal(request->parent_heuristic,
                                request->child_heuristic) ||
        memcmp(st->result.parent_heuristic_root,
               st->result.child_heuristic_root, 32u) == 0)
        return PM_ERR(LINEAGE);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_policy(
    const struct zcode_retrieval_profile_pair_measure_request *request)
{
    uint8_t policy_root[32];
    if (zcl_retrieval_comparison_policy_v2_root(
            request->policy, policy_root) != ZCL_RETRIEVAL_COMPARISON_OK)
        return PM_ERR(POLICY);
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
        return PM_ERR(POLICY);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_heuristic_roots(
    const struct zcode_retrieval_profile_pair_measure_request *request)
{
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
        return PM_ERR(BINDING);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_project_both(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    enum zcode_retrieval_profile_pair_measure_error error = measure_project(
        request->parent_profile, request->feature_snapshot,
        request->feature_rows, st->parent_indices,
        &st->result.parent_projection);
    if (error != PM_ERR(OK)) return error;
    return measure_project(
        request->child_profile, request->feature_snapshot,
        request->feature_rows, st->child_indices,
        &st->result.child_projection);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_proposals(
    const struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    const struct zcode_retrieval_profile_pair_measure_report *result =
        &st->result;
    uint8_t parent_proposal_root[32], child_proposal_root[32];
    if (memcmp(request->parent_heuristic->proposed_rule_root,
               st->parent_profile_root, 32u) != 0 ||
        memcmp(request->child_heuristic->proposed_rule_root,
               st->child_profile_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->observed_features_root,
               result->feature_snapshot_root, 32u) != 0 ||
        memcmp(request->child_heuristic->observed_features_root,
               result->feature_snapshot_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->expected_effect_root,
               result->parent_projection.candidate_ranking_root, 32u) != 0 ||
        memcmp(request->child_heuristic->expected_effect_root,
               result->child_projection.candidate_ranking_root, 32u) != 0)
        return PM_ERR(BINDING);
    if (!measure_proposal_root(
            request, st->parent_profile_root, result->feature_snapshot_root,
            result->parent_projection.candidate_ranking_root,
            parent_proposal_root) ||
        !measure_proposal_root(
            request, st->child_profile_root, result->feature_snapshot_root,
            result->child_projection.candidate_ranking_root,
            child_proposal_root) ||
        memcmp(parent_proposal_root,
               request->parent_heuristic->proposal_input_root, 32u) != 0 ||
        memcmp(child_proposal_root,
               request->child_heuristic->proposal_input_root, 32u) != 0)
        return PM_ERR(BINDING);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_check_workload(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    struct zcl_retrieval_evaluation_workload_task_v1 workload = {
        .task_id = request->task_id,
        .query = request->query,
        .relevant_paths = request->relevant_paths,
        .relevant_count = request->relevant_count,
    };
    enum zcl_retrieval_experiment_error workload_error;
    if (request->workload_version ==
            ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V1)
        workload_error = zcl_retrieval_evaluation_workload_root(
            &workload, 1u, request->expected_task_root,
            request->expected_source_root,
            request->expected_retrieval_projection_root, st->workload_root);
    else
        workload_error = zcl_retrieval_evaluation_workload_v2_root(
            &workload, 1u, request->expected_source_root,
            request->expected_retrieval_projection_root, st->workload_root);
    if (workload_error != ZCL_RETRIEVAL_EXPERIMENT_OK) return PM_ERR(WORKLOAD);
    if (memcmp(st->workload_root, request->policy->workload_root, 32u) != 0 ||
        memcmp(request->study->workloads_root, st->workload_root, 32u) != 0 ||
        memcmp(request->study->preregistration_policy_root,
               request->expected_policy_root, 32u) != 0)
        return PM_ERR(BINDING);
    return PM_ERR(OK);
}

static struct zcl_retrieval_ranked_file measure_ranked_row(
    const struct zcl_retrieval_feature_row_v1 *row)
{
    return (struct zcl_retrieval_ranked_file){
        .path = row->path,
        .context_bytes = row->context_bytes,
        .in_scope = false,
        .in_scope_available = false,
    };
}

static enum zcode_retrieval_profile_pair_measure_error pm_evaluate_pair(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    size_t row_count = st->row_count;
    struct zcl_retrieval_ranked_file
        parent_ranked[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {{0}};
    struct zcl_retrieval_ranked_file
        child_ranked[ZCL_RETRIEVAL_EVAL_RANK_MAX] = {{0}};
    for (size_t i = 0; i < row_count; i++) {
        if (st->parent_indices[i] >= row_count ||
            st->child_indices[i] >= row_count)
            return PM_ERR(EVALUATION);
        parent_ranked[i] =
            measure_ranked_row(&request->feature_rows[st->parent_indices[i]]);
        child_ranked[i] =
            measure_ranked_row(&request->feature_rows[st->child_indices[i]]);
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
    enum zcl_retrieval_experiment_error paired_error;
    if (request->workload_version ==
            ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V1)
        paired_error = zcl_retrieval_paired_evaluate(
            &paired_task, 1u, request->expected_task_root,
            request->expected_source_root,
            request->expected_retrieval_projection_root,
            &st->result.paired_evaluation);
    else
        paired_error = zcl_retrieval_paired_evaluate_v2(
            &paired_task, 1u, request->expected_task_root,
            request->expected_source_root,
            request->expected_retrieval_projection_root,
            &st->result.paired_evaluation);
    if (paired_error != ZCL_RETRIEVAL_EXPERIMENT_OK) return PM_ERR(EVALUATION);
    if (memcmp(st->result.paired_evaluation.workload_root,
               st->workload_root, 32u) != 0)
        return PM_ERR(EVALUATION);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_build_results(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    struct zcode_retrieval_profile_pair_measure_report *result = &st->result;
    bool complete = request->feature_snapshot->ranking_complete;
    struct zcl_retrieval_experiment_eval_report parent_eval, child_eval;
    measure_eval_report(
        &result->paired_evaluation.parent_metrics, &result->parent_projection,
        st->parent_indices, st->row_count, complete, &parent_eval);
    measure_eval_report(
        &result->paired_evaluation.child_metrics, &result->child_projection,
        st->child_indices, st->row_count, complete, &child_eval);
    if (zcl_retrieval_experiment_eval_result_init(
            &result->parent_result, &parent_eval,
            result->parent_heuristic_root,
            request->parent_heuristic->proposal_input_root,
            result->paired_evaluation.evaluation_input_root,
            request->expected_evaluator_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_init(
            &result->child_result, &child_eval,
            result->child_heuristic_root,
            request->child_heuristic->proposal_input_root,
            result->paired_evaluation.evaluation_input_root,
            request->expected_evaluator_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_root(
            &result->parent_result, result->parent_result_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_root(
            &result->child_result, result->child_result_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return PM_ERR(EVALUATION);
    return PM_ERR(OK);
}

static enum zcode_retrieval_profile_pair_measure_error pm_compare(
    struct pm_state *st)
{
    const struct zcode_retrieval_profile_pair_measure_request *request =
        st->request;
    struct zcode_retrieval_profile_pair_measure_report *result = &st->result;
    struct zcl_retrieval_comparison_arm_binding parent_binding = {0};
    struct zcl_retrieval_comparison_arm_binding child_binding = {0};
    memcpy(parent_binding.subject_root, result->parent_heuristic_root, 32u);
    memcpy(parent_binding.proposal_input_root,
           request->parent_heuristic->proposal_input_root, 32u);
    memcpy(parent_binding.result_root, result->parent_result_root, 32u);
    memcpy(child_binding.subject_root, result->child_heuristic_root, 32u);
    memcpy(child_binding.proposal_input_root,
           request->child_heuristic->proposal_input_root, 32u);
    memcpy(child_binding.result_root, result->child_result_root, 32u);
    uint8_t evaluation_input_root[32];
    memcpy(evaluation_input_root,
           result->paired_evaluation.evaluation_input_root, 32u);
    if (zcl_retrieval_comparison_observe_v2(
            request->policy, request->expected_policy_root,
            &result->paired_evaluation, evaluation_input_root,
            &result->parent_result, &parent_binding,
            &result->child_result, &child_binding,
            &result->comparison) != ZCL_RETRIEVAL_COMPARISON_OK)
        return PM_ERR(COMPARISON);
    return PM_ERR(OK);
}

/* Runs each stage in order; the first refusal is the result. */
static enum zcode_retrieval_profile_pair_measure_error pm_run(
    struct pm_state *st)
{
    enum zcode_retrieval_profile_pair_measure_error error;
    if ((error = pm_bind_study(st->request)) != PM_ERR(OK)) return error;
    if ((error = pm_bind_profiles(st)) != PM_ERR(OK)) return error;
    if ((error = pm_check_lineage(st)) != PM_ERR(OK)) return error;
    if ((error = pm_check_policy(st->request)) != PM_ERR(OK)) return error;
    if ((error = pm_check_heuristic_roots(st->request)) != PM_ERR(OK))
        return error;
    if ((error = pm_project_both(st)) != PM_ERR(OK)) return error;
    if ((error = pm_check_proposals(st)) != PM_ERR(OK)) return error;
    if ((error = pm_check_workload(st)) != PM_ERR(OK)) return error;
    if ((error = pm_evaluate_pair(st)) != PM_ERR(OK)) return error;
    if ((error = pm_build_results(st)) != PM_ERR(OK)) return error;
    return pm_compare(st);
}

enum zcode_retrieval_profile_pair_measure_error
zcode_retrieval_profile_pair_measure(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    struct zcode_retrieval_profile_pair_measure_report *report)
{
    size_t row_count = 0;
    enum zcode_retrieval_profile_pair_measure_error error =
        pm_validate_input(request, report, &row_count);
    if (error != PM_ERR(OK)) return error;
    struct pm_state st = { .request = request, .row_count = row_count };
    error = pm_run(&st);
    if (error != PM_ERR(OK)) return error;
    *report = st.result;
    return PM_ERR(OK);
}

