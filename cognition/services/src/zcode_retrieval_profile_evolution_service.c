/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, relevance-free retrieval-profile specialization. */
#include "services/zcode_retrieval_profile_evolution_service.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool evolution_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool evolution_memory_overlaps(const void *left, size_t left_size,
                                      const void *right, size_t right_size)
{
    uintptr_t left_address = (uintptr_t)left;
    uintptr_t right_address = (uintptr_t)right;
    if (left_address > UINTPTR_MAX - left_size ||
        right_address > UINTPTR_MAX - right_size)
        return true;
    return left_address < right_address + right_size &&
           right_address < left_address + left_size;
}

static bool evolution_bounded_text(const char *text, size_t maximum,
                                   size_t *length_out)
{
    if (!text || !length_out) return false;
    size_t length = 0;
    while (length <= maximum && text[length]) length++;
    if (length == 0 || length > maximum) return false;
    *length_out = length;
    return true;
}

static bool evolution_output_aliases(
    const struct zcode_retrieval_profile_evolution_request *request,
    struct zcode_retrieval_profile_evolution_report *report,
    size_t task_id_length, size_t query_length)
{
    size_t row_count = request->feature_snapshot->row_count;
#define OVERLAPS(ptr_, size_) \
    evolution_memory_overlaps(report, sizeof(*report), (ptr_), (size_))
    if (OVERLAPS(request, sizeof(*request)) ||
        OVERLAPS(request->parent_profile, sizeof(*request->parent_profile)) ||
        OVERLAPS(request->feature_snapshot,
                 sizeof(*request->feature_snapshot)) ||
        OVERLAPS(request->feature_rows,
                 row_count * sizeof(*request->feature_rows)) ||
        OVERLAPS(request->parent_heuristic,
                 sizeof(*request->parent_heuristic)) ||
        OVERLAPS(request->task_id, task_id_length + 1u) ||
        OVERLAPS(request->query, query_length + 1u))
        return true;
    for (size_t i = 0; i < row_count; i++) {
        const char *path = request->feature_rows[i].path;
        if (!path) continue;
        size_t path_length = 0;
        while (path_length <= 255u && path[path_length]) path_length++;
        size_t checked_length = path_length <= 255u
            ? path_length + 1u : 256u;
        if (OVERLAPS(path, checked_length))
            return true;
    }
#undef OVERLAPS
    return false;
}

static enum zcode_retrieval_profile_evolution_error evolution_project(
    const struct zcode_retrieval_profile_evolution_request *request,
    struct zcode_retrieval_profile_evolution_report *result)
{
    size_t parent_indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    size_t candidate_indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    enum zcl_retrieval_experiment_error retrieval_error =
        zcl_retrieval_profile_project(
            request->parent_profile, request->feature_snapshot,
            request->feature_rows, parent_indices,
            ZCL_RETRIEVAL_EVAL_RANK_MAX, &result->parent_projection);
    if (retrieval_error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_INCOMPLETE;
    if (retrieval_error != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL;
    retrieval_error = zcl_retrieval_profile_project(
        &result->candidate_profile, request->feature_snapshot,
        request->feature_rows, candidate_indices,
        ZCL_RETRIEVAL_EVAL_RANK_MAX, &result->candidate_projection);
    if (retrieval_error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_INCOMPLETE;
    if (retrieval_error != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL;
    return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK;
}

enum zcode_retrieval_profile_evolution_error
zcode_retrieval_profile_evolution_propose(
    const struct zcode_retrieval_profile_evolution_request *request,
    struct zcode_retrieval_profile_evolution_report *report)
{
    if (!request || !report || !request->parent_profile ||
        !request->feature_snapshot || !request->feature_rows ||
        !request->parent_heuristic || !request->task_id || !request->query)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NULL;
    size_t task_id_length = 0, query_length = 0;
    if (!evolution_bounded_text(request->task_id, 128u, &task_id_length) ||
        !evolution_bounded_text(request->query, 4096u, &query_length) ||
        request->candidate_context_byte_scale == 0 ||
        request->candidate_context_byte_scale ==
            request->parent_profile->context_byte_scale)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_PARAMETER;
    if (request->feature_snapshot->row_count == 0 ||
        request->feature_snapshot->row_count >
            ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL;
    if (evolution_output_aliases(
            request, report, task_id_length, query_length))
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_ALIAS;
    if (!evolution_root_any(request->expected_task_root) ||
        !evolution_root_any(request->expected_source_root) ||
        !evolution_root_any(request->expected_snapshot_source_root) ||
        !evolution_root_any(request->expected_retrieval_projection_root) ||
        !evolution_root_any(request->proposal_evaluator_root) ||
        !evolution_root_any(request->candidate_provenance_root))
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING;

    uint8_t query_root[32];
    if (zcl_retrieval_query_root(request->query, query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        memcmp(query_root, request->feature_snapshot->query_root, 32u) != 0 ||
        memcmp(request->expected_snapshot_source_root,
               request->feature_snapshot->source_root, 32u) != 0 ||
        memcmp(request->expected_retrieval_projection_root,
               request->feature_snapshot->codeindex_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING;

    struct zcode_retrieval_profile_evolution_report result = {0};
    result.candidate_profile = *request->parent_profile;
    result.candidate_profile.context_byte_scale =
        request->candidate_context_byte_scale;
    if (zcl_retrieval_profile_validate(request->parent_profile) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_validate(&result.candidate_profile) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL;
    if (vcs_zcode_heuristic_validate(request->parent_heuristic) !=
            VCS_ZCODE_ATTENTION_OK)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_HEURISTIC;
    if (memcmp(request->expected_task_root,
               request->parent_heuristic->task_root, 32u) != 0 ||
        memcmp(request->expected_source_root,
               request->parent_heuristic->source_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING;

    enum zcode_retrieval_profile_evolution_error error =
        evolution_project(request, &result);
    if (error != ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK) return error;
    if (zcl_retrieval_profile_root(
            request->parent_profile, result.parent_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_root(
            &result.candidate_profile, result.candidate_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_feature_snapshot_root(
            request->feature_snapshot, request->feature_rows,
            result.feature_snapshot_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        vcs_zcode_heuristic_root(
            request->parent_heuristic, result.parent_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING;
    if (memcmp(request->parent_heuristic->proposed_rule_root,
               result.parent_profile_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->observed_features_root,
               result.feature_snapshot_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->expected_effect_root,
               result.parent_projection.candidate_ranking_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING;

    bool evaluator_found = false;
    for (size_t i = 0;
         i < request->parent_heuristic->evaluator_count; i++) {
        if (memcmp(request->proposal_evaluator_root,
                   request->parent_heuristic->evaluator_roots[i], 32u) == 0) {
            evaluator_found = true;
            break;
        }
    }
    uint8_t parent_profile_proposal_root[32];
    if (!evaluator_found ||
        !zcl_retrieval_profile_proposal_input_root(
            request->expected_source_root,
            request->feature_snapshot->source_root,
            request->feature_snapshot->codeindex_root,
            request->task_id, request->query,
            request->feature_snapshot->baseline_ranking_root,
            result.parent_profile_root, result.feature_snapshot_root,
            result.parent_projection.candidate_ranking_root,
            request->parent_heuristic->study_root,
            request->parent_heuristic->preregistration_root,
            request->proposal_evaluator_root,
            parent_profile_proposal_root) ||
        memcmp(parent_profile_proposal_root,
               request->parent_heuristic->proposal_input_root, 32u) != 0 ||
        !zcl_retrieval_profile_proposal_input_root(
            request->expected_source_root,
            request->feature_snapshot->source_root,
            request->feature_snapshot->codeindex_root,
            request->task_id, request->query,
            request->feature_snapshot->baseline_ranking_root,
            result.candidate_profile_root, result.feature_snapshot_root,
            result.candidate_projection.candidate_ranking_root,
            request->parent_heuristic->study_root,
            request->parent_heuristic->preregistration_root,
            request->proposal_evaluator_root,
            result.proposal_input_root))
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING;
    if (memcmp(result.parent_projection.candidate_ranking_root,
               result.candidate_projection.candidate_ranking_root,
               32u) == 0)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NO_EFFECT;
    result.candidate_heuristic = *request->parent_heuristic;
    result.candidate_heuristic.derivation =
        VCS_ZCODE_HEURISTIC_SPECIALIZE;
    result.candidate_heuristic.parent_count = 1u;
    memset(result.candidate_heuristic.parent_roots, 0,
           sizeof(result.candidate_heuristic.parent_roots));
    memcpy(result.candidate_heuristic.parent_roots[0],
           result.parent_heuristic_root, 32u);
    memcpy(result.candidate_heuristic.proposed_rule_root,
           result.candidate_profile_root, 32u);
    memcpy(result.candidate_heuristic.observed_features_root,
           result.feature_snapshot_root, 32u);
    memcpy(result.candidate_heuristic.expected_effect_root,
           result.candidate_projection.candidate_ranking_root, 32u);
    memcpy(result.candidate_heuristic.proposal_input_root,
           result.proposal_input_root, 32u);
    memcpy(result.candidate_heuristic.provenance_root,
           request->candidate_provenance_root, 32u);
    if (vcs_zcode_heuristic_validate_derivation(
            &result.candidate_heuristic, request->parent_heuristic, 1u) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_heuristic_root(
            &result.candidate_heuristic,
            result.candidate_heuristic_root) != VCS_ZCODE_ATTENTION_OK)
        return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_HEURISTIC;
    result.evaluation_status = ZCL_ONTOLOGY_UNKNOWN;
    result.attention_status = ZCL_ONTOLOGY_INCOMPLETE;
    result.missing_attention_metrics =
        VCS_ZCODE_ATTENTION_METRIC_REQUIRED;
    *report = result;
    return ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK;
}

const char *zcode_retrieval_profile_evolution_error_string(
    enum zcode_retrieval_profile_evolution_error error)
{
    switch (error) {
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK: return "ok";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NULL: return "null argument";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_ALIAS: return "output aliases input";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_PARAMETER:
        return "candidate parameter is invalid";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_INCOMPLETE:
        return "required retrieval feature evidence is incomplete";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL:
        return "retrieval projection refused";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_HEURISTIC:
        return "heuristic lineage refused";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING:
        return "exact input binding mismatch";
    case ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NO_EFFECT:
        return "candidate ranking is unchanged";
    }
    return "unknown retrieval profile evolution error";
}
