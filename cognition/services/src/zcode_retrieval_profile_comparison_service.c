/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lineage-bound observation of retrieval-profile specialization. */
#include "services/zcode_retrieval_profile_comparison_service.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool rpc_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool rpc_overlaps(const void *left, size_t left_size,
                         const void *right, size_t right_size)
{
    uintptr_t l = (uintptr_t)left, r = (uintptr_t)right;
    if (l > UINTPTR_MAX - left_size || r > UINTPTR_MAX - right_size)
        return true;
    return l < r + right_size && r < l + left_size;
}

static bool rpc_output_aliases(
    const struct zcode_retrieval_profile_comparison_request *request,
    const struct zcode_retrieval_profile_comparison_report *report)
{
#define RPC_OVERLAPS(ptr_) \
    rpc_overlaps(report, sizeof(*report), (ptr_), sizeof(*(ptr_)))
    bool aliases = RPC_OVERLAPS(request) ||
        RPC_OVERLAPS(request->parent_heuristic) ||
        RPC_OVERLAPS(request->child_heuristic) ||
        RPC_OVERLAPS(request->policy) ||
        RPC_OVERLAPS(request->parent_result) ||
        RPC_OVERLAPS(request->child_result);
#undef RPC_OVERLAPS
    return aliases;
}

static bool rpc_lineage_boundary_equal(
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

static bool rpc_policy_evaluator_frozen(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    const struct vcs_zcode_heuristic_v1 *heuristic)
{
    for (size_t i = 0; i < heuristic->evaluator_count; i++)
        if (memcmp(policy->evaluator_root,
                   heuristic->evaluator_roots[i], 32u) == 0)
            return true;
    return false;
}

enum zcode_retrieval_profile_comparison_error
zcode_retrieval_profile_comparison_observe(
    const struct zcode_retrieval_profile_comparison_request *request,
    struct zcode_retrieval_profile_comparison_report *report)
{
    if (!request || !report || !request->parent_heuristic ||
        !request->child_heuristic || !request->policy ||
        !request->parent_result || !request->child_result)
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_NULL;
    if (rpc_output_aliases(request, report))
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_ALIAS;
    const uint8_t *roots[] = {
        request->expected_task_root, request->expected_source_root,
        request->expected_policy_root, request->parent_result_root,
        request->child_result_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!rpc_root_any(roots[i]))
            return ZCODE_RETRIEVAL_PROFILE_COMPARISON_ROOT;

    struct zcode_retrieval_profile_comparison_report result = {0};
    if (vcs_zcode_heuristic_root(
            request->parent_heuristic, result.parent_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_heuristic_root(
            request->child_heuristic, result.child_heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_HEURISTIC;
    if (request->child_heuristic->derivation !=
            VCS_ZCODE_HEURISTIC_SPECIALIZE ||
        vcs_zcode_heuristic_validate_derivation(
            request->child_heuristic, request->parent_heuristic, 1u) !=
            VCS_ZCODE_ATTENTION_OK)
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_LINEAGE;
    if (!rpc_lineage_boundary_equal(request->parent_heuristic,
                                    request->child_heuristic) ||
        memcmp(result.parent_heuristic_root,
               result.child_heuristic_root, 32u) == 0 ||
        memcmp(request->parent_heuristic->task_root,
               request->expected_task_root, 32u) != 0 ||
        memcmp(request->child_heuristic->task_root,
               request->expected_task_root, 32u) != 0 ||
        memcmp(request->parent_heuristic->source_root,
               request->expected_source_root, 32u) != 0 ||
        memcmp(request->child_heuristic->source_root,
               request->expected_source_root, 32u) != 0)
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_BINDING;

    uint8_t policy_root[32];
    if (zcl_retrieval_comparison_policy_root(
            request->policy, policy_root) != ZCL_RETRIEVAL_COMPARISON_OK)
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_POLICY;
    if (memcmp(policy_root, request->expected_policy_root, 32u) != 0 ||
        memcmp(policy_root,
               request->parent_heuristic->preregistration_root, 32u) != 0 ||
        memcmp(policy_root,
               request->child_heuristic->preregistration_root, 32u) != 0 ||
        !rpc_policy_evaluator_frozen(
            request->policy, request->parent_heuristic))
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_BINDING;

    struct zcl_retrieval_comparison_arm_binding parent = {0}, child = {0};
    memcpy(parent.subject_root, result.parent_heuristic_root, 32u);
    memcpy(parent.proposal_input_root,
           request->parent_heuristic->proposal_input_root, 32u);
    memcpy(parent.result_root, request->parent_result_root, 32u);
    memcpy(child.subject_root, result.child_heuristic_root, 32u);
    memcpy(child.proposal_input_root,
           request->child_heuristic->proposal_input_root, 32u);
    memcpy(child.result_root, request->child_result_root, 32u);
    if (zcl_retrieval_comparison_observe(
            request->policy, request->expected_policy_root,
            request->parent_result, &parent, request->child_result, &child,
            &result.observation) != ZCL_RETRIEVAL_COMPARISON_OK)
        return ZCODE_RETRIEVAL_PROFILE_COMPARISON_OBSERVATION;
    *report = result;
    return ZCODE_RETRIEVAL_PROFILE_COMPARISON_OK;
}

const char *zcode_retrieval_profile_comparison_error_string(
    enum zcode_retrieval_profile_comparison_error error)
{
    switch (error) {
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_OK: return "ok";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_NULL: return "null argument";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_ALIAS:
        return "output aliases input";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_ROOT: return "required root is zero";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_HEURISTIC:
        return "invalid heuristic";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_LINEAGE:
        return "invalid specialization lineage";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_POLICY:
        return "invalid comparison policy";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_BINDING:
        return "comparison binding mismatch";
    case ZCODE_RETRIEVAL_PROFILE_COMPARISON_OBSERVATION:
        return "retrieval observation refused";
    }
    return "unknown";
}
