/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lineage-bound observation of retrieval-profile specialization. */
#ifndef ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_COMPARISON_SERVICE_H
#define ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_COMPARISON_SERVICE_H

#include "retrieval/retrieval_comparison.h"
#include "vcs/zcode_attention_bid.h"

#include <stdint.h>

enum zcode_retrieval_profile_comparison_error {
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_OK = 0,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_NULL,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_ALIAS,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_ROOT,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_HEURISTIC,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_LINEAGE,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_POLICY,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_BINDING,
    ZCODE_RETRIEVAL_PROFILE_COMPARISON_OBSERVATION,
};

struct zcode_retrieval_profile_comparison_request {
    const struct vcs_zcode_heuristic_v1 *parent_heuristic;
    const struct vcs_zcode_heuristic_v1 *child_heuristic;
    const struct zcl_retrieval_comparison_policy_v1 *policy;
    const struct zcl_retrieval_experiment_eval_result_v1 *parent_result;
    const struct zcl_retrieval_experiment_eval_result_v1 *child_result;
    uint8_t expected_task_root[32];
    uint8_t expected_source_root[32];
    uint8_t expected_policy_root[32];
    uint8_t parent_result_root[32];
    uint8_t child_result_root[32];
};

struct zcode_retrieval_profile_comparison_report {
    struct zcl_retrieval_comparison_report observation;
    uint8_t parent_heuristic_root[32];
    uint8_t child_heuristic_root[32];
};

/* Verify one immediate SPECIALIZE edge and its exact preregistered pair of
 * retrieval observations. This pure read-only adapter performs no CAS/DB
 * access and grants no attention, lifecycle, work, execution, or authority.
 * The report is unchanged on every error. */
enum zcode_retrieval_profile_comparison_error
zcode_retrieval_profile_comparison_observe(
    const struct zcode_retrieval_profile_comparison_request *request,
    struct zcode_retrieval_profile_comparison_report *report);

const char *zcode_retrieval_profile_comparison_error_string(
    enum zcode_retrieval_profile_comparison_error error);

#endif /* ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_COMPARISON_SERVICE_H */
