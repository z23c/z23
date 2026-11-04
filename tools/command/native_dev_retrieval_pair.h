/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded CLI input for the maintained retrieval science adapter. */
#ifndef ZCL_NATIVE_DEV_RETRIEVAL_PAIR_H
#define ZCL_NATIVE_DEV_RETRIEVAL_PAIR_H

#include "json/json.h"
#include "services/zcode_retrieval_science_adapter_service.h"

#define ZCL_RETRIEVAL_PAIR_ARTIFACT_MAX (128u * 1024u)

struct zcl_native_retrieval_pair {
    struct json_value artifact;
    struct zcl_retrieval_profile_v1 parent_profile, child_profile;
    struct vcs_zcode_heuristic_v1 parent_heuristic, child_heuristic;
    struct zcl_retrieval_comparison_policy_v2 policy;
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_environment_policy_v1 environment;
    struct vcs_zcode_hardware_profile_v1 hardware;
    struct zcl_retrieval_feature_snapshot_v1 snapshot;
    struct zcl_retrieval_feature_row_v1 rows[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    const char *gold[ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX];
    struct zcode_retrieval_profile_pair_measure_request measurement;
    struct zcode_retrieval_science_result_request request;
};

/* Artifact pointers remain owned by pair until json_free(&pair->artifact). */
bool zcl_native_retrieval_pair_load(const struct json_value *input,
                                   struct zcl_native_retrieval_pair *pair);

struct zcl_command_request;
struct zcl_command_reply;
void zcl_native_handle_dev_retrieval_pair(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_DEV_RETRIEVAL_PAIR_H */
