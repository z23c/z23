/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: derive and compare one exact retrieval-profile evaluation pair. */
#ifndef ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SERVICE_H
#define ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SERVICE_H

#include "retrieval/retrieval_comparison.h"
#include "vcs/zcode_attention_bid.h"

#include <stddef.h>
#include <stdint.h>

enum zcode_retrieval_profile_pair_measure_error {
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK = 0,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_NULL,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ROOT,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PROFILE,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_INCOMPLETE,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_HEURISTIC,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_LINEAGE,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_POLICY,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_WORKLOAD,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_EVALUATION,
    ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_COMPARISON,
};

/* This request has no channel for caller-supplied rankings, metrics, guards,
 * result objects, result roots, comparison status, or runtime pair identity.
 * Both profiles must use the evaluator's fixed top-five semantics. */
struct zcode_retrieval_profile_pair_measure_request {
    const struct zcl_retrieval_profile_v1 *parent_profile;
    const struct zcl_retrieval_profile_v1 *child_profile;
    const struct zcl_retrieval_feature_snapshot_v1 *feature_snapshot;
    const struct zcl_retrieval_feature_row_v1 *feature_rows;
    const struct vcs_zcode_heuristic_v1 *parent_heuristic;
    const struct vcs_zcode_heuristic_v1 *child_heuristic;
    const struct zcl_retrieval_comparison_policy_v2 *policy;
    const char *task_id;
    const char *query;
    const char *const *relevant_paths;
    size_t relevant_count;
    uint8_t expected_task_root[32];
    uint8_t expected_source_root[32];
    uint8_t expected_snapshot_source_root[32];
    uint8_t expected_retrieval_projection_root[32];
    uint8_t expected_study_root[32];
    uint8_t expected_policy_root[32];
    uint8_t expected_evaluator_root[32];
};

struct zcode_retrieval_profile_pair_measure_report {
    struct zcl_retrieval_profile_report parent_projection;
    struct zcl_retrieval_profile_report child_projection;
    struct zcl_retrieval_paired_evaluation_report_v1 paired_evaluation;
    struct zcl_retrieval_experiment_eval_result_v1 parent_result;
    struct zcl_retrieval_experiment_eval_result_v1 child_result;
    struct zcl_retrieval_comparison_report_v2 comparison;
    uint8_t feature_snapshot_root[32];
    uint8_t parent_heuristic_root[32];
    uint8_t child_heuristic_root[32];
    uint8_t parent_result_root[32];
    uint8_t child_result_root[32];
};

/* Derive both ordered arms from one exact feature snapshot, measure them with
 * the maintained paired evaluator, construct both immutable results locally,
 * and apply the exact v2 workload policy. This pure read-only observation does
 * not establish source provenance, chronology, hidden-gold or holdout
 * independence, evaluator correctness, reproduction, signer independence,
 * acceptance, attention, lifecycle, work, execution, or authority. The report
 * is unchanged on every error and may not overlap any reachable input. */
enum zcode_retrieval_profile_pair_measure_error
zcode_retrieval_profile_pair_measure(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    struct zcode_retrieval_profile_pair_measure_report *report);

const char *zcode_retrieval_profile_pair_measure_error_string(
    enum zcode_retrieval_profile_pair_measure_error error);

#endif /* ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SERVICE_H */
