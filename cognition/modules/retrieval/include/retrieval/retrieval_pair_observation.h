/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical evidence for one derived retrieval-profile pair. */
#ifndef ZCL_RETRIEVAL_PAIR_OBSERVATION_H
#define ZCL_RETRIEVAL_PAIR_OBSERVATION_H

#include "retrieval/retrieval_comparison.h"

#include <stddef.h>
#include <stdint.h>

#define ZCL_RETRIEVAL_PAIR_OBSERVATION_VERSION 1u
#define ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES 596u
#define ZCL_RETRIEVAL_PAIR_OBSERVATION_DOMAIN \
    "zcl.retrieval_profile_pair_observation.v1"

enum zcl_retrieval_pair_observation_error {
    ZCL_RETRIEVAL_PAIR_OBSERVATION_OK = 0,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ALIAS,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_VERSION,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_PARAMETER,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ROOT,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_WIRE,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_RESULT,
    ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING,
};

/* Immutable observation joining one exact derived-profile pair to the
 * preregistered comparison that was actually computed over it. Roots name
 * evidence. source_root and snapshot_source_root must be identical because
 * v1 carries no independent source-to-snapshot generation proof. They do not
 * establish chronology, evaluator independence,
 * replication, acceptance, attention, lifecycle, or execution authority. */
struct zcl_retrieval_pair_observation_v1 {
    uint16_t schema_version;
    uint8_t comparison_status;
    uint8_t metric;
    uint8_t direction;
    uint8_t missing_arms;
    uint16_t failed_guards;
    int32_t directional_delta_bp;
    uint8_t study_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t action_root[32];
    uint8_t source_root[32];
    uint8_t snapshot_source_root[32];
    uint8_t retrieval_projection_root[32];
    uint8_t feature_snapshot_root[32];
    uint8_t parent_heuristic_root[32];
    uint8_t child_heuristic_root[32];
    uint8_t policy_root[32];
    uint8_t evaluator_root[32];
    uint8_t workload_root[32];
    uint8_t parent_arm_root[32];
    uint8_t child_arm_root[32];
    uint8_t evaluation_input_root[32];
    uint8_t parent_result_root[32];
    uint8_t child_result_root[32];
};

void zcl_retrieval_pair_observation_init(
    struct zcl_retrieval_pair_observation_v1 *observation);
enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_validate(
    const struct zcl_retrieval_pair_observation_v1 *observation);
enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_serialize(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    uint8_t out[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES]);
enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_pair_observation_v1 *out);
enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_root(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    uint8_t out[32]);

/* Reconstruct the paired report from the observation's exact arm identities
 * and the two canonical evaluator results, then rerun comparison_observe_v2.
 * This verifies all result, subject, evaluator, policy, workload, ordered-arm,
 * evaluation-input, and comparison-scalar bindings. */
enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_verify(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_experiment_eval_result_v1 *child);

const char *zcl_retrieval_pair_observation_error_string(
    enum zcl_retrieval_pair_observation_error error);

#endif /* ZCL_RETRIEVAL_PAIR_OBSERVATION_H */
