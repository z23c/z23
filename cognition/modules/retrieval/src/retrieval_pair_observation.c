/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical codec and verifier for derived retrieval-profile pairs. */
#include "retrieval/retrieval_pair_observation.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static const uint8_t pair_observation_magic[8] = {
    'Z', 'C', 'R', 'P', 'O', 'B', '1', '\n'
};

static bool rpo_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool rpo_overlaps(const void *left, size_t left_size,
                         const void *right, size_t right_size)
{
    uintptr_t l = (uintptr_t)left, r = (uintptr_t)right;
    if (left_size == 0 || right_size == 0) return false;
    if (l > UINTPTR_MAX - left_size || r > UINTPTR_MAX - right_size)
        return true;
    return l < r + right_size && r < l + left_size;
}

static bool rpo_metric_valid(uint8_t metric)
{
    return metric >= ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP &&
           metric <= ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP;
}

static bool rpo_direction_valid(uint8_t direction)
{
    return direction >= ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST &&
           direction <= ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN;
}

void zcl_retrieval_pair_observation_init(
    struct zcl_retrieval_pair_observation_v1 *observation)
{
    if (!observation) return;
    memset(observation, 0, sizeof(*observation));
    observation->schema_version = ZCL_RETRIEVAL_PAIR_OBSERVATION_VERSION;
}

enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_validate(
    const struct zcl_retrieval_pair_observation_v1 *observation)
{
    if (!observation) return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL;
    if (observation->schema_version !=
            ZCL_RETRIEVAL_PAIR_OBSERVATION_VERSION)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_VERSION;
    if (observation->comparison_status <
            ZCL_RETRIEVAL_COMPARISON_SATISFIED ||
        observation->comparison_status >
            ZCL_RETRIEVAL_COMPARISON_INCOMPLETE ||
        !rpo_metric_valid(observation->metric) ||
        !rpo_direction_valid(observation->direction) ||
        (observation->missing_arms &
         (uint8_t)~(ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING |
                    ZCL_RETRIEVAL_COMPARISON_CHILD_METRIC_MISSING)) != 0 ||
        (observation->failed_guards &
         (uint16_t)~ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL) != 0 ||
        observation->directional_delta_bp <
            -(int32_t)ZCL_RETRIEVAL_EVAL_BASIS_POINTS ||
        observation->directional_delta_bp >
            (int32_t)ZCL_RETRIEVAL_EVAL_BASIS_POINTS)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_PARAMETER;
    if ((observation->failed_guards != 0 &&
         observation->comparison_status !=
             ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED) ||
        (observation->failed_guards == 0 &&
         observation->missing_arms != 0 &&
         observation->comparison_status !=
             ZCL_RETRIEVAL_COMPARISON_INCOMPLETE) ||
        (observation->failed_guards == 0 &&
         observation->missing_arms == 0 &&
         observation->comparison_status ==
             ZCL_RETRIEVAL_COMPARISON_INCOMPLETE) ||
        ((observation->failed_guards != 0 ||
          observation->missing_arms != 0) &&
         observation->directional_delta_bp != 0))
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_PARAMETER;
    const uint8_t *const roots[] = {
        observation->study_root, observation->task_root,
        observation->candidate_root, observation->action_root,
        observation->source_root, observation->snapshot_source_root,
        observation->retrieval_projection_root,
        observation->feature_snapshot_root,
        observation->parent_heuristic_root,
        observation->child_heuristic_root, observation->policy_root,
        observation->evaluator_root, observation->workload_root,
        observation->parent_arm_root, observation->child_arm_root,
        observation->evaluation_input_root,
        observation->parent_result_root, observation->child_result_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!rpo_root_any(roots[i]))
            return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ROOT;
    if (memcmp(observation->source_root,
               observation->snapshot_source_root, 32u) != 0 ||
        memcmp(observation->parent_heuristic_root,
               observation->child_heuristic_root, 32u) == 0 ||
        memcmp(observation->parent_arm_root,
               observation->child_arm_root, 32u) == 0 ||
        memcmp(observation->parent_result_root,
               observation->child_result_root, 32u) == 0)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING;
    return ZCL_RETRIEVAL_PAIR_OBSERVATION_OK;
}

static void rpo_roots_const(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    const uint8_t *roots[18])
{
    roots[0] = observation->study_root;
    roots[1] = observation->task_root;
    roots[2] = observation->candidate_root;
    roots[3] = observation->action_root;
    roots[4] = observation->source_root;
    roots[5] = observation->snapshot_source_root;
    roots[6] = observation->retrieval_projection_root;
    roots[7] = observation->feature_snapshot_root;
    roots[8] = observation->parent_heuristic_root;
    roots[9] = observation->child_heuristic_root;
    roots[10] = observation->policy_root;
    roots[11] = observation->evaluator_root;
    roots[12] = observation->workload_root;
    roots[13] = observation->parent_arm_root;
    roots[14] = observation->child_arm_root;
    roots[15] = observation->evaluation_input_root;
    roots[16] = observation->parent_result_root;
    roots[17] = observation->child_result_root;
}

enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_serialize(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    uint8_t out[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES])
{
    if (!observation || !out)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL;
    if (rpo_overlaps(observation, sizeof(*observation), out,
                     ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES))
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ALIAS;
    enum zcl_retrieval_pair_observation_error error =
        zcl_retrieval_pair_observation_validate(observation);
    if (error != ZCL_RETRIEVAL_PAIR_OBSERVATION_OK) return error;
    uint8_t wire[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES] = {0};
    size_t off = 0;
    memcpy(wire + off, pair_observation_magic,
           sizeof(pair_observation_magic));
    off += sizeof(pair_observation_magic);
    zcl_write_u16_le(wire + off, observation->schema_version); off += 2u;
    wire[off++] = observation->comparison_status;
    wire[off++] = observation->metric;
    wire[off++] = observation->direction;
    wire[off++] = observation->missing_arms;
    zcl_write_u16_le(wire + off, observation->failed_guards); off += 2u;
    zcl_write_i32_le(wire + off, observation->directional_delta_bp);
    off += 4u;
    const uint8_t *roots[18];
    rpo_roots_const(observation, roots);
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(wire + off, roots[i], 32u);
        off += 32u;
    }
    if (off != sizeof(wire))
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_WIRE;
    memcpy(out, wire, sizeof(wire));
    return ZCL_RETRIEVAL_PAIR_OBSERVATION_OK;
}

static void rpo_roots_mutable(
    struct zcl_retrieval_pair_observation_v1 *observation,
    uint8_t *roots[18])
{
    roots[0] = observation->study_root;
    roots[1] = observation->task_root;
    roots[2] = observation->candidate_root;
    roots[3] = observation->action_root;
    roots[4] = observation->source_root;
    roots[5] = observation->snapshot_source_root;
    roots[6] = observation->retrieval_projection_root;
    roots[7] = observation->feature_snapshot_root;
    roots[8] = observation->parent_heuristic_root;
    roots[9] = observation->child_heuristic_root;
    roots[10] = observation->policy_root;
    roots[11] = observation->evaluator_root;
    roots[12] = observation->workload_root;
    roots[13] = observation->parent_arm_root;
    roots[14] = observation->child_arm_root;
    roots[15] = observation->evaluation_input_root;
    roots[16] = observation->parent_result_root;
    roots[17] = observation->child_result_root;
}

enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_pair_observation_v1 *out)
{
    if (!wire || !out) return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL;
    if (rpo_overlaps(wire, wire_len, out, sizeof(*out)))
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ALIAS;
    if (wire_len != ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES ||
        memcmp(wire, pair_observation_magic,
               sizeof(pair_observation_magic)) != 0) {
        memset(out, 0, sizeof(*out));
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_WIRE;
    }
    struct zcl_retrieval_pair_observation_v1 parsed = {0};
    size_t off = sizeof(pair_observation_magic);
    parsed.schema_version = zcl_read_u16_le(wire + off); off += 2u;
    parsed.comparison_status = wire[off++];
    parsed.metric = wire[off++];
    parsed.direction = wire[off++];
    parsed.missing_arms = wire[off++];
    parsed.failed_guards = zcl_read_u16_le(wire + off); off += 2u;
    parsed.directional_delta_bp = zcl_read_i32_le(wire + off); off += 4u;
    uint8_t *roots[18];
    rpo_roots_mutable(&parsed, roots);
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(roots[i], wire + off, 32u);
        off += 32u;
    }
    enum zcl_retrieval_pair_observation_error error = off == wire_len
        ? zcl_retrieval_pair_observation_validate(&parsed)
        : ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_WIRE;
    if (error == ZCL_RETRIEVAL_PAIR_OBSERVATION_OK) *out = parsed;
    else memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_root(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    uint8_t out[32])
{
    if (!observation || !out)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL;
    if (rpo_overlaps(observation, sizeof(*observation), out, 32u))
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ALIAS;
    uint8_t wire[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES];
    enum zcl_retrieval_pair_observation_error error =
        zcl_retrieval_pair_observation_serialize(observation, wire);
    if (error != ZCL_RETRIEVAL_PAIR_OBSERVATION_OK) return error;
    static const char domain[] = ZCL_RETRIEVAL_PAIR_OBSERVATION_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_PAIR_OBSERVATION_OK;
}

static void rpo_metrics_from_result(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    struct zcl_retrieval_eval_metrics *metrics)
{
    memset(metrics, 0, sizeof(*metrics));
    metrics->tasks = result->tasks;
    metrics->recall_at_5_bp = result->recall_at_5_bp;
    metrics->recall_at_20_bp = result->recall_at_20_bp;
    metrics->mrr_bp = result->mrr_bp;
    metrics->wrong_scope_at_5_bp = result->wrong_scope_at_5_bp;
    metrics->unique_files_at_5 = result->unique_files_at_5;
    metrics->wrong_scope_files_at_5 = result->wrong_scope_files_at_5;
    metrics->context_bytes_at_5 = result->context_bytes_at_5;
    metrics->approximate_tokens_at_5 =
        (result->context_bytes_at_5 + 3u) / 4u;
    metrics->recall_at_5_available = (result->flags &
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE) != 0;
    metrics->recall_at_20_available = (result->flags &
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE) != 0;
    metrics->mrr_available = (result->flags &
        ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE) != 0;
    metrics->wrong_scope_at_5_available = (result->flags &
        ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE) != 0;
}

enum zcl_retrieval_pair_observation_error
zcl_retrieval_pair_observation_verify(
    const struct zcl_retrieval_pair_observation_v1 *observation,
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_experiment_eval_result_v1 *child)
{
    if (!observation || !policy || !parent || !child)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL;
    enum zcl_retrieval_pair_observation_error error =
        zcl_retrieval_pair_observation_validate(observation);
    if (error != ZCL_RETRIEVAL_PAIR_OBSERVATION_OK) return error;
    if (zcl_retrieval_comparison_policy_v2_validate(policy) !=
            ZCL_RETRIEVAL_COMPARISON_OK)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_PARAMETER;
    if (zcl_retrieval_experiment_eval_result_validate(parent) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_validate(child) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_RESULT;
    uint8_t policy_root[32], parent_root[32], child_root[32];
    if (zcl_retrieval_comparison_policy_v2_root(policy, policy_root) !=
            ZCL_RETRIEVAL_COMPARISON_OK ||
        zcl_retrieval_experiment_eval_result_root(parent, parent_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_root(child, child_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_RESULT;
    uint8_t evaluation_input_root[32];
    if (zcl_retrieval_paired_evaluation_input_root(
            observation->workload_root, observation->parent_arm_root,
            observation->child_arm_root, evaluation_input_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING;
    if (memcmp(policy_root, observation->policy_root, 32u) != 0 ||
        memcmp(policy->evaluator_root, observation->evaluator_root, 32u) != 0 ||
        memcmp(policy->workload_root, observation->workload_root, 32u) != 0 ||
        memcmp(evaluation_input_root,
               observation->evaluation_input_root, 32u) != 0 ||
        memcmp(parent_root, observation->parent_result_root, 32u) != 0 ||
        memcmp(child_root, observation->child_result_root, 32u) != 0 ||
        memcmp(parent->subject_root,
               observation->parent_heuristic_root, 32u) != 0 ||
        memcmp(child->subject_root,
               observation->child_heuristic_root, 32u) != 0 ||
        memcmp(parent->evaluation_input_root,
               observation->evaluation_input_root, 32u) != 0 ||
        memcmp(child->evaluation_input_root,
               observation->evaluation_input_root, 32u) != 0 ||
        memcmp(parent->evaluator_root,
               observation->evaluator_root, 32u) != 0 ||
        memcmp(child->evaluator_root,
               observation->evaluator_root, 32u) != 0)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING;

    struct zcl_retrieval_paired_evaluation_report_v1 paired = {
        .schema_version = ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION,
        .task_count = parent->tasks,
    };
    rpo_metrics_from_result(parent, &paired.parent_metrics);
    rpo_metrics_from_result(child, &paired.child_metrics);
    memcpy(paired.expected_task_root, observation->task_root, 32u);
    memcpy(paired.source_root, observation->source_root, 32u);
    memcpy(paired.retrieval_projection_root,
           observation->retrieval_projection_root, 32u);
    memcpy(paired.workload_root, observation->workload_root, 32u);
    memcpy(paired.parent_arm_root, observation->parent_arm_root, 32u);
    memcpy(paired.child_arm_root, observation->child_arm_root, 32u);
    memcpy(paired.evaluation_input_root,
           observation->evaluation_input_root, 32u);
    struct zcl_retrieval_comparison_arm_binding parent_binding = {0};
    struct zcl_retrieval_comparison_arm_binding child_binding = {0};
    memcpy(parent_binding.subject_root,
           observation->parent_heuristic_root, 32u);
    memcpy(parent_binding.proposal_input_root,
           parent->proposal_input_root, 32u);
    memcpy(parent_binding.result_root,
           observation->parent_result_root, 32u);
    memcpy(child_binding.subject_root,
           observation->child_heuristic_root, 32u);
    memcpy(child_binding.proposal_input_root,
           child->proposal_input_root, 32u);
    memcpy(child_binding.result_root, observation->child_result_root, 32u);
    struct zcl_retrieval_comparison_report_v2 report;
    if (zcl_retrieval_comparison_observe_v2(
            policy, observation->policy_root, &paired,
            observation->evaluation_input_root, parent, &parent_binding,
            child, &child_binding, &report) != ZCL_RETRIEVAL_COMPARISON_OK)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING;
    if ((uint8_t)report.observation.status !=
            observation->comparison_status ||
        report.observation.metric != observation->metric ||
        report.observation.direction != observation->direction ||
        report.observation.missing_arms != observation->missing_arms ||
        report.observation.failed_guards != observation->failed_guards ||
        report.observation.directional_delta_bp !=
            observation->directional_delta_bp ||
        memcmp(report.observation.policy_root,
               observation->policy_root, 32u) != 0 ||
        memcmp(report.observation.parent_result_root,
               observation->parent_result_root, 32u) != 0 ||
        memcmp(report.observation.child_result_root,
               observation->child_result_root, 32u) != 0 ||
        memcmp(report.workload_root,
               observation->workload_root, 32u) != 0 ||
        memcmp(report.evaluation_input_root,
               observation->evaluation_input_root, 32u) != 0)
        return ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING;
    return ZCL_RETRIEVAL_PAIR_OBSERVATION_OK;
}

const char *zcl_retrieval_pair_observation_error_string(
    enum zcl_retrieval_pair_observation_error error)
{
    switch (error) {
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_OK: return "ok";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_NULL: return "null argument";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ALIAS:
        return "output aliases input";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_VERSION:
        return "unsupported version";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_PARAMETER:
        return "invalid observation parameter";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_ROOT:
        return "required root is zero";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_WIRE:
        return "invalid observation wire";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_RESULT:
        return "invalid evaluation result";
    case ZCL_RETRIEVAL_PAIR_OBSERVATION_ERR_BINDING:
        return "observation binding mismatch";
    }
    return "unknown";
}
