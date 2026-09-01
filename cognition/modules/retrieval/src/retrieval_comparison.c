/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: preregistered exact comparison of retrieval observations. */
#include "retrieval/retrieval_comparison.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool rc_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool rc_overlaps(const void *left, size_t left_size,
                        const void *right, size_t right_size)
{
    uintptr_t l = (uintptr_t)left, r = (uintptr_t)right;
    if (l > UINTPTR_MAX - left_size || r > UINTPTR_MAX - right_size)
        return true;
    return l < r + right_size && r < l + left_size;
}

static bool rc_metric_valid(uint8_t metric)
{
    return metric >= ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP &&
           metric <= ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP;
}

static bool rc_direction_valid(uint8_t direction)
{
    return direction >= ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST &&
           direction <= ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_validate(
    const struct zcl_retrieval_comparison_policy_v1 *policy)
{
    if (!policy) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (policy->schema_version != ZCL_RETRIEVAL_COMPARISON_POLICY_VERSION)
        return ZCL_RETRIEVAL_COMPARISON_VERSION;
    if (policy->reserved != 0 || policy->reserved_threshold != 0)
        return ZCL_RETRIEVAL_COMPARISON_RESERVED;
    if (!rc_metric_valid(policy->metric) ||
        !rc_direction_valid(policy->direction) ||
        policy->threshold_bp > ZCL_RETRIEVAL_EVAL_BASIS_POINTS ||
        policy->expected_tasks == 0 ||
        policy->expected_tasks > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return ZCL_RETRIEVAL_COMPARISON_PARAMETER;
    if ((policy->required_guards &
         (uint16_t)~ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL) != 0)
        return ZCL_RETRIEVAL_COMPARISON_PARAMETER;
    if (!rc_root_any(policy->evaluation_input_root) ||
        !rc_root_any(policy->evaluator_root))
        return ZCL_RETRIEVAL_COMPARISON_ROOT;
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_serialize(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    uint8_t out[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES])
{
    static const uint8_t magic[8] = {'Z','C','R','C','M','P','1','\n'};
    if (!policy || !out) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_overlaps(policy, sizeof(*policy), out,
                    ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_validate(policy);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES] = {0};
    memcpy(wire, magic, sizeof(magic));
    zcl_write_u16_le(wire + 8u, policy->schema_version);
    wire[10] = policy->metric;
    wire[11] = policy->direction;
    zcl_write_u16_le(wire + 12u, policy->required_guards);
    zcl_write_u16_le(wire + 14u, policy->reserved);
    zcl_write_u16_le(wire + 16u, policy->threshold_bp);
    zcl_write_u16_le(wire + 18u, policy->reserved_threshold);
    zcl_write_u32_le(wire + 20u, policy->expected_tasks);
    memcpy(wire + 24u, policy->evaluation_input_root, 32u);
    memcpy(wire + 56u, policy->evaluator_root, 32u);
    memcpy(out, wire, sizeof(wire));
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_comparison_policy_v1 *out)
{
    static const uint8_t magic[8] = {'Z','C','R','C','M','P','1','\n'};
    if (!wire || !out) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_overlaps(wire, wire_len, out, sizeof(*out)))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    if (wire_len != ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES ||
        memcmp(wire, magic, sizeof(magic)) != 0) {
        memset(out, 0, sizeof(*out));
        return ZCL_RETRIEVAL_COMPARISON_WIRE;
    }
    struct zcl_retrieval_comparison_policy_v1 parsed = {0};
    parsed.schema_version = zcl_read_u16_le(wire + 8u);
    parsed.metric = wire[10];
    parsed.direction = wire[11];
    parsed.required_guards = zcl_read_u16_le(wire + 12u);
    parsed.reserved = zcl_read_u16_le(wire + 14u);
    parsed.threshold_bp = zcl_read_u16_le(wire + 16u);
    parsed.reserved_threshold = zcl_read_u16_le(wire + 18u);
    parsed.expected_tasks = zcl_read_u32_le(wire + 20u);
    memcpy(parsed.evaluation_input_root, wire + 24u, 32u);
    memcpy(parsed.evaluator_root, wire + 56u, 32u);
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_validate(&parsed);
    if (error == ZCL_RETRIEVAL_COMPARISON_OK) *out = parsed;
    else memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_root(
    const struct zcl_retrieval_comparison_policy_v1 *policy, uint8_t out[32])
{
    if (!policy || !out) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_overlaps(policy, sizeof(*policy), out, 32u))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES];
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_serialize(policy, wire);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    static const char domain[] = ZCL_RETRIEVAL_COMPARISON_POLICY_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_validate(
    const struct zcl_retrieval_comparison_policy_v2 *policy)
{
    if (!policy) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (policy->schema_version !=
            ZCL_RETRIEVAL_COMPARISON_POLICY_V2_VERSION)
        return ZCL_RETRIEVAL_COMPARISON_VERSION;
    if (policy->reserved_threshold != 0)
        return ZCL_RETRIEVAL_COMPARISON_RESERVED;
    if (!rc_metric_valid(policy->metric) ||
        !rc_direction_valid(policy->direction) ||
        policy->evaluation_kind !=
            ZCL_RETRIEVAL_COMPARISON_DERIVED_PROFILE_PAIRED_V1 ||
        policy->threshold_bp > ZCL_RETRIEVAL_EVAL_BASIS_POINTS ||
        policy->expected_tasks == 0 ||
        policy->expected_tasks > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return ZCL_RETRIEVAL_COMPARISON_PARAMETER;
    if ((policy->required_guards &
         (uint16_t)~ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL) != 0)
        return ZCL_RETRIEVAL_COMPARISON_PARAMETER;
    if (!rc_root_any(policy->workload_root) ||
        !rc_root_any(policy->evaluator_root))
        return ZCL_RETRIEVAL_COMPARISON_ROOT;
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_serialize(
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    uint8_t out[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES])
{
    static const uint8_t magic[8] = {'Z','C','R','C','M','P','2','\n'};
    if (!policy || !out) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_overlaps(policy, sizeof(*policy), out,
                    ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_v2_validate(policy);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES] = {0};
    memcpy(wire, magic, sizeof(magic));
    zcl_write_u16_le(wire + 8u, policy->schema_version);
    wire[10] = policy->metric;
    wire[11] = policy->direction;
    zcl_write_u16_le(wire + 12u, policy->required_guards);
    zcl_write_u16_le(wire + 14u, policy->evaluation_kind);
    zcl_write_u16_le(wire + 16u, policy->threshold_bp);
    zcl_write_u16_le(wire + 18u, policy->reserved_threshold);
    zcl_write_u32_le(wire + 20u, policy->expected_tasks);
    memcpy(wire + 24u, policy->workload_root, 32u);
    memcpy(wire + 56u, policy->evaluator_root, 32u);
    memcpy(out, wire, sizeof(wire));
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_comparison_policy_v2 *out)
{
    static const uint8_t magic[8] = {'Z','C','R','C','M','P','2','\n'};
    if (!wire || !out) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_overlaps(wire, wire_len, out, sizeof(*out)))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    if (wire_len != ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES ||
        memcmp(wire, magic, sizeof(magic)) != 0) {
        memset(out, 0, sizeof(*out));
        return ZCL_RETRIEVAL_COMPARISON_WIRE;
    }
    struct zcl_retrieval_comparison_policy_v2 parsed = {0};
    parsed.schema_version = zcl_read_u16_le(wire + 8u);
    parsed.metric = wire[10];
    parsed.direction = wire[11];
    parsed.required_guards = zcl_read_u16_le(wire + 12u);
    parsed.evaluation_kind = zcl_read_u16_le(wire + 14u);
    parsed.threshold_bp = zcl_read_u16_le(wire + 16u);
    parsed.reserved_threshold = zcl_read_u16_le(wire + 18u);
    parsed.expected_tasks = zcl_read_u32_le(wire + 20u);
    memcpy(parsed.workload_root, wire + 24u, 32u);
    memcpy(parsed.evaluator_root, wire + 56u, 32u);
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_v2_validate(&parsed);
    if (error == ZCL_RETRIEVAL_COMPARISON_OK) *out = parsed;
    else memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_root(
    const struct zcl_retrieval_comparison_policy_v2 *policy, uint8_t out[32])
{
    if (!policy || !out) return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_overlaps(policy, sizeof(*policy), out, 32u))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES];
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_v2_serialize(policy, wire);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    static const char domain[] = ZCL_RETRIEVAL_COMPARISON_POLICY_V2_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

static uint16_t rc_metric_flag(uint8_t metric)
{
    static const uint16_t flags[] = {
        0, ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE,
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE,
        ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE,
        ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE,
    };
    return flags[metric];
}

static uint32_t rc_metric_value(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    uint8_t metric)
{
    switch (metric) {
    case ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP:
        return result->recall_at_5_bp;
    case ZCL_RETRIEVAL_COMPARISON_RECALL_AT_20_BP:
        return result->recall_at_20_bp;
    case ZCL_RETRIEVAL_COMPARISON_MRR_BP: return result->mrr_bp;
    default: return result->wrong_scope_at_5_bp;
    }
}

static bool rc_higher_direction(uint8_t direction)
{
    return direction == ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST ||
           direction == ZCL_RETRIEVAL_COMPARISON_NOT_LOWER_BY_MORE_THAN;
}

static bool rc_minimum_gain(uint8_t direction)
{
    return direction == ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST ||
           direction == ZCL_RETRIEVAL_COMPARISON_LOWER_BY_AT_LEAST;
}

static struct zcl_retrieval_comparison_report rc_fold_observation(
    uint8_t metric, uint8_t direction, uint16_t required_guards,
    uint16_t threshold_bp, const uint8_t policy_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding)
{
    struct zcl_retrieval_comparison_report result = {
        .metric = metric,
        .direction = direction,
        .failed_guards = (uint16_t)(required_guards & ~child->flags),
    };
    memcpy(result.policy_root, policy_root, 32u);
    memcpy(result.parent_result_root, parent_binding->result_root, 32u);
    memcpy(result.child_result_root, child_binding->result_root, 32u);
    uint16_t availability = rc_metric_flag(metric);
    if ((parent->flags & availability) == 0)
        result.missing_arms |= ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING;
    if ((child->flags & availability) == 0)
        result.missing_arms |= ZCL_RETRIEVAL_COMPARISON_CHILD_METRIC_MISSING;
    if (result.failed_guards != 0) {
        result.status = ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED;
    } else if (result.missing_arms != 0) {
        result.status = ZCL_RETRIEVAL_COMPARISON_INCOMPLETE;
    } else {
        int32_t parent_value = (int32_t)rc_metric_value(parent, metric);
        int32_t child_value = (int32_t)rc_metric_value(child, metric);
        result.directional_delta_bp = rc_higher_direction(direction)
            ? child_value - parent_value : parent_value - child_value;
        int32_t bound = rc_minimum_gain(direction)
            ? (int32_t)threshold_bp : -(int32_t)threshold_bp;
        result.status = result.directional_delta_bp >= bound
            ? ZCL_RETRIEVAL_COMPARISON_SATISFIED
            : ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED;
    }
    return result;
}

static bool rc_observe_aliases(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    const uint8_t expected_policy_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    const struct zcl_retrieval_comparison_report *report)
{
    return rc_overlaps(report, sizeof(*report), policy, sizeof(*policy)) ||
        rc_overlaps(report, sizeof(*report), expected_policy_root, 32u) ||
        rc_overlaps(report, sizeof(*report), parent, sizeof(*parent)) ||
        rc_overlaps(report, sizeof(*report), child, sizeof(*child)) ||
        rc_overlaps(report, sizeof(*report), parent_binding,
                    sizeof(*parent_binding)) ||
        rc_overlaps(report, sizeof(*report), child_binding,
                    sizeof(*child_binding));
}

enum zcl_retrieval_comparison_error zcl_retrieval_comparison_observe(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    const uint8_t expected_policy_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    struct zcl_retrieval_comparison_report *report)
{
    if (!policy || !expected_policy_root || !parent || !parent_binding ||
        !child || !child_binding || !report)
        return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_observe_aliases(policy, expected_policy_root, parent,
                           parent_binding, child, child_binding, report))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_validate(policy);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    uint8_t policy_root[32];
    error = zcl_retrieval_comparison_policy_root(policy, policy_root);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    if (!rc_root_any(expected_policy_root)) return ZCL_RETRIEVAL_COMPARISON_ROOT;
    if (memcmp(policy_root, expected_policy_root, 32u) != 0)
        return ZCL_RETRIEVAL_COMPARISON_BINDING;
    if (zcl_retrieval_experiment_eval_result_validate(parent) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_validate(child) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_COMPARISON_RESULT;
    if (parent->tasks != policy->expected_tasks ||
        child->tasks != policy->expected_tasks ||
        memcmp(parent_binding->result_root, child_binding->result_root, 32u) == 0 ||
        memcmp(parent_binding->subject_root, child_binding->subject_root, 32u) == 0)
        return ZCL_RETRIEVAL_COMPARISON_BINDING;
    if (zcl_retrieval_experiment_eval_result_verify_binding(
            parent, parent_binding->subject_root,
            parent_binding->proposal_input_root, policy->evaluation_input_root,
            policy->evaluator_root, parent_binding->result_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_verify_binding(
            child, child_binding->subject_root,
            child_binding->proposal_input_root, policy->evaluation_input_root,
            policy->evaluator_root, child_binding->result_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_COMPARISON_BINDING;

    struct zcl_retrieval_comparison_report result = rc_fold_observation(
        policy->metric, policy->direction, policy->required_guards,
        policy->threshold_bp, policy_root, parent, parent_binding, child,
        child_binding);
    *report = result;
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

static bool rc_paired_report_valid(
    const struct zcl_retrieval_paired_evaluation_report_v1 *paired)
{
    if (paired->schema_version != ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION ||
        paired->task_count == 0 ||
        paired->task_count > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return false;
    const uint8_t *roots[] = {
        paired->expected_task_root, paired->source_root,
        paired->retrieval_projection_root, paired->workload_root,
        paired->parent_arm_root, paired->child_arm_root,
        paired->evaluation_input_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!rc_root_any(roots[i])) return false;
    uint8_t computed[32];
    return zcl_retrieval_paired_evaluation_input_root(
               paired->workload_root, paired->parent_arm_root,
               paired->child_arm_root, computed) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK &&
           memcmp(computed, paired->evaluation_input_root, 32u) == 0;
}

static bool rc_metrics_match_result(
    const struct zcl_retrieval_eval_metrics *metrics,
    const struct zcl_retrieval_experiment_eval_result_v1 *result)
{
    const uint16_t availability_mask =
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE |
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE |
        ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE |
        ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE;
    uint16_t expected_flags = 0;
    if (metrics->recall_at_5_available)
        expected_flags |= ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE;
    if (metrics->recall_at_20_available)
        expected_flags |= ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE;
    if (metrics->mrr_available)
        expected_flags |= ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE;
    if (metrics->wrong_scope_at_5_available)
        expected_flags |= ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE;
    return metrics->tasks == result->tasks &&
        metrics->recall_at_5_bp == result->recall_at_5_bp &&
        metrics->recall_at_20_bp == result->recall_at_20_bp &&
        metrics->mrr_bp == result->mrr_bp &&
        metrics->wrong_scope_at_5_bp == result->wrong_scope_at_5_bp &&
        metrics->unique_files_at_5 == result->unique_files_at_5 &&
        metrics->wrong_scope_files_at_5 == result->wrong_scope_files_at_5 &&
        metrics->context_bytes_at_5 == result->context_bytes_at_5 &&
        metrics->context_bytes_at_5 <= UINT64_MAX - 3u &&
        metrics->approximate_tokens_at_5 ==
            (metrics->context_bytes_at_5 + 3u) / 4u &&
        (result->flags & availability_mask) == expected_flags;
}

static bool rc_observe_v2_aliases(
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    const uint8_t expected_policy_root[32],
    const struct zcl_retrieval_paired_evaluation_report_v1 *paired,
    const uint8_t expected_evaluation_input_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    const struct zcl_retrieval_comparison_report_v2 *report)
{
    return rc_overlaps(report, sizeof(*report), policy, sizeof(*policy)) ||
        rc_overlaps(report, sizeof(*report), expected_policy_root, 32u) ||
        rc_overlaps(report, sizeof(*report), paired, sizeof(*paired)) ||
        rc_overlaps(report, sizeof(*report),
                    expected_evaluation_input_root, 32u) ||
        rc_overlaps(report, sizeof(*report), parent, sizeof(*parent)) ||
        rc_overlaps(report, sizeof(*report), child, sizeof(*child)) ||
        rc_overlaps(report, sizeof(*report), parent_binding,
                    sizeof(*parent_binding)) ||
        rc_overlaps(report, sizeof(*report), child_binding,
                    sizeof(*child_binding));
}

enum zcl_retrieval_comparison_error zcl_retrieval_comparison_observe_v2(
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    const uint8_t expected_policy_root[32],
    const struct zcl_retrieval_paired_evaluation_report_v1 *paired,
    const uint8_t expected_evaluation_input_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    struct zcl_retrieval_comparison_report_v2 *report)
{
    if (!policy || !expected_policy_root || !paired ||
        !expected_evaluation_input_root || !parent || !parent_binding ||
        !child || !child_binding || !report)
        return ZCL_RETRIEVAL_COMPARISON_NULL;
    if (rc_observe_v2_aliases(
            policy, expected_policy_root, paired,
            expected_evaluation_input_root, parent, parent_binding, child,
            child_binding, report))
        return ZCL_RETRIEVAL_COMPARISON_ALIAS;
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_v2_validate(policy);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    uint8_t policy_root[32];
    error = zcl_retrieval_comparison_policy_v2_root(policy, policy_root);
    if (error != ZCL_RETRIEVAL_COMPARISON_OK) return error;
    if (!rc_root_any(expected_policy_root) ||
        !rc_root_any(expected_evaluation_input_root))
        return ZCL_RETRIEVAL_COMPARISON_ROOT;
    if (memcmp(policy_root, expected_policy_root, 32u) != 0)
        return ZCL_RETRIEVAL_COMPARISON_BINDING;
    if (!rc_paired_report_valid(paired))
        return ZCL_RETRIEVAL_COMPARISON_RESULT;
    if (memcmp(policy->workload_root, paired->workload_root, 32u) != 0 ||
        policy->expected_tasks != paired->task_count ||
        memcmp(expected_evaluation_input_root,
               paired->evaluation_input_root, 32u) != 0)
        return ZCL_RETRIEVAL_COMPARISON_BINDING;
    if (zcl_retrieval_experiment_eval_result_validate(parent) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_validate(child) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_COMPARISON_RESULT;
    if (parent->tasks != policy->expected_tasks ||
        child->tasks != policy->expected_tasks ||
        memcmp(parent_binding->result_root,
               child_binding->result_root, 32u) == 0 ||
        memcmp(parent_binding->subject_root,
               child_binding->subject_root, 32u) == 0 ||
        !rc_metrics_match_result(&paired->parent_metrics, parent) ||
        !rc_metrics_match_result(&paired->child_metrics, child))
        return ZCL_RETRIEVAL_COMPARISON_BINDING;
    if (zcl_retrieval_experiment_eval_result_verify_binding(
            parent, parent_binding->subject_root,
            parent_binding->proposal_input_root,
            paired->evaluation_input_root, policy->evaluator_root,
            parent_binding->result_root) != ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_experiment_eval_result_verify_binding(
            child, child_binding->subject_root,
            child_binding->proposal_input_root,
            paired->evaluation_input_root, policy->evaluator_root,
            child_binding->result_root) != ZCL_RETRIEVAL_EXPERIMENT_OK)
        return ZCL_RETRIEVAL_COMPARISON_BINDING;

    struct zcl_retrieval_comparison_report_v2 result = {0};
    result.observation = rc_fold_observation(
        policy->metric, policy->direction, policy->required_guards,
        policy->threshold_bp, policy_root, parent, parent_binding, child,
        child_binding);
    memcpy(result.workload_root, paired->workload_root, 32u);
    memcpy(result.evaluation_input_root, paired->evaluation_input_root, 32u);
    *report = result;
    return ZCL_RETRIEVAL_COMPARISON_OK;
}

const char *zcl_retrieval_comparison_error_string(
    enum zcl_retrieval_comparison_error error)
{
    switch (error) {
    case ZCL_RETRIEVAL_COMPARISON_OK: return "ok";
    case ZCL_RETRIEVAL_COMPARISON_NULL: return "null argument";
    case ZCL_RETRIEVAL_COMPARISON_ALIAS: return "output aliases input";
    case ZCL_RETRIEVAL_COMPARISON_VERSION: return "unsupported version";
    case ZCL_RETRIEVAL_COMPARISON_RESERVED: return "reserved field is nonzero";
    case ZCL_RETRIEVAL_COMPARISON_PARAMETER: return "invalid comparison policy";
    case ZCL_RETRIEVAL_COMPARISON_ROOT: return "required root is zero";
    case ZCL_RETRIEVAL_COMPARISON_WIRE: return "invalid policy wire";
    case ZCL_RETRIEVAL_COMPARISON_RESULT: return "invalid evaluation result";
    case ZCL_RETRIEVAL_COMPARISON_BINDING: return "comparison binding mismatch";
    }
    return "unknown";
}
