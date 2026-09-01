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

    struct zcl_retrieval_comparison_report result = {
        .metric = policy->metric,
        .direction = policy->direction,
        .failed_guards = (uint16_t)(policy->required_guards & ~child->flags),
    };
    memcpy(result.policy_root, policy_root, 32u);
    memcpy(result.parent_result_root, parent_binding->result_root, 32u);
    memcpy(result.child_result_root, child_binding->result_root, 32u);
    uint16_t availability = rc_metric_flag(policy->metric);
    if ((parent->flags & availability) == 0) result.missing_arms |=
        ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING;
    if ((child->flags & availability) == 0) result.missing_arms |=
        ZCL_RETRIEVAL_COMPARISON_CHILD_METRIC_MISSING;
    if (result.failed_guards != 0) {
        result.status = ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED;
    } else if (result.missing_arms != 0) {
        result.status = ZCL_RETRIEVAL_COMPARISON_INCOMPLETE;
    } else {
        int32_t parent_value = (int32_t)rc_metric_value(parent, policy->metric);
        int32_t child_value = (int32_t)rc_metric_value(child, policy->metric);
        result.directional_delta_bp = rc_higher_direction(policy->direction)
            ? child_value - parent_value : parent_value - child_value;
        int32_t bound = rc_minimum_gain(policy->direction)
            ? (int32_t)policy->threshold_bp
            : -(int32_t)policy->threshold_bp;
        result.status = result.directional_delta_bp >= bound
            ? ZCL_RETRIEVAL_COMPARISON_SATISFIED
            : ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED;
    }
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
