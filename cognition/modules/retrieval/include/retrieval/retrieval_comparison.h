/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: preregistered exact comparison of retrieval observations. */
#ifndef ZCL_RETRIEVAL_COMPARISON_H
#define ZCL_RETRIEVAL_COMPARISON_H

#include "retrieval/retrieval_evaluation_batch.h"
#include "retrieval/retrieval_experiment.h"

#include <stddef.h>
#include <stdint.h>

#define ZCL_RETRIEVAL_COMPARISON_POLICY_VERSION 1u
#define ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES 88u
#define ZCL_RETRIEVAL_COMPARISON_POLICY_DOMAIN \
    "zcl.retrieval_comparison_policy.v1"
#define ZCL_RETRIEVAL_COMPARISON_POLICY_V2_VERSION 2u
#define ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES 88u
#define ZCL_RETRIEVAL_COMPARISON_POLICY_V2_DOMAIN \
    "zcl.retrieval_comparison_policy.v2"

#define ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL \
    ((uint16_t)(ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED | \
                ZCL_RETRIEVAL_EVAL_RESULT_RETAINED_SET_PRESERVED | \
                ZCL_RETRIEVAL_EVAL_RESULT_CONTEXT_CEILING_PRESERVED))

#define ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING (1u << 0)
#define ZCL_RETRIEVAL_COMPARISON_CHILD_METRIC_MISSING (1u << 1)

enum zcl_retrieval_comparison_metric {
    ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP = 1,
    ZCL_RETRIEVAL_COMPARISON_RECALL_AT_20_BP = 2,
    ZCL_RETRIEVAL_COMPARISON_MRR_BP = 3,
    ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP = 4,
};

/* Directional delta is child-parent for the two HIGHER predicates and
 * parent-child for the two LOWER predicates. A minimum-gain predicate passes
 * at +threshold; a noninferiority predicate passes at -threshold. */
enum zcl_retrieval_comparison_direction {
    ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST = 1,
    ZCL_RETRIEVAL_COMPARISON_LOWER_BY_AT_LEAST = 2,
    ZCL_RETRIEVAL_COMPARISON_NOT_LOWER_BY_MORE_THAN = 3,
    ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN = 4,
};

enum zcl_retrieval_comparison_status {
    ZCL_RETRIEVAL_COMPARISON_SATISFIED = 1,
    ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED = 2,
    ZCL_RETRIEVAL_COMPARISON_INCOMPLETE = 3,
};

enum zcl_retrieval_comparison_evaluation_kind {
    ZCL_RETRIEVAL_COMPARISON_DERIVED_PROFILE_PAIRED_V1 = 1,
};

enum zcl_retrieval_comparison_error {
    ZCL_RETRIEVAL_COMPARISON_OK = 0,
    ZCL_RETRIEVAL_COMPARISON_NULL,
    ZCL_RETRIEVAL_COMPARISON_ALIAS,
    ZCL_RETRIEVAL_COMPARISON_VERSION,
    ZCL_RETRIEVAL_COMPARISON_RESERVED,
    ZCL_RETRIEVAL_COMPARISON_PARAMETER,
    ZCL_RETRIEVAL_COMPARISON_ROOT,
    ZCL_RETRIEVAL_COMPARISON_WIRE,
    ZCL_RETRIEVAL_COMPARISON_RESULT,
    ZCL_RETRIEVAL_COMPARISON_BINDING,
};

/* Frozen before observation. evaluation_input_root is the evidence owner's
 * exact shared pair/batch identity; expected_tasks is its bounded row count.
 * This policy does not establish chronology, hidden-gold or holdout
 * independence, replication, evaluator correctness, or authority. */
struct zcl_retrieval_comparison_policy_v1 {
    uint16_t schema_version;
    uint8_t metric;
    uint8_t direction;
    uint16_t required_guards;
    uint16_t reserved;
    uint16_t threshold_bp;
    uint16_t reserved_threshold;
    uint32_t expected_tasks;
    uint8_t evaluation_input_root[32];
    uint8_t evaluator_root[32];
};

/* Frozen before either derived-profile arm is observed. workload_root binds
 * only the preregisterable paired workload; the future ordered arm identity is
 * supplied separately to observe_v2. evaluation_kind identifies the sole
 * adapter whose paired metrics this version accepts. It establishes no
 * chronology, provenance, hidden-gold property, independence, evaluator
 * correctness, replication, attention, lifecycle, or authority. */
struct zcl_retrieval_comparison_policy_v2 {
    uint16_t schema_version;
    uint8_t metric;
    uint8_t direction;
    uint16_t required_guards;
    uint16_t evaluation_kind;
    uint16_t threshold_bp;
    uint16_t reserved_threshold;
    uint32_t expected_tasks;
    uint8_t workload_root[32];
    uint8_t evaluator_root[32];
};

/* Caller-owned expected identities. These are not accepted from the result
 * being checked. "parent" and "child" are labels only in this module: this
 * object proves no heuristic lineage or ancestry. */
struct zcl_retrieval_comparison_arm_binding {
    uint8_t subject_root[32];
    uint8_t proposal_input_root[32];
    uint8_t result_root[32];
};

struct zcl_retrieval_comparison_report {
    enum zcl_retrieval_comparison_status status;
    uint8_t metric;
    uint8_t direction;
    uint8_t missing_arms;
    uint16_t failed_guards;
    int32_t directional_delta_bp;
    uint8_t policy_root[32];
    uint8_t parent_result_root[32];
    uint8_t child_result_root[32];
};

struct zcl_retrieval_comparison_report_v2 {
    struct zcl_retrieval_comparison_report observation;
    uint8_t workload_root[32];
    uint8_t evaluation_input_root[32];
};

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_validate(
    const struct zcl_retrieval_comparison_policy_v1 *policy);
enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_serialize(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    uint8_t out[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES]);
enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_comparison_policy_v1 *out);
enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_root(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    uint8_t out[32]);

enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_validate(
    const struct zcl_retrieval_comparison_policy_v2 *policy);
enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_serialize(
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    uint8_t out[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES]);
enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_comparison_policy_v2 *out);
enum zcl_retrieval_comparison_error
zcl_retrieval_comparison_policy_v2_root(
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    uint8_t out[32]);

/* Pure observational fold over two existing immutable result objects. Required
 * guards apply to the child observation. Missing selected metrics yield
 * INCOMPLETE; a failed required guard is a known NOT_SATISFIED observation.
 * Malformed or misbound input is a hard error and leaves report unchanged. */
enum zcl_retrieval_comparison_error zcl_retrieval_comparison_observe(
    const struct zcl_retrieval_comparison_policy_v1 *policy,
    const uint8_t expected_policy_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    struct zcl_retrieval_comparison_report *report);

/* Bind a v2 workload policy to one computed paired observation and to two
 * immutable result objects before applying the same arithmetic as v1. Every
 * paired metric, availability bit, selected-file count, scope count, and
 * context-byte total must equal its result field. Guard bits remain
 * result-owned: the paired evaluator does not establish them, and only the
 * derived-profile adapter that observes those facts may set them. Malformed or
 * misbound input is a hard error and leaves report unchanged. */
enum zcl_retrieval_comparison_error zcl_retrieval_comparison_observe_v2(
    const struct zcl_retrieval_comparison_policy_v2 *policy,
    const uint8_t expected_policy_root[32],
    const struct zcl_retrieval_paired_evaluation_report_v1 *paired,
    const uint8_t expected_evaluation_input_root[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    struct zcl_retrieval_comparison_report_v2 *report);

const char *zcl_retrieval_comparison_error_string(
    enum zcl_retrieval_comparison_error error);

#endif /* ZCL_RETRIEVAL_COMPARISON_H */
