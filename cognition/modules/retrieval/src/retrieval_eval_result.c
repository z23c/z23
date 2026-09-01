/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical inert evidence for bounded retrieval experiments. */
#include "retrieval/retrieval_experiment.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

static bool rer_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool rer_memory_overlaps(const void *left, size_t left_size,
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

enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_validate(
    const struct zcl_retrieval_experiment_eval_result_v1 *result)
{
    if (!result) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (result->schema_version != ZCL_RETRIEVAL_EVAL_RESULT_VERSION)
        return ZCL_RETRIEVAL_EXPERIMENT_VERSION;
    if ((result->flags & ~ZCL_RETRIEVAL_EVAL_RESULT_FLAGS_ALL) != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_RESERVED;
    if (result->tasks == 0 ||
        result->tasks > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    const uint32_t metric_values[] = {
        result->recall_at_5_bp, result->recall_at_20_bp,
        result->mrr_bp, result->wrong_scope_at_5_bp,
    };
    const uint16_t metric_flags[] = {
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE,
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE,
        ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE,
        ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE,
    };
    for (size_t i = 0; i < 4u; i++) {
        if (metric_values[i] > ZCL_RETRIEVAL_EVAL_BASIS_POINTS ||
            ((result->flags & metric_flags[i]) == 0 &&
             metric_values[i] != 0))
            return ZCL_RETRIEVAL_EXPERIMENT_EVALUATION;
    }
    uint32_t selected_max = result->tasks * ZCL_RETRIEVAL_EXPERIMENT_TOP;
    if (result->unique_files_at_5 > selected_max ||
        result->changed_positions_at_5 > selected_max ||
        result->fallback_tasks > result->tasks ||
        result->context_bytes_at_5 > UINT64_MAX - 3u)
        return ZCL_RETRIEVAL_EXPERIMENT_EVALUATION;
    bool scope_available = (result->flags &
        ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE) != 0;
    if ((!scope_available && result->wrong_scope_files_at_5 != 0) ||
        (scope_available &&
         (result->unique_files_at_5 == 0 ||
          result->wrong_scope_files_at_5 > result->unique_files_at_5 ||
          result->wrong_scope_at_5_bp !=
              (uint32_t)((uint64_t)result->wrong_scope_files_at_5 *
                  ZCL_RETRIEVAL_EVAL_BASIS_POINTS /
                  result->unique_files_at_5))))
        return ZCL_RETRIEVAL_EXPERIMENT_EVALUATION;
    const uint8_t *const roots[] = {
        result->subject_root, result->proposal_input_root,
        result->evaluation_input_root, result->evaluator_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!rer_root_any(roots[i]))
            return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_init(
    struct zcl_retrieval_experiment_eval_result_v1 *out,
    const struct zcl_retrieval_experiment_eval_report *report,
    const uint8_t subject_root[32],
    const uint8_t proposal_input_root[32],
    const uint8_t evaluation_input_root[32],
    const uint8_t evaluator_root[32])
{
    if (!out || !report || !subject_root || !proposal_input_root ||
        !evaluation_input_root || !evaluator_root)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rer_memory_overlaps(out, sizeof(*out), report, sizeof(*report)) ||
        rer_memory_overlaps(out, sizeof(*out), subject_root, 32u) ||
        rer_memory_overlaps(out, sizeof(*out), proposal_input_root, 32u) ||
        rer_memory_overlaps(out, sizeof(*out), evaluation_input_root, 32u) ||
        rer_memory_overlaps(out, sizeof(*out), evaluator_root, 32u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    const struct zcl_retrieval_eval_metrics *metrics = &report->metrics;
    if (metrics->unique_files_at_5 > UINT32_MAX ||
        metrics->wrong_scope_files_at_5 > UINT32_MAX ||
        report->changed_positions_at_5 > UINT32_MAX ||
        report->fallback_tasks > UINT32_MAX ||
        metrics->context_bytes_at_5 > UINT64_MAX - 3u ||
        metrics->approximate_tokens_at_5 !=
            (metrics->context_bytes_at_5 + 3u) / 4u)
        return ZCL_RETRIEVAL_EXPERIMENT_EVALUATION;
    struct zcl_retrieval_experiment_eval_result_v1 result = {
        .schema_version = ZCL_RETRIEVAL_EVAL_RESULT_VERSION,
        .tasks = metrics->tasks,
        .recall_at_5_bp = metrics->recall_at_5_bp,
        .recall_at_20_bp = metrics->recall_at_20_bp,
        .mrr_bp = metrics->mrr_bp,
        .wrong_scope_at_5_bp = metrics->wrong_scope_at_5_bp,
        .unique_files_at_5 = (uint32_t)metrics->unique_files_at_5,
        .wrong_scope_files_at_5 =
            (uint32_t)metrics->wrong_scope_files_at_5,
        .changed_positions_at_5 =
            (uint32_t)report->changed_positions_at_5,
        .fallback_tasks = (uint32_t)report->fallback_tasks,
        .context_bytes_at_5 = metrics->context_bytes_at_5,
    };
    if (metrics->recall_at_5_available)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE;
    if (metrics->recall_at_20_available)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE;
    if (metrics->mrr_available)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE;
    if (metrics->wrong_scope_at_5_available)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE;
    if (report->top20_membership_preserved)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED;
    if (report->full_retained_set_preserved)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_RETAINED_SET_PRESERVED;
    if (report->context_ceiling_preserved)
        result.flags |= ZCL_RETRIEVAL_EVAL_RESULT_CONTEXT_CEILING_PRESERVED;
    memcpy(result.subject_root, subject_root, 32u);
    memcpy(result.proposal_input_root, proposal_input_root, 32u);
    memcpy(result.evaluation_input_root, evaluation_input_root, 32u);
    memcpy(result.evaluator_root, evaluator_root, 32u);
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_eval_result_validate(&result);
    if (error == ZCL_RETRIEVAL_EXPERIMENT_OK) *out = result;
    return error;
}

enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_serialize(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    uint8_t out[ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES])
{
    static const uint8_t magic[8] = {'Z','C','R','X','E','V','1','\n'};
    if (!result || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rer_memory_overlaps(result, sizeof(*result), out,
                            ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_eval_result_validate(result);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    uint8_t wire[ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES] = {0};
    memcpy(wire, magic, sizeof(magic));
    zcl_write_u16_le(wire + 8u, result->schema_version);
    zcl_write_u16_le(wire + 10u, result->flags);
    zcl_write_u32_le(wire + 12u, result->tasks);
    zcl_write_u32_le(wire + 16u, result->recall_at_5_bp);
    zcl_write_u32_le(wire + 20u, result->recall_at_20_bp);
    zcl_write_u32_le(wire + 24u, result->mrr_bp);
    zcl_write_u32_le(wire + 28u, result->wrong_scope_at_5_bp);
    zcl_write_u32_le(wire + 32u, result->unique_files_at_5);
    zcl_write_u32_le(wire + 36u, result->wrong_scope_files_at_5);
    zcl_write_u32_le(wire + 40u, result->changed_positions_at_5);
    zcl_write_u32_le(wire + 44u, result->fallback_tasks);
    zcl_write_u64_le(wire + 48u, result->context_bytes_at_5);
    memcpy(wire + 56u, result->subject_root, 32u);
    memcpy(wire + 88u, result->proposal_input_root, 32u);
    memcpy(wire + 120u, result->evaluation_input_root, 32u);
    memcpy(wire + 152u, result->evaluator_root, 32u);
    memcpy(out, wire, sizeof(wire));
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_experiment_eval_result_v1 *out)
{
    static const uint8_t magic[8] = {'Z','C','R','X','E','V','1','\n'};
    if (!wire || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rer_memory_overlaps(wire, wire_len, out, sizeof(*out)))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    if (wire_len != ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES ||
        memcmp(wire, magic, sizeof(magic)) != 0) {
        memset(out, 0, sizeof(*out));
        return ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE;
    }
    struct zcl_retrieval_experiment_eval_result_v1 result = {0};
    result.schema_version = zcl_read_u16_le(wire + 8u);
    result.flags = zcl_read_u16_le(wire + 10u);
    result.tasks = zcl_read_u32_le(wire + 12u);
    result.recall_at_5_bp = zcl_read_u32_le(wire + 16u);
    result.recall_at_20_bp = zcl_read_u32_le(wire + 20u);
    result.mrr_bp = zcl_read_u32_le(wire + 24u);
    result.wrong_scope_at_5_bp = zcl_read_u32_le(wire + 28u);
    result.unique_files_at_5 = zcl_read_u32_le(wire + 32u);
    result.wrong_scope_files_at_5 = zcl_read_u32_le(wire + 36u);
    result.changed_positions_at_5 = zcl_read_u32_le(wire + 40u);
    result.fallback_tasks = zcl_read_u32_le(wire + 44u);
    result.context_bytes_at_5 = zcl_read_u64_le(wire + 48u);
    memcpy(result.subject_root, wire + 56u, 32u);
    memcpy(result.proposal_input_root, wire + 88u, 32u);
    memcpy(result.evaluation_input_root, wire + 120u, 32u);
    memcpy(result.evaluator_root, wire + 152u, 32u);
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_eval_result_validate(&result);
    if (error == ZCL_RETRIEVAL_EXPERIMENT_OK) *out = result;
    else memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_root(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    uint8_t out[32])
{
    if (!result || !out) return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (rer_memory_overlaps(result, sizeof(*result), out, 32u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    uint8_t wire[ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_eval_result_serialize(result, wire);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    static const char domain[] = ZCL_RETRIEVAL_EVAL_RESULT_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    uint8_t root[32];
    sha3_256_finalize(&sha, root);
    memcpy(out, root, sizeof(root));
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_verify_binding(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    const uint8_t expected_subject_root[32],
    const uint8_t expected_proposal_input_root[32],
    const uint8_t expected_evaluation_input_root[32],
    const uint8_t expected_evaluator_root[32],
    const uint8_t expected_result_root[32])
{
    if (!result || !expected_subject_root || !expected_proposal_input_root ||
        !expected_evaluation_input_root || !expected_evaluator_root ||
        !expected_result_root)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    uint8_t result_root[32];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_eval_result_root(result, result_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    if (!rer_root_any(expected_subject_root) ||
        !rer_root_any(expected_proposal_input_root) ||
        !rer_root_any(expected_evaluation_input_root) ||
        !rer_root_any(expected_evaluator_root) ||
        !rer_root_any(expected_result_root) ||
        memcmp(result->subject_root, expected_subject_root, 32u) != 0 ||
        memcmp(result->proposal_input_root,
               expected_proposal_input_root, 32u) != 0 ||
        memcmp(result->evaluation_input_root,
               expected_evaluation_input_root, 32u) != 0 ||
        memcmp(result->evaluator_root, expected_evaluator_root, 32u) != 0 ||
        memcmp(result_root, expected_result_root, 32u) != 0)
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}
