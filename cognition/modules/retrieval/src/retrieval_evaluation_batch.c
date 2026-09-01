/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact, bounded paired inputs for the maintained retrieval evaluator. */
#include "retrieval/retrieval_evaluation_batch.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

static bool peb_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static bool peb_memory_overlaps(const void *left, size_t left_size,
                                const void *right, size_t right_size)
{
    uintptr_t left_address = (uintptr_t)left;
    uintptr_t right_address = (uintptr_t)right;
    if (left_size == 0 || right_size == 0) return false;
    if (left_address > UINTPTR_MAX - left_size ||
        right_address > UINTPTR_MAX - right_size)
        return true;
    return left_address < right_address + right_size &&
           right_address < left_address + left_size;
}

static enum zcl_retrieval_experiment_error peb_text_length(
    const char *text, size_t maximum, size_t *length_out)
{
    if (!text || !length_out) return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    size_t length = 0;
    while (length <= maximum && text[length]) length++;
    if (length == 0) return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (length > maximum) return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
    *length_out = length;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static void peb_write_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t encoded[2];
    zcl_write_u16_le(encoded, value);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

static void peb_write_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t encoded[4];
    zcl_write_u32_le(encoded, value);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

static void peb_write_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t encoded[8];
    zcl_write_u64_le(encoded, value);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

static void peb_write_text(struct sha3_256_ctx *sha, const char *text,
                           size_t length)
{
    peb_write_u32(sha, (uint32_t)length);
    sha3_256_write(sha, (const uint8_t *)text, length);
}

static enum zcl_retrieval_experiment_error peb_alias_text(
    const struct zcl_retrieval_paired_evaluation_report_v1 *out,
    const char *text, size_t length)
{
    if (peb_memory_overlaps(out, sizeof(*out), text, length + 1u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static enum zcl_retrieval_experiment_error peb_validate_workload(
    const struct zcl_retrieval_paired_evaluation_task_v1 *tasks,
    size_t task_count,
    const struct zcl_retrieval_paired_evaluation_report_v1 *out,
    struct sha3_256_ctx *sha)
{
    for (size_t i = 0; i < task_count; i++) {
        const struct zcl_retrieval_paired_evaluation_task_v1 *task = &tasks[i];
        size_t task_id_length = 0, query_length = 0;
        enum zcl_retrieval_experiment_error error = peb_text_length(
            task->task_id, ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX,
            &task_id_length);
        if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
        error = peb_text_length(
            task->query, ZCL_RETRIEVAL_PAIRED_EVALUATION_QUERY_MAX,
            &query_length);
        if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
        if (peb_alias_text(out, task->task_id, task_id_length) !=
                ZCL_RETRIEVAL_EXPERIMENT_OK ||
            peb_alias_text(out, task->query, query_length) !=
                ZCL_RETRIEVAL_EXPERIMENT_OK)
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
        for (size_t prior = 0; prior < i; prior++)
            if (strcmp(task->task_id, tasks[prior].task_id) == 0)
                return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
        if (!task->relevant_paths || task->relevant_count == 0)
            return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
        if (task->relevant_count > ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX)
            return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
        if (peb_memory_overlaps(out, sizeof(*out), task->relevant_paths,
                task->relevant_count * sizeof(task->relevant_paths[0])))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
        peb_write_text(sha, task->task_id, task_id_length);
        peb_write_text(sha, task->query, query_length);
        peb_write_u32(sha, (uint32_t)task->relevant_count);
        for (size_t relevant = 0; relevant < task->relevant_count;
             relevant++) {
            size_t path_length = 0;
            error = peb_text_length(task->relevant_paths[relevant],
                ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX, &path_length);
            if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
            if (peb_alias_text(out, task->relevant_paths[relevant],
                               path_length) !=
                    ZCL_RETRIEVAL_EXPERIMENT_OK)
                return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
            for (size_t prior = 0; prior < relevant; prior++)
                if (strcmp(task->relevant_paths[relevant],
                           task->relevant_paths[prior]) == 0)
                    return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
            peb_write_text(sha, task->relevant_paths[relevant], path_length);
        }
    }
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static enum zcl_retrieval_experiment_error peb_arm_root(
    const struct zcl_retrieval_paired_evaluation_task_v1 *tasks,
    size_t task_count, bool child, const uint8_t workload_root[32],
    const struct zcl_retrieval_paired_evaluation_report_v1 *out,
    uint8_t root[32])
{
    static const char domain[] = ZCL_RETRIEVAL_EVALUATION_ARM_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    peb_write_u16(&sha, ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION);
    sha3_256_write(&sha, workload_root, 32u);
    peb_write_u32(&sha, (uint32_t)task_count);
    for (size_t i = 0; i < task_count; i++) {
        const struct zcl_retrieval_paired_evaluation_task_v1 *task = &tasks[i];
        const struct zcl_retrieval_ranked_file *ranked = child ?
            task->child_ranked : task->parent_ranked;
        size_t ranked_count = child ? task->child_count : task->parent_count;
        bool complete = child ? task->child_complete : task->parent_complete;
        size_t task_id_length = 0;
        enum zcl_retrieval_experiment_error error = peb_text_length(
            task->task_id, ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX,
            &task_id_length);
        if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
        if ((!ranked && ranked_count != 0))
            return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
        if (ranked_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
            return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
        if (peb_memory_overlaps(out, sizeof(*out), ranked,
                                ranked_count * sizeof(ranked[0])))
            return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
        peb_write_text(&sha, task->task_id, task_id_length);
        uint8_t complete_byte = complete ? 1u : 0u;
        sha3_256_write(&sha, &complete_byte, 1u);
        peb_write_u32(&sha, (uint32_t)ranked_count);
        for (size_t row = 0; row < ranked_count; row++) {
            size_t path_length = 0;
            error = peb_text_length(ranked[row].path,
                ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX, &path_length);
            if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
            if (peb_alias_text(out, ranked[row].path, path_length) !=
                    ZCL_RETRIEVAL_EXPERIMENT_OK)
                return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;
            if (!ranked[row].in_scope_available && ranked[row].in_scope)
                return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
            for (size_t prior = 0; prior < row; prior++)
                if (strcmp(ranked[row].path, ranked[prior].path) == 0)
                    return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
            peb_write_text(&sha, ranked[row].path, path_length);
            peb_write_u64(&sha, ranked[row].context_bytes);
            uint8_t available = ranked[row].in_scope_available ? 1u : 0u;
            uint8_t in_scope = ranked[row].in_scope ? 1u : 0u;
            sha3_256_write(&sha, &available, 1u);
            sha3_256_write(&sha, &in_scope, 1u);
        }
    }
    sha3_256_finalize(&sha, root);
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}

enum zcl_retrieval_experiment_error zcl_retrieval_paired_evaluate(
    const struct zcl_retrieval_paired_evaluation_task_v1 *tasks,
    size_t task_count,
    const uint8_t expected_task_root[32],
    const uint8_t source_root[32],
    const uint8_t retrieval_projection_root[32],
    struct zcl_retrieval_paired_evaluation_report_v1 *out)
{
    static const char workload_domain[] =
        ZCL_RETRIEVAL_EVALUATION_WORKLOAD_DOMAIN;
    static const char input_domain[] =
        ZCL_RETRIEVAL_PAIRED_EVALUATION_INPUT_DOMAIN;
    if (!tasks || !expected_task_root || !source_root ||
        !retrieval_projection_root || !out)
        return ZCL_RETRIEVAL_EXPERIMENT_NULL;
    if (task_count == 0) return ZCL_RETRIEVAL_EXPERIMENT_SHAPE;
    if (task_count > ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX)
        return ZCL_RETRIEVAL_EXPERIMENT_CAPACITY;
    if (!peb_root_any(expected_task_root) || !peb_root_any(source_root) ||
        !peb_root_any(retrieval_projection_root))
        return ZCL_RETRIEVAL_EXPERIMENT_BINDING;
    if (peb_memory_overlaps(out, sizeof(*out), tasks,
                            task_count * sizeof(tasks[0])) ||
        peb_memory_overlaps(out, sizeof(*out), expected_task_root, 32u) ||
        peb_memory_overlaps(out, sizeof(*out), source_root, 32u) ||
        peb_memory_overlaps(out, sizeof(*out), retrieval_projection_root, 32u))
        return ZCL_RETRIEVAL_EXPERIMENT_ALIAS;

    struct zcl_retrieval_paired_evaluation_report_v1 result = {
        .schema_version = ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION,
        .task_count = (uint32_t)task_count,
    };
    memcpy(result.expected_task_root, expected_task_root, 32u);
    memcpy(result.source_root, source_root, 32u);
    memcpy(result.retrieval_projection_root, retrieval_projection_root, 32u);

    struct sha3_256_ctx workload_sha;
    sha3_256_init(&workload_sha);
    sha3_256_write(&workload_sha, (const uint8_t *)workload_domain,
                   sizeof(workload_domain));
    peb_write_u16(&workload_sha,
                  ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION);
    sha3_256_write(&workload_sha, expected_task_root, 32u);
    sha3_256_write(&workload_sha, source_root, 32u);
    sha3_256_write(&workload_sha, retrieval_projection_root, 32u);
    peb_write_u32(&workload_sha, (uint32_t)task_count);
    enum zcl_retrieval_experiment_error error = peb_validate_workload(
        tasks, task_count, out, &workload_sha);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    sha3_256_finalize(&workload_sha, result.workload_root);

    error = peb_arm_root(tasks, task_count, false, result.workload_root, out,
                         result.parent_arm_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;
    error = peb_arm_root(tasks, task_count, true, result.workload_root, out,
                         result.child_arm_root);
    if (error != ZCL_RETRIEVAL_EXPERIMENT_OK) return error;

    struct zcl_retrieval_gold_task parent[ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX];
    struct zcl_retrieval_gold_task child[ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX];
    for (size_t i = 0; i < task_count; i++) {
        parent[i] = (struct zcl_retrieval_gold_task){
            .task_id = tasks[i].task_id,
            .query = tasks[i].query,
            .relevant_paths = tasks[i].relevant_paths,
            .relevant_count = tasks[i].relevant_count,
            .ranked = tasks[i].parent_ranked,
            .ranked_count = tasks[i].parent_count,
            .ranking_complete = tasks[i].parent_complete,
        };
        child[i] = (struct zcl_retrieval_gold_task){
            .task_id = tasks[i].task_id,
            .query = tasks[i].query,
            .relevant_paths = tasks[i].relevant_paths,
            .relevant_count = tasks[i].relevant_count,
            .ranked = tasks[i].child_ranked,
            .ranked_count = tasks[i].child_count,
            .ranking_complete = tasks[i].child_complete,
        };
    }
    if (!zcl_retrieval_evaluate(parent, task_count, &result.parent_metrics) ||
        !zcl_retrieval_evaluate(child, task_count, &result.child_metrics))
        return ZCL_RETRIEVAL_EXPERIMENT_EVALUATION;

    struct sha3_256_ctx input_sha;
    sha3_256_init(&input_sha);
    sha3_256_write(&input_sha, (const uint8_t *)input_domain,
                   sizeof(input_domain));
    peb_write_u16(&input_sha, ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION);
    sha3_256_write(&input_sha, result.workload_root, 32u);
    sha3_256_write(&input_sha, result.parent_arm_root, 32u);
    sha3_256_write(&input_sha, result.child_arm_root, 32u);
    sha3_256_finalize(&input_sha, result.evaluation_input_root);
    *out = result;
    return ZCL_RETRIEVAL_EXPERIMENT_OK;
}
