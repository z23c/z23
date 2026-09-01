/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact, bounded paired inputs for the maintained retrieval evaluator. */
#ifndef ZCL_RETRIEVAL_EVALUATION_BATCH_H
#define ZCL_RETRIEVAL_EVALUATION_BATCH_H

#include "retrieval/retrieval_experiment.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION 1u
#define ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX 128u
#define ZCL_RETRIEVAL_PAIRED_EVALUATION_QUERY_MAX 768u
#define ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX 255u
#define ZCL_RETRIEVAL_EVALUATION_WORKLOAD_DOMAIN \
    "zcl.retrieval_evaluation_workload.v1"
#define ZCL_RETRIEVAL_EVALUATION_ARM_DOMAIN \
    "zcl.retrieval_evaluation_arm.v1"
#define ZCL_RETRIEVAL_PAIRED_EVALUATION_INPUT_DOMAIN \
    "zcl.retrieval_paired_evaluation_input.v1"

/* Caller order is exact identity for tasks, relevant paths, and rankings.
 * Task ids, relevant paths within a task, and ranked paths within an arm must
 * each be unique; no sorting, deduplication, or normalization is performed. */
struct zcl_retrieval_paired_evaluation_task_v1 {
    const char *task_id;
    const char *query;
    const char *const *relevant_paths;
    size_t relevant_count;
    const struct zcl_retrieval_ranked_file *parent_ranked;
    size_t parent_count;
    bool parent_complete;
    const struct zcl_retrieval_ranked_file *child_ranked;
    size_t child_count;
    bool child_complete;
};

struct zcl_retrieval_paired_evaluation_report_v1 {
    uint16_t schema_version;
    uint32_t task_count;
    struct zcl_retrieval_eval_metrics parent_metrics;
    struct zcl_retrieval_eval_metrics child_metrics;
    uint8_t expected_task_root[32];
    uint8_t source_root[32];
    uint8_t retrieval_projection_root[32];
    uint8_t workload_root[32];
    uint8_t parent_arm_root[32];
    uint8_t child_arm_root[32];
    uint8_t evaluation_input_root[32];
};

/* Computes two observations through zcl_retrieval_evaluate and their exact
 * SHA3-256 input identities. All integer prefixes are little-endian. Each
 * domain includes its terminating NUL in the hash.
 *
 * workload_root hashes: domain, u16 version, the exact nonzero expected task,
 * source, and retrieval-projection roots, u32 task count, then for every task
 * its u32-length-prefixed task id and query, u32 relevant count, and ordered
 * u32-length-prefixed relevant paths.
 *
 * Each arm root hashes: domain, u16 version, workload_root, u32 task count,
 * then for every task its length-prefixed task id, u8 complete, u32 ranked
 * count, and each ordered row as length-prefixed path, u64 context bytes,
 * u8 scope-available, u8 scope. Scope must be false when unavailable.
 *
 * evaluation_input_root hashes: domain, u16 version, workload_root,
 * parent_arm_root, child_arm_root. Parent/child order is semantic.
 *
 * The three external roots are caller assertions: this API binds them but
 * does not resolve them or authenticate that the supplied rows came from the
 * named source/projection generation. Roots identify only the declared bytes
 * and observed metrics. They establish no chronology, holdout independence,
 * evaluator correctness, replication, signer independence, acceptance,
 * attention, lifecycle, or authority.
 * On every error, out is unchanged. out may not overlap any reachable input. */
enum zcl_retrieval_experiment_error zcl_retrieval_paired_evaluate(
    const struct zcl_retrieval_paired_evaluation_task_v1 *tasks,
    size_t task_count,
    const uint8_t expected_task_root[32],
    const uint8_t source_root[32],
    const uint8_t retrieval_projection_root[32],
    struct zcl_retrieval_paired_evaluation_report_v1 *out);

#endif /* ZCL_RETRIEVAL_EVALUATION_BATCH_H */
