/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal CLI-only stream seam for the observational retrieval benchmark. */

#ifndef ZCL_TOOLS_NATIVE_DEV_RETRIEVAL_STREAM_H
#define ZCL_TOOLS_NATIVE_DEV_RETRIEVAL_STREAM_H

#include "json/json.h"
#include "retrieval/retrieval.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define ZCL_NATIVE_DEV_RETRIEVAL_SNAPSHOT_PATH_MAX 256u

#if defined(ZCL_TESTING)
enum zcl_native_dev_retrieval_test_phase {
    ZCL_NATIVE_DEV_RETRIEVAL_TEST_BEFORE_CODEINDEX_OPEN = 1,
    ZCL_NATIVE_DEV_RETRIEVAL_TEST_BEFORE_POST_CAPTURE = 2,
};

typedef bool (*zcl_native_dev_retrieval_test_hook)(
    enum zcl_native_dev_retrieval_test_phase phase, void *opaque);
void zcl_native_dev_retrieval_test_set_hook(
    zcl_native_dev_retrieval_test_hook hook, void *opaque);
#endif

struct zcl_native_dev_retrieval_snapshot_rank {
    struct zcl_retrieval_ranked_file rows[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    char paths[ZCL_RETRIEVAL_EVAL_RANK_MAX]
              [ZCL_NATIVE_DEV_RETRIEVAL_SNAPSHOT_PATH_MAX];
    size_t count;
    bool complete;
};

/* Recompute and copy only the relevance-free material required by a bounded
 * experiment. This deliberately exports no evaluator, gold, relevance, or
 * scope data and provides no path back into the frozen rankers. */
struct zcl_native_dev_retrieval_snapshot {
    char task_id[129];
    char query[4097];
    uint8_t source_root[32];
    uint8_t codeindex_source_root[32];
    uint8_t retrieval_projection_root[32];
    uint8_t bm25_ranking_root[32];
    uint8_t identifier_graph_ranking_root[32];
    struct zcl_native_dev_retrieval_snapshot_rank bm25;
    struct zcl_native_dev_retrieval_snapshot_rank identifier_graph;
};

int zcl_native_dev_retrieval_snapshot_compute(
    const struct json_value *input,
    struct zcl_native_dev_retrieval_snapshot *snapshot,
    char *error_code, size_t error_code_cap,
    char *error_message, size_t error_message_cap);

/* Compute one source-bound ranking and emit every adaptive page as JSONL.
 * Nothing is written until computation, source post-check, and all page
 * rendering have succeeded. Returns a zcl_command_exit value. */
int zcl_native_dev_retrieval_stream_jsonl(
    const struct json_value *input, size_t contract_bytes, FILE *out,
    char *error_code, size_t error_code_cap,
    char *error_message, size_t error_message_cap);

#endif
