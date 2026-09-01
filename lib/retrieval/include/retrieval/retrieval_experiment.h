/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: direct-gold-input-free, bounded retrieval-ranking experiments. */
#ifndef ZCL_RETRIEVAL_EXPERIMENT_H
#define ZCL_RETRIEVAL_EXPERIMENT_H

#include "retrieval/retrieval.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_RETRIEVAL_EXPERIMENT_TOP 5u
#define ZCL_RETRIEVAL_EXPERIMENT_WINDOW 20u
#define ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM \
    "bm25_prefix_graph_fill_context_guard_v1"

enum zcl_retrieval_experiment_error {
    ZCL_RETRIEVAL_EXPERIMENT_OK = 0,
    ZCL_RETRIEVAL_EXPERIMENT_NULL,
    ZCL_RETRIEVAL_EXPERIMENT_PARAMETER,
    ZCL_RETRIEVAL_EXPERIMENT_CAPACITY,
    ZCL_RETRIEVAL_EXPERIMENT_SHAPE,
    ZCL_RETRIEVAL_EXPERIMENT_BINDING,
    ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW,
    ZCL_RETRIEVAL_EXPERIMENT_ALIAS,
};

struct zcl_retrieval_experiment_report {
    size_t ranked_count;
    uint64_t bm25_context_bytes_at_5;
    uint64_t candidate_context_bytes_at_5;
    size_t changed_positions_at_5;
    bool used_bm25_fallback;
    bool top20_membership_preserved;
};

/* Project one candidate ranking from two already-sealed rankings. The only
 * experimental parameter is bm25_prefix (0..5). The first prefix rows are
 * retained in BM25 order; remaining top-five slots are taken in parent order
 * while respecting the original BM25 top-five byte ceiling. If that cannot
 * fill the observed top five, the deterministic fallback is the BM25 order.
 *
 * The parent and BM25 rankings must contain the same unique path/context
 * bindings. Projection changes order only: exact top-20 membership and the
 * entire retained set are preserved. Scope annotations are deliberately not
 * accepted or propagated by this relevance-free API. */
enum zcl_retrieval_experiment_error zcl_retrieval_experiment_project(
    const struct zcl_retrieval_ranked_file *bm25, size_t bm25_count,
    bool bm25_complete,
    const struct zcl_retrieval_ranked_file *parent, size_t parent_count,
    bool parent_complete, uint8_t bm25_prefix,
    struct zcl_retrieval_ranked_file *out, size_t out_capacity,
    struct zcl_retrieval_experiment_report *report);

/* Canonical root used by the observational benchmark's ranked-file rows. */
bool zcl_retrieval_ranked_files_root(
    const struct zcl_retrieval_ranked_file *ranked, size_t ranked_count,
    bool ranking_complete, uint8_t out[32]);

/* Seal the direct-gold-input-free proposal inputs. No gold path, relevance bit,
 * evaluator result, or scope label exists in this interface. Study,
 * preregistration and evaluator roots are opaque bindings only: this API does
 * not verify their objects, types, ordering, or protocol validity. A later,
 * separate evaluator may resolve and validate them before observing the
 * proposal. */
bool zcl_retrieval_experiment_proposal_input_root(
    const uint8_t source_root[32], const uint8_t codeindex_root[32],
    const char *task_id, const char *query,
    const uint8_t bm25_ranking_root[32],
    const uint8_t parent_ranking_root[32], uint8_t bm25_prefix,
    const uint8_t study_root[32], const uint8_t preregistration_root[32],
    const uint8_t evaluator_root[32], uint8_t out[32]);

const char *zcl_retrieval_experiment_error_string(
    enum zcl_retrieval_experiment_error error);

#endif /* ZCL_RETRIEVAL_EXPERIMENT_H */
