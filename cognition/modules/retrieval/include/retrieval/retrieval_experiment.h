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
#define ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX 32u
#define ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX 128u
#define ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM \
    "bm25_prefix_graph_fill_context_guard_v1"
#define ZCL_RETRIEVAL_PROFILE_ALGORITHM "context_bytes_profile_v1"
#define ZCL_RETRIEVAL_PROFILE_VERSION 1u
#define ZCL_RETRIEVAL_PROFILE_WIRE_BYTES 56u
#define ZCL_RETRIEVAL_PROFILE_DOMAIN "zcl.retrieval_profile.v1"
#define ZCL_RETRIEVAL_PROFILE_REPLAY_VERSION 1u
#define ZCL_RETRIEVAL_PROFILE_REPLAY_HYPOTHESIS_DOMAIN \
    "zcl.retrieval_profile_frozen_ranking_replay_hypothesis.v1"
#define ZCL_RETRIEVAL_PROFILE_REPLAY_CANDIDATES_DOMAIN \
    "zcl.retrieval_profile_frozen_ranking_replay_candidates.v1"
#define ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION 1u
#define ZCL_RETRIEVAL_FEATURE_SNAPSHOT_DOMAIN \
    "zcl.retrieval_feature_snapshot.v1"
#define ZCL_RETRIEVAL_EVAL_RESULT_VERSION 1u
#define ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES 184u
#define ZCL_RETRIEVAL_EVAL_RESULT_DOMAIN \
    "zcl.retrieval_experiment_eval_result.v1"
#define ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE (1u << 0)
#define ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE (1u << 1)
#define ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE (1u << 2)
#define ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE (1u << 3)
#define ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED (1u << 4)
#define ZCL_RETRIEVAL_EVAL_RESULT_RETAINED_SET_PRESERVED (1u << 5)
#define ZCL_RETRIEVAL_EVAL_RESULT_CONTEXT_CEILING_PRESERVED (1u << 6)
#define ZCL_RETRIEVAL_EVAL_RESULT_FLAGS_ALL \
    (ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE | \
     ZCL_RETRIEVAL_EVAL_RESULT_RECALL_20_AVAILABLE | \
     ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE | \
     ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE | \
     ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED | \
     ZCL_RETRIEVAL_EVAL_RESULT_RETAINED_SET_PRESERVED | \
     ZCL_RETRIEVAL_EVAL_RESULT_CONTEXT_CEILING_PRESERVED)
#define ZCL_RETRIEVAL_PROFILE_WEIGHT_MAX 10000u
#define ZCL_RETRIEVAL_PROFILE_GRAPH_DEPTH_MAX 2u
#define ZCL_RETRIEVAL_PROFILE_WINDOW_MAX 20u

enum zcl_retrieval_profile_feature {
    ZCL_RETRIEVAL_FEATURE_PATH = 0,
    ZCL_RETRIEVAL_FEATURE_GROUP = 1,
    ZCL_RETRIEVAL_FEATURE_PURPOSE = 2,
    ZCL_RETRIEVAL_FEATURE_SYMBOL_NAME = 3,
    ZCL_RETRIEVAL_FEATURE_SIGNATURE = 4,
    ZCL_RETRIEVAL_FEATURE_DOC = 5,
    ZCL_RETRIEVAL_FEATURE_GUARD = 6,
    /* Rarity is evidence-owner scoped; pool-local DF is not corpus IDF. */
    ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY = 7,
    /* A syntactic reverse reference is not a resolved call. */
    ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY = 8,
    ZCL_RETRIEVAL_FEATURE_TEST_PROXIMITY = 9,
    ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES = 10,
    ZCL_RETRIEVAL_FEATURE_PACKAGE_OWNERSHIP = 11,
    ZCL_RETRIEVAL_FEATURE_PLATFORM_COMPATIBILITY = 12,
    ZCL_RETRIEVAL_FEATURE_ONTOLOGY_RELATION = 13,
    ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT = 14,
};

#define ZCL_RETRIEVAL_FEATURE_BIT(feature_) \
    ((uint16_t)(UINT16_C(1) << (feature_)))
#define ZCL_RETRIEVAL_FEATURE_MASK_ALL \
    ((uint16_t)((UINT16_C(1) << ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT) - 1u))

enum zcl_retrieval_experiment_error {
    ZCL_RETRIEVAL_EXPERIMENT_OK = 0,
    ZCL_RETRIEVAL_EXPERIMENT_NULL,
    ZCL_RETRIEVAL_EXPERIMENT_PARAMETER,
    ZCL_RETRIEVAL_EXPERIMENT_CAPACITY,
    ZCL_RETRIEVAL_EXPERIMENT_SHAPE,
    ZCL_RETRIEVAL_EXPERIMENT_BINDING,
    ZCL_RETRIEVAL_EXPERIMENT_OVERFLOW,
    ZCL_RETRIEVAL_EXPERIMENT_ALIAS,
    ZCL_RETRIEVAL_EXPERIMENT_EVALUATION,
    ZCL_RETRIEVAL_EXPERIMENT_ALLOCATION,
    ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE,
    ZCL_RETRIEVAL_EXPERIMENT_VERSION,
    ZCL_RETRIEVAL_EXPERIMENT_RESERVED,
    ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE,
};

/* Retrieval owns this pure ranking rule. Generic ZCODE heuristic objects own
 * applicability, lineage, provenance, evaluators and budgets, and may bind
 * this object's root as proposed_rule_root. Integer weights are canonical;
 * no float/libm result enters profile or candidate identity. */
struct zcl_retrieval_profile_v1 {
    uint16_t schema_version;
    uint16_t feature_mask;
    uint16_t weight_bp[ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT];
    uint16_t identifier_df_max;
    uint8_t graph_depth;
    uint8_t rerank_window;
    uint8_t top_k;
    uint8_t reserved;
    uint16_t reserved_tail;
    uint64_t context_byte_scale;
};

/* Feature evidence is caller-owned POD. Each owner must derive its facts from
 * the exact roots named here before setting a row bit. FALSE and UNOBSERVED
 * are distinct: an absent bit is never silently scored as zero. */
struct zcl_retrieval_feature_snapshot_v1 {
    uint16_t schema_version;
    uint16_t row_count;
    bool ranking_complete;
    uint16_t available_features;
    uint16_t saturated_features;
    /* Exact extraction scopes for the two parameterized feature owners. */
    uint16_t identifier_df_max;
    uint8_t graph_depth;
    uint8_t reserved;
    /* Exact logical-row source identity and retrieval projection identity.
     * These are distinct from an enclosing workspace/VCS manifest root. */
    uint8_t source_root[32];
    uint8_t codeindex_root[32];
    uint8_t query_root[32];
    uint8_t baseline_ranking_root[32];
    uint8_t extractor_root[32];
};

struct zcl_retrieval_feature_row_v1 {
    const char *path;
    uint64_t context_bytes;
    uint16_t original_bm25_rank;
    uint16_t observed_features;
    /* CONTEXT_BYTES is derived from context_bytes and must remain zero here. */
    uint16_t feature_bp[ZCL_RETRIEVAL_PROFILE_FEATURE_COUNT];
};

struct zcl_retrieval_profile_report {
    size_t ranked_count;
    size_t changed_positions_at_top;
    uint64_t baseline_context_bytes_at_top;
    uint64_t candidate_context_bytes_at_top;
    bool used_baseline_fallback;
    bool retained_set_preserved;
    uint8_t profile_root[32];
    uint8_t feature_snapshot_root[32];
    uint8_t candidate_ranking_root[32];
};

/* A deliberately weaker profile experiment over an already-frozen ranking.
 * Unlike a feature snapshot, this input does not claim a current source,
 * codeindex, or retrieval-projection generation. It is useful for historical
 * counterfactual replay only. Relevance paths, evaluator scores, and
 * promotion state have no channel into this proposal surface. Baseline scope
 * fields may be present in the shared ranked-file carrier but are ignored,
 * erased, and excluded from replay identity. */
struct zcl_retrieval_profile_replay_task_v1 {
    const char *task_id;
    const char *query;
    const struct zcl_retrieval_ranked_file *baseline;
    size_t baseline_count;
    bool baseline_complete;
};

struct zcl_retrieval_profile_replay_candidate_v1 {
    struct zcl_retrieval_ranked_file
        ranked[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    size_t ranked_count;
    bool ranking_complete;
    uint8_t ranking_root[32];
};

struct zcl_retrieval_profile_replay_report_v1 {
    uint16_t schema_version;
    size_t task_count;
    size_t changed_positions_at_5;
    size_t fallback_tasks;
    bool top20_membership_preserved;
    bool full_retained_set_preserved;
    bool context_ceiling_preserved;
    uint8_t profile_root[32];
    uint8_t replay_hypothesis_root[32];
    uint8_t candidate_batch_root[32];
};

struct zcl_retrieval_experiment_report {
    size_t ranked_count;
    uint64_t bm25_context_bytes_at_5;
    uint64_t candidate_context_bytes_at_5;
    size_t changed_positions_at_5;
    bool used_bm25_fallback;
    bool top20_membership_preserved;
};

struct zcl_retrieval_experiment_eval_task {
    const char *task_id;
    const char *query;
    const char *const *relevant_paths;
    size_t relevant_count;
    const struct zcl_retrieval_ranked_file *bm25;
    size_t bm25_count;
    bool bm25_complete;
    const struct zcl_retrieval_ranked_file *parent;
    size_t parent_count;
    bool parent_complete;
};

struct zcl_retrieval_experiment_eval_report {
    struct zcl_retrieval_eval_metrics metrics;
    size_t changed_positions_at_5;
    size_t fallback_tasks;
    bool top20_membership_preserved;
    bool full_retained_set_preserved;
    bool context_ceiling_preserved;
};

/* Immutable post-proposal observation. `evaluation_input_root` is an opaque
 * exact batch identity here: this object does not claim that its bytes were
 * independently replayed, that gold was hidden before proposal, or that a
 * holdout is independent. A science statement may attribute the observation;
 * neither the statement nor this root promotes a heuristic or grants work. */
struct zcl_retrieval_experiment_eval_result_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint32_t tasks;
    uint32_t recall_at_5_bp;
    uint32_t recall_at_20_bp;
    uint32_t mrr_bp;
    uint32_t wrong_scope_at_5_bp;
    uint32_t unique_files_at_5;
    uint32_t wrong_scope_files_at_5;
    uint32_t changed_positions_at_5;
    uint32_t fallback_tasks;
    uint64_t context_bytes_at_5;
    uint8_t subject_root[32];
    uint8_t proposal_input_root[32];
    uint8_t evaluation_input_root[32];
    uint8_t evaluator_root[32];
};

void zcl_retrieval_profile_init(struct zcl_retrieval_profile_v1 *profile);
enum zcl_retrieval_experiment_error zcl_retrieval_profile_validate(
    const struct zcl_retrieval_profile_v1 *profile);
enum zcl_retrieval_experiment_error zcl_retrieval_profile_serialize(
    const struct zcl_retrieval_profile_v1 *profile,
    uint8_t out[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES]);
enum zcl_retrieval_experiment_error zcl_retrieval_profile_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_profile_v1 *out);
enum zcl_retrieval_experiment_error zcl_retrieval_profile_root(
    const struct zcl_retrieval_profile_v1 *profile, uint8_t out[32]);

/* Canonical query identity shared by feature extractors and composition
 * services. Keeping this in retrieval prevents a second owner from silently
 * relabeling an exact snapshot with different query bytes. */
enum zcl_retrieval_experiment_error zcl_retrieval_query_root(
    const char *query, uint8_t out[32]);

/* Root and project are relevance-free. They accept no gold, evaluator score,
 * scope label or acceptance input. Rows are in exact baseline-rank order;
 * the root commits declared identities and observation bytes but does not
 * verify that the caller derived them from the declared source. */
enum zcl_retrieval_experiment_error zcl_retrieval_feature_snapshot_root(
    const struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 *rows, uint8_t out[32]);
enum zcl_retrieval_experiment_error zcl_retrieval_profile_project(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 *rows,
    size_t *out_indices, size_t out_capacity,
    struct zcl_retrieval_profile_report *report);

/* Re-run the context-byte profile over ordered frozen baseline rows. This is
 * relevance-free and roots exactly that weaker historical hypothesis; it
 * never manufactures the source/codeindex/projection roots required by the
 * live generation-joined proposal API. The current v1 report is fixed at
 * top-five semantics, so profiles with top_k != 5 or tasks with fewer than
 * five baseline rows fail closed. */
enum zcl_retrieval_experiment_error zcl_retrieval_profile_replay_project(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_retrieval_profile_replay_task_v1 *tasks,
    size_t task_count,
    struct zcl_retrieval_profile_replay_candidate_v1 *candidates,
    size_t candidate_capacity,
    struct zcl_retrieval_profile_replay_report_v1 *report);

/* The first command-owned feature extractor intentionally exposes only exact
 * full-file context bytes. `codeindex_source_root` and
 * `retrieval_projection_root` must come from the same already generation-
 * joined snapshot as `baseline`; this pure function binds but cannot
 * authenticate that caller claim. Every other feature remains unavailable,
 * so profiles requesting it fail INCOMPLETE in profile_project(). */
enum zcl_retrieval_experiment_error
zcl_retrieval_context_feature_snapshot(
    const uint8_t codeindex_source_root[32],
    const uint8_t retrieval_projection_root[32], const char *query,
    const struct zcl_retrieval_ranked_file *baseline, size_t baseline_count,
    bool baseline_complete,
    struct zcl_retrieval_feature_snapshot_v1 *snapshot_out,
    struct zcl_retrieval_feature_row_v1 *rows_out, size_t rows_capacity);

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

/* Measure one already-proposed prefix over independently supplied reviewed
 * relevance. Projection remains relevance-free: every task is projected
 * before its gold paths are attached to the maintained evaluator. Scope is
 * intentionally unavailable because proposer-side scope labels are erased.
 * This report is an observation only; it does not retain, promote, schedule,
 * or authorize the candidate. */
enum zcl_retrieval_experiment_error zcl_retrieval_experiment_evaluate(
    const struct zcl_retrieval_experiment_eval_task *tasks,
    size_t task_count, uint8_t bm25_prefix,
    struct zcl_retrieval_experiment_eval_report *report);

/* Convert the maintained evaluator's exact POD observation into a canonical
 * inert result. The subject is normally a heuristic root. The evaluation
 * input owner remains responsible for defining, resolving, and replaying its
 * batch; this constructor merely binds that exact root without interpreting
 * it. Approximate tokens are checked against ceil(context_bytes/4) and omitted
 * from the wire because they are derived. */
enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_init(
    struct zcl_retrieval_experiment_eval_result_v1 *out,
    const struct zcl_retrieval_experiment_eval_report *report,
    const uint8_t subject_root[32],
    const uint8_t proposal_input_root[32],
    const uint8_t evaluation_input_root[32],
    const uint8_t evaluator_root[32]);
enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_validate(
    const struct zcl_retrieval_experiment_eval_result_v1 *result);
enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_serialize(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    uint8_t out[ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES]);
enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_retrieval_experiment_eval_result_v1 *out);
enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_root(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    uint8_t out[32]);
/* Re-root and compare the four structural bindings. It establishes identity,
 * not evaluator correctness, chronology, holdout independence, or authority. */
enum zcl_retrieval_experiment_error
zcl_retrieval_experiment_eval_result_verify_binding(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    const uint8_t expected_subject_root[32],
    const uint8_t expected_proposal_input_root[32],
    const uint8_t expected_evaluation_input_root[32],
    const uint8_t expected_evaluator_root[32],
    const uint8_t expected_result_root[32]);

/* Canonical root used by the observational benchmark's ranked-file rows. */
bool zcl_retrieval_ranked_files_root(
    const struct zcl_retrieval_ranked_file *ranked, size_t ranked_count,
    bool ranking_complete, uint8_t out[32]);

/* Seal the direct-gold-input-free proposal inputs. No gold path, relevance bit,
 * evaluator result, or scope label exists in this interface. Study,
 * preregistration and evaluator roots are opaque bindings only: this API does
 * not verify their objects, types, ordering, or protocol validity. A later,
 * separate evaluator may resolve and validate them before observing the
 * proposal. `retrieval_projection_root` binds the verified logical rows read
 * by the rankers; the source root remains a separate source-byte identity. */
bool zcl_retrieval_experiment_proposal_input_root(
    const uint8_t source_root[32],
    const uint8_t retrieval_projection_root[32],
    const char *task_id, const char *query,
    const uint8_t bm25_ranking_root[32],
    const uint8_t parent_ranking_root[32], uint8_t bm25_prefix,
    const uint8_t study_root[32], const uint8_t preregistration_root[32],
    const uint8_t evaluator_root[32], uint8_t out[32]);

/* Profile counterpart of the legacy prefix proposal. It binds the workspace
 * source generation, logical codeindex identities, supplied baseline/profile/
 * feature/candidate roots and opaque science roots. This pure binder checks
 * shape and nonzero roots; it does not resolve objects or authenticate their
 * relationships. It accepts no gold, relevance, scope, score, promotion, or
 * acceptance input. */
bool zcl_retrieval_profile_proposal_input_root(
    const uint8_t source_root[32],
    const uint8_t codeindex_source_root[32],
    const uint8_t retrieval_projection_root[32],
    const char *task_id, const char *query,
    const uint8_t baseline_ranking_root[32],
    const uint8_t profile_root[32],
    const uint8_t feature_snapshot_root[32],
    const uint8_t candidate_ranking_root[32],
    const uint8_t study_root[32], const uint8_t preregistration_root[32],
    const uint8_t evaluator_root[32], uint8_t out[32]);

const char *zcl_retrieval_experiment_error_string(
    enum zcl_retrieval_experiment_error error);

#endif /* ZCL_RETRIEVAL_EXPERIMENT_H */
