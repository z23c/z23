/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: evaluator-attributed admission for automatic attention choice. */
#ifndef ZCL_VCS_ZCODE_ATTENTION_VERIFIED_H
#define ZCL_VCS_ZCODE_ATTENTION_VERIFIED_H

#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_attention_bid.h"
#include "vcs/zcode_science.h"

struct vcs_zcode_attention_verified_report {
    struct vcs_zcode_attention_choice_report choice;
    size_t verified_count;
};

/* Verify one evaluator-signed RESULT statement against the exact immutable
 * bid, heuristic, and focus. Signature success proves evaluator attribution
 * only; it does not prove a score true, admit work, or grant authority. */
enum vcs_zcode_attention_error vcs_zcode_attention_bid_verify_statement(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_evaluator_signer[32]);

/* Positive mixed-lineage counterpart. Caller-supplied immediate-parent
 * objects are validated before focus or signed evaluator evidence is
 * considered. */
enum vcs_zcode_attention_error
vcs_zcode_attention_bid_verify_statement_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count,
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_evaluator_signer[32]);

/* Fail closed unless every row has exact evaluator attribution, then choose
 * the highest-priority nonempty class and its complete Pareto frontier.
 * Unknown, incomplete, unsigned, or mismatched evidence is an error rather
 * than a zero score or silent skip. All rows share the explicit local policy
 * and evaluator roots. Output indices retain input-array identity. */
enum vcs_zcode_attention_error vcs_zcode_attention_frontier_next_verified(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_verified_report *report);

/* Mixed seed/derived verified selection with immediate-parent binding only.
 * Parent objects are packed by row; every row's lineage and evidence is
 * checked before hard-priority/Pareto selection, including lower-priority and
 * dominated rows. Signature success proves evaluator attribution, not score
 * truth, and selection grants no task, action, or execution authority. */
enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_next_verified_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_verified_report *report);

#endif /* ZCL_VCS_ZCODE_ATTENTION_VERIFIED_H */
