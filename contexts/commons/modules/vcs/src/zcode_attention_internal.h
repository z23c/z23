/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private composition seams for attention lineage selection. */
#ifndef ZCL_VCS_ZCODE_ATTENTION_INTERNAL_H
#define ZCL_VCS_ZCODE_ATTENTION_INTERNAL_H

#include <stdbool.h>

#include "vcs/zcode_attention_bid.h"

/* Validate only the shape of a canonical packed batch layout. Row i consumes
 * exactly heuristics[i].parent_count consecutive parent objects. Parent
 * contents are deliberately unexamined here; row admission binds them. */
enum vcs_zcode_attention_error
vcs_zcode_attention_lineage_validate_batch_layout(
    const struct vcs_zcode_heuristic_v1 *heuristics, size_t heuristic_count,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total);

/* Mixed seed/derived structural admission for one row. */
enum vcs_zcode_attention_error
vcs_zcode_attention_bid_validate_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count);

/* Shared inward-owned focus/budget binding after the caller has admitted the
 * bid and heuristic through either the seed or derived structural seam. */
enum vcs_zcode_attention_error
vcs_zcode_attention_bid_validate_focus_binding(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus);

/* Private projection seam for already-verified policy filters. Every input
 * row is still structurally validated, but only eligible rows participate in
 * duplicate-generation, priority, and Pareto decisions. */
enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_choose_eligible_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const bool *eligible,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report);

#endif /* ZCL_VCS_ZCODE_ATTENTION_INTERNAL_H */
