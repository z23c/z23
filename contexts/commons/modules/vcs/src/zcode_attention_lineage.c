/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded mixed seed/derived attention-lineage admission. */
#include "zcode_attention_internal.h"

enum vcs_zcode_attention_error
vcs_zcode_attention_lineage_validate_batch_layout(
    const struct vcs_zcode_heuristic_v1 *heuristics, size_t heuristic_count,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total)
{
    if (heuristic_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS ||
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (heuristic_count != 0 && !heuristics)
        return VCS_ZCODE_ATTENTION_NULL;
    if (parent_total != 0 && !parents)
        return VCS_ZCODE_ATTENTION_NULL;
    if (parent_total == 0 && parents)
        return VCS_ZCODE_ATTENTION_COUNT;

    size_t expected_total = 0;
    for (size_t i = 0; i < heuristic_count; i++) {
        enum vcs_zcode_attention_error error =
            vcs_zcode_heuristic_validate(&heuristics[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (heuristics[i].parent_count >
            VCS_ZCODE_HEURISTIC_MAX_PARENTS)
            return VCS_ZCODE_ATTENTION_COUNT;
        expected_total += heuristics[i].parent_count;
    }
    if (expected_total != parent_total)
        return VCS_ZCODE_ATTENTION_COUNT;
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error
vcs_zcode_attention_bid_validate_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count)
{
    if (!heuristic) return VCS_ZCODE_ATTENTION_NULL;
    if (parent_count > VCS_ZCODE_HEURISTIC_MAX_PARENTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (parent_count != 0 && !parents)
        return VCS_ZCODE_ATTENTION_NULL;
    if (parent_count == 0 && parents)
        return VCS_ZCODE_ATTENTION_COUNT;

    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_validate(heuristic);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (heuristic->derivation == VCS_ZCODE_HEURISTIC_SEED) {
        if (parent_count != 0) return VCS_ZCODE_ATTENTION_COUNT;
        return vcs_zcode_attention_bid_validate_for_heuristic(
            bid, heuristic);
    }
    return vcs_zcode_attention_bid_validate_for_derivation(
        bid, heuristic, parents, parent_count);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_bid_validate_for_focus_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count,
    const struct vcs_zcode_focus_v1 *focus)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_attention_bid_validate_with_lineage(
            bid, heuristic, parents, parent_count);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    return vcs_zcode_attention_bid_validate_focus_binding(
        bid, heuristic, focus);
}
