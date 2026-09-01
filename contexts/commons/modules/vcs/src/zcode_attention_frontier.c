/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: hard-priority, Pareto-diverse projection of attention bids. */
#include "zcode_attention_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool af_memory_overlaps(const void *left, size_t left_size,
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

static bool af_root_is_zero(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate == 0;
}

static bool af_priority_valid(uint8_t priority_class)
{
    return priority_class >= VCS_ZCODE_ATTENTION_P0_SECURITY &&
           priority_class <= VCS_ZCODE_ATTENTION_P3_RESEARCH;
}

static bool af_bid_dominates(
    const struct vcs_zcode_attention_bid_v1 *left,
    const struct vcs_zcode_attention_bid_v1 *right)
{
    bool no_worse =
        left->expected_user_value_bp >= right->expected_user_value_bp &&
        left->information_gain_bp >= right->information_gain_bp &&
        left->blocker_relief_bp >= right->blocker_relief_bp &&
        left->reuse_potential_bp >= right->reuse_potential_bp &&
        left->evidence_strength_bp >= right->evidence_strength_bp &&
        left->risk_bp <= right->risk_bp &&
        left->overlap_bp <= right->overlap_bp &&
        left->expected_latency_us <= right->expected_latency_us &&
        left->expected_cost_milliunits <= right->expected_cost_milliunits;
    bool strictly_better =
        left->expected_user_value_bp > right->expected_user_value_bp ||
        left->information_gain_bp > right->information_gain_bp ||
        left->blocker_relief_bp > right->blocker_relief_bp ||
        left->reuse_potential_bp > right->reuse_potential_bp ||
        left->evidence_strength_bp > right->evidence_strength_bp ||
        left->risk_bp < right->risk_bp ||
        left->overlap_bp < right->overlap_bp ||
        left->expected_latency_us < right->expected_latency_us ||
        left->expected_cost_milliunits < right->expected_cost_milliunits;
    return no_worse && strictly_better;
}

static bool af_bid_subject_equal(
    const struct vcs_zcode_attention_bid_v1 *left,
    const struct vcs_zcode_attention_bid_v1 *right)
{
    /* Evidence is an observation of this logical candidate, not part of its
     * identity.  Two snapshots for one focus/heuristic/evaluator would make
     * the frontier schedule the same proposed action twice and let stale and
     * fresh scores coexist without a lifecycle decision.  Refuse that
     * ambiguity; callers must select one evidence generation first. */
    return memcmp(left->focus_root, right->focus_root, 32) == 0 &&
        memcmp(left->task_root, right->task_root, 32) == 0 &&
        memcmp(left->source_root, right->source_root, 32) == 0 &&
        memcmp(left->heuristic_root, right->heuristic_root, 32) == 0 &&
        memcmp(left->priority_policy_root,
               right->priority_policy_root, 32) == 0 &&
        memcmp(left->bid_evaluator_root,
               right->bid_evaluator_root, 32) == 0;
}

static enum vcs_zcode_attention_error af_frontier_project(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage, const bool *eligible,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_frontier_report *report)
{
    if (!query || !report ||
        (bid_count != 0 && (!bids || !heuristics)) ||
        (out_capacity != 0 && !out_indices))
        return VCS_ZCODE_ATTENTION_NULL;
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (with_lineage &&
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (with_lineage && parent_total != 0 && !parents)
        return VCS_ZCODE_ATTENTION_NULL;
    if (with_lineage && parent_total == 0 && parents)
        return VCS_ZCODE_ATTENTION_COUNT;
    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    index_span *= sizeof(*out_indices);
    size_t parent_span = with_lineage
        ? parent_total * sizeof(*parents) : 0;
    if ((bid_count != 0 &&
         (af_memory_overlaps(report, sizeof(*report), bids,
                             bid_count * sizeof(*bids)) ||
          af_memory_overlaps(report, sizeof(*report), heuristics,
                             bid_count * sizeof(*heuristics)) ||
          (out_capacity != 0 &&
           (af_memory_overlaps(out_indices, index_span, bids,
                               bid_count * sizeof(*bids)) ||
            af_memory_overlaps(out_indices, index_span, heuristics,
                               bid_count * sizeof(*heuristics)))))) ||
        (with_lineage && parent_total != 0 &&
         (af_memory_overlaps(report, sizeof(*report), parents,
                             parent_span) ||
          (out_capacity != 0 &&
           af_memory_overlaps(out_indices, index_span, parents,
                              parent_span)))) ||
        af_memory_overlaps(report, sizeof(*report), query, sizeof(*query)) ||
        (out_capacity != 0 &&
         (af_memory_overlaps(out_indices, index_span, query,
                             sizeof(*query)) ||
          af_memory_overlaps(out_indices, index_span, report,
                             sizeof(*report)))))
        return VCS_ZCODE_ATTENTION_ALIAS;
    if (with_lineage) {
        enum vcs_zcode_attention_error lineage_error =
            vcs_zcode_attention_lineage_validate_batch_layout(
                heuristics, bid_count, parents, parent_total);
        if (lineage_error != VCS_ZCODE_ATTENTION_OK)
            return lineage_error;
    }
    if (!af_priority_valid(query->priority_class))
        return VCS_ZCODE_ATTENTION_PRIORITY;
    const uint8_t *const query_roots[] = {
        query->focus_root, query->task_root, query->source_root,
        query->priority_policy_root, query->bid_evaluator_root,
    };
    for (size_t i = 0;
         i < sizeof(query_roots) / sizeof(query_roots[0]); i++) {
        if (af_root_is_zero(query_roots[i]))
            return VCS_ZCODE_ATTENTION_ROOT;
    }

    struct vcs_zcode_attention_frontier_report result = {0};
    if (!eligible) {
        result.input_count = bid_count;
    } else {
        for (size_t i = 0; i < bid_count; i++)
            if (eligible[i]) result.input_count++;
    }
    uint8_t roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {{0}};
    bool in_class[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    bool dominated[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    size_t parent_cursor = 0;
    for (size_t i = 0; i < bid_count; i++) {
        size_t row_parent_count = with_lineage
            ? heuristics[i].parent_count : 0;
        const struct vcs_zcode_heuristic_v1 *row_parents =
            row_parent_count != 0 ? &parents[parent_cursor] : NULL;
        enum vcs_zcode_attention_error error = with_lineage
            ? vcs_zcode_attention_bid_validate_with_lineage(
                &bids[i], &heuristics[i], row_parents, row_parent_count)
            : vcs_zcode_attention_bid_validate_for_heuristic(
                &bids[i], &heuristics[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        parent_cursor += row_parent_count;
        if (memcmp(bids[i].focus_root, query->focus_root, 32) != 0 ||
            memcmp(bids[i].task_root, query->task_root, 32) != 0 ||
            memcmp(bids[i].source_root, query->source_root, 32) != 0 ||
            memcmp(bids[i].priority_policy_root,
                   query->priority_policy_root, 32) != 0 ||
            memcmp(bids[i].bid_evaluator_root,
                   query->bid_evaluator_root, 32) != 0)
            return VCS_ZCODE_ATTENTION_BINDING;
        error = vcs_zcode_attention_bid_root(&bids[i], roots[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        for (size_t j = 0; eligible && eligible[i] && j < i; j++) {
            if (eligible[j] &&
                (memcmp(roots[i], roots[j], 32) == 0 ||
                 af_bid_subject_equal(&bids[i], &bids[j])))
                return VCS_ZCODE_ATTENTION_DUPLICATE;
        }
        if (!eligible) {
            for (size_t j = 0; j < i; j++) {
                if (memcmp(roots[i], roots[j], 32) == 0 ||
                    af_bid_subject_equal(&bids[i], &bids[j]))
                    return VCS_ZCODE_ATTENTION_DUPLICATE;
            }
        }
        in_class[i] = (!eligible || eligible[i]) &&
            bids[i].priority_class == query->priority_class;
        if (in_class[i]) result.class_candidate_count++;
    }
    for (size_t i = 0; i < bid_count; i++) {
        if (!in_class[i]) continue;
        for (size_t j = 0; j < bid_count; j++) {
            if (i != j && in_class[j] &&
                af_bid_dominates(&bids[j], &bids[i])) {
                dominated[i] = true;
                break;
            }
        }
        if (!dominated[i]) result.frontier_count++;
    }
    if (out_capacity < result.frontier_count) {
        *report = result;
        return VCS_ZCODE_ATTENTION_CAPACITY;
    }
    for (size_t i = 0; i < bid_count; i++) {
        if (!in_class[i] || dominated[i]) continue;
        size_t position = result.returned_count;
        while (position > 0 &&
               memcmp(roots[i], roots[out_indices[position - 1]], 32) < 0) {
            out_indices[position] = out_indices[position - 1];
            position--;
        }
        out_indices[position] = i;
        result.returned_count++;
    }
    *report = result;
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error vcs_zcode_attention_frontier_project(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_frontier_report *report)
{
    return af_frontier_project(
        bids, bid_count, heuristics, NULL, 0, false, NULL, query,
        out_indices, out_capacity, report);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_project_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_frontier_report *report)
{
    return af_frontier_project(
        bids, bid_count, heuristics, parents, parent_total, true, NULL, query,
        out_indices, out_capacity, report);
}

static enum vcs_zcode_attention_error af_frontier_choose(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage, const bool *eligible,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report)
{
    if (!query || !report ||
        (bid_count != 0 && (!bids || !heuristics)) ||
        (out_capacity != 0 && !out_indices))
        return VCS_ZCODE_ATTENTION_NULL;
    if (query->priority_class != VCS_ZCODE_ATTENTION_PRIORITY_AUTO)
        return VCS_ZCODE_ATTENTION_PRIORITY;
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (with_lineage &&
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (with_lineage && parent_total != 0 && !parents)
        return VCS_ZCODE_ATTENTION_NULL;
    if (with_lineage && parent_total == 0 && parents)
        return VCS_ZCODE_ATTENTION_COUNT;
    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    index_span *= sizeof(*out_indices);
    size_t parent_span = with_lineage
        ? parent_total * sizeof(*parents) : 0;
    if ((bid_count != 0 &&
         (af_memory_overlaps(report, sizeof(*report), bids,
                             bid_count * sizeof(*bids)) ||
          af_memory_overlaps(report, sizeof(*report), heuristics,
                             bid_count * sizeof(*heuristics)))) ||
        (with_lineage && parent_total != 0 &&
         (af_memory_overlaps(report, sizeof(*report), parents,
                             parent_span) ||
          (out_capacity != 0 && out_indices &&
           af_memory_overlaps(out_indices, index_span, parents,
                              parent_span)))) ||
        af_memory_overlaps(report, sizeof(*report), query, sizeof(*query)) ||
        (out_capacity != 0 && out_indices &&
         (af_memory_overlaps(out_indices, index_span, query, sizeof(*query)) ||
          af_memory_overlaps(out_indices, index_span,
                             report, sizeof(*report)))))
        return VCS_ZCODE_ATTENTION_ALIAS;

    struct vcs_zcode_attention_frontier_query exact = *query;
    struct vcs_zcode_attention_choice_report result = {0};
    size_t first_eligible = 0;
    while (first_eligible < bid_count && eligible && !eligible[first_eligible])
        first_eligible++;
    if (first_eligible == bid_count) {
        exact.priority_class = VCS_ZCODE_ATTENTION_P0_SECURITY;
        enum vcs_zcode_attention_error error =
            af_frontier_project(
                bids, bid_count, heuristics, parents, parent_total,
                with_lineage, eligible, &exact, out_indices, out_capacity,
                &result.frontier);
        if (error == VCS_ZCODE_ATTENTION_OK) *report = result;
        return error;
    }
    uint8_t selected = bids[first_eligible].priority_class;
    for (size_t i = first_eligible + 1u; i < bid_count; i++) {
        if ((!eligible || eligible[i]) && bids[i].priority_class < selected)
            selected = bids[i].priority_class;
    }
    exact.priority_class = selected;
    result.selected_priority_class = selected;
    enum vcs_zcode_attention_error error = af_frontier_project(
        bids, bid_count, heuristics, parents, parent_total, with_lineage,
        eligible,
        &exact, out_indices, out_capacity, &result.frontier);
    if (error == VCS_ZCODE_ATTENTION_OK ||
        error == VCS_ZCODE_ATTENTION_CAPACITY)
        *report = result;
    return error;
}

enum vcs_zcode_attention_error vcs_zcode_attention_frontier_choose(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report)
{
    return af_frontier_choose(
        bids, bid_count, heuristics, NULL, 0, false, NULL, query,
        out_indices, out_capacity, report);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_choose_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report)
{
    return af_frontier_choose(
        bids, bid_count, heuristics, parents, parent_total, true, NULL, query,
        out_indices, out_capacity, report);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_choose_eligible_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const bool *eligible,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report)
{
    if (bid_count != 0 && !eligible) return VCS_ZCODE_ATTENTION_NULL;
    return af_frontier_choose(
        bids, bid_count, heuristics, parents, parent_total, true, eligible,
        query, out_indices, out_capacity, report);
}
