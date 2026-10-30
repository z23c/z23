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

static bool af_bid_no_worse(
    const struct vcs_zcode_attention_bid_v1 *left,
    const struct vcs_zcode_attention_bid_v1 *right)
{
    return left->expected_user_value_bp >= right->expected_user_value_bp &&
        left->information_gain_bp >= right->information_gain_bp &&
        left->blocker_relief_bp >= right->blocker_relief_bp &&
        left->reuse_potential_bp >= right->reuse_potential_bp &&
        left->evidence_strength_bp >= right->evidence_strength_bp &&
        left->risk_bp <= right->risk_bp &&
        left->overlap_bp <= right->overlap_bp &&
        left->expected_latency_us <= right->expected_latency_us &&
        left->expected_cost_milliunits <= right->expected_cost_milliunits;
}

static bool af_bid_strictly_better(
    const struct vcs_zcode_attention_bid_v1 *left,
    const struct vcs_zcode_attention_bid_v1 *right)
{
    return left->expected_user_value_bp > right->expected_user_value_bp ||
        left->information_gain_bp > right->information_gain_bp ||
        left->blocker_relief_bp > right->blocker_relief_bp ||
        left->reuse_potential_bp > right->reuse_potential_bp ||
        left->evidence_strength_bp > right->evidence_strength_bp ||
        left->risk_bp < right->risk_bp ||
        left->overlap_bp < right->overlap_bp ||
        left->expected_latency_us < right->expected_latency_us ||
        left->expected_cost_milliunits < right->expected_cost_milliunits;
}

static bool af_bid_dominates(
    const struct vcs_zcode_attention_bid_v1 *left,
    const struct vcs_zcode_attention_bid_v1 *right)
{
    return af_bid_no_worse(left, right) &&
        af_bid_strictly_better(left, right);
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

static bool af_bid_bound_to_query(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_attention_frontier_query *query)
{
    return memcmp(bid->focus_root, query->focus_root, 32) == 0 &&
        memcmp(bid->task_root, query->task_root, 32) == 0 &&
        memcmp(bid->source_root, query->source_root, 32) == 0 &&
        memcmp(bid->priority_policy_root,
               query->priority_policy_root, 32) == 0 &&
        memcmp(bid->bid_evaluator_root,
               query->bid_evaluator_root, 32) == 0;
}

static bool af_frontier_duplicate_before(
    const struct vcs_zcode_attention_bid_v1 *bids,
    uint8_t roots[][32], const bool *eligible, size_t i)
{
    if (eligible && !eligible[i]) return false;
    for (size_t j = 0; j < i; j++) {
        if (eligible && !eligible[j]) continue;
        if (memcmp(roots[i], roots[j], 32) == 0 ||
            af_bid_subject_equal(&bids[i], &bids[j]))
            return true;
    }
    return false;
}

static enum vcs_zcode_attention_error af_frontier_row_check(
    const struct vcs_zcode_attention_bid_v1 *bids,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t *parent_cursor,
    bool with_lineage, const struct vcs_zcode_attention_frontier_query *query,
    uint8_t roots[][32], const bool *eligible, size_t i)
{
    size_t row_parent_count = with_lineage
        ? heuristics[i].parent_count : 0;
    const struct vcs_zcode_heuristic_v1 *row_parents =
        row_parent_count != 0 ? &parents[*parent_cursor] : NULL;
    enum vcs_zcode_attention_error error = with_lineage
        ? vcs_zcode_attention_bid_validate_with_lineage(
            &bids[i], &heuristics[i], row_parents, row_parent_count)
        : vcs_zcode_attention_bid_validate_for_heuristic(
            &bids[i], &heuristics[i]);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    *parent_cursor += row_parent_count;
    if (!af_bid_bound_to_query(&bids[i], query))
        return VCS_ZCODE_ATTENTION_BINDING;
    error = vcs_zcode_attention_bid_root(&bids[i], roots[i]);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (af_frontier_duplicate_before(bids, roots, eligible, i))
        return VCS_ZCODE_ATTENTION_DUPLICATE;
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error af_frontier_null_check(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity, const void *report)
{
    if (!query || !report ||
        (bid_count != 0 && (!bids || !heuristics)) ||
        (out_capacity != 0 && !out_indices))
        return VCS_ZCODE_ATTENTION_NULL;
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error af_frontier_count_check(
    size_t bid_count, bool with_lineage, size_t parent_total,
    const struct vcs_zcode_heuristic_v1 *parents)
{
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (with_lineage &&
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (with_lineage && parent_total != 0 && !parents)
        return VCS_ZCODE_ATTENTION_NULL;
    if (with_lineage && parent_total == 0 && parents)
        return VCS_ZCODE_ATTENTION_COUNT;
    return VCS_ZCODE_ATTENTION_OK;
}

static size_t af_frontier_index_span(size_t out_capacity)
{
    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    return index_span * sizeof(size_t);
}

static bool af_frontier_rows_alias(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    struct vcs_zcode_attention_frontier_report *report,
    size_t *out_indices, size_t out_capacity)
{
    if (bid_count == 0) return false;
    size_t index_span = af_frontier_index_span(out_capacity);
    return af_memory_overlaps(report, sizeof(*report), bids,
                              bid_count * sizeof(*bids)) ||
        af_memory_overlaps(report, sizeof(*report), heuristics,
                           bid_count * sizeof(*heuristics)) ||
        (out_capacity != 0 &&
         (af_memory_overlaps(out_indices, index_span, bids,
                             bid_count * sizeof(*bids)) ||
          af_memory_overlaps(out_indices, index_span, heuristics,
                             bid_count * sizeof(*heuristics))));
}

static bool af_frontier_parents_alias(
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    struct vcs_zcode_attention_frontier_report *report,
    size_t *out_indices, size_t out_capacity)
{
    size_t parent_span = parent_total * sizeof(*parents);
    return af_memory_overlaps(report, sizeof(*report), parents,
                              parent_span) ||
        (out_capacity != 0 &&
         af_memory_overlaps(out_indices, af_frontier_index_span(out_capacity),
                            parents, parent_span));
}

static bool af_frontier_query_alias(
    const struct vcs_zcode_attention_frontier_query *query,
    struct vcs_zcode_attention_frontier_report *report,
    size_t *out_indices, size_t out_capacity)
{
    size_t index_span = af_frontier_index_span(out_capacity);
    return af_memory_overlaps(report, sizeof(*report), query,
                              sizeof(*query)) ||
        (out_capacity != 0 &&
         (af_memory_overlaps(out_indices, index_span, query,
                             sizeof(*query)) ||
          af_memory_overlaps(out_indices, index_span, report,
                             sizeof(*report))));
}

static bool af_frontier_project_aliased(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage, const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_frontier_report *report)
{
    return af_frontier_rows_alias(bids, bid_count, heuristics, report,
                                  out_indices, out_capacity) ||
        (with_lineage && parent_total != 0 &&
         af_frontier_parents_alias(parents, parent_total, report,
                                   out_indices, out_capacity)) ||
        af_frontier_query_alias(query, report, out_indices, out_capacity);
}

static bool af_query_roots_set(
    const struct vcs_zcode_attention_frontier_query *query)
{
    const uint8_t *const query_roots[] = {
        query->focus_root, query->task_root, query->source_root,
        query->priority_policy_root, query->bid_evaluator_root,
    };
    for (size_t i = 0;
         i < sizeof(query_roots) / sizeof(query_roots[0]); i++) {
        if (af_root_is_zero(query_roots[i])) return false;
    }
    return true;
}

static enum vcs_zcode_attention_error af_frontier_query_precheck(
    const struct vcs_zcode_heuristic_v1 *heuristics, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage, const struct vcs_zcode_attention_frontier_query *query)
{
    if (with_lineage) {
        enum vcs_zcode_attention_error lineage_error =
            vcs_zcode_attention_lineage_validate_batch_layout(
                heuristics, bid_count, parents, parent_total);
        if (lineage_error != VCS_ZCODE_ATTENTION_OK)
            return lineage_error;
    }
    if (!af_priority_valid(query->priority_class))
        return VCS_ZCODE_ATTENTION_PRIORITY;
    if (!af_query_roots_set(query))
        return VCS_ZCODE_ATTENTION_ROOT;
    return VCS_ZCODE_ATTENTION_OK;
}

static size_t af_frontier_input_count(size_t bid_count, const bool *eligible)
{
    if (!eligible) return bid_count;
    size_t count = 0;
    for (size_t i = 0; i < bid_count; i++)
        if (eligible[i]) count++;
    return count;
}

static size_t af_frontier_mark_dominated(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const bool *in_class, bool *dominated)
{
    size_t frontier_count = 0;
    for (size_t i = 0; i < bid_count; i++) {
        if (!in_class[i]) continue;
        for (size_t j = 0; j < bid_count; j++) {
            if (i != j && in_class[j] &&
                af_bid_dominates(&bids[j], &bids[i])) {
                dominated[i] = true;
                break;
            }
        }
        if (!dominated[i]) frontier_count++;
    }
    return frontier_count;
}

static void af_frontier_emit_sorted(
    uint8_t roots[][32], const bool *in_class, const bool *dominated,
    size_t bid_count, size_t *out_indices, size_t *returned_count)
{
    for (size_t i = 0; i < bid_count; i++) {
        if (!in_class[i] || dominated[i]) continue;
        size_t position = *returned_count;
        while (position > 0 &&
               memcmp(roots[i], roots[out_indices[position - 1]], 32) < 0) {
            out_indices[position] = out_indices[position - 1];
            position--;
        }
        out_indices[position] = i;
        (*returned_count)++;
    }
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
    enum vcs_zcode_attention_error error = af_frontier_null_check(
        bids, bid_count, heuristics, query, out_indices, out_capacity, report);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    error = af_frontier_count_check(bid_count, with_lineage, parent_total,
                                    parents);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (af_frontier_project_aliased(bids, bid_count, heuristics, parents,
                                    parent_total, with_lineage, query,
                                    out_indices, out_capacity, report))
        return VCS_ZCODE_ATTENTION_ALIAS;
    error = af_frontier_query_precheck(heuristics, bid_count, parents,
                                       parent_total, with_lineage, query);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    struct vcs_zcode_attention_frontier_report result = {0};
    result.input_count = af_frontier_input_count(bid_count, eligible);
    uint8_t roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {{0}};
    bool in_class[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    bool dominated[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    size_t parent_cursor = 0;
    for (size_t i = 0; i < bid_count; i++) {
        error = af_frontier_row_check(bids, heuristics, parents,
                                      &parent_cursor, with_lineage, query,
                                      roots, eligible, i);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        in_class[i] = (!eligible || eligible[i]) &&
            bids[i].priority_class == query->priority_class;
        if (in_class[i]) result.class_candidate_count++;
    }
    result.frontier_count = af_frontier_mark_dominated(
        bids, bid_count, in_class, dominated);
    if (out_capacity < result.frontier_count) {
        *report = result;
        return VCS_ZCODE_ATTENTION_CAPACITY;
    }
    af_frontier_emit_sorted(roots, in_class, dominated, bid_count,
                            out_indices, &result.returned_count);
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

static size_t af_frontier_first_eligible(size_t bid_count, const bool *eligible)
{
    size_t first_eligible = 0;
    while (first_eligible < bid_count && eligible && !eligible[first_eligible])
        first_eligible++;
    return first_eligible;
}

static uint8_t af_frontier_selected_priority(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const bool *eligible, size_t first_eligible)
{
    uint8_t selected = bids[first_eligible].priority_class;
    for (size_t i = first_eligible + 1u; i < bid_count; i++) {
        if ((!eligible || eligible[i]) && bids[i].priority_class < selected)
            selected = bids[i].priority_class;
    }
    return selected;
}

static bool af_frontier_choose_report_alias(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage, const struct vcs_zcode_attention_frontier_query *query,
    struct vcs_zcode_attention_choice_report *report)
{
    return (bid_count != 0 &&
            (af_memory_overlaps(report, sizeof(*report), bids,
                                bid_count * sizeof(*bids)) ||
             af_memory_overlaps(report, sizeof(*report), heuristics,
                                bid_count * sizeof(*heuristics)))) ||
        (with_lineage && parent_total != 0 &&
         af_memory_overlaps(report, sizeof(*report), parents,
                            parent_total * sizeof(*parents))) ||
        af_memory_overlaps(report, sizeof(*report), query, sizeof(*query));
}

static bool af_frontier_choose_out_alias(
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage, const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report)
{
    if (out_capacity == 0 || !out_indices) return false;
    size_t index_span = af_frontier_index_span(out_capacity);
    return af_memory_overlaps(out_indices, index_span, query,
                              sizeof(*query)) ||
        af_memory_overlaps(out_indices, index_span, report,
                           sizeof(*report)) ||
        (with_lineage && parent_total != 0 &&
         af_memory_overlaps(out_indices, index_span, parents,
                            parent_total * sizeof(*parents)));
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
    enum vcs_zcode_attention_error error = af_frontier_null_check(
        bids, bid_count, heuristics, query, out_indices, out_capacity, report);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (query->priority_class != VCS_ZCODE_ATTENTION_PRIORITY_AUTO)
        return VCS_ZCODE_ATTENTION_PRIORITY;
    error = af_frontier_count_check(bid_count, with_lineage, parent_total,
                                    parents);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (af_frontier_choose_report_alias(bids, bid_count, heuristics, parents,
                                        parent_total, with_lineage, query,
                                        report) ||
        af_frontier_choose_out_alias(parents, parent_total, with_lineage,
                                     query, out_indices, out_capacity, report))
        return VCS_ZCODE_ATTENTION_ALIAS;

    struct vcs_zcode_attention_frontier_query exact = *query;
    struct vcs_zcode_attention_choice_report result = {0};
    size_t first_eligible = af_frontier_first_eligible(bid_count, eligible);
    if (first_eligible == bid_count) {
        exact.priority_class = VCS_ZCODE_ATTENTION_P0_SECURITY;
        error = af_frontier_project(
            bids, bid_count, heuristics, parents, parent_total,
            with_lineage, eligible, &exact, out_indices, out_capacity,
            &result.frontier);
        if (error == VCS_ZCODE_ATTENTION_OK) *report = result;
        return error;
    }
    uint8_t selected = af_frontier_selected_priority(
        bids, bid_count, eligible, first_eligible);
    exact.priority_class = selected;
    result.selected_priority_class = selected;
    error = af_frontier_project(
        bids, bid_count, heuristics, parents, parent_total, with_lineage,
        eligible, &exact, out_indices, out_capacity, &result.frontier);
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
