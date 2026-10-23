/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: evaluator-attributed admission for automatic attention choice. */
#include "vcs/zcode_attention_verified.h"

#include "zcode_attention_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AV_COUNT(array) (sizeof(array) / sizeof((array)[0]))

/* A byte range an input occupies. A zero-count range has no base, so it
 * never overlaps the outputs (a bare zero-size range can still "overlap"). */
struct av_span {
    const void *base;
    size_t bytes;
};

/* The caller's outputs: the report and the caller's index buffer. */
struct av_output_view {
    const void *report;
    size_t report_size;
    const size_t *indices;
    size_t index_span;
    size_t capacity;
};

static bool av_memory_overlaps(const void *left, size_t left_size,
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

static bool av_root_is_zero(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate == 0;
}

static struct av_span av_span_of(const void *base, size_t count,
                                 size_t element_size)
{
    struct av_span span = { NULL, 0 };
    if (count != 0) {
        span.base = base;
        span.bytes = count * element_size;
    }
    return span;
}

static bool av_any_null(bool required, const void *const ptrs[], size_t count)
{
    if (!required) return false;
    for (size_t i = 0; i < count; i++) {
        if (!ptrs[i]) return true;
    }
    return false;
}

static size_t av_index_span(size_t out_capacity)
{
    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    return index_span * sizeof(size_t);
}

static bool av_outputs_alias(const struct av_output_view *out,
                             const struct av_span *spans, size_t count)
{
    if (out->capacity != 0 &&
        av_memory_overlaps(out->indices, out->index_span, out->report,
                           out->report_size))
        return true;
    for (size_t i = 0; i < count; i++) {
        if (av_memory_overlaps(out->report, out->report_size,
                               spans[i].base, spans[i].bytes))
            return true;
        if (out->capacity != 0 &&
            av_memory_overlaps(out->indices, out->index_span,
                               spans[i].base, spans[i].bytes))
            return true;
    }
    return false;
}

static enum vcs_zcode_attention_error av_bid_lineage_shape_error(
    size_t bid_count, const struct vcs_zcode_heuristic_v1 *parents,
    size_t parent_total, bool with_lineage)
{
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (!with_lineage) return VCS_ZCODE_ATTENTION_OK;
    if (parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (parent_total != 0 && !parents) return VCS_ZCODE_ATTENTION_NULL;
    if (parent_total == 0 && parents) return VCS_ZCODE_ATTENTION_COUNT;
    return VCS_ZCODE_ATTENTION_OK;
}

static bool av_statement_is_result(
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_evaluator_signer[32])
{
    return !av_root_is_zero(expected_evaluator_signer) &&
        vcs_zcode_science_statement_verify(
            statement, expected_evaluator_signer) == VCS_ZCODE_SCIENCE_OK &&
        statement->profile == VCS_ZCODE_SCIENCE_PROFILE_RESULT;
}

static bool av_statement_binds(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_science_statement_v1 *statement)
{
    uint8_t heuristic_root[32], focus_root[32], bid_root[32];
    if (vcs_zcode_heuristic_root(heuristic, heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_focus_root(focus, focus_root) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_attention_bid_root(bid, bid_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return false;
    return memcmp(statement->subject_root, heuristic_root, 32) == 0 &&
           memcmp(statement->predicate_body_root, bid_root, 32) == 0 &&
           memcmp(statement->input_root, focus_root, 32) == 0 &&
           memcmp(statement->provenance_root, bid->evidence_root, 32) == 0 &&
           memcmp(statement->activity_root, bid->bid_evaluator_root, 32) == 0;
}

static enum vcs_zcode_attention_error av_verify_statement(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count,
    bool with_lineage,
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_evaluator_signer[32])
{
    if (!bid || !heuristic || !focus || !statement ||
        !expected_evaluator_signer)
        return VCS_ZCODE_ATTENTION_NULL;
    enum vcs_zcode_attention_error error = with_lineage
        ? vcs_zcode_attention_bid_validate_for_focus_with_lineage(
            bid, heuristic, parents, parent_count, focus)
        : vcs_zcode_attention_bid_validate_for_focus(
            bid, heuristic, focus);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (!av_statement_is_result(statement, expected_evaluator_signer))
        return VCS_ZCODE_ATTENTION_EVIDENCE;
    if (!av_statement_binds(bid, heuristic, focus, statement))
        return VCS_ZCODE_ATTENTION_BINDING;
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error vcs_zcode_attention_bid_verify_statement(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_evaluator_signer[32])
{
    return av_verify_statement(
        bid, heuristic, NULL, 0, false, focus, statement,
        expected_evaluator_signer);
}

enum vcs_zcode_attention_error
vcs_zcode_attention_bid_verify_statement_with_lineage(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_count,
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_evaluator_signer[32])
{
    return av_verify_statement(
        bid, heuristic, parents, parent_count, true, focus, statement,
        expected_evaluator_signer);
}

static enum vcs_zcode_attention_error av_verify_batch(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    struct vcs_zcode_attention_frontier_query *query)
{
    if (with_lineage) {
        enum vcs_zcode_attention_error error =
            vcs_zcode_attention_lineage_validate_batch_layout(
                heuristics, bid_count, parents, parent_total);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
    }
    if (av_root_is_zero(priority_policy_root) ||
        av_root_is_zero(bid_evaluator_root) ||
        av_root_is_zero(expected_evaluator_signer))
        return VCS_ZCODE_ATTENTION_ROOT;

    memset(query, 0, sizeof(*query));
    query->priority_class = VCS_ZCODE_ATTENTION_PRIORITY_AUTO;
    if (vcs_zcode_focus_root(focus, query->focus_root) !=
            VCS_ZCODE_FOCUS_OK)
        return VCS_ZCODE_ATTENTION_BINDING;
    memcpy(query->task_root, focus->task_root, 32);
    memcpy(query->source_root, focus->source_universe_root, 32);
    memcpy(query->priority_policy_root, priority_policy_root, 32);
    memcpy(query->bid_evaluator_root, bid_evaluator_root, 32);

    size_t parent_cursor = 0;
    for (size_t i = 0; i < bid_count; i++) {
        if (memcmp(bids[i].priority_policy_root,
                   priority_policy_root, 32) != 0 ||
            memcmp(bids[i].bid_evaluator_root,
                   bid_evaluator_root, 32) != 0)
            return VCS_ZCODE_ATTENTION_BINDING;
        size_t row_parent_count = with_lineage
            ? heuristics[i].parent_count : 0;
        const struct vcs_zcode_heuristic_v1 *row_parents =
            row_parent_count != 0 ? &parents[parent_cursor] : NULL;
        enum vcs_zcode_attention_error error = av_verify_statement(
            &bids[i], &heuristics[i], row_parents, row_parent_count,
            with_lineage, focus, &statements[i],
            expected_evaluator_signer);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        parent_cursor += row_parent_count;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error av_row_roots(
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_science_statement_v1 *statement,
    uint8_t heuristic_root[32], uint8_t statement_root[32])
{
    if (vcs_zcode_heuristic_root(heuristic, heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_science_statement_root(statement, statement_root) !=
            VCS_ZCODE_SCIENCE_OK)
        return VCS_ZCODE_ATTENTION_BINDING;
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error av_row_is_distinct(
    uint8_t statement_roots[][32], size_t index)
{
    for (size_t j = 0; j < index; j++) {
        if (memcmp(statement_roots[index], statement_roots[j], 32) == 0)
            return VCS_ZCODE_ATTENTION_DUPLICATE;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error av_fold_lifecycle(
    const char *workspace,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    struct vcs_zcode_heuristic_lifecycle_report *lifecycle)
{
    enum vcs_zcode_attention_error error =
        vcs_zcode_heuristic_lifecycle_fold(workspace, snapshot, lifecycle);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (!lifecycle->complete ||
        lifecycle->status == VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED)
        return VCS_ZCODE_ATTENTION_EVIDENCE;
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error av_frontier_next_verified(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    bool with_lineage,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_verified_report *report)
{
    const void *const scalars[] = {
        focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, report,
    };
    const void *const rows[] = { bids, heuristics, statements };
    const void *const outs[] = { out_indices };
    if (av_any_null(true, scalars, AV_COUNT(scalars)) ||
        av_any_null(bid_count != 0, rows, AV_COUNT(rows)) ||
        av_any_null(out_capacity != 0, outs, AV_COUNT(outs)))
        return VCS_ZCODE_ATTENTION_NULL;
    enum vcs_zcode_attention_error error = av_bid_lineage_shape_error(
        bid_count, parents, parent_total, with_lineage);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    struct av_output_view out = {
        report, sizeof(*report), out_indices, av_index_span(out_capacity),
        out_capacity,
    };
    struct av_span spans[] = {
        av_span_of(bids, bid_count, sizeof(*bids)),
        av_span_of(heuristics, bid_count, sizeof(*heuristics)),
        av_span_of(statements, bid_count, sizeof(*statements)),
        av_span_of(parents, with_lineage ? parent_total : 0,
                   sizeof(*parents)),
        av_span_of(focus, 1, sizeof(*focus)),
        av_span_of(priority_policy_root, 32, 1),
        av_span_of(bid_evaluator_root, 32, 1),
        av_span_of(expected_evaluator_signer, 32, 1),
    };
    if (av_outputs_alias(&out, spans, AV_COUNT(spans)))
        return VCS_ZCODE_ATTENTION_ALIAS;

    struct vcs_zcode_attention_frontier_query query;
    error = av_verify_batch(
        bids, bid_count, heuristics, parents, parent_total, with_lineage,
        statements, focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, &query);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    struct vcs_zcode_attention_verified_report result = {
        .verified_count = bid_count,
    };
    error = with_lineage
        ? vcs_zcode_attention_frontier_choose_with_lineage(
            bids, bid_count, heuristics, parents, parent_total, &query,
            out_indices, out_capacity, &result.choice)
        : vcs_zcode_attention_frontier_choose(
            bids, bid_count, heuristics, &query, out_indices,
            out_capacity, &result.choice);
    if (error == VCS_ZCODE_ATTENTION_OK ||
        error == VCS_ZCODE_ATTENTION_CAPACITY)
        *report = result;
    return error;
}

enum vcs_zcode_attention_error vcs_zcode_attention_frontier_next_verified(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_verified_report *report)
{
    return av_frontier_next_verified(
        bids, bid_count, heuristics, NULL, 0, false, statements, focus,
        priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, out_indices, out_capacity, report);
}

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
    struct vcs_zcode_attention_verified_report *report)
{
    return av_frontier_next_verified(
        bids, bid_count, heuristics, parents, parent_total, true,
        statements, focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, out_indices, out_capacity, report);
}

static enum vcs_zcode_attention_error av_lifecycle_eligibility(
    const char *workspace, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshots,
    const uint8_t lifecycle_local_policy_root[32],
    const uint8_t expected_evaluator_signer[32],
    bool eligible[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS])
{
    uint8_t statement_roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {
        {0}
    };
    for (size_t i = 0; i < bid_count; i++) {
        uint8_t heuristic_root[32];
        enum vcs_zcode_attention_error error = av_row_roots(
            &heuristics[i], &statements[i], heuristic_root,
            statement_roots[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        error = av_row_is_distinct(statement_roots, i);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (memcmp(snapshots[i].local_policy_root,
                   lifecycle_local_policy_root, 32) != 0 ||
            memcmp(snapshots[i].expected_signer,
                   expected_evaluator_signer, 32) != 0 ||
            memcmp(snapshots[i].heuristic_root, heuristic_root, 32) != 0 ||
            memcmp(snapshots[i].anchor_statement_root,
                   statement_roots[i], 32) != 0)
            return VCS_ZCODE_ATTENTION_BINDING;

        struct vcs_zcode_heuristic_lifecycle_report lifecycle;
        error = av_fold_lifecycle(workspace, &snapshots[i], &lifecycle);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (lifecycle.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED)
            eligible[i] = true;
        else if (lifecycle.status != VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED)
            return VCS_ZCODE_ATTENTION_EVIDENCE;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_next_verified_with_lineage_and_lifecycle(
    const char *workspace,
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshots,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t lifecycle_local_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_verified_report *report)
{
    const void *const scalars[] = {
        workspace, focus, priority_policy_root, lifecycle_local_policy_root,
        bid_evaluator_root, expected_evaluator_signer, report,
    };
    const void *const rows[] = { bids, heuristics, statements, snapshots };
    const void *const outs[] = { out_indices };
    if (av_any_null(true, scalars, AV_COUNT(scalars)) ||
        av_any_null(bid_count != 0, rows, AV_COUNT(rows)) ||
        av_any_null(out_capacity != 0, outs, AV_COUNT(outs)))
        return VCS_ZCODE_ATTENTION_NULL;
    enum vcs_zcode_attention_error error = av_bid_lineage_shape_error(
        bid_count, parents, parent_total, true);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    size_t workspace_span = strlen(workspace) + 1u;
    struct av_output_view out = {
        report, sizeof(*report), out_indices, av_index_span(out_capacity),
        out_capacity,
    };
    struct av_span spans[] = {
        av_span_of(bids, bid_count, sizeof(*bids)),
        av_span_of(heuristics, bid_count, sizeof(*heuristics)),
        av_span_of(statements, bid_count, sizeof(*statements)),
        av_span_of(snapshots, bid_count, sizeof(*snapshots)),
        av_span_of(parents, parent_total, sizeof(*parents)),
        av_span_of(workspace, workspace_span, 1),
        av_span_of(focus, 1, sizeof(*focus)),
        av_span_of(priority_policy_root, 32, 1),
        av_span_of(lifecycle_local_policy_root, 32, 1),
        av_span_of(bid_evaluator_root, 32, 1),
        av_span_of(expected_evaluator_signer, 32, 1),
    };
    if (av_outputs_alias(&out, spans, AV_COUNT(spans)))
        return VCS_ZCODE_ATTENTION_ALIAS;
    if (av_root_is_zero(lifecycle_local_policy_root))
        return VCS_ZCODE_ATTENTION_ROOT;

    struct vcs_zcode_attention_frontier_query query;
    error = av_verify_batch(
        bids, bid_count, heuristics, parents, parent_total, true,
        statements, focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, &query);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    bool eligible[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    error = av_lifecycle_eligibility(
        workspace, bid_count, heuristics, statements, snapshots,
        lifecycle_local_policy_root, expected_evaluator_signer, eligible);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    struct vcs_zcode_attention_verified_report result = {
        .verified_count = bid_count,
    };
    error = vcs_zcode_attention_frontier_choose_eligible_with_lineage(
        bids, bid_count, heuristics, parents, parent_total, eligible, &query,
        out_indices, out_capacity, &result.choice);
    if (error == VCS_ZCODE_ATTENTION_OK ||
        error == VCS_ZCODE_ATTENTION_CAPACITY)
        *report = result;
    return error;
}

static enum vcs_zcode_attention_error av_replication_shape_error(
    size_t bid_count, const struct vcs_zcode_heuristic_v1 *parents,
    size_t parent_total,
    const struct vcs_zcode_attention_bid_v1 *bids,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *lifecycle_snapshots,
    const struct vcs_build_action_v1 *actions,
    const struct vcs_zcode_heuristic_replication_snapshot_v1
        *replication_snapshots)
{
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS ||
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if ((parent_total != 0 && !parents) ||
        (parent_total == 0 && parents) ||
        (bid_count == 0 && (bids || heuristics || statements ||
                            lifecycle_snapshots || actions ||
                            replication_snapshots)))
        return VCS_ZCODE_ATTENTION_COUNT;
    return VCS_ZCODE_ATTENTION_OK;
}

static bool av_replication_snapshot_binds(
    const struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot,
    const uint8_t replication_local_policy_root[32],
    const uint8_t expected_evaluator_signer[32],
    const uint8_t heuristic_root[32], const uint8_t statement_root[32])
{
    return memcmp(snapshot->local_policy_root,
                  replication_local_policy_root, 32) == 0 &&
           memcmp(snapshot->expected_evaluator_signer,
                  expected_evaluator_signer, 32) == 0 &&
           memcmp(snapshot->heuristic_root, heuristic_root, 32) == 0 &&
           memcmp(snapshot->anchor_statement_root, statement_root, 32) == 0;
}

static enum vcs_zcode_attention_error av_replication_lifecycle_pass(
    const char *workspace, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *lifecycle_snapshots,
    const struct vcs_zcode_heuristic_replication_snapshot_v1
        *replication_snapshots,
    const uint8_t lifecycle_local_policy_root[32],
    const uint8_t replication_local_policy_root[32],
    const uint8_t expected_evaluator_signer[32],
    bool retained[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS],
    struct vcs_zcode_attention_qualified_report *result)
{
    uint8_t statement_roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {
        {0}
    };
    for (size_t i = 0; i < bid_count; i++) {
        uint8_t heuristic_root[32];
        enum vcs_zcode_attention_error error = av_row_roots(
            &heuristics[i], &statements[i], heuristic_root,
            statement_roots[i]);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        error = av_row_is_distinct(statement_roots, i);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (memcmp(lifecycle_snapshots[i].local_policy_root,
                   lifecycle_local_policy_root, 32) != 0 ||
            memcmp(lifecycle_snapshots[i].expected_signer,
                   expected_evaluator_signer, 32) != 0 ||
            memcmp(lifecycle_snapshots[i].heuristic_root,
                   heuristic_root, 32) != 0 ||
            memcmp(lifecycle_snapshots[i].anchor_statement_root,
                   statement_roots[i], 32) != 0 ||
            !av_replication_snapshot_binds(
                &replication_snapshots[i], replication_local_policy_root,
                expected_evaluator_signer, heuristic_root,
                statement_roots[i]))
            return VCS_ZCODE_ATTENTION_BINDING;

        struct vcs_zcode_heuristic_lifecycle_report lifecycle;
        error = av_fold_lifecycle(workspace, &lifecycle_snapshots[i],
                                  &lifecycle);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (lifecycle.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED) {
            result->retired_count++;
        } else if (lifecycle.status ==
                   VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED) {
            retained[i] = true;
            result->retained_count++;
        } else {
            return VCS_ZCODE_ATTENTION_EVIDENCE;
        }
    }
    return VCS_ZCODE_ATTENTION_OK;
}

static enum vcs_zcode_attention_error av_replication_qualify_pass(
    const char *workspace, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_build_action_v1 *actions,
    const struct vcs_zcode_heuristic_replication_snapshot_v1
        *replication_snapshots,
    int64_t now_unix,
    const bool retained[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS],
    bool eligible[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS],
    struct vcs_zcode_attention_qualified_report *result)
{
    for (size_t i = 0; i < bid_count; i++) {
        struct vcs_zcode_heuristic_replication_report replication;
        enum vcs_zcode_attention_error error =
            vcs_zcode_heuristic_replication_fold(
                workspace, &heuristics[i], &actions[i],
                &replication_snapshots[i], now_unix, &replication);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (!replication.complete) return VCS_ZCODE_ATTENTION_EVIDENCE;
        if (!retained[i]) continue;
        if (replication.qualified) {
            eligible[i] = true;
            result->qualified_count++;
        } else {
            result->retained_unqualified_count++;
        }
    }
    return VCS_ZCODE_ATTENTION_OK;
}

static bool av_replication_policy_unset(
    const uint8_t lifecycle_local_policy_root[32],
    const uint8_t replication_local_policy_root[32], int64_t now_unix)
{
    return av_root_is_zero(lifecycle_local_policy_root) ||
           av_root_is_zero(replication_local_policy_root) || now_unix <= 0;
}

enum vcs_zcode_attention_error
vcs_zcode_attention_frontier_next_verified_with_lifecycle_and_replication(
    const char *workspace,
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_heuristic_v1 *parents, size_t parent_total,
    const struct vcs_zcode_science_statement_v1 *statements,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *lifecycle_snapshots,
    const struct vcs_build_action_v1 *actions,
    const struct vcs_zcode_heuristic_replication_snapshot_v1
        *replication_snapshots,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t priority_policy_root[32],
    const uint8_t lifecycle_local_policy_root[32],
    const uint8_t replication_local_policy_root[32],
    const uint8_t bid_evaluator_root[32],
    const uint8_t expected_evaluator_signer[32],
    int64_t now_unix,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_qualified_report *report)
{
    const void *const scalars[] = {
        workspace, focus, priority_policy_root, lifecycle_local_policy_root,
        replication_local_policy_root, bid_evaluator_root,
        expected_evaluator_signer, report,
    };
    const void *const rows[] = {
        bids, heuristics, statements, lifecycle_snapshots, actions,
        replication_snapshots,
    };
    const void *const outs[] = { out_indices };
    if (av_any_null(true, scalars, AV_COUNT(scalars)) ||
        av_any_null(bid_count != 0, rows, AV_COUNT(rows)) ||
        av_any_null(out_capacity != 0, outs, AV_COUNT(outs)))
        return VCS_ZCODE_ATTENTION_NULL;
    enum vcs_zcode_attention_error error = av_replication_shape_error(
        bid_count, parents, parent_total, bids, heuristics, statements,
        lifecycle_snapshots, actions, replication_snapshots);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    size_t workspace_span = strlen(workspace) + 1u;
    struct av_output_view out = {
        report, sizeof(*report), out_indices, av_index_span(out_capacity),
        out_capacity,
    };
    struct av_span spans[] = {
        av_span_of(bids, bid_count, sizeof(*bids)),
        av_span_of(heuristics, bid_count, sizeof(*heuristics)),
        av_span_of(statements, bid_count, sizeof(*statements)),
        av_span_of(lifecycle_snapshots, bid_count,
                   sizeof(*lifecycle_snapshots)),
        av_span_of(actions, bid_count, sizeof(*actions)),
        av_span_of(replication_snapshots, bid_count,
                   sizeof(*replication_snapshots)),
        av_span_of(parents, parent_total, sizeof(*parents)),
        av_span_of(workspace, workspace_span, 1),
        av_span_of(focus, 1, sizeof(*focus)),
        av_span_of(priority_policy_root, 32, 1),
        av_span_of(lifecycle_local_policy_root, 32, 1),
        av_span_of(replication_local_policy_root, 32, 1),
        av_span_of(bid_evaluator_root, 32, 1),
        av_span_of(expected_evaluator_signer, 32, 1),
    };
    if (av_outputs_alias(&out, spans, AV_COUNT(spans)))
        return VCS_ZCODE_ATTENTION_ALIAS;
    if (av_replication_policy_unset(lifecycle_local_policy_root,
                                    replication_local_policy_root, now_unix))
        return VCS_ZCODE_ATTENTION_EVIDENCE;

    struct vcs_zcode_attention_frontier_query query;
    error = av_verify_batch(
        bids, bid_count, heuristics, parents, parent_total, true,
        statements, focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, &query);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    bool retained[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    bool eligible[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    struct vcs_zcode_attention_qualified_report result = {
        .verified_count = bid_count,
    };
    error = av_replication_lifecycle_pass(
        workspace, bid_count, heuristics, statements, lifecycle_snapshots,
        replication_snapshots, lifecycle_local_policy_root,
        replication_local_policy_root, expected_evaluator_signer, retained,
        &result);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    /* A second retained generation cannot be hidden by filtering one of the
     * two on replication. Resolve lifecycle ambiguity first, then qualify. */
    size_t retained_indices[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS];
    struct vcs_zcode_attention_choice_report retained_choice;
    error = vcs_zcode_attention_frontier_choose_eligible_with_lineage(
        bids, bid_count, heuristics, parents, parent_total, retained, &query,
        retained_indices, VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS,
        &retained_choice);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    error = av_replication_qualify_pass(
        workspace, bid_count, heuristics, actions, replication_snapshots,
        now_unix, retained, eligible, &result);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    error = vcs_zcode_attention_frontier_choose_eligible_with_lineage(
        bids, bid_count, heuristics, parents, parent_total, eligible, &query,
        out_indices, out_capacity, &result.choice);
    if (error == VCS_ZCODE_ATTENTION_OK ||
        error == VCS_ZCODE_ATTENTION_CAPACITY)
        *report = result;
    return error;
}
