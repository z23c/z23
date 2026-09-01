/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: evaluator-attributed admission for automatic attention choice. */
#include "vcs/zcode_attention_verified.h"

#include "zcode_attention_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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
    if (av_root_is_zero(expected_evaluator_signer) ||
        vcs_zcode_science_statement_verify(
            statement, expected_evaluator_signer) != VCS_ZCODE_SCIENCE_OK ||
        statement->profile != VCS_ZCODE_SCIENCE_PROFILE_RESULT)
        return VCS_ZCODE_ATTENTION_EVIDENCE;

    uint8_t heuristic_root[32], focus_root[32], bid_root[32];
    if (vcs_zcode_heuristic_root(heuristic, heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_focus_root(focus, focus_root) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_attention_bid_root(bid, bid_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return VCS_ZCODE_ATTENTION_BINDING;
    if (memcmp(statement->subject_root, heuristic_root, 32) != 0 ||
        memcmp(statement->predicate_body_root, bid_root, 32) != 0 ||
        memcmp(statement->input_root, focus_root, 32) != 0 ||
        memcmp(statement->provenance_root, bid->evidence_root, 32) != 0 ||
        memcmp(statement->activity_root, bid->bid_evaluator_root, 32) != 0)
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
    if (!focus || !priority_policy_root || !bid_evaluator_root ||
        !expected_evaluator_signer || !report ||
        (bid_count != 0 && (!bids || !heuristics || !statements)) ||
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
         (av_memory_overlaps(report, sizeof(*report), bids,
                             bid_count * sizeof(*bids)) ||
          av_memory_overlaps(report, sizeof(*report), heuristics,
                             bid_count * sizeof(*heuristics)) ||
          av_memory_overlaps(report, sizeof(*report), statements,
                             bid_count * sizeof(*statements)) ||
          (out_capacity != 0 &&
           (av_memory_overlaps(out_indices, index_span, bids,
                               bid_count * sizeof(*bids)) ||
            av_memory_overlaps(out_indices, index_span, heuristics,
                               bid_count * sizeof(*heuristics)) ||
            av_memory_overlaps(out_indices, index_span, statements,
                               bid_count * sizeof(*statements)))))) ||
        (with_lineage && parent_total != 0 &&
         (av_memory_overlaps(report, sizeof(*report), parents,
                             parent_span) ||
          (out_capacity != 0 &&
           av_memory_overlaps(out_indices, index_span, parents,
                              parent_span)))) ||
        av_memory_overlaps(report, sizeof(*report), focus, sizeof(*focus)) ||
        av_memory_overlaps(report, sizeof(*report), priority_policy_root, 32) ||
        av_memory_overlaps(report, sizeof(*report), bid_evaluator_root, 32) ||
        av_memory_overlaps(report, sizeof(*report),
                           expected_evaluator_signer, 32) ||
        (out_capacity != 0 &&
         (av_memory_overlaps(out_indices, index_span, focus, sizeof(*focus)) ||
          av_memory_overlaps(out_indices, index_span,
                             priority_policy_root, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             bid_evaluator_root, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             expected_evaluator_signer, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             report, sizeof(*report)))))
        return VCS_ZCODE_ATTENTION_ALIAS;

    struct vcs_zcode_attention_frontier_query query;
    enum vcs_zcode_attention_error error = av_verify_batch(
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
    if (!workspace || !focus || !priority_policy_root ||
        !lifecycle_local_policy_root || !bid_evaluator_root ||
        !expected_evaluator_signer || !report ||
        (bid_count != 0 &&
         (!bids || !heuristics || !statements || !snapshots)) ||
        (out_capacity != 0 && !out_indices))
        return VCS_ZCODE_ATTENTION_NULL;
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS ||
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (parent_total != 0 && !parents)
        return VCS_ZCODE_ATTENTION_NULL;
    if (parent_total == 0 && parents)
        return VCS_ZCODE_ATTENTION_COUNT;

    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    index_span *= sizeof(*out_indices);
    size_t parent_span = parent_total * sizeof(*parents);
    size_t workspace_span = strlen(workspace) + 1u;
    size_t snapshot_span = bid_count * sizeof(*snapshots);
    if ((bid_count != 0 &&
         (av_memory_overlaps(report, sizeof(*report), bids,
                             bid_count * sizeof(*bids)) ||
          av_memory_overlaps(report, sizeof(*report), heuristics,
                             bid_count * sizeof(*heuristics)) ||
          av_memory_overlaps(report, sizeof(*report), statements,
                             bid_count * sizeof(*statements)) ||
          av_memory_overlaps(report, sizeof(*report), snapshots,
                             snapshot_span) ||
          (out_capacity != 0 &&
           (av_memory_overlaps(out_indices, index_span, bids,
                               bid_count * sizeof(*bids)) ||
            av_memory_overlaps(out_indices, index_span, heuristics,
                               bid_count * sizeof(*heuristics)) ||
            av_memory_overlaps(out_indices, index_span, statements,
                               bid_count * sizeof(*statements)) ||
            av_memory_overlaps(out_indices, index_span, snapshots,
                               snapshot_span))))) ||
        (parent_total != 0 &&
         (av_memory_overlaps(report, sizeof(*report), parents, parent_span) ||
          (out_capacity != 0 && av_memory_overlaps(
              out_indices, index_span, parents, parent_span)))) ||
        av_memory_overlaps(report, sizeof(*report), workspace,
                           workspace_span) ||
        av_memory_overlaps(report, sizeof(*report), focus, sizeof(*focus)) ||
        av_memory_overlaps(report, sizeof(*report), priority_policy_root, 32) ||
        av_memory_overlaps(report, sizeof(*report),
                           lifecycle_local_policy_root, 32) ||
        av_memory_overlaps(report, sizeof(*report), bid_evaluator_root, 32) ||
        av_memory_overlaps(report, sizeof(*report),
                           expected_evaluator_signer, 32) ||
        (out_capacity != 0 &&
         (av_memory_overlaps(out_indices, index_span, workspace,
                             workspace_span) ||
          av_memory_overlaps(out_indices, index_span, focus, sizeof(*focus)) ||
          av_memory_overlaps(out_indices, index_span,
                             priority_policy_root, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             lifecycle_local_policy_root, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             bid_evaluator_root, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             expected_evaluator_signer, 32) ||
          av_memory_overlaps(out_indices, index_span,
                             report, sizeof(*report)))))
        return VCS_ZCODE_ATTENTION_ALIAS;
    if (av_root_is_zero(lifecycle_local_policy_root))
        return VCS_ZCODE_ATTENTION_ROOT;

    struct vcs_zcode_attention_frontier_query query;
    enum vcs_zcode_attention_error error = av_verify_batch(
        bids, bid_count, heuristics, parents, parent_total, true,
        statements, focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, &query);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    bool eligible[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    uint8_t statement_roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {
        {0}
    };
    for (size_t i = 0; i < bid_count; i++) {
        uint8_t heuristic_root[32];
        if (vcs_zcode_heuristic_root(&heuristics[i], heuristic_root) !=
                VCS_ZCODE_ATTENTION_OK ||
            vcs_zcode_science_statement_root(
                &statements[i], statement_roots[i]) !=
                VCS_ZCODE_SCIENCE_OK)
            return VCS_ZCODE_ATTENTION_BINDING;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(statement_roots[i], statement_roots[j], 32) == 0)
                return VCS_ZCODE_ATTENTION_DUPLICATE;
        }
        if (memcmp(snapshots[i].local_policy_root,
                   lifecycle_local_policy_root, 32) != 0 ||
            memcmp(snapshots[i].expected_signer,
                   expected_evaluator_signer, 32) != 0 ||
            memcmp(snapshots[i].heuristic_root, heuristic_root, 32) != 0 ||
            memcmp(snapshots[i].anchor_statement_root,
                   statement_roots[i], 32) != 0)
            return VCS_ZCODE_ATTENTION_BINDING;

        struct vcs_zcode_heuristic_lifecycle_report lifecycle;
        error = vcs_zcode_heuristic_lifecycle_fold(
            workspace, &snapshots[i], &lifecycle);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (!lifecycle.complete || lifecycle.status ==
                VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED)
            return VCS_ZCODE_ATTENTION_EVIDENCE;
        if (lifecycle.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED)
            eligible[i] = true;
        else if (lifecycle.status != VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED)
            return VCS_ZCODE_ATTENTION_EVIDENCE;
    }

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
    if (!workspace || !focus || !priority_policy_root ||
        !lifecycle_local_policy_root || !replication_local_policy_root ||
        !bid_evaluator_root || !expected_evaluator_signer || !report ||
        (bid_count != 0 &&
         (!bids || !heuristics || !statements || !lifecycle_snapshots ||
          !actions || !replication_snapshots)) ||
        (out_capacity != 0 && !out_indices))
        return VCS_ZCODE_ATTENTION_NULL;
    if (bid_count > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS ||
        parent_total > VCS_ZCODE_ATTENTION_FRONTIER_MAX_PARENT_OBJECTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if ((parent_total != 0 && !parents) ||
        (parent_total == 0 && parents) ||
        (bid_count == 0 && (bids || heuristics || statements ||
                            lifecycle_snapshots || actions ||
                            replication_snapshots)))
        return VCS_ZCODE_ATTENTION_COUNT;

    size_t index_span = out_capacity;
    if (index_span > VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS)
        index_span = VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS;
    index_span *= sizeof(*out_indices);
    size_t parent_span = parent_total * sizeof(*parents);
    size_t bid_span = bid_count * sizeof(*bids);
    size_t heuristic_span = bid_count * sizeof(*heuristics);
    size_t statement_span = bid_count * sizeof(*statements);
    size_t lifecycle_span = bid_count * sizeof(*lifecycle_snapshots);
    size_t action_span = bid_count * sizeof(*actions);
    size_t replication_span = bid_count * sizeof(*replication_snapshots);
    size_t workspace_span = strlen(workspace) + 1u;
#define AV_OUTPUT_ALIASES(pointer_, span_)                                  \
    (av_memory_overlaps(report, sizeof(*report), (pointer_), (span_)) ||    \
     (out_capacity != 0 && av_memory_overlaps(                             \
         out_indices, index_span, (pointer_), (span_))))
    if ((bid_count != 0 &&
         (AV_OUTPUT_ALIASES(bids, bid_span) ||
          AV_OUTPUT_ALIASES(heuristics, heuristic_span) ||
          AV_OUTPUT_ALIASES(statements, statement_span) ||
          AV_OUTPUT_ALIASES(lifecycle_snapshots, lifecycle_span) ||
          AV_OUTPUT_ALIASES(actions, action_span) ||
          AV_OUTPUT_ALIASES(replication_snapshots, replication_span))) ||
        (parent_total != 0 && AV_OUTPUT_ALIASES(parents, parent_span)) ||
        AV_OUTPUT_ALIASES(workspace, workspace_span) ||
        AV_OUTPUT_ALIASES(focus, sizeof(*focus)) ||
        AV_OUTPUT_ALIASES(priority_policy_root, 32) ||
        AV_OUTPUT_ALIASES(lifecycle_local_policy_root, 32) ||
        AV_OUTPUT_ALIASES(replication_local_policy_root, 32) ||
        AV_OUTPUT_ALIASES(bid_evaluator_root, 32) ||
        AV_OUTPUT_ALIASES(expected_evaluator_signer, 32) ||
        (out_capacity != 0 && av_memory_overlaps(
            out_indices, index_span, report, sizeof(*report)))) {
#undef AV_OUTPUT_ALIASES
        return VCS_ZCODE_ATTENTION_ALIAS;
    }
#undef AV_OUTPUT_ALIASES
    if (av_root_is_zero(lifecycle_local_policy_root) ||
        av_root_is_zero(replication_local_policy_root) || now_unix <= 0)
        return VCS_ZCODE_ATTENTION_EVIDENCE;

    struct vcs_zcode_attention_frontier_query query;
    enum vcs_zcode_attention_error error = av_verify_batch(
        bids, bid_count, heuristics, parents, parent_total, true,
        statements, focus, priority_policy_root, bid_evaluator_root,
        expected_evaluator_signer, &query);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    bool retained[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    bool eligible[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS] = {false};
    uint8_t statement_roots[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS][32] = {
        {0}
    };
    struct vcs_zcode_attention_qualified_report result = {
        .verified_count = bid_count,
    };
    for (size_t i = 0; i < bid_count; i++) {
        uint8_t heuristic_root[32];
        if (vcs_zcode_heuristic_root(&heuristics[i], heuristic_root) !=
                VCS_ZCODE_ATTENTION_OK ||
            vcs_zcode_science_statement_root(
                &statements[i], statement_roots[i]) !=
                VCS_ZCODE_SCIENCE_OK)
            return VCS_ZCODE_ATTENTION_BINDING;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(statement_roots[i], statement_roots[j], 32) == 0)
                return VCS_ZCODE_ATTENTION_DUPLICATE;
        }
        if (memcmp(lifecycle_snapshots[i].local_policy_root,
                   lifecycle_local_policy_root, 32) != 0 ||
            memcmp(lifecycle_snapshots[i].expected_signer,
                   expected_evaluator_signer, 32) != 0 ||
            memcmp(lifecycle_snapshots[i].heuristic_root,
                   heuristic_root, 32) != 0 ||
            memcmp(lifecycle_snapshots[i].anchor_statement_root,
                   statement_roots[i], 32) != 0 ||
            memcmp(replication_snapshots[i].local_policy_root,
                   replication_local_policy_root, 32) != 0 ||
            memcmp(replication_snapshots[i].expected_evaluator_signer,
                   expected_evaluator_signer, 32) != 0 ||
            memcmp(replication_snapshots[i].heuristic_root,
                   heuristic_root, 32) != 0 ||
            memcmp(replication_snapshots[i].anchor_statement_root,
                   statement_roots[i], 32) != 0)
            return VCS_ZCODE_ATTENTION_BINDING;

        struct vcs_zcode_heuristic_lifecycle_report lifecycle;
        error = vcs_zcode_heuristic_lifecycle_fold(
            workspace, &lifecycle_snapshots[i], &lifecycle);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (!lifecycle.complete || lifecycle.status ==
                VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED)
            return VCS_ZCODE_ATTENTION_EVIDENCE;
        if (lifecycle.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED) {
            result.retired_count++;
        } else if (lifecycle.status ==
                   VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED) {
            retained[i] = true;
            result.retained_count++;
        } else {
            return VCS_ZCODE_ATTENTION_EVIDENCE;
        }
    }

    /* A second retained generation cannot be hidden by filtering one of the
     * two on replication. Resolve lifecycle ambiguity first, then qualify. */
    size_t retained_indices[VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS];
    struct vcs_zcode_attention_choice_report retained_choice;
    error = vcs_zcode_attention_frontier_choose_eligible_with_lineage(
        bids, bid_count, heuristics, parents, parent_total, retained, &query,
        retained_indices, VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS,
        &retained_choice);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;

    for (size_t i = 0; i < bid_count; i++) {
        struct vcs_zcode_heuristic_replication_report replication;
        error = vcs_zcode_heuristic_replication_fold(
            workspace, &heuristics[i], &actions[i],
            &replication_snapshots[i], now_unix, &replication);
        if (error != VCS_ZCODE_ATTENTION_OK) return error;
        if (!replication.complete) return VCS_ZCODE_ATTENTION_EVIDENCE;
        if (!retained[i]) continue;
        if (replication.qualified) {
            eligible[i] = true;
            result.qualified_count++;
        } else {
            result.retained_unqualified_count++;
        }
    }

    error = vcs_zcode_attention_frontier_choose_eligible_with_lineage(
        bids, bid_count, heuristics, parents, parent_total, eligible, &query,
        out_indices, out_capacity, &result.choice);
    if (error == VCS_ZCODE_ATTENTION_OK ||
        error == VCS_ZCODE_ATTENTION_CAPACITY)
        *report = result;
    return error;
}
