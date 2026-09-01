/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: immutable heuristic proposals and non-authoritative attention bids. */
#ifndef ZCL_VCS_ZCODE_ATTENTION_BID_H
#define ZCL_VCS_ZCODE_ATTENTION_BID_H

#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_focus.h"

#define VCS_ZCODE_HEURISTIC_DOMAIN "zcl.zcode.heuristic.v1"
#define VCS_ZCODE_HEURISTIC_VERSION 1u
#define VCS_ZCODE_HEURISTIC_WIRE_BYTES 688u
#define VCS_ZCODE_HEURISTIC_MAX_EVALUATORS 4u
#define VCS_ZCODE_HEURISTIC_MAX_PARENTS 4u
#define VCS_ZCODE_HEURISTIC_MAX_CPU_SECONDS UINT32_C(86400)
#define VCS_ZCODE_HEURISTIC_MAX_PROCESSES UINT32_C(256)
#define VCS_ZCODE_HEURISTIC_MAX_MEMORY_BYTES \
    (UINT64_C(16) * 1024u * 1024u * 1024u)
#define VCS_ZCODE_HEURISTIC_MAX_CONTEXT_BYTES \
    (UINT64_C(64) * 1024u * 1024u)
#define VCS_ZCODE_HEURISTIC_MAX_OUTPUT_BYTES \
    (UINT64_C(4) * 1024u * 1024u * 1024u)

#define VCS_ZCODE_ATTENTION_BID_DOMAIN "zcl.attention_bid.v1"
#define VCS_ZCODE_ATTENTION_BID_VERSION 1u
#define VCS_ZCODE_ATTENTION_BID_WIRE_BYTES 272u
#define VCS_ZCODE_ATTENTION_BASIS_POINTS_MAX 10000u
#define VCS_ZCODE_ATTENTION_METRIC_EXPECTED_USER_VALUE (1u << 0)
#define VCS_ZCODE_ATTENTION_METRIC_INFORMATION_GAIN (1u << 1)
#define VCS_ZCODE_ATTENTION_METRIC_BLOCKER_RELIEF (1u << 2)
#define VCS_ZCODE_ATTENTION_METRIC_REUSE_POTENTIAL (1u << 3)
#define VCS_ZCODE_ATTENTION_METRIC_EVIDENCE_STRENGTH (1u << 4)
#define VCS_ZCODE_ATTENTION_METRIC_RISK (1u << 5)
#define VCS_ZCODE_ATTENTION_METRIC_OVERLAP (1u << 6)
#define VCS_ZCODE_ATTENTION_METRIC_LATENCY (1u << 7)
#define VCS_ZCODE_ATTENTION_METRIC_COST (1u << 8)
#define VCS_ZCODE_ATTENTION_METRIC_REQUIRED \
    (VCS_ZCODE_ATTENTION_METRIC_EXPECTED_USER_VALUE | \
     VCS_ZCODE_ATTENTION_METRIC_INFORMATION_GAIN | \
     VCS_ZCODE_ATTENTION_METRIC_BLOCKER_RELIEF | \
     VCS_ZCODE_ATTENTION_METRIC_REUSE_POTENTIAL | \
     VCS_ZCODE_ATTENTION_METRIC_EVIDENCE_STRENGTH | \
     VCS_ZCODE_ATTENTION_METRIC_RISK | \
     VCS_ZCODE_ATTENTION_METRIC_OVERLAP | \
     VCS_ZCODE_ATTENTION_METRIC_LATENCY | \
     VCS_ZCODE_ATTENTION_METRIC_COST)
#define VCS_ZCODE_ATTENTION_FRONTIER_MAX_BIDS 64u
#define VCS_ZCODE_ATTENTION_PRIORITY_AUTO 0u

enum vcs_zcode_heuristic_derivation {
    VCS_ZCODE_HEURISTIC_SEED = 1,
    VCS_ZCODE_HEURISTIC_SPECIALIZE = 2,
    VCS_ZCODE_HEURISTIC_GENERALIZE = 3,
    VCS_ZCODE_HEURISTIC_COMPOSE = 4,
    VCS_ZCODE_HEURISTIC_ANALOGIZE = 5,
    VCS_ZCODE_HEURISTIC_REPAIR = 6,
};

enum vcs_zcode_attention_priority {
    VCS_ZCODE_ATTENTION_P0_SECURITY = 1,
    VCS_ZCODE_ATTENTION_P1_USER_JOURNEY = 2,
    VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY = 3,
    VCS_ZCODE_ATTENTION_P3_RESEARCH = 4,
};

enum vcs_zcode_attention_error {
    VCS_ZCODE_ATTENTION_OK = 0,
    VCS_ZCODE_ATTENTION_NULL,
    VCS_ZCODE_ATTENTION_ALIAS,
    VCS_ZCODE_ATTENTION_WIRE_SIZE,
    VCS_ZCODE_ATTENTION_MAGIC,
    VCS_ZCODE_ATTENTION_VERSION,
    VCS_ZCODE_ATTENTION_RESERVED,
    VCS_ZCODE_ATTENTION_DERIVATION,
    VCS_ZCODE_ATTENTION_COUNT,
    VCS_ZCODE_ATTENTION_ORDER,
    VCS_ZCODE_ATTENTION_ROOT,
    VCS_ZCODE_ATTENTION_BUDGET,
    VCS_ZCODE_ATTENTION_PRIORITY,
    VCS_ZCODE_ATTENTION_METRIC,
    VCS_ZCODE_ATTENTION_BINDING,
    VCS_ZCODE_ATTENTION_DUPLICATE,
    VCS_ZCODE_ATTENTION_CAPACITY,
    VCS_ZCODE_ATTENTION_CAS,
    VCS_ZCODE_ATTENTION_EVIDENCE,
};

struct vcs_zcode_heuristic_v1 {
    uint16_t schema_version;
    uint8_t derivation;
    uint8_t evaluator_count;
    uint8_t parent_count;
    uint8_t task_root[32];
    uint8_t source_root[32];
    uint8_t agent_context_root[32];
    uint8_t ontology_context_root[32];
    uint8_t applicability_root[32];
    uint8_t observed_features_root[32];
    uint8_t proposed_rule_root[32];
    uint8_t expected_effect_root[32];
    /* Proposal generation is sealed to relevance-free inputs and the
     * existing science/preregistration roots before evaluator results exist. */
    uint8_t proposal_input_root[32];
    uint8_t study_root[32];
    uint8_t preregistration_root[32];
    uint8_t provenance_root[32];
    uint8_t evaluator_roots[VCS_ZCODE_HEURISTIC_MAX_EVALUATORS][32];
    uint8_t parent_roots[VCS_ZCODE_HEURISTIC_MAX_PARENTS][32];
    /* Requests only. These never grant execution, confinement, lease, wallet,
     * consensus, or deployment authority and cannot widen an action budget. */
    uint32_t requested_cpu_seconds;
    uint32_t requested_processes;
    uint64_t requested_memory_bytes;
    uint64_t requested_context_bytes;
    uint64_t requested_output_bytes;
};

struct vcs_zcode_attention_bid_v1 {
    uint16_t schema_version;
    uint8_t priority_class;
    uint8_t focus_root[32];
    uint8_t task_root[32];
    uint8_t source_root[32];
    uint8_t heuristic_root[32];
    uint8_t priority_policy_root[32];
    uint8_t bid_evaluator_root[32];
    uint8_t evidence_root[32];
    uint16_t expected_user_value_bp;
    uint16_t information_gain_bp;
    uint16_t blocker_relief_bp;
    uint16_t reuse_potential_bp;
    uint16_t evidence_strength_bp;
    uint16_t risk_bp;
    uint16_t overlap_bp;
    /* All nine observations are required for a frontier. Unknown values do
     * not silently become zero-cost or zero-risk. */
    uint16_t observed_metrics;
    uint64_t expected_latency_us;
    uint64_t expected_cost_milliunits;
};

struct vcs_zcode_attention_frontier_query {
    uint8_t focus_root[32];
    uint8_t task_root[32];
    uint8_t source_root[32];
    uint8_t priority_policy_root[32];
    uint8_t bid_evaluator_root[32];
    uint8_t priority_class;
};

struct vcs_zcode_attention_frontier_report {
    size_t input_count;
    size_t class_candidate_count;
    size_t frontier_count;
    size_t returned_count;
};

struct vcs_zcode_attention_choice_report {
    struct vcs_zcode_attention_frontier_report frontier;
    /* Zero only for an empty automatic choice. */
    uint8_t selected_priority_class;
};

const char *vcs_zcode_attention_error_string(
    enum vcs_zcode_attention_error error);

void vcs_zcode_heuristic_init(struct vcs_zcode_heuristic_v1 *heuristic);
enum vcs_zcode_attention_error vcs_zcode_heuristic_validate(
    const struct vcs_zcode_heuristic_v1 *heuristic);
enum vcs_zcode_attention_error vcs_zcode_heuristic_serialize(
    const struct vcs_zcode_heuristic_v1 *heuristic,
    uint8_t out[VCS_ZCODE_HEURISTIC_WIRE_BYTES]);
enum vcs_zcode_attention_error vcs_zcode_heuristic_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_heuristic_v1 *out);
enum vcs_zcode_attention_error vcs_zcode_heuristic_root(
    const struct vcs_zcode_heuristic_v1 *heuristic, uint8_t out[32]);

void vcs_zcode_attention_bid_init(struct vcs_zcode_attention_bid_v1 *bid);
enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate(
    const struct vcs_zcode_attention_bid_v1 *bid);
/* Cross-object structural admission: re-roots the heuristic, binds task and
 * source, and requires the bid evaluator among its sealed evaluator roots.
 * Referenced CAS objects and evidence remain untrusted until their owning
 * subsystems load, re-root, and validate them. */
enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate_for_heuristic(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic);
/* Re-roots the immutable focus and proves that the situation-specific bid,
 * reusable heuristic, exact task/source/context/StoryGraph, and budgets all
 * describe the same bounded observation. */
enum vcs_zcode_attention_error vcs_zcode_attention_bid_validate_for_focus(
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus);
enum vcs_zcode_attention_error vcs_zcode_attention_bid_serialize(
    const struct vcs_zcode_attention_bid_v1 *bid,
    uint8_t out[VCS_ZCODE_ATTENTION_BID_WIRE_BYTES]);
enum vcs_zcode_attention_error vcs_zcode_attention_bid_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_attention_bid_v1 *out);
enum vcs_zcode_attention_error vcs_zcode_attention_bid_root(
    const struct vcs_zcode_attention_bid_v1 *bid, uint8_t out[32]);

/* Store one structurally bound heuristic/bid pair under its canonical roots
 * in the existing workspace CAS. Both fixed wires are reloaded, parsed,
 * re-rooted, address-checked, and cross-bound before success is returned.
 * Admission is atomic and idempotent per object but grants no task,
 * assignment, action, execution, evidence, or acceptance authority. The
 * output roots are zero on every ordinary failure. */
enum vcs_zcode_attention_error vcs_zcode_attention_store_pair(
    const char *workspace,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_attention_bid_v1 *bid,
    uint8_t heuristic_root_out[32], uint8_t bid_root_out[32]);

/* This is a pure, class-isolated projection of untrusted proposals. It does
 * not perform task-conflict admission, admit work, or change ownership. A
 * caller must use vcs_zcode_task_index_conflict() and exclude every result
 * other than CLEAR, and validate each candidate with
 * vcs_zcode_attention_bid_validate_for_focus(), before presenting a bid as
 * safely takeable. Output indices are sorted by bid root for display only.
 * If capacity is too small, no indices are returned and frontier_count still
 * reports the required size. */
enum vcs_zcode_attention_error vcs_zcode_attention_frontier_project(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_frontier_report *report);

/* Choose the highest-priority nonempty class (P0 before P1 before P2 before
 * P3), then preserve its complete Pareto frontier. The query must use
 * VCS_ZCODE_ATTENTION_PRIORITY_AUTO; callers that need a diagnostic view of
 * one exact class use frontier_project instead. This is still a proposal view:
 * it grants no task, action, execution, or acceptance authority. */
enum vcs_zcode_attention_error vcs_zcode_attention_frontier_choose(
    const struct vcs_zcode_attention_bid_v1 *bids, size_t bid_count,
    const struct vcs_zcode_heuristic_v1 *heuristics,
    const struct vcs_zcode_attention_frontier_query *query,
    size_t *out_indices, size_t out_capacity,
    struct vcs_zcode_attention_choice_report *report);

#endif /* ZCL_VCS_ZCODE_ATTENTION_BID_H */
