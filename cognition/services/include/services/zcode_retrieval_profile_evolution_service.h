/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, relevance-free retrieval-profile specialization. */
#ifndef ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_EVOLUTION_SERVICE_H
#define ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_EVOLUTION_SERVICE_H

#include "ontology/ontology.h"
#include "retrieval/retrieval_experiment.h"
#include "vcs/zcode_attention_bid.h"

#include <stdint.h>

enum zcode_retrieval_profile_evolution_error {
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK = 0,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NULL,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_ALIAS,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_PARAMETER,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_INCOMPLETE,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_HEURISTIC,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING,
    ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NO_EFFECT,
};

/* This request contains proposal inputs only. There is deliberately no gold,
 * relevance, evaluator result, attention score, lifecycle decision, or
 * activation channel. The service derives exactly one candidate by copying
 * the parent profile and changing context_byte_scale. */
struct zcode_retrieval_profile_evolution_request {
    const struct zcl_retrieval_profile_v1 *parent_profile;
    uint64_t candidate_context_byte_scale;
    const struct zcl_retrieval_feature_snapshot_v1 *feature_snapshot;
    const struct zcl_retrieval_feature_row_v1 *feature_rows;
    const struct vcs_zcode_heuristic_v1 *parent_heuristic;
    uint8_t expected_task_root[32];
    uint8_t expected_source_root[32];
    uint8_t expected_snapshot_source_root[32];
    uint8_t expected_retrieval_projection_root[32];
    uint8_t proposal_evaluator_root[32];
    uint8_t candidate_provenance_root[32];
    const char *task_id;
    const char *query;
};

struct zcode_retrieval_profile_evolution_report {
    struct zcl_retrieval_profile_v1 candidate_profile;
    struct vcs_zcode_heuristic_v1 candidate_heuristic;
    struct zcl_retrieval_profile_report parent_projection;
    struct zcl_retrieval_profile_report candidate_projection;
    uint8_t parent_profile_root[32];
    uint8_t candidate_profile_root[32];
    uint8_t feature_snapshot_root[32];
    uint8_t parent_heuristic_root[32];
    uint8_t proposal_input_root[32];
    uint8_t candidate_heuristic_root[32];
    enum zcl_ontology_status evaluation_status;
    enum zcl_ontology_status attention_status;
    uint16_t missing_attention_metrics;
};

/* Build one immutable SPECIALIZE proposal over one exact feature snapshot.
 * The parent heuristic must already bind the parent profile, snapshot, and
 * projected ranking. The candidate keeps the parent's task/source/context,
 * science roots, evaluator set, applicability, and budgets. Its new
 * proposal root is the existing canonical one-profile proposal identity;
 * the candidate heuristic's parent_roots binds the exact immediate parent
 * without creating a parallel proposal-root policy. task_id is proposal
 * identity; expected_task_root remains the authoritative task binding.
 *
 * Success means only that the relevance-free counterfactual is reproducible
 * and changes the ranking. It does not mean better, retained, replicated,
 * selected, accepted, or active. The report is unchanged on every failure. */
enum zcode_retrieval_profile_evolution_error
zcode_retrieval_profile_evolution_propose(
    const struct zcode_retrieval_profile_evolution_request *request,
    struct zcode_retrieval_profile_evolution_report *report);

const char *zcode_retrieval_profile_evolution_error_string(
    enum zcode_retrieval_profile_evolution_error error);

#endif /* ZCL_SERVICES_ZCODE_RETRIEVAL_PROFILE_EVOLUTION_SERVICE_H */
