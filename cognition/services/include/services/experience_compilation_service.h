/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: compile one observable agent episode into verified reusable evidence. */
#ifndef ZCL_SERVICES_EXPERIENCE_COMPILATION_SERVICE_H
#define ZCL_SERVICES_EXPERIENCE_COMPILATION_SERVICE_H

#include "ontology/story_graph.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_attention_verified.h"
#include "vcs/zcode_focus.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zcl_experience_compilation_error {
    ZCL_EXPERIENCE_COMPILATION_OK = 0,
    ZCL_EXPERIENCE_COMPILATION_NULL,
    ZCL_EXPERIENCE_COMPILATION_ALIAS,
    ZCL_EXPERIENCE_COMPILATION_STORY,
    ZCL_EXPERIENCE_COMPILATION_FOCUS,
    ZCL_EXPERIENCE_COMPILATION_RECEIPT,
    ZCL_EXPERIENCE_COMPILATION_REPORT,
    ZCL_EXPERIENCE_COMPILATION_HEURISTIC,
    ZCL_EXPERIENCE_COMPILATION_SCIENCE,
    ZCL_EXPERIENCE_COMPILATION_ACCEPTANCE,
    ZCL_EXPERIENCE_COMPILATION_REPLICATION,
    ZCL_EXPERIENCE_COMPILATION_CAS,
};

/* One episode is one immutable shape. It composes existing authorities; it
 * does not mint task, execution, proof, local-acceptance, wallet, consensus,
 * publication, or deployment authority. The caller owns local_acceptance and
 * the policy that placed exact statement roots in it. */
struct zcl_experience_episode_v1 {
    const char *workspace;
    const struct zcl_story_graph_v1 *story;
    const struct vcs_zcode_task_v1 *task;
    const struct vcs_zcode_agent_context_v1 *agent_context;
    const struct vcs_zcode_focus_v1 *focus;
    const uint8_t (*claim_roots)[32];
    size_t claim_count;
    const struct vcs_zcode_work_receipt_v1 *work_receipt;
    const struct vcs_zcode_specialist_report_v1 *specialist_report;
    const struct vcs_zcode_heuristic_v1 *heuristic;
    const struct vcs_zcode_heuristic_v1 *parents;
    size_t parent_count;
    const struct vcs_zcode_attention_bid_v1 *attention_bid;
    const struct vcs_zcode_science_relation_set_v1 *relations;
    const struct vcs_zcode_science_statement_v1 *statement;
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *local_acceptance;
    /* Scientific qualification is one all-or-none bundle. Older captured
     * episodes may omit it, but an omitted or incomplete bundle can never
     * make a lesson relevant. */
    const struct zcl_ontology_predicate_v1 *outcome_predicate;
    const struct vcs_build_action_v1 *benchmark_action;
    const struct vcs_zcode_heuristic_replication_snapshot_v1
        *replication_acceptance;
    int64_t observed_at_unix;
};

/* This is a derived view over canonical evidence. captured=true means the
 * success or failure observation was stored and reverified. lesson_relevant
 * means the exact locally retained row survived relevance and lifecycle
 * selection. derived_rule_root identifies proposal bytes only; evidence and
 * local policy still decide every later use. */
struct zcl_experience_compilation_v1 {
    bool captured;
    bool lesson_relevant;
    bool replication_qualified;
    uint8_t outcome;
    uint8_t lifecycle_status;
    uint8_t lifecycle_reason;
    uint8_t replication_reason;
    uint16_t replicated_count;
    uint16_t required_reproductions;
    uint8_t story_root[32];
    uint8_t focus_root[32];
    uint8_t receipt_root[32];
    uint8_t report_root[32];
    uint8_t heuristic_root[32];
    uint8_t bid_root[32];
    uint8_t relations_root[32];
    uint8_t statement_root[32];
    uint8_t acceptance_snapshot_root[32];
    uint8_t outcome_predicate_root[32];
    uint8_t benchmark_action_root[32];
    uint8_t study_root[32];
    uint8_t original_result_root[32];
    uint8_t replication_snapshot_root[32];
    uint8_t derived_rule_root[32];
    uint8_t expected_effect_root[32];
};

const char *zcl_experience_compilation_error_string(
    enum zcl_experience_compilation_error error);

/* Validate every caller-supplied binding possible before writing, then
 * store/reload/parse/reroot the existing canonical wires and apply the
 * existing CAS-dependent lifecycle-and-replication-qualified attention
 * selector. Output is zero
 * on every non-alias failure. Aliasing output with any input is rejected
 * without modifying either region. A late CAS or accepted-lifecycle failure
 * can leave already verified addressed objects inert in CAS; no projection,
 * acceptance record, or alternate write path is created. */
enum zcl_experience_compilation_error zcl_experience_compile(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *out);

#endif /* ZCL_SERVICES_EXPERIENCE_COMPILATION_SERVICE_H */
