/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed independent-replication qualification adversarial tests. */
#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "services/experience_compilation_service.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_attention_verified.h"
#include "vcs/zcode_heuristic_replication.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HR_CHECK(name_, expression_) do {                                  \
    if (expression_) printf("  zcode_heuristic_replication: %s... OK\n",   \
                            (name_));                                      \
    else {                                                                 \
        printf("  zcode_heuristic_replication: %s... FAIL\n", (name_));   \
        failures++;                                                        \
    }                                                                      \
} while (0)

struct hr_fixture {
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_build_action_v1 action;
    struct vcs_zcode_heuristic_v1 heuristic;
    struct vcs_zcode_focus_v1 focus;
    struct vcs_zcode_attention_bid_v1 bid;
    struct vcs_zcode_benchmark_result_v1 original;
    struct vcs_zcode_benchmark_result_v1 reproduced[4];
    struct vcs_zcode_reproduction_v1 reproduction[4];
    struct vcs_zcode_science_statement_v1 anchor;
    struct vcs_zcode_science_statement_v1 statement[4];
    uint8_t evaluator_secret[32], evaluator_pubkey[32];
    uint8_t secret[4][32], pubkey[4][32];
    uint8_t study_root[32], task_root[32], heuristic_root[32];
    uint8_t candidate_root[32];
    uint8_t original_root[32], anchor_root[32];
    uint8_t reproduced_root[4][32], reproduction_root[4][32];
    uint8_t statement_root[4][32];
};

struct hr_experience_fixture {
    struct vcs_zcode_agent_context_v1 context;
    struct zcl_story_event_v1 story_event;
    struct zcl_story_graph_v1 story;
    struct zcl_ontology_predicate_v1 predicate;
    uint8_t claim_roots[1][32];
    struct vcs_zcode_focus_v1 focus;
    struct vcs_zcode_work_receipt_v1 receipt;
    struct vcs_zcode_specialist_report_v1 report;
    struct vcs_zcode_heuristic_v1 heuristic;
    struct vcs_zcode_attention_bid_v1 bid;
    struct vcs_zcode_science_relation_set_v1 anchor_relations;
    struct vcs_zcode_science_statement_v1 anchor;
    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 lifecycle;
    struct vcs_zcode_heuristic_replication_snapshot_v1 replication;
    struct zcl_experience_episode_v1 episode;
    uint8_t focus_root[32];
    uint8_t receipt_root[32];
    uint8_t heuristic_root[32];
    uint8_t anchor_root[32];
    uint8_t replication_statement_roots[4][32];
};

static void hr_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static bool hr_store(const char *workspace, const uint8_t root[32],
                     const uint8_t *wire, size_t wire_len)
{
    return vcs_object_put_addressed(workspace, root, wire, wire_len);
}

static bool hr_store_study(const char *workspace,
                           const struct vcs_zcode_study_spec_v1 *value,
                           uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    return vcs_zcode_study_spec_serialize(value, wire) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_root(value, root) == VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_task(const char *workspace,
                          const struct vcs_zcode_task_v1 *value,
                          uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_TASK_WIRE_BYTES];
    return vcs_zcode_task_serialize(value, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(value, root) == VCS_ZCODE_DEV_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_candidate(const char *workspace,
                               const struct vcs_zcode_candidate_v1 *value,
                               uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    return vcs_zcode_candidate_serialize(value, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(value, root) == VCS_ZCODE_DEV_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_result(
    const char *workspace, const struct vcs_zcode_benchmark_result_v1 *value,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
    return vcs_zcode_benchmark_result_serialize(value, wire) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_root(value, root) ==
            VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_reproduction(
    const char *workspace, const struct vcs_zcode_reproduction_v1 *value,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
    return vcs_zcode_reproduction_serialize(value, wire) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_reproduction_root(value, root) == VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_statement(
    const char *workspace, const struct vcs_zcode_science_statement_v1 *value,
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t root[32])
{
    uint8_t relation_wire[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES];
    uint8_t statement_wire[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES];
    uint8_t relation_root[32];
    size_t relation_len = 0;
    return vcs_zcode_science_relation_set_serialize(
               relations, relation_wire, &relation_len) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_relation_set_root(relations, relation_root) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_serialize(value, statement_wire) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(value, root) ==
               VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, relation_root, relation_wire, relation_len) &&
        hr_store(workspace, root, statement_wire, sizeof(statement_wire));
}

static void hr_statement_base(
    struct vcs_zcode_science_statement_v1 *statement, uint8_t profile,
    const uint8_t subject[32],
    const struct vcs_zcode_science_relation_set_v1 *relations, uint8_t tag)
{
    memset(statement, 0, sizeof(*statement));
    statement->schema_version = VCS_ZCODE_SCIENCE_STATEMENT_VERSION;
    statement->profile = profile;
    statement->access = VCS_ZCODE_SCIENCE_ACCESS_PUBLIC;
    statement->privacy = VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC;
    statement->redistribution = VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED;
    statement->authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED;
    statement->relation_count = relations->row_count;
    statement->relation_types = relations->row_count == 0 ? 0 :
        VCS_ZCODE_SCIENCE_RELATION_MASK(relations->rows[0].type);
    memcpy(statement->subject_root, subject, 32);
    hr_root(statement->predicate_body_root, tag);
    hr_root(statement->profile_schema_root, (uint8_t)(tag + 1u));
    hr_root(statement->provenance_root, (uint8_t)(tag + 2u));
    hr_root(statement->activity_root, (uint8_t)(tag + 3u));
    hr_root(statement->input_root, (uint8_t)(tag + 4u));
    hr_root(statement->authorship_assertion_root, (uint8_t)(tag + 5u));
    hr_root(statement->license_root, (uint8_t)(tag + 6u));
    hr_root(statement->access_policy_root, (uint8_t)(tag + 7u));
    hr_root(statement->privacy_policy_root, (uint8_t)(tag + 8u));
    hr_root(statement->external_identifiers_root, (uint8_t)(tag + 9u));
    hr_root(statement->citations_root, (uint8_t)(tag + 10u));
    (void)vcs_zcode_science_relation_set_root(
        relations, statement->relations_root);
}

static void hr_study_task_heuristic(struct hr_fixture *f)
{
    memset(&f->study, 0, sizeof(f->study));
    f->study.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    hr_root(f->study.hypothesis_root, 1);
    hr_root(f->study.null_hypothesis_root, 2);
    hr_root(f->study.source_root, 3);
    hr_root(f->study.dependency_lock_root, 4);
    hr_root(f->study.toolchain_capsule_root, 5);
    hr_root(f->study.protocol_root, 6);
    hr_root(f->study.workloads_root, 7);
    hr_root(f->study.metrics_root, 8);
    hr_root(f->study.estimator_tolerance_root, 9);
    hr_root(f->study.environment_policy_root, 10);
    hr_root(f->study.citations_root, 11);
    hr_root(f->study.preregistration_policy_root, 12);
    f->study.required_reproductions = 2;
    f->study.required_reviews = 1;
    f->study.sequence = 1;
    f->study.created_unix = 1000;
    f->study.expires_unix = 5000;
    (void)vcs_zcode_study_spec_root(&f->study, f->study_root);

    memset(&f->task, 0, sizeof(f->task));
    f->task.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(f->task.source_root, f->study.source_root, 32);
    memcpy(f->task.dependency_lock_root, f->study.dependency_lock_root, 32);
    memcpy(f->task.toolchain_capsule_root,
           f->study.toolchain_capsule_root, 32);
    hr_root(f->task.write_scope_root, 20);
    hr_root(f->task.acceptance_tests_root, 21);
    hr_root(f->task.proof_policy_root, 22);
    hr_root(f->task.model_policy_root, 23);
    memcpy(f->task.goal_root, f->study_root, 32);
    f->task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    f->task.max_changed_files = 8;
    f->task.max_patch_bytes = 65536;
    f->task.max_context_bytes = 65536;
    f->task.max_cpu_seconds = 60;
    f->task.max_memory_bytes = 16u * 1024u * 1024u;
    f->task.max_output_bytes = 1024u * 1024u;
    f->task.expires_unix = 5000;
    (void)vcs_zcode_task_root(&f->task, f->task_root);

    memset(&f->candidate, 0, sizeof(f->candidate));
    f->candidate.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(f->candidate.task_root, f->task_root, 32);
    memcpy(f->candidate.base_source_root, f->task.source_root, 32);
    hr_root(f->candidate.patch_root, 24);
    hr_root(f->candidate.candidate_source_root, 25);
    hr_root(f->candidate.adapter_policy_root, 26);
    hr_root(f->candidate.author_pubkey, 27);
    f->candidate.sequence = 1;
    f->candidate.created_unix = 1100;
    (void)vcs_zcode_candidate_root(&f->candidate, f->candidate_root);

    const char *workdir = NULL, *output = NULL, *resource = NULL;
    memset(&f->action, 0, sizeof(f->action));
    hr_root(f->action.source_sha256, 40);
    hr_root(f->action.source_cas_sha3, 41);
    hr_root(f->action.input_root_sha3, 42);
    hr_root(f->action.toolchain_capsule_sha3, 43);
    (void)vcs_build_action_v1_fixed_flags_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, f->action.flags_sha3);
    (void)vcs_build_action_v1_fixed_environment_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, f->action.environment_sha3);
    (void)vcs_build_action_v1_descriptors(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
        &workdir, &output, &resource);
    (void)snprintf(f->action.target, sizeof(f->action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(f->action.profile, sizeof(f->action.profile), "science");
    (void)snprintf(f->action.virtual_workdir,
                   sizeof(f->action.virtual_workdir), "%s", workdir);
    (void)snprintf(f->action.declared_outputs,
                   sizeof(f->action.declared_outputs), "%s", output);
    (void)snprintf(f->action.resource_policy,
                   sizeof(f->action.resource_policy), "%s", resource);
    f->action.sequence = 1;

    vcs_zcode_heuristic_init(&f->heuristic);
    f->heuristic.evaluator_count = 2;
    memcpy(f->heuristic.task_root, f->task_root, 32);
    memcpy(f->heuristic.source_root, f->study.source_root, 32);
    hr_root(f->heuristic.agent_context_root, 30);
    hr_root(f->heuristic.ontology_context_root, 31);
    hr_root(f->heuristic.applicability_root, 32);
    hr_root(f->heuristic.observed_features_root, 33);
    hr_root(f->heuristic.proposed_rule_root, 34);
    hr_root(f->heuristic.expected_effect_root, 35);
    hr_root(f->heuristic.proposal_input_root, 36);
    memcpy(f->heuristic.study_root, f->study_root, 32);
    memcpy(f->heuristic.preregistration_root,
           f->study.preregistration_policy_root, 32);
    hr_root(f->heuristic.provenance_root, 37);
    hr_root(f->heuristic.evaluator_roots[0], 38);
    hr_root(f->heuristic.evaluator_roots[1], 39);
    f->heuristic.requested_cpu_seconds = 30;
    f->heuristic.requested_processes = 1;
    f->heuristic.requested_memory_bytes = 1024u * 1024u;
    f->heuristic.requested_context_bytes = 4096;
    f->heuristic.requested_output_bytes = 4096;
    (void)vcs_zcode_heuristic_root(&f->heuristic, f->heuristic_root);
}

static void hr_result(struct vcs_zcode_benchmark_result_v1 *result,
                      const struct hr_fixture *f, uint8_t tag,
                      int64_t finished_unix)
{
    memset(result, 0, sizeof(*result));
    result->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    memcpy(result->study_root, f->study_root, 32);
    memcpy(result->task_root, f->task_root, 32);
    memcpy(result->candidate_root, f->candidate_root, 32);
    (void)vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &f->action,
        result->action_root);
    hr_root(result->achieved_environment_root, tag);
    hr_root(result->raw_sample_root, (uint8_t)(tag + 1u));
    hr_root(result->evidence_root, (uint8_t)(tag + 2u));
    result->status = VCS_ZCODE_BENCHMARK_OBSERVED;
    result->challenge_block_height = 1;
    hr_root(result->challenge_block_hash, 52);
    result->sequence = tag;
    result->started_unix = finished_unix - 10;
    result->finished_unix = finished_unix;
}

static bool hr_attention(struct hr_fixture *f)
{
    memset(&f->focus, 0, sizeof(f->focus));
    f->focus.schema_version = VCS_ZCODE_FOCUS_VERSION;
    f->focus.status = ZCL_ONTOLOGY_PROVED;
    f->focus.capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                            VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    f->focus.max_changed_files = 8;
    f->focus.max_patch_bytes = 65536;
    f->focus.max_context_bytes = 65536;
    f->focus.max_cpu_seconds = 60;
    f->focus.max_memory_bytes = 16u * 1024u * 1024u;
    f->focus.max_output_bytes = 1024u * 1024u;
    memcpy(f->focus.task_root, f->task_root, 32);
    memcpy(f->focus.goal_root, f->study_root, 32);
    memcpy(f->focus.source_universe_root, f->study.source_root, 32);
    memcpy(f->focus.context_root, f->heuristic.agent_context_root, 32);
    memcpy(f->focus.story_graph_root,
           f->heuristic.ontology_context_root, 32);
    if (vcs_zcode_focus_claim_set_root(
            NULL, 0, f->focus.claim_set_root) != VCS_ZCODE_FOCUS_OK)
        return false;
    memcpy(f->focus.required_evidence_root,
           f->heuristic.preregistration_root, 32);
    hr_root(f->focus.authority_limits_root, 199);

    vcs_zcode_attention_bid_init(&f->bid);
    f->bid.priority_class = VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY;
    if (vcs_zcode_focus_root(&f->focus, f->bid.focus_root) !=
            VCS_ZCODE_FOCUS_OK)
        return false;
    memcpy(f->bid.task_root, f->task_root, 32);
    memcpy(f->bid.source_root, f->study.source_root, 32);
    memcpy(f->bid.heuristic_root, f->heuristic_root, 32);
    hr_root(f->bid.priority_policy_root, 198);
    memcpy(f->bid.bid_evaluator_root,
           f->heuristic.evaluator_roots[0], 32);
    memcpy(f->bid.evidence_root, f->original_root, 32);
    f->bid.expected_user_value_bp = 7000;
    f->bid.information_gain_bp = 8000;
    f->bid.blocker_relief_bp = 6000;
    f->bid.reuse_potential_bp = 7000;
    f->bid.evidence_strength_bp = 9000;
    f->bid.risk_bp = 1000;
    f->bid.overlap_bp = 500;
    f->bid.observed_metrics = VCS_ZCODE_ATTENTION_METRIC_REQUIRED;
    f->bid.expected_latency_us = UINT64_C(1000000);
    f->bid.expected_cost_milliunits = 10;
    return vcs_zcode_attention_bid_validate_for_focus(
        &f->bid, &f->heuristic, &f->focus) == VCS_ZCODE_ATTENTION_OK;
}

static bool hr_fixture_build(const char *workspace, struct hr_fixture *f)
{
    memset(f, 0, sizeof(*f));
    hr_study_task_heuristic(f);
    uint8_t seed[32];
    hr_root(seed, 80);
    ed25519_keypair(f->evaluator_pubkey, f->evaluator_secret, seed);
    for (size_t i = 0; i < 4; i++) {
        hr_root(seed, (uint8_t)(81u + i));
        ed25519_keypair(f->pubkey[i], f->secret[i], seed);
    }
    hr_result(&f->original, f, 60, 1300);
    if (!hr_store_study(workspace, &f->study, f->study_root) ||
        !hr_store_task(workspace, &f->task, f->task_root) ||
        !hr_store_candidate(workspace, &f->candidate, f->candidate_root) ||
        !hr_store_result(workspace, &f->original, f->original_root) ||
        !hr_attention(f))
        return false;

    struct vcs_zcode_science_relation_set_v1 empty = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    hr_statement_base(&f->anchor, VCS_ZCODE_SCIENCE_PROFILE_RESULT,
                      f->heuristic_root, &empty, 90);
    (void)vcs_zcode_attention_bid_root(
        &f->bid, f->anchor.predicate_body_root);
    memcpy(f->anchor.provenance_root, f->original_root, 32);
    memcpy(f->anchor.activity_root, f->bid.bid_evaluator_root, 32);
    memcpy(f->anchor.input_root, f->bid.focus_root, 32);
    f->anchor.observed_unix = f->original.finished_unix;
    if (vcs_zcode_science_statement_seal(
            &f->anchor, f->evaluator_secret, f->evaluator_pubkey) !=
            VCS_ZCODE_SCIENCE_OK ||
        !hr_store_statement(workspace, &f->anchor, &empty, f->anchor_root))
        return false;

    for (size_t i = 0; i < 4; i++) {
        hr_result(&f->reproduced[i], f, (uint8_t)(100u + i * 3u),
                  (int64_t)(1400u + i));
        if (!hr_store_result(workspace, &f->reproduced[i],
                             f->reproduced_root[i]))
            return false;
        struct vcs_zcode_reproduction_v1 *r = &f->reproduction[i];
        memset(r, 0, sizeof(*r));
        r->schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(r->study_root, f->study_root, 32);
        memcpy(r->original_result_root, f->original_root, 32);
        memcpy(r->reproduced_result_root, f->reproduced_root[i], 32);
        memcpy(r->comparison_policy_root,
               f->study.preregistration_policy_root, 32);
        memcpy(r->original_environment_root,
               f->original.achieved_environment_root, 32);
        memcpy(r->reproduced_environment_root,
               f->reproduced[i].achieved_environment_root, 32);
        memcpy(r->reproducer_pubkey, f->pubkey[i], 32);
        r->verdict = i < 2 ? VCS_ZCODE_REPRODUCTION_REPLICATED :
            (i == 2 ? VCS_ZCODE_REPRODUCTION_INCONCLUSIVE :
                      VCS_ZCODE_REPRODUCTION_CONTRADICTED);
        r->sequence = i + 1u;
        r->created_unix = 1500 + (int64_t)i;
        if (!hr_store_reproduction(workspace, r, f->reproduction_root[i]))
            return false;

        struct vcs_zcode_science_relation_set_v1 support = {
            .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
            .row_count = 1,
            .rows = {{
                .type = VCS_ZCODE_SCIENCE_RELATION_SUPPORT,
            }},
        };
        memcpy(support.rows[0].statement_root, f->anchor_root, 32);
        hr_statement_base(&f->statement[i],
            VCS_ZCODE_SCIENCE_PROFILE_REPLICATION, f->heuristic_root,
            &support, (uint8_t)(130u + i * 11u));
        memcpy(f->statement[i].predicate_body_root,
               f->reproduction_root[i], 32);
        memcpy(f->statement[i].provenance_root, f->reproduced_root[i], 32);
        memcpy(f->statement[i].activity_root,
               r->comparison_policy_root, 32);
        memcpy(f->statement[i].input_root, f->original_root, 32);
        f->statement[i].observed_unix = r->created_unix;
        if (vcs_zcode_science_statement_seal(
                &f->statement[i], f->secret[i], f->pubkey[i]) !=
                VCS_ZCODE_SCIENCE_OK ||
            !hr_store_statement(workspace, &f->statement[i], &support,
                                f->statement_root[i]))
            return false;
    }
    return true;
}

static bool hr_rewrite_anchor_status(
    const char *workspace, struct hr_fixture *f, uint8_t status)
{
    struct vcs_zcode_science_relation_set_v1 empty = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    f->original.status = status;
    if (!hr_store_result(workspace, &f->original, f->original_root))
        return false;
    memcpy(f->anchor.provenance_root, f->original_root, 32);
    memset(f->anchor.signature, 0, sizeof(f->anchor.signature));
    return vcs_zcode_science_statement_seal(
               &f->anchor, f->evaluator_secret, f->evaluator_pubkey) ==
               VCS_ZCODE_SCIENCE_OK &&
        hr_store_statement(
            workspace, &f->anchor, &empty, f->anchor_root);
}

static bool hr_rewrite_reproduced_status(
    const char *workspace, struct hr_fixture *f, size_t row,
    uint8_t status, uint8_t verdict)
{
    if (row >= 4u) return false;
    f->reproduced[row].status = status;
    if (!hr_store_result(
            workspace, &f->reproduced[row], f->reproduced_root[row]))
        return false;
    memcpy(f->reproduction[row].reproduced_result_root,
           f->reproduced_root[row], 32);
    memcpy(f->reproduction[row].reproduced_environment_root,
           f->reproduced[row].achieved_environment_root, 32);
    f->reproduction[row].verdict = verdict;
    if (!hr_store_reproduction(
            workspace, &f->reproduction[row], f->reproduction_root[row]))
        return false;
    memcpy(f->statement[row].predicate_body_root,
           f->reproduction_root[row], 32);
    memcpy(f->statement[row].provenance_root,
           f->reproduced_root[row], 32);
    memset(f->statement[row].signature, 0,
           sizeof(f->statement[row].signature));
    if (vcs_zcode_science_statement_seal(
            &f->statement[row], f->secret[row], f->pubkey[row]) !=
            VCS_ZCODE_SCIENCE_OK)
        return false;
    struct vcs_zcode_science_relation_set_v1 support = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
        .row_count = 1,
        .rows = {{.type = VCS_ZCODE_SCIENCE_RELATION_SUPPORT}},
    };
    memcpy(support.rows[0].statement_root, f->anchor_root, 32);
    return hr_store_statement(
        workspace, &f->statement[row], &support, f->statement_root[row]);
}

static void hr_sort(uint8_t roots[][32], size_t count)
{
    for (size_t i = 1; i < count; i++) {
        uint8_t value[32];
        memcpy(value, roots[i], 32);
        size_t at = i;
        while (at != 0 && memcmp(roots[at - 1u], value, 32) > 0) {
            memcpy(roots[at], roots[at - 1u], 32);
            at--;
        }
        memcpy(roots[at], value, 32);
    }
}

static void hr_snapshot(
    struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot,
    const struct hr_fixture *f, const size_t rows[], size_t count)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->schema_version =
        VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_VERSION;
    snapshot->statement_count = (uint16_t)count;
    hr_root(snapshot->local_policy_root, 200);
    memcpy(snapshot->expected_evaluator_signer, f->evaluator_pubkey, 32);
    memcpy(snapshot->heuristic_root, f->heuristic_root, 32);
    memcpy(snapshot->anchor_statement_root, f->anchor_root, 32);
    for (size_t i = 0; i < count; i++)
        memcpy(snapshot->statement_roots[i], f->statement_root[rows[i]], 32);
    hr_sort(snapshot->statement_roots, count);
}

static void hr_lifecycle_snapshot(
    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    const struct hr_fixture *f)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->schema_version =
        VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_VERSION;
    snapshot->statement_count = 1;
    hr_root(snapshot->local_policy_root, 201);
    memcpy(snapshot->expected_signer, f->evaluator_pubkey, 32);
    memcpy(snapshot->heuristic_root, f->heuristic_root, 32);
    memcpy(snapshot->anchor_statement_root, f->anchor_root, 32);
    memcpy(snapshot->statement_roots[0], f->anchor_root, 32);
}

static bool hr_experience_build(
    const char *workspace, const struct hr_fixture *f,
    struct hr_experience_fixture *x)
{
#define HR_EXPERIENCE_FAIL(stage_) do {                                 \
    printf("  zcode_heuristic_replication: experience fixture %s failed\n", \
           (stage_));                                                    \
    return false;                                                        \
} while (0)
    static uint8_t source_excerpt[] =
        "experience compiler replication-qualified source excerpt";
    memset(x, 0, sizeof(*x));

    x->predicate.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    x->predicate.arity = 1;
    x->predicate.world = ZCL_ONTOLOGY_OPEN_WORLD;
    x->predicate.execution_tier = ZCL_ONTOLOGY_TIER_EXACT;
    x->predicate.explicit_negation = 1;
    hr_root(x->predicate.term_root, 210);
    hr_root(x->predicate.argument_type_roots[0], 211);
    if (!zcl_ontology_predicate_v1_root(
            &x->predicate, x->claim_roots[0]))
        HR_EXPERIENCE_FAIL("predicate");

    vcs_zcode_agent_context_init(&x->context);
    memcpy(x->context.task_root, f->task_root, 32);
    memcpy(x->context.source_root, f->task.source_root, 32);
    memcpy(x->context.goal_root, f->task.goal_root, 32);
    memcpy(x->context.source_tree_root, f->task.source_root, 32);
    (void)snprintf(x->context.query, sizeof(x->context.query),
                   "compile one independently reproduced experience");
    x->context.file_count = 1;
    (void)snprintf(x->context.files[0].path,
                   sizeof(x->context.files[0].path),
                   "cognition/services/src/experience_compilation_service.c");
    x->context.files[0].start_line = 1;
    x->context.files[0].full_file_bytes = sizeof(source_excerpt) - 1u;
    x->context.files[0].content = source_excerpt;
    x->context.files[0].content_len = sizeof(source_excerpt) - 1u;
    sha3_256(source_excerpt, sizeof(source_excerpt) - 1u,
             x->context.files[0].content_root);
    uint8_t context_root[32];
    if (vcs_zcode_agent_context_root(
            &x->context, f->task.max_context_bytes, context_root) !=
            VCS_ZCODE_AGENT_CONTEXT_OK)
        HR_EXPERIENCE_FAIL("context");

    x->story_event.schema_version = ZCL_STORY_GRAPH_VERSION;
    x->story_event.kind = ZCL_STORY_EVENT_USER_ASKS;
    x->story_event.status = ZCL_ONTOLOGY_PROVED;
    memcpy(x->story_event.universe_root, f->task.source_root, 32);
    memcpy(x->story_event.context_root, context_root, 32);
    memcpy(x->story_event.scene_root, f->task_root, 32);
    memcpy(x->story_event.entity_root, f->evaluator_pubkey, 32);
    (void)vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &f->action,
        x->story_event.action_root);
    hr_root(x->story_event.event_root, 212);
    memcpy(x->story_event.evidence_root, f->original_root, 32);
    x->story = (struct zcl_story_graph_v1) {
        .schema_version = ZCL_STORY_GRAPH_VERSION,
        .event_count = 1,
        .events = &x->story_event,
    };
    uint8_t story_root[32];
    if (!zcl_story_graph_v1_root(&x->story, story_root) ||
        vcs_zcode_focus_compose(
            &f->task, f->task_root, context_root, story_root,
            ZCL_ONTOLOGY_PROVED, 0, x->claim_roots, 1, &x->focus) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_root(&x->focus, x->focus_root) !=
            VCS_ZCODE_FOCUS_OK)
        HR_EXPERIENCE_FAIL("story-focus");

    x->receipt.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(x->receipt.task_root, f->task_root, 32);
    memcpy(x->receipt.candidate_root, f->candidate_root, 32);
    memcpy(x->receipt.action_root, x->story_event.action_root, 32);
    memcpy(x->receipt.input_root, x->focus_root, 32);
    memcpy(x->receipt.output_root, f->original_root, 32);
    memcpy(x->receipt.proof_policy_root, f->task.proof_policy_root, 32);
    memcpy(x->receipt.toolchain_capsule_root,
           f->task.toolchain_capsule_root, 32);
    hr_root(x->receipt.lease_id, 213);
    memcpy(x->receipt.evidence_root, f->original.evidence_root, 32);
    memcpy(x->receipt.confinement_root, x->focus.authority_limits_root, 32);
    x->receipt.work_kind = VCS_ZCODE_WORK_TEST;
    x->receipt.status = VCS_ZCODE_WORK_PASS;
    x->receipt.started_unix = 1200;
    x->receipt.finished_unix = 1300;
    if (vcs_zcode_work_receipt_seal(
            &x->receipt, f->evaluator_secret, f->evaluator_pubkey) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(&x->receipt, x->receipt_root) !=
            VCS_ZCODE_DEV_OK)
        HR_EXPERIENCE_FAIL("receipt");

    x->report.schema_version = VCS_ZCODE_FOCUS_VERSION;
    x->report.role = VCS_ZCODE_SPECIALIST_CODE;
    x->report.status = ZCL_ONTOLOGY_PROVED;
    x->report.context_bytes = sizeof(source_excerpt) - 1u;
    x->report.latency_us = 1000;
    x->report.files_opened = 1;
    x->report.tool_calls = 1;
    x->report.proof_reuse_count = 1;
    memcpy(x->report.focus_root, x->focus_root, 32);
    memcpy(x->report.claim_root, x->claim_roots[0], 32);
    memcpy(x->report.specialist_root, f->evaluator_pubkey, 32);
    memcpy(x->report.evidence_root, x->receipt_root, 32);
    memcpy(x->report.result_root, f->original_root, 32);
    memcpy(x->report.next_experiment_root, f->study_root, 32);
    memcpy(x->report.evaluator_root, f->bid.bid_evaluator_root, 32);

    x->heuristic = f->heuristic;
    memcpy(x->heuristic.agent_context_root, context_root, 32);
    memcpy(x->heuristic.ontology_context_root, story_root, 32);
    memcpy(x->heuristic.applicability_root, x->claim_roots[0], 32);
    memcpy(x->heuristic.provenance_root, x->receipt_root, 32);
    if (vcs_zcode_heuristic_root(
            &x->heuristic, x->heuristic_root) != VCS_ZCODE_ATTENTION_OK)
        HR_EXPERIENCE_FAIL("heuristic");

    x->bid = f->bid;
    memcpy(x->bid.focus_root, x->focus_root, 32);
    memcpy(x->bid.heuristic_root, x->heuristic_root, 32);
    memcpy(x->bid.evidence_root, f->original_root, 32);
    if (vcs_zcode_attention_bid_validate_for_focus(
            &x->bid, &x->heuristic, &x->focus) != VCS_ZCODE_ATTENTION_OK)
        HR_EXPERIENCE_FAIL("attention-bid");

    x->anchor_relations.schema_version =
        VCS_ZCODE_SCIENCE_RELATION_SET_VERSION;
    x->anchor = f->anchor;
    memcpy(x->anchor.subject_root, x->heuristic_root, 32);
    (void)vcs_zcode_attention_bid_root(
        &x->bid, x->anchor.predicate_body_root);
    memcpy(x->anchor.input_root, x->focus_root, 32);
    memset(x->anchor.signature, 0, sizeof(x->anchor.signature));
    if (vcs_zcode_science_statement_seal(
            &x->anchor, f->evaluator_secret, f->evaluator_pubkey) !=
            VCS_ZCODE_SCIENCE_OK ||
        !hr_store_statement(workspace, &x->anchor, &x->anchor_relations,
                            x->anchor_root))
        HR_EXPERIENCE_FAIL("anchor");

    for (size_t i = 0; i < 4; i++) {
        struct vcs_zcode_science_relation_set_v1 support = {
            .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
            .row_count = 1,
            .rows = {{.type = VCS_ZCODE_SCIENCE_RELATION_SUPPORT}},
        };
        memcpy(support.rows[0].statement_root, x->anchor_root, 32);
        struct vcs_zcode_science_statement_v1 statement = f->statement[i];
        memcpy(statement.subject_root, x->heuristic_root, 32);
        statement.relation_count = 1;
        statement.relation_types = VCS_ZCODE_SCIENCE_RELATION_MASK(
            VCS_ZCODE_SCIENCE_RELATION_SUPPORT);
        (void)vcs_zcode_science_relation_set_root(
            &support, statement.relations_root);
        memset(statement.signature, 0, sizeof(statement.signature));
        if (vcs_zcode_science_statement_seal(
                &statement, f->secret[i], f->pubkey[i]) !=
                VCS_ZCODE_SCIENCE_OK ||
            !hr_store_statement(workspace, &statement, &support,
                                x->replication_statement_roots[i]))
            HR_EXPERIENCE_FAIL("replication-statement");
    }

    x->lifecycle.schema_version =
        VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_VERSION;
    x->lifecycle.statement_count = 1;
    hr_root(x->lifecycle.local_policy_root, 201);
    memcpy(x->lifecycle.expected_signer, f->evaluator_pubkey, 32);
    memcpy(x->lifecycle.heuristic_root, x->heuristic_root, 32);
    memcpy(x->lifecycle.anchor_statement_root, x->anchor_root, 32);
    memcpy(x->lifecycle.statement_roots[0], x->anchor_root, 32);
    x->replication.schema_version =
        VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_VERSION;
    x->replication.statement_count = 2;
    hr_root(x->replication.local_policy_root, 200);
    memcpy(x->replication.expected_evaluator_signer,
           f->evaluator_pubkey, 32);
    memcpy(x->replication.heuristic_root, x->heuristic_root, 32);
    memcpy(x->replication.anchor_statement_root, x->anchor_root, 32);
    memcpy(x->replication.statement_roots,
           x->replication_statement_roots, 2u * 32u);
    hr_sort(x->replication.statement_roots, 2);

    x->episode = (struct zcl_experience_episode_v1) {
        .workspace = workspace,
        .story = &x->story,
        .task = &f->task,
        .agent_context = &x->context,
        .focus = &x->focus,
        .claim_roots = x->claim_roots,
        .claim_count = 1,
        .work_receipt = &x->receipt,
        .specialist_report = &x->report,
        .heuristic = &x->heuristic,
        .attention_bid = &x->bid,
        .relations = &x->anchor_relations,
        .statement = &x->anchor,
        .local_acceptance = &x->lifecycle,
        .outcome_predicate = &x->predicate,
        .benchmark_action = &f->action,
        .replication_acceptance = &x->replication,
        .observed_at_unix = 6000,
    };
    return true;
#undef HR_EXPERIENCE_FAIL
}

static enum vcs_zcode_attention_error hr_select(
    const char *workspace, const struct hr_fixture *f,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *lifecycle,
    const struct vcs_zcode_heuristic_replication_snapshot_v1 *replication,
    size_t *selected, struct vcs_zcode_attention_qualified_report *report)
{
    return vcs_zcode_attention_frontier_next_verified_with_lifecycle_and_replication(
        workspace, &f->bid, 1, &f->heuristic, NULL, 0, &f->anchor,
        lifecycle, &f->action, replication, &f->focus,
        f->bid.priority_policy_root, lifecycle->local_policy_root,
        replication->local_policy_root, f->bid.bid_evaluator_root,
        f->evaluator_pubkey, 6000, selected, 1, report);
}

static bool hr_report_unchanged(
    const struct vcs_zcode_heuristic_replication_report *report,
    const struct vcs_zcode_heuristic_replication_report *sentinel)
{
    return memcmp(report, sentinel, sizeof(*report)) == 0;
}

int test_zcode_heuristic_replication(void)
{
    int failures = 0;
    char workspace[160];
    int n = snprintf(workspace, sizeof(workspace),
        "test-tmp/zcode_heuristic_replication_%d", (int)getpid());
    test_cleanup_tmpdir(workspace);
    bool setup = n > 0 && (size_t)n < sizeof(workspace) &&
        (mkdir("test-tmp", 0700) == 0 || access("test-tmp", F_OK) == 0) &&
        mkdir(workspace, 0700) == 0 && vcs_object_store_init(workspace);
    HR_CHECK("workspace-initializes", setup);
    if (!setup) return failures + 1;

    struct hr_fixture f;
    bool built = hr_fixture_build(workspace, &f);
    HR_CHECK("signed-science-fixture-builds", built);
    if (!built) {
        test_cleanup_tmpdir(workspace);
        return failures + 1;
    }

    struct vcs_zcode_heuristic_replication_snapshot_v1 snapshot;
    struct vcs_zcode_heuristic_replication_report report, sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    hr_snapshot(&snapshot, &f, NULL, 0);
    HR_CHECK("empty-policy-set-is-complete-below-threshold",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && report.complete && !report.qualified &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD &&
        report.required_reproductions == 2 && report.validated_count == 0);

    const size_t one[] = {0};
    hr_snapshot(&snapshot, &f, one, 1);
    HR_CHECK("threshold-minus-one-remains-undetermined",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD);

    const size_t exact[] = {0, 1};
    hr_snapshot(&snapshot, &f, exact, 2);
    HR_CHECK("exact-distinct-signer-threshold-qualifies-after-expiry",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && report.qualified &&
        report.replicated_count == 2 &&
        report.reason == VCS_ZCODE_HEURISTIC_REPLICATION_REASON_NONE &&
        memcmp(report.study_root, f.study_root, 32) == 0 &&
        memcmp(report.original_result_root, f.original_root, 32) == 0);

    const size_t inconclusive[] = {0, 2};
    hr_snapshot(&snapshot, &f, inconclusive, 2);
    HR_CHECK("inconclusive-is-valid-but-does-not-count",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 1 && report.inconclusive_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_INCONCLUSIVE);

    const size_t contradicted[] = {0, 1, 3};
    hr_snapshot(&snapshot, &f, contradicted, 3);
    HR_CHECK("contradiction-blocks-without-synthetic-retirement",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 2 && report.contradicted_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_CONTRADICTED);

    hr_snapshot(&snapshot, &f, exact, 2);
    memcpy(snapshot.statement_roots[1], snapshot.statement_roots[0], 32);
    report = sentinel;
    HR_CHECK("duplicate-accepted-root-refuses-atomically",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_ORDER && hr_report_unchanged(&report, &sentinel));

    hr_snapshot(&snapshot, &f, exact, 2);
    snapshot.statement_roots[2][0] = 1;
    report = sentinel;
    HR_CHECK("inactive-root-and-output-alias-refuse",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_ROOT && hr_report_unchanged(&report, &sentinel) &&
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000,
            (struct vcs_zcode_heuristic_replication_report *)&snapshot) ==
            VCS_ZCODE_ATTENTION_ALIAS);

    hr_snapshot(&snapshot, &f, exact, 2);
    uint8_t missing[32];
    hr_root(missing, 250);
    memcpy(snapshot.statement_roots[0], missing, 32);
    hr_sort(snapshot.statement_roots, 2);
    report = sentinel;
    HR_CHECK("missing-policy-accepted-evidence-poisons-fold",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture duplicate_signer = f;
    duplicate_signer.statement[1] = f.statement[1];
    memcpy(duplicate_signer.reproduction[1].reproducer_pubkey,
           f.pubkey[0], 32);
    bool replay_built = hr_store_reproduction(
        workspace, &duplicate_signer.reproduction[1],
        duplicate_signer.reproduction_root[1]);
    memcpy(duplicate_signer.statement[1].predicate_body_root,
           duplicate_signer.reproduction_root[1], 32);
    memcpy(duplicate_signer.statement[1].signer_pubkey, f.pubkey[0], 32);
    memset(duplicate_signer.statement[1].signature, 0, 64);
    replay_built = replay_built &&
        vcs_zcode_science_statement_seal(
            &duplicate_signer.statement[1], f.secret[0], f.pubkey[0]) ==
            VCS_ZCODE_SCIENCE_OK;
    struct vcs_zcode_science_relation_set_v1 support = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
        .row_count = 1,
        .rows = {{.type = VCS_ZCODE_SCIENCE_RELATION_SUPPORT}},
    };
    memcpy(support.rows[0].statement_root, f.anchor_root, 32);
    replay_built = replay_built && hr_store_statement(
        workspace, &duplicate_signer.statement[1], &support,
        duplicate_signer.statement_root[1]);
    HR_CHECK("duplicate-signer-fixture-builds", replay_built);
    hr_snapshot(&snapshot, &duplicate_signer, exact, 2);
    report = sentinel;
    HR_CHECK("same-signer-cannot-satisfy-independence",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture self_signed = f;
    self_signed.statement[0] = f.statement[0];
    memcpy(self_signed.reproduction[0].reproducer_pubkey,
           f.evaluator_pubkey, 32);
    bool self_built = hr_store_reproduction(
        workspace, &self_signed.reproduction[0],
        self_signed.reproduction_root[0]);
    memcpy(self_signed.statement[0].predicate_body_root,
           self_signed.reproduction_root[0], 32);
    memcpy(self_signed.statement[0].signer_pubkey, f.evaluator_pubkey, 32);
    memset(self_signed.statement[0].signature, 0, 64);
    self_built = self_built && vcs_zcode_science_statement_seal(
        &self_signed.statement[0], f.evaluator_secret, f.evaluator_pubkey) ==
        VCS_ZCODE_SCIENCE_OK && hr_store_statement(
            workspace, &self_signed.statement[0], &support,
            self_signed.statement_root[0]);
    HR_CHECK("evaluator-reproduction-fixture-builds", self_built);
    hr_snapshot(&snapshot, &self_signed, one, 1);
    report = sentinel;
    HR_CHECK("evaluator-cannot-reproduce-own-result",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture mismatched_key = f;
    mismatched_key.statement[0] = f.statement[0];
    memcpy(mismatched_key.reproduction[0].reproducer_pubkey,
           f.pubkey[1], 32);
    bool mismatch_built = hr_store_reproduction(
        workspace, &mismatched_key.reproduction[0],
        mismatched_key.reproduction_root[0]);
    memcpy(mismatched_key.statement[0].predicate_body_root,
           mismatched_key.reproduction_root[0], 32);
    memset(mismatched_key.statement[0].signature, 0, 64);
    mismatch_built = mismatch_built && vcs_zcode_science_statement_seal(
        &mismatched_key.statement[0], f.secret[0], f.pubkey[0]) ==
        VCS_ZCODE_SCIENCE_OK && hr_store_statement(
            workspace, &mismatched_key.statement[0], &support,
            mismatched_key.statement_root[0]);
    HR_CHECK("declared-key-mismatch-fixture-builds", mismatch_built);
    hr_snapshot(&snapshot, &mismatched_key, one, 1);
    report = sentinel;
    HR_CHECK("signed-envelope-authenticates-declared-reproducer",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture post_hoc_policy = f;
    post_hoc_policy.statement[0] = f.statement[0];
    hr_root(post_hoc_policy.reproduction[0].comparison_policy_root, 251);
    bool post_hoc_policy_built = hr_store_reproduction(
        workspace, &post_hoc_policy.reproduction[0],
        post_hoc_policy.reproduction_root[0]);
    memcpy(post_hoc_policy.statement[0].predicate_body_root,
           post_hoc_policy.reproduction_root[0], 32);
    memcpy(post_hoc_policy.statement[0].activity_root,
           post_hoc_policy.reproduction[0].comparison_policy_root, 32);
    memset(post_hoc_policy.statement[0].signature, 0, 64);
    post_hoc_policy_built = post_hoc_policy_built &&
        vcs_zcode_science_statement_seal(
            &post_hoc_policy.statement[0], f.secret[0], f.pubkey[0]) ==
            VCS_ZCODE_SCIENCE_OK && hr_store_statement(
                workspace, &post_hoc_policy.statement[0], &support,
                post_hoc_policy.statement_root[0]);
    HR_CHECK("post-hoc-comparison-policy-fixture-builds",
             post_hoc_policy_built);
    hr_snapshot(&snapshot, &post_hoc_policy, one, 1);
    report = sentinel;
    HR_CHECK("signed-post-hoc-comparison-policy-refuses-atomically",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    const struct {
        uint8_t status;
        const char *fixture_name;
        const char *refusal_name;
    } ineligible_anchors[] = {
        {VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT,
         "negative-anchor-fixture-builds",
         "negative-anchor-cannot-qualify"},
        {VCS_ZCODE_BENCHMARK_NULL_RESULT,
         "null-anchor-fixture-builds",
         "null-anchor-cannot-qualify"},
        {VCS_ZCODE_BENCHMARK_EXECUTION_FAILED,
         "failed-anchor-fixture-builds",
         "failed-anchor-cannot-qualify"},
    };
    for (size_t i = 0;
         i < sizeof(ineligible_anchors) / sizeof(ineligible_anchors[0]); i++) {
        struct hr_fixture ineligible_anchor = f;
        bool ineligible_anchor_built = hr_rewrite_anchor_status(
            workspace, &ineligible_anchor, ineligible_anchors[i].status);
        HR_CHECK(ineligible_anchors[i].fixture_name,
                 ineligible_anchor_built);
        hr_snapshot(&snapshot, &ineligible_anchor, NULL, 0);
        report = sentinel;
        HR_CHECK(ineligible_anchors[i].refusal_name,
            vcs_zcode_heuristic_replication_fold(
                workspace, &f.heuristic, &f.action, &snapshot, 6000,
                &report) == VCS_ZCODE_ATTENTION_EVIDENCE &&
            hr_report_unchanged(&report, &sentinel));
    }

    const struct {
        uint8_t status;
        uint8_t verdict;
        const char *fixture_name;
        const char *refusal_name;
    } inconsistent_rows[] = {
        {VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT,
         VCS_ZCODE_REPRODUCTION_REPLICATED,
         "negative-replicated-fixture-builds",
         "negative-result-cannot-be-declared-replicated"},
        {VCS_ZCODE_BENCHMARK_NULL_RESULT,
         VCS_ZCODE_REPRODUCTION_REPLICATED,
         "null-replicated-fixture-builds",
         "null-result-cannot-be-declared-replicated"},
        {VCS_ZCODE_BENCHMARK_EXECUTION_FAILED,
         VCS_ZCODE_REPRODUCTION_REPLICATED,
         "failed-replicated-fixture-builds",
         "failed-result-cannot-be-declared-replicated"},
        {VCS_ZCODE_BENCHMARK_NULL_RESULT,
         VCS_ZCODE_REPRODUCTION_CONTRADICTED,
         "null-contradicted-fixture-builds",
         "null-result-cannot-be-declared-contradicted"},
        {VCS_ZCODE_BENCHMARK_EXECUTION_FAILED,
         VCS_ZCODE_REPRODUCTION_CONTRADICTED,
         "failed-contradicted-fixture-builds",
         "failed-result-cannot-be-declared-contradicted"},
    };
    for (size_t i = 0;
         i < sizeof(inconsistent_rows) / sizeof(inconsistent_rows[0]); i++) {
        struct hr_fixture inconsistent = f;
        bool inconsistent_built = hr_rewrite_reproduced_status(
            workspace, &inconsistent, 0, inconsistent_rows[i].status,
            inconsistent_rows[i].verdict);
        HR_CHECK(inconsistent_rows[i].fixture_name, inconsistent_built);
        hr_snapshot(&snapshot, &inconsistent, one, 1);
        report = sentinel;
        HR_CHECK(inconsistent_rows[i].refusal_name,
            vcs_zcode_heuristic_replication_fold(
                workspace, &f.heuristic, &f.action, &snapshot, 6000,
                &report) == VCS_ZCODE_ATTENTION_EVIDENCE &&
            hr_report_unchanged(&report, &sentinel));
    }

    struct hr_fixture negative_contradiction = f;
    bool negative_contradiction_built = hr_rewrite_reproduced_status(
        workspace, &negative_contradiction, 1,
        VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT,
        VCS_ZCODE_REPRODUCTION_CONTRADICTED);
    HR_CHECK("negative-contradiction-fixture-builds",
             negative_contradiction_built);
    hr_snapshot(&snapshot, &negative_contradiction, exact, 2);
    HR_CHECK("negative-result-is-an-honest-contradiction",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 1 && report.contradicted_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_CONTRADICTED);

    struct hr_fixture replayed_result = f;
    replayed_result.statement[1] = f.statement[1];
    memcpy(replayed_result.reproduction[1].reproduced_result_root,
           f.reproduced_root[0], 32);
    memcpy(replayed_result.reproduction[1].reproduced_environment_root,
           f.reproduced[0].achieved_environment_root, 32);
    bool result_replay_built = hr_store_reproduction(
        workspace, &replayed_result.reproduction[1],
        replayed_result.reproduction_root[1]);
    memcpy(replayed_result.statement[1].predicate_body_root,
           replayed_result.reproduction_root[1], 32);
    memcpy(replayed_result.statement[1].provenance_root,
           f.reproduced_root[0], 32);
    memset(replayed_result.statement[1].signature, 0, 64);
    result_replay_built = result_replay_built &&
        vcs_zcode_science_statement_seal(
            &replayed_result.statement[1], f.secret[1], f.pubkey[1]) ==
            VCS_ZCODE_SCIENCE_OK && hr_store_statement(
                workspace, &replayed_result.statement[1], &support,
                replayed_result.statement_root[1]);
    HR_CHECK("replayed-result-fixture-builds", result_replay_built);
    hr_snapshot(&snapshot, &replayed_result, exact, 2);
    report = sentinel;
    HR_CHECK("one-result-cannot-be-counted-by-two-signers",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture pre_study = f;
    pre_study.original.started_unix = 900;
    bool pre_study_built = hr_store_result(
        workspace, &pre_study.original, pre_study.original_root);
    struct vcs_zcode_science_relation_set_v1 empty = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    pre_study.anchor = f.anchor;
    memcpy(pre_study.anchor.provenance_root, pre_study.original_root, 32);
    memset(pre_study.anchor.signature, 0, 64);
    pre_study_built = pre_study_built &&
        vcs_zcode_science_statement_seal(
            &pre_study.anchor, f.evaluator_secret, f.evaluator_pubkey) ==
            VCS_ZCODE_SCIENCE_OK && hr_store_statement(
                workspace, &pre_study.anchor, &empty, pre_study.anchor_root);
    HR_CHECK("pre-study-result-fixture-builds", pre_study_built);
    hr_snapshot(&snapshot, &pre_study, NULL, 0);
    report = sentinel;
    HR_CHECK("pre-study-benchmark-cannot-qualify",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct vcs_build_action_v1 noncanonical_action = f.action;
    noncanonical_action.flags_sha3[0] ^= 1u;
    hr_snapshot(&snapshot, &f, NULL, 0);
    report = sentinel;
    HR_CHECK("noncanonical-action-cannot-qualify",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &noncanonical_action,
            &snapshot, 6000, &report) == VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    hr_snapshot(&snapshot, &f, one, 1);
    report = sentinel;
    HR_CHECK("future-cutoff-refuses-atomically",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 1499, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 lifecycle;
    struct vcs_zcode_attention_qualified_report qualified, qualified_before;
    size_t selected = SIZE_MAX;
    hr_lifecycle_snapshot(&lifecycle, &f);
    hr_snapshot(&snapshot, &f, exact, 2);
    HR_CHECK("retained-and-replicated-enters-attention-frontier",
        hr_select(workspace, &f, &lifecycle, &snapshot, &selected,
                  &qualified) == VCS_ZCODE_ATTENTION_OK && selected == 0 &&
        qualified.verified_count == 1 && qualified.retained_count == 1 &&
        qualified.qualified_count == 1 &&
        qualified.choice.frontier.input_count == 1);

    hr_snapshot(&snapshot, &f, one, 1);
    selected = SIZE_MAX;
    HR_CHECK("retained-below-threshold-is-ineligible-not-retired",
        hr_select(workspace, &f, &lifecycle, &snapshot, &selected,
                  &qualified) == VCS_ZCODE_ATTENTION_OK &&
        selected == SIZE_MAX &&
        qualified.retained_count == 1 && qualified.qualified_count == 0 &&
        qualified.retained_unqualified_count == 1 &&
        qualified.retired_count == 0);

    hr_snapshot(&snapshot, &f, contradicted, 3);
    selected = SIZE_MAX;
    HR_CHECK("contradiction-blocks-attention-without-retirement",
        hr_select(workspace, &f, &lifecycle, &snapshot, &selected,
                  &qualified) == VCS_ZCODE_ATTENTION_OK &&
        selected == SIZE_MAX &&
        qualified.retained_unqualified_count == 1 &&
        qualified.retired_count == 0);

    struct vcs_zcode_science_relation_set_v1 retract_relations = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
        .row_count = 1,
        .rows = {{.type = VCS_ZCODE_SCIENCE_RELATION_RETRACTION}},
    };
    memcpy(retract_relations.rows[0].statement_root, f.anchor_root, 32);
    struct vcs_zcode_science_statement_v1 retraction = f.anchor;
    retraction.profile = VCS_ZCODE_SCIENCE_PROFILE_RETRACTION;
    retraction.relation_count = 1;
    retraction.relation_types = VCS_ZCODE_SCIENCE_RELATION_MASK(
        VCS_ZCODE_SCIENCE_RELATION_RETRACTION);
    (void)vcs_zcode_science_relation_set_root(
        &retract_relations, retraction.relations_root);
    retraction.observed_unix = 1600;
    memset(retraction.signature, 0, sizeof(retraction.signature));
    uint8_t retraction_root[32];
    bool retraction_built = vcs_zcode_science_statement_seal(
            &retraction, f.evaluator_secret, f.evaluator_pubkey) ==
            VCS_ZCODE_SCIENCE_OK &&
        hr_store_statement(workspace, &retraction, &retract_relations,
                           retraction_root);
    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 retired = lifecycle;
    retired.statement_count = 2;
    memcpy(retired.statement_roots[1], retraction_root, 32);
    hr_sort(retired.statement_roots, 2);
    hr_snapshot(&snapshot, &f, exact, 2);
    selected = SIZE_MAX;
    HR_CHECK("qualified-retracted-row-remains-ineligible",
        retraction_built &&
        hr_select(workspace, &f, &retired, &snapshot, &selected,
                  &qualified) == VCS_ZCODE_ATTENTION_OK &&
        selected == SIZE_MAX && qualified.retained_count == 0 &&
        qualified.qualified_count == 0 && qualified.retired_count == 1);
    memcpy(snapshot.statement_roots[0], missing, 32);
    hr_sort(snapshot.statement_roots, 2);
    memset(&qualified, 0x7b, sizeof(qualified));
    qualified_before = qualified;
    HR_CHECK("malformed-replication-in-retired-row-poisons-batch",
        hr_select(workspace, &f, &retired, &snapshot, &selected,
                  &qualified) == VCS_ZCODE_ATTENTION_EVIDENCE &&
        memcmp(&qualified, &qualified_before, sizeof(qualified)) == 0);

    struct vcs_zcode_attention_bid_v1 generation_bids[2] = {f.bid, f.bid};
    struct vcs_zcode_heuristic_v1 generation_heuristics[2] = {
        f.heuristic, f.heuristic
    };
    struct vcs_zcode_science_statement_v1 generation_anchors[2] = {
        f.anchor, f.anchor
    };
    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 generation_lifecycle[2];
    struct vcs_build_action_v1 generation_actions[2] = {f.action, f.action};
    struct vcs_zcode_heuristic_replication_snapshot_v1 generation_replication[2];
    generation_bids[1].expected_user_value_bp++;
    (void)vcs_zcode_attention_bid_root(
        &generation_bids[1], generation_anchors[1].predicate_body_root);
    memset(generation_anchors[1].signature, 0,
           sizeof(generation_anchors[1].signature));
    struct vcs_zcode_science_relation_set_v1 no_relations = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    bool generation_built = vcs_zcode_science_statement_seal(
            &generation_anchors[1], f.evaluator_secret,
            f.evaluator_pubkey) == VCS_ZCODE_SCIENCE_OK;
    uint8_t second_anchor_root[32];
    generation_built = generation_built && hr_store_statement(
        workspace, &generation_anchors[1], &no_relations,
        second_anchor_root);
    hr_lifecycle_snapshot(&generation_lifecycle[0], &f);
    generation_lifecycle[1] = generation_lifecycle[0];
    memcpy(generation_lifecycle[1].anchor_statement_root,
           second_anchor_root, 32);
    memcpy(generation_lifecycle[1].statement_roots[0],
           second_anchor_root, 32);
    hr_snapshot(&generation_replication[0], &f, exact, 2);
    hr_snapshot(&generation_replication[1], &f, NULL, 0);
    memcpy(generation_replication[1].anchor_statement_root,
           second_anchor_root, 32);
    memset(&qualified, 0x7b, sizeof(qualified));
    qualified_before = qualified;
    selected = SIZE_MAX;
    HR_CHECK("unqualified-generation-cannot-hide-retained-duplicate",
        generation_built &&
        vcs_zcode_attention_frontier_next_verified_with_lifecycle_and_replication(
            workspace, generation_bids, 2, generation_heuristics, NULL, 0,
            generation_anchors, generation_lifecycle, generation_actions,
            generation_replication, &f.focus, f.bid.priority_policy_root,
            lifecycle.local_policy_root, snapshot.local_policy_root,
            f.bid.bid_evaluator_root, f.evaluator_pubkey, 6000,
            &selected, 1, &qualified) == VCS_ZCODE_ATTENTION_DUPLICATE &&
        selected == SIZE_MAX &&
        memcmp(&qualified, &qualified_before, sizeof(qualified)) == 0);

    hr_snapshot(&snapshot, &f, exact, 2);
    memcpy(snapshot.statement_roots[0], missing, 32);
    hr_sort(snapshot.statement_roots, 2);
    memset(&qualified, 0x7b, sizeof(qualified));
    qualified_before = qualified;
    selected = SIZE_MAX;
    HR_CHECK("malformed-accepted-replication-poisons-attention-atomically",
        hr_select(workspace, &f, &lifecycle, &snapshot, &selected,
                  &qualified) == VCS_ZCODE_ATTENTION_EVIDENCE &&
        selected == SIZE_MAX &&
        memcmp(&qualified, &qualified_before, sizeof(qualified)) == 0);

    struct hr_experience_fixture experience;
    struct zcl_experience_compilation_v1 compiled;
    bool experience_built = hr_experience_build(
        workspace, &f, &experience);
    struct vcs_zcode_heuristic_replication_report experience_replication;
    HR_CHECK("experience-compiler-returns-only-replicated-predicate-lesson",
        experience_built && vcs_zcode_heuristic_replication_fold(
            workspace, &experience.heuristic, &f.action,
            &experience.replication, 6000, &experience_replication) ==
                VCS_ZCODE_ATTENTION_OK &&
        zcl_experience_compile(
            &experience.episode, &compiled) ==
                ZCL_EXPERIENCE_COMPILATION_OK &&
        compiled.captured && compiled.lesson_relevant &&
        compiled.replication_qualified &&
        compiled.replication_reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_NONE &&
        compiled.replicated_count == 2 &&
        compiled.required_reproductions == 2 &&
        memcmp(compiled.outcome_predicate_root,
               experience.claim_roots[0], 32) == 0 &&
        memcmp(compiled.benchmark_action_root,
               experience.story_event.action_root, 32) == 0 &&
        memcmp(compiled.study_root, f.study_root, 32) == 0 &&
        memcmp(compiled.original_result_root, f.original_root, 32) == 0 &&
        memcmp(compiled.replication_snapshot_root,
               experience_replication.snapshot_root, 32) == 0);

    struct zcl_experience_compilation_v1 zero_compilation = {0};
    struct vcs_zcode_heuristic_replication_snapshot_v1 below =
        experience.replication;
    below.statement_count = 1;
    memset(below.statement_roots[1], 0, 32);
    struct zcl_experience_episode_v1 below_episode = experience.episode;
    below_episode.replication_acceptance = &below;
    struct zcl_experience_compilation_v1 below_compilation;
    HR_CHECK("experience-below-replication-threshold-captures-no-lesson",
        zcl_experience_compile(&below_episode, &below_compilation) ==
            ZCL_EXPERIENCE_COMPILATION_OK &&
        below_compilation.captured && !below_compilation.lesson_relevant &&
        !below_compilation.replication_qualified &&
        below_compilation.replication_reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD &&
        below_compilation.replicated_count == 1 &&
        below_compilation.required_reproductions == 2 &&
        memcmp(below_compilation.derived_rule_root,
               zero_compilation.derived_rule_root, 32) == 0);

    struct vcs_zcode_heuristic_replication_snapshot_v1
        contradicted_experience =
        experience.replication;
    memcpy(contradicted_experience.statement_roots[0],
           experience.replication_statement_roots[0], 32);
    memcpy(contradicted_experience.statement_roots[1],
           experience.replication_statement_roots[3], 32);
    hr_sort(contradicted_experience.statement_roots, 2);
    struct zcl_experience_episode_v1 contradicted_episode =
        experience.episode;
    contradicted_episode.replication_acceptance =
        &contradicted_experience;
    struct zcl_experience_compilation_v1 contradicted_compilation;
    HR_CHECK("experience-contradiction-captures-but-never-grants-lesson",
        zcl_experience_compile(
            &contradicted_episode, &contradicted_compilation) ==
                ZCL_EXPERIENCE_COMPILATION_OK &&
        contradicted_compilation.captured &&
        !contradicted_compilation.lesson_relevant &&
        !contradicted_compilation.replication_qualified &&
        contradicted_compilation.replication_reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_CONTRADICTED &&
        contradicted_compilation.replicated_count == 1);

    bool predicate_mutations_refused = true;
    for (size_t i = 0; i < 32; i++) {
        struct zcl_ontology_predicate_v1 predicate = experience.predicate;
        predicate.term_root[i] ^= (uint8_t)(i + 1u);
        struct zcl_experience_episode_v1 episode = experience.episode;
        episode.outcome_predicate = &predicate;
        struct zcl_experience_compilation_v1 refused;
        memset(&refused, 0x5a, sizeof(refused));
        predicate_mutations_refused = predicate_mutations_refused &&
            zcl_experience_compile(&episode, &refused) ==
                ZCL_EXPERIENCE_COMPILATION_REPORT &&
            memcmp(&refused, &zero_compilation, sizeof(refused)) == 0;
    }
    HR_CHECK("experience-predicate-byte-mutation-property-refuses-all",
             predicate_mutations_refused);

    struct vcs_build_action_v1 wrong_action = f.action;
    wrong_action.source_sha256[0] ^= 1u;
    struct zcl_experience_episode_v1 wrong_action_episode =
        experience.episode;
    wrong_action_episode.benchmark_action = &wrong_action;
    struct zcl_experience_compilation_v1 refused_compilation;
    memset(&refused_compilation, 0x5a, sizeof(refused_compilation));
    HR_CHECK("experience-wrong-benchmark-generation-refuses-atomically",
        zcl_experience_compile(
            &wrong_action_episode, &refused_compilation) ==
                ZCL_EXPERIENCE_COMPILATION_REPLICATION &&
        memcmp(&refused_compilation, &zero_compilation,
               sizeof(refused_compilation)) == 0);

    struct vcs_zcode_attention_bid_v1 wrong_evidence_bid = experience.bid;
    wrong_evidence_bid.evidence_root[0] ^= 1u;
    struct zcl_experience_episode_v1 wrong_evidence_episode =
        experience.episode;
    wrong_evidence_episode.attention_bid = &wrong_evidence_bid;
    memset(&refused_compilation, 0x5a, sizeof(refused_compilation));
    HR_CHECK("experience-stale-original-result-bid-refuses-atomically",
        zcl_experience_compile(
            &wrong_evidence_episode, &refused_compilation) ==
                ZCL_EXPERIENCE_COMPILATION_REPLICATION &&
        memcmp(&refused_compilation, &zero_compilation,
               sizeof(refused_compilation)) == 0);

    struct zcl_experience_episode_v1 stale_cutoff_episode =
        experience.episode;
    stale_cutoff_episode.observed_at_unix = 1400;
    memset(&refused_compilation, 0x5a, sizeof(refused_compilation));
    HR_CHECK("experience-future-reproduction-at-stale-cutoff-refuses",
        zcl_experience_compile(
            &stale_cutoff_episode, &refused_compilation) ==
                ZCL_EXPERIENCE_COMPILATION_REPLICATION &&
        memcmp(&refused_compilation, &zero_compilation,
               sizeof(refused_compilation)) == 0);

    struct vcs_zcode_heuristic_replication_snapshot_v1 wrong_replication =
        experience.replication;
    wrong_replication.statement_roots[0][0] ^= 1u;
    struct zcl_experience_episode_v1 wrong_replication_episode =
        experience.episode;
    wrong_replication_episode.replication_acceptance = &wrong_replication;
    memset(&refused_compilation, 0x5a, sizeof(refused_compilation));
    HR_CHECK("experience-missing-accepted-reproduction-refuses-atomically",
        zcl_experience_compile(
            &wrong_replication_episode, &refused_compilation) ==
                ZCL_EXPERIENCE_COMPILATION_REPLICATION &&
        memcmp(&refused_compilation, &zero_compilation,
               sizeof(refused_compilation)) == 0);

    struct zcl_experience_episode_v1 incomplete_episode = experience.episode;
    incomplete_episode.outcome_predicate = NULL;
    memset(&refused_compilation, 0x5a, sizeof(refused_compilation));
    HR_CHECK("experience-partial-scientific-bundle-fails-closed",
        zcl_experience_compile(&incomplete_episode, &refused_compilation) ==
            ZCL_EXPERIENCE_COMPILATION_NULL &&
        memcmp(&refused_compilation, &zero_compilation,
               sizeof(refused_compilation)) == 0);

    union {
        struct zcl_ontology_predicate_v1 predicate;
        struct zcl_experience_compilation_v1 output;
    } optional_alias;
    optional_alias.predicate = experience.predicate;
    struct zcl_ontology_predicate_v1 optional_alias_before =
        optional_alias.predicate;
    struct zcl_experience_episode_v1 optional_alias_episode =
        experience.episode;
    optional_alias_episode.outcome_predicate = &optional_alias.predicate;
    HR_CHECK("experience-optional-evidence-alias-refuses-without-write",
        zcl_experience_compile(
            &optional_alias_episode, &optional_alias.output) ==
                ZCL_EXPERIENCE_COMPILATION_ALIAS &&
        memcmp(&optional_alias.predicate, &optional_alias_before,
               sizeof(optional_alias_before)) == 0);

    char experience_replica[192];
    int experience_replica_n = snprintf(
        experience_replica, sizeof(experience_replica), "%s.experience",
        workspace);
    test_cleanup_tmpdir(experience_replica);
    struct hr_fixture replica_fixture;
    struct hr_experience_fixture replica_experience;
    struct zcl_experience_compilation_v1 replica_compiled;
    bool experience_reproduced = experience_replica_n > 0 &&
        (size_t)experience_replica_n < sizeof(experience_replica) &&
        mkdir(experience_replica, 0700) == 0 &&
        vcs_object_store_init(experience_replica) &&
        hr_fixture_build(experience_replica, &replica_fixture) &&
        hr_experience_build(
            experience_replica, &replica_fixture, &replica_experience) &&
        zcl_experience_compile(&replica_experience.episode,
                               &replica_compiled) ==
            ZCL_EXPERIENCE_COMPILATION_OK &&
        replica_compiled.lesson_relevant &&
        memcmp(&replica_compiled, &compiled, sizeof(compiled)) == 0;
    HR_CHECK("experience-independent-workspace-reproduces-exact-view",
             experience_reproduced);
    test_cleanup_tmpdir(experience_replica);

    memset(&qualified, 0x7b, sizeof(qualified));
    HR_CHECK("empty-scientific-frontier-has-exact-zero-counts",
        vcs_zcode_attention_frontier_next_verified_with_lifecycle_and_replication(
            workspace, NULL, 0, NULL, NULL, 0, NULL, NULL, NULL, NULL,
            &f.focus, f.bid.priority_policy_root,
            lifecycle.local_policy_root, snapshot.local_policy_root,
            f.bid.bid_evaluator_root, f.evaluator_pubkey, 6000,
            NULL, 0, &qualified) == VCS_ZCODE_ATTENTION_OK &&
        qualified.verified_count == 0 && qualified.retained_count == 0 &&
        qualified.qualified_count == 0 &&
        qualified.retained_unqualified_count == 0 &&
        qualified.retired_count == 0 &&
        qualified.choice.frontier.input_count == 0);

    test_cleanup_tmpdir(workspace);
    return failures;
}
