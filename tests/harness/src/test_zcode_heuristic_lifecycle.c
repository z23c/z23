/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: accepted-root heuristic lifecycle state-machine adversarial tests. */
#include "vcs/zcode_heuristic_lifecycle.h"

#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "ontology/story_graph.h"
#include "test/test_core.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_attention_verified.h"
#include "vcs/zcode_science.h"
#include "vcs/zcode_write_scope.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HL_CHECK(name_, expression_) do {                              \
    if (expression_) {                                                 \
        printf("  zcode_heuristic_lifecycle: %s... OK\n", (name_)); \
    } else {                                                           \
        printf("  zcode_heuristic_lifecycle: %s... FAIL\n", (name_)); \
        failures++;                                                    \
    }                                                                  \
} while (0)

static void hlt_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static bool hlt_hex_root(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) != 64u) return false;
    for (size_t i = 0; i < 32u; i++) {
        unsigned value = 0;
        for (size_t nibble = 0; nibble < 2u; nibble++) {
            unsigned char ch = (unsigned char)hex[i * 2u + nibble];
            unsigned digit = ch >= '0' && ch <= '9' ?
                (unsigned)(ch - (unsigned char)'0') :
                ch >= 'a' && ch <= 'f' ?
                (unsigned)(ch - (unsigned char)'a') + 10u : 16u;
            if (digit > 15u) return false;
            value = value * 16u + digit;
        }
        out[i] = (uint8_t)value;
    }
    return true;
}

static bool hlt_blob_exact(const char *workspace, const char *bytes,
                           const char *expected_hex, uint8_t out[32])
{
    uint8_t expected[32];
    if (!hlt_hex_root(expected_hex, expected) ||
        !vcs_object_put(workspace, (const uint8_t *)bytes, strlen(bytes),
                        VCS_TAG_BLOB, out))
        return false;
    if (memcmp(out, expected, 32) == 0) return true;
    printf("  zcode_heuristic_lifecycle: expected blob %s, got ",
           expected_hex);
    for (size_t i = 0; i < 32u; i++) printf("%02x", out[i]);
    printf("\n");
    return false;
}

static bool hlt_experience_focus(
    struct vcs_zcode_task_v1 *task, struct vcs_zcode_focus_v1 *focus,
    uint8_t task_root[32], uint8_t focus_root[32])
{
    static uint8_t context_bytes[] =
        "experience compilation: exact observable Grok CLI session metadata; "
        "private chain-of-thought discarded; focused acceptance engine";
    struct vcs_zcode_write_scope_v1 scope;
    vcs_zcode_write_scope_init(&scope);
    if (vcs_zcode_write_scope_add(&scope, "engine/modules/engine") !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_add(&scope, "tools/engine_unit.c") !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_add(&scope,
            "tests/harness/src/test_engine.c") != VCS_ZCODE_WRITE_SCOPE_OK)
        return false;

    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    if (!hlt_hex_root(
            "4fa5bc68fc1e4c48c8bcbee09781dc2ade5fdabfa011bc05e10b57e37dfa1d12",
            task->source_root) ||
        !hlt_hex_root(
            "e2178d444c161e2154742f3fd8c597910d30c5351446e197c5ea2e073033a2ee",
            task->toolchain_capsule_root) ||
        !hlt_hex_root(
            "316603c5716adff0a71f5a4610ad430e3d576db35f18bb7924da1c2cb9cdf04c",
            task->goal_root) ||
        vcs_zcode_write_scope_root(&scope, task->write_scope_root) !=
            VCS_ZCODE_WRITE_SCOPE_OK)
        return false;
    sha3_256((const uint8_t *)"z23 dependency lock: current main", 33u,
             task->dependency_lock_root);
    sha3_256((const uint8_t *)"make t-fast-exact ONLY=engine", 29u,
             task->acceptance_tests_root);
    sha3_256((const uint8_t *)
             "exact gate decides; malformed metadata refuses", 45u,
             task->proof_policy_root);
    memcpy(task->model_policy_root, task->toolchain_capsule_root, 32u);
    task->capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                         VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    task->max_changed_files = 8u;
    task->max_patch_bytes = UINT64_C(131072);
    task->max_context_bytes = UINT64_C(32768);
    task->max_cpu_seconds = 1800u;
    task->max_memory_bytes = UINT64_C(4) * 1024u * 1024u * 1024u;
    task->max_output_bytes = UINT64_C(64) * 1024u * 1024u;
    task->expires_unix = INT64_C(2000000000);
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK)
        return false;

    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    memcpy(context.task_root, task_root, 32u);
    memcpy(context.source_root, task->source_root, 32u);
    memcpy(context.goal_root, task->goal_root, 32u);
    memcpy(context.source_tree_root, task->source_root, 32u);
    strcpy(context.query,
           "capture observable Grok CLI metadata without thought");
    context.file_count = 1u;
    strcpy(context.files[0].path, "tools/engine_unit.c");
    context.files[0].start_line = 1u;
    context.files[0].full_file_bytes = sizeof(context_bytes) - 1u;
    context.files[0].content = context_bytes;
    context.files[0].content_len = sizeof(context_bytes) - 1u;
    sha3_256(context_bytes, sizeof(context_bytes) - 1u,
             context.files[0].content_root);
    uint8_t context_root[32];
    if (vcs_zcode_agent_context_root(&context, task->max_context_bytes,
                                     context_root) !=
            VCS_ZCODE_AGENT_CONTEXT_OK)
        return false;

    struct zcl_story_event_v1 event;
    memset(&event, 0, sizeof(event));
    event.schema_version = ZCL_STORY_GRAPH_VERSION;
    event.kind = ZCL_STORY_EVENT_USER_ASKS;
    event.status = ZCL_ONTOLOGY_PROVED;
    memcpy(event.universe_root, task->source_root, 32u);
    memcpy(event.context_root, context_root, 32u);
    memcpy(event.scene_root, task_root, 32u);
    memcpy(event.entity_root, task->model_policy_root, 32u);
    memcpy(event.action_root, task->goal_root, 32u);
    sha3_256((const uint8_t *)"experience compilation episode request", 38u,
             event.event_root);
    memcpy(event.evidence_root, task->source_root, 32u);
    struct zcl_story_graph_v1 graph = {
        .schema_version = ZCL_STORY_GRAPH_VERSION,
        .event_count = 1u,
        .events = &event,
    };
    uint8_t story_root[32];
    return zcl_story_graph_v1_root(&graph, story_root) &&
        vcs_zcode_focus_compose(task, task_root, context_root, story_root,
            ZCL_ONTOLOGY_PROVED, 0u, NULL, 0u, focus) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_root(focus, focus_root) == VCS_ZCODE_FOCUS_OK;
}

static bool hlt_store(
    const char *workspace,
    const struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t statement_root[32])
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
        vcs_zcode_science_statement_serialize(statement, statement_wire) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(statement, statement_root) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_object_put_addressed(workspace, relation_root, relation_wire,
                                 relation_len) &&
        vcs_object_put_addressed(workspace, statement_root, statement_wire,
                                 sizeof(statement_wire));
}

static bool hlt_report_store(
    const char *workspace, const struct vcs_zcode_specialist_report_v1 *report,
    uint8_t report_root[32])
{
    uint8_t wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
    struct vcs_zcode_specialist_report_v1 parsed;
    uint8_t checked[32];
    return vcs_zcode_specialist_report_serialize(report, wire) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_specialist_report_root(report, report_root) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_object_put_addressed(workspace, report_root, wire, sizeof(wire)) &&
        vcs_zcode_specialist_report_parse(wire, sizeof(wire), &parsed) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_specialist_report_root(&parsed, checked) ==
            VCS_ZCODE_FOCUS_OK &&
        memcmp(checked, report_root, 32) == 0;
}

static void hlt_report_init(
    struct vcs_zcode_specialist_report_v1 *report,
    const uint8_t focus_root[32], const uint8_t claim_root[32],
    const uint8_t specialist_root[32], const uint8_t evidence_root[32],
    const uint8_t result_root[32], const uint8_t next_root[32],
    const uint8_t evaluator_root[32], uint8_t status,
    uint64_t context_bytes, uint64_t latency_us, uint32_t files_opened,
    uint32_t tool_calls, uint32_t proof_reuse_count)
{
    memset(report, 0, sizeof(*report));
    report->schema_version = VCS_ZCODE_FOCUS_VERSION;
    report->role = VCS_ZCODE_SPECIALIST_CODE;
    report->status = status;
    report->context_bytes = context_bytes;
    report->latency_us = latency_us;
    report->files_opened = files_opened;
    report->tool_calls = tool_calls;
    report->proof_reuse_count = proof_reuse_count;
    memcpy(report->focus_root, focus_root, 32);
    memcpy(report->claim_root, claim_root, 32);
    memcpy(report->specialist_root, specialist_root, 32);
    memcpy(report->evidence_root, evidence_root, 32);
    memcpy(report->result_root, result_root, 32);
    memcpy(report->next_experiment_root, next_root, 32);
    memcpy(report->evaluator_root, evaluator_root, 32);
}

static void hlt_heuristic_init(
    struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t applicability_root[32],
    const uint8_t observed_root[32], const uint8_t rule_root[32],
    const uint8_t expected_root[32], const uint8_t proposal_root[32],
    const uint8_t provenance_root[32], const uint8_t evaluator_root[32])
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 1u;
    memcpy(heuristic->task_root, focus->task_root, 32);
    memcpy(heuristic->source_root, focus->source_universe_root, 32);
    memcpy(heuristic->agent_context_root, focus->context_root, 32);
    memcpy(heuristic->ontology_context_root, focus->story_graph_root, 32);
    memcpy(heuristic->applicability_root, applicability_root, 32);
    memcpy(heuristic->observed_features_root, observed_root, 32);
    memcpy(heuristic->proposed_rule_root, rule_root, 32);
    memcpy(heuristic->expected_effect_root, expected_root, 32);
    memcpy(heuristic->proposal_input_root, proposal_root, 32);
    memcpy(heuristic->study_root, focus->goal_root, 32);
    memcpy(heuristic->preregistration_root, focus->required_evidence_root, 32);
    memcpy(heuristic->provenance_root, provenance_root, 32);
    memcpy(heuristic->evaluator_roots[0], evaluator_root, 32);
    heuristic->requested_cpu_seconds = 1800u;
    heuristic->requested_processes = 32u;
    heuristic->requested_memory_bytes = UINT64_C(4) * 1024u * 1024u * 1024u;
    heuristic->requested_context_bytes = UINT64_C(32768);
    heuristic->requested_output_bytes = UINT64_C(64) * 1024u * 1024u;
}

static bool hlt_bid_init(
    struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t policy_root[32], const uint8_t evaluator_root[32],
    const uint8_t evidence_root[32], uint16_t evidence_strength)
{
    vcs_zcode_attention_bid_init(bid);
    bid->priority_class = VCS_ZCODE_ATTENTION_P2_PRODUCTIVITY;
    if (vcs_zcode_focus_root(focus, bid->focus_root) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_heuristic_root(heuristic, bid->heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK)
        return false;
    memcpy(bid->task_root, focus->task_root, 32);
    memcpy(bid->source_root, focus->source_universe_root, 32);
    memcpy(bid->priority_policy_root, policy_root, 32);
    memcpy(bid->bid_evaluator_root, evaluator_root, 32);
    memcpy(bid->evidence_root, evidence_root, 32);
    bid->expected_user_value_bp = 8000u;
    bid->information_gain_bp = 9000u;
    bid->blocker_relief_bp = 5000u;
    bid->reuse_potential_bp = 9000u;
    bid->evidence_strength_bp = evidence_strength;
    bid->risk_bp = 1000u;
    bid->overlap_bp = 500u;
    bid->observed_metrics = VCS_ZCODE_ATTENTION_METRIC_REQUIRED;
    bid->expected_latency_us = UINT64_C(120578583);
    bid->expected_cost_milliunits = 25u;
    return vcs_zcode_attention_bid_validate(bid) == VCS_ZCODE_ATTENTION_OK;
}

static bool hlt_bound_result(
    struct vcs_zcode_science_statement_v1 *statement,
    struct vcs_zcode_science_relation_set_v1 *relations,
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_focus_v1 *focus,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    memset(statement, 0, sizeof(*statement));
    memset(relations, 0, sizeof(*relations));
    relations->schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION;
    statement->schema_version = VCS_ZCODE_SCIENCE_STATEMENT_VERSION;
    statement->profile = VCS_ZCODE_SCIENCE_PROFILE_RESULT;
    statement->access = VCS_ZCODE_SCIENCE_ACCESS_PUBLIC;
    statement->privacy = VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC;
    statement->redistribution =
        VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED;
    statement->authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED;
    if (vcs_zcode_heuristic_root(heuristic, statement->subject_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_attention_bid_root(bid, statement->predicate_body_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_focus_root(focus, statement->input_root) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_science_relation_set_root(
            relations, statement->relations_root) != VCS_ZCODE_SCIENCE_OK)
        return false;
    memcpy(statement->provenance_root, bid->evidence_root, 32);
    memcpy(statement->activity_root, bid->bid_evaluator_root, 32);
    hlt_root(statement->profile_schema_root, 201u);
    hlt_root(statement->authorship_assertion_root, 202u);
    hlt_root(statement->license_root, 203u);
    hlt_root(statement->access_policy_root, 204u);
    hlt_root(statement->privacy_policy_root, 205u);
    hlt_root(statement->external_identifiers_root, 206u);
    hlt_root(statement->citations_root, 207u);
    statement->observed_unix = 1;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
        VCS_ZCODE_SCIENCE_OK;
}

static bool hlt_transition(
    struct vcs_zcode_science_statement_v1 *statement,
    struct vcs_zcode_science_relation_set_v1 *relations,
    const struct vcs_zcode_science_statement_v1 *anchor,
    const uint8_t predecessor_root[32], uint8_t profile,
    uint8_t relation_type, const uint8_t provenance_root[32],
    int64_t observed_unix, const uint8_t secret[32], const uint8_t pubkey[32])
{
    *statement = *anchor;
    memset(statement->signer_pubkey, 0, sizeof(statement->signer_pubkey));
    memset(statement->signature, 0, sizeof(statement->signature));
    memset(relations, 0, sizeof(*relations));
    relations->schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION;
    relations->row_count = 1u;
    relations->rows[0].type = relation_type;
    memcpy(relations->rows[0].statement_root, predecessor_root, 32);
    statement->profile = profile;
    statement->relation_count = 1u;
    statement->relation_types = VCS_ZCODE_SCIENCE_RELATION_MASK(relation_type);
    memcpy(statement->provenance_root, provenance_root, 32);
    if (vcs_zcode_science_relation_set_root(
            relations, statement->relations_root) != VCS_ZCODE_SCIENCE_OK)
        return false;
    statement->observed_unix = observed_unix;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
        VCS_ZCODE_SCIENCE_OK;
}

static enum vcs_zcode_attention_error hlt_select_retained(
    const char *workspace,
    const struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    const struct vcs_zcode_attention_bid_v1 *bid,
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_heuristic_v1 *parent,
    const struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_focus_v1 *focus, const uint8_t signer[32])
{
    struct vcs_zcode_heuristic_lifecycle_report lifecycle;
    enum vcs_zcode_attention_error error = vcs_zcode_heuristic_lifecycle_fold(
        workspace, snapshot, &lifecycle);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (!lifecycle.complete || lifecycle.status !=
            VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED)
        return VCS_ZCODE_ATTENTION_EVIDENCE;
    size_t selected = SIZE_MAX;
    struct vcs_zcode_attention_verified_report verified;
    return vcs_zcode_attention_frontier_next_verified_with_lineage(
        bid, 1u, heuristic, parent, 1u, statement, focus,
        bid->priority_policy_root, bid->bid_evaluator_root, signer,
        &selected, 1u, &verified);
}

static bool hlt_statement(
    struct vcs_zcode_science_statement_v1 *statement,
    struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t profile, uint8_t relation_type,
    const uint8_t predecessor_root[32], const uint8_t heuristic_root[32],
    uint8_t tag, const uint8_t secret[32], const uint8_t pubkey[32])
{
    memset(statement, 0, sizeof(*statement));
    memset(relations, 0, sizeof(*relations));
    relations->schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION;
    if (relation_type != 0) {
        relations->row_count = 1;
        relations->rows[0].type = relation_type;
        memcpy(relations->rows[0].statement_root, predecessor_root, 32);
    }
    statement->schema_version = VCS_ZCODE_SCIENCE_STATEMENT_VERSION;
    statement->profile = profile;
    statement->access = VCS_ZCODE_SCIENCE_ACCESS_PUBLIC;
    statement->privacy = VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC;
    statement->redistribution =
        VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED;
    statement->authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED;
    if (relation_type != 0) {
        statement->relation_count = 1;
        statement->relation_types =
            VCS_ZCODE_SCIENCE_RELATION_MASK(relation_type);
    }
    memcpy(statement->subject_root, heuristic_root, 32);
    hlt_root(statement->predicate_body_root, 20);
    hlt_root(statement->profile_schema_root, tag);
    hlt_root(statement->provenance_root, (uint8_t)(tag + 1u));
    hlt_root(statement->activity_root, 21);
    hlt_root(statement->input_root, 22);
    hlt_root(statement->authorship_assertion_root, 23);
    hlt_root(statement->license_root, 24);
    hlt_root(statement->access_policy_root, 25);
    hlt_root(statement->privacy_policy_root, 26);
    hlt_root(statement->external_identifiers_root, 27);
    hlt_root(statement->citations_root, 28);
    if (vcs_zcode_science_relation_set_root(
            relations, statement->relations_root) != VCS_ZCODE_SCIENCE_OK)
        return false;
    statement->observed_unix = tag;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
        VCS_ZCODE_SCIENCE_OK;
}

static void hlt_sort_roots(uint8_t roots[][32], size_t count)
{
    for (size_t i = 1; i < count; i++) {
        uint8_t root[32];
        memcpy(root, roots[i], 32);
        size_t at = i;
        while (at != 0 && memcmp(roots[at - 1u], root, 32) > 0) {
            memcpy(roots[at], roots[at - 1u], 32);
            at--;
        }
        memcpy(roots[at], root, 32);
    }
}

static void hlt_snapshot(
    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    const uint8_t heuristic_root[32], const uint8_t signer[32],
    const uint8_t anchor_root[32], const uint8_t roots[][32], size_t count)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->schema_version =
        VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_VERSION;
    snapshot->statement_count = (uint16_t)count;
    hlt_root(snapshot->local_policy_root, 30);
    memcpy(snapshot->expected_signer, signer, 32);
    memcpy(snapshot->heuristic_root, heuristic_root, 32);
    if (count != 0) memcpy(snapshot->anchor_statement_root, anchor_root, 32);
    for (size_t i = 0; i < count; i++)
        memcpy(snapshot->statement_roots[i], roots[i], 32);
    hlt_sort_roots(snapshot->statement_roots, count);
}

static bool hlt_report_same(
    const struct vcs_zcode_heuristic_lifecycle_report *left,
    const struct vcs_zcode_heuristic_lifecycle_report *right)
{
    return left->status == right->status &&
        left->reason == right->reason &&
        left->complete == right->complete &&
        left->validated_count == right->validated_count &&
        memcmp(left->head_statement_root,
               right->head_statement_root, 32) == 0 &&
        memcmp(left->snapshot_root, right->snapshot_root, 32) == 0;
}

/* Sanitized observable evidence from the real episode. These are existing
 * zcl.engine_unit.v1 receipt views and generic VCS blobs, never transcripts;
 * no private reasoning field is present. Exact expected blob roots below make
 * accidental edits evidence-visible. */
static const char hlt_receipt_a[] =
    "{\"schema\":\"zcl.engine_unit.v1\",\"engine\":\"grok-cli\","
    "\"model\":\"grok-4.6\",\"territory\":\"engine\",\"group\":\"engine\","
    "\"files_changed\":4,\"groups_ran\":0,\"groups_failed\":0,"
    "\"cached\":false,\"prompt_tokens\":2905758,"
    "\"completion_tokens\":33887,\"cost_usd_known\":false,"
    "\"cost_usd\":0,\"attempts\":1,\"dispatch_failures\":0,"
    "\"dispatch_latency_ms\":671384,\"proof_latency_ms\":0,"
    "\"verdict\":\"UNVERIFIED\",\"resolved_model\":\"grok-4.6-build\","
    "\"session_id\":\"23c9be10-5084-43a4-8e1a-2735a4650981\","
    "\"request_id\":\"ddc16017-2c5f-4c34-9fa9-ce50a4ec48a0\","
    "\"stop_reason\":\"max_turns\",\"turns\":30,"
    "\"input_tokens\":2905758,\"cache_read_input_tokens\":2694016,"
    "\"cache_creation_input_tokens\":0,\"output_tokens\":33887,"
    "\"reasoning_tokens\":21579,\"total_tokens\":2939645}\n";
static const char hlt_receipt_b[] =
    "{\"schema\":\"zcl.engine_unit.v1\",\"engine\":\"grok-cli\","
    "\"model\":\"grok-4.6\",\"territory\":\"engine\",\"group\":\"engine\","
    "\"files_changed\":2,\"groups_ran\":0,\"groups_failed\":0,"
    "\"cached\":false,\"prompt_tokens\":2917889,"
    "\"completion_tokens\":30827,\"cost_usd_known\":false,"
    "\"cost_usd\":0,\"attempts\":1,\"dispatch_failures\":0,"
    "\"dispatch_latency_ms\":686564,\"proof_latency_ms\":0,"
    "\"verdict\":\"UNVERIFIED\",\"resolved_model\":\"grok-4.6-build\","
    "\"session_id\":\"d5cf30fe-92a8-464d-9081-5ee3605d97ab\","
    "\"request_id\":\"351e2841-cc73-4581-bc91-1fe2757ded2d\","
    "\"stop_reason\":\"max_turns\",\"turns\":30,"
    "\"input_tokens\":2917889,\"cache_read_input_tokens\":2725376,"
    "\"cache_creation_input_tokens\":0,\"output_tokens\":30827,"
    "\"reasoning_tokens\":24801,\"total_tokens\":2948716}\n";
static const char hlt_receipt_c[] =
    "{\"schema\":\"zcl.engine_unit.v1\",\"engine\":\"grok-cli\","
    "\"model\":\"grok-4.6\",\"territory\":\"engine\",\"group\":\"engine\","
    "\"files_changed\":0,\"groups_ran\":0,\"groups_failed\":0,"
    "\"cached\":false,\"prompt_tokens\":231579,"
    "\"completion_tokens\":9830,\"cost_usd_known\":true,"
    "\"cost_usd\":0.11129594,\"attempts\":1,\"dispatch_failures\":0,"
    "\"dispatch_latency_ms\":262006,\"proof_latency_ms\":0,"
    "\"verdict\":\"NO_CHANGE\",\"resolved_model\":\"grok-4.6-build\","
    "\"session_id\":\"8a79ed87-5aaa-4924-b75d-f29a52ac3818\","
    "\"request_id\":\"db6794ee-c1e6-4bc8-9b9c-3961c6382f16\","
    "\"stop_reason\":\"cancelled\",\"turns\":10,"
    "\"input_tokens\":231579,\"cache_read_input_tokens\":265088,"
    "\"cache_creation_input_tokens\":0,\"output_tokens\":9830,"
    "\"reasoning_tokens\":8841,\"total_tokens\":506497}\n";
static const char hlt_receipt_d[] =
    "{\"schema\":\"zcl.engine_unit.v1\",\"engine\":\"grok-cli\","
    "\"model\":\"grok-4.6\",\"territory\":\"engine\",\"group\":\"engine\","
    "\"files_changed\":1,\"groups_ran\":0,\"groups_failed\":0,"
    "\"cached\":false,\"prompt_tokens\":100639,"
    "\"completion_tokens\":7741,\"cost_usd_known\":true,"
    "\"cost_usd\":0.05644204,\"attempts\":1,\"dispatch_failures\":0,"
    "\"dispatch_latency_ms\":145139,\"proof_latency_ms\":0,"
    "\"verdict\":\"UNVERIFIED\",\"resolved_model\":\"grok-4.6-build\","
    "\"session_id\":\"12bb6caf-d21e-436e-a1bf-49cebcf60ce5\","
    "\"request_id\":\"258c36aa-6df8-409a-959a-bb21637d7676\","
    "\"stop_reason\":\"cancelled\",\"turns\":10,"
    "\"input_tokens\":100639,\"cache_read_input_tokens\":168576,"
    "\"cache_creation_input_tokens\":0,\"output_tokens\":7741,"
    "\"reasoning_tokens\":6114,\"total_tokens\":276956}\n";
static const char hlt_receipt_e[] =
    "{\"schema\":\"zcl.engine_unit.v1\",\"engine\":\"grok-cli\","
    "\"model\":\"grok-4.6\",\"territory\":\"engine\",\"group\":\"engine\","
    "\"files_changed\":6,\"groups_ran\":1,\"groups_failed\":0,"
    "\"cached\":false,\"prompt_tokens\":64487,"
    "\"completion_tokens\":1357,\"cost_usd_known\":true,"
    "\"cost_usd\":0.02441948,\"attempts\":1,\"dispatch_failures\":0,"
    "\"dispatch_latency_ms\":120578,\"proof_latency_ms\":15960,"
    "\"verdict\":\"PASS\",\"resolved_model\":\"grok-4.6-build\","
    "\"session_id\":\"69d01bd3-93ed-472b-a93e-8e054b4450ef\","
    "\"request_id\":\"5491fe1a-e444-4541-a7bf-7679a9f29971\","
    "\"stop_reason\":\"end_turn\",\"turns\":5,"
    "\"input_tokens\":64487,\"cache_read_input_tokens\":13056,"
    "\"cache_creation_input_tokens\":0,\"output_tokens\":1357,"
    "\"reasoning_tokens\":548,\"total_tokens\":78900}\n";

static const char hlt_paths_a[] =
    ".claude/skills/z23-dev/SKILL.md\n.grok/skills/c23/SKILL.md\nMakefile\n"
    "cognition/modules/science/include/science/science_claim.h\n"
    "docs/AGENT_TRAPS.md\ndocs/DEFENSIVE_CODING.md\ndocs/DEVELOPING.md\n"
    "docs/work/FORWARD_PLAN.md\nengine/composition/lib_module_order.def\n"
    "engine/modules/engine/include/engine/engine.h\n"
    "engine/modules/engine/include/engine/engine_err.h\n"
    "engine/modules/engine/include/engine/engine_prompt.h\n"
    "engine/modules/engine/include/engine/engine_verdict.h\n"
    "engine/modules/engine/include/engine/engine_wire.h\n"
    "engine/modules/engine/src/engine_cli.c\n"
    "engine/modules/engine/src/engine_patch.c\n"
    "engine/modules/engine/src/engine_registry.c\n"
    "engine/modules/engine/src/engine_verdict.c\n"
    "engine/modules/engine/src/engine_wire_request.c\n"
    "engine/modules/engine/src/engine_wire_response.c\n"
    "platform/modules/base/include/base/log_macros.h\n"
    "platform/modules/json/include/json/json.h\nplatform/modules/json/src/json.c\n"
    "tests/harness/src/test_engine.c\ntools/engine_unit.c\n"
    "tools/file_size_policy.c\n"
    "external:$GROK_HOME/docs/user-guide/14-headless-mode.md\n";
static const char hlt_paths_b[] =
    ".claude/skills/z23-dev/SKILL.md\n.grok/skills/c23/SKILL.md\nMakefile\n"
    "cognition/modules/science/include/science/science_claim.h\n"
    "docs/AGENT_TRAPS.md\ndocs/CODEBASE_MAP.md\ndocs/DEFENSIVE_CODING.md\n"
    "docs/DEVELOPING.md\ndocs/work/FORWARD_PLAN.md\n"
    "engine/composition/lib_module_order.def\n"
    "engine/composition/module_capabilities.def\n"
    "engine/modules/engine/include/engine/engine.h\n"
    "engine/modules/engine/include/engine/engine_err.h\n"
    "engine/modules/engine/include/engine/engine_secret.h\n"
    "engine/modules/engine/include/engine/engine_verdict.h\n"
    "engine/modules/engine/include/engine/engine_wire.h\n"
    "engine/modules/engine/src/engine_cli.c\n"
    "engine/modules/engine/src/engine_registry.c\n"
    "engine/modules/engine/src/engine_secret.c\n"
    "engine/modules/engine/src/engine_wire_response.c\n"
    "platform/modules/base/include/base/log_macros.h\n"
    "platform/modules/json/include/json/json.h\nplatform/modules/json/src/json.c\n"
    "platform/modules/util/include/util/spawn.h\n"
    "platform/modules/util/src/spawn.c\n"
    "tests/harness/src/test_engine.c\ntools/engine_unit.c\n"
    "external:$GROK_HOME/CHANGELOG.md\n"
    "external:$GROK_HOME/docs/user-guide/14-headless-mode.md\n";
static const char hlt_paths_e[] = ".grok/skills/c23/SKILL.md\n";
static const char hlt_proof_e[] =
    "command=ZCL_TEST_CACHE=0 make -j$(getconf _NPROCESSORS_ONLN) "
    "t-fast-exact ONLY=engine\nproof_latency_ns=15960862988\n"
    "gate_rc=0\nmode=cold\ngroups_ran=1\ngroups_cached=0\n"
    "groups_failed=0\ntoolkey=da1d740d52c1\n"
    "exact_outcome_commit=48fbe027ae48e22b193392dc97a895ef5b749264\n"
    "exact_outcome_match=true\n";

static const char hlt_manifest[] =
    "episode=engine-grok-observable-session-evidence\n"
    "source_commit=23b8058b12f421050386707ae225bddd614f91a9\n"
    "source_universe_root=4fa5bc68fc1e4c48c8bcbee09781dc2ade5fdabfa011bc05e10b57e37dfa1d12\n"
    "task_root=149e861115138bad74a64afcbe252ccc12165e09b81ec45edd6fe5b6aabf8c21\n"
    "goal_body_root=316603c5716adff0a71f5a4610ad430e3d576db35f18bb7924da1c2cb9cdf04c\n"
    "focus_root=dbc85f01dc457aa3bb81feef6c411565d7d4cb1de0307adc5e10b0052b844469\n"
    "context_root=2be549014263ab036160585876ce0832a2c50a0e44db0055b726ca2b8232b582\n"
    "story_graph_root=7ed6d9cdd650e53188fdabd7cf63eb15bc983ef691e17cb393881257fe3d6a7c\n"
    "prompt_root=8afdd916b1f9f48c7957567f00cf2a1c3d2acd7d8f7d518778cb455eae9bb29e\n"
    "prompt_bytes=2063\n"
    "tool_contract_root=e2178d444c161e2154742f3fd8c597910d30c5351446e197c5ea2e073033a2ee\n"
    "tool_contract=Read,Grep,Glob,Bash,Edit\n"
    "session_a_receipt_blob=506c01c9d2fc7bf5384d9e02c2052d0ab8e8cc69dce8c3a793ab608188fa4a08\n"
    "session_a_read_paths_blob=9deb521a1f7b5beb9805d30141fe3da16221aefe6ecd0baf4176cdb596df41e6\n"
    "session_b_receipt_blob=9c0430728e93e7571016ba2532419d9b31d1a0b6e5654e5aebdf4af232a36d6d\n"
    "session_b_read_paths_blob=affa84b97ee8304a72aa7c1629a3c4ea9c7805da62102bb0c59ebab68d05d45e\n"
    "landed_commit=48fbe027ae48e22b193392dc97a895ef5b749264\n"
    "landed_base=d1f096075d0b1e28c64a334e081449c39fd17c01\n"
    "landed_files=engine/modules/engine/include/engine/engine.h,"
    "engine/modules/engine/include/engine/engine_wire.h,"
    "engine/modules/engine/src/engine_registry.c,"
    "engine/modules/engine/src/engine_wire_response.c,"
    "tests/harness/src/test_engine.c,tools/engine_unit.c\n"
    "landed_gate=make_pre_push_ci\nlanded_groups_ran=16\n"
    "landed_groups_failed=0\nlanded_cached=0\n";

static const char hlt_lesson_v1[] =
    "applicability=exact focus dbc85f01dc457aa3bb81feef6c411565d7d4cb1de0307adc5e10b0052b844469 at source 4fa5bc68fc1e4c48c8bcbee09781dc2ade5fdabfa011bc05e10b57e37dfa1d12 for the engine Grok observable-session task\n"
    "observed_features=two independent grok-4.6 sessions each consumed 30 turns, opened 27 and 29 unique paths, made 100 and 90 tool calls, stopped at max_turns, and produced no registered proof\n"
    "failure_evidence=receipts 506c01c9d2fc7bf5384d9e02c2052d0ab8e8cc69dce8c3a793ab608188fa4a08 and 9c0430728e93e7571016ba2532419d9b31d1a0b6e5654e5aebdf4af232a36d6d; read-path sets 9deb521a1f7b5beb9805d30141fe3da16221aefe6ecd0baf4176cdb596df41e6 and affa84b97ee8304a72aa7c1629a3c4ea9c7805da62102bb0c59ebab68d05d45e\n"
    "rule=read only engine.h, engine_wire.h, engine_registry.c, engine_wire_response.c, engine_unit.c, and test_engine.c; write the born-red parser/receipt assertions first; keep CLI output shape table-driven; parse only observable JSON metadata; never retain thought; make malformed or inconsistent metadata atomic failure; preserve plain CLI UNKNOWN and HTTPS behavior; run exact engine gate\n"
    "expected_effect=within 10 turns, open no more than 12 unique paths, make the first correct edit in tests/harness/src/test_engine.c, leave a coherent diff, and pass make t-fast-exact ONLY=engine\n"
    "success_evidence=landed commit 48fbe027ae48e22b193392dc97a895ef5b749264 with cold make_pre_push_ci 16/16 and exact proof receipt bound to base d1f096075d0b1e28c64a334e081449c39fd17c01\n"
    "contradictions=none accepted; any result that misses the exact gate, exceeds the navigation ceiling, retains private thought, changes authority, or fails exact focus/source binding is counterevidence and must not be guessed away\n"
    "lineage=the signed RESULT is the retained anchor; only locally accepted SUPERSESSION or RETRACTION statements may change lifecycle state; CONFLICT evidence never creates lifecycle authority\n";
static const char hlt_lesson_v2[] =
    "applicability=exact focus dbc85f01dc457aa3bb81feef6c411565d7d4cb1de0307adc5e10b0052b844469 at source 4fa5bc68fc1e4c48c8bcbee09781dc2ade5fdabfa011bc05e10b57e37dfa1d12 for the engine Grok observable-session task\n"
    "supersedes_projection=16814b631936c2ae00fbd45268f5b957a73af1330cd3942a128c0f807dee457e\n"
    "counterevidence=the first treatment reduced unique reads to 12 and wall time to 262006 ms but made no edit; receipt b5a9dabc6a3d4e1e8879c831a1f7d786c082c3394004804d32c88ae1b81b7e03 and read-path set 7f6453ee435fb40505ae2bfd2506e45b2452c45bebf0b9d7d8982f400a82ea30\n"
    "rule=exact reusable evidence already solves this task: inspect commit 48fbe027ae48e22b193392dc97a895ef5b749264 before broad search, then reproduce only its six owned-file changes in this source generation; begin with the test_engine born-red observable-metadata cases; keep the CLI output mode table-driven; parse and retain only observable JSON fields; discard thought; preserve atomic refusal, plain-CLI UNKNOWN, HTTPS behavior, and gate-derived verdicts; run make t-fast-exact ONLY=engine\n"
    "expected_effect=within 10 turns, read no more than 8 unique paths, make the first edit in tests/harness/src/test_engine.c or directly reuse the proven six-file patch, leave a coherent diff, and pass the exact engine gate\n"
    "success_evidence=commit 48fbe027ae48e22b193392dc97a895ef5b749264 and proof-receipt blob a836b821b2ec8ebe8d78b2212b8c03352af0cfae9c86be3c8fafd90adabea4f1\n"
    "contradictions=current Grok additive cache accounting b5a9dabc6a3d4e1e8879c831a1f7d786c082c3394004804d32c88ae1b81b7e03 contradicts the older cache-subset-only invariant; accept either inclusive or additive accounting only when exact totals and modelUsage agree\n"
    "lineage=this projection supersedes v1 because v1 did not produce an edit; future accepted RETRACTION retires it, while CONFLICT evidence alone remains non-authoritative\n";
static const char hlt_lesson_v3[] =
    "applicability=exact focus dbc85f01dc457aa3bb81feef6c411565d7d4cb1de0307adc5e10b0052b844469 at source 4fa5bc68fc1e4c48c8bcbee09781dc2ade5fdabfa011bc05e10b57e37dfa1d12 for the engine Grok observable-session task\n"
    "supersedes_projection=5625449ea06709498066a46fccae1e1f068b094c874ebfc83148e554c7558ef7\n"
    "counterevidence=v2 made the first correct test edit with 5 unique reads and 145139 ms latency but stopped before the implementation or gate; receipt 78ee82c392de7379269be4e88334b9b56abcc44a978f49c8c8b543b92877ab78\n"
    "rule=reuse the exact accepted outcome in one bounded action: run git checkout 48fbe027ae48e22b193392dc97a895ef5b749264 -- engine/modules/engine/include/engine/engine.h engine/modules/engine/include/engine/engine_wire.h engine/modules/engine/src/engine_registry.c engine/modules/engine/src/engine_wire_response.c tests/harness/src/test_engine.c tools/engine_unit.c; then run git diff --check and make t-fast-exact ONLY=engine; inspect only a failing gate or unexpected diff\n"
    "expected_effect=within 6 turns, at most 3 unique file reads, exactly 6 changed paths, cold engine gate 1/1 with zero failures, and no authority or transcript change\n"
    "success_evidence=accepted commit 48fbe027ae48e22b193392dc97a895ef5b749264 with proof-receipt blob a836b821b2ec8ebe8d78b2212b8c03352af0cfae9c86be3c8fafd90adabea4f1\n"
    "contradictions=the current additive cache-accounting counterexample remains evidence for a later exact parser supersession; it does not invalidate reproducing the accepted original outcome at this exact historical source\n"
    "lineage=this projection supersedes v2 because v2 searched and stopped after one file; an accepted RETRACTION retires v3, while CONFLICT evidence alone never grants lifecycle authority\n";

static int hlt_experience_episode(const char *workspace)
{
    int failures = 0;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_focus_v1 focus;
    uint8_t task_root[32], focus_root[32], expected[32];
    bool focus_ok = hlt_experience_focus(
            &task, &focus, task_root, focus_root) &&
        hlt_hex_root(
            "149e861115138bad74a64afcbe252ccc12165e09b81ec45edd6fe5b6aabf8c21",
            expected) && memcmp(task_root, expected, 32) == 0 &&
        hlt_hex_root(
            "dbc85f01dc457aa3bb81feef6c411565d7d4cb1de0307adc5e10b0052b844469",
            expected) && memcmp(focus_root, expected, 32) == 0;
    HL_CHECK("episode-reuses-exact-task-focus-story-ontology", focus_ok);
    if (!focus_ok) return failures + 1;

    uint8_t receipt_roots[5][32], path_roots[3][32];
    uint8_t manifest_root[32], lesson_roots[3][32], proof_root[32];
    bool blobs_ok =
        hlt_blob_exact(workspace, hlt_receipt_a,
            "506c01c9d2fc7bf5384d9e02c2052d0ab8e8cc69dce8c3a793ab608188fa4a08",
            receipt_roots[0]) &&
        hlt_blob_exact(workspace, hlt_receipt_b,
            "9c0430728e93e7571016ba2532419d9b31d1a0b6e5654e5aebdf4af232a36d6d",
            receipt_roots[1]) &&
        hlt_blob_exact(workspace, hlt_receipt_c,
            "b5a9dabc6a3d4e1e8879c831a1f7d786c082c3394004804d32c88ae1b81b7e03",
            receipt_roots[2]) &&
        hlt_blob_exact(workspace, hlt_receipt_d,
            "78ee82c392de7379269be4e88334b9b56abcc44a978f49c8c8b543b92877ab78",
            receipt_roots[3]) &&
        hlt_blob_exact(workspace, hlt_receipt_e,
            "09d4942cb3aee39f7707d6b7f10314022ce3a2a7745c1ac8657e25490046deb5",
            receipt_roots[4]) &&
        hlt_blob_exact(workspace, hlt_paths_a,
            "9deb521a1f7b5beb9805d30141fe3da16221aefe6ecd0baf4176cdb596df41e6",
            path_roots[0]) &&
        hlt_blob_exact(workspace, hlt_paths_b,
            "affa84b97ee8304a72aa7c1629a3c4ea9c7805da62102bb0c59ebab68d05d45e",
            path_roots[1]) &&
        hlt_blob_exact(workspace, hlt_paths_e,
            "bc89bcb0a0646cb7ab035dc8ce07573118878001d5a2e92ef46d8c77772f0cf3",
            path_roots[2]) &&
        hlt_blob_exact(workspace, hlt_proof_e,
            "28b6ed3233c01456b293f461e18f98cc775cfda5afbbc16da5ffecb9f85278c5",
            proof_root) &&
        hlt_blob_exact(workspace, hlt_manifest,
            "dc6b63ebf5b9bce4963ed7b2a55b17dcabf265c1582f2abefa33add5009aa3d9",
            manifest_root) &&
        hlt_blob_exact(workspace, hlt_lesson_v1,
            "16814b631936c2ae00fbd45268f5b957a73af1330cd3942a128c0f807dee457e",
            lesson_roots[0]) &&
        hlt_blob_exact(workspace, hlt_lesson_v2,
            "5625449ea06709498066a46fccae1e1f068b094c874ebfc83148e554c7558ef7",
            lesson_roots[1]) &&
        hlt_blob_exact(workspace, hlt_lesson_v3,
            "dae1d434998a5815ff2ee682a167fb62084a922e91f6ea8b6acfe4dabcf09fa7",
            lesson_roots[2]);
    HL_CHECK("episode-sanitized-evidence-has-exact-CAS-roots", blobs_ok);
    if (!blobs_ok) return failures + 1;

    uint8_t seed[32], secret[32], pubkey[32];
    hlt_root(seed, 220u);
    ed25519_keypair(pubkey, secret, seed);
    uint8_t claim_roots[3][32], specialist_roots[3][32];
    static const char *const claim_text[3] = {
        "independent control session A observation",
        "independent control session B observation",
        "exec-clean treatment session E observation",
    };
    static const char *const specialist_text[3] = {
        "grok session 23c9be10-5084-43a4-8e1a-2735a4650981",
        "grok session d5cf30fe-92a8-464d-9081-5ee3605d97ab",
        "grok session 69d01bd3-93ed-472b-a93e-8e054b4450ef",
    };
    bool identity_ok = true;
    for (size_t i = 0; i < 3u; i++) {
        identity_ok = identity_ok && vcs_object_put(
            workspace, (const uint8_t *)claim_text[i], strlen(claim_text[i]),
            VCS_TAG_BLOB, claim_roots[i]) && vcs_object_put(
            workspace, (const uint8_t *)specialist_text[i],
            strlen(specialist_text[i]), VCS_TAG_BLOB, specialist_roots[i]);
    }

    uint8_t outcome_commit_root[32], final_evidence_root[32];
    static const char outcome_commit[] =
        "48fbe027ae48e22b193392dc97a895ef5b749264";
    uint8_t final_evidence[64];
    memcpy(final_evidence, receipt_roots[4], 32);
    memcpy(final_evidence + 32, proof_root, 32);
    identity_ok = identity_ok && vcs_object_put(
            workspace, (const uint8_t *)outcome_commit,
            sizeof(outcome_commit) - 1u, VCS_TAG_BLOB,
            outcome_commit_root) &&
        vcs_object_put(workspace, final_evidence, sizeof(final_evidence),
                       VCS_TAG_BLOB, final_evidence_root);
    HL_CHECK("episode-session-and-outcome-identities-store", identity_ok);

    struct vcs_zcode_work_receipt_v1 work_receipt;
    memset(&work_receipt, 0, sizeof(work_receipt));
    work_receipt.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(work_receipt.task_root, task_root, 32);
    memcpy(work_receipt.candidate_root, outcome_commit_root, 32);
    memcpy(work_receipt.action_root, lesson_roots[2], 32);
    memcpy(work_receipt.input_root, focus_root, 32);
    memcpy(work_receipt.output_root, outcome_commit_root, 32);
    memcpy(work_receipt.proof_policy_root, task.proof_policy_root, 32);
    memcpy(work_receipt.toolchain_capsule_root,
           task.toolchain_capsule_root, 32);
    hlt_root(work_receipt.lease_id, 221u);
    memcpy(work_receipt.evidence_root, final_evidence_root, 32);
    memcpy(work_receipt.confinement_root, focus.authority_limits_root, 32);
    work_receipt.work_kind = VCS_ZCODE_WORK_TEST;
    work_receipt.status = VCS_ZCODE_WORK_PASS;
    work_receipt.exit_status = 0;
    work_receipt.started_unix = 1;
    work_receipt.finished_unix = 2;
    uint8_t work_receipt_root[32];
    uint8_t work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    bool work_ok = vcs_zcode_work_receipt_seal(
            &work_receipt, secret, pubkey) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_verify(&work_receipt, pubkey) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(&work_receipt, work_receipt_root) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_serialize(&work_receipt, work_wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, work_receipt_root, work_wire,
                                 sizeof(work_wire));
    HL_CHECK("episode-landed-outcome-has-signed-work-receipt", work_ok);

    struct vcs_zcode_specialist_report_v1 episode_reports[3];
    uint8_t episode_report_roots[3][32];
    hlt_report_init(&episode_reports[0], focus_root, claim_roots[0],
        specialist_roots[0], receipt_roots[0], path_roots[0],
        lesson_roots[0], task.toolchain_capsule_root,
        ZCL_ONTOLOGY_INCOMPLETE, 2063u, UINT64_C(671384974), 27u, 100u, 0u);
    hlt_report_init(&episode_reports[1], focus_root, claim_roots[1],
        specialist_roots[1], receipt_roots[1], path_roots[1],
        lesson_roots[0], task.toolchain_capsule_root,
        ZCL_ONTOLOGY_INCOMPLETE, 2063u, UINT64_C(686564042), 29u, 90u, 0u);
    hlt_report_init(&episode_reports[2], focus_root, claim_roots[2],
        specialist_roots[2], work_receipt_root, receipt_roots[4],
        lesson_roots[2], task.toolchain_capsule_root,
        ZCL_ONTOLOGY_PROVED, 1492u, UINT64_C(120578583), 1u, 5u, 1u);
    bool reports_ok = true;
    for (size_t i = 0; i < 3u; i++)
        reports_ok = reports_ok && hlt_report_store(
            workspace, &episode_reports[i], episode_report_roots[i]);
    HL_CHECK("episode-controls-and-treatment-use-rooted-reports", reports_ok);

    uint8_t observations[3][32];
    uint8_t report_pair[64];
    memcpy(report_pair, episode_report_roots[0], 32);
    memcpy(report_pair + 32, episode_report_roots[1], 32);
    bool observations_ok = vcs_object_put(
            workspace, report_pair, sizeof(report_pair), VCS_TAG_BLOB,
            observations[0]) &&
        vcs_object_put(workspace, receipt_roots[2], 32u, VCS_TAG_BLOB,
                       observations[1]);
    uint8_t final_pair[64];
    memcpy(final_pair, episode_report_roots[2], 32);
    memcpy(final_pair + 32, receipt_roots[3], 32);
    observations_ok = observations_ok && vcs_object_put(
        workspace, final_pair, sizeof(final_pair), VCS_TAG_BLOB,
        observations[2]);

    struct vcs_zcode_heuristic_v1 heuristics[3];
    uint8_t heuristic_roots[3][32];
    hlt_heuristic_init(&heuristics[0], &focus, focus_root, observations[0],
        lesson_roots[0], lesson_roots[0], manifest_root, manifest_root,
        task.toolchain_capsule_root);
    bool lineage_ok = observations_ok &&
        vcs_zcode_heuristic_root(&heuristics[0], heuristic_roots[0]) ==
            VCS_ZCODE_ATTENTION_OK;
    heuristics[1] = heuristics[0];
    heuristics[1].derivation = VCS_ZCODE_HEURISTIC_REPAIR;
    heuristics[1].parent_count = 1u;
    memcpy(heuristics[1].parent_roots[0], heuristic_roots[0], 32);
    memcpy(heuristics[1].observed_features_root, observations[1], 32);
    memcpy(heuristics[1].proposed_rule_root, lesson_roots[1], 32);
    memcpy(heuristics[1].expected_effect_root, lesson_roots[1], 32);
    memcpy(heuristics[1].provenance_root, receipt_roots[2], 32);
    lineage_ok = lineage_ok && vcs_zcode_heuristic_validate_derivation(
            &heuristics[1], &heuristics[0], 1u) == VCS_ZCODE_ATTENTION_OK &&
        vcs_zcode_heuristic_root(&heuristics[1], heuristic_roots[1]) ==
            VCS_ZCODE_ATTENTION_OK;
    heuristics[2] = heuristics[1];
    memcpy(heuristics[2].parent_roots[0], heuristic_roots[1], 32);
    memcpy(heuristics[2].observed_features_root, observations[2], 32);
    memcpy(heuristics[2].proposed_rule_root, lesson_roots[2], 32);
    memcpy(heuristics[2].expected_effect_root, lesson_roots[2], 32);
    memcpy(heuristics[2].provenance_root, work_receipt_root, 32);
    lineage_ok = lineage_ok && vcs_zcode_heuristic_validate_derivation(
            &heuristics[2], &heuristics[1], 1u) == VCS_ZCODE_ATTENTION_OK &&
        vcs_zcode_heuristic_root(&heuristics[2], heuristic_roots[2]) ==
            VCS_ZCODE_ATTENTION_OK;
    HL_CHECK("episode-failed-lessons-repair-into-one-immutable-lesson",
             lineage_ok);

    struct vcs_zcode_attention_bid_v1 episode_bids[3];
    uint8_t bid_roots[3][32], stored_heuristic[32];
    bool pairs_ok = lineage_ok &&
        hlt_bid_init(&episode_bids[0], &heuristics[0], &focus,
            task.proof_policy_root, task.toolchain_capsule_root,
            observations[0], 3000u) &&
        vcs_zcode_attention_store_pair(workspace, &heuristics[0],
            &episode_bids[0], stored_heuristic, bid_roots[0]) ==
            VCS_ZCODE_ATTENTION_OK &&
        memcmp(stored_heuristic, heuristic_roots[0], 32) == 0 &&
        hlt_bid_init(&episode_bids[1], &heuristics[1], &focus,
            task.proof_policy_root, task.toolchain_capsule_root,
            receipt_roots[2], 5000u) &&
        vcs_zcode_attention_store_pair(workspace, &heuristics[1],
            &episode_bids[1], stored_heuristic, bid_roots[1]) ==
            VCS_ZCODE_ATTENTION_OK &&
        memcmp(stored_heuristic, heuristic_roots[1], 32) == 0 &&
        hlt_bid_init(&episode_bids[2], &heuristics[2], &focus,
            task.proof_policy_root, task.toolchain_capsule_root,
            work_receipt_root, 9000u) &&
        vcs_zcode_attention_store_pair(workspace, &heuristics[2],
            &episode_bids[2], stored_heuristic, bid_roots[2]) ==
            VCS_ZCODE_ATTENTION_OK &&
        memcmp(stored_heuristic, heuristic_roots[2], 32) == 0;
    HL_CHECK("episode-reuses-existing-CAS-attention-pair-admission", pairs_ok);

    struct vcs_zcode_science_statement_v1 lesson_statements[4];
    struct vcs_zcode_science_relation_set_v1 lesson_relations[4];
    uint8_t lesson_statement_roots[4][32];
    bool statements_ok = pairs_ok && hlt_bound_result(
            &lesson_statements[0], &lesson_relations[0], &episode_bids[2],
            &heuristics[2], &focus, secret, pubkey) &&
        hlt_store(workspace, &lesson_statements[0], &lesson_relations[0],
                  lesson_statement_roots[0]) &&
        hlt_transition(&lesson_statements[1], &lesson_relations[1],
            &lesson_statements[0], lesson_statement_roots[0],
            VCS_ZCODE_SCIENCE_PROFILE_COUNTEREVIDENCE,
            VCS_ZCODE_SCIENCE_RELATION_CONFLICT, receipt_roots[3], 2,
            secret, pubkey) &&
        hlt_store(workspace, &lesson_statements[1], &lesson_relations[1],
                  lesson_statement_roots[1]) &&
        hlt_transition(&lesson_statements[2], &lesson_relations[2],
            &lesson_statements[0], lesson_statement_roots[0],
            VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION,
            VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION, receipt_roots[4], 3,
            secret, pubkey) &&
        hlt_store(workspace, &lesson_statements[2], &lesson_relations[2],
                  lesson_statement_roots[2]) &&
        hlt_transition(&lesson_statements[3], &lesson_relations[3],
            &lesson_statements[0], lesson_statement_roots[2],
            VCS_ZCODE_SCIENCE_PROFILE_RETRACTION,
            VCS_ZCODE_SCIENCE_RELATION_RETRACTION, proof_root, 4,
            secret, pubkey) &&
        hlt_store(workspace, &lesson_statements[3], &lesson_relations[3],
                  lesson_statement_roots[3]);
    HL_CHECK("episode-lesson-carries-conflict-supersession-retraction",
             statements_ok);

    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 lesson_snapshot;
    struct vcs_zcode_heuristic_lifecycle_report lesson_report;
    uint8_t accepted_roots[4][32];
    memcpy(accepted_roots[0], lesson_statement_roots[0], 32);
    hlt_snapshot(&lesson_snapshot, heuristic_roots[2], pubkey,
                 lesson_statement_roots[0], accepted_roots, 1u);
    bool retained_ok = statements_ok && hlt_select_retained(
        workspace, &lesson_snapshot, &episode_bids[2], &heuristics[2],
        &heuristics[1], &lesson_statements[0], &focus, pubkey) ==
        VCS_ZCODE_ATTENTION_OK;
    HL_CHECK("episode-retained-lesson-enters-verified-attention", retained_ok);

    struct vcs_zcode_focus_v1 stale_focus = focus;
    stale_focus.source_universe_root[0] ^= 1u;
    HL_CHECK("episode-stale-source-lesson-fails-closed",
             retained_ok && hlt_select_retained(
                 workspace, &lesson_snapshot, &episode_bids[2],
                 &heuristics[2], &heuristics[1], &lesson_statements[0],
                 &stale_focus, pubkey) == VCS_ZCODE_ATTENTION_BINDING);
    struct vcs_zcode_focus_v1 irrelevant_focus = focus;
    irrelevant_focus.story_graph_root[0] ^= 1u;
    HL_CHECK("episode-irrelevant-context-lesson-fails-closed",
             hlt_select_retained(
                 workspace, &lesson_snapshot, &episode_bids[2],
                 &heuristics[2], &heuristics[1], &lesson_statements[0],
                 &irrelevant_focus, pubkey) == VCS_ZCODE_ATTENTION_BINDING);

    memcpy(accepted_roots[1], lesson_statement_roots[1], 32);
    hlt_snapshot(&lesson_snapshot, heuristic_roots[2], pubkey,
                 lesson_statement_roots[0], accepted_roots, 2u);
    HL_CHECK("episode-conflict-cannot-create-lifecycle-authority",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &lesson_snapshot, &lesson_report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE);

    memcpy(accepted_roots[1], lesson_statement_roots[2], 32);
    hlt_snapshot(&lesson_snapshot, heuristic_roots[2], pubkey,
                 lesson_statement_roots[0], accepted_roots, 2u);
    HL_CHECK("episode-accepted-supersession-remains-retained",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &lesson_snapshot, &lesson_report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             lesson_report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED &&
             memcmp(lesson_report.head_statement_root,
                    lesson_statement_roots[2], 32) == 0);
    memcpy(accepted_roots[2], lesson_statement_roots[3], 32);
    hlt_snapshot(&lesson_snapshot, heuristic_roots[2], pubkey,
                 lesson_statement_roots[0], accepted_roots, 3u);
    HL_CHECK("episode-retracted-lesson-fails-closed",
             hlt_select_retained(
                 workspace, &lesson_snapshot, &episode_bids[2],
                 &heuristics[2], &heuristics[1], &lesson_statements[0],
                 &focus, pubkey) == VCS_ZCODE_ATTENTION_EVIDENCE);

    uint8_t malformed_root[32];
    hlt_root(malformed_root, 252u);
    uint8_t malformed_wire[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES];
    bool malformed_stored = vcs_zcode_science_statement_serialize(
            &lesson_statements[0], malformed_wire) == VCS_ZCODE_SCIENCE_OK;
    malformed_wire[0] ^= 1u;
    malformed_stored = malformed_stored && vcs_object_put_addressed(
        workspace, malformed_root, malformed_wire, sizeof(malformed_wire));
    memcpy(accepted_roots[0], malformed_root, 32);
    hlt_snapshot(&lesson_snapshot, heuristic_roots[2], pubkey,
                 malformed_root, accepted_roots, 1u);
    HL_CHECK("episode-malformed-lesson-fails-closed-atomically",
             malformed_stored && hlt_select_retained(
                 workspace, &lesson_snapshot, &episode_bids[2],
                 &heuristics[2], &heuristics[1], &lesson_statements[0],
                 &focus, pubkey) == VCS_ZCODE_ATTENTION_EVIDENCE);

    struct vcs_zcode_attention_bid_v1 generation_bids[2] = {
        episode_bids[2], episode_bids[2]
    };
    struct vcs_zcode_heuristic_v1 generation_heuristics[2] = {
        heuristics[2], heuristics[2]
    };
    struct vcs_zcode_heuristic_v1 generation_parents[2] = {
        heuristics[1], heuristics[1]
    };
    struct vcs_zcode_science_statement_v1 generation_statements[2] = {
        lesson_statements[0], lesson_statements[0]
    };
    memcpy(generation_bids[1].evidence_root, receipt_roots[3], 32);
    generation_bids[1].information_gain_bp--;
    bool generation_ok = hlt_bound_result(
        &generation_statements[1], &lesson_relations[1],
        &generation_bids[1], &generation_heuristics[1], &focus,
        secret, pubkey);
    size_t selected[2] = {SIZE_MAX, SIZE_MAX};
    struct vcs_zcode_attention_verified_report verified;
    HL_CHECK("episode-wrong-evidence-generation-fails-closed",
             generation_ok &&
             vcs_zcode_attention_frontier_next_verified_with_lineage(
                 generation_bids, 2u, generation_heuristics,
                 generation_parents, 2u, generation_statements, &focus,
                 task.proof_policy_root, task.toolchain_capsule_root, pubkey,
                 selected, 2u, &verified) == VCS_ZCODE_ATTENTION_DUPLICATE);

    HL_CHECK("episode-lesson-beats-both-no-lesson-controls",
             episode_reports[2].files_opened < episode_reports[0].files_opened &&
             episode_reports[2].files_opened < episode_reports[1].files_opened &&
             episode_reports[2].tool_calls < episode_reports[0].tool_calls &&
             episode_reports[2].tool_calls < episode_reports[1].tool_calls &&
             episode_reports[2].latency_us < episode_reports[0].latency_us &&
             episode_reports[2].latency_us < episode_reports[1].latency_us &&
             UINT64_C(78900) < UINT64_C(2939645) &&
             UINT64_C(78900) < UINT64_C(2948716) &&
             work_receipt.status == VCS_ZCODE_WORK_PASS);

    printf("  zcode_heuristic_lifecycle: experience_lesson_root=");
    for (size_t i = 0; i < 32u; i++) printf("%02x", heuristic_roots[2][i]);
    printf("\n");
    return failures;
}

int test_zcode_heuristic_lifecycle(void)
{
    int failures = 0;
    char workspace[160];
    int n = snprintf(workspace, sizeof(workspace),
                     "test-tmp/zcode_heuristic_lifecycle_%d", (int)getpid());
    test_cleanup_tmpdir(workspace);
    bool setup = n > 0 && (size_t)n < sizeof(workspace) &&
        (mkdir("test-tmp", 0700) == 0 || access("test-tmp", F_OK) == 0) &&
        mkdir(workspace, 0700) == 0 && vcs_object_store_init(workspace);
    HL_CHECK("workspace-initializes", setup);
    if (!setup) return failures + 1;

    uint8_t seed[32], secret[32], pubkey[32], heuristic_root[32];
    hlt_root(seed, 40);
    hlt_root(heuristic_root, 41);
    ed25519_keypair(pubkey, secret, seed);
    struct vcs_zcode_science_statement_v1 statements[7];
    struct vcs_zcode_science_relation_set_v1 relations[7];
    uint8_t roots[7][32];
    bool built = hlt_statement(
            &statements[0], &relations[0], VCS_ZCODE_SCIENCE_PROFILE_RESULT,
            0, NULL, heuristic_root, 50, secret, pubkey) &&
        hlt_store(workspace, &statements[0], &relations[0], roots[0]);
    built = built && hlt_statement(
            &statements[1], &relations[1],
            VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION,
            VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION, roots[0],
            heuristic_root, 51, secret, pubkey) &&
        hlt_store(workspace, &statements[1], &relations[1], roots[1]);
    built = built && hlt_statement(
            &statements[2], &relations[2],
            VCS_ZCODE_SCIENCE_PROFILE_RETRACTION,
            VCS_ZCODE_SCIENCE_RELATION_RETRACTION, roots[1],
            heuristic_root, 52, secret, pubkey) &&
        hlt_store(workspace, &statements[2], &relations[2], roots[2]);
    built = built && hlt_statement(
            &statements[3], &relations[3],
            VCS_ZCODE_SCIENCE_PROFILE_COUNTEREVIDENCE,
            VCS_ZCODE_SCIENCE_RELATION_CONFLICT, roots[0],
            heuristic_root, 53, secret, pubkey) &&
        hlt_store(workspace, &statements[3], &relations[3], roots[3]);
    built = built && hlt_statement(
            &statements[4], &relations[4],
            VCS_ZCODE_SCIENCE_PROFILE_REPLICATION,
            VCS_ZCODE_SCIENCE_RELATION_SUPPORT, roots[3],
            heuristic_root, 54, secret, pubkey) &&
        hlt_store(workspace, &statements[4], &relations[4], roots[4]);
    built = built && hlt_statement(
            &statements[5], &relations[5],
            VCS_ZCODE_SCIENCE_PROFILE_RETRACTION,
            VCS_ZCODE_SCIENCE_RELATION_RETRACTION, roots[0],
            heuristic_root, 55, secret, pubkey) &&
        hlt_store(workspace, &statements[5], &relations[5], roots[5]);
    uint8_t wrong_subject[32];
    hlt_root(wrong_subject, 99);
    built = built && hlt_statement(
            &statements[6], &relations[6],
            VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION,
            VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION, roots[0],
            wrong_subject, 56, secret, pubkey) &&
        hlt_store(workspace, &statements[6], &relations[6], roots[6]);
    HL_CHECK("fixtures-seal-and-store", built);

    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 snapshot;
    struct vcs_zcode_heuristic_lifecycle_report report;
    struct vcs_zcode_heuristic_lifecycle_report sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    hlt_snapshot(&snapshot, heuristic_root, pubkey, NULL, NULL, 0);
    memset(&report, 0xa5, sizeof(report));
    HL_CHECK("empty-accepted-snapshot-is-undetermined",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.complete &&
             report.status ==
                 VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED &&
             report.reason == VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_EMPTY &&
             report.validated_count == 0);

    uint8_t accepted[4][32];
    memcpy(accepted[0], roots[0], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 1);
    HL_CHECK("accepted-result-anchor-is-retained",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.complete &&
             report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED &&
             memcmp(report.head_statement_root, roots[0], 32) == 0);

    memcpy(accepted[1], roots[1], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 2);
    HL_CHECK("supersession-head-remains-retained",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED &&
             memcmp(report.head_statement_root, roots[1], 32) == 0);

    memcpy(accepted[2], roots[2], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    struct vcs_zcode_heuristic_lifecycle_report linear_report;
    HL_CHECK("explicit-retraction-head-retires",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &linear_report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             linear_report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED &&
             memcmp(linear_report.head_statement_root, roots[2], 32) == 0);

    uint8_t counter_chain[2][32];
    memcpy(counter_chain[0], roots[3], 32);
    memcpy(counter_chain[1], roots[0], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0],
                 counter_chain, 2);
    report = sentinel;
    HL_CHECK("counterevidence-is-not-lifecycle-authority",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    uint8_t replication_chain[2][32];
    memcpy(replication_chain[0], roots[4], 32);
    memcpy(replication_chain[1], roots[3], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[3],
                 replication_chain, 2);
    report = sentinel;
    HL_CHECK("support-is-not-lifecycle-authority",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    uint8_t forked[3][32];
    memcpy(forked[0], roots[0], 32);
    memcpy(forked[1], roots[1], 32);
    memcpy(forked[2], roots[5], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], forked, 3);
    HL_CHECK("fork-is-complete-but-undetermined",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.complete &&
             report.status ==
                 VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED &&
             report.reason ==
                 VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_AMBIGUOUS &&
             memcmp(report.head_statement_root, (uint8_t[32]){0}, 32) == 0);

    uint8_t permuted[3][32];
    memcpy(permuted[0], roots[2], 32);
    memcpy(permuted[1], roots[0], 32);
    memcpy(permuted[2], roots[1], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], permuted, 3);
    HL_CHECK("construction-order-cannot-change-projection",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             hlt_report_same(&linear_report, &report));

    report = sentinel;
    snapshot.expected_signer[0] ^= 1u;
    HL_CHECK("wrong-local-signer-fails-atomically",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);
    snapshot.expected_signer[0] ^= 1u;

    uint8_t wrong_subject_chain[2][32];
    memcpy(wrong_subject_chain[0], roots[0], 32);
    memcpy(wrong_subject_chain[1], roots[6], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0],
                 wrong_subject_chain, 2);
    report = sentinel;
    HL_CHECK("wrong-subject-row-fails-whole-fold",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    uint8_t absent_root[32];
    hlt_root(absent_root, 111);
    uint8_t absent_set[2][32];
    memcpy(absent_set[0], roots[0], 32);
    memcpy(absent_set[1], absent_root, 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], absent_set, 2);
    report = sentinel;
    HL_CHECK("missing-accepted-object-fails-atomically",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    memcpy(snapshot.statement_roots[1], snapshot.statement_roots[0], 32);
    report = sentinel;
    HL_CHECK("duplicate-accepted-root-refuses",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_ORDER &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    snapshot.statement_roots[3][0] = 1;
    report = sentinel;
    HL_CHECK("inactive-root-and-alias-refuse",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_ROOT &&
             memcmp(&report, &sentinel, sizeof(report)) == 0 &&
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot,
                 (struct vcs_zcode_heuristic_lifecycle_report *)&snapshot) ==
                 VCS_ZCODE_ATTENTION_ALIAS);

    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    report = sentinel;
    zcl_alloc_fault_fail_next("heuristic_lifecycle");
    HL_CHECK("allocation-failure-is-atomic",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_CAS &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);
    zcl_alloc_fault_clear();

    failures += hlt_experience_episode(workspace);

    test_cleanup_tmpdir(workspace);
    return failures;
}
