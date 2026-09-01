/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: validate, preserve, and retrieve one exact agent experience. */
#include "services/experience_compilation_service.h"

#include "util/log_macros.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static enum zcl_experience_compilation_error experience_fail(
    enum zcl_experience_compilation_error error, const char *detail)
{
    LOG_ERROR("experience.compile", "experience compilation refused: %s (%s)",
              zcl_experience_compilation_error_string(error), detail);
    return error;
}

static bool experience_root_equal(const uint8_t left[32],
                                  const uint8_t right[32])
{
    return memcmp(left, right, 32) == 0;
}

static bool experience_memory_overlaps(const void *left, size_t left_size,
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

static bool experience_workspace_size(const char *workspace, size_t *bytes)
{
    if (!workspace || !bytes) return false;
    size_t length = 0;
    while (length <= 4096u && workspace[length]) length++;
    if (length == 0 || length > 4096u) return false;
    *bytes = length + 1u;
    return true;
}

static bool experience_output_aliases(
    const struct zcl_experience_episode_v1 *episode,
    const struct zcl_experience_compilation_v1 *out, size_t workspace_bytes)
{
#define EXPERIENCE_INPUT_OVERLAPS(pointer, count) \
    experience_memory_overlaps(out, sizeof(*out), (pointer), (count))
    bool aliases =
        EXPERIENCE_INPUT_OVERLAPS(episode, sizeof(*episode)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->workspace, workspace_bytes) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->story, sizeof(*episode->story)) ||
        EXPERIENCE_INPUT_OVERLAPS(
            episode->story->events,
            episode->story->event_count * sizeof(*episode->story->events)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->task, sizeof(*episode->task)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->agent_context,
                                  sizeof(*episode->agent_context)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->focus, sizeof(*episode->focus)) ||
        (episode->claim_count != 0 && EXPERIENCE_INPUT_OVERLAPS(
            episode->claim_roots, episode->claim_count * 32u)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->work_receipt,
                                  sizeof(*episode->work_receipt)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->specialist_report,
                                  sizeof(*episode->specialist_report)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->heuristic,
                                  sizeof(*episode->heuristic)) ||
        (episode->parent_count != 0 && EXPERIENCE_INPUT_OVERLAPS(
            episode->parents,
            episode->parent_count * sizeof(*episode->parents))) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->attention_bid,
                                  sizeof(*episode->attention_bid)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->relations,
                                  sizeof(*episode->relations)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->statement,
                                  sizeof(*episode->statement)) ||
        EXPERIENCE_INPUT_OVERLAPS(episode->local_acceptance,
                                  sizeof(*episode->local_acceptance));
#undef EXPERIENCE_INPUT_OVERLAPS
    return aliases;
}

static bool experience_store_receipt(
    const char *workspace, const struct vcs_zcode_work_receipt_v1 *receipt,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    if (vcs_zcode_work_receipt_serialize(receipt, wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(receipt, root) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(workspace, root, wire, sizeof(wire))) {
        LOG_ERROR("experience.compile", "receipt CAS write failed");
        return false;
    }
    uint8_t *loaded = NULL;
    size_t loaded_len = 0;
    struct vcs_zcode_work_receipt_v1 parsed;
    uint8_t checked[32];
    bool ok = vcs_object_load_raw_bounded(
                  workspace, root, sizeof(wire), &loaded, &loaded_len) == 0 &&
        loaded_len == sizeof(wire) &&
        vcs_zcode_work_receipt_parse(loaded, loaded_len, &parsed) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(&parsed, checked) == VCS_ZCODE_DEV_OK &&
        experience_root_equal(root, checked) &&
        vcs_zcode_work_receipt_verify(&parsed, receipt->signer_pubkey) ==
            VCS_ZCODE_DEV_OK;
    free(loaded);
    if (!ok)
        LOG_ERROR("experience.compile", "receipt CAS revalidation failed");
    return ok;
}

static bool experience_store_report(
    const char *workspace,
    const struct vcs_zcode_specialist_report_v1 *report, uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
    if (vcs_zcode_specialist_report_serialize(report, wire) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_specialist_report_root(report, root) !=
            VCS_ZCODE_FOCUS_OK ||
        !vcs_object_put_addressed(workspace, root, wire, sizeof(wire))) {
        LOG_ERROR("experience.compile", "specialist report CAS write failed");
        return false;
    }
    uint8_t *loaded = NULL;
    size_t loaded_len = 0;
    struct vcs_zcode_specialist_report_v1 parsed;
    uint8_t checked[32];
    bool ok = vcs_object_load_raw_bounded(
                  workspace, root, sizeof(wire), &loaded, &loaded_len) == 0 &&
        loaded_len == sizeof(wire) &&
        vcs_zcode_specialist_report_parse(loaded, loaded_len, &parsed) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_specialist_report_root(&parsed, checked) ==
            VCS_ZCODE_FOCUS_OK &&
        experience_root_equal(root, checked);
    free(loaded);
    if (!ok)
        LOG_ERROR("experience.compile",
                  "specialist report CAS revalidation failed");
    return ok;
}

static bool experience_store_science(
    const char *workspace,
    const struct vcs_zcode_science_relation_set_v1 *relations,
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_signer[32], uint8_t relations_root[32],
    uint8_t statement_root[32])
{
    uint8_t relation_wire[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES];
    uint8_t statement_wire[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES];
    size_t relation_len = 0;
    if (vcs_zcode_science_relation_set_serialize(
            relations, relation_wire, &relation_len) != VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_relation_set_root(relations, relations_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_statement_validate_relations(statement, relations) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_statement_verify(statement, expected_signer) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_statement_serialize(statement, statement_wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_statement_root(statement, statement_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        !vcs_object_put_addressed(workspace, relations_root, relation_wire,
                                  relation_len) ||
        !vcs_object_put_addressed(workspace, statement_root, statement_wire,
                                  sizeof(statement_wire))) {
        LOG_ERROR("experience.compile", "science evidence CAS write failed");
        return false;
    }

    uint8_t *loaded_relations = NULL, *loaded_statement = NULL;
    size_t loaded_relations_len = 0, loaded_statement_len = 0;
    struct vcs_zcode_science_relation_set_v1 parsed_relations;
    struct vcs_zcode_science_statement_v1 parsed_statement;
    uint8_t checked_relations[32], checked_statement[32];
    bool ok = vcs_object_load_raw_bounded(
                  workspace, relations_root, sizeof(relation_wire),
                  &loaded_relations, &loaded_relations_len) == 0 &&
        vcs_object_load_raw_bounded(
                  workspace, statement_root, sizeof(statement_wire),
                  &loaded_statement, &loaded_statement_len) == 0 &&
        vcs_zcode_science_relation_set_parse(
                  loaded_relations, loaded_relations_len,
                  &parsed_relations) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_relation_set_root(
                  &parsed_relations, checked_relations) ==
            VCS_ZCODE_SCIENCE_OK &&
        experience_root_equal(relations_root, checked_relations) &&
        loaded_statement_len == sizeof(statement_wire) &&
        vcs_zcode_science_statement_parse(
                  loaded_statement, loaded_statement_len,
                  &parsed_statement) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(
                  &parsed_statement, checked_statement) ==
            VCS_ZCODE_SCIENCE_OK &&
        experience_root_equal(statement_root, checked_statement) &&
        vcs_zcode_science_statement_verify(
                  &parsed_statement, expected_signer) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_validate_relations(
                  &parsed_statement, &parsed_relations) ==
            VCS_ZCODE_SCIENCE_OK;
    free(loaded_relations);
    free(loaded_statement);
    if (!ok)
        LOG_ERROR("experience.compile", "science CAS revalidation failed");
    return ok;
}

static enum zcl_experience_compilation_error experience_validate_story_focus(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *result)
{
    if (!zcl_story_graph_v1_validate(episode->story) ||
        !zcl_story_graph_v1_root(episode->story, result->story_root) ||
        !experience_root_equal(result->story_root,
                               episode->focus->story_graph_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_STORY,
                               "graph is invalid or not the focused graph");
    if (vcs_zcode_focus_validate_for_context(
            episode->focus, episode->task, episode->agent_context,
            episode->claim_roots, episode->claim_count, true) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_root(episode->focus, result->focus_root) !=
            VCS_ZCODE_FOCUS_OK)
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_FOCUS,
                               "task, source, context, or generation moved");
    return ZCL_EXPERIENCE_COMPILATION_OK;
}

static enum zcl_experience_compilation_error experience_validate_observation(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *result, uint8_t *expected_outcome)
{
    uint8_t task_root[32];
    if ((episode->work_receipt->status != VCS_ZCODE_WORK_PASS &&
         episode->work_receipt->status != VCS_ZCODE_WORK_FAIL) ||
        vcs_zcode_task_root(episode->task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_verify(
            episode->work_receipt,
            episode->work_receipt->signer_pubkey) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(
            episode->work_receipt, result->receipt_root) != VCS_ZCODE_DEV_OK ||
        !experience_root_equal(task_root, episode->focus->task_root) ||
        !experience_root_equal(task_root,
                               episode->work_receipt->task_root) ||
        !experience_root_equal(episode->task->proof_policy_root,
                               episode->work_receipt->proof_policy_root) ||
        !experience_root_equal(episode->task->toolchain_capsule_root,
                         episode->work_receipt->toolchain_capsule_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_RECEIPT,
                               "signed work observation is stale or misbound");
    *expected_outcome = episode->work_receipt->status == VCS_ZCODE_WORK_PASS ?
        ZCL_ONTOLOGY_PROVED : ZCL_ONTOLOGY_DISPROVED;
    if (vcs_zcode_specialist_report_validate(
            episode->specialist_report) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_specialist_report_root(
            episode->specialist_report, result->report_root) !=
                VCS_ZCODE_FOCUS_OK ||
        episode->specialist_report->status != *expected_outcome ||
        !experience_root_equal(episode->specialist_report->focus_root,
                               result->focus_root) ||
        !experience_root_equal(episode->specialist_report->evidence_root,
                               result->receipt_root) ||
        !experience_root_equal(episode->specialist_report->result_root,
                               episode->work_receipt->output_root) ||
        !experience_root_equal(episode->specialist_report->specialist_root,
                               episode->work_receipt->signer_pubkey))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_REPORT,
                               "report does not describe the exact receipt");
    return ZCL_EXPERIENCE_COMPILATION_OK;
}

static enum zcl_experience_compilation_error experience_validate_lesson(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *result)
{
    if (episode->parent_count != episode->heuristic->parent_count ||
        vcs_zcode_attention_bid_verify_statement_with_lineage(
            episode->attention_bid, episode->heuristic, episode->parents,
            episode->parent_count, episode->focus, episode->statement,
            episode->local_acceptance->expected_signer) !=
                VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_heuristic_root(
            episode->heuristic, result->heuristic_root) !=
                VCS_ZCODE_ATTENTION_OK ||
        vcs_zcode_attention_bid_root(
            episode->attention_bid, result->bid_root) !=
                VCS_ZCODE_ATTENTION_OK ||
        !experience_root_equal(episode->heuristic->provenance_root,
                               result->receipt_root) ||
        !experience_root_equal(episode->attention_bid->evidence_root,
                               result->receipt_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_HEURISTIC,
                               "proposal, lineage, focus, or receipt moved");
    if (vcs_zcode_science_relation_set_root(
            episode->relations, result->relations_root) !=
                VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_statement_root(
            episode->statement, result->statement_root) !=
                VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_statement_validate_relations(
            episode->statement, episode->relations) !=
                VCS_ZCODE_SCIENCE_OK ||
        !experience_root_equal(episode->statement->relations_root,
                               result->relations_root) ||
        !experience_root_equal(episode->local_acceptance->heuristic_root,
                               result->heuristic_root) ||
        !experience_root_equal(
            episode->local_acceptance->anchor_statement_root,
            result->statement_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_SCIENCE,
                               "statement, relations, or anchor moved");
    return ZCL_EXPERIENCE_COMPILATION_OK;
}

static enum zcl_experience_compilation_error experience_capture(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *result)
{
    if (!experience_store_receipt(
            episode->workspace, episode->work_receipt, result->receipt_root) ||
        !experience_store_report(episode->workspace,
            episode->specialist_report, result->report_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_CAS,
                               "episode evidence did not round-trip");
    uint8_t stored_heuristic[32], stored_bid[32];
    if (vcs_zcode_attention_store_pair(
            episode->workspace, episode->heuristic, episode->attention_bid,
            stored_heuristic, stored_bid) != VCS_ZCODE_ATTENTION_OK ||
        !experience_root_equal(stored_heuristic, result->heuristic_root) ||
        !experience_root_equal(stored_bid, result->bid_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_CAS,
                               "heuristic and bid did not round-trip");
    if (!experience_store_science(
            episode->workspace, episode->relations, episode->statement,
            episode->local_acceptance->expected_signer,
            result->relations_root, result->statement_root))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_CAS,
                               "science evidence did not round-trip");
    return ZCL_EXPERIENCE_COMPILATION_OK;
}

static enum zcl_experience_compilation_error experience_select(
    const struct zcl_experience_episode_v1 *episode, uint8_t expected_outcome,
    struct zcl_experience_compilation_v1 *result)
{
    size_t selected = SIZE_MAX;
    struct vcs_zcode_attention_verified_report verified;
    enum vcs_zcode_attention_error attention_error =
        vcs_zcode_attention_frontier_next_verified_with_lineage_and_lifecycle(
            episode->workspace, episode->attention_bid, 1u,
            episode->heuristic, episode->parents, episode->parent_count,
            episode->statement, episode->local_acceptance, episode->focus,
            episode->attention_bid->priority_policy_root,
            episode->local_acceptance->local_policy_root,
            episode->attention_bid->bid_evaluator_root,
            episode->local_acceptance->expected_signer,
            &selected, 1u, &verified);
    if (attention_error != VCS_ZCODE_ATTENTION_OK)
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_ACCEPTANCE,
            vcs_zcode_attention_error_string(attention_error));
    struct vcs_zcode_heuristic_lifecycle_report lifecycle;
    if (vcs_zcode_heuristic_lifecycle_fold(
            episode->workspace, episode->local_acceptance, &lifecycle) !=
            VCS_ZCODE_ATTENTION_OK || !lifecycle.complete)
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_ACCEPTANCE,
                               "accepted lifecycle did not refold");
    result->captured = true;
    result->outcome = expected_outcome;
    result->lifecycle_status = lifecycle.status;
    result->lifecycle_reason = lifecycle.reason;
    memcpy(result->acceptance_snapshot_root, lifecycle.snapshot_root, 32);
    result->lesson_relevant =
        verified.choice.frontier.input_count == 1u &&
        verified.choice.frontier.frontier_count == 1u &&
        verified.choice.frontier.returned_count == 1u && selected == 0u;
    if (result->lesson_relevant) {
        memcpy(result->derived_rule_root,
               episode->heuristic->proposed_rule_root, 32);
        memcpy(result->expected_effect_root,
               episode->heuristic->expected_effect_root, 32);
    }
    return ZCL_EXPERIENCE_COMPILATION_OK;
}

const char *zcl_experience_compilation_error_string(
    enum zcl_experience_compilation_error error)
{
    switch (error) {
    case ZCL_EXPERIENCE_COMPILATION_OK: return "ok";
    case ZCL_EXPERIENCE_COMPILATION_NULL: return "null-or-empty-input";
    case ZCL_EXPERIENCE_COMPILATION_ALIAS: return "input-output-alias";
    case ZCL_EXPERIENCE_COMPILATION_STORY: return "story-binding-invalid";
    case ZCL_EXPERIENCE_COMPILATION_FOCUS: return "focus-binding-invalid";
    case ZCL_EXPERIENCE_COMPILATION_RECEIPT: return "receipt-invalid";
    case ZCL_EXPERIENCE_COMPILATION_REPORT: return "report-binding-invalid";
    case ZCL_EXPERIENCE_COMPILATION_HEURISTIC:
        return "heuristic-binding-invalid";
    case ZCL_EXPERIENCE_COMPILATION_SCIENCE:
        return "science-evidence-invalid";
    case ZCL_EXPERIENCE_COMPILATION_ACCEPTANCE:
        return "local-acceptance-invalid";
    case ZCL_EXPERIENCE_COMPILATION_CAS: return "cas-revalidation-failed";
    default: return "unknown";
    }
}

static enum zcl_experience_compilation_error experience_compile_checked(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *out)
{
    if (!out)
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_NULL,
                               "output absent");
    if (!episode) {
        memset(out, 0, sizeof(*out));
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_NULL,
                               "episode absent");
    }
    if (experience_memory_overlaps(out, sizeof(*out), episode,
                                   sizeof(*episode)))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_ALIAS,
                               "output overlaps episode shape");
    if (!episode->workspace || !episode->workspace[0]) {
        memset(out, 0, sizeof(*out));
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_NULL,
                               "workspace absent");
    }
    size_t workspace_bytes = 0;
    if (!experience_workspace_size(episode->workspace, &workspace_bytes)) {
        memset(out, 0, sizeof(*out));
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_NULL,
                               "workspace path is empty or unbounded");
    }
    if (!episode->story || !episode->task || !episode->agent_context ||
        !episode->focus || !episode->work_receipt ||
        !episode->specialist_report || !episode->heuristic ||
        !episode->attention_bid || !episode->relations ||
        !episode->statement || !episode->local_acceptance ||
        (episode->claim_count != 0 && !episode->claim_roots) ||
        (episode->parent_count != 0 && !episode->parents) ||
        (episode->parent_count == 0 && episode->parents)) {
        memset(out, 0, sizeof(*out));
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_NULL,
                               "required episode field absent");
    }
    if (episode->claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS ||
        episode->parent_count > VCS_ZCODE_HEURISTIC_MAX_PARENTS ||
        episode->story->event_count > ZCL_STORY_MAX_EVENTS) {
        memset(out, 0, sizeof(*out));
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_FOCUS,
                               "bounded episode count exceeded");
    }
    if (experience_output_aliases(episode, out, workspace_bytes))
        return experience_fail(ZCL_EXPERIENCE_COMPILATION_ALIAS,
                               "output overlaps episode input");
    memset(out, 0, sizeof(*out));

    struct zcl_experience_compilation_v1 result = {0};
    uint8_t expected_outcome = ZCL_ONTOLOGY_UNKNOWN;
    enum zcl_experience_compilation_error error =
        experience_validate_story_focus(episode, &result);
    if (error == ZCL_EXPERIENCE_COMPILATION_OK)
        error = experience_validate_observation(
            episode, &result, &expected_outcome);
    if (error == ZCL_EXPERIENCE_COMPILATION_OK)
        error = experience_validate_lesson(episode, &result);
    if (error == ZCL_EXPERIENCE_COMPILATION_OK)
        error = experience_capture(episode, &result);
    if (error == ZCL_EXPERIENCE_COMPILATION_OK)
        error = experience_select(episode, expected_outcome, &result);
    if (error != ZCL_EXPERIENCE_COMPILATION_OK) return error;
    *out = result;
    return ZCL_EXPERIENCE_COMPILATION_OK;
}

enum zcl_experience_compilation_error zcl_experience_compile(
    const struct zcl_experience_episode_v1 *episode,
    struct zcl_experience_compilation_v1 *out)
{
    return experience_compile_checked(episode, out);
}
