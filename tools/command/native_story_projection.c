/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: Project canonical ZCODE work facts into bounded StoryGraph events. */
#include "command/native_story_command.h"

#include "base/hex.h"
#include "sha3/sha3.h"
#include "vcs/zcode_app_run_observation.h"
#include "vcs/zcode_dev.h"

#include <string.h>

static bool story_decode(const char *hex, uint8_t out[32])
{
    memset(out, 0, 32);
    return hex && zcl_hex_decode_lower(hex, out, 32);
}

static bool story_nonempty(const char *value)
{
    return value && value[0];
}

static void story_projection_root(const uint8_t task[32], uint8_t kind,
                                  uint8_t out[32])
{
    static const char domain[] = "zcl.story.zcode_projection_event.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, task, 32);
    sha3_256_write(&sha, &kind, 1);
    sha3_256_finalize(&sha, out);
}

static enum zcl_ontology_status story_result_status(const char *result,
                                                     bool test)
{
    if (!story_nonempty(result) || strcmp(result, "unknown") == 0 ||
        strcmp(result, "not_started") == 0 ||
        (test && strcmp(result, "not_required") == 0))
        return ZCL_ONTOLOGY_UNKNOWN;
    if (strcmp(result, "passed") == 0 ||
        (test && strcmp(result, "passed_declared_tests") == 0))
        return ZCL_ONTOLOGY_PROVED;
    if (strcmp(result, "failed") == 0 ||
        (test && strcmp(result, "failed_or_not_reached") == 0))
        return ZCL_ONTOLOGY_DISPROVED;
    return ZCL_ONTOLOGY_INCOMPLETE;
}

static void story_pick_root(const uint8_t preferred[32],
                            const uint8_t fallback[32], uint8_t out[32])
{
    const uint8_t *chosen = preferred;
    bool nonzero = false;
    for (size_t i = 0; i < 32; i++) nonzero |= preferred[i] != 0;
    if (!nonzero) chosen = fallback;
    if (chosen != out) memcpy(out, chosen, 32);
}

static void story_fill_event(struct zcl_story_event_v1 *event, uint8_t kind,
                             enum zcl_ontology_status status,
                             const uint8_t universe[32],
                             const uint8_t context[32],
                             const uint8_t scene[32],
                             const uint8_t entity[32],
                             const uint8_t action[32],
                             const uint8_t evidence[32],
                             const uint8_t prior_event[32])
{
    memset(event, 0, sizeof(*event));
    event->schema_version = ZCL_STORY_GRAPH_VERSION;
    event->kind = kind;
    event->status = (uint8_t)status;
    memcpy(event->universe_root, universe, 32);
    memcpy(event->context_root, context, 32);
    memcpy(event->scene_root, scene, 32);
    memcpy(event->entity_root, entity, 32);
    memcpy(event->action_root, action, 32);
    memcpy(event->evidence_root, evidence, 32);
    story_projection_root(context, kind, event->event_root);
    if (prior_event) memcpy(event->cause_event_root, prior_event, 32);
}

bool zcl_story_graph_from_work_facts(
    const struct zcl_story_work_facts_v1 *facts,
    struct zcl_story_event_v1 events[7],
    struct zcl_story_graph_v1 *graph)
{
    if (!facts || !events || !graph) return false;
    uint8_t task[32], source[32], goal[32], agent_context[32];
    uint8_t candidate[32], candidate_source[32], patch[32], action[32];
    uint8_t receipt[32], output[32], lane[32], accepted_work[32];
    uint8_t proof_set[32];
    uint8_t proof_action[32], build_output[32];
    uint8_t app_receipt[32], app_observation[32], app_artifact[32];
    uint8_t app_invocation[32], app_action[32];
    if (!story_decode(facts->task_root, task) ||
        !story_decode(facts->source_root, source) ||
        !story_decode(facts->goal_root, goal))
        return false;
    bool have_context = story_decode(facts->agent_context_root, agent_context);
    bool have_candidate = story_decode(facts->candidate_root, candidate);
    bool have_candidate_source = story_decode(
        facts->candidate_source_root, candidate_source);
    bool have_patch = story_decode(facts->patch_root, patch);
    (void)story_decode(facts->action_root, action);
    (void)story_decode(facts->work_receipt_root, receipt);
    (void)story_decode(facts->output_root, output);
    bool have_proof_action = story_decode(
        facts->proof_action_root, proof_action);
    bool have_build_output = story_decode(
        facts->build_output_root, build_output);
    bool have_app_receipt = story_decode(
        facts->app_run_receipt_root, app_receipt);
    bool have_app_observation = story_decode(
        facts->app_run_observation_root, app_observation);
    bool have_app_artifact = story_decode(
        facts->app_run_artifact_root, app_artifact);
    bool have_app_invocation = story_decode(
        facts->app_run_invocation_root, app_invocation);
    bool have_app_action = story_decode(
        facts->app_run_action_root, app_action);
    bool have_lane = story_decode(facts->lane_receipt_root, lane);
    bool have_accepted_work = story_decode(
        facts->accepted_work_root, accepted_work);
    bool have_proof_set = story_decode(facts->proof_set_root, proof_set);
    uint8_t scene[32], relation[32], evidence[32];

    story_fill_event(&events[0], ZCL_STORY_EVENT_USER_ASKS,
                     ZCL_ONTOLOGY_PROVED, source, task, source, task, goal,
                     task, NULL);

    story_pick_root(agent_context, source, scene);
    story_pick_root(agent_context, goal, relation);
    story_pick_root(agent_context, task, evidence);
    enum zcl_ontology_status context_status = facts->agent_context_ambiguous
        ? ZCL_ONTOLOGY_INCOMPLETE
        : have_context ? ZCL_ONTOLOGY_PROVED : ZCL_ONTOLOGY_UNKNOWN;
    story_fill_event(&events[1], ZCL_STORY_EVENT_AGENT_FINDS_CODE,
                     context_status, source, task, scene, task, relation,
                     evidence, events[0].event_root);

    story_pick_root(candidate_source, source, scene);
    story_pick_root(patch, candidate, relation);
    story_pick_root(candidate, task, evidence);
    enum zcl_ontology_status edit_status =
        have_candidate && have_candidate_source && have_patch
            ? ZCL_ONTOLOGY_PROVED
            : have_candidate || have_candidate_source || have_patch
                ? ZCL_ONTOLOGY_INCOMPLETE : ZCL_ONTOLOGY_UNKNOWN;
    story_fill_event(&events[2], ZCL_STORY_EVENT_AGENT_EDITS, edit_status,
                     source, task, scene, task, relation, evidence,
                     events[1].event_root);

    story_pick_root(build_output, candidate_source, scene);
    story_pick_root(scene, source, scene);
    story_pick_root(proof_action, action, relation);
    story_pick_root(relation, task, relation);
    story_pick_root(proof_set, receipt, evidence);
    story_pick_root(evidence, task, evidence);
    enum zcl_ontology_status build_status = story_result_status(
        facts->build_result, false);
    if (build_status == ZCL_ONTOLOGY_PROVED &&
        (!have_proof_action || !have_build_output || !have_proof_set))
        build_status = ZCL_ONTOLOGY_INCOMPLETE;
    story_fill_event(&events[3], ZCL_STORY_EVENT_BUILD_COMPLETES,
                     build_status, source, task, scene, task, relation,
                     evidence, events[2].event_root);

    story_pick_root(build_output, candidate_source, scene);
    story_pick_root(scene, source, scene);
    story_pick_root(proof_action, action, relation);
    story_pick_root(relation, task, relation);
    story_pick_root(proof_set, receipt, evidence);
    story_pick_root(evidence, task, evidence);
    enum zcl_ontology_status test_status = story_result_status(
        facts->test_result, true);
    if (test_status == ZCL_ONTOLOGY_PROVED &&
        (!have_proof_set || !have_proof_action))
        test_status = ZCL_ONTOLOGY_INCOMPLETE;
    story_fill_event(&events[4], ZCL_STORY_EVENT_TEST_COMPLETES, test_status,
                     source, task, scene, task, relation, evidence,
                     events[3].event_root);

    story_pick_root(app_artifact, output, scene);
    story_pick_root(scene, candidate_source, scene);
    story_pick_root(scene, source, scene);
    story_pick_root(app_invocation, app_action, relation);
    story_pick_root(relation, output, relation);
    story_pick_root(relation, action, relation);
    story_pick_root(relation, task, relation);
    story_pick_root(app_observation, app_receipt, evidence);
    story_pick_root(evidence, task, evidence);
    enum zcl_ontology_status app_status = ZCL_ONTOLOGY_UNKNOWN;
    bool app_roots_complete = have_app_receipt && have_app_observation &&
        have_app_artifact && have_app_invocation && have_app_action;
    bool app_flags_complete =
        (facts->app_run_flags & VCS_ZCODE_APP_RUN_PROVED_FLAGS) ==
        VCS_ZCODE_APP_RUN_PROVED_FLAGS;
    if (facts->app_run_receipt_count > 0) {
        if (facts->valid_app_run_receipt_count == 0 ||
            facts->valid_app_run_receipt_count >
                facts->app_run_receipt_count ||
            !app_roots_complete)
            app_status = ZCL_ONTOLOGY_INCOMPLETE;
        else if (facts->app_run_status == VCS_ZCODE_WORK_PASS &&
                 facts->app_run_exit_status == 0 && app_flags_complete)
            app_status = ZCL_ONTOLOGY_PROVED;
        else if (facts->app_run_status == VCS_ZCODE_WORK_FAIL &&
                 (facts->app_run_flags & VCS_ZCODE_APP_RUN_LAUNCHED) != 0)
            app_status = ZCL_ONTOLOGY_DISPROVED;
        else
            app_status = ZCL_ONTOLOGY_INCOMPLETE;
    }
    story_fill_event(&events[5], ZCL_STORY_EVENT_APP_RUNS,
                     app_status, source, task, scene, task,
                     relation, evidence, events[4].event_root);

    story_pick_root(accepted_work, lane, scene);
    story_pick_root(scene, proof_set, scene);
    story_pick_root(scene, task, scene);
    story_pick_root(accepted_work, lane, relation);
    story_pick_root(relation, proof_set, relation);
    story_pick_root(relation, task, relation);
    story_pick_root(accepted_work, lane, evidence);
    story_pick_root(evidence, task, evidence);
    bool state_proven = facts->state && strcmp(facts->state, "PROVEN") == 0;
    bool acceptance_bound = have_lane && have_accepted_work &&
        memcmp(lane, accepted_work, 32) == 0;
    enum zcl_ontology_status accept_status = state_proven && acceptance_bound
        ? ZCL_ONTOLOGY_PROVED
        : state_proven || have_lane || have_accepted_work
            ? ZCL_ONTOLOGY_INCOMPLETE : ZCL_ONTOLOGY_UNKNOWN;
    /* The two receipts remain valid facts independently, but an observation
     * that finishes after acceptance cannot prove the projected causal edge.
     * Missing time evidence also fails closed once app_runs itself is PROVED. */
    if (accept_status == ZCL_ONTOLOGY_PROVED &&
        app_status == ZCL_ONTOLOGY_PROVED &&
        (facts->app_run_finished_unix <= 0 ||
         facts->lane_created_unix <= 0 ||
         facts->app_run_finished_unix > facts->lane_created_unix))
        accept_status = ZCL_ONTOLOGY_INCOMPLETE;
    story_fill_event(&events[6], ZCL_STORY_EVENT_USER_ACCEPTS, accept_status,
                     source, task, scene, task, relation, evidence,
                     events[5].event_root);

    memset(graph, 0, sizeof(*graph));
    graph->schema_version = ZCL_STORY_GRAPH_VERSION;
    graph->event_count = 7;
    graph->events = events;
    return zcl_story_graph_v1_validate(graph);
}
