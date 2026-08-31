/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Explain canonical development work as a bounded causal story. */
#include "command/native_story_command.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include "vcs/zcode_app_run_observation.h"
#include "vcs/zcode_dev.h"

#include <stdint.h>
#include <stdio.h>
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

static const char *story_input_string(const struct json_value *input,
                                      const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static const char *story_object_string(const struct json_value *object,
                                       const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : "";
}

static bool story_object_bool(const struct json_value *object,
                              const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static int64_t story_object_int(const struct json_value *object,
                                const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : 0;
}

static const char *story_status_name(enum zcl_ontology_status status)
{
    switch (status) {
    case ZCL_ONTOLOGY_PROVED: return "PROVED";
    case ZCL_ONTOLOGY_DISPROVED: return "DISPROVED";
    case ZCL_ONTOLOGY_BOTH: return "BOTH";
    case ZCL_ONTOLOGY_UNKNOWN: return "UNKNOWN";
    case ZCL_ONTOLOGY_INCOMPLETE: return "INCOMPLETE";
    default: return "INCOMPLETE";
    }
}

static void story_fail(struct zcl_command_reply *reply, const char *code,
                       const char *phase, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, "canonical ZCODE objects");
}

struct story_loaded_graph {
    struct zcl_story_event_v1 events[7];
    struct zcl_story_graph_v1 graph;
    struct zcl_story_show_v1 show;
};

static bool story_load_work(const struct zcl_command_request *request,
                            const char *workspace, const char *work,
                            const char *datadir,
                            struct story_loaded_graph *loaded,
                            struct zcl_command_reply *reply)
{
    if (!work || !work[0]) {
        story_fail(reply, "STORY_WORK_REQUIRED", "resolve",
                   "story projection requires one exact work id or task-root prefix");
        return false;
    }
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool input_ok = json_push_kv_str(&input, "workspace",
                                     workspace && workspace[0]
                                         ? workspace : ".") &&
                    json_push_kv_str(&input, "work", work) &&
                    (!datadir || !datadir[0] ||
                     json_push_kv_str(&input, "datadir", datadir)) &&
                    json_push_kv_bool(&input, "details", true);
    if (!input_ok) {
        json_free(&input);
        story_fail(reply, "STORY_INPUT_FAILED", "compose",
                   "canonical work-status input could not be composed");
        return false;
    }
    struct zcl_command_reply nested;
    zcl_command_reply_init(&nested, "zcl.zcode_work_status.v1");
    struct zcl_command_request nested_request = {
        .context = request ? request->context : NULL,
        .input = &input,
    };
    zcl_native_handle_zcode_work_status(&nested_request, &nested);
    json_free(&input);
    if (nested.status != ZCL_COMMAND_STATUS_PASSED) {
        zcl_command_reply_fail(
            reply, nested.status, nested.exit_code,
            nested.error.code[0] ? nested.error.code : "STORY_SOURCE_FAILED",
            nested.error.phase[0] ? nested.error.phase : "project",
            nested.error.retryable, false,
            nested.error.message[0] ? nested.error.message
                                    : "canonical work status is unavailable",
            nested.error.evidence[0] ? nested.error.evidence
                                     : "zcode.work.status");
        zcl_command_reply_free(&nested);
        return false;
    }
    const struct json_value *expert = json_get(&nested.data, "expert");
    struct zcl_story_work_facts_v1 facts = {
        .state = story_object_string(&nested.data, "state"),
        .build_result = story_object_string(&nested.data, "build_result"),
        .test_result = story_object_string(&nested.data, "test_result"),
        .task_root = story_object_string(expert, "task_root"),
        .source_root = story_object_string(expert, "source_root"),
        .goal_root = story_object_string(expert, "goal_root"),
        .agent_context_root = story_object_string(expert,
                                                   "agent_context_root"),
        .agent_context_ambiguous = story_object_bool(
            expert, "agent_context_ambiguous"),
        .candidate_root = story_object_string(expert, "candidate_root"),
        .candidate_source_root = story_object_string(
            expert, "candidate_source_root"),
        .patch_root = story_object_string(expert, "patch_root"),
        .action_root = story_object_string(expert, "action_id"),
        .work_receipt_root = story_object_string(expert,
                                                  "work_receipt_root"),
        .output_root = story_object_string(expert, "output_root"),
        .proof_action_root = story_object_string(
            expert, "proof_action_root"),
        .build_output_root = story_object_string(
            expert, "build_output_root"),
        .app_run_receipt_count = (uint32_t)story_object_int(
            expert, "app_run_receipt_count"),
        .valid_app_run_receipt_count = (uint32_t)story_object_int(
            expert, "valid_app_run_receipt_count"),
        .app_run_receipt_root = story_object_string(
            expert, "app_run_receipt_root"),
        .app_run_observation_root = story_object_string(
            expert, "app_run_observation_root"),
        .app_run_artifact_root = story_object_string(
            expert, "app_run_artifact_root"),
        .app_run_invocation_root = story_object_string(
            expert, "app_run_invocation_root"),
        .app_run_action_root = story_object_string(
            expert, "app_run_action_root"),
        .app_run_flags = (uint16_t)story_object_int(
            expert, "app_run_flags"),
        .app_run_status = (uint8_t)story_object_int(
            expert, "app_run_status"),
        .app_run_exit_status = (int32_t)story_object_int(
            expert, "app_run_exit_status"),
        .app_run_finished_unix = story_object_int(
            expert, "app_run_finished_unix"),
        .lane_receipt_root = story_object_string(expert,
                                                  "lane_receipt_root"),
        .accepted_work_root = story_object_string(expert,
                                                   "accepted_work_root"),
        .lane_created_unix = story_object_int(expert,
                                               "lane_created_unix"),
        .proof_set_root = story_object_string(expert, "proof_set_root"),
    };
    bool ok = zcl_story_graph_from_work_facts(
                  &facts, loaded->events, &loaded->graph) &&
              zcl_story_show_v1_build(&loaded->graph, &loaded->show);
    zcl_command_reply_free(&nested);
    if (!ok)
        story_fail(reply, "STORY_FACTS_INVALID", "project",
                   "reverified work status did not contain the rooted facts required by StoryGraph");
    return ok;
}

static bool story_push_root(struct json_value *object, const char *key,
                            const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    return json_push_kv_str(object, key, hex);
}

static bool story_push_event(struct json_value *array,
                             const struct zcl_story_event_v1 *event,
                             bool full)
{
    struct json_value row;
    json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(
                  &row, "relation", zcl_story_event_kind_name(event->kind)) &&
              json_push_kv_str(
                  &row, "status", story_status_name(event->status)) &&
              (!full || (story_push_root(
                              &row, "universe_root", event->universe_root) &&
                          story_push_root(
                              &row, "context_root", event->context_root) &&
                          story_push_root(
                              &row, "entity_root", event->entity_root))) &&
              story_push_root(&row, "scene_root", event->scene_root) &&
              story_push_root(&row, "action_root", event->action_root) &&
              story_push_root(&row, "event_root", event->event_root) &&
              story_push_root(&row, "evidence_root", event->evidence_root) &&
              story_push_root(&row, "cause_event_root",
                              event->cause_event_root) &&
              json_push_back(array, &row);
    json_free(&row);
    return ok;
}

static bool story_push_relation_names(struct json_value *object,
                                      const char *key,
                                      const struct zcl_story_graph_v1 *graph,
                                      enum zcl_ontology_status status)
{
    struct json_value names;
    json_init(&names); json_set_array(&names);
    bool ok = true;
    for (size_t i = 0; ok && i < graph->event_count; i++) {
        if (graph->events[i].status != status) continue;
        struct json_value name;
        json_init(&name);
        json_set_str(&name, zcl_story_event_kind_name(graph->events[i].kind));
        ok = json_push_back(&names, &name);
        json_free(&name);
    }
    if (ok) ok = json_push_kv(object, key, &names);
    json_free(&names);
    return ok;
}

static bool story_render_show(struct zcl_command_reply *reply,
                              const struct story_loaded_graph *loaded,
                              bool full)
{
    struct json_value events;
    json_init(&events); json_set_array(&events);
    bool ok = true;
    for (size_t i = 0; ok && i < loaded->graph.event_count; i++)
        ok = story_push_event(&events, &loaded->events[i], full);
    const char *largest_missing = "none";
    for (size_t i = 0; i < loaded->graph.event_count; i++)
        if (loaded->events[i].status != ZCL_ONTOLOGY_PROVED) {
            largest_missing = zcl_story_event_kind_name(
                loaded->events[i].kind);
            break;
        }
    bool app_missing = strcmp(largest_missing, "app_runs") == 0;
    const char *app_next = loaded->events[5].status ==
            ZCL_ONTOLOGY_INCOMPLETE
        ? "restore or repair the nested app-run observation and its exact build-receipt binding"
        : loaded->events[5].status == ZCL_ONTOLOGY_DISPROVED
        ? "inspect the exact app-run observation and repair the application before recording another run"
        : "capture one canonical receipt that binds the exact built application to its observed execution";
    ok = ok &&
        json_push_kv_str(&reply->data, "status",
                         story_status_name(loaded->show.status)) &&
        json_push_kv_bool(&reply->data, "complete", loaded->show.complete) &&
        story_push_root(&reply->data, "story_root",
                        loaded->show.story_root) &&
        story_push_root(&reply->data, "universe_root",
                        loaded->show.universe_root) &&
        json_push_kv_str(&reply->data, "universe_root_domain",
                         "zcl.zcode.task.source_root") &&
        story_push_root(&reply->data, "context_root",
                        loaded->show.context_root) &&
        story_push_root(&reply->data, "scene_root",
                        loaded->show.scene_root) &&
        json_push_kv(&reply->data, "events", &events) &&
        story_push_relation_names(&reply->data, "unknown_relations",
                                  &loaded->graph, ZCL_ONTOLOGY_UNKNOWN) &&
        story_push_relation_names(&reply->data, "incomplete_relations",
                                  &loaded->graph, ZCL_ONTOLOGY_INCOMPLETE) &&
        story_push_relation_names(&reply->data, "disproved_relations",
                                  &loaded->graph, ZCL_ONTOLOGY_DISPROVED) &&
        json_push_kv_str(&reply->data, "authority",
                         "canonical_zcode_readonly_projection") &&
        json_push_kv_bool(&reply->data, "stored", false) &&
        json_push_kv_str(&reply->data, "truth_system",
                         "zcl.ontology.status") &&
        json_push_kv_str(&reply->data, "largest_missing_relation",
                         largest_missing) &&
        json_push_kv_str(&reply->data, "next_action",
                         app_missing ? app_next
                         : strcmp(largest_missing, "none") == 0
                             ? "inspect story why for the complete causal chain"
                             : "inspect story why for the first non-PROVED causal relation");
    json_free(&events);
    return ok;
}

void zcl_native_handle_story_show(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct story_loaded_graph loaded;
    if (!story_load_work(request,
                         story_input_string(request->input, "workspace"),
                         story_input_string(request->input, "work"),
                         story_input_string(request->input, "datadir"),
                         &loaded, reply))
        return;
    bool full = request->view && strcmp(request->view, "full") == 0;
    if (!story_render_show(reply, &loaded, full))
        story_fail(reply, "STORY_OUTPUT_FAILED", "render",
                   "bounded story view could not be rendered");
}

static const struct zcl_story_event_v1 *story_find_kind(
    const struct zcl_story_graph_v1 *graph, const char *name)
{
    for (size_t i = 0; graph && name && i < graph->event_count; i++)
        if (strcmp(zcl_story_event_kind_name(graph->events[i].kind), name) == 0)
            return &graph->events[i];
    return NULL;
}

static const struct zcl_story_event_v1 *story_find_root(
    const struct zcl_story_graph_v1 *graph, const uint8_t root[32])
{
    for (size_t i = 0; graph && i < graph->event_count; i++)
        if (memcmp(graph->events[i].event_root, root, 32) == 0)
            return &graph->events[i];
    return NULL;
}

void zcl_native_handle_story_why(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct story_loaded_graph loaded;
    if (!story_load_work(request,
                         story_input_string(request->input, "workspace"),
                         story_input_string(request->input, "work"),
                         story_input_string(request->input, "datadir"),
                         &loaded, reply))
        return;
    const char *target = story_input_string(request->input, "event");
    const struct zcl_story_event_v1 *named = story_find_kind(
        &loaded.graph, target);
    uint8_t target_root[32];
    if (named) memcpy(target_root, named->event_root, 32);
    else if (!story_decode(target, target_root)) {
        story_fail(reply, "STORY_EVENT_INVALID", "resolve",
                   "event must be a development relation name or exact 64-hex event root");
        return;
    }
    struct zcl_story_why_v1 why;
    if (!zcl_story_why_v1_build(&loaded.graph, target_root, &why)) {
        story_fail(reply, "STORY_WHY_FAILED", "query",
                   "causal query could not be evaluated over the rooted story");
        return;
    }
    struct json_value chain;
    json_init(&chain); json_set_array(&chain);
    bool ok = true;
    for (size_t i = 0; ok && i < why.cause_count; i++) {
        const struct zcl_story_event_v1 *event = story_find_root(
            &loaded.graph, why.cause_event_roots[i]);
        if (!event) { ok = false; break; }
        bool full = request->view && strcmp(request->view, "full") == 0;
        ok = story_push_event(&chain, event, full);
    }
    ok = ok && json_push_kv_str(&reply->data, "status",
                                 story_status_name(why.status)) &&
         json_push_kv_bool(&reply->data, "complete", why.complete) &&
         story_push_root(&reply->data, "story_root", why.story_root) &&
         story_push_root(&reply->data, "target_event_root",
                         why.target_event_root) &&
         json_push_kv_bool(&reply->data, "target_unknown",
                           why.target_unknown) &&
         json_push_kv_bool(&reply->data, "missing_cause",
                           why.missing_cause) &&
         json_push_kv_bool(&reply->data, "cycle_detected",
                           why.cycle_detected) &&
         json_push_kv(&reply->data, "causal_chain", &chain) &&
         json_push_kv_str(&reply->data, "authority",
                          "canonical_zcode_readonly_projection");
    json_free(&chain);
    if (!ok)
        story_fail(reply, "STORY_WHY_OUTPUT_FAILED", "render",
                   "bounded causal explanation could not be rendered");
}

static bool story_push_root_list(struct json_value *object, const char *key,
                                 uint8_t roots[][32], size_t count)
{
    struct json_value values;
    json_init(&values); json_set_array(&values);
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        char hex[65];
        zcl_hex_encode(roots[i], 32, hex);
        struct json_value value;
        json_init(&value); json_set_str(&value, hex);
        ok = json_push_back(&values, &value);
        json_free(&value);
    }
    if (ok) ok = json_push_kv(object, key, &values);
    json_free(&values);
    return ok;
}

void zcl_native_handle_story_diff(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = story_input_string(request->input, "workspace");
    const char *datadir = story_input_string(request->input, "datadir");
    struct story_loaded_graph before, after;
    if (!story_load_work(request, workspace,
                         story_input_string(request->input, "before"),
                         datadir, &before, reply) ||
        !story_load_work(request, workspace,
                         story_input_string(request->input, "after"),
                         datadir, &after, reply))
        return;
    struct zcl_story_diff_v1 diff;
    if (!zcl_story_diff_v1_build(&before.graph, &after.graph, &diff)) {
        story_fail(reply, "STORY_DIFF_FAILED", "compare",
                   "rooted story comparison could not be evaluated");
        return;
    }
    bool ok = json_push_kv_str(&reply->data, "status",
                               story_status_name(diff.status)) &&
        json_push_kv_bool(&reply->data, "complete", diff.complete) &&
        story_push_root(&reply->data, "before_story_root",
                        diff.before_story_root) &&
        story_push_root(&reply->data, "after_story_root",
                        diff.after_story_root) &&
        story_push_root_list(&reply->data, "added_event_roots",
                             diff.added_event_roots, diff.added_count) &&
        story_push_root_list(&reply->data, "removed_event_roots",
                             diff.removed_event_roots, diff.removed_count) &&
        story_push_root_list(&reply->data, "changed_event_roots",
                             diff.changed_event_roots, diff.changed_count) &&
        json_push_kv_str(&reply->data, "before_status",
                         story_status_name(before.show.status)) &&
        json_push_kv_str(&reply->data, "after_status",
                         story_status_name(after.show.status)) &&
        json_push_kv_str(&reply->data, "authority",
                         "canonical_zcode_readonly_projection");
    if (!ok)
        story_fail(reply, "STORY_DIFF_OUTPUT_FAILED", "render",
                   "bounded story difference could not be rendered");
}
