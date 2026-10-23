/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Explain canonical development work as a bounded causal story. */
#include "command/native_story_command.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "command/native_story_internal.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "vcs/vcs_manifest.h"
#include "vcs/zcode_focus.h"

#include <stdint.h>
#include <string.h>

static const char *story_input_string(const struct json_value *input,
                                      const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
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

static const char *story_largest_missing(
    const struct zcl_story_graph_v1 *graph)
{
    for (size_t i = 0; graph && i < graph->event_count; i++)
        if (graph->events[i].status != ZCL_ONTOLOGY_PROVED)
            return zcl_story_event_kind_name(graph->events[i].kind);
    return "none";
}

static enum zcl_ontology_status story_proof_status(
    enum zcl_ontology_status build, enum zcl_ontology_status test)
{
    if (build == ZCL_ONTOLOGY_BOTH || test == ZCL_ONTOLOGY_BOTH)
        return ZCL_ONTOLOGY_INCOMPLETE;
    if (build == ZCL_ONTOLOGY_DISPROVED || test == ZCL_ONTOLOGY_DISPROVED)
        return ZCL_ONTOLOGY_DISPROVED;
    if (build == ZCL_ONTOLOGY_INCOMPLETE || test == ZCL_ONTOLOGY_INCOMPLETE)
        return ZCL_ONTOLOGY_INCOMPLETE;
    if (build == ZCL_ONTOLOGY_UNKNOWN || test == ZCL_ONTOLOGY_UNKNOWN)
        return ZCL_ONTOLOGY_UNKNOWN;
    return ZCL_ONTOLOGY_PROVED;
}

void story_journey_build(
    const struct story_loaded_work *loaded,
    struct story_journey_stage out[STORY_JOURNEY_STAGE_COUNT])
{
    if (!loaded || !out) return;
    const struct zcl_story_event_v1 *event = loaded->events;
    const enum zcl_ontology_status proof = story_proof_status(
        event[3].status, event[4].status);
    const struct story_journey_stage stages[STORY_JOURNEY_STAGE_COUNT] = {
        { "describe", "user", event[0].status, "user_asks",
          "canonical_task_goal_relation", "", false },
        { "reuse", "retrieval", event[1].status, "agent_finds_code",
          "context_and_reuse_relation", "story.focus", true },
        { "need", "user", ZCL_ONTOLOGY_UNKNOWN, "",
          "no_canonical_need_object", "", false },
        { "job", "code", event[0].status, "user_asks",
          "canonical_task_relation", "story.focus", true },
        { "candidate", "code", event[2].status, "agent_edits",
          "candidate_patch_relation", "zcode.work.run", true },
        { "proof", "proof", proof,
          "builds,tests", "build_and_declared_test_relations",
          "zcode.package.dev.evidence", true },
        { "reproduce", "platform", ZCL_ONTOLOGY_UNKNOWN, "",
          "reproduction_authority_not_inspected_by_story_show",
          "", false },
        { "accept", "user", event[6].status, "user_accepts",
          "user_acceptance_relation", "zcode.work.accept", true },
        { "use", "integration", ZCL_ONTOLOGY_UNKNOWN, "",
          "post_acceptance_use_authority_not_inspected_by_story_show",
          "", false },
    };
    memcpy(out, stages, sizeof(stages));
}

const struct story_journey_stage *story_journey_next(
    const struct story_journey_stage stages[STORY_JOURNEY_STAGE_COUNT])
{
    for (size_t i = 0; i < STORY_JOURNEY_STAGE_COUNT; i++)
        if (stages[i].actionable &&
            stages[i].status != ZCL_ONTOLOGY_PROVED)
            return &stages[i];
    return NULL;
}

static bool story_push_authority(struct json_value *object)
{
    return json_push_kv_str(object, "authority",
                            "canonical_zcode_readonly_projection");
}

static bool story_push_readonly_projection(struct json_value *object)
{
    return story_push_authority(object) &&
        json_push_kv_bool(object, "stored", false) &&
        json_push_kv_str(object, "truth_system", "zcl.ontology.status");
}

static bool story_request_full_view(const struct zcl_command_request *request)
{
    return request->view && strcmp(request->view, "full") == 0;
}

static const struct zcl_command_registry *story_journey_registry(
    const struct zcl_command_request *request)
{
    return request && request->context && request->context->registry
        ? request->context->registry : zcl_command_catalog();
}

static bool story_journey_stage_hint_ready(
    const struct zcl_command_registry *registry,
    const struct story_journey_stage *stage)
{
    if (!stage->next_command[0]) return true;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        registry, stage->next_command, NULL);
    return spec != NULL && spec->availability == ZCL_COMMAND_READY;
}

static bool story_push_journey_row(struct json_value *journey,
                                   const struct story_journey_stage *stage)
{
    struct json_value row;
    json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "stage", stage->stage) &&
        json_push_kv_str(&row, "role", stage->role) &&
        json_push_kv_str(&row, "status",
                         story_status_name(stage->status)) &&
        json_push_kv_str(&row, "reason", stage->reason) &&
        json_push_kv_str(&row, "evidence_event",
                         stage->evidence_event) &&
        json_push_kv_str(&row, "command_hint", stage->next_command) &&
        json_push_kv_bool(&row, "actionable", stage->actionable) &&
        json_push_back(journey, &row);
    json_free(&row);
    return ok;
}

static bool story_journey_inspection_required(
    const struct story_journey_stage stages[STORY_JOURNEY_STAGE_COUNT])
{
    bool required = false;
    for (size_t i = 0; i < STORY_JOURNEY_STAGE_COUNT; i++)
        required = required ||
            (!stages[i].actionable &&
             stages[i].status != ZCL_ONTOLOGY_PROVED);
    return required;
}

static const char *story_journey_next_stage_name(
    const struct story_journey_stage *next, bool inspection_required)
{
    if (next) return next->stage;
    return inspection_required ? "inspection_required" : "complete";
}

static bool story_push_journey(
    const struct zcl_command_request *request,
    const struct story_loaded_work *loaded,
    struct json_value *object)
{
    struct story_journey_stage stages[STORY_JOURNEY_STAGE_COUNT];
    story_journey_build(loaded, stages);
    const struct zcl_command_registry *registry =
        story_journey_registry(request);
    struct json_value journey;
    json_init(&journey); json_set_array(&journey);
    bool ok = true;
    bool hints_registered_available = true;
    for (size_t i = 0; ok && i < STORY_JOURNEY_STAGE_COUNT; i++) {
        hints_registered_available = hints_registered_available &&
            story_journey_stage_hint_ready(registry, &stages[i]);
        ok = story_push_journey_row(&journey, &stages[i]);
    }
    const struct story_journey_stage *next = story_journey_next(stages);
    bool inspection_required = story_journey_inspection_required(stages);
    if (ok) ok = json_push_kv(object, "journey", &journey) &&
        json_push_kv_bool(object,
                          "journey_command_hints_registered_available",
                          hints_registered_available) &&
        json_push_kv_str(object, "journey_next_command_hint",
                         next ? next->next_command : "") &&
        json_push_kv_str(object, "journey_next_stage",
                         story_journey_next_stage_name(
                             next, inspection_required)) &&
        json_push_kv_bool(object, "journey_actionable_complete", next == NULL) &&
        json_push_kv_bool(object, "journey_inspection_required",
                          inspection_required);
    json_free(&journey);
    return ok;
}

static bool story_push_show_events(struct json_value *events,
                                   const struct story_loaded_work *loaded,
                                   bool full)
{
    bool ok = true;
    for (size_t i = 0; ok && i < loaded->graph.event_count; i++)
        ok = story_push_event(events, &loaded->events[i], full);
    return ok;
}

static bool story_push_show_header(struct zcl_command_reply *reply,
                                   const struct story_loaded_work *loaded)
{
    return json_push_kv_str(&reply->data, "status",
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
                        loaded->show.scene_root);
}

static bool story_push_open_relations(struct json_value *object,
                                      const struct zcl_story_graph_v1 *graph)
{
    return story_push_relation_names(object, "unknown_relations", graph,
                                     ZCL_ONTOLOGY_UNKNOWN) &&
        story_push_relation_names(object, "incomplete_relations", graph,
                                  ZCL_ONTOLOGY_INCOMPLETE) &&
        story_push_relation_names(object, "disproved_relations", graph,
                                  ZCL_ONTOLOGY_DISPROVED);
}

static bool story_push_show_footer(struct zcl_command_reply *reply,
                                   const char *largest_missing,
                                   const char *next_action)
{
    return story_push_readonly_projection(&reply->data) &&
        json_push_kv_str(&reply->data, "largest_missing_relation",
                         largest_missing) &&
        json_push_kv_str(&reply->data, "next_action", next_action);
}

static const char *story_app_next_action(enum zcl_ontology_status status)
{
    return status == ZCL_ONTOLOGY_INCOMPLETE
        ? "restore or repair the nested app-run observation and its exact build-receipt binding"
        : status == ZCL_ONTOLOGY_DISPROVED
        ? "inspect the exact app-run observation and repair the application before recording another run"
        : "capture one canonical receipt that binds the exact built application to its observed execution";
}

static const char *story_show_next_action(
    const struct story_loaded_work *loaded, const char *largest_missing)
{
    const char *app_next = story_app_next_action(loaded->events[5].status);
    if (strcmp(largest_missing, "app_runs") == 0) return app_next;
    return strcmp(largest_missing, "none") == 0
        ? "inspect story why for the complete causal chain"
        : "inspect story why for the first non-PROVED causal relation";
}

static bool story_render_show(struct zcl_command_reply *reply,
                              const struct zcl_command_request *request,
                              const struct story_loaded_work *loaded,
                              bool full)
{
    struct json_value events;
    json_init(&events); json_set_array(&events);
    bool ok = story_push_show_events(&events, loaded, full);
    const char *largest_missing = story_largest_missing(&loaded->graph);
    const char *next_action = story_show_next_action(loaded, largest_missing);
    ok = ok && (!full || story_push_journey(
                    request, loaded, &reply->data)) &&
        story_push_show_header(reply, loaded) &&
        json_push_kv(&reply->data, "events", &events) &&
        story_push_open_relations(&reply->data, &loaded->graph) &&
        story_push_show_footer(reply, largest_missing, next_action);
    json_free(&events);
    return ok;
}

void zcl_native_handle_story_show(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct story_loaded_work loaded;
    if (!story_load_work(request,
                         story_input_string(request->input, "workspace"),
                         story_input_string(request->input, "work"),
                         story_input_string(request->input, "datadir"),
                         &loaded, reply))
        return;
    bool full = story_request_full_view(request);
    if (!story_render_show(reply, request, &loaded, full))
        story_fail(reply, "STORY_OUTPUT_FAILED", "render",
                   "bounded story view could not be rendered");
}

static const char *story_context_status_name(enum story_context_status status)
{
    switch (status) {
    case STORY_CONTEXT_PROVED: return "PROVED";
    case STORY_CONTEXT_UNKNOWN: return "UNKNOWN";
    case STORY_CONTEXT_AMBIGUOUS:
    case STORY_CONTEXT_UNAVAILABLE: return "INCOMPLETE";
    default: return "INCOMPLETE";
    }
}

static const char *story_context_reason(enum story_context_status status)
{
    switch (status) {
    case STORY_CONTEXT_PROVED: return "exact_context_reverified";
    case STORY_CONTEXT_UNKNOWN: return "no_context_recorded";
    case STORY_CONTEXT_AMBIGUOUS: return "multiple_contexts_for_task";
    case STORY_CONTEXT_UNAVAILABLE: return "context_bytes_not_reverified";
    default: return "context_status_invalid";
    }
}

static bool story_push_context_sources(
    struct json_value *object,
    const struct vcs_zcode_agent_context_v1 *context,
    size_t *excerpt_bytes)
{
    struct json_value sources;
    json_init(&sources);
    json_set_array(&sources);
    bool ok = true;
    *excerpt_bytes = 0;
    for (size_t i = 0; ok && i < context->file_count; i++) {
        const struct vcs_zcode_agent_context_entry_v1 *entry =
            &context->files[i];
        struct json_value source;
        json_init(&source);
        json_set_object(&source);
        ok = json_push_kv_str(&source, "path", entry->path) &&
            json_push_kv_int(&source, "start_line", entry->start_line) &&
            json_push_kv_int(&source, "excerpt_bytes",
                             (int64_t)entry->content_len) &&
            json_push_kv_int(&source, "full_file_bytes",
                             (int64_t)entry->full_file_bytes) &&
            json_push_back(&sources, &source);
        *excerpt_bytes += entry->content_len;
        json_free(&source);
    }
    if (ok) ok = json_push_kv(object, "selected_sources", &sources);
    json_free(&sources);
    return ok;
}

bool story_workspace_source_root(const char *workspace, uint8_t out[32])
{
    struct vcs_manifest first, second;
    uint8_t first_root[32], second_root[32];
    if (!vcs_manifest_build(workspace, NULL, &first)) return false;
    bool ok = vcs_manifest_tree_hash(&first, first_root);
    vcs_manifest_free(&first);
    if (!ok || !vcs_manifest_build(workspace, NULL, &second)) return false;
    ok = vcs_manifest_tree_hash(&second, second_root);
    vcs_manifest_free(&second);
    if (!ok || memcmp(first_root, second_root, 32) != 0) return false;
    memcpy(out, first_root, 32);
    return true;
}

static bool story_compose_change_plan(
    const struct zcl_command_request *request, const char *workspace,
    const struct story_loaded_work *loaded,
    const struct vcs_zcode_agent_context_v1 *context,
    struct zcl_command_reply *plan, const char **status, const char **reason,
    uint8_t workspace_root[32])
{
    uint8_t task_source_root[32];
    *status = "INCOMPLETE";
    *reason = "workspace_source_root_unavailable";
    if (!zcl_hex_decode_lower(loaded->source_root, task_source_root, 32) ||
        !story_workspace_source_root(workspace, workspace_root))
        return false;
    if (memcmp(task_source_root, workspace_root, 32) != 0) {
        *reason = "workspace_source_root_mismatch";
        return false;
    }

    struct json_value input;
    json_init(&input); json_set_object(&input);
    if (!json_push_kv_str(&input, "symbol", context->query)) {
        json_free(&input);
        *reason = "change_plan_input_unavailable";
        return false;
    }
    struct zcl_command_context command_context = request->context
        ? *request->context : (struct zcl_command_context){0};
    command_context.source_root = workspace;
    struct zcl_command_request nested_request = {
        .context = &command_context,
        .input = &input,
    };
    zcl_native_handle_code_change_plan(&nested_request, plan);
    json_free(&input);
    const struct json_value *found = json_get(&plan->data, "symbol_found");
    if (plan->status != ZCL_COMMAND_STATUS_PASSED || !found ||
        found->type != JSON_BOOL || !json_get_bool(found)) {
        *reason = "context_identifier_not_indexed";
        return false;
    }
    *status = "PROVED";
    *reason = "task_source_and_context_identifier_reverified";
    return true;
}

static bool story_compose_focus(
    const char *workspace, const struct story_loaded_work *loaded,
    const struct vcs_zcode_agent_context_v1 *context,
    struct vcs_zcode_focus_v1 *focus, uint8_t focus_root[32],
    uint8_t situation_root[32])
{
    struct vcs_zcode_task_v1 task;
    uint8_t task_root[32], context_root[32];
    if (!story_load_task(workspace, loaded, &task) ||
        !zcl_hex_decode_lower(loaded->task_root, task_root, 32) ||
        vcs_zcode_agent_context_root(
            context, (size_t)task.max_context_bytes, context_root) !=
            VCS_ZCODE_AGENT_CONTEXT_OK)
        return false;
    uint8_t flags = (context->flags & VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0
        ? VCS_ZCODE_FOCUS_CONTEXT_TRUNCATED : 0;
    return vcs_zcode_focus_compose(
               &task, task_root, context_root, loaded->show.story_root,
               loaded->show.status, flags, NULL, 0, focus) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_situation_root(focus, situation_root) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_root(focus, focus_root) == VCS_ZCODE_FOCUS_OK;
}

static bool story_push_focus_identity(
    struct json_value *object, const struct vcs_zcode_focus_v1 *focus,
    const uint8_t focus_root[32], const uint8_t situation_root[32])
{
    return json_push_kv_str(object, "focus_schema", "focus.v1") &&
        story_push_root(object, "focus_root", focus_root) &&
        story_push_root(object, "focus_situation_root", situation_root) &&
        story_push_root(object, "claim_set_root", focus->claim_set_root) &&
        json_push_kv_int(object, "claim_count", focus->claim_count) &&
        story_push_root(object, "required_evidence_root",
                        focus->required_evidence_root) &&
        story_push_root(object, "authority_limits_root",
                        focus->authority_limits_root) &&
        json_push_kv_int(object, "max_changed_files",
                         focus->max_changed_files) &&
        json_push_kv_int(object, "max_patch_bytes",
                         (int64_t)focus->max_patch_bytes) &&
        json_push_kv_int(object, "max_context_bytes",
                         (int64_t)focus->max_context_bytes) &&
        json_push_kv_int(object, "max_cpu_seconds",
                         focus->max_cpu_seconds) &&
        json_push_kv_int(object, "max_memory_bytes",
                         (int64_t)focus->max_memory_bytes) &&
        json_push_kv_int(object, "max_output_bytes",
                         (int64_t)focus->max_output_bytes);
}

static bool story_push_resume_constraints(
    struct json_value *object, const struct vcs_zcode_write_scope_v1 *scope,
    const uint8_t root[32], const struct story_loaded_work *loaded)
{
    struct json_value paths;
    json_init(&paths); json_set_array(&paths);
    bool ok = true;
    for (size_t i = 0; ok && i < scope->count; i++) {
        struct json_value path;
        json_init(&path);
        json_set_str(&path, scope->paths[i]);
        ok = path.type == JSON_STR && json_get_str(&path) &&
             json_push_back(&paths, &path);
        json_free(&path);
    }
    if (ok) ok = json_push_kv(object, "allowed_write_scopes", &paths) &&
        story_push_root(object, "write_scope_root", root) &&
        json_push_kv_str(object, "candidate_root", loaded->candidate_root) &&
        json_push_kv_str(object, "candidate_source_root",
                         loaded->candidate_source_root);
    json_free(&paths);
    return ok;
}

static const char *story_resume_next_action(
    enum story_context_status status, const struct story_loaded_work *loaded)
{
    switch (status) {
    case STORY_CONTEXT_UNKNOWN:
        return "Capture one canonical agent context for this task.";
    case STORY_CONTEXT_AMBIGUOUS:
        return "Resolve the task to one canonical agent context before resuming.";
    case STORY_CONTEXT_UNAVAILABLE:
        return "Restore or recapture the exact agent context; its CAS bytes could not be reverified.";
    case STORY_CONTEXT_PROVED:
        return loaded->next_action;
    default:
        return "Reverify the canonical task context before resuming.";
    }
}

static const char *story_focus_workspace(
    const struct zcl_command_request *request)
{
    const char *workspace = story_input_string(request->input, "workspace");
    return workspace && workspace[0] ? workspace : ".";
}

struct story_focus_state {
    const char *workspace;
    struct story_loaded_work loaded;
    struct vcs_zcode_write_scope_v1 scope;
    uint8_t scope_root[32];
    struct vcs_zcode_agent_context_v1 context;
    enum story_context_status context_status;
    struct vcs_zcode_focus_v1 focus;
    bool focus_ready;
    uint8_t focus_root[32];
    uint8_t situation_root[32];
    struct zcl_command_reply plan;
    const char *orientation_status;
    const char *orientation_reason;
    uint8_t workspace_source_root[32];
    bool plan_ready;
    size_t excerpt_bytes;
};

static bool story_focus_load(const struct zcl_command_request *request,
                             struct zcl_command_reply *reply,
                             struct story_focus_state *state)
{
    state->workspace = story_focus_workspace(request);
    if (!story_load_work(request, state->workspace,
                         story_input_string(request->input, "work"),
                         story_input_string(request->input, "datadir"),
                         &state->loaded, reply))
        return false;
    if (story_load_write_scope(state->workspace, &state->loaded,
                               &state->scope, state->scope_root))
        return true;
    story_fail(reply, "STORY_SCOPE_UNAVAILABLE", "verify",
               "task write constraints could not be reverified from exact CAS bytes");
    return false;
}

static bool story_focus_bind(struct zcl_command_reply *reply,
                             struct story_focus_state *state)
{
    vcs_zcode_agent_context_init(&state->context);
    state->context_status = story_load_agent_context(
        state->workspace, &state->loaded, &state->context);
    state->focus_ready = state->context_status == STORY_CONTEXT_PROVED &&
        story_compose_focus(state->workspace, &state->loaded,
                            &state->context, &state->focus,
                            state->focus_root, state->situation_root);
    if (state->context_status != STORY_CONTEXT_PROVED || state->focus_ready)
        return true;
    vcs_zcode_agent_context_free(&state->context);
    story_fail(reply, "STORY_FOCUS_BINDING_FAILED", "compose",
               "reverified task, context, and StoryGraph could not be bound into focus.v1");
    return false;
}

static void story_focus_orient(const struct zcl_command_request *request,
                               struct story_focus_state *state)
{
    zcl_command_reply_init(&state->plan, "zcl.code_change_plan.v1");
    state->orientation_status =
        story_context_status_name(state->context_status);
    state->orientation_reason = story_context_reason(state->context_status);
    memset(state->workspace_source_root, 0,
           sizeof(state->workspace_source_root));
    state->plan_ready = state->context_status == STORY_CONTEXT_PROVED &&
        story_compose_change_plan(request, state->workspace,
                                  &state->loaded, &state->context,
                                  &state->plan, &state->orientation_status,
                                  &state->orientation_reason,
                                  state->workspace_source_root);
}

static bool story_push_focus_constraints(struct story_focus_state *state,
                                         struct zcl_command_reply *reply)
{
    return story_push_resume_constraints(&reply->data, &state->scope,
                                         state->scope_root, &state->loaded) &&
        (!state->focus_ready ||
         story_push_focus_identity(&reply->data, &state->focus,
                                   state->focus_root,
                                   state->situation_root));
}

static bool story_push_focus_status(struct story_focus_state *state,
                                    struct zcl_command_reply *reply)
{
    const char *focus_status = state->context_status == STORY_CONTEXT_PROVED
        ? story_status_name(state->loaded.show.status)
        : story_context_status_name(state->context_status);
    return json_push_kv_str(&reply->data, "status", focus_status) &&
        json_push_kv_str(&reply->data, "story_status",
                         story_status_name(state->loaded.show.status)) &&
        json_push_kv_bool(&reply->data, "complete",
                          state->context_status == STORY_CONTEXT_PROVED &&
                          state->loaded.show.complete) &&
        json_push_kv_str(&reply->data, "work_id", state->loaded.work_id) &&
        json_push_kv_str(&reply->data, "goal", state->loaded.goal) &&
        json_push_kv_str(&reply->data, "state", state->loaded.state) &&
        json_push_kv_str(&reply->data, "stage", state->loaded.stage);
}

static bool story_push_focus_roots(struct story_focus_state *state,
                                   struct zcl_command_reply *reply)
{
    return json_push_kv_str(&reply->data, "task_root",
                            state->loaded.task_root) &&
        json_push_kv_str(&reply->data, "source_root",
                         state->loaded.source_root) &&
        json_push_kv_str(&reply->data, "goal_root",
                         state->loaded.goal_root) &&
        story_push_root(&reply->data, "story_root",
                        state->loaded.show.story_root) &&
        json_push_kv_str(&reply->data, "agent_context_root",
                         state->loaded.agent_context_root);
}

static bool story_push_focus_context(struct story_focus_state *state,
                                     struct zcl_command_reply *reply)
{
    bool proved = state->context_status == STORY_CONTEXT_PROVED;
    return json_push_kv_str(&reply->data, "context_status",
                            story_context_status_name(state->context_status)) &&
        json_push_kv_str(&reply->data, "context_reason",
                         story_context_reason(state->context_status)) &&
        json_push_kv_str(&reply->data, "context_query",
                         proved ? state->context.query : "") &&
        json_push_kv_int(&reply->data, "selected_source_count",
                         proved ? (int64_t)state->context.file_count : 0) &&
        json_push_kv_int(&reply->data, "selected_source_bytes",
                         (int64_t)state->excerpt_bytes) &&
        json_push_kv_bool(&reply->data, "context_truncated",
                          proved &&
                          (state->context.flags &
                           VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0);
}

static bool story_push_focus_orientation(struct story_focus_state *state,
                                         struct zcl_command_reply *reply)
{
    return json_push_kv_str(&reply->data, "orientation_status",
                            state->orientation_status) &&
        json_push_kv_str(&reply->data, "orientation_reason",
                         state->orientation_reason) &&
        json_push_kv_str(&reply->data, "orientation_query",
                         state->context_status == STORY_CONTEXT_PROVED
                             ? state->context.query : "") &&
        (!state->plan_ready ||
         (story_push_root(&reply->data, "orientation_source_root",
                          state->workspace_source_root) &&
          json_push_kv(&reply->data, "change_plan", &state->plan.data)));
}

static bool story_push_focus_relations(struct story_focus_state *state,
                                       struct zcl_command_reply *reply)
{
    return story_push_relation_names(&reply->data, "proved_relations",
                                     &state->loaded.graph,
                                     ZCL_ONTOLOGY_PROVED) &&
        story_push_open_relations(&reply->data, &state->loaded.graph);
}

static bool story_push_focus_next(struct story_focus_state *state,
                                  struct zcl_command_reply *reply)
{
    const char *next_action = story_resume_next_action(
        state->context_status, &state->loaded);
    const char *next_command = state->context_status == STORY_CONTEXT_PROVED
        ? state->loaded.next_safe_command : "zcode work start";
    return json_push_kv_str(&reply->data, "largest_missing_relation",
                            story_largest_missing(&state->loaded.graph)) &&
        json_push_kv_str(&reply->data, "next_action", next_action) &&
        json_push_kv_str(&reply->data, "next_safe_command", next_command) &&
        story_push_readonly_projection(&reply->data);
}

static bool story_push_focus_fields(struct story_focus_state *state,
                                    struct zcl_command_reply *reply)
{
    return story_push_focus_constraints(state, reply) &&
        story_push_focus_status(state, reply) &&
        story_push_focus_roots(state, reply) &&
        story_push_focus_context(state, reply) &&
        story_push_focus_orientation(state, reply) &&
        story_push_focus_relations(state, reply) &&
        story_push_focus_next(state, reply);
}

void zcl_native_handle_story_focus(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct story_focus_state state;
    if (!story_focus_load(request, reply, &state)) return;
    if (!story_focus_bind(reply, &state)) return;
    story_focus_orient(request, &state);
    bool ok = story_push_context_sources(&reply->data, &state.context,
                                         &state.excerpt_bytes) &&
        story_push_focus_fields(&state, reply);
    zcl_command_reply_free(&state.plan);
    vcs_zcode_agent_context_free(&state.context);
    if (!ok)
        story_fail(reply, "STORY_FOCUS_OUTPUT_FAILED", "render",
                   "bounded ontology focus view could not be rendered");
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

static bool story_why_target_root(const struct story_loaded_work *loaded,
                                  const char *target, uint8_t target_root[32],
                                  struct zcl_command_reply *reply)
{
    const struct zcl_story_event_v1 *named = story_find_kind(
        &loaded->graph, target);
    if (named) {
        memcpy(target_root, named->event_root, 32);
        return true;
    }
    if (target && zcl_hex_decode_lower(target, target_root, 32)) return true;
    story_fail(reply, "STORY_EVENT_INVALID", "resolve",
               "event must be a development relation name or exact 64-hex event root");
    return false;
}

static bool story_push_why_chain(struct json_value *chain,
                                 const struct story_loaded_work *loaded,
                                 const struct zcl_story_why_v1 *why,
                                 bool full)
{
    bool ok = true;
    for (size_t i = 0; ok && i < why->cause_count; i++) {
        const struct zcl_story_event_v1 *event = story_find_root(
            &loaded->graph, why->cause_event_roots[i]);
        if (!event) { ok = false; break; }
        ok = story_push_event(chain, event, full);
    }
    return ok;
}

static bool story_push_why_summary(struct zcl_command_reply *reply,
                                   const struct zcl_story_why_v1 *why)
{
    return json_push_kv_str(&reply->data, "status",
                            story_status_name(why->status)) &&
        json_push_kv_bool(&reply->data, "complete", why->complete) &&
        story_push_root(&reply->data, "story_root", why->story_root) &&
        story_push_root(&reply->data, "target_event_root",
                        why->target_event_root) &&
        json_push_kv_bool(&reply->data, "target_unknown",
                          why->target_unknown) &&
        json_push_kv_bool(&reply->data, "missing_cause",
                          why->missing_cause) &&
        json_push_kv_bool(&reply->data, "cycle_detected",
                          why->cycle_detected);
}

void zcl_native_handle_story_why(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct story_loaded_work loaded;
    if (!story_load_work(request,
                         story_input_string(request->input, "workspace"),
                         story_input_string(request->input, "work"),
                         story_input_string(request->input, "datadir"),
                         &loaded, reply))
        return;
    uint8_t target_root[32];
    if (!story_why_target_root(&loaded,
                               story_input_string(request->input, "event"),
                               target_root, reply))
        return;
    struct zcl_story_why_v1 why;
    if (!zcl_story_why_v1_build(&loaded.graph, target_root, &why)) {
        story_fail(reply, "STORY_WHY_FAILED", "query",
                   "causal query could not be evaluated over the rooted story");
        return;
    }
    struct json_value chain;
    json_init(&chain); json_set_array(&chain);
    bool ok = story_push_why_chain(&chain, &loaded, &why,
                                   story_request_full_view(request));
    ok = ok && story_push_why_summary(reply, &why) &&
        json_push_kv(&reply->data, "causal_chain", &chain) &&
        story_push_authority(&reply->data);
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

static bool story_push_diff_roots(struct zcl_command_reply *reply,
                                  struct zcl_story_diff_v1 *diff)
{
    return story_push_root(&reply->data, "before_story_root",
                           diff->before_story_root) &&
        story_push_root(&reply->data, "after_story_root",
                        diff->after_story_root) &&
        story_push_root_list(&reply->data, "added_event_roots",
                             diff->added_event_roots, diff->added_count) &&
        story_push_root_list(&reply->data, "removed_event_roots",
                             diff->removed_event_roots, diff->removed_count) &&
        story_push_root_list(&reply->data, "changed_event_roots",
                             diff->changed_event_roots, diff->changed_count);
}

void zcl_native_handle_story_diff(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = story_input_string(request->input, "workspace");
    const char *datadir = story_input_string(request->input, "datadir");
    struct story_loaded_work before, after;
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
        story_push_diff_roots(reply, &diff) &&
        json_push_kv_str(&reply->data, "before_status",
                         story_status_name(before.show.status)) &&
        json_push_kv_str(&reply->data, "after_status",
                         story_status_name(after.show.status)) &&
        story_push_authority(&reply->data);
    if (!ok)
        story_fail(reply, "STORY_DIFF_OUTPUT_FAILED", "render",
                   "bounded story difference could not be rendered");
}
