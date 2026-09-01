/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Explain canonical development work as a bounded causal story. */
#include "command/native_story_command.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "command/native_story_internal.h"
#include "json/json.h"
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

static bool story_render_show(struct zcl_command_reply *reply,
                              const struct story_loaded_work *loaded,
                              bool full)
{
    struct json_value events;
    json_init(&events); json_set_array(&events);
    bool ok = true;
    for (size_t i = 0; ok && i < loaded->graph.event_count; i++)
        ok = story_push_event(&events, &loaded->events[i], full);
    const char *largest_missing = story_largest_missing(&loaded->graph);
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
    struct story_loaded_work loaded;
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

void zcl_native_handle_story_focus(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = story_input_string(request->input, "workspace");
    if (!workspace || !workspace[0]) workspace = ".";
    struct story_loaded_work loaded;
    if (!story_load_work(request, workspace,
                         story_input_string(request->input, "work"),
                         story_input_string(request->input, "datadir"),
                         &loaded, reply))
        return;
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    enum story_context_status context_status = story_load_agent_context(
        workspace, &loaded, &context);
    struct vcs_zcode_focus_v1 focus;
    uint8_t focus_root[32], situation_root[32];
    bool focus_ready = context_status == STORY_CONTEXT_PROVED &&
        story_compose_focus(workspace, &loaded, &context, &focus,
                            focus_root, situation_root);
    if (context_status == STORY_CONTEXT_PROVED && !focus_ready) {
        vcs_zcode_agent_context_free(&context);
        story_fail(reply, "STORY_FOCUS_BINDING_FAILED", "compose",
                   "reverified task, context, and StoryGraph could not be bound into focus.v1");
        return;
    }
    struct zcl_command_reply plan;
    zcl_command_reply_init(&plan, "zcl.code_change_plan.v1");
    const char *orientation_status = story_context_status_name(context_status);
    const char *orientation_reason = story_context_reason(context_status);
    uint8_t workspace_source_root[32] = {0};
    bool plan_ready = context_status == STORY_CONTEXT_PROVED &&
        story_compose_change_plan(request, workspace, &loaded, &context,
                                  &plan, &orientation_status,
                                  &orientation_reason,
                                  workspace_source_root);
    size_t excerpt_bytes = 0;
    bool context_ok = story_push_context_sources(
        &reply->data, &context, &excerpt_bytes);
    const char *next_action = context_status == STORY_CONTEXT_UNKNOWN
        ? "Capture one canonical agent context for this task."
        : context_status == STORY_CONTEXT_AMBIGUOUS
        ? "Resolve the task to one canonical agent context before resuming."
        : context_status == STORY_CONTEXT_UNAVAILABLE
        ? "Restore or recapture the exact agent context; its CAS bytes could not be reverified."
        : loaded.next_action;
    const char *next_command = context_status == STORY_CONTEXT_PROVED
        ? loaded.next_safe_command : "zcode work start";
    const char *focus_status = context_status == STORY_CONTEXT_PROVED
        ? story_status_name(loaded.show.status)
        : story_context_status_name(context_status);
    bool ok = context_ok && (!focus_ready || story_push_focus_identity(
        &reply->data, &focus, focus_root, situation_root)) &&
        json_push_kv_str(&reply->data, "status",
                         focus_status) &&
        json_push_kv_str(&reply->data, "story_status",
                         story_status_name(loaded.show.status)) &&
        json_push_kv_bool(&reply->data, "complete",
                          context_status == STORY_CONTEXT_PROVED &&
                          loaded.show.complete) &&
        json_push_kv_str(&reply->data, "work_id", loaded.work_id) &&
        json_push_kv_str(&reply->data, "goal", loaded.goal) &&
        json_push_kv_str(&reply->data, "state", loaded.state) &&
        json_push_kv_str(&reply->data, "stage", loaded.stage) &&
        json_push_kv_str(&reply->data, "task_root", loaded.task_root) &&
        json_push_kv_str(&reply->data, "source_root", loaded.source_root) &&
        json_push_kv_str(&reply->data, "goal_root", loaded.goal_root) &&
        story_push_root(&reply->data, "story_root",
                        loaded.show.story_root) &&
        json_push_kv_str(&reply->data, "agent_context_root",
                         loaded.agent_context_root) &&
        json_push_kv_str(&reply->data, "context_status",
                         story_context_status_name(context_status)) &&
        json_push_kv_str(&reply->data, "context_reason",
                         story_context_reason(context_status)) &&
        json_push_kv_str(&reply->data, "context_query",
                         context_status == STORY_CONTEXT_PROVED
                             ? context.query : "") &&
        json_push_kv_int(&reply->data, "selected_source_count",
                         context_status == STORY_CONTEXT_PROVED
                             ? (int64_t)context.file_count : 0) &&
        json_push_kv_int(&reply->data, "selected_source_bytes",
                         (int64_t)excerpt_bytes) &&
        json_push_kv_bool(&reply->data, "context_truncated",
                          context_status == STORY_CONTEXT_PROVED &&
                          (context.flags &
                           VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0) &&
        json_push_kv_str(&reply->data, "orientation_status",
                         orientation_status) &&
        json_push_kv_str(&reply->data, "orientation_reason",
                         orientation_reason) &&
        json_push_kv_str(&reply->data, "orientation_query",
                         context_status == STORY_CONTEXT_PROVED
                             ? context.query : "") &&
        (!plan_ready ||
         (story_push_root(&reply->data, "orientation_source_root",
                          workspace_source_root) &&
          json_push_kv(&reply->data, "change_plan", &plan.data))) &&
        story_push_relation_names(&reply->data, "proved_relations",
                                  &loaded.graph, ZCL_ONTOLOGY_PROVED) &&
        story_push_relation_names(&reply->data, "unknown_relations",
                                  &loaded.graph, ZCL_ONTOLOGY_UNKNOWN) &&
        story_push_relation_names(&reply->data, "incomplete_relations",
                                  &loaded.graph, ZCL_ONTOLOGY_INCOMPLETE) &&
        story_push_relation_names(&reply->data, "disproved_relations",
                                  &loaded.graph, ZCL_ONTOLOGY_DISPROVED) &&
        json_push_kv_str(&reply->data, "largest_missing_relation",
                         story_largest_missing(&loaded.graph)) &&
        json_push_kv_str(&reply->data, "next_action", next_action) &&
        json_push_kv_str(&reply->data, "next_safe_command", next_command) &&
        json_push_kv_str(&reply->data, "authority",
                         "canonical_zcode_readonly_projection") &&
        json_push_kv_bool(&reply->data, "stored", false) &&
        json_push_kv_str(&reply->data, "truth_system",
                         "zcl.ontology.status");
    zcl_command_reply_free(&plan);
    vcs_zcode_agent_context_free(&context);
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
    const char *target = story_input_string(request->input, "event");
    const struct zcl_story_event_v1 *named = story_find_kind(
        &loaded.graph, target);
    uint8_t target_root[32];
    if (named) memcpy(target_root, named->event_root, 32);
    else if (!target || !zcl_hex_decode_lower(target, target_root, 32)) {
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
