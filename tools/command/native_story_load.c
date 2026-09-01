/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: Reverify canonical ZCODE work and context for StoryGraph reads. */
#include "command/native_story_internal.h"

#include "base/hex.h"
#include "command/native_story_command.h"
#include "json/json.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static bool story_copy(char *out, size_t out_size, const char *value)
{
    int n = snprintf(out, out_size, "%s", value ? value : "");
    return n >= 0 && (size_t)n < out_size;
}

static void story_load_fail(struct zcl_command_reply *reply, const char *code,
                            const char *phase, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, "canonical ZCODE objects");
}

static void story_work_facts_base(
    const struct json_value *data, const struct json_value *expert,
    struct zcl_story_work_facts_v1 *facts)
{
    *facts = (struct zcl_story_work_facts_v1) {
        .state = story_object_string(data, "state"),
        .build_result = story_object_string(data, "build_result"),
        .test_result = story_object_string(data, "test_result"),
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
        .proof_action_root = story_object_string(expert,
                                                  "proof_action_root"),
        .build_output_root = story_object_string(expert,
                                                  "build_output_root"),
    };
}

static void story_work_facts_app_run(
    const struct json_value *expert, struct zcl_story_work_facts_v1 *facts)
{
    facts->app_run_receipt_count = (uint32_t)story_object_int(
        expert, "app_run_receipt_count");
    facts->valid_app_run_receipt_count = (uint32_t)story_object_int(
        expert, "valid_app_run_receipt_count");
    facts->app_run_receipt_root = story_object_string(
        expert, "app_run_receipt_root");
    facts->app_run_observation_root = story_object_string(
        expert, "app_run_observation_root");
    facts->app_run_artifact_root = story_object_string(
        expert, "app_run_artifact_root");
    facts->app_run_invocation_root = story_object_string(
        expert, "app_run_invocation_root");
    facts->app_run_action_root = story_object_string(
        expert, "app_run_action_root");
    facts->app_run_flags = (uint16_t)story_object_int(
        expert, "app_run_flags");
    facts->app_run_status = (uint8_t)story_object_int(
        expert, "app_run_status");
    facts->app_run_exit_status = (int32_t)story_object_int(
        expert, "app_run_exit_status");
    facts->app_run_finished_unix = story_object_int(
        expert, "app_run_finished_unix");
    facts->lane_receipt_root = story_object_string(expert,
                                                    "lane_receipt_root");
    facts->accepted_work_root = story_object_string(
        expert, "accepted_work_root");
    facts->lane_created_unix = story_object_int(expert,
                                                 "lane_created_unix");
    facts->proof_set_root = story_object_string(expert, "proof_set_root");
}

static bool story_work_summary_copy(
    const struct json_value *data, const struct zcl_story_work_facts_v1 *facts,
    struct story_loaded_work *loaded)
{
    bool ok = story_copy(loaded->work_id, sizeof(loaded->work_id),
                         story_object_string(data, "work_id")) &&
        story_copy(loaded->goal, sizeof(loaded->goal),
                   story_object_string(data, "goal")) &&
        story_copy(loaded->state, sizeof(loaded->state), facts->state) &&
        story_copy(loaded->stage, sizeof(loaded->stage),
                   story_object_string(data, "stage")) &&
        story_copy(loaded->next_action, sizeof(loaded->next_action),
                   story_object_string(data, "next_action")) &&
        story_copy(loaded->next_safe_command,
                   sizeof(loaded->next_safe_command),
                   story_object_string(data, "next_safe_command")) &&
        story_copy(loaded->task_root, sizeof(loaded->task_root),
                   facts->task_root) &&
        story_copy(loaded->source_root, sizeof(loaded->source_root),
                   facts->source_root) &&
        story_copy(loaded->goal_root, sizeof(loaded->goal_root),
                   facts->goal_root) &&
        story_copy(loaded->agent_context_root,
                   sizeof(loaded->agent_context_root),
                   facts->agent_context_root);
    loaded->agent_context_ambiguous = facts->agent_context_ambiguous;
    return ok;
}

bool story_load_work(const struct zcl_command_request *request,
                     const char *workspace, const char *work,
                     const char *datadir, struct story_loaded_work *loaded,
                     struct zcl_command_reply *reply)
{
    if (!request || !loaded || !reply) return false;
    memset(loaded, 0, sizeof(*loaded));
    if (!work || !work[0]) {
        story_load_fail(
            reply, "STORY_WORK_REQUIRED", "resolve",
            "story projection requires one exact work id or task-root prefix");
        return false;
    }
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool input_ok = json_push_kv_str(
                        &input, "workspace",
                        workspace && workspace[0] ? workspace : ".") &&
                    json_push_kv_str(&input, "work", work) &&
                    (!datadir || !datadir[0] ||
                     json_push_kv_str(&input, "datadir", datadir)) &&
                    json_push_kv_bool(&input, "details", true);
    if (!input_ok) {
        json_free(&input);
        story_load_fail(reply, "STORY_INPUT_FAILED", "compose",
                        "canonical work-status input could not be composed");
        return false;
    }
    struct zcl_command_reply nested;
    zcl_command_reply_init(&nested, "zcl.zcode_work_status.v1");
    struct zcl_command_request nested_request = {
        .context = request->context,
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
    struct zcl_story_work_facts_v1 facts;
    story_work_facts_base(&nested.data, expert, &facts);
    story_work_facts_app_run(expert, &facts);
    bool copied = story_work_summary_copy(&nested.data, &facts, loaded);
    bool ok = copied && zcl_story_graph_from_work_facts(
                  &facts, loaded->events, &loaded->graph) &&
              zcl_story_show_v1_build(&loaded->graph, &loaded->show);
    zcl_command_reply_free(&nested);
    if (!ok)
        story_load_fail(
            reply, "STORY_FACTS_INVALID", "project",
            "reverified work status did not contain the bounded rooted facts required by StoryGraph");
    return ok;
}

bool story_load_task(const char *workspace,
                     const struct story_loaded_work *loaded,
                     struct vcs_zcode_task_v1 *task)
{
    uint8_t root[32], check[32], source[32], goal[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(loaded->task_root, root, 32) &&
        zcl_hex_decode_lower(loaded->source_root, source, 32) &&
        zcl_hex_decode_lower(loaded->goal_root, goal, 32) &&
        vcs_object_load_raw_bounded(workspace, root,
                                    VCS_ZCODE_TASK_WIRE_BYTES,
                                    &wire, &len) == 0 &&
        vcs_zcode_task_parse(wire, len, task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_validate(task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, check) == VCS_ZCODE_DEV_OK &&
        memcmp(root, check, 32) == 0 &&
        memcmp(source, task->source_root, 32) == 0 &&
        memcmp(goal, task->goal_root, 32) == 0;
    free(wire);
    return ok;
}

enum story_context_status story_load_agent_context(
    const char *workspace, const struct story_loaded_work *loaded,
    struct vcs_zcode_agent_context_v1 *context)
{
    if (!workspace || !workspace[0]) workspace = ".";
    if (!loaded || !context) return STORY_CONTEXT_UNAVAILABLE;
    if (loaded->agent_context_ambiguous) return STORY_CONTEXT_AMBIGUOUS;
    if (!loaded->agent_context_root[0]) return STORY_CONTEXT_UNKNOWN;
    struct vcs_zcode_task_v1 task;
    uint8_t root[32], task_root[32], *wire = NULL;
    size_t len = 0;
    bool ok = story_load_task(workspace, loaded, &task) &&
        zcl_hex_decode_lower(loaded->agent_context_root, root, 32) &&
        zcl_hex_decode_lower(loaded->task_root, task_root, 32) &&
        vcs_object_load_raw_bounded(workspace, root,
                                    (size_t)task.max_context_bytes,
                                    &wire, &len) == 0 &&
        vcs_zcode_agent_context_parse(wire, len,
                                      (size_t)task.max_context_bytes,
                                      context) ==
            VCS_ZCODE_AGENT_CONTEXT_OK &&
        vcs_zcode_agent_context_validate_for_task(
            context, &task, task_root, root, false) ==
            VCS_ZCODE_AGENT_CONTEXT_OK;
    free(wire);
    if (!ok) {
        vcs_zcode_agent_context_free(context);
        vcs_zcode_agent_context_init(context);
        return STORY_CONTEXT_UNAVAILABLE;
    }
    return STORY_CONTEXT_PROVED;
}
