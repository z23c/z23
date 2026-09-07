/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: contained model-neutral handoff for one verified ZCODE task. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/cleanse.h"
#include "base/log_macros.h"
#include "config/runtime.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "services/package_lifecycle.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/build_action.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_reuse.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_write_scope.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#include "native_zcode_work_run_priv.h"

const char *run_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

bool run_bool(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

void run_fail(struct zcl_command_reply *reply, const char *code,
              const char *phase, const char *detail, bool retryable,
              bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, retryable,
                           mutated, detail, "zcode.work.run");
}

bool run_add_work_next(struct zcl_command_reply *reply,
                       const char *command, const char *workspace,
                       const char *work_id, const char *adapter,
                       const char *reason)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = workspace && workspace[0] && work_id && work_id[0] &&
        json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "work", work_id) &&
        (!adapter || json_push_kv_str(&input, "adapter", adapter));
    char wire[sizeof(reply->next[0].input_json)];
    size_t n = ok ? json_write(&input, wire, sizeof(wire)) : 0;
    json_free(&input);
    return n > 0 && n < sizeof(wire) &&
        zcl_command_reply_add_next(reply, command, wire, reason);
}

const struct vcs_zcode_task_index_entry *run_resolve(
    const struct vcs_zcode_task_index *index, const char *work, bool *ambiguous)
{
    *ambiguous = false;
    size_t count = vcs_zcode_task_index_task_count(index);
    if (count == 0) return NULL;
    if (!work || !work[0] || strcmp(work, "latest") == 0) {
        const struct vcs_zcode_task_index_entry *best =
            vcs_zcode_task_index_task_at(index, 0);
        for (size_t i = 1; i < count; i++) {
            const struct vcs_zcode_task_index_entry *at =
                vcs_zcode_task_index_task_at(index, i);
            if (at->expires_unix > best->expires_unix ||
                (at->expires_unix == best->expires_unix &&
                 strcmp(at->task_root_hex, best->task_root_hex) > 0))
                best = at;
        }
        return best;
    }
    const char *prefix = strncmp(work, "work-", 5) == 0 ? work + 5 : work;
    size_t prefix_len = strlen(prefix);
    if (prefix_len < 8 || prefix_len > 64) return NULL;
    const struct vcs_zcode_task_index_entry *match = NULL;
    for (size_t i = 0; i < count; i++) {
        const struct vcs_zcode_task_index_entry *at =
            vcs_zcode_task_index_task_at(index, i);
        if (strncmp(at->task_root_hex, prefix, prefix_len) != 0) continue;
        if (match) { *ambiguous = true; return NULL; }
        match = at;
    }
    return match;
}

bool run_load_task(const char *workspace, const char *root_hex,
                   struct vcs_zcode_task_v1 *task)
{
    uint8_t root[32], check[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(root_hex, root, 32) &&
        vcs_object_load_raw_bounded(workspace, root, VCS_ZCODE_TASK_WIRE_BYTES,
                                    &wire, &len) == 0 &&
        len == VCS_ZCODE_TASK_WIRE_BYTES &&
        vcs_zcode_task_parse(wire, len, task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, check) == VCS_ZCODE_DEV_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

char *run_load_goal(const char *workspace,
                    const struct vcs_zcode_task_v1 *task)
{
    uint8_t *bytes = NULL, check[32];
    size_t len = 0;
    if (vcs_object_load_raw_bounded(workspace, task->goal_root, 4096,
                                    &bytes, &len) != 0 || len == 0 ||
        memchr(bytes, '\0', len)) {
        free(bytes);
        return NULL;
    }
    sha3_256(bytes, len, check);
    if (memcmp(check, task->goal_root, 32) != 0) {
        free(bytes);
        return NULL;
    }
    char *goal = zcl_malloc(len + 1u, "zcode.work.run.goal");
    if (!goal) { free(bytes); return NULL; }
    memcpy(goal, bytes, len); goal[len] = '\0'; free(bytes);
    return goal;
}

bool run_load_context(
    const char *workspace, const struct vcs_zcode_task_context_entry *entry,
    const struct vcs_zcode_task_v1 *task, const char *task_root_hex,
    struct vcs_zcode_agent_context_v1 *context,
    enum vcs_zcode_agent_context_result *admission)
{
    if (!admission) return false;
    *admission = VCS_ZCODE_AGENT_CONTEXT_NULL;
    uint8_t root[32], task_root[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(entry->context_root_hex, root, 32) &&
        zcl_hex_decode_lower(task_root_hex, task_root, 32) &&
        vcs_object_load_raw_bounded(workspace, root, task->max_context_bytes,
                                    &wire, &len) == 0 &&
        vcs_zcode_agent_context_parse(wire, len, task->max_context_bytes,
                                      context) ==
            VCS_ZCODE_AGENT_CONTEXT_OK;
    if (ok)
        *admission = vcs_zcode_agent_context_validate_for_task(
            context, task, task_root, root, true);
    free(wire);
    return ok && (*admission == VCS_ZCODE_AGENT_CONTEXT_OK ||
                  *admission == VCS_ZCODE_AGENT_CONTEXT_BINDING ||
                  *admission == VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE);
}

bool run_load_scope(const char *workspace,
                    const struct vcs_zcode_task_v1 *task,
                    struct vcs_zcode_write_scope_v1 *scope)
{
    uint8_t *wire = NULL, check[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, task->write_scope_root,
            VCS_ZCODE_WRITE_SCOPE_WIRE_MAX, &wire, &len) == 0 &&
        vcs_zcode_write_scope_parse(wire, len, scope) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(scope, check) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(check, task->write_scope_root, 32) == 0;
    free(wire);
    return ok;
}

/* One selection owns everything a reload allocates — the task index, the goal
 * bytes and the parsed agent context — so every exit path releases exactly
 * the same three things. */
void run_selection_init(struct run_selection *selection)
{
    memset(selection, 0, sizeof(*selection));
    vcs_zcode_agent_context_init(&selection->context);
    vcs_zcode_write_scope_init(&selection->scope);
    selection->context_admission = VCS_ZCODE_AGENT_CONTEXT_NULL;
}

void run_selection_free(struct run_selection *selection)
{
    free(selection->goal);
    selection->goal = NULL;
    vcs_zcode_agent_context_free(&selection->context);
    vcs_zcode_task_index_free(selection->index);
    selection->index = NULL;
}

struct run_behavior_diff {
    bool changed;
};

static void run_behavior_diff_cb(enum vcs_diff_kind kind,
                                 const struct vcs_entry *before,
                                 const struct vcs_entry *after, void *user)
{
    (void)kind;
    struct run_behavior_diff *diff = user;
    const char *path = after ? after->path : before ? before->path : NULL;
    if (path && strcmp(path, VCS_PACKAGE_DEPS_META_PATH) != 0)
        diff->changed = true;
}

static bool run_candidate_has_behavior_change(
    const char *workspace, const uint8_t base_root[32],
    const uint8_t candidate_root[32])
{
    struct vcs_manifest base, candidate;
    vcs_manifest_init(&base);
    vcs_manifest_init(&candidate);
    if (!vcs_tree_load(workspace, base_root, &base) ||
        !vcs_tree_load(workspace, candidate_root, &candidate)) {
        vcs_manifest_free(&candidate);
        vcs_manifest_free(&base);
        return false;
    }
    struct run_behavior_diff diff = {0};
    vcs_manifest_diff(&base, &candidate, run_behavior_diff_cb, &diff);
    vcs_manifest_free(&candidate);
    vcs_manifest_free(&base);
    return diff.changed;
}

bool run_candidate_workspace(const char *store,
                             const struct vcs_zcode_task_v1 *task,
                             const char *task_hex, uint32_t attempt,
                             const uint8_t source_root[32], char out[4400],
                             bool *created)
{
#if defined(_WIN32)
    (void)store; (void)task; (void)task_hex; (void)attempt;
    (void)source_root; (void)out;
    if (created) *created = false;
    /* Materializing executable package workspaces is disabled until the
     * restricted-token/Job-Object sandbox is qualified. */
    return false;
#else
    char parent[ZWORK_RUN_PATH_MAX];
    int n = snprintf(parent, sizeof(parent),
                     "/tmp/zclassic23-zcode-workspaces/%lu/%.64s",
                     (unsigned long)getuid(), task_hex);
    if (n <= 0 || (size_t)n >= sizeof(parent)) return false;
    struct zcl_result made = zcl_mkdir_p(parent, 0700);
    n = snprintf(out, ZWORK_RUN_PATH_MAX, "%s/attempt-%u", parent, attempt);
    if (!made.ok || n <= 0 || (size_t)n >= ZWORK_RUN_PATH_MAX) return false;
    if (mkdir(out, 0700) == 0) {
        *created = true;
        if (vcs_tree_materialize(store, source_root, out,
                                 task->max_output_bytes, 0u) != VCS_OK) {
            ZCL_IGNORE_RESULT(
                zcl_tree_remove(out),
                "best-effort rollback of a failed candidate materialization");
            return false;
        }
        return true;
    }
    struct stat st;
    *created = false;
    return errno == EEXIST && lstat(out, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static void run_feedback_timing(
    struct zcl_command_reply *reply, int64_t started_us)
{
    if (!reply || reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    int64_t elapsed = platform_time_monotonic_us() - started_us;
    (void)json_push_kv_int(&reply->data, "local_first_feedback_us",
                           elapsed < 0 ? 0 : elapsed);
}

void zcl_native_handle_zcode_work_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
#if defined(_WIN32)
    run_fail(reply, "PACKAGE_EXECUTION_UNSUPPORTED", "sandbox",
             "package execution is disabled on Windows until restricted "
             "tokens, Job Objects, low-integrity isolation, resource limits, "
             "and network denial pass adversarial qualification",
             false, false);
    return;
#endif
    int64_t feedback_started_us = platform_time_monotonic_us();
    const char *workspace_arg = run_str(request->input, "workspace");
    const char *work = run_str(request->input, "work");
    const char *adapter = run_str(request->input, "adapter");
    const char *proof_datadir_arg = run_str(request->input, "datadir");
    bool details = run_bool(request->input, "details");
    struct node_db *runtime_db = app_runtime_node_db();
    if ((!proof_datadir_arg || !proof_datadir_arg[0]) &&
        ((runtime_db && app_runtime_node_db_handle_open(runtime_db)) ||
         zcl_native_command_datadir_is_explicit()))
        proof_datadir_arg = zcl_native_command_datadir();
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    if (!adapter || !adapter[0]) adapter = "manual";
    bool codex_adapter = strcmp(adapter, "codex") == 0;
    if (strcmp(adapter, "manual") != 0 && !codex_adapter) {
        run_fail(reply, "ADAPTER_REFUSED", "adapter",
                 "adapter must name one fixed adapter: manual or codex",
                 false, false);
        return;
    }
    char codex_runner[ZWORK_RUN_PATH_MAX] = {0};
    if (codex_adapter && !run_codex_runner_path(codex_runner)) {
        run_fail(reply, "ADAPTER_UNAVAILABLE", "adapter",
                 "the fixed confined Codex runner or one supported single-run CODEX credential is unavailable; manual remains safe",
                 true, false);
        return;
    }
    char workspace[ZWORK_RUN_PATH_MAX];
    if (!platform_directory_canonical_real(workspace_arg, workspace,
                                           sizeof(workspace))) {
        run_fail(reply, "BAD_WORKSPACE", "resolve",
                 "workspace must resolve to an existing directory", false,
                 false);
        return;
    }
    char proof_datadir[ZWORK_RUN_PATH_MAX] = {0};
    if (proof_datadir_arg && proof_datadir_arg[0] &&
        !platform_directory_canonical_real(proof_datadir_arg, proof_datadir,
                                           sizeof(proof_datadir))) {
        run_fail(reply, "BAD_DATADIR", "resolve",
                 "datadir must resolve to an existing full-node data directory",
                 false, false);
        return;
    }
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? run_resolve(index, work, &ambiguous) : NULL;
    bool context_ambiguous = false;
    const struct vcs_zcode_task_context_entry *context_entry = entry
        ? vcs_zcode_task_index_context_for_task(
              index, entry->task_root_hex, &context_ambiguous) : NULL;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    struct vcs_zcode_write_scope_v1 scope;
    vcs_zcode_write_scope_init(&scope);
    enum vcs_zcode_agent_context_result context_admission =
        VCS_ZCODE_AGENT_CONTEXT_NULL;
    char *goal = NULL;
    bool loaded = entry && context_entry && !context_ambiguous &&
        run_load_task(workspace, entry->task_root_hex, &task) &&
        (goal = run_load_goal(workspace, &task)) != NULL &&
        run_load_context(workspace, context_entry, &task,
                         entry->task_root_hex, &context,
                         &context_admission) &&
        run_load_scope(workspace, &task, &scope) && !entry->expired;
    if (!loaded) {
        run_fail(reply, context_ambiguous ? "AMBIGUOUS_CONTEXT" :
                     ambiguous ? "AMBIGUOUS_WORK" : "WORK_HANDOFF_MISSING",
                 "resolve",
                 entry && entry->expired
                    ? "task expired; start a new bounded work item"
                    : context_ambiguous
                    ? "task has multiple contexts; select an exact expert context"
                    : "verified task, goal, and unique context could not be reloaded",
                 false, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    /* Terminal-for-run states: the candidate's evidence is complete (or the
     * work is already accepted).  Repeating run is an idempotent observation
     * of that fact — never a fresh candidate attempt.  This is the same
     * interpretation zcode work status gives the same lifecycle fact. */
    if (strcmp(entry->state, VCS_ZCODE_TASK_STATE_EVIDENCE_READY) == 0 ||
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0 ||
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0) {
        bool proven =
            strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0;
        bool decision =
            strcmp(entry->state,
                   VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0;
        char work_id[32];
        (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                       entry->task_root_hex);
        bool ok = json_push_kv_str(&reply->data, "work_id", work_id) &&
            json_push_kv_str(&reply->data, "state", entry->state) &&
            json_push_kv_str(&reply->data, "stage",
                             proven ? "Accepted" :
                             decision ? "Ready for your decision" :
                                        "Showing result") &&
            json_push_kv_str(&reply->data, "build_result", "passed") &&
            json_push_kv_str(&reply->data, "next_safe_command",
                             "zcode work status") &&
            json_push_kv_bool(&reply->data, "details_available", true) &&
            run_add_work_next(
                reply, "zcode.work.status", workspace, work_id, NULL,
                proven ? "show the accepted work and its publication state" :
                decision ? "show the candidate awaiting your acceptance decision" :
                           "show the exact build and reproduction state");
        if (!ok)
            run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                     "evidence-ready summary could not be rendered",
                     false, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    if (strcmp(entry->state, VCS_ZCODE_TASK_STATE_CANDIDATE_ADMITTED) == 0) {
        char pending_state[BUILD_PROOF_EVENT_STATE_MAX + 1];
        if (run_async_proof_pending(proof_datadir, entry->task_root_hex,
                                    entry->latest_candidate_root_hex,
                                    pending_state)) {
            /* Same lifecycle fact, same interpretation as zcode work status:
             * the admitted candidate waits on independent proof that is
             * outstanding in the bound node's ledger.  Repeating run is an
             * idempotent observation of that wait — not a failure and never
             * a fresh attempt. */
            char work_id[32];
            (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                           entry->task_root_hex);
            bool ok =
                json_push_kv_str(&reply->data, "work_id", work_id) &&
                json_push_kv_str(&reply->data, "state", "CANDIDATE_ADMITTED") &&
                json_push_kv_str(&reply->data, "stage",
                                 "Waiting for independent reproduction") &&
                json_push_kv_str(&reply->data, "build_result",
                                 "background_pending") &&
                json_push_kv_str(&reply->data, "async_proof_state",
                                 pending_state) &&
                json_push_kv_str(&reply->data, "next_safe_command",
                                 "zcode work status") &&
                json_push_kv_bool(&reply->data, "details_available", true) &&
                run_add_work_next(
                    reply, "zcode.work.status", workspace, work_id, NULL,
                    "show the admitted candidate while independent proof arrives");
            if (!ok)
                run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                         "admitted-candidate waiting summary could not be rendered",
                         false, false);
            free(goal); vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        run_fail(reply, "CANDIDATE_EXECUTION_INCOMPLETE", "build",
                 "the candidate is captured but its prior package execution produced no signed work receipt and no supervised independent proof is outstanding; preserve it and diagnose the package prerequisite before starting another attempt",
                 true, true);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    bool repairing = strcmp(entry->state,
                            VCS_ZCODE_TASK_STATE_REPAIR_NEEDED) == 0;
    if (entry->candidate_count >= 3u) {
        run_fail(reply, "REPAIR_LIMIT_REACHED", "repair",
                 "three candidate attempts are preserved; start a new bounded work item",
                 false, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    uint64_t candidate_sequence = entry->candidate_count + 1u;
    uint8_t materialize_root[32];
    bool materialize_root_ok = true;
    if (repairing)
        materialize_root_ok = zcl_hex_decode_lower(
            entry->latest_candidate_source_root_hex, materialize_root,
            sizeof(materialize_root));
    else
        memcpy(materialize_root, task.source_root, sizeof(materialize_root));
    char candidate_workspace[ZWORK_RUN_PATH_MAX];
    bool created = false;
    if (context_admission != VCS_ZCODE_AGENT_CONTEXT_OK ||
        !materialize_root_ok || !run_candidate_workspace(
            workspace, &task, entry->task_root_hex,
            (uint32_t)candidate_sequence, materialize_root,
            candidate_workspace, &created)) {
        run_fail(reply, "HANDOFF_REFUSED", "materialize",
                 context_admission == VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE
                    ? "complete context is required before model execution"
                    : context_admission == VCS_ZCODE_AGENT_CONTEXT_BINDING
                    ? "task and context bindings disagree"
                    : "isolated candidate workspace could not be created",
                 true, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    bool metadata_composed = false;
    if (!run_compose_candidate_metadata(
            candidate_workspace, &task, workspace, &metadata_composed)) {
        run_fail(reply, "DEPENDENCY_COMPOSITION_REFUSED", "compose",
                 "the exact task dependency lock could not be reflected in the isolated candidate metadata",
                 false, created);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    char prior_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    char *prior_packet = NULL;
    size_t prior_packet_len = 0;
    int prior_packet_status = repairing && !created
        ? run_read_packet(candidate_workspace, &prior_packet,
                          &prior_packet_len)
        : 0;
    if (run_packet_path(candidate_workspace, prior_packet_path))
        run_adapter_cleanup(candidate_workspace, prior_packet_path);
    if (prior_packet_status < 0) {
        run_fail(reply, "REPAIR_CONTEXT_REFUSED", "context",
                 "the bounded repair handoff was not a private regular packet",
                 true, false);
        free(prior_packet); free(goal);
        vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    if (!created) {
        uint8_t candidate_root[32];
        if (vcs_tree_capture_into(candidate_workspace, workspace,
                                  candidate_root) != VCS_OK) {
            run_fail(reply, "CANDIDATE_CAPTURE_FAILED", "capture",
                     "candidate workspace changed or contains a refused file",
                     true, false);
            free(prior_packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        if (memcmp(candidate_root, materialize_root, 32) != 0 &&
            run_candidate_has_behavior_change(
                workspace, materialize_root, candidate_root)) {
            struct run_admit_context admit = {
                .workspace = workspace,
                .candidate_workspace = candidate_workspace,
                .proof_datadir = proof_datadir,
                .goal = goal,
                .entry = entry,
                .context_entry = context_entry,
                .task = &task,
                .context = &context,
                .scope = &scope,
                .candidate_sequence = candidate_sequence,
                .adapter_name = "manual",
                .details = details,
            };
            bool handled = run_admit(&admit, reply);
            if (handled) run_feedback_timing(reply, feedback_started_us);
            if (!handled)
                run_fail(reply, "CANDIDATE_ADMISSION_FAILED", "admit",
                         "scratch identity or existing task composition failed",
                         true, false);
            free(prior_packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
    }
    struct json_value packet;
    json_init(&packet);
    char packet_detail[256];
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    bool packet_ok = false;
    if (prior_packet) {
        packet_ok = json_read(&packet, prior_packet, prior_packet_len) &&
            run_repair_packet_valid(&packet, goal, candidate_sequence);
        if (!packet_ok)
            (void)snprintf(packet_detail, sizeof(packet_detail),
                           "the bounded repair packet did not match the current goal and diagnostic");
    } else {
        packet_ok = run_packet(
            &packet, goal, workspace, proof_datadir, &task, &context, &scope,
            packet_detail);
    }
    free(prior_packet);
    if (!packet_ok) {
        run_fail(reply, "MODEL_CONTEXT_REFUSED", "context",
                 packet_detail[0] ? packet_detail
                                  : "the bounded model context could not be rendered",
                 true, created);
        json_free(&packet); free(goal);
        vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    size_t model_context_bytes = json_write(&packet, NULL, 0);
    if (packet_ok && codex_adapter) {
        char packet_path[ZWORK_RUN_PATH_MAX] = {0};
        char *adapter_output = zcl_malloc(ZWORK_ADAPTER_OUTPUT_MAX,
                                          "zcode.work.adapter.output");
        bool staged = adapter_output && run_write_packet(
            candidate_workspace, &packet, packet_path);
        const char *const argv[] = {
            codex_runner, candidate_workspace, packet_path, NULL,
        };
        int rc = staged ? zcl_spawn_capture(
            argv, adapter_output, ZWORK_ADAPTER_OUTPUT_MAX, 300000) : -1;
        run_adapter_cleanup(candidate_workspace, packet_path);
        if (!staged || rc != 0) {
            char detail[384];
            const char *kind = rc == 137 ? "timed out" :
                               rc == 69 || rc == 127 ? "is unavailable" :
                               "refused or failed";
            const char *output_tail = adapter_output ? adapter_output : "";
            size_t output_len = strlen(output_tail);
            if (output_len > 220u) output_tail += output_len - 220u;
            (void)snprintf(detail, sizeof(detail),
                           "confined Codex adapter %s (exit=%d)%s%.220s",
                           kind, rc,
                           adapter_output && adapter_output[0] ? ": " : "",
                           output_tail);
            run_fail(reply, rc == 137 ? "ADAPTER_TIMEOUT" :
                       rc == 69 || rc == 127 ? "ADAPTER_UNAVAILABLE" :
                                              "ADAPTER_REFUSAL",
                     "adapter", detail, rc != 70, staged);
            free(adapter_output); json_free(&packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        uint8_t candidate_root[32];
        bool captured = vcs_tree_capture_into(candidate_workspace, workspace,
                                              candidate_root) == VCS_OK;
        if (!captured || memcmp(candidate_root, materialize_root, 32) == 0 ||
            !run_candidate_has_behavior_change(
                workspace, materialize_root, candidate_root)) {
            run_fail(reply, captured ? "ADAPTER_REFUSAL" :
                                      "CANDIDATE_CAPTURE_FAILED",
                     captured ? "adapter" : "capture",
                     captured ? "Codex completed without an admissible behavior change beyond dependency composition"
                              : "Codex output could not be captured safely",
                     true, true);
            free(adapter_output); json_free(&packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        struct run_admit_context admit = {
            .workspace = workspace,
            .candidate_workspace = candidate_workspace,
            .proof_datadir = proof_datadir,
            .goal = goal,
            .entry = entry,
            .context_entry = context_entry,
            .task = &task,
            .context = &context,
            .scope = &scope,
            .candidate_sequence = candidate_sequence,
            .adapter_name = "codex",
            .details = details,
        };
        bool handled = run_admit(&admit, reply);
        if (handled) run_feedback_timing(reply, feedback_started_us);
        if (handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)json_push_kv_int(&reply->data, "model_context_bytes",
                                   (int64_t)model_context_bytes);
        if (handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)json_push_kv_bool(
                &reply->data, "candidate_dependency_metadata_changed",
                metadata_composed);
        if (details && handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)json_push_kv_str(&reply->data, "adapter_output",
                                   adapter_output);
        if (!handled)
            run_fail(reply, "CANDIDATE_ADMISSION_FAILED", "admit",
                     "confined Codex result could not enter existing candidate authority",
                     true, true);
        free(adapter_output); json_free(&packet); free(goal);
        vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    char manual_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    bool manual_staged = packet_ok && model_context_bytes > 0 &&
        run_write_packet(candidate_workspace, &packet, manual_packet_path);
    bool ok = manual_staged &&
        json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state", repairing
                         ? "REPAIR_NEEDED" : "AWAITING_CANDIDATE") &&
        json_push_kv_str(&reply->data, "stage", "Creating missing code") &&
        json_push_kv_str(&reply->data, "candidate_workspace",
                         candidate_workspace) &&
        json_push_kv_str(&reply->data, "adapter_packet_path",
                         manual_packet_path) &&
        json_push_kv_int(&reply->data, "model_context_bytes",
                         (int64_t)model_context_bytes) &&
        json_push_kv_bool(&reply->data,
                          "candidate_dependency_metadata_changed",
                          metadata_composed) &&
        json_push_kv_str(&reply->data, "authority", "NONE_MANUAL_HANDOFF") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        run_add_work_next(
            reply, "zcode.work.status", workspace, work_id, NULL,
            "after editing the candidate workspace, show its exact next action");
    json_free(&packet); free(goal); vcs_zcode_agent_context_free(&context);
    vcs_zcode_task_index_free(index);
    if (!ok)
        run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                 "bounded manual adapter packet could not be rendered",
                 false, created);
}
