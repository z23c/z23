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

/* Everything the request itself decides before any task is reloaded: which
 * adapter runs, which runner image it uses, and the two canonical
 * directories this run is bound to. */
struct run_request {
    const char *work;
    const char *adapter;
    bool codex_adapter;
    bool details;
    char workspace[ZWORK_RUN_PATH_MAX];
    char proof_datadir[ZWORK_RUN_PATH_MAX];
    char codex_runner[ZWORK_RUN_PATH_MAX];
};

/* An explicit datadir argument wins; otherwise a resident or explicitly
 * named node datadir binds this run to that node's ledger. */
static const char *run_request_datadir_arg(
    const struct zcl_command_request *request)
{
    const char *proof_datadir_arg = run_str(request->input, "datadir");
    struct node_db *runtime_db = app_runtime_node_db();
    if ((!proof_datadir_arg || !proof_datadir_arg[0]) &&
        ((runtime_db && app_runtime_node_db_handle_open(runtime_db)) ||
         zcl_native_command_datadir_is_explicit()))
        proof_datadir_arg = zcl_native_command_datadir();
    return proof_datadir_arg;
}

static bool run_request_adapter(struct run_request *req,
                                struct zcl_command_reply *reply)
{
    if (!req->adapter || !req->adapter[0]) req->adapter = "manual";
    req->codex_adapter = strcmp(req->adapter, "codex") == 0;
    if (strcmp(req->adapter, "manual") != 0 && !req->codex_adapter) {
        run_fail(reply, "ADAPTER_REFUSED", "adapter",
                 "adapter must name one fixed adapter: manual or codex",
                 false, false);
        return false;
    }
    if (req->codex_adapter && !run_codex_runner_path(req->codex_runner)) {
        run_fail(reply, "ADAPTER_UNAVAILABLE", "adapter",
                 "the fixed confined Codex runner or one supported single-run CODEX credential is unavailable; manual remains safe",
                 true, false);
        return false;
    }
    return true;
}

static bool run_request_paths(struct run_request *req,
                              const char *workspace_arg,
                              const char *proof_datadir_arg,
                              struct zcl_command_reply *reply)
{
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    if (!platform_directory_canonical_real(workspace_arg, req->workspace,
                                           ZWORK_RUN_PATH_MAX)) {
        run_fail(reply, "BAD_WORKSPACE", "resolve",
                 "workspace must resolve to an existing directory", false,
                 false);
        return false;
    }
    if (proof_datadir_arg && proof_datadir_arg[0] &&
        !platform_directory_canonical_real(proof_datadir_arg,
                                           req->proof_datadir,
                                           ZWORK_RUN_PATH_MAX)) {
        run_fail(reply, "BAD_DATADIR", "resolve",
                 "datadir must resolve to an existing full-node data directory",
                 false, false);
        return false;
    }
    return true;
}

static bool run_request_read(const struct zcl_command_request *request,
                             struct run_request *req,
                             struct zcl_command_reply *reply)
{
    memset(req, 0, sizeof(*req));
    const char *workspace_arg = run_str(request->input, "workspace");
    req->work = run_str(request->input, "work");
    req->adapter = run_str(request->input, "adapter");
    req->details = run_bool(request->input, "details");
    const char *proof_datadir_arg = run_request_datadir_arg(request);
    return run_request_adapter(req, reply) &&
        run_request_paths(req, workspace_arg, proof_datadir_arg, reply);
}

/* The run handler admits a task whose context is unique, whose canonical
 * facts all reload, and which has not expired. */
static bool run_session_load(struct run_selection *selection,
                             const char *workspace, const char *work)
{
    selection->index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    selection->entry = selection->index
        ? run_resolve(selection->index, work, &selection->ambiguous) : NULL;
    selection->context_entry = selection->entry
        ? vcs_zcode_task_index_context_for_task(
              selection->index, selection->entry->task_root_hex,
              &selection->context_ambiguous) : NULL;
    return selection->entry && selection->context_entry &&
        !selection->context_ambiguous &&
        run_load_task(workspace, selection->entry->task_root_hex,
                      &selection->task) &&
        (selection->goal = run_load_goal(workspace, &selection->task)) !=
            NULL &&
        run_load_context(workspace, selection->context_entry,
                         &selection->task, selection->entry->task_root_hex,
                         &selection->context,
                         &selection->context_admission) &&
        run_load_scope(workspace, &selection->task, &selection->scope) &&
        !selection->entry->expired;
}

static void run_session_refuse(struct zcl_command_reply *reply,
                               const struct run_selection *selection)
{
    run_fail(reply, selection->context_ambiguous ? "AMBIGUOUS_CONTEXT" :
                 selection->ambiguous ? "AMBIGUOUS_WORK" :
                 "WORK_HANDOFF_MISSING",
             "resolve",
             selection->entry && selection->entry->expired
                ? "task expired; start a new bounded work item"
                : selection->context_ambiguous
                ? "task has multiple contexts; select an exact expert context"
                : "verified task, goal, and unique context could not be reloaded",
             false, false);
}

/* Terminal-for-run states: the candidate's evidence is complete (or the
 * work is already accepted).  Repeating run is an idempotent observation
 * of that fact — never a fresh candidate attempt.  This is the same
 * interpretation zcode work status gives the same lifecycle fact. */
static bool run_state_is_terminal(const char *state)
{
    return strcmp(state, VCS_ZCODE_TASK_STATE_EVIDENCE_READY) == 0 ||
        strcmp(state, VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0 ||
        strcmp(state, VCS_ZCODE_TASK_STATE_PROVEN) == 0;
}

static void run_render_terminal(
    struct zcl_command_reply *reply,
    const struct vcs_zcode_task_index_entry *entry, const char *workspace)
{
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
}

/* Same lifecycle fact, same interpretation as zcode work status: the
 * admitted candidate waits on independent proof that is outstanding in the
 * bound node's ledger.  Repeating run is an idempotent observation of that
 * wait — not a failure and never a fresh attempt. */
static void run_render_awaiting_proof(
    struct zcl_command_reply *reply,
    const struct vcs_zcode_task_index_entry *entry, const char *workspace,
    const char *pending_state)
{
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
}

static void run_render_admitted(
    struct zcl_command_reply *reply,
    const struct vcs_zcode_task_index_entry *entry, const char *workspace,
    const char *proof_datadir)
{
    char pending_state[BUILD_PROOF_EVENT_STATE_MAX + 1];
    if (run_async_proof_pending(proof_datadir, entry->task_root_hex,
                                entry->latest_candidate_root_hex,
                                pending_state)) {
        run_render_awaiting_proof(reply, entry, workspace, pending_state);
        return;
    }
    run_fail(reply, "CANDIDATE_EXECUTION_INCOMPLETE", "build",
             "the candidate is captured but its prior package execution produced no signed work receipt and no supervised independent proof is outstanding; preserve it and diagnose the package prerequisite before starting another attempt",
             true, true);
}

/* Lifecycle states that end this run without a fresh candidate attempt. */
static bool run_lifecycle_handled(struct zcl_command_reply *reply,
                                  const struct run_selection *selection,
                                  const struct run_request *req)
{
    if (run_state_is_terminal(selection->entry->state)) {
        run_render_terminal(reply, selection->entry, req->workspace);
        return true;
    }
    if (strcmp(selection->entry->state,
               VCS_ZCODE_TASK_STATE_CANDIDATE_ADMITTED) == 0) {
        run_render_admitted(reply, selection->entry, req->workspace,
                            req->proof_datadir);
        return true;
    }
    if (selection->entry->candidate_count >= 3u) {
        run_fail(reply, "REPAIR_LIMIT_REACHED", "repair",
                 "three candidate attempts are preserved; start a new bounded work item",
                 false, false);
        return true;
    }
    return false;
}

/* One isolated candidate attempt: the workspace it materializes, whether
 * this invocation created it, and the bounded packet a previous attempt
 * may have left behind. */
struct run_attempt {
    uint64_t candidate_sequence;
    bool repairing;
    bool created;
    bool metadata_composed;
    uint8_t materialize_root[32];
    char candidate_workspace[ZWORK_RUN_PATH_MAX];
    char *prior_packet;
    size_t prior_packet_len;
};

static void run_attempt_free(struct run_attempt *attempt)
{
    free(attempt->prior_packet);
    attempt->prior_packet = NULL;
}

/* A fresh attempt materializes the task source; a repair attempt
 * materializes the exact candidate source the last attempt left. */
static bool run_materialize_root(const struct run_selection *selection,
                                 bool repairing,
                                 uint8_t materialize_root[32])
{
    if (repairing)
        return zcl_hex_decode_lower(
            selection->entry->latest_candidate_source_root_hex,
            materialize_root, 32);
    memcpy(materialize_root, selection->task.source_root, 32);
    return true;
}

static const char *run_handoff_refusal(
    enum vcs_zcode_agent_context_result admission)
{
    return admission == VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE
        ? "complete context is required before model execution"
        : admission == VCS_ZCODE_AGENT_CONTEXT_BINDING
        ? "task and context bindings disagree"
        : "isolated candidate workspace could not be created";
}

static bool run_attempt_open(struct run_attempt *attempt,
                             const struct run_request *req,
                             const struct run_selection *selection,
                             struct zcl_command_reply *reply)
{
    attempt->candidate_sequence = selection->entry->candidate_count + 1u;
    bool materialize_root_ok = run_materialize_root(
        selection, attempt->repairing, attempt->materialize_root);
    if (selection->context_admission != VCS_ZCODE_AGENT_CONTEXT_OK ||
        !materialize_root_ok || !run_candidate_workspace(
            req->workspace, &selection->task,
            selection->entry->task_root_hex,
            (uint32_t)attempt->candidate_sequence, attempt->materialize_root,
            attempt->candidate_workspace, &attempt->created)) {
        run_fail(reply, "HANDOFF_REFUSED", "materialize",
                 run_handoff_refusal(selection->context_admission),
                 true, false);
        return false;
    }
    if (!run_compose_candidate_metadata(
            attempt->candidate_workspace, &selection->task, req->workspace,
            &attempt->metadata_composed)) {
        run_fail(reply, "DEPENDENCY_COMPOSITION_REFUSED", "compose",
                 "the exact task dependency lock could not be reflected in the isolated candidate metadata",
                 false, attempt->created);
        return false;
    }
    return true;
}

/* A repair attempt may reuse the bounded packet the previous attempt left,
 * and the ephemeral adapter files are removed either way before this attempt
 * stages its own. */
static bool run_attempt_prior_packet(struct run_attempt *attempt,
                                     struct zcl_command_reply *reply)
{
    char prior_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    int prior_packet_status = attempt->repairing && !attempt->created
        ? run_read_packet(attempt->candidate_workspace,
                          &attempt->prior_packet, &attempt->prior_packet_len)
        : 0;
    if (run_packet_path(attempt->candidate_workspace, prior_packet_path))
        run_adapter_cleanup(attempt->candidate_workspace, prior_packet_path);
    if (prior_packet_status < 0) {
        run_fail(reply, "REPAIR_CONTEXT_REFUSED", "context",
                 "the bounded repair handoff was not a private regular packet",
                 true, false);
        return false;
    }
    return true;
}

static void run_admit_attempt(const struct run_request *req,
                              const struct run_selection *selection,
                              const struct run_attempt *attempt,
                              const char *adapter_name,
                              struct zcl_command_reply *reply, bool *handled)
{
    struct run_admit_context admit = {
        .workspace = req->workspace,
        .candidate_workspace = attempt->candidate_workspace,
        .proof_datadir = req->proof_datadir,
        .goal = selection->goal,
        .entry = selection->entry,
        .context_entry = selection->context_entry,
        .task = &selection->task,
        .context = &selection->context,
        .scope = &selection->scope,
        .candidate_sequence = attempt->candidate_sequence,
        .adapter_name = adapter_name,
        .details = req->details,
    };
    *handled = run_admit(&admit, reply);
}

static void run_manual_admit(const struct run_request *req,
                             const struct run_selection *selection,
                             const struct run_attempt *attempt,
                             int64_t feedback_started_us,
                             struct zcl_command_reply *reply)
{
    bool handled = false;
    run_admit_attempt(req, selection, attempt, "manual", reply, &handled);
    if (handled) run_feedback_timing(reply, feedback_started_us);
    if (!handled)
        run_fail(reply, "CANDIDATE_ADMISSION_FAILED", "admit",
                 "scratch identity or existing task composition failed",
                 true, false);
}

enum run_step { RUN_STEP_CONTINUE, RUN_STEP_DONE };

/* A candidate workspace this invocation did not create may already hold the
 * edited candidate; only a behavior change beyond dependency composition
 * counts as one worth admitting. */
static enum run_step run_attempt_capture_existing(
    const struct run_request *req, const struct run_selection *selection,
    const struct run_attempt *attempt, int64_t feedback_started_us,
    struct zcl_command_reply *reply)
{
    uint8_t candidate_root[32];
    if (vcs_tree_capture_into(attempt->candidate_workspace, req->workspace,
                              candidate_root) != VCS_OK) {
        run_fail(reply, "CANDIDATE_CAPTURE_FAILED", "capture",
                 "candidate workspace changed or contains a refused file",
                 true, false);
        return RUN_STEP_DONE;
    }
    if (memcmp(candidate_root, attempt->materialize_root, 32) != 0 &&
        run_candidate_has_behavior_change(
            req->workspace, attempt->materialize_root, candidate_root)) {
        run_manual_admit(req, selection, attempt, feedback_started_us, reply);
        return RUN_STEP_DONE;
    }
    return RUN_STEP_CONTINUE;
}

/* A repair attempt reuses the previous bounded packet only when it still
 * matches this goal and this attempt's diagnostic; otherwise the bounded
 * model context is composed fresh. */
static bool run_attempt_packet(struct json_value *packet,
                               const struct run_request *req,
                               const struct run_selection *selection,
                               const struct run_attempt *attempt,
                               char packet_detail[256])
{
    if (attempt->prior_packet) {
        bool packet_ok = json_read(packet, attempt->prior_packet,
                                   attempt->prior_packet_len) &&
            run_repair_packet_valid(packet, selection->goal,
                                    attempt->candidate_sequence);
        if (!packet_ok)
            (void)snprintf(packet_detail, 256,
                           "the bounded repair packet did not match the current goal and diagnostic");
        return packet_ok;
    }
    return run_packet(packet, selection->goal, req->workspace,
                      req->proof_datadir, &selection->task,
                      &selection->context, &selection->scope, packet_detail);
}

/* The confined Codex runner is spawned exactly once against the staged
 * packet, and the ephemeral packet is removed whether it succeeded or not. */
static int run_codex_invoke(const struct run_request *req,
                            const char *candidate_workspace,
                            const struct json_value *packet,
                            char *adapter_output, bool *staged_out)
{
    char packet_path[ZWORK_RUN_PATH_MAX] = {0};
    bool staged = adapter_output && run_write_packet(
        candidate_workspace, packet, packet_path);
    const char *const argv[] = {
        req->codex_runner, candidate_workspace, packet_path, NULL,
    };
    int rc = staged ? zcl_spawn_capture(
        argv, adapter_output, ZWORK_ADAPTER_OUTPUT_MAX, 300000) : -1;
    run_adapter_cleanup(candidate_workspace, packet_path);
    *staged_out = staged;
    return rc;
}

static void run_codex_refuse(struct zcl_command_reply *reply, int rc,
                             bool staged, const char *adapter_output)
{
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
}

static bool run_codex_captured(const struct run_request *req,
                               const struct run_attempt *attempt,
                               struct zcl_command_reply *reply)
{
    uint8_t candidate_root[32];
    bool captured = vcs_tree_capture_into(attempt->candidate_workspace,
                                          req->workspace,
                                          candidate_root) == VCS_OK;
    if (!captured ||
        memcmp(candidate_root, attempt->materialize_root, 32) == 0 ||
        !run_candidate_has_behavior_change(
            req->workspace, attempt->materialize_root, candidate_root)) {
        run_fail(reply, captured ? "ADAPTER_REFUSAL" :
                                  "CANDIDATE_CAPTURE_FAILED",
                 captured ? "adapter" : "capture",
                 captured ? "Codex completed without an admissible behavior change beyond dependency composition"
                          : "Codex output could not be captured safely",
                 true, true);
        return false;
    }
    return true;
}

static void run_codex_admit(const struct run_request *req,
                            const struct run_selection *selection,
                            const struct run_attempt *attempt,
                            size_t model_context_bytes,
                            const char *adapter_output,
                            int64_t feedback_started_us,
                            struct zcl_command_reply *reply)
{
    bool handled = false;
    run_admit_attempt(req, selection, attempt, "codex", reply, &handled);
    if (handled) run_feedback_timing(reply, feedback_started_us);
    if (handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)json_push_kv_int(&reply->data, "model_context_bytes",
                               (int64_t)model_context_bytes);
    if (handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)json_push_kv_bool(
            &reply->data, "candidate_dependency_metadata_changed",
            attempt->metadata_composed);
    if (req->details && handled &&
        reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)json_push_kv_str(&reply->data, "adapter_output",
                               adapter_output);
    if (!handled)
        run_fail(reply, "CANDIDATE_ADMISSION_FAILED", "admit",
                 "confined Codex result could not enter existing candidate authority",
                 true, true);
}

static void run_attempt_codex(const struct run_request *req,
                              const struct run_selection *selection,
                              const struct run_attempt *attempt,
                              const struct json_value *packet,
                              size_t model_context_bytes,
                              int64_t feedback_started_us,
                              struct zcl_command_reply *reply)
{
    char *adapter_output = zcl_malloc(ZWORK_ADAPTER_OUTPUT_MAX,
                                      "zcode.work.adapter.output");
    bool staged = false;
    int rc = run_codex_invoke(req, attempt->candidate_workspace, packet,
                              adapter_output, &staged);
    if (!staged || rc != 0)
        run_codex_refuse(reply, rc, staged, adapter_output);
    else if (run_codex_captured(req, attempt, reply))
        run_codex_admit(req, selection, attempt, model_context_bytes,
                        adapter_output, feedback_started_us, reply);
    free(adapter_output);
}

static bool run_manual_handoff_json(
    struct zcl_command_reply *reply, const struct run_request *req,
    const struct run_attempt *attempt, const char *work_id,
    const char *manual_packet_path, size_t model_context_bytes)
{
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state", attempt->repairing
                         ? "REPAIR_NEEDED" : "AWAITING_CANDIDATE") &&
        json_push_kv_str(&reply->data, "stage", "Creating missing code") &&
        json_push_kv_str(&reply->data, "candidate_workspace",
                         attempt->candidate_workspace) &&
        json_push_kv_str(&reply->data, "adapter_packet_path",
                         manual_packet_path) &&
        json_push_kv_int(&reply->data, "model_context_bytes",
                         (int64_t)model_context_bytes) &&
        json_push_kv_bool(&reply->data,
                          "candidate_dependency_metadata_changed",
                          attempt->metadata_composed) &&
        json_push_kv_str(&reply->data, "authority", "NONE_MANUAL_HANDOFF") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        run_add_work_next(
            reply, "zcode.work.status", req->workspace, work_id, NULL,
            "after editing the candidate workspace, show its exact next action");
}

static void run_render_manual_handoff(
    struct zcl_command_reply *reply, const struct run_request *req,
    const struct run_attempt *attempt, const char *work_id,
    const struct json_value *packet, size_t model_context_bytes,
    bool packet_ok)
{
    char manual_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    bool manual_staged = packet_ok && model_context_bytes > 0 &&
        run_write_packet(attempt->candidate_workspace, packet,
                         manual_packet_path);
    bool ok = manual_staged &&
        run_manual_handoff_json(reply, req, attempt, work_id,
                                manual_packet_path, model_context_bytes);
    if (!ok)
        run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                 "bounded manual adapter packet could not be rendered",
                 false, attempt->created);
}

/* Compose the bounded model context once, then hand it either to the
 * confined Codex adapter or to the person who will edit the candidate
 * workspace. */
static void run_attempt_finish(const struct run_request *req,
                               const struct run_selection *selection,
                               const struct run_attempt *attempt,
                               int64_t feedback_started_us,
                               struct zcl_command_reply *reply)
{
    struct json_value packet;
    json_init(&packet);
    char packet_detail[256];
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   selection->entry->task_root_hex);
    bool packet_ok = run_attempt_packet(&packet, req, selection, attempt,
                                        packet_detail);
    if (!packet_ok) {
        run_fail(reply, "MODEL_CONTEXT_REFUSED", "context",
                 packet_detail[0] ? packet_detail
                                  : "the bounded model context could not be rendered",
                 true, attempt->created);
        json_free(&packet);
        return;
    }
    size_t model_context_bytes = json_write(&packet, NULL, 0);
    if (req->codex_adapter)
        run_attempt_codex(req, selection, attempt, &packet,
                          model_context_bytes, feedback_started_us, reply);
    else
        run_render_manual_handoff(reply, req, attempt, work_id, &packet,
                                  model_context_bytes, packet_ok);
    json_free(&packet);
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
    struct run_request req;
    if (!run_request_read(request, &req, reply))
        return;
    struct run_selection selection;
    run_selection_init(&selection);
    if (!run_session_load(&selection, req.workspace, req.work)) {
        run_session_refuse(reply, &selection);
        run_selection_free(&selection);
        return;
    }
    if (run_lifecycle_handled(reply, &selection, &req)) {
        run_selection_free(&selection);
        return;
    }
    struct run_attempt attempt = {0};
    attempt.repairing = strcmp(selection.entry->state,
                               VCS_ZCODE_TASK_STATE_REPAIR_NEEDED) == 0;
    enum run_step step = RUN_STEP_CONTINUE;
    if (!run_attempt_open(&attempt, &req, &selection, reply) ||
        !run_attempt_prior_packet(&attempt, reply))
        step = RUN_STEP_DONE;
    if (step == RUN_STEP_CONTINUE && !attempt.created)
        step = run_attempt_capture_existing(&req, &selection, &attempt,
                                            feedback_started_us, reply);
    if (step == RUN_STEP_CONTINUE)
        run_attempt_finish(&req, &selection, &attempt, feedback_started_us,
                           reply);
    run_attempt_free(&attempt);
    run_selection_free(&selection);
}
