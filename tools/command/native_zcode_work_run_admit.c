/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: admission of one candidate into existing ZCODE candidate authority
 * for the native `zcode work run` command — deciding the bound ZBuild ledger,
 * composing the admission input, executing the contained scratch path, and
 * rendering the admitted or executed result — split out of
 * native_zcode_work_run_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_run_priv.h. */

#include "command/native_command.h"
#include "native_zcode_work_run_priv.h"

#include "base/hex.h"
#include "base/cleanse.h"
#include "config/runtime.h"
#include "json/json.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "vcs/build_action.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_write_scope.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool run_open_existing_ledger(
    struct node_db *ndb, const char *path, const char *reason)
{
    return ndb && path && path[0] && reason && reason[0] &&
           node_db_open_existing_runtime(ndb, path, reason);
}

static bool run_proof_roots_valid(const char *task_root_hex,
                                  const char *candidate_root_hex)
{
    return task_root_hex &&
        strlen(task_root_hex) == BUILD_PROOF_EVENT_ROOT_HEX &&
        candidate_root_hex &&
        strlen(candidate_root_hex) == BUILD_PROOF_EVENT_ROOT_HEX;
}

static bool run_proof_ledger_path(const char *proof_datadir,
                                  char db_path[ZWORK_RUN_PATH_MAX])
{
    if (!proof_datadir || !proof_datadir[0])
        return false;
    int n = snprintf(db_path, ZWORK_RUN_PATH_MAX, "%s/node.db",
                     proof_datadir);
    return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX &&
        access(db_path, F_OK) == 0;
}

/* The newest chain entry for this exact candidate decides: any state other
 * than SUPERSEDED means an independent proof is still outstanding. */
static bool run_proof_chain_pending(
    struct node_db *ndb, const char *task_root_hex,
    const char *candidate_root_hex,
    char state_out[BUILD_PROOF_EVENT_STATE_MAX + 1])
{
    struct db_build_proof_event events[64];
    int count = db_build_proof_events_for_task(ndb, task_root_hex, events,
                                               sizeof(events) /
                                                   sizeof(events[0]));
    const struct db_build_proof_event *latest = NULL;
    bool pending = false;
    for (int i = 0; i < count; i++) {
        if (strcmp(events[i].candidate_root_sha3, candidate_root_hex) != 0 ||
            !events[i].state[0])
            continue;
        latest = &events[i];
        if (strcmp(events[i].state, "SUPERSEDED") != 0)
            pending = true;
    }
    if (pending && latest)
        (void)snprintf(state_out, BUILD_PROOF_EVENT_STATE_MAX + 1u, "%s",
                       latest->state);
    return pending;
}

/* CANDIDATE_ADMITTED has exactly one meaning: the candidate is captured and
 * no signed work receipt exists for it yet.  Whether that is healthy waiting
 * or an incomplete execution is decided by one further fact — does the node
 * datadir this invocation is bound to hold an outstanding (not superseded)
 * async proof chain for the latest candidate?  The chain is keyed by task and
 * candidate roots because the task index cannot name the action before the
 * first receipt arrives.  A named or resident node datadir has a supervisor
 * that consumes that chain, so the wait is real and run must agree with zcode
 * work status instead of failing closed.  The closed scratch ledger has no
 * supervisor: a receipt gap there means the prior foreground execution never
 * finished, which stays CANDIDATE_EXECUTION_INCOMPLETE. */
bool run_async_proof_pending(
    const char *proof_datadir, const char *task_root_hex,
    const char *candidate_root_hex,
    char state_out[BUILD_PROOF_EVENT_STATE_MAX + 1])
{
    state_out[0] = '\0';
    if (!run_proof_roots_valid(task_root_hex, candidate_root_hex))
        return false;
    char db_path[ZWORK_RUN_PATH_MAX];
    if (!run_proof_ledger_path(proof_datadir, db_path))
        return false;
    struct node_db local_ndb = {0};
    struct node_db *runtime = app_runtime_node_db();
    bool owned = app_runtime_node_db_handle_open(runtime) &&
                 strcmp(db_path, runtime->path) == 0;
    struct node_db *ndb = owned ? runtime : &local_ndb;
    if (!owned && !run_open_existing_ledger(
            ndb, db_path, "zcode.work.run.proof_pending"))
        return false;
    bool pending = run_proof_chain_pending(ndb, task_root_hex,
                                           candidate_root_hex, state_out);
    if (!owned) node_db_close(ndb);
    return pending;
}

/* The exact facts the inner admission returned about the candidate it
 * captured.  A render reads only these; it never invents a value. */
struct run_admission_facts {
    const struct json_value *changed;
    const struct json_value *candidate;
    const struct json_value *candidate_source;
    const struct json_value *patch;
    const struct json_value *action;
    const struct json_value *proof_state;
    const struct json_value *proof_event;
    const struct json_value *proof_request;
    const struct json_value *submit_us;
};

static void run_admission_facts_read(const struct zcl_command_reply *inner,
                                     struct run_admission_facts *out)
{
    out->changed = json_get(&inner->data, "changed_files");
    out->candidate = json_get(&inner->data, "candidate_root");
    out->candidate_source = json_get(&inner->data, "candidate_source_root");
    out->patch = json_get(&inner->data, "patch_root");
    out->action = json_get(&inner->data, "action_id");
    out->proof_state = json_get(&inner->data, "async_proof_state");
    out->proof_event = json_get(&inner->data, "async_proof_event_root");
    out->proof_request = json_get(&inner->data, "remote_request_id");
    out->submit_us = json_get(&inner->data, "local_submit_us");
}

static bool run_admission_facts_complete(const struct run_admission_facts *f)
{
    return f->changed && f->candidate && f->candidate_source && f->patch &&
        f->action && f->proof_state && f->proof_event && f->proof_request &&
        f->submit_us;
}

/* The locally executed render needs neither the candidate source root nor the
 * action id, so it asks the narrower question. */
static bool run_admission_facts_renderable(
    const struct run_admission_facts *f)
{
    return f->changed && f->candidate && f->patch && f->proof_state &&
        f->proof_event && f->proof_request && f->submit_us;
}

static char *run_wire_hex(const char *workspace, const uint8_t root[32],
                          size_t maximum_bytes)
{
    uint8_t *wire = NULL;
    size_t len = 0;
    if (vcs_object_load_raw_bounded(workspace, root, maximum_bytes,
                                    &wire, &len) != 0 || len == 0 ||
        len > (SIZE_MAX - 1u) / 2u) {
        free(wire);
        return NULL;
    }
    char *hex = zcl_malloc(len * 2u + 1u, "zcode.work.run.wire_hex");
    if (hex) zcl_hex_encode(wire, len, hex);
    free(wire);
    return hex;
}

static bool run_scope_csv(const struct vcs_zcode_write_scope_v1 *scope,
                          char out[4097])
{
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < scope->count; i++) {
        size_t len = strlen(scope->paths[i]);
        size_t extra = len + (i ? 1u : 0u);
        if (extra > 4096u - used) return false;
        if (i) out[used++] = ',';
        memcpy(out + used, scope->paths[i], len);
        used += len;
        out[used] = '\0';
    }
    return used > 0;
}

static bool run_admit_input_scope(
    struct json_value *input, const struct run_admit_context *ctx,
    const char *datadir, const char *policy, const char *lock,
    const char *recipe, const char *scopes, const char *model_hex)
{
    return json_push_kv_str(input, "mode", "admit") &&
        json_push_kv_str(input, "workspace", ctx->workspace) &&
        json_push_kv_str(input, "datadir", datadir) &&
        json_push_kv_str(input, "goal", ctx->goal) &&
        json_push_kv_str(input, "proof_policy_hex", policy) &&
        json_push_kv_str(input, "dependency_lock_hex", lock) &&
        json_push_kv_str(input, "acceptance_recipe_hex", recipe) &&
        json_push_kv_str(input, "write_scope_csv", scopes) &&
        json_push_kv_str(input, "model_policy_root", model_hex);
}

static bool run_admit_input_binding(
    struct json_value *input, const struct run_admit_context *ctx,
    const char *author_hex, const char *adapter_hex,
    const char *execution_profile)
{
    return json_push_kv_str(input, "context_symbol", ctx->context->query) &&
        json_push_kv_str(input, "planned_task_root",
                         ctx->entry->task_root_hex) &&
        json_push_kv_str(input, "planned_context_root",
                         ctx->context_entry->context_root_hex) &&
        json_push_kv_str(input, "candidate_workspace",
                         ctx->candidate_workspace) &&
        json_push_kv_str(input, "adapter_policy_root", adapter_hex) &&
        json_push_kv_str(input, "author_pubkey", author_hex) &&
        json_push_kv_int(input, "candidate_sequence",
                         (int64_t)ctx->candidate_sequence) &&
        json_push_kv_str(input, "action_kind",
                         VCS_BUILD_ACTION_KIND_PACKAGE_V1) &&
        json_push_kv_str(input, "profile", execution_profile);
}

static bool run_admit_input_limits(struct json_value *input,
                                   const struct vcs_zcode_task_v1 *task)
{
    return json_push_kv_int(input, "expires_unix", task->expires_unix) &&
        json_push_kv_int(input, "max_changed_files",
                         task->max_changed_files) &&
        json_push_kv_int(input, "max_patch_bytes",
                         (int64_t)task->max_patch_bytes) &&
        json_push_kv_int(input, "max_context_bytes",
                         (int64_t)task->max_context_bytes) &&
        json_push_kv_int(input, "max_cpu_seconds", task->max_cpu_seconds) &&
        json_push_kv_int(input, "max_memory_bytes",
                         (int64_t)task->max_memory_bytes) &&
        json_push_kv_int(input, "max_output_bytes",
                         (int64_t)task->max_output_bytes);
}

static bool run_admit_input(
    struct json_value *input, const struct run_admit_context *ctx,
    const char *datadir, const char *author_hex, const char *adapter_hex,
    const char *execution_profile)
{
    char *policy = run_wire_hex(ctx->workspace, ctx->task->proof_policy_root,
                                VCS_ZCODE_PROOF_POLICY_WIRE_BYTES);
    char *lock = run_wire_hex(ctx->workspace,
                              ctx->task->dependency_lock_root,
                              VCS_PACKAGE_LOCK_MAX_WIRE_BYTES);
    char *recipe = run_wire_hex(ctx->workspace,
                                ctx->task->acceptance_tests_root,
                                VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES);
    char scopes[4097], model_hex[65];
    zcl_hex_encode(ctx->task->model_policy_root, 32, model_hex);
    json_init(input); json_set_object(input);
    bool ok = policy && lock && recipe && run_scope_csv(ctx->scope, scopes) &&
        run_admit_input_scope(input, ctx, datadir, policy, lock, recipe,
                              scopes, model_hex) &&
        run_admit_input_binding(input, ctx, author_hex, adapter_hex,
                                execution_profile) &&
        run_admit_input_limits(input, ctx->task);
    free(recipe); free(lock); free(policy);
    return ok;
}

static bool run_standard_policy(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    bool *standard)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_proof_policy_v1 policy;
    if (!standard || vcs_object_load_raw_bounded(
            workspace, task->proof_policy_root,
            VCS_ZCODE_PROOF_POLICY_WIRE_BYTES, &wire, &wire_len) != 0)
        return false;
    bool ok = vcs_zcode_proof_policy_parse(wire, wire_len, &policy) ==
              VCS_ZCODE_DEV_OK;
    free(wire);
    if (!ok) return false;
    *standard = policy.minimum_compile_receipts >= 2u ||
                policy.minimum_test_receipts >= 2u;
    return true;
}

static struct zcl_result run_plan_standard_peer(
    const char *datadir, const char *primary_action_id,
    char peer_action_id[BUILD_FABRIC_ID_HEX + 1])
{
    char db_path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb = {0};
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        !run_open_existing_ledger(
            &ndb, db_path, "zcode.work.run.standard_peer"))
        return ZCL_ERR(-1, "scratch ZBuild ledger could not be reopened");
    int64_t now = platform_time_wall_unix();
    char peer_job_id[BUILD_FABRIC_ID_HEX + 1];
    struct zcl_result result = build_fabric_plan_reproduction(
        &ndb, primary_action_id, VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1,
        now, peer_action_id, peer_job_id);
    if (result.ok) result = build_fabric_submit(&ndb, peer_job_id, now);
    node_db_close(&ndb);
    return result;
}

static struct zcl_result run_execute_action(
    const char *workspace, const char *datadir, const char *action_id,
    struct db_build_worker *worker, const uint8_t secret[32],
    const uint8_t pubkey[32], struct db_build_receipt *receipt,
    struct build_fabric_worker_feedback *feedback)
{
    char db_path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb = {0};
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        !run_open_existing_ledger(
            &ndb, db_path, "zcode.work.run.execute"))
        return ZCL_ERR(-1, "scratch ZBuild ledger could not be reopened");
    int64_t now = platform_time_wall_unix();
    worker->last_seen_at = now;
    struct zcl_result result = build_fabric_worker_approve(
        &ndb, worker, now);
    uint8_t lease_root[32];
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.zcode.work.local_lease.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, (const uint8_t *)action_id, strlen(action_id));
    sha3_256_finalize(&sha, lease_root);
    char lease_id[65];
    zcl_hex_encode(lease_root, 32, lease_id);
    struct db_build_action claimed_action;
    bool claimed = false;
    if (result.ok)
        result = build_fabric_claim(
            &ndb, worker->worker_id, lease_id, now,
            BUILD_FABRIC_LEASE_SECONDS_MAX, &claimed_action, &claimed);
    if (result.ok && (!claimed ||
        strcmp(claimed_action.action_id, action_id) != 0))
        result = ZCL_ERR(-1, "queued action was not claimable by exact id");
    if (result.ok)
        result = build_fabric_worker_execute(
            &ndb, workspace, datadir, action_id, lease_id,
            secret, pubkey, receipt, feedback);
    node_db_close(&ndb);
    return result;
}

static bool run_worker_feedback_json(
    struct json_value *out,
    const struct build_fabric_worker_feedback *feedback)
{
    json_init(out); json_set_object(out);
    bool present = feedback && feedback->present;
    return json_push_kv_bool(out, "available", present) &&
        (!present ||
         (json_push_kv_str(out, "stage", feedback->stage) &&
          json_push_kv_str(out, "compiler", feedback->compiler) &&
          json_push_kv_str(out, "path", feedback->path) &&
          json_push_kv_int(out, "line", feedback->line) &&
          json_push_kv_int(out, "column", feedback->column) &&
          json_push_kv_str(out, "message", feedback->message)));
}

static bool run_async_expert_json(
    struct json_value *expert,
    const struct vcs_zcode_task_index_entry *entry,
    const struct run_admission_facts *facts)
{
    return json_push_kv_str(expert, "task_root", entry->task_root_hex) &&
        json_push_kv_str(expert, "candidate_root",
                         json_get_str(facts->candidate)) &&
        json_push_kv_str(expert, "candidate_source_root",
                         json_get_str(facts->candidate_source)) &&
        json_push_kv_str(expert, "patch_root",
                         json_get_str(facts->patch)) &&
        json_push_kv_str(expert, "action_id", json_get_str(facts->action));
}

static bool run_async_state_json(
    struct zcl_command_reply *reply, const char *work_id,
    const struct run_admission_facts *facts)
{
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state", "CANDIDATE_ADMITTED") &&
        json_push_kv_str(&reply->data, "stage",
                         "Waiting for independent reproduction") &&
        json_push_kv_int(&reply->data, "changed_files",
                         json_get_int(facts->changed)) &&
        json_push_kv_str(&reply->data, "async_proof_state",
                         json_get_str(facts->proof_state)) &&
        json_push_kv_int(&reply->data, "local_submit_us",
                         json_get_int(facts->submit_us));
}

static bool run_async_result_json(struct zcl_command_reply *reply,
                                  const char *adapter_name)
{
    return json_push_kv_str(&reply->data, "build_result",
                            "background_pending") &&
        json_push_kv_int(&reply->data, "compile_receipts", 0) &&
        json_push_kv_int(&reply->data, "test_receipts", 0) &&
        json_push_kv_str(&reply->data, "sanitizer_result", "pending") &&
        json_push_kv_str(&reply->data, "remote_outcome",
                         "BACKGROUND_PENDING") &&
        json_push_kv_str(&reply->data, "adapter", adapter_name) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode work status") &&
        json_push_kv_bool(&reply->data, "details_available", true);
}

static bool run_async_details_json(
    struct zcl_command_reply *reply, const struct run_admission_facts *facts,
    const struct json_value *expert)
{
    return json_push_kv_str(&reply->data, "candidate_root",
                            json_get_str(facts->candidate)) &&
        json_push_kv_str(&reply->data, "patch_root",
                         json_get_str(facts->patch)) &&
        json_push_kv_str(&reply->data, "async_proof_event_root",
                         json_get_str(facts->proof_event)) &&
        json_push_kv_int(&reply->data, "remote_request_id",
                         json_get_int(facts->proof_request)) &&
        json_push_kv(&reply->data, "expert", expert);
}

/* Timing the inner admission measured is copied through when it is present
 * and simply absent otherwise, so a build that did not measure one still
 * renders the rest. */
static bool run_async_metric_json(struct zcl_command_reply *reply,
                                  const struct zcl_command_reply *inner)
{
    static const char *const metric_keys[] = {
        "foreground_request_creation_us",
        "durable_action_lookup_dedup_us",
        "live_rpc_encode_us",
        "live_rpc_admission_us",
        "live_rpc_decode_us",
        "live_rpc_request_bytes",
        "live_rpc_response_bytes",
    };
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(metric_keys) / sizeof(metric_keys[0]);
         i++) {
        const struct json_value *value = json_get(
            &inner->data, metric_keys[i]);
        if (value && value->type == JSON_INT)
            ok = json_push_kv_int(&reply->data, metric_keys[i],
                                  json_get_int(value));
    }
    return ok;
}

static bool run_async_reproduction_json(
    struct zcl_command_reply *reply, const struct zcl_command_reply *inner)
{
    static const char *const reproduction_string_keys[] = {
        "reproduction_action_id",
        "reproduction_job_id",
        "reproduction_async_proof_event_root",
    };
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(reproduction_string_keys) /
                                      sizeof(reproduction_string_keys[0]);
         i++) {
        const struct json_value *value = json_get(
            &inner->data, reproduction_string_keys[i]);
        if (value && value->type == JSON_STR)
            ok = json_push_kv_str(&reply->data, reproduction_string_keys[i],
                                  json_get_str(value));
    }
    const struct json_value *reproduction_request = json_get(
        &inner->data, "reproduction_remote_request_id");
    if (ok && reproduction_request &&
        reproduction_request->type == JSON_INT)
        ok = json_push_kv_int(
            &reply->data, "reproduction_remote_request_id",
            json_get_int(reproduction_request));
    return ok;
}

static bool run_render_async_admission(
    struct zcl_command_reply *reply,
    const struct vcs_zcode_task_index_entry *entry,
    const struct zcl_command_reply *inner, const char *adapter_name,
    const char *workspace, const char *proof_datadir, bool details)
{
    struct run_admission_facts facts;
    run_admission_facts_read(inner, &facts);
    if (!run_admission_facts_complete(&facts))
        return false;
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    struct json_value expert;
    json_init(&expert); json_set_object(&expert);
    bool ok = (!details || run_async_expert_json(&expert, entry, &facts)) &&
        run_async_state_json(reply, work_id, &facts) &&
        run_async_result_json(reply, adapter_name) &&
        (!details || run_async_details_json(reply, &facts, &expert)) &&
        run_add_work_next(
            reply, "zcode.work.status", workspace, work_id, NULL, proof_datadir,
            "show the admitted candidate while independent proof arrives");
    ok = ok && run_async_metric_json(reply, inner);
    ok = ok && (!details || run_async_reproduction_json(reply, inner));
    json_free(&expert);
    return ok;
}

/* Admission is bound to one ZBuild ledger: the explicit node datadir when the
 * caller named one, and otherwise the contained scratch ledger beside the
 * candidate workspace. */
static bool run_admit_datadir(const char *proof_datadir,
                              const char *candidate_workspace,
                              char datadir[ZWORK_RUN_PATH_MAX])
{
    if (proof_datadir && proof_datadir[0]) {
        int n = snprintf(datadir, ZWORK_RUN_PATH_MAX, "%s", proof_datadir);
        return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX;
    }
    (void)snprintf(datadir, ZWORK_RUN_PATH_MAX, "%s", candidate_workspace);
    char *slash = strrchr(datadir, '/');
    if (!slash) return false;
    (void)snprintf(slash, (size_t)(datadir + ZWORK_RUN_PATH_MAX - slash),
                   "/zbuild");
    return true;
}

/* The adapter policy root binds this attempt to its adapter, its exact expert
 * context, and — for a repair attempt — the parent candidate it repairs. */
static bool run_admit_adapter_root(const struct run_admit_context *ctx,
                                   char adapter_hex[65])
{
    uint8_t context_root[32], adapter_root[32];
    bool rooted = zcl_hex_decode_lower(ctx->context_entry->context_root_hex,
                                       context_root, 32);
    struct sha3_256_ctx sha;
    static const char manual_domain[] = "zcl.zcode.adapter.manual.v1";
    static const char codex_domain[] = "zcl.zcode.adapter.codex.v1";
    const char *domain = strcmp(ctx->adapter_name, "codex") == 0
        ? codex_domain : manual_domain;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1u);
    if (rooted) sha3_256_write(&sha, context_root, sizeof(context_root));
    if (rooted && ctx->candidate_sequence > 1u) {
        uint8_t parent_root[32];
        if (!zcl_hex_decode_lower(ctx->entry->latest_candidate_root_hex,
                                  parent_root, sizeof(parent_root)))
            rooted = false;
        else
            sha3_256_write(&sha, parent_root, sizeof(parent_root));
    }
    sha3_256_finalize(&sha, adapter_root);
    zcl_hex_encode(adapter_root, 32, adapter_hex);
    return rooted;
}

static bool run_admit_improve(struct json_value *input,
                              struct zcl_command_reply *inner)
{
    struct zcl_command_request inner_request = { .input = input };
    zcl_command_reply_init(inner, "zcl.zcode_improve.v1");
    zcl_native_handle_zcode_improve(&inner_request, inner);
    return inner->status == ZCL_COMMAND_STATUS_PASSED;
}

/* The inner admission's own typed refusal is preserved exactly; only a
 * refusal that named nothing falls back to the generic code. */
static void run_admit_refuse(struct zcl_command_reply *reply,
                             const struct zcl_command_reply *inner)
{
    run_fail(reply, inner->error.code[0] ? inner->error.code :
                 "CANDIDATE_ADMISSION_FAILED",
             inner->error.phase[0] ? inner->error.phase : "admit",
             inner->error.message[0] ? inner->error.message :
                 "existing candidate admission refused",
             inner->error.retryable, inner->error.mutated);
}

/* The contained scratch path runs the admitted action here, and runs the
 * independent standard-profile peer too when the proof policy asks for one. */
static struct zcl_result run_admit_execute(
    const struct run_admit_context *ctx, const char *datadir,
    const char *action_id, struct db_build_worker *worker,
    const uint8_t secret[32], const uint8_t pubkey[32], bool standard,
    struct db_build_receipt *receipt,
    struct build_fabric_worker_feedback *feedback,
    char peer_action_id[BUILD_FABRIC_ID_HEX + 1],
    struct db_build_receipt *peer_receipt)
{
    struct zcl_result executed = action_id
        ? run_execute_action(ctx->workspace, datadir, action_id, worker,
                             secret, pubkey, receipt, feedback)
        : ZCL_ERR(-1, "admission did not return an action id");
    if (executed.ok && receipt->exit_status == 0 && standard) {
        executed = run_plan_standard_peer(datadir, action_id, peer_action_id);
        if (executed.ok)
            executed = run_execute_action(
                ctx->workspace, datadir, peer_action_id, worker, secret,
                pubkey, peer_receipt, NULL);
    }
    return executed;
}

static void run_admit_build_failed(
    struct zcl_command_reply *reply, const char *message,
    const struct build_fabric_worker_feedback *feedback)
{
    run_fail(reply, "PACKAGE_BUILD_FAILED", "build", message, true, true);
    struct json_value compiler_feedback;
    if (run_worker_feedback_json(&compiler_feedback, feedback))
        (void)json_push_kv(&reply->data, "compiler_feedback",
                           &compiler_feedback);
    json_free(&compiler_feedback);
}

/* One decided outcome names the lifecycle state, the stage a person sees, the
 * sanitizer verdict and the exact next safe command. */
static const char *run_admit_state_name(bool passed, bool retry_ready)
{
    return passed ? "EVIDENCE_READY" :
           retry_ready ? "REPAIR_NEEDED" : "BLOCKED";
}

static const char *run_admit_stage_name(bool passed, bool retry_ready)
{
    return passed ? "Showing result" :
           retry_ready ? "Creating missing code" : "Needs attention";
}

static const char *run_admit_sanitizer_result(bool passed, bool standard)
{
    return passed && standard ? "passed_asan_ubsan" :
           standard ? "failed_or_unavailable" : "not_required";
}

static const char *run_admit_next_command(bool passed, bool retry_ready)
{
    return passed ? "zcode work status" :
           retry_ready
             ? "edit candidate_workspace, then rerun zcode work run"
             : "zcode work status";
}

static int64_t run_admit_receipt_count(bool passed, bool standard)
{
    return passed ? (standard ? 2 : 1) : 0;
}

static bool run_admit_passed(const struct db_build_receipt *receipt,
                             bool standard,
                             const struct db_build_receipt *peer_receipt)
{
    return receipt->exit_status == 0 &&
        (!standard || peer_receipt->exit_status == 0);
}

static bool run_admit_expert_core(
    struct json_value *expert, const struct run_admit_context *ctx,
    const struct run_admission_facts *facts)
{
    return facts->action && facts->candidate && facts->candidate_source &&
        facts->patch &&
        json_push_kv_str(expert, "task_root", ctx->entry->task_root_hex) &&
        json_push_kv_str(expert, "candidate_root",
                         json_get_str(facts->candidate)) &&
        json_push_kv_str(expert, "candidate_source_root",
                         json_get_str(facts->candidate_source)) &&
        json_push_kv_str(expert, "patch_root",
                         json_get_str(facts->patch)) &&
        json_push_kv_str(expert, "action_id", json_get_str(facts->action));
}

static bool run_admit_expert_receipt(
    struct json_value *expert, const struct db_build_receipt *receipt,
    bool standard, const char *peer_action_id,
    const struct db_build_receipt *peer_receipt)
{
    return json_push_kv_str(expert, "receipt_id", receipt->receipt_id) &&
        json_push_kv_str(expert, "output_root", receipt->output_sha3) &&
        json_push_kv_str(expert, "work_receipt_root",
                         receipt->work_receipt_sha3) &&
        (!standard ||
         (json_push_kv_str(expert, "standard_peer_action_id",
                           peer_action_id) &&
          json_push_kv_str(expert, "standard_peer_work_receipt_root",
                           peer_receipt->work_receipt_sha3)));
}

static bool run_admit_diagnostic_json(
    struct json_value *diagnostic, struct json_value *compiler_feedback,
    uint64_t candidate_sequence, const struct db_build_receipt *receipt,
    bool retry_ready,
    const struct build_fabric_worker_feedback *feedback)
{
    bool feedback_ok = run_worker_feedback_json(compiler_feedback, feedback);
    return json_push_kv_str(diagnostic, "stage",
                            "package_build_and_tests") &&
        json_push_kv_int(diagnostic, "attempt",
                         (int64_t)candidate_sequence) &&
        json_push_kv_int(diagnostic, "exit_status", receipt->exit_status) &&
        json_push_kv_bool(diagnostic, "retry_safe", retry_ready) &&
        feedback_ok &&
        json_push_kv(diagnostic, "compiler_feedback", compiler_feedback);
}

/* A repair attempt is offered only while attempts remain and the exact
 * candidate source the adapter may edit could be materialized again. */
static bool run_admit_retry_workspace(
    const struct run_admit_context *ctx,
    const struct run_admission_facts *facts, bool passed,
    char next_workspace[ZWORK_RUN_PATH_MAX])
{
    uint8_t next_source_root[32];
    bool next_created = false;
    bool retry_ready = !passed && ctx->candidate_sequence < 3u &&
        facts->candidate_source && json_get_str(facts->candidate_source) &&
        zcl_hex_decode_lower(json_get_str(facts->candidate_source),
                             next_source_root, sizeof(next_source_root)) &&
        run_candidate_workspace(ctx->workspace, ctx->task,
                                ctx->entry->task_root_hex,
                                (uint32_t)ctx->candidate_sequence + 1u,
                                next_source_root, next_workspace,
                                &next_created);
    (void)next_created;
    return retry_ready;
}

/* The repair handoff staged for the next attempt: the same bounded model
 * context plus the exact diagnostic that failed. */
struct run_admit_repair {
    struct json_value packet;
    char packet_path[ZWORK_RUN_PATH_MAX];
    size_t packet_bytes;
    bool packet_ok;
    bool packet_staged;
};

static void run_admit_repair_packet(
    struct run_admit_repair *repair, const struct run_admit_context *ctx,
    const char *datadir, const char *next_workspace,
    const struct json_value *diagnostic, bool retry_ready)
{
    json_init(&repair->packet); json_set_object(&repair->packet);
    char repair_detail[256];
    repair->packet_ok = !retry_ready ||
        (run_packet(&repair->packet, ctx->goal, ctx->workspace, datadir,
                    ctx->task, ctx->context, ctx->scope, repair_detail) &&
         json_push_kv(&repair->packet, "diagnostic", diagnostic));
    repair->packet_bytes = retry_ready && repair->packet_ok
        ? json_write(&repair->packet, NULL, 0) : 0;
    repair->packet_staged = !retry_ready ||
        (repair->packet_bytes > 0 && run_write_packet(
            next_workspace, &repair->packet, repair->packet_path));
}

static bool run_admit_render_identity(
    struct zcl_command_reply *reply, const char *work_id, bool passed,
    bool retry_ready)
{
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state",
                         run_admit_state_name(passed, retry_ready)) &&
        json_push_kv_str(&reply->data, "stage",
                         run_admit_stage_name(passed, retry_ready));
}

static bool run_admit_render_evidence(
    struct zcl_command_reply *reply,
    const struct run_admission_facts *facts, bool passed, bool standard,
    uint64_t candidate_sequence, const struct json_value *diagnostic)
{
    return json_push_kv_int(&reply->data, "changed_files",
                            json_get_int(facts->changed)) &&
        json_push_kv_str(&reply->data, "async_proof_state",
                         json_get_str(facts->proof_state)) &&
        json_push_kv_int(&reply->data, "local_submit_us",
                         json_get_int(facts->submit_us)) &&
        json_push_kv_str(&reply->data, "build_result",
                         passed ? "passed" : "failed") &&
        json_push_kv_int(&reply->data, "compile_receipts",
                         run_admit_receipt_count(passed, standard)) &&
        json_push_kv_int(&reply->data, "test_receipts",
                         run_admit_receipt_count(passed, standard)) &&
        json_push_kv_str(&reply->data, "sanitizer_result",
                         run_admit_sanitizer_result(passed, standard)) &&
        json_push_kv_int(&reply->data, "attempt",
                         (int64_t)candidate_sequence) &&
        json_push_kv(&reply->data, "diagnostic", diagnostic);
}

static bool run_admit_render_repair(
    struct zcl_command_reply *reply, bool retry_ready, bool details,
    const char *next_workspace, const struct run_admit_repair *repair)
{
    return (!retry_ready ||
            json_push_kv_str(&reply->data, "candidate_workspace",
                             next_workspace)) &&
        (!retry_ready ||
         (json_push_kv_str(&reply->data, "repair_packet_path",
                           repair->packet_path) &&
          json_push_kv_int(&reply->data, "model_context_bytes",
                           (int64_t)repair->packet_bytes))) &&
        (!retry_ready || !details ||
         json_push_kv(&reply->data, "repair_packet", &repair->packet));
}

static bool run_admit_render_details(
    struct zcl_command_reply *reply,
    const struct run_admission_facts *facts,
    const struct db_build_receipt *receipt, const struct json_value *expert)
{
    return json_push_kv_str(&reply->data, "candidate_root",
                            json_get_str(facts->candidate)) &&
        json_push_kv_str(&reply->data, "patch_root",
                         json_get_str(facts->patch)) &&
        json_push_kv_str(&reply->data, "work_receipt_root",
                         receipt->work_receipt_sha3) &&
        json_push_kv_str(&reply->data, "async_proof_event_root",
                         json_get_str(facts->proof_event)) &&
        json_push_kv_int(&reply->data, "remote_request_id",
                         json_get_int(facts->proof_request)) &&
        json_push_kv(&reply->data, "expert", expert);
}

static bool run_admit_render(
    struct zcl_command_reply *reply, const struct run_admit_context *ctx,
    const struct run_admission_facts *facts,
    const struct db_build_receipt *receipt, const struct json_value *expert,
    const struct json_value *diagnostic,
    const struct run_admit_repair *repair, const char *next_workspace,
    const char *work_id, bool passed, bool standard, bool retry_ready)
{
    return run_admit_render_identity(reply, work_id, passed, retry_ready) &&
        run_admit_render_evidence(reply, facts, passed, standard,
                                  ctx->candidate_sequence, diagnostic) &&
        run_admit_render_repair(reply, retry_ready, ctx->details,
                                next_workspace, repair) &&
        json_push_kv_str(&reply->data, "adapter", ctx->adapter_name) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         run_admit_next_command(passed, retry_ready)) &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!ctx->details ||
         run_admit_render_details(reply, facts, receipt, expert)) &&
        run_add_work_next(
            reply, "zcode.work.status", ctx->workspace, work_id, NULL,
            ctx->proof_datadir,
            retry_ready
              ? "show the repair state and its exact resumable action"
              : "show the exact build and reproduction state");
}

static bool run_admit_expert_json(
    struct json_value *expert, const struct run_admit_context *ctx,
    const struct run_admission_facts *facts,
    const struct db_build_receipt *receipt, bool standard,
    const char *peer_action_id,
    const struct db_build_receipt *peer_receipt)
{
    return !ctx->details ||
        (run_admit_expert_core(expert, ctx, facts) &&
         run_admit_expert_receipt(expert, receipt, standard, peer_action_id,
                                  peer_receipt));
}

/* Nothing is rendered unless every fact the summary reads is present and
 * every part it composes was composed. */
static bool run_admit_renderable(
    const struct run_admission_facts *facts,
    const struct db_build_receipt *receipt, bool diagnostic_ok,
    bool expert_ok, const struct run_admit_repair *repair)
{
    return run_admission_facts_renderable(facts) && diagnostic_ok &&
        expert_ok && repair->packet_ok && repair->packet_staged &&
        receipt->work_receipt_sha3[0];
}

/* The contained scratch path executes the admitted action and renders the
 * complete result, including the repair handoff a failed attempt leaves. */
static void run_admit_local(
    const struct run_admit_context *ctx, const char *datadir,
    const struct run_admission_facts *facts, struct db_build_worker *worker,
    uint8_t secret[32], const uint8_t pubkey[32], bool standard,
    struct zcl_command_reply *reply)
{
    struct db_build_receipt receipt;
    struct build_fabric_worker_feedback feedback;
    memset(&feedback, 0, sizeof(feedback));
    char peer_action_id[BUILD_FABRIC_ID_HEX + 1] = {0};
    struct db_build_receipt peer_receipt;
    memset(&peer_receipt, 0, sizeof(peer_receipt));
    const char *action_id = facts->action ? json_get_str(facts->action)
                                          : NULL;
    struct zcl_result executed = run_admit_execute(
        ctx, datadir, action_id, worker, secret, pubkey, standard, &receipt,
        &feedback, peer_action_id, &peer_receipt);
    memory_cleanse(secret, 32u);
    if (!executed.ok) {
        run_admit_build_failed(reply, executed.message, &feedback);
        return;
    }
    struct json_value expert;
    json_init(&expert); json_set_object(&expert);
    bool expert_ok = run_admit_expert_json(&expert, ctx, facts, &receipt,
                                           standard, peer_action_id,
                                           &peer_receipt);
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   ctx->entry->task_root_hex);
    bool passed = run_admit_passed(&receipt, standard, &peer_receipt);
    char next_workspace[ZWORK_RUN_PATH_MAX] = {0};
    bool retry_ready = run_admit_retry_workspace(ctx, facts, passed,
                                                 next_workspace);
    struct json_value diagnostic;
    json_init(&diagnostic); json_set_object(&diagnostic);
    struct json_value compiler_feedback;
    bool diagnostic_ok = run_admit_diagnostic_json(
        &diagnostic, &compiler_feedback, ctx->candidate_sequence, &receipt,
        retry_ready, &feedback);
    struct run_admit_repair repair = {0};
    run_admit_repair_packet(&repair, ctx, datadir, next_workspace,
                            &diagnostic, retry_ready);
    bool ok = run_admit_renderable(facts, &receipt, diagnostic_ok,
                                   expert_ok, &repair) &&
        run_admit_render(reply, ctx, facts, &receipt, &expert, &diagnostic,
                         &repair, next_workspace, work_id, passed, standard,
                         retry_ready);
    json_free(&compiler_feedback);
    json_free(&repair.packet); json_free(&diagnostic); json_free(&expert);
    if (!ok)
        run_fail(reply, "ADMISSION_OUTPUT_FAILED", "render",
                 "candidate admission summary could not be rendered",
                 false, true);
}

bool run_admit(const struct run_admit_context *ctx,
               struct zcl_command_reply *reply)
{
    char datadir[ZWORK_RUN_PATH_MAX];
    if (!run_admit_datadir(ctx->proof_datadir, ctx->candidate_workspace,
                           datadir))
        return false;
    struct zcl_result made = zcl_mkdir_p(datadir, 0700);
    struct db_build_worker worker;
    uint8_t secret[32] = {0}, pubkey[32] = {0};
    struct zcl_result identity = made.ok
        ? build_fabric_worker_identity_load(
              datadir, &worker, secret, pubkey)
        : made;
    char author_hex[65], adapter_hex[65];
    zcl_hex_encode(pubkey, 32, author_hex);
    bool rooted = run_admit_adapter_root(ctx, adapter_hex);
    if (!identity.ok || !rooted) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    bool standard = false;
    if (!run_standard_policy(ctx->workspace, ctx->task, &standard)) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    const char *execution_profile = standard
        ? VCS_BUILD_PACKAGE_PROFILE_STANDARD_A_V1
        : VCS_BUILD_PACKAGE_PROFILE_QUICK_V1;
    struct json_value input;
    if (!run_admit_input(&input, ctx, datadir, author_hex, adapter_hex,
                         execution_profile)) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    struct zcl_command_reply inner;
    bool admitted = run_admit_improve(&input, &inner);
    json_free(&input);
    if (!admitted) {
        run_admit_refuse(reply, &inner);
        memory_cleanse(secret, sizeof(secret));
        zcl_command_reply_free(&inner);
        return true;
    }
    struct run_admission_facts facts;
    run_admission_facts_read(&inner, &facts);
    /* An explicit full-node datadir means the daemon now owns this immutable
     * action.  Foreground work ends at admission: its enabled local worker or
     * a peer may consume the action later, but the originating CLI must never
     * race either owner by generically claiming the live queue.  Closed
     * scratch ledgers (no explicit proof datadir) retain the contained local
     * execution path used by deterministic unit/development fixtures. */
    if (ctx->proof_datadir && ctx->proof_datadir[0]) {
        memory_cleanse(secret, sizeof(secret));
        bool rendered = run_render_async_admission(
            reply, ctx->entry, &inner, ctx->adapter_name, ctx->workspace,
            ctx->proof_datadir, ctx->details);
        zcl_command_reply_free(&inner);
        if (!rendered)
            run_fail(reply, "ADMISSION_OUTPUT_FAILED", "render",
                     "live async admission summary could not be rendered",
                     false, true);
        return true;
    }
    run_admit_local(ctx, datadir, &facts, &worker, secret, pubkey, standard,
                    reply);
    zcl_command_reply_free(&inner);
    return true;
}
