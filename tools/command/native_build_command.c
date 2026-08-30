/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed native adapters for the durable ZBuild coordinator ledger. */

#include "command/native_command.h"

#include "base/hex.h"
#include "config/runtime.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { BF_NATIVE_MAX_ACTIONS = 256, BF_NATIVE_MAX_WORKERS = 128 };

static bool bf_hex_id(const char *value)
{
    if (!value || strlen(value) != BUILD_FABRIC_ID_HEX) return false;
    for (size_t i = 0; i < BUILD_FABRIC_ID_HEX; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static const char *bf_arg(const struct zcl_command_request *request,
                          const char *key)
{
    const struct json_value *v = request && request->input
        ? json_get(request->input, key) : NULL;
    const char *s = v ? json_get_str(v) : NULL;
    return s && s[0] ? s : NULL;
}

static const char *bf_datadir(const struct zcl_command_request *request)
{
    const char *value = bf_arg(request, "datadir");
    if (value) return value;
    value = zcl_native_command_datadir();
    return value && value[0] ? value : NULL;
}

static void bf_fail(struct zcl_command_reply *reply, const char *code,
                    const char *message, const char *evidence, bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           mutated, message, evidence ? evidence : "");
}

static bool bf_runtime_owns(const char *datadir)
{
    struct node_db *owned = app_runtime_node_db();
    if (!datadir || !datadir[0] ||
        !app_runtime_node_db_handle_open(owned))
        return false;
    char expected[1100];
    int n = snprintf(expected, sizeof(expected), "%s/node.db", datadir);
    return n > 0 && (size_t)n < sizeof(expected) &&
           strcmp(expected, owned->path) == 0;
}

static bool bf_forward_live(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply,
                            const char *rpc_method)
{
    const char *datadir = bf_datadir(request);
    return zcl_native_forward_live_command(
        request, datadir, rpc_method, "LIVE_BUILD_COMMAND_FAILED", "execute",
        "metaverse.build", reply);
}

static bool bf_open_write(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply,
                          struct node_db *local, struct node_db **out)
{
    const char *datadir = bf_datadir(request);
    char path[1100];
    if (out) *out = NULL;
    int n = datadir ? snprintf(path, sizeof(path), "%s/node.db", datadir) : -1;
    if (!local || !out || n <= 0 || (size_t)n >= sizeof(path)) {
        bf_fail(reply, "MISSING_DATADIR", "pass a valid node datadir",
                "metaverse.build", false);
        return false;
    }
    if (bf_runtime_owns(datadir)) {
        *out = app_runtime_node_db();
        return true;
    }
    char cookie[1100];
    int cn = snprintf(cookie, sizeof(cookie), "%s/.cookie", datadir);
    if (cn > 0 && (size_t)cn < sizeof(cookie) && access(cookie, R_OK) == 0) {
        bf_fail(reply, "LIVE_DATABASE_OWNED",
                "the resident node owns this database; submit the command "
                "through its authenticated RPC boundary",
                path, false);
        return false;
    }
    memset(local, 0, sizeof(*local));
    if (!node_db_open(local, path) || !local->open) {
        bf_fail(reply, "BUILD_STORE", "cannot open the build ledger",
                path, false);
        return false;
    }
    *out = local;
    return true;
}

static void bf_close_write(struct node_db *local, struct node_db *opened)
{
    if (local && opened == local)
        node_db_close(local);
}

static bool bf_open_read(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply, sqlite3 **db,
                         struct node_db *ndb)
{
    return zcl_native_node_db_require_readonly(
        bf_datadir(request), reply, "the build coordinator ledger", db, ndb);
}

static void bf_render_job(struct json_value *out,
                          const struct db_build_job *row)
{
    (void)json_push_kv_str(out, "job_id", row->job_id);
    (void)json_push_kv_str(out, "source_sha256", row->source_sha256);
    (void)json_push_kv_str(out, "source_cas_sha3", row->source_cas_sha3);
    (void)json_push_kv_str(out, "toolchain_sha3", row->toolchain_sha3);
    (void)json_push_kv_str(out, "profile", row->profile);
    (void)json_push_kv_str(out, "state", row->state);
    (void)json_push_kv_str(out, "outcome", row->outcome);
    (void)json_push_kv_bool(out, "cancel_requested", row->cancel_requested != 0);
    (void)json_push_kv_int(out, "created_at", row->created_at);
    (void)json_push_kv_int(out, "updated_at", row->updated_at);
}

static void bf_render_action(struct json_value *out,
                             const struct db_build_action *row)
{
    (void)json_push_kv_str(out, "action_id", row->action_id);
    (void)json_push_kv_int(out, "sequence", row->sequence);
    (void)json_push_kv_str(out, "kind", row->kind);
    (void)json_push_kv_str(out, "state", row->state);
    (void)json_push_kv_str(out, "outcome", row->outcome);
    (void)json_push_kv_str(out, "input_root_sha3", row->input_root_sha3);
    (void)json_push_kv_str(out, "target", row->target);
    (void)json_push_kv_str(out, "flags_sha3", row->flags_sha3);
    (void)json_push_kv_str(out, "environment_sha3", row->environment_sha3);
    (void)json_push_kv_str(out, "virtual_workdir", row->virtual_workdir);
    (void)json_push_kv_str(out, "declared_outputs", row->declared_outputs);
    (void)json_push_kv_str(out, "resource_policy", row->resource_policy);
    (void)json_push_kv_str(out, "output_root_sha3", row->output_root_sha3);
    (void)json_push_kv_str(out, "worker_id", row->worker_id);
    (void)json_push_kv_str(out, "last_error", row->last_error);
}

static void bf_render_worker(struct json_value *out,
                             const struct db_build_worker *row)
{
    (void)json_push_kv_str(out, "worker_id", row->worker_id);
    (void)json_push_kv_str(out, "signer_pubkey", row->signer_pubkey);
    (void)json_push_kv_str(out, "capabilities", row->capabilities);
    (void)json_push_kv_bool(out, "approved", row->approved != 0);
    (void)json_push_kv_bool(out, "revoked", row->revoked != 0);
    (void)json_push_kv_int(out, "approved_at", row->approved_at);
    (void)json_push_kv_int(out, "expires_at", row->expires_at);
    (void)json_push_kv_int(out, "last_seen_at", row->last_seen_at);
}

void zcl_native_handle_metaverse_build_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (bf_forward_live(request, reply, "build_plan_owned")) return;
    const char *source_sha = bf_arg(request, "source_sha256");
    const char *source_cas = bf_arg(request, "source_cas_sha3");
    const char *toolchain = bf_arg(request, "toolchain_sha3");
    const char *input_root = bf_arg(request, "input_root_sha3");
    const char *flags = bf_arg(request, "flags_sha3");
    const char *environment = bf_arg(request, "environment_sha3");
    const char *profile = bf_arg(request, "profile");
    if (!bf_hex_id(source_sha) || !bf_hex_id(source_cas) ||
        !bf_hex_id(toolchain) || !bf_hex_id(input_root) || !bf_hex_id(flags) ||
        !bf_hex_id(environment) || !profile ||
        strlen(profile) > BUILD_FABRIC_PROFILE_MAX) {
        bf_fail(reply, "INVALID_INPUT", "plan requires six exact lowercase "
                "64-hex digests and a profile of at most 31 bytes",
                "discover schema metaverse.build.plan", false);
        return;
    }
    uint8_t fixed_flags[32], fixed_environment[32];
    char fixed_flags_hex[65], fixed_environment_hex[65];
    vcs_build_action_v1_fixed_flags_root(fixed_flags);
    vcs_build_action_v1_fixed_environment_root(fixed_environment);
    zcl_hex_encode(fixed_flags, 32, fixed_flags_hex);
    zcl_hex_encode(fixed_environment, 32, fixed_environment_hex);
    if (strcmp(flags, fixed_flags_hex) != 0 ||
        strcmp(environment, fixed_environment_hex) != 0) {
        bf_fail(reply, "FIXED_PROFILE_MISMATCH",
                "the supervisor, not the requester, defines flags and environment",
                VCS_BUILD_PROFILE_SECURE_CANDIDATE_V1, false);
        return;
    }
    int64_t now = platform_time_wall_unix();
    struct db_build_job job = {0};
    struct db_build_action action = {0};
    (void)snprintf(job.source_sha256, sizeof(job.source_sha256), "%s", source_sha);
    (void)snprintf(job.source_cas_sha3, sizeof(job.source_cas_sha3), "%s", source_cas);
    (void)snprintf(job.toolchain_sha3, sizeof(job.toolchain_sha3), "%s", toolchain);
    (void)snprintf(job.profile, sizeof(job.profile), "%s", profile);
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.created_at = job.updated_at = now;
    (void)snprintf(action.kind, sizeof(action.kind),
                   "c23.compile.preprocessed.v1");
    (void)snprintf(action.state, sizeof(action.state), "SNAPSHOTTED");
    (void)snprintf(action.input_root_sha3, sizeof(action.input_root_sha3), "%s", input_root);
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action.flags_sha3, sizeof(action.flags_sha3), "%s",
                   fixed_flags_hex);
    (void)snprintf(action.environment_sha3, sizeof(action.environment_sha3),
                   "%s", fixed_environment_hex);
    (void)snprintf(action.virtual_workdir, sizeof(action.virtual_workdir), "/zbuild/src");
    (void)snprintf(action.declared_outputs, sizeof(action.declared_outputs), "unit.o");
    (void)snprintf(action.resource_policy, sizeof(action.resource_policy),
                   "%s", VCS_BUILD_RESOURCE_POLICY_V1);
    action.created_at = action.updated_at = now;
    struct zcl_result result = build_fabric_action_id(&job, &action,
                                                       action.action_id);
    if (result.ok)
        result = build_fabric_job_id(&job, action.action_id, job.job_id);
    (void)snprintf(action.job_id, sizeof(action.job_id), "%s", job.job_id);
    struct node_db local, *ndb = NULL;
    if (result.ok && bf_open_write(request, reply, &local, &ndb)) {
        result = build_fabric_plan(ndb, &job, &action);
        if (result.ok &&
            (!db_build_job_find(ndb, job.job_id, &job) ||
             !db_build_action_find(ndb, action.action_id, &action)))
            result = ZCL_ERR(-1, "persisted build plan could not be re-read");
        bf_close_write(&local, ndb);
    } else if (result.ok) {
        return;
    }
    if (!result.ok) {
        bf_fail(reply, "PLAN_REJECTED", result.message, action.action_id, false);
        return;
    }
    struct json_value job_json, action_json;
    json_init(&job_json); json_set_object(&job_json);
    json_init(&action_json); json_set_object(&action_json);
    bf_render_job(&job_json, &job);
    bf_render_action(&action_json, &action);
    (void)json_push_kv(&reply->data, "job", &job_json);
    (void)json_push_kv(&reply->data, "action", &action_json);
    json_free(&job_json); json_free(&action_json);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.build_plan.v1");
}

static void bf_job_transition(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply, bool cancel)
{
    if (bf_forward_live(request, reply,
                        cancel ? "build_cancel_owned" : "build_submit_owned"))
        return;
    const char *job_id = bf_arg(request, "job_id");
    if (!job_id) {
        bf_fail(reply, "MISSING_JOB_ID", "job_id is required", "", false);
        return;
    }
    struct node_db local, *ndb = NULL;
    if (!bf_open_write(request, reply, &local, &ndb)) return;
    struct zcl_result result = cancel
        ? build_fabric_cancel(ndb, job_id, platform_time_wall_unix())
        : build_fabric_submit(ndb, job_id, platform_time_wall_unix());
    struct db_build_job job;
    bool found = result.ok && db_build_job_find(ndb, job_id, &job);
    bf_close_write(&local, ndb);
    if (!result.ok || !found) {
        bf_fail(reply, cancel ? "CANCEL_REJECTED" : "SUBMIT_REJECTED",
                result.ok ? "updated job disappeared" : result.message,
                job_id, result.ok);
        return;
    }
    bf_render_job(&reply->data, &job);
}

void zcl_native_handle_metaverse_build_submit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{ bf_job_transition(request, reply, false); }

void zcl_native_handle_metaverse_build_cancel(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{ bf_job_transition(request, reply, true); }

void zcl_native_handle_metaverse_build_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *job_id = bf_arg(request, "job_id");
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!job_id || !bf_open_read(request, reply, &db, &ndb)) {
        if (!job_id) bf_fail(reply, "MISSING_JOB_ID", "job_id is required", "", false);
        return;
    }
    struct db_build_job job;
    struct db_build_action rows[BF_NATIVE_MAX_ACTIONS];
    bool found = db_build_job_find(&ndb, job_id, &job);
    int count = found ? db_build_job_actions(&ndb, job_id, rows,
                                              BF_NATIVE_MAX_ACTIONS) : 0;
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!found) { bf_fail(reply, "BUILD_NOT_FOUND", "build job not found", job_id, false); return; }
    bf_render_job(&reply->data, &job);
    struct json_value actions;
    json_init(&actions); json_set_array(&actions);
    for (int i = 0; i < count; i++) {
        struct json_value row; json_init(&row); json_set_object(&row);
        bf_render_action(&row, &rows[i]);
        (void)json_push_back(&actions, &row); json_free(&row);
    }
    (void)json_push_kv(&reply->data, "actions", &actions); json_free(&actions);
    (void)json_push_kv_int(&reply->data, "action_count", count);
}

void zcl_native_handle_metaverse_build_receipt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *receipt_id = bf_arg(request, "receipt_id");
    sqlite3 *db = NULL; struct node_db ndb;
    if (!receipt_id || !bf_open_read(request, reply, &db, &ndb)) {
        if (!receipt_id) bf_fail(reply, "MISSING_RECEIPT_ID", "receipt_id is required", "", false);
        return;
    }
    struct db_build_receipt row;
    bool found = db_build_receipt_find(&ndb, receipt_id, &row);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!found) { bf_fail(reply, "RECEIPT_NOT_FOUND", "build receipt not found", receipt_id, false); return; }
    (void)json_push_kv_str(&reply->data, "receipt_id", row.receipt_id);
    (void)json_push_kv_str(&reply->data, "action_id", row.action_id);
    (void)json_push_kv_str(&reply->data, "job_id", row.job_id);
    (void)json_push_kv_str(&reply->data, "worker_id", row.worker_id);
    (void)json_push_kv_str(&reply->data, "action_sha3", row.action_sha3);
    (void)json_push_kv_str(&reply->data, "output_sha3", row.output_sha3);
    (void)json_push_kv_str(&reply->data, "work_receipt_sha3",
                           row.work_receipt_sha3);
    (void)json_push_kv_str(&reply->data, "signature", row.signature);
    (void)json_push_kv_str(&reply->data, "confinement", row.confinement);
    (void)json_push_kv_str(&reply->data, "trust_state", row.trust_state);
    (void)json_push_kv_int(&reply->data, "exit_status", row.exit_status);
    (void)json_push_kv_int(&reply->data, "created_at", row.created_at);
}

void zcl_native_handle_metaverse_build_worker_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    sqlite3 *db = NULL; struct node_db ndb;
    if (!bf_open_read(request, reply, &db, &ndb)) return;
    struct db_build_worker rows[BF_NATIVE_MAX_WORKERS];
    int count = db_build_workers_list(&ndb, rows, BF_NATIVE_MAX_WORKERS);
    zcl_native_node_db_close_readonly(&db, &ndb);
    struct json_value workers; json_init(&workers); json_set_array(&workers);
    for (int i = 0; i < count; i++) {
        struct json_value row; json_init(&row); json_set_object(&row);
        bf_render_worker(&row, &rows[i]);
        (void)json_push_back(&workers, &row); json_free(&row);
    }
    (void)json_push_kv(&reply->data, "workers", &workers); json_free(&workers);
    (void)json_push_kv_int(&reply->data, "worker_count", count);
}

void zcl_native_handle_metaverse_build_worker_approve(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (bf_forward_live(request, reply, "build_worker_approve_owned")) return;
    const char *worker_id = bf_arg(request, "worker_id");
    const char *pubkey = bf_arg(request, "signer_pubkey");
    if (!bf_hex_id(worker_id) || !bf_hex_id(pubkey)) { bf_fail(reply, "INVALID_INPUT", "worker_id and signer_pubkey must be lowercase 64-hex values", "", false); return; }
    int64_t now = platform_time_wall_unix();
    struct db_build_worker worker = {0};
    (void)snprintf(worker.worker_id, sizeof(worker.worker_id), "%s", worker_id);
    (void)snprintf(worker.signer_pubkey, sizeof(worker.signer_pubkey), "%s", pubkey);
    const char *caps = bf_arg(request, "capabilities");
    if (caps && strlen(caps) > BUILD_FABRIC_CAPS_MAX) {
        bf_fail(reply, "INVALID_CAPABILITIES", "capabilities exceeds 1023 bytes",
                worker_id, false);
        return;
    }
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities), "%s",
                   caps ? caps : "linux,x86-64-v3,gcc,c23.compile.preprocessed.v1");
    const struct json_value *expiry = request->input ? json_get(request->input, "expires_at") : NULL;
    worker.expires_at = expiry ? json_get_int(expiry) : 0;
    worker.last_seen_at = now;
    struct node_db local, *ndb = NULL;
    if (!bf_open_write(request, reply, &local, &ndb)) return;
    struct zcl_result result = build_fabric_worker_approve(ndb, &worker, now);
    bool found = result.ok && db_build_worker_find(ndb, worker_id, &worker);
    bf_close_write(&local, ndb);
    if (!result.ok || !found) { bf_fail(reply, "APPROVAL_REJECTED", result.ok ? "approved worker disappeared" : result.message, worker_id, result.ok); return; }
    bf_render_worker(&reply->data, &worker);
}

void zcl_native_handle_metaverse_build_worker_revoke(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (bf_forward_live(request, reply, "build_worker_revoke_owned")) return;
    const char *worker_id = bf_arg(request, "worker_id");
    if (!worker_id) { bf_fail(reply, "MISSING_WORKER_ID", "worker_id is required", "", false); return; }
    struct node_db local, *ndb = NULL;
    if (!bf_open_write(request, reply, &local, &ndb)) return;
    struct zcl_result result = build_fabric_worker_revoke(
        ndb, worker_id, platform_time_wall_unix());
    struct db_build_worker worker;
    bool found = result.ok && db_build_worker_find(ndb, worker_id, &worker);
    bf_close_write(&local, ndb);
    if (!result.ok || !found) { bf_fail(reply, "REVOCATION_REJECTED", result.ok ? "revoked worker disappeared" : result.message, worker_id, result.ok); return; }
    bf_render_worker(&reply->data, &worker);
}
