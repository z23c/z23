/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Background requester-local dispatch over the existing work swarm. */

#include "config/boot_zcode_async_proof.h"
#include "config/boot_zcode_async_select.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "config/boot_zcode_swarm.h"
#include "controllers/strong_params.h"
#include "kernel/command_registry.h"
#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/build_fabric_async.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "util/log_macros.h"
#include "vcs/build_action.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    ASYNC_PROOF_BATCH = 16,
    /* Signed request lifetime covers context transport/admission in addition
     * to the separately declared execution CPU ceiling. */
    ASYNC_PROOF_TRANSPORT_SECONDS = 90,
};

static const char *async_proof_admission_name(uint8_t disposition)
{
    switch (disposition) {
    case VCS_ZCODE_WORK_ADMISSION_GRANTED: return "GRANTED";
    case VCS_ZCODE_WORK_ADMISSION_ATTACHED: return "ATTACHED";
    case VCS_ZCODE_WORK_ADMISSION_BUSY: return "BUSY";
    case VCS_ZCODE_WORK_ADMISSION_REFUSED: return "REFUSED";
    default: return "INVALID";
    }
}

void boot_zcode_async_proof_drain_admissions(
    struct vcs_zcode_work_node *work, int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!work || !ndb || !ndb->open) return;
    for (;;) {
        uint64_t peer = 0;
        struct vcs_zcode_work_admission_v1 admission;
        if (!vcs_zcode_work_node_next_admission(work, &peer, &admission))
            break;
        struct vcs_zcode_work_request_v1 request;
        if (!vcs_zcode_work_node_outbound_request(
                work, peer, admission.request_id, &request)) {
            LOG_ERROR("net.zcode_swarm", "admission lost its request");
            continue;
        }
        bool observed = boot_zcode_async_proof_observe_admission(
            ndb, peer, &request, &admission, now);
        bool rerouted = observed &&
            (admission.disposition == VCS_ZCODE_WORK_ADMISSION_BUSY ||
             admission.disposition == VCS_ZCODE_WORK_ADMISSION_REFUSED);
        char action_id[65];
        zcl_hex_encode(request.action_root, 32, action_id);
        LOG_INFO("zcode.proof_perf",
                 "schema=zcl.async_proof_perf.v1 action=%s "
                 "stage=worker_admission at_unix_us=%lld disposition=%s "
                 "reason=%u slot=%u lease_generation=%llu reroute=%d",
                 action_id, (long long)platform_time_realtime_us(),
                 async_proof_admission_name(admission.disposition),
                 admission.reason, admission.slot,
                 (unsigned long long)admission.lease_generation,
                 rerouted ? 1 : 0);
        if (!observed)
            LOG_WARN("net.zcode_swarm", "admission %s was not projected",
                     async_proof_admission_name(admission.disposition));
    }
}

static bool async_proof_rpc_run(
    const struct json_value *params, struct json_value *result,
    const char *schema, zcl_command_handler_fn handler,
    const char *fallback_code, const char *fallback_phase)
{
    const struct json_value *input = params && params->type == JSON_ARR &&
        json_size(params) == 1 ? json_at(params, 0) : NULL;
    if (!input || input->type != JSON_OBJ) {
        json_set_object(result);
        (void)json_push_kv_bool(result, "ok", false);
        (void)json_push_kv_str(result, "code", "INVALID_INPUT");
        (void)json_push_kv_str(result, "phase", "validate");
        (void)json_push_kv_str(result, "message",
                               "one canonical command input object is required");
        return true;
    }
    struct zcl_command_request request = { .input = input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, schema);
    handler(&request, &reply);
    json_set_object(result);
    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  reply.exit_code == ZCL_COMMAND_EXIT_OK;
    (void)json_push_kv_bool(result, "ok", passed);
    if (passed) {
        (void)json_push_kv(result, "data", &reply.data);
    } else {
        (void)json_push_kv_str(result, "code",
                               reply.error.code[0] ? reply.error.code :
                                                     fallback_code);
        (void)json_push_kv_str(result, "phase",
                               reply.error.phase[0] ? reply.error.phase :
                                                      fallback_phase);
        (void)json_push_kv_str(result, "message",
                               reply.error.message[0] ? reply.error.message :
                                                        "live admission failed");
        (void)json_push_kv_str(result, "evidence",
                               reply.error.evidence[0]
                                   ? reply.error.evidence : fallback_phase);
        (void)json_push_kv_bool(result, "retryable", reply.error.retryable);
        (void)json_push_kv_bool(result, "mutated", reply.error.mutated);
    }
    zcl_command_reply_free(&reply);
    return true;
}

static bool async_proof_rpc_admit(
    const struct json_value *params, bool help, struct json_value *result)
{
    RPC_HELP(help, result,
        "zcode_work_admit {input}\n"
        "Admit one canonical immutable action through the live node's owned "
        "proof ledger. Internal authenticated loopback surface.");
    bool handled = async_proof_rpc_run(
        params, result, "zcl.zcode_improve.v1",
        zcl_native_handle_zcode_improve, "ADMISSION_FAILED", "admit");
    boot_zcode_swarm_request_tick();
    return handled;
}

static bool async_proof_rpc_evidence(
    const struct json_value *params, bool help, struct json_value *result)
{
    RPC_HELP(help, result,
        "zcode_work_evidence {input}\n"
        "Evaluate one exact action through the live node's owned proof ledger. "
        "Internal authenticated loopback surface.");
    return async_proof_rpc_run(
        params, result, "zcl.zcode_evidence.v1",
        zcl_native_handle_zcode_evidence, "EVIDENCE_FAILED", "evaluate");
}

#define ASYNC_OWNED_WORK_RPC(name, method, schema, handler, fallback, phase) \
    static bool name(const struct json_value *params, bool help, \
                     struct json_value *result) \
    { \
        RPC_HELP(help, result, method " {input}\n" \
            "Run one canonical work-product command through the live " \
            "node's owned proof ledger."); \
        return async_proof_rpc_run(params, result, schema, handler, \
                                   fallback, phase); \
    }

ASYNC_OWNED_WORK_RPC(async_proof_rpc_work_status, "zcode_work_status",
    "zcl.zcode_work_status.v1", zcl_native_handle_zcode_work_status,
    "WORK_STATUS_FAILED", "status")
ASYNC_OWNED_WORK_RPC(async_proof_rpc_work_accept, "zcode_work_accept",
    "zcl.zcode_work_accept.v1", zcl_native_handle_zcode_work_accept,
    "WORK_ACCEPT_FAILED", "accept")
ASYNC_OWNED_WORK_RPC(async_proof_rpc_release_confirm,
    "zcode_work_release_confirm",
    "zcl.app_presentation_release_confirm.v1",
    zcl_native_handle_presentation_release_confirm,
    "RELEASE_CONFIRM_FAILED", "present")
ASYNC_OWNED_WORK_RPC(async_proof_rpc_publish_plan,
    "zcode_publish_plan_owned", "zcl.zcode_publish_plan.v1",
    zcl_native_handle_zcode_publish_plan,
    "PUBLISH_PLAN_FAILED", "plan")
ASYNC_OWNED_WORK_RPC(async_proof_rpc_publish_commit,
    "zcode_publish_commit_owned", "zcl.zcode_publish_commit.v1",
    zcl_native_handle_zcode_publish_commit,
    "PUBLISH_COMMIT_FAILED", "publish")

#undef ASYNC_OWNED_WORK_RPC

#define ASYNC_OWNED_BUILD_RPC(name, method, schema, handler, fallback) \
    static bool name(const struct json_value *params, bool help, \
                     struct json_value *result) \
    { \
        RPC_HELP(help, result, method " {input}\n" \
            "Execute one canonical build-ledger command through the live " \
            "node's owned SQLite handle."); \
        return async_proof_rpc_run(params, result, schema, handler, \
                                   fallback, "execute"); \
    }

ASYNC_OWNED_BUILD_RPC(async_proof_rpc_build_plan, "build_plan_owned",
    "zcl.build_plan.v1", zcl_native_handle_metaverse_build_plan,
    "PLAN_REJECTED")
ASYNC_OWNED_BUILD_RPC(async_proof_rpc_build_submit, "build_submit_owned",
    "zcl.build_job.v1", zcl_native_handle_metaverse_build_submit,
    "SUBMIT_REJECTED")
ASYNC_OWNED_BUILD_RPC(async_proof_rpc_build_cancel, "build_cancel_owned",
    "zcl.build_job.v1", zcl_native_handle_metaverse_build_cancel,
    "CANCEL_REJECTED")
ASYNC_OWNED_BUILD_RPC(async_proof_rpc_worker_approve,
    "build_worker_approve_owned", "zcl.build_worker.v1",
    zcl_native_handle_metaverse_build_worker_approve, "APPROVAL_REJECTED")
ASYNC_OWNED_BUILD_RPC(async_proof_rpc_worker_revoke,
    "build_worker_revoke_owned", "zcl.build_worker.v1",
    zcl_native_handle_metaverse_build_worker_revoke, "REVOCATION_REJECTED")

#undef ASYNC_OWNED_BUILD_RPC

void boot_zcode_async_proof_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"zcode", "zcode_work_admit", async_proof_rpc_admit, true},
        {"zcode", "zcode_work_evidence", async_proof_rpc_evidence, true},
        {"zcode", "zcode_work_status", async_proof_rpc_work_status, true},
        {"zcode", "zcode_work_accept", async_proof_rpc_work_accept, true},
        {"zcode", "zcode_work_release_confirm",
         async_proof_rpc_release_confirm, true},
        {"zcode", "zcode_publish_plan_owned",
         async_proof_rpc_publish_plan, true},
        {"zcode", "zcode_publish_commit_owned",
         async_proof_rpc_publish_commit, true},
        {"zcode", "build_plan_owned", async_proof_rpc_build_plan, true},
        {"zcode", "build_submit_owned", async_proof_rpc_build_submit, true},
        {"zcode", "build_cancel_owned", async_proof_rpc_build_cancel, true},
        {"zcode", "build_worker_approve_owned",
         async_proof_rpc_worker_approve, true},
        {"zcode", "build_worker_revoke_owned",
         async_proof_rpc_worker_revoke, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}

static uint8_t s_requester_secret[32];
static uint8_t s_requester_pubkey[32];
static bool s_requester_ready;
static char s_requester_datadir[4096];

static bool async_identity(const struct boot_svc_ctx *svc)
{
    if (!svc || !svc->datadir) return false;
    if (s_requester_ready &&
        strcmp(s_requester_datadir, svc->datadir) == 0)
        return true;
    struct db_build_worker requester;
    struct zcl_result loaded = build_fabric_worker_identity_load(
        svc->datadir, &requester, s_requester_secret, s_requester_pubkey);
    if (!loaded.ok) {
        LOG_WARN("net.zcode_async", "requester identity: %s",
                 loaded.message);
        return false;
    }
    int n = snprintf(s_requester_datadir, sizeof(s_requester_datadir),
                     "%s", svc->datadir);
    if (n <= 0 || (size_t)n >= sizeof(s_requester_datadir)) {
        memset(s_requester_secret, 0, sizeof(s_requester_secret));
        memset(s_requester_pubkey, 0, sizeof(s_requester_pubkey));
        return false;
    }
    s_requester_ready = true;
    return true;
}

static bool async_load_object(
    const char *workspace, const char *root_hex, size_t limit,
    uint8_t **wire, size_t *wire_len)
{
    uint8_t root[32];
    *wire = NULL;
    *wire_len = 0;
    return zcl_hex_decode_lower(root_hex, root, 32) &&
           vcs_object_load_raw_bounded(workspace, root, limit,
                                       wire, wire_len) == 0;
}

static bool async_load_task(const char *workspace,
                            const struct db_build_action *action,
                            struct vcs_zcode_task_v1 *task)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = async_load_object(workspace, action->task_root_sha3,
                                VCS_ZCODE_TASK_WIRE_BYTES,
                                &wire, &wire_len) &&
        vcs_zcode_task_parse(wire, wire_len, task) == VCS_ZCODE_DEV_OK;
    free(wire);
    return ok;
}

static struct zcl_result async_context_build(
    struct node_db *ndb, const struct db_build_job *job,
    struct db_build_action *action, int64_t now,
    const char *workspace, struct vcs_zcode_task_v1 *task,
    uint8_t context_root[32], bool *cache_hit, uint64_t *context_bytes)
{
    struct vcs_package_store *store = vcs_package_store_global();
    if (cache_hit) *cache_hit = false;
    if (context_bytes) *context_bytes = 0;
    if (!store || !workspace || workspace[0] != '/' || !cache_hit ||
        !context_bytes)
        return ZCL_ERR(-1, "package/CAS owners unavailable");
    if (!async_load_task(workspace, action, task))
        return ZCL_ERR(-1, "task object unavailable");
    if (action->context_root_sha3[0]) {
        struct vcs_package_store_status status;
        if (!zcl_hex_decode_lower(action->context_root_sha3,
                                  context_root, 32) ||
            !vcs_package_store_package_status(store, context_root, &status) ||
            !status.complete)
            return ZCL_ERR(-1, "bound context package is incomplete");
        *cache_hit = true;
        *context_bytes = status.total_bytes;
        return ZCL_OK;
    }
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    uint8_t *candidate_wire = NULL, *policy_wire = NULL, *input_wire = NULL;
    size_t candidate_len = 0, policy_len = 0, input_len = 0;
    bool loaded = async_load_object(workspace,
            action->candidate_root_sha3, VCS_ZCODE_CANDIDATE_WIRE_BYTES,
            &candidate_wire, &candidate_len) &&
        vcs_zcode_candidate_parse(candidate_wire, candidate_len,
                                  &candidate) == VCS_ZCODE_DEV_OK &&
        async_load_object(workspace,
            action->proof_policy_root_sha3,
            VCS_ZCODE_PROOF_POLICY_WIRE_BYTES, &policy_wire, &policy_len) &&
        vcs_zcode_proof_policy_parse(policy_wire, policy_len,
                                     &policy) == VCS_ZCODE_DEV_OK &&
        async_load_object(workspace, action->input_root_sha3,
                          task->max_context_bytes,
                          &input_wire, &input_len);
    free(policy_wire);
    free(candidate_wire);
    if (!loaded) {
        free(input_wire);
        return ZCL_ERR(-1, "candidate, policy, or fixed input unavailable");
    }
    struct vcs_zcode_work_context_v1 context;
    vcs_zcode_work_context_init(&context);
    bool source_ok = zcl_hex_decode_lower(
        job->source_sha256, context.source_sha256, 32);
    (void)snprintf(context.profile, sizeof(context.profile), "%s",
                   job->profile);
    context.task = *task;
    context.candidate = candidate;
    context.proof_policy = policy;
    context.fixed_input = input_wire;
    context.fixed_input_len = input_len;
    enum vcs_zcode_candidate_bundle_result candidate_bundle = source_ok
        ? vcs_zcode_candidate_bundle_export(
              workspace, task, &candidate,
              &context.candidate_authority,
              &context.candidate_authority_len)
        : VCS_ZCODE_CANDIDATE_BUNDLE_CAS;
    enum vcs_zcode_task_authority_result task_bundle =
        candidate_bundle == VCS_ZCODE_CANDIDATE_BUNDLE_OK
            ? vcs_zcode_task_authority_bundle_export(
                  workspace, task, &context.task_authority,
                  &context.task_authority_len)
            : VCS_ZCODE_TASK_AUTHORITY_CAS;
    uint8_t action_root[32];
    enum vcs_zcode_work_context_result packed =
        candidate_bundle == VCS_ZCODE_CANDIDATE_BUNDLE_OK &&
        task_bundle == VCS_ZCODE_TASK_AUTHORITY_OK
            ? vcs_zcode_work_context_put_for_kind_with_candidate(
                  store, &context, action->kind, now,
                  workspace, context_root, action_root)
            : VCS_ZCODE_WORK_CONTEXT_STALE;
    context.fixed_input = NULL;
    vcs_zcode_work_context_free(&context);
    free(input_wire);
    uint8_t expected_action[32];
    char context_hex[65];
    if (packed != VCS_ZCODE_WORK_CONTEXT_OK)
        return ZCL_ERR(-1, "context package refused: %s",
                       vcs_zcode_work_context_result_string(packed));
    if (!zcl_hex_decode_lower(action->action_id, expected_action, 32) ||
        memcmp(action_root, expected_action, 32) != 0) {
        return ZCL_ERR(-1, "context package does not bind the action");
    }
    zcl_hex_encode(context_root, 32, context_hex);
    if (!db_build_action_bind_context(ndb, action->action_id, context_hex))
        return ZCL_ERR(-1, "context root could not bind to the action");
    (void)snprintf(action->context_root_sha3,
                   sizeof(action->context_root_sha3), "%s", context_hex);
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, context_root, &status) ||
        !status.complete)
        return ZCL_ERR(-1, "new context package status disappeared");
    *context_bytes = status.total_bytes;
    return ZCL_OK;
}

static void async_dispatch(
    struct boot_svc_ctx *svc, struct vcs_zcode_work_node *work,
    struct node_db *ndb, const struct db_build_proof_event *event,
    int64_t now)
{
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, event->action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job))
        return;
    uint8_t work_kind = vcs_build_action_v1_work_kind(action.kind);
    if (work_kind != VCS_ZCODE_WORK_BUILD &&
        work_kind != VCS_ZCODE_WORK_TEST &&
        work_kind != VCS_ZCODE_WORK_FUZZ)
        return;
    struct vcs_zcode_task_v1 task;
    uint8_t context_root[32];
    bool context_cache_hit = false;
    uint64_t context_bytes = 0;
    int64_t context_started_us = platform_time_monotonic_us();
    struct zcl_result packed = async_context_build(
        ndb, &job, &action, now, event->workspace, &task, context_root,
        &context_cache_hit, &context_bytes);
    int64_t context_us = platform_time_monotonic_us() - context_started_us;
    if (!packed.ok) {
        LOG_WARN("net.zcode_async",
                 "dispatch refused action=%s stage=context_prepare reason=%s",
                 event->action_id,
                 packed.message[0] ? packed.message : "unnamed");
        return;
    }
    uint64_t peer = 0;
    struct vcs_zcode_work_capability_v1 capability;
    int64_t selection_started_us = platform_time_monotonic_us();
    if (!boot_zcode_async_select_peer(work, event, &job, work_kind, now,
                                      &peer, &capability)) {
        boot_zcode_async_log_no_peer(work, &job, event->action_id, now);
        return;
    }
    if (!async_identity(svc)) {
        LOG_WARN("net.zcode_async",
                 "dispatch refused action=%s stage=requester_identity",
                 event->action_id);
        return;
    }
    int64_t selection_us = platform_time_monotonic_us() - selection_started_us;
    uint32_t requested_lease =
        task.max_cpu_seconds < UINT32_MAX - ASYNC_PROOF_TRANSPORT_SECONDS
        ? task.max_cpu_seconds + ASYNC_PROOF_TRANSPORT_SECONDS
        : task.max_cpu_seconds;
    if (requested_lease < ASYNC_PROOF_TRANSPORT_SECONDS + 1u)
        requested_lease = ASYNC_PROOF_TRANSPORT_SECONDS + 1u;
    if (requested_lease > capability.max_lease_seconds)
        requested_lease = capability.max_lease_seconds;
    bool active_discovery = strcmp(event->state, "PEER_DISCOVERED") == 0 &&
        event->peer_id == peer && event->deadline_at > now;
    int64_t lease_end = now + requested_lease;
    int64_t deadline = active_discovery ? event->deadline_at :
        (lease_end < task.expires_unix ? lease_end : task.expires_unix - 1);
    if (deadline <= now) return;
    struct vcs_zcode_work_request_v1 request = {
        .request_id = event->request_id,
        .work_kind = work_kind,
        .target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3,
        .max_cpu_seconds = task.max_cpu_seconds < capability.max_cpu_seconds
            ? task.max_cpu_seconds : capability.max_cpu_seconds,
        .max_memory_bytes = task.max_memory_bytes < capability.max_memory_bytes
            ? task.max_memory_bytes : capability.max_memory_bytes,
        .max_output_bytes = task.max_output_bytes < capability.max_output_bytes
            ? task.max_output_bytes : capability.max_output_bytes,
        .deadline_unix = deadline,
    };
    (void)zcl_hex_decode_lower(action.task_root_sha3, request.task_root, 32);
    (void)zcl_hex_decode_lower(action.candidate_root_sha3,
                               request.candidate_root, 32);
    (void)zcl_hex_decode_lower(action.action_id, request.action_root, 32);
    (void)zcl_hex_decode_lower(action.input_root_sha3,
                               request.input_root, 32);
    memcpy(request.context_root, context_root, 32);
    (void)zcl_hex_decode_lower(action.proof_policy_root_sha3,
                               request.proof_policy_root, 32);
    (void)zcl_hex_decode_lower(job.toolchain_sha3,
                               request.toolchain_capsule_root, 32);
    if (!vcs_zcode_work_request_seal(
            &request, s_requester_secret, s_requester_pubkey))
        return;
    int64_t submit_started = platform_time_monotonic_us();
    enum vcs_zcode_work_node_result submitted = vcs_zcode_work_node_submit(
        work, peer, &request, now);
    int64_t submit_us = platform_time_monotonic_us() - submit_started;
    if (submitted != VCS_ZCODE_WORK_NODE_OK &&
        submitted != VCS_ZCODE_WORK_NODE_REPLAY)
        return;
    char context_hex[65];
    zcl_hex_encode(context_root, 32, context_hex);
    struct db_build_proof_event next;
    bool changed_lease = !active_discovery;
    if (changed_lease) {
        int64_t discovery_us = now > event->created_at
            ? (now - event->created_at) * INT64_C(1000000) : 0;
        struct zcl_result discovered = build_fabric_proof_transition(
            ndb, action.action_id, "PEER_DISCOVERED", peer,
            request.request_id, context_hex, NULL, deadline,
            discovery_us, now, &next);
        if (!discovered.ok) return;
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_REQUEST,
            .body.request = request,
        };
        LOG_INFO("zcode.proof_perf",
                 "schema=zcl.async_proof_perf.v1 action=%s "
                 "stage=requester_dispatch at_unix_us=%lld "
                 "context_prepare_us=%lld "
                 "context_bytes=%llu context_cache_hit=%d "
                 "peer_selection_us=%lld request_submit_us=%lld "
                 "request_wire_bytes=%zu retry=%d",
                 action.action_id, (long long)platform_time_realtime_us(),
                 (long long)(context_us < 0 ? 0 : context_us),
                 (unsigned long long)context_bytes, context_cache_hit ? 1 : 0,
                 (long long)(selection_us < 0 ? 0 : selection_us),
                 (long long)(submit_us < 0 ? 0 : submit_us),
                 vcs_zcode_work_swarm_wire_size(&message),
                 event->peer_id != 0 ? 1 : 0);
    }
}

static int64_t async_elapsed_us(int64_t later, int64_t earlier)
{
    if (later <= earlier) return 0;
    uint64_t delta = (uint64_t)(later - earlier);
    return delta > (uint64_t)INT64_MAX / UINT64_C(1000000)
        ? INT64_MAX : (int64_t)(delta * UINT64_C(1000000));
}

bool boot_zcode_async_proof_observe_progress(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_progress_v1 *progress, int64_t now)
{
    if (!ndb || !ndb->open || !request || !progress || peer == 0 || now <= 0)
        return false;
    char action_id[65];
    zcl_hex_encode(request->action_root, 32, action_id);
    struct db_build_proof_event current, next;
    if (!db_build_proof_event_latest(ndb, action_id, &current) ||
        current.request_id != request->request_id || current.peer_id != peer ||
        (current.deadline_at > 0 && now >= current.deadline_at))
        return false;
    const char *state = NULL;
    if (progress->stage == VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY &&
        strcmp(current.state, "PEER_DISCOVERED") == 0)
        state = "CONTEXT_READY";
    else if (progress->stage == VCS_ZCODE_WORK_PROGRESS_EXECUTION_STARTED &&
             strcmp(current.state, "CONTEXT_READY") == 0)
        state = "RUNNING";
    else
        return false;
    return build_fabric_proof_transition(
        ndb, action_id, state, peer, request->request_id, NULL, NULL,
        current.deadline_at, async_elapsed_us(now, current.created_at), now,
        &next).ok;
}

bool boot_zcode_async_proof_observe_admission(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_admission_v1 *admission, int64_t now)
{
    if (!ndb || !ndb->open || !request || !admission || peer == 0 ||
        now <= 0)
        return false;
    if (admission->disposition != VCS_ZCODE_WORK_ADMISSION_BUSY &&
        admission->disposition != VCS_ZCODE_WORK_ADMISSION_REFUSED)
        return true;
    char action_id[65];
    zcl_hex_encode(request->action_root, 32, action_id);
    struct db_build_proof_event current, reroute;
    if (!db_build_proof_event_latest(ndb, action_id, &current) ||
        current.request_id != request->request_id ||
        current.peer_id != peer ||
        strcmp(current.state, "PEER_DISCOVERED") != 0)
        return false;
    return build_fabric_proof_transition(
        ndb, action_id, "PEER_DISCOVERED", peer, request->request_id,
        NULL, NULL, now, 0, now, &reroute).ok;
}
bool boot_zcode_async_proof_observe_result(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result,
    const char *receipt_root, int64_t verification_us, int64_t now)
{
    if (!ndb || !ndb->open || !request || !result || !receipt_root ||
        !receipt_root[0] || peer == 0 || verification_us < 0 || now <= 0)
        return false;
    char action_id[65];
    zcl_hex_encode(request->action_root, 32, action_id);
    struct db_build_proof_event current, remote, verified;
    if (!db_build_proof_event_latest(ndb, action_id, &current) ||
        current.request_id != request->request_id ||
        current.peer_id != peer)
        return false;
    if (strcmp(current.state, "RECEIPT_VERIFIED") == 0)
        return strcmp(current.receipt_root_sha3, receipt_root) == 0;
    bool running = strcmp(current.state, "RUNNING") == 0;
    bool remote_recorded = strcmp(current.state, "REMOTE_GREEN") == 0 ||
        strcmp(current.state, "REMOTE_RED") == 0;
    if ((!running && !remote_recorded) ||
        (running && current.deadline_at > 0 && now >= current.deadline_at))
        return false;
    int64_t remote_us = async_elapsed_us(
        result->receipt.finished_unix, result->receipt.started_unix);
    const char *remote_state =
        result->receipt.status == VCS_ZCODE_WORK_PASS &&
        result->receipt.exit_status == 0 ? "REMOTE_GREEN" : "REMOTE_RED";
    if (running) {
        struct zcl_result marked = build_fabric_proof_transition(
            ndb, action_id, remote_state, peer, request->request_id, NULL,
            receipt_root, current.deadline_at, remote_us, now, &remote);
        if (!marked.ok) return false;
        current = remote;
    } else if (strcmp(current.receipt_root_sha3, receipt_root) != 0) {
        return false;
    }
    struct zcl_result marked = build_fabric_proof_transition(
        ndb, action_id, "RECEIPT_VERIFIED", peer, request->request_id,
        NULL, receipt_root, current.deadline_at, verification_us, now,
        &verified);
    return marked.ok;
}

bool boot_zcode_async_proof_workspace(
    struct node_db *ndb, const struct vcs_zcode_work_request_v1 *request,
    char out[4096])
{
    if (out) out[0] = '\0';
    if (!ndb || !ndb->open || !request || !out) return false;
    char action_id[65];
    zcl_hex_encode(request->action_root, 32, action_id);
    struct db_build_proof_event event;
    if (!db_build_proof_event_latest(ndb, action_id, &event) ||
        event.request_id != request->request_id || !event.workspace[0])
        return false;
    int n = snprintf(out, 4096, "%s", event.workspace);
    return n > 0 && n < 4096;
}

static void async_reproduce(
    struct node_db *ndb, const struct db_build_proof_event *event,
    int64_t now)
{
    struct build_fabric_proof_evaluation evaluation;
    int64_t evaluation_started_us = platform_time_monotonic_us();
    struct zcl_result evaluated = build_fabric_proof_evaluate(
        ndb, event->workspace, event->action_id, now, &evaluation);
    int64_t evaluation_us =
        platform_time_monotonic_us() - evaluation_started_us;
    /* REPRODUCED is the derived statement that the canonical proof policy is
     * satisfied. A policy may require requester-local reproduction, or may
     * instead authorize an approved independent-signer quorum. Do not impose
     * an undeclared local execution requirement that races peer work. */
    if (!evaluated.ok || !evaluation.policy_satisfied) return;
    struct db_build_proof_event requested, reproduced, ready;
    if (!build_fabric_proof_transition(
            ndb, event->action_id, "REPRODUCED", event->peer_id,
            event->request_id, NULL, NULL, event->deadline_at, 0, now,
            &reproduced).ok)
        return;
    int64_t total_us = db_build_proof_event_requested(
        ndb, event->action_id, event->request_id, &requested)
        ? async_elapsed_us(now, requested.created_at) : 0;
    int64_t projection_started_us = platform_time_monotonic_us();
    struct zcl_result readiness = build_fabric_proof_transition(
        ndb, event->action_id, "READY_FOR_ACCEPTANCE", event->peer_id,
        event->request_id, NULL, NULL, event->deadline_at, total_us, now,
        &ready);
    int64_t projection_us =
        platform_time_monotonic_us() - projection_started_us;
    if (!readiness.ok) {
        LOG_WARN("net.zcode_async",
                 "REPRODUCED durable; readiness retry required: %s",
                 readiness.message);
        return;
    }
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s "
             "stage=acceptance_ready at_unix_us=%lld "
             "local_verification_us=%lld "
             "projection_us=%lld total_background_us=%lld",
             event->action_id, (long long)platform_time_realtime_us(),
             (long long)(evaluation_us < 0 ? 0 : evaluation_us),
             (long long)(projection_us < 0 ? 0 : projection_us),
             (long long)total_us);
}

void boot_zcode_async_proof_tick(
    struct boot_svc_ctx *svc, struct vcs_zcode_work_node *work, int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!svc || !work || !ndb || !ndb->open || now <= 0) return;
    struct db_build_proof_event events[ASYNC_PROOF_BATCH];
    int count = db_build_proof_events_pending(
        ndb, events, ASYNC_PROOF_BATCH);
    for (int i = 0; i < count; i++) {
        bool dispatchable = strcmp(events[i].state, "REQUESTED") == 0 ||
            strcmp(events[i].state, "PEER_DISCOVERED") == 0 ||
            ((strcmp(events[i].state, "CONTEXT_READY") == 0 ||
              strcmp(events[i].state, "RUNNING") == 0) &&
             events[i].deadline_at > 0 && now >= events[i].deadline_at);
        if (dispatchable)
            async_dispatch(svc, work, ndb, &events[i], now);
        else if (strcmp(events[i].state, "REMOTE_GREEN") == 0 ||
                 strcmp(events[i].state, "REMOTE_RED") == 0) {
            struct db_build_proof_event verified;
            ZCL_IGNORE_RESULT(build_fabric_proof_transition(
                ndb, events[i].action_id, "RECEIPT_VERIFIED",
                events[i].peer_id, events[i].request_id, NULL, NULL,
                events[i].deadline_at, 0, now, &verified),
                "remote evidence stays durable and the result FIFO retries");
        }
        else if (strcmp(events[i].state, "RECEIPT_VERIFIED") == 0)
            async_reproduce(ndb, &events[i], now);
    }
}
