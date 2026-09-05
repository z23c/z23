/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The only lib/net-to-swarm adapter; see config/boot_zcode_swarm.h. */
#include "config/boot_zcode_swarm.h"
#include "config/boot_zcode_swarm_membership.h"
#include "config/boot_zcode_swarm_receipt.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_internal.h"
#include "config/boot_fleet_board.h"
#include "config/boot_mesh_status.h"
#include "config/boot_mesh_terminal.h"
#include "config/runtime.h"
#include "config/boot_zcode_async_proof.h"
#include "config/boot_zcode_work_perf.h"
#include "config/boot_zcode_work_progress.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "vcs/package_reward.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_work_node.h"
#include "vcs/zcode_work_context.h"
#include "vcs/vcs_object.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "net/peer_identity.h"
#include "net/peer_scoring.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/util.h"
#include "services/build_fabric_worker.h"
#include "services/build_fabric_service.h"
#include "supervisors/domains.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define ZCODE_SWARM_SYNC_PERIOD_SEC 15
#define ZCODE_SWARM_TICK_PERIOD_SEC 1
static zcl_mutex_t s_lock;
static bool s_lock_init;
static struct vcs_swarm_engine *s_engine;   /* owned here */
static struct vcs_zcode_work_node *s_work;  /* owned work adapter */
static struct vcs_service_book *s_book;     /* owned here */
static struct vcs_reward_ledger *s_ledger;  /* owned; may be NULL */
static char s_zcode_dir[4400];
static int64_t s_last_sync;                 /* wall seconds */
static int64_t s_last_tick;
static uint8_t s_work_secret[32];
static uint8_t s_work_pubkey[32];
static bool s_work_key_ready;
static int64_t s_work_capability_expires;
static char s_work_workspace[4096];
static struct boot_svc_ctx *s_svc;          /* borrowed; set by wire() */
static struct liveness_contract s_timer_contract;
static supervisor_child_id s_timer_child = SUPERVISOR_INVALID_ID;
static _Atomic bool s_work_wake_pending;
static uint64_t s_frames_sent;              /* supervisor progress marker */
static size_t boot_zcode_swarm_drain_node(
    struct msg_processor *mp, struct vcs_swarm_engine *engine,
    struct p2p_node *node);
static bool boot_zcode_work_refresh(struct boot_svc_ctx *svc, int64_t wall);
static bool boot_zcode_work_workspace(void)
{
    if (s_work_workspace[0]) return true;
    return getcwd(s_work_workspace, sizeof(s_work_workspace)) != NULL;
}
static bool boot_zcode_work_active_state(const char *state)
{
    return state && (strcmp(state, "QUEUED") == 0 ||
                     strcmp(state, "CLAIMED") == 0 ||
                     strcmp(state, "RUNNING") == 0 ||
                     strcmp(state, "VERIFYING") == 0 ||
                     strcmp(state, "ACCEPTED") == 0 ||
                     strcmp(state, "CACHE_HIT") == 0);
}
static const char *boot_zcode_work_action_kind(uint8_t work_kind, const uint8_t *input, size_t input_len)
{
    struct vcs_zcode_package_action_input_v1 package_input;
    if (work_kind == VCS_ZCODE_WORK_BUILD &&
        vcs_zcode_package_action_input_parse(input, input_len, &package_input) == VCS_ZCODE_ACTION_INPUT_OK)
        return VCS_BUILD_ACTION_KIND_PACKAGE_V1;
    if (work_kind == VCS_ZCODE_WORK_BUILD) return VCS_BUILD_ACTION_KIND_V1;
    if (work_kind == VCS_ZCODE_WORK_TEST)
        return VCS_BUILD_ACTION_KIND_TEST_V1;
    if (work_kind == VCS_ZCODE_WORK_FUZZ)
        return VCS_BUILD_ACTION_KIND_FUZZ_V1;
    return NULL;
}
/* Rebuild content.v2 into the fixed action; only ZBuild state is mutable. */
static struct zcl_result boot_zcode_work_admit(
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    struct vcs_package_store *store = vcs_package_store_global();
    struct node_db *ndb = app_runtime_node_db();
    if (!request || !store || !ndb || !ndb->open ||
        !boot_zcode_work_workspace())
        return ZCL_ERR(-1, "work admission owners unavailable");
    struct vcs_zcode_work_context_v1 context;
    enum vcs_zcode_work_context_result loaded =
        vcs_zcode_work_context_get(store, request->context_root, now,
                                   &context);
    if (loaded != VCS_ZCODE_WORK_CONTEXT_OK)
        return ZCL_ERR(-1, "context: %s",
                       vcs_zcode_work_context_result_string(loaded));
    const char *action_kind = boot_zcode_work_action_kind(
        request->work_kind, context.fixed_input, context.fixed_input_len);
    uint8_t preflight_action[32], preflight_input[32];
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    loaded = action_kind
        ? vcs_zcode_work_context_action_root_for_kind(
              &context, action_kind, now, preflight_action, preflight_input)
        : VCS_ZCODE_WORK_CONTEXT_ACTION;
    bool bound = loaded == VCS_ZCODE_WORK_CONTEXT_OK &&
        vcs_zcode_task_root(&context.task, task_root) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(&context.candidate, candidate_root) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(&context.proof_policy, policy_root) ==
            VCS_ZCODE_DEV_OK &&
        memcmp(preflight_action, request->action_root, 32) == 0 &&
        memcmp(preflight_input, request->input_root, 32) == 0 &&
        memcmp(task_root, request->task_root, 32) == 0 &&
        memcmp(candidate_root, request->candidate_root, 32) == 0 &&
        memcmp(policy_root, request->proof_policy_root, 32) == 0 &&
        memcmp(context.task.toolchain_capsule_root,
               request->toolchain_capsule_root, 32) == 0 &&
        action_kind != NULL &&
        request->max_cpu_seconds <= context.task.max_cpu_seconds &&
        request->max_memory_bytes <= context.task.max_memory_bytes &&
        request->max_output_bytes <= context.task.max_output_bytes;
    if (!bound) {
        vcs_zcode_work_context_free(&context);
        return ZCL_ERR(-1, "context does not reconstruct the signed request");
    }
    struct vcs_zcode_work_context_roots restored;
    loaded = vcs_zcode_work_context_restore_for_kind(
        store, request->context_root, s_work_workspace, action_kind, now,
        &restored);
    bool restored_exact = loaded == VCS_ZCODE_WORK_CONTEXT_OK &&
        memcmp(restored.action_root, preflight_action, 32) == 0 &&
        memcmp(restored.input_root, preflight_input, 32) == 0 &&
        memcmp(restored.source_manifest_id, context.source_sha256, 32) == 0 &&
        memcmp(restored.source_root,
               context.candidate.candidate_source_root, 32) == 0;
    if (!restored_exact) {
        vcs_zcode_work_context_free(&context);
        return ZCL_ERR(-1, "context source closure could not be restored");
    }
    struct db_build_job job = {0};
    struct db_build_action action = {0};
    zcl_hex_encode(context.source_sha256, 32, job.source_sha256);
    zcl_hex_encode(context.candidate.candidate_source_root, 32,
                   job.source_cas_sha3);
    zcl_hex_encode(context.task.toolchain_capsule_root, 32,
                   job.toolchain_sha3);
    (void)snprintf(job.profile, sizeof(job.profile), "%s", context.profile);
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.created_at = job.updated_at = now;
    action.sequence = 0;
    (void)snprintf(action.kind, sizeof(action.kind), "%s",
                   action_kind);
    (void)snprintf(action.state, sizeof(action.state), "SNAPSHOTTED");
    zcl_hex_encode(restored.input_root, 32, action.input_root_sha3);
    zcl_hex_encode(task_root, 32, action.task_root_sha3);
    zcl_hex_encode(candidate_root, 32, action.candidate_root_sha3);
    zcl_hex_encode(policy_root, 32, action.proof_policy_root_sha3);
    zcl_hex_encode(request->context_root, 32, action.context_root_sha3);
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t fixed_flags[32], fixed_environment[32];
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    if (!vcs_build_action_v1_descriptors(
            action_kind, &workdir, &output, &resource) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(
            action_kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action_kind, fixed_environment)) {
        vcs_zcode_work_context_free(&context);
        return ZCL_ERR(-1, "fixed action descriptor disappeared");
    }
    zcl_hex_encode(fixed_flags, 32, action.flags_sha3);
    zcl_hex_encode(fixed_environment, 32, action.environment_sha3);
    (void)snprintf(action.virtual_workdir, sizeof(action.virtual_workdir),
                   "%s", workdir);
    (void)snprintf(action.declared_outputs, sizeof(action.declared_outputs),
                   "%s", output);
    (void)snprintf(action.resource_policy, sizeof(action.resource_policy),
                   "%s", resource);
    action.created_at = action.updated_at = now;
    struct zcl_result ids = build_fabric_action_id(
        &job, &action, action.action_id);
    if (ids.ok && strcmp(action.action_id, "") != 0) {
        uint8_t checked[32];
        ids.ok = zcl_hex_decode_lower(action.action_id, checked, 32) &&
                 memcmp(checked, request->action_root, 32) == 0;
    }
    if (ids.ok)
        ids = build_fabric_job_id(&job, action.action_id, job.job_id);
    if (ids.ok)
        (void)snprintf(action.job_id, sizeof(action.job_id), "%s",
                       job.job_id);
    vcs_zcode_work_context_free(&context);
    if (!ids.ok) return ZCL_ERR(-1, "context action identity mismatch");
    ZCL_CHECK(build_fabric_plan(ndb, &job, &action));
    struct db_build_action current;
    if (!db_build_action_find(ndb, action.action_id, &current))
        return ZCL_ERR(-1, "planned remote action disappeared");
    if (strcmp(current.state, "SNAPSHOTTED") == 0)
        return build_fabric_submit(ndb, job.job_id, now);
    if (!boot_zcode_work_active_state(current.state))
        return ZCL_ERR(-1, "remote action is terminal: %s", current.state);
    return ZCL_OK;
}
static void boot_zcode_work_drain_admissions(int64_t now)
{
    if (!s_work || !s_svc || !s_svc->app_ctx || !s_svc->app_ctx->build_worker) return;
    for (;;) {
        uint64_t peer = 0;
        struct vcs_zcode_work_request_v1 request;
        if (!vcs_zcode_work_node_peek_request(s_work, &peer, &request))
            break;
        struct vcs_package_store_status status;
        struct vcs_package_store *store = vcs_package_store_global();
        if (!store || !vcs_package_store_package_status(
                store, request.context_root, &status) || !status.complete)
            break;
        int64_t admission_us = platform_time_monotonic_us();
        struct zcl_result admitted = boot_zcode_work_admit(&request, now);
        admission_us = platform_time_monotonic_us() - admission_us;
        uint64_t drained_peer = 0;
        struct vcs_zcode_work_request_v1 drained;
        if (!vcs_zcode_work_node_next_request(
                s_work, &drained_peer, &drained) || drained_peer != peer ||
            drained.request_id != request.request_id) {
            LOG_ERROR("net.zcode_swarm", "work admission FIFO changed");
            break;
        }
        if (!admitted.ok)
            LOG_WARN("net.zcode_swarm", "request %llu refused: %s",
                     (unsigned long long)request.request_id,
                     admitted.message);
        else {
            boot_zcode_work_perf_admission(&request, &status, s_engine, admission_us);
            boot_zcode_work_progress_context_ready(
                s_work, peer, &request, s_work_secret, s_work_pubkey, now);
        }
    }
}
static void boot_zcode_work_drain_cancels(int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!s_work || !ndb || !ndb->open) return;
    uint64_t peer = 0;
    struct vcs_zcode_work_cancel_v1 cancel;
    while (vcs_zcode_work_node_next_cancel(s_work, &peer, &cancel)) {
        struct vcs_zcode_work_request_v1 request;
        bool cancelled = false;
        if (!vcs_zcode_work_node_inbound_request(
                s_work, peer, cancel.request_id, &request, &cancelled) ||
            !cancelled)
            continue;
        char action_id[65];
        zcl_hex_encode(request.action_root, 32, action_id);
        struct db_build_action action;
        if (db_build_action_find(ndb, action_id, &action)) {
            struct zcl_result result = build_fabric_cancel(
                ndb, action.job_id, now);
            if (!result.ok)
                LOG_WARN("net.zcode_swarm", "cancel %llu: %s",
                         (unsigned long long)cancel.request_id,
                         result.message);
        }
    }
}
static void boot_zcode_work_publish_results(int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!s_work || !ndb || !ndb->open || !s_work_key_ready ||
        !boot_zcode_work_workspace())
        return;
    uint64_t peers[VCS_ZCODE_WORK_NODE_MAX_REQUESTS];
    struct vcs_zcode_work_request_v1 requests[
        VCS_ZCODE_WORK_NODE_MAX_REQUESTS];
    size_t count = vcs_zcode_work_node_inbound_requests(
        s_work, peers, requests, VCS_ZCODE_WORK_NODE_MAX_REQUESTS);
    for (size_t i = 0; i < count; i++) {
        char action_id[65];
        zcl_hex_encode(requests[i].action_root, 32, action_id);
        struct db_build_action action;
        if (!db_build_action_find(ndb, action_id, &action)) continue;
        boot_zcode_work_progress_execution_started(
            s_work, peers[i], &requests[i], &action,
            s_work_secret, s_work_pubkey);
        if (strcmp(action.state, "ACCEPTED") != 0 &&
             strcmp(action.state, "CACHE_HIT") != 0 &&
             strcmp(action.state, "FAILED") != 0)
            continue;
        struct db_build_receipt receipts[8];
        int receipt_count = db_build_job_receipts(
            ndb, action.job_id, receipts, 8);
        for (int j = 0; j < receipt_count; j++) {
            if (strcmp(receipts[j].action_id, action_id) != 0) continue;
            uint8_t receipt_root[32]; uint8_t *wire = NULL;
            size_t wire_len = 0;
            if (!zcl_hex_decode_lower(receipts[j].work_receipt_sha3,
                                      receipt_root, 32) ||
                vcs_object_load_raw(s_work_workspace, receipt_root, &wire,
                                    &wire_len) != 0)
                continue;
            struct vcs_zcode_work_result_v1 result = {
                .request_id = requests[i].request_id,
            };
            memcpy(result.task_root, requests[i].task_root, 32);
            memcpy(result.candidate_root, requests[i].candidate_root, 32);
            memcpy(result.action_root, requests[i].action_root, 32);
            bool parsed = vcs_zcode_work_receipt_parse(
                wire, wire_len, &result.receipt) == VCS_ZCODE_DEV_OK;
            free(wire);
            if (!parsed) continue;
            memcpy(result.output_root, result.receipt.output_root, 32);
            if (!vcs_zcode_work_result_verify(
                    &requests[i], &result, s_work_pubkey))
                continue;
            /* ANNOUNCE before RESULT: package frames drain first, so the
             * result-triggered fetch already knows its exact provider. */
            (void)vcs_swarm_engine_announce_to(s_engine, peers[i]);
            enum vcs_zcode_work_node_result published =
                vcs_zcode_work_node_publish_result(
                    s_work, peers[i], &result);
            if (published == VCS_ZCODE_WORK_NODE_OK) {
                struct vcs_zcode_work_swarm_message message = {
                    .type = VCS_ZCODE_WORK_SWARM_RESULT,
                    .body.result = result,
                };
                LOG_INFO("zcode.proof_perf",
                         "schema=zcl.async_proof_perf.v1 action=%s "
                         "stage=worker_result_publish at_unix_us=%lld "
                         "result_wire_bytes=%zu",
                         action_id, (long long)platform_time_realtime_us(),
                         vcs_zcode_work_swarm_wire_size(&message));
                /* publish_result released the physical worker slot. A
                 * requester that observed signed BUSY must see a strictly
                 * newer signed capacity fact now; waiting for the periodic
                 * refresh can strand work beyond its immutable deadline. */
                if (!boot_zcode_work_refresh(s_svc, now))
                    LOG_WARN("net.zcode_swarm",
                             "released worker slot was not advertised");
            }
            if (published != VCS_ZCODE_WORK_NODE_OK)
                LOG_WARN("net.zcode_swarm", "result %llu: %s",
                         (unsigned long long)requests[i].request_id,
                         vcs_zcode_work_node_result_string(published));
            break;
        }
    }
    (void)vcs_zcode_work_node_requeue_results(s_work, now);
}
static void boot_zcode_work_observe_results(int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!s_work || !ndb || !ndb->open || !boot_zcode_work_workspace())
        return;
    boot_zcode_work_progress_observe(s_work, now);
    for (;;) {
        uint64_t peer = 0;
        struct vcs_zcode_work_result_v1 result;
        if (!vcs_zcode_work_node_peek_result(s_work, &peer, &result)) break;
        struct vcs_zcode_work_request_v1 request;
        if (!vcs_zcode_work_node_outbound_request(
                s_work, peer, result.request_id, &request)) {
            LOG_ERROR("net.zcode_swarm", "verified result lost its request");
            break;
        }
        char receipt_id[65];
        if (!boot_zcode_work_result_observe(
                ndb, peer, &request, &result, s_work_workspace, now,
                receipt_id)) {
            LOG_WARN("net.zcode_swarm",
                     "result %llu was not durably lifecycle-bound",
                     (unsigned long long)result.request_id);
            break;
        }
        uint64_t drained_peer = 0;
        struct vcs_zcode_work_result_v1 drained;
        if (!vcs_zcode_work_node_next_result(
                s_work, &drained_peer, &drained) || drained_peer != peer ||
            drained.request_id != result.request_id) {
            LOG_ERROR("net.zcode_swarm", "work result FIFO changed");
            break;
        }
        LOG_INFO("net.zcode_swarm", "remote receipt %s observed untrusted",
                 receipt_id);
    }
}
static bool boot_zcode_work_refresh(struct boot_svc_ctx *svc, int64_t wall)
{
    if (!s_work || !svc || !svc->app_ctx || !svc->app_ctx->build_worker) return true;
    if (!s_work_key_ready) {
        struct db_build_worker worker;
        struct zcl_result loaded = build_fabric_worker_identity_load(
            svc->datadir, &worker, s_work_secret, s_work_pubkey);
        if (!loaded.ok)
            LOG_FAIL("net.zcode_swarm", "work identity: %s", loaded.message);
        s_work_key_ready = true;
    }
    struct vcs_toolchain_capsule_v1 capsule;
    struct vcs_zcode_work_capability_v1 capability = {0};
    if (!vcs_toolchain_capsule_v1_capture(&capsule) ||
        !vcs_toolchain_capsule_v1_root(
            &capsule, capability.toolchain_capsule_root))
        LOG_FAIL("net.zcode_swarm", "work toolchain capture failed");
    capability.work_kinds = (UINT32_C(1) << VCS_ZCODE_WORK_BUILD) |
                            (UINT32_C(1) << VCS_ZCODE_WORK_TEST) |
                            (UINT32_C(1) << VCS_ZCODE_WORK_FUZZ);
    capability.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
    capability.confinement = VCS_ZCODE_WORK_CONFINEMENT_V1_MASK;
    capability.max_cpu_seconds = 580;
    capability.max_memory_bytes = UINT64_C(2) * 1024u * 1024u * 1024u;
    capability.max_output_bytes = VCS_BUILD_ARTIFACT_MAX_BYTES;
    capability.max_lease_seconds = 600;
    capability.slots = 1;
    capability.queue_headroom = 1;
    capability.expires_unix = wall + 600;
    if (capability.expires_unix <= s_work_capability_expires)
        capability.expires_unix = s_work_capability_expires + 1;
    if (!vcs_zcode_work_capability_seal(
            &capability, s_work_secret, s_work_pubkey) ||
        !vcs_zcode_work_node_set_local_signer(
            s_work, s_work_secret, s_work_pubkey) ||
        !vcs_zcode_work_node_set_local_capability(s_work, &capability))
        LOG_FAIL("net.zcode_swarm", "work capability signing failed");
    s_work_capability_expires = capability.expires_unix;
    return true;
}
static void boot_zcode_swarm_lock(void)
{
    if (!s_lock_init) {
        /* wire() initializes eagerly before the supervisor child can
         * fire; this fallback covers a frame arriving on an unwired
         * msg_processor (single message-handler thread at that point). */
        zcl_mutex_init(&s_lock);
        s_lock_init = true;
    }
    zcl_mutex_lock(&s_lock);
}
/* score_fn for the engine: earned score from the reward ledger. Pseudo-
 * keys never appear there (zero today); a future authenticated-key swap
 * then needs no engine change. */
static uint64_t boot_zcode_swarm_score(const uint8_t contributor[33],
                                       void *ctx)
{
    (void)ctx;
    if (!s_ledger)
        return 0;
    struct vcs_reward_contributor_totals t;
    memset(&t, 0, sizeof(t));
    vcs_reward_contributor_totals(s_ledger, contributor, &t);
    return t.earned_score;
}

/* Lazily create the node-global engine. Caller holds s_lock. Returns NULL
 * (named, logged) when hosting is off or setup fails — the swarm stays off
 * for that frame/tick; nothing here is fatal. */
static struct vcs_swarm_engine *boot_zcode_swarm_ensure(
    struct boot_svc_ctx *svc)
{
    if (s_engine)
        return s_engine;
    if (!svc || !svc->datadir)
        return NULL;
    if (!GetBoolArg("-packagehost", false))
        return NULL;
    struct vcs_package_store *store = vcs_package_store_global();
    if (!store)
        return NULL;
    int n = snprintf(s_zcode_dir, sizeof(s_zcode_dir), "%s/zcode",
                     svc->datadir);
    if (n < 0 || (size_t)n >= sizeof(s_zcode_dir))
        LOG_NULL("net.zcode_swarm", "datadir path too long");
    s_book = vcs_service_book_load(s_zcode_dir);
    if (!s_book)
        LOG_NULL("net.zcode_swarm",
                 "service book unavailable; swarm off");
    /* The ledger is optional: tier resolution degrades to NEW_USER. */
    s_ledger = vcs_reward_ledger_load(s_zcode_dir);
    s_engine = vcs_swarm_engine_create(store, s_book, s_zcode_dir,
                                       boot_zcode_swarm_score, NULL);
    if (!s_engine) {
        vcs_reward_ledger_free(s_ledger);
        s_ledger = NULL;
        vcs_service_book_free(s_book);
        s_book = NULL;
        LOG_NULL("net.zcode_swarm", "engine create failed; swarm off");
    }
    vcs_swarm_engine_set_global(s_engine);
    s_work = vcs_zcode_work_node_create();
    if (!s_work) {
        vcs_swarm_engine_set_global(NULL);
        vcs_swarm_engine_free(s_engine); s_engine = NULL;
        vcs_reward_ledger_free(s_ledger); s_ledger = NULL;
        vcs_service_book_free(s_book); s_book = NULL;
        LOG_NULL("net.zcode_swarm", "work adapter create failed; swarm off");
    }
    vcs_zcode_work_node_set_global(s_work);
    if (!boot_zcode_work_refresh(svc,
            (int64_t)platform_time_wall_time_t())) {
        vcs_zcode_work_node_set_global(NULL);
        vcs_zcode_work_node_free(s_work); s_work = NULL;
        vcs_swarm_engine_set_global(NULL);
        vcs_swarm_engine_free(s_engine); s_engine = NULL;
        vcs_reward_ledger_free(s_ledger); s_ledger = NULL;
        vcs_service_book_free(s_book); s_book = NULL;
        LOG_NULL("net.zcode_swarm", "work capability failed; swarm off");
    }
    return s_engine;
}

bool boot_zcode_swarm_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *payload, size_t payload_len,
                            void *ctx)
{
    if (!mp || !node || !payload)
        LOG_FAIL("net.zcode_swarm", "null mp/node/payload");
    if (boot_zcode_dht_frame(mp, node, payload, payload_len,
                             (struct boot_svc_ctx *)ctx))
        return true;
    /* Mesh status must answer with hosting off: dispatch before ensure. */
    if (boot_mesh_status_frame(mp, node, payload, payload_len,
                               (struct boot_svc_ctx *)ctx))
        return true;
    /* The AI message board and wiki: every full node carries them, so the
     * board leg answers before swarm hosting is even considered. */
    if (boot_fleet_board_frame(mp, node, payload, payload_len, ctx))
        return true;
    /* Confined mesh terminal: same reasoning — its OPENs are answered on
     * the pairing authority alone, never gated on swarm hosting. */
    if (boot_mesh_terminal_frame(mp, node, payload, payload_len,
                                 (struct boot_svc_ctx *)ctx))
        return true;
    boot_zcode_swarm_lock();
    struct vcs_swarm_engine *engine =
        boot_zcode_swarm_ensure((struct boot_svc_ctx *)ctx);
    if (!engine) {
        zcl_mutex_unlock(&s_lock);
        return true; /* hosting off: drop quietly (never an offence) */
    }
    uint8_t key[33];
    if (!boot_zcode_swarm_peer_key(node, key)) {
        zcl_mutex_unlock(&s_lock);
        return true; /* no usable host identity: drop, never an offence */
    }
    (void)vcs_swarm_engine_peer_add(engine, boot_zcode_swarm_peer_id(node),
                                    key);
    int64_t day = (int64_t)platform_time_wall_time_t() / 86400;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    uint64_t peer_id = boot_zcode_swarm_peer_id(node);
    (void)vcs_zcode_work_node_peer_add(s_work, peer_id);
    if (boot_zcode_swarm_receipt_frame(mp, node, engine, s_book, s_zcode_dir,
                                       payload, payload_len, day)) {
        zcl_mutex_unlock(&s_lock);
        return true;
    }
    if (payload_len >= 4 && memcmp(payload, "ZCWS", 4) == 0) {
        enum vcs_zcode_work_node_result wr =
            vcs_zcode_work_node_handle_frame(s_work, peer_id, payload,
                                              payload_len, (int64_t)now);
        if (wr == VCS_ZCODE_WORK_NODE_OK) {
            struct vcs_zcode_work_swarm_message message;
            if (vcs_zcode_work_swarm_parse(payload, payload_len, &message)) {
                const uint8_t *wanted = message.type == VCS_ZCODE_WORK_SWARM_REQUEST
                    ? message.body.request.context_root
                    : message.type == VCS_ZCODE_WORK_SWARM_RESULT
                    ? message.body.result.output_root : NULL;
                if (wanted) {
                    /* The accepted signed work frame binds this immutable
                     * root to the authenticated transport sender.  Fetch
                     * directly from that session instead of waiting behind
                     * the independent broadcast-ANNOUNCE quota. */
                    (void)vcs_swarm_engine_fetch_from(
                        engine, wanted, day, now, &peer_id, 1);
                    vcs_swarm_engine_schedule_ready(engine, day, now);
                }
                /* Network callbacks may advance only the in-memory swarm.
                 * SQLite-backed admission/projection remains owned by the
                 * periodic service lane; doing it here races foreground
                 * requester transactions on the canonical node handle. */
                (void)boot_zcode_swarm_drain_node(mp, engine, node);
            }
        }
        zcl_mutex_unlock(&s_lock);
        if (wr == VCS_ZCODE_WORK_NODE_OK)
            boot_zcode_swarm_request_tick();
        if (wr != VCS_ZCODE_WORK_NODE_OK)
            LOG_WARN("net.zcode_swarm", "peer %llu work frame refused: %s",
                     (unsigned long long)peer_id, vcs_zcode_work_node_result_string(wr));
        if (wr == VCS_ZCODE_WORK_NODE_MALFORMED ||
            wr == VCS_ZCODE_WORK_NODE_REPLAY ||
            wr == VCS_ZCODE_WORK_NODE_UNREQUESTED ||
            wr == VCS_ZCODE_WORK_NODE_BINDING) {
            char context[96];
            (void)snprintf(context, sizeof(context), "zcode work: %s",
                           vcs_zcode_work_node_result_string(wr));
            if (mp->net_mgr)
                peer_scoring_record(mp->net_mgr, node,
                                    PEER_OFFENCE_INVALID_PAYLOAD, context);
        }
        return true;
    }
    struct vcs_swarm_frame_result ev = vcs_swarm_engine_handle_frame(
        engine, boot_zcode_swarm_peer_id(node), payload, payload_len, day,
        now);
    vcs_swarm_engine_schedule_ready(engine, day, now);
    (void)boot_zcode_swarm_drain_node(mp, engine, node);
    zcl_mutex_unlock(&s_lock);
    boot_zcode_swarm_request_tick();

    if (ev.penalty != VCS_SWARM_PENALTY_NONE && mp->net_mgr) {
        char context[96];
        (void)snprintf(context, sizeof(context), "zcode swarm: %s",
                       ev.rule ? ev.rule : "penalty");
        peer_scoring_record(mp->net_mgr, node,
                            boot_zcode_swarm_offence(ev.penalty), context);
    }
    if (ev.reply) {
        if (ev.reply_len > 0 && !atomic_load(&node->disconnect))
            boot_zcode_swarm_send(mp, node, ev.reply, ev.reply_len);
        free(ev.reply);
    }
    if (ev.disconnect_peer)
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_APPLICATION,
            P2P_DISCONNECT_SOURCE_APPLICATION, node->endpoint_generation);
    return true;
}

/* Throttled periodic work shared by the message-cycle tick and the
 * supervisor timer: membership sync every SYNC_PERIOD, engine scheduler
 * tick + work-node drains every TICK_PERIOD. Caller holds s_lock. */
static void boot_zcode_swarm_periodic(struct msg_processor *mp,
                                      struct vcs_swarm_engine *engine,
                                      struct boot_svc_ctx *svc, int64_t wall)
{
    if (wall - s_last_sync >= ZCODE_SWARM_SYNC_PERIOD_SEC) {
        s_last_sync = wall;
        boot_zcode_swarm_sync_membership(mp, engine, s_work);
    }
    bool due = wall - s_last_tick >= ZCODE_SWARM_TICK_PERIOD_SEC;
    bool woken = atomic_exchange(&s_work_wake_pending, false);
    if (due || woken) {
        if (due) s_last_tick = wall;
        vcs_swarm_engine_tick(engine, wall / 86400, (uint64_t)wall);
        vcs_zcode_work_node_tick(s_work, wall);
        boot_zcode_async_proof_tick(svc, s_work, wall);
        boot_zcode_async_proof_drain_admissions(s_work, wall);
        boot_zcode_work_drain_admissions(wall);
        boot_zcode_work_drain_cancels(wall);
        boot_zcode_work_publish_results(wall);
        boot_zcode_work_observe_results(wall);
        /* A result observed above derives RECEIPT_VERIFIED. Project readiness
         * in the same supervised turn instead of imposing another timer
         * boundary; canonical rows still gate every transition. */
        boot_zcode_async_proof_tick(svc, s_work, wall);
        if (svc->app_ctx && svc->app_ctx->build_worker && wall + 60 >= s_work_capability_expires)
            (void)boot_zcode_work_refresh(svc, wall);
    }
}

void boot_zcode_swarm_request_tick(void)
{
    atomic_store(&s_work_wake_pending, true);
    if (s_timer_child != SUPERVISOR_INVALID_ID)
        supervisor_request_tick(s_timer_child);
}

/* Drain queued frames for ONE node (bounded by the engine's outbound
 * queue; WANT/CANCEL/ANNOUNCE frames only — DATA replies go out
 * synchronously from the frame hook). Returns frames sent. Caller holds
 * s_lock; node must be ref-held by the caller. */
static size_t boot_zcode_swarm_drain_node(struct msg_processor *mp,
                                          struct vcs_swarm_engine *engine,
                                          struct p2p_node *node)
{
    if (!boot_zcode_swarm_eligible(node))
        return 0;
    size_t sent = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    for (;;) {
        uint64_t peer_out = 0;
        size_t frame_len = 0;
        uint64_t peer_id = boot_zcode_swarm_peer_id(node);
        if (!vcs_swarm_engine_next_outbound(engine, peer_id,
                                            &peer_out, frame,
                                            &frame_len))
            break;
        if (peer_out != peer_id || frame_len == 0)
            break; /* defensive: filter contract violated */
        boot_zcode_swarm_send(mp, node, frame, frame_len);
        sent++;
    }
    uint8_t work_frame[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    for (;;) {
        uint64_t peer_out = 0; size_t frame_len = 0;
        uint64_t peer_id = boot_zcode_swarm_peer_id(node);
        if (!vcs_zcode_work_node_next_outbound(
                s_work, peer_id, &peer_out, work_frame, &frame_len))
            break;
        if (peer_out != peer_id || frame_len == 0) break;
        boot_zcode_swarm_send(mp, node, work_frame, frame_len);
        sent++;
    }
    int64_t day = (int64_t)platform_time_wall_time_t() / 86400;
    sent += boot_zcode_swarm_receipt_drain(mp, node, engine, s_zcode_dir,
                                           day);
    return sent;
}

void boot_zcode_swarm_tick(struct msg_processor *mp, struct p2p_node *node,
                           void *ctx)
{
    if (!mp || !node)
        return;
    boot_fleet_board_tick(mp, node, ctx);
    int64_t wall = (int64_t)platform_time_wall_time_t();
    boot_zcode_swarm_lock();
    struct vcs_swarm_engine *engine =
        boot_zcode_swarm_ensure((struct boot_svc_ctx *)ctx);
    if (engine) {
        /* The message-cycle already owns this authenticated peer. Register
         * that exact session immediately so capability exchange never waits
         * behind the independent 15-second full-membership reconciliation. */
        (void)boot_zcode_swarm_add_peer(engine, s_work, node, false);
        boot_zcode_swarm_periodic(mp, engine, (struct boot_svc_ctx *)ctx,
                                  wall);
        (void)boot_zcode_swarm_drain_node(mp, engine, node);
    }
    zcl_mutex_unlock(&s_lock);
}

/* Supervisor on_tick: the swarm's real clock. Fires every
 * ZCODE_SWARM_TICK_PERIOD_SEC even without peer traffic — an idle
 * healthy connection still needs announces, WANTs, and outbound drains.
 * Progress marker = cumulative frames sent; a quiet child WITH active
 * downloads reports neither (a wedged download should raise NO_PROGRESS). */
static void boot_zcode_swarm_timer_tick(struct liveness_contract *self)
{
    (void)self;
    struct boot_svc_ctx *svc = s_svc;
    if (!svc || !svc->msg_processor)
        return; /* not wired: nothing legitimate to report */
    struct msg_processor *mp = svc->msg_processor;
    boot_zcode_dht_periodic(mp, svc);
    int64_t wall = (int64_t)platform_time_wall_time_t();
    boot_zcode_swarm_lock();
    if (svc != s_svc) {
        zcl_mutex_unlock(&s_lock);
        return; /* shutdown raced us */
    }
    struct vcs_swarm_engine *engine = boot_zcode_swarm_ensure(svc);
    if (!engine) {
        zcl_mutex_unlock(&s_lock);
        /* Hosting off is a legitimate nothing-to-do; an ensure FAILURE
         * (store closed, alloc) is already logged and is not idleness. */
        if (!GetBoolArg("-packagehost", false))
            supervisor_progress_idle(s_timer_child);
        return;
    }
    boot_zcode_swarm_periodic(mp, engine, svc, wall);
    /* Drain ALL eligible peers: snapshot under cs_nodes (connman's
     * message-cycle pattern), send outside it. Lock order here is
     * s_lock -> cs_nodes, same as sync_membership. */
    size_t sent = 0;
    struct net_manager *nm = mp->net_mgr;
    if (nm) {
        size_t snap_count = 0;
        struct p2p_node **snap = NULL;
        zcl_mutex_lock(&nm->cs_nodes);
        size_t num = nm->num_nodes;
        if (num > 0) {
            snap = zcl_malloc(num * sizeof(*snap), "zcode_swarm_snap");
            if (snap) {
                for (size_t i = 0; i < num; i++) {
                    struct p2p_node *node = nm->nodes[i];
                    if (!node || atomic_load(&node->disconnect))
                        continue;
                    snap[snap_count++] = node;
                    p2p_node_add_ref(node);
                }
            }
        }
        zcl_mutex_unlock(&nm->cs_nodes);
        for (size_t i = 0; i < snap_count; i++) {
            sent += boot_zcode_swarm_drain_node(mp, engine, snap[i]);
            p2p_node_release(snap[i]);
        }
        free(snap);
    }
    size_t active = vcs_swarm_engine_active_downloads(engine);
    zcl_mutex_unlock(&s_lock);
    if (sent > 0) {
        s_frames_sent += sent;
        supervisor_progress(s_timer_child, (int64_t)s_frames_sent);
    } else if (active == 0) {
        supervisor_progress_idle(s_timer_child);
    }
}

void boot_zcode_swarm_wire(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->msg_processor) {
        LOG_ERROR("net.zcode_swarm", "wire: null svc/msg_processor");
        return;
    }
    /* Eager mutex init: the supervisor tick-runner races the lazy path
     * in boot_zcode_swarm_lock otherwise. wire() runs single-threaded
     * at boot before the child is armed. */
    if (!s_lock_init) {
        zcl_mutex_init(&s_lock);
        s_lock_init = true;
    }
    msg_processor_set_zcode_swarm(svc->msg_processor,
                                  boot_zcode_swarm_frame,
                                  boot_zcode_swarm_tick, svc);
    s_svc = svc;
    boot_mesh_status_wire(svc);
    boot_fleet_board_wire(svc);
    boot_mesh_terminal_wire(svc);
    liveness_contract_init(&s_timer_contract, "net.zcode_swarm");
    s_timer_contract.on_tick = boot_zcode_swarm_timer_tick;
    supervisor_domains_init();
    s_timer_child = supervisor_register_in_domain(g_net_sup,
                                                  &s_timer_contract);
    if (s_timer_child == SUPERVISOR_INVALID_ID) {
        LOG_ERROR("net.zcode_swarm",
                  "supervisor register failed; swarm is message-driven only");
        return;
    }
    supervisor_set_period(s_timer_child, ZCODE_SWARM_TICK_PERIOD_SEC);
    supervisor_set_deadline(s_timer_child, 30);
    /* ARMED progress policy (gate-recognised form: one line, plain
     * non-zero literal — 30 min in us). A seeder with no peers is
     * legitimately quiet (idle-reported); a downloader that sends
     * nothing for 30 minutes is wedged. */
    supervisor_set_progress_max_quiet(s_timer_child, 1800000000);
}

void boot_zcode_swarm_shutdown(void)
{
    if (s_timer_child != SUPERVISOR_INVALID_ID) {
        supervisor_unregister(s_timer_child);
        s_timer_child = SUPERVISOR_INVALID_ID;
    }
    boot_zcode_dht_shutdown();
    boot_mesh_status_shutdown();
    boot_fleet_board_shutdown();
    boot_mesh_terminal_shutdown();
    boot_zcode_swarm_lock();
    s_svc = NULL;
    vcs_swarm_engine_set_global(NULL);
    vcs_zcode_work_node_set_global(NULL);
    if (s_work) vcs_zcode_work_node_free(s_work);
    s_work = NULL;
    if (s_engine) vcs_swarm_engine_free(s_engine);
    s_engine = NULL;
    if (s_book) vcs_service_book_free(s_book);
    s_book = NULL;
    if (s_ledger) vcs_reward_ledger_free(s_ledger);
    s_ledger = NULL;
    boot_zcode_swarm_receipt_close();
    s_last_sync = 0;
    s_last_tick = 0;
    s_frames_sent = 0;
    memset(s_work_secret, 0, sizeof(s_work_secret));
    memset(s_work_pubkey, 0, sizeof(s_work_pubkey));
    s_work_key_ready = false;
    s_work_capability_expires = 0;
    memset(s_work_workspace, 0, sizeof(s_work_workspace));
    zcl_mutex_unlock(&s_lock);
}
