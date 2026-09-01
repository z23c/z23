/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed progress telemetry on the existing ZCODE work swarm. */

#include "config/boot_zcode_work_progress.h"

#include "base/hex.h"
#include "config/boot_zcode_async_proof.h"
#include "config/runtime.h"
#include "models/build_fabric.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "util/log_macros.h"
#include "vcs/zcode_work_node.h"

#include <string.h>

static bool work_progress_make(
    struct vcs_zcode_work_progress_v1 *progress,
    const struct vcs_zcode_work_request_v1 *request,
    uint8_t stage, int64_t observed_unix,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!progress || !request || !secret || !pubkey || observed_unix <= 0)
        return false;
    memset(progress, 0, sizeof(*progress));
    progress->request_id = request->request_id;
    memcpy(progress->task_root, request->task_root, 32);
    memcpy(progress->candidate_root, request->candidate_root, 32);
    memcpy(progress->action_root, request->action_root, 32);
    progress->stage = stage;
    progress->observed_unix = observed_unix;
    return vcs_zcode_work_progress_seal(progress, secret, pubkey);
}

static void work_progress_publish(
    struct vcs_zcode_work_node *work, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    uint8_t stage, int64_t observed_unix,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    struct vcs_zcode_work_progress_v1 progress;
    if (!work_progress_make(&progress, request, stage, observed_unix,
                            secret, pubkey)) {
        LOG_WARN("net.zcode_swarm", "progress %u could not be signed", stage);
        return;
    }
    enum vcs_zcode_work_node_result result =
        vcs_zcode_work_node_publish_progress(work, peer, &progress);
    if (result == VCS_ZCODE_WORK_NODE_OK) {
        char action_id[65];
        zcl_hex_encode(request->action_root, 32, action_id);
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_PROGRESS,
            .body.progress = progress,
        };
        LOG_INFO("zcode.proof_perf",
                 "schema=zcl.async_proof_perf.v1 action=%s "
                 "stage=worker_progress_publish progress_stage=%u "
                 "at_unix_us=%lld progress_wire_bytes=%zu",
                 action_id, (unsigned)stage,
                 (long long)platform_time_realtime_us(),
                 vcs_zcode_work_swarm_wire_size(&message));
    }
    if (result != VCS_ZCODE_WORK_NODE_OK &&
        result != VCS_ZCODE_WORK_NODE_REPLAY)
        LOG_WARN("net.zcode_swarm", "progress %u: %s", stage,
                 vcs_zcode_work_node_result_string(result));
}

void boot_zcode_work_progress_context_ready(
    struct vcs_zcode_work_node *work, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const uint8_t secret[32], const uint8_t pubkey[32], int64_t now)
{
    work_progress_publish(
        work, peer, request, VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY, now,
        secret, pubkey);
}

void boot_zcode_work_progress_execution_started(
    struct vcs_zcode_work_node *work, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct db_build_action *action,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!action || action->started_at <= 0) return;
    work_progress_publish(
        work, peer, request, VCS_ZCODE_WORK_PROGRESS_EXECUTION_STARTED,
        action->started_at, secret, pubkey);
}

void boot_zcode_work_progress_observe(
    struct vcs_zcode_work_node *work, int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!work || !ndb || !ndb->open) return;
    for (;;) {
        uint64_t peer = 0;
        struct vcs_zcode_work_progress_v1 progress;
        if (!vcs_zcode_work_node_next_progress(work, &peer, &progress)) break;
        struct vcs_zcode_work_request_v1 request;
        if (!vcs_zcode_work_node_outbound_request(
                work, peer, progress.request_id, &request) ||
            !boot_zcode_async_proof_observe_progress(
                ndb, peer, &request, &progress, now)) {
            LOG_WARN("net.zcode_swarm", "progress %llu lost lifecycle binding",
                     (unsigned long long)progress.request_id);
            continue;
        }
        char action_id[65];
        zcl_hex_encode(request.action_root, 32, action_id);
        LOG_INFO("zcode.proof_perf",
                 "schema=zcl.async_proof_perf.v1 action=%s "
                 "stage=requester_progress_observe progress_stage=%u "
                 "at_unix_us=%lld",
                 action_id, (unsigned)progress.stage,
                 (long long)platform_time_realtime_us());
    }
}

bool boot_zcode_work_result_observe(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result,
    const char *fallback_workspace, int64_t now, char receipt_id[65])
{
    char workspace[4096];
    const char *owner = boot_zcode_async_proof_workspace(
        ndb, request, workspace) ? workspace : fallback_workspace;
    int64_t started = platform_time_monotonic_us();
    struct zcl_result observed = build_fabric_receipt_observe_remote(
        ndb, owner, request, result, now, receipt_id);
    int64_t elapsed = platform_time_monotonic_us() - started;
    if (!observed.ok) return false;
    int64_t projection_started_us = platform_time_monotonic_us();
    bool projected = boot_zcode_async_proof_observe_result(
        ndb, peer, request, result, receipt_id,
        elapsed < 0 ? 0 : elapsed, now);
    int64_t projection_us =
        platform_time_monotonic_us() - projection_started_us;
    if (projected) {
        char action_id[65];
        zcl_hex_encode(request->action_root, 32, action_id);
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_RESULT,
            .body.result = *result,
        };
        int64_t transport_us = result->receipt.finished_unix < now
            ? (now - result->receipt.finished_unix) * INT64_C(1000000) : 0;
        LOG_INFO("zcode.proof_perf",
                 "schema=zcl.async_proof_perf.v1 action=%s "
                 "stage=requester_result at_unix_us=%lld "
                 "result_transport_us=%lld "
                 "receipt_verification_us=%lld projection_us=%lld "
                 "result_wire_bytes=%zu",
                 action_id, (long long)platform_time_realtime_us(),
                 (long long)transport_us,
                 (long long)(elapsed < 0 ? 0 : elapsed),
                 (long long)(projection_us < 0 ? 0 : projection_us),
                 vcs_zcode_work_swarm_wire_size(&message));
    }
    return projected;
}
