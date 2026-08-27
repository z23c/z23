/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Independent-worker selection for async proof dispatch. */

#include "config/boot_zcode_async_select.h"

#include "base/hex.h"
#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "util/log_macros.h"
#include "vcs/zcode_work_node.h"

#include <string.h>

static bool async_capability_allows(
    const struct vcs_zcode_work_capability_v1 *capability,
    const struct db_build_job *job, uint8_t work_kind)
{
    uint8_t toolchain[32];
    return capability &&
        zcl_hex_decode_lower(job->toolchain_sha3, toolchain, 32) &&
        capability->queue_headroom > 0 &&
        capability->max_lease_seconds > 0 &&
        capability->target == VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3 &&
        (capability->work_kinds & (UINT32_C(1) << work_kind)) != 0 &&
        (capability->confinement & VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) ==
            VCS_ZCODE_WORK_CONFINEMENT_V1_MASK &&
        memcmp(capability->toolchain_capsule_root, toolchain, 32) == 0;
}

bool boot_zcode_async_select_peer(
    struct vcs_zcode_work_node *work,
    const struct db_build_proof_event *event,
    const struct db_build_job *job, uint8_t work_kind, int64_t now,
    uint64_t *peer_out, struct vcs_zcode_work_capability_v1 *capability_out)
{
    if (!work || !event || !job || !peer_out || !capability_out)
        return false;
    bool retry = event->deadline_at > 0 && now >= event->deadline_at;
    if (event->peer_id && !retry &&
        vcs_zcode_work_node_peer_capability(
            work, event->peer_id, now, capability_out)) {
        /* This request already consumed its peer slot. Zero advertised
         * headroom prevents a new lease; it must not evict the live one. */
        uint16_t headroom = capability_out->queue_headroom;
        if (headroom == 0) capability_out->queue_headroom = 1;
        bool still_eligible = async_capability_allows(
            capability_out, job, work_kind);
        capability_out->queue_headroom = headroom;
        if (still_eligible) {
            *peer_out = event->peer_id;
            return true;
        }
    }
    uint64_t peers[VCS_ZCODE_WORK_NODE_MAX_PEERS];
    struct vcs_zcode_work_capability_v1 capabilities[
        VCS_ZCODE_WORK_NODE_MAX_PEERS];
    size_t count = vcs_zcode_work_node_capable_peers(
        work, now, peers, capabilities, VCS_ZCODE_WORK_NODE_MAX_PEERS);
    size_t passes = retry ? 2 : 1;
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t i = 0; i < count; i++) {
            /* An expired request must move to a different physical worker:
             * the prior worker may have finished and lost its RESULT, while
             * its in-memory track intentionally retains no result bytes to
             * replay. */
            if (retry && peers[i] == event->peer_id)
                continue;
            /* Prefer signed free headroom.  On the second pass, a different
             * peer may be probed despite stale signed zero headroom.  This
             * grants no work authority: the receiving worker independently
             * admits, returns BUSY, or refuses the exact request. */
            uint16_t headroom = capabilities[i].queue_headroom;
            if (retry && pass == 1 && headroom == 0)
                capabilities[i].queue_headroom = 1;
            bool eligible = async_capability_allows(
                &capabilities[i], job, work_kind);
            capabilities[i].queue_headroom = headroom;
            if (!eligible) continue;
            *peer_out = peers[i];
            *capability_out = capabilities[i];
            return true;
        }
    }
    return false;
}

const char *boot_zcode_async_log_no_peer(
    struct vcs_zcode_work_node *work, const struct db_build_job *job,
    const char *action_id, int64_t now)
{
    uint64_t peers[VCS_ZCODE_WORK_NODE_MAX_PEERS];
    struct vcs_zcode_work_capability_v1 caps[VCS_ZCODE_WORK_NODE_MAX_PEERS];
    size_t capable = vcs_zcode_work_node_capable_peers(
        work, now, peers, caps, VCS_ZCODE_WORK_NODE_MAX_PEERS);
    char peer_toolchain[65];
    peer_toolchain[0] = '\0';
    bool toolchain_match = false;
    const char *job_toolchain =
        job && job->toolchain_sha3[0] ? job->toolchain_sha3 : "none";
    if (capable > 0)
        zcl_hex_encode(caps[0].toolchain_capsule_root, 32, peer_toolchain);
    for (size_t i = 0; i < capable; i++) {
        char hex[65];
        zcl_hex_encode(caps[i].toolchain_capsule_root, 32, hex);
        if (strcmp(hex, job_toolchain) == 0) {
            toolchain_match = true;
            break;
        }
    }
    const char *reason = capable == 0 ? "no-capable-worker" :
        toolchain_match ? "worker-busy-or-target-mismatch" :
        "toolchain-capsule-mismatch";
    const char *next = capable == 0
        ? "z23 join"
        : "run zcode work toolchain here and on the proving node";
    LOG_WARN("net.zcode_async",
             "dispatch refused action=%s stage=peer_selection "
             "reason=%s capable=%zu job_toolchain=%s "
             "peer0_toolchain=%s next_action=%s",
             action_id, reason, capable, job_toolchain,
             peer_toolchain[0] ? peer_toolchain : "none", next);
    return next;
}
