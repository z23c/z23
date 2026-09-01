/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_apply.c — fail-closed runtime PEER-snapshot activation boundary.
 *
 * Peer snapshot download and verification remain available, but runtime
 * activation is contained until one canonical installer can atomically bind
 * every consensus-state component and its rollback point.  In particular,
 * node.db UTXOs, coins_kv, shielded frontiers/nullifiers, reducer cursors,
 * chain evidence, and the served tip must never be promoted by independent
 * best-effort writes.
 *
 * DELIBERATE ASYMMETRY — keep this contained even though the sibling sovereign-
 * bundle installer (engine/composition/src/consensus_state_snapshot_install_activate.c) now
 * lifts ACTIVATE containment under a binary-baked authority (a replay-derived
 * RECEIPT or a CHECKPOINT_ROM manifest that reproduces the compiled
 * g_rom_state_checkpoint bit-for-bit). That path installs a bundle ONLY when
 * it matches a fingerprint baked into THIS binary. A PEER-OFFERED TIP carries no
 * such baked digest — its height/hash/root are the peer's own assertions, not a
 * sovereign fingerprint — so there is nothing here to bind, and this boundary
 * stays fail-closed by design. Do not "lift" it by analogy to the bundle path. */

#include "net/snapshot_sync_contract.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include "snapshot_sync_internal.h"

#define SNAPSYNC_SUBSYS "snapshot_sync"

static struct zcl_result snapsync_activation_contained(
    const struct snapshot_sync_service *svc,
    bool publish_blocker)
{
    struct blocker_record blocker;
    const char *reason =
        "runtime peer snapshot activation is disabled until "
        "consensus_state_snapshot_install atomically installs coins_kv, "
        "shielded frontiers/nullifiers, reducer cursors, provenance, and "
        "rollback; action=continue_normal_p2p_sync_or_upgrade";

    if (publish_blocker &&
        blocker_init(&blocker,
                     SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID,
                     SNAPSYNC_SUBSYS, BLOCKER_DEPENDENCY, reason))
        (void)blocker_set(&blocker);

    LOG_WARN(SNAPSYNC_SUBSYS,
             "peer snapshot activation contained h=%d peer=%u blocker=%s; "
             "continue normal P2P sync until the unified canonical installer "
             "is available",
             svc ? svc->offered_height : -1,
             svc ? svc->serving_peer_id : 0,
             SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
    return ZCL_ERR(
        SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE,
        "peer snapshot verified but activation contained by %s; continue "
        "normal P2P sync and upgrade only after "
        "consensus_state_snapshot_install is available",
        SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
}

struct zcl_result snapsync_stage_promote_active_internal(
    struct node_db *ndb,
    const struct snapshot_sync_service *svc,
    const uint8_t local_root[32],
    uint64_t local_count,
    const struct chain_evidence_record *verified)
{
    if (!ndb || !svc || !local_root) {
        LOG_WARN(SNAPSYNC_SUBSYS,
                 "activate: invalid args ndb=%p svc=%p root=%p",
                 (void *)ndb, (const void *)svc, (const void *)local_root);
        return ZCL_ERR(-1, "activate: null args ndb=%p svc=%p root=%p",
                       (void *)ndb, (const void *)svc,
                       (const void *)local_root);
    }

    /* Deliberately consume no staged or canonical state.  The verified
     * payload remains staged for inspection/a future transaction, while the
     * active node.db set, coins_kv, shielded history, reducer log/cursors,
     * chain evidence, and tip remain exactly at their prior generation. */
    (void)local_count;
    (void)verified;
    return snapsync_activation_contained(svc, true);
}

int snapsync_activate_verified_tip(const struct snapshot_sync_service *svc,
                                   struct main_state *ms)
{
    if (!svc || !ms)
        LOG_ERR(SNAPSYNC_SUBSYS,
                "activate_verified_tip: invalid args svc=%p ms=%p",
                (const void *)svc, (void *)ms);

    /* Belt-and-braces for a persisted/pre-containment COMPLETE state: direct
     * callers cannot mutate block_map, active_chain, coins tip, deferred-proof
     * posture, or the snapshot anchor slot either. */
    /* This legacy resume surface returns the same actionable error but does
     * not publish a process-global blocker: unlike the finalize path, it has
     * no service-state transition whose reset can own blocker cleanup. */
    (void)snapsync_activation_contained(svc, false);
    return SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE;
}
