/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "validation/sync_evidence_policy.h"
#include "validation/main_constants.h"

int zcl_finality_depth(void)
{
    return ZCL_FINALITY_DEPTH;
}

int zcl_immutable_height(int tip_height)
{
    if (tip_height < 0)
        return -1;
    return tip_height - ZCL_FINALITY_DEPTH;
}

bool zcl_is_finality_safe_anchor(int anchor_height, int peer_tip_height)
{
    int immutable = zcl_immutable_height(peer_tip_height);
    return immutable >= 0 && anchor_height >= 0 && anchor_height <= immutable;
}

bool zcl_is_snapshot_anchor_acceptable(int anchor_height, int peer_tip_height)
{
    if (zcl_is_finality_safe_anchor(anchor_height, peer_tip_height))
        return true;

    /* Power-node cold start serves the current UTXO set, so its commitment is
     * naturally bound to the peer's live tip. Finalized snapshot files remain
     * the preferred immutable anchor; live-tip offers still require FlyClient
     * proof plus SHA3 UTXO verification before activation. */
    return anchor_height >= 0 && anchor_height == peer_tip_height;
}

bool zcl_ibd_reorg_allowed(int reorg_depth)
{
    return reorg_depth >= 0 && reorg_depth <= MAX_IBD_REORG_LENGTH;
}

bool zcl_reorg_allowed(int tip_height, int fork_height, bool in_ibd,
                       const char **reason_out)
{
    if (tip_height < 0) {
        if (reason_out) *reason_out = "no_tip";
        return true;
    }
    if (fork_height >= tip_height) {
        if (reason_out) *reason_out = "no_disconnect";
        return true;
    }

    int depth = tip_height - fork_height;
    if (depth <= ZCL_FINALITY_DEPTH) {
        if (reason_out) *reason_out = "within_finality_depth";
        return true;
    }
    if (in_ibd && zcl_ibd_reorg_allowed(depth)) {
        if (reason_out) *reason_out = "ibd_reorg_allowed";
        return true;
    }

    if (reason_out) *reason_out = "below_finality_depth";
    return false;
}

bool zcl_chainwork_is_zero(const uint8_t chain_work[32])
{
    if (!chain_work)
        return true;
    for (int i = 0; i < 32; i++) {
        if (chain_work[i] != 0)
            return false;
    }
    return true;
}

int zcl_chainwork_compare_le(const uint8_t a[32], const uint8_t b[32])
{
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;

    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

bool zcl_chainwork_below_floor(const uint8_t chain_work[32],
                               const uint8_t floor_le[32])
{
    /* A zero floor is the "no floor configured" case: never reject. */
    if (zcl_chainwork_is_zero(floor_le))
        return false;
    return zcl_chainwork_compare_le(chain_work, floor_le) < 0;
}
