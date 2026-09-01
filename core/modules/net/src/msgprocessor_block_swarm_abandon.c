/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One fail-closed block-swarm abandonment transaction shared by the
 * integrity-mismatch and completion-silent fallback paths. */

#include "msgprocessor_internal.h"
#include "msgprocessor_snapshot_internal.h"

#include "event/event.h"
#include "net/fast_sync.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

void mp_block_swarm_mark_complete_through_height(
    struct block_swarm *swarm, int32_t have_height)
{
    if (!swarm || !swarm->piece_states ||
        have_height < swarm->manifest.start_height)
        return;

    int64_t complete_blocks =
        (int64_t)have_height - (int64_t)swarm->manifest.start_height + 1;
    if (complete_blocks <= 0)
        return;

    uint32_t full_pieces =
        (uint32_t)(complete_blocks / BLOCKS_PER_PIECE);
    if (full_pieces > swarm->manifest.num_pieces)
        full_pieces = swarm->manifest.num_pieces;

    for (uint32_t i = 0; i < full_pieces; i++) {
        if (swarm->piece_states[i] == CHUNK_COMPLETE)
            continue;
        swarm->piece_states[i] = CHUNK_COMPLETE;
        swarm->piece_peer[i] = -1;
        swarm->piece_request_time[i] = 0;
        swarm->pieces_complete++;
    }
    if (full_pieces > 0)
        swarm->last_complete_unix = (int64_t)platform_time_wall_time_t();
}

bool mp_block_swarm_abandon_locked(
    struct block_swarm *swarm, _Atomic bool *active,
    _Atomic int64_t *reaped_unix, int64_t now,
    struct block_swarm_abandonment *out)
{
    if (!swarm || !active || !reaped_unix || !atomic_load(active) ||
        !swarm->piece_states || swarm->manifest.num_pieces == 0)
        return false;

    if (out) {
        out->complete = swarm->pieces_complete;
        out->total = swarm->manifest.num_pieces;
        out->failed = swarm->pieces_failed;
        out->last_complete_unix = swarm->last_complete_unix;
    }
    block_swarm_free(swarm);
    atomic_store(active, false);
    atomic_store(reaped_unix, now);
    return true;
}

void mp_block_swarm_finish_abandon(struct msg_processor *mp)
{
    if (!mp || !mp->net_mgr)
        return;

    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t i = 0; i < mp->net_mgr->num_nodes; i++) {
        struct p2p_node *node = mp->net_mgr->nodes[i];
        if (!node)
            continue;
        for (int pi = 0; pi < PIECE_PIPELINE_DEPTH; pi++)
            node->blk_pipeline[pi].piece_index = -1;
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
}

void mp_block_swarm_report_integrity_abandon(
    struct msg_processor *mp, const struct p2p_node *node,
    uint32_t piece_index, const struct block_swarm_abandonment *abandoned)
{
    if (!abandoned)
        return;
    mp_block_swarm_finish_abandon(mp);
    LOG_WARN("net",
             "block swarm integrity failure at piece %u after %u/%u "
             "complete (%u failed) — abandoning swarm immediately; "
             "legacy getdata resumes body fetch",
             piece_index, abandoned->complete, abandoned->total,
             abandoned->failed);
    event_emitf(EV_BLOCK_REQUESTED, node ? (uint32_t)node->id : 0,
                "block_swarm_integrity_abandon piece=%u complete=%u "
                "total=%u failed=%u",
                piece_index, abandoned->complete, abandoned->total,
                abandoned->failed);
}
