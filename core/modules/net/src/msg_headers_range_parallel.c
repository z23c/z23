/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_headers_range_parallel.c — range-parallel getheaders span scheduling
 * and the getheaders exec actions. Split out of msg_headers.c so that file
 * stays under its shrink-only file-size pin; the functions below moved
 * verbatim. */

#include "net/msg_internal.h"
#include "net/msg_bounds_guard.h"
#include "net/p2p_message.h"
#include "net/peer_scoring.h"
#include "net/fast_sync.h"
#include "sync/sync_planner.h"
#include "storage/disk_block_io.h"
#include "storage/node_db_runtime.h"
#include "validation/check_block.h"
#include "validation/process_block.h"
#include "net/download.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include "util/timedata.h"
#include "coins/coins_view.h"
#include "chain/equihash.h"
#include "chain/pow.h"
#include "chain/checkpoints.h"
#include "crypto/sha256.h"
#include "util/clientversion.h"
#include "base/serialize_le.h"
#include "core/arith_uint256.h"
#include "net/netaddr.h"
#include "net/header_corroboration.h"
#include "net/checkpoint_header_fetch.h"
#include "net/header_serve_repair.h"
#include "platform/time_compat.h"
#include "services/header_range_scheduler.h"  // lib-layer-ok:net3-range-parallel-header-planner
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

/* Resolve a span-boundary height to a locally-known block hash: a compiled
 * checkpoint hash (held WITHOUT the intervening headers — the crux that
 * lets disjoint peers fork across a cold gap), else a block we already
 * hold at or below our frontier. Returns false when the height is neither
 * a checkpoint nor in our index (never fabricates a hash we lack). */
static bool hrs_resolve_anchor_hash(struct msg_processor *mp, int32_t height,
                                    int our_height, struct uint256 *out)
{
    if (!mp || !out)
        return false;
    if (checkpoints_hash_at_height(&mp->params->checkpointData, height, out))
        return true;
    if (height <= our_height) {
        struct block_index *bi =
            active_chain_at(&mp->main_state->chain_active, height);
        if (bi && bi->phashBlock) {
            *out = *bi->phashBlock;
            return true;
        }
    }
    return false;
}

static bool hrs_peer_eligible(struct msg_processor *mp, struct p2p_node *node)
{
    if (!mp || !node || !mp->main_state || !mp->net_mgr || !mp->params)
        return false;
    /* The header-band backfill owns the getheaders anchor while a band
     * hole is open (exec_getheaders_action drives it). Range-parallel
     * feeds the band, never fights it: stand down entirely until the band
     * closes. */
    if (syncsvc_header_band_hole_open())
        return false;
    /* Only a fast-sync-capable outbound peer participates. Legacy peers
     * cap batches at 160 and never learn the NODE_ZCL23 span protocol —
     * they keep the existing single-peer path. */
    if (node->inbound || node->state < PEER_SYNCING_HEADERS ||
        !peer_supports_fast_sync(node->services))
        return false;
    return true;
}

static int hrs_count_fast_peers(struct msg_processor *mp)
{
    int fast_peers = 0;
    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
        struct p2p_node *n = mp->net_mgr->nodes[pi];
        if (n && !n->inbound && !n->disconnect &&
            n->state >= PEER_ACTIVE &&
            peer_supports_fast_sync(n->services))
            fast_peers++;
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
    return fast_peers;
}

static size_t hrs_collect_anchors(const struct checkpoint_data *cpd,
                                  int our_height, int target,
                                  int32_t *anchors)
{
    size_t n_anchors = 0;
    for (int i = 0; cpd && cpd->entries && i < cpd->nEntries &&
                    n_anchors < HRS_MAX_SPANS; i++) {
        int h = cpd->entries[i].height;
        if (h > our_height && h < target)
            anchors[n_anchors++] = (int32_t)h;
    }
    return n_anchors;
}

static void hrs_emit_reclaimed_spans(const int32_t *stalled_ids,
                                     size_t n_stalled)
{
    for (size_t si = 0; si < n_stalled; si++) {
        int32_t sid = stalled_ids[si];
        bool dup = false;
        for (size_t sj = 0; sj < si; sj++) {
            if (stalled_ids[sj] == sid) { dup = true; break; }
        }
        if (dup)
            continue;
        event_emitf(EV_HEADERS_REJECTED, (uint32_t)sid,
                    "header span reclaimed from slow peer %d "
                    "(deadline missed; span reassigned, not scored)",
                    (int)sid);
    }
}

bool msg_try_range_parallel_getheaders(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       int our_height, int64_t now_seconds)
{
    if (!hrs_peer_eligible(mp, node))
        return false;

    struct main_state *ms = mp->main_state;
    int target = node->starting_height;
    if (ms->pindex_best_header &&
        ms->pindex_best_header->nHeight > target)
        target = ms->pindex_best_header->nHeight;
    int32_t gap = (int32_t)(target - our_height);

    /* Count connected fast-sync-capable outbound peers. */
    int fast_peers = hrs_count_fast_peers(mp);

    if (!hrs_should_parallelize(fast_peers, gap, 2000))
        return false;

    /* Anchors = compiled checkpoints strictly inside (our_height, target).
     * These are the only hashes we hold without having synced the
     * intervening headers, so they are the disjoint fork points that let N
     * peers cover N different checkpoint intervals at once. */
    const struct checkpoint_data *cpd = &mp->params->checkpointData;
    int32_t anchors[HRS_MAX_SPANS];
    size_t n_anchors = hrs_collect_anchors(cpd, our_height, target, anchors);

    struct header_range_scheduler *sched = header_range_scheduler_global();
    hrs_plan(sched, (int32_t)our_height, target, anchors, n_anchors);

    int64_t now_us = now_seconds * 1000000;

    /* Advance completions from our current header frontier so already-synced
     * spans free their peer slots before we (re)assign. */
    if (ms->pindex_best_header)
        hrs_note_frontier(sched, ms->pindex_best_header->nHeight);

    /* Sweep every expired span back into the free pool so a stalling peer
     * never stalls the whole sync, and demote EVERY reported stalling
     * owner — not just this peer. hrs_sweep_expired() is GLOBAL: it frees
     * every expired span in the table regardless of who is calling. A
     * "demote self, then discard the sweep's stalled-owner buffer"
     * pattern silently drops other peers' timeouts whenever some OTHER
     * peer's periodic tick happens to run the sweep first — by the time
     * the actually-stalled peer gets its own turn, hrs_peer_owns_expired_
     * span() is already false (its span was freed by someone else's
     * sweep) and it is never demoted. Reading the whole stalled-owner
     * buffer here means whichever peer's tick performs the sweep
     * correctly demotes every owner it evicted, including itself. */
    int32_t stalled_ids[HRS_MAX_SPANS];
    size_t n_stalled = hrs_sweep_expired(sched, now_us, stalled_ids, HRS_MAX_SPANS);
    /* The sweep above is the entire remedy, and it has already happened:
     * every expired span is back in the free pool and will be handed to
     * whichever peer asks next. That is a resource action — it bounds how
     * long one span can be held — and it deprioritises a slow peer
     * naturally, by giving its work to someone else.
     *
     * This used to ALSO charge PEER_OFFENCE_TIMEOUT to every swept owner.
     * That was a punishment for being slow, not for misbehaving. The
     * deadline is 30 seconds of wall clock for a span of up to ~2000
     * headers, which is an assumption about the peer's disk and link, not
     * a protocol rule: an honest node on a 7200rpm disk moving under
     * 2 MB/s misses it routinely, and so does a fast peer whose reply we
     * were too busy to read. Scoring it made ban-score a measure of
     * hardware, which pushes the network toward whoever has the fastest
     * storage — the opposite of what a full node should require.
     *
     * The signal is kept, not discarded: the stall is still reported, so
     * an operator can still see which peers are slow and we can still
     * learn where the code assumes fast storage. It just no longer counts
     * toward a ban. */
    hrs_emit_reclaimed_spans(stalled_ids, n_stalled);

    /* This peer's span: keep an existing live one, else claim a free span. */
    int32_t lo, hi;
    if (!hrs_peer_span(sched, node->id, now_us, &lo, &hi)) {
        int idx = hrs_assign(sched, node->id, now_us);
        if (idx < 0)
            return false;   /* no free span — fall back to single-peer path */
        if (!hrs_peer_span(sched, node->id, now_us, &lo, &hi))
            return false;
    }

    struct uint256 start_hash, stop_hash;
    if (!hrs_resolve_anchor_hash(mp, lo, our_height, &start_hash))
        return false;       /* cannot anchor — fall back */
    bool have_stop = hrs_resolve_anchor_hash(mp, hi, our_height, &stop_hash);

    push_getheaders_span(mp, node, &start_hash, have_stop ? &stop_hash : NULL);
    LOG_INFO("headers",
             "range-parallel: peer=%d span=[%d,%d] fast_peers=%d gap=%d",
             node->id, lo, hi, fast_peers, gap);
    return true;
}

static void exec_getheaders_tip_parent(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       struct block_index *tip)
{
    /* Prefer best_header whenever it leads the active tip — INCLUDING a
     * NULL tip (full-index boot before the active_chain window/authority
     * is seated). The old `tip &&` guard discarded best_header on a NULL
     * tip and fell to a genesis-only locator. */
    if (mp->main_state->pindex_best_header &&
        mp->main_state->pindex_best_header->phashBlock &&
        (!tip ||
         mp->main_state->pindex_best_header->nHeight > tip->nHeight)) {
        push_getheaders_from(mp, node, mp->main_state->pindex_best_header);
    } else if (tip && tip->pprev) {
        push_getheaders_from(mp, node, tip->pprev);
    } else {
        push_getheaders(mp, node);
    }
}

static void exec_getheaders_best_header(struct msg_processor *mp,
                                        struct p2p_node *node,
                                        struct block_index *tip)
{
    /* When the validated header chain already extends above the
     * active tip, anchor the request at best_header — re-anchoring
     * at the tip makes the peer re-send known headers (160 per
     * round trip through the whole known span). The periodic IBD
     * re-kick fires every 10s, so a tip anchor here permanently
     * resets the conversation below the known frontier. The
     * locator includes lower heights, so a stale best_header still
     * converges on the true fork point. */
    if (msg_processor_block_index_heights_repaired(mp) &&
        mp->main_state->pindex_best_header &&
        mp->main_state->pindex_best_header->phashBlock &&
        (!tip ||
         mp->main_state->pindex_best_header->nHeight > tip->nHeight)) {
        push_getheaders_from(mp, node, mp->main_state->pindex_best_header);
    } else {
        push_getheaders(mp, node);
    }
}

void exec_getheaders_action(struct msg_processor *mp,
                            struct p2p_node *node,
                            const struct sync_getheaders_action *action)
{
    struct block_index *tip;

    if (!mp || !node || !action || !action->should_send)
        return;

    tip = active_chain_tip(&mp->main_state->chain_active);

    /* While a header band hole is recorded, every periodic kick drives
     * the band: anchor at the contiguous frontier so the peer forks
     * there and serves the band. Tip-side progress continues via batch
     * continuations and unsolicited header/inv pushes. O(1) when no
     * band fact exists. */
    {
        struct block_index *band_anchor =
            syncsvc_header_band_backfill_anchor(&mp->main_state->chain_active);
        if (band_anchor) {
            push_getheaders_from(mp, node, band_anchor);
            return;
        }
    }

    switch (action->anchor) {
    case SYNC_HEADER_REQUEST_TIP_PARENT:
        exec_getheaders_tip_parent(mp, node, tip);
        break;
    case SYNC_HEADER_REQUEST_TIP:
    case SYNC_HEADER_REQUEST_EXPLICIT:
    default:
        exec_getheaders_best_header(mp, node, tip);
        break;
    }
}
