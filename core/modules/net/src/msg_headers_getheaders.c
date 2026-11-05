/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_headers_getheaders.c — outbound getheaders requests: push_getheaders_from,
 * push_getheaders, push_getheaders_span and their locator helpers, plus the
 * single-header announcement and the bounded header append it shares with the
 * getheaders reply. Split out of msg_headers.c as a behaviour-preserving move;
 * the file-scope state these functions share with msg_headers.c is declared in
 * msg_headers_internal.h. */

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
#include <sys/stat.h>
#include <stdatomic.h>
#include <pthread.h>
#include "msg_headers_internal.h"

/* Streak latches used only by the getheaders request builders below. They
 * moved with those functions; the counters they pair with stay in
 * msg_headers.c and are shared through msg_headers_internal.h. */
static _Atomic bool g_no_hash_streak = false;
static _Atomic bool g_snapshot_streak = false;
static _Atomic bool g_push_getheaders_snapshot_streak = false;
static _Atomic bool g_push_getheaders_span_snapshot_streak = false;

static struct block_index *push_getheaders_reanchor_target(struct msg_processor *mp)
{
    struct block_index *reanchor = NULL;
    if (mp && mp->main_state) {
        if (mp->main_state->pindex_best_header &&
            mp->main_state->pindex_best_header->phashBlock) {
            reanchor = mp->main_state->pindex_best_header;
        } else {
            struct block_index *tip =
                active_chain_tip(&mp->main_state->chain_active);
            if (tip && tip->phashBlock)
                reanchor = tip;
        }
    }
    return reanchor;
}

static bool push_getheaders_exp_locator(struct msg_processor *mp,
                                        struct block_index *from,
                                        struct block_locator *loc)
{
    /* Exponential locator: tip, tip-1, tip-2, tip-4, tip-8, ... genesis.
     * Walk pprev chain with exponentially increasing steps. */
    int max_hashes = 32;
    struct uint256 *tmp = zcl_malloc((size_t)max_hashes * sizeof(struct uint256),
                                     "exp_locator");
    if (!tmp) return false;
    int nh = 0;
    struct block_index *walk = from;
    int step = 1;
    while (walk && nh < max_hashes - 1) {
        if (walk->phashBlock)
            tmp[nh++] = *walk->phashBlock;
        /* Walk back 'step' blocks via pprev */
        struct block_index *prev_walk = walk;
        for (int s = 0; s < step && walk->pprev; s++)
            walk = walk->pprev;
        /* Stop when the walk made no progress (pprev exhausted — an
         * island root, not just the first hop): the old `walk == from`
         * test only caught the first iteration, so a detached-island
         * anchor degenerated the locator to [island hashes ×31,
         * genesis]. */
        if (walk == prev_walk) break;
        if (nh >= 10)
            step *= 2;  /* exponential after first 10 entries */
    }
    /* Always end with genesis */
    if (nh > 0 && nh < max_hashes)
        tmp[nh++] = mp->params->consensus.hashGenesisBlock;
    loc->vhave = tmp;
    loc->num_hashes = (size_t)nh;
    return true;
}

static bool push_getheaders_build_locator(struct msg_processor *mp,
                                          struct block_index *from,
                                          struct block_locator *loc)
{
    if (from && from->phashBlock &&
        msg_processor_block_index_heights_repaired(mp))
        return push_getheaders_exp_locator(mp, from, loc);

    struct zcl_result _r = syncsvc_build_getheaders_locator(loc,
                                          &mp->main_state->chain_active,
                                          (from && from->phashBlock) ? from : NULL,
                                          mp->main_state->pindex_best_header,
                                          &mp->params->consensus.hashGenesisBlock);
    if (!_r.ok) {
        fprintf(stderr, "[headers] %s:%d push_getheaders_from: build_locator failed: %s\n",
                _r.source_file, _r.source_line, _r.message);
        return false;
    }
    return true;
}

void push_getheaders_from(struct msg_processor *mp,
                          struct p2p_node *node,
                          struct block_index *from)
{
    /* Robust continuation anchor. A caller may hand us a block_index whose
     * stable per-node hash slot was never populated (phashBlock == NULL).
     * Dropping the request here is a SILENT header-sync stop — forbidden by
     * construction. Re-anchor at the best-header tree tip, then the active-
     * chain tip (both always carry a hash), so the conversation continues
     * from the highest hashed frontier we hold. Give up only when nothing
     * anywhere has a hash, and then LOUDLY with a counter. */
    if (from && !from->phashBlock) {
        struct block_index *reanchor = push_getheaders_reanchor_target(mp);
        uint64_t n = atomic_fetch_add(&g_getheaders_suppressed_no_hash, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_no_hash_streak))
            LOG_WARN("headers",
                     "push_getheaders_from: anchor h=%d has no block hash — "
                     "re-anchoring at %s (suppressed_no_hash=%llu)",
                     from->nHeight,
                     reanchor ? "best-header/chain tip"
                              : "NONE (request skipped)",
                     (unsigned long long)n);
        from = reanchor;
        if (!from)
            return;  /* no hashed frontier anywhere — cannot build a locator */
    } else {
        atomic_store(&g_no_hash_streak, false);
    }

    /* Snapshot sync owns the wire while a peer snapshot exchange is live;
     * requesting headers then just competes with chunk transfer. This is a
     * real, intentional pause — but never a silent one: count it and name
     * it so a snapshot exchange that latches active (and thus wedges header
     * sync after one in-flight batch) announces itself instead of stalling
     * quietly. */
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n = atomic_fetch_add(&g_getheaders_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_snapshot_streak))
            LOG_WARN("headers",
                     "push_getheaders_from: header request SUPPRESSED by "
                     "active snapshot sync (anchor h=%d suppressed_snapshot="
                     "%llu) — header sync is paused until the snapshot "
                     "exchange completes or resets",
                     from ? from->nHeight : -1, (unsigned long long)n);
        return;
    }
    atomic_store(&g_snapshot_streak, false);

    /* Build locator for getheaders request.
     * After bulk height repair, heights are trustworthy — use a proper
     * Bitcoin-style exponential locator for better branch identification.
     * Before repair, fall back to the safe 2-hash locator. */
    struct block_locator loc;
    block_locator_init(&loc);
    if (!push_getheaders_build_locator(mp, from, &loc))
        return;

    struct byte_stream s;
    stream_init(&s, 512);
    if (!getheaders_serialize(&s, &loc, NULL)) {
        stream_free(&s);
        block_locator_free(&loc);
        return;
    }

    /* Debug: log locator hashes to diagnose sync stall */
    if (loc.num_hashes > 0 && loc.num_hashes <= 20) {
        for (size_t li = 0; li < loc.num_hashes && li < 3; li++) {
            char lhex[65];
            uint256_get_hex(&loc.vhave[li], lhex);
            LOG_INFO("headers", "getheaders locator[%zu]: %s", li, lhex);
        }
    }

    p2p_node_begin_message(node, "getheaders", mp->params->pchMessageStart);
    p2p_node_write_message_data(node, s.data, s.size);
    p2p_node_end_message(node);
    stream_free(&s);
    block_locator_free(&loc);
}

void push_getheaders(struct msg_processor *mp, struct p2p_node *node)
{
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n =
            atomic_fetch_add(&g_push_getheaders_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_push_getheaders_snapshot_streak))
            LOG_WARN("headers",
                     "push_getheaders: request to %s SUPPRESSED by active "
                     "snapshot sync (suppressed=%llu)",
                     node->addr_name, (unsigned long long)n);
        return;
    }
    atomic_store(&g_push_getheaders_snapshot_streak, false);

    /* Use the active-chain locator, including recent ancestors. A locator
     * containing only tip+genesis makes a one-block local fork invisible to
     * peers: they do not know our tip and fall back to genesis, sending old
     * headers instead of the sibling that reorgs us back to the best chain. */
    {
        struct block_locator loc;
        block_locator_init(&loc);
        if (syncsvc_build_getheaders_locator(
                &loc, &mp->main_state->chain_active, NULL,
                mp->main_state->pindex_best_header,
                &mp->params->consensus.hashGenesisBlock).ok) {
            struct byte_stream s;
            stream_init(&s, 512);
            if (getheaders_serialize(&s, &loc, NULL)) {
                p2p_node_begin_message(node, "getheaders",
                                       mp->params->pchMessageStart);
                p2p_node_write_message_data(node, s.data, s.size);
                p2p_node_end_message(node);
            }
            stream_free(&s);
            block_locator_free(&loc);
            return;
        }
        /* Fall through to snapsync anchor locator path. Builder
         * already logged via ZCL_ERR source/line; no need to dup. */
    }

    /* After snapshot sync, use the snapshot anchor as the locator start. */
    struct block_index *anchor = msg_processor_snapshot_anchor(mp);
    if (anchor && anchor->phashBlock)
        push_getheaders_from(mp, node, anchor);
    else
        push_getheaders_from(mp, node, NULL);
}

void push_getheaders_span(struct msg_processor *mp, struct p2p_node *node,
                          const struct uint256 *start_hash,
                          const struct uint256 *stop_hash)
{
    if (!mp || !node || !start_hash)
        return;
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n = atomic_fetch_add(
            &g_push_getheaders_span_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(
                &g_push_getheaders_span_snapshot_streak))
            LOG_WARN("headers",
                     "push_getheaders_span: span request to %s SUPPRESSED "
                     "by active snapshot sync (suppressed=%llu)",
                     node->addr_name, (unsigned long long)n);
        return;
    }
    atomic_store(&g_push_getheaders_span_snapshot_streak, false);

    /* Minimal locator: [start_hash, genesis]. start_hash is a compiled
     * checkpoint (or our own frontier) so any honest full peer holds it
     * and forks there; genesis is the universal fallback. hash_stop
     * bounds the peer to this peer's span. */
    struct block_locator loc;
    block_locator_init(&loc);
    loc.vhave = zcl_malloc(2 * sizeof(struct uint256), "hrs_span_locator");
    if (!loc.vhave) {
        atomic_fetch_add(&g_push_getheaders_span_alloc_fail, 1);
        LOG_ERROR("headers",
                  "push_getheaders_span: locator alloc failed for %s — "
                  "span header request dropped",
                  node->addr_name);
        return;
    }
    loc.vhave[0] = *start_hash;
    loc.vhave[1] = mp->params->consensus.hashGenesisBlock;
    loc.num_hashes = 2;

    struct byte_stream s;
    stream_init(&s, 512);
    if (getheaders_serialize(&s, &loc, stop_hash)) {
        p2p_node_begin_message(node, "getheaders", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, s.data, s.size);
        p2p_node_end_message(node);
    }
    stream_free(&s);
    block_locator_free(&loc);
}

/* See net/msg_internal.h. */
bool getheaders_try_append_header(struct byte_stream *body,
                                  const struct block_header *hdr)
{
    size_t before = body->size;
    block_header_serialize(hdr, body);
    stream_write_compact_size(body, 0);  /* per-header tx count = 0 */
    /* Reserve headroom for the compact_size(count) prefix the caller writes
     * ahead of `body` (≤3 bytes for count ≤ 2000; 16 is generous). */
    if (body->error ||
        body->size + 16 > (size_t)MAX_PROTOCOL_MESSAGE_LENGTH) {
        body->size = before;
        return false;
    }
    return true;
}

/* See net/msg_internal.h. The servability gate is deliberately the same one
 * used by getheaders: a tip vote is useful only when the exact bytes this node
 * accepted are available and independently hash/PoW verified. */
bool push_verified_header_announcement(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       struct block_index *index)
{
    if (!mp || !mp->params || !node || !index)
        LOG_FAIL("headers", "tip announcement: invalid arguments");

    struct block_header hdr;
    block_header_init(&hdr);
    if (!getheaders_index_header_servable(mp, index, &hdr)) {
        LOG_WARN("headers",
                 "tip announcement: refusing unservable header h=%d peer=%s",
                 index->nHeight, node->addr_name);
        return false;
    }

    struct byte_stream body;
    stream_init(&body, 2048);
    stream_write_compact_size(&body, 1);
    if (!getheaders_try_append_header(&body, &hdr)) {
        stream_free(&body);
        LOG_FAIL("headers",
                 "tip announcement: serialization failed h=%d peer=%s",
                 index->nHeight, node->addr_name);
    }

    if (!p2p_node_begin_message(node, "headers",
                                mp->params->pchMessageStart)) {
        stream_free(&body);
        LOG_FAIL("headers",
                 "tip announcement: begin message failed h=%d peer=%s",
                 index->nHeight, node->addr_name);
    }
    p2p_node_write_message_data(node, body.data, body.size);
    bool sent = p2p_node_end_message(node);
    stream_free(&body);
    if (!sent)
        LOG_FAIL("headers", "tip announcement: send failed h=%d peer=%s",
                 index->nHeight, node->addr_name);
    return true;
}
