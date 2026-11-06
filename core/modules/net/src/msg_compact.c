/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_compact.c — BIP152 compact block message processing.
 * Split from msgprocessor.c for maintainability. */

#include "platform/time_compat.h"
#include "net/msg_internal.h"
#include "net/download.h"
#include "net/compact_blocks.h"
#include "net/peer_scoring.h"
#include "sync/sync_planner.h"
#include "storage/disk_block_io.h"
#include "validation/process_block.h"
#include "consensus/validation.h"
#include "chain/pow.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"  // lib-layer-ok:provable-tip-for-history-floor-compact-fallback
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── Helper: discard any pending compact block state for a peer ── */

static void compact_pending_clear(struct p2p_node *node)
{
    if (node->compact_pending_block) {
        block_free(node->compact_pending_block);
        free(node->compact_pending_block);
        node->compact_pending_block = NULL;
    }
    free(node->compact_missing_indices);
    node->compact_missing_indices = NULL;
    node->compact_num_missing = 0;
    node->compact_request_time = 0;
    memset(&node->compact_pending_hash, 0, sizeof(node->compact_pending_hash));
}

/* ── Helper: ask this peer for the full block ──────────────────── */

/* The header of a cmpctblock has only passed a cheap check against a target the
 * peer chose, so an unknown one earns no download slot. Ask this peer for headers
 * under the per-peer limit the reject probe uses: a real block then comes through
 * the normal header and body path, and a repeating peer drives no more requests.
 * With the limit closed, or headers paused for a snapshot, the probe is left armed
 * for the send tick, which retries under the same limit. */
static void compact_probe_unknown_header(struct msg_processor *mp,
                                         struct p2p_node *node)
{
    int64_t now_s = (int64_t)platform_time_wall_time_t();
    int64_t last_probe = atomic_load_explicit(&node->last_reject_probe_time,
                                              memory_order_relaxed);
    if (msg_processor_snapshot_active(mp) ||
        !syncsvc_should_probe_after_reject(now_s, last_probe)) {
        atomic_store_explicit(&node->reject_probe_pending, true,
                              memory_order_relaxed);
        return;
    }
    push_getheaders_from(mp, node, mp->main_state->pindex_best_header);
    atomic_store_explicit(&node->last_reject_probe_time, now_s,
                          memory_order_relaxed);
}

/* The request goes through the download manager, so the reply is not an
 * unrequested push and a stalled peer's slot is reassigned. A request already
 * in flight stands. A peer at its window, or a full table, leaves the hash queued
 * for any peer. A block at or below our tip asks for nothing: a collision on a
 * new block is above it, and a request here would count as forward work, ahead
 * of what the frontier needs and outside the history budget. */
static void compact_request_full_block(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       const struct uint256 *hash)
{
    if (!mp->main_state)
        return;
    struct block_index *bi =
        block_map_find(&mp->main_state->map_block_index, hash);
    if (!bi) {
        compact_probe_unknown_header(mp, node);
        return;
    }
    /* The provable frontier (H*) runs ahead of the chain on a seeded node, and
     * what lies at or below it is history: the same floor the block manifest
     * seed uses. */
    int32_t history = active_chain_height(&mp->main_state->chain_active);
    int32_t hstar = reducer_frontier_provable_tip_cached();
    if (hstar > history)
        history = hstar;
    if ((bi->nStatus & (BLOCK_HAVE_DATA | BLOCK_FAILED_MASK)) ||
        (int32_t)bi->nHeight <= history)
        return;

    struct download_manager *dm = get_download_mgr();
    int32_t height = (int32_t)bi->nHeight;
    uint32_t peer_id = (uint32_t)node->id;
    if (dl_peer_in_flight(dm, peer_id) >= dl_peer_adaptive_window(dm, peer_id) ||
        !dl_mark_requested(dm, hash, height, peer_id)) {
        dl_queue_priority(dm, hash, height);
        return;
    }

    struct inv_item inv;
    inv_item_init_typed(&inv, MSG_BLOCK, hash);
    struct byte_stream gd;
    stream_init(&gd, 64);
    if (stream_write_compact_size(&gd, 1) && inv_item_serialize(&inv, &gd)) {
        p2p_node_begin_message(node, "getdata", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, gd.data, gd.size);
        p2p_node_end_message(node);
    }
    stream_free(&gd);
}

/* Short ids can resolve to the wrong transactions, so a reconstruction that
 * does not match its header says nothing about the block or about the peer
 * (BIP152). It is dropped unsubmitted and unscored; true when that is what
 * happened. Recovery depends on the header, see compact_request_full_block: a full
 * block request, a header request, or nothing. The caller runs this before it
 * settles the download slot, since the received-pending hold that leaves behind
 * would refuse the request. */
static bool compact_body_needs_full_block(struct msg_processor *mp,
                                          struct p2p_node *node,
                                          const struct block *blk,
                                          const struct uint256 *hash)
{
    if (block_already_seen(hash) || msg_block_body_matches_header(blk))
        return false;
    char hex[65];
    uint256_get_hex(hash, hex);
    LOG_INFO("compact",
             "peer %s: compact block %s does not match its header; dropped",
             node->addr_name, hex);
    compact_request_full_block(mp, node, hash);
    return true;
}

/* ── Helper: feed a completed block into normal validation ─────── */

static void compact_submit_block(struct msg_processor *mp,
                                 struct p2p_node *node,
                                 struct block *blk)
{
    struct uint256 hash;
    block_header_get_hash(&blk->header, &hash);

    if (compact_body_needs_full_block(mp, node, blk, &hash))
        return;

    /* Clear any download-manager in-flight slot created when this block was
     * first announced via inv at tip (msg_tx.c at-tip getdata path), so a
     * compact-reconstructed block does not leave a slot to time out into a
     * spurious re-fetch. No-op (returns UINT32_MAX) when no slot exists. */
    (void)dl_mark_received(get_download_mgr(), &hash);

    if (block_already_seen(&hash)) {
        char hex[65];
        uint256_get_hex(&hash, hex);
        LOG_INFO("compact", "peer %s: compact block %s already seen, skipping",
                 node->addr_name, hex);
        return;
    }

    struct validation_state state;
    validation_state_init(&state);
    if (!mp || !mp->compact_block_submit) {
        validation_state_error(&state, "compact-submit-unavailable");
    } else {
        bool accepted = mp->compact_block_submit(blk, &state,
                                                 mp->compact_block_submit_ctx);
        if (!accepted && validation_state_is_valid(&state))
            validation_state_error(&state, "compact-submit-failed");
    }

    if (!validation_state_is_valid(&state) &&
        msg_block_validation_is_retryable(&state)) {
        char hex[65];
        uint256_get_hex(&hash, hex);
        LOG_INFO("compact",
                 "peer %s: compact block %s not finalized (%s); leaving retryable",
                 node->addr_name, hex, state.reject_reason);
        msg_block_note_retryable(mp, &hash, &state);
    } else if (!validation_state_is_valid(&state)) {
        char hex[65];
        uint256_get_hex(&hash, hex);
        LOG_WARN("compact", "peer %s: compact block %s rejected: %s",
                 node->addr_name, hex,
                 state.reject_reason[0] ? state.reject_reason : "unknown");
        event_emitf(EV_BLOCK_REJECTED, (uint32_t)node->id,
                    "compact hash=%s reason=%s", hex,
                    state.reject_reason[0] ? state.reject_reason : "unknown");
        block_mark_seen(&hash);
    } else {
        if (mp && mp->main_state) {
            struct block_index *landed =
                block_map_find(&mp->main_state->map_block_index, &hash);
            if (msg_blocks_should_mark_seen(&mp->main_state->chain_active,
                                             landed))
                block_mark_seen(&hash);
        }
        peer_scoring_on_good_interaction(node, peer_scoring_now_ms());
        node->last_block_time = (int64_t)platform_time_wall_time_t();
        node->blocks_received++;
    }
}

bool process_sendcmpct(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s)
{
    /* sendcmpct: [1 byte: announce] [8 bytes: version]
     * announce=1 means peer wants high-bandwidth mode (send compact blocks
     * unsolicited). version=1 is the only version we support. */
    uint8_t announce;
    uint64_t version;
    if (!stream_read_u8(s, &announce) || !stream_read_u64_le(s, &version)) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD, "malformed sendcmpct");
        LOG_FAIL("compact", "malformed sendcmpct from peer %s", node->addr_name);
    }

    if (version == COMPACT_BLOCK_VERSION) {
        node->send_compact = (announce != 0);
        LOG_INFO("compact", "peer %s: sendcmpct announce=%u version=%lu",
                 node->addr_name, announce, (unsigned long)version);
    }
    return true;
}

/* A getblocktxn reply is only taken within this long of the request. */
#define COMPACT_PENDING_MAX_AGE_SECS 30

/* A repeat of the cmpctblock this peer is already pending on, still inside the
 * reply window, has nothing to add: its getblocktxn is out and the stashed
 * partial block stands. Past the window the reply would be refused, so a
 * repeat then rebuilds and asks again. */
static bool compact_repeats_pending(const struct p2p_node *node,
                                    const struct uint256 *hash)
{
    if (!node->compact_pending_block ||
        memcmp(hash, &node->compact_pending_hash, sizeof(*hash)) != 0)
        return false;
    int64_t age = (int64_t)platform_time_wall_time_t() - node->compact_request_time;
    return age <= COMPACT_PENDING_MAX_AGE_SECS;
}

/* True when the block is stored, has not failed and is already on the active
 * chain, so a reconstruction of it could not be used. HAVE_DATA alone is not
 * enough: the reducer sets it when the body is persisted, before the block is
 * finalized (reducer_persist_ingested_body_locked), and a stored block that is
 * not yet connected is retried by its next arrival, which re-enters
 * reducer_ingest_block (the HAVE_DATA early return in the persist step, then
 * the drain). Such a block must still reach compact_submit_block. */
static bool compact_block_held(const struct msg_processor *mp,
                               const struct uint256 *hash)
{
    if (!mp->main_state)
        return false;
    const struct block_index *bi =
        block_map_find(&mp->main_state->map_block_index, hash);
    return bi && (bi->nStatus & BLOCK_HAVE_DATA) &&
           !(bi->nStatus & BLOCK_FAILED_MASK) &&
           active_chain_contains(&mp->main_state->chain_active, bi);
}

/* ── Helper: copy the mempool txs for reconstruction (one pass, one lock) ── */

static struct transaction *compact_load_mempool_txs(struct msg_processor *mp,
                                                    size_t *out_num_txs)
{
    struct transaction *mp_txs = NULL;
    *out_num_txs = 0;
    if (tx_mempool_size(mp->mempool) == 0)
        return NULL;
    if (!tx_mempool_snapshot_txs(mp->mempool, &mp_txs, out_num_txs))
        return NULL;
    return mp_txs;
}

/* ── Helper: free the mempool tx copies made for reconstruction ── */

static void compact_free_mempool_txs(struct transaction *mp_txs, size_t num_mp_txs)
{
    if (mp_txs) {
        for (size_t i = 0; i < num_mp_txs; i++)
            transaction_free(&mp_txs[i]);
        free(mp_txs);
    }
}

/* ── Helper: move a partial block into per-peer pending state ──── */

static bool compact_stash_partial_block(struct msg_processor *mp,
                                        struct p2p_node *node,
                                        const struct uint256 *block_hash,
                                        const struct block *out_block,
                                        uint64_t *missing_indices,
                                        size_t num_missing)
{
    node->compact_pending_block = zcl_malloc(sizeof(struct block),
                                              "compact_pending_block");
    if (!node->compact_pending_block)
        return false;

    *node->compact_pending_block = *out_block; /* move ownership */
    node->compact_pending_hash = *block_hash;
    node->compact_missing_indices = missing_indices;
    node->compact_num_missing = num_missing;
    node->compact_request_time = (int64_t)platform_time_wall_time_t();

    /* Send getblocktxn for the missing transactions. Only a
     * stashed peer can complete the reply, so the request is
     * built here, inside the stash-success branch; pre-fix it
     * ran unconditionally and read NULL indices when the
     * stash allocation above failed. */
    struct block_txn_request req;
    block_txn_request_init(&req);
    req.block_hash = *block_hash;
    req.indices = node->compact_missing_indices;
    req.num_indices = num_missing;

    struct byte_stream rs;
    stream_init(&rs, 256);
    if (block_txn_request_serialize(&req, &rs)) {
        p2p_node_begin_message(node, "getblocktxn",
                               mp->params->pchMessageStart);
        p2p_node_write_message_data(node, rs.data, rs.size);
        p2p_node_end_message(node);
    }
    stream_free(&rs);
    /* Don't free req — indices are owned by
     * node->compact_missing_indices */
    return true;
}

bool process_cmpctblock(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s)
{
    struct compact_block_msg cb;
    if (!compact_block_msg_deserialize(&cb, s)) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD, "invalid cmpctblock");
        LOG_FAIL("compact", "failed to deserialize cmpctblock from %s", node->addr_name);
    }

    struct uint256 block_hash;
    block_header_get_hash(&cb.header, &block_hash);

    char hex[65];
    uint256_get_hex(&block_hash, hex);
    LOG_INFO("compact", "peer %s: cmpctblock %s (%zu short txids, %zu prefilled)",
             node->addr_name, hex, cb.num_short_txids, cb.num_prefilled);

    /* Gate the expensive mempool collection + reconstruction below behind a
     * cheap dedup and a proof-of-work check on the announced header. An
     * unsolicited cmpctblock carries only a header + short txids; without this
     * gate a peer could spray cheap cmpctblocks to force repeated full-mempool
     * scans (CPU amplification). Mirrors Bitcoin Core's check of a cmpctblock
     * header's PoW before attempting reconstruction. */
    if (block_already_seen(&block_hash)) {
        compact_block_msg_free(&cb);
        return true;
    }
    if (!mp || !mp->params ||
        !CheckProofOfWork(block_hash, cb.header.nBits, &mp->params->consensus)) {
        if (mp)
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                                "cmpctblock failed pow gate");
        compact_block_msg_free(&cb);
        LOG_FAIL("compact", "cmpctblock from %s failed pow gate", node->addr_name);
    }

    /* A repeat of what is already pending and a block already stored add
     * nothing to rebuild; like the seen-block repeat above, neither is scored. */
    if (compact_repeats_pending(node, &block_hash)) {
        compact_block_msg_free(&cb);
        return true;
    }

    /* Discard any prior pending compact block for this peer */
    compact_pending_clear(node);

    if (compact_block_held(mp, &block_hash)) {
        compact_block_msg_free(&cb);
        return true;
    }

    /* Copy the mempool transactions for reconstruction in one pass */
    size_t num_mp_txs = 0;
    struct transaction *mp_txs = compact_load_mempool_txs(mp, &num_mp_txs);

    /* Attempt reconstruction. out_block is initialized here as well as in
     * compact_block_reconstruct(): the block_free() calls below run on
     * every reconstruction outcome, so this frame must never carry an
     * uninitialized struct block past a peer-controlled call. */
    struct block out_block;
    block_init(&out_block);
    uint64_t *missing_indices = NULL;
    size_t num_missing = 0;

    bool complete = compact_block_reconstruct(&cb, mp_txs, num_mp_txs,
                                              NULL, 0, &out_block,
                                              &missing_indices, &num_missing);

    if (complete) {
        LOG_INFO("compact", "peer %s: compact block fully reconstructed from mempool",
                 node->addr_name);
        compact_submit_block(mp, node, &out_block);
        block_free(&out_block);
    } else if (num_missing > 0) {
        LOG_INFO("compact", "peer %s: compact block missing %zu txs, sending getblocktxn",
                 node->addr_name, num_missing);

        /* Stash the partial block in per-peer state for blocktxn completion */
        if (compact_stash_partial_block(mp, node, &block_hash, &out_block,
                                        missing_indices, num_missing)) {
            missing_indices = NULL; /* ownership transferred */
        } else {
            /* Stash allocation failed: there is no pending state a
             * blocktxn reply could complete, so no request is sent.
             * Free the partial block; the function-tail free of
             * missing_indices below handles the index list (pre-fix the
             * tail was unreachable here because the unconditional
             * request build dereferenced the NULL indices first). */
            block_free(&out_block);
        }
    } else {
        block_free(&out_block);
    }

    free(missing_indices);

    /* Clean up mempool tx copies */
    compact_free_mempool_txs(mp_txs, num_mp_txs);

    compact_block_msg_free(&cb);
    return true;
}

bool process_getblocktxn(struct msg_processor *mp, struct p2p_node *node,
                         struct byte_stream *s)
{
    struct block_txn_request req;
    if (!block_txn_request_deserialize(&req, s)) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD, "invalid getblocktxn");
        LOG_FAIL("compact", "failed to deserialize getblocktxn from %s", node->addr_name);
    }

    char hex[65];
    uint256_get_hex(&req.block_hash, hex);
    LOG_INFO("compact", "peer %s: getblocktxn %s (%zu indices)",
             node->addr_name, hex, req.num_indices);

    /* Read the full block from disk */
    struct block_index *pindex = block_map_find(&mp->main_state->map_block_index,
                                                &req.block_hash);
    if (!pindex) {
        block_txn_request_free(&req);
        LOG_FAIL("compact", "getblocktxn for unknown block %s from %s",
                 hex, node->addr_name);
    }

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_index(&blk, pindex, mp->datadir)) {
        block_txn_request_free(&req);
        LOG_FAIL("compact", "failed to read block %s from disk", hex);
    }

    /* Build response with requested transactions */
    struct block_txn_response resp;
    block_txn_response_init(&resp);
    resp.block_hash = req.block_hash;
    resp.num_txs = req.num_indices;
    resp.txs = zcl_calloc(req.num_indices, sizeof(struct transaction), "compact_blocktxn_resp");
    if (!resp.txs) {
        block_free(&blk);
        block_txn_request_free(&req);
        LOG_FAIL("compact", "alloc failed for blocktxn response");
    }

    for (size_t i = 0; i < req.num_indices; i++) {
        transaction_init(&resp.txs[i]);
        if (req.indices[i] >= blk.num_vtx) {
            block_txn_response_free(&resp);
            block_free(&blk);
            block_txn_request_free(&req);
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_PROTOCOL_VIOLATION,
                                "getblocktxn index out of range");
            LOG_FAIL("compact", "index %lu >= %zu in getblocktxn from %s",
                     (unsigned long)req.indices[i], blk.num_vtx, node->addr_name);
        }
        if (!transaction_copy(&resp.txs[i], &blk.vtx[req.indices[i]])) {
            block_txn_response_free(&resp);
            block_free(&blk);
            block_txn_request_free(&req);
            LOG_FAIL("compact", "failed to copy tx %zu for blocktxn", i);
        }
    }

    /* Send blocktxn response */
    struct byte_stream rs;
    stream_init(&rs, 1024 * 1024);
    if (block_txn_response_serialize(&resp, &rs)) {
        p2p_node_begin_message(node, "blocktxn", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, rs.data, rs.size);
        p2p_node_end_message(node);
    }
    stream_free(&rs);

    block_txn_response_free(&resp);
    block_free(&blk);
    block_txn_request_free(&req);
    return true;
}

bool process_blocktxn(struct msg_processor *mp, struct p2p_node *node,
                      struct byte_stream *s)
{
    struct block_txn_response resp;
    if (!block_txn_response_deserialize(&resp, s)) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD, "invalid blocktxn");
        LOG_FAIL("compact", "failed to deserialize blocktxn from %s", node->addr_name);
    }

    char hex[65];
    uint256_get_hex(&resp.block_hash, hex);
    LOG_INFO("compact", "peer %s: blocktxn %s (%zu txs)",
             node->addr_name, hex, resp.num_txs);

    /* Match against pending compact block reconstruction */
    if (!node->compact_pending_block ||
        memcmp(&resp.block_hash, &node->compact_pending_hash,
               sizeof(struct uint256)) != 0) {
        LOG_WARN("compact", "peer %s: blocktxn %s — no matching pending compact block",
                 node->addr_name, hex);
        block_txn_response_free(&resp);
        return true;
    }

    /* Timeout check: reject stale responses (>30 seconds) */
    int64_t age = (int64_t)platform_time_wall_time_t() - node->compact_request_time;
    if (age > COMPACT_PENDING_MAX_AGE_SECS) {
        LOG_WARN("compact", "peer %s: blocktxn %s — stale response (%lld sec), discarding",
                 node->addr_name, hex, (long long)age);
        compact_pending_clear(node);
        block_txn_response_free(&resp);
        return true;
    }

    /* Fill in missing transactions */
    if (!compact_block_fill_missing(node->compact_pending_block, &resp,
                                    node->compact_missing_indices,
                                    node->compact_num_missing)) {
        LOG_WARN("compact", "peer %s: blocktxn %s — fill_missing failed",
                 node->addr_name, hex);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE, "bad blocktxn response");
        compact_pending_clear(node);
        block_txn_response_free(&resp);
        return true;
    }

    LOG_INFO("compact", "peer %s: compact block %s fully assembled from blocktxn",
             node->addr_name, hex);

    /* Submit the completed block for validation */
    compact_submit_block(mp, node, node->compact_pending_block);

    /* Clean up — block_free is called inside compact_pending_clear */
    compact_pending_clear(node);
    block_txn_response_free(&resp);
    return true;
}
