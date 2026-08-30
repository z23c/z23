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
#include "storage/disk_block_io.h"
#include "validation/process_block.h"
#include "consensus/validation.h"
#include "chain/pow.h"
#include "event/event.h"
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

/* ── Helper: feed a completed block into normal validation ─────── */

static void compact_submit_block(struct msg_processor *mp,
                                 struct p2p_node *node,
                                 struct block *blk)
{
    struct uint256 hash;
    block_header_get_hash(&blk->header, &hash);

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
                 "peer %s: compact block %s pending reducer finalization; leaving retryable",
                 node->addr_name, hex);
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

    /* Discard any prior pending compact block for this peer */
    compact_pending_clear(node);

    /* Collect mempool transactions for reconstruction */
    struct uint256 *mp_hashes = NULL;
    size_t num_mp = 0;
    size_t max_mp = tx_mempool_size(mp->mempool);
    if (max_mp > 0) {
        mp_hashes = zcl_malloc(max_mp * sizeof(struct uint256), "compact_mp_hashes");
        if (mp_hashes) {
            tx_mempool_query_hashes(mp->mempool, mp_hashes, max_mp, &num_mp);
        }
    }

    /* Look up each mempool hash to get the full transaction */
    struct transaction *mp_txs = NULL;
    size_t num_mp_txs = 0;
    if (num_mp > 0) {
        mp_txs = zcl_calloc(num_mp, sizeof(struct transaction), "compact_mp_txs");
        if (mp_txs) {
            for (size_t i = 0; i < num_mp; i++) {
                transaction_init(&mp_txs[num_mp_txs]);
                if (tx_mempool_lookup(mp->mempool, &mp_hashes[i], &mp_txs[num_mp_txs])) {
                    transaction_compute_hash(&mp_txs[num_mp_txs]);
                    num_mp_txs++;
                }
            }
        }
    }
    free(mp_hashes);

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
        node->compact_pending_block = zcl_malloc(sizeof(struct block),
                                                  "compact_pending_block");
        if (node->compact_pending_block) {
            *node->compact_pending_block = out_block; /* move ownership */
            node->compact_pending_hash = block_hash;
            node->compact_missing_indices = missing_indices;
            node->compact_num_missing = num_missing;
            node->compact_request_time = (int64_t)platform_time_wall_time_t();
            missing_indices = NULL; /* ownership transferred */
        } else {
            /* Alloc failed — fall back to just freeing */
            block_free(&out_block);
        }

        /* Send getblocktxn for missing transactions */
        struct block_txn_request req;
        block_txn_request_init(&req);
        req.block_hash = block_hash;
        req.indices = node->compact_missing_indices;
        req.num_indices = num_missing;

        struct byte_stream rs;
        stream_init(&rs, 256);
        if (block_txn_request_serialize(&req, &rs)) {
            p2p_node_begin_message(node, "getblocktxn", mp->params->pchMessageStart);
            p2p_node_write_message_data(node, rs.data, rs.size);
            p2p_node_end_message(node);
        }
        stream_free(&rs);
        /* Don't free req — indices are owned by node->compact_missing_indices */
    } else {
        block_free(&out_block);
    }

    free(missing_indices);

    /* Clean up mempool tx copies */
    if (mp_txs) {
        for (size_t i = 0; i < num_mp_txs; i++)
            transaction_free(&mp_txs[i]);
        free(mp_txs);
    }

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
    if (age > 30) {
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
