/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_tx.c — Transaction relay message processing.
 * Split from msgprocessor.c for maintainability. */

#include "platform/time_compat.h"
#include "net/msg_internal.h"
#include "net/msg_bounds_guard.h"
#include "net/peer_scoring.h"
#include "net/dandelion.h"
#include "net/download.h"
#include "sync/sync_state.h"
#include "validation/check_transaction.h"
#include "validation/accept_to_mempool.h"
#include "consensus/validation.h"
#include "consensus/upgrades.h"
#include "event/event.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/sync.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── Dandelion++ tx propagation ────────────────────────────────── */
struct dandelion_state g_dandelion;
bool g_dandelion_init = false;

/* ── incoming `tx` classification + scoring ──────────────
 *
 * Before, this handler silently upserted every deserialised tx,
 * ran no fee policy, and — critically — ran NO cryptographic
 * verification: a tx with a valid shape and existing prevouts but a
 * forged signature or shielded proof was admitted and fluffed
 * network-wide before block-connect rejected it.
 *
 * The acceptance gate (structural + shielded-proof + per-input
 * scriptSig verification + fee/conflict policy) now lives in the ONE
 * shared accept_to_mempool() helper (core/modules/validation), used by BOTH this
 * P2P path and the RPC sendrawtransaction path so they can never drift.
 * This wrapper only translates the shared result onto the net layer's
 * tx_accept_result, which the handler maps to peer ban-scoring. */
static enum tx_accept_result msg_tx_classify(struct msg_processor *mp,
                                              struct transaction *tx)
{
    if (!mp || !tx || !mp->mempool)
        return TX_ACCEPT_INTERNAL_ERROR;

    enum mempool_accept_result r =
        accept_to_mempool(mp->mempool, mp->coins_tip, mp->main_state,
                          mp->params, tx);

    switch (r) {
    case MEMPOOL_ACCEPT_OK:             return TX_ACCEPT_OK;
    case MEMPOOL_ACCEPT_INVALID:        return TX_ACCEPT_INVALID;
    case MEMPOOL_ACCEPT_DUPLICATE:      return TX_ACCEPT_DUPLICATE;
    case MEMPOOL_ACCEPT_CONFLICT:       return TX_ACCEPT_CONFLICT;
    case MEMPOOL_ACCEPT_BELOW_FEE:      return TX_ACCEPT_BELOW_FEE;
    case MEMPOOL_ACCEPT_MISSING_INPUTS: return TX_ACCEPT_MISSING_INPUTS;
    case MEMPOOL_ACCEPT_NONFINAL:       return TX_ACCEPT_NONFINAL;
    case MEMPOOL_ACCEPT_EXPIRING_SOON:  return TX_ACCEPT_EXPIRING_SOON;
    case MEMPOOL_ACCEPT_INTERNAL_ERROR: return TX_ACCEPT_INTERNAL_ERROR;
    case MEMPOOL_ACCEPT_UNVERIFIABLE:   return TX_ACCEPT_UNVERIFIABLE;
    }
    return TX_ACCEPT_INTERNAL_ERROR;
}

/* Volume bound for the one outcome that carries no ban-score.
 * Returns true when this peer has sent more unverifiable transactions in
 * the current window than the cap, i.e. when the complaint has stopped
 * being about our missing keys and started being about their send rate. */
static bool msg_tx_unverifiable_rate_exceeded(struct p2p_node *node)
{
    int64_t now = (int64_t)platform_time_wall_time_t();

    if (node->unverifiable_tx_window_start == 0 ||
        now - node->unverifiable_tx_window_start >=
            TX_UNVERIFIABLE_WINDOW_SECS) {
        node->unverifiable_tx_window_start = now;
        node->unverifiable_tx_window_count = 0;
    }
    node->unverifiable_tx_window_count++;
    return node->unverifiable_tx_window_count > TX_UNVERIFIABLE_WINDOW_MAX;
}

enum tx_accept_result msg_tx_accept(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    struct transaction *tx)
{
    enum tx_accept_result ar = msg_tx_classify(mp, tx);

    /* Peer scoring: only clearly-malicious outcomes get ban-score.
     * Missing inputs (orphan), duplicates, and below-relay-fee are
     * either our problem or a rate-limit, not misbehaviour.
     *
     * TX_ACCEPT_UNVERIFIABLE is the third category the comment above
     * always implied but the code could not express: the transaction may
     * be perfectly valid, we simply hold no verifying key to judge it.
     * Charging that to the sender punishes an honest peer for OUR boot
     * state, so it is unscored — up to the per-peer volume cap below,
     * past which the send RATE is the peer's own doing. */
    if (mp && node && mp->net_mgr) {
        switch (ar) {
        case TX_ACCEPT_INVALID:
            peer_scoring_record(mp->net_mgr, node,
                                PEER_OFFENCE_INVALID_MESSAGE,
                                "invalid tx");
            break;
        case TX_ACCEPT_CONFLICT:
            peer_scoring_record(mp->net_mgr, node,
                                PEER_OFFENCE_INVALID_MESSAGE,
                                "double-spend");
            break;
        case TX_ACCEPT_UNVERIFIABLE:
            if (msg_tx_unverifiable_rate_exceeded(node))
                peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                                    "unverifiable tx rate");
            break;
        case TX_ACCEPT_OK:
        case TX_ACCEPT_DUPLICATE:
        case TX_ACCEPT_BELOW_FEE:
        case TX_ACCEPT_MISSING_INPUTS:
        case TX_ACCEPT_NONFINAL:
        case TX_ACCEPT_EXPIRING_SOON:
        case TX_ACCEPT_INTERNAL_ERROR:
            break;
        }
    }

    return ar;
}

bool process_inv(struct msg_processor *mp, struct p2p_node *node,
                 struct byte_stream *s)
{
    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("net", "failed to read inv count from %s",
                 node->addr_name);

    if (msg_count_exceeds("net", "inv", count, MAX_INV_SZ, node->addr_name)) {
        event_emitf(EV_PEER_MISBEHAVE, (uint32_t)node->id,
                    "inv too large (%llu) from %s",
                    (unsigned long long)count, node->addr_name);
        /* PEER_OFFENCE_FLOOD's own doc comment names "inv" as covered —
         * score it like headers does for the same oversized-count
         * violation, so this specific abuse still accrues toward the
         * ban threshold across reconnects instead of only disconnecting. */
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                            "inv count exceeds MAX_INV_SZ");
        printf("Peer %s: inv message too large (%llu)\n",
               node->addr_name, (unsigned long long)count);
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_RESOURCE_LIMIT,
            P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
            node->endpoint_generation);
        return false;
    }

    struct byte_stream getdata;
    stream_init(&getdata, 256);
    uint64_t request_count = 0;

    for (uint64_t i = 0; i < count; i++) {
        struct inv_item inv;
        if (!inv_item_deserialize(&inv, s)) {
            stream_free(&getdata);
            LOG_FAIL("net", "failed to deserialize inv[%llu] from %s",
                     (unsigned long long)i, node->addr_name);
        }

        p2p_node_add_inventory_known(node, &inv);

        if (inv.type == MSG_BLOCK) {
            if (block_already_seen(&inv.hash))
                continue;
            /* Don't request blocks during snapshot sync */
            if (msg_processor_snapshot_active(mp))
                continue;
            struct block_index *bi = block_map_find(
                &mp->main_state->map_block_index, &inv.hash);
            struct block_index *tip = active_chain_tip(
                &mp->main_state->chain_active);
            /* Match ZClassic C++ IsInitialBlockDownload + inv handling:
             * Request blocks directly when our tip is recent (within
             * PoWTargetSpacing*20 = 75*20 = 1500s of now). During IBD,
             * rely on headers-first sync instead.
             *
             * Old logic used node->starting_height - 1000 which kept
             * the node in headers-only mode too long after catchup. */
            bool in_ibd = !tip || !tip->nTime ||
                          ((int64_t)tip->nTime <
                           (int64_t)platform_time_wall_time_t() - 75 * 20);
            bool need_data = !bi || !(bi->nStatus & BLOCK_HAVE_DATA);
            if (need_data && !in_ibd) {
                /* ZClassic C++: send getheaders FIRST, then getdata.
                 * Headers arrive before (or with) the block, preventing
                 * orphan rejection if the block's parent is unknown. */
                push_getheaders_from(mp, node, tip);
                /* Register the request with the download manager so a dropped
                 * or stalled serving peer is caught by dl_check_timeouts (run
                 * every cycle for ALL peers in msg_send_messages) and reassigned
                 * to another peer. Without this the at-tip path was untracked: a
                 * peer drop mid-body stalled new-block ingest until the 600s
                 * tip-stale watchdog. dl_mark_requested returns false when the
                 * hash is already in-flight, de-duping concurrent announces. */
                struct download_manager *dm = get_download_mgr();
                int32_t req_height = bi ? (int32_t)bi->nHeight : -1;
                if (dl_mark_requested(dm, &inv.hash, req_height,
                                      (uint32_t)node->id)) {
                    inv_item_serialize(&inv, &getdata);
                    request_count++;
                }
            } else if (need_data && in_ibd) {
                /* Ask for headers instead */
                push_getheaders_from(mp, node, tip);
            }
            if (tip && bi && active_chain_contains(
                    &mp->main_state->chain_active, bi)) {
                node->hash_continue = inv.hash;
            }
        } else if (inv.type == MSG_TX) {
            /* Dandelion: seeing a tx via inv means it's been fluffed.
             * Remove from stempool so we don't re-fluff on embargo. */
            if (g_dandelion_init)
                dandelion_stempool_remove(&g_dandelion, &inv.hash);

            if (tx_already_seen(&inv.hash))
                continue;
            if (!tx_mempool_exists(mp->mempool, &inv.hash)) {
                inv_item_serialize(&inv, &getdata);
                request_count++;
            }
        }
    }

    if (request_count > 0) {
        struct byte_stream msg;
        stream_init(&msg, getdata.size + 8);
        stream_write_compact_size(&msg, request_count);
        stream_write(&msg, getdata.data, getdata.size);

        p2p_node_begin_message(node, "getdata", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, msg.data, msg.size);
        p2p_node_end_message(node);
        stream_free(&msg);
    }
    stream_free(&getdata);
    return true;
}

bool process_tx_msg(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s)
{
    struct transaction tx;
    transaction_init(&tx);
    if (!transaction_deserialize(&tx, s)) {
        event_emitf(EV_MSG_DESERIALIZATION_FAIL, (uint32_t)node->id, "tx");
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE,
                            "malformed tx");
        transaction_free(&tx);
        LOG_FAIL("net", "failed to deserialize tx from %s",
                 node->addr_name);
    }

    struct uint256 hash;
    transaction_compute_hash(&tx);
    hash = tx.hash;

    if (tx_already_seen(&hash)) {
        transaction_free(&tx);
        return true;
    }
    tx_mark_seen(&hash);

    enum tx_accept_result ar = msg_tx_accept(mp, node, &tx);

    /* We reached no verdict on this transaction, so we have not really
     * "seen" it. Drop the dedupe mark: once the verifying keys are
     * installed, the next ordinary re-announcement gets a real answer
     * instead of being silently swallowed. Bounded work — the mark only
     * costs a re-run of the cheap structural checks, and the shielded
     * availability gate short-circuits ahead of any proof arithmetic —
     * and the per-peer rate cap in msg_tx_accept bounds the volume. */
    if (ar == TX_ACCEPT_UNVERIFIABLE)
        tx_clear_seen(&hash);

    if (ar == TX_ACCEPT_OK) {
        node->last_tx_time = (int64_t)platform_time_wall_time_t();
        event_emit(EV_TX_ACCEPTED, (uint32_t)node->id,
                   hash.data, 32);
        struct inv_item inv;
        inv_item_init_typed(&inv, MSG_TX, &hash);
        p2p_node_add_inventory_known(node, &inv);

        /* Dandelion++ tx relay: stem (1 peer) or fluff (all peers) */
        if (mp->net_mgr) {
            bool stemmed = false;

            if (g_dandelion_init) {
                dandelion_maybe_rotate_epoch(&g_dandelion, mp->net_mgr);

                if (dandelion_should_stem(&g_dandelion, node->id)) {
                    node_id_t stem_id = dandelion_get_stem_peer(
                        &g_dandelion, node->id);
                    if (stem_id != DANDELION_NODE_ID_NONE) {
                        /* Send full tx to stem peer (not inv) */
                        zcl_mutex_lock(&mp->net_mgr->cs_nodes);
                        for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                            struct p2p_node *sp = mp->net_mgr->nodes[pi];
                            if (sp->id == stem_id &&
                                sp->state >= PEER_HANDSHAKE_COMPLETE &&
                                !sp->disconnect) {
                                struct byte_stream bs;
                                stream_init(&bs, 512);
                                if (transaction_serialize(&tx, &bs)) {
                                    p2p_node_begin_message(
                                        sp, "tx",
                                        mp->params->pchMessageStart);
                                    p2p_node_write_message_data(
                                        sp, bs.data, bs.size);
                                    p2p_node_end_message(sp);
                                    p2p_node_add_inventory_known(sp, &inv);
                                    stemmed = true;
                                    g_dandelion.stat_stem_sent++;
                                }
                                stream_free(&bs);
                                break;
                            }
                        }
                        zcl_mutex_unlock(&mp->net_mgr->cs_nodes);

                        if (stemmed) {
                            dandelion_stempool_add(&g_dandelion, &hash,
                                                   node->id);
                        }
                    }
                }
            }

            /* Fluff: broadcast inv to all peers (normal relay) */
            if (!stemmed) {
                if (g_dandelion_init)
                    g_dandelion.stat_fluffed++;
                zcl_mutex_lock(&mp->net_mgr->cs_nodes);
                for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                    struct p2p_node *peer = mp->net_mgr->nodes[pi];
                    if (peer->id != node->id &&
                        peer->state >= PEER_HANDSHAKE_COMPLETE &&
                        !peer->disconnect && peer->relay_txes)
                        p2p_node_push_inventory(peer, &inv);
                }
                zcl_mutex_unlock(&mp->net_mgr->cs_nodes);

                /* If this tx was in the stem pool, remove it (it's now fluffed) */
                if (g_dandelion_init)
                    dandelion_stempool_remove(&g_dandelion, &hash);
            }
        }

        if (mp->wallet_tx_accepted)
            mp->wallet_tx_accepted(&tx, mp->wallet_tx_accepted_ctx);
    } else {
        event_emit(EV_TX_REJECTED, (uint32_t)node->id,
                   hash.data, 32);
    }

    transaction_free(&tx);
    return true;
}

/* test hook: when non-NULL, process_mempool calls this instead
 * of zcl_malloc for the scratch buffer. Returning NULL simulates OOM.
 * File-scope so the hook can only influence this one call site. */
static void *(*g_process_mempool_alloc_hook)(size_t) = NULL;

void msgprocessor_test_set_mempool_alloc_hook(void *(*hook)(size_t))
{
    g_process_mempool_alloc_hook = hook;
}

bool process_mempool(struct msg_processor *mp, struct p2p_node *node)
{
    size_t bytes = (size_t)MAX_INV_SZ * sizeof(struct uint256);
    struct uint256 *hashes = g_process_mempool_alloc_hook
        ? g_process_mempool_alloc_hook(bytes)
        : zcl_malloc(bytes, "mempool_inv_hashes");
    if (!hashes)
        LOG_FAIL("net", "process_mempool: OOM (%zu bytes)", bytes);

    size_t num = 0;
    tx_mempool_query_hashes(mp->mempool, hashes, MAX_INV_SZ, &num);

    for (size_t i = 0; i < num; i++) {
        struct inv_item inv;
        inv_item_init_typed(&inv, MSG_TX, &hashes[i]);
        p2p_node_push_inventory(node, &inv);
    }
    free(hashes);
    return true;
}

/* ── mempool sync-on-connect ──────────────────────────────────────
 *
 * A fresh node never proactively pulls a peer's mempool — it only
 * serves others' "mempool" requests (process_mempool above) and waits
 * for passive inv/tx relay. That leaves a freshly (re)connected node's
 * mempool view cold until the first spontaneous inv arrives. Pull once,
 * right after handshake, from any peer that told us it will relay. */
static bool msg_tx_deep_in_ibd(void)
{
    enum sync_state st = sync_get_state();
    return st == SYNC_HEADERS_DOWNLOAD ||
           st == SYNC_BLOCKS_DOWNLOAD ||
           st == SYNC_CONNECTING_BLOCKS;
}

bool msg_tx_maybe_request_mempool(struct msg_processor *mp,
                                  struct p2p_node *node)
{
    if (!mp || !node || !mp->params)
        return false;
    if (node->mempool_requested)
        return false;
    if (!node->relay_txes)
        return false;
    /* Bulk historical sync: mempool inventory is irrelevant and would
     * only compete with header/block bandwidth. */
    if (msg_tx_deep_in_ibd())
        return false;

    /* Set the guard before queuing the send so this stays exactly-once
     * per peer even if the caller somehow re-enters (e.g. a peer that
     * resends verack). */
    node->mempool_requested = true;

    p2p_node_begin_message(node, "mempool", mp->params->pchMessageStart);
    p2p_node_end_message(node);
    return true;
}
