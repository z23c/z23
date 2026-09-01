/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Inventory / peer-discovery message family:
 *   inv, getdata, notfound — block/tx availability advertising,
 *   addr, getaddr           — peer address gossip.
 *
 * The actual block/tx accept logic lives in msg_blocks.c and
 * msg_tx.c; the address-manager lives in addrman.c. These handlers
 * are thin adapters / forwarders for the dispatch table. */

#include "msgprocessor_internal.h"
#include "net/msg_bounds_guard.h"
#include "net/addrman.h"
#include "net/download.h"
#include "net/peer_scoring.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "storage/topology_store.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

bool mp_handle_inv(struct msg_processor *mp, struct p2p_node *node,
                   struct byte_stream *s)
{
    return process_inv(mp, node, s);
}

bool mp_handle_getdata(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s)
{
    return process_getdata(mp, node, s);
}

static bool process_notfound(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s)
{
    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("net", "failed to read notfound count from %s",
                 node->addr_name);

    /* notfound answers a getdata, so bound it by the same cap as inv/getdata
     * (the 2 MB frame cap already limits this, but cap at the call site so the
     * discipline is auditable and uniform across inv-bearing handlers). */
    if (msg_count_exceeds("net", "notfound", count, MAX_INV_SZ,
                          node->addr_name)) {
        /* Score like every other oversized-count flood (inv/getdata/addr/
         * headers) — see msg_tx.c::process_inv for why disconnect alone
         * lets a hostile peer repeat this forever across reconnects. */
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                            "notfound count exceeds MAX_INV_SZ");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_RESOURCE_LIMIT,
            P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
            node->endpoint_generation);
        return false;
    }

    struct download_manager *dm = get_download_mgr();
    for (uint64_t i = 0; i < count; i++) {
        struct inv_item inv;
        if (!inv_item_deserialize(&inv, s))
            LOG_FAIL("net", "failed to deserialize notfound inv[%llu] from %s",
                     (unsigned long long)i, node->addr_name);
        if (inv.type == MSG_BLOCK) {
            char hex[65];
            uint256_get_hex(&inv.hash, hex);
            printf("Peer %s: notfound block %s\n", node->addr_name, hex);
            /* Re-queue JUST this block so another peer can try. This used to
             * call dl_peer_disconnected(), which is a whole-peer action: it
             * orphaned and re-queued every in-flight request to this peer and
             * marked it inactive, once per missing block. See
             * net/download.h::dl_mark_notfound for the measured cost (50% of
             * all C3 stopwatch block requests settled as orphaned, ~483 per
             * notfound message) and why a single-peer client had nothing to
             * gain from it. */
            dl_mark_notfound(dm, (uint32_t)node->id, &inv.hash);
        }
    }
    return true;
}

bool mp_handle_notfound(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s)
{
    return process_notfound(mp, node, s);
}

/* A single addr message admits at most MAX_ADDR_TO_SEND (1000) entries, but
 * nothing previously stopped a peer from
 * repeating max-legal-size batches back-to-back forever for free — cheap
 * CPU/addrman-churn amplification with zero score cost. Fixed 60s window,
 * cap generous enough for legitimate bursts (an unsolicited self-announce
 * plus a getaddr response, each up to MAX_ADDR_TO_SEND) while still
 * catching sustained repetition. */
#define ADDR_RATE_WINDOW_SECS 60
#define ADDR_RATE_MAX_PER_WINDOW (MAX_ADDR_TO_SEND * 3)
#define ADDR_RATE_LEGACY_ZCL23_MAX_PER_WINDOW \
    (ADDRMAN_GETADDR_MAX + MAX_ADDR_TO_SEND * 2)

static bool process_addr(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s)
{
    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("net", "failed to read addr count from %s",
                 node->addr_name);

    /* Builds predating the eager-exchange cap fix advertised as many as
     * ADDRMAN_GETADDR_MAX addresses to another ZCL23 peer.  A staggered
     * rollout must not disconnect the still-stable node merely because it
     * runs those known old bytes.  Keep the compatibility envelope bounded,
     * count every wire entry against the rate limit, deserialize the whole
     * message, and admit only the ordinary MAX_ADDR_TO_SEND prefix.  Peers
     * without the authenticated handshake capability retain the strict cap. */
    uint64_t wire_cap = peer_supports_fast_sync(node->services)
                            ? ADDRMAN_GETADDR_MAX
                            : MAX_ADDR_TO_SEND;
    if (msg_count_exceeds("net", "addr", count, wire_cap,
                          node->addr_name)) {
        /* Score like every other oversized-count flood (inv/getdata/
         * notfound/headers) — see msg_tx.c::process_inv for why
         * disconnect alone lets a hostile peer repeat this forever
         * across reconnects. */
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                            "addr count exceeds negotiated wire cap");
        printf("Peer %s: addr message too large (%llu)\n",
               node->addr_name, (unsigned long long)count);
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_RESOURCE_LIMIT,
            P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
            node->endpoint_generation);
        return false;
    }

    uint64_t admit_count = count;
    if (admit_count > MAX_ADDR_TO_SEND) {
        admit_count = MAX_ADDR_TO_SEND;
        printf("Peer %s: legacy ZCL23 addr batch %llu; admitting bounded prefix %u\n",
               node->addr_name, (unsigned long long)count,
               (unsigned int)MAX_ADDR_TO_SEND);
    }

    /* Per-peer addr rate limit: a fixed window over TOTAL addresses
     * received (not message count), so one giant batch and many small
     * batches are both bounded the same way. */
    {
        int64_t now = GetTime();
        uint32_t rate_cap = peer_supports_fast_sync(node->services)
                                ? ADDR_RATE_LEGACY_ZCL23_MAX_PER_WINDOW
                                : ADDR_RATE_MAX_PER_WINDOW;
        if (node->addr_rate_window_start == 0 ||
            now - node->addr_rate_window_start >= ADDR_RATE_WINDOW_SECS) {
            node->addr_rate_window_start = now;
            node->addr_rate_window_count = 0;
        }
        node->addr_rate_window_count += (uint32_t)count;
        if (node->addr_rate_window_count > rate_cap) {
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                                "addr rate limit exceeded");
            printf("Peer %s: addr rate limit exceeded (%u in %ds)\n",
                   node->addr_name, node->addr_rate_window_count,
                   ADDR_RATE_WINDOW_SECS);
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_RESOURCE_LIMIT,
                P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
                node->endpoint_generation);
            return false;
        }
    }

    struct net_addr source;
    net_addr_init(&source);
    memcpy(source.ip, node->addr.svc.addr.ip, 16);

    /* Topology graph edge: node (the observer — our already-connected,
     * already-handshaked peer) told us about each address below. now stamped
     * once per message (not per address) — plenty precise for a
     * first-seen/last-seen graph edge. topology_store_record_edge()
     * independently PEDANTIC-validates (net_addr_is_routable) and renders
     * BOTH endpoints before storage; a not-open store or a rejected address
     * is a silent no-op here (observational only, never gates addrman). */
    int64_t topo_now = GetTime();

    for (uint64_t i = 0; i < count; i++) {
        struct net_address addr;
        net_address_init(&addr);
        if (!net_address_deserialize(&addr, s, true))
            LOG_FAIL("net", "failed to deserialize addr[%llu] from %s",
                     (unsigned long long)i, node->addr_name);

        if (i < admit_count && mp->net_mgr)
            addrman_add(&mp->net_mgr->addrman, &addr, &source, 0);
        if (i < admit_count)
            (void)topology_store_record_edge(&node->addr.svc.addr,
                                             node->addr.svc.port,
                                             &addr.svc.addr, addr.svc.port,
                                             topo_now, NULL);
    }
    return true;
}

bool mp_handle_addr(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s)
{
    return process_addr(mp, node, s);
}

static bool process_getaddr(struct msg_processor *mp, struct p2p_node *node)
{
    if (node->sent_addr)
        return true;
    node->sent_addr = true;

    if (!mp->net_mgr)
        return true;

    struct net_address addrs[MAX_ADDR_TO_SEND];
    size_t num = addrman_get_addr(&mp->net_mgr->addrman, addrs,
                                   MAX_ADDR_TO_SEND);

    if (num > 0) {
        struct byte_stream addr_msg;
        stream_init(&addr_msg, num * 30 + 8);
        if (!stream_write_compact_size(&addr_msg, (uint64_t)num)) {
            /* allocation failed (addr_msg.data NULL); skip sending the
             * addr message rather than emit a malformed one. */
            stream_free(&addr_msg);
            return true;
        }
        for (size_t i = 0; i < num; i++) {
            if (!net_address_serialize(&addrs[i], &addr_msg, true)) {
                stream_free(&addr_msg);
                return true;
            }
        }

        p2p_node_begin_message(node, "addr", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, addr_msg.data, addr_msg.size);
        p2p_node_end_message(node);
        stream_free(&addr_msg);
    }
    return true;
}

bool mp_handle_getaddr(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s)
{
    (void)s;
    return process_getaddr(mp, node);
}
