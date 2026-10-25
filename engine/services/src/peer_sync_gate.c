/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Pure peer eligibility policy for beginning and closing header sync.
 */

// one-result-type-ok:peer-sync-gate-predicates — exported bools are pure eligibility answers, not fallible operations
#include "sync/sync_planner.h"
#include "services/configured_sync_peers.h"
#include "net/net.h"
#include "util/log_macros.h"
#include <stdatomic.h>

/* ONION_EDGE_SYNC_GATE_startingheight
 *
 * A late outbound onion edge can complete VERSION/VERACK while advertising
 * start_height=0.  The ordinary substantially-behind gate then suppresses
 * every getheaders request, so the edge can remain ACTIVE without ever being
 * tested as a header source.  Permit exactly one probe for a native ZCL23
 * onion peer.  last_getheaders_time closes the exception as soon as that
 * request is recorded; all later rounds use the ordinary height/backoff
 * policy.  This is transport discovery only, never a validity shortcut. */
static bool zero_height_onion_probe_pending(const struct p2p_node *node)
{
    return node && !node->inbound && node->starting_height == 0 &&
           net_addr_is_tor(&node->addr.svc.addr) &&
           peer_supports_fast_sync(node->services) &&
           atomic_load_explicit(&node->last_getheaders_time,
                                memory_order_relaxed) == 0;
}

bool syncsvc_peer_is_behind(const struct p2p_node *node, int our_height)
{
    if (!node || zero_height_onion_probe_pending(node) ||
        node->starting_height < 0)
        return false;

    /* starting_height is handshake-static.  Keep peers inside the normal
     * reorg tolerance eligible, but gate a peer proven substantially behind.
     * The zero-height onion exception above lasts only until its first
     * request records last_getheaders_time. */
    return node->starting_height + SYNC_PEER_BEHIND_TOLERANCE < our_height;
}

/* Global sync states that are already inside an active header/block sync
 * phase; a peer that passed the earlier gates may begin syncing in them. */
static bool sync_state_is_actively_syncing(enum sync_state sync_state)
{
    return sync_state == SYNC_HEADERS_DOWNLOAD ||
           sync_state == SYNC_BLOCKS_DOWNLOAD ||
           sync_state == SYNC_CONNECTING_BLOCKS ||
           sync_state == SYNC_REORG ||
           sync_state == SYNC_REORG_RECOVERY;
}

/* Last gate for a peer that matched no earlier rule: sync may still begin
 * from a pre-sync state when either side has no height to compare yet. */
static bool idle_state_permits_peer_sync(const struct p2p_node *node,
                                         int our_height,
                                         enum sync_state sync_state)
{
    return (sync_state == SYNC_IDLE || sync_state == SYNC_FINDING_PEERS) &&
           (our_height <= 0 || node->starting_height < 0);
}

bool syncsvc_should_begin_peer_sync(const struct p2p_node *node,
                                    int our_height,
                                    int best_header_height,
                                    enum sync_state sync_state)
{
    if (!node)
        LOG_FAIL("header_sync", "begin_peer_sync: null node");
    /* Inbound peers stay refused (anti-eclipse) unless the peer comes from
     * an operator-named target: services/configured_sync_peers.h holds the
     * rule and why it grants no more trust than the outbound dial. */
    if (node->state != PEER_ACTIVE || !syncsvc_peer_may_serve_headers(node))
        return false;
    if (zero_height_onion_probe_pending(node))
        return true;
    if (node->starting_height > our_height ||
        sync_state == SYNC_FINDING_PEERS)
        return true;
    if (best_header_height > our_height + 1)
        return true;
    if (node->starting_height >= 0 || sync_state == SYNC_AT_TIP)
        return false;
    if (sync_state_is_actively_syncing(sync_state))
        return true;
    return idle_state_permits_peer_sync(node, our_height, sync_state);
}

bool syncsvc_should_mark_peer_caught_up(const struct p2p_node *node,
                                        int our_height,
                                        int best_header_height)
{
    if (!node || (node->state != PEER_SYNCING_HEADERS &&
                  node->state != PEER_SYNCING_BLOCKS))
        return false;
    if (zero_height_onion_probe_pending(node))
        return false;
    return best_header_height <= our_height + 1 &&
           node->starting_height <= our_height;
}

bool syncsvc_begin_peer_sync(struct p2p_node *node,
                             int our_height,
                             int best_header_height)
{
    configured_sync_peer_observe_session(node);
    if (!syncsvc_should_begin_peer_sync(node, our_height, best_header_height,
                                       sync_get_state()))
        return false;
    if (node->inbound)
        LOG_INFO("header_sync",
                 "configured-inbound header sync: peer=%s id=%d proved over "
                 "its own Noise session the identity this node authenticated "
                 "at an operator-named -addnode/-connect target; header sync "
                 "begins from it, so a \"0 outbound peers ... cannot sync\" "
                 "warning does not apply while this path serves headers",
                 node->addr_name, (int)node->id);
    peer_set_state_checked((uint32_t)node->id, &node->state,
                           PEER_SYNCING_HEADERS, "IBD start");
    if (sync_get_state() == SYNC_IDLE ||
        sync_get_state() == SYNC_FINDING_PEERS)
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "first outbound peer");
    return true;
}
