/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Pure peer eligibility policy for beginning and closing header sync.
 */

// one-result-type-ok:peer-sync-gate-predicates — exported bools are pure eligibility answers, not fallible operations
#include "sync/sync_planner.h"
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

bool syncsvc_should_begin_peer_sync(const struct p2p_node *node,
                                    int our_height,
                                    int best_header_height,
                                    enum sync_state sync_state)
{
    if (!node)
        LOG_FAIL("header_sync", "begin_peer_sync: null node");
    if (node->inbound || node->state != PEER_ACTIVE)
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
    if (sync_state == SYNC_HEADERS_DOWNLOAD ||
        sync_state == SYNC_BLOCKS_DOWNLOAD ||
        sync_state == SYNC_CONNECTING_BLOCKS ||
        sync_state == SYNC_REORG ||
        sync_state == SYNC_REORG_RECOVERY)
        return true;
    return (sync_state == SYNC_IDLE || sync_state == SYNC_FINDING_PEERS) &&
           (our_height <= 0 || node->starting_height < 0);
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
    if (!syncsvc_should_begin_peer_sync(node, our_height, best_header_height,
                                       sync_get_state()))
        return false;
    peer_set_state_checked((uint32_t)node->id, &node->state,
                           PEER_SYNCING_HEADERS, "IBD start");
    if (sync_get_state() == SYNC_IDLE ||
        sync_get_state() == SYNC_FINDING_PEERS)
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "first outbound peer");
    return true;
}
