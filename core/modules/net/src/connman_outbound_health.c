/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * connman_outbound_health — the outbound-health snapshot accessor. Split out
 * of connman.c so that file stays under its shrink-only file-size pin; the
 * functions below moved verbatim. */

#define _GNU_SOURCE  /* pthread_timedjoin_np */

#define _DEFAULT_SOURCE
#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "platform/socket_compat.h"
#include "connman_internal.h"
#include "net/connman.h"
#include "net/peer_lifecycle.h"
#include "net/peer_scoring.h"
#include "net/netbase.h"
#include "net/version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

static void connman_outbound_health_count_addnodes(
    struct connman *cm, struct connman_outbound_health *out)
{
    for (int i = 0; i < cm->num_addnodes; i++) {
        out->addnode_tcp_failures += cm->addnode_tcp_failures[i];
        out->addnode_protocol_failures +=
            cm->addnode_protocol_failures[i];
        if (cm->addnode_backoff_sec[i] > 0) {
            out->addnode_backoff_active++;
            if (cm->addnode_backoff_sec[i] > out->addnode_backoff_max_sec)
                out->addnode_backoff_max_sec = cm->addnode_backoff_sec[i];
        }
        if (cm->addnode_retired[i])
            out->addnode_retired_count++;
    }
}

/* Counts one peer in the /16 group table. Returns the group's new size,
 * or 0 when the table is full and the group is not already tracked. */
static size_t connman_outbound_health_group_bump(uint16_t *groups,
                                                 size_t *group_counts,
                                                 size_t *num_groups,
                                                 uint16_t group)
{
    size_t gi = 0;
    for (; gi < *num_groups; gi++) {
        if (groups[gi] == group)
            break;
    }
    if (gi == *num_groups &&
        *num_groups < DEFAULT_MAX_PEER_CONNECTIONS) {
        groups[*num_groups] = group;
        group_counts[*num_groups] = 0;
        (*num_groups)++;
    }
    if (gi >= *num_groups)
        return 0;
    group_counts[gi]++;
    return group_counts[gi];
}

/* Counts one peer into the inbound or outbound totals. Returns true for
 * an inbound peer, which the caller skips for the outbound group tables. */
static bool connman_outbound_health_count_node(
    struct connman_outbound_health *out, const struct p2p_node *n,
    bool handshaked, bool block_serving)
{
    if (n->inbound) {
        out->inbound_total++;
        if (block_serving)
            out->inbound_healthy++;
        else if (!handshaked)
            out->inbound_handshake_incomplete++;
        return true;
    }

    out->outbound_total++;
    if (n->state == PEER_CONNECTING)
        out->connecting++;
    if (!handshaked)
        out->handshake_incomplete++;
    else if (block_serving)
        out->healthy++;
    return false;
}

void connman_get_outbound_health(struct connman *cm,
                                 struct connman_outbound_health *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!cm) return;

    out->addnode_count = cm->num_addnodes > 0 ? (size_t)cm->num_addnodes : 0;
    connman_outbound_health_count_addnodes(cm, out);

    uint16_t groups[DEFAULT_MAX_PEER_CONNECTIONS];
    size_t group_counts[DEFAULT_MAX_PEER_CONNECTIONS];
    size_t num_groups = 0;
    uint16_t healthy_groups[DEFAULT_MAX_PEER_CONNECTIONS];
    size_t healthy_group_counts[DEFAULT_MAX_PEER_CONNECTIONS];
    size_t healthy_num_groups = 0;
    memset(groups, 0, sizeof(groups));
    memset(group_counts, 0, sizeof(group_counts));
    memset(healthy_groups, 0, sizeof(healthy_groups));
    memset(healthy_group_counts, 0, sizeof(healthy_group_counts));

    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        const struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->disconnect || n->is_feeler)
            continue;

        bool handshaked = n->state >= PEER_HANDSHAKE_COMPLETE;
        bool block_serving = handshaked &&
            (n->services & NODE_NETWORK) != 0;
        if (connman_outbound_health_count_node(out, n, handshaked,
                                               block_serving))
            continue;

        if (net_addr_is_ipv4(&n->addr.svc.addr)) {
            uint16_t group = ipv4_group16(n->addr.svc.addr.ip);
            size_t count = connman_outbound_health_group_bump(
                groups, group_counts, &num_groups, group);
            if (count > out->ipv4_max_group_size)
                out->ipv4_max_group_size = count;
            if (block_serving) {
                size_t healthy_count = connman_outbound_health_group_bump(
                    healthy_groups, healthy_group_counts,
                    &healthy_num_groups, group);
                if (healthy_count > out->healthy_ipv4_max_group_size)
                    out->healthy_ipv4_max_group_size = healthy_count;
            }
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);

    out->ipv4_group_count = num_groups;
    out->healthy_ipv4_group_count = healthy_num_groups;
}
