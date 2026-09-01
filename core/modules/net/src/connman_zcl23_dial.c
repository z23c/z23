/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Database-discovered ZCL23 endpoints are candidates for connman's one
 * persistent dial scheduler, never owners of a socket loop. This module owns
 * their reciprocal-connection recognition and durable addrman cooldown gate.
 */

#include "platform/time_compat.h"
#include "connman_internal.h"
#include "net/port_policy.h"
#include "util/log_macros.h"
#include "core/random.h"
#include <stdatomic.h>
#include <string.h>

static bool zcl23_endpoint_handshaked(struct connman *cm,
                                      const struct net_service *service)
{
    bool found = false;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        const struct p2p_node *node = cm->manager.nodes[i];
        if (!node || node->disconnect ||
            node->state < PEER_HANDSHAKE_COMPLETE ||
            (node->services & NODE_ZCL23) == 0)
            continue;
        if (net_service_eq(&node->addr.svc, service) ||
            (node->advertised_service_valid &&
             net_service_eq(&node->advertised_service, service))) {
            found = true;
            break;
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return found;
}

static bool zcl23_batch_has_service(const struct net_service *services,
                                    size_t count,
                                    const struct net_service *candidate)
{
    for (size_t i = 0; i < count; i++)
        if (net_service_eq(&services[i], candidate))
            return true;
    return false;
}

static bool zcl23_batch_diversity_ok(struct connman *cm,
                                     const struct net_service *services,
                                     size_t count,
                                     const struct net_addr *addr)
{
    if (net_addr_is_ipv4(addr)) {
        uint16_t group = ipv4_group16(addr->ip);
        int in_batch = 0;
        for (size_t i = 0; i < count; i++)
            if (net_addr_is_ipv4(&services[i].addr) &&
                ipv4_group16(services[i].addr.ip) == group)
                in_batch++;
        return connman_outbound_group_count(cm, group) + in_batch <
               MAX_OUTBOUND_PER_GROUP16;
    }
    if (net_addr_is_tor(addr)) {
        int in_batch = 0;
        for (size_t i = 0; i < count; i++)
            if (net_addr_is_tor(&services[i].addr))
                in_batch++;
        return connman_outbound_onion_count(cm) + in_batch <
               MAX_OUTBOUND_ONION;
    }
    if (net_addr_is_ipv6(addr)) {
        uint32_t group = ipv6_group32(addr->ip);
        int in_batch = 0;
        for (size_t i = 0; i < count; i++)
            if (net_addr_is_ipv6(&services[i].addr) &&
                ipv6_group32(services[i].addr.ip) == group)
                in_batch++;
        return connman_outbound_ipv6_group_count(cm, group) + in_batch <
               MAX_OUTBOUND_IPV6_GROUP32;
    }
    return true;
}

bool connman_gather_known_zcl23_candidate(
    struct connman *cm, const struct net_service *batch_services,
    size_t batch_count, struct connman_dial_candidate *out)
{
    if (!cm || !out || !cm->known_zcl23_peers)
        return false;

    struct connman_known_peer peers[8];
    int count = cm->known_zcl23_peers(cm->known_zcl23_peers_ctx, peers, 8);
    if (count <= 0)
        return false;
    if (count > 8)
        count = 8;

    atomic_fetch_add(&cm->zcl23_candidates_seen, (uint64_t)count);
    size_t start = (size_t)GetRand((uint64_t)count);
    int64_t now = (int64_t)platform_time_wall_time_t();
    for (int offset = 0; offset < count; offset++) {
        const struct connman_known_peer *peer =
            &peers[(start + (size_t)offset) % (size_t)count];
        struct net_address addr;
        net_address_init(&addr);
        memcpy(addr.svc.addr.ip, peer->ip, sizeof(addr.svc.addr.ip));
        addr.svc.port = peer->port;
        addr.nServices = peer->services;
        addr.nTime = (uint32_t)now;

        if (zcl23_endpoint_handshaked(cm, &addr.svc) ||
            !zcl_net_port_is_reachable_candidate(addr.svc.port) ||
            is_local(&cm->manager, &addr.svc) ||
            connman_addr_is_connected(cm, &addr) ||
            zcl23_batch_has_service(batch_services, batch_count, &addr.svc) ||
            !zcl23_batch_diversity_ok(cm, batch_services, batch_count,
                                      &addr.svc.addr)) {
            atomic_fetch_add(&cm->zcl23_policy_skips, 1);
            continue;
        }

        struct net_addr source;
        net_addr_init(&source);
        (void)addrman_add(&cm->manager.addrman, &addr, &source, 0);
        struct addr_info info;
        memset(&info, 0, sizeof(info));
        if (!addrman_find_info(&cm->manager.addrman, &addr.svc, &info)) {
            atomic_fetch_add(&cm->zcl23_policy_skips, 1);
            continue;
        }

        int cooldown =
            connman_addrman_retry_cooldown_for_attempts(info.attempts);
        if (info.last_try > 0 && now - info.last_try < cooldown) {
            atomic_fetch_add(&cm->zcl23_backoff_skips, 1);
            continue;
        }
        if (!connman_addrman_candidate_usable(cm, &info)) {
            atomic_fetch_add(&cm->zcl23_policy_skips, 1);
            continue;
        }

        addrman_attempt(&cm->manager.addrman, &addr.svc, now);
        out->addr = addr;
        out->source = CONNMAN_TARGET_ZCL23_DB;
        out->addnode_index = SIZE_MAX;
        out->is_feeler = false;
        atomic_fetch_add(&cm->zcl23_dials_scheduled, 1);
        return true;
    }
    return false;
}

void connman_evict_same_ip_inbound_when_outbound(struct connman *cm,
                                                 struct p2p_node *node)
{
    if (!cm || !node || node->disconnect || node->is_feeler)
        return;
    if (node->state < PEER_HANDSHAKE_COMPLETE)
        return;
    if (net_addr_is_operator_local(&node->addr.svc.addr))
        return;

    zcl_mutex_lock(&cm->manager.cs_nodes);
    bool have_outbound = false;
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->disconnect || n->is_feeler)
            continue;
        if (!net_addr_eq(&n->addr.svc.addr, &node->addr.svc.addr))
            continue;
        if (net_addr_is_operator_local(&n->addr.svc.addr))
            continue;
        if (!n->inbound && n->state >= PEER_HANDSHAKE_COMPLETE) {
            have_outbound = true;
            break;
        }
    }
    if (!have_outbound) {
        zcl_mutex_unlock(&cm->manager.cs_nodes);
        return;
    }

    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->disconnect || !n->inbound)
            continue;
        if (!net_addr_eq(&n->addr.svc.addr, &node->addr.svc.addr))
            continue;
        if (p2p_node_request_disconnect(
                n, P2P_DISCONNECT_EVICTED,
                P2P_DISCONNECT_SOURCE_PEER_POLICY,
                n->endpoint_generation)) {
            LOG_INFO("connman",
                     "evicted inbound %s; outbound handshake owns this IP",
                     n->addr_name);
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
}
