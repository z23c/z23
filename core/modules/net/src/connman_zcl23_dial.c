/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Database-discovered ZCL23 endpoints are candidates for connman's one
 * persistent dial scheduler, never owners of a socket loop. This module owns
 * their reciprocal-connection recognition and durable addrman cooldown gate,
 * and the mutual-dial tie-break.
 */

#include "platform/time_compat.h"
#include "connman_internal.h"
#include "net/noise_transport.h"
#include "net/port_policy.h"
#include "support/log_throttle.h"
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
    bool starving = connman_outbound_healthy_count(cm) == 0;
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

        if (info.last_try > 0 &&
            now - info.last_try < connman_addrman_retry_cooldown(&info, starving)) {
            atomic_fetch_add(&cm->zcl23_backoff_skips, 1);
            continue;
        }
        if (!connman_addrman_candidate_usable(cm, &info, starving)) {
            atomic_fetch_add(&cm->zcl23_policy_skips, 1);
            continue;
        }

        addrman_attempt(&cm->manager.addrman, &addr.svc, now, starving);
        out->addr = addr;
        out->source = CONNMAN_TARGET_ZCL23_DB;
        out->addnode_index = SIZE_MAX;
        out->is_feeler = false;
        atomic_fetch_add(&cm->zcl23_dials_scheduled, 1);
        return true;
    }
    return false;
}

/* ── Mutual-dial tie-break ─────────────────────────────────────────────
 * When two nodes hold authenticated sessions to each other in both
 * directions, both keep the session dialed by the lower Noise static key.
 * Each side reaches the same verdict from the two keys alone. */

/* node->transport is freed (plaintext fallback) by the socket thread under
 * cs_recv, so the read takes cs_recv; the order is cs_nodes -> cs_recv and
 * cs_recv is recursive, so a caller already inside the recv loop is safe.
 * The mutex is logically separate from the const view of the node. */
static bool connman_session_static(const struct p2p_node *n, uint8_t out[32])
{
    struct noise_transport_snapshot snap;
    zcl_mutex_t *recv_lock = (zcl_mutex_t *)&n->cs_recv;
    zcl_mutex_lock(recv_lock);
    bool ok = n->transport &&
              noise_transport_snapshot(n->transport, &snap);
    zcl_mutex_unlock(recv_lock);
    if (!ok)
        return false;
    memcpy(out, snap.remote_static, 32);
    return true;
}

static bool connman_is_addnode_service(const struct connman *cm,
                                       const struct net_service *svc)
{
    for (int i = 0; i < cm->num_addnodes; i++) {
        if (net_service_eq(&cm->addnodes[i].svc, svc))
            return true;
    }
    return false;
}

static struct connman_target_static *
connman_target_static_find(struct connman *cm, const struct net_service *svc)
{
    for (size_t i = 0; i < MAX_ADDNODES; i++) {
        struct connman_target_static *e = &cm->addnode_statics[i];
        if (e->known && net_service_eq(&e->svc, svc))
            return e;
    }
    return NULL;
}

void connman_mutual_dial_learn(struct connman *cm,
                               const struct p2p_node *outbound)
{
    uint8_t key[32];
    if (!cm || !outbound || outbound->inbound ||
        !connman_is_addnode_service(cm, &outbound->addr.svc) ||
        !connman_session_static(outbound, key))
        return;
    struct connman_target_static *slot =
        connman_target_static_find(cm, &outbound->addr.svc);
    /* At most MAX_ADDNODES targets exist, so a free or stale slot does. */
    for (size_t i = 0; !slot && i < MAX_ADDNODES; i++) {
        struct connman_target_static *e = &cm->addnode_statics[i];
        if (!e->known || !connman_is_addnode_service(cm, &e->svc))
            slot = e;
    }
    if (!slot)
        return;
    slot->svc = outbound->addr.svc;
    memcpy(slot->key, key, sizeof(slot->key));
    slot->known = true;
}

bool connman_mutual_dial_holds(struct connman *cm,
                               const struct p2p_node *node,
                               const struct net_service *target)
{
    uint8_t key[32];
    if (!cm || !node || !target || node->disconnect || !node->inbound ||
        !cm->manager.noise_enabled ||
        !net_addr_eq(&node->addr.svc.addr, &target->addr))
        return false;
    const struct connman_target_static *known =
        connman_target_static_find(cm, target);
    return known && connman_session_static(node, key) &&
           memcmp(key, known->key, sizeof(key)) == 0 &&
           memcmp(key, cm->manager.identity_pub, sizeof(key)) < 0;
}

static struct log_throttle g_mutual_dial_log = LOG_THROTTLE_INIT;
static _Atomic uint64_t g_mutual_dial_log_lines;

/* One named line per decision; the same peer key repeats at most once a
 * minute, with the suppressed count. */
static void connman_mutual_dial_log(const struct connman *cm,
                                    const struct p2p_node *outbound,
                                    bool keep_inbound,
                                    const uint8_t remote[32])
{
    uint64_t key = 0, suppressed = 0;
    memcpy(&key, remote, sizeof(key));
    if (key == LOG_THROTTLE_KEY_NONE)
        key--;
    if (!log_throttle_should_emit(&g_mutual_dial_log, key,
                                  (int64_t)platform_time_wall_time_t(), 60,
                                  &suppressed))
        return;
    const uint8_t *local = cm->manager.identity_pub;
    LOG_INFO("connman",
             "mutual-dial tie-break: peer=%s kept=%s local=%02x%02x%02x%02x "
             "remote=%02x%02x%02x%02x reason=%s suppressed=%llu",
             outbound->addr_name, keep_inbound ? "inbound" : "outbound",
             local[0], local[1], local[2], local[3],
             remote[0], remote[1], remote[2], remote[3],
             keep_inbound ? "remote-key-lower" : "local-key-lower",
             (unsigned long long)suppressed);
    atomic_fetch_add(&g_mutual_dial_log_lines, 1);
}

/* True when `inbound` is the kept session of a mutual dial with `outbound`:
 * both authenticated the same key, and that key is below ours. A pair whose
 * key is above ours keeps the outbound, as the same-IP eviction does. */
static bool connman_mutual_dial_keeps_inbound(const struct connman *cm,
                                              const struct p2p_node *outbound,
                                              const struct p2p_node *inbound)
{
    uint8_t out_key[32], in_key[32];
    if (!cm->manager.noise_enabled || outbound->disconnect ||
        !connman_session_static(outbound, out_key) ||
        !connman_session_static(inbound, in_key) ||
        memcmp(out_key, in_key, sizeof(in_key)) != 0)
        return false;
    int order = memcmp(in_key, cm->manager.identity_pub, sizeof(in_key));
    if (order != 0)
        connman_mutual_dial_log(cm, outbound, order < 0, in_key);
    return order < 0;
}

static void connman_mutual_dial_yield(struct connman *cm,
                                      struct p2p_node *outbound)
{
    connman_mutual_dial_learn(cm, outbound);
    (void)p2p_node_request_disconnect(outbound, P2P_DISCONNECT_EVICTED,
                                      P2P_DISCONNECT_SOURCE_PEER_POLICY,
                                      outbound->endpoint_generation);
}

#ifdef ZCL_TESTING
uint64_t connman_mutual_dial_log_lines_for_test(void)
{
    return atomic_load(&g_mutual_dial_log_lines);
}
#endif

/* The handshaked outbound that owns `node`'s IP, or NULL. */
static struct p2p_node *connman_same_ip_outbound_locked(
    struct connman *cm, const struct p2p_node *node)
{
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->disconnect || n->is_feeler || n->inbound)
            continue;
        if (!net_addr_eq(&n->addr.svc.addr, &node->addr.svc.addr))
            continue;
        if (net_addr_is_operator_local(&n->addr.svc.addr))
            continue;
        if (n->state >= PEER_HANDSHAKE_COMPLETE)
            return n;
    }
    return NULL;
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
    struct p2p_node *outbound = connman_same_ip_outbound_locked(cm, node);
    for (size_t i = 0; outbound && i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->disconnect || !n->inbound)
            continue;
        if (!net_addr_eq(&n->addr.svc.addr, &node->addr.svc.addr))
            continue;
        if (connman_mutual_dial_keeps_inbound(cm, outbound, n)) {
            connman_mutual_dial_yield(cm, outbound);
            continue;
        }
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
