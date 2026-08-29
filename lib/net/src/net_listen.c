/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Inbound server path: bind/listen socket setup and the accept-side
 * admission control that decides whether a newly accepted socket becomes a
 * peer. Split out of net.c unchanged — the admission checks here run in a
 * security-relevant order (ban check, per-IP sybil cap, aggregate loopback
 * ceiling, inbound cap with eviction) and must stay in that order. */

#include "net/net.h"
#include "net/v2_transport.h"
#include "net/peer_lifecycle.h"
#include "net/peer_scoring.h"
#include "net/peer_eviction.h"
#include "net_internal.h"
#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "util/log_json.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#endif

/* Throttles the "rejected banned peer on accept" line: a banned host that
 * keeps redialling must not be able to drive our own log volume. */
static struct log_throttle g_banned_accept_log = LOG_THROTTLE_INIT;

/* --- bind/listen --- */

bool bind_listen_port(struct net_manager *nm, const struct net_service *addr,
                      bool whitelisted)
{
    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    memset(&ss, 0, sizeof(ss));

    if (net_addr_is_ipv4(&addr->addr)) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(addr->port);
        memcpy(&s4->sin_addr, addr->addr.ip + 12, 4);
        sslen = sizeof(*s4);
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(addr->port);
        memcpy(&s6->sin6_addr, addr->addr.ip, 16);
        sslen = sizeof(*s6);
    }

    zcl_socket_t sock = socket(((struct sockaddr *)&ss)->sa_family,
                                SOCK_STREAM, IPPROTO_TCP);
    if (sock == ZCL_INVALID_SOCKET)
        LOG_FAIL("net", "socket() failed for listen port");

    int one = 1;
#ifndef _WIN32
#ifdef SO_NOSIGPIPE
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#else
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
#endif

    if (!set_socket_nonblocking(sock, true)) {
        close_socket(&sock);
        LOG_FAIL("net", "set_socket_nonblocking failed for listen port");
    }

    if (!net_addr_is_ipv4(&addr->addr)) {
#ifdef IPV6_V6ONLY
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
                   (const char *)&one, sizeof(one));
#endif
    }

    if (bind(sock, (struct sockaddr *)&ss, sslen) == ZCL_SOCKET_ERROR) {
        close_socket(&sock);
        LOG_FAIL("net", "bind() failed for listen port");
    }

    struct sockaddr_storage bound;
    socklen_t bound_len = sizeof(bound);
    memset(&bound, 0, sizeof(bound));
    if (getsockname(sock, (struct sockaddr *)&bound, &bound_len) != 0) {
        close_socket(&sock);
        LOG_FAIL("net", "getsockname() failed for bound listen port");
    }
    uint16_t local_port = 0;
    if (bound.ss_family == AF_INET)
        local_port = ntohs(((struct sockaddr_in *)&bound)->sin_port);
    else if (bound.ss_family == AF_INET6)
        local_port = ntohs(((struct sockaddr_in6 *)&bound)->sin6_port);
    if (local_port == 0) {
        close_socket(&sock);
        LOG_FAIL("net", "bound listen socket reported local port zero");
    }

    if (listen(sock, SOMAXCONN) == ZCL_SOCKET_ERROR) {
        close_socket(&sock);
        LOG_FAIL("net", "listen() failed");
    }

    if (nm->num_listen_sockets >= nm->listen_sockets_cap) {
        size_t newcap = nm->listen_sockets_cap ? nm->listen_sockets_cap * 2 : 4;
        struct listen_socket *tmp = zcl_realloc(nm->listen_sockets, newcap * sizeof(*tmp), "listen_sockets");
        if (!tmp) { close_socket(&sock); LOG_FAIL("net", "realloc failed for listen_sockets: newcap=%zu", newcap); }
        nm->listen_sockets = tmp;
        nm->listen_sockets_cap = newcap;
    }
    nm->listen_sockets[nm->num_listen_sockets].socket = sock;
    nm->listen_sockets[nm->num_listen_sockets].whitelisted = whitelisted;
    nm->listen_sockets[nm->num_listen_sockets].local_port = local_port;
    nm->num_listen_sockets++;

    if (net_addr_is_routable(&addr->addr) && nm->discover && !whitelisted)
        add_local(nm, addr, LOCAL_BIND);

    return true;
}

/* --- accept connection --- */

bool accept_connection(struct net_manager *nm, const struct listen_socket *ls)
{
    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    zcl_socket_t sock = accept(ls->socket, (struct sockaddr *)&ss, &sslen);

    if (sock == ZCL_INVALID_SOCKET) {
        int error = platform_socket_last_error();
        if (platform_socket_error_would_block(error) ||
            platform_socket_error_interrupted(error))
            return false;
        LOG_FAIL("net", "accept() returned invalid socket");
    }

    struct net_address addr;
    net_address_init(&addr);

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        memset(addr.svc.addr.ip, 0, 10);
        memset(addr.svc.addr.ip + 10, 0xff, 2);
        memcpy(addr.svc.addr.ip + 12, &s4->sin_addr, 4);
        addr.svc.port = ntohs(s4->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        memcpy(addr.svc.addr.ip, &s6->sin6_addr, 16);
        addr.svc.port = ntohs(s6->sin6_port);
    }

    bool is_whitelisted = ls->whitelisted;

    if (is_banned(nm, &addr.svc.addr) && !is_whitelisted) {
        close_socket(&sock);
        uint64_t suppressed = 0;
        if (log_throttle_should_emit(
                &g_banned_accept_log, 1,
                (int64_t)platform_time_wall_time_t(), 300, &suppressed)) {
            LOG_WARN("net", "rejected banned peer on accept "
                     "(suppressed=%llu)",
                     (unsigned long long)suppressed);
        }
        return false;
    }

    /* Per-IP inbound limit — sybil defence: one IP must not be able to
     * consume every inbound slot. Operator-configurable via
     * ZCL_PEER_MAX_INBOUND_PER_IP (default 3, the historical literal).
     *
     * This is a source-IP heuristic, not an identity check: at accept()
     * there is no peer identity yet, so several independent nodes behind
     * one NAT — or co-located on one host — share a single budget. Past the
     * cap we close before any bytes are exchanged, which the dialling node
     * can only observe as "remote-close, state=connecting", so the refusal
     * is logged loudly HERE (this side is the only side that knows why).
     *
     * LOOPBACK sources get a RAISED cap, never an unlimited one. Several
     * nodes on one host all arrive as 127.0.0.1 sharing one 16-byte key,
     * so the default cap of 3 refuses the fourth by construction — exactly
     * the local multi-node topology a cold-start sync proof is made of.
     * But "loopback" is not "trusted": opening a loopback socket needs no
     * privilege at all, so any unprivileged local process or any container
     * sharing this network namespace can do it, and 127.0.0.0/8 gives it
     * 16.7M distinct source keys to spread across. So the real bound is
     * the AGGREGATE one below — peer_scoring_max_inbound_loopback() slots
     * across ALL loopback sources together, 24 of 117 on stock settings,
     * with at least three quarters of inbound capacity permanently
     * reserved for non-loopback peers so a local flood cannot win the
     * post-restart race for every slot. Set ZCL_NET_LOOPBACK_INBOUND_MAX=0
     * to restore the pre-exemption behaviour exactly.
     *
     * RFC1918 is deliberately NOT exempt: on a hosted machine with
     * provider private networking the neighbouring tenants are RFC1918
     * sources, and loopback already solves the same-host problem. */
    int max_per_ip = peer_scoring_max_inbound_per_ip();
    int inbound_count = 0;
    int same_ip_count = 0;
    int loopback_inbound_count = 0;
    int max_inbound = nm->max_connections - MAX_OUTBOUND_CONNECTIONS;
    bool src_loopback = net_addr_is_operator_local(&addr.svc.addr);
    int max_loopback = peer_scoring_max_inbound_loopback(max_inbound);
    bool ip_cap_exempt = is_whitelisted ||
                         (src_loopback && max_loopback > 0);
    /* Evict-not-reject: when the inbound cap is hit, free a slot by
     * disconnecting the least-valuable existing inbound peer instead of
     * refusing the new one (peer_eviction_select() never picks outbound/
     * whitelisted peers, the longest-connected quartile, or a peer that
     * relayed a novel block/tx recently). Snapshotted and decided under
     * cs_nodes so the pick can't race a concurrent add/remove. */
    bool evicted = false;
    node_id_t evicted_id = 0;
    char evicted_addr_name[256] = "";
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < nm->num_nodes; i++) {
        if (nm->nodes[i]->inbound)
            inbound_count++;
        if (nm->nodes[i]->inbound &&
            memcmp(nm->nodes[i]->addr.svc.addr.ip, addr.svc.addr.ip, 16) == 0)
            same_ip_count++;
        if (nm->nodes[i]->inbound &&
            net_addr_is_operator_local(&nm->nodes[i]->addr.svc.addr))
            loopback_inbound_count++;
    }
    if (inbound_count >= max_inbound) {
        struct peer_eviction_candidate cand[PEER_EVICTION_MAX_CANDIDATES];
        struct p2p_node *cand_node[PEER_EVICTION_MAX_CANDIDATES];
        size_t ncand = nm->num_nodes < PEER_EVICTION_MAX_CANDIDATES
                            ? nm->num_nodes : PEER_EVICTION_MAX_CANDIDATES;
        for (size_t i = 0; i < ncand; i++) {
            struct p2p_node *cn = nm->nodes[i];
            cand[i].is_outbound = !cn->inbound;
            cand[i].whitelisted = cn->whitelisted;
            cand[i].connected_time = cn->time_connected;
            cand[i].last_block_time = cn->last_block_time;
            cand[i].last_tx_time = cn->last_tx_time;
            cand_node[i] = cn;
        }
        int victim_idx = peer_eviction_select(
            cand, ncand, (int64_t)platform_time_wall_time_t());
        if (victim_idx >= 0) {
            struct p2p_node *victim = cand_node[victim_idx];
            (void)p2p_node_request_disconnect(
                victim, P2P_DISCONNECT_EVICTED,
                P2P_DISCONNECT_SOURCE_PEER_POLICY,
                victim->endpoint_generation);
            evicted = true;
            evicted_id = victim->id;
            snprintf(evicted_addr_name, sizeof(evicted_addr_name), "%s",
                     victim->addr_name);
        }
    }
    zcl_mutex_unlock(&nm->cs_nodes);

    if (!ip_cap_exempt && same_ip_count >= max_per_ip) {
        close_socket(&sock);
        LOG_FAIL("net",
                 "too many inbound connections from same IP: count=%d "
                 "cap=%d (raise ZCL_PEER_MAX_INBOUND_PER_IP if this source "
                 "legitimately runs several nodes); the dialling node sees "
                 "only a zero-byte remote-close",
                 same_ip_count, max_per_ip);
    }

    /* Aggregate loopback ceiling. This, not the per-IP number, is what
     * bounds a local source: 127.0.0.0/8 is 16.7M distinct keys, so the
     * per-IP cap alone would bound nothing. Whitelisted listeners are
     * still exempt (an explicit operator decision), everything else on
     * loopback shares this budget. */
    if (!is_whitelisted && src_loopback && max_loopback > 0 &&
        loopback_inbound_count >= max_loopback) {
        close_socket(&sock);
        LOG_FAIL("net",
                 "loopback inbound ceiling reached: count=%d cap=%d of "
                 "max_inbound=%d (raise ZCL_NET_LOOPBACK_INBOUND_MAX, or "
                 "whitelist the listener, if this host legitimately runs "
                 "more local nodes); the dialling node sees only a "
                 "zero-byte remote-close",
                 loopback_inbound_count, max_loopback, max_inbound);
    }

    if (inbound_count >= max_inbound) {
        if (!evicted) {
            close_socket(&sock);
            LOG_FAIL("net", "max inbound connections reached and no evictable peer: %d >= %d",
                     inbound_count, max_inbound);
        }
        LOG_WARN("net", "inbound cap reached (%d >= %d): evicted node id=%d addr=%s to admit new peer",
                 inbound_count, max_inbound, evicted_id, evicted_addr_name);
    }

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
               (const char *)&one, sizeof(one));

    /* The accepted socket is a NEW socket and does NOT inherit the listener's
     * non-blocking mode: POSIX accept(2) does not carry file status flags
     * across, and Winsock does not propagate FIONBIO. It arrives BLOCKING on
     * every platform.
     *
     * On POSIX that stays invisible, because socket_send_data() asks for
     * non-blocking per call with MSG_DONTWAIT. Windows has no such flag --
     * the _WIN32 arm at the top of this file defines MSG_DONTWAIT to 0 -- so
     * there the same send() is an ordinary blocking send. One stalled inbound
     * peer would then park the caller inside send() holding cs_send, and on
     * the reactor write path (connman.c thread_socket_handler) cs_nodes as
     * well, stalling every other peer and every subsystem that walks nodes[].
     * A reader on Linux cannot observe that, which is why it is stated here.
     *
     * Fail closed. Both I/O paths ASSUME this socket is non-blocking: they
     * treat EWOULDBLOCK as the normal "nothing more right now" answer and
     * never bound a blocking call with SO_SNDTIMEO or SO_RCVTIMEO. A socket
     * whose mode we could not set is one the reactor cannot serve without
     * risking that stall, so refuse the peer rather than admit it. Same
     * statement, same order, as bind_listen_port above and as the outbound
     * dial in connect_socket_start(). */
    if (!set_socket_nonblocking(sock, true)) {
        close_socket(&sock);
        LOG_FAIL("net",
                 "set_socket_nonblocking failed for accepted inbound socket, "
                 "error=%d -- refusing peer: a blocking peer socket can stall "
                 "the reactor inside send()",
                 platform_socket_last_error());
    }

    struct p2p_node *node = p2p_node_create(nm, sock, &addr, "", true);
    if (!node) {
        close_socket(&sock);
        LOG_FAIL("net", "p2p_node_create failed for inbound connection");
    }

    /* v2 transport (default OFF): arm as RESPONDER in V2_DETECT when enabled.
     * The first inbound bytes decide plaintext (v1 magic) vs Noise msg1. */
    if (nm->v2_enabled) {
        uint8_t *unused = NULL;
        size_t unused_len = 0;
        node->transport = v2_transport_begin(false, nm->identity_priv,
                                             nm->message_start,
                                             &unused, &unused_len);
        free(unused);
    }

    p2p_node_add_ref(node);
    node->whitelisted = is_whitelisted;
    node->accepted_local_port = ls->local_port;
    peer_lifecycle_note_connected(node, PEER_LIFECYCLE_SOURCE_INBOUND);

    /* Inbound sessions get the same open line as outbound ones. Without it
     * every inbound close line in node.log would be an orphan, and a reader
     * counting opens against closes would see a permanent, meaningless
     * deficit. Emitted BEFORE the node is published into nodes[]: past that
     * point the manager ref this function holds is the only one, and the
     * disconnect sweep may retire the node. */
    char addr_safe[96];
    log_json_escape(addr_safe, sizeof(addr_safe), node->addr_name);
    log_jsonf(LOG_JSON_INFO, "peer_connected",
              "\"addr\":\"%s\",\"peer_id\":%d,\"inbound\":true",
              addr_safe, (int)node->id);

    zcl_mutex_lock(&nm->cs_nodes);
    nm_add_node(nm, node);
    zcl_mutex_unlock(&nm->cs_nodes);

    return true;
}
