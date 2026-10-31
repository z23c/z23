/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * connman_reactor — the per-iteration steps of the socket reactor thread
 * (thread_socket_handler in connman.c): building the poll set, servicing
 * ready sockets, the periodic peer-stats line, the liveness and TCP-connect
 * timeout checks, and retiring flagged nodes. Split out of connman.c so that
 * function stays under the cyclomatic cap; the blocks below moved verbatim
 * and run in the same order under the same cs_nodes hold. Every LOG_* call
 * stays in thread_socket_handler, which acts on the status these return. */

#define _GNU_SOURCE

#define _DEFAULT_SOURCE
#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "platform/socket_compat.h"
#include "connman_internal.h"
#include "net/connman.h"
#include "net/noise_transport.h"
#include "event/event.h"
#include "net/peer_bandwidth.h"
#include "net/peer_lifecycle.h"
#include "net/peer_liveness.h"
#include "net/peer_scoring.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/netbase.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/utiltime.h"
#include "util/safe_alloc.h"

/* Process-wide per-peer bandwidth quotas, owned by connman.c. */
extern struct peer_bandwidth g_peer_bw;
extern bool g_peer_bw_active;

size_t connman_reactor_build_pollset(struct connman *cm, size_t listen_count,
                                     platform_socket_pollfd *pfds,
                                     struct connman_reactor_node_fd *node_fds,
                                     size_t *n_node_fds,
                                     size_t *noise_advertising,
                                     size_t *noise_handshaked)
{
    size_t npfds = 0;
    *n_node_fds = 0;
    *noise_advertising = 0;
    *noise_handshaked = 0;

    /* Add listen sockets */
    for (size_t i = 0; i < listen_count && npfds < REACTOR_MAX_FDS; i++) {
        pfds[npfds].fd = cm->manager.listen_sockets[i].socket;
        pfds[npfds].events = PLATFORM_SOCKET_POLL_READ;
        pfds[npfds].revents = 0;
        npfds++;
    }

    /* Add connected nodes — snapshot fd + index under lock */
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes && npfds < REACTOR_MAX_FDS; i++) {
        struct p2p_node *node = cm->manager.nodes[i];
        zcl_socket_t fd = node->socket;
        if (fd == ZCL_INVALID_SOCKET) continue;
        short events = PLATFORM_SOCKET_POLL_READ;
        if (node->send_size > 0)
            events |= PLATFORM_SOCKET_POLL_WRITE;
        pfds[npfds].fd = fd;
        pfds[npfds].events = events;
        pfds[npfds].revents = 0;
        if (*n_node_fds < REACTOR_MAX_FDS) {
            node_fds[*n_node_fds].fd = fd;
            node_fds[*n_node_fds].node_idx = i;
            (*n_node_fds)++;
        }
        npfds++;
    }
    /* Noise-transport advertisement census (observation only — see
     * connman_get_noisetransport_stats). Same lock hold, own walk: the
     * poll-array loop above skips fd<0 and stops at REACTOR_MAX_FDS,
     * and a census that silently under-counts is worse than none. */
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        const struct p2p_node *n = cm->manager.nodes[i];
        if (!n || n->disconnect || n->state < PEER_HANDSHAKE_COMPLETE)
            continue;
        (*noise_handshaked)++;
        if (n->services & NODE_NOISE_HYBRID)
            (*noise_advertising)++;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return npfds;
}

void connman_reactor_accept_ready(struct connman *cm,
                                  const platform_socket_pollfd *pfds,
                                  size_t listen_count)
{
    /* Accept new connections via net.c accept_connection() */
    for (size_t i = 0; i < listen_count; i++) {
        if (pfds[i].revents & PLATFORM_SOCKET_POLL_READ)
            accept_connection(&cm->manager,
                              &cm->manager.listen_sockets[i]);
    }
}

/* Feed `buf` through the Noise transport seam. Returns true when the peer
 * was dropped (a disconnect was requested). `*plain`/`*plain_n` are updated
 * to the bytes the parser should see; `*dec` is the buffer the caller frees. */
static bool connman_reactor_noise_feed(struct connman *cm,
                                       struct p2p_node *node,
                                       const char *buf, int n,
                                       const char **plain,
                                       unsigned int *plain_n, uint8_t **dec)
{
    uint8_t *wire = NULL;
    size_t dec_len = 0, wire_len = 0;
    bool noise_dropped = false;
    if (!noise_transport_feed(node->transport,
                           (const uint8_t *)buf, (size_t)n,
                           &wire, &wire_len,
                           dec, &dec_len)) {
        connman_note_addnode_prehandshake_disconnect(
            cm, node, "noise-transport");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_TRANSPORT_ERROR,
            P2P_DISCONNECT_SOURCE_SOCKET,
            node->endpoint_generation);
        noise_dropped = true;
    } else {
        /* Handshake replies / flushed sealed pending go out
         * unmodified; cs_recv held, this takes cs_send. */
        if (wire_len)
            p2p_node_queue_raw(node, wire, wire_len);
        *plain = (const char *)*dec;
        *plain_n = (unsigned int)dec_len;
        /* Responder saw v1 magic: drop the transport and
         * continue plaintext. `dec` carries the buffered
         * raw bytes to replay through the parser. */
        if (node->transport->state ==
            NOISE_PLAINTEXT_FALLBACK) {
            noise_transport_free(node->transport);
            node->transport = NULL;
        }
    }
    free(wire);
    return noise_dropped;
}

/* `n` > 0 bytes arrived in `buf`; cs_recv is held by the caller. */
static void connman_reactor_recv_bytes(struct connman *cm,
                                       struct p2p_node *node,
                                       const char *buf, int n,
                                       uint32_t bw_id)
{
    /* Noise transport seam: decrypt below the message layer. The
     * plaintext path (transport == NULL) is the UNCHANGED else
     * — `plain`/`plain_n` remain the raw recv bytes. */
    const char *plain = buf;
    unsigned int plain_n = (unsigned int)n;
    uint8_t *dec = NULL;
    bool noise_dropped = false;
    if (node->transport)
        noise_dropped = connman_reactor_noise_feed(cm, node, buf, n,
                                                   &plain, &plain_n, &dec);
    if (!noise_dropped && plain_n &&
        !p2p_node_receive_bytes(node, plain, plain_n,
                                cm->manager.message_start)) {
        connman_note_addnode_prehandshake_disconnect(
            cm, node, "message-parse");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_MESSAGE_PARSE,
            P2P_DISCONNECT_SOURCE_SOCKET,
            node->endpoint_generation);
    }
    free(dec);
    /* Single framing-layer scoring point: the parse path has
     * no net_manager back-pointer, so it only TAGS abuse
     * (bad start-magic / oversize / parse-fail). Drain the tag
     * here where nm is in scope, scoring the peer once so a
     * reconnecting flooder still accrues toward the ban
     * threshold. No-op when nothing was tagged. */
    p2p_node_score_framing_offence(&cm->manager, node);
    node->last_recv = GetTime();
    atomic_store_explicit(
        &node->last_activity_monotonic_us,
        platform_time_monotonic_us(), memory_order_relaxed);
    node->recv_bytes += (uint64_t)n;
    /* Consume download tokens post-recv. */
    if (g_peer_bw_active)
        peer_bandwidth_consume(&g_peer_bw, bw_id,
                               PEER_BW_DOWN, (size_t)n);
}

/* recv() returned 0 (remote close) or < 0 (error). */
static void connman_reactor_recv_closed(struct connman *cm,
                                        struct p2p_node *node, int n)
{
    if (n == 0) {
        connman_note_addnode_prehandshake_disconnect(
            cm, node, "remote-close");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_REMOTE_CLOSE,
            P2P_DISCONNECT_SOURCE_SOCKET,
            node->endpoint_generation);
    } else {
        int err = platform_socket_last_error();
        if (!platform_socket_error_would_block(err) &&
            !platform_socket_error_interrupted(err)) {
            connman_note_addnode_prehandshake_disconnect(
                cm, node, "recv-error");
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_IO_ERROR,
                P2P_DISCONNECT_SOURCE_SOCKET,
                node->endpoint_generation);
        }
    }
}

static void connman_reactor_recv_node(struct connman *cm,
                                      struct p2p_node *node,
                                      zcl_socket_t target_fd)
{
    /* Bandwidth quota: check download budget before recv.
     * If no tokens available, skip this peer until refill. */
    uint32_t bw_id = (uint32_t)node->id;
    size_t bw_avail = g_peer_bw_active
        ? peer_bandwidth_available(&g_peer_bw, bw_id, PEER_BW_DOWN)
        : SIZE_MAX;
    if (bw_avail == 0) return;

    zcl_mutex_lock(&node->cs_recv);
    /* Backpressure: if the message queue is full, skip recv
     * until the processing thread drains it. This prevents
     * disconnecting fast senders (e.g. snapshot serving over
     * localhost) just because we can't parse fast enough. */
    size_t queued = node->recv_msg_count;
    if (queued >= MAX_RECV_MESSAGES) {
        zcl_mutex_unlock(&node->cs_recv);
        return;
    }
    char buf[0x10000];
    /* Cap recv size to bandwidth budget and remaining queue
     * space. If a fast peer is close to filling the complete
     * message queue, avoid reading a large kernel buffer that
     * would overflow the in-process protocol stream before the
     * message thread can drain it. */
    size_t recv_cap = connman_recv_cap_for_queue(queued,
                                                 sizeof(buf));
    if (bw_avail < recv_cap) recv_cap = bw_avail;
    if (recv_cap == 0) {
        zcl_mutex_unlock(&node->cs_recv);
        return;
    }
    int n = platform_socket_receive(target_fd, buf, recv_cap);
    if (n > 0)
        connman_reactor_recv_bytes(cm, node, buf, n, bw_id);
    else
        connman_reactor_recv_closed(cm, node, n);
    /* If disconnecting, clean up messages while holding lock */
    if (node->disconnect) {
        for (size_t mi = 0; mi < node->recv_msg_count; mi++)
            net_message_free(&node->recv_msgs[mi]);
        node->recv_msg_count = 0;
    }
    zcl_mutex_unlock(&node->cs_recv);
}

static void connman_reactor_send_node(struct p2p_node *node)
{
    /* Bandwidth quota: check upload budget before send. */
    uint32_t bw_id_s = (uint32_t)node->id;
    size_t up_avail = g_peer_bw_active
        ? peer_bandwidth_available(&g_peer_bw, bw_id_s, PEER_BW_UP)
        : SIZE_MAX;
    if (up_avail > 0) {
        zcl_mutex_lock(&node->cs_send);
        uint64_t before = node->send_bytes;
        socket_send_data(node);
        uint64_t sent = node->send_bytes - before;
        zcl_mutex_unlock(&node->cs_send);
        /* Consume upload tokens for actual bytes sent. */
        if (g_peer_bw_active && sent > 0)
            peer_bandwidth_consume(&g_peer_bw, bw_id_s,
                                   PEER_BW_UP, (size_t)sent);
    }
    /* If up_avail == 0, skip send — peer is throttled. */
}

void connman_reactor_dispatch_ready(
    struct connman *cm, const platform_socket_pollfd *pfds, size_t npfds,
    const struct connman_reactor_node_fd *node_fds, size_t n_node_fds,
    size_t listen_count)
{
    for (size_t pi = 0; pi < n_node_fds; pi++) {
        size_t poll_idx = listen_count + pi;
        if (poll_idx >= npfds) break;
        short rev = pfds[poll_idx].revents;
        if (!rev) continue;

        /* Find the node that still has this fd */
        zcl_socket_t target_fd = node_fds[pi].fd;
        struct p2p_node *node = NULL;
        for (size_t ni = 0; ni < cm->manager.num_nodes; ni++) {
            if (cm->manager.nodes[ni]->socket == target_fd) {
                node = cm->manager.nodes[ni];
                break;
            }
        }
        if (!node) continue; /* node was removed between poll and now */

        if ((rev & PLATFORM_SOCKET_POLL_READ) && !node->disconnect)
            connman_reactor_recv_node(cm, node, target_fd);

        if ((rev & PLATFORM_SOCKET_POLL_WRITE) && !node->disconnect)
            connman_reactor_send_node(node);

        /* POLLHUP/POLLERR — peer disconnected or socket error */
        if ((rev & (PLATFORM_SOCKET_POLL_HANGUP |
                    PLATFORM_SOCKET_POLL_ERROR)) && !node->disconnect) {
            connman_note_addnode_prehandshake_disconnect(
                cm, node, "poll-hup-err");
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_IO_ERROR,
                P2P_DISCONNECT_SOURCE_SOCKET,
                node->endpoint_generation);
        }
    }
}

void connman_reactor_log_peer_stats(struct connman *cm)
{
    /* Periodic peer stats (every 60s) */
    static int64_t last_peer_log = 0;
    static int64_t first_peer_log = 0;
    int64_t now_log = GetTime();
    if (first_peer_log == 0)
        first_peer_log = now_log;
    if (now_log - last_peer_log >= 60) {
        last_peer_log = now_log;
        size_t in = 0, out = 0, connected = 0;
        for (size_t pi = 0; pi < cm->manager.num_nodes; pi++) {
            struct p2p_node *p = cm->manager.nodes[pi];
            if (p->disconnect) continue;
            if (p->inbound) in++; else out++;
            if (p->state >= PEER_HANDSHAKE_COMPLETE) connected++;
        }
        if (out == 0 && cm->manager.num_nodes > 0 &&
            now_log - first_peer_log >= 60)
            printf("WARNING: 0 outbound peers (%zu inbound) "
                   "— cannot sync\n", in);
        else if (cm->manager.num_nodes > 0)
            printf("Peers: %zu (%zu out, %zu in, %zu active)\n",
                   cm->manager.num_nodes, out, in, connected);
        else if (now_log > 30) /* don't warn during first 30s */
            printf("WARNING: 0 peers connected\n");
    }
}

enum p2p_disconnect_reason connman_reactor_liveness_timeout(
    struct p2p_node *n, int64_t now_mono_us, const char **timeout_name,
    int64_t *silent_secs)
{
    enum p2p_disconnect_reason reason = P2P_DISCONNECT_NONE;
    *timeout_name = NULL;
    *silent_secs = 0;
    if (n->state >= PEER_HANDSHAKE_COMPLETE) {
        struct peer_liveness_sample sample = {
            .connected_us = atomic_load_explicit(
                &n->connected_monotonic_us,
                memory_order_relaxed),
            .last_activity_us = atomic_load_explicit(
                &n->last_activity_monotonic_us,
                memory_order_relaxed),
            .ping_sent_us = atomic_load_explicit(
                &n->keepalive_ping_sent_monotonic_us,
                memory_order_relaxed),
        };
        enum peer_liveness_action action =
            peer_liveness_decide(&sample, now_mono_us);
        if (action == PEER_LIVENESS_DISCONNECT_PONG_TIMEOUT) {
            reason = P2P_DISCONNECT_PONG_TIMEOUT;
            *timeout_name = "pong_timeout";
        } else if (action ==
                   PEER_LIVENESS_DISCONNECT_HARD_SILENCE) {
            reason = P2P_DISCONNECT_HARD_SILENCE;
            *timeout_name = "hard_silence";
        }
        if (reason != P2P_DISCONNECT_NONE) {
            *silent_secs = sample.last_activity_us > 0
                ? (now_mono_us - sample.last_activity_us) /
                      1000000LL
                : 0;
            event_emitf(EV_TCP_TIMEOUT, (uint32_t)n->id,
                        "%s silence=%llds state=%s",
                        *timeout_name, (long long)*silent_secs,
                        peer_state_name(n->state));
            peer_lifecycle_note_timeout(n, *timeout_name);
        }
    }
    return reason;
}

bool connman_reactor_connect_timeout(struct connman *cm, struct p2p_node *n,
                                     int64_t now_check, bool is_addnode,
                                     size_t addnode_index)
{
    /* TCP connect timeout: 10s for outbound peers stuck
     * in PEER_CONNECTING (TCP SYN sent, never reached
     * PEER_CONNECTED). time_connected is set at node
     * creation, so a peer still in PEER_CONNECTING after
     * 10s never finished the 3-way TCP handshake. Without
     * this fast cutoff those sockets sit forever, eat
     * outbound slots, and starve real peers — the live
     * failure mode that left this node with 1 working
     * outbound and 4 stuck in `connecting`.
     *
     * Loopback exemption: a 127.0.0.0/8 or ::1 socket either
     * succeeds instantly or never (no SYN-loss on lo). The
     * 10s cutoff was hitting our cold-boot zclassicd peer
     * before the message loop pushed our version frame,
     * killing the loopback fast lane until the next outbound
     * retry. Use the 90s handshake budget instead. */
    int connect_timeout =
        net_addr_is_local(&n->addr.svc.addr) ? 90 : 10;
    if (!n->inbound &&
        n->state == PEER_CONNECTING &&
        n->time_connected > 0 &&
        now_check - n->time_connected > connect_timeout) {
        event_emitf(EV_TCP_TIMEOUT, (uint32_t)n->id,
                    "tcp_connect %llds state=connecting",
                    (long long)(now_check - n->time_connected));
        /* Machine-readable in node.log, not only in the event
         * ring. Its own event name: the terminal
         * "peer_disconnected" line still follows from the sweep,
         * and may carry a different reason if another thread won
         * the causal CAS first. */
        p2p_log_peer_close(n, "peer_connect_timeout",
                           P2P_DISCONNECT_CONNECT_TIMEOUT,
                           P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER);
        peer_lifecycle_note_timeout(n, "tcp_connect");
        if (is_addnode)
            connman_record_addnode_failure(
                cm, addnode_index, CONNMAN_ADDNODE_FAILURE_TCP);
        (void)p2p_node_request_disconnect(
            n, P2P_DISCONNECT_CONNECT_TIMEOUT,
            P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER,
            n->endpoint_generation);
        return true;
    }
    return false;
}

void connman_reactor_close_flagged_node(struct p2p_node *node)
{
    enum p2p_disconnect_reason reason =
        (enum p2p_disconnect_reason)atomic_load_explicit(
            &node->disconnect_reason, memory_order_acquire);
    enum p2p_disconnect_source source =
        (enum p2p_disconnect_source)atomic_load_explicit(
            &node->disconnect_source, memory_order_relaxed);
    uint64_t generation = atomic_load_explicit(
        &node->disconnect_endpoint_generation,
        memory_order_relaxed);
    event_emitf(EV_TCP_DISCONNECTED, (uint32_t)node->id,
                "%s state=%s misbehavior=%d reason=%s source=%s "
                "endpoint_generation=%llu",
                node->addr_name,
                peer_state_name(node->state),
                node->misbehavior,
                p2p_disconnect_reason_name(reason),
                p2p_disconnect_source_name(source),
                (unsigned long long)generation);
    /* THE terminal record. This is the only place a p2p_node
     * leaves nodes[], so exactly one "peer_disconnected" line is
     * written per session — swept, replaced, deduped or evicted
     * alike, each with its own named reason. Emitted BEFORE the
     * forced state overwrite below so the line reports the state
     * the session actually reached, not PEER_DISCONNECTED. */
    p2p_log_peer_close(node, "peer_disconnected", reason, source);
    peer_lifecycle_note_disconnected(
        node, p2p_disconnect_reason_name(reason));

    /* Re-queue any in-flight blocks from this peer — both the
     * legacy download manager AND the parallel block swarm.
     * (g_block_swarm requeue is event-driven here; otherwise a
     * dead peer's pieces sit until the 8 s BLOCK_PIECE_TIMEOUT.) */
    {
        dl_peer_disconnected(msg_get_download_mgr(),
                              (uint32_t)node->id);
        mp_block_swarm_peer_disconnected((uint32_t)node->id);
    }

    /* Force disconnect — bypass transition validator since this
     * is cleanup, not a normal state change. The event was
     * already emitted (EV_TCP_DISCONNECTED above). */
    node->state = PEER_DISCONNECTED;
    p2p_node_close_socket(node);

    /* Clean send queue while holding cs_nodes. Use
     * send_segment_free (not a raw free) so each segment's
     * bytes are returned to the process-wide send budget;
     * otherwise g_send_total_bytes leaks on forced disconnect. */
    zcl_mutex_lock(&node->cs_send);
    while (node->send_head) {
        struct send_segment *seg = node->send_head;
        node->send_head = seg->next;
        send_segment_free(seg);
    }
    node->send_tail = NULL;
    node->send_size = 0;
    zcl_mutex_unlock(&node->cs_send);

    /* Clean recv messages */
    zcl_mutex_lock(&node->cs_recv);
    for (size_t mi = 0; mi < node->recv_msg_count; mi++)
        net_message_free(&node->recv_msgs[mi]);
    node->recv_msg_count = 0;
    zcl_mutex_unlock(&node->cs_recv);
}

enum connman_reactor_park connman_reactor_unlink_node(
    struct connman *cm, size_t i, struct p2p_node *node,
    uint64_t *hardcap_leaked)
{
    enum connman_reactor_park park = CONNMAN_REACTOR_PARK_DONE;
    cm->manager.nodes[i] =
        cm->manager.nodes[cm->manager.num_nodes - 1];
    cm->manager.num_nodes--;
    /* Drop the manager's ownership ref (taken at creation in
     * connect_node/accept_connection) now that the node has
     * left nodes[]. Any remaining ref belongs to an in-flight
     * message-cycle snapshot. Without this release no node
     * ever reached refcount 0, so the deferred list pinned at
     * its hard cap and every churned peer leaked. */
    p2p_node_release(node);
    if (p2p_node_get_ref(node) <= 0) {
        p2p_node_free(node);
    } else if (cm->num_deferred_free < cm->deferred_free_cap) {
        cm->deferred_free[cm->num_deferred_free++] = node;
    } else if (cm->deferred_free_cap <
               CONNMAN_DEFERRED_FREE_HARD_CAP) {
        /* grow the buffer rather than leak.
         * Double until hitting the hard cap. */
        size_t new_cap = cm->deferred_free_cap * 2;
        if (new_cap > CONNMAN_DEFERRED_FREE_HARD_CAP)
            new_cap = CONNMAN_DEFERRED_FREE_HARD_CAP;
        struct p2p_node **grown = zcl_realloc(
            cm->deferred_free,
            new_cap * sizeof(*cm->deferred_free),
            "connman_deferred_free");
        if (grown) {
            cm->deferred_free = grown;
            cm->deferred_free_cap = new_cap;
            cm->deferred_free[cm->num_deferred_free++] = node;
        } else {
            park = CONNMAN_REACTOR_PARK_REALLOC_FAILED;
        }
    } else {
        /* Hard ceiling with a live ref: a message-cycle
         * snapshot has been stuck holding refs for a long
         * time. Transition + running count, not a per-node
         * log storm. */
        (*hardcap_leaked)++;
        if (*hardcap_leaked == 1 ||
            *hardcap_leaked % 100 == 0)
            park = CONNMAN_REACTOR_PARK_HARDCAP_LOG;
    }
    return park;
}
