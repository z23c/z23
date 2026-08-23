/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "net/net.h"
#include "net/v2_transport.h"
#include "net/net_fault.h"
#include "net/onion_stream.h"
#include "net/peer_lifecycle.h"
#include "net/peer_scoring.h"
#include "net/peer_eviction.h"
#include "primitives/block.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_json.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "core/hash.h"
#include "core/random.h"
#include "core/utiltime.h"
#include "core/serialize.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "storage/sha3_sidecar_io.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "util/safe_alloc.h"
#include "net/file_market.h"
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#else
#define MSG_NOSIGNAL 0
#define MSG_DONTWAIT 0
#endif

/* --- net_message --- */
/*
 * Process-wide recv-queue byte budget.
 *
 * Per-message size is capped at 2 MB in net_message_read_data below,
 * but nothing prevented 1000 peers each feeding a 2 MB message into
 * our recv queue at the same time — 2 GB of kernel-invisible memory
 * pressure. This counter tracks the sum of every outstanding
 * msg->recv_alloc across all peers / messages and rejects new
 * allocations when adding them would push the total past the cap
 * (default 256 MiB, overridable via ZCL_MAX_RECVBUFFER_TOTAL_BYTES).
 *
 * Atomic so the common case (peer-thread read_data) needs no global
 * mutex. The cap is re-read from the environment on every check so
 * tests can tune it mid-process without a re-init hook.
 */
static _Atomic size_t g_recv_total_bytes = 0;
static struct log_throttle g_banned_accept_log = LOG_THROTTLE_INIT;

static size_t recv_total_bytes_cap(void)
{
    size_t cap = 256 * 1024 * 1024; /* 256 MiB default */
    const char *env = getenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES");
    if (env && *env) {
        char *endp = NULL;
        long long v = strtoll(env, &endp, 10);
        if (endp != env && v > 0 && (unsigned long long)v < SIZE_MAX)
            cap = (size_t)v;
    }
    return cap;
}

size_t net_recv_total_bytes(void)
{
    return atomic_load(&g_recv_total_bytes);
}

size_t net_recv_total_bytes_cap(void)
{
    return recv_total_bytes_cap();
}

/*
 * Process-wide send-queue byte budget — the symmetric mirror of the
 * recv budget above.
 *
 * Receive was already budgeted (g_recv_total_bytes), but SEND was not:
 * a single getdata for up to MAX_INV_SZ block hashes, or a slow-reader
 * peer that never drains its socket, would force us to buffer tens of
 * GB of send_segments -> OOM. This counter tracks the sum of every
 * live send_segment->size across all peers. process_getdata consults
 * it (and the per-peer node->send_size) to stop serving once over
 * budget (Core's fPauseSend behaviour) — it does NOT disconnect the
 * peer, which is within protocol and will simply re-request later.
 *
 * Charged in send_segment_create, released in send_segment_free, so
 * every path that frees a segment — socket drain, p2p_node_free, and
 * the connman forced-disconnect cleanup (which now calls
 * send_segment_free too) — returns its bytes to the budget. The
 * counter must therefore never leak on a forced disconnect.
 *
 * Default cap 512 MiB, overridable via ZCL_MAX_SENDBUFFER_TOTAL_BYTES.
 */
static _Atomic size_t g_send_total_bytes = 0;

static size_t send_total_bytes_cap(void)
{
    size_t cap = 512 * 1024 * 1024; /* 512 MiB default */
    const char *env = getenv("ZCL_MAX_SENDBUFFER_TOTAL_BYTES");
    if (env && *env) {
        char *endp = NULL;
        long long v = strtoll(env, &endp, 10);
        if (endp != env && v > 0 && (unsigned long long)v < SIZE_MAX)
            cap = (size_t)v;
    }
    return cap;
}

size_t net_send_total_bytes(void)
{
    return atomic_load(&g_send_total_bytes);
}

size_t net_send_total_bytes_cap(void)
{
    return send_total_bytes_cap();
}

bool net_send_over_budget(const struct p2p_node *node)
{
    /* Whitelisted / trusted peers are exempt — we never throttle them. */
    if (node && node->whitelisted)
        return false;

    /* Per-peer cap stops one slow reader from hoarding the whole budget;
     * the process-wide cap stops a swarm from doing the same in
     * aggregate. Either tripping pauses further serving. */
    if (node && node->send_size > net_send_peer_bytes_cap())
        return true;
    return atomic_load(&g_send_total_bytes) >= send_total_bytes_cap();
}

/* Realloc-failure counters for the two silent-drop growth sites further
 * down this file: p2p_node_push_address()'s addr_to_send buffer and
 * ban_addr_ex()'s ban list. Both used to `return;` on OOM with no log and
 * no counter — a dropped gossip address or (worse) a peer that should be
 * banned but silently isn't. Atomic so either site can bump from any
 * thread without a new lock. */
static _Atomic uint64_t g_net_addr_push_alloc_fail = 0;
static _Atomic uint64_t g_net_ban_alloc_fail = 0;

size_t net_send_peer_bytes_cap(void)
{
    size_t cap = 32 * 1024 * 1024; /* 32 MiB per peer default */
    const char *env = getenv("ZCL_MAX_SENDBUFFER_PEER_BYTES");
    if (env && *env) {
        char *endp = NULL;
        long long v = strtoll(env, &endp, 10);
        if (endp != env && v > 0 && (unsigned long long)v < SIZE_MAX)
            cap = (size_t)v;
    }
    return cap;
}

void net_message_init(struct net_message *msg,
                      const unsigned char msgstart[MESSAGE_START_SIZE])
{
    memset(msg, 0, sizeof(*msg));
    msg->in_data = false;
    msg->hdr_pos = 0;
    msg->data_pos = 0;
    msg->recv_data = NULL;
    msg->recv_alloc = 0;
    msg->time_usec = 0;
    memcpy(msg->expected_msgstart, msgstart, MESSAGE_START_SIZE);
    msg_header_init(&msg->hdr, msgstart);
}

void net_message_free(struct net_message *msg)
{
    if (msg->recv_data) {
        /* Return this message's bytes to the process-wide budget. */
        atomic_fetch_sub(&g_recv_total_bytes, msg->recv_alloc);
    }
    free(msg->recv_data);
    msg->recv_data = NULL;
    msg->recv_alloc = 0;
}

bool net_message_complete(const struct net_message *msg)
{
    if (!msg->in_data)
        return false;
    return msg->hdr.nMessageSize == msg->data_pos;
}

int net_message_read_header(struct net_message *msg,
                            const char *pch, unsigned int nbytes)
{
    unsigned int remaining = MSG_HEADER_SIZE - msg->hdr_pos;
    unsigned int copy = remaining < nbytes ? remaining : nbytes;

    memcpy(msg->hdr_buf + msg->hdr_pos, pch, copy);
    msg->hdr_pos += copy;

    if (msg->hdr_pos < MSG_HEADER_SIZE)
        return (int)copy;

    memcpy(&msg->hdr, msg->hdr_buf, MSG_HEADER_SIZE);

    /* Validate message start magic and size */
    if (memcmp(msg->hdr.pchMessageStart, msg->expected_msgstart,
               MESSAGE_START_SIZE) != 0)
        LOG_ERR("net", "message start magic mismatch");

    if (msg->hdr.nMessageSize > MAX_SIZE)
        LOG_ERR("net", "message size %u exceeds MAX_SIZE", msg->hdr.nMessageSize);

    msg->in_data = true;
    return (int)copy;
}

int net_message_read_data(struct net_message *msg,
                          const char *pch, unsigned int nbytes)
{
    unsigned int remaining = msg->hdr.nMessageSize - msg->data_pos;
    unsigned int copy = remaining < nbytes ? remaining : nbytes;

    /* Reject oversized messages BEFORE allocating.
     * MAX_PROTOCOL_MESSAGE_LENGTH = 2MB. An attacker sending a crafted
     * header with nMessageSize=2GB would cause OOM without this check. */
    if (msg->hdr.nMessageSize > 2 * 1024 * 1024) LOG_ERR("net", "message size %u exceeds 2MB limit", msg->hdr.nMessageSize);

    size_t needed = msg->data_pos + copy;
    if (msg->recv_alloc < needed) {
        size_t alloc = msg->hdr.nMessageSize;
        /* charge the delta against the process-wide recv budget
         * BEFORE reallocating. A swarm of peers each trying to stage a
         * 2 MB message must not be able to push our resident set past
         * the configured ceiling. */
        size_t delta = alloc - msg->recv_alloc;
        size_t cap = recv_total_bytes_cap();
        size_t prev = atomic_fetch_add(&g_recv_total_bytes, delta);
        if (prev + delta > cap) {
            atomic_fetch_sub(&g_recv_total_bytes, delta);
            LOG_ERR("net",
                    "recv queue budget exhausted: cap=%zu used=%zu add=%zu",
                    cap, prev, delta);
        }
        uint8_t *tmp = zcl_realloc(msg->recv_data, alloc, "msg_recv_data");
        if (!tmp) {
            atomic_fetch_sub(&g_recv_total_bytes, delta);
            LOG_ERR("net", "realloc failed for recv_data: size=%zu", alloc);
        }
        msg->recv_data = tmp;
        msg->recv_alloc = alloc;
    }

    memcpy(msg->recv_data + msg->data_pos, pch, copy);
    msg->data_pos += copy;
    return (int)copy;
}

/* --- send segment helpers --- */

static struct send_segment *send_segment_create(const uint8_t *data, size_t size)
{
    struct send_segment *seg = zcl_malloc(sizeof(*seg), "send_segment");
    if (!seg) LOG_NULL("net", "malloc failed for send_segment");
    seg->data = zcl_malloc(size, "send_segment_data");
    if (!seg->data) { free(seg); LOG_NULL("net", "malloc failed for send_segment_data: size=%zu", size); }
    memcpy(seg->data, data, size);
    seg->size = size;
    seg->next = NULL;
    /* Charge this segment against the process-wide send budget. Released
     * symmetrically in send_segment_free on every drain/disconnect path. */
    atomic_fetch_add(&g_send_total_bytes, size);
    return seg;
}

/* Exposed (declared in net.h) so the connman forced-disconnect cleanup
 * frees segments through the same path that releases the send budget,
 * instead of a raw free() that would leak g_send_total_bytes. */
void send_segment_free(struct send_segment *seg)
{
    if (!seg) return;
    /* Return this segment's bytes to the process-wide send budget. */
    atomic_fetch_sub(&g_send_total_bytes, seg->size);
    free(seg->data);
    free(seg);
}

/* --- p2p_node --- */

struct p2p_node *p2p_node_create(struct net_manager *nm, zcl_socket_t sock,
                                  const struct net_address *addr,
                                  const char *name, bool inbound)
{
    struct p2p_node *node = zcl_calloc(1, sizeof(*node), "p2p_node");
    if (!node) LOG_NULL("net", "calloc failed for p2p_node");

    node->socket = sock;
    node->addr = *addr;
    if (name && name[0]) {
        snprintf(node->addr_name, sizeof(node->addr_name), "%s", name);
    } else {
        char ipbuf[NET_ADDR_STR_MAX + 1];
        net_addr_to_string(&addr->svc.addr, ipbuf, sizeof(ipbuf));
        snprintf(node->addr_name, sizeof(node->addr_name), "%s:%u",
                 ipbuf, addr->svc.port);
    }

    node->state = inbound ? PEER_CONNECTED : PEER_CONNECTING;
    node->inbound = inbound;
    node->recv_version = INIT_PROTO_VERSION;
    node->time_connected = GetTime();
    int64_t connected_us = platform_time_monotonic_us();
    atomic_store_explicit(&node->connected_monotonic_us, connected_us,
                          memory_order_relaxed);
    atomic_store_explicit(&node->last_activity_monotonic_us, connected_us,
                          memory_order_relaxed);
    node->starting_height = -1;
    uint256_set_null(&node->hash_continue);
    net_service_init(&node->addr_local);

    zcl_mutex_init(&node->cs_send);
    zcl_mutex_init(&node->cs_recv);
    zcl_mutex_init(&node->cs_inventory);
    zcl_mutex_init(&node->cs_filter);

    rolling_bloom_init(&node->addr_known, 5000, 0.001);

    if (bip37_enabled()) {
        node->pfilter = zcl_calloc(1, sizeof(*node->pfilter), "bloom_filter");
        if (node->pfilter)
            bloom_filter_init(node->pfilter, 1, 0.0001, 0, BLOOM_UPDATE_NONE);
    } else {
        node->pfilter = NULL;
    }

    node->min_ping_usec_time = INT64_MAX;

    zcl_mutex_lock(&nm->cs_last_node_id);
    node->id = nm->last_node_id++;
    node->endpoint_generation = (uint64_t)(uint32_t)node->id + 1;
    zcl_mutex_unlock(&nm->cs_last_node_id);

    if (nm->signals.initialize_node)
        nm->signals.initialize_node(nm->signals.ctx, node->id, node);

    event_emitf(inbound ? EV_TCP_ACCEPTED : EV_TCP_CONNECTED,
                (uint32_t)node->id, "%s", node->addr_name);

    return node;
}

void p2p_node_free(struct p2p_node *node)
{
    if (!node) return;

    close_socket(&node->socket);

    zcl_mutex_lock(&node->cs_send);
    while (node->send_head) {
        struct send_segment *seg = node->send_head;
        node->send_head = seg->next;
        send_segment_free(seg);
    }
    zcl_mutex_unlock(&node->cs_send);

    zcl_mutex_lock(&node->cs_recv);
    for (size_t i = 0; i < node->recv_msg_count; i++)
        net_message_free(&node->recv_msgs[i]);
    node->recv_msg_count = 0;
    free(node->recv_msgs);
    node->recv_msgs = NULL;
    zcl_mutex_unlock(&node->cs_recv);

    free(node->addr_to_send);
    node->addr_to_send = NULL;
    free(node->inventory_to_send);
    node->inventory_to_send = NULL;
    free(node->inventory_known_hashes);
    node->inventory_known_hashes = NULL;
    free(node->askfor_set);
    node->askfor_set = NULL;
    free(node->askfor_map);
    node->askfor_map = NULL;

    if (node->pfilter) {
        bloom_filter_free(node->pfilter);
        free(node->pfilter);
        node->pfilter = NULL;
    }

    rolling_bloom_free(&node->addr_known);

    /* BIP152: free any pending compact block reconstruction */
    if (node->compact_pending_block) {
        block_free(node->compact_pending_block);
        free(node->compact_pending_block);
        node->compact_pending_block = NULL;
    }
    free(node->compact_missing_indices);
    node->compact_missing_indices = NULL;

    free(node->blk_bitmap);
    node->blk_bitmap = NULL;

    if (node->transport) {
        v2_transport_free(node->transport);
        node->transport = NULL;
    }

    zcl_mutex_destroy(&node->cs_send);
    zcl_mutex_destroy(&node->cs_recv);
    zcl_mutex_destroy(&node->cs_inventory);
    zcl_mutex_destroy(&node->cs_filter);

    free(node);
}

void p2p_node_add_ref(struct p2p_node *node)
{
    node->ref_count++;
}

void p2p_node_release(struct p2p_node *node)
{
    node->ref_count--;
}

int p2p_node_get_ref(struct p2p_node *node)
{
    return node->ref_count;
}

void p2p_node_close_socket(struct p2p_node *node)
{
    (void)p2p_node_request_disconnect(
        node, P2P_DISCONNECT_LOCAL_SHUTDOWN,
        P2P_DISCONNECT_SOURCE_SHUTDOWN,
        node ? node->endpoint_generation : 0);
    if (node->socket != ZCL_INVALID_SOCKET)
        close_socket(&node->socket);
}

const char *p2p_disconnect_reason_name(enum p2p_disconnect_reason reason)
{
    switch (reason) {
    case P2P_DISCONNECT_REMOTE_CLOSE: return "remote_close";
    case P2P_DISCONNECT_IO_ERROR: return "io_error";
    case P2P_DISCONNECT_TRANSPORT_ERROR: return "transport_error";
    case P2P_DISCONNECT_MESSAGE_PARSE: return "message_parse";
    case P2P_DISCONNECT_CONNECT_TIMEOUT: return "connect_timeout";
    case P2P_DISCONNECT_HANDSHAKE_TIMEOUT: return "handshake_timeout";
    case P2P_DISCONNECT_PONG_TIMEOUT: return "pong_timeout";
    case P2P_DISCONNECT_HARD_SILENCE: return "hard_silence";
    case P2P_DISCONNECT_PROTOCOL_VIOLATION: return "protocol_violation";
    case P2P_DISCONNECT_RESOURCE_LIMIT: return "resource_limit";
    case P2P_DISCONNECT_SYNC_STALL: return "sync_stall";
    case P2P_DISCONNECT_POLICY_ROTATION: return "policy_rotation";
    case P2P_DISCONNECT_FEELER_COMPLETE: return "feeler_complete";
    case P2P_DISCONNECT_FEELER_TIMEOUT: return "feeler_timeout";
    case P2P_DISCONNECT_SELF_CONNECTION: return "self_connection";
    case P2P_DISCONNECT_V2_UPGRADE: return "v2_upgrade";
    case P2P_DISCONNECT_EVICTED: return "evicted";
    case P2P_DISCONNECT_APPLICATION: return "application";
    case P2P_DISCONNECT_LOCAL_SHUTDOWN: return "local_shutdown";
    case P2P_DISCONNECT_NONE:
    default: return "unknown";
    }
}

const char *p2p_disconnect_source_name(enum p2p_disconnect_source source)
{
    switch (source) {
    case P2P_DISCONNECT_SOURCE_SOCKET: return "socket";
    case P2P_DISCONNECT_SOURCE_MESSAGE_HANDLER: return "message_handler";
    case P2P_DISCONNECT_SOURCE_KEEPALIVE: return "keepalive";
    case P2P_DISCONNECT_SOURCE_DIAL_SCHEDULER: return "dial_scheduler";
    case P2P_DISCONNECT_SOURCE_SYNC: return "sync";
    case P2P_DISCONNECT_SOURCE_PEER_POLICY: return "peer_policy";
    case P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR: return "resource_governor";
    case P2P_DISCONNECT_SOURCE_APPLICATION: return "application";
    case P2P_DISCONNECT_SOURCE_SHUTDOWN: return "shutdown";
    case P2P_DISCONNECT_SOURCE_UNKNOWN:
    default: return "unknown";
    }
}

/* One emitter for every close line, so the "peer_connected" open line always
 * has a partner in node.log. Fields mirror that line's style: addr first, then
 * peer_id, then the cause. `state` is the state the session actually reached,
 * which is what separates "never handshaked" from "was syncing and dropped" —
 * the distinction no reader could make while the close side was invisible.
 * See net.h for the event-name contract. */
void p2p_log_peer_close(const struct p2p_node *node, const char *event,
                        enum p2p_disconnect_reason reason,
                        enum p2p_disconnect_source source)
{
    if (!node || !event)
        return;

    char addr_safe[96];
    log_json_escape(addr_safe, sizeof(addr_safe), node->addr_name);

    /* Lifetime is wall-clock seconds since the socket was created. A clock
     * step backwards must not print a negative age. */
    int64_t now = GetTime();
    long long lifetime = 0;
    if (node->time_connected > 0 && now > node->time_connected)
        lifetime = (long long)(now - node->time_connected);

    log_jsonf(LOG_JSON_INFO, event,
              "\"addr\":\"%s\",\"peer_id\":%d,\"inbound\":%s,"
              "\"state\":\"%s\",\"reason\":\"%s\",\"source\":\"%s\","
              "\"version\":%d,\"misbehavior\":%d,\"lifetime_secs\":%lld,"
              "\"endpoint_generation\":%llu",
              addr_safe, (int)node->id,
              node->inbound ? "true" : "false",
              peer_state_name(node->state),
              p2p_disconnect_reason_name(reason),
              p2p_disconnect_source_name(source),
              node->version, node->misbehavior, lifetime,
              (unsigned long long)node->endpoint_generation);
}

bool p2p_node_request_disconnect(
    struct p2p_node *node, enum p2p_disconnect_reason reason,
    enum p2p_disconnect_source source, uint64_t endpoint_generation)
{
    if (!node || reason <= P2P_DISCONNECT_NONE)
        return false;
    if (endpoint_generation != 0 &&
        endpoint_generation != node->endpoint_generation)
        return false;

    int expected = P2P_DISCONNECT_NONE;
    if (!atomic_compare_exchange_strong_explicit(
            &node->disconnect_reason, &expected, (int)reason,
            memory_order_acq_rel, memory_order_acquire))
        return false;

    atomic_store_explicit(&node->disconnect_source, (int)source,
                          memory_order_relaxed);
    atomic_store_explicit(&node->disconnect_endpoint_generation,
                          node->endpoint_generation, memory_order_relaxed);
    atomic_store_explicit(&node->disconnect, true, memory_order_release);
    return true;
}

bool p2p_node_receive_bytes(struct p2p_node *node, const char *data,
                             unsigned int nbytes,
                             const unsigned char msgstart[MESSAGE_START_SIZE])
{
    if (net_partition_active_at((int64_t)platform_time_wall_time_t()))
        return true;

    unsigned int orig_nbytes = nbytes;
    int msg_idx = 0;
    while (nbytes > 0) {
        if (node->recv_msg_count >= MAX_RECV_MESSAGES)
            LOG_FAIL("net", "recv queue full: count=%zu max=%d", node->recv_msg_count, MAX_RECV_MESSAGES);
        if (node->recv_msg_count == 0 ||
            net_message_complete(&node->recv_msgs[node->recv_msg_count - 1])) {
            /* Enforce message queue limit — prevents OOM from fast senders */
            if (node->recv_msg_count >= MAX_RECV_MESSAGES) {
                event_emitf(EV_PEER_MISBEHAVE, (uint32_t)node->id,
                            "recv queue full (%zu msgs)", node->recv_msg_count);
                LOG_FAIL("net", "recv queue full after recheck: count=%zu", node->recv_msg_count);
            }
            if (node->recv_msg_count >= node->recv_msg_cap) {
                size_t newcap = node->recv_msg_cap ? node->recv_msg_cap * 2 : 16;
                if (newcap > MAX_RECV_MESSAGES) newcap = MAX_RECV_MESSAGES;
                struct net_message *tmp = zcl_realloc(node->recv_msgs,
                                                   newcap * sizeof(*tmp), "recv_msgs");
                if (!tmp) LOG_FAIL("net", "realloc failed for recv_msgs: newcap=%zu", newcap);
                node->recv_msgs = tmp;
                node->recv_msg_cap = newcap;
            }
            net_message_init(&node->recv_msgs[node->recv_msg_count], msgstart);
            node->recv_msg_count++;
        }

        struct net_message *msg = &node->recv_msgs[node->recv_msg_count - 1];
        int handled;
        if (!msg->in_data)
            handled = net_message_read_header(msg, data, nbytes);
        else
            handled = net_message_read_data(msg, data, nbytes);

        if (handled < 0) {
            /* Tag the framing offence for peer scoring. The parse functions
             * have no net_manager back-pointer, so classification happens here
             * from the message phase: read_header returns -1 BEFORE setting
             * msg->in_data (bad start-magic / size > MAX_SIZE => a header-level
             * offence, weight 50), whereas read_data returns -1 with in_data
             * already set (payload over MAX_PROTOCOL_MESSAGE_LENGTH / budget /
             * realloc => a payload offence, weight 20). The connman receive
             * caller drains + scores this exactly once. */
            atomic_store(&node->framing_offence,
                         msg->in_data ? (int)PEER_OFFENCE_INVALID_PAYLOAD
                                      : (int)PEER_OFFENCE_INVALID_HEADER);
            printf("  PARSE FAIL at msg_idx=%d offset=%u/%u in_data=%d "
                   "hdr_pos=%u data_pos=%u nMessageSize=%u "
                   "next4: %02x%02x%02x%02x\n",
                   msg_idx, orig_nbytes - nbytes, orig_nbytes,
                   msg->in_data, msg->hdr_pos, msg->data_pos,
                   msg->hdr.nMessageSize,
                   (unsigned char)data[0],
                   nbytes>1?(unsigned char)data[1]:0,
                   nbytes>2?(unsigned char)data[2]:0,
                   nbytes>3?(unsigned char)data[3]:0);
            LOG_FAIL("net", "message parse failed at msg_idx=%d offset=%u/%u", msg_idx, orig_nbytes - nbytes, orig_nbytes);
        }

        if (msg->in_data && msg->hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
            /* Belt-and-suspenders post-parse oversize check: the payload
             * exceeds the 2 MB protocol cap. Tag it as a payload offence so
             * the connman drain scores the peer before we drop the frame. */
            atomic_store(&node->framing_offence, (int)PEER_OFFENCE_INVALID_PAYLOAD);
            char dcmd[COMMAND_SIZE + 1];
            msg_header_get_command(&msg->hdr, dcmd, sizeof(dcmd));
            printf("Dropped oversized '%s' message: %u bytes > %u\n",
                   dcmd, msg->hdr.nMessageSize, MAX_PROTOCOL_MESSAGE_LENGTH);
            LOG_FAIL("net", "oversized message '%s': %u bytes > %u", dcmd, msg->hdr.nMessageSize, MAX_PROTOCOL_MESSAGE_LENGTH);
        }

        data += handled;
        nbytes -= (unsigned int)handled;
        msg_idx++;

        if (net_message_complete(msg)) {
            msg->time_usec = GetTimeMicros();
        }
    }
    return true;
}

void p2p_node_score_framing_offence(struct net_manager *nm,
                                    struct p2p_node *node)
{
    if (!nm || !node)
        return;
    /* Atomic exchange: read-and-clear so a single abusive frame is scored
     * exactly once and a reconnecting peer that repeats the abuse keeps
     * accruing toward the ban threshold. */
    int offence = atomic_exchange(&node->framing_offence,
                                  (int)PEER_OFFENCE_NONE);
    if (offence != (int)PEER_OFFENCE_NONE)
        peer_scoring_record(nm, node, (enum peer_offence)offence,
                            "framing layer");
}

void p2p_node_copy_stats(const struct p2p_node *node, struct node_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    stats->nodeid = node->id;
    stats->services = node->services;
    stats->last_send = node->last_send;
    stats->last_recv = node->last_recv;
    stats->time_connected = node->time_connected;
    stats->time_offset = node->time_offset;
    snprintf(stats->addr_name, sizeof(stats->addr_name), "%s", node->addr_name);
    stats->version = node->version;
    snprintf(stats->clean_sub_ver, sizeof(stats->clean_sub_ver), "%s",
             node->clean_sub_ver);
    stats->inbound = node->inbound;
    stats->starting_height = node->starting_height;
    stats->send_bytes = node->send_bytes;
    stats->recv_bytes = node->recv_bytes;
    stats->whitelisted = node->whitelisted;

    int64_t ping_wait = 0;
    if (node->ping_nonce_sent != 0 && node->ping_usec_start != 0)
        ping_wait = GetTimeMicros() - node->ping_usec_start;

    stats->ping_time = (double)node->ping_usec_time / 1e6;
    stats->ping_wait = (double)ping_wait / 1e6;

    if (net_addr_is_valid(&node->addr_local.addr)) {
        char buf[NET_ADDR_STR_MAX + 1];
        net_addr_to_string(&node->addr_local.addr, buf, sizeof(buf));
        snprintf(stats->addr_local, sizeof(stats->addr_local), "%s:%u",
                 buf, node->addr_local.port);
    }
}

void p2p_node_push_address(struct p2p_node *node, const struct net_address *addr)
{
    unsigned char key[NET_SERVICE_KEY_SIZE];
    net_service_get_key(&addr->svc, key);
    if (!net_addr_is_valid(&addr->svc.addr) ||
        rolling_bloom_contains(&node->addr_known, key, NET_SERVICE_KEY_SIZE))
        return;

    if (node->addr_to_send_count >= MAX_ADDR_TO_SEND) {
        uint64_t idx;
        GetRandBytes((unsigned char *)&idx, sizeof(idx));
        node->addr_to_send[idx % node->addr_to_send_count] = *addr;
    } else {
        if (node->addr_to_send_count >= node->addr_to_send_cap) {
            size_t newcap = node->addr_to_send_cap ? node->addr_to_send_cap * 2 : 64;
            struct net_address *tmp = zcl_realloc(node->addr_to_send,
                                               newcap * sizeof(*tmp), "addr_to_send");
            if (!tmp) {
                atomic_fetch_add(&g_net_addr_push_alloc_fail, 1);
                LOG_ERROR("net",
                          "p2p_node_push_address: addr_to_send realloc(%zu) "
                          "failed for peer=%s — address dropped",
                          newcap * sizeof(*tmp), node->addr_name);
                return;
            }
            node->addr_to_send = tmp;
            node->addr_to_send_cap = newcap;
        }
        node->addr_to_send[node->addr_to_send_count++] = *addr;
    }
}

void p2p_node_add_inventory_known(struct p2p_node *node, const struct inv_item *inv)
{
    zcl_mutex_lock(&node->cs_inventory);
    if (node->inventory_known_count >= node->inventory_known_cap) {
        size_t newcap = node->inventory_known_cap ? node->inventory_known_cap * 2 : 1024;
        if (newcap > MAX_INVENTORY_KNOWN) newcap = MAX_INVENTORY_KNOWN;
        if (node->inventory_known_count >= newcap) {
            memmove(node->inventory_known_hashes,
                    node->inventory_known_hashes + newcap / 2,
                    (newcap / 2) * sizeof(struct uint256));
            node->inventory_known_count = newcap / 2;
        } else {
            struct uint256 *tmp = zcl_realloc(node->inventory_known_hashes,
                                           newcap * sizeof(*tmp), "inv_known_hashes");
            if (!tmp) { zcl_mutex_unlock(&node->cs_inventory); return; }
            node->inventory_known_hashes = tmp;
            node->inventory_known_cap = newcap;
        }
    }
    node->inventory_known_hashes[node->inventory_known_count++] = inv->hash;
    zcl_mutex_unlock(&node->cs_inventory);
}

static bool inventory_known_contains(struct p2p_node *node,
                                      const struct uint256 *hash)
{
    for (size_t i = 0; i < node->inventory_known_count; i++)
        if (uint256_eq(&node->inventory_known_hashes[i], hash))
            return true;
    return false;
}

void p2p_node_push_inventory(struct p2p_node *node, const struct inv_item *inv)
{
    zcl_mutex_lock(&node->cs_inventory);
    if (!inventory_known_contains(node, &inv->hash)) {
        if (node->inventory_to_send_count >= node->inventory_to_send_cap) {
            size_t newcap = node->inventory_to_send_cap ?
                            node->inventory_to_send_cap * 2 : 256;
            struct inv_item *tmp = zcl_realloc(node->inventory_to_send,
                                            newcap * sizeof(*tmp), "inv_to_send");
            if (!tmp) { zcl_mutex_unlock(&node->cs_inventory); return; }
            node->inventory_to_send = tmp;
            node->inventory_to_send_cap = newcap;
        }
        node->inventory_to_send[node->inventory_to_send_count++] = *inv;
    }
    zcl_mutex_unlock(&node->cs_inventory);
}

/* --- message building (byte_stream based send buffer) --- */

static _Thread_local struct byte_stream tls_msg_stream;
static _Thread_local bool tls_msg_active = false;

bool p2p_node_begin_message(struct p2p_node *node, const char *command,
                             const unsigned char msgstart[MESSAGE_START_SIZE])
{
    zcl_mutex_lock(&node->cs_send);
    stream_init(&tls_msg_stream, 256);
    tls_msg_active = true;

    struct msg_header hdr;
    msg_header_init_full(&hdr, msgstart, command, 0);
    stream_write(&tls_msg_stream, (const uint8_t *)&hdr, MSG_HEADER_SIZE);
    return true;
}

void p2p_node_write_message_data(struct p2p_node *node,
                                  const uint8_t *data, size_t len)
{
    (void)node;
    if (tls_msg_active)
        stream_write(&tls_msg_stream, data, len);
}

bool p2p_node_end_message(struct p2p_node *node)
{
    if (!tls_msg_active) {
        zcl_mutex_unlock(&node->cs_send);
        LOG_FAIL("net", "end_message called without active tls_msg");
    }

    size_t total = tls_msg_stream.size;
    if (total == 0 || tls_msg_stream.error) {
        stream_free(&tls_msg_stream);
        tls_msg_active = false;
        zcl_mutex_unlock(&node->cs_send);
        LOG_FAIL("net", "message stream empty or error: size=%zu error=%d", total, tls_msg_stream.error);
    }

    uint8_t *buf = tls_msg_stream.data;

    unsigned int payload_size = (unsigned int)(total - MSG_HEADER_SIZE);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE] = (uint8_t)(payload_size & 0xff);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 1] = (uint8_t)((payload_size >> 8) & 0xff);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 2] = (uint8_t)((payload_size >> 16) & 0xff);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 3] = (uint8_t)((payload_size >> 24) & 0xff);

    struct uint256 hash;
    hash256(buf + MSG_HEADER_SIZE, total - MSG_HEADER_SIZE, hash.data);
    memcpy(buf + MESSAGE_START_SIZE + COMMAND_SIZE + 4, hash.data, 4);

    /* Log every outbound message — extract command from header */
    {
        char cmd[COMMAND_SIZE + 1];
        memcpy(cmd, buf + MESSAGE_START_SIZE, COMMAND_SIZE);
        cmd[COMMAND_SIZE] = '\0';
        /* Trim trailing nulls for clean display */
        for (int ci = COMMAND_SIZE - 1; ci >= 0 && cmd[ci] == '\0'; ci--)
            cmd[ci] = '\0';
        event_emitf(EV_MSG_SENT, (uint32_t)node->id,
                    "%s size=%u", cmd, payload_size);
    }

    /* v2 transport seam: seal below the message layer. The plaintext path
     * (transport == NULL) is the UNCHANGED else — byte-for-byte v1 wire. */
    struct send_segment *seg;
    if (node->transport) {
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        if (!v2_transport_write(node->transport, buf, total, &ct, &ct_len)) {
            free(ct);
            stream_free(&tls_msg_stream);
            tls_msg_active = false;
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_TRANSPORT_ERROR,
                P2P_DISCONNECT_SOURCE_MESSAGE_HANDLER,
                node->endpoint_generation);
            zcl_mutex_unlock(&node->cs_send);
            LOG_FAIL("net", "v2 transport write failed node id=%d", (int)node->id);
        }
        stream_free(&tls_msg_stream);
        tls_msg_active = false;
        if (ct_len == 0) {
            /* Buffered during handshake — nothing to put on the wire yet;
             * it is sealed and flushed when the handshake completes. */
            free(ct);
            zcl_mutex_unlock(&node->cs_send);
            return true;
        }
        seg = send_segment_create(ct, ct_len);
        free(ct);
    } else {
        seg = send_segment_create(buf, total);
        stream_free(&tls_msg_stream);
        tls_msg_active = false;
    }

    if (!seg) {
        zcl_mutex_unlock(&node->cs_send);
        LOG_FAIL("net", "send_segment_create failed for node id=%d", (int)node->id);
    }

    if (node->send_tail) {
        node->send_tail->next = seg;
        node->send_tail = seg;
    } else {
        node->send_head = seg;
        node->send_tail = seg;
    }
    node->send_size += seg->size;

    if (node->send_head == seg)
        socket_send_data(node);

    zcl_mutex_unlock(&node->cs_send);
    return true;
}

/* Queue raw bytes (handshake messages, or records already sealed by the v2
 * transport) verbatim onto the node's send stream. Mirrors the tail of
 * p2p_node_end_message but performs no framing/sealing. Lock order: callers on
 * the recv path hold cs_recv first, then this acquires cs_send. */
void p2p_node_queue_raw(struct p2p_node *node, const uint8_t *bytes, size_t len)
{
    if (!node || !bytes || len == 0)
        return;

    zcl_mutex_lock(&node->cs_send);
    struct send_segment *seg = send_segment_create(bytes, len);
    if (!seg) {
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_RESOURCE_LIMIT,
            P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
            node->endpoint_generation);
        zcl_mutex_unlock(&node->cs_send);
        LOG_WARN("net", "p2p_node_queue_raw: send_segment_create failed node id=%d",
                 (int)node->id);
        return;
    }
    if (node->send_tail) {
        node->send_tail->next = seg;
        node->send_tail = seg;
    } else {
        node->send_head = seg;
        node->send_tail = seg;
    }
    node->send_size += seg->size;
    if (node->send_head == seg)
        socket_send_data(node);
    zcl_mutex_unlock(&node->cs_send);
}

/* --- socket_send_data --- */

void socket_send_data(struct p2p_node *node)
{
    while (node->send_head) {
        struct send_segment *seg = node->send_head;
        size_t remain = seg->size - node->send_offset;

        ssize_t sent = send(node->socket,
                            (const char *)(seg->data + node->send_offset),
                            remain, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent > 0) {
            node->last_send = GetTime();
            node->send_bytes += (uint64_t)sent;
            node->send_offset += (size_t)sent;

            if (node->send_offset >= seg->size) {
                node->send_head = seg->next;
                if (!node->send_head)
                    node->send_tail = NULL;
                node->send_size -= seg->size;
                node->send_offset = 0;
                send_segment_free(seg);
            } else {
                break;
            }
        } else {
            if (sent < 0) {
                int err = errno;
                if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR && err != EINPROGRESS)
                    p2p_node_close_socket(node);
            }
            break;
        }
    }
}

/* --- net_manager --- */

void net_manager_init(struct net_manager *nm)
{
    memset(nm, 0, sizeof(*nm));
    nm->discover = true;
    nm->listen = true;
    nm->local_services = NODE_NETWORK;
    nm->max_connections = DEFAULT_MAX_PEER_CONNECTIONS;
    nm->stop_requested = false;

    addrman_init(&nm->addrman);

    zcl_mutex_init(&nm->cs_nodes);
    zcl_mutex_init(&nm->cs_local_host);
    zcl_mutex_init(&nm->cs_banned);
    zcl_mutex_init(&nm->cs_last_node_id);
    zcl_mutex_init(&nm->cs_total_bytes_recv);
    zcl_mutex_init(&nm->cs_total_bytes_sent);
    zcl_cond_init(&nm->msg_handler_cond);
    zcl_mutex_init(&nm->msg_handler_mutex);
}

void net_manager_free(struct net_manager *nm)
{
    for (size_t i = 0; i < nm->num_listen_sockets; i++)
        if (nm->listen_sockets[i].socket != ZCL_INVALID_SOCKET)
            close_socket(&nm->listen_sockets[i].socket);
    free(nm->listen_sockets);

    /* Teardown is a removal path like any other: a peer still in nodes[] here
     * was never swept, so without this line every live session disappears
     * from node.log at shutdown with no record. Report the causal reason when
     * one was already latched (a peer flagged but not yet swept), otherwise
     * local_shutdown. */
    for (size_t i = 0; i < nm->num_nodes; i++) {
        struct p2p_node *node = nm->nodes[i];
        enum p2p_disconnect_reason reason =
            (enum p2p_disconnect_reason)atomic_load_explicit(
                &node->disconnect_reason, memory_order_acquire);
        enum p2p_disconnect_source source =
            (enum p2p_disconnect_source)atomic_load_explicit(
                &node->disconnect_source, memory_order_relaxed);
        if (reason <= P2P_DISCONNECT_NONE) {
            reason = P2P_DISCONNECT_LOCAL_SHUTDOWN;
            source = P2P_DISCONNECT_SOURCE_SHUTDOWN;
        }
        p2p_log_peer_close(node, "peer_disconnected", reason, source);
        p2p_node_free(node);
    }
    free(nm->nodes);

    for (size_t i = 0; i < nm->num_disconnected; i++)
        p2p_node_free(nm->nodes_disconnected[i]);
    free(nm->nodes_disconnected);

    free(nm->local_hosts);
    free(nm->local_host_info);
    free(nm->banned);
    free(nm->whitelisted);
    free(nm->whitelist_prefix);

    addrman_free(&nm->addrman);

    zcl_mutex_destroy(&nm->cs_nodes);
    zcl_mutex_destroy(&nm->cs_local_host);
    zcl_mutex_destroy(&nm->cs_banned);
    zcl_mutex_destroy(&nm->cs_last_node_id);
    zcl_mutex_destroy(&nm->cs_total_bytes_recv);
    zcl_mutex_destroy(&nm->cs_total_bytes_sent);
    zcl_cond_destroy(&nm->msg_handler_cond);
    zcl_mutex_destroy(&nm->msg_handler_mutex);
}

/* --- find node --- */

/* Find a matching, NON-disconnect node and take a ref on it atomically under
 * cs_nodes. Returns the node with ref_count already incremented, or NULL.
 *
 * connect_node runs on a different thread (RPC addnode -> connman_open_
 * connection) than the socket disconnect sweep, which calls p2p_node_free()
 * the instant ref_count hits 0. A plain find that unlocks cs_nodes before
 * returning, then takes the add_ref afterwards, is a TOCTOU use-after-free:
 * the node can be freed in the gap. Keeping the find + add_ref inside one
 * cs_nodes acquire closes that window, and skipping disconnect-flagged nodes
 * avoids re-reffing a peer the sweep is about to reap. */
static struct p2p_node *find_node_by_service_locked(struct net_manager *nm,
                                                    const struct net_service *addr)
{
    struct p2p_node *existing = NULL;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < nm->num_nodes; i++) {
        if (net_addr_eq(&nm->nodes[i]->addr.svc.addr, &addr->addr) &&
            nm->nodes[i]->addr.svc.port == addr->port &&
            !nm->nodes[i]->disconnect) {
            existing = nm->nodes[i];
            p2p_node_add_ref(existing);
            break;
        }
    }
    zcl_mutex_unlock(&nm->cs_nodes);
    return existing;
}

/* --- add node to manager --- */

static bool nm_add_node(struct net_manager *nm, struct p2p_node *node)
{
    if (nm->num_nodes >= nm->nodes_cap) {
        size_t newcap = nm->nodes_cap ? nm->nodes_cap * 2 : 32;
        struct p2p_node **tmp = zcl_realloc(nm->nodes, newcap * sizeof(*tmp), "node_list");
        if (!tmp) LOG_FAIL("net", "realloc failed for node_list: newcap=%zu", newcap);
        nm->nodes = tmp;
        nm->nodes_cap = newcap;
    }
    nm->nodes[nm->num_nodes++] = node;
    return true;
}

/* --- connect_node ---
 *
 * SYMMETRIC-REF CONTRACT: connect_node ALWAYS returns either NULL or a node
 * with a +1 CALLER-owned ref. The caller MUST release that ref under cs_nodes
 * once it has finished deref'ing the node (see connman.c
 * connman_release_connect_node_ref). This closes two bugs at once:
 *   - UAF: previously the new-node path published the node at ref==1 (manager
 *     ref only) and returned a bare pointer; between the return and the
 *     dialer's peer_lifecycle_note_connected deref, the socket thread could
 *     recv POLLHUP -> disconnect -> reap -> free, and the dialer read freed
 *     memory. The extra CALLER ref pins the node across that window.
 *   - LEAK: the dedupe path returns find_node_by_service_locked's +1 ref;
 *     before this contract no caller released it, so on disconnect the reap
 *     saw ref>0 and parked the node in deferred_free forever. Now every caller
 *     releases symmetrically, so deduped returns are balanced too. */

struct p2p_node *connect_node_from_socket(struct net_manager *nm,
                                          struct net_address *addr_connect,
                                          const char *dest,
                                          zcl_socket_t sock,
                                          bool *created_out)
{
    if (created_out)
        *created_out = false;
    /* Re-dedupe under the SAME cs_nodes acquire that publishes the new node.
     * The up-front dedupe in connect_node (or the connman dialer's
     * already-connected gate) can lose a race: a duplicate connection to this
     * service may have completed while our dial was in flight — the whole
     * point of the parallel dialer is many in-flight dials at once. If a peer
     * for this service now exists, close OUR socket and hand back the existing
     * node with find_node_by_service_locked's +1 ref, preserving the
     * symmetric-ref contract (the caller releases exactly one ref either way).
     * `created_out` distinguishes a fresh node from this dedupe path so the
     * caller never mislabels an already-connected real peer (e.g. as a
     * feeler). */
    struct p2p_node *existing = find_node_by_service_locked(nm, &addr_connect->svc);
    if (existing) {
        close_socket(&sock);
        return existing;
    }

    struct p2p_node *node = p2p_node_create(nm, sock, addr_connect,
                                             dest ? dest : "", false);
    if (!node) {
        close_socket(&sock);
        LOG_NULL("net", "p2p_node_create failed for outbound connection");
    }

    /* v2 transport (default OFF): arm as INITIATOR when enabled and the peer's
     * advertised services carry NODE_V2TRANSPORT. Queues msg1 (`-> e`) raw; the
     * subsequent push_version rides sealed once the handshake completes. */
    if (nm->v2_enabled && (addr_connect->nServices & NODE_V2TRANSPORT)) {
        uint8_t *msg1 = NULL;
        size_t msg1_len = 0;
        node->transport = v2_transport_begin(true, nm->identity_priv,
                                             nm->message_start, &msg1, &msg1_len);
        if (node->transport && msg1_len)
            p2p_node_queue_raw(node, msg1, msg1_len);
        free(msg1);
    }

    /* Symmetric-ref contract: connect_node ALWAYS returns a +1 caller-owned
     * ref (matching the dedupe path, which returns the ref taken by
     * find_node_by_service_locked). Take TWO refs under the SAME cs_nodes
     * acquire that publishes the node into nodes[]: one MANAGER ref (released
     * by the reap sweep when the node leaves nodes[]) and one CALLER ref. With
     * ref_count==2 at publish time, the socket sweep can flag disconnect and
     * reap the manager ref concurrently (2->1) but cannot drive the node to 0
     * and free it under the caller. The caller drops its ref under cs_nodes
     * once it has finished deref'ing the node (peer_lifecycle_note_connected
     * etc), freeing it there iff that release brings ref to 0. */
    zcl_mutex_lock(&nm->cs_nodes);
    p2p_node_add_ref(node); /* MANAGER ref */
    p2p_node_add_ref(node); /* CALLER ref — released by connect_node's caller */
    nm_add_node(nm, node);
    zcl_mutex_unlock(&nm->cs_nodes);

    node->time_connected = GetTime();
    if (created_out)
        *created_out = true;

    /* Open line. `addr_name` — not the raw service string — because that is
     * the identity every close line, event and warning uses for this peer; a
     * reader pairing open with close must not have to reconcile two spellings
     * of the same endpoint (an addnode dest override differs from the service
     * string, and IPv6 brackets differ too). */
    char addr_safe[96];
    log_json_escape(addr_safe, sizeof(addr_safe), node->addr_name);
    log_jsonf(LOG_JSON_INFO, "peer_connected",
              "\"addr\":\"%s\",\"peer_id\":%d,\"inbound\":false",
              addr_safe, (int)node->id);
    return node;
}

struct p2p_node *connect_node(struct net_manager *nm,
                               struct net_address *addr_connect,
                               const char *dest)
{
    if (!dest && is_local(nm, &addr_connect->svc))
        LOG_NULL("net", "refusing connection to local address");

    /* Always dedupe by remote service, even for addnode/localhost connects.
     * The dest override exists to skip the localhost rejection, not to allow
     * parallel duplicate sockets to the same peer. Duplicate addnode sockets
     * cause repeated getheaders loops and can split one-shot fast-sync offers
     * across multiple connections. (connect_node_from_socket re-checks under
     * the publish lock to close the residual race.) */
    struct p2p_node *existing = find_node_by_service_locked(nm, &addr_connect->svc);
    if (existing)
        return existing;

    zcl_socket_t sock;
    bool sock_ok;
    if (net_addr_is_tor(&addr_connect->svc.addr)) {
        /* Onion endpoints never touch connect(2): the raw dynhost stream
         * rides an in-process Tor circuit and surfaces here as a bridged
         * socket fd. Fails closed (never a clearnet fallback) with its own
         * named error when the Tor runtime is absent or not ready. Circuit
         * builds need their own budget — the shared 5 s clearnet window is
         * far short of the 10-60 s a cold circuit takes. */
        sock_ok = onion_stream_connect(&addr_connect->svc, &sock,
                                       ONION_STREAM_CONNECT_TIMEOUT_MS);
    } else {
        sock_ok = connect_socket_directly(&addr_connect->svc, &sock,
                                          DEFAULT_CONNECT_TIMEOUT);
    }
    if (!sock_ok) {
        char addr_str[NET_SERVICE_STR_MAX + 1];
        net_service_to_string(&addr_connect->svc, addr_str, sizeof(addr_str));
        char addr_safe[96];
        log_json_escape(addr_safe, sizeof(addr_safe), addr_str);
        log_jsonf(LOG_JSON_WARN, "peer_connect_failed",
                  "\"addr\":\"%s\"", addr_safe);
        return NULL;
    }

    return connect_node_from_socket(nm, addr_connect, dest, sock, NULL);
}

/* --- ban management --- */

bool is_banned(struct net_manager *nm, const struct net_addr *addr)
{
    /* Localhost is NEVER banned — it's our own zclassicd */
    static const uint8_t lo_prefix[13] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,127};
    if (memcmp(addr->ip, lo_prefix, 13) == 0)
        return false;

    zcl_mutex_lock(&nm->cs_banned);
    int64_t now = GetTime();
    bool found = false;
    /* Lazy prune: while scanning for `addr`, swap-remove any entry whose
     * ban_until has already passed. No separate sweep thread/timer is
     * needed — every is_banned() call (the accept-inbound and outbound-
     * candidate paths both call it) gradually shrinks the table. This
     * does NOT rewrite banlist.dat on disk; the file self-heals to drop
     * expired rows the next time ban_addr()/unban_addr()/clear_banned()
     * calls ban_db_write(), which already filters by ban_until > now. */
    size_t i = 0;
    while (i < nm->num_banned) {
        if (now >= nm->banned[i].ban_until) {
            nm->banned[i] = nm->banned[nm->num_banned - 1];
            nm->num_banned--;
            continue; /* re-check the swapped-in entry at the same index */
        }
        if (net_addr_eq(&nm->banned[i].addr, addr)) {
            found = true;
            break;
        }
        i++;
    }
    zcl_mutex_unlock(&nm->cs_banned);
    return found;
}

/* Shared implementation behind ban_addr() (external/manual bans, score=0)
 * and peer_misbehaving()'s auto-ban (real score + offence reason). Persists
 * to banlist.dat when nm->datadir is set (see connman_load_addrman()). */
static void ban_addr_ex(struct net_manager *nm, const struct net_addr *addr,
                        int64_t ban_offset, bool since_epoch,
                        int32_t score_at_ban, const char *reason)
{
    int64_t ban_time = GetTime() + 24 * 60 * 60;
    if (ban_offset > 0)
        ban_time = (since_epoch ? 0 : GetTime()) + ban_offset;

    zcl_mutex_lock(&nm->cs_banned);
    for (size_t i = 0; i < nm->num_banned; i++) {
        if (net_addr_eq(&nm->banned[i].addr, addr)) {
            if (nm->banned[i].ban_until < ban_time)
                nm->banned[i].ban_until = ban_time;
            nm->banned[i].score_at_ban = score_at_ban;
            snprintf(nm->banned[i].reason, sizeof(nm->banned[i].reason),
                     "%s", reason ? reason : "");
            zcl_mutex_unlock(&nm->cs_banned);
            if (nm->datadir) ban_db_write(nm, nm->datadir);
            return;
        }
    }

    if (nm->num_banned >= nm->banned_cap) {
        size_t newcap = nm->banned_cap ? nm->banned_cap * 2 : 64;
        struct ban_entry *tmp = zcl_realloc(nm->banned, newcap * sizeof(*tmp), "ban_list");
        if (!tmp) {
            zcl_mutex_unlock(&nm->cs_banned);
            atomic_fetch_add(&g_net_ban_alloc_fail, 1);
            LOG_ERROR("net",
                      "ban_addr_ex: ban_list realloc(%zu) failed — peer "
                      "NOT recorded as banned (reason=%s)",
                      newcap * sizeof(*tmp), reason ? reason : "");
            return;
        }
        nm->banned = tmp;
        nm->banned_cap = newcap;
    }
    nm->banned[nm->num_banned].addr = *addr;
    nm->banned[nm->num_banned].prefix_len = net_addr_is_ipv4(addr) ? 32 : 128;
    nm->banned[nm->num_banned].ban_until = ban_time;
    nm->banned[nm->num_banned].score_at_ban = score_at_ban;
    snprintf(nm->banned[nm->num_banned].reason,
             sizeof(nm->banned[nm->num_banned].reason), "%s", reason ? reason : "");
    nm->num_banned++;
    zcl_mutex_unlock(&nm->cs_banned);

    if (nm->datadir) ban_db_write(nm, nm->datadir);
}

void ban_addr(struct net_manager *nm, const struct net_addr *addr,
              int64_t ban_offset, bool since_epoch)
{
    ban_addr_ex(nm, addr, ban_offset, since_epoch, 0, "manual");
}

/* Check if a peer is a trusted local node (localhost or whitelisted).
 * These peers are NEVER banned — they are our own infrastructure.
 *
 * Deliberately NARROW: an -addnode / -connect target is NOT trusted here.
 * Operator intent to dial an address is not evidence the address serves
 * valid consensus data, and exempting it would hand any peer that talks its
 * way onto the addnode list a permanent licence to feed us invalid blocks.
 * The stranding risk that exemption would have covered is handled instead by
 * the bounded last-peer ban in peer_misbehaving() below, which keeps the
 * penalty and bounds only its duration. */
static bool is_trusted_peer(const struct p2p_node *node)
{
    /* Localhost: 127.0.0.0/8 (IPv4-mapped: ::ffff:127.x.x.x) */
    static const uint8_t lo_prefix[13] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,127};
    if (memcmp(node->addr.svc.addr.ip, lo_prefix, 13) == 0)
        return true;
    /* Whitelisted peers (set by -whitelist or listen socket config) */
    if (node->whitelisted)
        return true;
    return false;
}

/* Would banning `node` leave this manager with no connected peer at all?
 *
 * True only when `node` is REGISTERED in nm->nodes (so a caller holding a
 * bare, unregistered p2p_node — every unit test that exercises scoring in
 * isolation — takes the ordinary path unchanged) and every other registered
 * node is already flagged for disconnect. A node with any other live peer
 * gets the ordinary full-length ban: this predicate is false the moment a
 * second peer exists.
 *
 * TRYLOCK, deliberately. peer_misbehaving() has a caller that is already
 * holding cs_nodes while it walks the node table — the header-span timeout
 * sweep in msg_headers.c (`peer_scoring_record(..., PEER_OFFENCE_TIMEOUT,
 * "header span deadline missed")`) — so a blocking acquire here would
 * self-deadlock the message thread the first time accumulated timeouts
 * crossed the ban threshold. Failing to acquire yields `false`, i.e. the
 * ORDINARY full-length ban: this function can only ever soften the outcome,
 * never harden it, so a missed acquire is exactly the pre-change behaviour
 * and never a new failure mode. */
static bool ban_would_strand_us(struct net_manager *nm,
                                const struct p2p_node *node)
{
    bool registered = false;
    size_t others_alive = 0;

    if (!zcl_mutex_trylock(&nm->cs_nodes))
        return false;
    for (size_t i = 0; i < nm->num_nodes; i++) {
        const struct p2p_node *n = nm->nodes[i];
        if (!n)
            continue;
        if (n == node) {
            registered = true;
            continue;
        }
        if (!n->disconnect)
            others_alive++;
    }
    zcl_mutex_unlock(&nm->cs_nodes);

    return registered && others_alive == 0;
}

/* Named, stable-reason blocker for the bounded last-peer ban (id declared in
 * net/peer_scoring.h; cleared at the handshake-complete choke point in
 * peer_lifecycle.c). The reason carries NO volatile data (no address, no
 * score) because blocker.h keys fault identity on the reason text — the
 * address goes to the peer_banned log line, which is where an operator reads
 * it from. */
static void raise_last_peer_ban_blocker(void)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof reason,
             "the only connected peer crossed the ban threshold — a bounded "
             "recovery ban was applied instead of the full ZCL_PEER_BAN_HOURS "
             "so the node keeps a route back to the network; if this repeats, "
             "either the peer is genuinely bad (give the node a second peer "
             "source via -addnode) or our own validation is rejecting a valid "
             "chain (see the peer_banned log lines for the address and "
             "offence)");
    /* The duration is deliberately absent from the reason: it is volatile
     * config, and blocker.h folds the reason into fault identity. */
    struct blocker_record rec;
    if (!blocker_init(&rec, PEER_LAST_PEER_BAN_BLOCKER_ID, "net",
                      BLOCKER_TRANSIENT, reason))
        return; /* raw-return-ok:blocker-init-failed-already-logged */
    (void)blocker_set(&rec);
}

void peer_misbehaving(struct net_manager *nm, struct p2p_node *node,
                      int howmuch, const char *reason)
{
    if (!nm || !node || howmuch <= 0) return;

    /* NEVER penalize trusted peers — see is_trusted_peer() above for exactly
     * which peers that is (localhost and whitelisted; NOT addnode). */
    if (is_trusted_peer(node))
        return;

    int new_score = atomic_fetch_add(&node->misbehavior, howmuch) + howmuch;
    event_emitf(EV_PEER_MISBEHAVE, (uint32_t)node->id,
                "+%d=%d %s", howmuch, new_score,
                reason ? reason : "");

    /* Thresholds are operator-configurable via peer_scoring_init() / env;
     * we default to 100 score / 24h ban to match historical behaviour. */
    int threshold = peer_scoring_ban_threshold();
    int hours = peer_scoring_ban_hours();
    if (new_score >= threshold) {
        /* Last-peer recovery. The offence weights and the threshold are a
         * real DoS defence and are NOT relaxed: the peer is still scored,
         * still banned, still disconnected. What is bounded is the ban's
         * DURATION, and only in the one case where the full-length ban would
         * leave the node with zero peers and therefore no route back to the
         * network — a freshly-wiped node dialling a single -addnode is the
         * live instance of that case, and one misclassified block would
         * otherwise strand it for ZCL_PEER_BAN_HOURS across restarts
         * (banlist.dat persists). With any second peer connected this branch
         * is not taken and behaviour is byte-identical to before.
         *
         * ban_addr_ex() only ever EXTENDS an existing ban, so a peer that
         * already earned a full-length ban keeps it. */
        bool strand = ban_would_strand_us(nm, node);
        int last_peer_secs = peer_scoring_last_peer_ban_secs();
        int64_t ban_secs = strand ? (int64_t)last_peer_secs
                                  : (int64_t)hours * 60 * 60;

        event_emitf(EV_PEER_BANNED, (uint32_t)node->id,
                    "score=%d %s", new_score,
                    reason ? reason : "threshold");
        char addr_safe[96];
        char reason_safe[160];
        log_json_escape(addr_safe, sizeof(addr_safe), node->addr_name);
        log_json_escape(reason_safe, sizeof(reason_safe),
                         reason ? reason : "threshold reached");
        log_jsonf(LOG_JSON_WARN, "peer_banned",
                  "\"addr\":\"%s\",\"score\":%d,\"reason\":\"%s\","
                  "\"ban_hours\":%d,\"ban_secs\":%lld,\"last_peer\":%s",
                  addr_safe, new_score, reason_safe, hours,
                  (long long)ban_secs, strand ? "true" : "false");
        ban_addr_ex(nm, &node->addr.svc.addr,
                   ban_secs, false,
                   new_score, reason ? reason : "threshold reached");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_PROTOCOL_VIOLATION,
            P2P_DISCONNECT_SOURCE_PEER_POLICY,
            node->endpoint_generation);

        if (strand) {
            /* Say it out loud: a silent bounded ban would look identical to
             * a healthy node with nothing to do. */
            raise_last_peer_ban_blocker();
            LOG_WARN("net",
                     "peer %s was our ONLY peer — applied a bounded %ds "
                     "recovery ban instead of %dh so the node can re-dial "
                     "(blocker %s raised)",
                     node->addr_name, last_peer_secs, hours,
                     PEER_LAST_PEER_BAN_BLOCKER_ID);
        }
    }
}

bool unban_addr(struct net_manager *nm, const struct net_addr *addr)
{
    zcl_mutex_lock(&nm->cs_banned);
    for (size_t i = 0; i < nm->num_banned; i++) {
        if (net_addr_eq(&nm->banned[i].addr, addr)) {
            nm->banned[i] = nm->banned[nm->num_banned - 1];
            nm->num_banned--;
            zcl_mutex_unlock(&nm->cs_banned);
            if (nm->datadir) ban_db_write(nm, nm->datadir);
            return true;
        }
    }
    zcl_mutex_unlock(&nm->cs_banned);
    return false;
}

void clear_banned(struct net_manager *nm)
{
    zcl_mutex_lock(&nm->cs_banned);
    nm->num_banned = 0;
    zcl_mutex_unlock(&nm->cs_banned);
    if (nm->datadir) ban_db_write(nm, nm->datadir);
}

/* ── Ban persistence: <datadir>/banlist.dat ──────────────────────────
 * One self-verifying file — see the doc comment on ban_db_write()/
 * ban_db_read() in net.h for the format rationale. Reuses
 * EV_ADDRMAN_CORRUPT for the (rare) quarantine event since a corrupt
 * banlist.dat is the same class of datadir-tampering concern as a
 * corrupt peers.dat, and adding a dedicated event type would require
 * touching lib/event/src (outside this module's file set). */
#define BAN_DB_MAGIC "ZBAN"
#define BAN_DB_VERSION 1u

static const struct ssio_spec g_ban_db_spec = {
    .body_name     = "banlist.dat",
    .sidecar_name  = "banlist.dat.sha3", /* unused on the embedded path;
                                          * kept so ssio_quarantine() can
                                          * sweep aside a stray legacy
                                          * sidecar if one is ever found */
    .magic         = BAN_DB_MAGIC,
    .version       = BAN_DB_VERSION,
    .domain        = "net_ban",
    .malloc_label  = "ban_db_hash_buf",
    .corrupt_event = EV_ADDRMAN_CORRUPT,
};

struct ban_db_payload_ctx {
    const uint8_t *data;
    size_t size;
};

static bool ban_db_emit_payload(FILE *f, void *ctx_, uint64_t *out_payload_size,
                                uint8_t out_payload_sha3[32])
{
    struct ban_db_payload_ctx *ctx = (struct ban_db_payload_ctx *)ctx_;
    if (ctx->size > 0 && fwrite(ctx->data, 1, ctx->size, f) != ctx->size)
        return false;
    zcl_sha3_256(ctx->data, ctx->size, out_payload_sha3);
    *out_payload_size = (uint64_t)ctx->size;
    return true;
}

bool ban_db_write(struct net_manager *nm, const char *datadir)
{
    if (!nm || !datadir) return false;

    /* Two-pass: serialize entries first (count unknown up front since
     * expired rows are skipped), then prepend the count. Avoids patching
     * raw bytes into an already-written buffer (endian-fragile). */
    struct byte_stream entries;
    stream_init(&entries, 4096);

    int64_t now = GetTime();
    uint32_t live = 0;
    zcl_mutex_lock(&nm->cs_banned);
    for (size_t i = 0; i < nm->num_banned; i++) {
        const struct ban_entry *b = &nm->banned[i];
        if (b->ban_until <= now)
            continue; /* lazy prune: never persist an already-expired ban */
        stream_write(&entries, b->addr.ip, 16);
        stream_write(&entries, b->addr.torv3, TORV3_ADDR_SIZE);
        stream_write_u8(&entries, b->addr.has_torv3 ? 1 : 0);
        stream_write_u8(&entries, b->prefix_len);
        stream_write_i64_le(&entries, b->ban_until);
        stream_write_i32_le(&entries, b->score_at_ban);
        stream_write(&entries, (const unsigned char *)b->reason, sizeof(b->reason));
        live++;
    }
    zcl_mutex_unlock(&nm->cs_banned);

    struct byte_stream s;
    stream_init(&s, entries.size + 8);
    stream_write_u32_le(&s, live);
    stream_write(&s, entries.data, entries.size);
    stream_free(&entries);

    struct ban_db_payload_ctx ctx = { .data = s.data, .size = s.size };
    struct zcl_result wr = ssio_write_embedded(datadir, &g_ban_db_spec,
                                               ban_db_emit_payload, &ctx);
    stream_free(&s);
    if (!wr.ok) {
        LOG_WARN("net", "ban_db_write: %s", wr.message);
        return false;
    }
    return true;
}

bool ban_db_read(struct net_manager *nm, const char *datadir)
{
    if (!nm || !datadir) return false;

    struct ssio_sidecar_header hdr;
    uint64_t payload_off = 0;
    enum ssio_read_verdict v = ssio_verify_embedded(datadir, &g_ban_db_spec,
                                                    &hdr, &payload_off);
    if (v == SSIO_READ_MISSING)
        return false; /* clean first-run/no persisted bans yet */
    if (v != SSIO_READ_OK) {
        LOG_WARN("net", "ban_db_read: integrity check failed (verdict=%d) — "
                 "quarantining banlist.dat and starting with no persisted bans",
                 (int)v);
        ssio_quarantine(datadir, &g_ban_db_spec, "verify_failed");
        return false;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", datadir, g_ban_db_spec.body_name);
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long total = ftell(f);
    if (total < 0 || (uint64_t)total < payload_off) { fclose(f); return false; }
    size_t payload_size = (size_t)total - (size_t)payload_off;
    if (fseek(f, (long)payload_off, SEEK_SET) != 0) { fclose(f); return false; }

    uint8_t *buf = zcl_malloc(payload_size > 0 ? payload_size : 1, "ban_db_read_buf");
    if (!buf) { fclose(f); return false; }
    size_t rd = payload_size > 0 ? fread(buf, 1, payload_size, f) : 0;
    fclose(f);
    if (rd != payload_size) { free(buf); return false; }

    struct byte_stream s;
    stream_init_from_data(&s, buf, payload_size);

    uint32_t count = 0;
    bool ok = stream_read_u32_le(&s, &count);
    if (ok && count > MAX_BAN_ENTRIES) {
        LOG_WARN("net", "ban_db_read: count %u exceeds MAX_BAN_ENTRIES (%d) — refusing",
                 count, MAX_BAN_ENTRIES);
        ok = false;
    }

    int64_t now = GetTime();
    uint32_t loaded = 0, expired_skipped = 0;
    for (uint32_t i = 0; ok && i < count; i++) {
        struct ban_entry b;
        memset(&b, 0, sizeof(b));
        uint8_t has_torv3 = 0;
        ok = ok && stream_read(&s, b.addr.ip, 16);
        ok = ok && stream_read(&s, b.addr.torv3, TORV3_ADDR_SIZE);
        ok = ok && stream_read_u8(&s, &has_torv3);
        ok = ok && stream_read_u8(&s, &b.prefix_len);
        ok = ok && stream_read_i64_le(&s, &b.ban_until);
        ok = ok && stream_read_i32_le(&s, &b.score_at_ban);
        ok = ok && stream_read(&s, (unsigned char *)b.reason, sizeof(b.reason));
        if (!ok) break;
        b.addr.has_torv3 = has_torv3 != 0;
        b.reason[sizeof(b.reason) - 1] = '\0';

        if (b.ban_until <= now) {
            expired_skipped++;
            continue; /* lazy prune at load time too */
        }

        zcl_mutex_lock(&nm->cs_banned);
        if (nm->num_banned >= nm->banned_cap) {
            size_t newcap = nm->banned_cap ? nm->banned_cap * 2 : 64;
            struct ban_entry *tmp = zcl_realloc(nm->banned, newcap * sizeof(*tmp), "ban_list");
            if (tmp) { nm->banned = tmp; nm->banned_cap = newcap; }
        }
        if (nm->num_banned < nm->banned_cap) {
            nm->banned[nm->num_banned++] = b;
            loaded++;
        }
        zcl_mutex_unlock(&nm->cs_banned);
    }

    stream_free(&s);
    free(buf);

    if (!ok) {
        LOG_WARN("net", "ban_db_read: malformed payload (loaded %u entries "
                 "before the parse error) — keeping what loaded", loaded);
    }
    LOG_INFO("net", "ban_db_read: loaded %u bans (%u expired skipped) from %s",
             loaded, expired_skipped, path);
    return true;
}

/* --- local address management --- */

static int find_local_host(struct net_manager *nm, const struct net_addr *addr)
{
    for (size_t i = 0; i < nm->num_local_hosts; i++)
        if (net_addr_eq(&nm->local_hosts[i], addr))
            return (int)i;
    return -1;
}

bool add_local(struct net_manager *nm, const struct net_service *addr, int score)
{
    if (!net_addr_is_routable(&addr->addr))
        LOG_FAIL("net", "add_local: address is not routable");

    if (!nm->discover && score < LOCAL_MANUAL)
        LOG_FAIL("net", "add_local: discover disabled and score=%d < LOCAL_MANUAL", score);

    zcl_mutex_lock(&nm->cs_local_host);

    enum zcl_network net = net_addr_get_network(&addr->addr);
    if (nm->limited[net]) {
        zcl_mutex_unlock(&nm->cs_local_host);
        LOG_FAIL("net", "add_local: network %d is limited", (int)net);
    }

    int idx = find_local_host(nm, &addr->addr);
    if (idx >= 0) {
        if (score >= nm->local_host_info[idx].score) {
            nm->local_host_info[idx].score = score + 1;
            nm->local_host_info[idx].port = addr->port;
        }
    } else {
        if (nm->num_local_hosts >= nm->local_hosts_cap) {
            size_t newcap = nm->local_hosts_cap ? nm->local_hosts_cap * 2 : 8;
            struct net_addr *ha = zcl_realloc(nm->local_hosts, newcap * sizeof(*ha), "local_hosts");
            struct local_service_info *hi = zcl_realloc(nm->local_host_info,
                                                      newcap * sizeof(*hi), "local_host_info");
            if (!ha || !hi) {
                zcl_mutex_unlock(&nm->cs_local_host);
                LOG_FAIL("net", "realloc failed for local_hosts: newcap=%zu", newcap);
            }
            nm->local_hosts = ha;
            nm->local_host_info = hi;
            nm->local_hosts_cap = newcap;
        }
        size_t n = nm->num_local_hosts;
        nm->local_hosts[n] = addr->addr;
        nm->local_host_info[n].score = score;
        nm->local_host_info[n].port = addr->port;
        nm->num_local_hosts++;
    }

    zcl_mutex_unlock(&nm->cs_local_host);
    return true;
}

bool remove_local(struct net_manager *nm, const struct net_service *addr)
{
    zcl_mutex_lock(&nm->cs_local_host);
    int idx = find_local_host(nm, &addr->addr);
    if (idx >= 0) {
        nm->local_hosts[idx] = nm->local_hosts[nm->num_local_hosts - 1];
        nm->local_host_info[idx] = nm->local_host_info[nm->num_local_hosts - 1];
        nm->num_local_hosts--;
    }
    zcl_mutex_unlock(&nm->cs_local_host);
    return idx >= 0;
}

bool is_local(struct net_manager *nm, const struct net_service *addr)
{
    zcl_mutex_lock(&nm->cs_local_host);
    int idx = find_local_host(nm, &addr->addr);
    zcl_mutex_unlock(&nm->cs_local_host);
    return idx >= 0;
}

bool is_reachable_net(struct net_manager *nm, enum zcl_network net)
{
    zcl_mutex_lock(&nm->cs_local_host);
    bool result = !nm->limited[net];
    zcl_mutex_unlock(&nm->cs_local_host);
    return result;
}

void set_limited(struct net_manager *nm, enum zcl_network net, bool limited)
{
    if (net == NET_UNROUTABLE) return;
    zcl_mutex_lock(&nm->cs_local_host);
    nm->limited[net] = limited;
    zcl_mutex_unlock(&nm->cs_local_host);
}

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
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
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

    if (sock == ZCL_INVALID_SOCKET)
        LOG_FAIL("net", "accept() returned invalid socket");

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
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

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

/* --- socket handler loop (one iteration) --- */

/* --- addr db --- */

bool addr_db_write(const struct net_manager *nm, const char *datadir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/peers.dat", datadir);

    struct byte_stream s;
    stream_init(&s, 65536);

    stream_write(&s, nm->message_start, MESSAGE_START_SIZE);

    if (!addrman_serialize(&nm->addrman, &s)) {
        stream_free(&s);
        LOG_FAIL("net", "addrman_serialize failed for peers.dat");
    }

    struct uint256 hash;
    hash256(s.data, s.size, hash.data);
    stream_write(&s, hash.data, 32);

    FILE *f = fopen(path, "wb");
    if (!f) { stream_free(&s); LOG_FAIL("net", "fopen failed for peers.dat write: %s", path); }
    size_t written = fwrite(s.data, 1, s.size, f);
    fclose(f);
    stream_free(&s);

    return written == s.size || written > 0;
}

bool addr_db_read(struct net_manager *nm, const char *datadir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/peers.dat", datadir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            return false; /* clean first-run/cold-start path */
        LOG_FAIL("net", "fopen failed for peers.dat read: %s", path);
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < (long)(MESSAGE_START_SIZE + 32)) {
        fclose(f);
        LOG_FAIL("net", "peers.dat too small: size=%ld", file_size);
    }

    uint8_t *buf = zcl_malloc((size_t)file_size, "net_file_buf");
    if (!buf) { fclose(f); LOG_FAIL("net", "malloc failed for peers.dat: size=%ld", file_size); }
    if (fread(buf, 1, (size_t)file_size, f) != (size_t)file_size) {
        free(buf);
        fclose(f);
        LOG_FAIL("net", "fread failed for peers.dat: expected %ld bytes", file_size);
    }
    fclose(f);

    size_t data_size = (size_t)file_size - 32;
    struct uint256 stored_hash;
    memcpy(stored_hash.data, buf + data_size, 32);

    struct uint256 computed_hash;
    hash256(buf, data_size, computed_hash.data);

    if (!uint256_eq(&stored_hash, &computed_hash)) {
        free(buf);
        LOG_FAIL("net", "peers.dat hash mismatch — file corrupted");
    }

    if (memcmp(buf, nm->message_start, MESSAGE_START_SIZE) != 0) {
        free(buf);
        LOG_FAIL("net", "peers.dat message_start mismatch — wrong network");
    }

    struct byte_stream s;
    stream_init_from_data(&s, buf + MESSAGE_START_SIZE,
                          data_size - MESSAGE_START_SIZE);

    bool ok = addrman_deserialize(&nm->addrman, &s);
    stream_free(&s);
    free(buf);
    return ok;
}
