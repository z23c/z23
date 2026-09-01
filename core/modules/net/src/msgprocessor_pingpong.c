/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* P2P keepalive / advisory: ping, pong, feefilter, reject. None of
 * these need access to the chain or mempool — they tweak per-node
 * latency/state and emit a reply. */

#include "platform/time_compat.h"
#include "msgprocessor_internal.h"
#include "net/version.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static bool process_ping(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s)
{
    uint64_t nonce = 0;
    if (node->version >= BIP0031_VERSION) {
        if (!stream_read_u64_le(s, &nonce))
            LOG_FAIL("net", "failed to read ping nonce from %s",
                     node->addr_name);
    }

    if (node->version >= BIP0031_VERSION) {
        struct byte_stream reply;
        stream_init(&reply, 8);
        if (!stream_write_u64_le(&reply, nonce)) {
            /* allocation failed (reply.data NULL); drop the pong rather
             * than emit a malformed/empty message. */
            stream_free(&reply);
            return true;
        }

        p2p_node_begin_message(node, "pong", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, reply.data, reply.size);
        p2p_node_end_message(node);
        stream_free(&reply);
    }
    return true;
}

static bool process_pong(struct p2p_node *node, struct byte_stream *s)
{
    uint64_t nonce = 0;
    if (!stream_read_u64_le(s, &nonce))
        LOG_FAIL("net", "failed to read pong nonce from %s",
                 node->addr_name);

    if (node->ping_nonce_sent != 0 && nonce == node->ping_nonce_sent) {
        int64_t now = platform_time_monotonic_us();
        int64_t rtt = now - node->ping_usec_start;
        if (rtt > 0) {
            node->ping_usec_time = rtt;
            if (node->min_ping_usec_time == 0 || rtt < node->min_ping_usec_time)
                node->min_ping_usec_time = rtt;
            /* Exponential moving average: new = 0.8 * old + 0.2 * sample */
            if (node->avg_latency_us == 0)
                node->avg_latency_us = rtt;
            else
                node->avg_latency_us =
                    (node->avg_latency_us * 4 + rtt) / 5;
        }
        node->ping_nonce_sent = 0;
        atomic_store_explicit(&node->keepalive_ping_sent_monotonic_us, 0,
                              memory_order_relaxed);
    }
    return true;
}

static bool process_reject(struct p2p_node *node, struct byte_stream *s)
{
    (void)node;
    uint64_t msg_len;
    if (!stream_read_compact_size(s, &msg_len))
        return true;
    char msg_type[32] = {0};
    if (msg_len > 0) {
        if (msg_len < sizeof(msg_type)) {
            stream_read_bytes(s, (unsigned char *)msg_type, msg_len);
        } else {
            /* Oversized message-type string: the old code silently skipped
             * storing it but left the read cursor behind, so `code` and
             * `reason` below were read from the WRONG offset (the tail of
             * msg_type's own bytes) instead of their real wire position —
             * a truncate-without-consuming bug, not just a truncate. reject
             * is advisory-only (no consequence beyond a log line), so a
             * bounds-checked skip keeps the rest of the parse aligned
             * without needing to keep the string around. */
            if (msg_len > stream_remaining(s))
                return true;  /* declared length exceeds the message body */
            s->read_pos += (size_t)msg_len;
        }
    }
    uint8_t code = 0;
    if (!stream_read_u8(s, &code))
        return true;  /* truncated reject is non-fatal */
    uint64_t reason_len = 0;
    char reason[256] = {0};
    if (stream_read_compact_size(s, &reason_len) && reason_len > 0) {
        if (reason_len < sizeof(reason))
            stream_read_bytes(s, (unsigned char *)reason, reason_len);
        /* else: reason is the last field on the wire — an oversized one
         * cannot misalign anything further, so leaving it unread (and
         * `reason` empty) is a safe truncation, not a misparse. */
    }
    printf("Peer %s: reject %s (code=%d) %s\n",
           node->addr_name, msg_type, code, reason);
    return true;
}

static bool process_feefilter(struct p2p_node *node, struct byte_stream *s)
{
    uint64_t fee_rate = 0;
    if (!stream_read_u64_le(s, &fee_rate))
        LOG_FAIL("net", "failed to read feefilter rate from %s",
                 node->addr_name);
    (void)fee_rate;
    (void)node;
    return true;
}

bool mp_handle_ping(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s)
{
    return process_ping(mp, node, s);
}

bool mp_handle_pong(struct msg_processor *mp, struct p2p_node *node,
                    struct byte_stream *s)
{
    (void)mp;
    return process_pong(node, s);
}

bool mp_handle_feefilter(struct msg_processor *mp, struct p2p_node *node,
                         struct byte_stream *s)
{
    (void)mp;
    return process_feefilter(node, s);
}

bool mp_handle_reject(struct msg_processor *mp, struct p2p_node *node,
                      struct byte_stream *s)
{
    (void)mp;
    return process_reject(node, s);
}
