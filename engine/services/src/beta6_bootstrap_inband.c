/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Answer the eight beta6 bootstrap messages on ordinary P2P peers.
 *
 * This is the PRODUCTION path of the beta6 snapshot server. A stock
 * zclassicd v2.1.2-beta6 client dials the bootstrap peers compiled into its
 * binary on the ordinary P2P port (8033 on mainnet), and it will only
 * fast-sync from a peer it reaches THERE. On this host that port is z23's own
 * peer-to-peer socket, so the eight messages have to be answered in-band on an
 * ordinary peer connection rather than on a side listener.
 *
 * core/modules/net owns the socket, the dispatch table and the `version`
 * services word, so the seam is two function pointers the boot glue installs
 * (net/msgprocessor.h): `armed` decides whether NODE_BOOTSTRAP goes into the
 * services word, and `message` is this file. With nothing installed the bit
 * stays clear and the eight commands are ignored, which is exactly what the
 * node did before the seam existed.
 *
 * What the client requires of this path (bootstrap.cpp:606-673, 1497-1519):
 *  - chunk replies come back in REQUEST ORDER, which they do because one peer
 *    is dispatched sequentially by the message loop;
 *  - a refusal must be prompt, never a stall: the client aborts a stream that
 *    delivers under 32 KiB/s for a full 60 s window. So an over-quota bucket
 *    is refused BY NAME here instead of being spaced out with a sleep the way
 *    the dedicated listener does — this runs on the shared message thread and
 *    must never park it;
 *  - every parallel stream must see byte-identical manifest bytes, which they
 *    do because the manifest is encoded once at arm time and shared.
 *
 * Everything served is a bounded positioned read of an already-hashed,
 * immutable manifest; the source tree is opened read-only and never written.
 */
#include "services/beta6_bootstrap.h"

#include "chain/chainparams.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/protocol.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* protocol.h:REJECT_INVALID — the code a beta6 client prints beside the
 * reason string when it logs "bootstrap peer rejected <cmd>: <reason>". */
#define BETA6_REJECT_INVALID 0x10
/* bootstrap.cpp:BOOTSTRAP_MAX_REJECT_MESSAGE_LENGTH — the client refuses a
 * longer reason string outright, which would lose the named refusal. */
#define BETA6_REJECT_REASON_MAX 111u

static char s_network[BETA6_BS_MAX_NETWORK_LEN];
static char s_params_dir[4096];
/* Encoded once while arming and read-only afterwards: every peer thread that
 * can reach it observes the same bytes, which is what makes the client's
 * cross-stream manifest-equality check pass. */
static unsigned char *s_manifest_bytes;
static size_t s_manifest_len;
static bool s_ready;

/* ── framing ─────────────────────────────────────────────────────────── */

static bool send_reply(struct msg_processor *mp, struct p2p_node *node,
                       const char *command, const unsigned char *payload,
                       size_t payload_len)
{
    if (payload_len > BETA6_BS_MAX_MESSAGE_LEN)
        LOG_FAIL("beta6boot", "beta6 %s reply of %zu bytes is over the message cap",
                 command, payload_len);
    if (!p2p_node_begin_message(node, command, mp->params->pchMessageStart))
        LOG_FAIL("beta6boot", "could not begin the beta6 %s reply to peer %s", command,
                 node->addr_name);
    if (payload_len > 0)
        p2p_node_write_message_data(node, payload, payload_len);
    return p2p_node_end_message(node);
}

/* A named refusal in the shape the client parses: the rejected command, a
 * code, and a reason. The dedicated listener sends an empty `reject`, which
 * the client also treats as fatal but cannot name; naming it turns an operator
 * mistake into a one-line diagnosis in the client's own log. */
static bool send_reject(struct msg_processor *mp, struct p2p_node *node,
                        const char *rejected, const char *reason)
{
    struct byte_stream out;
    stream_init(&out, 160);
    size_t reason_len = strlen(reason);
    if (reason_len > BETA6_REJECT_REASON_MAX)
        reason_len = BETA6_REJECT_REASON_MAX;
    bool ok = stream_write_compact_size(&out, strlen(rejected)) &&
              stream_write_bytes(&out, (const unsigned char *)rejected,
                                 strlen(rejected)) &&
              stream_write_u8(&out, BETA6_REJECT_INVALID) &&
              stream_write_compact_size(&out, reason_len) &&
              stream_write_bytes(&out, (const unsigned char *)reason, reason_len);
    if (ok)
        ok = send_reply(mp, node, "reject", out.data, out.size);
    stream_free(&out);
    return ok;
}

/* ── quota ───────────────────────────────────────────────────────────── */

/* The peer's serve bucket. Uses the connection's own address rather than any
 * gossiped one, so a peer cannot charge its traffic to somebody else. */
static bool peer_quota_key(const struct p2p_node *node, char *out, size_t out_size)
{
    char ip[64] = { 0 };
    if (net_addr_to_string(&node->addr.svc.addr, ip, sizeof(ip)) <= 0)
        return false;
    return beta6_bs_quota_key(ip, out, out_size).ok;
}

/* ── serve handlers ──────────────────────────────────────────────────── */

static bool serve_snapshot_manifest(struct msg_processor *mp, struct p2p_node *node)
{
    if (!s_manifest_bytes)
        return send_reject(mp, node, "getbsman", "no beta6 snapshot is armed");
    return send_reply(mp, node, "bsman", s_manifest_bytes, s_manifest_len);
}

static bool serve_param_manifest(struct msg_processor *mp, struct p2p_node *node)
{
    struct beta6_bs_manifest manifest;
    struct zcl_result built = beta6_bs_param_manifest(s_params_dir, s_network, &manifest);
    if (!built.ok) {
        LOG_INFO("beta6boot", "peer %s: no zcash params to serve: %s", node->addr_name,
                 built.message);
        return send_reject(mp, node, "getbspman", built.message);
    }
    struct byte_stream out;
    stream_init(&out, 4096);
    bool ok = beta6_bs_manifest_encode(&manifest, &out).ok &&
              send_reply(mp, node, "bspman", out.data, out.size);
    stream_free(&out);
    beta6_bs_manifest_free(&manifest);
    return ok;
}

/* Decode a chunk request and bound it before anything touches the disk. */
static bool decode_chunk_request(const unsigned char *payload, size_t payload_len,
                                 struct beta6_bs_chunk_request *request)
{
    struct byte_stream in;
    stream_init_from_data(&in, payload, payload_len);
    bool ok = beta6_bs_chunk_request_decode(&in, request).ok && stream_remaining(&in) == 0;
    stream_free(&in);
    return ok && request->length > 0 && request->length <= BETA6_BS_CHUNK_SIZE;
}

/* Charge the peer's bucket, or name the refusal. The in-band path NEVER
 * spaces a send out — it runs on the shared message thread — so both quota
 * codes come back here as one prompt refusal. */
static bool quota_admits(const struct p2p_node *node, uint32_t bytes)
{
    char quota_key[80] = { 0 };
    if (!peer_quota_key(node, quota_key, sizeof(quota_key)))
        return true; /* an unaddressable peer is charged to no bucket */
    int64_t now_ms = clock_now_wall_ms();
    struct zcl_result allowed = beta6_bs_quota_check(quota_key, node->whitelisted, now_ms);
    if (!allowed.ok)
        return false;
    beta6_bs_quota_charge(quota_key, node->whitelisted, now_ms, bytes);
    return true;
}

static bool serve_chunk(struct msg_processor *mp, struct p2p_node *node,
                        const unsigned char *payload, size_t payload_len, bool params)
{
    const char *command = params ? "getbspchk" : "getbschk";
    struct beta6_bs_chunk_request request;
    if (!decode_chunk_request(payload, payload_len, &request)) {
        LOG_INFO("beta6boot", "peer %s: malformed %s", node->addr_name, command);
        return send_reject(mp, node, command, "malformed bootstrap chunk request");
    }
    if (!quota_admits(node, request.length)) {
        LOG_INFO("beta6boot", "peer %s: %s refused, over the daily serve cap",
                 node->addr_name, command);
        return send_reject(mp, node, command, "over the daily beta6 bootstrap serve cap");
    }

    unsigned char *data = zcl_malloc(request.length, "beta6 inband chunk");
    if (!data)
        LOG_FAIL("beta6boot", "out of memory for a %u byte beta6 chunk",
                 (unsigned)request.length);
    struct zcl_result chunk = params ? beta6_bs_read_param_chunk(s_params_dir, s_network,
                                                                 &request, data,
                                                                 request.length)
                                     : beta6_bs_read_chunk(&request, data, request.length);
    if (!chunk.ok) {
        LOG_INFO("beta6boot", "peer %s: %s refused: %s", node->addr_name, command,
                 chunk.message);
        free(data);
        return send_reject(mp, node, command, chunk.message);
    }

    struct byte_stream out;
    stream_init(&out, request.length + 32);
    bool ok = beta6_bs_chunk_encode(request.file_index, request.offset, data,
                                    request.length, &out).ok &&
              send_reply(mp, node, params ? "bspchk" : "bschk", out.data, out.size);
    stream_free(&out);
    free(data);
    return ok;
}

/* ── seam ────────────────────────────────────────────────────────────── */

static bool inband_dispatch(struct msg_processor *mp, struct p2p_node *node,
                            const char *command, const unsigned char *payload,
                            size_t payload_len)
{
    if (strcmp(command, "getbsman") == 0)
        return serve_snapshot_manifest(mp, node);
    if (strcmp(command, "getbspman") == 0)
        return serve_param_manifest(mp, node);
    if (strcmp(command, "getbschk") == 0)
        return serve_chunk(mp, node, payload, payload_len, false);
    if (strcmp(command, "getbspchk") == 0)
        return serve_chunk(mp, node, payload, payload_len, true);
    /* bsman/bschk/bspman/bspchk are the SERVER's replies. z23 fast-syncs
     * through its own state offers and never asks a beta6 peer for a
     * snapshot, so an unsolicited reply is nothing this node asked for:
     * drop it by name rather than parse attacker-shaped bytes. */
    LOG_INFO("beta6boot", "peer %s: ignoring unsolicited beta6 %s", node->addr_name,
             command);
    return true;
}

struct zcl_result beta6_bs_inband_serve(struct msg_processor *mp, struct p2p_node *node,
                                        const char *command,
                                        const unsigned char *payload,
                                        size_t payload_len)
{
    if (!mp || !mp->params || !node || !command)
        return ZCL_OK;
    struct zcl_result serving = beta6_bs_inband_status();
    if (!serving.ok) {
        if (!send_reject(mp, node, command, "beta6 bootstrap serving is not armed"))
            return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                           "could not tell peer %s that beta6 serving is not armed",
                           node->addr_name);
        return ZCL_OK;
    }
    if (!inband_dispatch(mp, node, command, payload, payload_len))
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "could not enqueue the beta6 %s reply to peer %s", command,
                       node->addr_name);
    return ZCL_OK;
}

struct zcl_result beta6_bs_inband_status(void)
{
    if (!s_ready)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "the beta6 in-band bootstrap manifest is not cached");
    return beta6_bs_status();
}

struct zcl_result beta6_bs_inband_params_status(void)
{
    if (!s_ready)
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "beta6 in-band seam is not armed");
    if (s_params_dir[0] == '\0')
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "armed without -paramsdir: getbspman is answered "
                       "with a reject");
    return ZCL_OK;
}

struct zcl_result beta6_bs_inband_arm(const char *network, const char *params_dir)
{
    struct zcl_result armed = beta6_bs_status();
    if (!armed.ok)
        return armed;
    beta6_bs_inband_disarm();

    struct byte_stream out;
    stream_init(&out, 65536);
    struct zcl_result encoded = beta6_bs_manifest_encode(beta6_bs_manifest(), &out);
    if (!encoded.ok) {
        stream_free(&out);
        return encoded;
    }
    if (out.size > BETA6_BS_MAX_MESSAGE_LEN) {
        stream_free(&out);
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "the beta6 bootstrap manifest is %zu bytes and does not fit in "
                       "one P2P message",
                       out.size);
    }
    s_manifest_bytes = zcl_malloc(out.size, "beta6 inband manifest");
    if (!s_manifest_bytes) {
        stream_free(&out);
        return ZCL_ERR(BETA6_BS_ERR_REFUSED,
                       "out of memory encoding the beta6 bootstrap manifest");
    }
    memcpy(s_manifest_bytes, out.data, out.size);
    s_manifest_len = out.size;
    stream_free(&out);

    snprintf(s_network, sizeof(s_network), "%s", network ? network : "");
    snprintf(s_params_dir, sizeof(s_params_dir), "%s", params_dir ? params_dir : "");
    s_ready = true;
    return ZCL_OK;
}

void beta6_bs_inband_disarm(void)
{
    s_ready = false;
    free(s_manifest_bytes);
    s_manifest_bytes = NULL;
    s_manifest_len = 0;
    s_network[0] = '\0';
    s_params_dir[0] = '\0';
}
