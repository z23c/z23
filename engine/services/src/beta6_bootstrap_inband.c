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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
        return false;
    if (!p2p_node_begin_message(node, command, mp->params->pchMessageStart))
        return false;
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
    return beta6_bs_quota_key(ip, out, out_size);
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
    char err[256] = { 0 };
    if (!beta6_bs_param_manifest(s_params_dir, s_network, &manifest, err, sizeof(err))) {
        LOG_INFO("beta6boot", "peer %s: no zcash params to serve: %s", node->addr_name,
                 err);
        return send_reject(mp, node, "getbspman", err);
    }
    struct byte_stream out;
    stream_init(&out, 4096);
    bool ok = beta6_bs_manifest_encode(&manifest, &out) &&
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
    bool ok = beta6_bs_chunk_request_decode(&in, request) && stream_remaining(&in) == 0;
    stream_free(&in);
    return ok && request->length > 0 && request->length <= BETA6_BS_CHUNK_SIZE;
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

    char quota_key[80] = { 0 };
    bool stop = false;
    if (peer_quota_key(node, quota_key, sizeof(quota_key))) {
        int64_t now_ms = (int64_t)time(NULL) * 1000;
        if (!beta6_bs_quota_allow(quota_key, node->whitelisted, now_ms, &stop)) {
            LOG_INFO("beta6boot", "peer %s: %s refused, over the daily serve cap",
                     node->addr_name, command);
            return send_reject(mp, node, command,
                               "over the daily beta6 bootstrap serve cap");
        }
        beta6_bs_quota_charge(quota_key, node->whitelisted, now_ms, request.length);
    }

    unsigned char *data = zcl_malloc(request.length, "beta6 inband chunk");
    if (!data)
        return false;
    char err[256] = { 0 };
    bool read_ok = params ? beta6_bs_read_param_chunk(s_params_dir, s_network, &request,
                                                      data, request.length, err,
                                                      sizeof(err))
                          : beta6_bs_read_chunk(&request, data, request.length, err,
                                                sizeof(err));
    if (!read_ok) {
        LOG_INFO("beta6boot", "peer %s: %s refused: %s", node->addr_name, command, err);
        free(data);
        return send_reject(mp, node, command, err);
    }

    struct byte_stream out;
    stream_init(&out, request.length + 32);
    bool ok = beta6_bs_chunk_encode(request.file_index, request.offset, data,
                                    request.length, &out) &&
              send_reply(mp, node, params ? "bspchk" : "bschk", out.data, out.size);
    stream_free(&out);
    free(data);
    return ok;
}

/* ── seam ────────────────────────────────────────────────────────────── */

bool beta6_bs_inband_serve(struct msg_processor *mp, struct p2p_node *node,
                           const char *command, const unsigned char *payload,
                           size_t payload_len)
{
    if (!mp || !mp->params || !node || !command)
        return true;
    if (!s_ready || !beta6_bs_is_armed())
        return send_reject(mp, node, command, "beta6 bootstrap serving is not armed");

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

bool beta6_bs_inband_armed(void)
{
    return s_ready && beta6_bs_is_armed();
}

bool beta6_bs_inband_arm(const char *network, const char *params_dir, char *err,
                         size_t err_size)
{
    if (!beta6_bs_is_armed()) {
        snprintf(err, err_size,
                 "the beta6 bootstrap service is not armed; set -beta6-bootstrap-source");
        return false;
    }
    beta6_bs_inband_disarm();

    struct byte_stream out;
    stream_init(&out, 65536);
    if (!beta6_bs_manifest_encode(beta6_bs_manifest(), &out)) {
        stream_free(&out);
        snprintf(err, err_size, "could not encode the beta6 bootstrap manifest");
        return false;
    }
    if (out.size > BETA6_BS_MAX_MESSAGE_LEN) {
        stream_free(&out);
        snprintf(err, err_size,
                 "the beta6 bootstrap manifest does not fit in one P2P message");
        return false;
    }
    s_manifest_bytes = zcl_malloc(out.size, "beta6 inband manifest");
    if (!s_manifest_bytes) {
        stream_free(&out);
        snprintf(err, err_size, "out of memory encoding the beta6 bootstrap manifest");
        return false;
    }
    memcpy(s_manifest_bytes, out.data, out.size);
    s_manifest_len = out.size;
    stream_free(&out);

    snprintf(s_network, sizeof(s_network), "%s", network ? network : "");
    snprintf(s_params_dir, sizeof(s_params_dir), "%s", params_dir ? params_dir : "");
    s_ready = true;
    return true;
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
