/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Mesh status requester lane: begin one bounded pairing-bound
 * status request against a paired peer's live Noise session. Shared
 * state, receipt ingress, poll, and the responder lane live in
 * boot_mesh_status.c (see the internal header for the seam). */

// one-result-type-ok:closed-security-verdict — begin returns a bounded
// verdict enum the caller must branch on; no diagnostic text crosses the
// wire. Failure logging happens here at the request edge.

#include "config/boot_mesh_status.h"
#include "config/boot_mesh_route.h"
#include "boot_mesh_status_internal.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_access.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/random_secret.h"
#include "models/mesh_pairing.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"

#include <stdlib.h>
#include <string.h>

/* Closed code -> text table; one row per verdict. */
static const struct {
    enum boot_mesh_status_begin_result result;
    const char *text;
} k_begin_result_text[] = {
    {MESH_STATUS_BEGIN_OK, "ok"},
    {MESH_STATUS_BEGIN_BAD_ARGUMENT, "bad_argument"},
    {MESH_STATUS_BEGIN_UNAVAILABLE, "unavailable"},
    {MESH_STATUS_BEGIN_NOISE_DISABLED, "noise_transport_disabled"},
    {MESH_STATUS_BEGIN_NOT_PAIRED, "not_paired"},
    {MESH_STATUS_BEGIN_REVOKED, "revoked"},
    {MESH_STATUS_BEGIN_EXPIRED, "expired"},
    {MESH_STATUS_BEGIN_PEER_NOT_CONNECTED, "peer_not_connected"},
    {MESH_STATUS_BEGIN_ROUTE_PENDING, "route_pending"},
    {MESH_STATUS_BEGIN_ROUTE_IDENTITY_MISMATCH, "route_identity_mismatch"},
    {MESH_STATUS_BEGIN_ROUTE_DOWNGRADE, "route_plaintext_downgrade"},
    {MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE, "identity_unavailable"},
    {MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE, "peer_identity_unavailable"},
    {MESH_STATUS_BEGIN_BUSY, "busy"},
    {MESH_STATUS_BEGIN_SEND_FAILED, "send_failed"},
};

const char *boot_mesh_status_begin_result_string(
    enum boot_mesh_status_begin_result result)
{
    for (size_t i = 0;
         i < sizeof(k_begin_result_text) / sizeof(k_begin_result_text[0]); i++)
        if (k_begin_result_text[i].result == result)
            return k_begin_result_text[i].text;
    return "bad_argument";
}

/* Session-peer lookup lives in boot_mesh_status.c as
 * boot_mesh_find_session_peer (internal header): the terminal lane's pump
 * needs the identical lookup, so it is shared rather than copied. The peer's
 * held-delegation lookup is shared the same way, as boot_mesh_peer_delegation
 * — an open and a status request must pre-flight the identical authority the
 * responder re-verifies. */

/* True when the caller's arguments are well formed; decodes the pairing id. */
static bool mesh_status_begin_args_ok(const char *pairing_id_hex,
                                      uint8_t request_id_out[32],
                                      uint8_t pairing_id[32])
{
    return pairing_id_hex && strlen(pairing_id_hex) == MESH_PAIRING_ID_HEX &&
           zcl_hex_decode_lower(pairing_id_hex, pairing_id, 32) &&
           request_id_out;
}

/* Maps a route-acquire verdict to the begin verdict (OK when acquired). */
static enum boot_mesh_status_begin_result mesh_status_begin_route_verdict(
    enum boot_mesh_route_result route)
{
    switch (route) {
    case BOOT_MESH_ROUTE_ACQUIRED: return MESH_STATUS_BEGIN_OK;
    case BOOT_MESH_ROUTE_PENDING:
    case BOOT_MESH_ROUTE_RESOURCE_DEFERRED:
        return MESH_STATUS_BEGIN_ROUTE_PENDING;
    case BOOT_MESH_ROUTE_IDENTITY_MISMATCH:
        return MESH_STATUS_BEGIN_ROUTE_IDENTITY_MISMATCH;
    case BOOT_MESH_ROUTE_DOWNGRADE:
        return MESH_STATUS_BEGIN_ROUTE_DOWNGRADE;
    case BOOT_MESH_ROUTE_AMBIGUOUS_ENDPOINT:
        return MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE;
    case BOOT_MESH_ROUTE_BUSY:
        return MESH_STATUS_BEGIN_BUSY;
    case BOOT_MESH_ROUTE_NO_ENDPOINT:
    case BOOT_MESH_ROUTE_EXHAUSTED:
        return MESH_STATUS_BEGIN_PEER_NOT_CONNECTED;
    default:
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    }
}

/* No live session peer: try to acquire a route. OK means *peer is held. */
static enum boot_mesh_status_begin_result mesh_status_begin_acquire_route(
    struct boot_svc_ctx *svc, const struct db_mesh_pairing *row, int64_t now,
    struct p2p_node **peer, struct noise_transport_snapshot *session)
{
    int64_t now_mono = platform_time_monotonic_ms();
    if (now_mono <= 0)
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    enum boot_mesh_route_result route = boot_mesh_route_acquire(
        svc, row, (uint64_t)now, (uint64_t)now_mono, peer, session);
    return mesh_status_begin_route_verdict(route);
}

/* True when the responder's delegation is held and authorizes status. */
static bool mesh_status_begin_responder_ok(
    struct node_db *ndb, const struct db_mesh_pairing *row,
    const char *pairing_id_hex, const struct noise_transport_snapshot *session,
    int64_t now, struct vcs_zcode_dht_delegation *responder_delegation)
{
    uint8_t network_genesis[32];
    return boot_mesh_peer_delegation(row, responder_delegation) &&
           boot_zcode_dht_network_genesis(network_genesis) &&
           mesh_pairing_service_authorize_status(
               ndb, network_genesis, pairing_id_hex, responder_delegation,
               session->remote_static, now) == MESH_PAIRING_OK;
}

/* Draws a free request id. 0 ok, 1 random source failed, 2 collisions. */
static int mesh_status_begin_draw_request_id(
    struct mesh_status_request_v1 *request)
{
    bool have_id = false;
    for (int attempt = 0; attempt < 4 && !have_id; attempt++) {
        if (!zcl_random_secret_bytes(request->request_id, 32,
                                     "mesh_status_request"))
            return 1;
        have_id = mesh_status_request_id_free(request->request_id);
    }
    return have_id ? 0 : 2;
}

/* Fills the request fields that follow the id draw. */
static void mesh_status_begin_fill_request(
    struct mesh_status_request_v1 *request, const struct msg_processor *mp,
    const struct db_mesh_pairing *row,
    const struct vcs_zcode_dht_delegation *local,
    const struct noise_transport_snapshot *session,
    const uint8_t pairing_id[32], int64_t now)
{
    memcpy(request->network_genesis,
           mp->params->consensus.hashGenesisBlock.data, 32);
    memcpy(request->target_master_pubkey, row->peer_master_pubkey, 32);
    memcpy(request->requester_master_pubkey, local->doc.master_pubkey, 32);
    memcpy(request->requester_noise_static, mp->net_mgr->identity_pub, 32);
    memcpy(request->pairing_id, pairing_id, 32);
    /* The request binds the shared session evidence (see the header). */
    memcpy(request->transcript_hash, session->transcript_hash, 32);
    request->connection_generation = session->connection_generation;
    request->issued_unix = (uint64_t)now;
    request->expires_unix = (uint64_t)now + MESH_STATUS_REQUEST_LIFETIME_SECONDS;
}

enum boot_mesh_status_begin_result boot_mesh_status_begin(
    const char *pairing_id_hex, uint8_t request_id_out[32])
{
    uint8_t pairing_id[32];
    if (!mesh_status_begin_args_ok(pairing_id_hex, request_id_out, pairing_id))
        return MESH_STATUS_BEGIN_BAD_ARGUMENT;

    uint64_t generation = 0;
    struct boot_svc_ctx *svc = mesh_status_service(&generation);
    if (!svc || !svc->msg_processor || !svc->datadir)
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    struct msg_processor *mp = svc->msg_processor;
    if (!mp->net_mgr || !mp->params) {
        LOG_ERROR("net.mesh_status", "begin: msg_processor incomplete");
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    }
    if (!mp->net_mgr->noise_enabled)
        return MESH_STATUS_BEGIN_NOISE_DISABLED;

    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_ERROR("net.mesh_status", "begin: node_db unavailable");
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0) {
        LOG_ERROR("net.mesh_status", "begin: wall clock unavailable");
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    }
    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id_hex, &row))
        return MESH_STATUS_BEGIN_NOT_PAIRED;
    if (!mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, now))
        return row.revoked_at != 0 ? MESH_STATUS_BEGIN_REVOKED
                                   : MESH_STATUS_BEGIN_EXPIRED;

    /* The request names OUR anchored master identity from the filed local
     * delegation; without it no honest request can be composed. */
    struct vcs_zcode_dht_delegation local;
    char error[160];
    if (!vcs_zcode_dht_delegation_load(svc->datadir, &local, error,
                                       sizeof(error))) {
        LOG_ERROR("net.mesh_status",
                  "begin: local delegation unavailable (%s)", error);
        return MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE;
    }

    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    struct p2p_node *peer = boot_mesh_find_session_peer(
        mp->net_mgr, row.peer_noise_pubkey, &session);
    if (!peer) {
        enum boot_mesh_status_begin_result route_verdict =
            mesh_status_begin_acquire_route(svc, &row, now, &peer, &session);
        if (route_verdict != MESH_STATUS_BEGIN_OK)
            return route_verdict;
    }

    struct vcs_zcode_dht_delegation responder_delegation;
    if (!mesh_status_begin_responder_ok(ndb, &row, pairing_id_hex, &session,
                                        now, &responder_delegation)) {
        p2p_node_release(peer);
        return MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE;
    }

    struct mesh_status_request_v1 request;
    memset(&request, 0, sizeof(request));
    request.version = MESH_STATUS_PROTO_VERSION;
    request.flags = MESH_STATUS_PROTO_FLAGS_NONE;
    request.capability = MESH_STATUS_CAP_STATUS_READ;
    int id_status = mesh_status_begin_draw_request_id(&request);
    if (id_status == 1) {
        p2p_node_release(peer);
        LOG_ERROR("net.mesh_status", "begin: request id generation failed");
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    }
    if (id_status != 0) {
        p2p_node_release(peer);
        LOG_ERROR("net.mesh_status", "begin: request id collision persisted");
        return MESH_STATUS_BEGIN_BUSY;
    }
    mesh_status_begin_fill_request(&request, mp, &row, &local, &session,
                                   pairing_id, now);

    uint8_t wire[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
    enum mesh_status_proto_error encoded =
        mesh_status_request_v1_encode(&request, wire);
    if (encoded != MESH_STATUS_PROTO_OK) {
        p2p_node_release(peer);
        LOG_ERROR("net.mesh_status", "begin: request encode failed: %s",
                  mesh_status_proto_error_string(encoded));
        return MESH_STATUS_BEGIN_UNAVAILABLE;
    }

    /* Admit the pending entry before sending so a fast receipt can never
     * arrive to a missing slot. */
    if (!mesh_status_pending_admit(
            &request, row.peer_master_pubkey,
            responder_delegation.online_pubkey, generation)) {
        p2p_node_release(peer);
        return MESH_STATUS_BEGIN_BUSY;
    }
    if (!mesh_status_send(mp, peer, MESH_STATUS_FRAME_KIND_REQUEST, wire,
                          sizeof(wire))) {
        mesh_status_pending_retract(request.request_id);
        p2p_node_release(peer);
        return MESH_STATUS_BEGIN_SEND_FAILED;
    }
    p2p_node_release(peer);
    memcpy(request_id_out, request.request_id, 32);
    return MESH_STATUS_BEGIN_OK;
}
