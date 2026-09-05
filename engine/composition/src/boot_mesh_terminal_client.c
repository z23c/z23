/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Mesh terminal requester lane: begin one pairing-bound confined
 * terminal as a "terminal" stream to a paired peer, then pump bounded
 * DATA both ways through poll/write/drain until watchdogs or a named
 * close ends it. Mirrors boot_mesh_status_requester.c's begin discipline;
 * message ingress and the responder lane live in boot_mesh_terminal.c
 * (see the internal header for the seam). This lane keeps no session
 * table and no lock of its own: the stream primitive owns both. */

// one-result-type-ok:closed-security-verdict — open/poll/write return
// bounded verdicts the caller must branch on; no diagnostic text crosses
// the wire. Drop/refusal logging happens here at the request edge.

#include "config/boot_mesh_terminal.h"
#include "config/boot_zcode_dht.h"
#include "config/mesh_stream.h"
#include "boot_mesh_status_internal.h"
#include "boot_mesh_terminal_internal.h"

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/random_secret.h"
#include "models/mesh_pairing.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "util/log_macros.h"
#include "vcs/zcode_dht_identity.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static struct boot_svc_ctx *g_client_svc; /* borrowed; set by wire() */

/* One requested terminal's own state, hung off its stream. The stream
 * owns the identity, the peer binding, the credit window and the
 * lifetime; this is only what a requester adds to them. */
struct mesh_terminal_client_session {
    bool open_confirmed; /* OK receipt accepted */
    bool ended;          /* refused, closed, or watchdog-expired */
    bool close_reason_named; /* vs a CLOSED receipt's remote-only evidence */
    struct mesh_terminal_open_v1 open;
    uint8_t expected_responder_master[32];
    uint8_t expected_responder_online[32];
    uint8_t peer_noise_static[32];
    char pairing_id_hex[MESH_PAIRING_ID_HEX + 1];
    enum mesh_terminal_receipt_status verdict;
    uint8_t close_reason; /* enum mesh_terminal_close_reason, when named */
    uint64_t opened_unix;
    uint64_t last_activity_unix;
    uint64_t seq_out; /* last outbound DATA seq */
    uint64_t seq_in;  /* last accepted inbound DATA seq */
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint8_t output[MESH_TERMINAL_CLIENT_OUTPUT_MAX];
    size_t output_len;
};

/* Quiet-drop counters: in-namespace garbage and unauthenticated probes are
 * local policy events, never offences against the peer. */
static _Atomic uint64_t g_client_dropped_malformed;
static _Atomic uint64_t g_client_receipts_refused;
static _Atomic uint64_t g_client_output_overflow;

const char *boot_mesh_terminal_open_result_string(
    enum boot_mesh_terminal_open_result result)
{
    switch (result) {
    case MESH_TERMINAL_OPEN_OK: return "ok";
    case MESH_TERMINAL_OPEN_BAD_ARGUMENT: return "bad_argument";
    case MESH_TERMINAL_OPEN_UNAVAILABLE: return "unavailable";
    case MESH_TERMINAL_OPEN_NOISE_DISABLED:
        return "noise_transport_disabled";
    case MESH_TERMINAL_OPEN_NOT_PAIRED: return "not_paired";
    case MESH_TERMINAL_OPEN_REVOKED: return "revoked";
    case MESH_TERMINAL_OPEN_EXPIRED: return "expired";
    case MESH_TERMINAL_OPEN_PEER_NOT_CONNECTED: return "peer_not_connected";
    case MESH_TERMINAL_OPEN_IDENTITY_UNAVAILABLE:
        return "identity_unavailable";
    case MESH_TERMINAL_OPEN_PEER_IDENTITY_UNAVAILABLE:
        return "peer_identity_unavailable";
    case MESH_TERMINAL_OPEN_BUSY: return "busy";
    case MESH_TERMINAL_OPEN_SEND_FAILED: return "send_failed";
    }
    return "bad_argument";
}

const char *boot_mesh_terminal_client_state_string(
    enum boot_mesh_terminal_client_state state)
{
    switch (state) {
    case MESH_TERMINAL_CLIENT_OPENING: return "opening";
    case MESH_TERMINAL_CLIENT_LIVE: return "live";
    case MESH_TERMINAL_CLIENT_REFUSED: return "refused";
    case MESH_TERMINAL_CLIENT_ENDED: return "ended";
    case MESH_TERMINAL_CLIENT_UNKNOWN: return "unknown";
    }
    return "unknown";
}

struct boot_svc_ctx *boot_mesh_terminal_client_service(void)
{
    return g_client_svc;
}

void boot_mesh_terminal_client_wire(struct boot_svc_ctx *svc)
{
    g_client_svc = svc;
}

void boot_mesh_terminal_client_shutdown(void)
{
    g_client_svc = NULL;
}

/* ── Reaching one session ────────────────────────────────────────────── */

/* Every verb below runs its whole body inside a stream visit, so the
 * session it touches is alive for exactly as long as it is touched and
 * the stream's lane lock is the only lock in the lane. */
struct client_visit {
    const uint8_t *terminal_id;
    bool found;
    /* Per-verb inputs and outputs. */
    const uint8_t *bytes;
    size_t len;
    uint8_t *out;
    size_t out_cap;
    size_t moved;
    bool ok;
    uint16_t cols;
    uint16_t rows;
    struct boot_mesh_terminal_client_view *view;
    enum boot_mesh_terminal_client_state state;
    size_t live;
};

static struct mesh_terminal_client_session *client_session(
    const struct mesh_stream *st, const uint8_t terminal_id[32])
{
    struct mesh_terminal_client_session *s = st->service_state;
    if (!st->local_initiator || !s)
        return NULL;
    if (terminal_id && memcmp(s->open.terminal_id, terminal_id, 32) != 0)
        return NULL;
    return s;
}

/* One watchdog pass over a session: the OPEN receipt must arrive inside
 * the answer window, and a live session obeys the granted idle and
 * lifetime ceilings. Ending is local and silent — the responder's
 * watchdogs and this one are independent, by design. */
static void client_watchdog(struct mesh_terminal_client_session *s,
                            uint64_t now_unix)
{
    if (s->ended)
        return;
    if (!s->open_confirmed &&
        now_unix >=
            s->opened_unix + MESH_TERMINAL_CLIENT_RECEIPT_TIMEOUT_SECONDS) {
        s->ended = true;
        s->verdict = MESH_TERMINAL_RECEIPT_EXPIRED;
        return;
    }
    if (!s->open_confirmed)
        return;
    if (now_unix >= s->opened_unix + MESH_TERMINAL_SERVICE_LIFETIME_SECONDS) {
        s->ended = true;
        s->close_reason = MESH_TERMINAL_CLOSE_LIFETIME_LIMIT;
        s->close_reason_named = true;
        return;
    }
    if (now_unix >=
        s->last_activity_unix + MESH_TERMINAL_SERVICE_IDLE_SECONDS) {
        s->ended = true;
        s->close_reason = MESH_TERMINAL_CLOSE_IDLE_TIMEOUT;
        s->close_reason_named = true;
    }
}

void boot_mesh_terminal_client_tick(struct mesh_stream *st, uint64_t now_unix)
{
    struct mesh_terminal_client_session *s = client_session(st, NULL);
    if (s)
        client_watchdog(s, now_unix);
}

/* ── Message ingress ─────────────────────────────────────────────────── */

/* The receipt must bind the CURRENT session with the responder: the
 * signature (verified inside decode, under the receipt's embedded online
 * key) and matches_open alone would accept a receipt minted on an older
 * connection or by a different key, so the stream's live binding and the
 * delegation-derived responder identity are checked here — exactly the
 * status lane's receipt_accept discipline. */
static bool client_receipt_binds(
    const struct mesh_terminal_client_session *s,
    const struct mesh_terminal_receipt_v1 *receipt,
    const struct noise_transport_snapshot *session)
{
    if (!session || !session->established)
        return false;
    if (memcmp(receipt->transcript_hash, s->open.transcript_hash, 32) != 0 ||
        receipt->connection_generation != s->open.connection_generation)
        return false;
    /* The arrival transport must be the very session the open was sent
     * on: a second connection to the same responder carries the same
     * remote static but a different transcript, and must not arm the
     * session (the DATA path makes the identical demand). */
    if (memcmp(session->transcript_hash, s->open.transcript_hash, 32) != 0 ||
        session->connection_generation != s->open.connection_generation)
        return false;
    if (memcmp(receipt->responder_noise_static, s->peer_noise_static, 32) !=
            0 ||
        memcmp(session->remote_static, s->peer_noise_static, 32) != 0)
        return false;
    if (memcmp(receipt->responder_master_pubkey,
               s->expected_responder_master, 32) != 0 ||
        memcmp(receipt->responder_online_pubkey,
               s->expected_responder_online, 32) != 0)
        return false;
    return true;
}

static void client_receipt(struct mesh_stream *st,
                           struct mesh_terminal_client_session *s,
                           const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_receipt_v1 receipt;
    if (mesh_terminal_receipt_v1_decode(&receipt, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    struct noise_transport_snapshot session;
    boot_mesh_terminal_stream_session(st, &session);
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    if (memcmp(receipt.request_id, s->open.terminal_id, 32) != 0 || s->ended ||
        !client_receipt_binds(s, &receipt, &session) ||
        mesh_terminal_receipt_v1_matches_open(&receipt, &s->open) !=
            MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_client_receipts_refused, 1);
        return;
    }
    if (receipt.status == MESH_TERMINAL_RECEIPT_CLOSED) {
        /* The responder ended the session and sent its evidence; keep the
         * verdict inspectable until the stream's linger runs out. The
         * named reason lives in the receipt's evidence capsule on the
         * responder, so the local view does not invent one. */
        s->verdict = MESH_TERMINAL_RECEIPT_CLOSED;
        s->ended = true;
        s->close_reason_named = false;
        s->last_activity_unix = now;
    } else if (receipt.status == MESH_TERMINAL_RECEIPT_OK &&
               !s->open_confirmed) {
        s->open_confirmed = true;
        s->verdict = MESH_TERMINAL_RECEIPT_OK;
        s->last_activity_unix = now;
    } else if (!s->open_confirmed) {
        /* A named refusal ends the never-armed session with the
         * responder's verdict: no grant was made, so poll reports REFUSED
         * and the verdict stays inspectable until the requester reaps it. */
        s->verdict = receipt.status;
        s->ended = true;
        s->close_reason_named = false;
        s->last_activity_unix = now;
    } else {
        /* Duplicate OK, or a refusal after live (the responder never
         * refuses an armed session): count, not re-arm, not end. */
        atomic_fetch_add(&g_client_receipts_refused, 1);
    }
}

/* Screen bytes into the bounded FIFO. Returns how many bytes were kept,
 * so the caller grants back exactly what it did not retain. */
static size_t client_screen(struct mesh_terminal_client_session *s,
                            const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_data_v1 data;
    if (mesh_terminal_data_v1_decode(&data, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return 0;
    }
    if (!s->open_confirmed || s->ended || data.seq <= s->seq_in ||
        memcmp(data.terminal_id, s->open.terminal_id, 32) != 0) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return 0;
    }
    if (data.payload_len > MESH_TERMINAL_DATA_PAYLOAD_MAX ||
        s->output_len + data.payload_len > sizeof(s->output)) {
        /* The bounded FIFO is full: drop the frame rather than grow. The
         * responder's own 1 MiB byte-out ceiling makes this a laggard
         * reader, not an unbounded peer. */
        atomic_fetch_add(&g_client_output_overflow, 1);
        return 0;
    }
    memcpy(s->output + s->output_len, data.payload, data.payload_len);
    s->output_len += data.payload_len;
    s->seq_in = data.seq;
    s->bytes_out += data.payload_len;
    s->last_activity_unix = (uint64_t)platform_time_wall_time_t();
    return data.payload_len;
}

static void client_close_message(struct mesh_terminal_client_session *s,
                                 const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_close_v1 close_frame;
    if (mesh_terminal_close_v1_decode(&close_frame, wire, wire_len) !=
            MESH_TERMINAL_PROTO_OK ||
        memcmp(close_frame.terminal_id, s->open.terminal_id, 32) != 0 ||
        !s->open_confirmed) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    s->ended = true;
    s->close_reason = close_frame.reason;
    s->close_reason_named = true;
}

void boot_mesh_terminal_client_message(struct mesh_stream *st,
                                       const uint8_t *payload, size_t len)
{
    struct mesh_terminal_client_session *s = client_session(st, NULL);
    if (!s || len < 1u) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        (void)mesh_stream_grant(st, (uint32_t)len);
        return;
    }
    const uint8_t *wire = payload + 1;
    size_t wire_len = len - 1u;
    size_t kept = 0;
    switch (payload[0]) {
    case MESH_TERMINAL_MSG_RECEIPT:
        client_receipt(st, s, wire, wire_len);
        break;
    case MESH_TERMINAL_MSG_DATA:
        kept = client_screen(s, wire, wire_len);
        break;
    case MESH_TERMINAL_MSG_CLOSE:
        client_close_message(s, wire, wire_len);
        break;
    default:
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        break;
    }
    /* Credit is the FIFO: everything this lane did not retain is granted
     * back at once, and the retained screen bytes are granted when the
     * reader drains them. A responder can therefore never run further
     * ahead than the reader has room for. */
    if (len > kept)
        (void)mesh_stream_grant(st, (uint32_t)(len - kept));
}

void boot_mesh_terminal_client_ended(struct mesh_stream *st,
                                     enum mesh_stream_refusal reason,
                                     const uint8_t *payload, size_t len)
{
    struct mesh_terminal_client_session *s = client_session(st, NULL);
    if (!s)
        return;
    /* The responder's own verdict, when it sent one with the close. */
    if (payload && len >= 1u) {
        if (payload[0] == MESH_TERMINAL_MSG_RECEIPT)
            client_receipt(st, s, payload + 1, len - 1u);
        else if (payload[0] == MESH_TERMINAL_MSG_CLOSE)
            client_close_message(s, payload + 1, len - 1u);
    }
    if (s->ended)
        return;
    s->ended = true;
    /* No service verdict arrived: name the ending from the stream's own
     * reason so the requester never has to guess. */
    switch (reason) {
    case MESH_STREAM_REFUSED_PEER_UNPAIRED:
        s->verdict = MESH_TERMINAL_RECEIPT_NOT_PAIRED;
        break;
    case MESH_STREAM_REFUSED_SERVICE_UNKNOWN:
    case MESH_STREAM_REFUSED_LINK_NOT_NOISE:
        s->verdict = MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE;
        break;
    case MESH_STREAM_REFUSED_CAP:
        s->verdict = MESH_TERMINAL_RECEIPT_CONCURRENCY_LIMIT;
        break;
    case MESH_STREAM_ENDED_IDLE:
        s->close_reason = MESH_TERMINAL_CLOSE_IDLE_TIMEOUT;
        s->close_reason_named = true;
        break;
    case MESH_STREAM_ENDED_SESSION_LOST:
    case MESH_STREAM_ENDED_SHUTDOWN:
        s->close_reason = MESH_TERMINAL_CLOSE_SESSION_LOST;
        s->close_reason_named = true;
        break;
    case MESH_STREAM_REFUSED_CREDIT_EXCEEDED:
        /* The peer sent more than the reader had room for. On an armed
         * session that is the byte budget, by name; before the grant it
         * is a peer that never spoke this lane's protocol. */
        if (!s->open_confirmed)
            s->verdict = MESH_TERMINAL_RECEIPT_SESSION_MISMATCH;
        else {
            s->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
            s->close_reason_named = true;
        }
        break;
    default:
        if (!s->open_confirmed)
            s->verdict = MESH_TERMINAL_RECEIPT_SESSION_MISMATCH;
        else {
            s->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
            s->close_reason_named = true;
        }
        break;
    }
}

void boot_mesh_terminal_client_release(struct mesh_stream *st)
{
    struct mesh_terminal_client_session *s = st->service_state;
    st->service_state = NULL;
    if (!s)
        return;
    memory_cleanse(s, sizeof(*s));
    free(s);
}

/* ── Open ────────────────────────────────────────────────────────────── */

/* Counts live requester streams and refuses a terminal id already in
 * flight, in one pass over the one table. */
static bool client_open_survey(struct mesh_stream *st, void *ctx)
{
    struct client_visit *v = ctx;
    struct mesh_terminal_client_session *s = client_session(st, NULL);
    if (!s)
        return true;
    v->live++;
    if (v->terminal_id &&
        memcmp(s->open.terminal_id, v->terminal_id, 32) == 0)
        v->found = true;
    return true;
}

enum boot_mesh_terminal_open_result boot_mesh_terminal_client_open(
    const char *pairing_id_hex, uint16_t cols, uint16_t rows,
    uint8_t terminal_id_out[32])
{
    uint8_t pairing_id[32];
    if (!pairing_id_hex || strlen(pairing_id_hex) != MESH_PAIRING_ID_HEX ||
        !zcl_hex_decode_lower(pairing_id_hex, pairing_id, 32) ||
        !terminal_id_out || cols > MESH_TERMINAL_MAX_COLS ||
        rows > MESH_TERMINAL_MAX_ROWS)
        return MESH_TERMINAL_OPEN_BAD_ARGUMENT;

    struct boot_svc_ctx *svc = boot_mesh_terminal_client_service();
    if (!svc || !svc->msg_processor || !svc->datadir)
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    struct msg_processor *mp = svc->msg_processor;
    if (!mp->net_mgr || !mp->params) {
        LOG_ERROR("net.mesh_terminal", "client open: msg_processor incomplete");
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    }
    if (!mp->net_mgr->noise_enabled)
        return MESH_TERMINAL_OPEN_NOISE_DISABLED;

    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_ERROR("net.mesh_terminal", "client open: node_db unavailable");
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0) {
        LOG_ERROR("net.mesh_terminal", "client open: wall clock unavailable");
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    }
    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id_hex, &row))
        return MESH_TERMINAL_OPEN_NOT_PAIRED;
    if (!mesh_pairing_allows(&row, MESH_PAIRING_CAP_TERMINAL_EXEC, now))
        return row.revoked_at != 0 ? MESH_TERMINAL_OPEN_REVOKED
                                   : MESH_TERMINAL_OPEN_EXPIRED;

    /* The open names OUR anchored master identity from the filed local
     * delegation; without it no honest open can be composed. */
    struct vcs_zcode_dht_delegation local;
    char error[160];
    if (!vcs_zcode_dht_delegation_load(svc->datadir, &local, error,
                                       sizeof(error))) {
        LOG_ERROR("net.mesh_terminal",
                  "client open: local delegation unavailable (%s)", error);
        return MESH_TERMINAL_OPEN_IDENTITY_UNAVAILABLE;
    }

    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    struct p2p_node *peer = boot_mesh_find_session_peer(
        mp->net_mgr, row.peer_noise_pubkey, &session);
    if (!peer)
        return MESH_TERMINAL_OPEN_PEER_NOT_CONNECTED;

    /* Pre-flight the exact authority the responder will re-verify: the
     * peer's greatest-seq held delegation must support this pairing. */
    struct vcs_zcode_dht_delegation responder_delegation;
    uint8_t network_genesis[32];
    if (!boot_mesh_peer_delegation(&row, &responder_delegation) ||
        !boot_zcode_dht_network_genesis(network_genesis) ||
        mesh_pairing_service_authorize_terminal(
            ndb, network_genesis, pairing_id_hex, &responder_delegation,
            session.remote_static, now) != MESH_PAIRING_OK) {
        p2p_node_release(peer);
        return MESH_TERMINAL_OPEN_PEER_IDENTITY_UNAVAILABLE;
    }
    p2p_node_release(peer);

    struct mesh_terminal_open_v1 open;
    memset(&open, 0, sizeof(open));
    open.version = MESH_TERMINAL_PROTO_VERSION;
    open.flags = MESH_TERMINAL_PROTO_FLAGS_NONE;
    open.capability = MESH_TERMINAL_CAP_TERMINAL_EXEC;
    bool have_id = false;
    for (int attempt = 0; attempt < 4 && !have_id; attempt++) {
        if (!zcl_random_secret_bytes(open.terminal_id, 32,
                                     "mesh_terminal_open")) {
            LOG_ERROR("net.mesh_terminal",
                      "client open: terminal id generation failed");
            return MESH_TERMINAL_OPEN_UNAVAILABLE;
        }
        struct client_visit v;
        memset(&v, 0, sizeof(v));
        v.terminal_id = open.terminal_id;
        mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_open_survey, &v);
        if (v.live >= MESH_TERMINAL_CLIENT_SESSIONS_MAX)
            return MESH_TERMINAL_OPEN_BUSY;
        have_id = !v.found;
    }
    if (!have_id) {
        LOG_ERROR("net.mesh_terminal",
                  "client open: terminal id collision persisted");
        return MESH_TERMINAL_OPEN_BUSY;
    }
    memcpy(open.network_genesis,
           mp->params->consensus.hashGenesisBlock.data, 32);
    memcpy(open.target_master_pubkey, row.peer_master_pubkey, 32);
    memcpy(open.requester_master_pubkey, local.doc.master_pubkey, 32);
    memcpy(open.requester_noise_static, mp->net_mgr->identity_pub, 32);
    memcpy(open.pairing_id, pairing_id, 32);
    /* The open binds the shared session evidence; the responder's decide
     * refuses anything else. */
    memcpy(open.transcript_hash, session.transcript_hash, 32);
    open.connection_generation = session.connection_generation;
    open.issued_unix = (uint64_t)now;
    open.expires_unix = (uint64_t)now + MESH_TERMINAL_OPEN_MAX_LIFETIME_SECONDS;
    open.cols = cols ? cols : 80;
    open.rows = rows ? rows : 24;

    uint8_t wire[MESH_TERMINAL_OPEN_V1_WIRE_BYTES];
    enum mesh_terminal_proto_error encoded =
        mesh_terminal_open_v1_encode(&open, wire);
    if (encoded != MESH_TERMINAL_PROTO_OK) {
        LOG_ERROR("net.mesh_terminal", "client open: encode failed: %s",
                  mesh_terminal_proto_error_string(encoded));
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    }

    struct mesh_terminal_client_session *s =
        zcl_calloc(1, sizeof(*s), "mesh_terminal_client_session");
    if (!s)
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    s->open = open;
    memcpy(s->expected_responder_master, row.peer_master_pubkey, 32);
    memcpy(s->expected_responder_online, responder_delegation.online_pubkey,
           32);
    memcpy(s->peer_noise_static, session.remote_static, 32);
    snprintf(s->pairing_id_hex, sizeof(s->pairing_id_hex), "%s",
             pairing_id_hex);
    s->verdict = MESH_TERMINAL_RECEIPT_INTERNAL;
    s->opened_unix = (uint64_t)now;
    s->last_activity_unix = (uint64_t)now;

    /* The stream slot is reserved before the OPEN reaches the wire, so a
     * fast receipt can never arrive to a missing session. The credit this
     * open grants is exactly the screen FIFO: the responder can never run
     * further ahead than this lane has room to keep. */
    enum mesh_stream_refusal opened = mesh_stream_open(
        MESH_TERMINAL_SERVICE_NAME, session.remote_static,
        (uint32_t)MESH_TERMINAL_CLIENT_OUTPUT_MAX, wire, sizeof(wire), s,
        NULL);
    if (opened != MESH_STREAM_OK) {
        memory_cleanse(s, sizeof(*s));
        free(s);
        LOG_ERROR("net.mesh_terminal", "client open refused: %s",
                  mesh_stream_refusal_string(opened));
        switch (opened) {
        case MESH_STREAM_REFUSED_PEER_NOT_CONNECTED:
            return MESH_TERMINAL_OPEN_PEER_NOT_CONNECTED;
        case MESH_STREAM_REFUSED_CAP:
        case MESH_STREAM_REFUSED_ID_IN_USE:
            return MESH_TERMINAL_OPEN_BUSY;
        case MESH_STREAM_REFUSED_LINK_NOT_NOISE:
            return MESH_TERMINAL_OPEN_NOISE_DISABLED;
        default:
            return MESH_TERMINAL_OPEN_SEND_FAILED;
        }
    }
    memcpy(terminal_id_out, open.terminal_id, 32);
    return MESH_TERMINAL_OPEN_OK;
}

/* ── Session verbs ───────────────────────────────────────────────────── */

static bool client_poll_visit(struct mesh_stream *st, void *ctx)
{
    struct client_visit *v = ctx;
    struct mesh_terminal_client_session *s =
        client_session(st, v->terminal_id);
    if (!s)
        return true;
    v->found = true;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    client_watchdog(s, now);
    if (v->view) {
        memset(v->view, 0, sizeof(*v->view));
        v->view->verdict = s->verdict;
        v->view->close_reason =
            (enum mesh_terminal_close_reason)s->close_reason;
        v->view->close_reason_named = s->close_reason_named;
        v->view->cols = s->open.cols;
        v->view->rows = s->open.rows;
        v->view->bytes_in = s->bytes_in;
        v->view->bytes_out = s->bytes_out;
        v->view->output_pending = s->output_len;
        v->view->idle_seconds =
            now > s->last_activity_unix ? now - s->last_activity_unix : 0;
    }
    /* REFUSED means no terminal was ever granted: an unanswered OPEN or a
     * named refusal. ENDED means a terminal existed and finished — a
     * locally named close reason (watchdog expiry, the responder's close,
     * the operator's close), the OK verdict, or the CLOSED receipt. */
    v->state =
        s->ended
            ? ((s->verdict == MESH_TERMINAL_RECEIPT_OK ||
                s->verdict == MESH_TERMINAL_RECEIPT_CLOSED ||
                s->close_reason_named)
                   ? MESH_TERMINAL_CLIENT_ENDED
                   : MESH_TERMINAL_CLIENT_REFUSED)
            : (s->open_confirmed ? MESH_TERMINAL_CLIENT_LIVE
                                 : MESH_TERMINAL_CLIENT_OPENING);
    return false;
}

enum boot_mesh_terminal_client_state boot_mesh_terminal_client_poll(
    const uint8_t terminal_id[32],
    struct boot_mesh_terminal_client_view *view_out)
{
    if (!terminal_id)
        return MESH_TERMINAL_CLIENT_UNKNOWN;
    struct client_visit v;
    memset(&v, 0, sizeof(v));
    v.terminal_id = terminal_id;
    v.view = view_out;
    v.state = MESH_TERMINAL_CLIENT_UNKNOWN;
    mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_poll_visit, &v);
    return v.found ? v.state : MESH_TERMINAL_CLIENT_UNKNOWN;
}

static bool client_drain_visit(struct mesh_stream *st, void *ctx)
{
    struct client_visit *v = ctx;
    struct mesh_terminal_client_session *s =
        client_session(st, v->terminal_id);
    if (!s)
        return true;
    v->found = true;
    if (s->output_len) {
        v->moved = s->output_len < v->out_cap ? s->output_len : v->out_cap;
        memcpy(v->out, s->output, v->moved);
        memmove(s->output, s->output + v->moved, s->output_len - v->moved);
        s->output_len -= v->moved;
        /* The reader made room: hand that much credit back so the
         * responder may send again. */
        (void)mesh_stream_grant(st, (uint32_t)v->moved);
    }
    return false;
}

size_t boot_mesh_terminal_client_drain(const uint8_t terminal_id[32],
                                       uint8_t *out, size_t out_cap)
{
    if (!terminal_id || !out || out_cap == 0)
        return 0;
    struct client_visit v;
    memset(&v, 0, sizeof(v));
    v.terminal_id = terminal_id;
    v.out = out;
    v.out_cap = out_cap;
    mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_drain_visit, &v);
    return v.moved;
}

static bool client_write_visit(struct mesh_stream *st, void *ctx)
{
    struct client_visit *v = ctx;
    struct mesh_terminal_client_session *s =
        client_session(st, v->terminal_id);
    if (!s)
        return true;
    v->found = true;
    if (!s->open_confirmed || s->ended ||
        s->bytes_in + v->len > MESH_TERMINAL_SERVICE_MAX_BYTES_IN)
        return false;
    uint64_t seq = s->seq_out;
    uint64_t sent_bytes = 0;
    bool ok = true;
    for (size_t off = 0; off < v->len && ok;) {
        size_t take = v->len - off < MESH_TERMINAL_DATA_PAYLOAD_MAX
                          ? v->len - off
                          : MESH_TERMINAL_DATA_PAYLOAD_MAX;
        struct mesh_terminal_data_v1 data;
        memset(&data, 0, sizeof(data));
        memcpy(data.terminal_id, s->open.terminal_id, 32);
        data.seq = ++seq;
        data.payload_len = (uint16_t)take;
        memcpy(data.payload, v->bytes + off, take);
        uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t msg[MESH_TERMINAL_MSG_MAX];
        size_t msg_len = 0;
        if (mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                         &wire_len) == MESH_TERMINAL_PROTO_OK)
            msg_len = boot_mesh_terminal_msg(MESH_TERMINAL_MSG_DATA, wire,
                                             wire_len, msg, sizeof(msg));
        if (!msg_len || !mesh_stream_send(st, msg, msg_len)) {
            ok = false;
            break;
        }
        sent_bytes += take;
        off += take;
    }
    if (sent_bytes) {
        s->seq_out = ok ? seq : seq - 1;
        s->bytes_in += sent_bytes;
        s->last_activity_unix = (uint64_t)platform_time_wall_time_t();
    }
    v->ok = ok;
    return false;
}

bool boot_mesh_terminal_client_write(const uint8_t terminal_id[32],
                                     const uint8_t *bytes, size_t len)
{
    if (!terminal_id || !bytes || len == 0)
        return false;
    struct client_visit v;
    memset(&v, 0, sizeof(v));
    v.terminal_id = terminal_id;
    v.bytes = bytes;
    v.len = len;
    mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_write_visit, &v);
    return v.ok;
}

static bool client_resize_visit(struct mesh_stream *st, void *ctx)
{
    struct client_visit *v = ctx;
    struct mesh_terminal_client_session *s =
        client_session(st, v->terminal_id);
    if (!s)
        return true;
    v->found = true;
    if (!s->open_confirmed || s->ended)
        return false;
    struct mesh_terminal_resize_v1 resize;
    memset(&resize, 0, sizeof(resize));
    memcpy(resize.terminal_id, s->open.terminal_id, 32);
    resize.cols = v->cols;
    resize.rows = v->rows;
    uint8_t wire[MESH_TERMINAL_RESIZE_V1_WIRE_BYTES];
    if (mesh_terminal_resize_v1_encode(&resize, wire) !=
        MESH_TERMINAL_PROTO_OK)
        return false;
    uint8_t msg[MESH_TERMINAL_MSG_MAX];
    size_t msg_len = boot_mesh_terminal_msg(MESH_TERMINAL_MSG_RESIZE, wire,
                                            sizeof(wire), msg, sizeof(msg));
    v->ok = msg_len && mesh_stream_send(st, msg, msg_len);
    return false;
}

bool boot_mesh_terminal_client_resize(const uint8_t terminal_id[32],
                                      uint16_t cols, uint16_t rows)
{
    if (!terminal_id || cols == 0 || cols > MESH_TERMINAL_MAX_COLS ||
        rows == 0 || rows > MESH_TERMINAL_MAX_ROWS)
        return false;
    struct client_visit v;
    memset(&v, 0, sizeof(v));
    v.terminal_id = terminal_id;
    v.cols = cols;
    v.rows = rows;
    mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_resize_visit, &v);
    return v.ok;
}

static bool client_close_visit(struct mesh_stream *st, void *ctx)
{
    struct client_visit *v = ctx;
    struct mesh_terminal_client_session *s =
        client_session(st, v->terminal_id);
    if (!s)
        return true;
    v->found = true;
    if (s->ended)
        return false;
    /* Best-effort close message to the bound peer; a session whose
     * connection already died just ends locally, which is the honest
     * state. The responder answers with its CLOSED evidence and ends the
     * stream, so no stream is closed from here. */
    struct mesh_terminal_close_v1 close_frame;
    memset(&close_frame, 0, sizeof(close_frame));
    memcpy(close_frame.terminal_id, s->open.terminal_id, 32);
    close_frame.reason = MESH_TERMINAL_CLOSE_REQUESTED;
    uint8_t wire[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
    if (mesh_terminal_close_v1_encode(&close_frame, wire) ==
        MESH_TERMINAL_PROTO_OK) {
        uint8_t msg[MESH_TERMINAL_MSG_MAX];
        size_t msg_len = boot_mesh_terminal_msg(MESH_TERMINAL_MSG_CLOSE, wire,
                                                sizeof(wire), msg,
                                                sizeof(msg));
        if (msg_len)
            (void)mesh_stream_send(st, msg, msg_len);
    }
    s->ended = true;
    s->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
    s->close_reason_named = true;
    return false;
}

bool boot_mesh_terminal_client_close(const uint8_t terminal_id[32])
{
    if (!terminal_id)
        return false;
    struct client_visit v;
    memset(&v, 0, sizeof(v));
    v.terminal_id = terminal_id;
    mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_close_visit, &v);
    return v.found;
}

/* ── Test seam ───────────────────────────────────────────────────────── */

#ifdef ZCL_TESTING
static uint64_t g_client_test_id;

bool boot_mesh_terminal_client_test_inject(
    const struct mesh_terminal_open_v1 *open,
    const uint8_t expected_responder_master[32],
    const uint8_t expected_responder_online[32],
    const uint8_t peer_noise_static[32], const char *pairing_id_hex,
    uint64_t opened_unix, uint64_t last_activity_unix, bool open_confirmed,
    uint8_t terminal_id_out[32], uint64_t *stream_id_out)
{
    if (!open || !expected_responder_master || !expected_responder_online ||
        !peer_noise_static || !terminal_id_out)
        return false;
    /* The seam reserves a session exactly as the open path does, ceiling
     * included: a fifth concurrent requester session is refused. */
    struct client_visit survey;
    memset(&survey, 0, sizeof(survey));
    mesh_stream_visit(MESH_TERMINAL_SERVICE_NAME, client_open_survey,
                      &survey);
    if (survey.live >= MESH_TERMINAL_CLIENT_SESSIONS_MAX)
        return false;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    struct mesh_terminal_client_session *s =
        zcl_calloc(1, sizeof(*s), "mesh_terminal_client_session");
    if (!s)
        return false;
    s->open = *open;
    memcpy(s->expected_responder_master, expected_responder_master, 32);
    memcpy(s->expected_responder_online, expected_responder_online, 32);
    memcpy(s->peer_noise_static, peer_noise_static, 32);
    if (pairing_id_hex)
        snprintf(s->pairing_id_hex, sizeof(s->pairing_id_hex), "%s",
                 pairing_id_hex);
    s->verdict = MESH_TERMINAL_RECEIPT_INTERNAL;
    s->opened_unix = opened_unix ? opened_unix : now;
    s->last_activity_unix = last_activity_unix ? last_activity_unix : now;
    s->open_confirmed = open_confirmed;
    if (!mesh_stream_test_inject(MESH_TERMINAL_SERVICE_NAME, peer_noise_static,
                                 open->transcript_hash,
                                 open->connection_generation, true,
                                 g_client_test_id,
                                 (uint32_t)MESH_TERMINAL_CLIENT_OUTPUT_MAX,
                                 s)) {
        memory_cleanse(s, sizeof(*s));
        free(s);
        return false;
    }
    if (stream_id_out)
        *stream_id_out = g_client_test_id;
    g_client_test_id += 2u;
    memcpy(terminal_id_out, open->terminal_id, 32);
    return true;
}

void boot_mesh_terminal_client_test_reset(void)
{
    /* Unregister first: that ends and releases every terminal stream, so
     * no injected session outlives the reset. */
    mesh_stream_service_unregister(MESH_TERMINAL_SERVICE_NAME);
    mesh_stream_test_reset();
    (void)boot_mesh_terminal_register_service();
    g_client_test_id = 0;
}
#endif
