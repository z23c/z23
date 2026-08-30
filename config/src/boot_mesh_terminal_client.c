/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Mesh terminal requester lane: begin one pairing-bound confined
 * terminal against a paired peer's live Noise session, then pump bounded
 * DATA both ways through poll/write/drain until watchdogs or a named
 * close ends it. Mirrors boot_mesh_status_requester.c's begin discipline;
 * frame ingress and the responder lane live in boot_mesh_terminal.c (see
 * the internal header for the seam). */

// one-result-type-ok:closed-security-verdict — open/poll/write return
// bounded verdicts the caller must branch on; no diagnostic text crosses
// the wire. Drop/refusal logging happens here at the request edge.

#include "config/boot_mesh_terminal.h"
#include "boot_mesh_status_internal.h"
#include "boot_mesh_terminal_internal.h"

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "crypto/random_secret.h"
#include "models/mesh_pairing.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static zcl_mutex_t g_client_lock;
static _Atomic int g_client_lock_state;
static struct boot_svc_ctx *g_client_svc; /* borrowed; set by wire() */

struct mesh_terminal_client_session {
    bool used;
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
static struct mesh_terminal_client_session
    g_sessions[MESH_TERMINAL_CLIENT_SESSIONS_MAX];

/* Quiet-drop counters: in-namespace garbage and unauthenticated probes are
 * local policy events, never offences against the peer. */
static _Atomic uint64_t g_client_dropped_unauthenticated;
static _Atomic uint64_t g_client_dropped_malformed;
static _Atomic uint64_t g_client_receipts_refused;
static _Atomic uint64_t g_client_output_overflow;

static void client_lock(void)
{
    if (atomic_load_explicit(&g_client_lock_state, memory_order_acquire) !=
        2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_client_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_client_lock);
            atomic_store_explicit(&g_client_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_client_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_client_lock);
}

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
    client_lock();
    struct boot_svc_ctx *svc = g_client_svc;
    zcl_mutex_unlock(&g_client_lock);
    return svc;
}

void boot_mesh_terminal_client_wire(struct boot_svc_ctx *svc)
{
    client_lock();
    g_client_svc = svc;
    memset(g_sessions, 0, sizeof(g_sessions));
    zcl_mutex_unlock(&g_client_lock);
}

void boot_mesh_terminal_client_shutdown(void)
{
    client_lock();
    g_client_svc = NULL;
    memset(g_sessions, 0, sizeof(g_sessions));
    zcl_mutex_unlock(&g_client_lock);
}

/* ── Table helpers (locked) ──────────────────────────────────────────── */

static struct mesh_terminal_client_session *client_find_locked(
    const uint8_t terminal_id[32])
{
    for (size_t i = 0; i < MESH_TERMINAL_CLIENT_SESSIONS_MAX; i++) {
        if (g_sessions[i].used &&
            memcmp(g_sessions[i].open.terminal_id, terminal_id, 32) == 0)
            return &g_sessions[i];
    }
    return NULL;
}

/* One watchdog pass over a session: the OPEN receipt must arrive inside
 * the answer window, and a live session obeys the granted idle and
 * lifetime ceilings. Ending is local and silent where no bound peer
 * session exists to hear a CLOSE — the responder's watchdogs and this one
 * are independent, by design. */
static void client_watchdog_locked(struct mesh_terminal_client_session *s,
                                   uint64_t now_unix)
{
    if (!s->used || s->ended)
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
    if (now_unix >=
        s->opened_unix + MESH_TERMINAL_SERVICE_LIFETIME_SECONDS) {
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

/* The receipt must bind the CURRENT session with the responder: the
 * signature (verified inside decode, under the receipt's embedded online
 * key) and matches_open alone would accept a receipt minted on an older
 * connection or by a different key, so the live snapshot and the
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

/* Resolve the live bound peer for a session verb, under the lane lock (the
 * responder's pump takes net-locks under the lane lock too, so this keeps
 * one lock order everywhere). Returns a referenced node or NULL; the
 * caller releases. */
static struct p2p_node *client_bound_peer_locked(
    struct boot_svc_ctx *svc, const struct mesh_terminal_client_session *s,
    struct noise_transport_snapshot *snap_out)
{
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr)
        return NULL;
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    struct p2p_node *peer = boot_mesh_find_session_peer(
        svc->msg_processor->net_mgr, s->peer_noise_static, &snap);
    if (!peer)
        return NULL;
    if (!snap.established ||
        memcmp(snap.transcript_hash, s->open.transcript_hash, 32) != 0 ||
        snap.connection_generation != s->open.connection_generation ||
        memcmp(snap.remote_static, s->peer_noise_static, 32) != 0) {
        p2p_node_release(peer);
        return NULL;
    }
    if (snap_out)
        *snap_out = snap;
    return peer;
}

/* ── Open ────────────────────────────────────────────────────────────── */

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
    if (!boot_mesh_peer_delegation(&row, &responder_delegation) ||
        mesh_pairing_service_authorize_terminal(
            ndb, pairing_id_hex, &responder_delegation, session.remote_static,
            now) != MESH_PAIRING_OK) {
        p2p_node_release(peer);
        return MESH_TERMINAL_OPEN_PEER_IDENTITY_UNAVAILABLE;
    }

    struct mesh_terminal_open_v1 open;
    memset(&open, 0, sizeof(open));
    open.version = MESH_TERMINAL_PROTO_VERSION;
    open.flags = MESH_TERMINAL_PROTO_FLAGS_NONE;
    open.capability = MESH_TERMINAL_CAP_TERMINAL_EXEC;
    bool have_id = false;
    for (int attempt = 0; attempt < 4 && !have_id; attempt++) {
        if (!zcl_random_secret_bytes(open.terminal_id, 32,
                                     "mesh_terminal_open")) {
            p2p_node_release(peer);
            LOG_ERROR("net.mesh_terminal",
                      "client open: terminal id generation failed");
            return MESH_TERMINAL_OPEN_UNAVAILABLE;
        }
        client_lock();
        have_id = client_find_locked(open.terminal_id) == NULL;
        zcl_mutex_unlock(&g_client_lock);
    }
    if (!have_id) {
        p2p_node_release(peer);
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
        p2p_node_release(peer);
        LOG_ERROR("net.mesh_terminal", "client open: encode failed: %s",
                  mesh_terminal_proto_error_string(encoded));
        return MESH_TERMINAL_OPEN_UNAVAILABLE;
    }

    /* Reserve the client slot before sending so a fast receipt can never
     * arrive to a missing session. */
    client_lock();
    struct mesh_terminal_client_session *slot = NULL;
    for (size_t i = 0; i < MESH_TERMINAL_CLIENT_SESSIONS_MAX && !slot; i++)
        if (!g_sessions[i].used)
            slot = &g_sessions[i];
    if (slot) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->open = open;
        memcpy(slot->expected_responder_master, row.peer_master_pubkey, 32);
        memcpy(slot->expected_responder_online,
               responder_delegation.online_pubkey, 32);
        memcpy(slot->peer_noise_static, session.remote_static, 32);
        snprintf(slot->pairing_id_hex, sizeof(slot->pairing_id_hex), "%s",
                 pairing_id_hex);
        slot->verdict = MESH_TERMINAL_RECEIPT_INTERNAL;
        slot->opened_unix = (uint64_t)now;
        slot->last_activity_unix = (uint64_t)now;
    }
    zcl_mutex_unlock(&g_client_lock);
    if (!slot) {
        p2p_node_release(peer);
        return MESH_TERMINAL_OPEN_BUSY;
    }

    if (!boot_mesh_terminal_send(mp, peer, MESH_TERMINAL_FRAME_KIND_OPEN,
                                 wire, sizeof(wire))) {
        client_lock();
        memset(slot, 0, sizeof(*slot));
        zcl_mutex_unlock(&g_client_lock);
        p2p_node_release(peer);
        return MESH_TERMINAL_OPEN_SEND_FAILED;
    }
    p2p_node_release(peer);
    memcpy(terminal_id_out, open.terminal_id, 32);
    return MESH_TERMINAL_OPEN_OK;
}

/* ── Ingress ─────────────────────────────────────────────────────────── */

void boot_mesh_terminal_client_receipt(struct p2p_node *node,
                                       const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_receipt_v1 receipt;
    if (mesh_terminal_receipt_v1_decode(&receipt, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        atomic_fetch_add(&g_client_dropped_unauthenticated, 1);
        return;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    client_lock();
    struct mesh_terminal_client_session *s =
        client_find_locked(receipt.request_id);
    if (!s || s->ended || !client_receipt_binds(s, &receipt, &session) ||
        mesh_terminal_receipt_v1_matches_open(&receipt, &s->open) !=
            MESH_TERMINAL_PROTO_OK) {
        zcl_mutex_unlock(&g_client_lock);
        atomic_fetch_add(&g_client_receipts_refused, 1);
        return;
    }
    if (receipt.status == MESH_TERMINAL_RECEIPT_CLOSED) {
        /* The responder ended the session and sent its evidence; keep the
         * verdict inspectable until the requester reaps it. The named
         * reason lives in the receipt's evidence capsule on the responder,
         * so the local view does not invent one. */
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
        zcl_mutex_unlock(&g_client_lock);
        atomic_fetch_add(&g_client_receipts_refused, 1);
        return;
    }
    zcl_mutex_unlock(&g_client_lock);
}

void boot_mesh_terminal_client_data(struct p2p_node *node,
                                    const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_data_v1 data;
    if (mesh_terminal_data_v1_decode(&data, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        atomic_fetch_add(&g_client_dropped_unauthenticated, 1);
        return;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    client_lock();
    struct mesh_terminal_client_session *s =
        client_find_locked(data.terminal_id);
    if (!s || !s->open_confirmed || s->ended ||
        data.seq <= s->seq_in ||
        memcmp(session.remote_static, s->peer_noise_static, 32) != 0 ||
        memcmp(session.transcript_hash, s->open.transcript_hash, 32) != 0 ||
        session.connection_generation != s->open.connection_generation) {
        zcl_mutex_unlock(&g_client_lock);
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    if (data.payload_len > MESH_TERMINAL_DATA_PAYLOAD_MAX ||
        s->output_len + data.payload_len > sizeof(s->output)) {
        /* The bounded FIFO is full: drop the frame rather than grow. The
         * responder's own 1 MiB byte-out ceiling makes this a laggard
         * reader, not an unbounded peer. */
        zcl_mutex_unlock(&g_client_lock);
        atomic_fetch_add(&g_client_output_overflow, 1);
        return;
    }
    memcpy(s->output + s->output_len, data.payload, data.payload_len);
    s->output_len += data.payload_len;
    s->seq_in = data.seq;
    s->bytes_out += data.payload_len;
    s->last_activity_unix = now;
    zcl_mutex_unlock(&g_client_lock);
}

void boot_mesh_terminal_client_close_frame(struct p2p_node *node,
                                           const uint8_t *wire,
                                           size_t wire_len)
{
    struct mesh_terminal_close_v1 close_frame;
    if (mesh_terminal_close_v1_decode(&close_frame, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        atomic_fetch_add(&g_client_dropped_unauthenticated, 1);
        return;
    }
    client_lock();
    struct mesh_terminal_client_session *s =
        client_find_locked(close_frame.terminal_id);
    if (!s || !s->open_confirmed ||
        memcmp(session.remote_static, s->peer_noise_static, 32) != 0 ||
        memcmp(session.transcript_hash, s->open.transcript_hash, 32) != 0 ||
        session.connection_generation != s->open.connection_generation) {
        zcl_mutex_unlock(&g_client_lock);
        atomic_fetch_add(&g_client_dropped_malformed, 1);
        return;
    }
    s->ended = true;
    s->close_reason = close_frame.reason;
    s->close_reason_named = true;
    zcl_mutex_unlock(&g_client_lock);
}

/* ── Session verbs ───────────────────────────────────────────────────── */

enum boot_mesh_terminal_client_state boot_mesh_terminal_client_poll(
    const uint8_t terminal_id[32],
    struct boot_mesh_terminal_client_view *view_out)
{
    if (!terminal_id)
        return MESH_TERMINAL_CLIENT_UNKNOWN;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    client_lock();
    struct mesh_terminal_client_session *s = client_find_locked(terminal_id);
    if (!s) {
        zcl_mutex_unlock(&g_client_lock);
        return MESH_TERMINAL_CLIENT_UNKNOWN;
    }
    client_watchdog_locked(s, now);
    if (view_out) {
        memset(view_out, 0, sizeof(*view_out));
        view_out->verdict = s->verdict;
        view_out->close_reason =
            (enum mesh_terminal_close_reason)s->close_reason;
        view_out->close_reason_named = s->close_reason_named;
        view_out->cols = s->open.cols;
        view_out->rows = s->open.rows;
        view_out->bytes_in = s->bytes_in;
        view_out->bytes_out = s->bytes_out;
        view_out->output_pending = s->output_len;
        view_out->idle_seconds =
            now > s->last_activity_unix ? now - s->last_activity_unix : 0;
    }
    /* REFUSED means no terminal was ever granted: an unanswered OPEN or a
     * named refusal. ENDED means a terminal existed and finished — a
     * locally named close reason (watchdog expiry, CLOSE frame, the
     * operator's close), the OK verdict, or the responder's CLOSED
     * receipt. */
    enum boot_mesh_terminal_client_state state =
        s->ended
            ? ((s->verdict == MESH_TERMINAL_RECEIPT_OK ||
                s->verdict == MESH_TERMINAL_RECEIPT_CLOSED ||
                s->close_reason_named)
                   ? MESH_TERMINAL_CLIENT_ENDED
                   : MESH_TERMINAL_CLIENT_REFUSED)
            : (s->open_confirmed ? MESH_TERMINAL_CLIENT_LIVE
                                 : MESH_TERMINAL_CLIENT_OPENING);
    zcl_mutex_unlock(&g_client_lock);
    return state;
}

size_t boot_mesh_terminal_client_drain(const uint8_t terminal_id[32],
                                       uint8_t *out, size_t out_cap)
{
    if (!terminal_id || !out || out_cap == 0)
        return 0;
    client_lock();
    struct mesh_terminal_client_session *s = client_find_locked(terminal_id);
    size_t moved = 0;
    if (s && s->output_len) {
        moved = s->output_len < out_cap ? s->output_len : out_cap;
        memcpy(out, s->output, moved);
        memmove(s->output, s->output + moved, s->output_len - moved);
        s->output_len -= moved;
    }
    zcl_mutex_unlock(&g_client_lock);
    return moved;
}

bool boot_mesh_terminal_client_write(const uint8_t terminal_id[32],
                                     const uint8_t *bytes, size_t len)
{
    if (!terminal_id || (!bytes && len) || len == 0)
        return false;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    struct boot_svc_ctx *svc = boot_mesh_terminal_client_service();
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr)
        return false;

    client_lock();
    struct mesh_terminal_client_session *s = client_find_locked(terminal_id);
    if (!s || !s->open_confirmed || s->ended ||
        s->bytes_in + len > MESH_TERMINAL_SERVICE_MAX_BYTES_IN) {
        zcl_mutex_unlock(&g_client_lock);
        return false;
    }
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    struct p2p_node *peer = client_bound_peer_locked(svc, s, &snap);
    if (!peer) {
        zcl_mutex_unlock(&g_client_lock);
        return false;
    }
    uint64_t seq = s->seq_out;
    uint64_t sent_bytes = 0;
    bool ok = true;
    for (size_t off = 0; off < len && ok;) {
        size_t take = len - off < MESH_TERMINAL_DATA_PAYLOAD_MAX
                          ? len - off
                          : MESH_TERMINAL_DATA_PAYLOAD_MAX;
        struct mesh_terminal_data_v1 data;
        memset(&data, 0, sizeof(data));
        memcpy(data.terminal_id, terminal_id, 32);
        data.seq = ++seq;
        data.payload_len = (uint16_t)take;
        memcpy(data.payload, bytes + off, take);
        uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        if (mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                         &wire_len) !=
                MESH_TERMINAL_PROTO_OK ||
            !boot_mesh_terminal_send(svc->msg_processor, peer,
                                     MESH_TERMINAL_FRAME_KIND_DATA, wire,
                                     wire_len)) {
            ok = false;
            break;
        }
        sent_bytes += take;
        off += take;
    }
    if (sent_bytes) {
        s->seq_out = ok ? seq : seq - 1;
        s->bytes_in += sent_bytes;
        s->last_activity_unix = now;
    }
    p2p_node_release(peer);
    zcl_mutex_unlock(&g_client_lock);
    return ok;
}

bool boot_mesh_terminal_client_resize(const uint8_t terminal_id[32],
                                      uint16_t cols, uint16_t rows)
{
    if (!terminal_id || cols == 0 || cols > MESH_TERMINAL_MAX_COLS ||
        rows == 0 || rows > MESH_TERMINAL_MAX_ROWS)
        return false;
    struct boot_svc_ctx *svc = boot_mesh_terminal_client_service();
    if (!svc)
        return false;
    bool sent = false;
    client_lock();
    struct mesh_terminal_client_session *s = client_find_locked(terminal_id);
    if (!s || !s->open_confirmed || s->ended) {
        zcl_mutex_unlock(&g_client_lock);
        return false;
    }
    struct p2p_node *peer = client_bound_peer_locked(svc, s, NULL);
    if (!peer) {
        zcl_mutex_unlock(&g_client_lock);
        return false;
    }
    struct mesh_terminal_resize_v1 resize;
    memset(&resize, 0, sizeof(resize));
    memcpy(resize.terminal_id, terminal_id, 32);
    resize.cols = cols;
    resize.rows = rows;
    uint8_t wire[MESH_TERMINAL_RESIZE_V1_WIRE_BYTES];
    if (mesh_terminal_resize_v1_encode(&resize, wire) ==
        MESH_TERMINAL_PROTO_OK)
        sent = boot_mesh_terminal_send(svc->msg_processor, peer,
                                       MESH_TERMINAL_FRAME_KIND_RESIZE,
                                       wire, sizeof(wire));
    p2p_node_release(peer);
    zcl_mutex_unlock(&g_client_lock);
    return sent;
}

bool boot_mesh_terminal_client_close(const uint8_t terminal_id[32])
{
    if (!terminal_id)
        return false;
    struct boot_svc_ctx *svc = boot_mesh_terminal_client_service();
    if (!svc)
        return false;
    bool ours = false;
    client_lock();
    struct mesh_terminal_client_session *s = client_find_locked(terminal_id);
    if (!s) {
        zcl_mutex_unlock(&g_client_lock);
        return false;
    }
    ours = true;
    if (!s->ended) {
        /* Best-effort CLOSE to the bound peer; a session whose connection
         * already died just ends locally, which is the honest state. */
        struct p2p_node *peer = client_bound_peer_locked(svc, s, NULL);
        if (peer) {
            struct mesh_terminal_close_v1 close_frame;
            memset(&close_frame, 0, sizeof(close_frame));
            memcpy(close_frame.terminal_id, terminal_id, 32);
            close_frame.reason = MESH_TERMINAL_CLOSE_REQUESTED;
            uint8_t wire[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
            if (mesh_terminal_close_v1_encode(&close_frame, wire) ==
                MESH_TERMINAL_PROTO_OK)
                (void)boot_mesh_terminal_send(
                    svc->msg_processor, peer, MESH_TERMINAL_FRAME_KIND_CLOSE,
                    wire, sizeof(wire));
            p2p_node_release(peer);
        }
        s->ended = true;
        s->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
        s->close_reason_named = true;
    }
    zcl_mutex_unlock(&g_client_lock);
    return ours;
}

/* ── Test seam ───────────────────────────────────────────────────────── */

#ifdef ZCL_TESTING
bool boot_mesh_terminal_client_test_inject(
    const struct mesh_terminal_open_v1 *open,
    const uint8_t expected_responder_master[32],
    const uint8_t expected_responder_online[32],
    const uint8_t peer_noise_static[32], const char *pairing_id_hex,
    uint64_t opened_unix, uint64_t last_activity_unix, bool open_confirmed,
    uint8_t terminal_id_out[32])
{
    if (!open || !expected_responder_master || !expected_responder_online ||
        !peer_noise_static || !terminal_id_out)
        return false;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    client_lock();
    struct mesh_terminal_client_session *slot = NULL;
    for (size_t i = 0; i < MESH_TERMINAL_CLIENT_SESSIONS_MAX && !slot; i++)
        if (!g_sessions[i].used)
            slot = &g_sessions[i];
    if (!slot) {
        zcl_mutex_unlock(&g_client_lock);
        return false;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->open = *open;
    memcpy(slot->expected_responder_master, expected_responder_master, 32);
    memcpy(slot->expected_responder_online, expected_responder_online, 32);
    memcpy(slot->peer_noise_static, peer_noise_static, 32);
    if (pairing_id_hex)
        snprintf(slot->pairing_id_hex, sizeof(slot->pairing_id_hex), "%s",
                 pairing_id_hex);
    slot->verdict = MESH_TERMINAL_RECEIPT_INTERNAL;
    slot->opened_unix = opened_unix ? opened_unix : now;
    slot->last_activity_unix = last_activity_unix ? last_activity_unix : now;
    slot->open_confirmed = open_confirmed;
    memcpy(terminal_id_out, open->terminal_id, 32);
    zcl_mutex_unlock(&g_client_lock);
    return true;
}

void boot_mesh_terminal_client_test_reset(void)
{
    client_lock();
    memset(g_sessions, 0, sizeof(g_sessions));
    zcl_mutex_unlock(&g_client_lock);
}
#endif
