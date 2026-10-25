/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Mesh status wire: pairing-bound request responder and bounded
 * pending-request lifecycle, multiplexed on zpkgswm (see the header). */

// one-result-type-ok:closed-security-verdict — the decide/compose/accept
// helpers return bounded verdicts the caller must branch on; no diagnostic
// text crosses the wire. Drop/refusal logging happens at the frame edge.

#include "config/boot_mesh_status.h"
#include "config/boot_mesh_route.h"
#include "boot_mesh_status_internal.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_access.h"
#include "config/runtime.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/diagnostics_controller.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "mind.h"
#include "models/mesh_machine_observation.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "services/p2p_node_noise.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Receipts are valid at most this long after observation; bounded well under
 * the protocol lifetime ceiling so matches_request can accept them. */
#define MESH_STATUS_RECEIPT_VALIDITY_SECONDS 30u
#define MESH_STATUS_RESPONDER_REPLAY_MAX 256u
#define MESH_STATUS_RESPONDER_REPLAY_MS UINT64_C(30000)
#define MESH_STATUS_RESPONDER_RATE_PER_SECOND 4u

static zcl_mutex_t g_mesh_lock;
static _Atomic int g_mesh_lock_state;
static struct boot_svc_ctx *g_mesh_svc; /* borrowed; set by wire() */
static uint64_t g_mesh_generation;

struct mesh_status_pending {
    bool used;
    bool done;
    struct mesh_status_request_v1 request;
    uint8_t expected_responder_master[32];
    uint8_t expected_responder_online[32];
    uint64_t generation;   /* g_mesh_generation at begin */
    uint64_t expires_mono; /* seconds */
    struct mesh_status_receipt_v1 receipt;
};
static struct mesh_status_pending g_pending[MESH_STATUS_PENDING_MAX];

struct mesh_status_seen_request {
    bool used;
    uint8_t remote_static[32];
    uint8_t transcript_hash[32];
    uint8_t request_id[32];
    uint64_t connection_generation;
    uint64_t seen_mono_ms;
};
static struct mesh_status_seen_request
    g_seen_requests[MESH_STATUS_RESPONDER_REPLAY_MAX];

/* Quiet-drop counters: in-namespace garbage and unauthenticated probes are
 * local policy events, never offences against the peer. */
static _Atomic uint64_t g_mesh_dropped_unauthenticated;
static _Atomic uint64_t g_mesh_dropped_malformed;
static _Atomic uint64_t g_mesh_dropped_unknown_kind;
static _Atomic uint64_t g_mesh_receipts_unsolicited;
static _Atomic uint64_t g_mesh_receipts_refused;
static _Atomic uint64_t g_mesh_requests_replayed;
static _Atomic uint64_t g_mesh_requests_rate_limited;

static void mesh_lock(void)
{
    if (atomic_load_explicit(&g_mesh_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_mesh_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_mesh_lock);
            atomic_store_explicit(&g_mesh_lock_state, 2, memory_order_release);
        } else {
            while (atomic_load_explicit(&g_mesh_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_mesh_lock);
}

static uint64_t mesh_now_mono(void)
{
    return (uint64_t)(platform_time_monotonic_ms() / 1000);
}

/* Application replay/rate gate. Noise record counters stop ciphertext replay,
 * but an authenticated requester can still resend a decoded request in a new
 * record. One exact request is admitted once per transcript generation, and
 * each authenticated session receives a small bounded cadence. */
/* A slot is expired once its replay window has elapsed (or the clock moved
 * backwards past it). */
static bool mesh_seen_expired(const struct mesh_status_seen_request *seen,
                              uint64_t now_mono_ms)
{
    return now_mono_ms < seen->seen_mono_ms ||
           now_mono_ms - seen->seen_mono_ms >= MESH_STATUS_RESPONDER_REPLAY_MS;
}

static bool mesh_seen_same_session(const struct mesh_status_seen_request *seen,
                                   const struct noise_transport_snapshot *session)
{
    return seen->connection_generation == session->connection_generation &&
           memcmp(seen->remote_static, session->remote_static, 32) == 0 &&
           memcmp(seen->transcript_hash, session->transcript_hash, 32) == 0;
}

/* Caller holds g_mesh_lock. Reclaims expired slots, remembers the first free
 * slot, counts this session's admissions within the last second, and returns
 * true when the exact request was already admitted in this session. */
static bool mesh_responder_seen_replay_locked(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session, uint64_t now_mono_ms,
    struct mesh_status_seen_request **slot_out, size_t *recent_out)
{
    for (size_t i = 0; i < MESH_STATUS_RESPONDER_REPLAY_MAX; i++) {
        struct mesh_status_seen_request *seen = &g_seen_requests[i];
        if (seen->used && mesh_seen_expired(seen, now_mono_ms))
            memset(seen, 0, sizeof(*seen));
        if (!seen->used) {
            if (!*slot_out)
                *slot_out = seen;
            continue;
        }
        if (!mesh_seen_same_session(seen, session))
            continue;
        if (memcmp(seen->request_id, request->request_id, 32) == 0)
            return true;
        if (now_mono_ms >= seen->seen_mono_ms &&
            now_mono_ms - seen->seen_mono_ms < UINT64_C(1000))
            (*recent_out)++;
    }
    return false;
}

static bool mesh_responder_request_admit(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session, uint64_t now_mono_ms)
{
    if (!request || !session || !session->established) {
        LOG_ERROR("net.mesh_status", "responder admit: invalid session input");
        return false;
    }
    mesh_lock();
    struct mesh_status_seen_request *slot = NULL;
    size_t recent = 0;
    if (mesh_responder_seen_replay_locked(request, session, now_mono_ms,
                                          &slot, &recent)) {
        zcl_mutex_unlock(&g_mesh_lock);
        atomic_fetch_add(&g_mesh_requests_replayed, 1);
        return false;
    }
    if (!slot || recent >= MESH_STATUS_RESPONDER_RATE_PER_SECOND) {
        zcl_mutex_unlock(&g_mesh_lock);
        atomic_fetch_add(&g_mesh_requests_rate_limited, 1);
        return false;
    }
    slot->used = true;
    memcpy(slot->remote_static, session->remote_static, 32);
    memcpy(slot->transcript_hash, session->transcript_hash, 32);
    memcpy(slot->request_id, request->request_id, 32);
    slot->connection_generation = session->connection_generation;
    slot->seen_mono_ms = now_mono_ms;
    zcl_mutex_unlock(&g_mesh_lock);
    return true;
}

#ifdef ZCL_TESTING
bool boot_mesh_status_test_responder_admit(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session, uint64_t now_mono_ms)
{
    return mesh_responder_request_admit(request, session, now_mono_ms);
}
#endif

/* ── Pure decision ───────────────────────────────────────────────────── */

struct mesh_status_reason_row {
    enum mesh_pairing_reason reason;
    enum mesh_status_receipt_status status;
};

/* Every pairing reason maps to exactly one receipt status. A reason absent
 * from this table (none exists today) falls through to INTERNAL. */
static enum mesh_status_receipt_status mesh_status_from_pairing_reason(
    enum mesh_pairing_reason reason)
{
    static const struct mesh_status_reason_row rows[] = {
        {MESH_PAIRING_OK, MESH_STATUS_RECEIPT_OK},
        {MESH_PAIRING_NOT_FOUND, MESH_STATUS_RECEIPT_NOT_PAIRED},
        /* A pairing is genesis-bound: a foreign-genesis request names no
         * authority this node holds. */
        {MESH_PAIRING_NETWORK_MISMATCH, MESH_STATUS_RECEIPT_NOT_PAIRED},
        {MESH_PAIRING_ALREADY_REVOKED, MESH_STATUS_RECEIPT_REVOKED},
        {MESH_PAIRING_EXPIRED, MESH_STATUS_RECEIPT_EXPIRED},
        {MESH_PAIRING_SESSION_MISMATCH, MESH_STATUS_RECEIPT_SESSION_MISMATCH},
        {MESH_PAIRING_AUTHORITY_CHANGED,
         MESH_STATUS_RECEIPT_AUTHORITY_CHANGED},
        {MESH_PAIRING_DELEGATION_INVALID,
         MESH_STATUS_RECEIPT_DELEGATION_INVALID},
        {MESH_PAIRING_MASTER_INACTIVE, MESH_STATUS_RECEIPT_DELEGATION_INVALID},
        {MESH_PAIRING_BEACON_UNAVAILABLE,
         MESH_STATUS_RECEIPT_DELEGATION_INVALID},
        {MESH_PAIRING_BEACON_PROVISIONAL,
         MESH_STATUS_RECEIPT_DELEGATION_INVALID},
        {MESH_PAIRING_CAPABILITY_UNAVAILABLE,
         MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE},
        {MESH_PAIRING_BAD_ARGUMENT, MESH_STATUS_RECEIPT_INTERNAL},
        {MESH_PAIRING_FINGERPRINT_MISMATCH, MESH_STATUS_RECEIPT_INTERNAL},
        {MESH_PAIRING_WINDOW_INVALID, MESH_STATUS_RECEIPT_INTERNAL},
        {MESH_PAIRING_IDENTITY_COLLISION, MESH_STATUS_RECEIPT_INTERNAL},
        {MESH_PAIRING_PERSIST_FAILED, MESH_STATUS_RECEIPT_INTERNAL},
        /* Revocation-ceremony verdicts; authorize_status never produces them. */
        {MESH_PAIRING_CONFIRMATION_INVALID, MESH_STATUS_RECEIPT_INTERNAL},
        {MESH_PAIRING_PLAN_EXPIRED, MESH_STATUS_RECEIPT_INTERNAL},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        if (rows[i].reason == reason)
            return rows[i].status;
    }
    return MESH_STATUS_RECEIPT_INTERNAL;
}

/* Request-shape gate: argument presence, capability, and the request's own
 * validation. Returns OK when every check passes, otherwise the refusal. */
static enum mesh_status_receipt_status mesh_status_decide_request_gate(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    const uint8_t network_genesis[32], uint64_t now_unix)
{
    if (!request || !session || !session->established || !network_genesis ||
        now_unix == 0)
        return MESH_STATUS_RECEIPT_INTERNAL;
    if (request->capability != MESH_STATUS_CAP_STATUS_READ)
        return MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE;
    if (mesh_status_request_v1_validate(request) != MESH_STATUS_PROTO_OK)
        return MESH_STATUS_RECEIPT_BAD_REQUEST;
    return MESH_STATUS_RECEIPT_OK;
}

/* Time window and live-session binding. Returns OK when every check passes,
 * otherwise the refusal. Runs only after the request gate has passed. */
static enum mesh_status_receipt_status mesh_status_decide_session_gate(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    const uint8_t network_genesis[32], uint64_t now_unix)
{
    if (now_unix < request->issued_unix || now_unix >= request->expires_unix)
        return MESH_STATUS_RECEIPT_EXPIRED;
    /* Live-session binding: transcript and generation are transcript-derived
     * and shared by both sides (the per-side serial left the wire in
     * 2114f5257 — only shared session evidence is bound). */
    if (memcmp(request->transcript_hash, session->transcript_hash, 32) != 0 ||
        request->connection_generation != session->connection_generation ||
        memcmp(request->requester_noise_static, session->remote_static,
               32) != 0)
        return MESH_STATUS_RECEIPT_SESSION_MISMATCH;
    if (memcmp(request->network_genesis, network_genesis, 32) != 0)
        return MESH_STATUS_RECEIPT_NOT_PAIRED;
    return MESH_STATUS_RECEIPT_OK;
}

/* The one delegation whose noise static names the session's remote. Returns
 * NULL unless exactly one delegation matches. */
static const struct vcs_zcode_dht_delegation *mesh_status_single_live_delegation(
    const struct vcs_zcode_dht_delegation *delegations, size_t delegation_count,
    const uint8_t remote_static[32])
{
    const struct vcs_zcode_dht_delegation *live = NULL;
    size_t live_count = 0;
    for (size_t i = 0; i < delegation_count; i++) {
        if (memcmp(delegations[i].noise_static_pubkey, remote_static, 32) == 0) {
            live = &delegations[i];
            live_count++;
        }
    }
    return live_count == 1 ? live : NULL;
}

/* Authorize the live delegation's pairing row and read its revocation
 * generation. */
static enum mesh_status_receipt_status mesh_status_decide_row_verdict(
    struct node_db *ndb, const uint8_t network_genesis[32],
    const struct vcs_zcode_dht_delegation *live,
    const struct noise_transport_snapshot *session, uint64_t now_unix,
    uint64_t *revocation_generation_out)
{
    /* Pairing ids are per-side: each node derives its row id from the
     * PEER's master+noise identity, so the id a request carries names the
     * requester's own row and can never name ours. The only row that can
     * authorize this session is the one the live delegation (already
     * matched to the session's remote static) points at — derive its id. */
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    if (!mesh_pairing_id_derive(network_genesis, live->doc.master_pubkey,
                                live->noise_static_pubkey, pairing_id))
        return MESH_STATUS_RECEIPT_DELEGATION_INVALID;
    enum mesh_pairing_reason authorized = mesh_pairing_service_authorize_status(
        ndb, network_genesis, pairing_id, live, session->remote_static,
        (int64_t)now_unix);
    if (authorized != MESH_PAIRING_OK)
        return mesh_status_from_pairing_reason(authorized);
    /* The pairing row carries the receipt's revocation-generation evidence.
     * A row that vanished or revoked between authorize and this read is an
     * authority change, not an OK. */
    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id, &row) || row.revoked_at != 0)
        return MESH_STATUS_RECEIPT_AUTHORITY_CHANGED;
    if (revocation_generation_out)
        *revocation_generation_out = row.revocation_generation;
    return MESH_STATUS_RECEIPT_OK;
}

enum mesh_status_receipt_status boot_mesh_status_decide(
    struct node_db *ndb, const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *delegations,
    size_t delegation_count, const uint8_t network_genesis[32],
    uint64_t now_unix, uint64_t *revocation_generation_out)
{
    if (revocation_generation_out)
        *revocation_generation_out = 0;
    enum mesh_status_receipt_status verdict =
        mesh_status_decide_request_gate(request, session, network_genesis,
                                        now_unix);
    if (verdict != MESH_STATUS_RECEIPT_OK)
        return verdict;
    verdict = mesh_status_decide_session_gate(request, session, network_genesis,
                                              now_unix);
    if (verdict != MESH_STATUS_RECEIPT_OK)
        return verdict;
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return MESH_STATUS_RECEIPT_INTERNAL;
    const struct vcs_zcode_dht_delegation *live =
        mesh_status_single_live_delegation(delegations, delegation_count,
                                           session->remote_static);
    if (!live)
        return MESH_STATUS_RECEIPT_DELEGATION_INVALID;
    return mesh_status_decide_row_verdict(ndb, network_genesis, live, session,
                                          now_unix, revocation_generation_out);
}

/* ── Pure receipt composition ────────────────────────────────────────── */

/* Argument presence and session establishment. Logs and refuses on failure. */
static bool mesh_status_compose_args_ok(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32],
    const uint8_t responder_online_seed[32],
    const struct mesh_status_receipt_v1 *out, uint64_t now_unix)
{
    if (!request || !session || !session->established || !network_genesis ||
        !responder_master_pubkey || !responder_online_pubkey ||
        !responder_noise_static || !responder_online_seed || !out ||
        now_unix == 0)
        LOG_FAIL("net.mesh_status", "compose: null/unestablished argument");
    return true;
}

/* A receipt never outlives its request, and never runs past the validity
 * window; an already-expired request still gets a well-formed expiry. */
static uint64_t mesh_status_receipt_expiry(uint64_t now_unix,
                                           uint64_t request_expires_unix)
{
    uint64_t expires = now_unix + MESH_STATUS_RECEIPT_VALIDITY_SECONDS;
    if (expires > request_expires_unix)
        expires = request_expires_unix;
    if (expires <= now_unix)
        expires = now_unix + 1; /* expired-request refusal stays well-formed */
    return expires;
}

/* Fill every receipt field except the capsule and the signature. */
static bool mesh_status_receipt_fill(
    struct mesh_status_receipt_v1 *out,
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    enum mesh_status_receipt_status status, const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32], uint64_t revocation_generation,
    uint64_t now_unix)
{
    memset(out, 0, sizeof(*out));
    out->version = MESH_STATUS_PROTO_VERSION;
    out->flags = MESH_STATUS_PROTO_FLAGS_NONE;
    out->status = status;
    memcpy(out->request_id, request->request_id, 32);
    if (mesh_status_request_v1_root(request, out->request_root) !=
        MESH_STATUS_PROTO_OK)
        LOG_FAIL("net.mesh_status", "compose: request root failed");
    memcpy(out->network_genesis, network_genesis, 32);
    memcpy(out->pairing_id, request->pairing_id, 32);
    memcpy(out->responder_master_pubkey, responder_master_pubkey, 32);
    memcpy(out->responder_online_pubkey, responder_online_pubkey, 32);
    memcpy(out->responder_noise_static, responder_noise_static, 32);
    /* The receipt always carries the responder's LIVE session view, never
     * the request's claim. */
    memcpy(out->transcript_hash, session->transcript_hash, 32);
    out->connection_generation = session->connection_generation;
    out->revocation_generation = revocation_generation;
    out->observed_unix = now_unix;
    out->expires_unix =
        mesh_status_receipt_expiry(now_unix, request->expires_unix);
    return true;
}

/* Bind the capsule into the receipt, then sign it with the online key. */
static bool mesh_status_receipt_seal(struct mesh_status_receipt_v1 *out,
                                     const uint8_t *capsule, size_t capsule_len,
                                     const uint8_t responder_online_seed[32])
{
    out->capsule_len = (uint16_t)capsule_len;
    if (capsule_len)
        memcpy(out->capsule, capsule, capsule_len);
    if (mesh_status_capsule_v1_root(out->capsule, capsule_len,
                                    out->capsule_root) !=
        MESH_STATUS_PROTO_OK)
        LOG_FAIL("net.mesh_status", "compose: capsule root failed");
    enum mesh_status_proto_error signed_result =
        mesh_status_receipt_v1_sign(out, responder_online_seed);
    if (signed_result != MESH_STATUS_PROTO_OK)
        LOG_FAIL("net.mesh_status", "compose: sign failed: %s",
                 mesh_status_proto_error_string(signed_result));
    return true;
}

bool boot_mesh_status_compose_receipt(
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    enum mesh_status_receipt_status status, const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32], uint64_t revocation_generation,
    uint64_t now_unix, const uint8_t *capsule, size_t capsule_len,
    const uint8_t responder_online_seed[32],
    struct mesh_status_receipt_v1 *out)
{
    if (!mesh_status_compose_args_ok(request, session, network_genesis,
                                     responder_master_pubkey,
                                     responder_online_pubkey,
                                     responder_noise_static,
                                     responder_online_seed, out, now_unix))
        return false;
    if (status == MESH_STATUS_RECEIPT_OK &&
        (!capsule || capsule_len == 0 || capsule_len > MESH_STATUS_CAPSULE_MAX))
        LOG_FAIL("net.mesh_status", "compose: OK receipt without a capsule");
    if (status != MESH_STATUS_RECEIPT_OK)
        capsule_len = 0;
    if (!mesh_status_receipt_fill(out, request, session, status,
                                  network_genesis, responder_master_pubkey,
                                  responder_online_pubkey,
                                  responder_noise_static,
                                  revocation_generation, now_unix))
        return false;
    return mesh_status_receipt_seal(out, capsule, capsule_len,
                                    responder_online_seed);
}

/* ── Pure requester-side acceptance ──────────────────────────────────── */

bool boot_mesh_status_receipt_accept(
    const struct mesh_status_receipt_v1 *receipt,
    const struct mesh_status_request_v1 *request,
    const struct noise_transport_snapshot *session,
    const uint8_t expected_responder_master[32],
    const uint8_t expected_responder_online[32])
{
    if (!receipt || !request || !session || !session->established ||
        !expected_responder_master || !expected_responder_online)
        return false;
    /* The receipt must bind the CURRENT session with the sending node: a
     * receipt arriving on a newer or different connection is refused. */
    if (memcmp(receipt->transcript_hash, session->transcript_hash, 32) != 0 ||
        receipt->connection_generation != session->connection_generation ||
        memcmp(receipt->responder_noise_static, session->remote_static,
               32) != 0 ||
        memcmp(receipt->responder_master_pubkey, expected_responder_master,
               32) != 0 ||
        memcmp(receipt->responder_online_pubkey, expected_responder_online,
               32) != 0)
        return false;
    return mesh_status_receipt_v1_matches_request(receipt, request) ==
           MESH_STATUS_PROTO_OK;
}

/* ── Responder lane ──────────────────────────────────────────────────── */

/* Snapshot connected peers under cs_nodes, then return the first whose
 * established Noise session names the paired Noise static. Caller releases
 * the returned reference. Never dials. Shared with the mesh terminal lane
 * (declared in the internal header). */
struct p2p_node *boot_mesh_find_session_peer(
    struct net_manager *nm, const uint8_t peer_noise[32],
    struct noise_transport_snapshot *session_out)
{
    struct p2p_node *candidates[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
    size_t count = 0;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0;
         i < nm->num_nodes && count < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++) {
        struct p2p_node *node = nm->nodes[i];
        if (!boot_zcode_dht_peer_ready(node))
            continue;
        candidates[count++] = node;
        p2p_node_add_ref(node);
    }
    zcl_mutex_unlock(&nm->cs_nodes);
    struct p2p_node *found = NULL;
    for (size_t i = 0; i < count; i++) {
        struct noise_transport_snapshot snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        if (!found && p2p_node_noise_snapshot(candidates[i], &snapshot) &&
            snapshot.established &&
            memcmp(snapshot.remote_static, peer_noise, 32) == 0) {
            found = candidates[i];
            *session_out = snapshot;
        } else {
            p2p_node_release(candidates[i]);
        }
    }
    return found;
}

/* ── Complete session observation ─────────────────────────────────────── */

/* Under cs_nodes, once: take a reference on every ready node, up to
 * BOOT_MESH_OBSERVE_MAX_READY. *overflow is set when the table holds more
 * ready nodes than that; the surplus is then not captured. */
static size_t mesh_observe_capture(struct net_manager *nm,
                                   struct p2p_node *held[], bool *overflow)
{
    size_t count = 0;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < nm->num_nodes; i++) {
        struct p2p_node *node = nm->nodes[i];
        if (!boot_zcode_dht_peer_ready(node))
            continue;
        if (count >= BOOT_MESH_OBSERVE_MAX_READY) {
            *overflow = true;
            break;
        }
        held[count++] = node;
        p2p_node_add_ref(node);
    }
    zcl_mutex_unlock(&nm->cs_nodes);
    return count;
}

/* Read each captured node outside the lock and release nothing. True when
 * one holds an established session naming `peer_noise`. The
 * snapshot is a locked read: false means the node holds no established
 * session when read, a definite non-match. Only a node whose transport is
 * gone when read (it was present under the ready check, so it is being torn
 * down) proves nothing either way and sets *lost_transport. */
static bool mesh_observe_inspect(struct p2p_node *held[], size_t count,
                                 const uint8_t peer_noise[32],
                                 bool *lost_transport)
{
    for (size_t i = 0; i < count; i++) {
        struct noise_transport_snapshot snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        /* One read under the node's cs_recv: the socket thread frees the
         * transport there on a plaintext fallback, so the pointer and the
         * snapshot must come from the same critical section. */
        enum p2p_node_noise_phase phase =
            p2p_node_noise_read(held[i], &snapshot);
        if (phase == P2P_NODE_NOISE_NONE)
            *lost_transport = true;
        else if (snapshot.established &&
                 memcmp(snapshot.remote_static, peer_noise, 32) == 0)
            return true;
    }
    return false;
}

/* Drop every captured reference under cs_nodes: node reference counts are
 * plain integers that the connection manager only changes under that
 * lock. */
static void mesh_observe_release(struct net_manager *nm,
                                 struct p2p_node *held[], size_t count)
{
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < count; i++)
        p2p_node_release(held[i]);
    zcl_mutex_unlock(&nm->cs_nodes);
}

/* One membership capture, then one later read per captured node. Membership
 * is fixed when cs_nodes is held to capture every ready node; each captured
 * node's session is read afterwards under that node's transport lock while
 * its reference is held. This is not an atomic view of all sessions: each
 * read reports its node at its own later moment. A node that joins the table
 * or becomes ready after the capture is not seen until the next call. LIVE: a
 * captured node's locked read is established and names `peer_noise` (even
 * when the table held more ready nodes than the bound). ABSENT: every ready
 * node in the captured membership was read under its transport lock, and none
 * held an established session naming this peer when read. INCOMPLETE: more
 * ready nodes than the capture bound, a captured node had lost its transport
 * when read, or an argument is NULL. References are taken and dropped under
 * cs_nodes, so none is held on return; allocates nothing. cs_nodes is taken
 * twice, once to capture the membership and once to drop the references;
 * membership is fixed only at the first. */
enum boot_mesh_session_observation boot_mesh_observe_session_peer(
    struct net_manager *nm, const uint8_t peer_noise[32])
{
    if (!nm || !peer_noise)
        return BOOT_MESH_SESSION_INCOMPLETE;
    struct p2p_node *held[BOOT_MESH_OBSERVE_MAX_READY];
    bool overflow = false, lost_transport = false;
    size_t count = mesh_observe_capture(nm, held, &overflow);
    bool live = mesh_observe_inspect(held, count, peer_noise, &lost_transport);
    mesh_observe_release(nm, held, count);
    if (live)
        return BOOT_MESH_SESSION_LIVE;
    return overflow || lost_transport ? BOOT_MESH_SESSION_INCOMPLETE
                                      : BOOT_MESH_SESSION_ABSENT;
}

struct mesh_delegation_collect {
    struct vcs_zcode_dht_delegation matched[2];
    size_t matched_count;
    uint8_t remote_static[32];
};

/* Runs under the DHT global lock (boot_zcode_dht_service_apply): memory
 * copies only, no I/O. */
static void mesh_collect_delegation(struct vcs_zcode_dht_service *service,
                                    void *opaque)
{
    struct mesh_delegation_collect *collect = opaque;
    if (!service || !collect)
        return;
    collect->matched_count = vcs_zcode_dht_service_delegations_for_noise(
        service, collect->remote_static, collect->matched,
        sizeof(collect->matched) / sizeof(collect->matched[0]));
}

/* The responder's own receipt identity: the filed local delegation names the
 * master (which must be ACTIVE in the local ZID projection) and the online
 * key the receipt is signed with. Any inconsistency fails closed: the codec
 * refuses to sign zeroed identity fields, so there is no honest receipt to
 * emit and the request is dropped after logging. Shared with the mesh
 * terminal lane (declared in the internal header) so fail-closed identity
 * can never drift between the two lanes. */
bool boot_mesh_local_identity(struct node_db *ndb, const char *datadir,
                                uint8_t master_out[32],
                                uint8_t online_pub_out[32],
                                uint8_t online_seed_out[32])
{
    char error[160];
    struct vcs_zcode_dht_delegation local;
    if (!vcs_zcode_dht_delegation_load(datadir, &local, error,
                                       sizeof(error))) {
        LOG_ERROR("net.mesh_status",
                  "responder identity unavailable: no filed delegation (%s)",
                  error);
        return false;
    }
    struct zid_identity identity;
    if (!ndb || !app_runtime_node_db_handle_open(ndb) ||
        !db_zid_identity_find(ndb, local.doc.master_pubkey, &identity) ||
        strcmp(identity.status, ZID_IDENTITY_STATUS_ACTIVE) != 0) {
        LOG_ERROR("net.mesh_status",
                  "responder identity unavailable: delegation master is not "
                  "ACTIVE in the local ZID projection");
        return false;
    }
    if (!vcs_zcode_dht_online_key_load(datadir, online_seed_out,
                                      online_pub_out, error,
                                      sizeof(error))) {
        LOG_ERROR("net.mesh_status",
                  "responder identity unavailable: online key (%s)", error);
        return false;
    }
    if (memcmp(online_pub_out, local.online_pubkey, 32) != 0) {
        LOG_ERROR("net.mesh_status",
                  "responder identity inconsistent: online key differs from "
                  "the filed delegation");
        memory_cleanse(online_seed_out, 32);
        return false;
    }
    memcpy(master_out, local.doc.master_pubkey, 32);
    return true;
}

/* ── Shared peer-delegation lookup (both requester lanes) ────────────── */

struct mesh_peer_delegation_collect {
    struct vcs_zcode_dht_delegation *held;
    size_t held_max;
    struct vcs_zcode_dht_delegation best;
    uint8_t genesis[32];
    uint8_t master[32];
    uint8_t noise_static[32];
    bool found;
    bool ambiguous;
};

/* Runs under the DHT service lock: memory copies only. The greatest sequence
 * for the exact paired identity wins; two different online keys at that same
 * sequence are ambiguous and fail closed. */
static void mesh_collect_peer_delegation(struct vcs_zcode_dht_service *service,
                                         void *opaque)
{
    struct mesh_peer_delegation_collect *collect = opaque;
    if (!service || !collect || !collect->held)
        return;
    size_t count = vcs_zcode_dht_service_delegations(
        service, collect->held, collect->held_max);
    for (size_t i = 0; i < count; i++) {
        struct vcs_zcode_dht_delegation *candidate = &collect->held[i];
        if (memcmp(candidate->network_genesis, collect->genesis, 32) != 0 ||
            memcmp(candidate->doc.master_pubkey, collect->master, 32) != 0 ||
            memcmp(candidate->noise_static_pubkey,
                   collect->noise_static, 32) != 0)
            continue;
        if (!collect->found ||
            candidate->doc.seq > collect->best.doc.seq) {
            collect->best = *candidate;
            collect->found = true;
            collect->ambiguous = false;
        } else if (candidate->doc.seq == collect->best.doc.seq &&
                   memcmp(candidate->online_pubkey,
                          collect->best.online_pubkey, 32) != 0) {
            collect->ambiguous = true;
        }
    }
}

bool boot_mesh_peer_delegation(const struct db_mesh_pairing *row,
                               struct vcs_zcode_dht_delegation *out)
{
    struct mesh_peer_delegation_collect collect;
    memset(&collect, 0, sizeof(collect));
    collect.held = zcl_malloc(
        VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS * sizeof(*collect.held),
        "mesh_status.peer_delegations");
    if (!collect.held) {
        LOG_ERROR("net.mesh_status", "peer delegation alloc failed");
        return false;
    }
    collect.held_max = VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS;
    memcpy(collect.genesis, row->network_genesis, 32);
    memcpy(collect.master, row->peer_master_pubkey, 32);
    memcpy(collect.noise_static, row->peer_noise_pubkey, 32);
    bool available = boot_zcode_dht_service_apply(
        mesh_collect_peer_delegation, &collect);
    bool found = available && collect.found && !collect.ambiguous;
    if (found)
        *out = collect.best;
    free(collect.held);
    return found;
}

/* Render the redacted machine-identity capsule. Oversize output is replaced
 * by a minimal deterministic marker object — never truncated mid-document. */
static bool mesh_render_capsule(uint8_t out[MESH_STATUS_CAPSULE_MAX],
                                size_t *out_len)
{
    static const char oversize[] =
        "{\"schema\":\"zcl.machine_mesh_identity.v1\",\"capsule_oversize\":true}";
    *out_len = 0;
    struct json_value capsule;
    json_init(&capsule);
    if (!machine_identity_dump_state_json(&capsule, NULL)) {
        json_free(&capsule);
        LOG_ERROR("net.mesh_status", "capsule render refused");
        return false;
    }
    /* What this node's mind holds, if it has one. It rides inside this
     * capsule rather than on a wire of its own so it inherits the receipt's
     * signature and expiry: a mind row is exactly as trustworthy, and
     * exactly as fresh, as the receipt that carried it. A node with no
     * resident adds nothing here — silence, never an empty claim. */
    struct json_value mind;
    if (zcl_mind_capsule_render(&mind)) {
        (void)json_push_kv(&capsule, "mind", &mind);
        json_free(&mind);
    }
    size_t needed = json_write(&capsule, NULL, 0);
    if (needed == 0) {
        json_free(&capsule);
        LOG_ERROR("net.mesh_status", "capsule serialization failed");
        return false;
    }
    if (needed > MESH_STATUS_CAPSULE_MAX) {
        json_free(&capsule);
        if (sizeof(oversize) - 1 > MESH_STATUS_CAPSULE_MAX) {
            LOG_ERROR("net.mesh_status", "oversize marker exceeds the cap");
            return false;
        }
        memcpy(out, oversize, sizeof(oversize) - 1);
        *out_len = sizeof(oversize) - 1;
        return true;
    }
    char buffer[MESH_STATUS_CAPSULE_MAX + 1];
    size_t written = json_write(&capsule, buffer, sizeof(buffer));
    json_free(&capsule);
    if (written != needed) {
        LOG_ERROR("net.mesh_status", "capsule serialization truncated");
        return false;
    }
    /* Opt-in plugins block (-meshstatusplugins): off is exactly the identity
     * render; on copies a cached snapshot, never touching the store here. */
    mesh_status_capsule_finish(buffer, needed, out, out_len);
    return true;
}

bool mesh_status_send(struct msg_processor *mp, struct p2p_node *node,
                      uint8_t kind, const uint8_t *wire, size_t wire_len)
{
    uint8_t frame[MESH_STATUS_FRAME_MAX];
    if (wire_len + MESH_STATUS_FRAME_PREFIX_LEN + 1u > sizeof(frame)) {
        LOG_ERROR("net.mesh_status", "frame %zu bytes exceeds the bound",
                  wire_len);
        return false;
    }
    memcpy(frame, MESH_STATUS_FRAME_PREFIX, MESH_STATUS_FRAME_PREFIX_LEN);
    frame[MESH_STATUS_FRAME_PREFIX_LEN] = kind;
    memcpy(frame + MESH_STATUS_FRAME_PREFIX_LEN + 1u, wire, wire_len);
    if (!p2p_node_begin_message(node, "zpkgswm", mp->params->pchMessageStart)) {
        LOG_ERROR("net.mesh_status", "begin_message failed for peer %lld",
                  (long long)node->id);
        return false;
    }
    p2p_node_write_message_data(node, frame,
                                wire_len + MESH_STATUS_FRAME_PREFIX_LEN + 1u);
    if (!p2p_node_end_message(node)) {
        LOG_ERROR("net.mesh_status", "end_message failed for peer %lld",
                  (long long)node->id);
        return false;
    }
    return true;
}

static void mesh_respond(struct msg_processor *mp, struct p2p_node *node,
                         const uint8_t *wire, size_t wire_len,
                         struct boot_svc_ctx *svc)
{
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!p2p_node_noise_snapshot(node, &session) || !session.established) {
        /* Plaintext v1 or mid-handshake: drop with NO receipt — responder
         * keys and signatures never cross an unauthenticated channel. The
         * requester's local timeout is the honest signal. */
        atomic_fetch_add(&g_mesh_dropped_unauthenticated, 1);
        return;
    }
    struct mesh_status_request_v1 request;
    if (mesh_status_request_v1_decode(&request, wire, wire_len) !=
        MESH_STATUS_PROTO_OK) {
        atomic_fetch_add(&g_mesh_dropped_malformed, 1);
        return;
    }
    if (!mesh_responder_request_admit(
            &request, &session,
            (uint64_t)platform_time_monotonic_ms()))
        return;
    if (!mp->params || !mp->net_mgr || !svc || !svc->datadir) {
        LOG_ERROR("net.mesh_status", "respond: composition incomplete");
        return;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    uint8_t genesis[32];
    memcpy(genesis, mp->params->consensus.hashGenesisBlock.data, 32);

    struct mesh_delegation_collect collect;
    memset(&collect, 0, sizeof(collect));
    memcpy(collect.remote_static, session.remote_static, 32);
    (void)boot_zcode_dht_service_apply(mesh_collect_delegation, &collect);

    struct node_db *ndb = app_runtime_node_db();
    uint64_t revocation_generation = 0;
    enum mesh_status_receipt_status status = boot_mesh_status_decide(
        ndb, &request, &session, collect.matched, collect.matched_count,
        genesis, now, &revocation_generation);

    uint8_t master[32], online_pub[32], online_seed[32];
    if (!boot_mesh_local_identity(ndb, svc->datadir, master, online_pub,
                                  online_seed))
        return; /* context logged inside; no honest receipt exists */

    uint8_t capsule[MESH_STATUS_CAPSULE_MAX];
    size_t capsule_len = 0;
    if (status == MESH_STATUS_RECEIPT_OK &&
        !mesh_render_capsule(capsule, &capsule_len))
        status = MESH_STATUS_RECEIPT_INTERNAL;

    struct mesh_status_receipt_v1 receipt;
    bool composed = boot_mesh_status_compose_receipt(
        &request, &session, status, genesis, master, online_pub,
        mp->net_mgr->identity_pub, revocation_generation, now, capsule,
        capsule_len, online_seed, &receipt);
    memory_cleanse(online_seed, sizeof(online_seed));
    if (!composed)
        return; /* context logged inside compose */
    uint8_t receipt_wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
    size_t receipt_len = 0;
    if (mesh_status_receipt_v1_encode(&receipt, receipt_wire,
                                      sizeof(receipt_wire),
                                      &receipt_len) != MESH_STATUS_PROTO_OK) {
        LOG_ERROR("net.mesh_status", "signed receipt failed to encode");
        return;
    }
    (void)mesh_status_send(mp, node, MESH_STATUS_FRAME_KIND_RECEIPT,
                           receipt_wire, receipt_len);
}

/* ── Requester lane ──────────────────────────────────────────────────── */

static void mesh_pending_cleanup_locked(uint64_t monotonic_s)
{
    for (size_t i = 0; i < MESH_STATUS_PENDING_MAX; i++) {
        struct mesh_status_pending *entry = &g_pending[i];
        if (entry->used && monotonic_s >= entry->expires_mono)
            memset(entry, 0, sizeof(*entry));
    }
}

static struct mesh_status_pending *mesh_pending_find_locked(
    const uint8_t request_id[32])
{
    for (size_t i = 0; i < MESH_STATUS_PENDING_MAX; i++) {
        if (g_pending[i].used &&
            memcmp(g_pending[i].request.request_id, request_id, 32) == 0)
            return &g_pending[i];
    }
    return NULL;
}

/* ── Cross-TU helpers for the requester lane (internal header) ───────── */

struct boot_svc_ctx *mesh_status_service(uint64_t *generation_out)
{
    mesh_lock();
    struct boot_svc_ctx *svc = g_mesh_svc;
    if (generation_out)
        *generation_out = g_mesh_generation;
    zcl_mutex_unlock(&g_mesh_lock);
    return svc;
}

bool mesh_status_request_id_free(const uint8_t request_id[32])
{
    mesh_lock();
    bool free_id = mesh_pending_find_locked(request_id) == NULL;
    zcl_mutex_unlock(&g_mesh_lock);
    return free_id;
}

/* Admit the pending entry before the request is sent so a fast receipt can
 * never arrive to a missing slot. Expired entries are reclaimed; a table of
 * live requests refuses admission rather than destroying prior work. */
bool mesh_status_pending_admit(const struct mesh_status_request_v1 *request,
                               const uint8_t expected_responder_master[32],
                               const uint8_t expected_responder_online[32],
                               uint64_t generation)
{
    if (!request || !expected_responder_master ||
        !expected_responder_online || generation == 0) {
        LOG_ERROR("net.mesh_status", "pending admit: invalid binding input");
        return false;
    }
    uint64_t now_mono = mesh_now_mono();
    mesh_lock();
    mesh_pending_cleanup_locked(now_mono);
    struct mesh_status_pending *slot = NULL;
    for (size_t i = 0; i < MESH_STATUS_PENDING_MAX; i++) {
        if (!g_pending[i].used && !slot) {
            slot = &g_pending[i];
        }
    }
    if (slot) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->request = *request;
        memcpy(slot->expected_responder_master, expected_responder_master, 32);
        memcpy(slot->expected_responder_online, expected_responder_online, 32);
        slot->generation = generation;
        slot->expires_mono =
            now_mono + MESH_STATUS_REQUEST_LIFETIME_SECONDS + 5u;
    }
    zcl_mutex_unlock(&g_mesh_lock);
    return slot != NULL;
}

/* Send-failed path: clear the admitted entry only when it still names this
 * exact request and has not completed. */
void mesh_status_pending_retract(const uint8_t request_id[32])
{
    mesh_lock();
    struct mesh_status_pending *entry = mesh_pending_find_locked(request_id);
    if (entry && !entry->done)
        memset(entry, 0, sizeof(*entry));
    zcl_mutex_unlock(&g_mesh_lock);
}

/* Receipt ingress: decode (verifies the signature under the embedded online
 * key), then complete the matching pending entry only when the receipt binds
 * the CURRENT session with the sending node. Everything else is a quiet
 * drop; the pending entry's own expiry is the honest terminal signal. */
static void mesh_receive(struct p2p_node *node, const uint8_t *wire,
                         size_t wire_len)
{
    struct mesh_status_receipt_v1 receipt;
    if (mesh_status_receipt_v1_decode(&receipt, wire, wire_len) !=
        MESH_STATUS_PROTO_OK) {
        atomic_fetch_add(&g_mesh_dropped_malformed, 1);
        return;
    }
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!p2p_node_noise_snapshot(node, &session) || !session.established) {
        atomic_fetch_add(&g_mesh_dropped_unauthenticated, 1);
        return;
    }
    uint64_t now_mono = mesh_now_mono();
    mesh_lock();
    mesh_pending_cleanup_locked(now_mono);
    struct mesh_status_pending *entry =
        mesh_pending_find_locked(receipt.request_id);
    if (!entry || entry->done ||
        entry->generation != g_mesh_generation) {
        zcl_mutex_unlock(&g_mesh_lock);
        atomic_fetch_add(&g_mesh_receipts_unsolicited, 1);
        return;
    }
    bool accepted = boot_mesh_status_receipt_accept(
        &receipt, &entry->request, &session,
        entry->expected_responder_master,
        entry->expected_responder_online);
    if (accepted) {
        entry->receipt = receipt;
        entry->done = true;
        entry->expires_mono = now_mono + MESH_STATUS_RESULT_RETENTION_S;
    }
    zcl_mutex_unlock(&g_mesh_lock);
    if (!accepted)
        atomic_fetch_add(&g_mesh_receipts_refused, 1);
}

bool boot_mesh_status_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *payload, size_t payload_len,
                            struct boot_svc_ctx *svc)
{
    if (!payload || payload_len < MESH_STATUS_FRAME_PREFIX_LEN + 1u ||
        memcmp(payload, MESH_STATUS_FRAME_PREFIX,
               MESH_STATUS_FRAME_PREFIX_LEN) != 0)
        return false;
    uint8_t kind = payload[MESH_STATUS_FRAME_PREFIX_LEN];
    const uint8_t *wire = payload + MESH_STATUS_FRAME_PREFIX_LEN + 1u;
    size_t wire_len = payload_len - MESH_STATUS_FRAME_PREFIX_LEN - 1u;
    if (!mp || !node)
        return true; /* our namespace, unusable context: drop quietly */
    switch (kind) {
    case MESH_STATUS_FRAME_KIND_REQUEST:
        mesh_respond(mp, node, wire, wire_len, svc);
        return true;
    case MESH_STATUS_FRAME_KIND_RECEIPT:
        mesh_receive(node, wire, wire_len);
        return true;
    default:
        atomic_fetch_add(&g_mesh_dropped_unknown_kind, 1);
        return true;
    }
}

enum boot_mesh_status_poll_state boot_mesh_status_poll(
    const uint8_t request_id[32], struct mesh_status_receipt_v1 *receipt_out)
{
    if (!request_id)
        return MESH_STATUS_POLL_UNKNOWN;
    uint64_t now_mono = mesh_now_mono();
    mesh_lock();
    struct mesh_status_pending *entry = mesh_pending_find_locked(request_id);
    enum boot_mesh_status_poll_state state;
    if (!entry || entry->generation != g_mesh_generation) {
        state = MESH_STATUS_POLL_UNKNOWN;
    } else if (entry->done) {
        if (now_mono >= entry->expires_mono) {
            memset(entry, 0, sizeof(*entry)); /* retention over */
            state = MESH_STATUS_POLL_UNKNOWN;
        } else {
            if (receipt_out)
                *receipt_out = entry->receipt;
            state = entry->receipt.status == MESH_STATUS_RECEIPT_OK
                        ? MESH_STATUS_POLL_OK
                        : MESH_STATUS_POLL_REFUSED;
        }
    } else if (now_mono >= entry->expires_mono) {
        memset(entry, 0, sizeof(*entry)); /* cancel on expiry */
        state = MESH_STATUS_POLL_EXPIRED;
    } else {
        state = MESH_STATUS_POLL_PENDING;
    }
    zcl_mutex_unlock(&g_mesh_lock);
    return state;
}

void boot_mesh_status_wire(struct boot_svc_ctx *svc)
{
    mesh_lock();
    g_mesh_svc = svc;
    g_mesh_generation++;
    if (!g_mesh_generation)
        g_mesh_generation++;
    memset(g_pending, 0, sizeof(g_pending));
    memset(g_seen_requests, 0, sizeof(g_seen_requests));
    zcl_mutex_unlock(&g_mesh_lock);
    boot_mesh_status_refresh_start(svc);
}

void boot_mesh_status_shutdown(void)
{
    boot_mesh_status_refresh_shutdown();
    boot_mesh_route_reset();
    mesh_lock();
    g_mesh_svc = NULL;
    g_mesh_generation++;
    if (!g_mesh_generation)
        g_mesh_generation++;
    memset(g_pending, 0, sizeof(g_pending));
    memset(g_seen_requests, 0, sizeof(g_seen_requests));
    zcl_mutex_unlock(&g_mesh_lock);
}

/* The single durable-evidence handoff: every verified terminal receipt —
 * whether it completed a single `ops mesh status` poll or a fleet probe
 * inside `ops mesh machines` — enters the observation store through here.
 * The store itself refuses older or equivocal evidence and treats an
 * exact-root replay as idempotent, so concurrent callers cannot regress a
 * row. */
bool boot_mesh_status_persist_observation(
    struct node_db *ndb, const struct mesh_status_receipt_v1 *receipt)
{
    if (!ndb || !receipt ||
        receipt->observed_unix > INT64_MAX ||
        receipt->expires_unix > INT64_MAX) {
        LOG_ERROR("net.mesh_status", "persist observation: invalid input");
        return false;
    }
    struct db_mesh_machine_observation row;
    memset(&row, 0, sizeof(row));
    zcl_hex_encode(receipt->pairing_id, 32, row.pairing_id);
    if (mesh_status_receipt_v1_encode(
            receipt, row.receipt_wire, sizeof(row.receipt_wire),
            &row.receipt_len) != MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_root(receipt, row.receipt_root) !=
            MESH_STATUS_PROTO_OK) {
        LOG_ERROR("net.mesh_status", "persist observation: encode/root failed");
        return false;
    }
    row.status = receipt->status;
    row.observed_unix = (int64_t)receipt->observed_unix;
    row.expires_unix = (int64_t)receipt->expires_unix;
    row.received_unix = (int64_t)platform_time_wall_time_t();
    if (row.received_unix <= 0) {
        LOG_ERROR("net.mesh_status", "persist observation: wall clock unavailable");
        return false;
    }
    return db_mesh_machine_observation_save(ndb, &row);
}

/* Domain-separated SHA3-256 fingerprint of a public key, hex-encoded. The
 * one implementation every mesh operator surface uses, so a rendered
 * fingerprint can never drift between the receipt view and the fleet view. */
void boot_mesh_status_key_fingerprint(const char *domain,
                                      const uint8_t key[32], char out[65])
{
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&hash, key, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}
