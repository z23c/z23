/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Mesh status wire: pairing-bound request responder and bounded
 * pending-request lifecycle, multiplexed on zpkgswm (see the header). */

// one-result-type-ok:closed-security-verdict — the decide/compose/accept
// helpers return bounded verdicts the caller must branch on; no diagnostic
// text crosses the wire. Drop/refusal logging happens at the frame edge.

#include "config/boot_mesh_status.h"
#include "boot_mesh_status_internal.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht_access.h"
#include "config/runtime.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/diagnostics_controller.h"
#include "json/json.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/net.h"
#include "net/v2_transport.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Receipts are valid at most this long after observation; bounded well under
 * the protocol lifetime ceiling so matches_request can accept them. */
#define MESH_STATUS_RECEIPT_VALIDITY_SECONDS 30u

static zcl_mutex_t g_mesh_lock;
static _Atomic int g_mesh_lock_state;
static struct boot_svc_ctx *g_mesh_svc; /* borrowed; set by wire() */
static uint64_t g_mesh_generation;

struct mesh_status_pending {
    bool used;
    bool done;
    struct mesh_status_request_v1 request;
    uint8_t expected_responder_master[32];
    uint64_t generation;   /* g_mesh_generation at begin */
    uint64_t expires_mono; /* seconds */
    struct mesh_status_receipt_v1 receipt;
};
static struct mesh_status_pending g_pending[MESH_STATUS_PENDING_MAX];

/* Quiet-drop counters: in-namespace garbage and unauthenticated probes are
 * local policy events, never offences against the peer. */
static _Atomic uint64_t g_mesh_dropped_unauthenticated;
static _Atomic uint64_t g_mesh_dropped_malformed;
static _Atomic uint64_t g_mesh_dropped_unknown_kind;
static _Atomic uint64_t g_mesh_receipts_unsolicited;
static _Atomic uint64_t g_mesh_receipts_refused;

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

/* ── Pure decision ───────────────────────────────────────────────────── */

static enum mesh_status_receipt_status mesh_status_from_pairing_reason(
    enum mesh_pairing_reason reason)
{
    switch (reason) {
    case MESH_PAIRING_OK: return MESH_STATUS_RECEIPT_OK;
    case MESH_PAIRING_NOT_FOUND: return MESH_STATUS_RECEIPT_NOT_PAIRED;
    /* A pairing is genesis-bound: a foreign-genesis request names no
     * authority this node holds. */
    case MESH_PAIRING_NETWORK_MISMATCH: return MESH_STATUS_RECEIPT_NOT_PAIRED;
    case MESH_PAIRING_ALREADY_REVOKED: return MESH_STATUS_RECEIPT_REVOKED;
    case MESH_PAIRING_EXPIRED: return MESH_STATUS_RECEIPT_EXPIRED;
    case MESH_PAIRING_SESSION_MISMATCH:
        return MESH_STATUS_RECEIPT_SESSION_MISMATCH;
    case MESH_PAIRING_AUTHORITY_CHANGED:
        return MESH_STATUS_RECEIPT_AUTHORITY_CHANGED;
    case MESH_PAIRING_DELEGATION_INVALID:
    case MESH_PAIRING_MASTER_INACTIVE:
    case MESH_PAIRING_BEACON_UNAVAILABLE:
    case MESH_PAIRING_BEACON_PROVISIONAL:
        return MESH_STATUS_RECEIPT_DELEGATION_INVALID;
    case MESH_PAIRING_CAPABILITY_UNAVAILABLE:
        return MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE;
    case MESH_PAIRING_BAD_ARGUMENT:
    case MESH_PAIRING_FINGERPRINT_MISMATCH:
    case MESH_PAIRING_WINDOW_INVALID:
    case MESH_PAIRING_IDENTITY_COLLISION:
    case MESH_PAIRING_PERSIST_FAILED:
        return MESH_STATUS_RECEIPT_INTERNAL;
    }
    return MESH_STATUS_RECEIPT_INTERNAL;
}

enum mesh_status_receipt_status boot_mesh_status_decide(
    struct node_db *ndb, const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *delegations,
    size_t delegation_count, const uint8_t network_genesis[32],
    uint64_t now_unix, uint64_t *revocation_generation_out)
{
    if (revocation_generation_out)
        *revocation_generation_out = 0;
    if (!request || !session || !session->established || !network_genesis ||
        now_unix == 0)
        return MESH_STATUS_RECEIPT_INTERNAL;
    if (request->capability != MESH_STATUS_CAP_STATUS_READ)
        return MESH_STATUS_RECEIPT_CAPABILITY_UNAVAILABLE;
    if (mesh_status_request_v1_validate(request) != MESH_STATUS_PROTO_OK)
        return MESH_STATUS_RECEIPT_BAD_REQUEST;
    if (now_unix < request->issued_unix || now_unix >= request->expires_unix)
        return MESH_STATUS_RECEIPT_EXPIRED;
    /* Live-session binding: transcript and generation are transcript-derived
     * and shared by both sides; the serial is per-side and is only echoed
     * for the requester's own current-session check (see the header). */
    if (memcmp(request->transcript_hash, session->transcript_hash, 32) != 0 ||
        request->connection_generation != session->connection_generation ||
        memcmp(request->requester_noise_static, session->remote_static,
               32) != 0)
        return MESH_STATUS_RECEIPT_SESSION_MISMATCH;
    if (memcmp(request->network_genesis, network_genesis, 32) != 0)
        return MESH_STATUS_RECEIPT_NOT_PAIRED;
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return MESH_STATUS_RECEIPT_INTERNAL;

    const struct vcs_zcode_dht_delegation *live = NULL;
    for (size_t i = 0; i < delegation_count; i++) {
        if (memcmp(delegations[i].noise_static_pubkey, session->remote_static,
                   32) == 0) {
            live = &delegations[i];
            break;
        }
    }
    if (!live)
        return MESH_STATUS_RECEIPT_DELEGATION_INVALID;

    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    zcl_hex_encode(request->pairing_id, 32, pairing_id);
    enum mesh_pairing_reason authorized = mesh_pairing_service_authorize_status(
        ndb, pairing_id, live, session->remote_static, (int64_t)now_unix);
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

/* ── Pure receipt composition ────────────────────────────────────────── */

bool boot_mesh_status_compose_receipt(
    const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session,
    enum mesh_status_receipt_status status, const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32], uint64_t revocation_generation,
    uint64_t now_unix, const uint8_t *capsule, size_t capsule_len,
    const uint8_t responder_online_seed[32],
    struct mesh_status_receipt_v1 *out)
{
    if (!request || !session || !session->established || !network_genesis ||
        !responder_master_pubkey || !responder_online_pubkey ||
        !responder_noise_static || !responder_online_seed || !out ||
        now_unix == 0) {
        LOG_ERROR("net.mesh_status", "compose: null/unestablished argument");
        return false;
    }
    if (status == MESH_STATUS_RECEIPT_OK &&
        (!capsule || capsule_len == 0 || capsule_len > MESH_STATUS_CAPSULE_MAX)) {
        LOG_ERROR("net.mesh_status", "compose: OK receipt without a capsule");
        return false;
    }
    if (status != MESH_STATUS_RECEIPT_OK)
        capsule_len = 0;
    memset(out, 0, sizeof(*out));
    out->version = MESH_STATUS_PROTO_VERSION;
    out->flags = MESH_STATUS_PROTO_FLAGS_NONE;
    out->status = status;
    memcpy(out->request_id, request->request_id, 32);
    if (mesh_status_request_v1_root(request, out->request_root) !=
        MESH_STATUS_PROTO_OK) {
        LOG_ERROR("net.mesh_status", "compose: request root failed");
        return false;
    }
    memcpy(out->network_genesis, network_genesis, 32);
    memcpy(out->pairing_id, request->pairing_id, 32);
    memcpy(out->responder_master_pubkey, responder_master_pubkey, 32);
    memcpy(out->responder_online_pubkey, responder_online_pubkey, 32);
    memcpy(out->responder_noise_static, responder_noise_static, 32);
    /* The receipt always carries the responder's LIVE session view, never
     * the request's claim. */
    memcpy(out->transcript_hash, session->transcript_hash, 32);
    out->connection_generation = session->connection_generation;
    out->connection_serial = request->connection_serial;
    out->revocation_generation = revocation_generation;
    out->observed_unix = now_unix;
    uint64_t expires = now_unix + MESH_STATUS_RECEIPT_VALIDITY_SECONDS;
    if (expires > request->expires_unix)
        expires = request->expires_unix;
    if (expires <= now_unix)
        expires = now_unix + 1; /* expired-request refusal stays well-formed */
    out->expires_unix = expires;
    out->capsule_len = (uint16_t)capsule_len;
    if (capsule_len)
        memcpy(out->capsule, capsule, capsule_len);
    if (mesh_status_capsule_v1_root(out->capsule, capsule_len,
                                    out->capsule_root) !=
        MESH_STATUS_PROTO_OK) {
        LOG_ERROR("net.mesh_status", "compose: capsule root failed");
        return false;
    }
    enum mesh_status_proto_error signed_result =
        mesh_status_receipt_v1_sign(out, responder_online_seed);
    if (signed_result != MESH_STATUS_PROTO_OK) {
        LOG_ERROR("net.mesh_status", "compose: sign failed: %s",
                  mesh_status_proto_error_string(signed_result));
        return false;
    }
    return true;
}

/* ── Pure requester-side acceptance ──────────────────────────────────── */

bool boot_mesh_status_receipt_accept(
    const struct mesh_status_receipt_v1 *receipt,
    const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session,
    const uint8_t expected_responder_master[32])
{
    if (!receipt || !request || !session || !session->established ||
        !expected_responder_master)
        return false;
    /* The receipt must bind the CURRENT session with the sending node: a
     * receipt arriving on a newer or different connection is refused. */
    if (memcmp(receipt->transcript_hash, session->transcript_hash, 32) != 0 ||
        receipt->connection_generation != session->connection_generation ||
        receipt->connection_serial != session->connection_serial ||
        memcmp(receipt->responder_noise_static, session->remote_static,
               32) != 0 ||
        memcmp(receipt->responder_master_pubkey, expected_responder_master,
               32) != 0)
        return false;
    return mesh_status_receipt_v1_matches_request(receipt, request) ==
           MESH_STATUS_PROTO_OK;
}

/* ── Responder lane ──────────────────────────────────────────────────── */

struct mesh_delegation_collect {
    struct vcs_zcode_dht_delegation *held; /* heap snapshot buffer */
    size_t held_max;
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
    if (!service || !collect || !collect->held)
        return;
    size_t count = vcs_zcode_dht_service_delegations(service, collect->held,
                                                     collect->held_max);
    for (size_t i = 0; i < count && collect->matched_count < 2; i++) {
        if (memcmp(collect->held[i].noise_static_pubkey,
                   collect->remote_static, 32) == 0) {
            collect->matched[collect->matched_count++] = collect->held[i];
        }
    }
}

/* The responder's own receipt identity: the filed local delegation names the
 * master (which must be ACTIVE in the local ZID projection) and the online
 * key the receipt is signed with. Any inconsistency fails closed: the codec
 * refuses to sign zeroed identity fields, so there is no honest receipt to
 * emit and the request is dropped after logging. */
static bool mesh_local_identity(struct node_db *ndb, const char *datadir,
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
    if (!vcs_zcode_dht_online_key_load_or_create(datadir, online_seed_out,
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
    memcpy(out, buffer, needed);
    *out_len = needed;
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
    struct v2_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !v2_transport_snapshot(node->transport, &session) ||
        !session.established) {
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
    if (!mp->params || !mp->net_mgr || !svc || !svc->datadir) {
        LOG_ERROR("net.mesh_status", "respond: composition incomplete");
        return;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    uint8_t genesis[32];
    memcpy(genesis, mp->params->consensus.hashGenesisBlock.data, 32);

    struct mesh_delegation_collect collect;
    memset(&collect, 0, sizeof(collect));
    collect.held = zcl_malloc(VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS *
                                  sizeof(*collect.held),
                              "mesh_status.delegations");
    if (!collect.held) {
        LOG_ERROR("net.mesh_status", "delegation snapshot alloc failed");
        return;
    }
    collect.held_max = VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS;
    memcpy(collect.remote_static, session.remote_static, 32);
    (void)boot_zcode_dht_service_apply(mesh_collect_delegation, &collect);

    struct node_db *ndb = app_runtime_node_db();
    uint64_t revocation_generation = 0;
    enum mesh_status_receipt_status status = boot_mesh_status_decide(
        ndb, &request, &session, collect.matched, collect.matched_count,
        genesis, now, &revocation_generation);
    free(collect.held);

    uint8_t master[32], online_pub[32], online_seed[32];
    if (!mesh_local_identity(ndb, svc->datadir, master, online_pub,
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
 * never arrive to a missing slot. Evicts expired entries, then the oldest. */
bool mesh_status_pending_admit(const struct mesh_status_request_v1 *request,
                               const uint8_t expected_responder_master[32],
                               uint64_t generation)
{
    uint64_t now_mono = mesh_now_mono();
    mesh_lock();
    mesh_pending_cleanup_locked(now_mono);
    struct mesh_status_pending *slot = NULL;
    size_t oldest = 0;
    for (size_t i = 0; i < MESH_STATUS_PENDING_MAX; i++) {
        if (!g_pending[i].used && !slot) {
            slot = &g_pending[i];
            continue;
        }
        if (g_pending[i].used &&
            g_pending[i].expires_mono < g_pending[oldest].expires_mono)
            oldest = i;
    }
    if (!slot && g_pending[oldest].used)
        slot = &g_pending[oldest];
    if (slot) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->request = *request;
        memcpy(slot->expected_responder_master, expected_responder_master, 32);
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
    struct v2_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !v2_transport_snapshot(node->transport, &session) ||
        !session.established) {
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
        entry->expected_responder_master);
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
    zcl_mutex_unlock(&g_mesh_lock);
}

void boot_mesh_status_shutdown(void)
{
    mesh_lock();
    g_mesh_svc = NULL;
    g_mesh_generation++;
    if (!g_mesh_generation)
        g_mesh_generation++;
    memset(g_pending, 0, sizeof(g_pending));
    zcl_mutex_unlock(&g_mesh_lock);
}
