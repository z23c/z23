/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Confined-terminal lane: pairing-bound OPEN responder, bounded
 * session table, and the supervised pump tick, multiplexed on zpkgswm
 * (see the header). */

// one-result-type-ok:closed-security-verdict — decide/compose return
// bounded verdicts the caller must branch on; no diagnostic text crosses
// the wire. Drop/refusal logging happens at the frame edge.

#include "config/boot_mesh_terminal.h"
#include "boot_mesh_status_internal.h"
#include "boot_mesh_terminal_internal.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_access.h"
#include "config/file_ops.h"
#include "config/runtime.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "models/mesh_pairing.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/util.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static zcl_mutex_t g_term_lock;
static _Atomic int g_term_lock_state;
static struct boot_svc_ctx *g_term_svc; /* borrowed; set by wire() */
static supervisor_child_id g_term_child = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_term_contract;
static char g_term_shell[600]; /* -terminalshell; empty = lane unavailable */

struct mesh_terminal_session {
    bool used;
    struct mesh_terminal_open_v1 open; /* the session's authority binding */
    struct mesh_terminal_worker worker;
    char workdir[600];
    uint64_t seq_out; /* last outbound DATA seq */
    uint64_t seq_in;  /* last accepted inbound DATA seq */
};
static struct mesh_terminal_session g_sessions[MESH_TERMINAL_SESSIONS_MAX];

/* Quiet-drop counters: in-namespace garbage and unauthenticated probes are
 * local policy events, never offences against the peer. */
static _Atomic uint64_t g_term_dropped_unauthenticated;
static _Atomic uint64_t g_term_dropped_malformed;
static _Atomic uint64_t g_term_dropped_unknown_kind;
static _Atomic uint64_t g_term_opens_replayed;
static _Atomic uint64_t g_term_opens_rate_limited;
static _Atomic uint64_t g_term_opens_refused;
static _Atomic uint64_t g_term_data_dropped;
static _Atomic uint64_t g_term_sessions_ended;

struct mesh_terminal_seen_open {
    bool used;
    uint8_t remote_static[32];
    uint8_t transcript_hash[32];
    uint8_t terminal_id[32];
    uint64_t connection_generation;
    uint64_t seen_mono_ms;
};
static struct mesh_terminal_seen_open
    g_seen_opens[MESH_TERMINAL_OPEN_ADMIT_MAX];

static void term_lock(void)
{
    if (atomic_load_explicit(&g_term_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_term_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_term_lock);
            atomic_store_explicit(&g_term_lock_state, 2, memory_order_release);
        } else {
            while (atomic_load_explicit(&g_term_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_term_lock);
}

/* Application replay/rate gate for OPEN frames. Noise record counters stop
 * ciphertext replay, but an authenticated requester can still resend a
 * decoded open in a new record, and every OPEN that survives to the spawn
 * path costs a fork. One exact open is admitted once per transcript
 * generation, and each authenticated session receives a small bounded
 * cadence. */
static bool terminal_open_admit(const struct mesh_terminal_open_v1 *open,
                                const struct noise_transport_snapshot *session,
                                uint64_t now_mono_ms)
{
    if (!open || !session || !session->established) {
        LOG_ERROR("net.mesh_terminal", "open admit: invalid session input");
        return false;
    }
    term_lock();
    struct mesh_terminal_seen_open *slot = NULL;
    size_t recent = 0;
    for (size_t i = 0; i < MESH_TERMINAL_OPEN_ADMIT_MAX; i++) {
        struct mesh_terminal_seen_open *seen = &g_seen_opens[i];
        if (seen->used &&
            (now_mono_ms < seen->seen_mono_ms ||
             now_mono_ms - seen->seen_mono_ms >= MESH_TERMINAL_OPEN_ADMIT_MS))
            memset(seen, 0, sizeof(*seen));
        if (!seen->used) {
            if (!slot)
                slot = seen;
            continue;
        }
        bool same_session =
            seen->connection_generation == session->connection_generation &&
            memcmp(seen->remote_static, session->remote_static, 32) == 0 &&
            memcmp(seen->transcript_hash, session->transcript_hash, 32) == 0;
        if (!same_session)
            continue;
        if (memcmp(seen->terminal_id, open->terminal_id, 32) == 0) {
            zcl_mutex_unlock(&g_term_lock);
            atomic_fetch_add(&g_term_opens_replayed, 1);
            return false;
        }
        if (now_mono_ms >= seen->seen_mono_ms &&
            now_mono_ms - seen->seen_mono_ms < UINT64_C(1000))
            recent++;
    }
    if (!slot || recent >= MESH_TERMINAL_OPEN_RATE_PER_SECOND) {
        zcl_mutex_unlock(&g_term_lock);
        atomic_fetch_add(&g_term_opens_rate_limited, 1);
        return false;
    }
    slot->used = true;
    memcpy(slot->remote_static, session->remote_static, 32);
    memcpy(slot->transcript_hash, session->transcript_hash, 32);
    memcpy(slot->terminal_id, open->terminal_id, 32);
    slot->connection_generation = session->connection_generation;
    slot->seen_mono_ms = now_mono_ms;
    zcl_mutex_unlock(&g_term_lock);
    return true;
}

#ifdef ZCL_TESTING
bool boot_mesh_terminal_test_open_admit(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session, uint64_t now_mono_ms)
{
    return terminal_open_admit(open, session, now_mono_ms);
}
#endif

/* ── Pure decision ───────────────────────────────────────────────────── */

static enum mesh_terminal_receipt_status terminal_from_pairing_reason(
    enum mesh_pairing_reason reason)
{
    switch (reason) {
    case MESH_PAIRING_OK: return MESH_TERMINAL_RECEIPT_OK;
    case MESH_PAIRING_NOT_FOUND: return MESH_TERMINAL_RECEIPT_NOT_PAIRED;
    /* A pairing is genesis-bound: a foreign-genesis request names no
     * authority this node holds. */
    case MESH_PAIRING_NETWORK_MISMATCH: return MESH_TERMINAL_RECEIPT_NOT_PAIRED;
    case MESH_PAIRING_ALREADY_REVOKED: return MESH_TERMINAL_RECEIPT_REVOKED;
    case MESH_PAIRING_EXPIRED: return MESH_TERMINAL_RECEIPT_EXPIRED;
    case MESH_PAIRING_SESSION_MISMATCH:
        return MESH_TERMINAL_RECEIPT_SESSION_MISMATCH;
    case MESH_PAIRING_AUTHORITY_CHANGED:
        return MESH_TERMINAL_RECEIPT_AUTHORITY_CHANGED;
    case MESH_PAIRING_DELEGATION_INVALID:
    case MESH_PAIRING_MASTER_INACTIVE:
    case MESH_PAIRING_BEACON_UNAVAILABLE:
    case MESH_PAIRING_BEACON_PROVISIONAL:
        return MESH_TERMINAL_RECEIPT_DELEGATION_INVALID;
    case MESH_PAIRING_CAPABILITY_UNAVAILABLE:
        return MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE;
    case MESH_PAIRING_BAD_ARGUMENT:
    case MESH_PAIRING_FINGERPRINT_MISMATCH:
    case MESH_PAIRING_WINDOW_INVALID:
    case MESH_PAIRING_IDENTITY_COLLISION:
    case MESH_PAIRING_PERSIST_FAILED:
    /* Revocation-ceremony verdicts; authorize_terminal never produces
     * them. */
    case MESH_PAIRING_CONFIRMATION_INVALID:
    case MESH_PAIRING_PLAN_EXPIRED:
        return MESH_TERMINAL_RECEIPT_INTERNAL;
    }
    return MESH_TERMINAL_RECEIPT_INTERNAL;
}

enum mesh_terminal_receipt_status boot_mesh_terminal_decide(
    struct node_db *ndb, const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *delegations,
    size_t delegation_count, const uint8_t network_genesis[32],
    uint64_t now_unix, uint64_t *revocation_generation_out)
{
    if (revocation_generation_out)
        *revocation_generation_out = 0;
    if (!open || !session || !session->established || !network_genesis ||
        now_unix == 0)
        return MESH_TERMINAL_RECEIPT_INTERNAL;
    if (open->capability != MESH_TERMINAL_CAP_TERMINAL_EXEC)
        return MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE;
    if (mesh_terminal_open_v1_validate(open) != MESH_TERMINAL_PROTO_OK)
        return MESH_TERMINAL_RECEIPT_BAD_REQUEST;
    if (now_unix < open->issued_unix || now_unix >= open->expires_unix)
        return MESH_TERMINAL_RECEIPT_EXPIRED;
    /* Live-session binding: transcript and generation are transcript-
     * derived and shared by both sides (mesh status, 2114f5257). */
    if (memcmp(open->transcript_hash, session->transcript_hash, 32) != 0 ||
        open->connection_generation != session->connection_generation ||
        memcmp(open->requester_noise_static, session->remote_static, 32) != 0)
        return MESH_TERMINAL_RECEIPT_SESSION_MISMATCH;
    if (memcmp(open->network_genesis, network_genesis, 32) != 0)
        return MESH_TERMINAL_RECEIPT_NOT_PAIRED;
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return MESH_TERMINAL_RECEIPT_INTERNAL;

    const struct vcs_zcode_dht_delegation *live = NULL;
    size_t live_count = 0;
    for (size_t i = 0; i < delegation_count; i++) {
        if (memcmp(delegations[i].noise_static_pubkey, session->remote_static,
                   32) == 0) {
            live = &delegations[i];
            live_count++;
        }
    }
    if (live_count != 1)
        return MESH_TERMINAL_RECEIPT_DELEGATION_INVALID;

    /* Pairing ids are per-side: each node derives its row id from the
     * PEER's master+noise identity, so the id an open carries names the
     * requester's own row and can never name ours. The only row that can
     * authorize this session is the one the live delegation (already
     * matched to the session's remote static) points at — derive its id. */
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    if (!mesh_pairing_id_derive(network_genesis, live->doc.master_pubkey,
                                live->noise_static_pubkey, pairing_id))
        return MESH_TERMINAL_RECEIPT_DELEGATION_INVALID;
    enum mesh_pairing_reason authorized =
        mesh_pairing_service_authorize_terminal(
            ndb, network_genesis, pairing_id, live, session->remote_static,
            (int64_t)now_unix);
    if (authorized != MESH_PAIRING_OK)
        return terminal_from_pairing_reason(authorized);
    /* The pairing row carries the receipt's revocation-generation evidence.
     * A row that vanished or revoked between authorize and this read is an
     * authority change, not an OK. */
    struct db_mesh_pairing row;
    if (!db_mesh_pairing_find(ndb, pairing_id, &row) || row.revoked_at != 0)
        return MESH_TERMINAL_RECEIPT_AUTHORITY_CHANGED;
    if (revocation_generation_out)
        *revocation_generation_out = row.revocation_generation;
    return MESH_TERMINAL_RECEIPT_OK;
}

/* ── Pure capsule rendering ──────────────────────────────────────────── */

/* Oversize output is replaced by a minimal deterministic marker object —
 * never truncated mid-document. */
static bool terminal_capsule_commit(struct json_value *capsule,
                                    uint8_t out[MESH_TERMINAL_CAPSULE_MAX],
                                    size_t *out_len)
{
    static const char oversize[] =
        "{\"schema\":\"zcl.terminal_capsule.v1\",\"capsule_oversize\":true}";
    size_t needed = json_write(capsule, NULL, 0);
    if (needed == 0 || needed > MESH_TERMINAL_CAPSULE_MAX) {
        json_free(capsule);
        if (sizeof(oversize) - 1 > MESH_TERMINAL_CAPSULE_MAX) {
            LOG_ERROR("net.mesh_terminal", "oversize marker exceeds the cap");
            return false;
        }
        memcpy(out, oversize, sizeof(oversize) - 1);
        *out_len = sizeof(oversize) - 1;
        return true;
    }
    char buffer[MESH_TERMINAL_CAPSULE_MAX + 1];
    size_t written = json_write(capsule, buffer, sizeof(buffer));
    json_free(capsule);
    if (written != needed) {
        LOG_ERROR("net.mesh_terminal", "capsule serialization truncated");
        return false;
    }
    memcpy(out, buffer, needed);
    *out_len = needed;
    return true;
}

bool boot_mesh_terminal_render_grant_capsule(
    uint8_t out[MESH_TERMINAL_CAPSULE_MAX], size_t *out_len)
{
    if (!out || !out_len)
        return false;
    *out_len = 0;
    struct json_value capsule;
    json_init(&capsule);
    json_set_object(&capsule);
    bool rendered =
        json_push_kv_str(&capsule, "schema", "zcl.terminal_grant.v1") &&
        json_push_kv_int(&capsule, "max_lifetime_s",
                         (int64_t)MESH_TERMINAL_SERVICE_LIFETIME_SECONDS) &&
        json_push_kv_int(&capsule, "idle_seconds",
                         (int64_t)MESH_TERMINAL_SERVICE_IDLE_SECONDS) &&
        json_push_kv_int(&capsule, "max_bytes_in",
                         (int64_t)MESH_TERMINAL_SERVICE_MAX_BYTES_IN) &&
        json_push_kv_int(&capsule, "max_bytes_out",
                         (int64_t)MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
    if (!rendered) {
        json_free(&capsule);
        LOG_ERROR("net.mesh_terminal", "grant capsule render refused");
        return false;
    }
    return terminal_capsule_commit(&capsule, out, out_len);
}

bool boot_mesh_terminal_render_close_capsule(
    uint64_t bytes_in, uint64_t bytes_out, uint64_t duration_seconds,
    enum mesh_terminal_close_reason reason,
    uint8_t out[MESH_TERMINAL_CAPSULE_MAX], size_t *out_len)
{
    if (!out || !out_len || bytes_in > INT64_MAX || bytes_out > INT64_MAX ||
        duration_seconds > INT64_MAX)
        return false;
    *out_len = 0;
    struct json_value capsule;
    json_init(&capsule);
    json_set_object(&capsule);
    bool rendered =
        json_push_kv_str(&capsule, "schema", "zcl.terminal_close_evidence.v1") &&
        json_push_kv_int(&capsule, "bytes_in", (int64_t)bytes_in) &&
        json_push_kv_int(&capsule, "bytes_out", (int64_t)bytes_out) &&
        json_push_kv_int(&capsule, "duration_s", (int64_t)duration_seconds) &&
        json_push_kv_str(&capsule, "reason",
                         mesh_terminal_close_reason_string(reason));
    if (!rendered) {
        json_free(&capsule);
        LOG_ERROR("net.mesh_terminal", "close capsule render refused");
        return false;
    }
    return terminal_capsule_commit(&capsule, out, out_len);
}

bool boot_mesh_terminal_pairing_lost(
    struct node_db *ndb, const struct mesh_terminal_open_v1 *open,
    uint64_t now_unix, enum mesh_terminal_close_reason *reason_out)
{
    enum mesh_terminal_close_reason lost = MESH_TERMINAL_CLOSE_REVOKED;
    bool is_lost = true;
    char pairing_hex[MESH_PAIRING_ID_HEX + 1];
    struct db_mesh_pairing row;
    /* The session's authority is THIS node's row for the requester's
     * identity pair — the open's own pairing_id names the requester-side
     * row (ids are per-side), so derive the local id exactly as the open
     * decision did. A derive failure is authority lost, like every other
     * unusable input. */
    if (open && reason_out && ndb && ndb->open &&
        mesh_pairing_id_derive(open->network_genesis,
                               open->requester_master_pubkey,
                               open->requester_noise_static, pairing_hex)) {
        if (db_mesh_pairing_find(ndb, pairing_hex, &row)) {
            if (row.revoked_at != 0)
                lost = MESH_TERMINAL_CLOSE_REVOKED;
            else if ((row.capability_mask & MESH_PAIRING_CAP_TERMINAL_EXEC) !=
                     MESH_PAIRING_CAP_TERMINAL_EXEC)
                lost = MESH_TERMINAL_CLOSE_REVOKED; /* grant no longer exists */
            else if ((uint64_t)row.expires_at <= now_unix)
                lost = MESH_TERMINAL_CLOSE_EXPIRED;
            else
                is_lost = false;
        }
    }
    /* A vanished row, an unreadable db, or an unusable argument cannot
     * keep a live terminal alive: rows are insert-only, so a row that is
     * gone went by revocation-class action, and fail-closed applies to
     * authority exactly as it does to frames. */
    if (is_lost && reason_out)
        *reason_out = lost;
    return is_lost;
}

/* ── Pure receipt composition ────────────────────────────────────────── */

bool boot_mesh_terminal_compose_receipt(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session,
    enum mesh_terminal_receipt_status status,
    const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32], uint64_t revocation_generation,
    uint64_t now_unix, const uint8_t *capsule, size_t capsule_len,
    const uint8_t responder_online_seed[32],
    struct mesh_terminal_receipt_v1 *out)
{
    if (!open || !session || !session->established || !network_genesis ||
        !responder_master_pubkey || !responder_online_pubkey ||
        !responder_noise_static || !responder_online_seed || !out ||
        now_unix == 0) {
        LOG_ERROR("net.mesh_terminal", "compose: null/unestablished argument");
        return false;
    }
    bool wants_capsule =
        status == MESH_TERMINAL_RECEIPT_OK ||
        status == MESH_TERMINAL_RECEIPT_CLOSED;
    if (wants_capsule &&
        (!capsule || capsule_len == 0 ||
         capsule_len > MESH_TERMINAL_CAPSULE_MAX)) {
        LOG_ERROR("net.mesh_terminal",
                  "compose: OK/CLOSED receipt without a capsule");
        return false;
    }
    if (!wants_capsule)
        capsule_len = 0; /* refusals are composed bare however called */
    memset(out, 0, sizeof(*out));
    out->version = MESH_TERMINAL_PROTO_VERSION;
    out->flags = MESH_TERMINAL_PROTO_FLAGS_NONE;
    out->status = status;
    memcpy(out->request_id, open->terminal_id, 32);
    if (mesh_terminal_open_v1_root(open, out->request_root) !=
        MESH_TERMINAL_PROTO_OK) {
        LOG_ERROR("net.mesh_terminal", "compose: open root failed");
        return false;
    }
    memcpy(out->network_genesis, network_genesis, 32);
    memcpy(out->pairing_id, open->pairing_id, 32);
    memcpy(out->responder_master_pubkey, responder_master_pubkey, 32);
    memcpy(out->responder_online_pubkey, responder_online_pubkey, 32);
    memcpy(out->responder_noise_static, responder_noise_static, 32);
    /* The receipt always carries the responder's LIVE session view, never
     * the request's claim. */
    memcpy(out->transcript_hash, session->transcript_hash, 32);
    out->connection_generation = session->connection_generation;
    out->revocation_generation = revocation_generation;
    out->observed_unix = now_unix;
    if (status == MESH_TERMINAL_RECEIPT_CLOSED) {
        /* The close evidence legitimately lands long after the open's
         * answer window; matches_open binds it on observed >= issued
         * alone, so no clamp here. */
        out->expires_unix = now_unix + MESH_TERMINAL_RECEIPT_VALIDITY_SECONDS;
    } else {
        uint64_t expires =
            now_unix + MESH_TERMINAL_RECEIPT_VALIDITY_SECONDS;
        if (expires > open->expires_unix)
            expires = open->expires_unix;
        if (expires <= now_unix)
            expires = now_unix + 1; /* expired-open refusal stays well-formed */
        out->expires_unix = expires;
    }
    out->capsule_len = (uint16_t)capsule_len;
    if (capsule_len)
        memcpy(out->capsule, capsule, capsule_len);
    if (mesh_terminal_capsule_v1_root(out->capsule, capsule_len,
                                      out->capsule_root) !=
        MESH_TERMINAL_PROTO_OK) {
        LOG_ERROR("net.mesh_terminal", "compose: capsule root failed");
        return false;
    }
    enum mesh_terminal_proto_error signed_result =
        mesh_terminal_receipt_v1_sign(out, responder_online_seed);
    if (signed_result != MESH_TERMINAL_PROTO_OK) {
        LOG_ERROR("net.mesh_terminal", "compose: sign failed: %s",
                  mesh_terminal_proto_error_string(signed_result));
        return false;
    }
    return true;
}

/* ── Session table helpers (locked) ──────────────────────────────────── */

static struct mesh_terminal_session *terminal_find_locked(
    const uint8_t terminal_id[32])
{
    for (size_t i = 0; i < MESH_TERMINAL_SESSIONS_MAX; i++) {
        if (g_sessions[i].used &&
            memcmp(g_sessions[i].open.terminal_id, terminal_id, 32) == 0)
            return &g_sessions[i];
    }
    return NULL;
}

static struct mesh_terminal_session *terminal_free_slot_locked(void)
{
    for (size_t i = 0; i < MESH_TERMINAL_SESSIONS_MAX; i++)
        if (!g_sessions[i].used)
            return &g_sessions[i];
    return NULL;
}

/* A session's frames are only honored on the SAME established Noise
 * session the open was bound to: a receipt, DATA, resize, or close arriving
 * over a newer or different connection is refused. */
static bool terminal_binds_session(
    const struct mesh_terminal_session *s,
    const struct noise_transport_snapshot *session)
{
    return session && session->established &&
           memcmp(session->transcript_hash, s->open.transcript_hash, 32) == 0 &&
           session->connection_generation == s->open.connection_generation &&
           memcmp(session->remote_static, s->open.requester_noise_static,
                  32) == 0;
}

/* ── Frame send (ZMTERM prefix on zpkgswm) ───────────────────────────── */

/* The prefix+kind frame writer, in mesh_status_send's implementation shape
 * (boot_mesh_status.c): the same "zpkgswm" carrier, this lane's own
 * namespace. Declared in the internal header because the requester lane's
 * open/write/resize/close verbs send through it too; the prefix itself
 * stays private to this lane's translation units. */
bool boot_mesh_terminal_send(struct msg_processor *mp,
                             struct p2p_node *node, uint8_t kind,
                             const uint8_t *wire, size_t wire_len)
{
    uint8_t frame[MESH_TERMINAL_FRAME_MAX];
    if (wire_len + MESH_TERMINAL_FRAME_PREFIX_LEN + 1u > sizeof(frame)) {
        LOG_ERROR("net.mesh_terminal", "frame %zu bytes exceeds the bound",
                  wire_len);
        return false;
    }
    memcpy(frame, MESH_TERMINAL_FRAME_PREFIX, MESH_TERMINAL_FRAME_PREFIX_LEN);
    frame[MESH_TERMINAL_FRAME_PREFIX_LEN] = kind;
    memcpy(frame + MESH_TERMINAL_FRAME_PREFIX_LEN + 1u, wire, wire_len);
    if (!p2p_node_begin_message(node, "zpkgswm", mp->params->pchMessageStart)) {
        LOG_ERROR("net.mesh_terminal", "begin_message failed for peer %lld",
                  (long long)node->id);
        return false;
    }
    p2p_node_write_message_data(
        node, frame, wire_len + MESH_TERMINAL_FRAME_PREFIX_LEN + 1u);
    if (!p2p_node_end_message(node)) {
        LOG_ERROR("net.mesh_terminal", "end_message failed for peer %lld",
                  (long long)node->id);
        return false;
    }
    return true;
}

/* ── Session ending ──────────────────────────────────────────────────── */

struct mesh_terminal_end {
    struct node_db *ndb;
    const char *datadir;
    uint8_t master[32];
    uint8_t online_pub[32];
    uint8_t online_seed[32];
    bool identity_ok;
};

/* The responder's own receipt identity, resolved once per ending batch.
 * Shared with the mesh status lane (boot_mesh_local_identity): same
 * fail-closed rules — no filed delegation, non-ACTIVE master, or online
 * key mismatch means no honest receipt exists. */
static bool terminal_end_identity(struct mesh_terminal_end *end)
{
    end->identity_ok = end->ndb && end->datadir &&
                       boot_mesh_local_identity(end->ndb, end->datadir,
                                                end->master, end->online_pub,
                                                end->online_seed);
    return end->identity_ok;
}

/* End one session: CLOSED receipt with byte/duration evidence (when the
 * live session still binds and an honest identity exists), a CLOSE frame,
 * a census-verified kill, and workdir removal. `node`/`snap`/`end` may be
 * NULL (the pump could not find the peer, or identity resolution was
 * skipped): the receipt is then skipped — the requester's own watchdog is
 * the honest terminal signal — and cleanup still runs. */
static void terminal_end_locked(struct msg_processor *mp,
                                struct p2p_node *node,
                                struct mesh_terminal_session *s,
                                const struct noise_transport_snapshot *snap,
                                struct mesh_terminal_end *end,
                                uint64_t now_unix)
{
    enum mesh_terminal_close_reason reason =
        s->worker.close_reason; /* enforcement paths already named it */
    atomic_fetch_add(&g_term_sessions_ended, 1);
    if (node && snap && end && end->identity_ok && mp && mp->net_mgr) {
        uint64_t duration = 0;
        if (now_unix > (uint64_t)s->worker.started_unix)
            duration = now_unix - (uint64_t)s->worker.started_unix;
        uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
        size_t capsule_len = 0;
        if (boot_mesh_terminal_render_close_capsule(
                s->worker.bytes_in, s->worker.bytes_out, duration, reason,
                capsule, &capsule_len)) {
            struct mesh_terminal_receipt_v1 receipt;
            /* responder_noise_static is THIS node's Noise identity, the
             * same field the status lane receipts carry; the requester
             * compares it against its own view of our session static. */
            if (boot_mesh_terminal_compose_receipt(
                    &s->open, snap, MESH_TERMINAL_RECEIPT_CLOSED,
                    s->open.network_genesis, end->master, end->online_pub,
                    mp->net_mgr->identity_pub, 0, now_unix, capsule,
                    capsule_len, end->online_seed, &receipt)) {
                uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
                size_t wire_len = 0;
                if (mesh_terminal_receipt_v1_encode(
                        &receipt, wire, sizeof(wire), &wire_len) ==
                    MESH_TERMINAL_PROTO_OK)
                    (void)boot_mesh_terminal_send(
                        mp, node, MESH_TERMINAL_FRAME_KIND_RECEIPT, wire,
                        wire_len);
            }
        }
        struct mesh_terminal_close_v1 close_frame;
        memset(&close_frame, 0, sizeof(close_frame));
        memcpy(close_frame.terminal_id, s->open.terminal_id, 32);
        close_frame.reason = (uint8_t)reason;
        uint8_t close_wire[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
        if (mesh_terminal_close_v1_encode(&close_frame, close_wire) ==
            MESH_TERMINAL_PROTO_OK)
            (void)boot_mesh_terminal_send(mp, node,
                                      MESH_TERMINAL_FRAME_KIND_CLOSE,
                                      close_wire, sizeof(close_wire));
    }
    mesh_terminal_worker_kill(&s->worker);
    dir_remove_tree(s->workdir);
    memset(s, 0, sizeof(*s));
}

/* ── OPEN responder ──────────────────────────────────────────────────── */

struct mesh_terminal_delegation_collect {
    struct vcs_zcode_dht_delegation matched[2];
    size_t matched_count;
    uint8_t remote_static[32];
};

/* Runs under the DHT global lock (boot_zcode_dht_service_apply): memory
 * copies only, no I/O. */
static void terminal_collect_delegation(struct vcs_zcode_dht_service *service,
                                        void *opaque)
{
    struct mesh_terminal_delegation_collect *collect = opaque;
    if (!service || !collect)
        return;
    collect->matched_count = vcs_zcode_dht_service_delegations_for_noise(
        service, collect->remote_static, collect->matched,
        sizeof(collect->matched) / sizeof(collect->matched[0]));
}

static bool terminal_workdir(const char *datadir,
                             const struct mesh_terminal_open_v1 *open,
                             char *out, size_t out_cap)
{
    if (!datadir || !open)
        return false;
    char hex[MESH_PAIRING_ID_HEX + 1];
    zcl_hex_encode(open->terminal_id, 32, hex);
    int n = snprintf(out, out_cap, "%s/terminals/%s.d", datadir, hex);
    if (n <= 0 || (size_t)n >= out_cap)
        return false;
    char parent[560];
    n = snprintf(parent, sizeof(parent), "%s/terminals", datadir);
    if (n <= 0 || (size_t)n >= sizeof(parent))
        return false;
    if (mkdir(parent, 0700) != 0 && errno != EEXIST)
        return false;
    if (mkdir(out, 0700) != 0 && errno != EEXIST)
        return false;
    return true;
}

/* Compose + send one refusal (or OK) receipt for an OPEN. */
static void terminal_answer_open(struct msg_processor *mp,
                                 struct p2p_node *node,
                                 const struct mesh_terminal_open_v1 *open,
                                 const struct noise_transport_snapshot *snap,
                                 enum mesh_terminal_receipt_status status,
                                 uint64_t revocation_generation,
                                 uint64_t now_unix, const uint8_t *genesis,
                                 const uint8_t *master, const uint8_t *online_pub,
                                 const uint8_t *online_seed,
                                 const uint8_t *noise_static)
{
    uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
    size_t capsule_len = 0;
    if (status == MESH_TERMINAL_RECEIPT_OK &&
        !boot_mesh_terminal_render_grant_capsule(capsule, &capsule_len))
        status = MESH_TERMINAL_RECEIPT_INTERNAL;
    struct mesh_terminal_receipt_v1 receipt;
    if (!boot_mesh_terminal_compose_receipt(
            open, snap, status, genesis, master, online_pub, noise_static,
            revocation_generation, now_unix, capsule, capsule_len, online_seed,
            &receipt))
        return;
    uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (mesh_terminal_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                        &wire_len) != MESH_TERMINAL_PROTO_OK) {
        LOG_ERROR("net.mesh_terminal", "signed receipt failed to encode");
        return;
    }
    (void)boot_mesh_terminal_send(mp, node, MESH_TERMINAL_FRAME_KIND_RECEIPT,
                              wire, wire_len);
    if (status != MESH_TERMINAL_RECEIPT_OK)
        atomic_fetch_add(&g_term_opens_refused, 1);
}

static void terminal_respond_open(struct msg_processor *mp,
                                  struct p2p_node *node, const uint8_t *wire,
                                  size_t wire_len, struct boot_svc_ctx *svc)
{
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        /* Plaintext v1 or mid-handshake: drop with NO receipt — responder
         * keys and signatures never cross an unauthenticated channel. The
         * requester's local timeout is the honest signal. */
        atomic_fetch_add(&g_term_dropped_unauthenticated, 1);
        return;
    }
    struct mesh_terminal_open_v1 open;
    if (mesh_terminal_open_v1_decode(&open, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return;
    }
    if (!terminal_open_admit(&open, &session,
                             (uint64_t)platform_time_monotonic_ms()))
        return;
    if (!mp->params || !mp->net_mgr || !svc || !svc->datadir) {
        LOG_ERROR("net.mesh_terminal", "respond: composition incomplete");
        return;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    uint8_t genesis[32];
    memcpy(genesis, mp->params->consensus.hashGenesisBlock.data, 32);

    struct mesh_terminal_delegation_collect collect;
    memset(&collect, 0, sizeof(collect));
    memcpy(collect.remote_static, session.remote_static, 32);
    (void)boot_zcode_dht_service_apply(terminal_collect_delegation, &collect);

    struct node_db *ndb = app_runtime_node_db();
    uint64_t revocation_generation = 0;
    enum mesh_terminal_receipt_status status = boot_mesh_terminal_decide(
        ndb, &open, &session, collect.matched, collect.matched_count, genesis,
        now, &revocation_generation);

    uint8_t master[32], online_pub[32], online_seed[32];
    if (!boot_mesh_local_identity(ndb, svc->datadir, master, online_pub,
                                  online_seed))
        return; /* context logged inside; no honest receipt exists */

    /* Post-decide bounded-resource verdicts, still answered by name. */
    term_lock();
    bool id_in_use = status == MESH_TERMINAL_RECEIPT_OK &&
                     terminal_find_locked(open.terminal_id) != NULL;
    bool table_full = status == MESH_TERMINAL_RECEIPT_OK &&
                      terminal_free_slot_locked() == NULL;
    zcl_mutex_unlock(&g_term_lock);
    if (id_in_use)
        status = MESH_TERMINAL_RECEIPT_SESSION_MISMATCH;
    else if (table_full)
        status = MESH_TERMINAL_RECEIPT_CONCURRENCY_LIMIT;
    if (status != MESH_TERMINAL_RECEIPT_OK) {
        terminal_answer_open(mp, node, &open, &session, status,
                             revocation_generation, now, genesis, master,
                             online_pub, online_seed,
                             mp->net_mgr->identity_pub);
        memory_cleanse(online_seed, 32);
        return;
    }

    /* Spawn the confined worker. Every spawn failure is an honest
     * CONFINEMENT_UNAVAILABLE: the node never answers OK with no cage. */
    char workdir[600];
    if (!terminal_workdir(svc->datadir, &open, workdir, sizeof(workdir))) {
        LOG_ERROR("net.mesh_terminal", "terminal workdir unavailable");
        terminal_answer_open(mp, node, &open, &session,
                             MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE,
                             revocation_generation, now, genesis, master,
                             online_pub, online_seed,
                             mp->net_mgr->identity_pub);
        memory_cleanse(online_seed, 32);
        return;
    }
    struct mesh_terminal_worker_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.shell_path = g_term_shell;
    cfg.workdir = workdir;
    cfg.cols = open.cols;
    cfg.rows = open.rows;
    cfg.max_bytes_in = MESH_TERMINAL_SERVICE_MAX_BYTES_IN;
    cfg.max_bytes_out = MESH_TERMINAL_SERVICE_MAX_BYTES_OUT;
    cfg.lifetime_seconds = MESH_TERMINAL_SERVICE_LIFETIME_SECONDS;
    cfg.idle_seconds = MESH_TERMINAL_SERVICE_IDLE_SECONDS;
    struct mesh_terminal_worker worker;
    struct zcl_result spawned =
        mesh_terminal_worker_spawn(&cfg, (int64_t)now, &worker);
    if (!spawned.ok) {
        LOG_ERROR("net.mesh_terminal", "confined spawn refused: %s",
                  spawned.message);
        terminal_answer_open(mp, node, &open, &session,
                             MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE,
                             revocation_generation, now, genesis, master,
                             online_pub, online_seed,
                             mp->net_mgr->identity_pub);
        memory_cleanse(online_seed, 32);
        dir_remove_tree(workdir);
        return;
    }

    term_lock();
    struct mesh_terminal_session *slot = terminal_free_slot_locked();
    bool id_raced = slot && terminal_find_locked(open.terminal_id) != NULL;
    if (!slot || id_raced) {
        zcl_mutex_unlock(&g_term_lock);
        /* Lost a race (last slot, or a same-id open landed first): kill
         * the fresh worker and refuse rather than exceed the table bound
         * or shadow a live session. */
        mesh_terminal_worker_kill(&worker);
        dir_remove_tree(workdir);
        terminal_answer_open(mp, node, &open, &session,
                             id_raced
                                 ? MESH_TERMINAL_RECEIPT_SESSION_MISMATCH
                                 : MESH_TERMINAL_RECEIPT_CONCURRENCY_LIMIT,
                             revocation_generation, now, genesis, master,
                             online_pub, online_seed,
                             mp->net_mgr->identity_pub);
        memory_cleanse(online_seed, 32);
        return;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->open = open;
    slot->worker = worker;
    memcpy(slot->workdir, workdir, sizeof(workdir));
    slot->seq_out = 0;
    slot->seq_in = 0;
    zcl_mutex_unlock(&g_term_lock);

    terminal_answer_open(mp, node, &open, &session, MESH_TERMINAL_RECEIPT_OK,
                         revocation_generation, now, genesis, master,
                         online_pub, online_seed, mp->net_mgr->identity_pub);
    memory_cleanse(online_seed, 32);
    LOG_INFO("net.mesh_terminal",
             "confined terminal opened: peer %lld, lifetime %llus, "
             "budgets %llu/%llu bytes",
             (long long)node->id,
             (unsigned long long)MESH_TERMINAL_SERVICE_LIFETIME_SECONDS,
             (unsigned long long)MESH_TERMINAL_SERVICE_MAX_BYTES_IN,
             (unsigned long long)MESH_TERMINAL_SERVICE_MAX_BYTES_OUT);
}

/* ── DATA / RESIZE / CLOSE ingress ───────────────────────────────────── */

/* Responder-side DATA. Returns true when a responder session claims the
 * frame (even to drop it — replay or a failed worker write); false when no
 * responder session binds it, so the dispatch can offer it to the
 * requester lane. */
static bool terminal_receive_data(struct p2p_node *node, const uint8_t *wire,
                                  size_t wire_len)
{
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        atomic_fetch_add(&g_term_dropped_unauthenticated, 1);
        return true;
    }
    struct mesh_terminal_data_v1 data;
    if (mesh_terminal_data_v1_decode(&data, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return true;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    term_lock();
    struct mesh_terminal_session *s = terminal_find_locked(data.terminal_id);
    if (!s || !terminal_binds_session(s, &session)) {
        zcl_mutex_unlock(&g_term_lock);
        return false; /* not ours; the requester lane may claim it */
    }
    /* Strictly increasing per-terminal sequence: the Noise record counters
     * stop ciphertext replay, not a decoded frame replayed in a new
     * record. */
    if (data.seq <= s->seq_in) {
        zcl_mutex_unlock(&g_term_lock);
        atomic_fetch_add(&g_term_data_dropped, 1);
        return true;
    }
    struct zcl_result r =
        mesh_terminal_worker_input(&s->worker, data.payload, data.payload_len,
                                   (int64_t)now);
    if (r.ok)
        s->seq_in = data.seq;
    zcl_mutex_unlock(&g_term_lock);
    if (!r.ok && r.code == MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT)
        LOG_WARN("net.mesh_terminal",
                 "keyboard budget overrun ended a terminal session");
    /* Other failures (NOT_RUNNING, IO) are handled by the pump's
     * enforcement pass; the frame is dropped by not advancing seq_in. */
    return true;
}

static void terminal_receive_resize(struct p2p_node *node,
                                    const uint8_t *wire, size_t wire_len)
{
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        atomic_fetch_add(&g_term_dropped_unauthenticated, 1);
        return;
    }
    struct mesh_terminal_resize_v1 resize;
    if (mesh_terminal_resize_v1_decode(&resize, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return;
    }
    term_lock();
    struct mesh_terminal_session *s =
        terminal_find_locked(resize.terminal_id);
    bool ok = s && terminal_binds_session(s, &session) &&
              mesh_terminal_worker_resize(&s->worker, resize.cols,
                                          resize.rows)
                  .ok;
    zcl_mutex_unlock(&g_term_lock);
    if (!ok)
        atomic_fetch_add(&g_term_data_dropped, 1);
}

/* Responder-side CLOSE, mirroring terminal_receive_data's claimed/fall-
 * through contract. */
static bool terminal_receive_close(struct msg_processor *mp,
                                   struct p2p_node *node, const uint8_t *wire,
                                   size_t wire_len, struct boot_svc_ctx *svc)
{
    struct noise_transport_snapshot session;
    memset(&session, 0, sizeof(session));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &session) ||
        !session.established) {
        atomic_fetch_add(&g_term_dropped_unauthenticated, 1);
        return true;
    }
    struct mesh_terminal_close_v1 close_frame;
    if (mesh_terminal_close_v1_decode(&close_frame, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return true;
    }
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    term_lock();
    struct mesh_terminal_session *s =
        terminal_find_locked(close_frame.terminal_id);
    if (!s || !terminal_binds_session(s, &session)) {
        zcl_mutex_unlock(&g_term_lock);
        return false; /* not ours; the requester lane may claim it */
    }
    /* The requester asked to close: name it so the evidence receipt and
     * the kill keep the worker's default REQUESTED reason. */
    s->worker.close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
    struct node_db *ndb = svc ? app_runtime_node_db() : NULL;
    struct mesh_terminal_end end = { .ndb = ndb, .datadir = svc ? svc->datadir : NULL };
    terminal_end_identity(&end);
    terminal_end_locked(mp, node, s, &session, &end, now);
    memory_cleanse(end.online_seed, sizeof(end.online_seed));
    zcl_mutex_unlock(&g_term_lock);
    return true;
}

/* ── Supervised pump tick ────────────────────────────────────────────── */

static void terminal_pump_tick(struct liveness_contract *contract)
{
    (void)contract;
    term_lock();
    struct boot_svc_ctx *svc = g_term_svc;
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr) {
        zcl_mutex_unlock(&g_term_lock);
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0) {
        zcl_mutex_unlock(&g_term_lock);
        return;
    }
    bool any_live = false;
    bool did_work = false;
    for (size_t i = 0; i < MESH_TERMINAL_SESSIONS_MAX; i++) {
        struct mesh_terminal_session *s = &g_sessions[i];
        if (!s->used)
            continue;
        any_live = true;
        struct noise_transport_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        struct p2p_node *node = boot_mesh_find_session_peer(
            svc->msg_processor->net_mgr, s->open.requester_noise_static,
            &snap);
        if (!node || !terminal_binds_session(s, &snap)) {
            /* The session's connection is gone or was re-established:
             * no bound receipt can exist, so end silently — the
             * requester's watchdog and the named CLOSE-less timeout are
             * the honest signals on that side. */
            if (node)
                p2p_node_release(node);
            s->worker.close_reason = MESH_TERMINAL_CLOSE_SESSION_LOST;
            terminal_end_locked(svc->msg_processor, NULL, s, NULL, NULL,
                                (uint64_t)now);
            continue;
        }
        /* Authority before budget: a pairing that no longer grants
         * terminal-exec ends the session with its named reason and
         * evidence, whatever the budget says. */
        enum mesh_terminal_close_reason authority_reason =
            MESH_TERMINAL_CLOSE_REQUESTED;
        if (boot_mesh_terminal_pairing_lost(app_runtime_node_db(), &s->open,
                                            (uint64_t)now,
                                            &authority_reason)) {
            s->worker.close_reason = authority_reason;
            struct node_db *ndb = app_runtime_node_db();
            struct mesh_terminal_end end = {
                .ndb = ndb,
                .datadir = svc->datadir,
            };
            terminal_end_identity(&end);
            terminal_end_locked(svc->msg_processor, node, s, &snap, &end,
                                (uint64_t)now);
            memory_cleanse(end.online_seed, sizeof(end.online_seed));
            p2p_node_release(node);
            continue;
        }
        /* Budget enforcement first: a dead or over-budget session ends
         * with its named reason and evidence before any further output. */
        if (mesh_terminal_worker_budget_exceeded(&s->worker, now)) {
            struct node_db *ndb = app_runtime_node_db();
            struct mesh_terminal_end end = {
                .ndb = ndb,
                .datadir = svc->datadir,
            };
            terminal_end_identity(&end);
            terminal_end_locked(svc->msg_processor, node, s, &snap, &end,
                                (uint64_t)now);
            memory_cleanse(end.online_seed, sizeof(end.online_seed));
            p2p_node_release(node);
            continue;
        }
        /* Drain bounded output into DATA frames. */
        for (int chunk = 0; chunk < MESH_TERMINAL_PUMP_CHUNKS_PER_TICK;
             chunk++) {
            uint8_t buf[MESH_TERMINAL_WORKER_IO_CHUNK];
            size_t n = 0;
            struct zcl_result r = mesh_terminal_worker_output(
                &s->worker, buf, sizeof(buf), &n, now);
            if (!r.ok || n == 0)
                break;
            did_work = true;
            size_t off = 0;
            while (off < n) {
                size_t take = n - off;
                if (take > MESH_TERMINAL_DATA_PAYLOAD_MAX)
                    take = MESH_TERMINAL_DATA_PAYLOAD_MAX;
                struct mesh_terminal_data_v1 frame;
                memset(&frame, 0, sizeof(frame));
                memcpy(frame.terminal_id, s->open.terminal_id, 32);
                frame.seq = ++s->seq_out;
                frame.payload_len = (uint16_t)take;
                memcpy(frame.payload, buf + off, take);
                uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
                size_t wire_len = 0;
                if (mesh_terminal_data_v1_encode(&frame, wire, sizeof(wire),
                                                 &wire_len) ==
                    MESH_TERMINAL_PROTO_OK)
                    (void)boot_mesh_terminal_send(
                        svc->msg_processor, node,
                        MESH_TERMINAL_FRAME_KIND_DATA, wire, wire_len);
                off += take;
            }
        }
        p2p_node_release(node);
    }
    if (!any_live || !did_work)
        supervisor_progress_idle(g_term_child);
    zcl_mutex_unlock(&g_term_lock);
}

/* ── Frame dispatch ──────────────────────────────────────────────────── */

bool boot_mesh_terminal_frame(struct msg_processor *mp, struct p2p_node *node,
                              const uint8_t *payload, size_t payload_len,
                              struct boot_svc_ctx *svc)
{
    if (!payload || payload_len < MESH_TERMINAL_FRAME_PREFIX_LEN + 1u ||
        memcmp(payload, MESH_TERMINAL_FRAME_PREFIX,
               MESH_TERMINAL_FRAME_PREFIX_LEN) != 0)
        return false;
    uint8_t kind = payload[MESH_TERMINAL_FRAME_PREFIX_LEN];
    const uint8_t *wire = payload + MESH_TERMINAL_FRAME_PREFIX_LEN + 1u;
    size_t wire_len = payload_len - MESH_TERMINAL_FRAME_PREFIX_LEN - 1u;
    if (!mp || !node)
        return true; /* our namespace, unusable context: drop quietly */
    switch (kind) {
    case MESH_TERMINAL_FRAME_KIND_OPEN:
        terminal_respond_open(mp, node, wire, wire_len, svc);
        return true;
    case MESH_TERMINAL_FRAME_KIND_RECEIPT:
        /* Receipts only ever travel requester-ward; the responder table
         * never holds a session waiting on one. */
        boot_mesh_terminal_client_receipt(node, wire, wire_len);
        return true;
    case MESH_TERMINAL_FRAME_KIND_DATA:
        if (!terminal_receive_data(node, wire, wire_len))
            boot_mesh_terminal_client_data(node, wire, wire_len);
        return true;
    case MESH_TERMINAL_FRAME_KIND_RESIZE:
        terminal_receive_resize(node, wire, wire_len);
        return true;
    case MESH_TERMINAL_FRAME_KIND_CLOSE:
        if (!terminal_receive_close(mp, node, wire, wire_len, svc))
            boot_mesh_terminal_client_close_frame(node, wire, wire_len);
        return true;
    default:
        atomic_fetch_add(&g_term_dropped_unknown_kind, 1);
        return true;
    }
}

/* ── Lifecycle ───────────────────────────────────────────────────────── */

void boot_mesh_terminal_wire(struct boot_svc_ctx *svc)
{
    term_lock();
    if (g_term_child != SUPERVISOR_INVALID_ID || g_term_svc) {
        zcl_mutex_unlock(&g_term_lock);
        LOG_ERROR("net.mesh_terminal", "wire: already wired");
        return;
    }
    g_term_svc = svc;
    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_seen_opens, 0, sizeof(g_seen_opens));
    g_term_shell[0] = '\0';
    const char *shell = GetArg("-terminalshell", "");
    if (shell && shell[0] == '/') {
        snprintf(g_term_shell, sizeof(g_term_shell), "%s", shell);
    } else if (shell && shell[0]) {
        LOG_ERROR("net.mesh_terminal",
                  "-terminalshell must be absolute; the terminal lane "
                  "answers CONFINEMENT_UNAVAILABLE until it is");
    }
    zcl_mutex_unlock(&g_term_lock);

    /* The requester lane arms and disarms with the responder's lifecycle:
     * one wire, one shutdown, always together. */
    boot_mesh_terminal_client_wire(svc);

    liveness_contract_init(&g_term_contract, "net.mesh_terminal_pump");
    g_term_contract.on_tick = terminal_pump_tick;
    supervisor_domains_init();
    g_term_child = supervisor_register_in_domain(g_net_sup, &g_term_contract);
    if (g_term_child == SUPERVISOR_INVALID_ID) {
        LOG_ERROR("net.mesh_terminal", "pump supervisor register failed");
        return;
    }
    supervisor_set_period(g_term_child, 1);
    /* 100 ms cadence: keyboard/screen latency a human tolerates, still
     * far under any stall deadline. */
    g_term_contract.period_us = 100000;
    supervisor_request_min_tick_ms(100);
    supervisor_set_deadline(g_term_child, 30);
    supervisor_set_progress_exempt(
        g_term_child, "paired peers may never open a terminal");
}

void boot_mesh_terminal_shutdown(void)
{
    term_lock();
    supervisor_child_id child = g_term_child;
    g_term_child = SUPERVISOR_INVALID_ID;
    g_term_svc = NULL;
    for (size_t i = 0; i < MESH_TERMINAL_SESSIONS_MAX; i++) {
        struct mesh_terminal_session *s = &g_sessions[i];
        if (!s->used)
            continue;
        mesh_terminal_worker_kill(&s->worker);
        dir_remove_tree(s->workdir);
    }
    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_seen_opens, 0, sizeof(g_seen_opens));
    zcl_mutex_unlock(&g_term_lock);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_unregister(child);
    boot_mesh_terminal_client_shutdown();
    /* Barrier with a callback already snapshotted by the supervisor. */
    term_lock();
    zcl_mutex_unlock(&g_term_lock);
}
