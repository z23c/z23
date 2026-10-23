/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Confined-terminal service on the mesh stream primitive: the
 * pairing-bound open decision, the signed receipts, and the drain that
 * moves screen bytes into stream DATA (see the header). The stream owns
 * the framing, the table, the credit and the tick. */

// one-result-type-ok:closed-security-verdict — decide/compose return
// bounded verdicts the caller must branch on; no diagnostic text crosses
// the wire. Drop/refusal logging happens at the frame edge.

#include "config/boot_mesh_terminal.h"
#include "config/mesh_stream.h"
#include "boot_mesh_status_internal.h"
#include "boot_mesh_terminal_internal.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_access.h"
#include "config/file_ops.h"
#include "config/runtime.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "models/mesh_pairing.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/util.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static struct boot_svc_ctx *g_term_svc; /* borrowed; set by wire() */
static bool g_term_unconfined; /* -terminalacceptunconfined admitted */
static char g_term_shell[600]; /* -terminalshell; empty = lane unavailable */
static uint64_t g_term_max_out = MESH_TERMINAL_SERVICE_MAX_BYTES_OUT; /* -terminalmaxbytesout */

/* First four bytes of the pairing id as hex: enough to tell peers apart in a
 * log without naming the pairing. */
static void terminal_peer_prefix(const struct mesh_terminal_open_v1 *open,
                                 char out[9])
{
    zcl_hex_encode(open->pairing_id, 4, out);
}

static const char *terminal_state_name(void)
{
    return g_term_unconfined ? MESH_TERMINAL_CONFINEMENT_UNCONFINED
                             : "confined";
}

static void terminal_log_opened(const struct mesh_terminal_open_v1 *open,
                                uint64_t stream_id)
{
    char peer[9];
    terminal_peer_prefix(open, peer);
    LOG_INFO("net.mesh_terminal",
             "terminal opened (%s): peer %s, stream %llu, lifetime %llus, "
             "budgets %llu/%llu bytes",
             terminal_state_name(), peer, (unsigned long long)stream_id,
             (unsigned long long)MESH_TERMINAL_SERVICE_LIFETIME_SECONDS,
             (unsigned long long)MESH_TERMINAL_SERVICE_MAX_BYTES_IN,
             (unsigned long long)boot_mesh_terminal_max_bytes_out());
}

/* One confined terminal's own state, hung off its stream. The stream owns
 * the identity, the peer binding, the credit window and the lifetime;
 * this is only what a terminal adds to them. */
struct mesh_terminal_session {
    struct mesh_terminal_open_v1 open; /* the session's authority binding */
    struct mesh_terminal_worker worker;
    char workdir[600];
    uint64_t seq_out; /* last outbound DATA seq */
    uint64_t seq_in;  /* last accepted inbound DATA seq */
};

/* Live confined workers, so a fifth concurrent OPEN is refused by name
 * rather than queued. Read and written only from service callbacks, which
 * the stream primitive runs under its one lane lock. */
static size_t g_term_live;

/* Quiet-drop counters: in-namespace garbage is a local policy event,
 * never an offence against the peer. The unauthenticated-link drop is
 * the stream primitive's: no frame reaches this lane off an established
 * Noise session. */
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

/* A used entry older than the admit window, or stamped after now (the clock
 * stepped back), frees its slot. */
static bool terminal_open_seen_stale(const struct mesh_terminal_seen_open *seen,
                                     uint64_t now_mono_ms)
{
    return seen->used &&
           (now_mono_ms < seen->seen_mono_ms ||
            now_mono_ms - seen->seen_mono_ms >= MESH_TERMINAL_OPEN_ADMIT_MS);
}

/* An entry admitted within the last second counts toward the session's
 * per-second cadence. */
static bool terminal_open_seen_recent(const struct mesh_terminal_seen_open *seen,
                                      uint64_t now_mono_ms)
{
    return now_mono_ms >= seen->seen_mono_ms &&
           now_mono_ms - seen->seen_mono_ms < UINT64_C(1000);
}

/* Application replay/rate gate for OPEN frames. Noise record counters stop
 * ciphertext replay, but an authenticated requester can still resend a
 * decoded open in a new record, and every OPEN that survives to the spawn
 * path costs a fork. One exact open is admitted once per transcript
 * generation, and each authenticated session receives a small bounded
 * cadence. Runs under the stream lane lock, like every other callback in
 * this file. */
static bool terminal_open_admit(const struct mesh_terminal_open_v1 *open,
                                const struct noise_transport_snapshot *session,
                                uint64_t now_mono_ms)
{
    if (!open || !session || !session->established) {
        LOG_ERROR("net.mesh_terminal", "open admit: invalid session input");
        return false;
    }
    struct mesh_terminal_seen_open *slot = NULL;
    size_t recent = 0;
    for (size_t i = 0; i < MESH_TERMINAL_OPEN_ADMIT_MAX; i++) {
        struct mesh_terminal_seen_open *seen = &g_seen_opens[i];
        if (terminal_open_seen_stale(seen, now_mono_ms))
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
            atomic_fetch_add(&g_term_opens_replayed, 1);
            return false;
        }
        if (terminal_open_seen_recent(seen, now_mono_ms))
            recent++;
    }
    if (!slot || recent >= MESH_TERMINAL_OPEN_RATE_PER_SECOND) {
        atomic_fetch_add(&g_term_opens_rate_limited, 1);
        return false;
    }
    slot->used = true;
    memcpy(slot->remote_static, session->remote_static, 32);
    memcpy(slot->transcript_hash, session->transcript_hash, 32);
    memcpy(slot->terminal_id, open->terminal_id, 32);
    slot->connection_generation = session->connection_generation;
    slot->seen_mono_ms = now_mono_ms;
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

/* Receipt verdict for each pairing verdict. A pairing is genesis-bound: a
 * foreign-genesis request names no authority this node holds. A reason with
 * no row here is an internal verdict. */
static const struct {
    enum mesh_pairing_reason reason;
    enum mesh_terminal_receipt_status status;
} g_terminal_pairing_verdicts[] = {
    { MESH_PAIRING_OK, MESH_TERMINAL_RECEIPT_OK },
    { MESH_PAIRING_NOT_FOUND, MESH_TERMINAL_RECEIPT_NOT_PAIRED },
    { MESH_PAIRING_NETWORK_MISMATCH, MESH_TERMINAL_RECEIPT_NOT_PAIRED },
    { MESH_PAIRING_ALREADY_REVOKED, MESH_TERMINAL_RECEIPT_REVOKED },
    { MESH_PAIRING_EXPIRED, MESH_TERMINAL_RECEIPT_EXPIRED },
    { MESH_PAIRING_SESSION_MISMATCH, MESH_TERMINAL_RECEIPT_SESSION_MISMATCH },
    { MESH_PAIRING_AUTHORITY_CHANGED, MESH_TERMINAL_RECEIPT_AUTHORITY_CHANGED },
    { MESH_PAIRING_DELEGATION_INVALID, MESH_TERMINAL_RECEIPT_DELEGATION_INVALID },
    { MESH_PAIRING_MASTER_INACTIVE, MESH_TERMINAL_RECEIPT_DELEGATION_INVALID },
    { MESH_PAIRING_BEACON_UNAVAILABLE, MESH_TERMINAL_RECEIPT_DELEGATION_INVALID },
    { MESH_PAIRING_BEACON_PROVISIONAL, MESH_TERMINAL_RECEIPT_DELEGATION_INVALID },
    { MESH_PAIRING_CAPABILITY_UNAVAILABLE,
      MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE },
    { MESH_PAIRING_BAD_ARGUMENT, MESH_TERMINAL_RECEIPT_INTERNAL },
    { MESH_PAIRING_FINGERPRINT_MISMATCH, MESH_TERMINAL_RECEIPT_INTERNAL },
    { MESH_PAIRING_WINDOW_INVALID, MESH_TERMINAL_RECEIPT_INTERNAL },
    { MESH_PAIRING_IDENTITY_COLLISION, MESH_TERMINAL_RECEIPT_INTERNAL },
    { MESH_PAIRING_PERSIST_FAILED, MESH_TERMINAL_RECEIPT_INTERNAL },
    /* Revocation-ceremony verdicts; authorize_terminal never produces
     * them. */
    { MESH_PAIRING_CONFIRMATION_INVALID, MESH_TERMINAL_RECEIPT_INTERNAL },
    { MESH_PAIRING_PLAN_EXPIRED, MESH_TERMINAL_RECEIPT_INTERNAL },
};

static enum mesh_terminal_receipt_status terminal_from_pairing_reason(
    enum mesh_pairing_reason reason)
{
    for (size_t i = 0;
         i < sizeof(g_terminal_pairing_verdicts) /
                 sizeof(g_terminal_pairing_verdicts[0]);
         i++) {
        if (g_terminal_pairing_verdicts[i].reason == reason)
            return g_terminal_pairing_verdicts[i].status;
    }
    return MESH_TERMINAL_RECEIPT_INTERNAL;
}

/* Request checks: the open's shape, capability, validity window. Run before
 * any session or pairing state is read. */
static enum mesh_terminal_receipt_status terminal_decide_request_status(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session,
    const uint8_t network_genesis[32], uint64_t now_unix)
{
    if (!open || !session || !session->established || !network_genesis ||
        now_unix == 0)
        return MESH_TERMINAL_RECEIPT_INTERNAL;
    if (open->capability != MESH_TERMINAL_CAP_TERMINAL_EXEC)
        return MESH_TERMINAL_RECEIPT_CAPABILITY_UNAVAILABLE;
    if (mesh_terminal_open_v1_validate(open) != MESH_TERMINAL_PROTO_OK)
        return MESH_TERMINAL_RECEIPT_BAD_REQUEST;
    if (now_unix < open->issued_unix || now_unix >= open->expires_unix)
        return MESH_TERMINAL_RECEIPT_EXPIRED;
    return MESH_TERMINAL_RECEIPT_OK;
}

/* Live-session binding: transcript and generation are transcript-derived and
 * shared by both sides (mesh status). */
static enum mesh_terminal_receipt_status terminal_decide_binding_status(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session,
    const uint8_t network_genesis[32])
{
    if (memcmp(open->transcript_hash, session->transcript_hash, 32) != 0 ||
        open->connection_generation != session->connection_generation ||
        memcmp(open->requester_noise_static, session->remote_static, 32) != 0)
        return MESH_TERMINAL_RECEIPT_SESSION_MISMATCH;
    if (memcmp(open->network_genesis, network_genesis, 32) != 0)
        return MESH_TERMINAL_RECEIPT_NOT_PAIRED;
    return MESH_TERMINAL_RECEIPT_OK;
}

/* The one delegation whose noise key is the session's peer. Zero matches or
 * several matches are never authority. */
static enum mesh_terminal_receipt_status terminal_live_delegation(
    const struct vcs_zcode_dht_delegation *delegations,
    size_t delegation_count, const struct noise_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation **live_out)
{
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
    *live_out = live;
    return MESH_TERMINAL_RECEIPT_OK;
}

/* Pairing ids are per-side: each node derives its row id from the PEER's
 * master+noise identity, so the id an open carries names the requester's own
 * row and can never name ours. The only row that can authorize this session
 * is the one the live delegation (already matched to the session's remote
 * static) points at — derive its id. */
static enum mesh_terminal_receipt_status terminal_authorize_live(
    struct node_db *ndb, const uint8_t network_genesis[32],
    const struct vcs_zcode_dht_delegation *live,
    const struct noise_transport_snapshot *session, uint64_t now_unix,
    char pairing_id[MESH_PAIRING_ID_HEX + 1])
{
    if (!mesh_pairing_id_derive(network_genesis, live->doc.master_pubkey,
                                live->noise_static_pubkey, pairing_id))
        return MESH_TERMINAL_RECEIPT_DELEGATION_INVALID;
    enum mesh_pairing_reason authorized =
        mesh_pairing_service_authorize_terminal(
            ndb, network_genesis, pairing_id, live, session->remote_static,
            (int64_t)now_unix);
    if (authorized != MESH_PAIRING_OK)
        return terminal_from_pairing_reason(authorized);
    return MESH_TERMINAL_RECEIPT_OK;
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
    enum mesh_terminal_receipt_status verdict =
        terminal_decide_request_status(open, session, network_genesis,
                                       now_unix);
    if (verdict != MESH_TERMINAL_RECEIPT_OK)
        return verdict;
    verdict = terminal_decide_binding_status(open, session, network_genesis);
    if (verdict != MESH_TERMINAL_RECEIPT_OK)
        return verdict;
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return MESH_TERMINAL_RECEIPT_INTERNAL;

    const struct vcs_zcode_dht_delegation *live = NULL;
    verdict = terminal_live_delegation(delegations, delegation_count, session,
                                       &live);
    if (verdict != MESH_TERMINAL_RECEIPT_OK)
        return verdict;

    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    verdict = terminal_authorize_live(ndb, network_genesis, live, session,
                                      now_unix, pairing_id);
    if (verdict != MESH_TERMINAL_RECEIPT_OK)
        return verdict;
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
    return boot_mesh_terminal_render_grant_capsule_marked(
        g_term_unconfined ? MESH_TERMINAL_CONFINEMENT_UNCONFINED : NULL, out,
        out_len);
}

bool boot_mesh_terminal_render_grant_capsule_marked(
    const char *marker, uint8_t out[MESH_TERMINAL_CAPSULE_MAX],
    size_t *out_len)
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
                         (int64_t)boot_mesh_terminal_max_bytes_out());
    if (rendered && marker)
        rendered = json_push_kv_str(&capsule, "terminal_confinement", marker);
    if (!rendered) {
        json_free(&capsule);
        LOG_ERROR("net.mesh_terminal", "grant capsule render refused");
        return false;
    }
    return terminal_capsule_commit(&capsule, out, out_len);
}

/* worker-exited carries exactly one status; every other reason carries
 * none. */
static bool terminal_close_status_valid(enum mesh_terminal_close_reason reason,
                                        int exit_code, int signal)
{
    bool has_exit = exit_code >= 0;
    bool has_signal = signal != 0;
    if (exit_code < -1 || exit_code > 255 || signal < 0 || signal > 64)
        return false;
    if (reason == MESH_TERMINAL_CLOSE_WORKER_EXITED)
        return has_exit != has_signal;
    return !has_exit && !has_signal;
}

/* Shared body: writes "exit_code" when >= 0 and "signal" when > 0. */
static bool terminal_render_close(uint64_t bytes_in, uint64_t bytes_out,
                                  uint64_t duration_seconds,
                                  enum mesh_terminal_close_reason reason,
                                  int exit_code, int signal,
                                  uint8_t out[MESH_TERMINAL_CAPSULE_MAX],
                                  size_t *out_len)
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
    if (rendered && exit_code >= 0)
        rendered = json_push_kv_int(&capsule, "exit_code", exit_code);
    if (rendered && signal > 0)
        rendered = json_push_kv_int(&capsule, "signal", signal);
    if (!rendered) {
        json_free(&capsule);
        LOG_ERROR("net.mesh_terminal", "close capsule render refused");
        return false;
    }
    return terminal_capsule_commit(&capsule, out, out_len);
}

/* The pre-status shape: no status keys whatever the reason, exactly what a
 * node that predates the fields sends. */
bool boot_mesh_terminal_render_close_capsule(
    uint64_t bytes_in, uint64_t bytes_out, uint64_t duration_seconds,
    enum mesh_terminal_close_reason reason,
    uint8_t out[MESH_TERMINAL_CAPSULE_MAX], size_t *out_len)
{
    return terminal_render_close(bytes_in, bytes_out, duration_seconds,
                                 reason, -1, 0, out, out_len);
}

bool boot_mesh_terminal_render_close_capsule_status(
    uint64_t bytes_in, uint64_t bytes_out, uint64_t duration_seconds,
    enum mesh_terminal_close_reason reason, int exit_code, int signal,
    uint8_t out[MESH_TERMINAL_CAPSULE_MAX], size_t *out_len)
{
    if (!terminal_close_status_valid(reason, exit_code, signal))
        return false;
    return terminal_render_close(bytes_in, bytes_out, duration_seconds,
                                 reason, exit_code, signal, out, out_len);
}

uint64_t boot_mesh_terminal_resolve_max_bytes_out(int64_t arg)
{
    if (arg < (int64_t)MESH_TERMINAL_SERVICE_MIN_BYTES_OUT_ARG ||
        (uint64_t)arg > MESH_TERMINAL_SERVICE_MAX_BYTES_OUT_ARG)
        return MESH_TERMINAL_SERVICE_MAX_BYTES_OUT;
    return (uint64_t)arg;
}

uint64_t boot_mesh_terminal_max_bytes_out(void)
{
    return g_term_max_out;
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

/* Open and session inputs: each must be present before any output byte is
 * written. */
static bool terminal_compose_open_ok(const struct mesh_terminal_open_v1 *open,
                                     const struct noise_transport_snapshot *session,
                                     const uint8_t network_genesis[32],
                                     uint64_t now_unix)
{
    return open && session && session->established && network_genesis &&
           now_unix != 0;
}

/* Responder key material and the output buffer. */
static bool terminal_compose_keys_ok(
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32],
    const uint8_t responder_online_seed[32],
    const struct mesh_terminal_receipt_v1 *out)
{
    return responder_master_pubkey && responder_online_pubkey &&
           responder_noise_static && responder_online_seed && out;
}

/* Validity window. A CLOSED receipt takes the full window: its close evidence
 * lands long after the open's answer window, and matches_open binds it on
 * observed >= issued alone, so no clamp here. Any other receipt is clamped to
 * the open's own expiry and never comes out already expired. */
static uint64_t terminal_receipt_expiry(
    const struct mesh_terminal_open_v1 *open,
    enum mesh_terminal_receipt_status status, uint64_t now_unix)
{
    uint64_t expires = now_unix + MESH_TERMINAL_RECEIPT_VALIDITY_SECONDS;
    if (status == MESH_TERMINAL_RECEIPT_CLOSED)
        return expires;
    if (expires > open->expires_unix)
        expires = open->expires_unix;
    if (expires <= now_unix)
        expires = now_unix + 1; /* expired-open refusal stays well-formed */
    return expires;
}

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
    if (!terminal_compose_open_ok(open, session, network_genesis, now_unix) ||
        !terminal_compose_keys_ok(responder_master_pubkey,
                                  responder_online_pubkey,
                                  responder_noise_static,
                                  responder_online_seed, out)) {
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
    out->expires_unix = terminal_receipt_expiry(open, status, now_unix);
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

/* ── The lane's own message envelope ─────────────────────────────────── */

/* One leading kind byte then the mesh_terminal_proto wire, inside a
 * stream DATA or CLOSE payload. Returns 0 when the message does not fit,
 * so a caller never sends a truncated one. */
size_t boot_mesh_terminal_msg(uint8_t kind, const uint8_t *wire, size_t wire_len,
                           uint8_t *out, size_t out_cap)
{
    if (!wire || wire_len == 0 || 1u + wire_len > out_cap)
        return 0;
    out[0] = kind;
    memcpy(out + 1, wire, wire_len);
    return 1u + wire_len;
}

/* The stream's peer binding in the shape the pure decision and the
 * receipt composition already take. A stream only ever exists on an
 * established Noise session — that is the primitive's own invariant, and
 * every frame it delivers was checked against this exact binding. */
void boot_mesh_terminal_stream_session(const struct mesh_stream *st,
                                      struct noise_transport_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    out->established = true;
    memcpy(out->remote_static, st->peer_static, 32);
    memcpy(out->transcript_hash, st->transcript_hash, 32);
    out->connection_generation = st->connection_generation;
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

/* The responder's own receipt identity, resolved once per ending.
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

/* The remote shell's status for the close evidence: a signal death names
 * the signal, a normal exit names the (8-bit) exit code. Only a
 * worker-exited ending carries one. */
static void terminal_close_status(const struct mesh_terminal_worker *w,
                                  int *exit_code, int *signal)
{
    *exit_code = -1;
    *signal = 0;
    if (w->close_reason != MESH_TERMINAL_CLOSE_WORKER_EXITED)
        return;
    if (w->term_signal > 0 && w->term_signal <= 64)
        *signal = w->term_signal;
    else
        *exit_code = (w->exit_code >= 0 && w->exit_code <= 255) ? w->exit_code
                                                                : 255;
}

/* End one live session: the CLOSED receipt with byte/duration evidence as
 * the stream's last DATA (when an honest identity exists and the credit
 * is there), then the stream CLOSE naming the reason. The kill, the
 * workdir removal and the state release happen in on_close, which the
 * primitive runs exactly once per stream however the stream ends. */
static void terminal_end_session(struct mesh_stream *st,
                                 struct mesh_terminal_session *s,
                                 uint64_t now_unix)
{
    enum mesh_terminal_close_reason reason =
        s->worker.close_reason; /* enforcement paths already named it */
    struct boot_svc_ctx *svc = g_term_svc;
    struct msg_processor *mp = svc ? svc->msg_processor : NULL;
    struct mesh_terminal_end end = {
        .ndb = svc ? app_runtime_node_db() : NULL,
        .datadir = svc ? svc->datadir : NULL,
    };
    terminal_end_identity(&end);
    if (end.identity_ok && mp && mp->net_mgr) {
        struct noise_transport_snapshot snap;
        boot_mesh_terminal_stream_session(st, &snap);
        uint64_t duration = 0;
        if (now_unix > (uint64_t)s->worker.started_unix)
            duration = now_unix - (uint64_t)s->worker.started_unix;
        uint8_t capsule[MESH_TERMINAL_CAPSULE_MAX];
        size_t capsule_len = 0;
        int status_exit = -1, status_signal = 0;
        terminal_close_status(&s->worker, &status_exit, &status_signal);
        if (boot_mesh_terminal_render_close_capsule_status(
                s->worker.bytes_in, s->worker.bytes_out, duration, reason,
                status_exit, status_signal, capsule, &capsule_len)) {
            struct mesh_terminal_receipt_v1 receipt;
            /* responder_noise_static is THIS node's Noise identity, the
             * same field the status lane receipts carry; the requester
             * compares it against its own view of our session static. */
            if (boot_mesh_terminal_compose_receipt(
                    &s->open, &snap, MESH_TERMINAL_RECEIPT_CLOSED,
                    s->open.network_genesis, end.master, end.online_pub,
                    mp->net_mgr->identity_pub, 0, now_unix, capsule,
                    capsule_len, end.online_seed, &receipt)) {
                uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
                size_t wire_len = 0;
                if (mesh_terminal_receipt_v1_encode(
                        &receipt, wire, sizeof(wire), &wire_len) ==
                    MESH_TERMINAL_PROTO_OK) {
                    uint8_t msg[MESH_TERMINAL_MSG_MAX];
                    size_t msg_len =
                        boot_mesh_terminal_msg(MESH_TERMINAL_MSG_RECEIPT, wire,
                                     wire_len, msg, sizeof(msg));
                    if (msg_len)
                        (void)mesh_stream_send(st, msg, msg_len);
                }
            }
        }
    }
    memory_cleanse(end.online_seed, sizeof(end.online_seed));

    struct mesh_terminal_close_v1 close_frame;
    memset(&close_frame, 0, sizeof(close_frame));
    memcpy(close_frame.terminal_id, s->open.terminal_id, 32);
    close_frame.reason = (uint8_t)reason;
    uint8_t close_wire[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
    uint8_t msg[MESH_TERMINAL_MSG_MAX];
    size_t msg_len = 0;
    if (mesh_terminal_close_v1_encode(&close_frame, close_wire) ==
        MESH_TERMINAL_PROTO_OK)
        msg_len = boot_mesh_terminal_msg(MESH_TERMINAL_MSG_CLOSE, close_wire,
                               sizeof(close_wire), msg, sizeof(msg));
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE,
                      msg_len ? msg : NULL, msg_len);
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
    if (!platform_private_directory_ensure(parent))
        return false;
    if (!platform_private_directory_ensure(out))
        return false;
    return true;
}

/* Compose one signed receipt into the reply buffer the primitive gave us.
 * An OK reply becomes the stream's first DATA; a refusal reply rides the
 * CLOSE, so a refused open still carries this node's named, signed
 * verdict and reserves nothing. */
static size_t terminal_compose_reply(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *snap,
    enum mesh_terminal_receipt_status status, uint64_t revocation_generation,
    uint64_t now_unix, const uint8_t *genesis, const uint8_t *master,
    const uint8_t *online_pub, const uint8_t *online_seed,
    const uint8_t *noise_static, uint8_t *out, size_t out_cap)
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
        return 0;
    uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (mesh_terminal_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                        &wire_len) != MESH_TERMINAL_PROTO_OK) {
        LOG_ERROR("net.mesh_terminal", "signed receipt failed to encode");
        return 0;
    }
    if (status != MESH_TERMINAL_RECEIPT_OK)
        atomic_fetch_add(&g_term_opens_refused, 1);
    return boot_mesh_terminal_msg(MESH_TERMINAL_MSG_RECEIPT, wire, wire_len, out,
                        out_cap);
}

/* The message processor the receipt needs, or NULL while boot is incomplete. */
static struct msg_processor *terminal_ready_processor(
    const struct boot_svc_ctx *svc)
{
    struct msg_processor *mp = svc ? svc->msg_processor : NULL;
    if (!mp || !mp->params || !mp->net_mgr || !svc->datadir)
        return NULL;
    return mp;
}

/* Spawn the confined worker. Every spawn failure is an honest
 * CONFINEMENT_UNAVAILABLE: the node never answers OK with no cage. */
static enum mesh_terminal_receipt_status terminal_spawn_worker(
    const char *datadir, const struct mesh_terminal_open_v1 *open,
    uint64_t now, char *workdir, size_t workdir_cap,
    struct mesh_terminal_worker *worker, bool *spawned)
{
    if (!terminal_workdir(datadir, open, workdir, workdir_cap)) {
        LOG_ERROR("net.mesh_terminal", "terminal workdir unavailable");
        return MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE;
    }
    struct mesh_terminal_worker_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.shell_path = g_term_shell;
    cfg.workdir = workdir;
    cfg.cols = open->cols;
    cfg.rows = open->rows;
    cfg.max_bytes_in = MESH_TERMINAL_SERVICE_MAX_BYTES_IN;
    cfg.max_bytes_out = boot_mesh_terminal_max_bytes_out();
    cfg.lifetime_seconds = MESH_TERMINAL_SERVICE_LIFETIME_SECONDS;
    cfg.idle_seconds = MESH_TERMINAL_SERVICE_IDLE_SECONDS;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, (int64_t)now, worker);
    if (!r.ok) {
        LOG_ERROR("net.mesh_terminal",
                  "confined spawn refused (%s): %s",
                  mesh_terminal_worker_error_string(
                      (enum mesh_terminal_worker_error)r.code),
                  r.message);
        dir_remove_tree(workdir);
        return MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE;
    }
    *spawned = true;
    return MESH_TERMINAL_RECEIPT_OK;
}

/* The service's answer to an inbound stream OPEN. Every refusal is the
 * node's own signed verdict riding the CLOSE; only an OK reserves a
 * confined worker, and only after the cage exists. */
static enum mesh_stream_refusal terminal_service_open(
    struct mesh_stream *st, const uint8_t *payload, size_t payload_len,
    uint8_t *reply, size_t reply_cap, size_t *reply_len, void *ctx)
{
    (void)ctx;
    *reply_len = 0;
    struct noise_transport_snapshot session;
    boot_mesh_terminal_stream_session(st, &session);
    struct mesh_terminal_open_v1 open;
    if (mesh_terminal_open_v1_decode(&open, payload, payload_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return MESH_STREAM_REFUSED_MALFORMED;
    }
    if (!terminal_open_admit(&open, &session,
                             (uint64_t)platform_time_monotonic_ms()))
        return MESH_STREAM_CLOSED_BY_SERVICE;
    struct boot_svc_ctx *svc = g_term_svc;
    struct msg_processor *mp = terminal_ready_processor(svc);
    if (!mp) {
        LOG_ERROR("net.mesh_terminal", "respond: composition incomplete");
        return MESH_STREAM_REFUSED_UNAVAILABLE;
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
        return MESH_STREAM_REFUSED_UNAVAILABLE; /* no honest receipt exists */

    /* Post-decide bounded-resource verdict, still answered by name. */
    if (status == MESH_TERMINAL_RECEIPT_OK &&
        g_term_live >= MESH_TERMINAL_SESSIONS_MAX)
        status = MESH_TERMINAL_RECEIPT_CONCURRENCY_LIMIT;

    char workdir[600];
    struct mesh_terminal_worker worker;
    memset(&worker, 0, sizeof(worker));
    bool spawned = false;
    if (status == MESH_TERMINAL_RECEIPT_OK)
        status = terminal_spawn_worker(svc->datadir, &open, now, workdir,
                                       sizeof(workdir), &worker, &spawned);

    struct mesh_terminal_session *s = NULL;
    if (status == MESH_TERMINAL_RECEIPT_OK) {
        s = zcl_calloc(1, sizeof(*s), "mesh_terminal_session");
        if (!s) {
            mesh_terminal_worker_kill(&worker);
            dir_remove_tree(workdir);
            spawned = false;
            status = MESH_TERMINAL_RECEIPT_INTERNAL;
        }
    }

    *reply_len = terminal_compose_reply(
        &open, &session, status, revocation_generation, now, genesis, master,
        online_pub, online_seed, mp->net_mgr->identity_pub, reply, reply_cap);
    memory_cleanse(online_seed, 32);
    if (status != MESH_TERMINAL_RECEIPT_OK) {
        if (spawned) {
            mesh_terminal_worker_kill(&worker);
            dir_remove_tree(workdir);
        }
        return MESH_STREAM_CLOSED_BY_SERVICE;
    }

    s->open = open;
    s->worker = worker;
    memcpy(s->workdir, workdir, sizeof(workdir));
    st->service_state = s;
    g_term_live++;
    terminal_log_opened(&open, st->id);
    return MESH_STREAM_OK;
}

/* ── DATA ingress ────────────────────────────────────────────────────── */

/* Responder-side keyboard bytes. The stream already proved the frame came
 * over the session this terminal was opened on and inside the credit this
 * node granted; the strictly increasing per-terminal sequence stays as
 * the lane's own replay guard, because a decoded frame can be replayed in
 * a new Noise record. */
static void terminal_receive_data(struct mesh_stream *st,
                                  struct mesh_terminal_session *s,
                                  const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_data_v1 data;
    if (mesh_terminal_data_v1_decode(&data, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return;
    }
    if (memcmp(data.terminal_id, s->open.terminal_id, 32) != 0 ||
        data.seq <= s->seq_in) {
        atomic_fetch_add(&g_term_data_dropped, 1);
        return;
    }
    struct zcl_result r = mesh_terminal_worker_input(
        &s->worker, data.payload, data.payload_len,
        (int64_t)platform_time_wall_time_t());
    if (r.ok)
        s->seq_in = data.seq;
    else if (r.code == MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT)
        LOG_WARN("net.mesh_terminal",
                 "keyboard budget overrun ended a terminal session");
    /* Other failures (NOT_RUNNING, IO) are handled by the drain's
     * enforcement pass; the frame is dropped by not advancing seq_in. */
    (void)st;
}

static void terminal_receive_resize(struct mesh_terminal_session *s,
                                    const uint8_t *wire, size_t wire_len)
{
    struct mesh_terminal_resize_v1 resize;
    if (mesh_terminal_resize_v1_decode(&resize, wire, wire_len) !=
        MESH_TERMINAL_PROTO_OK) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return;
    }
    if (memcmp(resize.terminal_id, s->open.terminal_id, 32) != 0 ||
        !mesh_terminal_worker_resize(&s->worker, resize.cols, resize.rows).ok)
        atomic_fetch_add(&g_term_data_dropped, 1);
}

static void terminal_service_data(struct mesh_stream *st,
                                  const uint8_t *payload, size_t payload_len,
                                  void *ctx)
{
    (void)ctx;
    if (st->local_initiator) {
        /* The requester grants for itself: what it keeps in its screen
         * FIFO stays spent until a reader drains it. */
        boot_mesh_terminal_client_message(st, payload, payload_len);
        return;
    }
    /* The responder queues nothing: every keyboard byte is handed to the
     * confined worker or dropped here, so the credit goes straight back
     * and the requester's window is only ever spent by bytes in flight. */
    (void)mesh_stream_grant(st, (uint32_t)payload_len);
    struct mesh_terminal_session *s = st->service_state;
    if (!s || payload_len < 1u) {
        atomic_fetch_add(&g_term_dropped_malformed, 1);
        return;
    }
    const uint8_t *wire = payload + 1;
    size_t wire_len = payload_len - 1u;
    switch (payload[0]) {
    case MESH_TERMINAL_MSG_DATA:
        terminal_receive_data(st, s, wire, wire_len);
        return;
    case MESH_TERMINAL_MSG_RESIZE:
        terminal_receive_resize(s, wire, wire_len);
        return;
    case MESH_TERMINAL_MSG_CLOSE: {
        struct mesh_terminal_close_v1 close_frame;
        if (mesh_terminal_close_v1_decode(&close_frame, wire, wire_len) !=
                MESH_TERMINAL_PROTO_OK ||
            memcmp(close_frame.terminal_id, s->open.terminal_id, 32) != 0) {
            atomic_fetch_add(&g_term_dropped_malformed, 1);
            return;
        }
        /* The requester asked to close: name it so the evidence receipt
         * and the kill keep the worker's default REQUESTED reason. */
        s->worker.close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
        terminal_end_session(st, s, (uint64_t)platform_time_wall_time_t());
        return;
    }
    default:
        atomic_fetch_add(&g_term_dropped_unknown_kind, 1);
        return;
    }
}

/* ── The stream drain ────────────────────────────────────────────────── */

/* One live responder session, once per stream tick. Authority first, then
 * budget, then bounded screen output into stream DATA — and the credit
 * window stops the drain dead when the requester has not read what it
 * already has. */
static void terminal_service_tick(struct mesh_stream *st, int64_t now,
                                  void *ctx)
{
    (void)ctx;
    if (st->local_initiator) {
        boot_mesh_terminal_client_tick(st, (uint64_t)now);
        return;
    }
    struct mesh_terminal_session *s = st->service_state;
    if (!s)
        return;
    /* Authority before budget: a pairing that no longer grants
     * terminal-exec ends the session with its named reason and evidence,
     * whatever the budget says. */
    enum mesh_terminal_close_reason authority_reason =
        MESH_TERMINAL_CLOSE_REQUESTED;
    if (boot_mesh_terminal_pairing_lost(app_runtime_node_db(), &s->open,
                                        (uint64_t)now, &authority_reason)) {
        s->worker.close_reason = authority_reason;
        terminal_end_session(st, s, (uint64_t)now);
        return;
    }
    if (mesh_terminal_worker_budget_exceeded(&s->worker, now)) {
        terminal_end_session(st, s, (uint64_t)now);
        return;
    }
    for (int chunk = 0; chunk < MESH_TERMINAL_PUMP_CHUNKS_PER_TICK; chunk++) {
        if (st->send_credit < 1u + MESH_TERMINAL_DATA_V1_HEADER_BYTES)
            break; /* credit exhausted: the requester must read first */
        uint8_t buf[MESH_TERMINAL_WORKER_IO_CHUNK];
        size_t n = 0;
        struct zcl_result r =
            mesh_terminal_worker_output(&s->worker, buf, sizeof(buf), &n, now);
        if (!r.ok || n == 0)
            break;
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
                MESH_TERMINAL_PROTO_OK) {
                uint8_t msg[MESH_TERMINAL_MSG_MAX];
                size_t msg_len = boot_mesh_terminal_msg(MESH_TERMINAL_MSG_DATA, wire,
                                              wire_len, msg, sizeof(msg));
                if (!msg_len || !mesh_stream_send(st, msg, msg_len))
                    return; /* no credit or no peer: try again next tick */
            }
            off += take;
        }
    }
}

/* ── Ending ──────────────────────────────────────────────────────────── */

static void terminal_service_close(struct mesh_stream *st,
                                   enum mesh_stream_refusal reason,
                                   const uint8_t *payload, size_t payload_len,
                                   void *ctx)
{
    (void)ctx;
    if (st->local_initiator) {
        /* The requester keeps its verdict readable until the slot's
         * linger runs out; the release below is the requester's own. */
        boot_mesh_terminal_client_ended(st, reason, payload, payload_len);
        return;
    }
    /* The responder keeps nothing a caller could read after the end, so
     * the slot goes back now instead of lingering. */
    mesh_stream_release(st);
}

static void terminal_service_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    if (st->local_initiator) {
        boot_mesh_terminal_client_release(st);
        return;
    }
    struct mesh_terminal_session *s = st->service_state;
    st->service_state = NULL;
    if (!s)
        return;
    atomic_fetch_add(&g_term_sessions_ended, 1);
    mesh_terminal_worker_kill(&s->worker);
    char peer[9];
    terminal_peer_prefix(&s->open, peer);
    int64_t ended = (int64_t)platform_time_wall_time_t();
    LOG_INFO("net.mesh_terminal",
             "terminal closed (%s): peer %s, reason %s, bytes in %llu, "
             "bytes out %llu, duration %llus",
             terminal_state_name(), peer,
             mesh_terminal_close_reason_string(s->worker.close_reason),
             (unsigned long long)s->worker.bytes_in,
             (unsigned long long)s->worker.bytes_out,
             (unsigned long long)(ended > s->worker.started_unix
                                      ? ended - s->worker.started_unix
                                      : 0));
    dir_remove_tree(s->workdir);
    memory_cleanse(s, sizeof(*s));
    free(s);
    if (g_term_live)
        g_term_live--;
}

/* ── Lifecycle ───────────────────────────────────────────────────────── */

/* One registration serves both halves: the primitive tells them apart by
 * which side opened the stream. The capability named here is what the
 * primitive demands of the peer's pairing row before an OPEN ever reaches
 * this lane; the lane's own decision then re-verifies the delegation
 * binding, the genesis and the live session on top of it. */
bool boot_mesh_terminal_register_service(void)
{
    struct mesh_stream_service service;
    memset(&service, 0, sizeof(service));
    service.name = MESH_TERMINAL_SERVICE_NAME;
    service.required_pairing_capability = MESH_PAIRING_CAP_TERMINAL_EXEC;
    service.on_open = terminal_service_open;
    service.on_data = terminal_service_data;
    service.on_close = terminal_service_close;
    service.on_tick = terminal_service_tick;
    service.on_release = terminal_service_release;
    return mesh_stream_service_register(&service);
}

bool boot_mesh_terminal_configure(enum mesh_terminal_platform platform,
                                const char *shell, bool accept_unconfined,
                                char *out, size_t out_cap, bool *unconfined,
                                const char **why)
{
    const char *refusal =
        mesh_terminal_confinement_refusal(platform, accept_unconfined);
    *unconfined = false;
    *why = NULL;
    if (out_cap)
        out[0] = '\0';
    if (accept_unconfined && refusal) {
        *why = refusal;
    } else if (!shell || !shell[0]) {
        return false;
    } else if (!mesh_terminal_shell_path_valid(platform, shell)) {
        *why = "shell-path-invalid";
    } else if (refusal) {
        *why = refusal;
    } else if (snprintf(out, out_cap, "%s", shell) >= (int)out_cap) {
        out[0] = '\0';
        *why = "shell-path-too-long";
    } else {
        *unconfined = accept_unconfined;
        return true;
    }
    return false;
}

/* Reads -terminalmaxbytesout, -terminalshell and -terminalacceptunconfined. The shell is set only
 * when its path is valid and the platform gate admits the lane; every other
 * state leaves it empty, so the lane answers CONFINEMENT_UNAVAILABLE. */
static void terminal_configure_shell(void)
{
    const char *why = NULL;
    int64_t out_arg = GetArgInt("-terminalmaxbytesout", 0);
    g_term_max_out = boot_mesh_terminal_resolve_max_bytes_out(out_arg);
    if (out_arg != 0 && g_term_max_out != (uint64_t)out_arg)
        LOG_WARN("net.mesh_terminal",
                 "-terminalmaxbytesout out of range; using the default %llu",
                 (unsigned long long)g_term_max_out);
    bool configured = boot_mesh_terminal_configure(
        MESH_TERMINAL_PLATFORM_NATIVE, GetArg("-terminalshell", ""),
        GetBoolArg("-terminalacceptunconfined", false), g_term_shell,
        sizeof(g_term_shell), &g_term_unconfined, &why);
    if (why)
        LOG_ERROR("net.mesh_terminal",
                  "terminal lane off: %s; it answers "
                  "CONFINEMENT_UNAVAILABLE", why);
    else if (configured && g_term_unconfined)
        LOG_WARN("net.mesh_terminal",
                 "terminal_confinement: %s; the remote shell runs as "
                 "this Windows user with all of its rights; only peers "
                 "paired with the terminal capability can open it",
                 MESH_TERMINAL_CONFINEMENT_UNCONFINED);
}

void boot_mesh_terminal_wire(struct boot_svc_ctx *svc)
{
    if (g_term_svc) {
        LOG_ERROR("net.mesh_terminal", "wire: already wired");
        return;
    }
    g_term_svc = svc;
    memset(g_seen_opens, 0, sizeof(g_seen_opens));
    g_term_live = 0;
    g_term_shell[0] = '\0';
    terminal_configure_shell();

    /* The requester lane arms and disarms with the responder's lifecycle:
     * one wire, one shutdown, always together. */
    boot_mesh_terminal_client_wire(svc);

    if (!boot_mesh_terminal_register_service())
        LOG_ERROR("net.mesh_terminal", "terminal stream service refused");
}

void boot_mesh_terminal_shutdown(void)
{
    /* Unregistering ends every live terminal stream, and each on_close
     * kills its worker (census-verified) and removes its workdir. */
    mesh_stream_service_unregister(MESH_TERMINAL_SERVICE_NAME);
    g_term_svc = NULL;
    memset(g_seen_opens, 0, sizeof(g_seen_opens));
    g_term_live = 0;
    boot_mesh_terminal_client_shutdown();
}
