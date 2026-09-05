/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The multiplexed stream primitive on zpkgswm ("ZSTRM"): frame
 * codec, the one stream table both sides share, credit accounting, the
 * service registry, and the single supervised drain (see the header). */

// one-result-type-ok:closed-security-verdict — every entry point returns a
// bounded named verdict the caller must branch on; no diagnostic text
// crosses the wire. Drop/refusal logging happens at the frame edge.

#include "config/mesh_stream.h"
#include "boot_mesh_status_internal.h"

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "base/serialize_le.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

/* Frame header bounds. OPEN is the widest: id, credit, name length, the
 * name itself, and the payload length. */
#define STREAM_HDR_MAX                                              \
    (MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u + 4u + 1u +             \
     MESH_STREAM_SERVICE_NAME_MAX + 2u)

static zcl_mutex_t g_stream_lock;
static _Atomic int g_stream_lock_state;
static struct boot_svc_ctx *g_stream_svc; /* borrowed; set by wire() */
static supervisor_child_id g_stream_child = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_stream_contract;

static struct mesh_stream_service g_services[MESH_STREAM_SERVICES_MAX];
static char g_service_names[MESH_STREAM_SERVICES_MAX]
                           [MESH_STREAM_SERVICE_NAME_MAX + 1];
static bool g_service_used[MESH_STREAM_SERVICES_MAX];

static struct mesh_stream g_streams[MESH_STREAM_TABLE_MAX];

/* Per-peer OPEN cadence. An authenticated peer may not make this node run
 * a service's admission work — pairing reads, spawns — faster than this. */
struct mesh_stream_open_rate {
    bool used;
    uint8_t peer_static[32];
    int64_t window_unix;
    uint32_t opens;
};
static struct mesh_stream_open_rate g_open_rate[MESH_STREAM_PER_PEER_MAX];

/* Quiet-drop counters: in-namespace garbage and unauthenticated probes are
 * local policy events, never offences against the peer. */
static _Atomic uint64_t g_dropped_unauthenticated;
static _Atomic uint64_t g_dropped_malformed;
static _Atomic uint64_t g_dropped_unknown_kind;
static _Atomic uint64_t g_opens_refused;
static _Atomic uint64_t g_streams_opened;
static _Atomic uint64_t g_streams_ended;
static _Atomic uint64_t g_credit_violations;

static void stream_lock(void)
{
    if (atomic_load_explicit(&g_stream_lock_state, memory_order_acquire) !=
        2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_stream_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_stream_lock);
            atomic_store_explicit(&g_stream_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_stream_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_stream_lock);
}

const char *mesh_stream_refusal_string(enum mesh_stream_refusal reason)
{
    switch (reason) {
    case MESH_STREAM_OK: return "stream_ok";
    case MESH_STREAM_REFUSED_LINK_NOT_NOISE: return "stream_link_not_noise";
    case MESH_STREAM_REFUSED_PEER_UNPAIRED: return "stream_peer_unpaired";
    case MESH_STREAM_REFUSED_SERVICE_UNKNOWN: return "stream_service_unknown";
    case MESH_STREAM_REFUSED_CAP: return "stream_cap";
    case MESH_STREAM_REFUSED_CREDIT_EXCEEDED: return "stream_credit_exceeded";
    case MESH_STREAM_REFUSED_MALFORMED: return "stream_malformed";
    case MESH_STREAM_REFUSED_ID_PARITY: return "stream_id_parity";
    case MESH_STREAM_REFUSED_ID_IN_USE: return "stream_id_in_use";
    case MESH_STREAM_REFUSED_RATE: return "stream_open_rate";
    case MESH_STREAM_REFUSED_UNAVAILABLE: return "stream_unavailable";
    case MESH_STREAM_REFUSED_PEER_NOT_CONNECTED:
        return "stream_peer_not_connected";
    case MESH_STREAM_ENDED_IDLE: return "stream_idle_timeout";
    case MESH_STREAM_ENDED_SESSION_LOST: return "stream_session_lost";
    case MESH_STREAM_ENDED_SHUTDOWN: return "stream_shutdown";
    case MESH_STREAM_CLOSED_BY_SERVICE: return "stream_closed_by_service";
    }
    return "stream_malformed";
}

/* ── Service registry (locked) ───────────────────────────────────────── */

static int stream_service_index_locked(const char *name, size_t name_len)
{
    if (!name || name_len == 0 || name_len > MESH_STREAM_SERVICE_NAME_MAX)
        return -1;
    for (size_t i = 0; i < MESH_STREAM_SERVICES_MAX; i++) {
        if (!g_service_used[i])
            continue;
        if (strlen(g_service_names[i]) == name_len &&
            memcmp(g_service_names[i], name, name_len) == 0)
            return (int)i;
    }
    return -1;
}

bool mesh_stream_service_register(const struct mesh_stream_service *service)
{
    if (!service || !service->name)
        LOG_FAIL("net.mesh_stream", "register: no service");
    size_t name_len = strlen(service->name);
    if (name_len == 0 || name_len > MESH_STREAM_SERVICE_NAME_MAX)
        LOG_FAIL("net.mesh_stream", "register: name length %zu out of bounds",
                 name_len);
    for (size_t i = 0; i < name_len; i++) {
        char c = service->name[i];
        bool printable = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                         c == '_' || c == '.';
        if (!printable)
            LOG_FAIL("net.mesh_stream",
                     "register: service name must be lowercase, digits, "
                     "'_' or '.'");
    }
    stream_lock();
    if (stream_service_index_locked(service->name, name_len) >= 0) {
        zcl_mutex_unlock(&g_stream_lock);
        LOG_FAIL("net.mesh_stream", "register: service already registered");
    }
    size_t slot = MESH_STREAM_SERVICES_MAX;
    for (size_t i = 0; i < MESH_STREAM_SERVICES_MAX && slot == MESH_STREAM_SERVICES_MAX;
         i++)
        if (!g_service_used[i])
            slot = i;
    if (slot == MESH_STREAM_SERVICES_MAX) {
        zcl_mutex_unlock(&g_stream_lock);
        LOG_FAIL("net.mesh_stream", "register: service registry full");
    }
    g_services[slot] = *service;
    memcpy(g_service_names[slot], service->name, name_len);
    g_service_names[slot][name_len] = '\0';
    g_services[slot].name = g_service_names[slot];
    g_service_used[slot] = true;
    zcl_mutex_unlock(&g_stream_lock);
    return true;
}

/* Forward declaration: unregistering a service ends its live streams. */
static void stream_close_locked(struct mesh_stream *st,
                                enum mesh_stream_refusal reason,
                                const uint8_t *payload, size_t payload_len);

void mesh_stream_service_unregister(const char *name)
{
    if (!name)
        return;
    stream_lock();
    int index = stream_service_index_locked(name, strlen(name));
    if (index >= 0) {
        for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++) {
            if (!g_streams[i].used || g_streams[i].service != (uint16_t)index)
                continue;
            stream_close_locked(&g_streams[i], MESH_STREAM_ENDED_SHUTDOWN,
                                NULL, 0);
            /* The service is going away: nothing is left to read its
             * verdict, so no slot lingers. */
            mesh_stream_release(&g_streams[i]);
        }
        memset(&g_services[index], 0, sizeof(g_services[index]));
        memset(g_service_names[index], 0, sizeof(g_service_names[index]));
        g_service_used[index] = false;
    }
    zcl_mutex_unlock(&g_stream_lock);
}

/* ── Table helpers (locked) ──────────────────────────────────────────── */

/* A stream's frames are only honoured on the SAME established Noise
 * session the stream was opened on: a frame arriving over a newer or
 * different connection is not this stream's frame. */
static bool stream_binds_session(const struct mesh_stream *st,
                                 const struct noise_transport_snapshot *snap)
{
    return snap && snap->established &&
           memcmp(snap->transcript_hash, st->transcript_hash, 32) == 0 &&
           snap->connection_generation == st->connection_generation &&
           memcmp(snap->remote_static, st->peer_static, 32) == 0;
}

/* Live streams only: a half-closed slot still holds its id so a verdict
 * can be read, but it is no longer a channel any frame reaches. */
static struct mesh_stream *stream_find_locked(
    uint64_t id, const struct noise_transport_snapshot *snap)
{
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++) {
        if (g_streams[i].used && !g_streams[i].ended &&
            g_streams[i].id == id &&
            stream_binds_session(&g_streams[i], snap))
            return &g_streams[i];
    }
    return NULL;
}

static struct mesh_stream *stream_free_slot_locked(void)
{
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
        if (!g_streams[i].used)
            return &g_streams[i];
    return NULL;
}

/* Streams that still carry frames. A half-closed slot is a verdict, not a
 * channel, so it never keeps a peer from opening a new stream. */
static size_t stream_peer_count_locked(const uint8_t peer_static[32])
{
    size_t n = 0;
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
        if (g_streams[i].used && !g_streams[i].ended &&
            memcmp(g_streams[i].peer_static, peer_static, 32) == 0)
            n++;
    return n;
}

/* Bounded per-peer OPEN cadence, evaluated before any service admission
 * work. A peer with no slot left evicts the oldest expired window. */
static bool stream_open_admit_locked(const uint8_t peer_static[32],
                                     int64_t now_unix)
{
    struct mesh_stream_open_rate *slot = NULL;
    for (size_t i = 0; i < MESH_STREAM_PER_PEER_MAX; i++) {
        struct mesh_stream_open_rate *r = &g_open_rate[i];
        if (r->used && memcmp(r->peer_static, peer_static, 32) == 0) {
            if (now_unix != r->window_unix) {
                r->window_unix = now_unix;
                r->opens = 0;
            }
            if (r->opens >= MESH_STREAM_OPEN_RATE_PER_SECOND)
                return false;
            r->opens++;
            return true;
        }
        if (!r->used && !slot)
            slot = r;
        else if (r->used && r->window_unix != now_unix && !slot)
            slot = r;
    }
    if (!slot)
        return false;
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->peer_static, peer_static, 32);
    slot->window_unix = now_unix;
    slot->opens = 1;
    return true;
}

/* Initiator parity. The peer that dialed the connection mints even ids,
 * the peer that accepted it mints odd ids, so two sides opening a stream
 * at the same instant can never mint the same id. `node->inbound` is true
 * exactly when the peer dialed us. */
static uint64_t stream_local_parity(const struct p2p_node *node)
{
    return node->inbound ? 1u : 0u;
}

/* The peer's live pairing row for this Noise static, when one grants the
 * capability the service asked for. The scan is bounded by the pairing
 * list ceiling; an unreadable list fails closed. */
static bool stream_peer_pairing_allows(uint64_t capability, int64_t now_unix,
                                       const uint8_t peer_static[32])
{
    if (capability == 0)
        return true; /* the service owns its own, stronger decision */
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb)
        return false;
    struct db_mesh_pairing rows[64];
    int count = db_mesh_pairing_list(ndb, rows, sizeof(rows) / sizeof(rows[0]));
    if (count <= 0)
        return false;
    for (int i = 0; i < count; i++) {
        if (memcmp(rows[i].peer_noise_pubkey, peer_static, 32) != 0)
            continue;
        if (mesh_pairing_allows(&rows[i], capability, now_unix))
            return true;
    }
    return false;
}

/* ── Frame send ──────────────────────────────────────────────────────── */

/* Write one ZSTRM frame: a small header from the stack and the service
 * payload straight from the caller's buffer, so no frame-sized copy ever
 * exists and one DATA payload may run to the frame ceiling. */
static bool stream_write_frame(struct msg_processor *mp, struct p2p_node *node,
                               const uint8_t *header, size_t header_len,
                               const uint8_t *payload, size_t payload_len)
{
    if (!mp || !mp->params || !node)
        LOG_FAIL("net.mesh_stream", "send: composition incomplete");
    if (header_len + payload_len > MESH_STREAM_FRAME_MAX)
        LOG_FAIL("net.mesh_stream", "send: %zu bytes exceeds the frame bound",
                 header_len + payload_len);
    if (!p2p_node_begin_message(node, "zpkgswm", mp->params->pchMessageStart))
        LOG_FAIL("net.mesh_stream", "begin_message failed for peer %lld",
                 (long long)node->id);
    p2p_node_write_message_data(node, header, header_len);
    if (payload_len)
        p2p_node_write_message_data(node, payload, payload_len);
    if (!p2p_node_end_message(node))
        LOG_FAIL("net.mesh_stream", "end_message failed for peer %lld",
                 (long long)node->id);
    return true;
}

static size_t stream_put_prefix(uint8_t *out, uint8_t kind, uint64_t id)
{
    memcpy(out, MESH_STREAM_FRAME_PREFIX, MESH_STREAM_FRAME_PREFIX_LEN);
    out[MESH_STREAM_FRAME_PREFIX_LEN] = kind;
    zcl_write_u64_le(out + MESH_STREAM_FRAME_PREFIX_LEN + 1u, id);
    return MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
}

static bool stream_send_open(struct msg_processor *mp, struct p2p_node *node,
                             uint64_t id, const char *name,
                             uint32_t initial_window, const uint8_t *payload,
                             size_t payload_len)
{
    uint8_t header[STREAM_HDR_MAX];
    size_t n = stream_put_prefix(header, MESH_STREAM_KIND_OPEN, id);
    zcl_write_u32_le(header + n, initial_window);
    n += 4u;
    size_t name_len = strlen(name);
    header[n++] = (uint8_t)name_len;
    memcpy(header + n, name, name_len);
    n += name_len;
    zcl_write_u16_le(header + n, (uint16_t)payload_len);
    n += 2u;
    return stream_write_frame(mp, node, header, n, payload, payload_len);
}

static bool stream_send_data(struct msg_processor *mp, struct p2p_node *node,
                             uint64_t id, const uint8_t *payload,
                             size_t payload_len)
{
    uint8_t header[STREAM_HDR_MAX];
    size_t n = stream_put_prefix(header, MESH_STREAM_KIND_DATA, id);
    zcl_write_u16_le(header + n, (uint16_t)payload_len);
    n += 2u;
    return stream_write_frame(mp, node, header, n, payload, payload_len);
}

static bool stream_send_window(struct msg_processor *mp, struct p2p_node *node,
                               uint64_t id, uint32_t credit)
{
    uint8_t header[STREAM_HDR_MAX];
    size_t n = stream_put_prefix(header, MESH_STREAM_KIND_WINDOW, id);
    zcl_write_u32_le(header + n, credit);
    n += 4u;
    return stream_write_frame(mp, node, header, n, NULL, 0);
}

static bool stream_send_close(struct msg_processor *mp, struct p2p_node *node,
                              uint64_t id, enum mesh_stream_refusal reason,
                              const uint8_t *payload, size_t payload_len)
{
    uint8_t header[STREAM_HDR_MAX];
    size_t n = stream_put_prefix(header, MESH_STREAM_KIND_CLOSE, id);
    header[n++] = (uint8_t)reason;
    zcl_write_u16_le(header + n, (uint16_t)payload_len);
    n += 2u;
    return stream_write_frame(mp, node, header, n, payload, payload_len);
}

/* The live bound peer for a stream, under the lane lock. Returns a
 * referenced node or NULL; the caller releases. */
static struct p2p_node *stream_bound_peer_locked(
    const struct mesh_stream *st, struct noise_transport_snapshot *snap_out)
{
    struct boot_svc_ctx *svc = g_stream_svc;
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr)
        return NULL;
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    struct p2p_node *peer = boot_mesh_find_session_peer(
        svc->msg_processor->net_mgr, st->peer_static, &snap);
    if (!peer)
        return NULL;
    if (!stream_binds_session(st, &snap)) {
        p2p_node_release(peer);
        return NULL;
    }
    if (snap_out)
        *snap_out = snap;
    return peer;
}

/* ── Stream verbs (lane lock held by the caller) ─────────────────────── */

bool mesh_stream_send(struct mesh_stream *st, const uint8_t *payload,
                      size_t payload_len)
{
    if (!st || !st->used || st->ended || (!payload && payload_len))
        return false;
    if (payload_len == 0 || payload_len > MESH_STREAM_PAYLOAD_MAX)
        LOG_FAIL("net.mesh_stream", "send: payload %zu out of bounds",
                 payload_len);
    if (payload_len > (size_t)st->send_credit) {
        atomic_fetch_add(&g_credit_violations, 1);
        LOG_FAIL("net.mesh_stream", "send: %s (%zu bytes, %u credit)",
                 mesh_stream_refusal_string(MESH_STREAM_REFUSED_CREDIT_EXCEEDED),
                 payload_len, st->send_credit);
    }
    struct boot_svc_ctx *svc = g_stream_svc;
    struct p2p_node *peer = stream_bound_peer_locked(st, NULL);
    if (!peer)
        return false;
    bool ok = stream_send_data(svc->msg_processor, peer, st->id, payload,
                               payload_len);
    p2p_node_release(peer);
    if (!ok)
        return false;
    st->send_credit -= (uint32_t)payload_len;
    st->bytes_sent += payload_len;
    st->last_activity_unix = (int64_t)platform_time_wall_time_t();
    return true;
}

bool mesh_stream_grant(struct mesh_stream *st, uint32_t credit)
{
    if (!st || !st->used || st->ended || credit == 0)
        return false;
    if (credit > MESH_STREAM_INITIAL_WINDOW ||
        st->recv_credit > MESH_STREAM_INITIAL_WINDOW - credit)
        LOG_FAIL("net.mesh_stream", "grant: %s (%u + %u over the ceiling)",
                 mesh_stream_refusal_string(MESH_STREAM_REFUSED_CREDIT_EXCEEDED),
                 st->recv_credit, credit);
    /* Room made is room made: the receiver records what it will accept
     * before it tries to say so. A WINDOW frame that never reaches the
     * peer only means the peer sends less than it could — never that this
     * node accepts more than it has room for. */
    st->recv_credit += credit;
    struct boot_svc_ctx *svc = g_stream_svc;
    struct p2p_node *peer = stream_bound_peer_locked(st, NULL);
    if (!peer)
        return false;
    bool ok = stream_send_window(svc->msg_processor, peer, st->id, credit);
    p2p_node_release(peer);
    return ok;
}

/* End one stream: the service's on_close first (so it can release or keep
 * its own state), then the CLOSE frame when the peer is still there. The
 * slot becomes half-closed, not free — the verdict outlives the channel
 * until mesh_stream_release or the linger mark. Never re-entrant:
 * `ended` is set before on_close runs. */
static void stream_close_locked(struct mesh_stream *st,
                                enum mesh_stream_refusal reason,
                                const uint8_t *payload, size_t payload_len)
{
    if (!st || !st->used || st->ended)
        return;
    st->ended = true;
    st->end_reason = reason;
    st->send_credit = 0;
    st->recv_credit = 0;
    st->last_activity_unix = (int64_t)platform_time_wall_time_t();
    atomic_fetch_add(&g_streams_ended, 1);
    struct boot_svc_ctx *svc = g_stream_svc;
    if (svc && svc->msg_processor) {
        struct p2p_node *peer = stream_bound_peer_locked(st, NULL);
        if (peer) {
            (void)stream_send_close(svc->msg_processor, peer, st->id, reason,
                                    payload, payload_len);
            p2p_node_release(peer);
        }
    }
    const struct mesh_stream_service *service =
        g_service_used[st->service] ? &g_services[st->service] : NULL;
    if (service && service->on_close)
        service->on_close(st, reason, payload, payload_len, service->ctx);
}

void mesh_stream_close(struct mesh_stream *st, enum mesh_stream_refusal reason,
                       const uint8_t *payload, size_t payload_len)
{
    stream_close_locked(st, reason, payload, payload_len);
}

void mesh_stream_release(struct mesh_stream *st)
{
    if (!st || !st->used)
        return;
    st->used = false; /* re-entry guard: on_release can never recurse here */
    const struct mesh_stream_service *service =
        g_service_used[st->service] ? &g_services[st->service] : NULL;
    if (service && service->on_release)
        service->on_release(st, service->ctx);
    memset(st, 0, sizeof(*st));
}

/* ── Initiator ───────────────────────────────────────────────────────── */

enum mesh_stream_refusal mesh_stream_open(
    const char *service_name, const uint8_t peer_noise_static[32],
    uint32_t initial_window, const uint8_t *payload, size_t payload_len,
    void *service_state, uint64_t *stream_id_out)
{
    if (!service_name || !peer_noise_static || (!payload && payload_len))
        return MESH_STREAM_REFUSED_MALFORMED;
    if (payload_len > MESH_STREAM_PAYLOAD_MAX)
        return MESH_STREAM_REFUSED_MALFORMED;
    if (initial_window == 0)
        initial_window = MESH_STREAM_INITIAL_WINDOW;
    if (initial_window > MESH_STREAM_INITIAL_WINDOW)
        return MESH_STREAM_REFUSED_CREDIT_EXCEEDED;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0)
        return MESH_STREAM_REFUSED_UNAVAILABLE;

    stream_lock();
    struct boot_svc_ctx *svc = g_stream_svc;
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr) {
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    int index = stream_service_index_locked(service_name,
                                            strlen(service_name));
    if (index < 0) {
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_SERVICE_UNKNOWN;
    }
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    struct p2p_node *peer = boot_mesh_find_session_peer(
        svc->msg_processor->net_mgr, peer_noise_static, &snap);
    if (!peer) {
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_PEER_NOT_CONNECTED;
    }
    if (!snap.established) {
        p2p_node_release(peer);
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_LINK_NOT_NOISE;
    }
    if (stream_peer_count_locked(snap.remote_static) >=
        MESH_STREAM_PER_PEER_MAX) {
        p2p_node_release(peer);
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_CAP;
    }
    struct mesh_stream *slot = stream_free_slot_locked();
    if (!slot) {
        p2p_node_release(peer);
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_CAP;
    }

    /* The lowest free id of our own parity on this peer. The per-peer cap
     * bounds the search; a table that cannot answer refuses by name
     * rather than reuse a live id. */
    uint64_t id = 0;
    bool have_id = false;
    uint64_t parity = stream_local_parity(peer);
    for (size_t step = 0; step <= MESH_STREAM_PER_PEER_MAX && !have_id;
         step++) {
        uint64_t candidate = parity + 2u * (uint64_t)step;
        bool taken = false;
        for (size_t i = 0; i < MESH_STREAM_TABLE_MAX && !taken; i++)
            taken = g_streams[i].used && g_streams[i].id == candidate &&
                    memcmp(g_streams[i].peer_static, snap.remote_static,
                           32) == 0;
        if (!taken) {
            id = candidate;
            have_id = true;
        }
    }
    if (!have_id) {
        p2p_node_release(peer);
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_ID_IN_USE;
    }

    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->local_initiator = true;
    slot->id = id;
    slot->service = (uint16_t)index;
    memcpy(slot->peer_static, snap.remote_static, 32);
    memcpy(slot->transcript_hash, snap.transcript_hash, 32);
    slot->connection_generation = snap.connection_generation;
    slot->send_credit = initial_window;
    slot->recv_credit = initial_window;
    slot->opened_unix = now;
    slot->last_activity_unix = now;
    slot->service_state = service_state;

    bool sent = stream_send_open(svc->msg_processor, peer, id,
                                 g_service_names[index], initial_window,
                                 payload, payload_len);
    p2p_node_release(peer);
    if (!sent) {
        memset(slot, 0, sizeof(*slot));
        zcl_mutex_unlock(&g_stream_lock);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    atomic_fetch_add(&g_streams_opened, 1);
    if (stream_id_out)
        *stream_id_out = id;
    zcl_mutex_unlock(&g_stream_lock);
    return MESH_STREAM_OK;
}

void mesh_stream_visit(const char *service_name, mesh_stream_visitor visit,
                       void *ctx)
{
    if (!service_name || !visit)
        return;
    stream_lock();
    int index = stream_service_index_locked(service_name,
                                            strlen(service_name));
    if (index >= 0) {
        for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++) {
            if (!g_streams[i].used ||
                g_streams[i].service != (uint16_t)index)
                continue;
            if (!visit(&g_streams[i], ctx))
                break;
        }
    }
    zcl_mutex_unlock(&g_stream_lock);
}

/* ── Frame ingress ───────────────────────────────────────────────────── */

/* An inbound OPEN: parity, cadence, cap, service, pairing, then the
 * service's own decision. Every refusal is answered by name with a CLOSE
 * carrying whatever evidence the service composed — a refused stream is
 * never reserved. */
static void stream_receive_open(struct msg_processor *mp,
                                struct p2p_node *node,
                                const struct noise_transport_snapshot *snap,
                                uint64_t id, const uint8_t *body,
                                size_t body_len)
{
    if (!mp || body_len < 4u + 1u) {
        /* No composition context means no honest answer exists; a refusal
         * we cannot send is not a refusal. */
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    uint32_t initial_window = zcl_read_u32_le(body);
    size_t name_len = body[4];
    if (name_len == 0 || name_len > MESH_STREAM_SERVICE_NAME_MAX ||
        body_len < 4u + 1u + name_len + 2u) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    const char *name = (const char *)(body + 5);
    size_t payload_len = zcl_read_u16_le(body + 5 + name_len);
    const uint8_t *payload = body + 5 + name_len + 2;
    if (body_len != 4u + 1u + name_len + 2u + payload_len ||
        payload_len > MESH_STREAM_PAYLOAD_MAX) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0)
        return;

    /* An inbound OPEN must carry the PEER's parity, never ours. */
    uint64_t peer_parity = 1u - stream_local_parity(node);
    enum mesh_stream_refusal refusal = MESH_STREAM_OK;
    if ((id & 1u) != peer_parity)
        refusal = MESH_STREAM_REFUSED_ID_PARITY;

    stream_lock();
    int index = -1;
    if (refusal == MESH_STREAM_OK && stream_find_locked(id, snap) != NULL)
        refusal = MESH_STREAM_REFUSED_ID_IN_USE;
    if (refusal == MESH_STREAM_OK &&
        !stream_open_admit_locked(snap->remote_static, now))
        refusal = MESH_STREAM_REFUSED_RATE;
    if (refusal == MESH_STREAM_OK &&
        (stream_peer_count_locked(snap->remote_static) >=
             MESH_STREAM_PER_PEER_MAX ||
         stream_free_slot_locked() == NULL))
        refusal = MESH_STREAM_REFUSED_CAP;
    if (refusal == MESH_STREAM_OK &&
        (initial_window == 0 || initial_window > MESH_STREAM_INITIAL_WINDOW))
        refusal = MESH_STREAM_REFUSED_CREDIT_EXCEEDED;
    if (refusal == MESH_STREAM_OK) {
        index = stream_service_index_locked(name, name_len);
        if (index < 0)
            refusal = MESH_STREAM_REFUSED_SERVICE_UNKNOWN;
        else if (!stream_peer_pairing_allows(
                     g_services[index].required_pairing_capability, now,
                     snap->remote_static))
            refusal = MESH_STREAM_REFUSED_PEER_UNPAIRED;
    }
    if (refusal != MESH_STREAM_OK || index < 0) {
        zcl_mutex_unlock(&g_stream_lock);
        atomic_fetch_add(&g_opens_refused, 1);
        (void)stream_send_close(mp, node, id, refusal, NULL, 0);
        return;
    }

    /* Reserve the slot before the service decides, so the service may
     * send on its own stream from inside on_open. */
    struct mesh_stream *slot = stream_free_slot_locked();
    if (!slot) {
        zcl_mutex_unlock(&g_stream_lock);
        atomic_fetch_add(&g_opens_refused, 1);
        (void)stream_send_close(mp, node, id, MESH_STREAM_REFUSED_CAP, NULL,
                                0);
        return;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->local_initiator = false;
    slot->peer_answered = true;
    slot->id = id;
    slot->service = (uint16_t)index;
    memcpy(slot->peer_static, snap->remote_static, 32);
    memcpy(slot->transcript_hash, snap->transcript_hash, 32);
    slot->connection_generation = snap->connection_generation;
    slot->send_credit = initial_window;
    slot->recv_credit = initial_window;
    slot->opened_unix = now;
    slot->last_activity_unix = now;

    uint8_t reply[MESH_STREAM_SERVICE_REPLY_MAX];
    size_t reply_len = 0;
    const struct mesh_stream_service *service = &g_services[index];
    enum mesh_stream_refusal verdict =
        service->on_open
            ? service->on_open(slot, payload, payload_len, reply,
                               sizeof(reply), &reply_len, service->ctx)
            : MESH_STREAM_OK;
    if (reply_len > sizeof(reply))
        reply_len = 0; /* a service can never widen its own reply bound */
    if (verdict != MESH_STREAM_OK) {
        /* The service explained its refusal; the evidence rides the CLOSE
         * and the slot is released — a refused stream is never reserved. */
        memset(slot, 0, sizeof(*slot));
        zcl_mutex_unlock(&g_stream_lock);
        atomic_fetch_add(&g_opens_refused, 1);
        (void)stream_send_close(mp, node, id, verdict,
                                reply_len ? reply : NULL, reply_len);
        return;
    }
    atomic_fetch_add(&g_streams_opened, 1);
    if (reply_len)
        (void)mesh_stream_send(slot, reply, reply_len);
    zcl_mutex_unlock(&g_stream_lock);
}

static void stream_receive_data(const struct noise_transport_snapshot *snap,
                                uint64_t id, const uint8_t *body,
                                size_t body_len)
{
    if (body_len < 2u) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    size_t payload_len = zcl_read_u16_le(body);
    if (body_len != 2u + payload_len ||
        payload_len > MESH_STREAM_PAYLOAD_MAX) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    stream_lock();
    struct mesh_stream *st = stream_find_locked(id, snap);
    if (!st) {
        zcl_mutex_unlock(&g_stream_lock);
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    if (payload_len > (size_t)st->recv_credit) {
        /* The peer spent credit it was never granted: end the stream by
         * name rather than absorb the overrun. */
        atomic_fetch_add(&g_credit_violations, 1);
        stream_close_locked(st, MESH_STREAM_REFUSED_CREDIT_EXCEEDED, NULL, 0);
        zcl_mutex_unlock(&g_stream_lock);
        return;
    }
    st->recv_credit -= (uint32_t)payload_len;
    st->bytes_received += payload_len;
    st->peer_answered = true;
    st->last_activity_unix = (int64_t)platform_time_wall_time_t();
    const struct mesh_stream_service *service =
        g_service_used[st->service] ? &g_services[st->service] : NULL;
    if (service && service->on_data)
        service->on_data(st, body + 2, payload_len, service->ctx);
    zcl_mutex_unlock(&g_stream_lock);
}

static void stream_receive_window(const struct noise_transport_snapshot *snap,
                                  uint64_t id, const uint8_t *body,
                                  size_t body_len)
{
    if (body_len != 4u) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    uint32_t credit = zcl_read_u32_le(body);
    stream_lock();
    struct mesh_stream *st = stream_find_locked(id, snap);
    if (!st) {
        zcl_mutex_unlock(&g_stream_lock);
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    if (credit == 0 || credit > MESH_STREAM_INITIAL_WINDOW ||
        st->send_credit > MESH_STREAM_INITIAL_WINDOW - credit) {
        /* A grant above the ceiling is a protocol violation, not a
         * generous peer: end the stream by name. */
        atomic_fetch_add(&g_credit_violations, 1);
        stream_close_locked(st, MESH_STREAM_REFUSED_CREDIT_EXCEEDED, NULL, 0);
        zcl_mutex_unlock(&g_stream_lock);
        return;
    }
    st->send_credit += credit;
    st->peer_answered = true;
    st->last_activity_unix = (int64_t)platform_time_wall_time_t();
    zcl_mutex_unlock(&g_stream_lock);
}

static void stream_receive_close(const struct noise_transport_snapshot *snap,
                                 uint64_t id, const uint8_t *body,
                                 size_t body_len)
{
    if (body_len < 3u) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    enum mesh_stream_refusal reason = (enum mesh_stream_refusal)body[0];
    size_t payload_len = zcl_read_u16_le(body + 1);
    if (body_len != 3u + payload_len ||
        payload_len > MESH_STREAM_PAYLOAD_MAX) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    if (reason > MESH_STREAM_CLOSED_BY_SERVICE)
        reason = MESH_STREAM_REFUSED_MALFORMED;
    stream_lock();
    struct mesh_stream *st = stream_find_locked(id, snap);
    if (!st) {
        zcl_mutex_unlock(&g_stream_lock);
        atomic_fetch_add(&g_dropped_malformed, 1);
        return;
    }
    /* The peer already ended it: half-close and run on_close without
     * sending a CLOSE back. */
    st->ended = true;
    st->end_reason = reason;
    st->send_credit = 0;
    st->recv_credit = 0;
    st->last_activity_unix = (int64_t)platform_time_wall_time_t();
    atomic_fetch_add(&g_streams_ended, 1);
    const struct mesh_stream_service *service =
        g_service_used[st->service] ? &g_services[st->service] : NULL;
    if (service && service->on_close)
        service->on_close(st, reason, body + 3, payload_len, service->ctx);
    zcl_mutex_unlock(&g_stream_lock);
}

bool mesh_stream_frame(struct msg_processor *mp, struct p2p_node *node,
                       const uint8_t *payload, size_t payload_len,
                       struct boot_svc_ctx *svc)
{
    (void)svc;
    size_t head = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
    if (!payload || payload_len < MESH_STREAM_FRAME_PREFIX_LEN + 1u ||
        memcmp(payload, MESH_STREAM_FRAME_PREFIX,
               MESH_STREAM_FRAME_PREFIX_LEN) != 0)
        return false;
    if (!node)
        return true; /* our namespace, unusable context: drop quietly */
    if (payload_len < head || payload_len > MESH_STREAM_FRAME_MAX) {
        atomic_fetch_add(&g_dropped_malformed, 1);
        return true;
    }
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    if (!node->transport ||
        !noise_transport_snapshot(node->transport, &snap) ||
        !snap.established) {
        /* Plaintext v1 or mid-handshake: a stream is never carried over a
         * link that is not an established Noise session. */
        atomic_fetch_add(&g_dropped_unauthenticated, 1);
        return true;
    }
    uint8_t kind = payload[MESH_STREAM_FRAME_PREFIX_LEN];
    uint64_t id = zcl_read_u64_le(payload + MESH_STREAM_FRAME_PREFIX_LEN + 1u);
    const uint8_t *body = payload + head;
    size_t body_len = payload_len - head;
    switch (kind) {
    case MESH_STREAM_KIND_OPEN:
        stream_receive_open(mp, node, &snap, id, body, body_len);
        return true;
    case MESH_STREAM_KIND_DATA:
        stream_receive_data(&snap, id, body, body_len);
        return true;
    case MESH_STREAM_KIND_WINDOW:
        stream_receive_window(&snap, id, body, body_len);
        return true;
    case MESH_STREAM_KIND_CLOSE:
        stream_receive_close(&snap, id, body, body_len);
        return true;
    default:
        atomic_fetch_add(&g_dropped_unknown_kind, 1);
        return true;
    }
}

/* ── The one supervised drain ────────────────────────────────────────── */

/* Every live stream, once per tick: the session it was opened on must
 * still be there, the idle mark must not have passed, and then the
 * service moves whatever it has into DATA within the credit it holds. No
 * service keeps a pump of its own. */
static void stream_pump_tick(struct liveness_contract *contract)
{
    (void)contract;
    stream_lock();
    struct boot_svc_ctx *svc = g_stream_svc;
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr) {
        zcl_mutex_unlock(&g_stream_lock);
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0) {
        zcl_mutex_unlock(&g_stream_lock);
        return;
    }
    bool any_live = false;
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++) {
        struct mesh_stream *st = &g_streams[i];
        if (!st->used)
            continue;
        /* A half-closed slot is a verdict waiting to be read: reap it at
         * the linger mark, never tick it. */
        if (st->ended) {
            if (now > st->last_activity_unix &&
                now - st->last_activity_unix >= MESH_STREAM_LINGER_SECONDS)
                mesh_stream_release(st);
            continue;
        }
        any_live = true;
        struct p2p_node *peer = stream_bound_peer_locked(st, NULL);
        if (!peer) {
            stream_close_locked(st, MESH_STREAM_ENDED_SESSION_LOST, NULL, 0);
            continue;
        }
        p2p_node_release(peer);
        if (now > st->last_activity_unix &&
            now - st->last_activity_unix >= MESH_STREAM_IDLE_SECONDS) {
            stream_close_locked(st, MESH_STREAM_ENDED_IDLE, NULL, 0);
            continue;
        }
        const struct mesh_stream_service *service =
            g_service_used[st->service] ? &g_services[st->service] : NULL;
        if (service && service->on_tick)
            service->on_tick(st, now, service->ctx);
    }
    if (!any_live)
        supervisor_progress_idle(g_stream_child);
    zcl_mutex_unlock(&g_stream_lock);
}

/* ── Lifecycle ───────────────────────────────────────────────────────── */

void mesh_stream_wire(struct boot_svc_ctx *svc)
{
    stream_lock();
    if (g_stream_child != SUPERVISOR_INVALID_ID || g_stream_svc) {
        zcl_mutex_unlock(&g_stream_lock);
        LOG_ERROR("net.mesh_stream", "wire: already wired");
        return;
    }
    g_stream_svc = svc;
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
        mesh_stream_release(&g_streams[i]);
    memset(g_open_rate, 0, sizeof(g_open_rate));
    zcl_mutex_unlock(&g_stream_lock);

    liveness_contract_init(&g_stream_contract, "net.mesh_stream_pump");
    g_stream_contract.on_tick = stream_pump_tick;
    supervisor_domains_init();
    g_stream_child = supervisor_register_in_domain(g_net_sup,
                                                   &g_stream_contract);
    if (g_stream_child == SUPERVISOR_INVALID_ID) {
        LOG_ERROR("net.mesh_stream", "pump supervisor register failed");
        return;
    }
    supervisor_set_period(g_stream_child, 1);
    /* 100 ms cadence: keyboard/screen latency a human tolerates, still
     * far under any stall deadline. */
    g_stream_contract.period_us = 100000;
    supervisor_request_min_tick_ms(100);
    supervisor_set_deadline(g_stream_child, 30);
    supervisor_set_progress_exempt(g_stream_child,
                                   "paired peers may never open a stream");
}

void mesh_stream_shutdown(void)
{
    stream_lock();
    supervisor_child_id child = g_stream_child;
    g_stream_child = SUPERVISOR_INVALID_ID;
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
        if (g_streams[i].used)
            stream_close_locked(&g_streams[i], MESH_STREAM_ENDED_SHUTDOWN,
                                NULL, 0);
    g_stream_svc = NULL;
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
        mesh_stream_release(&g_streams[i]);
    memset(g_open_rate, 0, sizeof(g_open_rate));
    zcl_mutex_unlock(&g_stream_lock);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_unregister(child);
    /* Barrier with a callback already snapshotted by the supervisor. */
    stream_lock();
    zcl_mutex_unlock(&g_stream_lock);
}

#ifdef ZCL_TESTING
void mesh_stream_test_reset(void)
{
    stream_lock();
    for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
        mesh_stream_release(&g_streams[i]);
    memset(g_open_rate, 0, sizeof(g_open_rate));
    zcl_mutex_unlock(&g_stream_lock);
}

void mesh_stream_test_bind(struct boot_svc_ctx *svc)
{
    stream_lock();
    g_stream_svc = svc;
    zcl_mutex_unlock(&g_stream_lock);
}

size_t mesh_stream_test_live_count(const char *service_name)
{
    if (!service_name)
        return 0;
    stream_lock();
    size_t n = 0;
    int index = stream_service_index_locked(service_name,
                                            strlen(service_name));
    if (index >= 0)
        for (size_t i = 0; i < MESH_STREAM_TABLE_MAX; i++)
            if (g_streams[i].used && !g_streams[i].ended &&
                g_streams[i].service == (uint16_t)index)
                n++;
    zcl_mutex_unlock(&g_stream_lock);
    return n;
}

bool mesh_stream_test_inject(const char *service_name,
                             const uint8_t peer_static[32],
                             const uint8_t transcript_hash[32],
                             uint64_t connection_generation,
                             bool local_initiator, uint64_t id,
                             uint32_t initial_window, void *service_state)
{
    if (!service_name || !peer_static || !transcript_hash)
        return false;
    if (initial_window == 0 || initial_window > MESH_STREAM_INITIAL_WINDOW)
        return false;
    int64_t now = (int64_t)platform_time_wall_time_t();
    stream_lock();
    int index = stream_service_index_locked(service_name,
                                            strlen(service_name));
    struct mesh_stream *slot = index >= 0 ? stream_free_slot_locked() : NULL;
    if (!slot) {
        zcl_mutex_unlock(&g_stream_lock);
        return false;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->local_initiator = local_initiator;
    slot->id = id;
    slot->service = (uint16_t)index;
    memcpy(slot->peer_static, peer_static, 32);
    memcpy(slot->transcript_hash, transcript_hash, 32);
    slot->connection_generation = connection_generation;
    slot->send_credit = initial_window;
    slot->recv_credit = initial_window;
    slot->opened_unix = now;
    slot->last_activity_unix = now;
    slot->service_state = service_state;
    zcl_mutex_unlock(&g_stream_lock);
    return true;
}
#endif
