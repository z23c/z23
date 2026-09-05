/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The TCP tunnel service on the mesh stream primitive: the local
 * listeners, the loopback-only acceptor, the explicit allow table, and the
 * byte copy that spends nothing but the stream's own credit. The stream
 * owns the framing, the table, the window and the per-stream tick (see
 * config/mesh_tunnel.h).
 *
 * LOCK ORDER. `g_tun_lock` is strictly INNER to the stream lane lock: a
 * stream callback already holds the lane lock and may take this one; a
 * path that holds this one never calls mesh_stream_open, _visit or any
 * other verb that takes the lane lock. Every such path drops this lock
 * first, which is why the accept path snapshots its work before opening a
 * stream and the close path marks before it visits. */

// one-result-type-ok:closed-security-verdict — every entry point returns a
// bounded named verdict the caller must branch on; no diagnostic text
// crosses the wire.

#include "config/mesh_tunnel.h"
#include "config/mesh_stream.h"

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "models/mesh_pairing.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "supervisors/domains.h"
#include "util/file_io.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TUN_TAG "net.mesh_tunnel"

/* The ONLY address this service ever dials. Not a parameter, not a row
 * field, not a name to resolve: a constant, so no allow row and no peer
 * payload can move the acceptor off this machine's own loopback. */
#define MESH_TUNNEL_TARGET_HOST_V4 INADDR_LOOPBACK

static zcl_mutex_t g_tun_lock;
static _Atomic int g_tun_lock_state;
static struct boot_svc_ctx *g_tun_svc; /* borrowed; set by wire() */
static supervisor_child_id g_tun_child = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_tun_contract;
static bool g_tun_registered;

/* One local listener the operator opened. Initiator side only. */
struct mesh_tunnel_listener {
    bool used;
    uint64_t id;
    uint8_t peer_static[32];
    char peer[65];
    uint16_t remote_port;
    uint16_t local_port;
    platform_socket_t sock;
    uint64_t streams_total;
    uint64_t bytes_to_peer;   /* retired: live streams add their own */
    uint64_t bytes_from_peer;
    int64_t opened_unix;
};
static struct mesh_tunnel_listener g_listeners[MESH_TUNNEL_LISTENERS_MAX];
static uint64_t g_next_tunnel_id = 1;

static struct mesh_tunnel_allow_row g_allow[MESH_TUNNEL_ALLOW_MAX];
static size_t g_allow_count;
static bool g_allow_loaded;

/* One tunnelled TCP connection's own state, hung off its stream. The
 * stream owns the identity, the peer binding, the credit and the
 * lifetime; this is only the socket and the one chunk in flight. */
struct mesh_tunnel_session {
    platform_socket_t sock;
    bool connecting; /* acceptor: the loopback dial has not completed */
    bool local_eof;  /* our socket returned EOF; nothing more to read */
    uint64_t listener_id; /* initiator: the local listener that made it */
    uint32_t pending_len;
    uint32_t pending_off;
    uint64_t bytes_to_peer;
    uint64_t bytes_from_peer;
    uint8_t pending[MESH_TUNNEL_CHUNK];
};

static _Atomic uint64_t g_tun_opens_refused;
static _Atomic uint64_t g_tun_streams_opened;
static _Atomic uint64_t g_tun_dials_failed;

static void tunnel_lock(void)
{
    if (atomic_load_explicit(&g_tun_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_tun_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_tun_lock);
            atomic_store_explicit(&g_tun_lock_state, 2, memory_order_release);
        } else {
            while (atomic_load_explicit(&g_tun_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_tun_lock);
}

static void tunnel_unlock(void) { zcl_mutex_unlock(&g_tun_lock); }

const char *mesh_tunnel_refusal_string(enum mesh_tunnel_refusal reason)
{
    switch (reason) {
    case MESH_TUNNEL_OK: return "tunnel_ok";
    case MESH_TUNNEL_REFUSED_MALFORMED: return "tunnel_malformed";
    case MESH_TUNNEL_REFUSED_TARGET_NOT_ALLOWED:
        return "tunnel_target_not_allowed";
    case MESH_TUNNEL_REFUSED_DIAL_FAILED: return "tunnel_dial_failed";
    case MESH_TUNNEL_REFUSED_CAP: return "tunnel_cap";
    case MESH_TUNNEL_REFUSED_UNAVAILABLE: return "tunnel_unavailable";
    case MESH_TUNNEL_REFUSED_LOCAL_BIND_FAILED:
        return "tunnel_local_bind_failed";
    case MESH_TUNNEL_REFUSED_PEER_UNPAIRED: return "tunnel_peer_unpaired";
    case MESH_TUNNEL_ENDED_LOCAL_CLOSE: return "tunnel_local_closed";
    }
    return "tunnel_unavailable";
}

/* ── The OPEN header ─────────────────────────────────────────────────── */

/* "ZTUN", version, reserved, port. Fixed width, so a peer can never make
 * the acceptor read a length it chose. */
static size_t tunnel_open_encode(uint16_t port, uint8_t out[8])
{
    memcpy(out, "ZTUN", 4);
    out[4] = 1;
    out[5] = 0;
    out[6] = (uint8_t)(port >> 8);
    out[7] = (uint8_t)(port & 0xffu);
    return MESH_TUNNEL_OPEN_BYTES;
}

static bool tunnel_open_decode(const uint8_t *in, size_t len, uint16_t *port)
{
    if (!in || len != MESH_TUNNEL_OPEN_BYTES || memcmp(in, "ZTUN", 4) != 0 ||
        in[4] != 1 || in[5] != 0)
        return false;
    *port = (uint16_t)(((uint16_t)in[6] << 8) | (uint16_t)in[7]);
    return *port != 0;
}

/* ── Peer naming ─────────────────────────────────────────────────────── */

/* The live pairing row for one Noise static, rendered as the pairing id
 * the operator sees everywhere else. No row means the node cannot name
 * the peer, and every decision that needs a name fails closed. */
static bool tunnel_peer_id(const uint8_t peer_static[32], int64_t now,
                           char out[65])
{
    out[0] = '\0';
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb)
        return false;
    struct db_mesh_pairing rows[64];
    int count = db_mesh_pairing_list(ndb, rows, sizeof(rows) / sizeof(rows[0]));
    for (int i = 0; i < count; i++) {
        if (memcmp(rows[i].peer_noise_pubkey, peer_static, 32) != 0)
            continue;
        if (!mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_STATUS_READ, now))
            continue;
        snprintf(out, 65, "%s", rows[i].pairing_id);
        return true;
    }
    return false;
}

/* The reverse: the Noise static one pairing id names. */
static bool tunnel_peer_static(const char *pairing_id, int64_t now,
                               uint8_t out[32])
{
    struct node_db *ndb = app_runtime_node_db();
    struct db_mesh_pairing row;
    if (!ndb || !pairing_id || strlen(pairing_id) != 64 ||
        !db_mesh_pairing_find(ndb, pairing_id, &row) ||
        !mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, now))
        return false;
    memcpy(out, row.peer_noise_pubkey, 32);
    return true;
}

/* ── The allow table ─────────────────────────────────────────────────── */

static bool tunnel_allow_path(char *out, size_t cap)
{
    struct boot_svc_ctx *svc = g_tun_svc;
    if (!svc || !svc->datadir || !svc->datadir[0])
        return false;
    return snprintf(out, cap, "%s/%s", svc->datadir,
                    MESH_TUNNEL_ALLOW_FILE) < (int)cap;
}

/* One row: `<64 hex pairing id> <port> <why...>`. Anything else is not a
 * row — a malformed line grants nothing and is skipped by name. */
static bool tunnel_allow_parse(char *line, struct mesh_tunnel_allow_row *out)
{
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '#' || *line == '\0')
        return false;
    char *sp = strchr(line, ' ');
    if (!sp)
        return false;
    *sp = '\0';
    uint8_t raw[32];
    if (strlen(line) != 64 || !zcl_hex_decode_lower(line, raw, 32))
        return false;
    snprintf(out->peer, sizeof(out->peer), "%s", line);
    char *port_text = sp + 1;
    while (*port_text == ' ')
        port_text++;
    char *end = NULL;
    unsigned long port = strtoul(port_text, &end, 10);
    if (end == port_text || port == 0 || port > 65535u)
        return false;
    out->port = (uint16_t)port;
    while (*end == ' ')
        end++;
    snprintf(out->why, sizeof(out->why), "%s", end);
    return true;
}

/* Read the allow file into the table. Called with the tunnel lock held.
 * No file is not an error: it is the honest answer that nothing is
 * allowed, which is also what an unreadable or over-long file means. */
static void tunnel_allow_load_locked(void)
{
    g_allow_count = 0;
    g_allow_loaded = true;
    memset(g_allow, 0, sizeof(g_allow));
    char path[1024];
    char *text = NULL;
    size_t len = 0;
    if (!tunnel_allow_path(path, sizeof(path)) ||
        !zcl_read_whole_file_text(path, MESH_TUNNEL_ALLOW_FILE_MAX, &text,
                                  &len, TUN_TAG))
        return;
    char *cursor = text;
    while (cursor && *cursor && g_allow_count < MESH_TUNNEL_ALLOW_MAX) {
        char *nl = strchr(cursor, '\n');
        if (nl)
            *nl = '\0';
        struct mesh_tunnel_allow_row row;
        memset(&row, 0, sizeof(row));
        if (tunnel_allow_parse(cursor, &row))
            g_allow[g_allow_count++] = row;
        if (!nl)
            break;
        cursor = nl + 1;
    }
    free(text);
}

/* The whole admission decision on the acceptor side: an exact
 * (pairing id, port) match, and nothing else. No wildcard, no range, no
 * default. Called with the tunnel lock held. */
static bool tunnel_allowed_locked(const char *peer, uint16_t port)
{
    if (!g_allow_loaded)
        tunnel_allow_load_locked();
    for (size_t i = 0; i < g_allow_count; i++)
        if (g_allow[i].port == port &&
            strncmp(g_allow[i].peer, peer, 64) == 0)
            return true;
    return false;
}

/* Rewrite the file from the table, then reload it, so what a caller reads
 * back is exactly what the next OPEN will read. Tunnel lock held. */
static bool tunnel_allow_persist_locked(void)
{
    char path[1024], tmp[1088];
    if (!tunnel_allow_path(path, sizeof(path)) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    FILE *f = fopen(tmp, "w");
    if (!f)
        return false;
    bool ok = fprintf(f, "# <pairing id> <port> <why> — nothing is allowed "
                         "without a row here\n") > 0;
    for (size_t i = 0; i < g_allow_count && ok; i++)
        ok = fprintf(f, "%s %u %s\n", g_allow[i].peer,
                     (unsigned)g_allow[i].port, g_allow[i].why) > 0;
    if (fclose(f) != 0)
        ok = false;
    if (!ok || rename(tmp, path) != 0) {
        remove(tmp);
        return false;
    }
    tunnel_allow_load_locked();
    return true;
}

/* ── Sockets ─────────────────────────────────────────────────────────── */

static void tunnel_socket_drop(platform_socket_t *sock)
{
    if (*sock == PLATFORM_SOCKET_INVALID)
        return;
    (void)platform_socket_shutdown_both(*sock);
    (void)platform_socket_close(*sock);
    *sock = PLATFORM_SOCKET_INVALID;
}

static void tunnel_loopback_v4(struct sockaddr_in *addr, uint16_t port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = htonl(MESH_TUNNEL_TARGET_HOST_V4);
}

/* Bind one listener on 127.0.0.1 only. A tunnel entrance that answered on
 * any other interface would hand the whole LAN the peer's port. */
static platform_socket_t tunnel_bind_loopback(uint16_t port, uint16_t *bound)
{
    platform_socket_t sock =
        platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (sock == PLATFORM_SOCKET_INVALID)
        return PLATFORM_SOCKET_INVALID;
    struct sockaddr_in addr;
    tunnel_loopback_v4(&addr, port);
    if (platform_socket_bind(sock, (struct sockaddr *)&addr, sizeof(addr)) !=
            0 ||
        platform_socket_listen(sock, (int)MESH_TUNNEL_LISTENERS_MAX) != 0) {
        tunnel_socket_drop(&sock);
        return PLATFORM_SOCKET_INVALID;
    }
    struct sockaddr_in got;
    size_t got_len = sizeof(got);
    memset(&got, 0, sizeof(got));
    if (platform_socket_local_address(sock, (struct sockaddr *)&got,
                                      &got_len) != 0) {
        tunnel_socket_drop(&sock);
        return PLATFORM_SOCKET_INVALID;
    }
    *bound = ntohs(got.sin_port);
    return sock;
}

/* ── The stream service ──────────────────────────────────────────────── */

static void tunnel_end(struct mesh_stream *st, enum mesh_tunnel_refusal why)
{
    const char *token = mesh_tunnel_refusal_string(why);
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE,
                      (const uint8_t *)token, strlen(token));
}

/* Move what the peer sent into the socket, and grant credit back ONLY for
 * bytes that actually left. A socket nobody reads therefore stalls its own
 * tunnel at one chunk and never grows this node's memory. */
static void tunnel_flush(struct mesh_stream *st,
                         struct mesh_tunnel_session *s)
{
    while (s->pending_off < s->pending_len) {
        int n = platform_socket_send_nonblocking(
            s->sock, s->pending + s->pending_off,
            (size_t)(s->pending_len - s->pending_off));
        if (n > 0) {
            s->pending_off += (uint32_t)n;
            s->bytes_from_peer += (uint64_t)n;
            (void)mesh_stream_grant(st, (uint32_t)n);
            continue;
        }
        if (n < 0 && platform_socket_error_would_block(
                         platform_socket_last_error()))
            return;
        tunnel_end(st, MESH_TUNNEL_ENDED_LOCAL_CLOSE);
        return;
    }
    s->pending_off = 0;
    s->pending_len = 0;
}

/* Move socket bytes toward the peer, never reading more than the credit
 * this side holds. Socket EOF is the tunnel's end, named. */
static void tunnel_drain_socket(struct mesh_stream *st,
                                struct mesh_tunnel_session *s)
{
    while (!s->local_eof && st->send_credit > 0) {
        uint32_t take = st->send_credit < MESH_TUNNEL_CHUNK
                            ? st->send_credit
                            : MESH_TUNNEL_CHUNK;
        uint8_t buf[MESH_TUNNEL_CHUNK];
        int n = platform_socket_receive_nonblocking(s->sock, buf, take);
        if (n > 0) {
            if (!mesh_stream_send(st, buf, (size_t)n)) {
                /* The credit was checked above; a refusal here means the
                 * link went away, and the pump ends the stream by name. */
                return;
            }
            s->bytes_to_peer += (uint64_t)n;
            continue;
        }
        if (n < 0 && platform_socket_error_would_block(
                         platform_socket_last_error()))
            return;
        s->local_eof = true;
        tunnel_end(st, MESH_TUNNEL_ENDED_LOCAL_CLOSE);
        return;
    }
}

/* The acceptor's answer to an inbound OPEN. Two gates, both fail-closed:
 * the peer must hold a live pairing row this node can name it by, and an
 * allow row must admit that exact name and that exact port. Only then is
 * a loopback dial attempted, and only ever to loopback. */
static enum mesh_stream_refusal tunnel_service_open(
    struct mesh_stream *st, const uint8_t *payload, size_t payload_len,
    uint8_t *reply, size_t reply_cap, size_t *reply_len, void *ctx)
{
    (void)ctx;
    (void)reply;
    (void)reply_cap;
    *reply_len = 0;
    uint16_t port = 0;
    if (!tunnel_open_decode(payload, payload_len, &port)) {
        atomic_fetch_add(&g_tun_opens_refused, 1);
        return MESH_STREAM_REFUSED_MALFORMED;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    char peer[65];
    if (!tunnel_peer_id(st->peer_static, now, peer)) {
        atomic_fetch_add(&g_tun_opens_refused, 1);
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    }
    tunnel_lock();
    bool allowed = tunnel_allowed_locked(peer, port);
    tunnel_unlock();
    if (!allowed) {
        atomic_fetch_add(&g_tun_opens_refused, 1);
        LOG_WARN(TUN_TAG, "%s: no allow row admits port %u for this peer",
                 mesh_tunnel_refusal_string(
                     MESH_TUNNEL_REFUSED_TARGET_NOT_ALLOWED),
                 (unsigned)port);
        return MESH_STREAM_CLOSED_BY_SERVICE;
    }
    struct mesh_tunnel_session *s =
        zcl_calloc(1, sizeof(*s), "mesh_tunnel_session");
    if (!s)
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    s->sock = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (s->sock == PLATFORM_SOCKET_INVALID) {
        free(s);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    (void)platform_socket_set_no_delay(s->sock, true);
    struct sockaddr_in addr;
    tunnel_loopback_v4(&addr, port);
    if (platform_socket_connect(s->sock, (struct sockaddr *)&addr,
                                sizeof(addr)) != 0) {
        if (!platform_socket_error_in_progress(platform_socket_last_error())) {
            atomic_fetch_add(&g_tun_dials_failed, 1);
            tunnel_socket_drop(&s->sock);
            free(s);
            return MESH_STREAM_CLOSED_BY_SERVICE;
        }
        s->connecting = true;
    }
    st->service_state = s;
    atomic_fetch_add(&g_tun_streams_opened, 1);
    LOG_INFO(TUN_TAG, "tunnel accepted: stream %llu to loopback port %u",
             (unsigned long long)st->id, (unsigned)port);
    return MESH_STREAM_OK;
}

static void tunnel_service_data(struct mesh_stream *st,
                                const uint8_t *payload, size_t payload_len,
                                void *ctx)
{
    (void)ctx;
    struct mesh_tunnel_session *s = st->service_state;
    if (!s || payload_len == 0)
        return;
    /* The stream layer never delivers more than the credit this side
     * granted, and this side grants only what has left for the socket, so
     * the chunk always fits. A payload that does not is the primitive
     * behaving unlike its contract: end the tunnel rather than grow. */
    if (s->pending_len + payload_len > MESH_TUNNEL_CHUNK) {
        tunnel_end(st, MESH_TUNNEL_REFUSED_CAP);
        return;
    }
    memcpy(s->pending + s->pending_len, payload, payload_len);
    s->pending_len += (uint32_t)payload_len;
    tunnel_flush(st, s);
}

/* One live tunnel, once per stream tick: finish the dial if it is still
 * in flight, push what the peer sent, then pull what the socket has. */
static void tunnel_stream_tick(struct mesh_stream *st, int64_t now)
{
    (void)now;
    struct mesh_tunnel_session *s = st->service_state;
    if (!s)
        return;
    if (s->connecting) {
        if (platform_socket_wait_writable(s->sock, 0) <= 0)
            return;
        int pending = 0;
        if (platform_socket_pending_error(s->sock, &pending) != 0 ||
            pending != 0) {
            atomic_fetch_add(&g_tun_dials_failed, 1);
            tunnel_end(st, MESH_TUNNEL_REFUSED_DIAL_FAILED);
            return;
        }
        s->connecting = false;
    }
    tunnel_flush(st, s);
    if (!st->ended)
        tunnel_drain_socket(st, s);
}

static void tunnel_service_tick(struct mesh_stream *st, int64_t now,
                                void *ctx)
{
    (void)ctx;
    tunnel_stream_tick(st, now);
}

static void tunnel_service_close(struct mesh_stream *st,
                                 enum mesh_stream_refusal reason,
                                 const uint8_t *payload, size_t payload_len,
                                 void *ctx)
{
    (void)ctx;
    (void)payload;
    (void)payload_len;
    (void)reason;
    struct mesh_tunnel_session *s = st->service_state;
    /* The peer said the far end is done: stop the local socket both ways
     * so the local program sees the same end this stream did. */
    if (s && s->sock != PLATFORM_SOCKET_INVALID)
        (void)platform_socket_shutdown_both(s->sock);
    /* The tunnel keeps no verdict a caller reads after the end: the slot
     * goes back now instead of lingering. */
    mesh_stream_release(st);
}

static void tunnel_service_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    struct mesh_tunnel_session *s = st->service_state;
    st->service_state = NULL;
    if (!s)
        return;
    tunnel_socket_drop(&s->sock);
    if (s->listener_id) {
        tunnel_lock();
        for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++)
            if (g_listeners[i].used && g_listeners[i].id == s->listener_id) {
                g_listeners[i].bytes_to_peer += s->bytes_to_peer;
                g_listeners[i].bytes_from_peer += s->bytes_from_peer;
            }
        tunnel_unlock();
    }
    free(s);
}

static bool tunnel_register_service(void)
{
    struct mesh_stream_service service;
    memset(&service, 0, sizeof(service));
    service.name = MESH_TUNNEL_SERVICE_NAME;
    /* The primitive proves the peer is a paired machine at all and
     * refuses `stream_peer_unpaired` before on_open runs. The AUTHORITY
     * that admits a target is the allow row, which names one peer and one
     * port — strictly narrower than any capability bit. */
    service.required_pairing_capability = MESH_PAIRING_CAP_STATUS_READ;
    service.on_open = tunnel_service_open;
    service.on_data = tunnel_service_data;
    service.on_close = tunnel_service_close;
    service.on_tick = tunnel_service_tick;
    service.on_release = tunnel_service_release;
    return mesh_stream_service_register(&service);
}

/* ── The listener beat ───────────────────────────────────────────────── */

/* One accept, turned into one stream. Runs with NO lock held, because
 * mesh_stream_open takes the lane lock (see the lock-order note). */
static void tunnel_accept_one(const uint8_t peer_static[32],
                              uint16_t remote_port, uint64_t listener_id,
                              platform_socket_t accepted)
{
    struct mesh_tunnel_session *s =
        zcl_calloc(1, sizeof(*s), "mesh_tunnel_session");
    if (!s) {
        platform_socket_t drop = accepted;
        tunnel_socket_drop(&drop);
        return;
    }
    s->sock = accepted;
    s->listener_id = listener_id;
    (void)platform_socket_set_no_delay(s->sock, true);
    uint8_t header[MESH_TUNNEL_OPEN_BYTES];
    size_t header_len = tunnel_open_encode(remote_port, header);
    uint64_t stream_id = 0;
    enum mesh_stream_refusal r =
        mesh_stream_open(MESH_TUNNEL_SERVICE_NAME, peer_static,
                         MESH_TUNNEL_CHUNK, header, header_len, s, &stream_id);
    if (r != MESH_STREAM_OK) {
        LOG_WARN(TUN_TAG, "tunnel connection refused by the stream layer: %s",
                 mesh_stream_refusal_string(r));
        tunnel_socket_drop(&s->sock);
        free(s);
        return;
    }
    atomic_fetch_add(&g_tun_streams_opened, 1);
    tunnel_lock();
    for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++)
        if (g_listeners[i].used && g_listeners[i].id == listener_id)
            g_listeners[i].streams_total++;
    tunnel_unlock();
}

/* Every listener, once per beat: drain a bounded number of accepts, and
 * open one stream for each. */
static void tunnel_listener_beat(void)
{
    for (int round = 0; round < MESH_TUNNEL_ACCEPTS_PER_TICK; round++) {
        uint8_t peer_static[32];
        uint16_t remote_port = 0;
        uint64_t listener_id = 0;
        platform_socket_t accepted = PLATFORM_SOCKET_INVALID;
        tunnel_lock();
        for (size_t i = 0;
             i < MESH_TUNNEL_LISTENERS_MAX && accepted == PLATFORM_SOCKET_INVALID;
             i++) {
            struct mesh_tunnel_listener *l = &g_listeners[i];
            if (!l->used || l->sock == PLATFORM_SOCKET_INVALID)
                continue;
            struct sockaddr_in from;
            size_t from_len = sizeof(from);
            memset(&from, 0, sizeof(from));
            platform_socket_t got = platform_socket_accept(
                l->sock, (struct sockaddr *)&from, &from_len);
            if (got == PLATFORM_SOCKET_INVALID)
                continue;
            /* The listener is bound to loopback, so this can only be a
             * local connection; check it anyway, because a tunnel
             * entrance is exactly where an assumption must not be one. */
            if (from.sin_family != AF_INET ||
                ntohl(from.sin_addr.s_addr) != MESH_TUNNEL_TARGET_HOST_V4) {
                tunnel_socket_drop(&got);
                continue;
            }
            (void)platform_socket_set_nonblocking(got, true);
            memcpy(peer_static, l->peer_static, 32);
            remote_port = l->remote_port;
            listener_id = l->id;
            accepted = got;
        }
        tunnel_unlock();
        if (accepted == PLATFORM_SOCKET_INVALID)
            return;
        tunnel_accept_one(peer_static, remote_port, listener_id, accepted);
    }
}

static void tunnel_listener_tick(struct liveness_contract *contract)
{
    (void)contract;
    if (!g_tun_svc)
        return;
    tunnel_listener_beat();
    supervisor_progress_idle(g_tun_child);
}

/* ── Operator verbs ──────────────────────────────────────────────────── */

enum mesh_tunnel_refusal mesh_tunnel_listen(const char *peer_pairing_id,
                                            uint16_t remote_port,
                                            uint16_t local_port,
                                            uint64_t *tunnel_id_out,
                                            uint16_t *bound_port_out)
{
    if (!peer_pairing_id || remote_port == 0 || !tunnel_id_out ||
        !bound_port_out)
        return MESH_TUNNEL_REFUSED_MALFORMED;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t peer_static[32];
    if (!tunnel_peer_static(peer_pairing_id, now, peer_static))
        return MESH_TUNNEL_REFUSED_PEER_UNPAIRED;
    tunnel_lock();
    struct mesh_tunnel_listener *slot = NULL;
    for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++)
        if (!g_listeners[i].used) {
            slot = &g_listeners[i];
            break;
        }
    if (!slot) {
        tunnel_unlock();
        return MESH_TUNNEL_REFUSED_CAP;
    }
    uint16_t bound = 0;
    platform_socket_t sock = tunnel_bind_loopback(local_port, &bound);
    if (sock == PLATFORM_SOCKET_INVALID) {
        tunnel_unlock();
        return MESH_TUNNEL_REFUSED_LOCAL_BIND_FAILED;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->id = g_next_tunnel_id++;
    memcpy(slot->peer_static, peer_static, 32);
    snprintf(slot->peer, sizeof(slot->peer), "%s", peer_pairing_id);
    slot->remote_port = remote_port;
    slot->local_port = bound;
    slot->sock = sock;
    slot->opened_unix = now;
    *tunnel_id_out = slot->id;
    *bound_port_out = bound;
    tunnel_unlock();
    LOG_INFO(TUN_TAG, "tunnel listening on loopback port %u for peer port %u",
             (unsigned)bound, (unsigned)remote_port);
    return MESH_TUNNEL_OK;
}

struct tunnel_close_visit {
    uint64_t listener_id;
    size_t closed;
};

static bool tunnel_close_visit(struct mesh_stream *st, void *ctx)
{
    struct tunnel_close_visit *v = ctx;
    struct mesh_tunnel_session *s = st->service_state;
    if (s && s->listener_id == v->listener_id && !st->ended) {
        tunnel_end(st, MESH_TUNNEL_ENDED_LOCAL_CLOSE);
        v->closed++;
    }
    return true;
}

bool mesh_tunnel_close(uint64_t tunnel_id)
{
    platform_socket_t sock = PLATFORM_SOCKET_INVALID;
    bool found = false;
    tunnel_lock();
    for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++)
        if (g_listeners[i].used && g_listeners[i].id == tunnel_id) {
            sock = g_listeners[i].sock;
            memset(&g_listeners[i], 0, sizeof(g_listeners[i]));
            found = true;
        }
    tunnel_unlock();
    if (!found)
        return false;
    tunnel_socket_drop(&sock);
    /* Outside the tunnel lock: the visit takes the stream lane lock. */
    struct tunnel_close_visit v = {tunnel_id, 0};
    mesh_stream_visit(MESH_TUNNEL_SERVICE_NAME, tunnel_close_visit, &v);
    return true;
}

struct tunnel_live_sum {
    uint64_t listener_id;
    uint64_t open;
    uint64_t to_peer;
    uint64_t from_peer;
};

struct tunnel_list_visit {
    struct tunnel_live_sum sums[MESH_TUNNEL_LISTENERS_MAX];
    size_t count;
};

static bool tunnel_list_visit(struct mesh_stream *st, void *ctx)
{
    struct tunnel_list_visit *v = ctx;
    struct mesh_tunnel_session *s = st->service_state;
    if (!s || !s->listener_id || st->ended)
        return true;
    for (size_t i = 0; i < v->count; i++)
        if (v->sums[i].listener_id == s->listener_id) {
            v->sums[i].open++;
            v->sums[i].to_peer += s->bytes_to_peer;
            v->sums[i].from_peer += s->bytes_from_peer;
            return true;
        }
    if (v->count < MESH_TUNNEL_LISTENERS_MAX)
        v->sums[v->count++] = (struct tunnel_live_sum){s->listener_id, 1,
                                                       s->bytes_to_peer,
                                                       s->bytes_from_peer};
    return true;
}

size_t mesh_tunnel_list(struct mesh_tunnel_row *out, size_t cap,
                        size_t *total)
{
    struct tunnel_list_visit live;
    memset(&live, 0, sizeof(live));
    mesh_stream_visit(MESH_TUNNEL_SERVICE_NAME, tunnel_list_visit, &live);
    size_t written = 0, seen = 0;
    tunnel_lock();
    for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++) {
        struct mesh_tunnel_listener *l = &g_listeners[i];
        if (!l->used)
            continue;
        seen++;
        if (!out || written >= cap)
            continue;
        struct mesh_tunnel_row *row = &out[written++];
        memset(row, 0, sizeof(*row));
        row->tunnel_id = l->id;
        snprintf(row->peer, sizeof(row->peer), "%s", l->peer);
        row->remote_port = l->remote_port;
        row->local_port = l->local_port;
        row->streams_total = l->streams_total;
        row->bytes_to_peer = l->bytes_to_peer;
        row->bytes_from_peer = l->bytes_from_peer;
        row->opened_unix = l->opened_unix;
        for (size_t j = 0; j < live.count; j++)
            if (live.sums[j].listener_id == l->id) {
                row->streams_open = live.sums[j].open;
                row->bytes_to_peer += live.sums[j].to_peer;
                row->bytes_from_peer += live.sums[j].from_peer;
            }
    }
    tunnel_unlock();
    if (total)
        *total = seen;
    return written;
}

enum mesh_tunnel_refusal mesh_tunnel_allow(const char *peer_pairing_id,
                                           uint16_t port, const char *why)
{
    uint8_t raw[32];
    if (!peer_pairing_id || strlen(peer_pairing_id) != 64 ||
        !zcl_hex_decode_lower(peer_pairing_id, raw, 32) || port == 0)
        return MESH_TUNNEL_REFUSED_MALFORMED;
    tunnel_lock();
    if (!g_allow_loaded)
        tunnel_allow_load_locked();
    struct mesh_tunnel_allow_row *slot = NULL;
    for (size_t i = 0; i < g_allow_count; i++)
        if (g_allow[i].port == port &&
            strncmp(g_allow[i].peer, peer_pairing_id, 64) == 0)
            slot = &g_allow[i];
    if (!slot && g_allow_count >= MESH_TUNNEL_ALLOW_MAX) {
        tunnel_unlock();
        return MESH_TUNNEL_REFUSED_CAP;
    }
    if (!slot)
        slot = &g_allow[g_allow_count++];
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->peer, sizeof(slot->peer), "%s", peer_pairing_id);
    slot->port = port;
    snprintf(slot->why, sizeof(slot->why), "%s", why ? why : "");
    for (char *c = slot->why; *c; c++)
        if (*c == '\n' || *c == '\r')
            *c = ' ';
    bool ok = tunnel_allow_persist_locked();
    tunnel_unlock();
    return ok ? MESH_TUNNEL_OK : MESH_TUNNEL_REFUSED_UNAVAILABLE;
}

bool mesh_tunnel_deny(const char *peer_pairing_id, uint16_t port)
{
    if (!peer_pairing_id || strlen(peer_pairing_id) != 64)
        return false;
    tunnel_lock();
    if (!g_allow_loaded)
        tunnel_allow_load_locked();
    bool removed = false;
    for (size_t i = 0; i < g_allow_count;) {
        if (g_allow[i].port == port &&
            strncmp(g_allow[i].peer, peer_pairing_id, 64) == 0) {
            g_allow[i] = g_allow[--g_allow_count];
            memset(&g_allow[g_allow_count], 0, sizeof(g_allow[0]));
            removed = true;
            continue;
        }
        i++;
    }
    bool ok = removed && tunnel_allow_persist_locked();
    tunnel_unlock();
    return ok;
}

size_t mesh_tunnel_allow_list(struct mesh_tunnel_allow_row *out, size_t cap,
                              size_t *total)
{
    tunnel_lock();
    if (!g_allow_loaded)
        tunnel_allow_load_locked();
    size_t written = 0;
    for (size_t i = 0; i < g_allow_count; i++) {
        if (!out || written >= cap)
            break;
        out[written++] = g_allow[i];
    }
    if (total)
        *total = g_allow_count;
    tunnel_unlock();
    return written;
}

/* ── Lifecycle ───────────────────────────────────────────────────────── */

void mesh_tunnel_wire(struct boot_svc_ctx *svc)
{
    if (g_tun_svc) {
        LOG_ERROR(TUN_TAG, "wire: already wired");
        return;
    }
    g_tun_svc = svc;
    tunnel_lock();
    memset(g_listeners, 0, sizeof(g_listeners));
    tunnel_allow_load_locked();
    size_t rows = g_allow_count;
    tunnel_unlock();
    LOG_INFO(TUN_TAG,
             "tunnel service armed; the allow table admits only what it "
             "names (rows read: %zu)", rows);

    g_tun_registered = tunnel_register_service();
    if (!g_tun_registered) {
        LOG_ERROR(TUN_TAG, "tunnel stream service refused");
        return;
    }
    liveness_contract_init(&g_tun_contract, "net.mesh_tunnel_listeners");
    g_tun_contract.on_tick = tunnel_listener_tick;
    supervisor_domains_init();
    g_tun_child = supervisor_register_in_domain(g_net_sup, &g_tun_contract);
    if (g_tun_child == SUPERVISOR_INVALID_ID) {
        LOG_ERROR(TUN_TAG, "listener supervisor register failed");
        return;
    }
    supervisor_set_period(g_tun_child, 1);
    /* The same cadence the stream pump runs at: a local connect is
     * answered inside one beat, and the beat does nothing when the
     * operator has opened no listener. */
    g_tun_contract.period_us = 100000;
    supervisor_request_min_tick_ms(100);
    supervisor_set_deadline(g_tun_child, 30);
    supervisor_set_progress_exempt(g_tun_child,
                                   "an operator may never open a tunnel");
}

void mesh_tunnel_shutdown(void)
{
    supervisor_child_id child = g_tun_child;
    g_tun_child = SUPERVISOR_INVALID_ID;
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_unregister(child);
    if (g_tun_registered)
        mesh_stream_service_unregister(MESH_TUNNEL_SERVICE_NAME);
    g_tun_registered = false;
    tunnel_lock();
    for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++)
        if (g_listeners[i].used)
            tunnel_socket_drop(&g_listeners[i].sock);
    memset(g_listeners, 0, sizeof(g_listeners));
    memset(g_allow, 0, sizeof(g_allow));
    g_allow_count = 0;
    g_allow_loaded = false;
    tunnel_unlock();
    g_tun_svc = NULL;
}

#ifdef ZCL_TESTING
void mesh_tunnel_test_bind(struct boot_svc_ctx *svc)
{
    if (!svc) {
        if (g_tun_registered)
            mesh_stream_service_unregister(MESH_TUNNEL_SERVICE_NAME);
        g_tun_registered = false;
        g_tun_svc = NULL;
        return;
    }
    g_tun_svc = svc;
    tunnel_lock();
    tunnel_allow_load_locked();
    tunnel_unlock();
    if (!g_tun_registered)
        g_tun_registered = tunnel_register_service();
}

void mesh_tunnel_test_reset(void)
{
    tunnel_lock();
    for (size_t i = 0; i < MESH_TUNNEL_LISTENERS_MAX; i++)
        if (g_listeners[i].used)
            tunnel_socket_drop(&g_listeners[i].sock);
    memset(g_listeners, 0, sizeof(g_listeners));
    memset(g_allow, 0, sizeof(g_allow));
    g_allow_count = 0;
    g_allow_loaded = false;
    g_next_tunnel_id = 1;
    tunnel_unlock();
}

struct tunnel_tick_visit {
    int64_t now;
};

static bool tunnel_tick_visit(struct mesh_stream *st, void *ctx)
{
    struct tunnel_tick_visit *v = ctx;
    if (!st->ended)
        tunnel_stream_tick(st, v->now);
    return true;
}

void mesh_tunnel_test_tick(int64_t now_unix)
{
    tunnel_listener_beat();
    struct tunnel_tick_visit v = {now_unix};
    mesh_stream_visit(MESH_TUNNEL_SERVICE_NAME, tunnel_tick_visit, &v);
}
#endif
