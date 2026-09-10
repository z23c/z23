/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Accept beta6 bootstrap clients and answer the eight snapshot messages.
 *
 * A beta6 client drives its fast-sync over a DEDICATED socket outside its own
 * CNode peer set (bootstrap.cpp:1666-1712, 3183-3372): connect, a plain
 * version/verack handshake that must show NODE_BOOTSTRAP, then getbsman/bsman
 * followed by pipelined getbschk/bschk. It opens up to -bootstrapstreams (4 by
 * default) such sockets in parallel and requires every stream to serve a
 * byte-identical manifest.
 *
 * Two properties of the client are contract for this loop:
 *  - chunk replies must come back in REQUEST ORDER (it pops its in-flight
 *    deque front-first and compares file/offset/length, bootstrap.cpp:1512-1519),
 *    so this serves one connection strictly sequentially;
 *  - a stream that delivers under 32 KiB/s for a full 60 s window is aborted
 *    (bootstrap.cpp:184-210), so a refusal must be answered promptly rather
 *    than stalled.
 *
 * Everything served comes from the already-armed, already-hashed manifest; the
 * source tree is opened read-only and this module never writes to it.
 *
 * // supervisor-ok:owned-optout-listener — this service owns its own lifecycle
 * and there is nothing for a supervisor to restart: it exists only while an
 * operator has named BOTH a snapshot directory and a listen address, it holds
 * no state a stall could corrupt (every reply is a bounded read of an
 * immutable, already-hashed manifest), and beta6_bs_listen_stop() shuts down
 * the accept socket and every session socket and then joins all of those
 * threads. A dead listener degrades exactly to the pre-existing behaviour —
 * beta6 clients fall back to ordinary P2P sync — so restarting it blindly
 * would be less honest than leaving it stopped and reporting it stopped
 * through `beta6_snapshot_bootstrap.serving`.
 */
#include "services/beta6_bootstrap.h"

#include "core/hash.h"
#include "platform/socket_compat.h"
#include "base/safe_alloc.h"
#include "base/log_macros.h"
#include "util/sync.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define BETA6_MSG_HEADER_SIZE 24
#define BETA6_COMMAND_SIZE 12
#define BETA6_IO_TIMEOUT_MS 120000
#define BETA6_MAX_SESSIONS 16
/* version.h:12,21 — a beta6 client refuses a peer below MIN_PEER_PROTO_VERSION
 * and reads our version payload at INIT_PROTO_VERSION, where CAddress carries
 * no nTime. */
#define BETA6_PROTOCOL_VERSION 170011
#define BETA6_NODE_NETWORK (1ULL << 0)
#define BETA6_NODE_BOOTSTRAP (1ULL << 24)

struct beta6_listener {
    platform_socket_t socket;
    pthread_t thread;
    bool running;
    bool stopping;
    uint16_t port;
    unsigned char magic[4];
    char network[BETA6_BS_MAX_NETWORK_LEN];
    char params_dir[4096];
    /* The manifest is immutable while armed, so its wire bytes are encoded
     * once and every stream is served the same buffer — which is also what
     * makes the client's cross-stream manifest-equality check pass. */
    unsigned char *manifest_bytes;
    size_t manifest_len;
};

struct beta6_session {
    platform_socket_t socket;
    struct beta6_listener *listener;
    char peer_ip[64];
    char quota_key[80];
    int slot;
};

/* One row per live session, and the thread is JOINABLE rather than detached.
 * A detached download thread would still be reading g_listener.manifest_bytes
 * after beta6_bs_listen_stop() freed it, so shutdown shuts each session socket
 * down and joins its thread before releasing anything it can reach. A finished
 * row stays occupied until something joins it: the next accept reaps them
 * lazily, and stop() reaps whatever is left. */
struct beta6_session_slot {
    bool used;
    bool finished;
    platform_socket_t socket;
    pthread_t tid;
};

static struct beta6_listener g_listener;
static zcl_mutex_t g_session_lock;
static bool g_session_lock_ready;
static struct beta6_session_slot g_sessions[BETA6_MAX_SESSIONS];

static void session_lock_init_once(void)
{
    if (!g_session_lock_ready) {
        zcl_mutex_init(&g_session_lock);
        g_session_lock_ready = true;
    }
}

/* ── framing ─────────────────────────────────────────────────────────── */

static bool send_message(struct beta6_session *session, const char *command,
                         const unsigned char *payload, size_t payload_len)
{
    if (payload_len > BETA6_BS_MAX_MESSAGE_LEN)
        return false;
    unsigned char header[BETA6_MSG_HEADER_SIZE];
    memset(header, 0, sizeof(header));
    memcpy(header, session->listener->magic, 4);
    size_t command_len = strlen(command);
    if (command_len > BETA6_COMMAND_SIZE)
        return false;
    memcpy(header + 4, command, command_len);
    uint32_t size = (uint32_t)payload_len;
    memcpy(header + 16, &size, 4);

    unsigned char digest[32];
    hash256(payload ? payload : (const unsigned char *)"", payload_len, digest);
    memcpy(header + 20, digest, 4);

    if (!platform_socket_send_all(session->socket, header, sizeof(header)))
        return false;
    if (payload_len == 0)
        return true;
    return platform_socket_send_all(session->socket, payload, payload_len);
}

static bool receive_exact(platform_socket_t socket, unsigned char *out, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int part = platform_socket_receive(socket, out + got, len - got);
        if (part <= 0)
            return false;
        got += (size_t)part;
    }
    return true;
}

/* Read one framed message. `payload` is caller-freed on success. */
static bool receive_message(platform_socket_t socket, const unsigned char magic[4],
                            char command[BETA6_COMMAND_SIZE + 1], unsigned char **payload,
                            size_t *payload_len)
{
    unsigned char header[BETA6_MSG_HEADER_SIZE];
    if (!receive_exact(socket, header, sizeof(header)))
        return false;
    if (memcmp(header, magic, 4) != 0)
        return false;
    memcpy(command, header + 4, BETA6_COMMAND_SIZE);
    command[BETA6_COMMAND_SIZE] = '\0';

    uint32_t size = 0;
    memcpy(&size, header + 16, 4);
    if (size > BETA6_BS_MAX_MESSAGE_LEN)
        return false;

    unsigned char *body = NULL;
    if (size > 0) {
        body = zcl_malloc(size, "beta6 bootstrap message body");
        if (!body)
            return false;
        if (!receive_exact(socket, body, size)) {
            free(body);
            return false;
        }
    }
    unsigned char digest[32];
    hash256(body ? body : (const unsigned char *)"", size, digest);
    if (memcmp(digest, header + 20, 4) != 0) {
        free(body);
        return false;
    }
    *payload = body;
    *payload_len = size;
    return true;
}

/* ── handshake ───────────────────────────────────────────────────────── */

/* A CAddress read at INIT_PROTO_VERSION: services + 16-byte IP + big-endian
 * port, with no nTime (protocol.h:100-118, nVersion 209 < CADDR_TIME_VERSION). */
static bool write_address(struct byte_stream *out, uint64_t services)
{
    unsigned char ip[16] = { 0 };
    return stream_write_u64_le(out, services) && stream_write_bytes(out, ip, sizeof(ip)) &&
           stream_write_u8(out, 0) && stream_write_u8(out, 0);
}

static bool send_version(struct beta6_session *session)
{
    struct byte_stream payload;
    stream_init(&payload, 256);
    const char *user_agent = "/ZClassic23-beta6-bootstrap/";
    uint64_t services = BETA6_NODE_NETWORK | BETA6_NODE_BOOTSTRAP;
    bool ok = stream_write_i32_le(&payload, BETA6_PROTOCOL_VERSION) &&
              stream_write_u64_le(&payload, services) &&
              stream_write_i64_le(&payload, (int64_t)time(NULL)) &&
              write_address(&payload, services) && write_address(&payload, services) &&
              stream_write_u64_le(&payload, 0) &&
              stream_write_compact_size(&payload, strlen(user_agent)) &&
              stream_write_bytes(&payload, (const unsigned char *)user_agent,
                                 strlen(user_agent)) &&
              stream_write_i32_le(&payload, 0) && stream_write_u8(&payload, 1);
    if (ok)
        ok = send_message(session, "version", payload.data, payload.size);
    if (ok)
        ok = send_message(session, "verack", NULL, 0);
    stream_free(&payload);
    return ok;
}

/* ── serve handlers ──────────────────────────────────────────────────── */

static bool serve_snapshot_manifest(struct beta6_session *session)
{
    const struct beta6_listener *listener = session->listener;
    if (!listener->manifest_bytes)
        return send_message(session, "reject", NULL, 0);
    return send_message(session, "bsman", listener->manifest_bytes, listener->manifest_len);
}

static bool serve_param_manifest(struct beta6_session *session)
{
    struct beta6_bs_manifest manifest;
    char err[256] = { 0 };
    if (!beta6_bs_param_manifest(session->listener->params_dir, session->listener->network,
                                 &manifest, err, sizeof(err))) {
        LOG_INFO("beta6boot", "peer %s: no zcash params to serve: %s", session->peer_ip, err);
        return send_message(session, "reject", NULL, 0);
    }
    struct byte_stream out;
    stream_init(&out, 4096);
    bool ok = beta6_bs_manifest_encode(&manifest, &out) &&
              send_message(session, "bspman", out.data, out.size);
    stream_free(&out);
    beta6_bs_manifest_free(&manifest);
    return ok;
}

/* Charge the per-address quota and, when the bucket is over its cap and
 * throttling is on, wait out the spacing gap rather than dropping the peer. */
static bool quota_gate(struct beta6_session *session, uint32_t bytes)
{
    for (int attempt = 0; attempt < 64; attempt++) {
        bool stop = false;
        int64_t now_ms = (int64_t)time(NULL) * 1000;
        if (beta6_bs_quota_allow(session->quota_key, false, now_ms, &stop)) {
            beta6_bs_quota_charge(session->quota_key, false, now_ms, bytes);
            return true;
        }
        if (stop)
            return false;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    return false;
}

static bool serve_chunk(struct beta6_session *session, const unsigned char *payload,
                        size_t payload_len, bool params)
{
    struct byte_stream in;
    stream_init_from_data(&in, payload, payload_len);
    struct beta6_bs_chunk_request request;
    bool decoded = beta6_bs_chunk_request_decode(&in, &request) && stream_remaining(&in) == 0;
    stream_free(&in);
    const char *command = params ? "getbspchk" : "getbschk";
    if (!decoded || request.length == 0 || request.length > BETA6_BS_CHUNK_SIZE) {
        LOG_INFO("beta6boot", "peer %s: malformed %s", session->peer_ip, command);
        return false;
    }
    if (!quota_gate(session, request.length)) {
        LOG_INFO("beta6boot", "peer %s: %s refused, over the daily serve cap",
                 session->peer_ip, command);
        return send_message(session, "reject", NULL, 0);
    }

    unsigned char *data = zcl_malloc(request.length, "beta6 bootstrap chunk");
    if (!data)
        return false;
    char err[256] = { 0 };
    bool ok = params ? beta6_bs_read_param_chunk(session->listener->params_dir,
                                                 session->listener->network, &request, data,
                                                 request.length, err, sizeof(err))
                     : beta6_bs_read_chunk(&request, data, request.length, err, sizeof(err));
    if (!ok) {
        LOG_INFO("beta6boot", "peer %s: %s refused: %s", session->peer_ip, command, err);
        free(data);
        return send_message(session, "reject", NULL, 0);
    }

    struct byte_stream out;
    stream_init(&out, request.length + 32);
    ok = beta6_bs_chunk_encode(request.file_index, request.offset, data, request.length,
                               &out) &&
         send_message(session, params ? "bspchk" : "bschk", out.data, out.size);
    stream_free(&out);
    free(data);
    return ok;
}

static bool dispatch(struct beta6_session *session, const char *command,
                     const unsigned char *payload, size_t payload_len)
{
    if (strcmp(command, "version") == 0)
        return send_version(session);
    if (strcmp(command, "verack") == 0)
        return true;
    if (strcmp(command, "getbsman") == 0)
        return serve_snapshot_manifest(session);
    if (strcmp(command, "getbspman") == 0)
        return serve_param_manifest(session);
    if (strcmp(command, "getbschk") == 0)
        return serve_chunk(session, payload, payload_len, false);
    if (strcmp(command, "getbspchk") == 0)
        return serve_chunk(session, payload, payload_len, true);
    /* Anything else is not this service's business; a beta6 bootstrap socket
     * sends nothing else, and ignoring keeps an accidental ordinary peer from
     * being answered as if it were one. */
    return true;
}

static void *session_thread(void *opaque)
{
    struct beta6_session *session = opaque;
    platform_socket_set_receive_timeout(session->socket, BETA6_IO_TIMEOUT_MS);
    platform_socket_set_send_timeout(session->socket, BETA6_IO_TIMEOUT_MS);

    while (!g_listener.stopping) {
        char command[BETA6_COMMAND_SIZE + 1];
        unsigned char *payload = NULL;
        size_t payload_len = 0;
        if (!receive_message(session->socket, session->listener->magic, command, &payload,
                             &payload_len))
            break;
        bool ok = dispatch(session, command, payload, payload_len);
        free(payload);
        if (!ok)
            break;
    }

    /* Retire the socket under the lock and publish `finished` last, so a
     * concurrent stop() either sees a live socket it may shut down or a
     * finished row it may only join — never a descriptor number this thread
     * has already closed. */
    LOCK(g_session_lock);
    platform_socket_shutdown_both(g_sessions[session->slot].socket);
    platform_socket_close(g_sessions[session->slot].socket);
    g_sessions[session->slot].socket = PLATFORM_SOCKET_INVALID;
    g_sessions[session->slot].finished = true;
    UNLOCK(g_session_lock);
    free(session);
    return NULL;
}

/* ── accept loop ─────────────────────────────────────────────────────── */

/* Join and free every row whose thread has already returned. Caller holds the
 * session lock; the join is done outside it because a finished thread cannot
 * need the lock again. */
static void sessions_reap_finished_locked(void)
{
    for (int i = 0; i < BETA6_MAX_SESSIONS; i++) {
        if (!g_sessions[i].used || !g_sessions[i].finished)
            continue;
        pthread_t tid = g_sessions[i].tid;
        UNLOCK(g_session_lock);
        pthread_join(tid, NULL);
        LOCK(g_session_lock);
        g_sessions[i].used = false;
        g_sessions[i].finished = false;
    }
}

/* Reserve a session row, reaping finished ones first. Returns its index, or
 * -1 when BETA6_MAX_SESSIONS clients are already being served. */
static int session_slot_take(platform_socket_t socket)
{
    session_lock_init_once();
    LOCK(g_session_lock);
    sessions_reap_finished_locked();
    int slot = -1;
    for (int i = 0; i < BETA6_MAX_SESSIONS && slot < 0; i++) {
        if (!g_sessions[i].used)
            slot = i;
    }
    if (slot >= 0) {
        g_sessions[slot].used = true;
        g_sessions[slot].finished = false;
        g_sessions[slot].socket = socket;
    }
    UNLOCK(g_session_lock);
    return slot;
}

/* Give a reserved row back without a thread ever having run in it. */
static void session_slot_abandon(int slot)
{
    LOCK(g_session_lock);
    g_sessions[slot].used = false;
    g_sessions[slot].socket = PLATFORM_SOCKET_INVALID;
    UNLOCK(g_session_lock);
}

static void spawn_session(platform_socket_t accepted, const struct sockaddr_in *from)
{
    int slot = session_slot_take(accepted);
    if (slot < 0) {
        platform_socket_close(accepted);
        return;
    }
    struct beta6_session *session = zcl_calloc(1, sizeof(*session), "beta6 bootstrap session");
    if (!session) {
        session_slot_abandon(slot);
        platform_socket_close(accepted);
        return;
    }
    session->socket = accepted;
    session->listener = &g_listener;
    session->slot = slot;
    if (!platform_socket_format_address(AF_INET, &from->sin_addr, session->peer_ip,
                                        sizeof(session->peer_ip)))
        snprintf(session->peer_ip, sizeof(session->peer_ip), "unknown");
    if (!beta6_bs_quota_key(session->peer_ip, session->quota_key,
                            sizeof(session->quota_key)))
        snprintf(session->quota_key, sizeof(session->quota_key), "unknown");

    if (thread_registry_spawn("beta6-bs-session", session_thread, session,
                              &g_sessions[slot].tid) != 0) {
        session_slot_abandon(slot);
        platform_socket_close(accepted);
        free(session);
    }
}

/* Shut every live session socket down, then join every session thread. Called
 * only after the accept thread has stopped, so no new row can appear. */
static void sessions_stop_all(void)
{
    LOCK(g_session_lock);
    for (int i = 0; i < BETA6_MAX_SESSIONS; i++) {
        if (g_sessions[i].used && !g_sessions[i].finished &&
            g_sessions[i].socket != PLATFORM_SOCKET_INVALID)
            platform_socket_shutdown_both(g_sessions[i].socket);
    }
    for (int i = 0; i < BETA6_MAX_SESSIONS; i++) {
        if (!g_sessions[i].used)
            continue;
        pthread_t tid = g_sessions[i].tid;
        UNLOCK(g_session_lock);
        pthread_join(tid, NULL);
        LOCK(g_session_lock);
        g_sessions[i].used = false;
        g_sessions[i].finished = false;
    }
    UNLOCK(g_session_lock);
}

static void *accept_thread(void *opaque)
{
    (void)opaque;
    while (!g_listener.stopping) {
        struct sockaddr_in from;
        size_t from_size = sizeof(from);
        platform_socket_t accepted =
            platform_socket_accept(g_listener.socket, (struct sockaddr *)&from, &from_size);
        if (accepted == PLATFORM_SOCKET_INVALID) {
            if (g_listener.stopping)
                break;
            continue;
        }
        spawn_session(accepted, &from);
    }
    return NULL;
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

static bool encode_cached_manifest(char *err, size_t err_size)
{
    const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
    struct byte_stream out;
    stream_init(&out, 65536);
    if (!beta6_bs_manifest_encode(manifest, &out)) {
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
    g_listener.manifest_bytes = zcl_malloc(out.size, "beta6 bootstrap manifest");
    if (!g_listener.manifest_bytes) {
        stream_free(&out);
        snprintf(err, err_size, "out of memory encoding the beta6 bootstrap manifest");
        return false;
    }
    memcpy(g_listener.manifest_bytes, out.data, out.size);
    g_listener.manifest_len = out.size;
    stream_free(&out);
    return true;
}

static bool bind_listen_socket(const char *bind_ip, uint16_t port, char *err,
                               size_t err_size)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (platform_socket_parse_address(AF_INET, bind_ip, &address.sin_addr) != 1) {
        snprintf(err, err_size, "beta6 bootstrap listen address is not an IPv4 address");
        return false;
    }
    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0, false, true);
    if (sock == PLATFORM_SOCKET_INVALID) {
        snprintf(err, err_size, "could not create the beta6 bootstrap listen socket");
        return false;
    }
    platform_socket_set_reuse_address(sock, 1);
    if (platform_socket_bind(sock, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        platform_socket_listen(sock, 16) != 0) {
        platform_socket_close(sock);
        snprintf(err, err_size, "could not bind the beta6 bootstrap listen port");
        return false;
    }
    g_listener.socket = sock;
    g_listener.port = port;
    return true;
}

bool beta6_bs_listen_start(const char *bind_ip, uint16_t port, const unsigned char magic[4],
                           const char *network, const char *params_dir, char *err,
                           size_t err_size)
{
    if (g_listener.running) {
        snprintf(err, err_size, "the beta6 bootstrap listener is already running");
        return false;
    }
    if (!beta6_bs_is_armed()) {
        snprintf(err, err_size,
                 "the beta6 bootstrap service is not armed; set -beta6-bootstrap-source");
        return false;
    }
    if (!bind_ip || !magic || !network) {
        snprintf(err, err_size, "the beta6 bootstrap listener needs an address and network");
        return false;
    }

    memset(&g_listener, 0, sizeof(g_listener));
    memcpy(g_listener.magic, magic, 4);
    snprintf(g_listener.network, sizeof(g_listener.network), "%s", network);
    snprintf(g_listener.params_dir, sizeof(g_listener.params_dir), "%s",
             params_dir ? params_dir : "");
    if (!encode_cached_manifest(err, err_size))
        return false;
    if (!bind_listen_socket(bind_ip, port, err, err_size)) {
        free(g_listener.manifest_bytes);
        g_listener.manifest_bytes = NULL;
        return false;
    }

    session_lock_init_once();
    g_listener.running = true;
    if (thread_registry_spawn("beta6-bs-accept", accept_thread, NULL,
                              &g_listener.thread) != 0) {
        g_listener.running = false;
        platform_socket_close(g_listener.socket);
        free(g_listener.manifest_bytes);
        g_listener.manifest_bytes = NULL;
        snprintf(err, err_size, "could not start the beta6 bootstrap accept thread");
        return false;
    }
    LOG_INFO("beta6boot", "serving beta6 bootstrap snapshots on %s:%u from %s", bind_ip,
             (unsigned)port, beta6_bs_source_dir());
    return true;
}

void beta6_bs_listen_stop(void)
{
    if (!g_listener.running)
        return;
    g_listener.stopping = true;
    platform_socket_shutdown_both(g_listener.socket);
    platform_socket_close(g_listener.socket);
    pthread_join(g_listener.thread, NULL);
    sessions_stop_all();
    free(g_listener.manifest_bytes);
    g_listener.manifest_bytes = NULL;
    g_listener.running = false;
    g_listener.stopping = false;
}

bool beta6_bs_listen_running(void)
{
    return g_listener.running;
}

uint16_t beta6_bs_listen_port(void)
{
    return g_listener.running ? g_listener.port : 0;
}
