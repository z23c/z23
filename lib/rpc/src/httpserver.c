/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "rpc/httpserver.h"
#include "rpc/http_middleware.h"
#include <sys/stat.h>
#include "rpc/rpc_timeout.h"
#include "net/ws_events.h"
#include "json/json.h"
#include "rpc/protocol.h"
#include "core/random.h"
#include "encoding/utilstrencodings.h"
#include "metrics/prometheus_metrics.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/trace.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"

#define RPC_HTTP_WORKERS 4
#define RPC_HTTP_QUEUE_CAP 64

/* Upper bound on a single serialized JSON-RPC response body. Generous
 * enough for the largest legitimate responses (gettxoutsetinfo, a full
 * listunspent / getrawmempool true) while bounding the one-shot
 * allocation an authenticated client can drive. A response that would
 * exceed this returns a proper RPC error envelope instead of a partial
 * or out-of-band send. */
#define RPC_HTTP_MAX_RESP_BYTES ((size_t)128 * 1024 * 1024)

/* ── SINGLE-OWNER INVARIANT for accepted sockets ───────────────────
 *
 * Every accepted fd has exactly ONE owner at every instant, and no
 * owner may hold it without a deadline. The owners, in order:
 *
 *   1. the listener      accept() → enqueue_client() succeeds
 *   2. the client queue  enqueue_client() → dequeue_client()
 *   3. a worker          dequeue_client() → handle_client()'s done:
 *   4. ws_events         after a successful /events upgrade
 *
 * The queue is a WAITING ROOM, not a resource pool. It must never be
 * the reason the server refuses work, so before it reports itself
 * full it surrenders every entry it is no longer entitled to own: a
 * peer that has hung up with nothing to serve, or an entry that has
 * waited past RPC_HTTP_QUEUE_WAIT_MS.
 *
 * Why this exists: g_client_queue_count used to be a one-way ratchet.
 * Its only decrementer was a worker returning from handle_client(),
 * and handle_client() dispatches into the node — a wedged RPC method,
 * or a client that stops reading a large response (there was no send
 * deadline either), parks a worker forever. Four such workers pinned
 * the count at RPC_HTTP_QUEUE_CAP for the life of the process: every
 * later client got an instant 503 "RPC server busy" while the listener
 * thread sat healthily in accept(), and every queued fd stayed open in
 * CLOSE-WAIT with its unread request still in the receive queue,
 * because the only owner that could ever close it never arrived. A
 * long-running node's RPC front door died and never came back.
 *
 * With the rules below the worst case is bounded by the residency
 * deadline, not by the process lifetime. */

/* How long a connection may sit in the admission queue before the
 * queue gives it up. Defaults to the per-request watchdog budget
 * (rpc_timeout's 10 s): a request that has not even been READ within
 * the whole time it was allowed to RUN is past any client's patience,
 * and its slot is worth more than its fd. 0 disables age-based
 * reclaim (hang-up reclaim still runs). Operators tune with
 * ZCL_RPC_QUEUE_WAIT_MS. */
#define RPC_HTTP_QUEUE_WAIT_MS_DEFAULT 10000

/* Socket deadlines for a served connection. SO_RCVTIMEO bounds
 * slowloris; SO_SNDTIMEO bounds the mirror attack — a client that
 * sends a request and then stops reading, which otherwise parks a
 * worker in write() with no deadline of its own. The rpc_timeout
 * watchdog is not a substitute: it fails open when its 128 slots are
 * exhausted and is disabled outright by ZCL_RPC_TIMEOUT_MS=0. */
#define RPC_HTTP_SOCKET_TIMEOUT_SEC 5

/* ── Connection abstraction for plain + TLS ───────────────────────── */

struct rpc_conn {
    int     fd;
    SSL    *ssl;         /* NULL for plain-text connections */
    int64_t admitted_us; /* monotonic stamp set by enqueue_client() */
};

static int g_listen_fd = -1;
static const struct rpc_table *g_table = NULL;
static pthread_t g_listen_thread;
static bool g_listen_thread_started = false;
/* g_running coordinates the listener + worker threads with rpc_http_stop().
 * volatile is *not* a thread-synchronization primitive in C (it's for MMIO
 * and signal handlers); reads/writes across threads need atomic semantics
 * for memory ordering. The shutdown path also broadcasts g_client_queue_cond
 * after flipping this, so workers in dequeue_client wake; this atomic is
 * belt-and-suspenders for any other read sites. */
static _Atomic bool g_running = false;
static struct rpc_http_middleware g_middleware;
static bool g_middleware_active = false;
static struct rpc_timeout_mgr g_rpc_timeout;
static bool g_rpc_timeout_active = false;
static char g_rpc_user[128];
static char g_rpc_password[128];
static char g_rpc_password_prev[128];  /* previous cookie — valid until next rotation */
static char g_cookie_file[1024];
static bool g_auth_required = false;
static bool g_cookie_mode = false;     /* true when using generated cookie (not explicit user/pass) */
static pthread_mutex_t g_cookie_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_cookie_rotate_thread;
static bool g_cookie_rotate_started = false;
static int g_cookie_rotate_sec = 86400; /* default 24h, env ZCL_RPC_COOKIE_ROTATE_SEC */
/* Prometheus /metrics HTTP endpoint. Off by default; an operator
 * sets ZCL_METRICS_HTTP_ENABLE=1 to expose the metrics renderer. Gated behind
 * the same RPC Basic-auth
 * cookie the wallet endpoints use. Prometheus `scrape_configs`
 * supports `basic_auth: { username_file: ..., password_file: ... }` —
 * point
 * those at the two halves of `~/.zclassic-c23/.cookie` and the
 * scraper authenticates exactly like `zclassic-cli`. Previously the
 * endpoint was open by design, exposing peer counts / tx volume /
 * mempool size to anyone who could reach the TLS listener — usable
 * for network fingerprinting. The HTTP middleware (rate-limit + ban
 * + loopback bypass) still runs first, unchanged. */
static bool g_metrics_http_enable = false;
static pthread_t g_worker_threads[RPC_HTTP_WORKERS];
static size_t g_workers_started = 0;
static struct rpc_conn g_client_queue[RPC_HTTP_QUEUE_CAP];
static size_t g_client_queue_head = 0;
static size_t g_client_queue_tail = 0;
static size_t g_client_queue_count = 0;
static pthread_mutex_t g_client_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_client_queue_cond = PTHREAD_COND_INITIALIZER;
/* Residency deadline in ms; see RPC_HTTP_QUEUE_WAIT_MS_DEFAULT. Read
 * and written under g_client_queue_mutex. */
static int g_client_queue_wait_ms = RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
/* Admission accounting. Without these the ratchet was silent: the
 * front door reported "busy" with nothing anywhere saying how deep the
 * queue was or how long its head had been rotting. All under
 * g_client_queue_mutex. */
static size_t   g_client_queue_peak = 0;
static uint64_t g_client_admitted = 0;
static uint64_t g_client_reclaimed_hangup = 0;
static uint64_t g_client_reclaimed_stale = 0;
static uint64_t g_client_rejected_busy = 0;

/* ── TLS state ────────────────────────────────────────────────────── */
static SSL_CTX *g_tls_ctx = NULL;
static int g_tls_listen_fd = -1;
static pthread_t g_tls_listen_thread;
static bool g_tls_listen_thread_started = false;
static uint16_t g_tls_port = 0;

/* Supervisor liveness for the 4 RPC HTTP threads. Root children (not
 * supervisor_register_in_domain(...)): lib/rpc cannot include the app-side
 * supervisors/domains.h without a lib-layering violation — see
 * util/thread_liveness.h ("RPC-timeout" is already listed there as one of
 * the lib/-layer cross-cutting infra threads on this pattern). All four
 * legitimately idle (accept() blocks with no deterministic timeout, the
 * worker pool blocks on a queue condvar, the cookie rotator sleeps on a
 * fixed cadence) so they are liveness-only (no deadline, no progress
 * gate) — present on the tree, heartbeat when they do work, never falsely
 * flagged for a quiet cycle. g_worker_threads spawns RPC_HTTP_WORKERS
 * workers under one name ("zcl_rpc_worker"); they share ONE contract —
 * any worker's heartbeat proves at least one worker loop is alive. */
static struct thread_liveness_child g_rpc_worker_liveness = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_rpc_listen_liveness = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_rpc_tls_liveness    = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_rpc_cookie_liveness = { .id = SUPERVISOR_INVALID_ID };

bool rpc_http_test_build_response_envelope(bool rpc_ok,
                                           const char *method,
                                           struct json_value *rpc_result,
                                           const struct json_value *id,
                                           struct json_value *response)
{
    struct json_value null_err = {0};
    struct json_value null_res = {0};
    bool ok = true;

    if (!rpc_result || !id || !response)
        return false;

    json_init(response);
    json_set_object(response);

    if (rpc_ok) {
        ok = ok && json_push_kv(response, "result", rpc_result);
        json_set_null(&null_err);
        ok = ok && json_push_kv(response, "error", &null_err);
        json_free(&null_err);
    } else {
        json_set_null(&null_res);
        ok = ok && json_push_kv(response, "result", &null_res);
        json_free(&null_res);
        if (rpc_result->type == JSON_OBJ)
            ok = ok && json_push_kv_str(rpc_result, "method",
                                        method ? method : "");
        ok = ok && json_push_kv(response, "error", rpc_result);
    }

    ok = ok && json_push_kv(response, "id", id);
    return ok;
}

/* Both credential buffers in check_auth() below are 512 bytes and both strings
 * are NUL-terminated inside them, so no live length can reach this bound. */
#define RPC_AUTH_CT_BYTES 512u

/* Constant-time comparison to prevent timing attacks on RPC credentials.
 * Returns 0 on match.
 *
 * The loop runs a FIXED RPC_AUTH_CT_BYTES iterations. It used to run
 * min(alen, blen), which made the work — and so the response latency —
 * proportional to the length of the configured credential: an attacker who
 * walks the Basic-auth string from 1 byte upward sees the time stop growing
 * exactly at strlen("user:password"), recovering the secret's length without
 * ever guessing a byte of it. Leaking the length is a small win on its own,
 * but it is precisely what a constant-time compare is supposed to deny, and it
 * shrinks the search space for everything that follows.
 *
 * Reads past either string are replaced by 0 rather than skipped, so the
 * iteration count depends on neither length. The `alen ^ blen` fold still
 * makes any length difference a mismatch, so short-circuiting is unnecessary:
 * both live lengths are < RPC_AUTH_CT_BYTES, hence equal lengths are always
 * fully compared. */
static int constant_time_strcmp(const char *a, size_t alen,
                                 const char *b, size_t blen)
{
    unsigned int diff = (unsigned int)(alen ^ blen);
    for (size_t i = 0; i < RPC_AUTH_CT_BYTES; i++) {
        unsigned char ca = i < alen ? (unsigned char)a[i] : 0u;
        unsigned char cb = i < blen ? (unsigned char)b[i] : 0u;
        diff |= (unsigned int)(ca ^ cb);
    }
    return diff == 0 ? 0 : 1;
}

static bool check_auth(const char *auth_header)
{
    if (!g_auth_required) return true;
    if (!auth_header) return false;

    while (*auth_header == ' ') auth_header++;
    if (strncmp(auth_header, "Basic ", 6) != 0) return false;
    const char *b64 = auth_header + 6;
    while (*b64 == ' ') b64++;

    unsigned char decoded[512];
    size_t dlen = DecodeBase64(b64, decoded, sizeof(decoded) - 1, NULL);
    decoded[dlen] = '\0';

    char expected[512];
    /* constant_time_strcmp() reads a fixed RPC_AUTH_CT_BYTES from each side;
     * bind that bound to the buffers so the two cannot drift apart. */
    static_assert(sizeof decoded >= RPC_AUTH_CT_BYTES, "decoded too small");
    static_assert(sizeof expected >= RPC_AUTH_CT_BYTES, "expected too small");
    pthread_mutex_lock(&g_cookie_mutex);
    snprintf(expected, sizeof(expected), "%s:%s", g_rpc_user, g_rpc_password);
    size_t elen = strlen(expected);
    bool ok = (constant_time_strcmp((const char *)decoded, dlen,
                                    expected, elen) == 0);

    /* Accept previous cookie during rotation transition window */
    if (!ok && g_cookie_mode && g_rpc_password_prev[0]) {
        snprintf(expected, sizeof(expected), "%s:%s",
                 g_rpc_user, g_rpc_password_prev);
        elen = strlen(expected);
        ok = (constant_time_strcmp((const char *)decoded, dlen,
                                   expected, elen) == 0);
    }
    pthread_mutex_unlock(&g_cookie_mutex);

    memory_cleanse(expected, sizeof(expected));
    memory_cleanse(decoded, sizeof(decoded));
    return ok;
}

/* ── I/O wrappers: plain fd or SSL ─────────────────────────────── */

static ssize_t conn_read(const struct rpc_conn *c, void *buf, size_t len)
{
    if (c->ssl)
        return SSL_read(c->ssl, buf, (int)len);
    return read(c->fd, buf, len);
}

static ssize_t conn_write(const struct rpc_conn *c, const void *buf, size_t len)
{
    if (c->ssl)
        return SSL_write(c->ssl, buf, (int)len);
    return write(c->fd, buf, len);
}

/* Send the whole buffer, or give up. A blocking write() with
 * SO_SNDTIMEO set returns SHORT when the window closes mid-transfer,
 * so the send deadline that stops a non-reading client from parking a
 * worker would otherwise truncate a large response into a corrupt
 * reply. The rule here is progress, not wall-clock: any bytes accepted
 * restart the deadline, so a slow-but-live client is served in full
 * however long it takes, and only a client that moves ZERO bytes for a
 * whole RPC_HTTP_SOCKET_TIMEOUT_SEC window is dropped. Returns false
 * when the connection is finished; the caller is already unwinding to
 * done: on any subsequent failure. */
static bool conn_write_all(const struct rpc_conn *c, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;

    while (sent < len) {
        ssize_t w = conn_write(c, p + sent, len - sent);
        if (w > 0) {
            sent += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

/* Cap request-header count so an endless-header stream (a slowloris variant)
 * cannot pin a server thread reading header lines forever. Legitimate
 * RPC/metrics/WebSocket clients send well under this. */
#define HTTP_MAX_REQUEST_HEADERS 512

static bool read_line(const struct rpc_conn *c, char *buf, size_t buflen)
{
    size_t pos = 0;
    while (pos < buflen - 1) {
        char ch;
        ssize_t r = conn_read(c, &ch, 1);
        if (r <= 0) return false;
        if (ch == '\n') {
            if (pos > 0 && buf[pos - 1] == '\r')
                pos--;
            buf[pos] = '\0';
            return true;
        }
        buf[pos++] = ch;
    }
    buf[pos] = '\0';
    return true;
}

static bool read_exact(const struct rpc_conn *c, char *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t r = conn_read(c, buf + total, len - total);
        if (r <= 0) return false;
        total += (size_t)r;
    }
    return true;
}

static void send_response_with_type(const struct rpc_conn *c, int status_code,
                                     const char *status_text,
                                     const char *content_type,
                                     const char *body, size_t body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);
    if (!conn_write_all(c, header, (size_t)hlen))
        return;
    if (body_len > 0)
        (void)conn_write_all(c, body, body_len);
}

static void send_response(const struct rpc_conn *c, int status_code,
                            const char *status_text,
                            const char *body, size_t body_len)
{
    send_response_with_type(c, status_code, status_text,
                            "application/json", body, body_len);
}

static void conn_close(struct rpc_conn *c)
{
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* Abandon a connection without touching the wire. conn_close() sends a
 * TLS close_notify, and SSL_shutdown() is socket I/O that can block for
 * the full SO_SNDTIMEO — unacceptable for a connection dropped while
 * the admission queue's mutex is held. A peer we are refusing to serve
 * is owed no graceful close, so free the SSL object and close the fd. */
static void conn_discard(struct rpc_conn *c)
{
    if (c->ssl) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* Bound both directions of a served socket. Applied to every accepted
 * fd we are about to write to — including the 503 rejection path, where
 * a client that never reads would otherwise wedge the ACCEPT LOOP
 * itself and stop the node taking any new RPC at all. */
static void conn_set_deadlines(int fd)
{
    struct timeval tv = { .tv_sec = RPC_HTTP_SOCKET_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* True when nothing this connection could ever say is still coming:
 * the peer is fully gone (POLLHUP/POLLERR/POLLNVAL), or it is readable
 * only because it hit end-of-file with no bytes buffered. A half-close
 * WITH a complete request pending is legitimate HTTP and is NOT a
 * hang-up — POLLIN plus a peekable byte keeps the connection.
 * Non-blocking by construction: the peek runs only when poll() has
 * already said the socket is readable. */
static bool conn_peer_gone(const struct rpc_conn *c)
{
    if (c->fd < 0)
        return true;

    struct pollfd pfd = { .fd = c->fd, .events = POLLIN, .revents = 0 };
    int r = poll(&pfd, 1, 0);
    if (r < 0)
        return errno != EINTR;   /* a broken poll target is unservable */
    if (r == 0)
        return false;            /* connected, still thinking */
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        return true;
    if (pfd.revents & POLLIN) {
        char probe;
        ssize_t n = recv(c->fd, &probe, 1, MSG_PEEK);
        if (n == 0)
            return true;         /* clean EOF, nothing to serve */
    }
    return false;
}

/* Surrender every queued entry the queue is no longer entitled to own
 * and compact the survivors back into the ring in arrival order.
 * Returns the number of slots reclaimed.
 *
 * Called ONLY from the full-queue branch of enqueue_client(), so it
 * costs nothing on the happy path and is O(RPC_HTTP_QUEUE_CAP) on a
 * path that is already degraded. This is the single-owner rule being
 * enforced, not a background sweep bolted on top of a leak: the queue
 * owns these fds, and an owner that cannot serve them must release
 * them. conn_discard() cannot block, so the mutex hold stays bounded.
 *
 * Caller holds g_client_queue_mutex. */
static size_t queue_reclaim_locked(int64_t now_us)
{
    struct rpc_conn kept[RPC_HTTP_QUEUE_CAP];
    size_t nkept = 0;
    size_t reclaimed = 0;
    int64_t wait_us = (int64_t)g_client_queue_wait_ms * 1000;

    for (size_t i = 0; i < g_client_queue_count; i++) {
        struct rpc_conn c =
            g_client_queue[(g_client_queue_head + i) % RPC_HTTP_QUEUE_CAP];

        if (conn_peer_gone(&c)) {
            g_client_reclaimed_hangup++;
            conn_discard(&c);
            reclaimed++;
            continue;
        }
        if (wait_us > 0 && now_us - c.admitted_us >= wait_us) {
            g_client_reclaimed_stale++;
            conn_discard(&c);
            reclaimed++;
            continue;
        }
        kept[nkept++] = c;
    }

    if (reclaimed > 0) {
        for (size_t i = 0; i < nkept; i++)
            g_client_queue[i] = kept[i];
        g_client_queue_head = 0;
        g_client_queue_tail = nkept % RPC_HTTP_QUEUE_CAP;
        g_client_queue_count = nkept;
    }

    return reclaimed;
}

static bool enqueue_client(struct rpc_conn conn)
{
    bool ok = false;
    size_t reclaimed = 0;

    pthread_mutex_lock(&g_client_queue_mutex);
    if (g_client_queue_count >= RPC_HTTP_QUEUE_CAP)
        reclaimed = queue_reclaim_locked(platform_time_monotonic_us());

    if (g_client_queue_count < RPC_HTTP_QUEUE_CAP) {
        conn.admitted_us = platform_time_monotonic_us();
        g_client_queue[g_client_queue_tail] = conn;
        g_client_queue_tail =
            (g_client_queue_tail + 1) % RPC_HTTP_QUEUE_CAP;
        g_client_queue_count++;
        if (g_client_queue_count > g_client_queue_peak)
            g_client_queue_peak = g_client_queue_count;
        g_client_admitted++;
        ok = true;
        pthread_cond_signal(&g_client_queue_cond);
    } else {
        /* Genuine saturation: RPC_HTTP_QUEUE_CAP clients are all still
         * connected and all still inside the residency deadline. The
         * 503 the caller sends is honest backpressure, and the next
         * admission after the deadline expires clears it. */
        g_client_rejected_busy++;
    }
    pthread_mutex_unlock(&g_client_queue_mutex);

    if (reclaimed > 0) {
        fprintf(stderr,  // obs-ok:helper-context-logged
                "RPC server: admission queue was full; reclaimed %zu "
                "abandoned connection(s)\n", reclaimed);
    }

    return ok;
}

/* Pop the head, or {.fd = -1} when empty. Caller holds
 * g_client_queue_mutex. One popper for the worker path, the test hook,
 * and the shutdown drain — the drain used to carry its own copy of
 * this arithmetic. */
static struct rpc_conn queue_pop_locked(void)
{
    struct rpc_conn conn = { .fd = -1, .ssl = NULL, .admitted_us = 0 };

    if (g_client_queue_count > 0) {
        conn = g_client_queue[g_client_queue_head];
        g_client_queue_head =
            (g_client_queue_head + 1) % RPC_HTTP_QUEUE_CAP;
        g_client_queue_count--;
    }
    return conn;
}

static struct rpc_conn dequeue_client(void)
{
    struct rpc_conn conn;

    pthread_mutex_lock(&g_client_queue_mutex);
    /* Timed wait so a worker never blocks past a shutdown that skipped
     * the cond_broadcast (e.g., an abort path that bypasses
     * rpc_http_stop). 2 s wake is invisible under load — the cond is
     * signaled on each enqueue — and bounded under shutdown. */
    while (g_client_queue_count == 0 && g_running) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 2;
        pthread_cond_timedwait(&g_client_queue_cond, &g_client_queue_mutex,
                               &deadline);
    }

    conn = queue_pop_locked();
    pthread_mutex_unlock(&g_client_queue_mutex);

    return conn;
}

/* ── Admission-queue test surface ──────────────────────────────────
 *
 * Same convention as rpc_http_test_build_response_envelope above:
 * production and the regression test drive the EXACT same admission
 * path, so the single-owner invariant is proved on the real code
 * rather than on a copy of it. */

bool rpc_http_test_queue_admit(int fd)
{
    struct rpc_conn conn = { .fd = fd, .ssl = NULL, .admitted_us = 0 };
    return enqueue_client(conn);
}

int rpc_http_test_queue_take(void)
{
    /* Non-blocking on purpose: dequeue_client() would park for 2 s on
     * an empty queue and a test must never depend on that. */
    pthread_mutex_lock(&g_client_queue_mutex);
    struct rpc_conn conn = queue_pop_locked();
    pthread_mutex_unlock(&g_client_queue_mutex);
    return conn.fd;
}

void rpc_http_test_queue_reset(int wait_ms)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    while (g_client_queue_count > 0) {
        struct rpc_conn c = queue_pop_locked();
        conn_discard(&c);
    }
    g_client_queue_head = 0;
    g_client_queue_tail = 0;
    g_client_queue_peak = 0;
    g_client_admitted = 0;
    g_client_reclaimed_hangup = 0;
    g_client_reclaimed_stale = 0;
    g_client_rejected_busy = 0;
    g_client_queue_wait_ms = wait_ms >= 0 ? wait_ms
                                          : RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
    pthread_mutex_unlock(&g_client_queue_mutex);
}

void rpc_http_test_queue_stats(struct rpc_http_queue_stats *out)
{
    if (!out) return;
    pthread_mutex_lock(&g_client_queue_mutex);
    out->capacity          = RPC_HTTP_QUEUE_CAP;
    out->depth             = g_client_queue_count;
    out->peak_depth        = g_client_queue_peak;
    out->admitted          = g_client_admitted;
    out->reclaimed_hangup  = g_client_reclaimed_hangup;
    out->reclaimed_stale   = g_client_reclaimed_stale;
    out->rejected_busy     = g_client_rejected_busy;
    pthread_mutex_unlock(&g_client_queue_mutex);
}

/* Two-pass serialization of a JSON-RPC response. json_write() returns
 * the FULL required length regardless of the buffer it is handed (it
 * only writes where pos < buflen, and a zero-length buffer is never
 * dereferenced), so we size first with a zero-length probe, reject
 * anything past RPC_HTTP_MAX_RESP_BYTES, then allocate exactly len+1
 * and write the body. This replaces the old fixed 4 MiB buffer whose
 * unclamped length was fed straight to write() — for a response larger
 * than the buffer that read (len - 4 MiB) bytes past the allocation and
 * shipped adjacent heap memory to the client (crash/DoS + info-leak).
 *
 * On success: *out_buf owns a heap buffer the caller must free(), and
 * *out_len is the exact body length to send. Returns false (with
 * *out_buf == NULL) on OOM or when the response exceeds the cap; the
 * caller sends a proper RPC error envelope instead.
 *
 * Exposed (non-static) so the regression test exercises the exact same
 * sizing path the HTTP response uses — same convention as
 * rpc_http_test_build_response_envelope above. */
bool rpc_http_test_serialize_response(const struct json_value *response,
                                      char **out_buf, size_t *out_len)
{
    if (!response || !out_buf || !out_len) {
        if (out_buf) *out_buf = NULL;
        if (out_len) *out_len = 0;
        return false;
    }
    *out_buf = NULL;
    *out_len = 0;

    /* Pass 1: size the body without writing (zero-length buffer). */
    size_t need = json_write(response, NULL, 0);
    if (need > RPC_HTTP_MAX_RESP_BYTES) {
        LOG_FAIL("rpc", "response too large: %zu > %zu bytes", need,
                 RPC_HTTP_MAX_RESP_BYTES);
        return false;
    }

    char *buf = zcl_malloc(need + 1, "http_resp_buf");
    if (!buf) {
        LOG_FAIL("rpc", "response buffer alloc failed: %zu bytes", need + 1);
        return false;
    }

    /* Pass 2: write exactly into a buffer sized to hold the whole body.
     * json_write writes the NUL only when pos < buflen; need+1 guarantees
     * room for it, and the returned length is the body length to send. */
    size_t wrote = json_write(response, buf, need + 1);
    if (wrote != need) {
        /* Should be impossible (the two passes serialize the same value),
         * but never ship a length that disagrees with what we wrote. Free
         * before logging since LOG_FAIL returns. */
        free(buf);
        LOG_FAIL("rpc", "response size mismatch: sized %zu wrote %zu", need,
                 wrote);
    }

    *out_buf = buf;
    *out_len = wrote;
    return true;
}

static void handle_client(struct rpc_conn conn)
{
    struct trace_span *rpc_span = trace_start("rpc.dispatch");
    int client_fd = conn.fd;
    /* Ownership hand-off flag. Set only where another module takes the
     * fd; done: is then the SINGLE exit that closes what we still own.
     * The /events upgrade used to `return` past done: outright, which
     * also leaked the rpc_span trace_start() allocated above. */
    bool fd_transferred = false;
    /* Declared before the first `goto done` so the label never reads an
     * indeterminate slot id. -1 means table full or module disabled;
     * either way we proceed without tracking. */
    int tmo_slot = -1;

    /* Bound both directions before touching the wire: slowloris on the
     * read side, a client that stops reading on the write side. */
    conn_set_deadlines(client_fd);

    /* Cheapest possible drop for a client that already hung up. It
     * costs one poll(), and it keeps a dead peer from consuming a
     * middleware decision and one of rpc_timeout's 128 slots on its way
     * to being closed anyway. */
    if (conn_peer_gone(&conn))
        goto done;

    /* Look up the source IP via getpeername() so we can drive the
     * middleware (rate limit + ban check) without changing the queue
     * shape. */
    uint32_t client_ip_be = 0x0100007Fu; /* fall back to 127.0.0.1 */
    {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        if (getpeername(client_fd, (struct sockaddr *)&peer, &peer_len) == 0
            && peer.sin_family == AF_INET) {
            client_ip_be = peer.sin_addr.s_addr;
        }
    }

    /* Register this request with the timeout watchdog. The watchdog
     * will shutdown() our fd if the dispatch phase runs past
     * ZCL_RPC_TIMEOUT_MS — our in-flight read/write then fails and
     * we unwind cleanly. */
    if (g_rpc_timeout_active) {
        tmo_slot = rpc_timeout_register(&g_rpc_timeout, client_fd, client_ip_be);
    }

    /* Pre-flight: ban + rate limit BEFORE we touch the request.
     * The middleware is loopback-aware and will exempt 127.0.0.0/8
     * from ban + per-IP buckets. */
    if (g_middleware_active) {
        enum rpc_http_decision d =
            rpc_http_middleware_check(&g_middleware, client_ip_be);
        if (d == RPC_HTTP_BANNED) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                -32003, "IP banned", NULL, NULL);
            send_response(&conn, 403, "Forbidden", errbuf, elen);
            goto done;
        }
        if (d == RPC_HTTP_RATE_LIMITED_GLOBAL ||
            d == RPC_HTTP_RATE_LIMITED_PER_IP) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                -32005, "Rate limit exceeded", NULL, NULL);
            send_response(&conn, 429, "Too Many Requests",
                          errbuf, elen);
            goto done;
        }
    }

    char method[16];
    char path[256];
    char line[4096];

    if (!read_line(&conn, line, sizeof(line)))
        goto done;

    if (sscanf(line, "%15s %255s", method, path) != 2)
        goto done;

    /* GET /metrics serves Prometheus text when enabled via
     * ZCL_METRICS_HTTP_ENABLE=1. Auth required — same Basic-auth
     * cookie the wallet endpoints use. Scrapers point
     * `basic_auth.password_file` at the cookie and authenticate as
     * `zclassic-cli` does. Rate-limit + ban middleware has already
     * run for this connection above. */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/metrics") == 0) {
        if (!g_metrics_http_enable) {
            /* Drain request headers so the socket closes cleanly. */
            int drain_hdrs = 0;
            while (read_line(&conn, line, sizeof(line))) {
                if (line[0] == '\0') break;
                if (++drain_hdrs > HTTP_MAX_REQUEST_HEADERS) goto done;
            }
            const char *msg = "metrics endpoint disabled "
                              "(set ZCL_METRICS_HTTP_ENABLE=1)";
            send_response_with_type(&conn, 404, "Not Found",
                                    "text/plain; charset=utf-8",
                                    msg, strlen(msg));
            goto done;
        }

        char metrics_auth[512] = {0};
        int metrics_hdrs = 0;
        while (read_line(&conn, line, sizeof(line))) {
            if (line[0] == '\0') break;
            if (++metrics_hdrs > HTTP_MAX_REQUEST_HEADERS) goto done;
            if (strncasecmp(line, "Authorization:", 14) == 0)
                snprintf(metrics_auth, sizeof(metrics_auth),
                         "%s", line + 14);
        }

        if (!check_auth(metrics_auth[0] ? metrics_auth : NULL)) {
            if (g_middleware_active)
                rpc_http_middleware_record_auth_fail(&g_middleware,
                                                     client_ip_be);
            const char *msg = "authentication required";
            send_response_with_type(&conn, 401, "Unauthorized",
                                    "text/plain; charset=utf-8",
                                    msg, strlen(msg));
            goto done;
        }
        if (g_middleware_active)
            rpc_http_middleware_record_success(&g_middleware, client_ip_be);

        size_t cap = 131072;
        char *buf = zcl_malloc(cap, "http_read_buf");
        if (!buf) {
            const char *oom = "out of memory";
            send_response_with_type(&conn, 500, "Internal Server Error",
                                    "text/plain; charset=utf-8",
                                    oom, strlen(oom));
            goto done;
        }
        size_t n = metrics_prometheus_render_prometheus(buf, cap);
        /* Prometheus exposition format 0.0.4 */
        send_response_with_type(&conn, 200, "OK",
            "text/plain; version=0.0.4; charset=utf-8",
            buf, n);
        free(buf);
        goto done;
    }

    /* WebSocket event stream at GET /events.
     * Check for WebSocket upgrade request before rejecting non-POST.
     * The path may include a query string: /events?domain=chain,peer */
    if (strcmp(method, "GET") == 0 &&
        (strncmp(path, "/events", 7) == 0 &&
         (path[7] == '\0' || path[7] == '?'))) {
        /* Read headers looking for WebSocket upgrade fields */
        char ws_key[128] = {0};
        char ws_auth[512] = {0};
        bool is_upgrade = false;
        int ws_hdrs = 0;
        while (read_line(&conn, line, sizeof(line))) {
            if (line[0] == '\0') break;
            if (++ws_hdrs > HTTP_MAX_REQUEST_HEADERS) goto done;
            if (strncasecmp(line, "Upgrade:", 8) == 0 &&
                strstr(line + 8, "websocket"))
                is_upgrade = true;
            if (strncasecmp(line, "Authorization:", 14) == 0)
                snprintf(ws_auth, sizeof(ws_auth), "%s", line + 14);
            if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
                const char *p = line + 18;
                while (*p == ' ') p++;
                snprintf(ws_key, sizeof(ws_key), "%s", p);
                /* Trim trailing whitespace */
                size_t kl = strlen(ws_key);
                while (kl > 0 && (ws_key[kl-1] == '\r' ||
                       ws_key[kl-1] == '\n' || ws_key[kl-1] == ' '))
                    ws_key[--kl] = '\0';
            }
        }
        if (is_upgrade && ws_key[0]) {
            /* Same Basic-auth gate as the JSON-RPC path: the event
             * stream exposes chain/peer/wallet activity, so an
             * unauthenticated upgrade is an information leak. */
            if (!check_auth(ws_auth[0] ? ws_auth : NULL)) {
                if (g_middleware_active)
                    rpc_http_middleware_record_auth_fail(&g_middleware,
                                                         client_ip_be);
                char errbuf[256];
                size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                    HTTP_UNAUTHORIZED, "Unauthorized", NULL, NULL);
                send_response(&conn, 401, "Unauthorized", errbuf, elen);
                goto done;
            }
            if (g_middleware_active)
                rpc_http_middleware_record_success(&g_middleware,
                                                   client_ip_be);
            /* ws_events owns a raw fd only — handing it a TLS socket
             * would write the 101 handshake plaintext beneath the TLS
             * stream and orphan the SSL object on the early return.
             * Refuse over SSL instead; done: SSL_frees via conn_close. */
            if (conn.ssl) {
                char errbuf[256];
                size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                    RPC_INVALID_REQUEST,
                    "WebSocket /events not supported on the TLS listener",
                    NULL, NULL);
                send_response(&conn, 501, "Not Implemented", errbuf, elen);
                goto done;
            }
            const char *query = strchr(path, '?');
            if (ws_events_upgrade(client_fd, path, ws_key, query)) {
                /* Ownership moves to ws_events (which polls for
                 * POLLHUP and reaps idle clients itself). Record the
                 * hand-off and fall through to the ONE exit — the old
                 * bare `return` skipped trace_end() and leaked the
                 * rpc.dispatch span on every successful upgrade. */
                fd_transferred = true;
                goto done;
            }
            /* Upgrade failed — fall through to 503 */
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                -32006, "WebSocket capacity full (max 100)", NULL, NULL);
            send_response(&conn, 503, "Service Unavailable",
                          errbuf, elen);
            goto done;
        }
        /* Not a WebSocket upgrade — fall through to reject */
    }

    /* No blog over clearnet. Blog is Tor-only via dynhost.
     * Clearnet serves ONLY authenticated RPC (POST). */
    if (strcmp(method, "POST") != 0) {
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            RPC_INVALID_REQUEST, "Method not allowed", NULL, NULL);
        send_response(&conn, 405, "Method Not Allowed", errbuf, elen);
        goto done;
    }

    size_t content_length = 0;
    char auth_value[512] = {0};
    int post_hdrs = 0;
    while (read_line(&conn, line, sizeof(line))) {
        if (line[0] == '\0') break;
        if (++post_hdrs > HTTP_MAX_REQUEST_HEADERS) goto done;
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            char *endp = NULL;
            long v = strtol(line + 15, &endp, 10);
            if (endp == line + 15 || v < 0 || v > 10 * 1024 * 1024)
                content_length = 0;
            else
                content_length = (size_t)v;
        }
        if (strncasecmp(line, "Authorization:", 14) == 0)
            snprintf(auth_value, sizeof(auth_value), "%s", line + 14);
    }

    if (!check_auth(auth_value[0] ? auth_value : NULL)) {
        if (g_middleware_active)
            rpc_http_middleware_record_auth_fail(&g_middleware, client_ip_be);
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            HTTP_UNAUTHORIZED, "Unauthorized", NULL, NULL);
        send_response(&conn, 401, "Unauthorized", errbuf, elen);
        goto done;
    }
    if (g_middleware_active)
        rpc_http_middleware_record_success(&g_middleware, client_ip_be);

    if (content_length == 0 || content_length > 10 * 1024 * 1024) {
        if (content_length > 10 * 1024 * 1024) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INVALID_REQUEST, "Request body too large", NULL, NULL);
            send_response(&conn, 413, "Payload Too Large", errbuf, elen);
        }
        goto done;
    }

    char *body = zcl_malloc(content_length + 1, "http_body");
    if (!body) goto done;

    if (!read_exact(&conn, body, content_length)) {
        free(body);
        goto done;
    }
    body[content_length] = '\0';

    struct json_value request;
    json_init(&request);
    if (!json_read(&request, body, content_length)) {
        free(body);
        json_free(&request);
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            RPC_PARSE_ERROR, "Parse error", NULL, NULL);
        send_response(&conn, 200, "OK", errbuf, elen);
        goto done;
    }
    free(body);

    struct json_request req;
    json_request_init(&req);
    if (!json_request_parse(&req, &request)) {
        json_free(&request);
        json_request_free(&req);
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            RPC_INVALID_REQUEST, "Invalid request", NULL, NULL);
        send_response(&conn, 200, "OK", errbuf, elen);
        goto done;
    }
    json_free(&request);

    /* Now that we know the method name, label the timeout slot so
     * EV_RPC_TIMEOUT carries useful context if the watchdog kills us
     * during dispatch. */
    if (tmo_slot >= 0) {
        rpc_timeout_set_method(&g_rpc_timeout, tmo_slot, req.method);
    }
    trace_attr_str(rpc_span, "method", req.method);

    struct json_value result;
    json_init(&result);
    bool rpc_ok = rpc_table_execute(g_table, req.method, &req.params, &result);

    /* Build standard JSON-RPC response:
     *   success: {result: <data>, error: null, id: <id>}
     *   failure: {result: null, error: {code, message, method}, id: <id>}
     * Route through the shared helper so the HTTP path and the
     * regression test exercise the same stack-init discipline. */
    struct json_value response;
    json_init(&response);
    bool response_ok = rpc_http_test_build_response_envelope(
        rpc_ok, req.method, &result, &req.id, &response);

    char *resp_buf = NULL;
    size_t resp_len = 0;
    if (response_ok &&
        rpc_http_test_serialize_response(&response, &resp_buf, &resp_len)) {
        /* Body sized and written by the same value: send exactly the
         * bytes we wrote — never an unclamped length past the buffer. */
        send_response(&conn, 200, "OK", resp_buf, resp_len);
        free(resp_buf);
    } else {
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            RPC_OUT_OF_MEMORY, "Internal error: response too large or "
            "out of memory", req.method, NULL);
        send_response(&conn, 500, "Internal Server Error",
                      errbuf, elen);
    }

    json_free(&result);
    json_free(&response);
    json_request_free(&req);

/* THE single exit. Every path out of this function lands here, so the
 * worker's ownership of the connection ends in exactly one place. */
done:
    if (tmo_slot >= 0) {
        rpc_timeout_unregister(&g_rpc_timeout, tmo_slot);
    }
    trace_end(rpc_span);
    if (!fd_transferred)
        conn_close(&conn);
}

static void *rpc_worker_thread_fn(void *arg)
{
    (void)arg;

    while (g_running) {
        struct rpc_conn conn = dequeue_client();
        thread_liveness_beat(&g_rpc_worker_liveness, -1);
        if (conn.fd < 0)
            continue;
        handle_client(conn);
    }

    return NULL;
}

static void *listen_thread_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(g_listen_fd,
                                (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_rpc_listen_liveness, -1);
        if (client_fd < 0) {
            if (g_running)
                perror("accept");
            continue;
        }
        struct rpc_conn conn = { .fd = client_fd, .ssl = NULL,
                                 .admitted_us = 0 };
        if (!enqueue_client(conn)) {
            /* Bound the 503 write: this runs ON THE ACCEPT LOOP, so a
             * client that never reads its rejection would otherwise
             * stop the node accepting any RPC at all. */
            conn_set_deadlines(client_fd);
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INTERNAL_ERROR, "RPC server busy", NULL, NULL);
            send_response(&conn, 503, "Service Unavailable",
                          errbuf, elen);
            conn_close(&conn);
        }
    }
    return NULL;
}

/* ── TLS listener thread ──────────────────────────────────────────── */

static void *tls_listen_thread_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(g_tls_listen_fd,
                                (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_rpc_tls_liveness, -1);
        if (client_fd < 0) {
            if (g_running)
                perror("tls accept");
            continue;
        }

        /* Bound the inline handshake: SSL_accept runs on the accept
         * loop, so a slowloris client that never finishes the handshake
         * would stall ALL new TLS RPC connections. Blocking-socket
         * timeouts make its internal reads/writes fail after 5 s and
         * fall into the existing drop path below. */
        struct timeval hs_tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &hs_tv, sizeof(hs_tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &hs_tv, sizeof(hs_tv));

        /* Perform TLS handshake */
        SSL *ssl = SSL_new(g_tls_ctx);
        if (!ssl) {
            fprintf(stderr, "RPC TLS: SSL_new failed\n");  // obs-ok:helper-context-logged
            close(client_fd);
            continue;
        }
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            /* TLS handshake failure — drop silently (common with
             * port scanners and misconfigured clients) */
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        struct rpc_conn conn = { .fd = client_fd, .ssl = ssl,
                                 .admitted_us = 0 };
        if (!enqueue_client(conn)) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INTERNAL_ERROR, "RPC server busy", NULL, NULL);
            send_response(&conn, 503, "Service Unavailable",
                          errbuf, elen);
            conn_close(&conn);
        }
    }
    return NULL;
}

/* ── TLS initialization ───────────────────────────────────────────── */

static SSL_CTX *tls_init(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        LOG_NULL("rpc", "TLS: SSL_CTX_new failed");

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        SSL_CTX_free(ctx);
        LOG_NULL("rpc", "TLS: failed to load certificate: %s", cert_path);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        LOG_NULL("rpc", "TLS: failed to load private key: %s", key_path);
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        LOG_NULL("rpc", "TLS: cert/key mismatch");
    }

    return ctx;
}

/* ── Cookie file write (atomic, owner-only) ─────────────────────────
 * Create the RPC cookie restrictively in one step instead of
 * fopen("w") (which honors the umask → typically world-readable) THEN
 * chmod(0600): that create-then-chmod leaves a window where any local
 * user can read the credentials, which grant full wallet access
 * (including dumpprivkey/z_exportkey). open(O_CREAT|O_EXCL, 0600)
 * guarantees the file is owner-only from the instant it exists; we
 * unlink first so O_EXCL succeeds on rotation/restart. Returns NULL on
 * failure (caller logs context). */
static FILE *rpc_cookie_fopen_secure(const char *path)
{
    /* Drop any stale cookie so O_EXCL can win the create race; O_EXCL
     * refuses to follow a symlink an attacker may have planted. */
    unlink(path);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0)
        return NULL;
    FILE *f = fdopen(fd, "w");
    if (!f)
        close(fd);
    return f;
}

/* ── Cookie rotation ────────────────────────────────────────────── */

void rpc_http_cookie_rotate(void)
{
    pthread_mutex_lock(&g_cookie_mutex);
    if (!g_cookie_mode || !g_auth_required) {
        pthread_mutex_unlock(&g_cookie_mutex);
        return;
    }

    /* Shift current → previous */
    memory_cleanse(g_rpc_password_prev, sizeof(g_rpc_password_prev));
    memcpy(g_rpc_password_prev, g_rpc_password, sizeof(g_rpc_password));

    /* Generate new password */
    uint64_t r1 = GetRand(UINT64_MAX);
    uint64_t r2 = GetRand(UINT64_MAX);
    snprintf(g_rpc_password, sizeof(g_rpc_password),
             "%016llx%016llx",
             (unsigned long long)r1, (unsigned long long)r2);

    /* Write new cookie to disk (owner-only, no world-readable window) */
    if (g_cookie_file[0]) {
        FILE *f = rpc_cookie_fopen_secure(g_cookie_file);
        if (f) {
            fprintf(f, "%s:%s", g_rpc_user, g_rpc_password);
            fclose(f);
        }
    }
    pthread_mutex_unlock(&g_cookie_mutex);
    printf("RPC cookie rotated\n");
}

static void *cookie_rotate_thread_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        /* Sleep in 1-second ticks so we notice shutdown promptly */
        for (int i = 0; i < g_cookie_rotate_sec && g_running; i++)
            sleep(1);
        thread_liveness_beat(&g_rpc_cookie_liveness, -1);
        if (g_running)
            rpc_http_cookie_rotate();
    }
    return NULL;
}

int rpc_http_cookie_rotate_sec(void)
{
    return g_cookie_rotate_sec;
}

/* ── Server start/stop ──────────────────────────────────────────── */

bool rpc_http_start(const struct rpc_table *table, uint16_t port,
                     const char *rpc_user, const char *rpc_password,
                     const char *datadir)
{
    if (g_running || g_listen_thread_started || g_workers_started > 0)
        return false;

    g_client_queue_head = 0;
    g_client_queue_tail = 0;
    g_client_queue_count = 0;
    g_client_queue_peak = 0;
    g_client_admitted = 0;
    g_client_reclaimed_hangup = 0;
    g_client_reclaimed_stale = 0;
    g_client_rejected_busy = 0;
    /* Admission-queue residency deadline. 0 keeps entries until their
     * peer hangs up; any positive value is the ceiling on how long the
     * front door can stay saturated. */
    g_client_queue_wait_ms = RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
    {
        const char *qw = getenv("ZCL_RPC_QUEUE_WAIT_MS");
        if (qw && *qw) {
            int v = atoi(qw);
            if (v >= 0)
                g_client_queue_wait_ms = v;
        }
    }
    g_table = table;
    g_rpc_user[0] = '\0';
    g_rpc_password[0] = '\0';
    memory_cleanse(g_rpc_password_prev, sizeof(g_rpc_password_prev));
    g_cookie_file[0] = '\0';
    g_auth_required = false;
    g_cookie_mode = false;
    if (rpc_user && rpc_password) {
        snprintf(g_rpc_user, sizeof(g_rpc_user), "%s", rpc_user);
        snprintf(g_rpc_password, sizeof(g_rpc_password), "%s", rpc_password);
        g_auth_required = true;
    } else if (datadir) {
        snprintf(g_rpc_user, sizeof(g_rpc_user), "__cookie__");
        uint64_t r1 = GetRand(UINT64_MAX);
        uint64_t r2 = GetRand(UINT64_MAX);
        snprintf(g_rpc_password, sizeof(g_rpc_password),
                 "%016llx%016llx",
                 (unsigned long long)r1, (unsigned long long)r2);
        g_auth_required = true;
        g_cookie_mode = true;

        snprintf(g_cookie_file, sizeof(g_cookie_file),
                 "%s/.cookie", datadir);
        /* Create owner-only (0600) atomically — never a world-readable
         * window between create and chmod. */
        FILE *f = rpc_cookie_fopen_secure(g_cookie_file);
        if (f) {
            fprintf(f, "%s:%s", g_rpc_user, g_rpc_password);
            fclose(f);
            printf("RPC cookie written to %s\n", g_cookie_file);
        }

        /* Record the bound RPC port alongside the cookie. NOT secret (the
         * port is visible to anyone who can already reach the loopback
         * listener), so a plain world-readable file is fine — no
         * rpc_cookie_fopen_secure() needed. This is what lets a CLI
         * invocation of the form `-rpcport=<N>` (no `-datadir=`) find the
         * right sibling datadir by scanning `<HOME>/.zclassic-c23*` for one
         * whose recorded port matches (see cli_autodiscover_datadir_for_port
         * in src/main.c) instead of guessing the default datadir's cookie
         * and getting an indistinguishable 401. Best-effort like the cookie
         * write above: a failure here only degrades auto-discovery, it
         * never blocks RPC startup. */
        char port_path[600];
        snprintf(port_path, sizeof(port_path), "%s/.rpcport", datadir);
        FILE *pf = fopen(port_path, "w");
        if (pf) {
            fprintf(pf, "%u", port);
            fclose(pf);
        }
    }

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        perror("socket");
        return false;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_listen_fd);
        g_listen_fd = -1;
        return false;
    }

    if (listen(g_listen_fd, 8) < 0) {
        perror("listen");
        close(g_listen_fd);
        g_listen_fd = -1;
        return false;
    }

    /* Rate limit + per-IP bucket + IP ban for the HTTP RPC surface.
     * Init once on first start; load env config so operators can tune
     * via ZCL_RPC_RPS / ZCL_RPC_PER_IP_RPS / ZCL_RPC_BAN_* without a
     * rebuild. */
    if (!g_middleware_active) {
        rpc_http_middleware_init(&g_middleware);
        rpc_http_middleware_load_from_env(&g_middleware);
        g_middleware_active = true;
    }
    /* Publish the global handle so metrics and native RPC diagnostics can read
     * the live config and stats without reaching into httpserver.c. */
    rpc_http_middleware_set_global(&g_middleware);

    /* Per-request timeout watchdog. ZCL_RPC_TIMEOUT_MS=0 disables
     * entirely so operators can opt out. Watchdog thread is dormant
     * in that case. */
    if (!g_rpc_timeout_active) {
        rpc_timeout_init(&g_rpc_timeout);
        rpc_timeout_load_from_env(&g_rpc_timeout);
        g_rpc_timeout_active = true;
    }
    rpc_timeout_set_global(&g_rpc_timeout);
    if (!rpc_timeout_start_watchdog(&g_rpc_timeout)) {
        fprintf(stderr, "RPC server: rpc_timeout watchdog start failed\n");  // obs-ok:helper-context-logged
    }

    /* Optional GET /metrics Prometheus endpoint. Accept "1", "true",
     * "yes", "on" as truthy; anything else leaves it off. */
    g_metrics_http_enable = false;
    const char *mx = getenv("ZCL_METRICS_HTTP_ENABLE");
    if (mx && *mx) {
        if (strcmp(mx, "1") == 0 ||
            strcasecmp(mx, "true") == 0 ||
            strcasecmp(mx, "yes")  == 0 ||
            strcasecmp(mx, "on")   == 0) {
            g_metrics_http_enable = true;
            printf("RPC server: GET /metrics Prometheus endpoint enabled\n");
        }
    }

    /* RPC cookie rotation. Default 24h; operators tune via
     * ZCL_RPC_COOKIE_ROTATE_SEC. Set to 0 to disable rotation. Only
     * active in cookie mode (no explicit rpcuser/rpcpassword). */
    g_cookie_rotate_sec = 86400;
    const char *rot_env = getenv("ZCL_RPC_COOKIE_ROTATE_SEC");
    if (rot_env && *rot_env) {
        int v = atoi(rot_env);
        if (v >= 0)
            g_cookie_rotate_sec = v;
    }
    g_cookie_rotate_started = false;
    if (g_cookie_mode && g_cookie_rotate_sec > 0) {
        /* Thread created after g_running is set (below) */
    }

    /* Optional TLS listener for non-loopback RPC. Set ZCL_RPC_TLS_CERT
     * and ZCL_RPC_TLS_KEY to PEM file paths. TLS listener binds to
     * 0.0.0.0 on rpcport+1 (or ZCL_RPC_TLS_PORT). Plain-text listener
     * stays on 127.0.0.1 for local tools. */
    g_tls_ctx = NULL;
    g_tls_listen_fd = -1;
    g_tls_listen_thread_started = false;
    g_tls_port = 0;
    {
        const char *cert = getenv("ZCL_RPC_TLS_CERT");
        const char *key  = getenv("ZCL_RPC_TLS_KEY");
        if (cert && cert[0] && key && key[0]) {
            g_tls_ctx = tls_init(cert, key);
            if (g_tls_ctx) {
                /* Determine TLS port */
                g_tls_port = port + 1;
                const char *tp = getenv("ZCL_RPC_TLS_PORT");
                if (tp && *tp) {
                    int v = atoi(tp);
                    if (v > 0 && v < 65536)
                        g_tls_port = (uint16_t)v;
                }

                /* Create TLS listen socket on all interfaces */
                g_tls_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (g_tls_listen_fd >= 0) {
                    int topt = 1;
                    setsockopt(g_tls_listen_fd, SOL_SOCKET, SO_REUSEADDR,
                               &topt, sizeof(topt));

                    struct sockaddr_in taddr;
                    memset(&taddr, 0, sizeof(taddr));
                    taddr.sin_family = AF_INET;
                    taddr.sin_addr.s_addr = htonl(INADDR_ANY);
                    taddr.sin_port = htons(g_tls_port);

                    if (bind(g_tls_listen_fd, (struct sockaddr *)&taddr,
                             sizeof(taddr)) < 0) {
                        fprintf(stderr, "RPC TLS: bind port %u failed: %s\n",  // obs-ok:helper-context-logged
                                g_tls_port, strerror(errno));
                        close(g_tls_listen_fd);
                        g_tls_listen_fd = -1;
                    } else if (listen(g_tls_listen_fd, 8) < 0) {
                        fprintf(stderr, "RPC TLS: listen failed: %s\n",  // obs-ok:helper-context-logged
                                strerror(errno));
                        close(g_tls_listen_fd);
                        g_tls_listen_fd = -1;
                    }
                }

                if (g_tls_listen_fd < 0) {
                    /* TLS socket failed — clean up ctx but continue
                     * with plain-text listener only */
                    SSL_CTX_free(g_tls_ctx);
                    g_tls_ctx = NULL;
                    fprintf(stderr, "RPC TLS: disabled (socket failed)\n");  // obs-ok:helper-context-logged
                }
            }
        }
    }

    g_running = true;
    printf("RPC server listening on 127.0.0.1:%u\n", port);
    if (g_tls_ctx)
        printf("RPC TLS server listening on 0.0.0.0:%u\n", g_tls_port);

    for (size_t i = 0; i < RPC_HTTP_WORKERS; i++) {
        if (thread_registry_spawn("zcl_rpc_worker", rpc_worker_thread_fn,
                                      NULL, &g_worker_threads[i]) != 0) {
            perror("thread_registry_spawn");
            g_running = false;
            shutdown(g_listen_fd, SHUT_RDWR);
            close(g_listen_fd);
            g_listen_fd = -1;
            pthread_mutex_lock(&g_client_queue_mutex);
            pthread_cond_broadcast(&g_client_queue_cond);
            pthread_mutex_unlock(&g_client_queue_mutex);
            for (size_t j = 0; j < i; j++)
                pthread_join(g_worker_threads[j], NULL);
            g_workers_started = 0;
            return false;
        }
        g_workers_started = i + 1;
        if (i == 0)
            thread_liveness_register(&g_rpc_worker_liveness, "zcl_rpc_worker", 0, 0);
    }

    if (thread_registry_spawn("zcl_rpc_listen", listen_thread_fn, NULL,
                                  &g_listen_thread) != 0) {
        perror("thread_registry_spawn");
        g_running = false;
        pthread_mutex_lock(&g_client_queue_mutex);
        pthread_cond_broadcast(&g_client_queue_cond);
        pthread_mutex_unlock(&g_client_queue_mutex);
        for (size_t i = 0; i < g_workers_started; i++)
            pthread_join(g_worker_threads[i], NULL);
        g_workers_started = 0;
        close(g_listen_fd);
        g_listen_fd = -1;
        return false;
    }
    g_listen_thread_started = true;
    thread_liveness_register(&g_rpc_listen_liveness, "zcl_rpc_listen", 0, 0);

    /* Start TLS listener thread if configured */
    if (g_tls_ctx && g_tls_listen_fd >= 0) {
        if (thread_registry_spawn("zcl_rpc_tls", tls_listen_thread_fn,
                                      NULL, &g_tls_listen_thread) == 0) {
            g_tls_listen_thread_started = true;
            thread_liveness_register(&g_rpc_tls_liveness, "zcl_rpc_tls", 0, 0);
        } else {
            fprintf(stderr, "RPC TLS: listener thread start failed\n");  // obs-ok:helper-context-logged
            close(g_tls_listen_fd);
            g_tls_listen_fd = -1;
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
        }
    }

    /* Start cookie rotation background thread */
    if (g_cookie_mode && g_cookie_rotate_sec > 0) {
        if (thread_registry_spawn("zcl_rpc_cookie", cookie_rotate_thread_fn,
                                      NULL, &g_cookie_rotate_thread) == 0) {
            g_cookie_rotate_started = true;
            thread_liveness_register(&g_rpc_cookie_liveness, "zcl_rpc_cookie", 0, 0);
            printf("RPC cookie rotation: every %d seconds\n",
                   g_cookie_rotate_sec);
        }
    }

    return true;
}

void rpc_http_stop(void)
{
    g_running = false;
    if (g_listen_fd >= 0) {
        shutdown(g_listen_fd, SHUT_RDWR);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_tls_listen_fd >= 0) {
        shutdown(g_tls_listen_fd, SHUT_RDWR);
        close(g_tls_listen_fd);
        g_tls_listen_fd = -1;
    }
    pthread_mutex_lock(&g_client_queue_mutex);
    pthread_cond_broadcast(&g_client_queue_cond);
    pthread_mutex_unlock(&g_client_queue_mutex);
    if (g_listen_thread_started) {
        pthread_join(g_listen_thread, NULL);
        g_listen_thread_started = false;
        thread_liveness_retire(&g_rpc_listen_liveness);
    }
    if (g_tls_listen_thread_started) {
        pthread_join(g_tls_listen_thread, NULL);
        g_tls_listen_thread_started = false;
        thread_liveness_retire(&g_rpc_tls_liveness);
    }
    if (g_workers_started > 0) {
        for (size_t i = 0; i < g_workers_started; i++)
            pthread_join(g_worker_threads[i], NULL);
        g_workers_started = 0;
        thread_liveness_retire(&g_rpc_worker_liveness);
    }

    pthread_mutex_lock(&g_client_queue_mutex);
    while (g_client_queue_count > 0) {
        struct rpc_conn c = queue_pop_locked();
        conn_discard(&c);
    }
    g_client_queue_head = 0;
    g_client_queue_tail = 0;
    pthread_mutex_unlock(&g_client_queue_mutex);

    if (g_cookie_rotate_started) {
        pthread_join(g_cookie_rotate_thread, NULL);
        g_cookie_rotate_started = false;
        thread_liveness_retire(&g_rpc_cookie_liveness);
    }

    if (g_cookie_file[0]) {
        unlink(g_cookie_file);
        g_cookie_file[0] = '\0';
    }
    g_table = NULL;
    g_auth_required = false;
    g_cookie_mode = false;
    memory_cleanse(g_rpc_user, sizeof(g_rpc_user));
    memory_cleanse(g_rpc_password, sizeof(g_rpc_password));
    memory_cleanse(g_rpc_password_prev, sizeof(g_rpc_password_prev));
    if (g_rpc_timeout_active) {
        rpc_timeout_stop_watchdog(&g_rpc_timeout);
        rpc_timeout_set_global(NULL);
        rpc_timeout_destroy(&g_rpc_timeout);
        g_rpc_timeout_active = false;
    }
    if (g_middleware_active) {
        rpc_http_middleware_set_global(NULL);
        rpc_http_middleware_destroy(&g_middleware);
        g_middleware_active = false;
    }
    if (g_tls_ctx) {
        SSL_CTX_free(g_tls_ctx);
        g_tls_ctx = NULL;
    }
    printf("RPC server stopped.\n");
}

bool rpc_http_is_running(void)
{
    return g_running;
}

bool rpc_http_tls_active(void)
{
    return g_tls_ctx != NULL && g_running;
}
