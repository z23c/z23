/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "rpc/httpserver.h"
#include "httpserver_auth.h"
#include "httpserver_queue.h"
#include "httpserver_request.h"
#include "httpserver_transport.h"
#include "rpc/http_middleware.h"
#include "rpc/rpc_timeout.h"
#include "json/json.h"
#include "rpc/protocol.h"
#include "util/log_macros.h"
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "util/thread_registry.h"
#include "util/thread_liveness.h"

#define RPC_HTTP_WORKERS 4

/* ── SINGLE-OWNER INVARIANT for accepted sockets ───────────────────
 *
 * Every accepted fd has exactly ONE owner at every instant, and no
 * owner may hold it without a deadline. The owners, in order:
 *
 *   1. listener   accept() → rpc_http_queue_admit() succeeds
 *   2. queue      rpc_http_queue_admit() → rpc_http_queue_take_wait()
 *   3. worker     rpc_http_queue_take_wait() → request dispatch returns
 *   4. ws_events         after a successful /events upgrade
 *
 * The queue is a WAITING ROOM, not a resource pool. It must never be
 * the reason the server refuses work, so before it reports itself
 * full it surrenders every entry it is no longer entitled to own: a
 * peer that has hung up with nothing to serve, or an entry that has
 * waited past RPC_HTTP_QUEUE_WAIT_MS.
 *
 * Why: a worker parked in request dispatch (a wedged RPC method, or a client
 * that stops reading a large response) would otherwise pin
 * g_client_queue_count at RPC_HTTP_QUEUE_CAP, leaving later clients with an
 * instant 503 and queued fds in CLOSE-WAIT. With the rules below the worst
 * case is bounded by the residency deadline, not by the process lifetime. */

/* How long a connection may sit in the admission queue before the
 * queue gives it up. Defaults to the per-request watchdog budget
 * (rpc_timeout's 10 s): a request that has not even been READ within
 * the whole time it was allowed to RUN is past any client's patience,
 * and its slot is worth more than its fd. 0 disables age-based
 * reclaim (hang-up reclaim still runs). Operators tune with
 * ZCL_RPC_QUEUE_WAIT_MS. */
#define RPC_HTTP_QUEUE_WAIT_MS_DEFAULT 10000

/* A listening socket is not a cancellation primitive on Windows.  In
 * particular, closesocket() in the shutdown thread is not guaranteed to wake
 * a blocking accept() already running in another thread.  Keep accept behind
 * a short readiness wait so g_running is the cross-platform cancellation
 * authority and an idle listener leaves promptly even when Winsock does not
 * interrupt that accept. */
#define RPC_HTTP_ACCEPT_POLL_MS 250

static platform_socket_t g_listen_fd = PLATFORM_SOCKET_INVALID;
static pthread_t g_listen_thread;
static bool g_listen_thread_started = false;
/* g_running coordinates the listener + worker threads with rpc_http_stop().
 * volatile is *not* a thread-synchronization primitive in C (it's for MMIO
 * and signal handlers); reads/writes across threads need atomic semantics
 * for memory ordering. The shutdown path also broadcasts g_client_queue_cond
 * after flipping this, so workers in the queue wait wake; this atomic is
 * belt-and-suspenders for any other read sites. */
static _Atomic bool g_running = false;
static struct rpc_http_middleware g_middleware;
static bool g_middleware_active = false;
static struct rpc_timeout_mgr g_rpc_timeout;
static bool g_rpc_timeout_active = false;
static struct rpc_http_request_context g_request_context;
/* Prometheus /metrics HTTP endpoint. Off by default; an operator
 * sets ZCL_METRICS_HTTP_ENABLE=1 to expose the metrics renderer. Gated behind
 * the same RPC Basic-auth
 * cookie the wallet endpoints use. Prometheus `scrape_configs`
 * supports `basic_auth: { username_file: ..., password_file: ... }` —
 * point
 * those at the two halves of `~/.zclassic-c23/.cookie` and the
 * scraper authenticates exactly like `zclassic-cli`. An open endpoint
 * would expose peer counts / tx volume / mempool size to anyone who can
 * reach the TLS listener (network fingerprinting). The HTTP middleware (rate-limit + ban
 * + loopback bypass) still runs first, unchanged. */
static pthread_t g_worker_threads[RPC_HTTP_WORKERS];
static size_t g_workers_started = 0;

/* ── TLS state ────────────────────────────────────────────────────── */
static SSL_CTX *g_tls_ctx = NULL;
static platform_socket_t g_tls_listen_fd = PLATFORM_SOCKET_INVALID;
static pthread_t g_tls_listen_thread;
static bool g_tls_listen_thread_started = false;
static uint16_t g_tls_port = 0;

/* Supervisor liveness for the 4 RPC HTTP threads. Root children (not
 * supervisor_register_in_domain(...)): engine/modules/rpc cannot include the app-side
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

static void *rpc_worker_thread_fn(void *arg)
{
    (void)arg;

    while (g_running) {
        struct rpc_conn conn = rpc_http_queue_take_wait(&g_running);
        thread_liveness_beat(&g_rpc_worker_liveness, -1);
        if (conn.fd == PLATFORM_SOCKET_INVALID)
            continue;
        rpc_http_request_handle(conn, &g_request_context);
    }

    return NULL;
}

static bool rpc_listener_ready(platform_socket_t listener,
                               const char *label)
{
    platform_socket_pollfd pfd = {
        .fd = listener,
        .events = PLATFORM_SOCKET_POLL_READ,
        .revents = 0,
    };
    int ready = platform_socket_poll(&pfd, 1, RPC_HTTP_ACCEPT_POLL_MS);
    if (ready > 0 && (pfd.revents & PLATFORM_SOCKET_POLL_READ) != 0)
        return true;
    if (ready < 0 && g_running &&
        !platform_socket_error_interrupted(platform_socket_last_error())) {
        fprintf(stderr, "RPC %s listener poll failed: socket_error=%d\n",
                label, platform_socket_last_error());
    } else if (ready > 0 && g_running &&
               (pfd.revents & (PLATFORM_SOCKET_POLL_ERROR |
                                PLATFORM_SOCKET_POLL_HANGUP)) != 0) {
        fprintf(stderr, "RPC %s listener poll failed: revents=0x%x\n",
                label, (unsigned int)(unsigned short)pfd.revents);
    }
    return false;
}

static void *listen_thread_fn(void *arg)
{
    (void)arg;
    /* Captured before start returns and never rewritten.  Shutdown may close
     * the underlying socket, but it does not race this thread on the global
     * descriptor variable. */
    const platform_socket_t listener = g_listen_fd;
    while (g_running) {
        if (!rpc_listener_ready(listener, "plain"))
            continue;
        if (!g_running)
            break;
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        platform_socket_t client_fd = platform_socket_accept(
            listener, (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_rpc_listen_liveness, -1);
        if (client_fd == PLATFORM_SOCKET_INVALID) {
            if (g_running)
                perror("accept");
            continue;
        }
        struct rpc_conn conn = { .fd = client_fd, .ssl = NULL,
                                 .admitted_us = 0 };
        if (!rpc_http_queue_admit(conn)) {
            /* Bound the 503 write: this runs ON THE ACCEPT LOOP, so a
             * client that never reads its rejection would otherwise
             * stop the node accepting any RPC at all. */
            rpc_conn_set_deadlines(client_fd);
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INTERNAL_ERROR, "RPC server busy", NULL, NULL);
            rpc_conn_send_response(&conn, 503, "Service Unavailable",
                                   errbuf, elen);
            rpc_conn_close(&conn);
        }
    }
    return NULL;
}

/* ── TLS listener thread ──────────────────────────────────────────── */

static void *tls_listen_thread_fn(void *arg)
{
    (void)arg;
    const platform_socket_t listener = g_tls_listen_fd;
    while (g_running) {
        if (!rpc_listener_ready(listener, "TLS"))
            continue;
        if (!g_running)
            break;
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        platform_socket_t client_fd = platform_socket_accept(
            listener, (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_rpc_tls_liveness, -1);
        if (client_fd == PLATFORM_SOCKET_INVALID) {
            if (g_running)
                perror("tls accept");
            continue;
        }

        /* Bound the inline handshake: SSL_accept runs on the accept
         * loop, so a slowloris client that never finishes the handshake
         * would stall ALL new TLS RPC connections. Blocking-socket
         * timeouts make its internal reads/writes fail after 5 s and
         * fall into the existing drop path below. */
        (void)platform_socket_set_receive_timeout(client_fd, 5000);
        (void)platform_socket_set_send_timeout(client_fd, 5000);

        /* Perform TLS handshake */
        SSL *ssl = SSL_new(g_tls_ctx);
        if (!ssl) {
            fprintf(stderr, "RPC TLS: SSL_new failed\n");  // obs-ok:helper-context-logged
            platform_socket_close(client_fd);
            continue;
        }
        /* Computed into a variable rather than split across the #if arms of a
         * single `if (`: the split form opens a brace in each arm and closes
         * it in neither, so any tool counting braces without evaluating the
         * preprocessor loses track of the enclosing function from here on. */
#if defined(_WIN32)
        /* Winsock's SOCKET is handle-sized; SSL_set_fd takes an int, so
         * refuse a descriptor that cannot round-trip rather than truncate. */
        const bool fd_bound = client_fd <= INT_MAX &&
                              SSL_set_fd(ssl, (int)client_fd) == 1;
#else
        const bool fd_bound = SSL_set_fd(ssl, client_fd) == 1;
#endif
        if (!fd_bound) {
            SSL_free(ssl);
            platform_socket_close(client_fd);
            continue;
        }
        if (SSL_accept(ssl) <= 0) {
            /* TLS handshake failure — drop silently (common with
             * port scanners and misconfigured clients) */
            SSL_free(ssl);
            platform_socket_close(client_fd);
            continue;
        }

        struct rpc_conn conn = { .fd = client_fd, .ssl = ssl,
                                 .admitted_us = 0 };
        if (!rpc_http_queue_admit(conn)) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INTERNAL_ERROR, "RPC server busy", NULL, NULL);
            rpc_conn_send_response(&conn, 503, "Service Unavailable",
                                   errbuf, elen);
            rpc_conn_close(&conn);
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

/* ── Server start/stop ──────────────────────────────────────────── */

/* True when a previous rpc_http_start() is still live in whole or in
 * part, so a second start must refuse without touching anything. */
static bool rpc_http_already_started(void)
{
    return g_running || g_listen_thread_started || g_workers_started > 0;
}

/* ZCL_RPC_QUEUE_WAIT_MS: how long a connection may wait in the
 * admission queue. A missing, empty or negative value keeps the
 * default residency deadline. */
static int rpc_queue_wait_ms_from_env(const char *env)
{
    if (env && *env) {
        int value = atoi(env);
        if (value >= 0)
            return value;
    }
    return RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
}

/* Opens the 127.0.0.1 listener socket and puts it into listen state.
 * Reports the failing step with perror() exactly as before and
 * returns false; cleanup on failure belongs to rpc_http_stop(). */
static bool rpc_loopback_listener_open(uint16_t port)
{
    g_listen_fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (g_listen_fd == PLATFORM_SOCKET_INVALID) {
        perror("socket");
        return false;
    }

    int opt = 1;
    (void)platform_socket_set_reuse_address(g_listen_fd, opt != 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (platform_socket_bind(g_listen_fd, (struct sockaddr *)&addr,
                             sizeof(addr)) < 0) {
        perror("bind");
        return false;
    }

    if (platform_socket_listen(g_listen_fd, 8) < 0) {
        perror("listen");
        return false;
    }

    return true;
}

/* Brings the HTTP middleware up on first start and publishes it. */
static void rpc_http_configure_middleware(void)
{
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
    g_request_context.middleware = &g_middleware;
}

/* Brings the per-request timeout manager up on first start and
 * publishes it. The watchdog thread itself is started by the caller
 * so its failure is reported from rpc_http_start(). */
static void rpc_http_init_rpc_timeout(void)
{
    /* Per-request timeout watchdog. ZCL_RPC_TIMEOUT_MS=0 disables
     * entirely so operators can opt out. Watchdog thread is dormant
     * in that case. */
    if (!g_rpc_timeout_active) {
        rpc_timeout_init(&g_rpc_timeout);
        rpc_timeout_load_from_env(&g_rpc_timeout);
        g_rpc_timeout_active = true;
    }
    rpc_timeout_set_global(&g_rpc_timeout);
}

/* Truthy spellings for ZCL_METRICS_HTTP_ENABLE: "1", "true", "yes"
 * or "on" (case-insensitive); NULL, empty and anything else leave
 * the endpoint off. */
static bool rpc_metrics_env_flag_enabled(const char *value)
{
    return value != NULL && *value != '\0' &&
           (strcmp(value, "1") == 0 ||
            strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes")  == 0 ||
            strcasecmp(value, "on")   == 0);
}

/* The TLS listener needs both halves of the keypair configured. */
static bool rpc_tls_env_configured(const char *cert, const char *key)
{
    return cert != NULL && cert[0] != '\0' &&
           key != NULL && key[0] != '\0';
}

/* TLS listen port: rpcport+1 unless ZCL_RPC_TLS_PORT names a valid
 * port number. */
static uint16_t rpc_tls_port_from_env(const char *env, uint16_t fallback)
{
    if (env == NULL || *env == '\0')
        return fallback;
    int v = atoi(env);
    if (v <= 0 || v >= 65536)
        return fallback;
    return (uint16_t)v;
}

/* Creates the TLS listen socket on all interfaces and puts it into
 * listen state. On open, bind or listen failure the socket is closed
 * and g_tls_listen_fd is left invalid so the caller can drop TLS and
 * keep the plain-text listener. */
static void rpc_tls_listen_socket_setup(void)
{
    /* Create TLS listen socket on all interfaces */
    g_tls_listen_fd = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, false);
    if (g_tls_listen_fd != PLATFORM_SOCKET_INVALID) {
        char terr[32]; /* Winsock errors have no strerror() */
        (void)platform_socket_set_reuse_address(g_tls_listen_fd, true);

        struct sockaddr_in taddr;
        memset(&taddr, 0, sizeof(taddr));
        taddr.sin_family = AF_INET;
        taddr.sin_addr.s_addr = htonl(INADDR_ANY);
        taddr.sin_port = htons(g_tls_port);

        if (platform_socket_bind(g_tls_listen_fd,
                (struct sockaddr *)&taddr, sizeof(taddr)) < 0) {
            fprintf(stderr, "RPC TLS: bind port %u failed: %s\n",  // obs-ok:helper-context-logged
                    g_tls_port, platform_socket_error_string(
                        platform_socket_last_error(), terr, sizeof(terr)));
            platform_socket_close(g_tls_listen_fd);
            g_tls_listen_fd = PLATFORM_SOCKET_INVALID;
        } else if (platform_socket_listen(g_tls_listen_fd, 8) < 0) {
            fprintf(stderr, "RPC TLS: listen failed: %s\n",  // obs-ok:helper-context-logged
                    platform_socket_error_string(
                        platform_socket_last_error(), terr, sizeof(terr)));
            platform_socket_close(g_tls_listen_fd);
            g_tls_listen_fd = PLATFORM_SOCKET_INVALID;
        }
    }
}

/* Spawns the worker pool. g_workers_started records how far a partial
 * run got so rpc_http_stop() joins exactly what exists. */
static bool rpc_http_spawn_workers(void)
{
    for (size_t i = 0; i < RPC_HTTP_WORKERS; i++) {
        if (thread_registry_spawn("zcl_rpc_worker", rpc_worker_thread_fn,
                                      NULL, &g_worker_threads[i]) != 0) {
            perror("thread_registry_spawn");
            return false;
        }
        g_workers_started = i + 1;
        if (i == 0)
            thread_liveness_register(&g_rpc_worker_liveness, "zcl_rpc_worker", 0, 0);
    }
    return true;
}

/* Starts the TLS listener thread when TLS came up. On spawn failure
 * tears the TLS listener back down; the plain listener keeps serving. */
static void rpc_tls_spawn_listener(void)
{
    /* Start TLS listener thread if configured */
    if (g_tls_ctx && g_tls_listen_fd != PLATFORM_SOCKET_INVALID) {
        if (thread_registry_spawn("zcl_rpc_tls", tls_listen_thread_fn,
                                      NULL, &g_tls_listen_thread) == 0) {
            g_tls_listen_thread_started = true;
            thread_liveness_register(&g_rpc_tls_liveness, "zcl_rpc_tls", 0, 0);
        } else {
            fprintf(stderr, "RPC TLS: listener thread start failed\n");  // obs-ok:helper-context-logged
            platform_socket_close(g_tls_listen_fd);
            g_tls_listen_fd = PLATFORM_SOCKET_INVALID;
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
        }
    }
}

bool rpc_http_start(const struct rpc_table *table, uint16_t port,
                     const char *rpc_user, const char *rpc_password,
                     const char *datadir)
{
    if (rpc_http_already_started())
        return false;

    int queue_wait_ms = RPC_HTTP_QUEUE_WAIT_MS_DEFAULT;
    {
        const char *queue_wait_env = getenv("ZCL_RPC_QUEUE_WAIT_MS");
        queue_wait_ms = rpc_queue_wait_ms_from_env(queue_wait_env);
    }
    rpc_http_queue_start(queue_wait_ms);
    g_request_context = (struct rpc_http_request_context) {
        .table = table,
        .middleware = NULL,
        .timeout = NULL,
        .metrics_http_enable = false,
    };
    rpc_http_auth_configure(rpc_user, rpc_password, datadir, port);
    if (!rpc_loopback_listener_open(port))
        goto fail;

    rpc_http_configure_middleware();

    rpc_http_init_rpc_timeout();
    if (!rpc_timeout_start_watchdog(&g_rpc_timeout)) {
        fprintf(stderr, "RPC server: rpc_timeout watchdog start failed\n");  // obs-ok:helper-context-logged
    }
    g_request_context.timeout = &g_rpc_timeout;

    /* Optional GET /metrics Prometheus endpoint. Accept "1", "true",
     * "yes", "on" as truthy; anything else leaves it off. */
    g_request_context.metrics_http_enable = false;
    const char *mx = getenv("ZCL_METRICS_HTTP_ENABLE");
    if (rpc_metrics_env_flag_enabled(mx)) {
        g_request_context.metrics_http_enable = true;
        printf("RPC server: GET /metrics Prometheus endpoint enabled\n");
    }

    /* Optional TLS listener for non-loopback RPC. Set ZCL_RPC_TLS_CERT
     * and ZCL_RPC_TLS_KEY to PEM file paths. TLS listener binds to
     * 0.0.0.0 on rpcport+1 (or ZCL_RPC_TLS_PORT). Plain-text listener
     * stays on 127.0.0.1 for local tools. */
    g_tls_ctx = NULL;
    g_tls_listen_fd = PLATFORM_SOCKET_INVALID;
    g_tls_listen_thread_started = false;
    g_tls_port = 0;
    {
        const char *cert = getenv("ZCL_RPC_TLS_CERT");
        const char *key  = getenv("ZCL_RPC_TLS_KEY");
        if (rpc_tls_env_configured(cert, key)) {
            g_tls_ctx = tls_init(cert, key);
            if (g_tls_ctx) {
                /* Determine TLS port */
                g_tls_port = port + 1;
                const char *tp = getenv("ZCL_RPC_TLS_PORT");
                g_tls_port = rpc_tls_port_from_env(tp, g_tls_port);

                rpc_tls_listen_socket_setup();

                if (g_tls_listen_fd == PLATFORM_SOCKET_INVALID) {
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

    if (!rpc_http_spawn_workers())
        goto fail;

    if (thread_registry_spawn("zcl_rpc_listen", listen_thread_fn, NULL,
                                  &g_listen_thread) != 0) {
        perror("thread_registry_spawn");
        goto fail;
    }
    g_listen_thread_started = true;
    thread_liveness_register(&g_rpc_listen_liveness, "zcl_rpc_listen", 0, 0);

    rpc_tls_spawn_listener();

    rpc_http_auth_start_rotation();
    return true;

fail:
    rpc_http_stop();
    return false;
}

void rpc_http_stop(void)
{
    g_running = false;
    /* Liveness children must retire in reverse registration order because
     * supervisor_unregister() compacts its registry. Stop the cookie child
     * now, but retain credentials until every request worker has joined. */
    rpc_http_auth_stop_rotation();
    if (g_listen_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_shutdown_both(g_listen_fd);
        platform_socket_close(g_listen_fd);
        g_listen_fd = PLATFORM_SOCKET_INVALID;
    }
    if (g_tls_listen_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_shutdown_both(g_tls_listen_fd);
        platform_socket_close(g_tls_listen_fd);
        g_tls_listen_fd = PLATFORM_SOCKET_INVALID;
    }
    rpc_http_queue_wake();
    if (g_tls_listen_thread_started) {
        pthread_join(g_tls_listen_thread, NULL);
        g_tls_listen_thread_started = false;
        thread_liveness_retire(&g_rpc_tls_liveness);
    }
    if (g_listen_thread_started) {
        pthread_join(g_listen_thread, NULL);
        g_listen_thread_started = false;
        thread_liveness_retire(&g_rpc_listen_liveness);
    }
    if (g_workers_started > 0) {
        for (size_t i = 0; i < g_workers_started; i++)
            pthread_join(g_worker_threads[i], NULL);
        g_workers_started = 0;
        thread_liveness_retire(&g_rpc_worker_liveness);
    }

    rpc_http_queue_drain();
    rpc_http_auth_stop();
    g_request_context.table = NULL;
    g_request_context.middleware = NULL;
    g_request_context.timeout = NULL;
    g_request_context.metrics_http_enable = false;
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

