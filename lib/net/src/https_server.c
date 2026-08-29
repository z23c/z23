/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Public HTTPS server — serves the block explorer.
 * Uses OpenSSL for TLS. HTTP port redirects to HTTPS.
 * Bounded worker pool prevents unbounded detached thread growth.
 *
 * Listens on high ports (8443/8080) to avoid needing root or setcap on the node.
 * For public 443/80 access, a tiny capped userspace forwarder maps the ports
 * (the node stays unprivileged). See tools/zcl_portfwd.c,
 * deploy/systemd/zcl-portfwd.service, and docs/BLOCK_EXPLORER_HOSTING.md. */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif
#include "net/acme_challenge.h"
#include "net/https_frontdoor.h"
#include "net/https_server.h"
#include "https_server_internal.h"
#include "net/site_routes.h"
#include "platform/socket_compat.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"
#include "util/write_all.h"
#include "metrics/prometheus_metrics.h"

static SSL_CTX *g_ssl_ctx = NULL;
static platform_socket_t g_https_fd = PLATFORM_SOCKET_INVALID;
static platform_socket_t g_http_fd = PLATFORM_SOCKET_INVALID;
static pthread_t g_https_thread;
static pthread_t g_http_thread;
static pthread_t g_worker_threads[16];
static unsigned g_worker_threads_started = 0;
static bool g_https_thread_started = false;
static bool g_http_thread_started = false;
static _Atomic bool g_running = false;
static _Atomic int g_https_port = 0;
static char g_hostname[256] = "";
static pthread_mutex_t g_https_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_client_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_client_queue_cv = PTHREAD_COND_INITIALIZER;

/* Supervisor liveness for the 3 HTTPS/HTTP threads. Root children (not
 * supervisor_register_in_domain(...)): lib/net cannot include the app-side
 * supervisors/domains.h without a lib-layering violation — see
 * util/thread_liveness.h. All three legitimately idle (accept() blocks with
 * no deterministic timeout; the worker pool blocks on a queue condvar), so
 * they are liveness-only (no deadline, no progress gate) — present on the
 * tree, heartbeat when they do work, never falsely flagged for a quiet
 * cycle. g_worker_threads spawns N workers under one name ("zcl_https_wkr");
 * they share ONE contract — any worker's heartbeat proves at least one
 * worker loop is alive, the simplest honest claim for a pool. */
static struct thread_liveness_child g_https_wkr_liveness    = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_https_listen_liveness = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_http_listen_liveness  = { .id = SUPERVISOR_INVALID_ID };

/* Connection limit — prevents OOM under heavy load.
 * Each connection mallocs HTTPS_RESPONSE_BUFFER_SIZE for response data. */
#define MAX_HTTPS_CONNECTIONS 64
#define HTTPS_RESPONSE_BUFFER_SIZE (1024 * 1024)
static _Atomic int g_active_connections = 0;
static struct https_frontdoor_queue g_client_queue;

static bool client_queue_push(const struct https_frontdoor_client *client)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    bool ok = https_frontdoor_queue_push(&g_client_queue, client);
    pthread_cond_signal(&g_client_queue_cv);
    pthread_mutex_unlock(&g_client_queue_mutex);
    return ok;
}

static bool client_queue_pop(struct https_frontdoor_client *client)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    while (g_client_queue.len == 0 && atomic_load(&g_running))
        pthread_cond_wait(&g_client_queue_cv, &g_client_queue_mutex);
    bool ok = https_frontdoor_queue_pop(&g_client_queue, client);
    pthread_mutex_unlock(&g_client_queue_mutex);
    return ok;
}

static void client_queue_close_all(void)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    https_frontdoor_queue_close_all(&g_client_queue);
    pthread_mutex_unlock(&g_client_queue_mutex);
}

/* Written once by https_server_start_on_port() before any listener thread
 * exists, then read-only for the process lifetime — no lock needed. */
const char *https_server_configured_hostname(void)
{
    return g_hostname;
}

/* ── HTTP helpers ─────────────────────────────────────────── */

/* SSL_write may not accept the whole buffer at once — write in chunks. */
static void https_write_all(SSL *ssl, const unsigned char *buf, size_t n)
{
    size_t written = 0;
    while (written < n) {
        size_t chunk = n - written;
        if (chunk > 16384) chunk = 16384;
        int w = SSL_write(ssl, buf + written, (int)chunk);
        if (w <= 0) break;
        written += (size_t)w;
    }
}

/* App-mount handler prototypes — expanded from net/site_routes.def, the
 * single registry (lib/net never includes app/ headers). The same def
 * also generates the dispatch below, the onion twin in onion_service.c,
 * and the ratelimit classification in onion_ratelimit.c. */
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_EXTERN_##flavor(handler)
#include "net/site_routes.def"
#undef SITE_ROUTE

/* ── HTTPS handler ────────────────────────────────────────── */

static void handle_https_client(SSL *ssl, platform_socket_t fd,
                                int64_t deadline_ms)
{
    struct https_frontdoor_ssl_reader reader = {
        .ssl = ssl, .fd = fd, .deadline_ms = deadline_ms,
    };
    char line[4096];
    if (!https_frontdoor_read_line(&reader, https_frontdoor_ssl_read_byte,
                                   line, sizeof(line), deadline_ms))
        return;

    char method[16] = "", path[2048] = "";
    if (sscanf(line, "%15s %2047s", method, path) != 2)
        return;

    /* Read remaining headers (discard). Cap the count so a peer streaming
     * endless headers cannot pin this thread. */
    int hdr_count = 0;
    bool headers_complete = false;
    while (https_frontdoor_read_line(&reader,
                                     https_frontdoor_ssl_read_byte,
                                     line, sizeof(line), deadline_ms)) {
        if (line[0] == '\0') {
            headers_complete = true;
            break;
        }
        if (++hdr_count > HTTP_MAX_REQUEST_HEADERS) return;
    }
    if (!headers_complete)
        return;
    if (!platform_socket_set_nonblocking(fd, false))
        return;

    /* Only serve GET requests to explorer routes */
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
        const char *resp =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "Only GET is supported.\n";
        SSL_write(ssl, resp, (int)strlen(resp));
        return;
    }

    /* Redirect root to explorer */
    if (strcmp(path, "/") == 0) {
        const char *resp =
            "HTTP/1.1 302 Found\r\n"
            "Location: /explorer\r\n"
            "Connection: close\r\n\r\n";
        SSL_write(ssl, resp, (int)strlen(resp));
        return;
    }

    /* Prometheus /metrics endpoint on HTTPS */
    if (strcmp(path, "/metrics") == 0) {
        size_t cap = 131072;
        char *mbuf = zcl_malloc(cap, "https_metrics_buf");
        if (!mbuf) return;
        size_t n = metrics_prometheus_render_prometheus(mbuf, cap);
        char hdr[256];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
            "Connection: close\r\n"
            "Content-Length: %zu\r\n\r\n", n);
        SSL_write(ssl, hdr, hlen);
        size_t written = 0;
        while (written < n) {
            size_t chunk = n - written;
            if (chunk > 16384) chunk = 16384;
            int w = SSL_write(ssl, mbuf + written, (int)chunk);
            if (w <= 0) break;
            written += (size_t)w;
        }
        free(mbuf);
        return;
    }

    /* Operator-private API gate — this clearnet 0.0.0.0 listener is
     * untrusted ingress, and the API router cannot authenticate (it
     * never sees headers or peer identity — see api_handle_request),
     * so the gate lives here. The onion service exposes no /api;
     * wallet_gui calls explorer_handle_request in-process and is
     * unaffected. Deliberately no Access-Control-Allow-Origin
     * header on the refusal. */
    if (strncmp(path, "/api", 4) == 0) {
        extern bool api_route_is_operator_private(const char *path);
        if (api_route_is_operator_private(path)) {
            const char *resp =
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n\r\n"
                "{\"error\":\"operator-private endpoint: "
                "not served on the public listener\"}";
            SSL_write(ssl, resp, (int)strlen(resp));
            return;
        }
    }

    /* App MVC mounts — expanded from net/site_routes.def in registry
     * order. This listener is GET/HEAD-only (checked above), so every
     * row's POST surface (the store's order mints, the names register,
     * the yardsale ceremony) stays onion-only; the store and market_chunk
     * mounts are onion-only and expand to nothing here. PLAIN rows prefix-match
     * with no boundary guard; DATADIR and FAILCLOSED rows keep their
     * path[N] ∈ {NUL, '/', '?'} guard; DATADIR passes NULL for the
     * datadir (the handler resolves GetDataDir(true) itself — this
     * listener carries no datadir context); FAILCLOSED turns a handler 0
     * into a 503 carrying the row's fail_body. */
#define ZCL_HTTPS_DISPATCH_STORE(id, prefix, handler, fail_body) \
    /* onion-only mount — this listener never serves it */
#define ZCL_HTTPS_DISPATCH_ONIONCLOSED(id, prefix, handler, fail_body) \
    /* onion-only mount — this listener never serves it */
#define ZCL_HTTPS_DISPATCH_PLAIN(id, prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0) { \
        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE, \
                                        "https_" #id "_buf"); \
        if (!buf) return; \
        size_t site_n_ = handler(method, path, NULL, 0, buf, \
                                 HTTPS_RESPONSE_BUFFER_SIZE); \
        if (site_n_ > 0) \
            https_write_all(ssl, buf, site_n_); \
        free(buf); \
        return; \
    }
#define ZCL_HTTPS_DISPATCH_DATADIR(id, prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        (path[sizeof(prefix) - 1] == 0 || path[sizeof(prefix) - 1] == '/' || \
         path[sizeof(prefix) - 1] == '?')) { \
        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE, \
                                        "https_" #id "_buf"); \
        if (!buf) return; \
        size_t site_n_ = handler(method, path, NULL, 0, buf, \
                                 HTTPS_RESPONSE_BUFFER_SIZE, NULL); \
        if (site_n_ > 0) \
            https_write_all(ssl, buf, site_n_); \
        free(buf); \
        return; \
    }
#define ZCL_HTTPS_DISPATCH_FAILCLOSED(id, prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        (path[sizeof(prefix) - 1] == 0 || path[sizeof(prefix) - 1] == '/' || \
         path[sizeof(prefix) - 1] == '?')) { \
        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE, \
                                        "https_" #id "_buf"); \
        if (!buf) return; \
        size_t site_n_ = handler(method, path, NULL, 0, buf, \
                                 HTTPS_RESPONSE_BUFFER_SIZE); \
        if (site_n_ > 0) { \
            https_write_all(ssl, buf, site_n_); \
        } else { \
            const char *resp = \
                "HTTP/1.1 503 Service Unavailable\r\n" \
                "Content-Type: text/plain\r\n" \
                "Connection: close\r\n\r\n" fail_body; \
            SSL_write(ssl, resp, (int)strlen(resp)); \
        } \
        free(buf); \
        return; \
    }
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_HTTPS_DISPATCH_##flavor(id, prefix, handler, fail_body)
#include "net/site_routes.def"
#undef SITE_ROUTE
#undef ZCL_HTTPS_DISPATCH_FAILCLOSED
#undef ZCL_HTTPS_DISPATCH_ONIONCLOSED
#undef ZCL_HTTPS_DISPATCH_DATADIR
#undef ZCL_HTTPS_DISPATCH_PLAIN
#undef ZCL_HTTPS_DISPATCH_STORE

    extern const char *explorer_canonical_shortcut(const char *path);

    /* Explorer + API routes — call the explorer handler (which delegates /api/) */
    if (strncmp(path, "/explorer", 9) == 0 ||
        strncmp(path, "/api", 4) == 0 ||
        explorer_canonical_shortcut(path) != NULL) {
        extern size_t explorer_handle_request(const char *, const char *,
            const unsigned char *, size_t, unsigned char *, size_t);

        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE,
                                        "https_resp_buf");
        if (!buf) return;

        size_t n = explorer_handle_request(method, path, NULL, 0, buf,
                                           HTTPS_RESPONSE_BUFFER_SIZE);
        if (n > 0) {
            /* Write in chunks — SSL_write may not accept large buffers at once */
            size_t written = 0;
            while (written < n) {
                size_t chunk = n - written;
                if (chunk > 16384) chunk = 16384;
                int w = SSL_write(ssl, buf + written, (int)chunk);
                if (w <= 0) break;
                written += (size_t)w;
            }
        } else {
            const char *resp =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Not found.\n";
            SSL_write(ssl, resp, (int)strlen(resp));
        }
        free(buf);
        return;
    }

    /* Anything else → 404 */
    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: /explorer\r\n"
        "Connection: close\r\n\r\n";
    SSL_write(ssl, resp, (int)strlen(resp));
}

static void handle_https_client_fd(platform_socket_t fd, int64_t deadline_ms)
{
    atomic_fetch_add(&g_active_connections, 1);

    if (!platform_socket_set_nonblocking(fd, true)) {
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }

    /* The condition is computed into a variable rather than split across the
     * #if arms of a single `if (`. Both spellings compile, but the split form
     * opens a brace in each arm and closes it in neither, so any tool that
     * counts braces without evaluating the preprocessor double-counts and
     * loses track of which function it is in for the rest of the file --
     * which is exactly how check-log-macro-return-type came to report five
     * correct LOG_FAIL uses as errors. */
#if defined(_WIN32)
    /* Winsock's SOCKET is handle-sized; SSL_set_fd takes an int, so refuse a
     * descriptor that cannot round-trip instead of truncating it. */
    const bool fd_bound = (uintptr_t)fd <= INT_MAX &&
                          SSL_set_fd(ssl, (int)(uintptr_t)fd) == 1;
#else
    const bool fd_bound = SSL_set_fd(ssl, fd) == 1;
#endif
    if (!fd_bound) {
        SSL_free(ssl);
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }

    if (!https_frontdoor_ssl_accept(ssl, fd, deadline_ms)) {
        SSL_free(ssl);
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }

    handle_https_client(ssl, fd, deadline_ms);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    platform_socket_close(fd);
    atomic_fetch_sub(&g_active_connections, 1);
}

static void *https_listen_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        platform_socket_t client_fd = platform_socket_accept(
            g_https_fd, (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_https_listen_liveness, -1);
        if (client_fd == PLATFORM_SOCKET_INVALID) {
            continue;
        }

        /* Reject if too many concurrent connections (prevents OOM) */
        if (atomic_load(&g_active_connections) >= MAX_HTTPS_CONNECTIONS) {
            const char *busy = "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 5\r\nConnection: close\r\n\r\n";
            /* Best-effort courtesy status: this connection is being closed
             * either way, and the alternative to a partial 503 is a bare RST,
             * which the client already handles. Not worth logging — an
             * attacker driving us to the connection cap would then also
             * control our log volume. */
            (void)platform_socket_send_all(client_fd, busy, strlen(busy));
            platform_socket_close(client_fd);
            continue;
        }

        /* Slowloris protection: 15s timeout for HTTPS requests.
         * Heavy pages (HODL, stats) are pre-cached so serve instantly. */
        (void)platform_socket_set_receive_timeout(client_fd, 15000);
        (void)platform_socket_set_send_timeout(client_fd, 15000);

        int64_t deadline_ms = 0;
        if (!https_frontdoor_deadline_start(&deadline_ms)) {
            platform_socket_close(client_fd);
            continue;
        }
        struct https_frontdoor_client ca = {
            .fd = client_fd,
            .tls = true,
            .deadline_ms = deadline_ms,
        };
        if (!client_queue_push(&ca)) {
            const char *busy = "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 5\r\nConnection: close\r\n\r\n";
            /* Best-effort: see the connection-cap branch above. */
            (void)platform_socket_send_all(client_fd, busy, strlen(busy));
            platform_socket_close(client_fd);
        }
    }
    return NULL;
}

/* ── HTTP listener (port 80) ──────────────────────────────── */
/* The requests this accepts are served by https_server_redirect.c. */

static void *http_listen_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        platform_socket_t client_fd = platform_socket_accept(
            g_http_fd, (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_http_listen_liveness, -1);
        if (client_fd == PLATFORM_SOCKET_INVALID) {
            continue;
        }

        (void)platform_socket_set_receive_timeout(client_fd, 5000);

        int64_t deadline_ms = 0;
        if (!https_frontdoor_deadline_start(&deadline_ms)) {
            platform_socket_close(client_fd);
            continue;
        }
        struct https_frontdoor_client ca = {
            .fd = client_fd,
            .tls = false,
            .deadline_ms = deadline_ms,
        };
        if (!client_queue_push(&ca)) {
            const char *busy = "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 5\r\nConnection: close\r\n\r\n";
            /* Best-effort: see https_listen_fn(). */
            (void)platform_socket_send_all(client_fd, busy, strlen(busy));
            platform_socket_close(client_fd);
        }
    }
    return NULL;
}

static void *https_worker_fn(void *arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        struct https_frontdoor_client ca;

        if (!client_queue_pop(&ca))
            break;
        thread_liveness_beat(&g_https_wkr_liveness, -1);
        if (ca.fd == PLATFORM_SOCKET_INVALID)
            continue;
        if (!https_frontdoor_deadline_active(ca.deadline_ms)) {
            platform_socket_close(ca.fd);
            continue;
        }
        if (ca.tls)
            handle_https_client_fd(ca.fd, ca.deadline_ms);
        else
            https_server_handle_http_client_fd(ca.fd, ca.deadline_ms);
    }

    return NULL;
}

/* ── Bind helper ──────────────────────────────────────────── */

static platform_socket_t bind_port(uint16_t port, bool any_addr)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        LOG_ERR("https", "socket() failed");

    (void)platform_socket_set_reuse_address(fd, true);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = any_addr ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (platform_socket_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        platform_socket_close(fd);
        LOG_ERR("https", "bind port %u failed", port);
    }
    if (platform_socket_listen(fd, 32) != 0) {
        platform_socket_close(fd);
        LOG_ERR("https", "listen on port %u failed", port);
    }
    return fd;
}

/* ── Public API ───────────────────────────────────────────── */

bool https_server_start_on_port(const char *cert_path, const char *key_path,
                                const char *hostname, int https_port, int http_port)
{
    unsigned started_workers = 0;

#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif

    pthread_mutex_lock(&g_https_state_mutex);
    if (atomic_load(&g_running) || g_https_thread_started) {
        pthread_mutex_unlock(&g_https_state_mutex);
        return true;
    }

    if (hostname)
        snprintf(g_hostname, sizeof(g_hostname), "%s", hostname);

    /* Init OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    g_ssl_ctx = SSL_CTX_new(method);
    if (!g_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "SSL_CTX_new failed");
        return false;
    }

    /* Set minimum TLS 1.2 */
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);

    /* TLS-ALPN-01 responder (RFC 8737). One call: the module owns the armed
     * state and the challenge certificate, and presents it only while an ACME
     * validation is in flight for the name in SNI. Port 80 is deliberately not
     * forwarded here, so this is the only challenge type the node can answer
     * -- see net/acme_challenge.h. */
    if (!acme_alpn_install(g_ssl_ctx)) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "cannot install the TLS-ALPN-01 certificate responder");
        return false;
    }

    if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, cert_path) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "failed to load cert: %s", cert_path);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "failed to load private key: %s", key_path);
        return false;
    }
    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "cert/key mismatch: cert=%s key=%s",
                  cert_path, key_path);
        return false;
    }

    /* Bind HTTPS port (iptables redirects 443→default 8443) */
    g_https_fd = bind_port(https_port, true);
    if (g_https_fd == PLATFORM_SOCKET_INVALID) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "cannot bind HTTPS port %d", https_port);
        return false;
    }

    /* Bind HTTP port for redirect */
    g_http_fd = bind_port(http_port, true);
    if (g_http_fd == PLATFORM_SOCKET_INVALID) {
        fprintf(stderr, "HTTPS: cannot bind port %d, HTTP redirect won't work\n",  // obs-ok:bind-failure-non-fatal
                http_port);
        /* Non-fatal — continue with HTTPS only */
    }

    atomic_store(&g_running, true);
    atomic_store(&g_https_port, https_port);
    g_client_queue = (struct https_frontdoor_queue){0};
    atomic_store(&g_active_connections, 0);

    for (unsigned i = 0; i < (sizeof(g_worker_threads) / sizeof(g_worker_threads[0])); i++) {
        if (thread_registry_spawn("zcl_https_wkr", https_worker_fn,
                                      NULL, &g_worker_threads[i]) != 0) {
            fprintf(stderr, "HTTPS: worker thread failed\n");  // obs-ok:thread-spawn-fallback-logged
            break;
        }
        started_workers++;
        if (i == 0)
            thread_liveness_register(&g_https_wkr_liveness, "zcl_https_wkr", 0, 0);
    }
    g_worker_threads_started = started_workers;
    if (g_worker_threads_started == 0) {
        atomic_store(&g_running, false);
        platform_socket_close(g_https_fd);
        g_https_fd = PLATFORM_SOCKET_INVALID;
        if (g_http_fd != PLATFORM_SOCKET_INVALID) {
            platform_socket_close(g_http_fd);
            g_http_fd = PLATFORM_SOCKET_INVALID;
        }
        if (g_ssl_ctx) {
            SSL_CTX_free(g_ssl_ctx);
            g_ssl_ctx = NULL;
        }
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "no worker threads could be started");
        return false;
    }

    if (thread_registry_spawn("zcl_https_listen", https_listen_fn, NULL,
                                  &g_https_thread) != 0) {
        platform_socket_close(g_https_fd);
        g_https_fd = PLATFORM_SOCKET_INVALID;
        atomic_store(&g_running, false);
        pthread_cond_broadcast(&g_client_queue_cv);
        pthread_mutex_unlock(&g_https_state_mutex);
        for (unsigned i = 0; i < g_worker_threads_started; i++)
            pthread_join(g_worker_threads[i], NULL);
        g_worker_threads_started = 0;
        if (g_ssl_ctx) {
            SSL_CTX_free(g_ssl_ctx);
            g_ssl_ctx = NULL;
        }
        LOG_ERROR("https", "thread_registry_spawn failed for HTTPS listen thread");
        return false;
    }
    g_https_thread_started = true;
    thread_liveness_register(&g_https_listen_liveness, "zcl_https_listen", 0, 0);

    if (g_http_fd != PLATFORM_SOCKET_INVALID) {
        if (thread_registry_spawn("zcl_http_listen", http_listen_fn, NULL,
                                      &g_http_thread) != 0) {
            fprintf(stderr, "HTTPS: HTTP redirect thread failed\n");  // obs-ok:thread-spawn-fallback-logged
            platform_socket_close(g_http_fd);
            g_http_fd = PLATFORM_SOCKET_INVALID;
        } else {
            g_http_thread_started = true;
            thread_liveness_register(&g_http_listen_liveness, "zcl_http_listen", 0, 0);
        }
    }
    pthread_mutex_unlock(&g_https_state_mutex);

    printf("HTTPS server listening on 0.0.0.0:%d (TLS)\n", https_port);
    if (g_http_fd != PLATFORM_SOCKET_INVALID)
        printf("HTTP redirect on 0.0.0.0:%d -> https://%s\n", http_port, g_hostname);

    return true;
}

bool https_server_start(const char *cert_path, const char *key_path,
                         const char *hostname)
{
    return https_server_start_on_port(cert_path, key_path, hostname, 8443, 8080);
}

void https_server_stop(void)
{
    pthread_t https_thread;
    pthread_t http_thread;
    pthread_t worker_threads[sizeof(g_worker_threads) / sizeof(g_worker_threads[0])];
    unsigned worker_threads_started = 0;
    bool have_https_thread = false;
    bool have_http_thread = false;
    platform_socket_t https_fd = PLATFORM_SOCKET_INVALID;
    platform_socket_t http_fd = PLATFORM_SOCKET_INVALID;

    pthread_mutex_lock(&g_https_state_mutex);
    if (!atomic_load(&g_running) && !g_https_thread_started &&
        !g_http_thread_started && g_worker_threads_started == 0) {
        pthread_mutex_unlock(&g_https_state_mutex);
        return;
    }
    atomic_store(&g_running, false);
    atomic_store(&g_https_port, 0);
    https_fd = g_https_fd;
    http_fd = g_http_fd;
    g_https_fd = PLATFORM_SOCKET_INVALID;
    g_http_fd = PLATFORM_SOCKET_INVALID;
    if (g_https_thread_started) {
        https_thread = g_https_thread;
        g_https_thread_started = false;
        have_https_thread = true;
    }
    if (g_http_thread_started) {
        http_thread = g_http_thread;
        g_http_thread_started = false;
        have_http_thread = true;
    }
    worker_threads_started = g_worker_threads_started;
    for (unsigned i = 0; i < worker_threads_started; i++)
        worker_threads[i] = g_worker_threads[i];
    g_worker_threads_started = 0;
    pthread_mutex_unlock(&g_https_state_mutex);

    if (https_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_shutdown_both(https_fd);
        platform_socket_close(https_fd);
    }
    if (http_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_shutdown_both(http_fd);
        platform_socket_close(http_fd);
    }
    pthread_cond_broadcast(&g_client_queue_cv);
    client_queue_close_all();

    if (have_https_thread) {
        pthread_join(https_thread, NULL);
        thread_liveness_retire(&g_https_listen_liveness);
    }
    if (have_http_thread) {
        pthread_join(http_thread, NULL);
        thread_liveness_retire(&g_http_listen_liveness);
    }
    for (unsigned i = 0; i < worker_threads_started; i++)
        pthread_join(worker_threads[i], NULL);
    if (worker_threads_started > 0)
        thread_liveness_retire(&g_https_wkr_liveness);
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
    printf("HTTPS server stopped.\n");
}

/* ── Deferred HTTPS start (after IBD completes) ──────────── */

bool https_server_is_running(void)
{
    return atomic_load(&g_running);
}

int https_server_port(void)
{
    return atomic_load(&g_https_port);
}
