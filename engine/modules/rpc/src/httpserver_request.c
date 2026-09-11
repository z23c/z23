/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Authenticated request dispatch for an already-admitted RPC connection.
 *
 * Listener and queue ownership end at this interface. The caller supplies a
 * read-only runtime context; this unit owns the connection until it closes it
 * or explicitly transfers the raw descriptor to ws_events. */

#include "httpserver_request.h"

#include "httpserver_auth.h"
#include "httpserver_transport.h"
#include "json/json.h"
#include "metrics/prometheus_metrics.h"
#include "net/ws_events.h"
#include "rpc/httpserver.h"
#include "rpc/protocol.h"
#include "util/safe_alloc.h"
#include "util/trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define HTTP_MAX_REQUEST_HEADERS 512

/* Pre-flight for one admitted connection, in the original order: drop a
 * peer that already hung up, resolve the source IP, register the timeout
 * slot, then run the ban + rate-limit middleware. Returns false when the
 * caller must head straight for its single exit; *tmo_slot is written
 * before any false return so that exit always sees a valid slot id. */
static bool http_request_preflight(
    struct rpc_conn *conn,
    const struct rpc_http_request_context *context,
    platform_socket_t client_fd,
    uint32_t *client_ip_be,
    int *tmo_slot)
{
    /* Cheapest possible drop for a client that already hung up. It
     * costs one poll(), and it keeps a dead peer from consuming a
     * middleware decision and one of rpc_timeout's 128 slots on its way
     * to being closed anyway. */
    if (rpc_conn_peer_gone(conn))
        return false;

    /* Look up the source IP via getpeername() so we can drive the
     * middleware (rate limit + ban check) without changing the queue
     * shape. */
    {
        struct sockaddr_in peer;
#if defined(_WIN32)
        int peer_len = sizeof(peer);
#else
        socklen_t peer_len = sizeof(peer);
#endif
        if (getpeername(client_fd, (struct sockaddr *)&peer, &peer_len) == 0
            && peer.sin_family == AF_INET) {
            *client_ip_be = peer.sin_addr.s_addr;
        }
    }

    /* Register this request with the timeout watchdog. The watchdog
     * will shutdown() our fd if the dispatch phase runs past
     * ZCL_RPC_TIMEOUT_MS — our in-flight read/write then fails and
     * we unwind cleanly. */
    if (context->timeout != NULL) {
        *tmo_slot = rpc_timeout_register(context->timeout, client_fd,
                                         *client_ip_be);
    }

    /* Pre-flight: ban + rate limit BEFORE we touch the request.
     * The middleware is loopback-aware and will exempt 127.0.0.0/8
     * from ban + per-IP buckets. */
    if (context->middleware != NULL) {
        enum rpc_http_decision d =
            rpc_http_middleware_check(context->middleware, *client_ip_be);
        if (d == RPC_HTTP_BANNED) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                -32003, "IP banned", NULL, NULL);
            rpc_conn_send_response(conn, 403, "Forbidden", errbuf, elen);
            return false;
        }
        if (d == RPC_HTTP_RATE_LIMITED_GLOBAL ||
            d == RPC_HTTP_RATE_LIMITED_PER_IP) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                -32005, "Rate limit exceeded", NULL, NULL);
            rpc_conn_send_response(conn, 429, "Too Many Requests",
                          errbuf, elen);
            return false;
        }
    }

    return true;
}

/* GET /metrics. Every path in here is terminal in the original, so the
 * caller unconditionally falls through to its single exit afterwards. */
static void http_handle_metrics_route(
    struct rpc_conn *conn,
    const struct rpc_http_request_context *context,
    uint32_t client_ip_be,
    char *line,
    size_t line_sz)
{
    if (!context->metrics_http_enable) {
        /* Drain request headers so the socket closes cleanly. */
        int drain_hdrs = 0;
        while (read_line(conn, line, line_sz)) {
            if (line[0] == '\0') break;
            if (++drain_hdrs > HTTP_MAX_REQUEST_HEADERS) return;
        }
        const char *msg = "metrics endpoint disabled "
                          "(set ZCL_METRICS_HTTP_ENABLE=1)";
        rpc_conn_send_response_with_type(conn, 404, "Not Found",
                                "text/plain; charset=utf-8",
                                msg, strlen(msg));
        return;
    }

    char metrics_auth[512] = {0};
    int metrics_hdrs = 0;
    while (read_line(conn, line, line_sz)) {
        if (line[0] == '\0') break;
        if (++metrics_hdrs > HTTP_MAX_REQUEST_HEADERS) return;
        if (strncasecmp(line, "Authorization:", 14) == 0)
            snprintf(metrics_auth, sizeof(metrics_auth),
                     "%s", line + 14);
    }

    if (!rpc_http_auth_check(metrics_auth[0] ? metrics_auth : NULL)) {
        if (context->middleware != NULL)
            rpc_http_middleware_record_auth_fail(context->middleware,
                                                 client_ip_be);
        const char *msg = "authentication required";
        rpc_conn_send_response_with_type(conn, 401, "Unauthorized",
                                "text/plain; charset=utf-8",
                                msg, strlen(msg));
        return;
    }
    if (context->middleware != NULL)
        rpc_http_middleware_record_success(context->middleware,
                                           client_ip_be);

    size_t cap = 131072;
    char *buf = zcl_malloc(cap, "http_read_buf");
    if (!buf) {
        const char *oom = "out of memory";
        rpc_conn_send_response_with_type(conn, 500,
                                "Internal Server Error",
                                "text/plain; charset=utf-8",
                                oom, strlen(oom));
        return;
    }
    size_t n = metrics_prometheus_render_prometheus(buf, cap);
    /* Prometheus exposition format 0.0.4 */
    rpc_conn_send_response_with_type(conn, 200, "OK",
        "text/plain; version=0.0.4; charset=utf-8",
        buf, n);
    free(buf);
}

/* The /events path match, verbatim from the original guard: the path may
 * carry a query string (/events?domain=chain,peer) but nothing else. */
static bool http_path_is_events(const char *path)
{
    return strncmp(path, "/events", 7) == 0 &&
           (path[7] == '\0' || path[7] == '?');
}

/* Read headers looking for WebSocket upgrade fields. Returns false only
 * on the header-count guard, which is terminal for the caller. This loop
 * keeps its own HTTP_MAX_REQUEST_HEADERS counter, exactly as the other
 * header readers in this file do. */
static bool http_events_read_headers(
    struct rpc_conn *conn,
    char *line,
    size_t line_sz,
    char *ws_key,
    size_t ws_key_sz,
    char *ws_auth,
    size_t ws_auth_sz,
    bool *is_upgrade)
{
    int ws_hdrs = 0;
    while (read_line(conn, line, line_sz)) {
        if (line[0] == '\0') break;
        if (++ws_hdrs > HTTP_MAX_REQUEST_HEADERS) return false;
        if (strncasecmp(line, "Upgrade:", 8) == 0 &&
            strstr(line + 8, "websocket"))
            *is_upgrade = true;
        if (strncasecmp(line, "Authorization:", 14) == 0)
            snprintf(ws_auth, ws_auth_sz, "%s", line + 14);
        if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
            const char *p = line + 18;
            while (*p == ' ') p++;
            snprintf(ws_key, ws_key_sz, "%s", p);
            /* Trim trailing whitespace */
            size_t kl = strlen(ws_key);
            while (kl > 0 && (ws_key[kl-1] == '\r' ||
                   ws_key[kl-1] == '\n' || ws_key[kl-1] == ' '))
                ws_key[--kl] = '\0';
        }
    }
    return true;
}

/* WebSocket event stream at GET /events. Returns true when the route is
 * terminal (the caller goes to its single exit), false when the request
 * was not a WebSocket upgrade and must fall through to the non-POST
 * rejection below — exactly the original "fall through to reject". */
static bool http_handle_events_route(
    struct rpc_conn *conn,
    const struct rpc_http_request_context *context,
    const char *path,
    platform_socket_t client_fd,
    uint32_t client_ip_be,
    char *line,
    size_t line_sz,
    bool *fd_transferred)
{
    char ws_key[128] = {0};
    char ws_auth[512] = {0};
    bool is_upgrade = false;
    if (!http_events_read_headers(conn, line, line_sz,
                                  ws_key, sizeof(ws_key),
                                  ws_auth, sizeof(ws_auth), &is_upgrade))
        return true;
    if (is_upgrade && ws_key[0]) {
        /* Same Basic-auth gate as the JSON-RPC path: the event
         * stream exposes chain/peer/wallet activity, so an
         * unauthenticated upgrade is an information leak. */
        if (!rpc_http_auth_check(ws_auth[0] ? ws_auth : NULL)) {
            if (context->middleware != NULL)
                rpc_http_middleware_record_auth_fail(context->middleware,
                                                     client_ip_be);
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                HTTP_UNAUTHORIZED, "Unauthorized", NULL, NULL);
            rpc_conn_send_response(conn, 401, "Unauthorized",
                          errbuf, elen);
            return true;
        }
        if (context->middleware != NULL)
            rpc_http_middleware_record_success(context->middleware,
                                               client_ip_be);
        /* ws_events owns a raw fd only — handing it a TLS socket
         * would write the 101 handshake plaintext beneath the TLS
         * stream and orphan the SSL object on the early return.
         * Refuse over SSL instead; done: SSL_frees via conn_close. */
        if (conn->ssl) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INVALID_REQUEST,
                "WebSocket /events not supported on the TLS listener",
                NULL, NULL);
            rpc_conn_send_response(conn, 501, "Not Implemented",
                          errbuf, elen);
            return true;
        }
        const char *query = strchr(path, '?');
        if (ws_events_upgrade(client_fd, path, ws_key, query)) {
            /* Ownership moves to ws_events (which polls for
             * POLLHUP and reaps idle clients itself). Record the
             * hand-off and fall through to the ONE exit — the old
             * bare `return` skipped trace_end() and leaked the
             * rpc.dispatch span on every successful upgrade. */
            *fd_transferred = true;
            return true;
        }
        /* Upgrade failed — fall through to 503 */
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            -32006, "WebSocket capacity full (max 100)", NULL, NULL);
        rpc_conn_send_response(conn, 503, "Service Unavailable",
                      errbuf, elen);
        return true;
    }
    /* Not a WebSocket upgrade — fall through to reject */
    return false;
}

/* Scan the POST request headers for Content-Length and Authorization.
 * Returns false only on the header-count guard, which is terminal for
 * the caller. Keeps its own HTTP_MAX_REQUEST_HEADERS counter. */
static bool http_post_read_headers(
    struct rpc_conn *conn,
    char *line,
    size_t line_sz,
    size_t *content_length,
    char *auth_value,
    size_t auth_value_sz)
{
    int post_hdrs = 0;
    while (read_line(conn, line, line_sz)) {
        if (line[0] == '\0') break;
        if (++post_hdrs > HTTP_MAX_REQUEST_HEADERS) return false;
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            char *endp = NULL;
            long v = strtol(line + 15, &endp, 10);
            if (endp == line + 15 || v < 0 || v > 10 * 1024 * 1024)
                *content_length = 0;
            else
                *content_length = (size_t)v;
        }
        if (strncasecmp(line, "Authorization:", 14) == 0)
            snprintf(auth_value, auth_value_sz, "%s", line + 14);
    }
    return true;
}

/* Non-POST rejection, POST header scan, Basic-auth gate and the body
 * bounds check. Returns false when the caller must go to its single
 * exit; only the oversize-body branch sends a response first. */
static bool http_parse_and_authenticate_post(
    struct rpc_conn *conn,
    const struct rpc_http_request_context *context,
    const char *method,
    char *line,
    size_t line_sz,
    uint32_t client_ip_be,
    size_t *content_length)
{
    /* No blog over clearnet. Blog is Tor-only via dynhost.
     * Clearnet serves ONLY authenticated RPC (POST). */
    if (strcmp(method, "POST") != 0) {
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            RPC_INVALID_REQUEST, "Method not allowed", NULL, NULL);
        rpc_conn_send_response(conn, 405, "Method Not Allowed",
                      errbuf, elen);
        return false;
    }

    char auth_value[512] = {0};
    if (!http_post_read_headers(conn, line, line_sz, content_length,
                                auth_value, sizeof(auth_value)))
        return false;

    if (!rpc_http_auth_check(auth_value[0] ? auth_value : NULL)) {
        if (context->middleware != NULL)
            rpc_http_middleware_record_auth_fail(context->middleware,
                                                 client_ip_be);
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            HTTP_UNAUTHORIZED, "Unauthorized", NULL, NULL);
        rpc_conn_send_response(conn, 401, "Unauthorized", errbuf, elen);
        return false;
    }
    if (context->middleware != NULL)
        rpc_http_middleware_record_success(context->middleware,
                                           client_ip_be);

    if (*content_length == 0 || *content_length > 10 * 1024 * 1024) {
        if (*content_length > 10 * 1024 * 1024) {
            char errbuf[256];
            size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
                RPC_INVALID_REQUEST, "Request body too large", NULL,
                NULL);
            rpc_conn_send_response(conn, 413, "Payload Too Large",
                          errbuf, elen);
        }
        return false;
    }

    return true;
}

/* Read the body, parse it, execute the method and write the envelope.
 * Every path in the original flows to the same point just before the
 * single exit, so this is one unconditional call for the caller. */
static void http_dispatch_json_rpc(
    struct rpc_conn *conn,
    const struct rpc_http_request_context *context,
    size_t content_length,
    int tmo_slot,
    struct trace_span *rpc_span)
{
    char *body = zcl_malloc(content_length + 1, "http_body");
    if (!body) return;

    if (!read_exact(conn, body, content_length)) {
        free(body);
        return;
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
        rpc_conn_send_response(conn, 200, "OK", errbuf, elen);
        return;
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
        rpc_conn_send_response(conn, 200, "OK", errbuf, elen);
        return;
    }
    json_free(&request);

    /* Now that we know the method name, label the timeout slot so
     * EV_RPC_TIMEOUT carries useful context if the watchdog kills us
     * during dispatch. */
    if (tmo_slot >= 0) {
        rpc_timeout_set_method(context->timeout, tmo_slot, req.method);
    }
    trace_attr_str(rpc_span, "method", req.method);

    struct json_value result;
    json_init(&result);
    bool rpc_ok = rpc_table_execute(context->table, req.method,
                                    &req.params, &result);

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
        rpc_conn_send_response(conn, 200, "OK", resp_buf, resp_len);
        free(resp_buf);
    } else {
        char errbuf[256];
        size_t elen = json_rpc_error_response(errbuf, sizeof(errbuf),
            RPC_OUT_OF_MEMORY, "Internal error: response too large or "
            "out of memory", req.method, NULL);
        rpc_conn_send_response(conn, 500, "Internal Server Error",
                      errbuf, elen);
    }

    json_free(&result);
    json_free(&response);
    json_request_free(&req);
}

void rpc_http_request_handle(
    struct rpc_conn conn,
    const struct rpc_http_request_context *context)
{
    struct trace_span *rpc_span = trace_start("rpc.dispatch");
        platform_socket_t client_fd = conn.fd;
    /* Ownership hand-off flag. Set only where another module takes the
     * fd; done: is then the SINGLE exit that closes what we still own.
     * The /events upgrade used to `return` past done: outright, which
     * also leaked the rpc_span trace_start() allocated above. */
    bool fd_transferred = false;
    /* Declared before the first `goto done` so the label never reads an
     * indeterminate slot id. -1 means table full or module disabled;
     * either way we proceed without tracking. */
    int tmo_slot = -1;
    uint32_t client_ip_be = 0x0100007Fu; /* fall back to 127.0.0.1 */

    /* Bound both directions before touching the wire: slowloris on the
     * read side, a client that stops reading on the write side. */
    rpc_conn_set_deadlines(client_fd);

    if (!http_request_preflight(&conn, context, client_fd, &client_ip_be,
                                &tmo_slot))
        goto done;

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
        http_handle_metrics_route(&conn, context, client_ip_be,
                                  line, sizeof(line));
        goto done;
    }

    /* WebSocket event stream at GET /events.
     * Check for WebSocket upgrade request before rejecting non-POST.
     * The path may include a query string: /events?domain=chain,peer */
    if (strcmp(method, "GET") == 0 && http_path_is_events(path)) {
        if (http_handle_events_route(&conn, context, path, client_fd,
                                     client_ip_be, line, sizeof(line),
                                     &fd_transferred))
            goto done;
    }

    size_t content_length = 0;
    if (!http_parse_and_authenticate_post(&conn, context, method, line,
                                          sizeof(line), client_ip_be,
                                          &content_length))
        goto done;

    http_dispatch_json_rpc(&conn, context, content_length, tmo_slot,
                           rpc_span);

/* THE single exit. Every path out of this function lands here, so the
 * worker's ownership of the connection ends in exactly one place. */
done:
    if (tmo_slot >= 0) {
        rpc_timeout_unregister(context->timeout, tmo_slot);
    }
    trace_end(rpc_span);
    if (!fd_transferred)
        rpc_conn_close(&conn);
}
