/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Loopback RPC client: speaks HTTP+JSON-RPC to the local zclassic23 node.
 * Native command handlers and the tools/command CLI are its consumers.
 * See controllers/rpc_client.h for the public API. */

#include "controllers/rpc_client.h"

#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "platform/time_compat.h"
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util/safe_alloc.h"

/* Hard wall-clock deadlines so a dead-but-listening RPC port (a wedged node
 * that accepts the TCP connection but never answers, a firewalled listener,
 * a livelocked reducer) can never hang a native command indefinitely — the
 * class that once spun a flagless `status` for days. Every native command
 * routes its one loopback RPC through node_rpc_call_http, so bounding it here
 * bounds the whole typed CLI surface, not just `status`.
 *
 * connect: a healthy loopback node either accepts immediately or the kernel
 * refuses instantly; anything slower is not a node we should wait on.
 * total: an outer cap on connect + send + receive, so even a peer that dribbles
 * one byte at a time under SO_RCVTIMEO cannot outlast the budget.
 * Both are overridable for tests; bounded to sane floors/ceilings. */
#define RPC_CONNECT_MS_DEFAULT 2000
#define RPC_TOTAL_MS_DEFAULT   10000

static long rpc_env_ms(const char *name, long def, long lo, long hi)
{
    const char *v = getenv(name);
    if (v && v[0]) {
        char *end = NULL;
        long parsed = strtol(v, &end, 10);
        if (end && *end == 0 && parsed >= lo && parsed <= hi)
            return parsed;
    }
    return def;
}

static long rpc_connect_ms(void)
{
    return rpc_env_ms("ZCL_RPC_CONNECT_MS", RPC_CONNECT_MS_DEFAULT, 1, 60000);
}

static long rpc_total_ms(void)
{
    return rpc_env_ms("ZCL_RPC_DEADLINE_MS", RPC_TOTAL_MS_DEFAULT, 1, 600000);
}

/* Callers that pass explicit deadlines (e.g. the ~250ms status front door)
 * bypass the env-only defaults above but must still be bounded to the same
 * sane floor/ceiling — an unclamped caller-supplied 0 or negative value
 * would otherwise busy-spin or silently mean "no timeout". */
static long rpc_clamp_ms(long v, long lo, long hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int64_t rpc_now_ms(void)
{
    return platform_time_monotonic_ms();
}

/* Non-blocking connect bounded by `budget_ms`. Returns 0 on success, or a
 * negative code the caller maps to a typed error body: -1 refused, -2 timed
 * out, -3 other. The socket is left blocking on success. */
static int rpc_connect_deadline(int sock, const struct sockaddr_in *addr,
                                long budget_ms)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
        return -3;

    int rc = connect(sock, (const struct sockaddr *)addr, sizeof(*addr));
    if (rc == 0) {
        (void)fcntl(sock, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS)
        return errno == ECONNREFUSED ? -1 : -3;

    struct pollfd pfd = { .fd = sock, .events = POLLOUT };
    int pr;
    do {
        pr = poll(&pfd, 1, (int)budget_ms);
    } while (pr < 0 && errno == EINTR);
    if (pr == 0)
        return -2; /* connect timed out */
    if (pr < 0)
        return -3;

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0)
        return -3;
    if (soerr != 0)
        return soerr == ECONNREFUSED ? -1 : -3;

    (void)fcntl(sock, F_SETFL, flags);
    return 0;
}

static char *rpc_transport_error(const char *reason)
{
    char *out = zcl_malloc(512, "rpc transport error json");
    if (!out)
        return NULL;
    snprintf(out, 512,
        "{\"error\":{\"code\":-32603,\"message\":\"%s\"}}", reason);
    return out;
}

static int g_port = 18232;
static char g_datadir[512];

#ifdef ZCL_TESTING
static node_rpc_test_fn g_test_rpc_hook;

void node_rpc_client_set_test_hook(node_rpc_test_fn fn)
{
    g_test_rpc_hook = fn;
}
#endif

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const char *in, size_t len, char *out)
{
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint8_t a = (uint8_t)in[i], b = (uint8_t)in[i+1], c = (uint8_t)in[i+2];
        out[j++] = b64[a >> 2];
        out[j++] = b64[((a & 3) << 4) | (b >> 4)];
        out[j++] = b64[((b & 0xf) << 2) | (c >> 6)];
        out[j++] = b64[c & 0x3f];
    }
    if (i < len) {
        uint8_t a = (uint8_t)in[i];
        out[j++] = b64[a >> 2];
        if (i + 1 < len) {
            uint8_t b2 = (uint8_t)in[i+1];
            out[j++] = b64[((a & 3) << 4) | (b2 >> 4)];
            out[j++] = b64[(b2 & 0xf) << 2];
        } else {
            out[j++] = b64[(a & 3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = 0;
}

/* Re-read the RPC auth cookie from <datadir>/.cookie on EVERY call so a
 * node restart that rotates the cookie is picked up by long-lived callers.
 * Returns false (and clears any stale cookie) if the file is
 * missing/unreadable/empty — callers MUST NOT proceed to send a request
 * with an empty credential, because the node then answers 401 Unauthorized
 * with no hint that the real cause is a cookie problem.  That silent 401
 * masquerades as a generic auth failure on every tool. */
static bool read_cookie_at(const char *datadir, char *cookie,
                           size_t cookie_cap)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/.cookie", datadir);
    FILE *f = fopen(path, "r");
    if (!f) {
        cookie[0] = 0;
        return false;
    }
    size_t n = fread(cookie, 1, cookie_cap - 1, f);
    fclose(f);
    cookie[n] = 0;
    char *nl = strchr(cookie, '\n');
    if (nl) *nl = 0;
    if (cookie[0] == 0)
        return false;
    return n > 0;
}

/* Build a self-describing error body for the "no usable auth cookie" case.
 * Heap-allocated like every other node_rpc_call return value; caller frees.
 * Do not disclose the wallet/datadir path through a command response or log.
 * The operator action remains explicit without naming the credential location.
 * Kept short so it survives the native-handler message budget. */
static char *cookie_error_body(const char *datadir)
{
    (void)datadir;
    char *out = zcl_malloc(768, "rpc cookie error json");
    if (!out) return NULL;
    snprintf(out, 768,
        "{\"error\":{\"code\":-32603,\"message\":"
        "\"cannot read RPC auth cookie — is the node running and is the "
        "selected datadir correct?\"}}");
    return out;
}

void node_rpc_client_init(const char *datadir, int rpc_port)
{
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
    g_port = rpc_port;
}

const char *node_rpc_client_datadir(void)
{
    return g_datadir;
}

bool node_rpc_port_listening(int rpc_port, long connect_ms)
{
    if (rpc_port < 1 || rpc_port > 65535)
        return false;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return false;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)rpc_port),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int rc = rpc_connect_deadline(sock, &addr,
                                  rpc_clamp_ms(connect_ms, 1, 60000));
    close(sock);
    return rc == 0;
}

/* Shared implementation behind both the env-defaulted node_rpc_call_http
 * and the explicit-deadline node_rpc_call_http_deadline. `connect_ms`/
 * `total_ms` are already-resolved budgets (env defaults or a caller's tight
 * front-door budget) — clamped here to the same sane floor/ceiling either
 * way so no caller can accidentally request an unbounded wait. */
static char *node_rpc_call_http_impl(const char *method,
                                     const char *params_json,
                                     long connect_ms, long total_ms,
                                     const char *datadir, int rpc_port)
{
    connect_ms = rpc_clamp_ms(connect_ms, 1, 60000);
    total_ms = rpc_clamp_ms(total_ms, 1, 600000);

    /* Fail fast with an actionable message rather than sending an empty
     * credential that the node would reject with a cryptic 401. */
    char cookie[256];
    if (!datadir || !datadir[0] || !read_cookie_at(
            datadir, cookie, sizeof(cookie)))
        return cookie_error_body(datadir);

    char body[8192];
    int blen;
    if (params_json && params_json[0])
        blen = snprintf(body, sizeof(body),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
            method, params_json);
    else
        blen = snprintf(body, sizeof(body),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":[]}",
            method);

    const int64_t deadline_ms = rpc_now_ms() + total_ms;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return rpc_transport_error("socket failed");

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)rpc_port),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    /* Bound the connect so a firewalled/hung local port cannot block the whole
     * command. Never wait past the overall deadline. */
    long connect_budget = connect_ms;
    long remaining = (long)(deadline_ms - rpc_now_ms());
    if (remaining < 1)
        remaining = 1;
    if (connect_budget > remaining)
        connect_budget = remaining;
    int crc = rpc_connect_deadline(sock, &addr, connect_budget);
    if (crc != 0) {
        close(sock);
        if (crc == -1)
            return rpc_transport_error(
                "cannot connect to node (connection refused) — is the node "
                "running and is -rpcport correct?");
        if (crc == -2)
            return rpc_transport_error(
                "cannot connect to node (connect timed out) — the RPC port "
                "is not accepting connections; check -rpcport and the node");
        return rpc_transport_error("cannot connect to node");
    }

    /* Past connect, a hang means "accepted but not answering" (busy/wedged).
     * SO_RCVTIMEO/SO_SNDTIMEO bound each syscall; the outer deadline below
     * bounds the total so slow trickles cannot outlast the budget either. */
    {
        long rem = (long)(deadline_ms - rpc_now_ms());
        if (rem < 1)
            rem = 1;
        struct timeval tv = {
            .tv_sec = rem / 1000,
            .tv_usec = (rem % 1000) * 1000,
        };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    char auth_b64[512];
    base64_encode(cookie, strlen(cookie), auth_b64);
    memset(cookie, 0, sizeof(cookie));

    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n", auth_b64, blen);

    /* MSG_NOSIGNAL: a peer reset mid-send must return EPIPE, not raise
     * SIGPIPE and kill the caller. Treat any short/failed write as
     * fatal for this request — a truncated POST yields a bogus reply. */
    if (send(sock, header, (size_t)hlen, MSG_NOSIGNAL) != (ssize_t)hlen ||
        send(sock, body,   (size_t)blen, MSG_NOSIGNAL) != (ssize_t)blen) {
        close(sock);
        return strdup("{\"error\":{\"code\":-32603,"
                      "\"message\":\"failed to send request to node\"}}");
    }

    size_t cap = 65536, len = 0;
    char *buf = zcl_malloc(cap, "rpc response buf");
    if (!buf) { close(sock); return NULL; }
    bool timed_out = false;
    for (;;) {
        if (rpc_now_ms() >= deadline_ms) {
            timed_out = true;
            break;
        }
        if (len + 4096 > cap) {
            size_t newcap = cap * 2;
            char *tmp = zcl_realloc(buf, newcap, "rpc response buf");
            if (!tmp) { free(buf); close(sock); return NULL; }
            buf = tmp;
            cap = newcap;
        }
        ssize_t n = recv(sock, buf + len, cap - len - 1, 0);
        if (n < 0) {
            /* SO_RCVTIMEO fired (EAGAIN/EWOULDBLOCK) or a real read error —
             * either way this request is done; a partial read yields a bogus
             * reply, so surface a timeout rather than parse garbage. */
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                timed_out = true;
            break;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(sock);

    if (timed_out && len == 0) {
        free(buf);
        return rpc_transport_error(
            "node accepted the connection but did not answer within the "
            "deadline — the node is busy or wedged; retry, or inspect "
            "`ops state --subsystem=supervisor`");
    }
    buf[len] = 0;

    /* Validate HTTP framing before stripping headers.  A server-side request
     * watchdog can close the socket after the HTTP preamble was written but
     * before the JSON body is complete.  recv() then reports a clean EOF, not
     * EAGAIN, so `timed_out` is false even though the response is truncated.
     * Never hand that fragment to the JSON layer as a misleading BAD_RPC_BODY. */
    char *body_start = strstr(buf, "\r\n\r\n");
    if (body_start) {
        size_t body_offset = (size_t)(body_start + 4 - buf);
        size_t body_len = len >= body_offset ? len - body_offset : 0;
        char *content_length = strstr(buf, "Content-Length:");
        if (content_length && content_length < body_start) {
            char *value = content_length + strlen("Content-Length:");
            while (value < body_start && (*value == ' ' || *value == '\t'))
                value++;
            errno = 0;
            char *end = NULL;
            unsigned long long expected = strtoull(value, &end, 10);
            if (errno == 0 && end && end > value && end <= body_start &&
                expected > (unsigned long long)body_len) {
                free(buf);
                return rpc_transport_error(
                    "node connection closed before the complete response "
                    "arrived (truncated reply) — the node is busy or its "
                    "request deadline is too short; retry, or inspect "
                    "`ops state --subsystem=supervisor`");
            }
        }
        body_start += 4;
        size_t bslen = len - (size_t)(body_start - buf);
        memmove(buf, body_start, bslen + 1);
    }

    /* Extract "result" from {"result":...,"error":null,"id":1} */
    struct json_value v;
    bool parsed = false;
    if (json_read(&v, buf, strlen(buf))) {
        parsed = true;
        const struct json_value *res = json_get(&v, "result");
        const struct json_value *err = json_get(&v, "error");
        if (err && err->type != JSON_NULL) {
            char *out = zcl_malloc(4096, "rpc error json");
            if (!out) { json_free(&v); free(buf); return NULL; }
            json_write(err, out, 4096);
            json_free(&v);
            free(buf);
            return out;
        }
        if (res) {
            char *out = zcl_malloc(cap, "rpc result json");
            if (!out) { json_free(&v); free(buf); return NULL; }
            json_write(res, out, cap);
            json_free(&v);
            free(buf);
            return out;
        }
        json_free(&v);
    }

    /* A deadline that fired part-way through the reply leaves a TRUNCATED
     * body — commonly just the HTTP headers, because the node writes those
     * before its handler blocks. The fragment is not JSON, so every caller
     * that parses this return value reports its own "unparseable body"
     * (e.g. core.wallet.utxo.list -> TOOL_ERROR "RPC listunspent returned an
     * unparseable body") and the operator learns nothing about the real
     * cause. The `timed_out && len == 0` branch above already names the
     * empty case; this names the partial one, so a slow node reads as a slow
     * node at every layer. Only the unparseable path is redirected: a body
     * that parsed is a real answer even if the FIN arrived late. */
    if (timed_out && !parsed) {
        free(buf);
        return rpc_transport_error(
            "node answered only partially before the deadline (truncated "
            "reply) — the node is busy or wedged; retry, or inspect "
            "`ops state --subsystem=supervisor`");
    }
    return buf;
}

/* The default out-of-process HTTP backend, using the env-configurable
 * defaults (ZCL_RPC_CONNECT_MS / ZCL_RPC_DEADLINE_MS). */
char *node_rpc_call_http(const char *method, const char *params_json)
{
    return node_rpc_call_http_impl(method, params_json, rpc_connect_ms(),
                                   rpc_total_ms(), g_datadir, g_port);
}

/* Same HTTP backend, but with the caller's own connect/total budget instead
 * of the generic env-configurable defaults — for front doors (e.g.
 * core.status.brief) that must answer far faster than the 10s generic
 * ceiling tolerates. */
char *node_rpc_call_http_deadline(const char *method, const char *params_json,
                                  long connect_ms, long total_ms)
{
    return node_rpc_call_http_impl(method, params_json, connect_ms, total_ms,
                                   g_datadir, g_port);
}

char *node_rpc_call_at_deadline(const char *datadir, int rpc_port,
                                const char *method, const char *params_json,
                                long connect_ms, long total_ms)
{
#ifdef ZCL_TESTING
    if (g_test_rpc_hook)
        return g_test_rpc_hook(method, params_json);
#endif
    return node_rpc_call_http_impl(method, params_json, connect_ms, total_ms,
                                   datadir, rpc_port);
}

/* Public entry every controller and the diagnostics dumper call. Routes to
 * the HTTP backend; the test hook lets controller tests stub the node. */
char *node_rpc_call(const char *method, const char *params_json)
{
#ifdef ZCL_TESTING
    if (g_test_rpc_hook)
        return g_test_rpc_hook(method, params_json);
#endif
    return node_rpc_call_http(method, params_json);
}

/* Same as node_rpc_call (including the ZCL_TESTING hook, so tests can stub
 * a deadline-aware caller too) but with an explicit connect/total budget —
 * see node_rpc_call_http_deadline. */
char *node_rpc_call_deadline(const char *method, const char *params_json,
                             long connect_ms, long total_ms)
{
#ifdef ZCL_TESTING
    if (g_test_rpc_hook)
        return g_test_rpc_hook(method, params_json);
#endif
    return node_rpc_call_http_deadline(method, params_json, connect_ms,
                                       total_ms);
}
