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
#include <errno.h>
#include <time.h>

#include "platform/time_compat.h"
#include "platform/socket_compat.h"

#include "util/safe_alloc.h"

/* Hard wall-clock deadlines so a dead-but-listening RPC port (a wedged node
 * that accepts the TCP connection but never answers, a firewalled listener,
 * a livelocked reducer) can never hang a native command indefinitely. Every
 * native command routes its one loopback RPC through node_rpc_call_http, so
 * bounding it here bounds the whole typed CLI surface.
 *
 * connect: a healthy loopback node either accepts immediately or the kernel
 * refuses instantly; anything slower is not a node we should wait on.
 * total: an outer cap on connect + send + receive, so even a peer that dribbles
 * one byte at a time under SO_RCVTIMEO cannot outlast the budget.
 * Both are overridable for tests; bounded to sane floors/ceilings. */
#define RPC_CONNECT_MS_DEFAULT 2000
#define RPC_TOTAL_MS_DEFAULT   10000

static long rpc_env_ms(const char *value, long def, long lo, long hi)
{
    if (value && value[0]) {
        char *end = NULL;
        long parsed = strtol(value, &end, 10);
        if (end && *end == 0 && parsed >= lo && parsed <= hi)
            return parsed;
    }
    return def;
}

static long rpc_connect_ms(void)
{
    return rpc_env_ms(getenv("ZCL_RPC_CONNECT_MS"), RPC_CONNECT_MS_DEFAULT, 1, 60000);
}

static long rpc_total_ms(void)
{
    return rpc_env_ms(getenv("ZCL_RPC_DEADLINE_MS"), RPC_TOTAL_MS_DEFAULT, 1, 600000);
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

#ifdef ZCL_TESTING
/* Test-only seam: a script replaces the clock and the connect/writable/
 * readable results the deadline loops see, so readiness and EINTR schedules
 * drive the production connect/send/receive code. Every socket call and any
 * wait past the script is real. See struct node_rpc_test_script. */
static struct node_rpc_test_script *g_script;
static node_rpc_test_connect_wait_fn g_connect_wait;
static void *g_connect_wait_ctx;

void node_rpc_test_set_connect_wait(node_rpc_test_connect_wait_fn wait, void *ctx)
{
    g_connect_wait = wait;
    g_connect_wait_ctx = ctx;
}

void node_rpc_test_set_script(struct node_rpc_test_script *script)
{
    g_script = script;
}

/* Next scripted wait result (-1 EINTR, 0 timeout, 1 ready) or -2 for a real
 * wait; logs the wait argument and advances the fake clock by the step. Step
 * 'q' first really waits until bytes are queued, then reports ready. */
static int rpc_script_wait(platform_socket_t sock, const struct node_rpc_test_step *steps,
                           int *calls, int *log, int wait_ms)
{
    if (*calls < 8)
        log[*calls] = wait_ms;
    const struct node_rpc_test_step step = *calls < 3 ? steps[*calls]
                                                      : (struct node_rpc_test_step){0};
    (*calls)++;
    if (!step.kind)
        return -2;
    if (step.kind == 'q')
        (void)platform_socket_wait_readable(sock, 1000);
    g_script->now += step.adv_ms;
    errno = EINTR;
    return step.kind == 'i' ? -1 : step.kind != 'z';
}
#endif

static int64_t rpc_now_ms(void)
{
#ifdef ZCL_TESTING
    if (g_script) {
        const int64_t scripted = g_script->iseq < 6 ? g_script->seq[g_script->iseq] : 0;
        if (scripted) {
            g_script->iseq++;
            return scripted;
        }
        return g_script->now;
    }
#endif
    return platform_time_monotonic_ms();
}

static int rpc_wait_writable(platform_socket_t sock, int wait_ms)
{
#ifdef ZCL_TESTING
    if (g_script) {
        int r = rpc_script_wait(sock, g_script->w, &g_script->nw, g_script->ww, wait_ms);
        if (r != -2)
            return r;
    }
#endif
    return platform_socket_wait_writable(sock, wait_ms);
}

static int rpc_wait_readable(platform_socket_t sock, int wait_ms)
{
#ifdef ZCL_TESTING
    if (g_script) {
        int r = rpc_script_wait(sock, g_script->r, &g_script->nr, g_script->wr, wait_ms);
        if (r != -2)
            return r;
    }
#endif
    return platform_socket_wait_readable(sock, wait_ms);
}

static int rpc_connect_start(platform_socket_t sock,
                             const struct sockaddr_in *addr)
{
    int rc = platform_socket_connect(sock, (const struct sockaddr *)addr,
                                     sizeof(*addr));
#ifdef ZCL_TESTING
    if (g_connect_wait || (g_script && g_script->pending)) {
        errno = EINPROGRESS; /* the connect did run: only the report changes */
        return -1; /* raw-return-ok:test-seam-pending-connect */
    }
    if (g_script && rc != 0 && platform_socket_wait_writable(sock, 1000) > 0)
        return 0;
#endif
    return rc;
}

static int64_t rpc_deadline_after(int64_t now_ms, int64_t delta_ms)
{
    int64_t sum;
    if (__builtin_add_overflow(now_ms, delta_ms, &sum))
        return delta_ms > 0 ? INT64_MAX : INT64_MIN;
    return sum;
}

/* The difference of two int64 values is formed in uint64, where it is exact
 * once deadline > now, so no pair of readings can overflow. */
static int rpc_deadline_remaining_ms(int64_t now_ms, int64_t deadline_ms)
{
    if (deadline_ms <= now_ms)
        return 0;
    uint64_t left = (uint64_t)deadline_ms - (uint64_t)now_ms;
    return left > INT32_MAX ? INT32_MAX : (int)left;
}

static int64_t rpc_phase_deadline_ms(int64_t now_ms, int64_t deadline_ms,
                                   int64_t phase_ms)
{
    int64_t phase_end = rpc_deadline_after(now_ms, phase_ms);
    return deadline_ms < phase_end ? deadline_ms : phase_end;
}

/* Non-blocking connect that may wait until the absolute `until_ms`. Returns 0
 * on success, or a negative code the caller maps to a typed error body: -1
 * refused, -2 timed out, -3 other. The wait is recomputed from the clock after
 * every interrupted, zero-timeout or readiness wake, so a signal storm cannot
 * restart the original allowance. Readiness that is only observed at or after
 * `until_ms` is a timeout, not a success, so the connect phase never outlives
 * its own deadline. The socket remains nonblocking on success so every later
 * send and receive is governed by the same outer deadline. */
static int rpc_connect_until(platform_socket_t sock,
                             const struct sockaddr_in *addr, int64_t until_ms)
{
    int rc = rpc_connect_start(sock, addr);
    if (rc == 0) return 0;
    int error = platform_socket_last_error();
    if (!platform_socket_error_in_progress(error))
        return platform_socket_error_refused(error) ? -1 : -3;

    for (;;) {
        int wait_ms = rpc_deadline_remaining_ms(rpc_now_ms(), until_ms);
        if (wait_ms == 0)
            return -2; /* connect timed out */
        int pr;
#ifdef ZCL_TESTING
        if (g_connect_wait)
            pr = g_connect_wait(wait_ms, g_connect_wait_ctx);
        else
#endif
            pr = rpc_wait_writable(sock, wait_ms);
        if (pr > 0) {
            if (rpc_deadline_remaining_ms(rpc_now_ms(), until_ms) == 0)
                return -2;
            break;
        }
        if (pr < 0 && !platform_socket_error_interrupted(
                          platform_socket_last_error()))
            return -3;
    }

    int soerr = 0;
    if (platform_socket_pending_error(sock, &soerr) < 0)
        return -3;
    if (soerr != 0)
        return platform_socket_error_refused(soerr) ? -1 : -3;

    return 0;
}

/* Returns RPC_SEND_OK, RPC_SEND_FAILED, or RPC_SEND_EXPIRED when the deadline
 * passed before this call put a single byte on the wire. The deadline is
 * re-checked after every writable wake and immediately before each send, so
 * no byte is transmitted after an expired wait. */
enum { RPC_SEND_OK = 1, RPC_SEND_FAILED = 0, RPC_SEND_EXPIRED = -1 };

static int rpc_send_deadline(platform_socket_t sock, const void *data,
                             size_t size, int64_t deadline_ms)
{
    const unsigned char *bytes = data;
    size_t sent = 0;
    while (sent < size) {
        int wait_ms = rpc_deadline_remaining_ms(rpc_now_ms(), deadline_ms);
        if (wait_ms == 0) return sent ? RPC_SEND_FAILED : RPC_SEND_EXPIRED;
        int ready = rpc_wait_writable(sock, wait_ms);
        if (ready == 0) continue;
        if (ready < 0) {
            if (platform_socket_error_interrupted(platform_socket_last_error()))
                continue;
            return RPC_SEND_FAILED;
        }
        if (rpc_deadline_remaining_ms(rpc_now_ms(), deadline_ms) == 0)
            return sent ? RPC_SEND_FAILED : RPC_SEND_EXPIRED;
        size_t chunk = size - sent;
        int part = chunk > INT32_MAX ? INT32_MAX : (int)chunk;
#if defined(_WIN32)
        int n = send(sock, (const char *)bytes + sent, part, 0);
#else
        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags = MSG_NOSIGNAL;
#endif
        int n = (int)send(sock, bytes + sent, (size_t)part, send_flags);
#endif
        if (n > 0) { sent += (size_t)n; continue; }
        if (n < 0) {
            int error = platform_socket_last_error();
            if (platform_socket_error_interrupted(error) ||
                platform_socket_error_would_block(error))
                continue;
        }
        return RPC_SEND_FAILED;
    }
    return RPC_SEND_OK;
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

int64_t node_rpc_test_deadline_after(int64_t now_ms, int64_t delta_ms)
{
    return rpc_deadline_after(now_ms, delta_ms);
}

int node_rpc_test_deadline_remaining_ms(int64_t now_ms, int64_t deadline_ms)
{
    return rpc_deadline_remaining_ms(now_ms, deadline_ms);
}

int64_t node_rpc_test_phase_deadline_ms(int64_t now_ms, int64_t deadline_ms,
                                        int64_t phase_ms)
{
    return rpc_phase_deadline_ms(now_ms, deadline_ms, phase_ms);
}

int node_rpc_test_client_port(void)
{
    return g_port;
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
    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                   true, true);
    if (sock == PLATFORM_SOCKET_INVALID)
        return false;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)rpc_port),
    };
    if (platform_socket_parse_address(AF_INET, "127.0.0.1",
                                      &addr.sin_addr) != 1) {
        platform_socket_close(sock);
        return false;
    }
    int rc = rpc_connect_until(sock, &addr, rpc_deadline_after(
        rpc_now_ms(), rpc_clamp_ms(connect_ms, 1, 60000)));
    platform_socket_close(sock);
    return rc == 0;
}

/* Compose the JSON-RPC POST body into a fixed caller-supplied buffer.
 * Returns the exact composed length on success, or -1 when the composed
 * request does not fit. A truncated body must never be sent: snprintf
 * reports the would-have-written length, and feeding that length to send()
 * would read past the buffer and publish a Content-Length the truncated
 * body cannot satisfy. Callers refuse before connecting. */
static int rpc_compose_request_body(char *body, size_t body_cap,
                                    const char *method,
                                    const char *params_json)
{
    int blen;
    if (params_json && params_json[0])
        blen = snprintf(body, body_cap,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
            method, params_json);
    else
        blen = snprintf(body, body_cap,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":[]}",
            method);
    if (blen < 0 || (size_t)blen >= body_cap)
        return -1; /* raw-return-ok:compose-size signal, named by caller */
    return blen;
}

/* What one call may spend. A relative budget (`absolute == false`) starts its
 * `total_ms` clock after the cookie read, exactly as the env-defaulted callers
 * always did. An absolute budget carries the caller's `deadline_ms` from entry
 * and refuses to issue a request once it has passed. */
struct rpc_budget {
    long connect_ms;
    long total_ms;
    int64_t deadline_ms;
    bool absolute;
};

static bool rpc_budget_expired(const struct rpc_budget *budget)
{
    return budget->absolute && rpc_deadline_remaining_ms(
        rpc_now_ms(), budget->deadline_ms) == 0;
}

/* The caller's deadline passed before any request byte was sent. */
static char *rpc_deadline_expired_body(const char *phase)
{
    char *out = zcl_malloc(512, "rpc deadline expired json");
    if (!out)
        return NULL;
    snprintf(out, 512,
        "{\"error\":{\"code\":%d,\"message\":\"RPC deadline expired %s; no "
        "request was sent\"}}", NODE_RPC_DEADLINE_EXPIRED, phase);
    return out;
}

/* Double the response buffer. False on allocation failure (buffer freed). */
static bool rpc_receive_grow(char **bufp, size_t *capp)
{
    char *tmp = zcl_realloc(*bufp, *capp * 2, "rpc response buf");
    if (!tmp) { free(*bufp); *bufp = NULL; return false; }
    *bufp = tmp;
    *capp *= 2;
#ifdef ZCL_TESTING
    if (g_script) {
        g_script->now += g_script->alloc_adv_ms; /* a slow allocation moves the clock */
        if (!g_script->grown_at)
            g_script->grown_at = g_script->nr;
    }
#endif
    return true;
}

/* Read until EOF, error or the absolute deadline. The wait is measured after
 * any buffer growth, so a slow allocation cannot leave a stale allowance, and
 * readiness seen at or after the deadline is a timeout: queued bytes are not
 * read. A would-block/EINTR after readiness is a spurious wake: it re-checks
 * the same absolute deadline, which alone bounds the call (there is no
 * arbitrary wake-count cutoff). Returns false only on allocation failure. */
static bool rpc_receive_until(platform_socket_t sock, int64_t deadline_ms,
                              char **bufp, size_t *lenp, size_t *capp,
                              bool *timed_out)
{
    for (;;) {
        if (*lenp + 4096 > *capp && !rpc_receive_grow(bufp, capp))
            return false;
        int wait_ms = rpc_deadline_remaining_ms(rpc_now_ms(), deadline_ms);
        if (wait_ms == 0) { *timed_out = true; return true; }
        int ready = rpc_wait_readable(sock, wait_ms);
        if (ready == 0) continue;
        if (ready < 0) {
            if (platform_socket_error_interrupted(platform_socket_last_error()))
                continue;
            return true;
        }
        if (rpc_deadline_remaining_ms(rpc_now_ms(), deadline_ms) == 0) {
            *timed_out = true;
            return true;
        }
        int n = platform_socket_receive(sock, *bufp + *lenp,
                                        *capp - *lenp - 1);
        if (n > 0) { *lenp += (size_t)n; continue; }
        if (n == 0) return true;
        /* A real read error ends the request; a partial read yields a bogus
         * reply, so surface a timeout rather than parse garbage. */
        int error = platform_socket_last_error();
        if (platform_socket_error_would_block(error) ||
            platform_socket_error_interrupted(error)) {
            continue;
        }
        if (platform_socket_error_timed_out(error)) {
            *timed_out = true;
        }
        return true;
    }
}

/* Shared implementation behind the env-defaulted node_rpc_call_http, the
 * relative-deadline node_rpc_call_http_deadline and the absolute-deadline
 * node_rpc_call_*_until. A relative `total_ms` is clamped here to the same
 * sane floor/ceiling either way so no caller can accidentally request an
 * unbounded wait. */
static char *node_rpc_call_http_impl(const char *method,
                                     const char *params_json,
                                     struct rpc_budget budget,
                                     const char *datadir, int rpc_port)
{
    budget.connect_ms = rpc_clamp_ms(budget.connect_ms, 1, 60000);
    budget.total_ms = rpc_clamp_ms(budget.total_ms, 1, 600000);

    if (rpc_budget_expired(&budget))
        return rpc_deadline_expired_body("before the cookie read");

    /* Fail fast with an actionable message rather than sending an empty
     * credential that the node would reject with a cryptic 401. The read is
     * blocking file I/O and cannot be preempted by the deadline checks. */
    char cookie[256];
    if (!datadir || !datadir[0] || !read_cookie_at(
            datadir, cookie, sizeof(cookie)))
        return cookie_error_body(datadir);
    if (rpc_budget_expired(&budget)) {
        memset(cookie, 0, sizeof(cookie));
        return rpc_deadline_expired_body("during the cookie read");
    }

    char body[8192];
    int blen = rpc_compose_request_body(body, sizeof(body), method,
                                        params_json);
    if (blen < 0) {
        memset(cookie, 0, sizeof(cookie));
        return rpc_transport_error("JSON-RPC request too large — pass "
                                   "smaller parameters");
    }

    const int64_t deadline_ms = budget.absolute
        ? budget.deadline_ms
        : rpc_deadline_after(rpc_now_ms(), budget.total_ms);

    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                   true, true);
    if (sock == PLATFORM_SOCKET_INVALID)
        return rpc_transport_error("socket failed");

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)rpc_port),
    };
    if (platform_socket_parse_address(AF_INET, "127.0.0.1",
                                      &addr.sin_addr) != 1) {
        platform_socket_close(sock);
        return rpc_transport_error("invalid loopback address");
    }
    if (rpc_budget_expired(&budget)) {
        platform_socket_close(sock);
        memset(cookie, 0, sizeof(cookie));
        return rpc_deadline_expired_body("before connect");
    }

    /* Bound the connect so a firewalled/hung local port cannot block the whole
     * command: min(overall deadline, connect phase), recomputed after every
     * interrupted or readiness wake. */
    const int64_t now_ms = rpc_now_ms();
    int64_t connect_until = rpc_phase_deadline_ms(
        now_ms, deadline_ms, budget.connect_ms);
    /* A relative budget always granted the connect at least 1ms. */
    if (!budget.absolute && connect_until <= now_ms)
        connect_until = rpc_deadline_after(now_ms, 1);
    int crc = rpc_connect_until(sock, &addr, connect_until);
    if (crc != 0) {
        memset(cookie, 0, sizeof(cookie));
        platform_socket_close(sock);
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

    char auth_b64[512];
    base64_encode(cookie, strlen(cookie), auth_b64);
    memset(cookie, 0, sizeof(cookie));

    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: engine/application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n", auth_b64, blen);

    if (rpc_budget_expired(&budget)) {
        platform_socket_close(sock);
        return rpc_deadline_expired_body("before transmit");
    }

    /* MSG_NOSIGNAL: a peer reset mid-send must return EPIPE, not raise
     * SIGPIPE and kill the caller. Treat any short/failed write as
     * fatal for this request — a truncated POST yields a bogus reply. */
    int sent = rpc_send_deadline(sock, header, (size_t)hlen, deadline_ms);
    if (sent == RPC_SEND_EXPIRED && budget.absolute) {
        platform_socket_close(sock);
        return rpc_deadline_expired_body("before transmit");
    }
    if (sent != RPC_SEND_OK ||
        rpc_send_deadline(sock, body, (size_t)blen, deadline_ms) !=
            RPC_SEND_OK) {
        platform_socket_close(sock);
        return strdup("{\"error\":{\"code\":-32603,"
                      "\"message\":\"failed to send request to node\"}}");
    }

    size_t cap = 65536, len = 0;
    char *buf = zcl_malloc(cap, "rpc response buf");
    if (!buf) { platform_socket_close(sock); return NULL; }
    bool timed_out = false;
    bool alloc_ok = rpc_receive_until(sock, deadline_ms, &buf, &len, &cap,
                                      &timed_out);
    platform_socket_close(sock);
    if (!alloc_ok)
        return NULL;

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
    struct rpc_budget budget = {
        .connect_ms = rpc_connect_ms(), .total_ms = rpc_total_ms()
    };
    return node_rpc_call_http_impl(method, params_json, budget, g_datadir,
                                   g_port);
}

static struct rpc_budget rpc_relative_budget(long connect_ms, long total_ms)
{
    return (struct rpc_budget){ .connect_ms = connect_ms,
                                .total_ms = total_ms };
}

static struct rpc_budget rpc_absolute_budget(long connect_ms,
                                             int64_t deadline_ms)
{
    return (struct rpc_budget){ .connect_ms = connect_ms,
                                .deadline_ms = deadline_ms,
                                .absolute = true };
}

/* Same HTTP backend, but with the caller's own connect/total budget instead
 * of the generic env-configurable defaults — for front doors (e.g.
 * core.status.brief) that must answer far faster than the 10s generic
 * ceiling tolerates. */
char *node_rpc_call_http_deadline(const char *method, const char *params_json,
                                  long connect_ms, long total_ms)
{
    return node_rpc_call_http_impl(method, params_json,
        rpc_relative_budget(connect_ms, total_ms), g_datadir, g_port);
}

char *node_rpc_call_at_deadline(const char *datadir, int rpc_port,
                                const char *method, const char *params_json,
                                long connect_ms, long total_ms)
{
#ifdef ZCL_TESTING
    if (g_test_rpc_hook)
        return g_test_rpc_hook(method, params_json);
#endif
    return node_rpc_call_http_impl(method, params_json,
        rpc_relative_budget(connect_ms, total_ms), datadir, rpc_port);
}

char *node_rpc_call_at_until(const char *datadir, int rpc_port,
                             const char *method, const char *params_json,
                             long connect_ms, int64_t deadline_ms)
{
#ifdef ZCL_TESTING
    if (g_test_rpc_hook)
        return g_test_rpc_hook(method, params_json);
#endif
    return node_rpc_call_http_impl(method, params_json,
        rpc_absolute_budget(connect_ms, deadline_ms), datadir, rpc_port);
}

char *node_rpc_call_until(const char *method, const char *params_json,
                          long connect_ms, int64_t deadline_ms)
{
    return node_rpc_call_at_until(g_datadir, g_port, method, params_json,
                                  connect_ms, deadline_ms);
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
