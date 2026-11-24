/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: minimal loopback HTTP/1.1 POST client. One total deadline bounds
 * connect, send and every receive together on a real monotonic clock (never
 * the UI clock, which is virtual under the headless backend), so a
 * node that accepts and never answers costs at most the deadline. Waits run
 * in short slices that look at a cancel flag, so another thread can end the
 * request in flight without a cross-thread socket call. Content-Length
 * bodies only (chunked or oversized replies are BAD_REPLY). The
 * authorization value lives on the stack for one send and is cleansed. */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "platform/socket_compat.h"
#include "zw.h"

#define ZW_REPLY_MAX (8u * 1024u * 1024u)
#define ZW_CONNECT_MS 500
#define WAIT_SLICE_MS 50

/* Lets another thread abort the request in flight. fired is permanent (shutdown:
 * every later request fails before it connects); abort ends only the request in
 * flight and is cleared by the worker before its next job (the watchdog). Both
 * are plain atomic stores: Winsock can block a cross-thread shutdown() while a
 * recv is pending, so the flags are polled between wait slices instead. */
struct zw_cancel {
    atomic_bool fired, abort;
};

struct zw_cancel *zw_cancel_new(void)
{
    return zcl_calloc(1, sizeof(struct zw_cancel), "zw_cancel");
}

void zw_cancel_free(struct zw_cancel *c) { free(c); }

void zw_cancel_fire(struct zw_cancel *c)
{
    if (c) atomic_store(&c->fired, true);
}

void zw_cancel_abort(struct zw_cancel *c)
{
    if (c) atomic_store(&c->abort, true);
}

void zw_cancel_clear_abort(struct zw_cancel *c)
{
    if (c) atomic_store(&c->abort, false);
}

static bool cancel_fired(struct zw_cancel *c)
{
    return c && (atomic_load(&c->fired) || atomic_load(&c->abort));
}

void zw_buf_free(struct zw_buf *b)
{
    free(b->data);
    *b = (struct zw_buf){0};
}

const char *zw_phase_name(int phase)
{
    static const char *const k[] = { "idle", "locate", "connect", "send", "recv" };
    return phase >= 0 && phase <= ZW_PHASE_RECV ? k[phase] : "idle";
}

static void set_phase(atomic_int *p, int v)
{
    if (p) atomic_store(p, v);
}

static bool buf_add(struct zw_buf *b, const char *p, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n + 1) cap *= 2;
        char *d = zcl_realloc(b->data, cap, "zw_http_buf");
        if (!d) return false;
        b->data = d;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = 0;
    return true;
}

static uint64_t now_ns(void) { return zw_monotonic_ms() * 1000000u; }

static int32_t remaining_ms(uint64_t deadline_ns)
{
    uint64_t now = now_ns();
    return now >= deadline_ns ? 0 : (int32_t)((deadline_ns - now) / 1000000u);
}

/* Wait until s is readable (writable when for_write) or until stop_ns, in
 * WAIT_SLICE_MS slices that look at the cancel flag. ZW_OK means ready. for_write is the
 * pending connect only (it also watches the failure set); never for send space. */
static enum zw_err wait_ready(platform_socket_t s, struct zw_cancel *c, uint64_t stop_ns, bool for_write)
{
    for (;;) {
        if (cancel_fired(c)) return ZW_ERR_IO;
        int32_t left = remaining_ms(stop_ns);
        if (left <= 0) return ZW_ERR_TIMEOUT;
        int slice = left < WAIT_SLICE_MS ? left : WAIT_SLICE_MS;
        int r = for_write ? platform_socket_wait_connected(s, slice) : platform_socket_wait_readable(s, slice);
        if (r != 0) return r > 0 ? ZW_OK : ZW_ERR_IO;
    }
}

static enum zw_err connect_loopback(const struct zw_endpoint *ep, uint64_t deadline_ns, struct zw_cancel *c,
                                    platform_socket_t *out)
{
    if (cancel_fired(c)) return ZW_ERR_IO;
    platform_socket_t s = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (s == PLATFORM_SOCKET_INVALID) return ZW_ERR_IO;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(ep->port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* the host is always 127.0.0.1 */
    platform_socket_connect_fail_fast(s); /* a refused loopback connect must not retry the SYN on Windows */
    int rc = platform_socket_connect(s, (const struct sockaddr *)&a, sizeof(a));
    if (rc != 0 && !platform_socket_error_in_progress(platform_socket_last_error())) {
        bool refused = platform_socket_error_refused(platform_socket_last_error());
        platform_socket_close(s);
        return refused ? ZW_ERR_REFUSED : ZW_ERR_IO;
    }
    if (rc != 0) {
        uint64_t cap_ns = now_ns() + (uint64_t)ZW_CONNECT_MS * 1000000u;
        enum zw_err w = wait_ready(s, c, cap_ns < deadline_ns ? cap_ns : deadline_ns, true);
        int err = 0;
        if (w != ZW_OK || platform_socket_pending_error(s, &err) != 0 || err != 0) {
            bool refused = err != 0 && platform_socket_error_refused(err);
            platform_socket_close(s);
            return w != ZW_OK ? w : refused ? ZW_ERR_REFUSED : ZW_ERR_IO;
        }
    }
    platform_socket_set_nonblocking(s, false);
    *out = s;
    return ZW_OK;
}

/* Parse the status line and framing headers of a complete reply. */
static enum zw_err parse_reply(struct zw_buf *raw, struct zw_buf *reply, int *status)
{
    /* A peer that closes without a byte leaves raw->data NULL, and a truncated
     * header has no blank line: check the length before any string call. */
    if (!raw->data || raw->len < 12 || strncmp(raw->data, "HTTP/1.", 7) != 0) return ZW_ERR_BAD_REPLY;
    char *end = strstr(raw->data, "\r\n\r\n");
    if (!end) return ZW_ERR_BAD_REPLY;
    *status = atoi(raw->data + 9);
    *end = 0;
    for (char *p = raw->data; *p; p++) *p = (char)((*p >= 'A' && *p <= 'Z') ? *p + 32 : *p);
    if (strstr(raw->data, "transfer-encoding: chunked")) return ZW_ERR_BAD_REPLY;
    char *cl = strstr(raw->data, "content-length:");
    char *body = end + 4;
    size_t have = raw->len - (size_t)(body - raw->data);
    if (cl) {
        size_t want = (size_t)strtoull(cl + 15, NULL, 10);
        if (want > ZW_REPLY_MAX || have < want) return ZW_ERR_BAD_REPLY;
        have = want;
    }
    /* The headers were lowercased in place; the body was not touched. */
    return buf_add(reply, body, have) ? ZW_OK : ZW_ERR_NOMEM;
}

static enum zw_err send_request(platform_socket_t s, const struct zw_endpoint *ep, const char *body, size_t len)
{
    char head[sizeof(ep->auth) + 256];
    int hn = snprintf(head, sizeof(head),
                      "POST / HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nAuthorization: %s\r\n"
                      "Content-Type: application/json\r\nContent-Length: %zu\r\n"
                      "Connection: close\r\n\r\n", (unsigned)ep->port, ep->auth, len);
    bool sent = hn > 0 && (size_t)hn < sizeof(head) && platform_socket_send_all(s, head, (size_t)hn) &&
                platform_socket_send_all(s, body, len);
    memory_cleanse(head, sizeof(head));
    return sent ? ZW_OK : ZW_ERR_IO;
}

/* Read until the peer closes, the deadline passes or the request is cancelled. */
static enum zw_err receive_all(platform_socket_t s, uint64_t deadline_ns, struct zw_cancel *c, struct zw_buf *raw)
{
    char chunk[4096];
    for (;;) {
        enum zw_err w = wait_ready(s, c, deadline_ns, false);
        if (w != ZW_OK) return w;
        int n = platform_socket_receive(s, chunk, sizeof(chunk));
        if (n == 0) return ZW_OK;
        if (n < 0) {
            int e = platform_socket_last_error();
            if (platform_socket_error_would_block(e)) continue;
            return platform_socket_error_timed_out(e) ? ZW_ERR_TIMEOUT : ZW_ERR_IO;
        }
        if (raw->len + (size_t)n > ZW_REPLY_MAX + 4096) return ZW_ERR_BAD_REPLY;
        if (!buf_add(raw, chunk, (size_t)n)) return ZW_ERR_NOMEM;
    }
}

enum zw_err zw_http_post(const struct zw_endpoint *ep, const char *body, size_t len,
                         struct zw_buf *reply, uint32_t deadline_ms, int *http_status,
                         atomic_int *phase, struct zw_cancel *cancel)
{
    uint32_t ms = deadline_ms ? deadline_ms : 5000u;
    uint64_t deadline_ns = now_ns() + (uint64_t)ms * 1000000u;
    platform_socket_t s;
    set_phase(phase, ZW_PHASE_CONNECT);
    enum zw_err e = connect_loopback(ep, deadline_ns, cancel, &s);
    if (e != ZW_OK) return e;
    platform_socket_set_receive_timeout(s, (int)ms);
    set_phase(phase, ZW_PHASE_SEND);
    e = send_request(s, ep, body, len);
    struct zw_buf raw = {0};
    set_phase(phase, ZW_PHASE_RECV);
    if (e == ZW_OK) e = receive_all(s, deadline_ns, cancel, &raw);
    platform_socket_close(s);
    if (e == ZW_OK) e = parse_reply(&raw, reply, http_status);
    zw_buf_free(&raw);
    return e;
}
