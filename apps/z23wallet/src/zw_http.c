/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: minimal loopback HTTP/1.1 POST client: bounded connect and read,
 * Content-Length bodies only (chunked or oversized replies are BAD_REPLY).
 * The authorization value lives on the stack for one send and is cleansed. */
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

/* Lets another thread abort the request in flight. The worker never blocks in a
 * single receive: it waits in short slices and looks at this flag between them, so
 * fire is a plain atomic store (no cross-thread socket call, which Winsock can
 * block on) and the request ends within one slice. After fire, every new request
 * fails before it connects. */
struct zw_cancel {
    atomic_bool fired;
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

static bool cancel_fired(struct zw_cancel *c) { return c && atomic_load(&c->fired); }

/* Wait for the socket to become readable in WAIT_SLICE_MS steps, up to timeout_ms.
 * ZW_OK means readable (data or EOF). */
static enum zw_err wait_readable(platform_socket_t s, struct zw_cancel *c, uint32_t timeout_ms)
{
    for (uint32_t waited = 0; waited < timeout_ms; waited += WAIT_SLICE_MS) {
        if (cancel_fired(c)) return ZW_ERR_IO;
        int r = platform_socket_wait_readable(s, WAIT_SLICE_MS);
        if (r != 0) return r > 0 ? ZW_OK : ZW_ERR_IO;
    }
    return ZW_ERR_TIMEOUT;
}

void zw_buf_free(struct zw_buf *b)
{
    free(b->data);
    *b = (struct zw_buf){0};
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

static enum zw_err connect_loopback(const struct zw_endpoint *ep, struct zw_cancel *c, platform_socket_t *out)
{
    platform_socket_t s = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (s == PLATFORM_SOCKET_INVALID) return ZW_ERR_IO;
    if (cancel_fired(c)) {
        platform_socket_close(s);
        return ZW_ERR_IO;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(ep->port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* the host is always 127.0.0.1 */
    int rc = platform_socket_connect(s, (const struct sockaddr *)&a, sizeof(a));
    if (rc != 0 && !platform_socket_error_in_progress(platform_socket_last_error())) {
        bool refused = platform_socket_error_refused(platform_socket_last_error());
        platform_socket_close(s);
        return refused ? ZW_ERR_REFUSED : ZW_ERR_IO;
    }
    if (rc != 0) {
        int w = platform_socket_wait_writable(s, ZW_CONNECT_MS);
        int err = 0;
        if (w == 0 || platform_socket_pending_error(s, &err) != 0 || err != 0) {
            bool refused = err != 0 && platform_socket_error_refused(err);
            platform_socket_close(s);
            return w == 0 ? ZW_ERR_TIMEOUT : refused ? ZW_ERR_REFUSED : ZW_ERR_IO;
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

/* Read until the peer closes. Each wait is bounded by timeout_ms and ends at once
 * when the request is cancelled. */
static enum zw_err read_reply(platform_socket_t s, struct zw_cancel *c, uint32_t timeout_ms,
                              struct zw_buf *raw)
{
    char chunk[4096];
    for (;;) {
        enum zw_err e = wait_readable(s, c, timeout_ms);
        if (e != ZW_OK) return e;
        int n = platform_socket_receive(s, chunk, sizeof(chunk));
        if (n == 0) return ZW_OK;
        if (n < 0) {
            int err = platform_socket_last_error();
            return platform_socket_error_timed_out(err) || platform_socket_error_would_block(err)
                       ? ZW_ERR_TIMEOUT : ZW_ERR_IO;
        }
        if (raw->len + (size_t)n > ZW_REPLY_MAX + 4096) return ZW_ERR_BAD_REPLY;
        if (!buf_add(raw, chunk, (size_t)n)) return ZW_ERR_NOMEM;
    }
}

enum zw_err zw_http_post(const struct zw_endpoint *ep, const char *body, size_t len,
                         struct zw_buf *reply, uint32_t timeout_ms, int *http_status,
                         struct zw_cancel *cancel)
{
    platform_socket_t s;
    enum zw_err e = connect_loopback(ep, cancel, &s);
    if (e != ZW_OK) return e;
    platform_socket_set_receive_timeout(s, (int)timeout_ms);
    char head[512];
    int hn = snprintf(head, sizeof(head),
                      "POST / HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nAuthorization: %s\r\n"
                      "Content-Type: application/json\r\nContent-Length: %zu\r\n"
                      "Connection: close\r\n\r\n", (unsigned)ep->port, ep->auth, len);
    bool sent = hn > 0 && (size_t)hn < sizeof(head) && platform_socket_send_all(s, head, (size_t)hn) &&
                platform_socket_send_all(s, body, len);
    memory_cleanse(head, sizeof(head));
    struct zw_buf raw = {0};
    e = sent ? read_reply(s, cancel, timeout_ms, &raw) : ZW_ERR_IO;
    platform_socket_close(s);
    if (e == ZW_OK) e = parse_reply(&raw, reply, http_status);
    zw_buf_free(&raw);
    return e;
}
