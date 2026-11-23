/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: minimal loopback HTTP/1.1 POST client: bounded connect and read,
 * Content-Length bodies only (chunked or oversized replies are BAD_REPLY).
 * The authorization value lives on the stack for one send and is cleansed. */
#include <stdlib.h>
#include <string.h>

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "platform/socket_compat.h"
#include "zw.h"

#define ZW_REPLY_MAX (8u * 1024u * 1024u)
#define ZW_CONNECT_MS 500

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

static enum zw_err connect_loopback(const struct zw_endpoint *ep, platform_socket_t *out)
{
    platform_socket_t s = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (s == PLATFORM_SOCKET_INVALID) return ZW_ERR_IO;
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
    char *end = strstr(raw->data, "\r\n\r\n");
    if (raw->len < 12 || strncmp(raw->data, "HTTP/1.", 7) != 0 || !end) return ZW_ERR_BAD_REPLY;
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

enum zw_err zw_http_post(const struct zw_endpoint *ep, const char *body, size_t len,
                         struct zw_buf *reply, uint32_t timeout_ms, int *http_status)
{
    platform_socket_t s;
    enum zw_err e = connect_loopback(ep, &s);
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
    e = sent ? ZW_OK : ZW_ERR_IO;
    char chunk[4096];
    while (e == ZW_OK) {
        int n = platform_socket_receive(s, chunk, sizeof(chunk));
        if (n == 0) break;
        if (n < 0) {
            e = platform_socket_error_timed_out(platform_socket_last_error()) ||
                platform_socket_error_would_block(platform_socket_last_error())
                    ? ZW_ERR_TIMEOUT : ZW_ERR_IO;
            break;
        }
        if (raw.len + (size_t)n > ZW_REPLY_MAX + 4096) { e = ZW_ERR_BAD_REPLY; break; }
        if (!buf_add(&raw, chunk, (size_t)n)) e = ZW_ERR_NOMEM;
    }
    platform_socket_close(s);
    if (e == ZW_OK) e = parse_reply(&raw, reply, http_status);
    zw_buf_free(&raw);
    return e;
}
