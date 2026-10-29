/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "http.h"
#include "relay.h"
#include "base/cleanse.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HEADER_CAP 16384u
static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static bool wait_io(int fd, short events, int64_t deadline, int alive)
{
    for (;;) {
        int64_t now = now_ms();
        if (now < 0 || now >= deadline || !zapp_relay_client_alive(alive)) return false;
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, 50);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return false;
        if (rc > 0) return !(p.revents & (POLLERR | POLLNVAL));
    }
}
static int connect_loopback(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) || fcntl(fd, F_SETFL, O_NONBLOCK)) {
        close(fd); return -1;
    }
    return fd;
}
static bool send_all(int fd, const void *data, size_t size, int64_t deadline, int alive)
{
    for (size_t sent = 0; sent < size;) {
        if (!wait_io(fd, POLLOUT, deadline, alive)) return false;
        ssize_t n = send(fd, (const char *)data + sent, size - sent, MSG_NOSIGNAL);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}
/* buf holds cap + 1 bytes; the body read so far is NUL-terminated on success. */
static bool receive_all(int fd, unsigned char *buf, size_t cap, size_t *used,
                        int64_t deadline, int alive)
{
    *used = 0;
    for (;;) {
        if (!wait_io(fd, POLLIN, deadline, alive)) return false;
        ssize_t n = recv(fd, buf + *used, cap - *used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 0) return false;
        if (n == 0) { buf[*used] = 0; return true; }
        *used += (size_t)n;
        if (*used == cap) return false;
    }
}
static const char *header(const char *head, size_t length, const char *name)
{
    size_t n = strlen(name);
    for (const char *line = head; line && line < head + length;) {
        const char *next = memmem(line, (size_t)(head + length - line), "\r\n", 2);
        if (!next) return NULL;
        if ((size_t)(next - line) > n && !strncasecmp(line, name, n) && line[n] == ':') {
            const char *value = line + n + 1;
            while (*value == ' ') value++;
            return value;
        }
        line = next + 2;
    }
    return NULL;
}
static bool dechunk(unsigned char *body, size_t *size)
{
    size_t in = 0, out = 0;
    for (;;) {
        char *end = NULL;
        unsigned long chunk = strtoul((const char *)body + in, &end, 16);
        if (!end || end == (char *)body + in) return false;
        const unsigned char *crlf = end ? memmem(end, *size - (size_t)((unsigned char *)end - body), "\r\n", 2) : NULL;
        if (!crlf) return false;
        in = (size_t)(crlf - body) + 2;
        if (!chunk) { *size = out; return true; }
        if (chunk > *size - in || *size - in - chunk < 2) return false;
        memmove(body + out, body + in, chunk);
        out += chunk; in += chunk + 2;
    }
}
static bool parse_response(unsigned char *raw, size_t used, size_t *offset, size_t *size)
{
    const unsigned char *split = memmem(raw, used, "\r\n\r\n", 4);
    if (!split || (size_t)(split - raw) > HEADER_CAP || used < 12 ||
        (memcmp(raw, "HTTP/1.1 200", 12) && memcmp(raw, "HTTP/1.0 200", 12))) return false;
    size_t head = (size_t)(split - raw) + 2;
    *offset = head + 2; *size = used - *offset;
    const char *encoding = header((const char *)raw, head, "Transfer-Encoding");
    if (encoding && !strncasecmp(encoding, "chunked", 7)) return dechunk(raw + *offset, size);
    const char *length = header((const char *)raw, head, "Content-Length");
    return !length || strtoull(length, NULL, 10) == *size;
}
static bool format_head(const struct zapp_http_request *r, char *head, size_t cap, size_t *length)
{
    int n = r->body ? snprintf(head, cap, "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Content-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        r->method, r->path, r->content_type, r->body_size) :
        snprintf(head, cap, "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        r->method, r->path);
    *length = n > 0 ? (size_t)n : 0;
    return n > 0 && (size_t)n < cap;
}
static bool request_valid(const struct zapp_http_request *r)
{
    return r && r->port && r->method && r->path && r->timeout_ms > 0 && r->response_cap &&
        (!r->body || r->content_type);
}
static bool transfer(const struct zapp_http_request *r, int fd, const char *head, size_t head_length,
                     unsigned char *raw, size_t cap, int64_t deadline, size_t *offset, size_t *length)
{
    size_t used = 0;
    return fd >= 0 && send_all(fd, head, head_length, deadline, r->alive_fd) &&
        (!r->body || send_all(fd, r->body, r->body_size, deadline, r->alive_fd)) &&
        receive_all(fd, raw, cap, &used, deadline, r->alive_fd) &&
        parse_response(raw, used, offset, length) && *length <= r->response_cap;
}
bool zapp_http_exchange(const struct zapp_http_request *r, unsigned char **body, size_t *size)
{
    *body = NULL; *size = 0;
    char head[1024]; size_t head_length = 0;
    if (!request_valid(r) || !format_head(r, head, sizeof(head), &head_length)) return false;
    int64_t start = now_ms(), deadline = start + r->timeout_ms;
    size_t cap = r->response_cap + HEADER_CAP, offset = 0, length = 0;
    unsigned char *raw = start >= 0 ? malloc(cap + 1) : NULL;
    int fd = raw ? connect_loopback(r->port) : -1;
    bool ok = transfer(r, fd, head, head_length, raw, cap, deadline, &offset, &length);
    if (fd >= 0) close(fd);
    if (ok) {
        memmove(raw, raw + offset, length); raw[length] = 0;
        memory_cleanse(raw + length + 1, cap - length);
        *body = raw; *size = length;
    }
    else if (raw) { memory_cleanse(raw, cap + 1); free(raw); }
    return ok;
}
