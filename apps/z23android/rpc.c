/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "rpc.h"
#include "base/cleanse.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define COOKIE_CAP 256u

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static enum zapp_rpc_result fail(enum zapp_rpc_result kind, char *why, size_t cap, const char *step, int err)
{
    if (err) snprintf(why, cap, "%s: %s", step, strerror(err));
    else snprintf(why, cap, "%s", step);
    return kind;
}

/* Reads the first line of <directory>/<name>, without its line end. False when absent or empty. */
static bool read_line(const char *directory, const char *name, char *buf, size_t cap)
{
    char file[1200];
    int n = snprintf(file, sizeof(file), "%s/%s", directory, name);
    if (n <= 0 || (size_t)n >= sizeof(file)) return false;
    int fd = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t got = read(fd, buf, cap - 1);
    close(fd);
    if (got <= 0) return false;
    buf[got] = 0;
    buf[strcspn(buf, "\r\n")] = 0;
    return buf[0] != 0;
}

static void base64(const unsigned char *in, size_t n, char *out)
{
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0u) | (i + 2 < n ? in[i + 2] : 0u);
        *out++ = digits[v >> 18 & 63];
        *out++ = digits[v >> 12 & 63];
        *out++ = i + 1 < n ? digits[v >> 6 & 63] : '=';
        *out++ = i + 2 < n ? digits[v & 63] : '=';
    }
    *out = 0;
}

static bool wait_fd(int fd, short events, int64_t deadline)
{
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) { errno = ETIMEDOUT; return false; }
        struct pollfd p = {fd, events, 0};
        int rc = poll(&p, 1, left > INT32_MAX ? INT32_MAX : (int)left);
        if (rc > 0) return true;
        if (rc == 0) { errno = ETIMEDOUT; return false; }
        if (errno != EINTR) return false;
    }
}

/* Connects to 127.0.0.1:port before the deadline. Returns the descriptor, or -1 with errno set. */
static int connect_loopback(unsigned port, int64_t deadline)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int err = 0;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 && errno != EINPROGRESS) err = errno;
    if (!err && !wait_fd(fd, POLLOUT, deadline)) err = errno;
    socklen_t length = sizeof(err);
    if (!err && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &length) != 0) err = errno;
    if (err) { close(fd); errno = err; return -1; }
    return fd;
}

static bool send_all(int fd, const char *data, size_t length, int64_t deadline)
{
    while (length) {
        ssize_t n = send(fd, data, length, MSG_NOSIGNAL);
        if (n > 0) { data += n; length -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno != EAGAIN) return false;
        if (!wait_fd(fd, POLLOUT, deadline)) return false;
    }
    return true;
}

static const char *head_value(const char *head, size_t length, const char *name);

/* True once the reply head names a Content-Length and that many body bytes have arrived. */
static bool reply_complete(const char *reply, size_t used)
{
    const char *split = memmem(reply, used, "\r\n\r\n", 4);
    const char *declared = split ? head_value(reply, (size_t)(split - reply) + 2, "Content-Length") : NULL;
    return declared && used - (size_t)(split + 4 - reply) >= strtoull(declared, NULL, 10);
}

/* Reads until the reply is complete or the node closes the connection. False on error, timeout or a
 * reply over cap - 1. */
static bool receive_all(int fd, char *out, size_t cap, size_t *used, int64_t deadline)
{
    *used = 0;
    for (;;) {
        if (*used + 1 >= cap) { errno = EMSGSIZE; return false; }
        ssize_t n = recv(fd, out + *used, cap - 1 - *used, 0);
        if (n > 0) {
            *used += (size_t)n;
            out[*used] = 0;
            if (reply_complete(out, *used)) return true;
            continue;
        }
        if (n == 0) { out[*used] = 0; return true; }
        if (errno == EINTR) continue;
        if (errno != EAGAIN || !wait_fd(fd, POLLIN, deadline)) return false;
    }
}

/* The value of a header in the reply head, or NULL. */
static const char *head_value(const char *head, size_t length, const char *name)
{
    size_t n = strlen(name);
    for (const char *line = head; line < head + length;) {
        const char *end = memmem(line, (size_t)(head + length - line), "\r\n", 2);
        if (!end) break;
        if ((size_t)(end - line) > n && !strncasecmp(line, name, n) && line[n] == ':') {
            line += n + 1;
            while (*line == ' ') ++line;
            return line;
        }
        line = end + 2;
    }
    return NULL;
}

/* Moves the body of a complete 200 reply to the start of out. Names the problem in why otherwise. */
static bool reply_body(char *out, size_t used, char *why, size_t why_cap)
{
    char *split = memmem(out, used, "\r\n\r\n", 4);
    if (!split || used < 12 || (memcmp(out, "HTTP/1.1 200", 12) && memcmp(out, "HTTP/1.0 200", 12))) {
        int code = used > 9 ? atoi(out + 9) : 0;
        if (split && code) snprintf(why, why_cap, "the node answered HTTP %d", code);
        else snprintf(why, why_cap, "the node sent a reply that is not HTTP");
        return false;
    }
    size_t head = (size_t)(split - out) + 2;
    char *body = split + 4;
    size_t length = used - (size_t)(body - out);
    const char *encoding = head_value(out, head, "Transfer-Encoding");
    const char *declared = head_value(out, head, "Content-Length");
    if (encoding || (declared && strtoull(declared, NULL, 10) != length)) {
        snprintf(why, why_cap, "the node reply is chunked or incomplete");
        return false;
    }
    memmove(out, body, length);
    out[length] = 0;
    return true;
}

/* Head and body leave in one send, so the node never answers and closes with the body unread. */
static enum zapp_rpc_result exchange(unsigned port, const char *cookie, const char *request, size_t request_length,
                                     int64_t deadline, char *out, size_t cap, char *why, size_t why_cap)
{
    char token[COOKIE_CAP * 2], message[1280];
    base64((const unsigned char *)cookie, strlen(cookie), token);
    int head = snprintf(message, sizeof(message),
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", token, request_length);
    memory_cleanse(token, sizeof(token));
    bool fits = head > 0 && (size_t)head + request_length < sizeof(message);
    if (fits) memcpy(message + head, request, request_length);
    size_t length = fits ? (size_t)head + request_length : 0;
    int fd = fits ? connect_loopback(port, deadline) : -1;
    if (fd < 0) {
        memory_cleanse(message, sizeof(message));
        if (!fits) return fail(ZAPP_RPC_FAILED, why, why_cap, "request too large", 0);
        return fail(errno == ECONNREFUSED ? ZAPP_RPC_UNREACHABLE : ZAPP_RPC_FAILED, why, why_cap, "connect", errno);
    }
    size_t used = 0;
    bool ok = send_all(fd, message, length, deadline);
    int err = ok ? 0 : errno;
    memory_cleanse(message, sizeof(message));
    ok = ok && receive_all(fd, out, cap, &used, deadline);
    if (!err && !ok) err = errno;
    close(fd);
    if (!ok) return fail(ZAPP_RPC_FAILED, why, why_cap, "exchange", err);
    return reply_body(out, used, why, why_cap) ? ZAPP_RPC_OK : ZAPP_RPC_FAILED;
}

/* Reads the port and cookie the node recorded in datadir, or says why it cannot be reached. */
static enum zapp_rpc_result endpoint(const char *datadir, unsigned *port, char *cookie, size_t cookie_cap,
                                     char *why, size_t why_cap)
{
    char text[32], *end = NULL;
    if (!read_line(datadir, ".rpcport", text, sizeof(text)))
        return fail(ZAPP_RPC_UNREACHABLE, why, why_cap, "no RPC port file", 0);
    long value = strtol(text, &end, 10);
    if (*end || value <= 0 || value > 65535)
        return fail(ZAPP_RPC_FAILED, why, why_cap, "RPC port file is not a port", 0);
    *port = (unsigned)value;
    if (!read_line(datadir, ".cookie", cookie, cookie_cap))
        return fail(ZAPP_RPC_UNREACHABLE, why, why_cap, "no RPC cookie", 0);
    return ZAPP_RPC_OK;
}

enum zapp_rpc_result zapp_rpc_call(const char *datadir, const char *method, const char *params,
                                   int timeout_ms, char *out, size_t cap, char *why, size_t why_cap)
{
    if (!why || !why_cap) return ZAPP_RPC_FAILED;
    if (!datadir || !method || !params || !out || cap < 256 || timeout_ms <= 0)
        return fail(ZAPP_RPC_FAILED, why, why_cap, "bad request", 0);
    char cookie[COOKIE_CAP], request[512];
    unsigned port = 0;
    enum zapp_rpc_result rc = endpoint(datadir, &port, cookie, sizeof(cookie), why, why_cap);
    if (rc != ZAPP_RPC_OK) return rc;
    int64_t now = now_ms();
    int length = snprintf(request, sizeof(request), "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
                          method, params);
    rc = now < 0 ? fail(ZAPP_RPC_FAILED, why, why_cap, "clock", errno) :
        length <= 0 || (size_t)length >= sizeof(request) ? fail(ZAPP_RPC_FAILED, why, why_cap, "request too large", 0) :
        exchange(port, cookie, request, (size_t)length, now + timeout_ms, out, cap, why, why_cap);
    memory_cleanse(cookie, sizeof(cookie));
    return rc;
}
