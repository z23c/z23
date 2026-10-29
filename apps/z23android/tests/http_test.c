/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "http.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool zapp_relay_client_alive(int fd) { (void)fd; return true; }
static const char *const replies[] = {
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\n\r\nfail",
    "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ntoo long body",
    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ntoo long body",
    "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nZZ\r\nbad\r\n0\r\n\r\n",
};
static int listener;
static void *serve(void *unused)
{
    (void)unused;
    for (size_t i = 0; i < sizeof(replies) / sizeof(replies[0]); i++) {
        int fd = accept(listener, NULL, NULL); assert(fd >= 0);
        char request[4096]; size_t used = 0;
        while (!memmem(request, used, i ? "\r\n\r\nping" : "\r\n\r\n", i ? 8 : 4)) {
            ssize_t n = recv(fd, request + used, sizeof(request) - used, 0); assert(n > 0); used += (size_t)n;
        }
        assert(!strncmp(request, i ? "POST /v1/x HTTP/1.1\r\n" : "GET /health HTTP/1.1\r\n", i ? 21 : 22));
        assert(send(fd, replies[i], strlen(replies[i]), 0) == (ssize_t)strlen(replies[i]));
        close(fd);
    }
    return NULL;
}
/* Streaming cases: the server delivers each piece in its own TCP segment. */
struct stream_case { const char *pieces[8]; bool ok; const char *body; size_t stop_after, cap; };
static const struct stream_case stream_cases[] = {
    {{"HTTP/1.1 200 OK\r\nContent-Type: audio/pcm;rate=24000\r\nTransfer-Encoding: chunked\r\n\r\n",
      "5\r\nhel", "lo\r", "\n6\r\n wor", "ld\r\n0\r\n\r\n"}, true, "hello world", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-", "Encoding: chunked\r\n", "\r\n", "A\r\n0123456789\r\n", "1\r", "\na\r\n0",
      "\r\n\r\n"}, true, "0123456789a", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"}, true, "hello", 0, 0},
    {{"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", "defg", "hij"}, true, "abcdefghij", 0, 0},
    {{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}, true, "", 0, 0},
    {{"HTTP/1.1 200 OK\r\n\r\nuntil", " close"}, true, "until close", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", "3\r\ndef\r\n0\r\n\r\n"}, false, "abc", 1, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\nZZ\r\nbad\r\n0\r\n\r\n"}, false, "abc", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n0\r\n\r\n"}, false, "abc", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n"}, false, "", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab"}, false, "ab", 0, 0},
    {{"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"}, false, "short", 0, 0},
    {{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcd"}, false, "", 0, 0},
    {{"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\n\r\nfail"}, false, "", 0, 0},
    {{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n0\r\n\r\n"}, false, "", 0, 4},
};
#define STREAM_CASES (sizeof(stream_cases) / sizeof(stream_cases[0]))
static void *serve_pieces(void *unused)
{
    (void)unused;
    for (size_t i = 0; i < STREAM_CASES; i++) {
        int fd = accept(listener, NULL, NULL); assert(fd >= 0);
        int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        char request[4096]; size_t used = 0;
        while (!memmem(request, used, "\r\n\r\n", 4)) {
            ssize_t n = recv(fd, request + used, sizeof(request) - used, 0); assert(n > 0); used += (size_t)n;
        }
        for (size_t k = 0; k < 8 && stream_cases[i].pieces[k]; k++) {
            const char *piece = stream_cases[i].pieces[k];
            if (send(fd, piece, strlen(piece), MSG_NOSIGNAL) < 0) break;
            usleep(3000);
        }
        close(fd);
    }
    return NULL;
}
struct collected { char text[64], type[64]; size_t used, calls, stop_after; };
static bool collect(const unsigned char *data, size_t size, void *ctx)
{
    struct collected *c = ctx;
    assert(size && c->used + size < sizeof(c->text));
    memcpy(c->text + c->used, data, size); c->used += size; c->text[c->used] = 0;
    return ++c->calls != c->stop_after;
}
static void note_type(const char *type, void *ctx)
{
    struct collected *c = ctx;
    snprintf(c->type, sizeof(c->type), "%s", type);
}
static void stream_cases_run(uint16_t port)
{
    pthread_t thread; assert(!pthread_create(&thread, NULL, serve_pieces, NULL));
    for (size_t i = 0; i < STREAM_CASES; i++) {
        const struct stream_case *k = &stream_cases[i];
        struct collected c = {.stop_after = k->stop_after};
        struct zapp_http_request r = {.port = port, .method = "GET", .path = "/s",
            .response_cap = k->cap ? k->cap : 64, .timeout_ms = 5000, .alive_fd = -1, .on_type = note_type};
        assert(zapp_http_stream(&r, collect, &c) == k->ok);
        assert(!strcmp(c.text, k->body));
        assert(!strcmp(c.type, i ? "" : "audio/pcm;rate=24000"));
    }
    pthread_join(thread, NULL);
    struct zapp_http_request none = {.port = port, .method = "GET", .path = "/s", .response_cap = 8,
        .timeout_ms = 100, .alive_fd = -1};
    assert(!zapp_http_stream(&none, NULL, NULL));
}
static bool exchange(uint16_t port, bool post, size_t cap, unsigned char **body, size_t *size)
{
    struct zapp_http_request r = {.port = port, .method = post ? "POST" : "GET",
        .path = post ? "/v1/x" : "/health", .content_type = post ? "application/json" : NULL,
        .body = post ? "ping" : NULL, .body_size = post ? 4 : 0, .response_cap = cap,
        .timeout_ms = 5000, .alive_fd = -1};
    return zapp_http_exchange(&r, body, size);
}
static uint16_t open_listener(void)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t n = sizeof(a);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0 && !bind(listener, (struct sockaddr *)&a, n) && !listen(listener, 8) &&
        !getsockname(listener, (struct sockaddr *)&a, &n));
    return ntohs(a.sin_port);
}
int main(void)
{
    uint16_t port = open_listener();
    pthread_t thread; assert(!pthread_create(&thread, NULL, serve, NULL));
    unsigned char *body = NULL; size_t size = 0;
    assert(exchange(port, false, 64, &body, &size) && size == 5 && !strcmp((char *)body, "hello")); free(body);
    assert(exchange(port, true, 64, &body, &size) && size == 11 && !strcmp((char *)body, "hello world")); free(body);
    assert(!exchange(port, true, 64, &body, &size) && !body && !size);
    assert(!exchange(port, true, 64, &body, &size) && !body);
    assert(!exchange(port, true, 12, &body, &size) && !body);
    assert(exchange(port, true, 13, &body, &size) && size == 13 && !strcmp((char *)body, "too long body")); free(body);
    assert(!exchange(port, true, 64, &body, &size) && !body);
    pthread_join(thread, NULL);
    stream_cases_run(port);
    close(listener);
    assert(!exchange(port, false, 64, &body, &size) && !body);
    puts("http tests passed");
    return 0;
}
