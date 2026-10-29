/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "http.h"
#include <arpa/inet.h>
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
    "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\ntoo long body",
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
static bool exchange(uint16_t port, bool post, size_t cap, unsigned char **body, size_t *size)
{
    struct zapp_http_request r = {.port = port, .method = post ? "POST" : "GET",
        .path = post ? "/v1/x" : "/health", .content_type = post ? "application/json" : NULL,
        .body = post ? "ping" : NULL, .body_size = post ? 4 : 0, .response_cap = cap,
        .timeout_ms = 5000, .alive_fd = -1};
    return zapp_http_exchange(&r, body, size);
}
int main(void)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t n = sizeof(a);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0 && !bind(listener, (struct sockaddr *)&a, n) && !listen(listener, 8) &&
        !getsockname(listener, (struct sockaddr *)&a, &n));
    uint16_t port = ntohs(a.sin_port);
    pthread_t thread; assert(!pthread_create(&thread, NULL, serve, NULL));
    unsigned char *body = NULL; size_t size = 0;
    assert(exchange(port, false, 64, &body, &size) && size == 5 && !strcmp((char *)body, "hello")); free(body);
    assert(exchange(port, true, 64, &body, &size) && size == 11 && !strcmp((char *)body, "hello world")); free(body);
    assert(!exchange(port, true, 64, &body, &size) && !body && !size);
    assert(!exchange(port, true, 64, &body, &size) && !body);
    assert(!exchange(port, true, 8, &body, &size) && !body);
    assert(!exchange(port, true, 64, &body, &size) && !body);
    pthread_join(thread, NULL); close(listener);
    assert(!exchange(port, false, 64, &body, &size) && !body);
    puts("http tests passed");
    return 0;
}
