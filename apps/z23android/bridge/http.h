/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_HTTP_H
#define Z23_ANDROID_HTTP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zapp_http_request {
    uint16_t port;
    const char *method, *path, *content_type;
    const void *body;
    size_t body_size, response_cap;
    int timeout_ms;
    int alive_fd; /* Aborts when this client disconnects; -1 disables the check. */
    /* Streaming only: receives the response Content-Type, if any, before the first body byte. */
    void (*on_type)(const char *content_type, void *ctx);
};
/* One HTTP/1.1 exchange with 127.0.0.1. Succeeds only for status 200 with a
 * complete body. The body is NUL-terminated; the caller cleanses and frees it. */
bool zapp_http_exchange(const struct zapp_http_request *request,
                        unsigned char **body, size_t *size);
/* Like zapp_http_exchange, but hands the decoded body to on_body as it arrives, in pieces of
 * any size. response_cap bounds the total body. False when on_body returns false, the body is
 * incomplete or malformed, the deadline passes or the client disconnects. */
bool zapp_http_stream(const struct zapp_http_request *request,
                      bool (*on_body)(const unsigned char *data, size_t size, void *ctx), void *ctx);
#endif
