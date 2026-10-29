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
};
/* One HTTP/1.1 exchange with 127.0.0.1. Succeeds only for status 200 with a
 * complete body. The body is NUL-terminated; the caller cleanses and frees it. */
bool zapp_http_exchange(const struct zapp_http_request *request,
                        unsigned char **body, size_t *size);
#endif
