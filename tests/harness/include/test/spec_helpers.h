/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared helpers for wallet spec tests.
 * Include ONCE per spec file — provides GET, POST, has, not_has. */

#ifndef ZCL_TEST_SPEC_HELPERS_H
#define ZCL_TEST_SPEC_HELPERS_H

#include "test/spec.h"
#include "controllers/wallet_view_controller.h"
#include <string.h>
#include <stdint.h>

static uint8_t _resp[131072];

__attribute__((unused))
static size_t GET(const char *path) {
    memset(_resp, 0, sizeof(_resp));
    return wallet_view_handle_request("GET", path, NULL, 0,
                                       _resp, sizeof(_resp));
}

__attribute__((unused))
static size_t POST(const char *path, const char *body) {
    memset(_resp, 0, sizeof(_resp));
    return wallet_view_handle_request("POST", path,
        (const uint8_t *)body, body ? strlen(body) : 0,
        _resp, sizeof(_resp));
}

/* Does the rendered page contain this text? */
__attribute__((unused))
static bool has(const char *needle) {
    return strstr((char *)_resp, needle) != NULL;
}

/* Is the response a valid 200 HTML page? */
__attribute__((unused))
static bool is_200(void) {
    return has("HTTP/1.1 200 OK") && has("text/html");
}

/* Is the page in loading state (no DB)? */
__attribute__((unused))
static bool is_loading(void) {
    return has("Wallet Loading");
}

#endif
