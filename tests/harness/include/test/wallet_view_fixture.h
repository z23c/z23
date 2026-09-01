/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * DEFINE_WALLET_VIEW_CLIENT — the request/response client the wallet-view
 * specs stamp out. Split out of test/test_helpers.h; it is the only macro
 * there that expands to a call into a node symbol. */

#ifndef TEST_WALLET_VIEW_FIXTURE_H
#define TEST_WALLET_VIEW_FIXTURE_H

#include "test/test_core.h"
#include "controllers/wallet_view_controller.h"

/* Wallet view spec helpers.
 * Defines a fixed response buffer plus uniform request helpers. */
#define DEFINE_WALLET_VIEW_CLIENT(buf_name, len_name, request_name, get_name, \
                                  post_name, has_name, buf_size) \
    static uint8_t buf_name[(buf_size)]; \
    static size_t len_name __attribute__((unused)); \
    static size_t request_name(const char *method, const char *path, \
                               const char *body) __attribute__((unused)); \
    static size_t request_name(const char *method, const char *path, \
                               const char *body) { \
        memset(buf_name, 0, sizeof(buf_name)); \
        len_name = wallet_view_handle_request( \
            method, path, \
            body ? (const uint8_t *)body : NULL, \
            body ? strlen(body) : 0, \
            buf_name, sizeof(buf_name)); \
        return len_name; \
    } \
    static size_t get_name(const char *path) __attribute__((unused)); \
    static size_t get_name(const char *path) { \
        return request_name("GET", path, NULL); \
    } \
    static size_t post_name(const char *path, const char *body) \
        __attribute__((unused)); \
    static size_t post_name(const char *path, const char *body) { \
        return request_name("POST", path, body); \
    } \
    static bool has_name(const char *needle) __attribute__((unused)); \
    static bool has_name(const char *needle) { \
        return strstr((char *)buf_name, needle) != NULL; \
    }

#endif /* TEST_WALLET_VIEW_FIXTURE_H */
