/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded asynchronous and blocking outbound onion fetch ownership,
 * isolated from the embedded Tor thread and service-publication lifecycle. */

#define _DEFAULT_SOURCE
#include "net/tor_integration.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int dynhost_client_fetch(const char *, uint16_t, const char *,
    void (*)(int, const uint8_t *, size_t, void *), void *, int)
    __attribute__((weak));

int tor_integration_fetch_onion(const char *onion_address,
                                const char *path,
                                tor_fetch_callback_fn callback,
                                void *ctx,
                                int timeout_secs)
{
    if (!dynhost_client_fetch)
        LOG_ERR("tor", "dynhost_client_fetch not linked (stub build)");
    if (!tor_integration_is_enabled())
        LOG_ERR("tor", "fetch_onion called but Tor not running");

    return dynhost_client_fetch(onion_address, 80, path,
        (void (*)(int, const uint8_t *, size_t, void *))callback,
        ctx, timeout_secs);
}

#define ONION_FETCH_BODY_MAX (1u << 20) /* 1 MiB */

struct blocking_fetch_ctx {
    _Atomic int refs;        /* waiter + callback; 0 => free */
    _Atomic int complete;    /* 0=pending, 1=ok, -1=error */
    int status;
    uint8_t *body;
    size_t body_len;
};

static void blocking_fetch_release(struct blocking_fetch_ctx *ctx)
{
    if (atomic_fetch_sub(&ctx->refs, 1) == 1) {
        free(ctx->body);
        free(ctx);
    }
}

static void blocking_fetch_cb(int status, const uint8_t *body,
                              size_t body_len, void *arg)
{
    struct blocking_fetch_ctx *ctx = arg;
    ctx->status = status;

    if (body_len > ONION_FETCH_BODY_MAX) {
        LOG_WARN("tor", "onion response of %zu bytes exceeds the %u-byte "
                        "ceiling — refused", body_len,
                 (unsigned)ONION_FETCH_BODY_MAX);
        atomic_store(&ctx->complete, -1);
        blocking_fetch_release(ctx);
        return;
    }

    if (body && body_len > 0) {
        ctx->body = zcl_malloc(body_len + 1, "onion_fetch_body");
        if (ctx->body) {
            memcpy(ctx->body, body, body_len);
            ctx->body[body_len] = '\0';
            ctx->body_len = body_len;
        }
    }
    atomic_store(&ctx->complete, status >= 200 ? 1 : -1);
    blocking_fetch_release(ctx);
}

int tor_integration_fetch_onion_blocking(const char *onion_address,
                                         const char *path,
                                         struct onion_fetch_result *result,
                                         int timeout_secs)
{
    if (!result)
        LOG_ERR("tor", "fetch_onion_blocking called with NULL result");
    memset(result, 0, sizeof(*result));

    struct blocking_fetch_ctx *ctx =
        zcl_malloc(sizeof(*ctx), "onion_fetch_ctx");
    if (!ctx)
        LOG_ERR("tor", "onion fetch context allocation failed");
    memset(ctx, 0, sizeof(*ctx));
    atomic_init(&ctx->refs, 2);
    atomic_init(&ctx->complete, 0);

    int rc = tor_integration_fetch_onion(onion_address, path,
                                         blocking_fetch_cb, ctx,
                                         timeout_secs);
    if (rc < 0) {
        /* Dispatch failed: release both waiter and never-called callback. */
        blocking_fetch_release(ctx);
        blocking_fetch_release(ctx);
        atomic_store(&result->complete, -1);
        LOG_ERR("tor", "fetch_onion failed for %s%s", onion_address, path);
    }

    int wait_ms = (timeout_secs > 0 ? timeout_secs : 60) * 1000;
    for (int elapsed = 0; elapsed < wait_ms; elapsed += 100) {
        if (atomic_load(&ctx->complete) != 0) {
            int ok = atomic_load(&ctx->complete) == 1;
            result->status = ctx->status;
            result->body = ctx->body;
            result->body_len = ctx->body_len;
            ctx->body = NULL;
            atomic_store(&result->complete, ok ? 1 : -1);
            blocking_fetch_release(ctx);
            return ok ? 0 : -1;
        }
        usleep(100000);
    }

    /* The callback retains its reference and may safely finish later. */
    blocking_fetch_release(ctx);
    atomic_store(&result->complete, -1);
    LOG_ERR("tor", "fetch_onion_blocking timed out after %ds for %s%s",
            timeout_secs > 0 ? timeout_secs : 60, onion_address, path);
}
