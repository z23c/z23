/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Recover a failed RPC bind while independent frontend siblings stay live. */
#include "config/boot_rpc_retry.h"
#include "kernel/service_kernel.h"
#include "platform/time_compat.h"
#include "rpc/httpserver.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <stdatomic.h>

#define RPC_RETRY_FIRST_US (5LL * 1000000LL)
#define RPC_RETRY_CAP_US (300LL * 1000000LL)

/* The condition runner stops and joins before the frontend kernel shuts down.
 * The pointer is published only after the first frontend start attempt. */
static _Atomic(struct zcl_service_kernel *) g_rpc_retry_kernel;
static _Atomic int g_rpc_retry_attempts;
static _Atomic int64_t g_rpc_retry_next_us;

void boot_rpc_retry_arm(struct zcl_service_kernel *kernel)
{
    if (!kernel || !kernel->started)
        return;
    atomic_store(&g_rpc_retry_attempts, 0);
    atomic_store(&g_rpc_retry_next_us,
                 platform_time_monotonic_us() + RPC_RETRY_FIRST_US);
    atomic_store(&g_rpc_retry_kernel, kernel);
}

void boot_rpc_retry_disarm(struct zcl_service_kernel *kernel)
{
    struct zcl_service_kernel *current = kernel;
    (void)atomic_compare_exchange_strong(&g_rpc_retry_kernel, &current, NULL);
}

bool boot_rpc_retry_failed(void)
{
    struct zcl_service_kernel *kernel = atomic_load(&g_rpc_retry_kernel);
    struct zcl_service_status status;
    return kernel &&
           zcl_service_kernel_status(kernel, "rpc_http", &status) &&
           status.state == ZCL_SERVICE_FAILED && !rpc_http_is_running();
}

bool boot_rpc_retry_due(int64_t now_us)
{
    return boot_rpc_retry_failed() &&
           now_us >= atomic_load(&g_rpc_retry_next_us);
}

static int64_t rpc_retry_delay_us(int attempts)
{
    int64_t delay = RPC_RETRY_FIRST_US;
    for (int i = 0; i < attempts; i++) {
        if (delay >= RPC_RETRY_CAP_US / 3)
            return RPC_RETRY_CAP_US;
        delay *= 3;
    }
    return delay;
}

bool boot_rpc_retry_attempt(int64_t now_us)
{
    if (!boot_rpc_retry_due(now_us))
        return false;
    struct zcl_service_kernel *kernel = atomic_load(&g_rpc_retry_kernel);
    int attempts = atomic_fetch_add(&g_rpc_retry_attempts, 1) + 1;
    atomic_store(&g_rpc_retry_next_us,
                 now_us + rpc_retry_delay_us(attempts));
    LOG_WARN("rpc_http", "retrying failed RPC listener bind: attempt=%d", attempts);
    return zcl_service_kernel_retry_failed(kernel, "rpc_http");
}

bool boot_rpc_retry_recovered(void)
{
    struct zcl_service_kernel *kernel = atomic_load(&g_rpc_retry_kernel);
    struct zcl_service_status status;
    return kernel &&
           zcl_service_kernel_status(kernel, "rpc_http", &status) &&
           status.state == ZCL_SERVICE_STARTED && rpc_http_is_running() &&
           !rpc_is_in_warmup(NULL, 0);
}
