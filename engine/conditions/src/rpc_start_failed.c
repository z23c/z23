/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Retry a failed RPC listener and witness its real readiness. */
#include "conditions/rpc_start_failed.h"
#include "config/boot_rpc_retry.h"
#include "framework/condition.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_macros.h"

static bool detect_rpc_start_failed(void)
{
    return boot_rpc_retry_failed();
}

static bool urgent_rpc_start_failed(void)
{
    return boot_rpc_retry_due(platform_time_monotonic_us());
}

static enum condition_remedy_result remedy_rpc_start_failed(void)
{
    struct blocker_record blocker;
    /* blocker-id: rpc.start_failed */
    if (blocker_init(&blocker, BOOT_RPC_START_FAILED_BLOCKER,
                     BOOT_RPC_START_FAILED_OWNER, BLOCKER_DEPENDENCY,
                     "RPC listener failed to bind; retry scheduled"))
        (void)blocker_set(&blocker);
    else
        LOG_WARN("rpc_http", "could not record failed RPC bind blocker");

    int64_t now_us = platform_time_monotonic_us();
    if (!boot_rpc_retry_due(now_us))
        return COND_REMEDY_SKIP;
    (void)boot_rpc_retry_attempt(now_us);
    return COND_REMEDY_OK;
}

static bool witness_rpc_start_failed(int64_t target_at_detect)
{
    // honest-witness-ok: the retry helper reads the actual RPC listener and warmup state.
    (void)target_at_detect;
    if (!boot_rpc_retry_recovered())
        return false; // raw-return-ok:listener-not-ready-is-unwitnessed
    blocker_clear(BOOT_RPC_START_FAILED_BLOCKER);
    return true;
}

static struct condition c_rpc_start_failed = {
    .name = "rpc_start_failed",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 300,
    .max_attempts = 4,
    .cooldown_secs = 300,
    .cooldown_max_rearms = 0,
    .detect = detect_rpc_start_failed,
    .remedy = remedy_rpc_start_failed,
    .witness = witness_rpc_start_failed,
    .urgent = urgent_rpc_start_failed,
    .witness_window_secs = 30,
};

void register_rpc_start_failed(void)
{
    (void)condition_register(&c_rpc_start_failed);
}
