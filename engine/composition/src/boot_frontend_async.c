// supervisor-ok:bounded-frontend-start — one-shot thread, joined at shutdown; no resident service
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Frontend/Tor start off the restart path.
 *
 * Registering and starting the frontend kernel (rpc_http, explorer, api cache,
 * miner, zcode store and the onion_tor bootstrap) took 1.2 s at normal load and
 * 11 s at load 80 on r1's warm boots. P2P, the reducer and the runtime kernel do
 * not depend on any frontend service, so the start runs on one tracked thread
 * that boot_frontend_async_stop joins BEFORE the kernel is stopped or anything
 * the services use is freed.
 *
 * Until the thread reaches rpc_http, the RPC warm-up flag stays set: every RPC
 * that reaches rpc_table_execute answers -28 (and nothing is bound on the wire
 * yet). A failed start keeps today's DEGRADED_SERVING state and arms the
 * rpc_http bind retry exactly as the synchronous path did. */
#include "config/boot_internal.h"
#include "config/boot_rpc_retry.h"
#include "kernel/service_kernel.h"
#include "event/event.h"
#include "util/service_state.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "config/boot_background_workers.h"
#include "platform/time_compat.h"
#include "boot_timing_marks_internal.h"
#include <pthread.h>
#include <stdatomic.h>

static pthread_t g_fe_thread;
static bool g_fe_thread_started;
static atomic_bool g_fe_started; /* start called; done is only meaningful then */
static atomic_bool g_fe_done;
static atomic_bool g_fe_stop;
#ifdef ZCL_TESTING
static atomic_bool g_fe_hold;
static bool (*g_fe_test_body)(struct boot_svc_ctx *);
#endif

static bool frontend_start_body(struct boot_svc_ctx *svc)
{
#ifdef ZCL_TESTING
    if (g_fe_test_body)
        return g_fe_test_body(svc);
#endif
    return boot_register_frontend_services(svc) &&
           zcl_service_kernel_start_all(&svc->frontend_kernel);
}

/* A frontend failure is not data loss: keep P2P and chain advancement alive,
 * report DEGRADED_SERVING, and retry a failed RPC bind. The retry leaves
 * healthy frontend siblings running. */
static void frontend_run(struct boot_svc_ctx *svc)
{
    int64_t t0 = boot_clock_ms();
#ifdef ZCL_TESTING
    while (atomic_load(&g_fe_hold) && !atomic_load(&g_fe_stop))
        platform_sleep_ms(2);
#endif
    boot_configure_frontend_rpc(svc);
    if (!frontend_start_body(svc)) {
        LOG_WARN("frontend", "frontend services failed to start; serving DEGRADED (RPC/explorer/Tor may be unavailable)");
        event_emitf(EV_BOOT_ACTIVATE, 0,
                    "degraded_serving frontend_services_unavailable");
        service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                              "frontend_services_unavailable");
    }
    boot_rpc_retry_arm(&svc->frontend_kernel);
    LOG_INFO("frontend", "svc.frontend_tor_start (async) %lldms", (long long)(boot_clock_ms() - t0));
    atomic_store(&g_fe_done, true);
}

static void *frontend_thread_main(void *arg)
{
    frontend_run(arg);
    return NULL;
}

void boot_frontend_async_start(struct boot_svc_ctx *svc)
{
    atomic_store(&g_fe_done, false);
    atomic_store(&g_fe_stop, false);
    atomic_store(&g_fe_started, true);
    // thread-supervision-ok: one frontend start thread, joined by boot_frontend_async_stop before the kernel stops
    if (thread_registry_spawn("zcl_frontend", frontend_thread_main, svc,
                              &g_fe_thread) == 0) {
        g_fe_thread_started = true;
        return;
    }
    LOG_WARN("frontend", "frontend start thread failed to spawn; starting inline");
    frontend_run(svc);
}

void boot_frontend_async_stop(void)
{
    atomic_store(&g_fe_stop, true);
    if (!g_fe_thread_started)
        return;
    /* Always ends in a blocking join: the kernel must not stop, nor its
     * contexts free, under a start that is still running. */
    (void)boot_join_thread_bounded(g_fe_thread, "frontend start", 60);
    g_fe_thread_started = false;
}

bool boot_frontend_async_done(void)
{
    return atomic_load(&g_fe_done);
}

/* True once the start body finished (success or degraded, thread or inline
 * fallback), or when no start was ever requested. False on timeout or when a
 * shutdown was requested first: the caller must then NOT report READY. The
 * thread is only observed, never touched, so nothing it uses can be freed
 * here. */
bool boot_frontend_async_wait_done(int64_t timeout_ms)
{
    int64_t deadline = boot_clock_ms() + timeout_ms;
    while (atomic_load(&g_fe_started) && !atomic_load(&g_fe_done)) {
        if (thread_registry_shutdown_requested() || boot_clock_ms() >= deadline)
            return false;
        platform_sleep_ms(5);
    }
    return true;
}

/* READY / serving / rpc_bound and the A/B promote are reported only after the
 * frontend start body ran, as when it was synchronous: bootwait polls
 * phase=serving and then uses RPC, so an earlier READY would hand it
 * ECONNREFUSED. Waits in bounded slices, logging each; only a shutdown request
 * ends the wait early (returns false: do not report READY or promote). */
#define FE_GATE_SLICE_MS 30000
bool boot_frontend_async_gate_ready(const char *what)
{
    int64_t t0 = boot_clock_ms();
    while (!boot_frontend_async_wait_done(FE_GATE_SLICE_MS)) {
        if (thread_registry_shutdown_requested()) {
            LOG_WARN("frontend", "shutdown requested before the frontend start finished; not reporting %s", what);
            return false;
        }
        LOG_WARN("frontend", "%s still waiting for the frontend start (%lldms)",
                 what, (long long)(boot_clock_ms() - t0));
    }
    return true;
}

#ifdef ZCL_TESTING
void boot_frontend_async_test_hold(bool hold)
{
    atomic_store(&g_fe_hold, hold);
}

void boot_frontend_async_test_body(bool (*body)(struct boot_svc_ctx *))
{
    g_fe_test_body = body;
}
#endif
