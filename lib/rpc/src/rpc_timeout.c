/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTTP RPC request timeout watchdog.
 *
 * See rpc/rpc_timeout.h for the design sketch.  This TU owns the
 * slot table + watchdog thread + global handle.  event_emit() is
 * invoked from the watchdog thread only (not from register/
 * unregister hot paths) so the RPC dispatch path takes no extra
 * event cost unless a kill actually fires.
 */

#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "rpc/rpc_timeout.h"
#include "event/event.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RPC_TIMEOUT_DEFAULT_MS       10000
#define RPC_TIMEOUT_DEFAULT_SWEEP_MS   250

/* ── Global handle — guarded by its own mutex ─────────────── */

static pthread_mutex_t g_global_lock = PTHREAD_MUTEX_INITIALIZER;
static struct rpc_timeout_mgr *g_global_mgr = NULL;

void rpc_timeout_set_global(struct rpc_timeout_mgr *mgr)
{
    pthread_mutex_lock(&g_global_lock);
    g_global_mgr = mgr;
    pthread_mutex_unlock(&g_global_lock);
}

struct rpc_timeout_mgr *rpc_timeout_get_global(void)
{
    pthread_mutex_lock(&g_global_lock);
    struct rpc_timeout_mgr *m = g_global_mgr;
    pthread_mutex_unlock(&g_global_lock);
    return m;
}

/* ── Utilities ─────────────────────────────────────────────── */

static int64_t now_us(void)
{
    /* MONOTONIC: this clock drives RPC deadline/elapsed math only. With a
     * wall clock, a backward NTP/suspend step makes elapsed go negative so
     * the watchdog stops killing genuinely-stuck RPCs, and a forward step
     * instantly kills healthy in-flight RPCs. The monotonic clock never
     * inverts (matches http_middleware.c's timeout source). */
    return platform_time_monotonic_us();
}

static void parse_env_int(const char *name, int *dst, int min_v, int max_v)
{
    const char *v = getenv(name);
    if (!v || !*v) return;
    char *endp = NULL;
    long n = strtol(v, &endp, 10);
    if (endp == v || *endp != '\0') return;
    if (n < (long)min_v) n = min_v;
    if (n > (long)max_v) n = max_v;
    *dst = (int)n;
}

static void ip_be_to_str(uint32_t ip_be, char *out, size_t outlen)
{
    struct in_addr a;
    a.s_addr = ip_be;
    if (!platform_socket_format_address(AF_INET, &a, out, outlen))
        snprintf(out, outlen, "0.0.0.0");
}

/* ── Lifecycle ─────────────────────────────────────────────── */

void rpc_timeout_init(struct rpc_timeout_mgr *mgr)
{
    if (!mgr) return;
    memset(mgr, 0, sizeof(*mgr));
    mgr->timeout_ms          = RPC_TIMEOUT_DEFAULT_MS;
    mgr->proof_timeout_ms    = RPC_PROOF_BUILD_TIMEOUT_MS;
    mgr->watchdog_period_ms  = RPC_TIMEOUT_DEFAULT_SWEEP_MS;
    pthread_mutex_init(&mgr->lock, NULL);
    pthread_cond_init(&mgr->wakeup, NULL);
    mgr->initialized = true;
}

void rpc_timeout_destroy(struct rpc_timeout_mgr *mgr)
{
    if (!mgr || !mgr->initialized) return;
    rpc_timeout_stop_watchdog(mgr);
    pthread_mutex_destroy(&mgr->lock);
    pthread_cond_destroy(&mgr->wakeup);
    mgr->initialized = false;
}

void rpc_timeout_load_from_env(struct rpc_timeout_mgr *mgr)
{
    if (!mgr || !mgr->initialized) return;
    pthread_mutex_lock(&mgr->lock);
    parse_env_int("ZCL_RPC_TIMEOUT_MS",       &mgr->timeout_ms,         0, 600000);
    parse_env_int("ZCL_RPC_PROOF_TIMEOUT_MS", &mgr->proof_timeout_ms,   1, 600000);
    parse_env_int("ZCL_RPC_TIMEOUT_SWEEP_MS", &mgr->watchdog_period_ms, 10, 60000);
    pthread_mutex_unlock(&mgr->lock);
}

void rpc_timeout_reset_state(struct rpc_timeout_mgr *mgr)
{
    if (!mgr || !mgr->initialized) return;
    pthread_mutex_lock(&mgr->lock);
    memset(mgr->slots, 0, sizeof(mgr->slots));
    mgr->stat_registered = 0;
    mgr->stat_completed  = 0;
    mgr->stat_killed     = 0;
    mgr->stat_sweeps     = 0;
    pthread_mutex_unlock(&mgr->lock);
}

/* ── Slot registration ─────────────────────────────────────── */

int rpc_timeout_register(struct rpc_timeout_mgr *mgr,
                          platform_socket_t client_fd, uint32_t ip_be)
{
    if (!mgr || !mgr->initialized) return -1;
    if (mgr->timeout_ms <= 0) {
        /* Disabled — no tracking, caller can ignore slot id. */
        return -1;
    }

    int slot = -1;
    pthread_mutex_lock(&mgr->lock);
    for (int i = 0; i < RPC_TIMEOUT_MAX_SLOTS; i++) {
        if (!mgr->slots[i].in_use) {
            mgr->slots[i].in_use    = true;
            mgr->slots[i].killed    = false;
            mgr->slots[i].client_fd = client_fd;
            mgr->slots[i].ip_be     = ip_be;
            mgr->slots[i].start_us  = now_us();
            mgr->slots[i].timeout_ms = mgr->timeout_ms;
            mgr->slots[i].method[0] = '\0';
            mgr->stat_registered++;
            slot = i;
            break;
        }
    }
    pthread_mutex_unlock(&mgr->lock);
    return slot;
}

void rpc_timeout_set_method(struct rpc_timeout_mgr *mgr,
                             int slot, const char *method)
{
    if (!mgr || !mgr->initialized) return;
    if (slot < 0 || slot >= RPC_TIMEOUT_MAX_SLOTS) return;
    if (!method) return;
    pthread_mutex_lock(&mgr->lock);
    if (mgr->slots[slot].in_use) {
        size_t n = strnlen(method, RPC_TIMEOUT_METHOD_LEN - 1);
        memcpy(mgr->slots[slot].method, method, n);
        mgr->slots[slot].method[n] = '\0';
        /* Shielded planning performs a real, non-broadcast Sapling proof
         * preflight before it persists a reservation, and commit rebuilds
         * the exact proof before durable relay. Keep the ordinary 10-second
         * worker ceiling for every other method, but give these exact owner
         * surfaces the bounded proof-building budget. The
         * generic deadline still wins when an operator configured it higher;
         * a method label can extend a slot, never shorten one. */
        if ((strcmp(method, "getnewaddress") == 0 ||
             strcmp(method, "z_getnewaddress") == 0) &&
            RPC_WALLET_MUTATION_TIMEOUT_MS > mgr->slots[slot].timeout_ms) {
            mgr->slots[slot].timeout_ms = RPC_WALLET_MUTATION_TIMEOUT_MS;
        }
        if ((strcmp(method, "z_sendmany") == 0 ||
             strcmp(method, "rescanwitnesses") == 0 ||
             strcmp(method, "vault_intent_plan") == 0 ||
             strcmp(method, "vault_intent_fanout_plan") == 0 ||
             strcmp(method, "vault_intent_commit") == 0) &&
            mgr->proof_timeout_ms > mgr->slots[slot].timeout_ms) {
            mgr->slots[slot].timeout_ms = mgr->proof_timeout_ms;
        }
        /* Onion market retrieval is sequential blocking embedded-Tor
         * fetches inside one RPC (see RPC_MARKET_DELIVERY_TIMEOUT_MS). */
        if (strcmp(method, "zmarket_purchase_retrieve") == 0 &&
            RPC_MARKET_DELIVERY_TIMEOUT_MS > mgr->slots[slot].timeout_ms) {
            mgr->slots[slot].timeout_ms = RPC_MARKET_DELIVERY_TIMEOUT_MS;
        }
    }
    pthread_mutex_unlock(&mgr->lock);
}

void rpc_timeout_unregister(struct rpc_timeout_mgr *mgr, int slot)
{
    if (!mgr || !mgr->initialized) return;
    if (slot < 0 || slot >= RPC_TIMEOUT_MAX_SLOTS) return;
    pthread_mutex_lock(&mgr->lock);
    if (mgr->slots[slot].in_use) {
        if (!mgr->slots[slot].killed) {
            mgr->stat_completed++;
        }
        memset(&mgr->slots[slot], 0, sizeof(mgr->slots[slot]));
    }
    pthread_mutex_unlock(&mgr->lock);
}

bool rpc_timeout_was_killed(struct rpc_timeout_mgr *mgr, int slot)
{
    if (!mgr || !mgr->initialized) return false;
    if (slot < 0 || slot >= RPC_TIMEOUT_MAX_SLOTS) return false;
    pthread_mutex_lock(&mgr->lock);
    bool k = mgr->slots[slot].in_use && mgr->slots[slot].killed;
    pthread_mutex_unlock(&mgr->lock);
    return k;
}

/* ── Sweep ─────────────────────────────────────────────────── */

int rpc_timeout_sweep(struct rpc_timeout_mgr *mgr, int64_t current_us)
{
    if (!mgr || !mgr->initialized) return 0;
    if (mgr->timeout_ms <= 0) return 0;

    /* We can hold the lock while collecting hits, then release it
     * and run shutdown()+event_emit() outside so we don't stall new
     * registrations.  Snapshot the kill list (bounded to slot count)
     * then act on it. */
    struct kill_info {
        platform_socket_t fd;
        uint32_t ip_be;
        int64_t  elapsed_us;
        char     method[RPC_TIMEOUT_METHOD_LEN];
    };
    struct kill_info kills[RPC_TIMEOUT_MAX_SLOTS];
    int nkills = 0;

    pthread_mutex_lock(&mgr->lock);
    mgr->stat_sweeps++;
    for (int i = 0; i < RPC_TIMEOUT_MAX_SLOTS; i++) {
        if (!mgr->slots[i].in_use) continue;
        if (mgr->slots[i].killed)  continue;
        int64_t elapsed = current_us - mgr->slots[i].start_us;
        int64_t deadline_us = (int64_t)mgr->slots[i].timeout_ms * 1000;
        if (elapsed < deadline_us) continue;

        mgr->slots[i].killed = true;
        mgr->stat_killed++;

        kills[nkills].fd         = mgr->slots[i].client_fd;
        kills[nkills].ip_be      = mgr->slots[i].ip_be;
        kills[nkills].elapsed_us = elapsed;
        memcpy(kills[nkills].method, mgr->slots[i].method,
               RPC_TIMEOUT_METHOD_LEN);
        nkills++;
    }
    pthread_mutex_unlock(&mgr->lock);

    for (int i = 0; i < nkills; i++) {
        /* Force the worker's in-flight read/write to fail fast. */
        if (kills[i].fd != PLATFORM_SOCKET_INVALID)
            (void)platform_socket_shutdown_both(kills[i].fd);
        char ipbuf[32];
        ip_be_to_str(kills[i].ip_be, ipbuf, sizeof(ipbuf));
        const char *m = kills[i].method[0] ? kills[i].method : "(none)";
        event_emitf(EV_RPC_TIMEOUT, 0,
                    "method=%s elapsed_ms=%lld ip=%s",
                    m,
                    (long long)(kills[i].elapsed_us / 1000),
                    ipbuf);
    }

    return nkills;
}

/* ── Watchdog thread ───────────────────────────────────────── */

/* Supervisor liveness: the RPC-timeout watchdog sweeps on a ~250 ms cadence
 * (deadline=120 s). Progress marker = sweep count; no-progress gate disabled
 * (a sweep with no expiries is normal). Single global watchdog, so one
 * module-static child suffices. See util/thread_liveness.h. */
static struct thread_liveness_child g_rpc_timeout_child = {
    .id = SUPERVISOR_INVALID_ID
};

static void *watchdog_fn(void *arg)
{
    struct rpc_timeout_mgr *mgr = (struct rpc_timeout_mgr *)arg;

    pthread_mutex_lock(&mgr->lock);
    while (mgr->watchdog_running) {
        int period = mgr->watchdog_period_ms;
        if (period < 10) period = 10;

        struct timespec wake;
        platform_time_realtime_timespec(&wake);
        wake.tv_sec  += period / 1000;
        wake.tv_nsec += (long)(period % 1000) * 1000000L;
        if (wake.tv_nsec >= 1000000000L) {
            wake.tv_sec  += 1;
            wake.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&mgr->wakeup, &mgr->lock, &wake);
        if (!mgr->watchdog_running) break;
        pthread_mutex_unlock(&mgr->lock);

        rpc_timeout_sweep(mgr, now_us());
        /* Heartbeat onto the supervisor tree (atomic-only; zero behavior
         * change). stat_sweeps is the progress marker. */
        thread_liveness_beat(&g_rpc_timeout_child, (int64_t)mgr->stat_sweeps);

        pthread_mutex_lock(&mgr->lock);
    }
    pthread_mutex_unlock(&mgr->lock);
    /* Abnormal-exit signal for the supervisor's die-vs-stall decision. A
     * graceful stop marks the child complete first, so this is ignored there. */
    thread_liveness_worker_exited(&g_rpc_timeout_child);
    return NULL;
}

bool rpc_timeout_start_watchdog(struct rpc_timeout_mgr *mgr)
{
    if (!mgr || !mgr->initialized) return false;
    if (mgr->timeout_ms <= 0) return true;   /* disabled — nothing to do */

    pthread_mutex_lock(&mgr->lock);
    if (mgr->watchdog_started) {
        pthread_mutex_unlock(&mgr->lock);
        return true;
    }
    mgr->watchdog_running = true;
    pthread_mutex_unlock(&mgr->lock);

    /* SAFE PERMANENT auto-restart: the watchdog is a pure periodic sweep of
     * the timeout registry; all persistent state lives on `mgr`, not the
     * thread, so re-entering the loop from scratch (re-locking mgr->lock) is a
     * no-op on correctness. Storm cap: 5 restarts / 60 s → permanent
     * "thread_restart_storm_zcl_rpc_timeout" blocker. The worker tid lives in
     * g_rpc_timeout_child.worker_tid so respawn + stop share one handle. */
    // supervised:zcl_rpc_timeout (thread_liveness_register_restartable below)
    if (thread_registry_spawn("zcl_rpc_timeout", watchdog_fn, mgr,
                                  &g_rpc_timeout_child.worker_tid) != 0) {
        pthread_mutex_lock(&mgr->lock);
        mgr->watchdog_running = false;
        pthread_mutex_unlock(&mgr->lock);
        return false;
    }
    (void)thread_liveness_register_restartable(&g_rpc_timeout_child,
                                   "zcl_rpc_timeout",
                                   /*deadline_secs=*/120,
                                   /*progress_quiet_us=*/0,
                                   watchdog_fn, mgr,
                                   /*intensity_max=*/5, /*period_secs=*/60);
    mgr->watchdog_started = true;
    return true;
}

void rpc_timeout_stop_watchdog(struct rpc_timeout_mgr *mgr)
{
    if (!mgr || !mgr->initialized) return;
    pthread_mutex_lock(&mgr->lock);
    bool was_started = mgr->watchdog_started;
    pthread_mutex_unlock(&mgr->lock);
    if (was_started) {
        /* Mark complete FIRST (no more auto-restart), then signal the loop to
         * exit, then join the current worker tid + retire. */
        thread_liveness_stop_begin(&g_rpc_timeout_child);
        pthread_mutex_lock(&mgr->lock);
        mgr->watchdog_running = false;
        pthread_cond_broadcast(&mgr->wakeup);
        pthread_mutex_unlock(&mgr->lock);
        thread_liveness_stop_finish(&g_rpc_timeout_child);
        mgr->watchdog_started = false;
    }
}

/* ── Snapshot ─────────────────────────────────────────────── */

void rpc_timeout_snapshot_take(struct rpc_timeout_mgr *mgr,
                                struct rpc_timeout_snapshot *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!mgr || !mgr->initialized) return;

    pthread_mutex_lock(&mgr->lock);
    out->timeout_ms          = mgr->timeout_ms;
    out->proof_timeout_ms    = mgr->proof_timeout_ms;
    out->watchdog_period_ms  = mgr->watchdog_period_ms;
    out->registered          = mgr->stat_registered;
    out->completed           = mgr->stat_completed;
    out->killed              = mgr->stat_killed;
    out->sweeps              = mgr->stat_sweeps;

    size_t active = 0;
    for (int i = 0; i < RPC_TIMEOUT_MAX_SLOTS; i++) {
        if (mgr->slots[i].in_use) active++;
    }
    out->active_slots = active;
    pthread_mutex_unlock(&mgr->lock);
}
