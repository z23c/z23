/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_sd_watchdog.c — systemd watchdog heartbeat service.
 *
 * Part of the boot composition root (extracted from boot_services.c). This
 * unit owns the systemd WATCHDOG=1 heartbeat: it pings the systemd notify
 * socket every WATCHDOG_USEC/4 microseconds while the process liveness
 * signals remain fresh. A negative node-health verdict stays fail-loud in
 * status/conditions, but is not a process-hang signal: restarting cannot fix
 * an owner gate, trust review, peer outage, or other named degradation.
 * No-op when NOTIFY_SOCKET is absent (e.g. CLI use).
 *
 * Pillar 7 — "supervise the supervisor": the ping is gated on the root
 * supervisor's sweep heartbeat (util/supervisor.h) being fresh, TWICE:
 * once here (the explicit `supervisor_alive` check below, which also
 * drives the STATUS= label) and once more inside sd_notify_watchdog_ping()
 * itself via sd_notify_set_health_check() (registered in
 * boot_sd_watchdog_start below) — a defense-in-depth backstop so the
 * guarantee holds even for a future caller of sd_notify_watchdog_ping()
 * that forgets to check supervisor health first. The node-health snapshot
 * below is collected independently of the supervisor tree, so a
 * wedged/dead zcl_supervisor thread would otherwise leave every
 * supervisor-driven stage frozen while this tick kept pinging happily
 * (health looking fine from a stale-but-not-yet-detected angle) — this is
 * the PREFERRED escalation path from the design: a frozen sweep stops the
 * ping, systemd's own WatchdogSec timer then kills + restarts the unit. The
 * independent off-systemd fallback (no ping to stop) is
 * lib/util/src/supervisor_backstop.c.
 *
 * Owns: the file-statics g_sd_watchdog_id / g_sd_watchdog_ctx tracking the
 * registered health-ring periodic (the COLLECT half), plus g_pet_tid and
 * friends for the dedicated PET thread. The pet thread is spawned here
 * because it must outlive health-ring contention: a supervised child riding
 * the ring could be starved by the very collect blocking it exists to
 * survive. boot_sd_watchdog_tick stays private here. */

#include "platform/time_compat.h"
#include "config/boot_internal.h"
#include "services/node_health_service.h"
#include "services/binary_ab_fallback.h"
#include "health/heartbeat.h"
#include "util/log_macros.h"
#include "util/sd_notify.h"
#include "util/boot_progress.h"
#include "util/supervisor.h"
#include "util/supervisor_backstop.h"
#include "util/thread_registry.h"
#include "net/tor_integration.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── systemd watchdog heartbeat ─────────────────────────────────
 * Two halves, deliberately on different threads:
 *
 *   1. COLLECT tick (lib/health periodic ring): runs node_health_collect,
 *      which publishes diagnostic health evidence, and emits
 *      the STATUS= line. This half MAY block — a collect can wait minutes
 *      on reducer-held locks during bulk ingest — and when it does, only
 *      the verdict/status go stale.
 *
 *   2. PET thread (dedicated, this file): pings WATCHDOG=1 every
 *      WATCHDOG_USEC/4 from CHEAP ATOMICS ONLY (runtime progress,
 *      boot_progress, supervisor sweep heartbeat). It never runs a collect
 *      and never takes a node lock, so ring contention cannot starve the
 *      heartbeat. Before this split the ping rode the same ring as the
 *      collect: a >WatchdogSec collect block stopped the ping on a fully
 *      healthy, progressing node. The loop had a second half: it treated
 *      the CONTENT of a fresh health verdict as a hang signal. Intentional
 *      long-lived postures (first body-history proof, owner trust review)
 *      therefore stopped the pet even while the process, supervisor, RPC,
 *      and health collector remained live. Restarting cannot satisfy those
 *      gates and only prevents the work that can. Together those were the
 *      2026-08-02 and 2026-08-05 kill loops.
 *
 * Health verdict content and collection cadence are handled by the
 * condition/remedy/operator planes; neither decides process liveness. A
 * collect may remain blocked while the reducer continues useful work. The
 * independently sampled runtime pillars below stop the ping when the process
 * actually freezes.
 *
 * No-op when NOTIFY_SOCKET is absent (e.g. CLI invocation). */
static health_subsystem_id g_sd_watchdog_id = HEALTH_INVALID_ID;
static struct boot_svc_ctx *g_sd_watchdog_ctx;

/* Pet-thread state. */
static _Atomic bool g_pet_stop       = false;
static _Atomic bool g_pet_handle_set = false;
static pthread_t    g_pet_tid;
static _Atomic bool g_notify_ready_sent = false;

/* Type=notify first-boot must not fire READY=1 on hostname-only onion
 * readiness, and must not treat "Tor requested but not running" as
 * "Tor was never asked for". Hold READY until DESCRIPTOR PUBLICATION
 * whenever the operator asked for onion. */
bool boot_sd_watchdog_onion_blocks_ready(void)
{
    if (!tor_integration_is_requested() && !tor_integration_is_enabled())
        return false;
    return !tor_integration_is_ready();
}

static bool    boot_sd_watchdog_supervisor_alive(void);
static int64_t boot_sd_watchdog_freshness_bound_us(void);

/* ── Earned readiness ────────────────────────────────────────────
 *
 * READY=1 used to rest on ONE fact: the onion descriptor was published
 * (and on NO fact at all when onion was never requested — the gate
 * returned false and the notify went out unconditionally). It was also
 * emitted from the top of the pet loop, BEFORE and independent of the
 * pet's own liveness decision, so a dead message pump, a dead dial
 * scheduler, or a frozen supervisor sweep did not hold it back. A node
 * could therefore tell systemd it was ready while nothing inside it was
 * running.
 *
 * Now each leg is confirmed on its own evidence and the legs are ANDed.
 * No leg is inferred from another — in particular a published descriptor
 * says nothing about whether a peer can reach us, which is why the
 * status line reports `rendezvous=unconfirmed` verbatim: nothing in this
 * tree observes a completed rendezvous or an inbound circuit, so that
 * fact is named as missing rather than quietly inferred from the
 * descriptor. It is deliberately NOT part of the conjunction: a leg no
 * observable can ever confirm would be a gate that can never pass.
 *
 * Withholding READY is not a kill. While a leg is unconfirmed the node
 * keeps extending the Type=notify start timeout, exactly like a slow
 * boot step does — a node that is slow to confirm a leg must not be
 * SIGTERMed for being slow, and restarting cannot confirm a leg anyway.
 */
bool boot_ready_legs_all_confirmed(const struct boot_ready_legs *l)
{
    return l && l->descriptor && l->listener && l->pump && l->sweep;
}

unsigned boot_ready_legs_confirmed_count(const struct boot_ready_legs *l)
{
    if (!l)
        return 0;
    return (unsigned)(l->descriptor ? 1 : 0) + (unsigned)(l->listener ? 1 : 0) +
           (unsigned)(l->pump ? 1 : 0) + (unsigned)(l->sweep ? 1 : 0);
}

void boot_ready_legs_describe(const struct boot_ready_legs *l,
                              char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    if (!l) {
        snprintf(out, cap, "legs=unavailable");
        return;
    }
    snprintf(out, cap,
             "descriptor=%s listener=%s pump=%s sweep=%s rendezvous=%s",
             l->descriptor ? "yes" : "no",
             l->listener   ? "yes" : "no",
             l->pump       ? "yes" : "no",
             l->sweep      ? "yes" : "no",
             "unconfirmed");
}

static void boot_sd_watchdog_collect_ready_legs(struct boot_ready_legs *out)
{
    if (!out)
        return;
    struct boot_svc_ctx *svc = g_sd_watchdog_ctx;

    /* Descriptor: onion published, or onion was never asked for. */
    out->descriptor = !boot_sd_watchdog_onion_blocks_ready();

    /* Sweep: the root supervisor is sweeping (or has not swept yet this
     * boot, which is not a wedge). */
    out->sweep = boot_sd_watchdog_supervisor_alive();

    if (!svc || !svc->connman) {
        /* No connman in this process shape (CLI/limited profile): the two
         * network legs are not applicable, and an inapplicable leg must
         * not be an unpassable one. */
        out->listener = true;
        out->pump     = true;
        return;
    }

    /* Listener: a bound P2P socket, or listening was not requested. */
    bool listen_requested = svc->app_ctx ? svc->app_ctx->listen : true;
    out->listener = !listen_requested ||
                    svc->connman->manager.num_listen_sockets > 0;

    /* Pump: BOTH connman loops must have run recently. Unlike the
     * watchdog gate, a connman that was never started does NOT count as
     * fresh here — "the pump never started" is precisely the state this
     * leg exists to refuse. */
    out->pump = svc->connman->started &&
                connman_runtime_progress_fresh(
                    svc->connman, boot_sd_watchdog_freshness_bound_us());
}

/* One hour, same window boot_phase uses for a slow boot step. */
#define BOOT_READY_EXTEND_TIMEOUT_USEC (3600ULL * 1000000ULL)

static void boot_sd_watchdog_maybe_notify_ready(void)
{
    if (atomic_load(&g_notify_ready_sent))
        return;

    struct boot_ready_legs legs = {0};
    boot_sd_watchdog_collect_ready_legs(&legs);
    char desc[192];
    boot_ready_legs_describe(&legs, desc, sizeof(desc));

    if (!boot_ready_legs_all_confirmed(&legs)) {
        char status[256];
        snprintf(status, sizeof(status), "holding READY: %s", desc);
        sd_notify_status(status);

        /* Buy more start budget ONLY when a leg newly confirmed.
         *
         * Extending on every pet period made TimeoutStartSec unreachable:
         * the deadline moved out an hour faster than it could ever
         * arrive, so a leg that would never confirm (a failed bind, a
         * pump that never started) hung the boot forever instead of
         * letting Restart=always retry it — and a restart is frequently
         * the thing that actually clears a stuck descriptor.
         *
         * The high-water mark makes the signal monotonic, so at most one
         * extension is granted per leg (four in a boot's life) and a leg
         * that flaps yes/no/yes cannot buy time by oscillating. Slowness
         * is still generously tolerated: the deadline sits a full
         * BOOT_READY_EXTEND_TIMEOUT_USEC past the last real confirmation,
         * which is an hour to publish a descriptor after everything else
         * is up. */
        static _Atomic unsigned s_best_legs;
        unsigned confirmed = boot_ready_legs_confirmed_count(&legs);
        unsigned prev = atomic_load(&s_best_legs);
        bool new_high = false;
        while (confirmed > prev) {
            /* On failure the CAS reloads `prev` with the current value,
             * so the loop re-tests against whoever raced us. */
            if (atomic_compare_exchange_weak(&s_best_legs, &prev, confirmed)) {
                new_high = true;
                break;
            }
        }
        if (new_high)
            (void)sd_notify_extend_timeout_usec(BOOT_READY_EXTEND_TIMEOUT_USEC);

        /* Log only when the leg set changes, so a long hold costs one
         * line per transition rather than one per pet period. Compared
         * as a hash through one atomic: this runs on both the service
         * start thread and the pet thread. */
        static _Atomic uint32_t s_last_legs_hash;
        uint32_t h = 2166136261u;
        for (const char *p = desc; *p; p++)
            h = (h ^ (uint32_t)(unsigned char)*p) * 16777619u;
        if (atomic_exchange(&s_last_legs_hash, h) != h) {
            printf("[sd-watchdog] holding READY=1: %s\n", desc);
            fflush(stdout);
        }
        return;
    }
    if (!sd_notify_ready())
        return;
    atomic_store(&g_notify_ready_sent, true);
    char status[256];
    snprintf(status, sizeof(status), "zclassic23 started (%s)", desc);
    sd_notify_status(status);
    printf("[sd-watchdog] READY=1 sent: %s\n", desc);
    fflush(stdout);
}

/* Pillar 7: true unless the root supervisor's sweep heartbeat
 * (util/supervisor.h) has gone stale. A heartbeat of 0 means the
 * supervisor hasn't completed its first sweep yet this boot (normal
 * during very early startup, before app_init_services starts it) —
 * that is NOT a wedge, so it does not block the ping. Uses the same
 * freeze threshold as the off-systemd fallback watcher
 * (lib/util/src/supervisor_backstop.c) so the two escalation paths
 * agree on what "frozen" means. */
static bool boot_sd_watchdog_supervisor_alive(void)
{
    uint64_t hb = supervisor_sweep_heartbeat();
    if (hb == 0)
        return true;
    int64_t age_us = platform_time_monotonic_us() - supervisor_sweep_last_us();
    return age_us < SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US;
}

static int64_t boot_sd_watchdog_freshness_bound_us(void)
{
    uint64_t wd_us = sd_notify_watchdog_usec();
    return wd_us > 0 ? (int64_t)wd_us : 120LL * 1000000;
}

/* A healthy sweep alone is insufficient: the sweep intentionally runs apart
 * from child callbacks, the message handler, and the dial scheduler. Gate the
 * keepalive on all three execution pillars so a frozen worker cannot be hidden
 * by an otherwise-live monitoring thread. */
static bool boot_sd_watchdog_runtime_alive(void)
{
    if (!boot_sd_watchdog_supervisor_alive())
        return false;
    int64_t bound_us = boot_sd_watchdog_freshness_bound_us();
    if (supervisor_tick_runner_running() &&
        supervisor_tick_runner_last_hb_age_us() >= bound_us)
        return false;
    return !g_sd_watchdog_ctx ||
           connman_runtime_progress_fresh(g_sd_watchdog_ctx->connman,
                                          bound_us);
}

/* boot_progress freshness, shared by the collect tick (STATUS label) and
 * the pet thread. Snapshot import bulk INSERT, block-by-block catchup, and
 * UTXO replay all take longer than WatchdogSec and would otherwise be
 * killed mid-write, so a recently-bumped boot_progress counts as alive.
 * Freshness window mirrors WATCHDOG_USEC. */
static bool boot_sd_watchdog_recent_progress(void)
{
    int64_t last_us = boot_progress_last_us();
    if (last_us <= 0)
        return false;
    uint64_t wd_us = sd_notify_watchdog_usec();
    int64_t window_us = wd_us > 0 ? (int64_t)wd_us
                                  : (int64_t)(120 * 1000000LL);
    struct timespec now_ts;
    platform_time_monotonic_timespec(&now_ts);
    int64_t now_us = (int64_t)now_ts.tv_sec * 1000000
                   + (int64_t)now_ts.tv_nsec / 1000;
    return now_us - last_us < window_us;
}

/* Pure pet decision — ONE code path for the pet thread and the ZCL_TESTING
 * seam (mirrors supervisor_backstop's backstop_decide factoring). Collection
 * freshness is deliberately absent: node_health_collect may block for minutes
 * on reducer-held locks while every runtime pillar remains live. */
static bool boot_sd_watchdog_pet_decide(bool runtime_gate_alive)
{
    return runtime_gate_alive;
}

/* runtime_alive includes connman. IBD with a peer-floor drop is not a
 * frozen sweep; recent boot_progress keeps the ping in that case. */
static bool boot_sd_watchdog_keepalive_supervisor(bool runtime_alive,
                                                  bool sweep_alive,
                                                  bool recent_progress)
{
    return runtime_alive || (recent_progress && sweep_alive);
}

#ifdef ZCL_TESTING
bool boot_sd_watchdog_test_pet_decide(bool runtime_gate_alive)
{
    return boot_sd_watchdog_pet_decide(runtime_gate_alive);
}

bool boot_sd_watchdog_test_keepalive_supervisor(bool runtime_alive,
                                                bool sweep_alive,
                                                bool recent_progress)
{
    return boot_sd_watchdog_keepalive_supervisor(runtime_alive, sweep_alive,
                                                 recent_progress);
}
#endif

/* PET half. Sleeps in 1 s slices so boot_sd_watchdog_stop's pthread_join
 * never waits a full period. */
static void *boot_sd_watchdog_pet_main(void *arg)
{
    (void)arg;
    uint64_t wd_us = sd_notify_watchdog_usec();
    int64_t bound_us = wd_us > 0 ? (int64_t)wd_us : 120LL * 1000000;
    int64_t period_us = bound_us / 4;
    if (period_us < 5000000)  period_us = 5000000;  /* never DoS systemd */
    if (period_us > 60000000) period_us = 60000000;
    while (!atomic_load(&g_pet_stop) &&
           !thread_registry_shutdown_requested()) {
        bool recent = boot_sd_watchdog_recent_progress();
        bool runtime_gate_alive = boot_sd_watchdog_keepalive_supervisor(
            boot_sd_watchdog_runtime_alive(),
            boot_sd_watchdog_supervisor_alive(),
            recent);
        boot_sd_watchdog_maybe_notify_ready();
        if (boot_sd_watchdog_pet_decide(runtime_gate_alive)) {
            sd_notify_watchdog_ping();
        }
        int64_t left_us = period_us;
        while (left_us > 0 && !atomic_load(&g_pet_stop) &&
               !thread_registry_shutdown_requested()) {
            int64_t slice_us = left_us < 1000000 ? left_us : 1000000;
            struct timespec req = {
                .tv_sec  = (time_t)(slice_us / 1000000),
                .tv_nsec = (long)((slice_us % 1000000) * 1000),
            };
            nanosleep(&req, NULL);
            left_us -= slice_us;
        }
    }
    thread_registry_unregister_self();
    return NULL;
}

/* COLLECT half: refresh the published verdict + STATUS= line. Runs on the
 * shared health ring, so it may lag behind reducer lock contention — by
 * design that lag now degrades only freshness, never the pet cadence. */
static void boot_sd_watchdog_tick(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!sd_notify_is_active() || !svc)
        return;
    struct node_health_snapshot snap = {0};
    node_health_collect(&snap, svc->node_db, svc->state);
    /* Refresh status line — useful for `systemctl status zclassic23`.
     * Include the recent-progress label so operators can see which
     * subsystem is keeping the watchdog alive during bulk ops, and a
     * supervisor=FROZEN marker when Pillar 7's gate is the reason the
     * ping stopped (as opposed to a plain health/progress lapse). */
    bool recent_progress = boot_sd_watchdog_recent_progress();
    bool supervisor_alive = boot_sd_watchdog_runtime_alive();
    char status[320];
    const char *label = recent_progress ? boot_progress_last_label() : NULL;
    snprintf(status, sizeof(status),
             "h=%d peers=%zu mirror_lag=%lld sev=%s%s%s%s",
             snap.tip_height, snap.peer_count,
             (long long)snap.mirror_lag_blocks,
             snap.mirror_lag_breach_severity[0]
                 ? snap.mirror_lag_breach_severity : "none",
             label ? " busy=" : "",
             label ? label : "",
             supervisor_alive ? "" : " supervisor=FROZEN");
    sd_notify_status(status);
}

/* Start the systemd watchdog heartbeat (runtime service kernel entry). */
bool boot_sd_watchdog_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;

    /* NOTE: binary_ab_promote_on_ready_env() deliberately does NOT fire
     * here — sd_watchdog starts 8th of 15 runtime services, so "reached
     * sd_watchdog" is not "booted successfully". The promotion/streak-reset
     * fires at the END of boot_start_runtime_and_catchup()
     * (boot_services.c), after every runtime service, EV_NODE_READY, and
     * the catchup/backfill spin-up. */
    if (!sd_notify_init()) {
        /* Not running under systemd notify supervision (e.g. invoked
         * from a CLI). Silent success — the unit is functionally
         * complete without WatchdogSec. */
        return true;
    }
    g_sd_watchdog_ctx = svc;

    /* Collect/status cadence: half the configured WatchdogSec, clamped to
     * at least 5s. When WATCHDOG_USEC is unset the unit didn't ask for a
     * watchdog — still emit periodic STATUS= lines on a 30s cadence so
     * operators see a live status in `systemctl status`. (The PET cadence
     * is computed independently in boot_sd_watchdog_pet_main.) */
    uint64_t wd_us = sd_notify_watchdog_usec();
    int period_secs;
    if (wd_us > 0) {
        int64_t half = (int64_t)(wd_us / 2 / 1000000);
        if (half < 5) half = 5;
        if (half > 3600) half = 3600;
        period_secs = (int)half;
    } else {
        period_secs = 30;
    }
    g_sd_watchdog_id = health_register_periodic("sd_watchdog", period_secs,
                                                boot_sd_watchdog_tick, svc);
    if (g_sd_watchdog_id == HEALTH_INVALID_ID)
        return false;
    /* Defense-in-depth: sd_notify_watchdog_ping() itself now refuses to
     * send WATCHDOG=1 whenever the root supervisor sweep is stale, even
     * if some future call site forgets the explicit check above. */
    sd_notify_set_health_check(boot_sd_watchdog_runtime_alive);
    atomic_store(&g_notify_ready_sent, false);
    /* Composed readiness: the call names every unconfirmed leg in the
     * status line and in node.log, and holds READY until all of them are
     * confirmed on their own evidence. */
    boot_sd_watchdog_maybe_notify_ready();

    /* Pet half: dedicated thread — see the heartbeat section header for why
     * it must not ride the health ring. */
    atomic_store(&g_pet_stop, false);
    // thread-supervision-ok:pets-systemd-from-atomics-only-a-supervised-child-could-be-starved-by-the-ring-contention-this-thread-exists-to-survive
    if (thread_registry_spawn("zcl_sd_watchdog_pet",
                              boot_sd_watchdog_pet_main, NULL,
                              &g_pet_tid) != 0) {
        /* No pet thread = no heartbeat once boot progress goes quiet. Fail
         * the service start: under WatchdogSec a silently un-petted unit is
         * a kill loop waiting for the first long collect stall. */
        LOG_FAIL("sd_watchdog", "pet thread spawn failed");
        return false;
    }
    atomic_store(&g_pet_handle_set, true);
    printf("[sd-watchdog] active, collect_period=%ds WATCHDOG_USEC=%llu\n",
           period_secs, (unsigned long long)wd_us);
    return true;
}

/* Stop the systemd watchdog heartbeat (runtime service kernel entry). */
void boot_sd_watchdog_stop(void *ctx)
{
    (void)ctx;
    atomic_store(&g_pet_stop, true);
    if (atomic_load(&g_pet_handle_set)) {
        pthread_join(g_pet_tid, NULL);
        atomic_store(&g_pet_handle_set, false);
    }
    if (g_sd_watchdog_id != HEALTH_INVALID_ID) {
        health_unregister(g_sd_watchdog_id);
        g_sd_watchdog_id = HEALTH_INVALID_ID;
    }
    if (sd_notify_is_active())
        sd_notify_stopping("shutdown");
    sd_notify_set_health_check(NULL);
    g_sd_watchdog_ctx = NULL;
}
