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
 * platform/modules/util/src/supervisor_backstop.c.
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
#include "util/thread_work_probe.h"
#include "net/tor_integration.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── systemd watchdog heartbeat ─────────────────────────────────
 * Two halves, deliberately on different threads:
 *
 *   1. COLLECT tick (engine/modules/health periodic ring): runs node_health_collect,
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
 * (platform/modules/util/src/supervisor_backstop.c) so the two escalation paths
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

static bool boot_sd_watchdog_runtime_pillars(bool sweep_alive,
                                             bool tick_alive,
                                             bool connman_alive)
{
    return sweep_alive && tick_alive && connman_alive;
}

/* ── What a runtime pillar is allowed to measure ─────────────────────────
 *
 * Every pillar below used to be one question: "did this loop get back to the
 * top of itself within WATCHDOG_USEC?" That question is not about the loop. It
 * is about how much work the loop was handed and how fast the machine
 * underneath it runs, and it graded honest nodes dead for the wrong reasons:
 *
 *   - The DIAL SCHEDULER. One pass of thread_open_connections() is permitted
 *     by its own code to block for DEFAULT_CONNECT_TIMEOUT on the clearnet
 *     race and then a whole ONION_STREAM_CONNECT_TIMEOUT_MS budget per onion
 *     candidate, with one retry on a FRESH budget after a torn-down circuit.
 *     That permitted budget is larger than the entire watchdog window, so on
 *     any node dialing a slow or dead hidden service the marker goes stale by
 *     construction while the thread is doing exactly what it was told to do.
 *     Observed on the development fleet: five-minute gaps between passes,
 *     every one of them ending in a successful dial.
 *
 *   - The MESSAGE PUMP. A cycle serves whatever the connected peers asked
 *     for. On a rotating disk one run of getblock takes longer than the
 *     window; on an SSD it does not. Same node, same code, opposite verdict.
 *
 *   - The TICK RUNNER. run_due_ticks() is serial, so the heartbeat freezes
 *     for as long as the slowest child's on_tick takes — again a disk-speed
 *     measurement, not a wedge.
 *
 * The fix is not a bigger number; a bigger number is the same defect further
 * away. The gate asks whether the kernel reports completed work on the thread,
 * or whether the thread explicitly entered an operation-specific bounded wait.
 * CPU time, major faults and block-I/O bytes cover computing, paging and
 * completed device work. A deadline-bound wait lease covers the intentional
 * interval where a socket poll or device request may complete none of those.
 * Once that declared deadline passes, silence is dead again. See
 * util/thread_work_probe.h.
 *
 * So each pillar is now `marker fresh OR that thread is working OR an explicit
 * bounded wait is still within its deadline`. What this cannot see is a thread
 * spinning in a livelock: it burns CPU and reads as working. That is a
 * different failure with a different detector (the supervisor tree's
 * NO_PROGRESS contracts) and must never be claimed as covered here. */
static bool boot_sd_watchdog_pillar_alive(bool marker_fresh,
                                          bool thread_working,
                                          bool bounded_wait_active)
{
    return marker_fresh || thread_working || bounded_wait_active;
}

/* Both connman loops must be alive. The conjunction is safe now that each
 * term is a liveness observation rather than an activity one: before this,
 * ANDing two "did the loop come round" markers meant either loop blocking on
 * its own honest budget killed the process. */
static bool boot_sd_watchdog_connman_alive(bool msg_marker_fresh,
                                           bool msg_working,
                                           bool dial_marker_fresh,
                                           bool dial_working,
                                           bool dial_bounded_wait_active)
{
    return boot_sd_watchdog_pillar_alive(msg_marker_fresh, msg_working,
                                         false) &&
           boot_sd_watchdog_pillar_alive(dial_marker_fresh, dial_working,
                                         dial_bounded_wait_active);
}

/* One work-probe slot per gated thread. Touched only by the pet thread. */
struct wd_work_slot {
    long                      tid;
    struct thread_work_sample prev;
    bool                      have_prev;
};
static struct wd_work_slot g_work_tick;
static struct wd_work_slot g_work_msg;
static struct wd_work_slot g_work_dial;

/* Did the kernel do work on `tid` since the previous pet period? A tid we
 * cannot read — no such thread yet, a non-Linux host, a sandbox that denies
 * /proc — reports NOT working, so the gate falls back to the marker alone
 * exactly as it behaved before this probe existed. Unobservable is never
 * evidence of life. */
static bool boot_sd_watchdog_thread_working(struct wd_work_slot *slot, long tid)
{
    struct thread_work_sample now;
    if (!slot)
        return false;
    if (!thread_work_probe_sample(tid, &now)) {
        slot->have_prev = false;
        return false;
    }
    bool advanced = slot->have_prev && slot->tid == tid &&
                    thread_work_probe_advanced(&slot->prev, &now);
    slot->tid       = tid;
    slot->prev      = now;
    slot->have_prev = true;
    return advanced;
}

/* A healthy sweep alone is insufficient: the sweep intentionally runs apart
 * from child callbacks, the message handler, and the dial scheduler. Gate the
 * keepalive on all three execution pillars so a frozen worker cannot be hidden
 * by an otherwise-live monitoring thread.
 *
 * Sampling happens on every pet period, not only when a marker is stale, so
 * the "since last period" comparison is always over one period. It is four
 * reads of kernel-generated pseudo-files per period; they take no node lock
 * and issue no block-device I/O, so they cannot be delayed by the storage
 * whose slowness this whole function exists to stop mistaking for death. */
static bool boot_sd_watchdog_runtime_alive(void)
{
    int64_t bound_us = boot_sd_watchdog_freshness_bound_us();
    int64_t now_us   = platform_time_monotonic_us();

    /* run_due_ticks() is serial. A permanently wedged callback starves every
     * later periodic callback, so the runner remains a runtime pillar. */
    bool tick_running = supervisor_tick_runner_running();
    bool tick_working = boot_sd_watchdog_thread_working(
        &g_work_tick, supervisor_tick_runner_tid());
    bool tick_alive = !tick_running ||
                      boot_sd_watchdog_pillar_alive(
                          supervisor_tick_runner_last_hb_age_us() < bound_us,
                          tick_working, false);

    struct connman_loop_liveness ll;
    connman_observe_loop_liveness(
        g_sd_watchdog_ctx ? g_sd_watchdog_ctx->connman : NULL, &ll);
    bool msg_working  = boot_sd_watchdog_thread_working(&g_work_msg,
                                                        ll.message_tid);
    bool dial_working = boot_sd_watchdog_thread_working(&g_work_dial,
                                                        ll.dial_tid);
    bool msg_fresh  = ll.message_last_progress_us > 0 &&
                      now_us - ll.message_last_progress_us >= 0 &&
                      now_us - ll.message_last_progress_us < bound_us;
    bool dial_fresh = ll.dial_last_progress_us > 0 &&
                      now_us - ll.dial_last_progress_us >= 0 &&
                      now_us - ll.dial_last_progress_us < bound_us;
    bool dial_wait_active = ll.dial_bounded_wait_until_us > now_us;
    /* A connman that has not started yet is not a wedge — the same carve-out
     * connman_runtime_progress_fresh() makes for its own callers. */
    bool connman_alive = !ll.started || boot_sd_watchdog_connman_alive(
        msg_fresh, msg_working, dial_fresh, dial_working, dial_wait_active);
    return boot_sd_watchdog_runtime_pillars(
        boot_sd_watchdog_supervisor_alive(), tick_alive, connman_alive);
}

/* Name every pillar for the withhold/resume log line. Withholding the ping
 * asks systemd to SIGABRT this process; an operator reading the journal must
 * be told WHICH leg refused, not just that one did. */
static void boot_sd_watchdog_describe_pillars(char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    int64_t bound_us = boot_sd_watchdog_freshness_bound_us();
    int64_t now_us   = platform_time_monotonic_us();
    struct connman_loop_liveness ll;
    connman_observe_loop_liveness(
        g_sd_watchdog_ctx ? g_sd_watchdog_ctx->connman : NULL, &ll);
    int64_t msg_age  = ll.message_last_progress_us > 0
                           ? now_us - ll.message_last_progress_us : -1;
    int64_t dial_age = ll.dial_last_progress_us > 0
                           ? now_us - ll.dial_last_progress_us : -1;
    snprintf(out, cap,
             "sweep=%d tick_running=%d tick_hb_age_us=%lld "
             "connman_started=%d msg_age_us=%lld dial_age_us=%lld "
             "dial_wait_until_us=%lld bound_us=%lld work_probe=%d",
             (int)boot_sd_watchdog_supervisor_alive(),
             (int)supervisor_tick_runner_running(),
             (long long)supervisor_tick_runner_last_hb_age_us(),
             (int)ll.started, (long long)msg_age, (long long)dial_age,
             (long long)ll.dial_bounded_wait_until_us,
             (long long)bound_us, (int)thread_work_probe_supported());
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

bool boot_sd_watchdog_test_runtime_pillars(bool sweep_alive,
                                           bool tick_alive,
                                           bool connman_alive)
{
    return boot_sd_watchdog_runtime_pillars(sweep_alive, tick_alive,
                                            connman_alive);
}

bool boot_sd_watchdog_test_pillar_alive(bool marker_fresh, bool thread_working,
                                        bool bounded_wait_active)
{
    return boot_sd_watchdog_pillar_alive(marker_fresh, thread_working,
                                         bounded_wait_active);
}

bool boot_sd_watchdog_test_connman_alive(bool msg_marker_fresh,
                                         bool msg_working,
                                         bool dial_marker_fresh,
                                         bool dial_working,
                                         bool dial_bounded_wait_active)
{
    return boot_sd_watchdog_connman_alive(msg_marker_fresh, msg_working,
                                          dial_marker_fresh, dial_working,
                                          dial_bounded_wait_active);
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
        bool pet = boot_sd_watchdog_pet_decide(runtime_gate_alive);
        /* Say it out loud, on the edge only. Withholding the ping asks
         * systemd to SIGABRT this process WatchdogSec later, and until now it
         * happened in total silence: the only trace was `status=134` in the
         * journal, with nothing anywhere naming which leg refused. Diagnosing
         * one instance cost hours of archive archaeology that a single line
         * here would have answered. Edge-triggered, so a long refusal logs
         * once, not once per period. */
        static bool s_last_pet = true;
        if (pet != s_last_pet) {
            /* `runtime=0` alone cost hours of archaeology: it names the
             * conjunction, not the term. Print every pillar's raw observation
             * so the journal answers "which leg refused, and by how much"
             * without a rebuild. */
            char pillars[256];
            boot_sd_watchdog_describe_pillars(pillars, sizeof(pillars));
            if (pet) {
                LOG_INFO("boot",
                         "[sd_watchdog] pinging again: recent_progress=%d %s",
                         (int)recent, pillars);
            } else {
                LOG_WARN("boot",
                         "[sd_watchdog] WITHHOLDING the watchdog ping — "
                         "systemd will kill this process unless it resumes: "
                         "recent_progress=%d %s",
                         (int)recent, pillars);
            }
            s_last_pet = pet;
        }
        if (pet) {
            int64_t send_start_us = platform_time_monotonic_us();
            sd_notify_watchdog_ping();
            int64_t send_us = platform_time_monotonic_us() - send_start_us;
            /* The pet thread has one blocking call: sd_send() inside
             * sd_notify_watchdog_ping(). A slow-but-not-yet-full systemd
             * receiver can make it take real time even after it stops
             * hanging outright (sd_notify.c's non-blocking socket now
             * bounds the worst case, but a receiver right at the edge is
             * still worth naming before the next stall repeats it). */
            if (send_us > period_us / 2) {
                LOG_WARN("boot",
                         "[sd_watchdog] notify send took %lld ms",
                         (long long)(send_us / 1000));
            }
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
    /* Defense-in-depth: sd_notify_watchdog_ping() itself refuses to send
     * WATCHDOG=1 whenever the root supervisor sweep is stale, even if some
     * future call site forgets the explicit check above.
     *
     * It registers the SWEEP check, which is what the guarantee in this
     * file's header is about, and NOT boot_sd_watchdog_runtime_alive. That
     * distinction is load-bearing. The pet's policy is the disjunction
     * boot_sd_watchdog_keepalive_supervisor computes — runtime_alive OR
     * (recent_progress AND sweep_alive) — whose second half exists so that a
     * snapshot import, a block-by-block catchup or a UTXO replay is not
     * killed mid-write. Registering runtime_alive here made the effective
     * gate `A || B` on the outside and `A` on the inside, which is `A`: the
     * carve-out could never fire, and a node writing at full rate was killed
     * anyway. A backstop must be WEAKER than the policy it backs, or it
     * silently replaces it. */
    sd_notify_set_health_check(boot_sd_watchdog_supervisor_alive);
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
