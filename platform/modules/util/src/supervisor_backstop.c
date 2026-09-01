/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * supervisor_backstop — implementation. See util/supervisor_backstop.h for
 * design notes. */
#define _GNU_SOURCE  /* thread_registry_spawn / pthread_setname_np internals */

#include "platform/time_compat.h"
#include "util/supervisor_backstop.h"
#include "util/supervisor.h"
#include "util/boot_phase.h"
#include "util/thread_registry.h"
#include "util/sd_notify.h"
#include "util/log_macros.h"
#include "json/json.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

static _Atomic bool    g_running             = false;
static _Atomic bool    g_stop_requested      = false;
static pthread_t       g_thread_id;
static _Atomic bool    g_thread_handle_set   = false;

static _Atomic int64_t g_poll_interval_us    = SUPERVISOR_BACKSTOP_DEFAULT_POLL_US;
static _Atomic int64_t g_freeze_threshold_us = SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US;

/* #Pillar-7 — latched exactly like chain_tip_watchdog's g_respawn_requested
 * (services/chain_tip_watchdog.h): set only when a freeze was declared while
 * NOT under systemd notify supervision. main() polls this alongside the
 * tip-watchdog's flag after app_shutdown() and re-execs when either is set. */
static _Atomic bool    g_respawn_requested   = false;

#ifdef ZCL_TESTING
static _Atomic bool g_force_off_systemd      = false;
static _Atomic bool g_force_off_systemd_set  = false;
static _Atomic int  g_force_boot_stage       = 0;
static _Atomic bool g_force_boot_stage_set   = false;
#endif

static bool backstop_off_systemd(void)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_force_off_systemd_set))
        return atomic_load(&g_force_off_systemd);
#endif
    return !sd_notify_is_active();
}

/* Current boot stage as an int, with a test override so a hermetic test
 * can pin it. Production always reads the real boot_stage_current(). */
static int backstop_boot_stage(void)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_force_boot_stage_set))
        return atomic_load(&g_force_boot_stage);
#endif
    return (int)boot_stage_current();
}

/* Pure decision, shared by the production poll loop and the ZCL_TESTING
 * seam — ONE code path, mirroring chain_tip_watchdog's wd_apply_tick
 * factoring. Edge-triggered: fires exactly once per freeze episode. */
static bool backstop_decide(struct supervisor_backstop_state *st,
                            uint64_t heartbeat, int64_t now_us,
                            int64_t freeze_threshold_us)
{
    if (!st->initialized) {
        st->initialized    = true;
        st->last_heartbeat = heartbeat;
        st->last_change_us = now_us;
        st->already_fired  = false;
        return false;
    }
    if (heartbeat != st->last_heartbeat) {
        st->last_heartbeat = heartbeat;
        st->last_change_us = now_us;
        st->already_fired  = false;   /* re-arm: the sweep is moving again */
        return false;
    }
    if (st->already_fired)
        return false;                /* don't re-declare every poll */
    if (freeze_threshold_us <= 0)
        return false;
    if (now_us - st->last_change_us < freeze_threshold_us)
        return false;
    st->already_fired = true;
    return true;
}

/* Boot-stage-aware wrapper around backstop_decide — the ONE decision the
 * production poll loop and the ZCL_TESTING seam both make. Two changes
 * versus the bare heartbeat check:
 *
 *   1. Liveness = sweep_hb + boot_progress. EITHER the supervisor sweep
 *      advancing OR a boot loop pumping boot_progress_note() re-arms the
 *      freeze episode. During serving, boot_progress is static (no boot
 *      loop runs), so the sweep heartbeat is the sole signal and a frozen
 *      sweep still fires — the serving invariant is untouched.
 *
 *   2. Budget scales UP (never down) to SUPERVISOR_BACKSTOP_BOOT_FREEZE_US
 *      while in a pre-serving boot stage, so a long single-threaded boot
 *      stage that hasn't started the sweep yet is not mistaken for a hang.
 *
 * `out_budget_us` (optional) receives the effective budget used, for the
 * caller's diagnostic message. */
static bool backstop_decide_staged(struct supervisor_backstop_state *st,
                                   uint64_t sweep_hb, uint64_t boot_progress,
                                   int boot_stage, int64_t now_us,
                                   int64_t serving_threshold_us,
                                   int64_t *out_budget_us)
{
    uint64_t liveness = sweep_hb + boot_progress;

    int64_t budget = serving_threshold_us;
    if (serving_threshold_us > 0 &&
        boot_stage >= 0 && boot_stage < BOOT_STAGE_SERVICES_RUNNING &&
        SUPERVISOR_BACKSTOP_BOOT_FREEZE_US > budget)
        budget = SUPERVISOR_BACKSTOP_BOOT_FREEZE_US;

    if (out_budget_us)
        *out_budget_us = budget;
    return backstop_decide(st, liveness, now_us, budget);
}

/* A freeze declaration requires a continuous series of watcher observations.
 * CLOCK_MONOTONIC advances while a process is SIGSTOPed or a host is
 * suspended, but the watcher cannot establish which thread was healthy over
 * that unobserved interval. Rebase instead of converting an observation gap
 * into evidence against the supervisor. Genuine supervisor wedges remain
 * bounded because this watcher continues polling throughout them. */
static bool backstop_observation_gap(int64_t previous_poll_us,
                                     int64_t now_us,
                                     int64_t freeze_threshold_us)
{
    return previous_poll_us > 0 && now_us > previous_poll_us &&
           freeze_threshold_us > 0 &&
           now_us - previous_poll_us >= freeze_threshold_us;
}

#ifdef ZCL_TESTING
bool supervisor_backstop_test_check(struct supervisor_backstop_state *state,
                                    uint64_t heartbeat, int64_t now_us,
                                    int64_t freeze_threshold_us)
{
    return backstop_decide(state, heartbeat, now_us, freeze_threshold_us);
}

bool supervisor_backstop_test_check_staged(
    struct supervisor_backstop_state *state,
    uint64_t sweep_hb, uint64_t boot_progress, int boot_stage,
    int64_t now_us, int64_t serving_threshold_us)
{
    return backstop_decide_staged(state, sweep_hb, boot_progress, boot_stage,
                                  now_us, serving_threshold_us, NULL);
}

bool supervisor_backstop_test_observation_gap(
    int64_t previous_poll_us, int64_t now_us, int64_t freeze_threshold_us)
{
    return backstop_observation_gap(previous_poll_us, now_us,
                                    freeze_threshold_us);
}

void supervisor_backstop_test_force_boot_stage(int boot_stage)
{
    atomic_store(&g_force_boot_stage, boot_stage);
    atomic_store(&g_force_boot_stage_set, true);
}

void supervisor_backstop_test_reset(void)
{
    atomic_store(&g_respawn_requested, false);
    atomic_store(&g_force_off_systemd, false);
    atomic_store(&g_force_off_systemd_set, false);
    atomic_store(&g_force_boot_stage, 0);
    atomic_store(&g_force_boot_stage_set, false);
}

void supervisor_backstop_test_force_off_systemd(bool off_systemd)
{
    atomic_store(&g_force_off_systemd, off_systemd);
    atomic_store(&g_force_off_systemd_set, true);
}

void supervisor_backstop_test_poll(struct supervisor_backstop_state *state,
                                  int64_t now_us, int64_t freeze_threshold_us)
{
    uint64_t hb   = supervisor_sweep_heartbeat();
    uint64_t bp   = boot_progress_marker();
    int      stg  = backstop_boot_stage();
    if (backstop_decide_staged(state, hb, bp, stg, now_us,
                               freeze_threshold_us, NULL)) {
        if (backstop_off_systemd())
            atomic_store(&g_respawn_requested, true);
    }
}
#endif

static void *backstop_thread_main(void *arg)
{
    (void)arg;
    struct supervisor_backstop_state st;
    st.initialized = false;
    st.already_fired = false;
    st.last_heartbeat = 0;
    st.last_change_us = 0;
    int64_t last_poll_us = 0;

    while (!atomic_load(&g_stop_requested) &&
           !thread_registry_shutdown_requested()) {
        uint64_t hb        = supervisor_sweep_heartbeat();
        uint64_t bp        = boot_progress_marker();
        int      stg       = backstop_boot_stage();
        int64_t  now       = platform_time_monotonic_us();
        int64_t  freeze_us = atomic_load(&g_freeze_threshold_us);
        int64_t  budget_us = freeze_us;

        if (backstop_observation_gap(last_poll_us, now, freeze_us)) {
            /* The whole process (including this watcher) was unobserved for
             * a complete serving budget. Seed a fresh episode from the
             * current facts; never turn SIGSTOP or host suspend into a
             * supervisor-failure assertion. */
            st.initialized = false;
        }
        last_poll_us = now;

        if (backstop_decide_staged(&st, hb, bp, stg, now, freeze_us,
                                   &budget_us)) {
            fprintf(stderr,  // obs-ok:supervisor-backstop-fatal-notice
                "[supervisor-backstop] FATAL supervisor sweep frozen for "
                ">=%llds (heartbeat=%llu boot_progress=%llu stage=%s) -- root "
                "liveness thread is dead or wedged inside a child callback\n",
                (long long)(budget_us / 1000000), (unsigned long long)hb,
                (unsigned long long)bp, boot_stage_name((enum boot_stage)stg));
            LOG_WARN("supervisor_backstop", "[supervisor_backstop] sweep heartbeat frozen >=%llds at count=%llu (boot_progress=%llu stage=%s)", (long long)(budget_us / 1000000), (unsigned long long)hb, (unsigned long long)bp, boot_stage_name((enum boot_stage)stg));
            if (backstop_off_systemd()) {
                atomic_store(&g_respawn_requested, true);
                fprintf(stderr,  // obs-ok:supervisor-backstop-respawn-notice
                    "[supervisor-backstop] no systemd notify socket -- "
                    "requesting orderly shutdown + in-process self-respawn\n");
                thread_registry_request_shutdown();
            } else {
                fprintf(stderr,  // obs-ok:supervisor-backstop-systemd-notice
                    "[supervisor-backstop] systemd notify socket present -- "
                    "boot_sd_watchdog already stopped pinging WATCHDOG=1; "
                    "systemd's own restart recovers the unit\n");
            }
        }

        int64_t poll_us = atomic_load(&g_poll_interval_us);
        if (poll_us < 100000) poll_us = 100000;   /* floor: never busy-spin */
        struct timespec req = {
            .tv_sec  = (time_t)(poll_us / 1000000),
            .tv_nsec = (long)((poll_us % 1000000) * 1000)
        };
        nanosleep(&req, NULL);
    }
    thread_registry_unregister_self();
    return NULL;
}

bool supervisor_backstop_start(int64_t poll_interval_us,
                               int64_t freeze_threshold_us)
{
    bool was = atomic_exchange(&g_running, true);
    if (was) return true;   /* idempotent */
    atomic_store(&g_stop_requested, false);
    atomic_store(&g_poll_interval_us,
        poll_interval_us > 0 ? poll_interval_us
                             : (int64_t)SUPERVISOR_BACKSTOP_DEFAULT_POLL_US);
    atomic_store(&g_freeze_threshold_us,
        freeze_threshold_us > 0 ? freeze_threshold_us
                                : (int64_t)SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US);

    pthread_t tid;
    /* This thread's entire job is detecting a dead/wedged zcl_supervisor
     * sweep, so it cannot be registered ON the tree it watches — a wedged
     * supervisor could never notice its own watcher going quiet either.
     * See the header doc comment for the full design rationale. */
    // thread-supervision-ok:watches-the-supervisor-itself-cannot-be-supervised-by-it
    int rc = thread_registry_spawn("zcl_supervisor_backstop",
                                   backstop_thread_main, NULL, &tid);
    if (rc != 0) {
        atomic_store(&g_running, false);
        LOG_FAIL("supervisor_backstop", "thread_registry_spawn rc=%d", rc);
    }
    g_thread_id = tid;
    atomic_store(&g_thread_handle_set, true);
    return true;
}

void supervisor_backstop_stop(void)
{
    if (!atomic_load(&g_running)) return;
    atomic_store(&g_stop_requested, true);
    atomic_store(&g_running, false);
    if (atomic_load(&g_thread_handle_set)) {
        pthread_join(g_thread_id, NULL);
        atomic_store(&g_thread_handle_set, false);
    }
}

bool supervisor_backstop_respawn_requested(void)
{
    return atomic_load(&g_respawn_requested);
}

bool supervisor_backstop_dump_state_json(struct json_value *out,
                                         const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    json_push_kv_bool(out, "running", atomic_load(&g_running));
    json_push_kv_int (out, "poll_interval_us",
                      atomic_load(&g_poll_interval_us));
    json_push_kv_int (out, "freeze_threshold_us",
                      atomic_load(&g_freeze_threshold_us));
    json_push_kv_bool(out, "respawn_requested",
                      atomic_load(&g_respawn_requested));
    json_push_kv_int (out, "sweep_heartbeat",
                      (int64_t)supervisor_sweep_heartbeat());
    json_push_kv_int (out, "sweep_last_age_us",
                      platform_time_monotonic_us() - supervisor_sweep_last_us());
    /* Boot-stage-aware liveness inputs: during a pre-serving boot stage
     * boot_progress feeds the freeze episode alongside the sweep, and the
     * effective budget is the generous boot value, not the 30 s bar. */
    int stg = (int)boot_stage_current();
    json_push_kv_int (out, "boot_progress",
                      (int64_t)boot_progress_marker());
    json_push_kv_str (out, "boot_stage", boot_stage_name((enum boot_stage)stg));
    json_push_kv_int (out, "effective_freeze_threshold_us",
                      (stg >= 0 && stg < BOOT_STAGE_SERVICES_RUNNING &&
                       SUPERVISOR_BACKSTOP_BOOT_FREEZE_US >
                           atomic_load(&g_freeze_threshold_us))
                          ? (int64_t)SUPERVISOR_BACKSTOP_BOOT_FREEZE_US
                          : atomic_load(&g_freeze_threshold_us));
    return true;
}
