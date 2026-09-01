/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Heartbeat ring + single sweeper thread. See heartbeat.h for the
 * design rationale and edge-triggered stall semantics.
 */

#include "health/heartbeat.h"
#include "core/utiltime.h"
#include "json/json.h"
#include "platform/os_sandbox.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include "util/time_authority.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct entry {
    bool             active;
    bool             periodic;            /* true → tick on cadence, ignore heartbeats */
    char             name[HEALTH_NAME_MAX];
    int64_t          deadline_secs;       /* stall: max gap. periodic: tick period. */
    void           (*on_stall)(void *);   /* also used as the periodic tick cb */
    void            *ctx;
    _Atomic int64_t  last_beat_us;        /* stall: last heartbeat. periodic: last fire. */
    int64_t          last_stall_beat_us;  /* beat-timestamp the last
                                            * stall fired against; used to
                                            * edge-trigger (don't refire
                                            * unless a fresh heartbeat
                                            * arrived since). Unused for
                                            * periodic. */
    int              on_stall_fired;
};

static struct entry    g_entries[HEALTH_REGISTRY_CAP];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static _Atomic bool    g_running = false;
static _Atomic bool    g_started = false;
static _Atomic int     g_check_interval_ms = 1000;

/* Supervisor liveness: the sweeper is the very thread a silent
 * wedge here would leave undetected without a supervisor. It heartbeats onto the
 * tree so a wedge is a named blocker, not a silent stop. deadline=120 s
 * (interval defaults to 1 s; retunable, but far under the deadline);
 * progress marker = sweep count; no-progress gate disabled (the deadline
 * already covers a frozen loop). */
static struct thread_liveness_child g_sweep_child = {
    .id = SUPERVISOR_INVALID_ID
};
static _Atomic uint64_t g_sweep_count = 0;

void health_set_check_interval_ms(int ms)
{
    if (ms < 1) ms = 1;
    atomic_store(&g_check_interval_ms, ms);
}

/* Shared slot find + init for both register entry points. The two
 * public callers differ only in the `periodic` flag and the registry-
 * full error string (which branches on `periodic`); everything else —
 * the NULL/period guard, the now_us capture, the slot-find loop, and
 * the full field init — is identical. */
static health_subsystem_id slot_alloc_and_fill(const char *name,
                                               int64_t period_secs,
                                               void (*cb)(void *),
                                               void *ctx,
                                               bool periodic)
{
    if (!name || !cb || period_secs <= 0)
        return HEALTH_INVALID_ID;

    int64_t now_us = GetTimeMicros();

    pthread_mutex_lock(&g_mu);
    int slot = -1;
    for (int i = 0; i < HEALTH_REGISTRY_CAP; i++) {
        if (!g_entries[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_mu);
        if (periodic)
            fprintf(stderr, "[health] registry full (cap=%d), cannot register periodic '%s'\n",
                    HEALTH_REGISTRY_CAP, name);
        else
            fprintf(stderr, "[health] registry full (cap=%d), cannot register '%s'\n",
                    HEALTH_REGISTRY_CAP, name);
        return HEALTH_INVALID_ID; // obs-ok:health-registry-full-sentinel-return
    }

    g_entries[slot].active = true;
    g_entries[slot].periodic = periodic;
    strncpy(g_entries[slot].name, name, HEALTH_NAME_MAX - 1);
    g_entries[slot].name[HEALTH_NAME_MAX - 1] = '\0';
    g_entries[slot].deadline_secs = period_secs;
    g_entries[slot].on_stall = cb;
    g_entries[slot].ctx = ctx;
    /* For periodic, last_beat_us tracks "last fire"; seeding to now
     * means the first fire happens `period_secs` from registration,
     * not immediately. For stall entries it tracks the last heartbeat. */
    atomic_store(&g_entries[slot].last_beat_us, now_us);
    /* Sentinel: NEVER seed last_stall_beat_us == last_beat_us, because
     * the edge-trigger check skips when they're equal (treating it as
     * "already fired against this beat"). 0 means "no stall ever fired
     * against this entry"; the first missed-deadline sweep will fire.
     * Unused for periodic. */
    g_entries[slot].last_stall_beat_us = 0;
    g_entries[slot].on_stall_fired = 0;
    pthread_mutex_unlock(&g_mu);

    return slot;
}

health_subsystem_id health_register(const char *name,
                                     int64_t deadline_secs,
                                     void (*on_stall)(void *),
                                     void *ctx)
{
    return slot_alloc_and_fill(name, deadline_secs, on_stall, ctx, false);
}

health_subsystem_id health_register_periodic(const char *name,
                                              int64_t period_secs,
                                              void (*cb)(void *),
                                              void *ctx)
{
    return slot_alloc_and_fill(name, period_secs, cb, ctx, true);
}

void health_heartbeat(health_subsystem_id id)
{
    if (id < 0 || id >= HEALTH_REGISTRY_CAP) return;
    if (!g_entries[id].active) return;
    if (g_entries[id].periodic) return;  /* no-op for periodic ticks */
    atomic_store(&g_entries[id].last_beat_us, GetTimeMicros());
}

void health_unregister(health_subsystem_id id)
{
    if (id < 0 || id >= HEALTH_REGISTRY_CAP) return;
    pthread_mutex_lock(&g_mu);
    g_entries[id].active = false;
    pthread_mutex_unlock(&g_mu);
}

int health_snapshot_all(struct health_snapshot *out, int max)
{
    if (!out || max <= 0) return 0;
    int64_t now_us = GetTimeMicros();
    int n = 0;

    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < HEALTH_REGISTRY_CAP && n < max; i++) {
        if (!g_entries[i].active) continue;
        int64_t beat_us = atomic_load(&g_entries[i].last_beat_us);
        int64_t age_us  = now_us - beat_us;
        strncpy(out[n].name, g_entries[i].name, HEALTH_NAME_MAX);
        out[n].name[HEALTH_NAME_MAX - 1] = '\0';
        out[n].deadline_secs = g_entries[i].deadline_secs;
        out[n].last_beat_age_secs = age_us / 1000000;
        out[n].on_stall_fired = g_entries[i].on_stall_fired;
        out[n].periodic = g_entries[i].periodic;
        out[n].currently_stalled = !g_entries[i].periodic &&
            ((age_us / 1000000) > g_entries[i].deadline_secs);
        n++;
    }
    pthread_mutex_unlock(&g_mu);
    return n;
}

static void sweep_once(void)
{
    int64_t now_us = GetTimeMicros();

    /* Snapshot the entries we need to fire on, OUTSIDE the lock.
     * Calling on_stall() while holding g_mu would deadlock the
     * callback if it touches the ring (e.g. heartbeats a sibling).
     * Collect fire candidates first, then release the lock and
     * invoke. */
    struct {
        void (*fn)(void *);
        void  *ctx;
        int    slot;
        int64_t beat_us;
    } fires[HEALTH_REGISTRY_CAP];
    int nfires = 0;

    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < HEALTH_REGISTRY_CAP; i++) {
        if (!g_entries[i].active) continue;
        int64_t beat_us = atomic_load(&g_entries[i].last_beat_us);
        int64_t age_us  = now_us - beat_us;
        int64_t threshold_us = g_entries[i].deadline_secs * (int64_t)1000000;
        if (age_us < threshold_us) continue;

        if (g_entries[i].periodic) {
            /* Periodic tick: fire on every sweep where age >= period.
             * Advance last_beat_us to now so the next fire is
             * period_secs from this moment. */
            atomic_store(&g_entries[i].last_beat_us, now_us);
            g_entries[i].on_stall_fired++;
            fires[nfires].fn = g_entries[i].on_stall;
            fires[nfires].ctx = g_entries[i].ctx;
            fires[nfires].slot = i;
            fires[nfires].beat_us = now_us;
            nfires++;
        } else {
            /* Stall edge-trigger: only fire if beat_us has advanced
             * since the last firing, OR this is the first stall ever
             * for this entry (last_stall_beat_us == 0). */
            if (beat_us == g_entries[i].last_stall_beat_us) {
                /* Already fired against this beat-timestamp. Skip. */
                continue;
            }
            g_entries[i].last_stall_beat_us = beat_us;
            g_entries[i].on_stall_fired++;
            fires[nfires].fn = g_entries[i].on_stall;
            fires[nfires].ctx = g_entries[i].ctx;
            fires[nfires].slot = i;
            fires[nfires].beat_us = beat_us;
            nfires++;
        }
    }
    pthread_mutex_unlock(&g_mu);

    for (int k = 0; k < nfires; k++) {
        fires[k].fn(fires[k].ctx);
    }
}

static void *sweeper_thread(void *arg)
{
    (void)arg;
    while (atomic_load(&g_running)) {
        /* Landlock retrofit join — see os_sandbox_landlock_apply_to_self().
         * This thread predates -sandbox=steady's late sandbox entry; joining
         * from inside its own loop is idempotent and a cheap no-op once
         * joined (or while the sandbox is inactive). */
        if (os_sandbox_active())
            (void)os_sandbox_landlock_apply_to_self();

        sweep_once();
        /* time-discipline organ: fold one real-clock sample every sweep
         * (~1 Hz). This IS the "existing supervised tick" the sampler rides
         * on — zcl_health_sweep is already a supervisor-tree child (see
         * thread_liveness_register_restartable below), so no dedicated
         * thread is spun up for skew/step tracking. O(1), no allocation,
         * no locks. See util/time_authority.h. */
        time_auth_observe();
        /* Heartbeat onto the supervisor tree (atomic-only; zero behavior
         * change). Marker advances every sweep so a frozen loop is visible. */
        thread_liveness_beat(&g_sweep_child,
                             (int64_t)atomic_fetch_add(&g_sweep_count, 1) + 1);
        int interval_ms = atomic_load(&g_check_interval_ms);
        struct timespec ts = {
            .tv_sec  = interval_ms / 1000,
            .tv_nsec = (long)(interval_ms % 1000) * 1000000L,
        };
        nanosleep(&ts, NULL);
    }
    /* Abnormal-exit signal for the supervisor's die-vs-stall decision. A
     * graceful stop marks the child complete first, so this is ignored there. */
    thread_liveness_worker_exited(&g_sweep_child);
    return NULL;
}

bool health_start(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_started, &expected, true))
        return true; /* already running */

    atomic_store(&g_running, true);
    /* SAFE PERMANENT auto-restart: the sweeper is a pure snapshot-and-dispatch
     * loop with no consensus/shared mutable state (each sweep is independent),
     * so re-entering it from scratch is a no-op on correctness. Storm cap:
     * 5 restarts / 60 s → permanent "thread_restart_storm_zcl_health_sweep"
     * blocker. This is the very thread whose 8.6 h silent wedge motivated the
     * supervisor — now a repeat death self-heals or names a blocker. */
    // supervised:zcl_health_sweep (thread_liveness_register_restartable below)
    int rc = thread_registry_spawn("zcl_health_sweep", sweeper_thread,
                                       NULL, &g_sweep_child.worker_tid);
    if (rc != 0) {
        fprintf(stderr, "[health] sweeper spawn failed: rc=%d\n", rc);
        atomic_store(&g_running, false);
        atomic_store(&g_started, false);
        return false;
    }
    (void)thread_liveness_register_restartable(&g_sweep_child,
                                   "zcl_health_sweep",
                                   /*deadline_secs=*/120,
                                   /*progress_quiet_us=*/0,
                                   sweeper_thread, NULL,
                                   /*intensity_max=*/5, /*period_secs=*/60);
    return true;
}

void health_stop(void)
{
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_started, &expected, false))
        return; /* not running */
    thread_liveness_stop_begin(&g_sweep_child);   /* no more auto-restart */
    atomic_store(&g_running, false);              /* signal the loop to exit */
    thread_liveness_stop_finish(&g_sweep_child);  /* join current tid + retire */
}

void health_reset_for_test(void)
{
    health_stop();
    pthread_mutex_lock(&g_mu);
    memset(g_entries, 0, sizeof(g_entries));
    pthread_mutex_unlock(&g_mu);
    atomic_store(&g_check_interval_ms, 1000);
}

bool health_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;

    struct health_snapshot snaps[HEALTH_REGISTRY_CAP];
    int n = health_snapshot_all(snaps, HEALTH_REGISTRY_CAP);

    json_push_kv_int(out, "registry_cap", HEALTH_REGISTRY_CAP);
    json_push_kv_int(out, "entry_count", n);
    json_push_kv_int(out, "check_interval_ms",
                     atomic_load(&g_check_interval_ms));
    json_push_kv_bool(out, "sweeper_running",
                      atomic_load(&g_started));

    struct json_value entries;
    json_init(&entries);
    json_set_array(&entries);
    for (int i = 0; i < n; i++) {
        struct json_value e;
        json_init(&e);
        json_set_object(&e);
        json_push_kv_str(&e, "name", snaps[i].name);
        json_push_kv_int(&e, "deadline_secs", snaps[i].deadline_secs);
        json_push_kv_int(&e, "last_beat_age_secs",
                         snaps[i].last_beat_age_secs);
        json_push_kv_int(&e, "fires_total", snaps[i].on_stall_fired);
        json_push_kv_bool(&e, "periodic", snaps[i].periodic);
        json_push_kv_bool(&e, "currently_stalled", snaps[i].currently_stalled);
        json_push_back(&entries, &e);
    }
    json_push_kv(out, "entries", &entries);
    return true;
}
