/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * backpressure watchdog implementation. See net/tip_watchdog.h
 * for the rationale and state machine. */

#include "platform/time_compat.h"
#include "net/tip_watchdog.h"
#include "net/download.h"
#include "event/event.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

static _Atomic int64_t g_last_tip_advance_ns = 0;
static _Atomic int64_t g_entered_active_ns   = 0;
static _Atomic bool    g_active              = false;
static _Atomic int     g_last_tip_height     = 0;

/* Re-arm hysteresis latch (see tip_watchdog.h). Init true so the
 * first stall episode of a fresh process can enter. Consumed on
 * entry to ACTIVE; re-armed only when the byte estimate is observed
 * below DOWNLOAD_QUEUE_LOW_WATER while INACTIVE — "the backlog has
 * dropped below HIGH_WATER/2 since the last exit". */
static _Atomic bool    g_armed               = true;

static _Atomic uint64_t g_stat_entered  = 0;
static _Atomic uint64_t g_stat_cleared  = 0;
static _Atomic uint64_t g_stat_rejected = 0;
static _Atomic uint64_t g_stat_drained  = 0;

/* Test overrides. -1 means "use the real source". The clock override
 * is signed so we can encode "unset" cleanly; the queue-bytes and
 * dl-counts overrides use int64 for the same reason. The byte
 * override skips the estimate formula entirely; the counts override
 * feeds the real formula (lets tests assert the in_flight/queued
 * accounting itself). */
static _Atomic int64_t g_test_now_ns       = -1;
static _Atomic int64_t g_test_queue_bytes  = -1;
static _Atomic int64_t g_test_dl_in_flight = -1;
static _Atomic int64_t g_test_dl_queued    = -1;

static int64_t now_ns_real(void)
{
    struct timespec ts;
    if (platform_time_monotonic_timespec(&ts) != 0)
        return (int64_t)platform_time_wall_time_t() * 1000000000LL;
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static int64_t now_ns(void)
{
    int64_t t = atomic_load(&g_test_now_ns);
    return (t >= 0) ? t : now_ns_real();
}

/* in_flight slots may each be paid back with a block body; queued
 * entries are hash + bookkeeping only and have solicited nothing yet.
 * Charging them differently is what makes the estimate honest —
 * charging queued entries the in-flight body size grossly over-states
 * the real queue footprint and false-triggers backpressure. See the
 * constants block in tip_watchdog.h for the full reachability
 * arithmetic. */
static size_t download_queue_bytes_estimate(void)
{
    int64_t override = atomic_load(&g_test_queue_bytes);
    if (override >= 0) return (size_t)override;

    uint64_t in_flight = 0, queued = 0;
    int64_t t_in_flight = atomic_load(&g_test_dl_in_flight);
    int64_t t_queued    = atomic_load(&g_test_dl_queued);
    if (t_in_flight >= 0 || t_queued >= 0) {
        in_flight = (t_in_flight >= 0) ? (uint64_t)t_in_flight : 0;
        queued    = (t_queued    >= 0) ? (uint64_t)t_queued    : 0;
    } else {
        struct download_manager *dm = msg_get_download_mgr();
        if (!dm) return 0;
        dl_get_stats(dm, NULL, NULL, NULL, &in_flight, &queued);
    }
    return (size_t)(in_flight * BACKPRESSURE_AVG_BLOCK_BYTES +
                    queued * DL_QUEUED_ENTRY_BYTES);
}

void tip_watchdog_init(void)
{
    atomic_store(&g_last_tip_advance_ns, now_ns());
}

void tip_watchdog_note_tip_advance(int height)
{
    atomic_store(&g_last_tip_advance_ns, now_ns());
    atomic_store(&g_last_tip_height, height);
}

bool tip_watchdog_is_active(void)
{
    return atomic_load(&g_active);
}

static int64_t stall_threshold_ns(void)
{
    return (int64_t)TIP_STALL_THRESHOLD_SEC * 1000000000LL;
}

static int64_t reject_window_ns(void)
{
    return (int64_t)BACKPRESSURE_REJECT_SEC * 1000000000LL;
}

static void enter_active(int64_t now)
{
    if (atomic_exchange(&g_active, true)) return;
    /* Consume the re-arm latch: no re-entry after this episode until
     * the estimate is observed below DOWNLOAD_QUEUE_LOW_WATER while
     * INACTIVE (tip_watchdog_tick re-arms it). */
    atomic_store(&g_armed, false);
    atomic_store(&g_entered_active_ns, now);

    size_t drained = 0;
    struct download_manager *dm = msg_get_download_mgr();
    if (dm) drained = dl_drain_for_backpressure(dm);
    atomic_fetch_add(&g_stat_drained, drained);
    atomic_fetch_add(&g_stat_entered, 1);

    event_emitf(EV_BACKPRESSURE_ACTIVE, 0,
                "tip_stalled drained=%zu high_water_bytes=%lu",
                drained, (unsigned long)DOWNLOAD_QUEUE_HIGH_WATER);
}

static void leave_active(int64_t now, const char *reason)
{
    if (!atomic_exchange(&g_active, false)) return;
    int64_t entered = atomic_load(&g_entered_active_ns);
    int64_t held_ms = entered ? (now - entered) / 1000000 : 0;
    atomic_fetch_add(&g_stat_cleared, 1);
    event_emitf(EV_BACKPRESSURE_CLEAR, 0,
                "reason=%s held_ms=%lld", reason, (long long)held_ms);
}

bool tip_watchdog_tick(void)
{
    int64_t now = now_ns();
    int64_t since_advance = now - atomic_load(&g_last_tip_advance_ns);
    bool active = atomic_load(&g_active);
    size_t bytes = download_queue_bytes_estimate();

    if (!active) {
        /* Re-arm only while INACTIVE: a drain-induced dip during an
         * ACTIVE episode must not pre-arm the next entry — the latch
         * tracks "backlog halved since the last exit". */
        if (bytes < DOWNLOAD_QUEUE_LOW_WATER)
            atomic_store(&g_armed, true);
        if (since_advance > stall_threshold_ns() &&
            bytes > DOWNLOAD_QUEUE_HIGH_WATER &&
            atomic_load(&g_armed)) {
            enter_active(now);
            return true;
        }
        return false;
    }

    /* ACTIVE: clear if tip has advanced or cooldown elapsed. */
    if (since_advance < stall_threshold_ns()) {
        leave_active(now, "tip_advanced");
        return false;
    }
    int64_t in_active = now - atomic_load(&g_entered_active_ns);
    if (in_active >= reject_window_ns()) {
        leave_active(now, "cooldown_elapsed");
        return false;
    }
    return true;
}

bool tip_watchdog_should_reject(uint32_t peer_id, const char *cmd)
{
    if (!atomic_load(&g_active) || !cmd) return false;
    /* Only the two commands that lead to block-body work. inv triggers
     * a getdata round-trip, block carries the body itself. */
    if (strcmp(cmd, "inv") != 0 && strcmp(cmd, "block") != 0)
        return false;

    atomic_fetch_add(&g_stat_rejected, 1);
    event_emitf(EV_BACKPRESSURE_REJECT, peer_id, "cmd=%s", cmd);
    return true;
}

void tip_watchdog_test_reset(void)
{
    atomic_store(&g_active, false);
    atomic_store(&g_armed, true);
    atomic_store(&g_entered_active_ns, 0);
    atomic_store(&g_stat_entered, 0);
    atomic_store(&g_stat_cleared, 0);
    atomic_store(&g_stat_rejected, 0);
    atomic_store(&g_stat_drained, 0);
    atomic_store(&g_test_now_ns, -1);
    atomic_store(&g_test_queue_bytes, -1);
    atomic_store(&g_test_dl_in_flight, -1);
    atomic_store(&g_test_dl_queued, -1);
    atomic_store(&g_last_tip_height, 0);
    atomic_store(&g_last_tip_advance_ns, now_ns_real());
}

void tip_watchdog_test_set_now_ns(int64_t v)
{
    atomic_store(&g_test_now_ns, v);
}

void tip_watchdog_test_set_queue_bytes(size_t v)
{
    atomic_store(&g_test_queue_bytes, (int64_t)v);
}

void tip_watchdog_test_set_dl_counts(int64_t in_flight, int64_t queued)
{
    atomic_store(&g_test_dl_in_flight, in_flight);
    atomic_store(&g_test_dl_queued, queued);
}

void tip_watchdog_test_inject_tip_advance(int height, int64_t when_ns)
{
    atomic_store(&g_last_tip_height, height);
    atomic_store(&g_last_tip_advance_ns, when_ns);
}
