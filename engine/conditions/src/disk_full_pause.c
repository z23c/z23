/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/disk_full_pause.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "event/event.h"
#include "services/disk_monitor.h"
#include "services/storage_reclaim.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>

/* A full disk is a TRANSIENT resource shortage, not a consensus fault: it is
 * recoverable the instant the operator (or our own derived-byte reclaim) frees
 * space. So this condition uses the continue-with-cooldown tier (sticky-node
 * plan #7), NOT a finite max_attempts give-up:
 *
 *   - max_attempts is small so a one-time INFORMATIONAL operator notice fires
 *     once per episode (the operator should know a disk filled up), but
 *   - cooldown_secs > 0 with cooldown_max_rearms == 0 means the engine re-arms
 *     the reclaim remedy every cooldown_secs FOREVER (unbounded) instead of
 *     latching operator_needed permanently. A disk that stays full for a day,
 *     a week, or forever NEVER becomes a terminal operator page — the node
 *     pauses-and-resumes and self-heals the instant space returns.
 *
 * This mirrors peer_floor_violated.c (another recoverable external-resource
 * class): a fast finite ladder for the one-time notice, then unbounded
 * cooldown re-arm. The previous design (max_attempts=288, no cooldown) was an
 * S2 violation: a 24 h-full disk would have escalated to a terminal page on a
 * recoverable class. */
#define DISK_FULL_POLL_SECS        15
#define DISK_FULL_BACKOFF_SECS     300     /* 5 min between fast reclaim attempts */
#define DISK_FULL_MAX_ATTEMPTS     5       /* one-time informational page, then... */
#define DISK_FULL_COOLDOWN_SECS    300     /* ...unbounded re-arm every 5 min */

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_disk_full_pause(void)
{
    return disk_monitor_is_critical();
}

static enum condition_remedy_result remedy_disk_full_pause(void)
{
    struct disk_monitor_status st;
    disk_monitor_status_snapshot(&st);

    /* 1. Name the stall: a BLOCKER_RESOURCE blocker so the operator (and the
     *    supervisor sweep) see a NAMED blocker, never a silent write refuse. */
    struct blocker_record r;
    if (blocker_init(&r, "disk-full", "storage", BLOCKER_RESOURCE,
                     "free space below refuse threshold; reclaiming derived bytes")) {
        (void)blocker_set(&r);
    }

    /* 2. Reclaim DERIVED/temp bytes. The sqlite WAL files are derived — a
     *    checkpoint+truncate returns their bytes without losing committed
     *    state — and stale *.tmp files are crash orphans. storage_reclaim_derived
     *    does both (best-effort; the witness, not this call, decides success).
     *    This is what makes the condition AUTO-TERMINATING: it can actually move
     *    free bytes back above the refuse threshold so the witness clears,
     *    instead of only logging intent and re-arming forever. */
    struct storage_reclaim_result rec = storage_reclaim_derived(st.datadir);
    LOG_INFO("condition",
             "[condition:disk_full_pause] CRITICAL free=%lld refuse_thr=%lld "
             "datadir=%s — reclaimed sources_ok=%d/%d tmp_removed=%d "
             "tmp_bytes=%lld",
             (long long)st.last_free_bytes,
             (long long)st.refuse_free_bytes, st.datadir,
             rec.sources_ok, rec.sources_total, rec.tmp_files_removed,
             (long long)rec.tmp_bytes_removed);

    /* 3. Force a fresh poll so the witness sees the post-reclaim level. */
    disk_monitor_poll_now();

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    /* Transient: report OK and let the witness decide. We never return
     * FAILED here (that would accrue attempts toward operator_needed); a
     * still-full disk is re-detected and re-remedied on the next backoff. */
    return COND_REMEDY_OK;
}

static bool witness_disk_full_pause(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: this condition is ENVIRONMENTAL, not chain-progress.
    // The "symptom moved" here means free disk space actually returned — there
    // is no tip/cursor/H* to observe. disk_monitor_poll_now() forces a FRESH
    // statvfs() of the real filesystem (not FSM/poison state), and the witness
    // passes only when that real re-measure shows space is no longer critical.
    disk_monitor_poll_now();
    return !disk_monitor_is_critical();
}

static bool detail_disk_full_pause(struct json_value *out)
{
    struct disk_monitor_status st;
    disk_monitor_status_snapshot(&st);
    return out &&
        json_push_kv_int(out, "free_bytes", (int64_t)st.last_free_bytes) &&
        json_push_kv_int(out, "refuse_thr", (int64_t)st.refuse_free_bytes) &&
        json_push_kv_int(out, "level", (int)st.level);
}

static struct condition c_disk_full_pause = {
    .name = "disk_full_pause",
    .severity = COND_CRITICAL,
    .poll_secs = DISK_FULL_POLL_SECS,
    .backoff_secs = DISK_FULL_BACKOFF_SECS,
    .max_attempts = DISK_FULL_MAX_ATTEMPTS,
    /* Continue-with-cooldown (sticky-node plan #7): a full disk is a
     * recoverable external-resource shortage. After the fast attempts fire a
     * one-time informational page, the engine re-arms the reclaim remedy every
     * DISK_FULL_COOLDOWN_SECS, UNBOUNDED (cooldown_max_rearms = 0), so the node
     * pauses-and-resumes forever and NEVER terminally pages on a recoverable
     * full disk. The episode resets the instant detect() goes false (space
     * returns). */
    .cooldown_secs = DISK_FULL_COOLDOWN_SECS,
    .cooldown_max_rearms = 0,
    .detect = detect_disk_full_pause,
    .remedy = remedy_disk_full_pause,
    .witness = witness_disk_full_pause,
    .detail = detail_disk_full_pause,
    .witness_window_secs = DISK_FULL_BACKOFF_SECS,
};

void register_disk_full_pause(void)
{
    (void)condition_register(&c_disk_full_pause);
}

#ifdef ZCL_TESTING
void disk_full_pause_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
}

int disk_full_pause_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
