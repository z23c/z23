/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * disk_low_pause — reclaims derived bytes when an index-fold "*.disk_low"
 * blocker is set; see conditions/disk_low_pause.h for the full contract. */

#include "conditions/disk_low_pause.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "event/event.h"
#include "services/disk_monitor.h"
#include "services/storage_reclaim.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>

/* Same recoverable-external-resource class as disk_full_pause.c: a low-disk
 * index backfill hold is recoverable the instant space returns (operator
 * action or our own derived-byte reclaim), so this uses the
 * continue-with-cooldown tier (sticky-node plan #7) rather than a finite
 * give-up. See disk_full_pause.c's header comment for the full rationale;
 * this condition mirrors it exactly. */
#define DISK_LOW_POLL_SECS        15
#define DISK_LOW_BACKOFF_SECS     300     /* 5 min between fast reclaim attempts */
#define DISK_LOW_MAX_ATTEMPTS     5        /* one-time informational page, then... */
#define DISK_LOW_COOLDOWN_SECS    300      /* ...unbounded re-arm every 5 min */

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

/* The only two index_fold_disk_ok() callers today — keep this list in sync
 * with engine/services/src/address_index_service.c and
 * engine/services/src/txindex_projection_service.c the same way the diagnostics
 * dumpers list is kept in sync (CLAUDE.md "Adding state introspection"). */
static bool detect_disk_low_pause(void)
{
    return blocker_exists("address_index.disk_low") ||
           blocker_exists("txindex.disk_low");
}

static enum condition_remedy_result remedy_disk_low_pause(void)
{
    /* This condition does not own the "<index_id>.disk_low" blockers'
     * lifecycle — index_fold_guard.c's index_fold_disk_ok() raises and
     * clears them on the fold's own tip-follow cadence. Our job is only to
     * reclaim DERIVED bytes and force a fresh poll so that NEXT call sees
     * the freed headroom. */
    struct disk_monitor_status st;
    disk_monitor_status_snapshot(&st);

    if (st.datadir[0]) {
        struct storage_reclaim_result rec = storage_reclaim_derived(st.datadir);
        LOG_INFO("condition",
                 "[condition:disk_low_pause] index-fold disk_low blocker(s) "
                 "present — datadir=%s free=%lld reclaimed sources_ok=%d/%d "
                 "tmp_removed=%d tmp_bytes=%lld",
                 st.datadir, (long long)st.last_free_bytes,
                 rec.sources_ok, rec.sources_total, rec.tmp_files_removed,
                 (long long)rec.tmp_bytes_removed);
    } else {
        LOG_WARN("condition",
                 "[condition:disk_low_pause] index-fold disk_low blocker(s) "
                 "present but disk_monitor has no datadir yet — skipping "
                 "reclaim this round");
    }

    disk_monitor_poll_now();

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    /* Transient: never FAILED here — a still-low disk is re-detected and
     * re-remedied on the next backoff/cooldown round. */
    return COND_REMEDY_OK;
}

static bool witness_disk_low_pause(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: re-reads the real durable blocker registry state
    // (not FSM/poison state). The "<index_id>.disk_low" blockers are cleared
    // by index_fold_disk_ok() on its own next call once free space returns
    // above the fold's floor — this witness simply observes that fact.
    return !detect_disk_low_pause();
}

static bool detail_disk_low_pause(struct json_value *out)
{
    struct disk_monitor_status st;
    disk_monitor_status_snapshot(&st);
    return out &&
        json_push_kv_int(out, "free_bytes", (int64_t)st.last_free_bytes) &&
        json_push_kv_int(out, "address_index_disk_low",
                          blocker_exists("address_index.disk_low")) &&
        json_push_kv_int(out, "txindex_disk_low",
                          blocker_exists("txindex.disk_low"));
}

static struct condition c_disk_low_pause = {
    .name = "disk_low_pause",
    .severity = COND_CRITICAL,
    .poll_secs = DISK_LOW_POLL_SECS,
    .backoff_secs = DISK_LOW_BACKOFF_SECS,
    .max_attempts = DISK_LOW_MAX_ATTEMPTS,
    /* Continue-with-cooldown (sticky-node plan #7): see disk_full_pause.c —
     * same reasoning, this is the index-fold-scoped sibling. */
    .cooldown_secs = DISK_LOW_COOLDOWN_SECS,
    .cooldown_max_rearms = 0,
    .detect = detect_disk_low_pause,
    .remedy = remedy_disk_low_pause,
    .witness = witness_disk_low_pause,
    .detail = detail_disk_low_pause,
    .witness_window_secs = DISK_LOW_BACKOFF_SECS,
};

void register_disk_low_pause(void)
{
    (void)condition_register(&c_disk_low_pause);
}

#ifdef ZCL_TESTING
void disk_low_pause_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
}

int disk_low_pause_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
