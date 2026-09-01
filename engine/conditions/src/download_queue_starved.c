/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/download_queue_starved.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "net/connman.h"
#include "net/download.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdio.h>

#define QUEUE_STARVED_TRIGGER_SECS 120
#define QUEUE_STARVED_RATIO_DEN 10

static _Atomic int64_t g_first_seen;
static _Atomic uint64_t g_inflight_at_detect;
static _Atomic uint64_t g_queued_at_detect;
static _Atomic uint64_t g_requested_at_detect;
static _Atomic uint64_t g_received_at_detect;
static _Atomic uint64_t g_timed_out_at_detect;
static _Atomic int64_t g_age_at_detect;
static _Atomic uint64_t g_last_witness_requested;
static _Atomic uint64_t g_last_witness_received;
static _Atomic uint64_t g_last_witness_timed_out;
static _Atomic uint64_t g_last_witness_inflight;
static _Atomic uint64_t g_last_witness_queued;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

/* Pending work is LIVE state only: a queued or in-flight block. A cumulative
 * counter arm (`requested > received + timed_out`) is unsafe here: any settle
 * path leak (disconnect-requeue, backpressure-drain) leaves a permanent
 * residue that re-satisfies the condition every cycle even at tip with
 * queued==0 and inflight==0, paging the operator with nothing wrong. Counter
 * drift is a watched diagnostic (dl_diagnostics.accounting_drift), not a
 * detect input. */
static bool download_work_pending(uint64_t inflight, uint64_t queued)
{
    return queued > 0 || inflight > 0;
}

/* A PERMANENT typed blocker (bad PoW, malformed block, consensus reject, an
 * irreducible fold hole — see util/blocker.h) means H* cannot advance no
 * matter how much download work is kept in flight: kick_local_sync (the
 * remedy below) can NEVER clear a fold blocker. Once one is active, download
 * starvation observed here is a SYMPTOM of that blocker, not an independent,
 * operator-actionable local fault — paging on it manufactures an
 * unresolvable page riding on top of the real, already-named wedge. Reuse
 * the SAME class query chain_tip_watchdog.c:wd_deterministic_stall_cause()
 * already uses to classify a stall as deterministic
 * (chain_tip_watchdog.c:304, `blocker_count_by_class(BLOCKER_PERMANENT)`) —
 * do not invent a second mechanism for the same fact. */
static bool permanent_fold_blocker_active(void)
{
    return blocker_count_by_class(BLOCKER_PERMANENT) > 0;
}

static bool detect_download_queue_starved(void)
{
    struct connman *cm = sync_monitor_connman();
    struct download_manager *dm =
        sync_monitor_download_manager();
    int64_t now = platform_time_wall_unix();
    /* Defer: never START a new episode while a permanent fold blocker holds
     * H* — see permanent_fold_blocker_active() above. An episode that is
     * ALREADY active when the blocker appears is deferred by the witness
     * below (detect() gates episode START, never CONTINUATION — see
     * framework/condition.c condition_tick_one). */
    if (permanent_fold_blocker_active()) {
        atomic_store(&g_first_seen, 0);
        return false;
    }
    if (sync_get_state() != SYNC_BLOCKS_DOWNLOAD || !cm || !dm ||
        connman_get_node_count(cm) == 0) {
        atomic_store(&g_first_seen, 0);
        return false;
    }

    uint64_t requested = 0, received = 0, timed_out = 0;
    uint64_t inflight = 0, queued = 0;
    dl_get_stats(dm, &requested, &received, &timed_out, &inflight, &queued);
    if (!download_work_pending(inflight, queued)) {
        atomic_store(&g_first_seen, 0);
        return false;
    }
    uint64_t threshold = DL_MAX_IN_FLIGHT_TOTAL_IBD /
                         QUEUE_STARVED_RATIO_DEN;
    if (inflight >= threshold) {
        atomic_store(&g_first_seen, 0);
        return false;
    }
    int64_t first = atomic_load(&g_first_seen);
    if (first == 0) {
        atomic_store(&g_first_seen, now);
        return false;
    }
    int64_t age = now - first;
    if (age < QUEUE_STARVED_TRIGGER_SECS)
        return false;

    atomic_store(&g_inflight_at_detect, inflight);
    atomic_store(&g_queued_at_detect, queued);
    atomic_store(&g_requested_at_detect, requested);
    atomic_store(&g_received_at_detect, received);
    atomic_store(&g_timed_out_at_detect, timed_out);
    atomic_store(&g_age_at_detect, age);
    return true;
}

static enum condition_remedy_result remedy_download_queue_starved(void)
{
    LOG_WARN("condition", "[condition:download_queue_starved] in_flight=%llu queued=%llu " "age=%llds action=kick_refill", (unsigned long long)atomic_load(&g_inflight_at_detect), (unsigned long long)atomic_load(&g_queued_at_detect), (long long)atomic_load(&g_age_at_detect));
    sync_monitor_kick_local_sync("condition:download_queue_starved");
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_download_queue_starved(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Same defer as detect() above: if a permanent fold blocker becomes (or
     * already is) active while this episode is active, honestly treat the
     * episode as resolved from THIS condition's point of view — the real
     * cause is the named fold blocker (visible via native blocker diagnostics
     * and the chain_tip_watchdog cause probe), not a queue refill this remedy could
     * ever fix. detail_download_queue_starved() below still reports the
     * deferral (permanent_blocker_active / permanent_blocker_id /
     * permanent_blocker_reason) so the clear is never silent. */
    if (permanent_fold_blocker_active())
        return true;
    if (sync_get_state() != SYNC_BLOCKS_DOWNLOAD)
        return true;

    struct download_manager *dm =
        sync_monitor_download_manager();
    if (!dm)
        return false;
    /* HONEST witness (Law 7): the remedy (kick_refill) is async and mutates
     * nothing observable on return. The symptom is pending download work that
     * is not being kept in flight, so a witness is either (a) new requests went
     * out after detection, or (b) the pending work drained/settled while the
     * episode was active. The second arm prevents an at-tip/normal-lookahead
     * node from keeping an operator latch after the only needed body has
     * already been received and no queue/in-flight work remains. */
    uint64_t requested = 0, received = 0, timed_out = 0;
    uint64_t inflight = 0, queued = 0;
    dl_get_stats(dm, &requested, &received, &timed_out, &inflight, &queued);
    atomic_store(&g_last_witness_requested, requested);
    atomic_store(&g_last_witness_received, received);
    atomic_store(&g_last_witness_timed_out, timed_out);
    atomic_store(&g_last_witness_inflight, inflight);
    atomic_store(&g_last_witness_queued, queued);
    return requested > atomic_load(&g_requested_at_detect) ||
           !download_work_pending(inflight, queued);
}

static bool detail_download_queue_starved(struct json_value *out)
{
    struct connman *cm = sync_monitor_connman();
    struct download_manager *dm = sync_monitor_download_manager();
    uint64_t requested = 0;
    uint64_t received = 0;
    uint64_t timed_out = 0;
    uint64_t inflight = 0;
    uint64_t queued = 0;
    struct dl_diagnostics diag;
    dl_get_diagnostics(dm, &diag);
    if (dm) {
        dl_get_stats(dm, &requested, &received, &timed_out, &inflight,
                     &queued);
    }

    bool ok = true;
    ok = ok && json_push_kv_str(out, "sync_state",
                                sync_state_name(sync_get_state()));
    ok = ok && json_push_kv_bool(out, "has_connman", cm != NULL);
    ok = ok && json_push_kv_bool(out, "has_download_manager", dm != NULL);
    ok = ok && json_push_kv_int(
        out, "peer_count", cm ? (int64_t)connman_get_node_count(cm) : -1);
    ok = ok && json_push_kv_int(out, "inflight_threshold",
                                DL_MAX_IN_FLIGHT_TOTAL_IBD /
                                    QUEUE_STARVED_RATIO_DEN);
    ok = ok && json_push_kv_int(out, "trigger_secs",
                                QUEUE_STARVED_TRIGGER_SECS);
    ok = ok && json_push_kv_int(out, "first_seen_unix",
                                atomic_load(&g_first_seen));
    ok = ok && json_push_kv_int(out, "detect_age_s",
                                atomic_load(&g_age_at_detect));
    ok = ok && json_push_kv_int(out, "requested_at_detect",
                                (int64_t)atomic_load(
                                    &g_requested_at_detect));
    ok = ok && json_push_kv_int(out, "received_at_detect",
                                (int64_t)atomic_load(
                                    &g_received_at_detect));
    ok = ok && json_push_kv_int(out, "timed_out_at_detect",
                                (int64_t)atomic_load(
                                    &g_timed_out_at_detect));
    ok = ok && json_push_kv_int(out, "inflight_at_detect",
                                (int64_t)atomic_load(
                                    &g_inflight_at_detect));
    ok = ok && json_push_kv_int(out, "queued_at_detect",
                                (int64_t)atomic_load(&g_queued_at_detect));
    ok = ok && json_push_kv_int(out, "current_requested",
                                (int64_t)requested);
    ok = ok && json_push_kv_int(out, "current_received",
                                (int64_t)received);
    ok = ok && json_push_kv_int(out, "current_timed_out",
                                (int64_t)timed_out);
    ok = ok && json_push_kv_int(out, "current_inflight",
                                (int64_t)inflight);
    ok = ok && json_push_kv_int(out, "current_queued",
                                (int64_t)queued);
    ok = ok && json_push_kv_int(out, "last_witness_requested",
                                (int64_t)atomic_load(
                                    &g_last_witness_requested));
    ok = ok && json_push_kv_int(out, "last_witness_received",
                                (int64_t)atomic_load(
                                    &g_last_witness_received));
    ok = ok && json_push_kv_int(out, "last_witness_timed_out",
                                (int64_t)atomic_load(
                                    &g_last_witness_timed_out));
    ok = ok && json_push_kv_int(out, "last_witness_inflight",
                                (int64_t)atomic_load(
                                    &g_last_witness_inflight));
    ok = ok && json_push_kv_int(out, "last_witness_queued",
                                (int64_t)atomic_load(
                                    &g_last_witness_queued));
    ok = ok && json_push_kv_bool(
        out, "witness_request_counter_advanced",
        atomic_load(&g_last_witness_requested) >
            atomic_load(&g_requested_at_detect));
    bool pending = dm && download_work_pending(inflight, queued);
    bool witness_pending = download_work_pending(
        atomic_load(&g_last_witness_inflight),
        atomic_load(&g_last_witness_queued));
    ok = ok && json_push_kv_bool(out, "pending_download_work", pending);
    ok = ok && json_push_kv_bool(out, "witness_download_work_drained",
                                 !witness_pending);
    ok = ok && json_push_kv_int(out, "total_orphaned",
                                (int64_t)diag.total_orphaned);
    ok = ok && json_push_kv_int(out, "accounting_drift",
                                diag.accounting_drift);
    ok = ok && json_push_kv_int(out, "assign_attempts",
                                (int64_t)diag.assign_attempts);
    ok = ok && json_push_kv_int(out, "assign_successes",
                                (int64_t)diag.assign_successes);
    ok = ok && json_push_kv_int(out, "assign_zero_results",
                                (int64_t)diag.assign_zero_results);
    ok = ok && json_push_kv_str(out, "last_assign_result",
                                dl_assign_result_name(
                                    diag.last_assign_result));
    ok = ok && json_push_kv_int(out, "last_assign_peer_id",
                                diag.last_assign_peer_id);
    ok = ok && json_push_kv_int(out, "last_assign_available",
                                (int64_t)diag.last_assign_available);
    ok = ok && json_push_kv_int(out, "last_assign_assigned",
                                (int64_t)diag.last_assign_assigned);
    ok = ok && json_push_kv_int(out, "last_assign_queue_len",
                                (int64_t)diag.last_assign_queue_len);
    ok = ok && json_push_kv_int(out, "last_assign_active",
                                (int64_t)diag.last_assign_active);
    ok = ok && json_push_kv_int(out, "oldest_in_flight_age_seconds",
                                diag.oldest_in_flight_age_seconds);
    ok = ok && json_push_kv_int(out, "overdue_in_flight",
                                (int64_t)diag.overdue_in_flight);
    ok = ok && json_push_kv_str(
        out, "remedy_contract",
        "kick_local_sync is witnessed when total_requested advances past requested_at_detect or the pending queue/in-flight work drains; DEFERRED (not attempted) whenever a permanent fold blocker is active, since a queue kick can never clear one");

    /* Honest deferral (Law 7): a permanent fold blocker means this
     * condition's own diagnosis (starved download queue) is not the
     * operator-actionable cause — see permanent_fold_blocker_active().
     * Name the blocker actually holding H* rather than silently clearing. */
    bool permanent_blocker_active = permanent_fold_blocker_active();
    char blocker_id[BLOCKER_ID_MAX] = "";
    char blocker_reason[BLOCKER_REASON_MAX] = "";
    if (permanent_blocker_active) {
        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        for (int i = 0; i < n; i++) {
            if (snaps[i].class == BLOCKER_PERMANENT) {
                snprintf(blocker_id, sizeof(blocker_id), "%s", snaps[i].id);
                snprintf(blocker_reason, sizeof(blocker_reason), "%s",
                         snaps[i].reason);
                break;
            }
        }
    }
    ok = ok && json_push_kv_bool(out, "permanent_blocker_active",
                                 permanent_blocker_active);
    ok = ok && json_push_kv_str(out, "permanent_blocker_id", blocker_id);
    ok = ok && json_push_kv_str(out, "permanent_blocker_reason",
                                blocker_reason);
    char deferred_summary[BLOCKER_REASON_MAX + 128] = "";
    if (permanent_blocker_active) {
        snprintf(deferred_summary, sizeof(deferred_summary),
                 "deferred: superseded by permanent fold blocker '%s' (%s)",
                 blocker_id, blocker_reason);
    }
    ok = ok && json_push_kv_str(out, "deferred_reason", deferred_summary);
    return ok;
}

static struct condition c_download_queue_starved = {
    .name = "download_queue_starved",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 120,
    /* Page after 5 unwitnessed kick_refill attempts (the request counter never
     * advanced), THEN re-arm on the cooldown below — escalate once without ever
     * permanently giving up. (100000 attempts at 120s backoff made this
     * effectively non-escalating; a hard cap-and-latch made a transient no-peer
     * stall permanent. Re-arm is the robust middle: page + keep trying.) */
    .max_attempts = 5,
    .detect = detect_download_queue_starved,
    .remedy = remedy_download_queue_starved,
    .witness = witness_download_queue_starved,
    .detail = detail_download_queue_starved,
    .witness_window_secs = 60,
    /* External-resource fault (peers / bandwidth / a momentarily empty fetch
     * window) — NOT a deterministic local fault. Re-arm on a long cooldown so a
     * transient fetch stall can never become a permanent operator_needed latch;
     * the remedy keeps retrying every 5 min, unbounded, until the queue refills.
     * Mirrors peer_floor_violated (the proven external-dependency pattern). */
    .cooldown_secs = 300,
    .cooldown_max_rearms = 0,
};

void register_download_queue_starved(void)
{
    (void)condition_register(&c_download_queue_starved);
}

#ifdef ZCL_TESTING
void download_queue_starved_test_reset(void)
{
    atomic_store(&g_first_seen, 0);
    atomic_store(&g_inflight_at_detect, 0);
    atomic_store(&g_queued_at_detect, 0);
    atomic_store(&g_requested_at_detect, 0);
    atomic_store(&g_received_at_detect, 0);
    atomic_store(&g_timed_out_at_detect, 0);
    atomic_store(&g_age_at_detect, 0);
    atomic_store(&g_last_witness_requested, 0);
    atomic_store(&g_last_witness_received, 0);
    atomic_store(&g_last_witness_timed_out, 0);
    atomic_store(&g_last_witness_inflight, 0);
    atomic_store(&g_last_witness_queued, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

int download_queue_starved_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
