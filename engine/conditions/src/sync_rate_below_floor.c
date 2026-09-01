/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_rate_below_floor — see the header for the SYMPTOM/REMEDY/WITNESSED
 * contract. Purely observational: reads the same lock-free cursor primitive
 * reducer_drive_watchdog.c wraps (utxo_apply_stage_cursor() /
 * tip_finalize_stage_cursor() — plain atomic loads, see "Threading" in
 * platform/modules/util/include/util/stage.h; that file's own wrapper is private
 * (file-static), so this file calls the underlying accessors directly),
 * plus connman's own peer/height accessors and ibd_throttle's own brief-
 * mutex status snapshot. Nothing here touches progress_store, coins_kv, or
 * any lock the reducer drive holds (LOCK-ORDER LAW), and nothing here can
 * gate or slow the fold. */

#include "conditions/sync_rate_below_floor.h"
#include "conditions/condition_registry.h"

#include "base/text_fit.h"
#include "framework/condition.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "json/json.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "services/ibd_throttle.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SYNC_RATE_BLOCKER_ID "sync_rate_below_floor"
#define SYNC_RATE_OWNER      "sync_rate"

/* Fixed-point scale: every *_bps_scaled value below is bps * SYNC_RATE_SCALE,
 * so the hot path stays integer/atomic (no _Atomic double). */
#define SYNC_RATE_SCALE 1000

/* Deliberately far below the measured worst-case LEGITIMATE fold
 * rate (~50 blk/s pprev-walk ceiling) so a healthy node
 * under heavy proof-validation load never false-fires; this only catches a
 * node that is genuinely crawling (< 1 block/sec of real, non-throttled
 * work) while it has both peers and a real backlog to fold. */
#define SYNC_RATE_DEFAULT_FLOOR_BPS 1

/* Below this many microseconds of REAL (post-throttle-subtraction) elapsed
 * time, a window's rate estimate is too noisy to trust (a single block's
 * jitter would dominate) — the sample is skipped, not counted either way. */
#define SYNC_RATE_MIN_WINDOW_US (2 * 1000 * 1000)

/* K consecutive below-floor windows required before naming the episode.
 * With poll_secs=30 while inactive this is >= 2.5 minutes of sustained
 * sub-floor throughput — generous margin against a single slow window. */
#define SYNC_RATE_CONSECUTIVE_TICKS 5

/* Rolling sample baseline (single-writer: the condition-engine tick thread —
 * see framework/condition.c). */
static _Atomic bool    g_prev_valid;
static _Atomic int64_t g_prev_now_us;
static _Atomic int64_t g_prev_cursor;
static _Atomic int64_t g_prev_throttle_wait_us;

static _Atomic int     g_below_floor_streak;
/* Most recent WINDOW measurement (any outcome, above or below floor); -1 =
 * no valid measurement yet this episode of sampling. Read by witness(). */
static _Atomic int64_t g_last_bps_scaled = -1;
/* Whether the last detect() tick saw peers + pending work (the gate). A
 * false here means the symptom this condition names cannot currently apply
 * — witness() treats that as an honest clear. */
static _Atomic bool    g_last_had_work;

/* Frozen at the rising edge of an episode. */
static _Atomic int64_t g_bps_at_detect = -1;
static _Atomic int64_t g_floor_at_detect = -1;
static _Atomic int     g_network_tip_at_detect = -1;
static _Atomic int64_t g_log_head_at_detect = -1;
static _Atomic int64_t g_last_fire_unix;
static char g_dominant_blocker_id_at_detect[BLOCKER_ID_MAX];
static char g_dominant_blocker_reason_at_detect[BLOCKER_REASON_MAX];

#ifdef ZCL_TESTING
static _Atomic int     g_test_remedy_calls;
static _Atomic int64_t g_test_cursor_override = -1;
static _Atomic int64_t g_test_log_head_override = -1;
static _Atomic int64_t g_test_throttle_wait_us_override = -1;
static _Atomic int64_t g_test_now_us_override = -1;
#endif

static int64_t sr_now_us(void)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_now_us_override);
    if (forced >= 0)
        return forced;
#endif
    return platform_time_monotonic_us();
}

/* Same primitive reducer_drive_watchdog.c's (file-static)
 * reducer_drive_watchdog_read_cursor() wraps. */
static uint64_t sr_read_apply_cursor(void)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_cursor_override);
    if (forced >= 0)
        return (uint64_t)forced;
#endif
    return utxo_apply_stage_cursor();
}

/* log_head — the same definition node_health_service.c uses:
 * tip_finalize_stage_cursor() (lock-free), the terminal/durable reducer
 * cursor. -1 = unavailable. */
static int64_t sr_read_log_head(void)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_log_head_override);
    if (forced >= 0)
        return forced;
#endif
    uint64_t h = tip_finalize_stage_cursor();
    return (h <= (uint64_t)INT64_MAX) ? (int64_t)h : -1;
}

static int64_t sr_read_throttle_wait_us(void)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_throttle_wait_us_override);
    if (forced >= 0)
        return forced;
#endif
    struct ibd_throttle_status st;
    ibd_throttle_status_snapshot(&st);
    return st.total_wait_us;
}

static int64_t sr_floor_bps_scaled(void)
{
    const char *v = getenv("ZCL_SYNC_RATE_FLOOR_BPS");
    if (v && v[0]) {
        char *end = NULL;
        long long n = strtoll(v, &end, 10);
        if (end && *end == '\0' && n > 0)
            return (int64_t)n * SYNC_RATE_SCALE;
    }
    return (int64_t)SYNC_RATE_DEFAULT_FLOOR_BPS * SYNC_RATE_SCALE;
}

/* Best-effort: the currently dominant ACTIVE blocker (causal priority order,
 * util/blocker.h), if any — the likely root cause a slow window is a
 * SYMPTOM of, not something this condition invents an opinion about. Empty
 * strings when no blocker is active. */
static void sr_capture_dominant_blocker(char *id_out, size_t id_cap,
                                        char *reason_out, size_t reason_cap)
{
    if (id_out && id_cap)
        id_out[0] = '\0';
    if (reason_out && reason_cap)
        reason_out[0] = '\0';
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    const struct blocker_snapshot *dom = blocker_select_dominant(snaps, n);
    if (!dom)
        return;
    if (id_out)
        snprintf(id_out, id_cap, "%s", dom->id);
    if (reason_out)
        snprintf(reason_out, reason_cap, "%s", dom->reason);
}

static void sr_reset_sampling(void)
{
    atomic_store(&g_prev_valid, false);
    atomic_store(&g_below_floor_streak, 0);
    atomic_store(&g_last_had_work, false);
}

static void sr_store_baseline(int64_t now_us, int64_t cursor,
                              int64_t throttle_wait_us)
{
    atomic_store(&g_prev_now_us, now_us);
    atomic_store(&g_prev_cursor, cursor);
    atomic_store(&g_prev_throttle_wait_us, throttle_wait_us);
    atomic_store(&g_prev_valid, true);
}

static struct condition c_sync_rate_below_floor;

static bool detect_sync_rate_below_floor(void)
{
    struct connman *cm = sync_monitor_connman();
    if (!cm || connman_get_node_count(cm) == 0) {
        sr_reset_sampling();
        return false;
    }

    int network_tip = connman_max_peer_height(cm);
    int64_t log_head = sr_read_log_head();
    if (network_tip <= 0 || log_head < 0 || (int64_t)network_tip <= log_head) {
        /* No positively-confirmed pending work (at tip, or no usable peer
         * height signal) — the symptom this condition names cannot apply. */
        sr_reset_sampling();
        return false;
    }
    atomic_store(&g_last_had_work, true);

    int64_t now_us = sr_now_us();
    int64_t cursor_now = (int64_t)sr_read_apply_cursor();
    int64_t throttle_now_us = sr_read_throttle_wait_us();

    if (!atomic_load(&g_prev_valid)) {
        sr_store_baseline(now_us, cursor_now, throttle_now_us);
        atomic_store(&g_below_floor_streak, 0);
        return false;
    }

    int64_t prev_now_us = atomic_load(&g_prev_now_us);
    int64_t prev_cursor = atomic_load(&g_prev_cursor);
    int64_t prev_throttle_us = atomic_load(&g_prev_throttle_wait_us);

    int64_t elapsed_us = now_us - prev_now_us;
    if (elapsed_us <= 0) {
        /* Backward/duplicate clock sample — cannot measure; leave the
         * baseline untouched and wait for the next real tick. */
        return false;
    }

    /* Roll the baseline forward for the NEXT window regardless of outcome
     * below, so a skipped/invalid window never compounds into a stale,
     * artificially-long elapsed_us on the following tick. */
    sr_store_baseline(now_us, cursor_now, throttle_now_us);

    int64_t cursor_delta = (cursor_now >= prev_cursor)
                               ? (cursor_now - prev_cursor)
                               : 0; /* reorg/rewind: no negative rate */
    int64_t throttle_delta_us = (throttle_now_us >= prev_throttle_us)
                                    ? (throttle_now_us - prev_throttle_us)
                                    : 0;

    int64_t effective_elapsed_us = elapsed_us - throttle_delta_us;
    if (effective_elapsed_us < SYNC_RATE_MIN_WINDOW_US) {
        /* Either too short a window, or ibd_throttle's OWN deliberate sleep
         * ate nearly all of it — not a real-work measurement either way. Do
         * not count this tick toward the streak. */
        return false;
    }

    int64_t bps_scaled =
        (cursor_delta * SYNC_RATE_SCALE * 1000000) / effective_elapsed_us;
    atomic_store(&g_last_bps_scaled, bps_scaled);

    int64_t floor_scaled = sr_floor_bps_scaled();
    if (bps_scaled >= floor_scaled) {
        atomic_store(&g_below_floor_streak, 0);
        return false;
    }

    int streak = atomic_fetch_add(&g_below_floor_streak, 1) + 1;
    if (streak < SYNC_RATE_CONSECUTIVE_TICKS)
        return false;

    bool active = atomic_load(&c_sync_rate_below_floor.state.currently_active);
    if (!active) {
        atomic_store(&g_bps_at_detect, bps_scaled);
        atomic_store(&g_floor_at_detect, floor_scaled);
        atomic_store(&g_network_tip_at_detect, network_tip);
        atomic_store(&g_log_head_at_detect, log_head);
        sr_capture_dominant_blocker(g_dominant_blocker_id_at_detect,
                                    sizeof(g_dominant_blocker_id_at_detect),
                                    g_dominant_blocker_reason_at_detect,
                                    sizeof(g_dominant_blocker_reason_at_detect));
    }
    return true;
}

static enum condition_remedy_result remedy_sync_rate_below_floor(void)
{
    int64_t bps = atomic_load(&g_bps_at_detect);
    int64_t floor = atomic_load(&g_floor_at_detect);
    int tip = atomic_load(&g_network_tip_at_detect);
    int64_t head = atomic_load(&g_log_head_at_detect);
    const char *dom_id = g_dominant_blocker_id_at_detect[0]
                             ? g_dominant_blocker_id_at_detect : "(none)";

    /* This sentence does not fit BLOCKER_REASON_MAX: 282 bytes with every
     * value empty, 330 on a live fire with a real dominant blocker id, 361
     * with a 63-char id. Formatting straight into a 256-byte local cut the
     * closing "clears when the rate recovers" clause off with nothing to show
     * it. Build it whole, then let zcl_text_fit mark and log the cut. */
    char full[BLOCKER_REASON_MAX * 2];
    snprintf(full, sizeof(full),
             "fold rate %lld.%03lld bps below floor %lld.%03lld bps for >= "
             "%d consecutive windows while peers connected and pending work "
             "exists (network_tip=%d log_head=%lld); dominant active "
             "blocker=%s (recovery ladder invoked — never gates or slows the "
             "fold; clears when the rate recovers or the backlog drains)",
             (long long)(bps / SYNC_RATE_SCALE),
             (long long)(bps % SYNC_RATE_SCALE < 0 ? -(bps % SYNC_RATE_SCALE)
                                                    : bps % SYNC_RATE_SCALE),
             (long long)(floor / SYNC_RATE_SCALE),
             (long long)(floor % SYNC_RATE_SCALE),
             SYNC_RATE_CONSECUTIVE_TICKS, tip, (long long)head, dom_id);
    char reason[BLOCKER_REASON_MAX];
    (void)zcl_text_fit(reason, sizeof(reason), full, "condition",
                       "sync_rate_below_floor.reason");

    struct blocker_record r;
    if (blocker_init(&r, SYNC_RATE_BLOCKER_ID, SYNC_RATE_OWNER,
                     BLOCKER_TRANSIENT, reason)) {
        (void)blocker_set(&r);
        atomic_store(&g_last_fire_unix, platform_time_wall_unix());
    }

    /* ACT: close the detect->act loop. A sustained growing gap (peers +
     * pending work, fold crawling below floor for K windows) is the most
     * direct "not catching up" signal — hand it to the top-level
     * always-terminating recovery ladder (sticky_escalator), whose rungs
     * re-derive on their own supervised ticks and self-clear on real tip
     * progress. This never touches a validity predicate or the fold write
     * path (CLAUDE.md "Consensus parity is inviolable"); note_stall is cheap,
     * reentrant-safe, and idempotent (a no-op re-arm if the ladder is already
     * armed by chain_tip_watchdog). The operator page remains the LAST resort
     * on the ladder, never the first response to this recoverable class. */
    sticky_escalator_note_stall("sync_rate_below_floor");

    LOG_WARN("condition",
             "[condition:sync_rate_below_floor] observed_bps_x1000=%lld "
             "floor_bps_x1000=%lld network_tip=%d log_head=%lld "
             "dominant_blocker=%s action=name_blocker+ladder_kick",
             (long long)bps, (long long)floor, tip, (long long)head, dom_id);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    /* The remedy took a corrective action (armed the ladder). The symptom
     * does not clear this instant — the engine downgrades an un-witnessed OK
     * to COND_REMEDY_UNWITNESSED and re-arms on the 600s cooldown, re-noting
     * the stall until the fold recovers (witness clears) or drains. */
    return COND_REMEDY_OK;
}

static bool witness_sync_rate_below_floor(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: an honest clear on EITHER the rate recovering OR the
    // gate resolving (no peers, or the backlog drained — network_tip <=
    // log_head) — the named symptom ("behind and not catching up") cannot
    // hold when there is nothing left to catch up on.
    if (!atomic_load(&g_last_had_work)) {
        blocker_clear(SYNC_RATE_BLOCKER_ID);
        return true;
    }
    int64_t bps = atomic_load(&g_last_bps_scaled);
    if (bps < 0)
        return false; /* no fresh sample yet — cannot confirm recovery */
    int64_t floor = sr_floor_bps_scaled();
    bool resolved = bps >= floor;
    if (resolved)
        blocker_clear(SYNC_RATE_BLOCKER_ID);
    return resolved;
}

static bool detail_sync_rate_below_floor(struct json_value *out)
{
    if (!out)
        return false;
    bool ok = true;
    ok = ok && json_push_kv_int(out, "observed_bps_x1000",
                                atomic_load(&g_bps_at_detect));
    ok = ok && json_push_kv_int(out, "floor_bps_x1000",
                                atomic_load(&g_floor_at_detect));
    ok = ok && json_push_kv_int(out, "network_tip_at_detect",
                                atomic_load(&g_network_tip_at_detect));
    ok = ok && json_push_kv_int(out, "log_head_at_detect",
                                atomic_load(&g_log_head_at_detect));
    ok = ok && json_push_kv_str(out, "dominant_blocker_id",
                                g_dominant_blocker_id_at_detect);
    ok = ok && json_push_kv_str(out, "dominant_blocker_reason",
                                g_dominant_blocker_reason_at_detect);
    ok = ok && json_push_kv_int(out, "last_fire_unix",
                                atomic_load(&g_last_fire_unix));
    ok = ok && json_push_kv_int(out, "current_bps_x1000",
                                atomic_load(&g_last_bps_scaled));
    ok = ok && json_push_kv_int(out, "current_floor_bps_x1000",
                                sr_floor_bps_scaled());
    ok = ok && json_push_kv_int(out, "below_floor_streak",
                                atomic_load(&g_below_floor_streak));
    ok = ok && json_push_kv_bool(out, "pending_work",
                                 atomic_load(&g_last_had_work));
    return ok;
}

static struct condition c_sync_rate_below_floor = {
    .name = "sync_rate_below_floor",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    .max_attempts = 1,
    .detect = detect_sync_rate_below_floor,
    .remedy = remedy_sync_rate_below_floor,
    .witness = witness_sync_rate_below_floor,
    .detail = detail_sync_rate_below_floor,
    .witness_window_secs = 60,
    /* Continue-with-cooldown (sticky-node plan #7): a slow fold is not a
     * deterministic-unrecoverable local fault — it is an external-load
     * symptom (heavy proof validation, a slow disk, a throttled IBD lane)
     * that may ease on its own. Re-arm every 10 minutes, unbounded, while it
     * stays below floor; the episode clears instantly (via witness) the
     * moment the rate recovers or the backlog drains. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
};

void register_sync_rate_below_floor(void)
{
    (void)condition_register(&c_sync_rate_below_floor);
}

bool sync_rate_below_floor_dump_state_json(struct json_value *out,
                                           const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    bool ok = true;
    ok = ok && json_push_kv_bool(out, "active",
                                 atomic_load(&c_sync_rate_below_floor
                                                  .state.currently_active));
    ok = ok && json_push_kv_bool(out, "pending_work",
                                 atomic_load(&g_last_had_work));
    ok = ok && json_push_kv_int(out, "current_bps_x1000",
                                atomic_load(&g_last_bps_scaled));
    ok = ok && json_push_kv_int(out, "current_floor_bps_x1000",
                                sr_floor_bps_scaled());
    ok = ok && json_push_kv_int(out, "below_floor_streak",
                                atomic_load(&g_below_floor_streak));
    ok = ok && json_push_kv_int(out, "consecutive_ticks_required",
                                SYNC_RATE_CONSECUTIVE_TICKS);

    /* Episode-start snapshot (frozen at the rising edge — see
     * detect_sync_rate_below_floor()); -1 fields mean no episode has fired
     * yet since the last reset. */
    ok = ok && json_push_kv_int(out, "observed_bps_x1000_at_detect",
                                atomic_load(&g_bps_at_detect));
    ok = ok && json_push_kv_int(out, "floor_bps_x1000_at_detect",
                                atomic_load(&g_floor_at_detect));
    ok = ok && json_push_kv_int(out, "network_tip_at_detect",
                                atomic_load(&g_network_tip_at_detect));
    ok = ok && json_push_kv_int(out, "log_head_at_detect",
                                atomic_load(&g_log_head_at_detect));
    ok = ok && json_push_kv_str(out, "dominant_blocker_id_at_detect",
                                g_dominant_blocker_id_at_detect);
    ok = ok && json_push_kv_int(out, "last_fire_unix",
                                atomic_load(&g_last_fire_unix));
    return ok;
}

#ifdef ZCL_TESTING
void sync_rate_below_floor_test_reset(void)
{
    atomic_store(&g_prev_valid, false);
    atomic_store(&g_prev_now_us, 0);
    atomic_store(&g_prev_cursor, 0);
    atomic_store(&g_prev_throttle_wait_us, 0);
    atomic_store(&g_below_floor_streak, 0);
    atomic_store(&g_last_bps_scaled, -1);
    atomic_store(&g_last_had_work, false);
    atomic_store(&g_bps_at_detect, -1);
    atomic_store(&g_floor_at_detect, -1);
    atomic_store(&g_network_tip_at_detect, -1);
    atomic_store(&g_log_head_at_detect, -1);
    atomic_store(&g_last_fire_unix, 0);
    g_dominant_blocker_id_at_detect[0] = '\0';
    g_dominant_blocker_reason_at_detect[0] = '\0';
    atomic_store(&g_test_remedy_calls, 0);
    atomic_store(&g_test_cursor_override, -1);
    atomic_store(&g_test_log_head_override, -1);
    atomic_store(&g_test_throttle_wait_us_override, -1);
    atomic_store(&g_test_now_us_override, -1);
    blocker_clear(SYNC_RATE_BLOCKER_ID);
    condition_reset_state(&c_sync_rate_below_floor);
}

int sync_rate_below_floor_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

void sync_rate_below_floor_test_set_cursor_override(int64_t v)
{
    atomic_store(&g_test_cursor_override, v);
}

void sync_rate_below_floor_test_set_log_head_override(int64_t v)
{
    atomic_store(&g_test_log_head_override, v);
}

void sync_rate_below_floor_test_set_throttle_wait_us_override(int64_t v)
{
    atomic_store(&g_test_throttle_wait_us_override, v);
}

void sync_rate_below_floor_test_set_now_us_override(int64_t v)
{
    atomic_store(&g_test_now_us_override, v);
}
#endif
