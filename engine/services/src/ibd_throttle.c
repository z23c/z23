/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * IBD Throttle — see header.
 *
 * Token-bucket: a `double` counter of tokens, refilled whenever
 * an acquire() happens based on the elapsed wall-clock time since
 * the last refill. The counter is capped at `burst`. Each
 * successful acquire consumes exactly 1.0 token.
 *
 * Everything here is protected by a single mutex. The critical
 * section is tiny (arithmetic + clock_gettime), and the hot path
 * doesn't take any other locks, so this is fine under contention.
 *
 * `acquire()` loops by:
 *    1. Taking the lock, refilling, and attempting to consume.
 *    2. On failure, dropping the lock and sleeping 1ms.
 *    3. Goto 1.
 *
 * Under saturation each caller wakes up roughly once per
 * `1000/blocks_per_sec` milliseconds, spends a few microseconds
 * in the lock, and sleeps again. This is the right shape for a
 * writer throttle — the sleep dominates, not the lock.
 */
// one-result-type-ok:predicate-and-json-dump-bool:ibd_throttle_is_running,ibd_throttle_try_acquire
// — both are pure predicates (an answer, not a failure): is_running reports
// lifecycle state, try_acquire reports "was a token available right now?"
// and tests rely on its non-blocking bool return to drive deterministic
// accounting. ibd_throttle_dump_state_json is the mandated *_dump_state_json
// bool contract. ibd_throttle_acquire — the one genuinely fallible-shaped
// action export in this file — is converted to struct zcl_result below.

#include "platform/time_compat.h"
#include "services/ibd_throttle.h"

#include "event/event.h"
#include "json/json.h"
#include "services/disk_monitor.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util/log_macros.h"

/* ── Module state ───────────────────────────────────────────── */

struct ibd_throttle_state {
    pthread_mutex_t lock;
    bool            running;

    int64_t blocks_per_sec;   /* resolved */
    int64_t burst;            /* resolved */

    double  tokens;           /* current bucket level [0, burst] */
    int64_t last_refill_us;   /* CLOCK_MONOTONIC in microseconds */

    /* Counters for observability + test assertions. */
    uint64_t acquired_count;
    uint64_t blocked_count;
    int64_t  total_wait_us;

    /* Edge trigger for EV_IBD_THROTTLED — at most once every 60s. */
    int64_t  last_event_us;
    uint64_t blocked_since_last_event;
    int64_t  wait_since_last_event_us;
};

static struct ibd_throttle_state g_it = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ── Time helper ────────────────────────────────────────────── */

static int64_t it_now_us(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* ── Config ─────────────────────────────────────────────────── */

void ibd_throttle_config_defaults(struct ibd_throttle_config *cfg)
{
    if (!cfg) return;
    cfg->blocks_per_sec = IBD_THROTTLE_DEFAULT_BLOCKS_PER_SEC;
    cfg->burst          = IBD_THROTTLE_DEFAULT_BURST;
}

static int64_t it_env_int64(const char *name, int64_t fallback)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long long n = strtoll(v, &end, 10);
    if (!end || *end != '\0' || n <= 0) return fallback;
    return (int64_t)n;
}

void ibd_throttle_config_from_env(struct ibd_throttle_config *cfg)
{
    if (!cfg) return;
    ibd_throttle_config_defaults(cfg);
    cfg->blocks_per_sec = it_env_int64("ZCL_IBD_BLOCKS_PER_SEC",
                                        cfg->blocks_per_sec);
    cfg->burst          = it_env_int64("ZCL_IBD_BURST", cfg->burst);
}

/* ── Pure primitive ─────────────────────────────────────────── */

double ibd_throttle_refill(double current_tokens,
                           double rate_per_sec,
                           double burst,
                           int64_t elapsed_us)
{
    if (current_tokens < 0.0) current_tokens = 0.0;
    if (rate_per_sec  <= 0.0) return current_tokens;
    if (elapsed_us    <  0)   elapsed_us = 0;

    double added = rate_per_sec * ((double)elapsed_us / 1e6);
    double next  = current_tokens + added;
    if (next > burst) next = burst;
    return next;
}

/* Assumes lock held. */
static void it_refill_locked(int64_t now_us)
{
    int64_t elapsed = now_us - g_it.last_refill_us;
    if (elapsed < 0) elapsed = 0;
    /* Disk back-pressure: when the free-space watchdog reports CRITICAL, stop
     * refilling AND drain the bucket so acquire() blocks the IBD block writer
     * until reclaim frees space (no new bytes apply to a near-full disk). This
     * is the IBD-path twin of the db_txn_begin gate; it resumes automatically
     * when disk_monitor_is_critical() clears. The pure refill primitive
     * (ibd_throttle_refill) is left untouched so its determinism is intact. */
    if (disk_monitor_is_critical()) {
        g_it.tokens = 0.0;
        g_it.last_refill_us = now_us;
        return;
    }
    g_it.tokens = ibd_throttle_refill(g_it.tokens,
                                       (double)g_it.blocks_per_sec,
                                       (double)g_it.burst,
                                       elapsed);
    g_it.last_refill_us = now_us;
}

/* ── Event emission (rate-limited) ──────────────────────────── */

/* Assumes lock held. Emits at most once every 60s with aggregated
 * stats since the last emission. Returns a detached copy of the
 * payload bits so the caller can drop the lock before calling
 * event_emitf (which may take its own locks). */
static bool it_drain_pending_event_locked(int64_t now_us,
                                           uint64_t *out_blocked,
                                           int64_t  *out_wait_us,
                                           int64_t  *out_rate,
                                           int64_t  *out_burst)
{
    if (g_it.blocked_since_last_event == 0) return false;
    if (g_it.last_event_us != 0 &&
        now_us - g_it.last_event_us < 60 * 1000000LL) return false;

    *out_blocked = g_it.blocked_since_last_event;
    *out_wait_us = g_it.wait_since_last_event_us;
    *out_rate    = g_it.blocks_per_sec;
    *out_burst   = g_it.burst;

    g_it.last_event_us             = now_us;
    g_it.blocked_since_last_event  = 0;
    g_it.wait_since_last_event_us  = 0;
    return true;
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct zcl_result ibd_throttle_start(const struct ibd_throttle_config *cfg)
{
    struct ibd_throttle_config resolved;
    if (cfg) {
        resolved = *cfg;
    } else {
        ibd_throttle_config_from_env(&resolved);
    }
    if (resolved.blocks_per_sec <= 0)
        resolved.blocks_per_sec = IBD_THROTTLE_DEFAULT_BLOCKS_PER_SEC;
    if (resolved.burst <= 0)
        resolved.burst = IBD_THROTTLE_DEFAULT_BURST;

    pthread_mutex_lock(&g_it.lock);
    if (g_it.running) {
        pthread_mutex_unlock(&g_it.lock);
        return ZCL_ERR(-1, "start called but throttle already running");
    }
    g_it.running        = true;
    g_it.blocks_per_sec = resolved.blocks_per_sec;
    g_it.burst          = resolved.burst;
    /* Start the bucket full so a just-started node doesn't block
     * the first `burst` acquires while the bucket warms up. */
    g_it.tokens         = (double)g_it.burst;
    g_it.last_refill_us = it_now_us();

    g_it.acquired_count           = 0;
    g_it.blocked_count            = 0;
    g_it.total_wait_us            = 0;
    g_it.last_event_us            = 0;
    g_it.blocked_since_last_event = 0;
    g_it.wait_since_last_event_us = 0;
    pthread_mutex_unlock(&g_it.lock);
    return ZCL_OK;
}

void ibd_throttle_stop(void)
{
    pthread_mutex_lock(&g_it.lock);
    g_it.running = false;
    pthread_mutex_unlock(&g_it.lock);
}

bool ibd_throttle_is_running(void)
{
    pthread_mutex_lock(&g_it.lock);
    bool r = g_it.running;
    pthread_mutex_unlock(&g_it.lock);
    return r;
}

/* ── Hot path ───────────────────────────────────────────────── */

bool ibd_throttle_try_acquire(void)
{
    pthread_mutex_lock(&g_it.lock);
    if (!g_it.running) {
        pthread_mutex_unlock(&g_it.lock);
        return true; /* no-op pass-through */
    }
    int64_t now = it_now_us();
    it_refill_locked(now);
    if (g_it.tokens < 1.0) {
        pthread_mutex_unlock(&g_it.lock);
        return false;
    }
    g_it.tokens -= 1.0;
    g_it.acquired_count++;
    pthread_mutex_unlock(&g_it.lock);
    return true;
}

struct zcl_result ibd_throttle_acquire(void)
{
    /* Fast path: try once without sleeping. */
    if (ibd_throttle_try_acquire()) return ZCL_OK;

    int64_t wait_start = it_now_us();
    bool emit = false;
    uint64_t ev_blocked = 0;
    int64_t  ev_wait = 0;
    int64_t  ev_rate = 0;
    int64_t  ev_burst = 0;

    while (true) {
        platform_sleep_ms(1);

        pthread_mutex_lock(&g_it.lock);
        if (!g_it.running) {
            pthread_mutex_unlock(&g_it.lock);
            return ZCL_OK;
        }
        int64_t now = it_now_us();
        it_refill_locked(now);
        if (g_it.tokens >= 1.0) {
            g_it.tokens -= 1.0;
            g_it.acquired_count++;
            int64_t waited = now - wait_start;
            g_it.blocked_count++;
            g_it.total_wait_us += waited;
            g_it.blocked_since_last_event++;
            g_it.wait_since_last_event_us += waited;

            emit = it_drain_pending_event_locked(now, &ev_blocked,
                                                  &ev_wait, &ev_rate,
                                                  &ev_burst);
            pthread_mutex_unlock(&g_it.lock);
            break;
        }
        pthread_mutex_unlock(&g_it.lock);
    }

    if (emit) {
        event_emitf(EV_IBD_THROTTLED, 0,
                    "blocked=%" PRIu64 " total_wait_ms=%" PRId64
                    " rate=%" PRId64 " burst=%" PRId64,
                    ev_blocked, ev_wait / 1000, ev_rate, ev_burst);
    }
    return ZCL_OK;
}

/* ── Status ─────────────────────────────────────────────────── */

void ibd_throttle_status_snapshot(struct ibd_throttle_status *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_it.lock);
    out->running          = g_it.running;
    out->blocks_per_sec   = g_it.blocks_per_sec;
    out->burst            = g_it.burst;
    out->tokens_available = g_it.tokens;
    out->acquired_count   = g_it.acquired_count;
    out->blocked_count    = g_it.blocked_count;
    out->total_wait_us    = g_it.total_wait_us;
    pthread_mutex_unlock(&g_it.lock);
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe — uses
 * the existing snapshot helper which already takes the throttle lock. */
bool ibd_throttle_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    struct ibd_throttle_status s = {0};
    ibd_throttle_status_snapshot(&s);
    json_set_object(out);
    json_push_kv_bool(out, "running", s.running);
    json_push_kv_int(out, "blocks_per_sec", s.blocks_per_sec);
    json_push_kv_int(out, "burst", s.burst);
    json_push_kv_real(out, "tokens_available", s.tokens_available);
    json_push_kv_int(out, "acquired_count", (int64_t)s.acquired_count);
    json_push_kv_int(out, "blocked_count", (int64_t)s.blocked_count);
    json_push_kv_int(out, "total_wait_us", s.total_wait_us);
    return true;
}
