/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * IBD Throttle — token-bucket rate limiter for block commit.
 *
 * Motivation
 * ----------
 * During Initial Block Download (IBD) a single firehose peer can
 * feed `process_block` → `update_coins` → SQLite faster than any
 * other subsystem on the node can keep up. That means:
 *
 *   - The mempool acceptance path (shared DB writer) stalls.
 *   - `wallet_backup_service` can't grab its write lock in time.
 *   - `db_maintenance`'s WAL checkpoint runs back-to-back with
 *     the IBD writer and falls behind.
 *   - The scheduler thread starves waiting on the event ring
 *     because the IBD writer never yields.
 *
 * This service sits between `process_block` and `update_coins`
 * (and the subsequent disk commit) as a classic token-bucket:
 * callers must `ibd_throttle_acquire()` one token per block
 * before taking the DB write lock. Tokens refill at a steady rate
 * (`blocks_per_sec`) up to a small burst ceiling so the node can
 * absorb short spikes without penalty. When the bucket is empty,
 * `acquire()` sleeps in 1ms increments until a token becomes
 * available — no condvars, no signalling, keep it simple.
 *
 * Tunables
 * --------
 *   ZCL_IBD_BLOCKS_PER_SEC  (default 500)
 *   ZCL_IBD_BURST           (default 50)
 *
 * Design notes
 * ------------
 * - The token count is floating-point so fractional refill
 *   between sub-millisecond events doesn't drop tokens on the
 *   floor.
 * - `ibd_throttle_refill` is the pure primitive used by both the
 *   thread-aware `acquire()` wrapper and the unit tests. It
 *   takes the current token count, rate, burst, and elapsed
 *   microseconds and returns the new token count — no globals,
 *   no time calls, fully deterministic.
 * - `acquire()` loops calling `try_acquire()` after each sleep
 *   so tests using `try_acquire()` exclusively don't have to
 *   wait on real wall-clock time.
 * - When the throttle has not been started, `acquire()` is a
 *   no-op that returns `true`. This lets callers unconditionally
 *   call it even on archival nodes without throttling configured.
 *
 * Event emission
 * --------------
 * Emitting an event on every blocked acquire would be too noisy
 * during genuine IBD saturation. Instead, when the blocked count
 * accumulates (at least one block waited longer than the refill
 * interval) the service rate-limits `EV_IBD_THROTTLED` to at most
 * once every 60 seconds with aggregated stats.
 */

#ifndef ZCL_SERVICES_IBD_THROTTLE_H
#define ZCL_SERVICES_IBD_THROTTLE_H
/* See ibd_throttle.c for the one-result-type-ok marker covering
 * ibd_throttle_is_running / ibd_throttle_try_acquire (pure predicates) and
 * ibd_throttle_dump_state_json (the mandated dump-bool contract).
 * ibd_throttle_acquire is converted to struct zcl_result below. */

#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>

/* ── Defaults ───────────────────────────────────────────────── */

#define IBD_THROTTLE_DEFAULT_BLOCKS_PER_SEC  500
#define IBD_THROTTLE_DEFAULT_BURST            50

/* ── Config ─────────────────────────────────────────────────── */

struct ibd_throttle_config {
    int64_t blocks_per_sec;   /* 0 = use default (500) */
    int64_t burst;            /* 0 = use default (50)  */
};

/* Fill with compile-time defaults (no env lookup). */
void ibd_throttle_config_defaults(struct ibd_throttle_config *cfg);

/* Fill with defaults then overlay any ZCL_IBD_* env vars. */
void ibd_throttle_config_from_env(struct ibd_throttle_config *cfg);

/* ── Status snapshot ────────────────────────────────────────── */

struct ibd_throttle_status {
    bool     running;
    int64_t  blocks_per_sec;      /* resolved */
    int64_t  burst;               /* resolved */
    double   tokens_available;    /* current */
    uint64_t acquired_count;      /* successful acquires (total) */
    uint64_t blocked_count;       /* acquires that had to wait */
    int64_t  total_wait_us;       /* cumulative wall-time spent blocked */
};

void ibd_throttle_status_snapshot(struct ibd_throttle_status *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * Wired into `z23 dumpstate ibd_throttle`. */
struct json_value;
bool ibd_throttle_dump_state_json(struct json_value *out, const char *key);

/* ── Lifecycle ──────────────────────────────────────────────── */

/* Start the throttle with the given config. `cfg` may be NULL,
 * in which case the env-derived defaults are used. Returns ZCL_OK
 * on success; a non-ok result if already running. */
struct zcl_result ibd_throttle_start(const struct ibd_throttle_config *cfg);

/* Stop the throttle. After this returns `acquire()` is a no-op
 * again. Safe to call when not running. */
void ibd_throttle_stop(void);

/* True if `ibd_throttle_start` has been called and not yet stopped. */
bool ibd_throttle_is_running(void);

/* ── Hot-path ───────────────────────────────────────────────── */

/* Acquire 1 token. When the bucket is empty, sleeps in 1ms
 * increments until a token is available. Always returns ZCL_OK
 * (the only way this returns a non-ok result is if the service
 * rejects the caller entirely, which it never does today — the
 * zcl_result surface is here so a future rejection path has
 * somewhere to report a reason). When not running, returns ZCL_OK
 * immediately without consuming anything.
 *
 * Safe to call from any thread. */
struct zcl_result ibd_throttle_acquire(void);

/* Non-blocking variant: consume 1 token if available. Returns
 * true on success, false if the bucket was empty. Tests use this
 * to drive deterministic accounting. When not running, returns
 * true immediately (consistent with acquire()). */
bool ibd_throttle_try_acquire(void);

/* ── Testable primitives (no globals, no time/sleep) ────────── */

/* Returns the new token count after refilling for `elapsed_us`
 * microseconds at `rate_per_sec` tokens/sec, capped at `burst`.
 * Safe to call with `current_tokens < 0` (treated as 0).
 * Safe to call with `rate_per_sec <= 0` (returns unchanged). */
double ibd_throttle_refill(double current_tokens,
                           double rate_per_sec,
                           double burst,
                           int64_t elapsed_us);

#endif /* ZCL_SERVICES_IBD_THROTTLE_H */
