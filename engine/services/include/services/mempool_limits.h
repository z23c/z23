/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mempool Limits — resource caps & expiry for `struct tx_mempool`.
 *
 * Motivation
 * ----------
 * Without limits, a malicious peer can exhaust node memory by
 * flooding low-fee-per-byte transactions. The in-tree mempool has
 * a single 300 MB wall (`core/modules/validation/src/txmempool.c:216`) that
 * stops the bleed but doesn't let good transactions replace bad
 * ones, and has no count cap, no expiry, and no configurable
 * minimum relay fee. This service layers policy on top of the
 * data structure without touching the data structure itself.
 *
 * How it works
 * ------------
 *   enforce  — called after every `tx_mempool_add_unchecked`.
 *              While the pool is over `max_bytes` or `max_tx_count`,
 *              it snapshots (hash, fee, tx_size, time), sorts by
 *              fee-per-byte ascending, and removes the worst entry.
 *              Emits `EV_MEMPOOL_EVICT` with a summary string.
 *
 *   expire   — called periodically from the service's pthread.
 *              Snapshots once, picks everything older than
 *              `expiry_seconds`, removes each. Emits
 *              `EV_MEMPOOL_EXPIRE` with a count.
 *
 * Wiring
 * ------
 *   mempool_limits_start(pool, cfg) does two things:
 *     1. Registers `tx_mempool_set_post_add_hook` so that every
 *        successful add triggers `mempool_limits_enforce`.
 *     2. Launches a background pthread that calls
 *        `mempool_limits_expire` every `tick_seconds`.
 *
 *   mempool_limits_stop() unregisters the hook and joins the
 *   thread. Safe to call from any thread; idempotent.
 *
 * Thread safety
 * -------------
 * Every operation re-acquires `pool->cs` via the mempool's own
 * API (`tx_mempool_collect_views`, `tx_mempool_remove`). We never
 * hold the pool lock and a service lock simultaneously, so no
 * inversion is possible. The service lock protects only lifecycle
 * + stats counters.
 *
 * Test seams
 * ----------
 * - `mempool_limits_enforce` and `mempool_limits_expire` are
 *   pure: `(pool, config) → (evicted|expired count)`. Tests call
 *   them directly without starting the thread.
 * - `mempool_limits_set_clock_fn(fn)` injects a fake wall clock so
 *   expiry tests don't have to sleep.
 */

#ifndef ZCL_SERVICES_MEMPOOL_LIMITS_H
#define ZCL_SERVICES_MEMPOOL_LIMITS_H

#include "platform/time_compat.h"
#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct tx_mempool;

/* ── Defaults ────────────────────────────────────────────────
 * Values are generous enough that a correctly-configured mainnet
 * node never notices them, but tight enough that a firehose of
 * dust transactions can't blow past 512 MB RSS before we push
 * back. Environment overrides are read once in
 * `mempool_limits_config_defaults`.
 *
 *   ZCL_MEMPOOL_MAX_BYTES       int64  (default 300 MB)
 *   ZCL_MEMPOOL_MAX_TXS         int64  (default 50 000)
 *   ZCL_MEMPOOL_EXPIRY_SECONDS  int64  (default 72*3600 = 72 h)
 *   ZCL_MIN_RELAY_FEE_ZAT       int64  (default 100 zatoshi)
 *   ZCL_MEMPOOL_LIMITS_TICK_SEC int    (default 60 s)
 */

#define MEMPOOL_LIMITS_DEFAULT_MAX_BYTES    (int64_t)(300LL * 1024 * 1024)
#define MEMPOOL_LIMITS_DEFAULT_MAX_TX_COUNT (int64_t)50000
#define MEMPOOL_LIMITS_DEFAULT_EXPIRY_SEC   (int64_t)(72LL * 3600)
#define MEMPOOL_LIMITS_DEFAULT_MIN_RELAY    (int64_t)100
#define MEMPOOL_LIMITS_DEFAULT_TICK_SEC     60

/* ── Config ─────────────────────────────────────────────────── */

struct mempool_limits_config {
    int64_t max_bytes;             /* 0 = use default */
    int64_t max_tx_count;          /* 0 = use default */
    int64_t expiry_seconds;        /* 0 = use default */
    int64_t min_relay_fee_zat;     /* 0 = use default — advisory (enforced by callers) */
    int     tick_seconds;          /* 0 = use default */
};

/* Populate from defaults, then apply the `ZCL_MEMPOOL_*` env
 * overrides if present. Env parsing is permissive: unparseable
 * values silently fall back to the default for that field. */
void mempool_limits_config_defaults(struct mempool_limits_config *cfg);

/* ── Stats snapshot ─────────────────────────────────────────── */

struct mempool_limits_stats {
    bool    running;
    int64_t enforce_calls;
    int64_t expire_calls;
    int64_t evicted_total;            /* across all calls */
    int64_t expired_total;            /* across all calls */
    int64_t last_enforce_evicted;     /* most recent enforce return value */
    int64_t last_expire_expired;      /* most recent expire return value */
    int64_t last_enforce_unix;        /* 0 if never */
    int64_t last_expire_unix;         /* 0 if never */
};

void mempool_limits_stats_snapshot(struct mempool_limits_stats *out);
void mempool_limits_reset_stats(void); /* test helper */

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * Wired into `z23 dumpstate mempool_limits`. */
struct json_value;
bool mempool_limits_dump_state_json(struct json_value *out, const char *key);

/* ── Synchronous operations (test-callable) ─────────────────── */

/* Evict lowest fee-per-byte entries until `pool` is within
 * both `max_bytes` and `max_tx_count`. Returns the number of
 * entries removed (0 if already within limits). NULL/invalid
 * inputs return 0. Emits `EV_MEMPOOL_EVICT` exactly once per
 * non-zero call with a summary payload. */
int mempool_limits_enforce(struct tx_mempool *pool,
                            const struct mempool_limits_config *cfg);

/* Remove entries whose `time` field is older than
 * `now - expiry_seconds`. Returns number removed. Uses the
 * injected clock (`mempool_limits_set_clock_fn`) if one is set,
 * otherwise `platform_time_wall_time_t()`. Emits `EV_MEMPOOL_EXPIRE` on non-zero
 * removal counts. */
int mempool_limits_expire(struct tx_mempool *pool,
                           const struct mempool_limits_config *cfg);

/* Advisory min-relay-fee check — ZCL_OK when `(fee, tx_size)` meets
 * `min_relay_fee_zat` as an absolute floor, ZCL_ERR (with a reason)
 * otherwise. Integration callers use this at acceptance time to reject
 * sub-minimum txs before they ever enter the mempool. Zero-size txs
 * are a ZCL_ERR. */
struct zcl_result mempool_limits_passes_min_relay(
    const struct mempool_limits_config *cfg, int64_t fee, size_t tx_size);

/* ── Lifecycle ──────────────────────────────────────────────── */

/* Start background expiry thread and register the post-add hook.
 * Stores `pool` and `cfg` internally — both must outlive the
 * service (typical pattern: globals owned by boot). Safe to call
 * from any thread, idempotent across a matching stop(). Returns
 * ZCL_OK on a successful start; a non-ok result carries the reason
 * it could not start (NULL pool, already running, or spawn failure). */
struct zcl_result mempool_limits_start(struct tx_mempool *pool,
                           const struct mempool_limits_config *cfg);

/* Stop background thread and unregister the hook. Safe to call
 * multiple times; no-op when already stopped. */
void mempool_limits_stop(void);

/* ── Test seams ─────────────────────────────────────────────── */

/* Inject a fake wall clock for deterministic expiry tests.
 * `fn` returns seconds since Unix epoch. Pass NULL to revert to
 * the real `platform_time_wall_time_t()`. */
typedef int64_t (*mempool_limits_clock_fn)(void);
void mempool_limits_set_clock_fn(mempool_limits_clock_fn fn);

#endif /* ZCL_SERVICES_MEMPOOL_LIMITS_H */
