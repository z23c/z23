// one-result-type-ok:json-dump-bool-only:mempool_limits_dump_state_json —
// mempool_limits_passes_min_relay is converted to struct zcl_result below.
// The sole remaining bool export is the native dump-state function;
// the dump convention (CLAUDE.md "Adding state introspection") mandates a
// bool return (false = couldn't populate), not struct zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mempool Limits — see header for rationale.
 *
 * Sorting: we snapshot (hash, fee, tx_size, time) and sort the
 * snapshot by fee-per-byte ascending. The worst entry goes
 * first. `enforce` then walks the sorted array removing from
 * the front until both byte and count budgets are met.
 *
 * Because we drop the pool lock between the snapshot and each
 * remove, another thread may remove or add entries between
 * steps. That's fine: `tx_mempool_remove` is a no-op if the
 * hash is gone, and new adds will re-trigger `enforce` via
 * the post-add hook. The worst case is a transiently-
 * over-budget pool for a few microseconds; we still converge
 * to the configured cap.
 *
 * Stats: simple scalar counters protected by the service mutex.
 * Intended for tests and future Prometheus export — not for
 * hot-path reads.
 */

#include "platform/time_compat.h"
#include "services/mempool_limits.h"
#include "validation/txmempool.h"
#include "event/event.h"
#include "json/json.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/mem_pressure.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

/* Supervisor deadline (sec). The loop ticks every tick_seconds
 * (default 60) and heartbeats at the top of each sub-second wake, so
 * 3x the default tick gives ample slack before a genuine wedge fires. */
#define MEMPOOL_LIMITS_SUPERVISOR_DEADLINE_SEC 180

/* ── Module state ───────────────────────────────────────────── */

struct mempool_limits_state {
    pthread_mutex_t lock;
    pthread_t       thread;
    bool            thread_running;
    bool            stop_requested;

    struct tx_mempool           *pool;
    struct mempool_limits_config cfg;

    /* Stats counters. */
    int64_t enforce_calls;
    int64_t expire_calls;
    int64_t evicted_total;
    int64_t expired_total;
    int64_t last_enforce_evicted;
    int64_t last_expire_expired;
    int64_t last_enforce_unix;
    int64_t last_expire_unix;

    /* Injected clock for expiry tests. */
    mempool_limits_clock_fn clock_fn;

    /* Supervisor liveness. loop_ticks advances once per
     * outer-loop wake so the supervisor sees forward progress between
     * the (sparse) enforce/expire runs. */
    _Atomic supervisor_child_id supervisor_id;
    _Atomic int64_t             loop_ticks;
};

static struct mempool_limits_state g_ml = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};

static struct liveness_contract g_ml_contract;

/* ── mem_pressure sink (Rung 1 follow-on, docs/adr/0003-os-substrate-
 * verdict.md) ──────────────────────────────────────────────────────
 * A REAL shrink target: mempool_limits_enforce() is the same eviction
 * path already run after every accepted tx (relay-layer data, never
 * consensus state — evicting a pending tx changes what this node relays,
 * not what any block can contain). Under pressure we call it with a
 * TEMPORARILY tightened budget (half at HIGH, a quarter at CRITICAL) so
 * the pool sheds bytes beyond its steady-state cap; the configured cap
 * itself (g_ml.cfg) is left untouched, so normal admission resumes at the
 * regular limit on the next accepted tx. */
static void ml_shrink_for_pressure(enum mem_pressure_level level, void *ctx)
{
    (void)ctx;

    pthread_mutex_lock(&g_ml.lock);
    struct tx_mempool *pool = g_ml.pool;
    struct mempool_limits_config tight = g_ml.cfg;
    pthread_mutex_unlock(&g_ml.lock);

    if (!pool)
        return;

    int64_t divisor = (level >= MEM_CRITICAL) ? 4 : 2;
    if (tight.max_bytes > 0) tight.max_bytes /= divisor;
    if (tight.max_tx_count > 0) tight.max_tx_count /= divisor;
    if (tight.max_bytes <= 0) tight.max_bytes = 1;
    if (tight.max_tx_count <= 0) tight.max_tx_count = 1;

    int evicted = mempool_limits_enforce(pool, &tight);
    if (evicted > 0)
        LOG_INFO("mempool_limits",
                 "mem_pressure shrink: level=%s evicted=%d "
                 "(tightened max_bytes=%lld max_tx_count=%lld)",
                 mem_pressure_level_name(level), evicted,
                 (long long)tight.max_bytes, (long long)tight.max_tx_count);
}

static struct mem_pressure_sink g_ml_pressure_sink = {
    .name = "mempool_limits",
    .shrink = ml_shrink_for_pressure,
    .ctx = NULL,
};

/* ── Supervisor liveness ────────────────────────────────────── */

static void ml_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_ml.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_ml.loop_ticks));
}

static void ml_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int64_t enforce = -1;
    int64_t expire = -1;
    if (pthread_mutex_trylock(&g_ml.lock) == 0) {
        enforce = g_ml.enforce_calls;
        expire = g_ml.expire_calls;
        pthread_mutex_unlock(&g_ml.lock);
    }
    LOG_WARN("mempool_limits",
             "[mempool_limits] supervisor stall reason=%s ticks=%lld enforce=%lld expire=%lld",
             reason, (long long)atomic_load(&g_ml.loop_ticks),
             (long long)enforce, (long long)expire);
}

static struct zcl_result ml_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-4, "mempool_limits: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_ml.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, MEMPOOL_LIMITS_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, atomic_load(&g_ml.loop_ticks));
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_ml_contract, "op.mempool_limits");
    atomic_store(&g_ml_contract.period_secs, 0);
    atomic_store(&g_ml_contract.deadline_secs,
                 MEMPOOL_LIMITS_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_ml_contract.progress_max_quiet_us, 0);
    g_ml_contract.on_stall = ml_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_op_sup, &g_ml_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-5, "mempool_limits: supervisor_register failed");
    atomic_store(&g_ml.supervisor_id, id);
    supervisor_progress(id, atomic_load(&g_ml.loop_ticks));
    supervisor_tick(id);
    return ZCL_OK;
}

/* ── Clock ──────────────────────────────────────────────────── */

/* Caller must NOT hold g_ml.lock — this function takes it. */
static int64_t ml_now_unix_locked_safe(void)
{
    mempool_limits_clock_fn fn;
    pthread_mutex_lock(&g_ml.lock);
    fn = g_ml.clock_fn;
    pthread_mutex_unlock(&g_ml.lock);
    if (fn) return fn();
    return (int64_t)platform_time_wall_time_t();
}

void mempool_limits_set_clock_fn(mempool_limits_clock_fn fn)
{
    pthread_mutex_lock(&g_ml.lock);
    g_ml.clock_fn = fn;
    pthread_mutex_unlock(&g_ml.lock);
}

/* ── Env parsing ────────────────────────────────────────────── */

static int64_t env_i64(const char *name, int64_t fallback)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long long parsed = strtoll(v, &end, 10);
    if (end == v || parsed <= 0) return fallback;
    return (int64_t)parsed;
}

static int env_int(const char *name, int fallback)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v || parsed <= 0) return fallback;
    return (int)parsed;
}

void mempool_limits_config_defaults(struct mempool_limits_config *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_bytes =
        env_i64("ZCL_MEMPOOL_MAX_BYTES", MEMPOOL_LIMITS_DEFAULT_MAX_BYTES);
    cfg->max_tx_count =
        env_i64("ZCL_MEMPOOL_MAX_TXS", MEMPOOL_LIMITS_DEFAULT_MAX_TX_COUNT);
    cfg->expiry_seconds =
        env_i64("ZCL_MEMPOOL_EXPIRY_SECONDS", MEMPOOL_LIMITS_DEFAULT_EXPIRY_SEC);
    cfg->min_relay_fee_zat =
        env_i64("ZCL_MIN_RELAY_FEE_ZAT", MEMPOOL_LIMITS_DEFAULT_MIN_RELAY);
    cfg->tick_seconds =
        env_int("ZCL_MEMPOOL_LIMITS_TICK_SEC", MEMPOOL_LIMITS_DEFAULT_TICK_SEC);
}

/* Fill in zeroed fields with hard defaults (never reads env).
 * Used by `enforce`/`expire` when a caller passes a partially
 * populated config from a test. */
static struct mempool_limits_config ml_resolve_cfg(
    const struct mempool_limits_config *in)
{
    struct mempool_limits_config r = {0};
    if (in) r = *in;
    if (r.max_bytes        <= 0) r.max_bytes        = MEMPOOL_LIMITS_DEFAULT_MAX_BYTES;
    if (r.max_tx_count     <= 0) r.max_tx_count     = MEMPOOL_LIMITS_DEFAULT_MAX_TX_COUNT;
    if (r.expiry_seconds   <= 0) r.expiry_seconds   = MEMPOOL_LIMITS_DEFAULT_EXPIRY_SEC;
    if (r.min_relay_fee_zat < 0) r.min_relay_fee_zat = MEMPOOL_LIMITS_DEFAULT_MIN_RELAY;
    if (r.tick_seconds     <= 0) r.tick_seconds     = MEMPOOL_LIMITS_DEFAULT_TICK_SEC;
    return r;
}

/* ── Min relay fee ──────────────────────────────────────────── */

struct zcl_result mempool_limits_passes_min_relay(
    const struct mempool_limits_config *cfg, int64_t fee, size_t tx_size)
{
    if (tx_size == 0)
        return ZCL_ERR(-1, "mempool_limits_passes_min_relay: tx_size=0");
    struct mempool_limits_config r = ml_resolve_cfg(cfg);
    if (fee < r.min_relay_fee_zat)
        return ZCL_ERR(-2,
                       "mempool_limits_passes_min_relay: fee %lld below "
                       "min relay %lld",
                       (long long)fee, (long long)r.min_relay_fee_zat);
    return ZCL_OK;
}

/* ── Fee-per-byte sort (ascending worst-first) ──────────────── */

/* Compare two non-negative fractions p/q and r/s (each part a
 * non-negative int64, denominators strictly positive) WITHOUT any
 * multiplication, via the Euclidean / continued-fraction algorithm.
 * Returns -1, 0 or +1 for p/q <,==,> r/s. Each step strictly shrinks
 * the operands, so this terminates. */
static int ml_cmp_frac(int64_t p, int64_t q, int64_t r, int64_t s)
{
    for (;;) {
        int64_t fp = p / q, fr = r / s;        /* integer (floor) parts */
        if (fp != fr) return fp < fr ? -1 : 1; // raw-return-ok:value-compare
        int64_t rp = p - fp * q;               /* remainders (in range) */
        int64_t rr = r - fr * s;
        if (rp == 0 && rr == 0) return 0;      /* both integers, equal */
        if (rp == 0) return -1;                // raw-return-ok:value-compare
        if (rr == 0) return  1;                // raw-return-ok:value-compare
        /* Fractional parts left: compare reciprocals (q/rp) vs (s/rr),
         * which flips the result — recurse with operands swapped. */
        int64_t np = s, nq = rr, nr = q, ns = rp;
        p = np; q = nq; r = nr; s = ns;
    }
}

/* Compare two non-negative products `a*b` and `c*d` (each operand a
 * non-negative int64) WITHOUT 2's-complement overflow. Returns -1, 0
 * or +1 for (a*b) <,==,> (c*d).
 *
 * Why this exists: the fee-per-byte comparator below cross-multiplies
 * fee*size. fee is bounded by MAX_MONEY (~2.1e15) and size by
 * MAX_TX_SIZE_AFTER_SAPLING (~1.0e5), so a product can reach ~2.1e20 —
 * far past INT64_MAX (~9.2e18). A raw int64 multiply silently wraps to
 * a small/negative value and inverts the eviction sort, so high-fee
 * txs get evicted while low-fee dust is retained, defeating the
 * DoS-protection eviction policy. We compare without ever forming an
 * out-of-range product. `__int128` would be exact but is rejected
 * under -Werror=pedantic in app code, so this stays strict-ISO-C.
 *
 * Strategy: guard each multiply against overflow. If neither overflows
 * INT64_MAX, compare the exact products. If exactly one overflows that
 * side is the larger (all operands non-negative ⇒ its true product
 * strictly exceeds any in-range one). If both overflow, compare the
 * equivalent fractions a/c vs d/b with the multiplication-free helper.
 * Callers clamp b and c (the cross denominators) to >= 1. */
static int ml_cmp_products(int64_t a, int64_t b, int64_t c, int64_t d)
{
    bool lhs_of = (a != 0 && b > INT64_MAX / a);
    bool rhs_of = (c != 0 && d > INT64_MAX / c);
    if (!lhs_of && !rhs_of) {
        int64_t lhs = a * b;
        int64_t rhs = c * d;
        if (lhs < rhs) return -1; // raw-return-ok:value-compare
        if (lhs > rhs) return  1; // raw-return-ok:value-compare
        return 0;
    }
    if (lhs_of != rhs_of) return lhs_of ? 1 : -1; // raw-return-ok:value-compare
    /* Both overflow: a*b ? c*d  ⇔  a/c ? d/b  (c>0, b>0). */
    return ml_cmp_frac(a, c, d, b);
}

static int ml_fpb_cmp(const void *a, const void *b)
{
    const struct tx_mempool_entry_view *av = a;
    const struct tx_mempool_entry_view *bv = b;
    /* Compare fee/size as cross-multiplication to avoid floating
     * point:  (a.fee * b.size) vs (b.fee * a.size). Done through an
     * overflow-safe helper because fee*size can exceed INT64_MAX. */
    int64_t a_size = (int64_t)(av->tx_size ? av->tx_size : 1);
    int64_t b_size = (int64_t)(bv->tx_size ? bv->tx_size : 1);
    int cmp = ml_cmp_products(av->fee, b_size, bv->fee, a_size);
    if (cmp < 0) return -1; // raw-return-ok:qsort-comparator
    if (cmp > 0) return  1;
    /* Tie-break: older first (earlier `time` ⇒ evict sooner). */
    if (av->time < bv->time) return -1; // raw-return-ok:qsort-comparator
    if (av->time > bv->time) return  1;
    return 0;
}

/* ── Enforce ────────────────────────────────────────────────── */

int mempool_limits_enforce(struct tx_mempool *pool,
                            const struct mempool_limits_config *cfg_in)
{
    if (!pool) return 0;
    struct mempool_limits_config cfg = ml_resolve_cfg(cfg_in);

    /* Snapshot current sizes. If we're already under both caps,
     * there's nothing to do — this is the hot-path early exit
     * that every add goes through. */
    size_t cur_count = tx_mempool_size(pool);
    uint64_t cur_bytes = tx_mempool_total_size(pool);
    if ((int64_t)cur_count <= cfg.max_tx_count &&
        (int64_t)cur_bytes <= cfg.max_bytes) {
        int64_t now = ml_now_unix_locked_safe();
        pthread_mutex_lock(&g_ml.lock);
        g_ml.enforce_calls++;
        g_ml.last_enforce_unix = now;
        g_ml.last_enforce_evicted = 0;
        pthread_mutex_unlock(&g_ml.lock);
        return 0;
    }

    /* Need to evict. Allocate a snapshot buffer. */
    size_t cap = cur_count;
    struct tx_mempool_entry_view *views =
        zcl_calloc(cap, sizeof(*views), "mempool enforce views");
    if (!views) return 0;

    size_t n = tx_mempool_collect_views(pool, views, cap);
    if (n == 0) { free(views); return 0; }

    qsort(views, n, sizeof(*views), ml_fpb_cmp);

    uint64_t bytes_before = cur_bytes;
    int evicted = 0;
    const char *reason = "size";
    /* Walk worst-first removing entries until we fit both caps. */
    for (size_t i = 0; i < n; i++) {
        size_t count_after = tx_mempool_size(pool);
        uint64_t bytes_after = tx_mempool_total_size(pool);
        bool over_bytes = (int64_t)bytes_after > cfg.max_bytes;
        bool over_count = (int64_t)count_after > cfg.max_tx_count;
        if (!over_bytes && !over_count) break;
        reason = over_bytes ? "size" : "count";
        tx_mempool_remove(pool, &views[i].hash);
        evicted++;
    }
    uint64_t bytes_after_final = tx_mempool_total_size(pool);

    free(views);

    int64_t now_after = ml_now_unix_locked_safe();
    pthread_mutex_lock(&g_ml.lock);
    g_ml.enforce_calls++;
    g_ml.evicted_total    += evicted;
    g_ml.last_enforce_evicted = evicted;
    g_ml.last_enforce_unix = now_after;
    pthread_mutex_unlock(&g_ml.lock);

    if (evicted > 0) {
        event_emitf(EV_MEMPOOL_EVICT, 0,
                    "reason=%s evicted=%d bytes_before=%" PRIu64
                    " bytes_after=%" PRIu64 " cap_bytes=%" PRId64
                    " cap_txs=%" PRId64,
                    reason, evicted,
                    bytes_before, bytes_after_final,
                    cfg.max_bytes, cfg.max_tx_count);
    }
    return evicted;
}

/* ── Expire ─────────────────────────────────────────────────── */

int mempool_limits_expire(struct tx_mempool *pool,
                           const struct mempool_limits_config *cfg_in)
{
    if (!pool) return 0;
    struct mempool_limits_config cfg = ml_resolve_cfg(cfg_in);

    size_t cur_count = tx_mempool_size(pool);
    int64_t now = ml_now_unix_locked_safe();
    if (cur_count == 0) {
        pthread_mutex_lock(&g_ml.lock);
        g_ml.expire_calls++;
        g_ml.last_expire_unix = now;
        g_ml.last_expire_expired = 0;
        pthread_mutex_unlock(&g_ml.lock);
        return 0;
    }

    struct tx_mempool_entry_view *views =
        zcl_calloc(cur_count, sizeof(*views), "mempool expire views");
    if (!views) return 0;
    size_t n = tx_mempool_collect_views(pool, views, cur_count);

    int64_t cutoff = now - cfg.expiry_seconds;
    int expired = 0;
    for (size_t i = 0; i < n; i++) {
        if (views[i].time <= cutoff) {
            tx_mempool_remove(pool, &views[i].hash);
            expired++;
        }
    }
    free(views);

    pthread_mutex_lock(&g_ml.lock);
    g_ml.expire_calls++;
    g_ml.expired_total += expired;
    g_ml.last_expire_expired = expired;
    g_ml.last_expire_unix = now;
    pthread_mutex_unlock(&g_ml.lock);

    if (expired > 0) {
        event_emitf(EV_MEMPOOL_EXPIRE, 0,
                    "expired=%d cutoff_unix=%" PRId64 " age_sec=%" PRId64,
                    expired, cutoff, cfg.expiry_seconds);
    }
    return expired;
}

/* ── Stats ──────────────────────────────────────────────────── */

void mempool_limits_stats_snapshot(struct mempool_limits_stats *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_ml.lock);
    out->running              = g_ml.thread_running;
    out->enforce_calls        = g_ml.enforce_calls;
    out->expire_calls         = g_ml.expire_calls;
    out->evicted_total        = g_ml.evicted_total;
    out->expired_total        = g_ml.expired_total;
    out->last_enforce_evicted = g_ml.last_enforce_evicted;
    out->last_expire_expired  = g_ml.last_expire_expired;
    out->last_enforce_unix    = g_ml.last_enforce_unix;
    out->last_expire_unix     = g_ml.last_expire_unix;
    pthread_mutex_unlock(&g_ml.lock);
}

void mempool_limits_reset_stats(void)
{
    pthread_mutex_lock(&g_ml.lock);
    g_ml.enforce_calls = 0;
    g_ml.expire_calls = 0;
    g_ml.evicted_total = 0;
    g_ml.expired_total = 0;
    g_ml.last_enforce_evicted = 0;
    g_ml.last_expire_expired = 0;
    g_ml.last_enforce_unix = 0;
    g_ml.last_expire_unix = 0;
    pthread_mutex_unlock(&g_ml.lock);
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe — defers
 * to the existing snapshot helper which takes the service lock. */
bool mempool_limits_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    struct mempool_limits_stats s = {0};
    mempool_limits_stats_snapshot(&s);
    json_set_object(out);
    json_push_kv_bool(out, "running", s.running);
    json_push_kv_int(out, "enforce_calls", s.enforce_calls);
    json_push_kv_int(out, "expire_calls", s.expire_calls);
    json_push_kv_int(out, "evicted_total", s.evicted_total);
    json_push_kv_int(out, "expired_total", s.expired_total);
    json_push_kv_int(out, "last_enforce_evicted", s.last_enforce_evicted);
    json_push_kv_int(out, "last_expire_expired", s.last_expire_expired);
    json_push_kv_int(out, "last_enforce_unix", s.last_enforce_unix);
    json_push_kv_int(out, "last_expire_unix", s.last_expire_unix);
    return true;
}

/* ── Post-add hook (registered with txmempool) ──────────────── */

static void ml_post_add_hook(struct tx_mempool *pool)
{
    /* `cfg` is read without a lock — it was filled in once at
     * start() and never mutated afterwards. Pool pointer we
     * receive from the hook is the same one we registered with,
     * but we defensively use it directly (test scenarios can
     * rewire). */
    (void)mempool_limits_enforce(pool, &g_ml.cfg);
}

/* ── Thread loop ────────────────────────────────────────────── */

static void *ml_thread_fn(void *arg)
{
    (void)arg;
    int tick;
    pthread_mutex_lock(&g_ml.lock);
    tick = g_ml.cfg.tick_seconds > 0
         ? g_ml.cfg.tick_seconds
         : MEMPOOL_LIMITS_DEFAULT_TICK_SEC;
    pthread_mutex_unlock(&g_ml.lock);

    struct timespec now;
    platform_time_monotonic_timespec(&now);
    int64_t now_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    int64_t next_at_ms = now_ms + (int64_t)tick * 1000;

    while (true) {
        pthread_mutex_lock(&g_ml.lock);
        bool stop = g_ml.stop_requested;
        pthread_mutex_unlock(&g_ml.lock);
        if (stop) break;

        atomic_fetch_add(&g_ml.loop_ticks, 1);
        ml_supervisor_heartbeat();

        platform_time_monotonic_timespec(&now);
        now_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
        if (now_ms >= next_at_ms) {
            struct tx_mempool *pool;
            struct mempool_limits_config cfg;
            pthread_mutex_lock(&g_ml.lock);
            pool = g_ml.pool;
            cfg  = g_ml.cfg;
            pthread_mutex_unlock(&g_ml.lock);
            if (pool) {
                (void)mempool_limits_expire(pool, &cfg);
                (void)mempool_limits_enforce(pool, &cfg);
            }
            next_at_ms = now_ms + (int64_t)cfg.tick_seconds * 1000;
        }
        platform_sleep_ms(100);
    }

    pthread_mutex_lock(&g_ml.lock);
    g_ml.thread_running = false;
    pthread_mutex_unlock(&g_ml.lock);
    return NULL;
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct zcl_result mempool_limits_start(struct tx_mempool *pool,
                           const struct mempool_limits_config *cfg_in)
{
    if (!pool) return ZCL_ERR(-1, "start called with null pool");

    pthread_mutex_lock(&g_ml.lock);
    if (g_ml.thread_running) {
        pthread_mutex_unlock(&g_ml.lock);
        return ZCL_ERR(-2, "start called but thread already running");
    }
    g_ml.pool = pool;
    g_ml.cfg  = ml_resolve_cfg(cfg_in);
    g_ml.stop_requested = false;
    g_ml.thread_running = true;
    pthread_mutex_unlock(&g_ml.lock);

    /* Idempotent (mem_pressure_register_sink no-ops on a pointer already
     * registered) — safe to call on every start, including a stop/restart
     * cycle. */
    (void)mem_pressure_register_sink(&g_ml_pressure_sink);

    /* Register the acceptance hook before the thread starts so
     * any concurrent add is already subject to enforcement. */
    tx_mempool_set_post_add_hook(ml_post_add_hook);

    int rc = thread_registry_spawn("zcl_mempool_lim", ml_thread_fn, NULL,
                                       &g_ml.thread);
    if (rc != 0) {
        tx_mempool_set_post_add_hook(NULL);
        pthread_mutex_lock(&g_ml.lock);
        g_ml.thread_running = false;
        pthread_mutex_unlock(&g_ml.lock);
        return ZCL_ERR(-3, "thread_registry_spawn failed (%d)", rc);
    }

    struct zcl_result sup_r = ml_register_supervisor();
    if (!sup_r.ok) {
        mempool_limits_stop();
        return sup_r;
    }
    return ZCL_OK;
}

void mempool_limits_stop(void)
{
    pthread_t th;
    bool joinable = false;

    /* Unregister hook first so any in-flight add stops calling
     * us. This is racy-but-benign: a hook call that started
     * before we clear the pointer still sees the service state
     * (pool, cfg) — that's fine while shutdown is in progress. */
    tx_mempool_set_post_add_hook(NULL);

    supervisor_child_id id = atomic_load(&g_ml.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);

    pthread_mutex_lock(&g_ml.lock);
    if (g_ml.thread_running) {
        g_ml.stop_requested = true;
        th = g_ml.thread;
        joinable = true;
    }
    pthread_mutex_unlock(&g_ml.lock);

    if (joinable) {
        pthread_join(th, NULL);
        pthread_mutex_lock(&g_ml.lock);
        g_ml.thread_running = false;
        g_ml.stop_requested = false;
        g_ml.pool = NULL;
        pthread_mutex_unlock(&g_ml.lock);
    }
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_ml.supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}
