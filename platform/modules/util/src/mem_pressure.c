/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mem_pressure — implementation. See util/mem_pressure.h. */

#include "util/mem_pressure.h"

#include "health/heartbeat.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "platform/allocator_compat.h"

/* ── Env-tunable threshold percentages (sane defaults) ───────────── */

#define MEM_PRESSURE_DEFAULT_ELEVATED_PCT 50
#define MEM_PRESSURE_DEFAULT_HIGH_PCT     75
#define MEM_PRESSURE_DEFAULT_CRITICAL_PCT 90

struct mem_pressure_thresholds {
    int elevated_pct;
    int high_pct;
    int critical_pct;
};

static int env_pct(const char *name, int fallback)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v || parsed <= 0 || parsed > 100) return fallback;
    return (int)parsed;
}

static void mem_pressure_thresholds_from_env(struct mem_pressure_thresholds *t)
{
    t->elevated_pct = env_pct("ZCL_MEM_PRESSURE_ELEVATED_PCT",
                              MEM_PRESSURE_DEFAULT_ELEVATED_PCT);
    t->high_pct = env_pct("ZCL_MEM_PRESSURE_HIGH_PCT",
                          MEM_PRESSURE_DEFAULT_HIGH_PCT);
    t->critical_pct = env_pct("ZCL_MEM_PRESSURE_CRITICAL_PCT",
                              MEM_PRESSURE_DEFAULT_CRITICAL_PCT);
    /* A misconfigured (non-monotonic) env override would make the ladder
     * non-sensical (e.g. HIGH lower than ELEVATED); fall back to the full
     * default set rather than serve a broken ladder. */
    if (!(t->elevated_pct < t->high_pct && t->high_pct < t->critical_pct)) {
        t->elevated_pct = MEM_PRESSURE_DEFAULT_ELEVATED_PCT;
        t->high_pct = MEM_PRESSURE_DEFAULT_HIGH_PCT;
        t->critical_pct = MEM_PRESSURE_DEFAULT_CRITICAL_PCT;
    }
}

/* ── State ─────────────────────────────────────────────────────── */

static pthread_mutex_t g_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mem_pressure_sink *g_sinks[MEM_PRESSURE_MAX_SINKS];
static int g_sink_count;

static _Atomic int g_level = MEM_NOMINAL;
static _Atomic int64_t g_last_poll_unix;
static _Atomic int64_t g_current_bytes = -1;
static _Atomic int64_t g_denominator_bytes = -1;
static _Atomic int g_denominator_basis; /* enum below, stored as int for atomics */
static _Atomic int64_t g_last_rss_bytes = -1;
static _Atomic int64_t g_charged_bytes = -1;
static _Atomic int64_t g_evictable_bytes = -1;
static health_subsystem_id g_health_id = HEALTH_INVALID_ID;

enum mem_pressure_denominator_basis {
    MEM_PRESSURE_BASIS_NONE = 0,
    MEM_PRESSURE_BASIS_CGROUP_HIGH,
    MEM_PRESSURE_BASIS_CGROUP_MAX,
    MEM_PRESSURE_BASIS_SYS_AVAILABLE,
    MEM_PRESSURE_BASIS_SYS_TOTAL,
};

static const char *basis_name(enum mem_pressure_denominator_basis b)
{
    switch (b) {
    case MEM_PRESSURE_BASIS_CGROUP_HIGH: return "cgroup_high";
    case MEM_PRESSURE_BASIS_CGROUP_MAX:  return "cgroup_max";
    case MEM_PRESSURE_BASIS_SYS_AVAILABLE: return "system_available";
    case MEM_PRESSURE_BASIS_SYS_TOTAL:   return "sys_total";
    default:                             return "unavailable";
    }
}

const char *mem_pressure_level_name(enum mem_pressure_level level)
{
    switch (level) {
    case MEM_NOMINAL:  return "nominal";
    case MEM_ELEVATED: return "elevated";
    case MEM_HIGH:     return "high";
    case MEM_CRITICAL: return "critical";
    default:           return "unknown";
    }
}

/* ── Built-in default sink: malloc_trim ──────────────────────────
 *
 * The exact idiom already used at engine/services/src/bg_validation_service.c,
 * engine/services/src/consensus_snapshot_export_service.c, and
 * core/modules/net/src/fast_sync.c after bulk transient-heap churn: glibc keeps
 * freed chunks in its arenas instead of returning them to the OS, so
 * RESIDENT memory stair-steps upward and never falls back on its own.
 * malloc_trim(0) hands retained-but-unused pages back to the kernel. This
 * is purely memory discipline — it frees no live data, touches no
 * consensus state, and is always safe to call. */
static void mem_pressure_shrink_malloc_trim(enum mem_pressure_level level,
                                            void *ctx)
{
    (void)level;
    (void)ctx;
    platform_allocator_release_free_pages();
}

static struct mem_pressure_sink g_malloc_trim_sink = {
    .name = "malloc_trim",
    .shrink = mem_pressure_shrink_malloc_trim,
    .ctx = NULL,
};

/* Idempotent (mem_pressure_register_sink no-ops on a pointer already in the
 * registry) — cheap enough (<=16-entry linear scan under a mutex) to call
 * on every tick/start rather than latch with a separate one-shot flag,
 * which keeps mem_pressure_reset_for_testing() simple: clearing the
 * registry is enough to make the next tick re-install this sink. */
static void mem_pressure_ensure_builtin_sinks(void)
{
    (void)mem_pressure_register_sink(&g_malloc_trim_sink);
}

/* ── Registry ─────────────────────────────────────────────────── */

bool mem_pressure_register_sink(struct mem_pressure_sink *sink)
{
    if (!sink || !sink->shrink)
        LOG_FAIL("mem_pressure",
                 "register_sink: NULL sink or NULL shrink callback");

    pthread_mutex_lock(&g_registry_lock);
    for (int i = 0; i < g_sink_count; i++) {
        if (g_sinks[i] == sink) {
            pthread_mutex_unlock(&g_registry_lock);
            return true; /* idempotent re-registration */
        }
    }
    if (g_sink_count >= MEM_PRESSURE_MAX_SINKS) {
        pthread_mutex_unlock(&g_registry_lock);
        LOG_FAIL("mem_pressure",
                 "register_sink: registry full (cap=%d), dropping '%s'",
                 MEM_PRESSURE_MAX_SINKS, sink->name ? sink->name : "?");
    }
    atomic_store(&sink->last_shrink_unix, 0);
    atomic_store(&sink->shrink_calls, 0);
    g_sinks[g_sink_count++] = sink;
    pthread_mutex_unlock(&g_registry_lock);
    return true;
}

enum mem_pressure_level mem_pressure_current(void)
{
    return (enum mem_pressure_level)atomic_load(&g_level);
}

/* ── Level computation ────────────────────────────────────────── */

static enum mem_pressure_level classify(int64_t current_bytes,
                                        int64_t denom_bytes,
                                        const struct mem_pressure_thresholds *t)
{
    if (current_bytes < 0 || denom_bytes <= 0)
        return MEM_NOMINAL; /* raw-return-ok:unknown-defaults-to-nominal */

    /* Integer percentage compare without overflow: current*100 can exceed
     * INT64_MAX only for absurd (>92 exabyte) inputs — not reachable on any
     * real host, but guard anyway per the pedantic-attack-surface doctrine. */
    if (current_bytes > (INT64_MAX / 100))
        return MEM_CRITICAL; /* raw-return-ok:overflow-guard-fail-safe-high */

    int64_t pct = (current_bytes * 100) / denom_bytes;
    if (pct >= t->critical_pct) return MEM_CRITICAL;
    if (pct >= t->high_pct)     return MEM_HIGH;
    if (pct >= t->elevated_pct) return MEM_ELEVATED;
    return MEM_NOMINAL;
}


/* Droppable page cache in a cgroup's charge, or -1 for "not known".
 *
 * The droppable tier is the page cache the kernel can reclaim by simply
 * dropping a clean page: memory.stat `file` LESS every part of it that the
 * kernel cannot drop on demand. `shmem` needs a swap write, `unevictable` is
 * mlocked, and `file_dirty`/`file_writeback` must reach the disk first — on
 * an HDD box a bulk block/WAL flush pins hundreds of MiB there for seconds
 * at a time, and a cgroup throttled against exactly those pages must not
 * read NOMINAL because they happen to sit in the `file` row.
 *
 * Every row must be readable before anything is subtracted, and every row
 * is checked RAW against `cgroup_current` before any arithmetic combines
 * them: memory.stat and memory.current are two files sampled at different
 * instants, so a torn read can make any single row -- not only a derived
 * combination -- larger than the charge it is supposed to be part of. A
 * present `file` with an unreadable `shmem`, `file_dirty` or any other
 * exclusion would otherwise subtract a tier that is provably not droppable,
 * which under-reports pressure -- the wrong direction to guess in. Checking
 * only a derived value (e.g. `file` minus the exclusions) against the charge
 * is not enough: shmem=3 GiB against file=12 GiB and current=10.18 GiB
 * derives evictable=9 GiB, which reads as UNDER the charge and never trips
 * a derived-only guard, even though the raw `file` row alone already
 * exceeds `current` and proves the read is torn. An unreadable OR
 * inconsistent row makes the whole tier UNKNOWN (-1), a different fact from
 * a readable zero, and is published as one. */
static int64_t cgroup_evictable_bytes(const struct os_proc_cgroup_mem_stat *s,
                                      int64_t cgroup_current)
{
    const int64_t raw_rows[] = { s->file, s->shmem, s->unevictable,
                                 s->file_dirty, s->file_writeback };
    for (size_t i = 0; i < sizeof(raw_rows) / sizeof(raw_rows[0]); i++) {
        if (raw_rows[i] < 0 || raw_rows[i] > cgroup_current)
            return -1; // raw-return-ok:row-unreadable-or-torn-against-charge
    }

    /* Sum the exclusion tier with an overflow guard before each add, the
     * same doctrine as classify()'s percentage guard below: a corrupt or
     * adversarial read must fail closed to UNKNOWN, not wrap. */
    int64_t excluded = 0;
    const int64_t exclusion_rows[] = { s->shmem, s->unevictable,
                                       s->file_dirty, s->file_writeback };
    for (size_t i = 0; i < sizeof(exclusion_rows) / sizeof(exclusion_rows[0]);
        i++) {
        if (exclusion_rows[i] > INT64_MAX - excluded)
            return -1; // raw-return-ok:exclusion-sum-overflow
        excluded += exclusion_rows[i];
    }

    if (excluded > s->file)
        return -1; // raw-return-ok:torn-read-exclusions-exceed-file
    return s->file - excluded;
}

/* Unreclaimable share of a cgroup's charge.
 *
 * memory.current counts droppable page cache, so a sequential pass over the
 * block files (the paced boot integrity scan, a reindex, any bulk read)
 * walks it up to memory.high with no growth at all in the node's working
 * set — and every 5 s tick then dropped the parsed-block cache and halved
 * the mempool to give back memory the kernel would have released for free.
 * Subtracting only the droppable tier fixes that without silencing a real
 * charge. cgroup_evictable_bytes() already leaves the tier UNKNOWN for any
 * row (raw or derived) that disagrees with the charge, so a value it
 * returns here is either -1 or provably within [0, cgroup_current]. */
static int64_t cgroup_unreclaimable_bytes(const struct os_proc_mem *m)
{
    atomic_store(&g_charged_bytes, m->cgroup_current);
    int64_t evictable = cgroup_evictable_bytes(&m->cgroup_stat,
                                               m->cgroup_current);
    atomic_store(&g_evictable_bytes, evictable);
    if (evictable <= 0)
        return m->cgroup_current; // raw-return-ok:no-droppable-cache-known
    return m->cgroup_current - evictable;
}

/* The one operator-visible line the organ emits. Its own function so the
 * charge/evictable split can be printed without adding a decision point to
 * mem_pressure_poll_tick, which the complexity baseline holds at its exact
 * current value. charged_bytes and evictable_bytes are both -1 for "not
 * known" — off a cgroup basis, or when memory.stat was unreadable or torn —
 * which an operator must be able to tell from a readable evictable_bytes=0,
 * a cgroup that genuinely holds no droppable cache. */
static void log_shrink_walk(enum mem_pressure_level level,
                            int64_t current_bytes, int64_t denom_bytes,
                            enum mem_pressure_denominator_basis basis)
{
    LOG_WARN("mem_pressure",
             "level=%s current_bytes=%lld denom_bytes=%lld basis=%s "
             "charged_bytes=%lld evictable_bytes=%lld — walking shrink sinks",
             mem_pressure_level_name(level), (long long)current_bytes,
             (long long)denom_bytes, basis_name(basis),
             (long long)atomic_load(&g_charged_bytes),
             (long long)atomic_load(&g_evictable_bytes));
}
void mem_pressure_poll_tick(void)
{
    mem_pressure_ensure_builtin_sinks();

    struct os_proc_mem mem;
    bool ok = os_proc_mem_read(&mem);
    atomic_store(&g_charged_bytes, -1);
    atomic_store(&g_evictable_bytes, -1);

    struct mem_pressure_thresholds t;
    mem_pressure_thresholds_from_env(&t);

    int64_t current_bytes = -1;
    int64_t denom_bytes = -1;
    enum mem_pressure_denominator_basis basis = MEM_PRESSURE_BASIS_NONE;

    if (ok) {
        if (mem.cgroup_current >= 0 && mem.cgroup_high > 0) {
            current_bytes = cgroup_unreclaimable_bytes(&mem);
            denom_bytes = mem.cgroup_high;
            basis = MEM_PRESSURE_BASIS_CGROUP_HIGH;
        } else if (mem.cgroup_current >= 0 && mem.cgroup_max > 0) {
            current_bytes = cgroup_unreclaimable_bytes(&mem);
            denom_bytes = mem.cgroup_max;
            basis = MEM_PRESSURE_BASIS_CGROUP_MAX;
        } else if (mem.sys_total_bytes > 0 && mem.sys_avail_bytes >= 0 &&
                   mem.sys_avail_bytes <= mem.sys_total_bytes) {
            current_bytes = mem.sys_total_bytes - mem.sys_avail_bytes;
            denom_bytes = mem.sys_total_bytes;
            basis = MEM_PRESSURE_BASIS_SYS_AVAILABLE;
        } else if (mem.sys_total_bytes > 0) {
            current_bytes = mem.rss_bytes;
            denom_bytes = mem.sys_total_bytes;
            basis = MEM_PRESSURE_BASIS_SYS_TOTAL;
        }
    }

    enum mem_pressure_level level = classify(current_bytes, denom_bytes, &t);

    atomic_store(&g_current_bytes, current_bytes);
    atomic_store(&g_denominator_bytes, denom_bytes);
    atomic_store(&g_denominator_basis, (int)basis);
    atomic_store(&g_last_rss_bytes, ok ? mem.rss_bytes : -1);
    atomic_store(&g_last_poll_unix, (int64_t)platform_time_wall_time_t());
    atomic_store(&g_level, (int)level);

    if (level < MEM_HIGH)
        return;

    log_shrink_walk(level, current_bytes, denom_bytes, basis);

    pthread_mutex_lock(&g_registry_lock);
    int count = g_sink_count;
    struct mem_pressure_sink *snapshot[MEM_PRESSURE_MAX_SINKS];
    memcpy(snapshot, g_sinks, sizeof(struct mem_pressure_sink *) * (size_t)count);
    pthread_mutex_unlock(&g_registry_lock);

    int64_t now = (int64_t)platform_time_wall_time_t();
    for (int i = 0; i < count; i++) {
        struct mem_pressure_sink *s = snapshot[i];
        if (!s || !s->shrink) continue; // raw-return-ok:defensive-skip-malformed-entry
        s->shrink(level, s->ctx);
        atomic_store(&s->last_shrink_unix, now);
        atomic_fetch_add(&s->shrink_calls, 1);
    }
}

/* ── Health-ring wiring (no dedicated thread) ────────────────────── */

static void mem_pressure_health_tick(void *ctx)
{
    (void)ctx;
    mem_pressure_poll_tick();
}

bool mem_pressure_start(void)
{
    if (g_health_id != HEALTH_INVALID_ID)
        return true; /* already registered */
    mem_pressure_ensure_builtin_sinks();
    g_health_id = health_register_periodic("mem_pressure",
                                           MEM_PRESSURE_POLL_SECS,
                                           mem_pressure_health_tick, NULL);
    if (g_health_id == HEALTH_INVALID_ID)
        LOG_FAIL("mem_pressure", "start: health_register_periodic failed");
    return true;
}

void mem_pressure_stop(void)
{
    if (g_health_id == HEALTH_INVALID_ID)
        return;
    health_unregister(g_health_id);
    g_health_id = HEALTH_INVALID_ID;
}

/* ── Diagnostics ──────────────────────────────────────────────── */

bool mem_pressure_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false; // raw-return-ok:null-arg

    struct mem_pressure_thresholds t;
    mem_pressure_thresholds_from_env(&t);

    enum mem_pressure_level level =
        (enum mem_pressure_level)atomic_load(&g_level);
    json_push_kv_str(out, "level", mem_pressure_level_name(level));
    json_push_kv_int(out, "current_bytes", atomic_load(&g_current_bytes));
    json_push_kv_int(out, "denominator_bytes", atomic_load(&g_denominator_bytes));
    json_push_kv_str(out, "denominator_basis",
                     basis_name((enum mem_pressure_denominator_basis)
                                atomic_load(&g_denominator_basis)));
    json_push_kv_int(out, "rss_bytes", atomic_load(&g_last_rss_bytes));
    json_push_kv_int(out, "charged_bytes", atomic_load(&g_charged_bytes));
    json_push_kv_int(out, "evictable_bytes", atomic_load(&g_evictable_bytes));
    json_push_kv_int(out, "last_poll_unix", atomic_load(&g_last_poll_unix));
    json_push_kv_int(out, "elevated_pct", t.elevated_pct);
    json_push_kv_int(out, "high_pct", t.high_pct);
    json_push_kv_int(out, "critical_pct", t.critical_pct);
    json_push_kv_bool(out, "polling_active", g_health_id != HEALTH_INVALID_ID);

    struct json_value sinks;
    json_init(&sinks);
    json_set_array(&sinks);
    pthread_mutex_lock(&g_registry_lock);
    for (int i = 0; i < g_sink_count; i++) {
        struct mem_pressure_sink *s = g_sinks[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "name", s->name ? s->name : "?");
        json_push_kv_int(&row, "last_shrink_unix",
                         atomic_load(&s->last_shrink_unix));
        json_push_kv_int(&row, "shrink_calls", atomic_load(&s->shrink_calls));
        json_push_back(&sinks, &row);
        json_free(&row);
    }
    pthread_mutex_unlock(&g_registry_lock);
    json_push_kv(out, "sinks", &sinks);
    json_free(&sinks);

    return true;
}

#ifdef ZCL_TESTING
void mem_pressure_reset_for_testing(void)
{
    mem_pressure_stop();
    pthread_mutex_lock(&g_registry_lock);
    memset(g_sinks, 0, sizeof(g_sinks));
    g_sink_count = 0;
    pthread_mutex_unlock(&g_registry_lock);
    atomic_store(&g_level, MEM_NOMINAL);
    atomic_store(&g_last_poll_unix, 0);
    atomic_store(&g_current_bytes, -1);
    atomic_store(&g_denominator_bytes, -1);
    atomic_store(&g_denominator_basis, MEM_PRESSURE_BASIS_NONE);
    atomic_store(&g_last_rss_bytes, -1);
    atomic_store(&g_charged_bytes, -1);
    atomic_store(&g_evictable_bytes, -1);
    atomic_store(&g_malloc_trim_sink.last_shrink_unix, 0);
    atomic_store(&g_malloc_trim_sink.shrink_calls, 0);
}
#endif
