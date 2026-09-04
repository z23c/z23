/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage_pacing — implementation. See util/storage_pacing.h for why the node
 * classifies its own disk and what each bound is for.
 *
 * The policy table is a pure function of the class so the whole decision can
 * be pinned by a test without a disk; everything stateful here is the
 * one-shot resolution and the maintenance token.
 */

#include "platform/time_compat.h"
#include "util/storage_pacing.h"

#include "json/json.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define SP_SUBSYS "storage_pacing"

#define MiB (1024LL * 1024LL)

/* ── the policy table ──────────────────────────────────────────────────
 *
 * The rotational column is the whole point of the module, so each number is
 * justified rather than round:
 *
 *   readahead 8 MiB   — one blk*.dat is 128 MiB; 8 MiB is 16 windows per
 *                       file, big enough that the drive streams and small
 *                       enough that a wrong guess wastes little cache.
 *   gap 250 ms        — long enough that a checkpoint's writeback drains
 *                       before the next writer queues behind the same head.
 *   WAL 64 MiB        — the field box reached 383 MiB against a 49 MiB
 *                       database; 64 MiB keeps the WAL smaller than any
 *                       store it fronts.
 *   log 32 MiB        — a log is read by tailing it. 32 MiB is already more
 *                       history than anyone tails, and 40x under the 1.3 GB
 *                       that was actually on disk.
 *   compact 250% /
 *   64 MiB floor      — a store carrying three bytes of file per byte of
 *                       live data has more garbage than data.
 */
static const struct storage_pacing k_rotational = {
    .klass = PLATFORM_STORAGE_CLASS_ROTATIONAL,
    .sequential_readahead = true,
    .boot_readahead_window_bytes = 8 * MiB,
    .serialize_maintenance = true,
    .maintenance_gap_ms = 250,
    .wal_truncate_bytes = 64 * MiB,
    .log_rotate_bytes = 32 * MiB,
    .compact_floor_bytes = 64 * MiB,
    .compact_ratio_pct = 250,
};

/* Solid state also gets bounds — just looser ones. An SSD does not make an
 * unbounded log or an uncompacted store correct, it only makes them cheaper. */
static const struct storage_pacing k_solid = {
    .klass = PLATFORM_STORAGE_CLASS_SOLID,
    .sequential_readahead = false,
    .boot_readahead_window_bytes = 0,
    .serialize_maintenance = false,
    .maintenance_gap_ms = 0,
    .wal_truncate_bytes = 256 * MiB,
    .log_rotate_bytes = 128 * MiB,
    .compact_floor_bytes = 256 * MiB,
    .compact_ratio_pct = 400,
};

struct storage_pacing storage_pacing_for_class(enum platform_storage_class klass)
{
    struct storage_pacing p =
        klass == PLATFORM_STORAGE_CLASS_ROTATIONAL ? k_rotational : k_solid;
    /* UNKNOWN is paced like solid state but must still REPORT unknown: a
     * status reader has to be able to tell a measured answer from a default. */
    p.klass = klass;
    return p;
}

/* ── overrides ─────────────────────────────────────────────────────────
 * Optional, never required. A malformed or absent value leaves the
 * compiled-in number exactly as it was. */

static void override_bytes_mb(const char *name, int64_t *field)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        return;
    char *end = NULL;
    long long mb = strtoll(v, &end, 10);
    if (end == v || mb <= 0 || mb > (1LL << 20))
        return;
    *field = mb * MiB;
}

static void override_i64(const char *name, int64_t *field, int64_t lo,
                         int64_t hi)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        return;
    char *end = NULL;
    long long n = strtoll(v, &end, 10);
    if (end == v || (int64_t)n < lo || (int64_t)n > hi)
        return;
    *field = (int64_t)n;
}

static void apply_overrides(struct storage_pacing *p)
{
    override_bytes_mb("ZCL_WAL_TRUNCATE_MB", &p->wal_truncate_bytes);
    override_bytes_mb("ZCL_LOG_ROTATE_MB", &p->log_rotate_bytes);
    override_bytes_mb("ZCL_COMPACT_FLOOR_MB", &p->compact_floor_bytes);
    override_bytes_mb("ZCL_BOOT_READAHEAD_MB", &p->boot_readahead_window_bytes);
    int64_t ratio = p->compact_ratio_pct;
    override_i64("ZCL_COMPACT_RATIO_PCT", &ratio, 110, 10000);
    p->compact_ratio_pct = (int)ratio;
    override_i64("ZCL_MAINTENANCE_GAP_MS", &p->maintenance_gap_ms, 0, 60000);
}

/* ── resolution ────────────────────────────────────────────────────── */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct storage_pacing g_pacing;
static _Atomic bool g_resolved = false;
static const char *g_source = "default";
static _Atomic int g_forced = PLATFORM_STORAGE_CLASS_UNKNOWN;
static bool g_forced_set = false;

static enum platform_storage_class resolve_class(const char *datadir,
                                                 const char **source)
{
    if (g_forced_set) {
        *source = "forced";
        return (enum platform_storage_class)atomic_load(&g_forced);
    }

    enum platform_storage_class over =
        platform_storage_class_parse(getenv("ZCL_STORAGE_CLASS"));
    if (over != PLATFORM_STORAGE_CLASS_UNKNOWN) {
        *source = "override";
        return over;
    }

    if (datadir && datadir[0]) {
        hw_profile_init(datadir);
        bool known = false;
        bool rotational = hw_profile_datadir_rotational(&known);
        if (known) {
            *source = "sysfs";
            return rotational ? PLATFORM_STORAGE_CLASS_ROTATIONAL
                              : PLATFORM_STORAGE_CLASS_SOLID;
        }
    }

    /* A SLOW already-measured bench median proves a seek; a fast one only
     * proves the sample file was cached, so it is deliberately not evidence. */
    if (hw_bench_measured()) {
        int64_t us = hw_bench_pread_us();
        if (us >= PLATFORM_STORAGE_ROTATIONAL_MEDIAN_US) {
            *source = "bench";
            return PLATFORM_STORAGE_CLASS_ROTATIONAL;
        }
    }

    if (datadir && datadir[0]) {
        int64_t median_us = 0;
        if (platform_storage_random_read_median_us(
                datadir, PLATFORM_STORAGE_PROBE_SAMPLES,
                PLATFORM_STORAGE_PROBE_BLOCK_BYTES,
                PLATFORM_STORAGE_PROBE_MIN_FILE_BYTES, &median_us)) {
            *source = "probe";
            return platform_storage_class_from_median_us(median_us);
        }
    }

    *source = "default";
    return PLATFORM_STORAGE_CLASS_UNKNOWN;
}

void storage_pacing_init(const char *datadir)
{
    if (atomic_load_explicit(&g_resolved, memory_order_acquire))
        return;
    pthread_mutex_lock(&g_lock);
    if (atomic_load_explicit(&g_resolved, memory_order_relaxed)) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    const char *source = "default";
    enum platform_storage_class klass = resolve_class(datadir, &source);
    g_pacing = storage_pacing_for_class(klass);
    apply_overrides(&g_pacing);
    g_source = source;
    atomic_store_explicit(&g_resolved, true, memory_order_release);
    pthread_mutex_unlock(&g_lock);

    /* Once, at boot, in plain words: an operator on a slow box must be able
     * to see that the node knows it is on a slow box. */
    LOG_INFO(SP_SUBSYS,
             "datadir storage=%s (%s) wal_truncate=%lldMB log_rotate=%lldMB "
             "compact=%d%%/%lldMB readahead=%lldMB gap=%lldms",
             platform_storage_class_name(klass), source,
             (long long)(g_pacing.wal_truncate_bytes / MiB),
             (long long)(g_pacing.log_rotate_bytes / MiB),
             g_pacing.compact_ratio_pct,
             (long long)(g_pacing.compact_floor_bytes / MiB),
             (long long)(g_pacing.boot_readahead_window_bytes / MiB),
             (long long)g_pacing.maintenance_gap_ms);
}

const struct storage_pacing *storage_pacing(void)
{
    if (!atomic_load_explicit(&g_resolved, memory_order_acquire)) {
        /* Serve the safe default rather than probing from an arbitrary
         * caller: a query must never inject a megabyte of IO into a hot path. */
        static struct storage_pacing fallback;
        static _Atomic bool built = false;
        if (!atomic_load(&built)) {
            fallback = storage_pacing_for_class(PLATFORM_STORAGE_CLASS_UNKNOWN);
            atomic_store(&built, true);
        }
        return &fallback;
    }
    return &g_pacing;
}

enum platform_storage_class storage_pacing_class(void)
{
    return storage_pacing()->klass;
}

const char *storage_pacing_source(void)
{
    return atomic_load_explicit(&g_resolved, memory_order_acquire) ? g_source
                                                                   : "default";
}

/* ── maintenance token ─────────────────────────────────────────────── */

static pthread_mutex_t g_maint_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int64_t g_maint_last_end_ms = 0;

bool storage_pacing_maintenance_begin(void)
{
    const struct storage_pacing *p = storage_pacing();
    if (!p->serialize_maintenance)
        return true;
    pthread_mutex_lock(&g_maint_lock);
    int64_t last = atomic_load(&g_maint_last_end_ms);
    int64_t now = platform_time_monotonic_ms();
    int64_t wait = p->maintenance_gap_ms - (now - last);
    if (last > 0 && wait > 0) {
        if (wait > p->maintenance_gap_ms)
            wait = p->maintenance_gap_ms; /* clock went backwards */
        platform_sleep_ms((int)wait);
    }
    return true;
}

void storage_pacing_maintenance_end(void)
{
    if (!storage_pacing()->serialize_maintenance)
        return;
    atomic_store(&g_maint_last_end_ms, platform_time_monotonic_ms());
    pthread_mutex_unlock(&g_maint_lock);
}

/* ── test seams ────────────────────────────────────────────────────── */

void storage_pacing_force_class_for_testing(enum platform_storage_class klass)
{
    pthread_mutex_lock(&g_lock);
    g_forced_set = true;
    atomic_store(&g_forced, (int)klass);
    g_pacing = storage_pacing_for_class(klass);
    apply_overrides(&g_pacing);
    g_source = "forced";
    atomic_store_explicit(&g_resolved, true, memory_order_release);
    pthread_mutex_unlock(&g_lock);
}

void storage_pacing_reset_for_testing(void)
{
    pthread_mutex_lock(&g_lock);
    g_forced_set = false;
    atomic_store(&g_forced, (int)PLATFORM_STORAGE_CLASS_UNKNOWN);
    atomic_store_explicit(&g_resolved, false, memory_order_release);
    g_source = "default";
    pthread_mutex_unlock(&g_lock);
}

bool storage_pacing_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    const struct storage_pacing *p = storage_pacing();
    json_set_object(out);
    json_push_kv_str(out, "class", platform_storage_class_name(p->klass));
    json_push_kv_str(out, "source", storage_pacing_source());
    json_push_kv_bool(out, "resolved",
                      atomic_load_explicit(&g_resolved, memory_order_acquire));
    json_push_kv_bool(out, "sequential_readahead", p->sequential_readahead);
    json_push_kv_int(out, "boot_readahead_window_bytes",
                     p->boot_readahead_window_bytes);
    json_push_kv_bool(out, "serialize_maintenance", p->serialize_maintenance);
    json_push_kv_int(out, "maintenance_gap_ms", p->maintenance_gap_ms);
    json_push_kv_int(out, "wal_truncate_bytes", p->wal_truncate_bytes);
    json_push_kv_int(out, "log_rotate_bytes", p->log_rotate_bytes);
    json_push_kv_int(out, "compact_floor_bytes", p->compact_floor_bytes);
    json_push_kv_int(out, "compact_ratio_pct", p->compact_ratio_pct);
    diag_push_health(out, true, "");
    return true;
}
