/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage memory profile — see storage/memory_profile.h. */

#include "storage/memory_profile.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "platform/time_compat.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>

static _Atomic bool g_steady;
static atomic_flag g_cache_guard = ATOMIC_FLAG_INIT;
static bool g_cache_valid;
static struct storage_cache_snapshot g_cache_snapshot;

static bool cache_publish(const struct storage_cache_snapshot *sample)
{
    if (!sample || atomic_flag_test_and_set_explicit(&g_cache_guard, memory_order_acquire)) return false;
    g_cache_snapshot = *sample;
    g_cache_valid = true;
    atomic_flag_clear_explicit(&g_cache_guard, memory_order_release);
    return true;
}

enum storage_cache_snapshot_status storage_memory_profile_cached(struct storage_cache_snapshot *out)
{
    if (!out) return STORAGE_CACHE_SNAPSHOT_UNAVAILABLE;
    if (atomic_flag_test_and_set_explicit(&g_cache_guard, memory_order_acquire)) return STORAGE_CACHE_SNAPSHOT_BUSY;
    enum storage_cache_snapshot_status result = STORAGE_CACHE_SNAPSHOT_UNAVAILABLE;
    if (g_cache_valid) { *out = g_cache_snapshot; result = STORAGE_CACHE_SNAPSHOT_READY; }
    atomic_flag_clear_explicit(&g_cache_guard, memory_order_release);
    return result;
}
#ifdef ZCL_TESTING
bool storage_memory_profile_test_publish(const struct storage_cache_snapshot *sample) { return cache_publish(sample); }
void storage_memory_profile_test_reset(void) { if (!atomic_flag_test_and_set(&g_cache_guard)) { g_cache_valid = false; atomic_flag_clear(&g_cache_guard); } }
bool storage_memory_profile_test_guard(bool acquire) {
    if (acquire) return !atomic_flag_test_and_set(&g_cache_guard);
    atomic_flag_clear(&g_cache_guard); return true;
}
#endif

static struct storage_cache_sample cache_sample(void (*lock)(void), void (*unlock)(void),
                                                sqlite3 *(*get_db)(void))
{
    struct storage_cache_sample result = { STORAGE_CACHE_CLOSED, 0 };
    lock();
    sqlite3 *db = get_db();
    if (db) {
        int current = 0, high = 0;
        int rc = sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_USED, &current, &high, 0);
        result.state = rc == SQLITE_OK ? STORAGE_CACHE_READY : STORAGE_CACHE_ERROR;
        if (rc == SQLITE_OK) result.bytes = current;
    }
    unlock();
    return result;
}

bool storage_memory_profile_read_cache(struct storage_cache_usage *out)
{
    if (!out) return false;
    *out = (struct storage_cache_usage){0};
    out->progress = cache_sample(progress_store_tx_lock, progress_store_tx_unlock, progress_store_db);
    out->projection = cache_sample(projection_store_tx_lock, projection_store_tx_unlock, projection_store_db);
    return true;
}

static const char *cache_state_name(enum storage_cache_state state)
{
    return state == STORAGE_CACHE_READY ? "ready" : state == STORAGE_CACHE_CLOSED ? "closed" : "error";
}

void storage_memory_profile_log_cache(void)
{
    struct storage_cache_snapshot sample = {.started_unix = (int64_t)platform_time_wall_time_t()};
    (void)storage_memory_profile_read_cache(&sample.usage);
    sample.finished_unix = (int64_t)platform_time_wall_time_t();
    if (sample.started_unix <= 0 || sample.finished_unix < sample.started_unix)
        sample.started_unix = sample.finished_unix = -1;
    (void)cache_publish(&sample);
    struct storage_cache_usage usage = sample.usage;
    fprintf(stderr,  // obs-ok:storage-memory-profile
            "[storage] sqlite cache used: progress_state=%s progress_bytes=%lld projection_state=%s projection_bytes=%lld\n",
            cache_state_name(usage.progress.state), (long long)usage.progress.bytes,
            cache_state_name(usage.projection.state), (long long)usage.projection.bytes);
}

int64_t storage_memory_profile_steady_mmap(int64_t folding_mmap_bytes)
{
    return folding_mmap_bytes < STORAGE_STEADY_MMAP_BYTES
               ? folding_mmap_bytes : STORAGE_STEADY_MMAP_BYTES;
}

int64_t storage_memory_profile_steady_cache_kib(int64_t folding_cache_kib)
{
    return folding_cache_kib < STORAGE_STEADY_CACHE_KIB
               ? folding_cache_kib : STORAGE_STEADY_CACHE_KIB;
}

bool storage_memory_profile_is_steady(void)
{
    return atomic_load(&g_steady);
}

bool storage_memory_profile_set(bool steady)
{
    /* Sequential, never nested: progress_store and projection_store each take
     * only their own tx lock inside their apply function. */
    int64_t mmap = 0, cache_kib = 0, p_mmap = 0, p_cache = 0;
    int pr = progress_store_apply_memory_profile(steady, &mmap, &cache_kib);
    int jr = projection_store_apply_memory_profile(steady, &p_mmap, &p_cache);
    int conns = (pr > 0) + (jr > 0);
    atomic_store(&g_steady, steady);
    /* mmap/cache reported are the kernel connection's (the largest); the
     * projection connection is capped by the same ceilings. */
    fprintf(stderr,  // obs-ok:storage-memory-profile
            "[storage] memory profile %s: mmap=%lld cache=%lld on %d "
            "connections\n",
            steady ? "steady" : "folding", (long long)mmap,
            (long long)cache_kib * 1024, conns);
    return pr >= 0 && jr >= 0;
}
