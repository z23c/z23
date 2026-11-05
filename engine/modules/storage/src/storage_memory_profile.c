/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage memory profile — see storage/memory_profile.h. */

#include "storage/memory_profile.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic bool g_steady;

static enum storage_cache_state cache_state(int result)
{
    return result > 0 ? STORAGE_CACHE_READY : result == 0 ? STORAGE_CACHE_CLOSED : STORAGE_CACHE_ERROR;
}

void storage_memory_profile_read_cache(struct storage_cache_usage *out)
{
    if (!out) return;
    *out = (struct storage_cache_usage){0};
    out->progress.state = cache_state(progress_store_cache_used(&out->progress.bytes));
    out->projection.state = cache_state(projection_store_cache_used(&out->projection.bytes));
}

static const char *cache_state_name(enum storage_cache_state state)
{
    return state == STORAGE_CACHE_READY ? "ready" : state == STORAGE_CACHE_CLOSED ? "closed" : "error";
}

void storage_memory_profile_log_cache(void)
{
    struct storage_cache_usage usage;
    storage_memory_profile_read_cache(&usage);
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
