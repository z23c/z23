/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage memory profile — see storage/memory_profile.h. */

#include "storage/memory_profile.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic bool g_steady;

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
