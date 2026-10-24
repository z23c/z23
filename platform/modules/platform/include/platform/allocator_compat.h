/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: glibc-only mallopt/malloc_trim bulk-allocation hooks, so a batch
 * loader (bg_validation_service, fast_sync, boot_index) can tell the arena to
 * stop mmap'ing above 32KiB and later hand freed pages back to the OS; a
 * silent no-op under musl/Darwin, where neither knob exists. */

#ifndef ZCL_PLATFORM_ALLOCATOR_COMPAT_H
#define ZCL_PLATFORM_ALLOCATOR_COMPAT_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

static inline void platform_allocator_prepare_bulk(void)
{
#if defined(__GLIBC__)
    (void)mallopt(M_MMAP_THRESHOLD, 32768);
#endif
}

/* Default glibc arena ceiling. glibc gives every thread that contends on
 * malloc its own 64 MB-reserved arena (default limit 8 x cores); a node with
 * dozens of threads strands freed memory across them. Measured 2026-10-24 at
 * about 2 h uptime: rhett2 uncapped RssAnon 3165 MB, with MALLOC_ARENA_MAX=4
 * RssAnon 1930 MB (1.24 GB, 39% less); r1 capped RssAnon 1760 MB. */
#define PLATFORM_ALLOCATOR_ARENA_CAP_DEFAULT 4

/* Pure decision: the arena cap to apply, or 0 to leave glibc alone. An
 * operator's MALLOC_ARENA_MAX (set to anything, even empty) or a
 * GLIBC_TUNABLES naming glibc.malloc.arena_max always wins. */
static inline int platform_allocator_arena_cap(const char *malloc_arena_max_env,
                                               const char *glibc_tunables_env)
{
    if (malloc_arena_max_env != NULL)
        return 0;
    if (glibc_tunables_env != NULL &&
        strstr(glibc_tunables_env, "glibc.malloc.arena_max") != NULL)
        return 0;
    return PLATFORM_ALLOCATOR_ARENA_CAP_DEFAULT;
}

/* Apply the default cap. Call at the top of main(), before any thread
 * exists. Returns the cap applied, 0 if nothing was (operator setting kept,
 * mallopt refused, or not glibc). */
static inline int platform_allocator_cap_arenas(void)
{
#if defined(__GLIBC__)
    int cap = platform_allocator_arena_cap(getenv("MALLOC_ARENA_MAX"),
                                           getenv("GLIBC_TUNABLES"));
    if (cap > 0 && mallopt(M_ARENA_MAX, cap) == 1)
        return cap;
#endif
    return 0;
}

static inline void platform_allocator_release_free_pages(void)
{
#if defined(__GLIBC__)
    (void)malloc_trim(0);
#endif
}

#endif
