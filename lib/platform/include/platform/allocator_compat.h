/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Provide portable allocator tuning and free-page release helpers. */

#ifndef ZCL_PLATFORM_ALLOCATOR_COMPAT_H
#define ZCL_PLATFORM_ALLOCATOR_COMPAT_H

#if defined(__GLIBC__)
#include <malloc.h>
#endif

static inline void platform_allocator_prepare_bulk(void)
{
#if defined(__GLIBC__)
    (void)mallopt(M_MMAP_THRESHOLD, 32768);
#endif
}

static inline void platform_allocator_release_free_pages(void)
{
#if defined(__GLIBC__)
    (void)malloc_trim(0);
#endif
}

#endif
