/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_PLATFORM_STDIO_COMPAT_H
#define ZCL_PLATFORM_STDIO_COMPAT_H

#include <stdio.h>

/* Hold the CRT stream mutex across a multi-call record emission. */
static inline void platform_stdio_lock(FILE *stream)
{
#if defined(_WIN32)
    _lock_file(stream);
#else
    flockfile(stream);
#endif
}

static inline void platform_stdio_unlock(FILE *stream)
{
#if defined(_WIN32)
    _unlock_file(stream);
#else
    funlockfile(stream);
#endif
}

#endif
