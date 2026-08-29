/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hold the C runtime's stream mutex across a multi-call record emission, so
 * a log line assembled from several stdio calls cannot be interleaved with
 * another thread's.
 *
 * This lives in base, not platform, because its only caller is
 * lib/base/src/log_level.c -- the bottom of the logging stack, which every
 * other library including platform itself logs through. Nothing here touches
 * the OS beyond the C runtime, so base can own it without acquiring a
 * dependency. */
#ifndef ZCL_BASE_STDIO_LOCK_H
#define ZCL_BASE_STDIO_LOCK_H

#include <stdio.h>

static inline void zcl_stdio_lock(FILE *stream)
{
#if defined(_WIN32)
    _lock_file(stream);
#else
    flockfile(stream);
#endif
}

static inline void zcl_stdio_unlock(FILE *stream)
{
#if defined(_WIN32)
    _unlock_file(stream);
#else
    funlockfile(stream);
#endif
}

#endif /* ZCL_BASE_STDIO_LOCK_H */
