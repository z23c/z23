/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: overflow-safe size and uint64 arithmetic for foundation modules. */
#ifndef ZCL_BASE_CHECKED_H
#define ZCL_BASE_CHECKED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Checked arithmetic for sizes and durable counters.  Every failure clears a
 * non-NULL result so callers cannot accidentally consume a partial value. */
static inline bool zcl_size_add(size_t a, size_t b, size_t *out)
{
    if (out)
        *out = 0;
    if (a > SIZE_MAX - b)
        return false;
    if (out)
        *out = a + b;
    return true;
}

static inline bool zcl_size_mul(size_t a, size_t b, size_t *out)
{
    if (out)
        *out = 0;
    if (a != 0 && b > SIZE_MAX / a)
        return false;
    if (out)
        *out = a * b;
    return true;
}

static inline bool zcl_u64_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out)
        *out = 0;
    if (a > UINT64_MAX - b)
        return false;
    if (out)
        *out = a + b;
    return true;
}

static inline bool zcl_u64_mul(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out)
        *out = 0;
    if (a != 0 && b > UINT64_MAX / a)
        return false;
    if (out)
        *out = a * b;
    return true;
}

#endif /* ZCL_BASE_CHECKED_H */
