/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one pure span token. The swappable controller and the admitted
 * plugin executable both include this header, so one source change is the
 * leaf and the bytes a second store verifies.
 */
#ifndef ZCL_CONTROLLERS_LOOP_SPAN_H
#define ZCL_CONTROLLERS_LOOP_SPAN_H

#include <stddef.h>
#include <stdint.h>

/* Representative input. ZCL_LOOP_SPAN_SPEC is the FNV-1a 32 result of those
 * four bytes (offset basis 2166136261, prime 16777619). */
#define ZCL_LOOP_SPAN_TEXT "span"
#define ZCL_LOOP_SPAN_SPEC 687964865u

static inline uint32_t zcl_loop_span_token(const char *text, size_t len)
{
    uint32_t hash = 2166136261u;
    const unsigned char *bytes = (const unsigned char *)(text ? text : "");
    size_t n = text ? len : 0;
    size_t i;
    for (i = 0; i < n; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

#endif
