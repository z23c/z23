/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: does a string end with a suffix. Header-only so tools that link
 * no util object (z23-lint) and the node tooling share one body. */
#ifndef ZCL_UTIL_STR_SUFFIX_H
#define ZCL_UTIL_STR_SUFFIX_H

#include <stdbool.h>
#include <string.h>

/* True when s ends with suffix (s may equal suffix, or suffix be empty). Both
 * must be non-NULL NUL-terminated strings. */
static inline bool zcl_str_has_suffix(const char *s, const char *suffix)
{
    size_t n = strlen(s), k = strlen(suffix);
    return n >= k && strcmp(s + n - k, suffix) == 0;
}

#endif /* ZCL_UTIL_STR_SUFFIX_H */
