/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_UTIL_PARSE_NUM_H
#define ZCL_UTIL_PARSE_NUM_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Shared base-10 int64_t string parser.
 *
 * Folds two near-identical local parsers that previously lived in the
 * chaos simulator (parse_i64) and the recovery-policy service
 * (parse_int64). Both used strtoll(base=10) with an errno check and an
 * end-pointer check; this canonical form keeps the recovery-policy
 * variant's defensive null-check on `end` (strtoll leaves `end`
 * unchanged on some inputs, so guard before dereferencing).
 *
 * Returns true and stores the value in *out when `s` is a non-empty
 * string that parses fully (no trailing characters) without overflow.
 * Header-only static inline so standalone tools (e.g. the chaos sim,
 * which links only a subset of platform/modules/util) and the full node share one
 * definition without a new translation unit. */
static inline bool zcl_parse_i64(const char *s, int64_t *out)
{
    if (!s || !*s || !out) return false;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || (end && *end != '\0')) return false;
    *out = (int64_t)v;
    return true;
}

#endif
