/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Semantic-version RANGE matching for C23, built on zsemver.
 *          Allocation-free and bounded: the whole parsed range lives in
 *          the caller's struct.
 *
 * Grammar (a deliberate subset of npm's range syntax):
 *
 *   range      := set ( "||" set )*
 *   set        := comparator ( ws comparator )*        -- intersection
 *   comparator := [ "<" | "<=" | ">" | ">=" | "=" ] version
 *               | "^" version     -- compatible-with (npm caret)
 *               | "~" version     -- approximately-equivalent (npm tilde)
 *   version    := strict SemVer 2.0.0 (see zsemver)
 *
 *   ^1.2.3 := >=1.2.3 <2.0.0      ^0.2.3 := >=0.2.3 <0.3.0
 *   ^0.0.3 := >=0.0.3 <0.0.4      ~1.2.3 := >=1.2.3 <1.3.0
 *
 * Exclusions (documented, fail-closed at parse): wildcards (x, *),
 * hyphen ranges, and the empty range. Whitespace is spaces/tabs only.
 *
 * Prerelease rule (npm-compatible): a version carrying a prerelease
 * satisfies a comparator set only when some comparator in that set has
 * the SAME [major, minor, patch] and itself carries a prerelease.
 *
 * Bounds: at most ZRANGE_MAX_SETS sets and ZRANGE_MAX_COMPARATORS
 * comparators in total; anything larger is a parse error, not a silent
 * truncation.
 */
#ifndef ZRANGE_H
#define ZRANGE_H

#include "zsemver/zsemver.h"

#include <stdbool.h>
#include <stddef.h>

#define ZRANGE_MAX_SETS 4u
#define ZRANGE_MAX_COMPARATORS 16u

typedef enum {
  ZRANGE_LT,
  ZRANGE_LE,
  ZRANGE_GT,
  ZRANGE_GE,
  ZRANGE_EQ
} zrange_op;

typedef struct {
  zrange_op op;
  zsemver version; /* parsed comparators borrow the range input */
} zrange_comparator;

typedef struct {
  size_t start; /* index into comps[] */
  size_t count;
} zrange_set;

typedef struct {
  zrange_comparator comps[ZRANGE_MAX_COMPARATORS];
  size_t comp_count;
  zrange_set sets[ZRANGE_MAX_SETS];
  size_t set_count;
} zrange;

/* Parse a range over str[0..len). Returns false on any grammar violation
 * or bound overflow; *out is zeroed in that case. */
bool zrange_parse_n(const char *str, size_t len, zrange *out);

/* NUL-terminated convenience wrapper. */
bool zrange_parse(const char *str, zrange *out);

/* True when version satisfies the range (any set fully satisfied, with
 * the prerelease rule applied per set). NULL arguments return false. */
bool zrange_satisfies(const zrange *range, const zsemver *version);

/* Parse both strings and test; false when either fails to parse. */
bool zrange_test(const char *range, const char *version);

#endif /* ZRANGE_H */
