/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict Semantic Versioning 2.0.0 (semver.org) parsing and
 *          precedence comparison for C23, with zero allocation.
 *
 * Design notes:
 *  - zsemver_parse_n() validates the FULL SemVer 2.0.0 grammar: numeric
 *    core with no leading zeros, dot-separated prerelease identifiers
 *    (numeric ones again without leading zeros), and build metadata. No
 *    allocation, no global state; the parsed struct borrows the input.
 *  - zsemver_compare() implements precedence only: build metadata is
 *    ignored (per spec item 10), a version without a prerelease outranks
 *    the same core with one, numeric identifiers rank below alphanumeric
 *    ones, and a shorter identifier list ranks below a longer one when it
 *    is a prefix of it.
 *  - Prerelease/build fields point INTO the parsed input string; keep the
 *    input alive while inspecting them.
 */
#ifndef ZSEMVER_H
#define ZSEMVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint64_t major;
  uint64_t minor;
  uint64_t patch;
  const char *prerelease; /* borrowed; NULL when absent */
  size_t prerelease_len;
  const char *build; /* borrowed; NULL when absent */
  size_t build_len;
} zsemver;

/* Parse a strict SemVer 2.0.0 version over str[0..len). Returns false on
 * any grammar violation; *out is zeroed in that case. */
bool zsemver_parse_n(const char *str, size_t len, zsemver *out);

/* NUL-terminated convenience wrapper over zsemver_parse_n(). */
bool zsemver_parse(const char *str, zsemver *out);

/* Precedence comparison per semver.org item 11: <0 when a outranks b, 0
 * when equal in precedence (build metadata ignored), >0 otherwise. The
 * result is exactly -1, 0, or 1. */
int zsemver_compare(const zsemver *a, const zsemver *b);

#endif /* ZSEMVER_H */
