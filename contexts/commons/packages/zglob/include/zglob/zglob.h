/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shell-style wildcard (glob) matching for C23 — allocation-free,
 *          NUL-free (explicit lengths), iterative with star backtracking.
 *
 * Design notes:
 *  - Pattern syntax: '*' matches any run (including empty), '?' exactly
 *    one character, '[...]' a character class with ranges ('a-z') and
 *    negation ('!' first), and '\' escapes the next character literally
 *    (inside classes too). ']' first in a class is a literal ']'.
 *  - Matching is iterative with a single star fallback point, so runtime
 *    stays O(pattern * text) worst case without recursion or allocation;
 *    a malformed pattern (unterminated class, trailing escape) never
 *    matches and never loops.
 *  - Both inputs carry explicit lengths; embedded NULs match like any
 *    other byte. The zglob_match() wrapper takes NUL-terminated strings.
 */
#ifndef ZGLOB_H
#define ZGLOB_H

#include <stdbool.h>
#include <stddef.h>

/* Match str[0..slen) against pat[0..plen); true on a full match. */
bool zglob_match_n(const char *pat, size_t plen, const char *str,
                   size_t slen);

/* NUL-terminated convenience wrapper. */
bool zglob_match(const char *pat, const char *str);

#endif /* ZGLOB_H */
