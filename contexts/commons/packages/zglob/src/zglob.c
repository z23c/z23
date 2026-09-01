/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: glob matching (see the header for the syntax contract). */
#include "zglob/zglob.h"

#include <stdint.h>
#include <string.h>

/* Match one bracket class over pat[*p..plen) against character c.
 * On a syntactically complete class, advances *p past the closing ']'
 * and returns 1 (matched) or 0 (no match). Returns -1 when the class is
 * malformed (unterminated); the matcher treats that as "no match". */
static int class_match(const char *pat, size_t plen, size_t *p, char c) {
  size_t i = *p; /* at '[' */
  i++;
  bool negate = false;
  if (i < plen && pat[i] == '!') {
    negate = true;
    i++;
  }
  bool matched = false;
  bool first = true;
  bool closed = false;
  while (i < plen) {
    char lo = pat[i];
    if (lo == ']' && !first) {
      closed = true;
      i++;
      break;
    }
    first = false;
    if (lo == '\\' && i + 1 < plen) {
      lo = pat[i + 1];
      i += 2;
    } else {
      i++;
    }
    /* Range? lo '-' hi, with '-' not the class's last character. */
    if (i < plen && pat[i] == '-' && i + 1 < plen && pat[i + 1] != ']') {
      i++; /* skip '-' */
      char hi = pat[i];
      if (hi == '\\' && i + 1 < plen) {
        hi = pat[i + 1];
        i += 2;
      } else {
        i++;
      }
      if ((unsigned char)c >= (unsigned char)lo &&
          (unsigned char)c <= (unsigned char)hi)
        matched = true;
    } else if (c == lo) {
      matched = true;
    }
  }
  if (!closed)
    return -1;
  *p = i;
  return matched != negate ? 1 : 0;
}

bool zglob_match_n(const char *pat, size_t plen, const char *str,
                   size_t slen) {
  if (!pat || !str)
    return false;
  size_t pi = 0, si = 0;
  size_t star_p = SIZE_MAX, star_s = 0; /* last '*' fallback point */
  while (si < slen) {
    if (pi < plen) {
      char pc = pat[pi];
      if (pc == '*') {
        star_p = pi++;
        star_s = si;
        continue;
      }
      if (pc == '?') {
        pi++;
        si++;
        continue;
      }
      if (pc == '[') {
        size_t save = pi;
        int m = class_match(pat, plen, &pi, str[si]);
        if (m < 0)
          return false; /* malformed class: never matches */
        if (m > 0) {
          si++;
          continue;
        }
        pi = save; /* fall through to star backtrack */
      } else {
        if (pc == '\\') {
          if (pi + 1 >= plen)
            return false; /* trailing escape: malformed pattern */
          pi++;
          pc = pat[pi];
        }
        if (pc == str[si]) {
          pi++;
          si++;
          continue;
        }
      }
    }
    /* Mismatch (or pattern exhausted): retry from the last '*'. */
    if (star_p != SIZE_MAX) {
      pi = star_p + 1;
      si = ++star_s;
      continue;
    }
    return false;
  }
  /* Text exhausted: only '*' runs may remain in the pattern. A trailing
   * escape or an unterminated class leaves the pattern incomplete. */
  while (pi < plen) {
    if (pat[pi] == '*') {
      pi++;
      continue;
    }
    if (pat[pi] == '[') {
      size_t probe = pi;
      if (class_match(pat, plen, &probe, '\0') < 0)
        return false; /* malformed class even against no text */
    }
    return false;
  }
  return true;
}

bool zglob_match(const char *pat, const char *str) {
  if (!pat || !str)
    return false;
  return zglob_match_n(pat, strlen(pat), str, strlen(str));
}
