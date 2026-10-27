/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: glob matching (see the header for the syntax contract). */
#include "zglob/zglob.h"

#include <stdint.h>
#include <string.h>

/* Read one class character at pat[*i], resolving a '\\' escape, and
 * advance *i past what was read. */
static char class_take_char(const char *pat, size_t plen, size_t *i) {
  char ch = pat[*i];
  if (ch == '\\' && *i + 1 < plen) {
    ch = pat[*i + 1];
    *i += 2;
  } else {
    (*i)++;
  }
  return ch;
}

/* Test the class element at pat[*i] (a single character or a lo-'-'hi
 * range) against c, advancing *i past the whole element. */
static bool class_element_matches(const char *pat, size_t plen, size_t *i,
                                  char c) {
  char lo = class_take_char(pat, plen, i);
  /* Range? lo '-' hi, with '-' not the class's last character. */
  if (*i < plen && pat[*i] == '-' && *i + 1 < plen && pat[*i + 1] != ']') {
    (*i)++; /* skip '-' */
    char hi = class_take_char(pat, plen, i);
    return (unsigned char)c >= (unsigned char)lo &&
           (unsigned char)c <= (unsigned char)hi;
  }
  return c == lo;
}

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
    if (pat[i] == ']' && !first) {
      closed = true;
      i++;
      break;
    }
    first = false;
    if (class_element_matches(pat, plen, &i, c))
      matched = true;
  }
  if (!closed)
    return -1;
  *p = i;
  return matched != negate ? 1 : 0;
}

/* Match one non-'*' pattern element at pat[*pi] against the text byte sc.
 * Advances *pi past what it consumes and returns 1 on a match, 0 on a
 * mismatch, -1 on a malformed pattern. */
static int zglob_match_element(const char *pat, size_t plen, size_t *pi,
                               char sc) {
  char pc = pat[*pi];
  if (pc == '?') {
    (*pi)++;
    return 1;
  }
  if (pc == '[') {
    size_t save = *pi;
    int m = class_match(pat, plen, pi, sc);
    if (m < 0)
      return -1; /* malformed class: never matches */
    if (m > 0)
      return 1;
    *pi = save; /* fall through to star backtrack */
    return 0;
  }
  if (pc == '\\') {
    if (*pi + 1 >= plen)
      return -1; /* trailing escape: malformed pattern */
    (*pi)++;
    pc = pat[*pi];
  }
  if (pc == sc) {
    (*pi)++;
    return 1;
  }
  return 0;
}

/* Scan the unconsumed pattern tail: return 1 when only '*' runs remain,
 * 0 otherwise. */
static int zglob_tail_only_stars(const char *pat, size_t plen, size_t pi) {
  while (pi < plen) {
    if (pat[pi] == '*') {
      pi++;
      continue;
    }
    if (pat[pi] == '[') {
      size_t probe = pi;
      if (class_match(pat, plen, &probe, '\0') < 0)
        return 0; /* malformed class even against no text */
    }
    return 0;
  }
  return 1;
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
      int m = zglob_match_element(pat, plen, &pi, str[si]);
      if (m < 0)
        return false;
      if (m > 0) {
        si++;
        continue;
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
  return zglob_tail_only_stars(pat, plen, pi) > 0;
}

bool zglob_match(const char *pat, const char *str) {
  if (!pat || !str)
    return false;
  return zglob_match_n(pat, strlen(pat), str, strlen(str));
}
