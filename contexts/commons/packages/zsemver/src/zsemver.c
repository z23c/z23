/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict SemVer 2.0.0 parse + precedence (see the header). */
#include "zsemver/zsemver.h"

#include <string.h>

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static bool is_ident_char(char c) {
  return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         c == '-';
}

/* Parse one core numeric field: digits only, no leading zeros unless the
 * field is exactly "0", bounded at UINT64_MAX. Advances *pos past the
 * field. */
static bool parse_number(const char *str, size_t len, size_t *pos,
                         uint64_t *out) {
  size_t start = *pos;
  uint64_t value = 0;
  while (*pos < len && is_digit(str[*pos])) {
    unsigned digit = (unsigned)(str[*pos] - '0');
    if (value > (UINT64_MAX - digit) / 10u)
      return false; /* overflow */
    value = value * 10u + digit;
    (*pos)++;
  }
  size_t digits = *pos - start;
  if (digits == 0)
    return false;
  if (digits > 1 && str[start] == '0')
    return false; /* leading zero */
  *out = value;
  return true;
}

/* Validate one dot-separated identifier list over str[start..end).
 * When numeric_strict is set (prerelease), all-numeric identifiers must
 * not carry leading zeros. Build metadata allows them. */
static bool parse_identifiers(const char *str, size_t start, size_t end,
                              bool numeric_strict) {
  if (start == end)
    return false; /* empty list */
  size_t pos = start;
  while (pos <= end) {
    size_t id_start = pos;
    while (pos < end && str[pos] != '.') {
      if (!is_ident_char(str[pos]))
        return false;
      pos++;
    }
    size_t id_len = pos - id_start;
    if (id_len == 0)
      return false; /* empty identifier */
    if (numeric_strict) {
      bool all_digits = true;
      for (size_t i = id_start; i < pos; i++)
        if (!is_digit(str[i])) {
          all_digits = false;
          break;
        }
      if (all_digits && id_len > 1 && str[id_start] == '0')
        return false;
    }
    if (pos == end)
      break;
    pos++; /* skip '.' */
  }
  return true;
}

bool zsemver_parse_n(const char *str, size_t len, zsemver *out) {
  if (!out)
    return false;
  memset(out, 0, sizeof(*out));
  if (!str || len == 0)
    return false;

  size_t pos = 0;
  if (!parse_number(str, len, &pos, &out->major))
    return false;
  if (pos >= len || str[pos] != '.')
    return false;
  pos++;
  if (!parse_number(str, len, &pos, &out->minor))
    return false;
  if (pos >= len || str[pos] != '.')
    return false;
  pos++;
  if (!parse_number(str, len, &pos, &out->patch))
    return false;

  if (pos < len && str[pos] == '-') {
    size_t pre_start = ++pos;
    while (pos < len && str[pos] != '+')
      pos++;
    if (!parse_identifiers(str, pre_start, pos, true))
      return false;
    out->prerelease = str + pre_start;
    out->prerelease_len = pos - pre_start;
  }
  if (pos < len && str[pos] == '+') {
    size_t build_start = ++pos;
    if (!parse_identifiers(str, build_start, len, false))
      return false;
    out->build = str + build_start;
    out->build_len = len - build_start;
    pos = len;
  }
  if (pos != len)
    return false; /* trailing garbage */
  return true;
}

bool zsemver_parse(const char *str, zsemver *out) {
  return str && zsemver_parse_n(str, strlen(str), out);
}

static int cmp_u64(uint64_t a, uint64_t b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/* Compare one prerelease identifier pair. Numeric identifiers rank below
 * alphanumeric ones; two numeric identifiers compare by value; two
 * alphanumeric identifiers compare ASCII-lexically. */
static int cmp_identifier(const char *a, size_t a_len, const char *b,
                          size_t b_len) {
  bool a_num = true, b_num = true;
  for (size_t i = 0; i < a_len; i++)
    if (!is_digit(a[i])) {
      a_num = false;
      break;
    }
  for (size_t i = 0; i < b_len; i++)
    if (!is_digit(b[i])) {
      b_num = false;
      break;
    }
  if (a_num && b_num) {
    /* Identifier lengths are bounded by valid input, and numeric
     * identifiers have no leading zeros, so value comparison via length
     * then digits is exact without conversion. */
    if (a_len != b_len)
      return a_len < b_len ? -1 : 1;
    return memcmp(a, b, a_len) < 0 ? -1 : memcmp(a, b, a_len) > 0 ? 1 : 0;
  }
  if (a_num != b_num)
    return a_num ? -1 : 1;
  size_t n = a_len < b_len ? a_len : b_len;
  int c = memcmp(a, b, n);
  if (c != 0)
    return c < 0 ? -1 : 1;
  return cmp_u64(a_len, b_len);
}

static int cmp_prerelease(const zsemver *a, const zsemver *b) {
  if (!a->prerelease && !b->prerelease)
    return 0;
  if (!a->prerelease)
    return 1; /* release outranks prerelease */
  if (!b->prerelease)
    return -1;
  size_t ap = 0, bp = 0;
  for (;;) {
    bool a_more = ap < a->prerelease_len;
    bool b_more = bp < b->prerelease_len;
    if (!a_more && !b_more)
      return 0;
    if (!a_more)
      return -1; /* shorter list ranks lower when prefix-equal */
    if (!b_more)
      return 1;
    size_t a_start = ap, b_start = bp;
    while (ap < a->prerelease_len && a->prerelease[ap] != '.')
      ap++;
    while (bp < b->prerelease_len && b->prerelease[bp] != '.')
      bp++;
    int c = cmp_identifier(a->prerelease + a_start, ap - a_start,
                           b->prerelease + b_start, bp - b_start);
    if (c != 0)
      return c;
    ap++; /* skip '.' */
    bp++;
  }
}

int zsemver_compare(const zsemver *a, const zsemver *b) {
  if (!a || !b)
    return 0;
  int c = cmp_u64(a->major, b->major);
  if (c)
    return c;
  c = cmp_u64(a->minor, b->minor);
  if (c)
    return c;
  c = cmp_u64(a->patch, b->patch);
  if (c)
    return c;
  return cmp_prerelease(a, b);
}
