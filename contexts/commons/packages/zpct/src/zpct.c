/* zpct — RFC 3986 percent-encoding. See include/zpct/zpct.h. */
#include "zpct/zpct.h"

#include <stdint.h>

static int zpct__in_set(unsigned char c, zpct_set set) {
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
      c == '~')
    return 1; /* unreserved: always */
  if (set >= ZPCT_SUBDELIM)
    switch (c) {
    case '!': case '$': case '&': case '\'': case '(':
    case ')': case '*': case '+': case ',': case ';': case '=':
      return 1;
    default: break;
    }
  if (set >= ZPCT_PCHAR && (c == ':' || c == '@')) return 1;
  return 0;
}

int zpct_is_unescaped(unsigned char c, zpct_set set) {
  if (set < ZPCT_UNRESERVED || set > ZPCT_PCHAR) return 0;
  return zpct__in_set(c, set);
}

size_t zpct_encode(char *dst, size_t cap, const void *src, size_t n,
                   zpct_set set) {
  static const char HEX[] = "0123456789ABCDEF";
  const unsigned char *p = src;
  size_t i, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZPCT_MAX) return SIZE_MAX;
  if (set < ZPCT_UNRESERVED || set > ZPCT_PCHAR) return SIZE_MAX;
  for (i = 0; i < n; i++) {
    unsigned char c = p[i];
    if (zpct__in_set(c, set)) {
      if (dst != NULL && len + 1 < cap) dst[len] = (char)c;
      len++;
    } else {
      if (dst != NULL && len + 1 < cap) dst[len] = '%';
      len++;
      if (dst != NULL && len + 1 < cap) dst[len] = HEX[c >> 4];
      len++;
      if (dst != NULL && len + 1 < cap) dst[len] = HEX[c & 15];
      len++;
    }
  }
  if (dst != NULL && cap > 0) dst[len < cap ? len : cap - 1] = '\0';
  return len;
}

static int zpct__hexval(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

size_t zpct_decode(char *dst, size_t cap, const void *src, size_t n,
                   size_t *out_len) {
  const unsigned char *p = src;
  size_t i = 0, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZPCT_MAX) return SIZE_MAX;
  while (i < n) {
    unsigned char c = p[i];
    if (c == '%') {
      int hi, lo;
      if (i + 2 >= n) return SIZE_MAX; /* truncated triplet */
      hi = zpct__hexval(p[i + 1]);
      lo = zpct__hexval(p[i + 2]);
      if (hi < 0 || lo < 0) return SIZE_MAX;
      c = (unsigned char)((hi << 4) | lo);
      i += 3;
    } else {
      i++;
    }
    if (dst != NULL && len + 1 < cap) dst[len] = (char)c;
    len++;
  }
  if (dst != NULL && cap > 0) dst[len < cap ? len : cap - 1] = '\0';
  if (out_len != NULL) *out_len = len;
  return len;
}
