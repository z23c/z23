/* zhtml — bounded HTML escaping. See include/zhtml/zhtml.h. */
#include "zhtml/zhtml.h"

#include <stdint.h>
#include <string.h>

static size_t zhtml__emit(char *dst, size_t cap, size_t len, char c) {
  if (dst != NULL && len + 1 < cap) dst[len] = c;
  return len + 1;
}

static size_t zhtml__emit_str(char *dst, size_t cap, size_t len,
                              const char *s) {
  while (*s != '\0') len = zhtml__emit(dst, cap, len, *s++);
  return len;
}

static size_t zhtml__finish(char *dst, size_t cap, size_t len) {
  if (dst != NULL && cap > 0) dst[len < cap ? len : cap - 1] = '\0';
  return len;
}

size_t zhtml_escape(char *dst, size_t cap, const void *src, size_t n) {
  const unsigned char *p = src;
  size_t i, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZHTML_MAX) return SIZE_MAX;
  for (i = 0; i < n; i++) {
    switch (p[i]) {
    case '&': len = zhtml__emit_str(dst, cap, len, "&amp;"); break;
    case '<': len = zhtml__emit_str(dst, cap, len, "&lt;"); break;
    case '>': len = zhtml__emit_str(dst, cap, len, "&gt;"); break;
    case '"': len = zhtml__emit_str(dst, cap, len, "&quot;"); break;
    case '\'': len = zhtml__emit_str(dst, cap, len, "&#39;"); break;
    default: len = zhtml__emit(dst, cap, len, (char)p[i]); break;
    }
  }
  return zhtml__finish(dst, cap, len);
}

/* Emit a codepoint as UTF-8. Returns new len, SIZE_MAX on invalid. */
static size_t zhtml__emit_cp(char *dst, size_t cap, size_t len,
                             uint32_t cp) {
  if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return SIZE_MAX;
  if (cp < 0x20 && cp != '\t' && cp != '\n' && cp != '\r')
    return SIZE_MAX; /* C0 control */
  if (cp == 0x7F) return SIZE_MAX;  /* DEL control */
  if (cp < 0x80) return zhtml__emit(dst, cap, len, (char)cp);
  if (cp < 0x800) {
    len = zhtml__emit(dst, cap, len, (char)(0xC0 | (cp >> 6)));
    return zhtml__emit(dst, cap, len, (char)(0x80 | (cp & 0x3F)));
  }
  if (cp < 0x10000) {
    len = zhtml__emit(dst, cap, len, (char)(0xE0 | (cp >> 12)));
    len = zhtml__emit(dst, cap, len, (char)(0x80 | ((cp >> 6) & 0x3F)));
    return zhtml__emit(dst, cap, len, (char)(0x80 | (cp & 0x3F)));
  }
  len = zhtml__emit(dst, cap, len, (char)(0xF0 | (cp >> 18)));
  len = zhtml__emit(dst, cap, len, (char)(0x80 | ((cp >> 12) & 0x3F)));
  len = zhtml__emit(dst, cap, len, (char)(0x80 | ((cp >> 6) & 0x3F)));
  return zhtml__emit(dst, cap, len, (char)(0x80 | (cp & 0x3F)));
}

static int zhtml__hexval(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static uint32_t zhtml__numeric_digit(uint32_t cp, unsigned radix, unsigned digit) {
  if (cp > (0x10FFFFu - digit) / radix) return UINT32_MAX;
  return cp * radix + digit;
}

/* Accumulate the digit run starting at p[j], radix 16 when hex else 10.
 * On success returns the codepoint and sets *endp to the index that ended
 * the scan; returns UINT32_MAX on overflow or a run longer than ZHTML_MAX
 * digits. */
static uint32_t zhtml__scan_digits(const unsigned char *p, size_t n,
                                   size_t j, int hex, size_t *endp) {
  uint32_t cp = 0;
  size_t digits = 0, k;
  for (k = j; k < n; k++) {
    int v = hex ? zhtml__hexval(p[k])
                : (p[k] >= '0' && p[k] <= '9' ? p[k] - '0' : -1);
    if (v < 0) break;
    cp = zhtml__numeric_digit(cp, hex ? 16u : 10u, (unsigned)v);
    if (cp == UINT32_MAX) return UINT32_MAX;
    digits++;
    if (digits > ZHTML_MAX) return UINT32_MAX;
  }
  *endp = k;
  return cp;
}

/* Parse the numeric reference whose '#' sits at p[*i + 1]. On success
 * emits and advances *i past the ';'. Returns SIZE_MAX on malformed
 * input. */
static size_t zhtml__numeric_entity(char *dst, size_t cap, size_t len,
                                    const unsigned char *p, size_t n,
                                    size_t *i) {
  uint32_t cp;
  size_t j = *i + 2, k;
  int hex = 0;
  if (j < n && (p[j] == 'x' || p[j] == 'X')) {
    hex = 1;
    j++;
  }
  cp = zhtml__scan_digits(p, n, j, hex, &k);
  if (cp == UINT32_MAX) return SIZE_MAX;
  if (k == j || k >= n || p[k] != ';') return SIZE_MAX;
  *i = k + 1;
  return zhtml__emit_cp(dst, cap, len, cp);
}

/* Parse the named reference that starts after the '&' at p[*i]. On
 * success emits and advances *i past the ';'. Returns SIZE_MAX on
 * malformed input. */
static size_t zhtml__named_entity(char *dst, size_t cap, size_t len,
                                  const unsigned char *p, size_t n,
                                  size_t *i) {
  size_t j = *i + 1, k;
  static const struct {
    const char *name;
    char ch;
  } NAMED[] = {
      {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'},
      {"apos", '\''},
  };
  /* Named. */
  for (k = j; k < n && k - j < 5; k++)
    if (p[k] == ';') break;
  if (k >= n || p[k] != ';') return SIZE_MAX;
  for (j = 0; j < sizeof(NAMED) / sizeof(NAMED[0]); j++) {
    size_t nl = 0;
    while (NAMED[j].name[nl] != '\0') nl++;
    if (nl == k - (*i + 1) && memcmp(p + *i + 1, NAMED[j].name, nl) == 0) {
      *i = k + 1;
      return zhtml__emit(dst, cap, len, NAMED[j].ch);
    }
  }
  return SIZE_MAX;
}

/* Parse one entity starting at p[*i] == '&'. On success emits and
 * advances *i past the ';'. Returns SIZE_MAX on malformed input. */
static size_t zhtml__entity(char *dst, size_t cap, size_t len,
                            const unsigned char *p, size_t n, size_t *i) {
  size_t j = *i + 1;
  if (j < n && p[j] == '#')
    return zhtml__numeric_entity(dst, cap, len, p, n, i);
  return zhtml__named_entity(dst, cap, len, p, n, i);
}

size_t zhtml_unescape(char *dst, size_t cap, const void *src, size_t n) {
  const unsigned char *p = src;
  size_t i = 0, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZHTML_MAX) return SIZE_MAX;
  while (i < n) {
    if (p[i] == '&') {
      len = zhtml__entity(dst, cap, len, p, n, &i);
      if (len == SIZE_MAX) return SIZE_MAX;
    } else {
      len = zhtml__emit(dst, cap, len, (char)p[i]);
      i++;
    }
  }
  return zhtml__finish(dst, cap, len);
}
