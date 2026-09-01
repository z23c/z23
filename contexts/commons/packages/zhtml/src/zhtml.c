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

/* Parse one entity starting at p[*i] == '&'. On success emits and
 * advances *i past the ';'. Returns SIZE_MAX on malformed input. */
static size_t zhtml__entity(char *dst, size_t cap, size_t len,
                            const unsigned char *p, size_t n, size_t *i) {
  size_t j = *i + 1, k;
  static const struct {
    const char *name;
    char ch;
  } NAMED[] = {
      {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'},
      {"apos", '\''},
  };
  if (j < n && p[j] == '#') {
    uint32_t cp = 0;
    int hex = 0;
    size_t digits = 0;
    j++;
    if (j < n && (p[j] == 'x' || p[j] == 'X')) {
      hex = 1;
      j++;
    }
    for (k = j; k < n; k++) {
      int v = hex ? zhtml__hexval(p[k])
                  : (p[k] >= '0' && p[k] <= '9' ? p[k] - '0' : -1);
      if (v < 0) break;
      cp = cp * (hex ? 16u : 10u) + (uint32_t)v;
      if (cp > 0x7FFFFFFF) return SIZE_MAX; /* absurd */
      digits++;
      if (digits > 8) return SIZE_MAX;
    }
    if (digits == 0 || k >= n || p[k] != ';') return SIZE_MAX;
    *i = k + 1;
    return zhtml__emit_cp(dst, cap, len, cp);
  }
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
