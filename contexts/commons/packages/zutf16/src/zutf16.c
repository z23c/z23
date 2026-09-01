/* zutf16 — strict UTF-8 <-> UTF-16LE. See include/zutf16/zutf16.h. */
#include "zutf16/zutf16.h"

#include <string.h>

size_t zutf16_decode_cp(const void *src, size_t n, uint32_t *cp) {
  const unsigned char *p = src;
  uint32_t v;
  size_t need, i;
  if (p == NULL || cp == NULL) return 0;
  if (n == 0) return SIZE_MAX;
  if (p[0] < 0x80) {
    *cp = p[0];
    return 1;
  }
  if (p[0] < 0xC2) return 0; /* continuation or overlong lead */
  if (p[0] < 0xE0) {
    v = p[0] & 0x1F;
    need = 2;
  } else if (p[0] < 0xF0) {
    v = p[0] & 0x0F;
    need = 3;
  } else if (p[0] < 0xF5) {
    v = p[0] & 0x07;
    need = 4;
  } else {
    return 0;
  }
  if (n < need) return SIZE_MAX;
  for (i = 1; i < need; i++) {
    if ((p[i] & 0xC0) != 0x80) return 0;
    v = (v << 6) | (uint32_t)(p[i] & 0x3F);
  }
  /* Overlong / surrogate / out-of-range rejection. */
  if (need == 3 && v < 0x800) return 0;
  if (need == 4 && v < 0x10000) return 0;
  if (v >= 0xD800 && v <= 0xDFFF) return 0;
  if (v > 0x10FFFF) return 0;
  *cp = v;
  return need;
}

size_t zutf16_encode_cp(uint16_t *units, uint32_t cp) {
  if (units == NULL) return 0;
  if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
  if (cp < 0x10000) {
    units[0] = (uint16_t)cp;
    return 1;
  }
  cp -= 0x10000;
  units[0] = (uint16_t)(0xD800 | (cp >> 10));
  units[1] = (uint16_t)(0xDC00 | (cp & 0x3FF));
  return 2;
}

/* Emit one UTF-16 unit as LE bytes into the measuring writer. */
static size_t zutf16__emit_unit(void *dst, size_t cap, size_t len,
                                uint16_t u) {
  unsigned char *d = dst;
  if (d != NULL) {
    if (len + 1 < cap) d[len] = (unsigned char)(u & 0xFF);
    if (len + 2 < cap) d[len + 1] = (unsigned char)(u >> 8);
  }
  return len + 2;
}

size_t zutf16_from_utf8(void *dst, size_t cap, const void *src,
                        size_t n) {
  const unsigned char *p = src;
  size_t i = 0, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZUTF16_MAX) return SIZE_MAX;
  while (i < n) {
    uint32_t cp;
    uint16_t units[2];
    size_t used = zutf16_decode_cp(p + i, n - i, &cp);
    size_t nu, k;
    if (used == 0 || used == SIZE_MAX) return SIZE_MAX;
    i += used;
    nu = zutf16_encode_cp(units, cp);
    for (k = 0; k < nu; k++) len = zutf16__emit_unit(dst, cap, len, units[k]);
  }
  return len;
}

/* Emit one codepoint as UTF-8 into the measuring writer. */
static size_t zutf16__emit_utf8(void *dst, size_t cap, size_t len,
                                uint32_t cp) {
  unsigned char *d = dst, tmp[4];
  size_t n, i;
  if (cp < 0x80) {
    tmp[0] = (unsigned char)cp;
    n = 1;
  } else if (cp < 0x800) {
    tmp[0] = (unsigned char)(0xC0 | (cp >> 6));
    tmp[1] = (unsigned char)(0x80 | (cp & 0x3F));
    n = 2;
  } else if (cp < 0x10000) {
    tmp[0] = (unsigned char)(0xE0 | (cp >> 12));
    tmp[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
    tmp[2] = (unsigned char)(0x80 | (cp & 0x3F));
    n = 3;
  } else {
    tmp[0] = (unsigned char)(0xF0 | (cp >> 18));
    tmp[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
    tmp[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
    tmp[3] = (unsigned char)(0x80 | (cp & 0x3F));
    n = 4;
  }
  for (i = 0; i < n; i++) {
    if (d != NULL && len + 1 < cap) d[len] = tmp[i];
    len++;
  }
  return len;
}

/* Read one UTF-16LE unit pair at p[*i], decode to cp.
 * Returns 0 on invalid, advancing nothing. */
static int zutf16__take_unit(const unsigned char *p, size_t n, size_t *i,
                             uint32_t *cp) {
  uint16_t w1, w2;
  if (*i + 2 > n) return 0;
  w1 = (uint16_t)(p[*i] | ((uint16_t)p[*i + 1] << 8));
  if (w1 >= 0xD800 && w1 <= 0xDBFF) {
    if (*i + 4 > n) return 0; /* truncated pair */
    w2 = (uint16_t)(p[*i + 2] | ((uint16_t)p[*i + 3] << 8));
    if (w2 < 0xDC00 || w2 > 0xDFFF) return 0; /* unpaired high */
    *cp = 0x10000u + (((uint32_t)(w1 - 0xD800) << 10) |
                      (uint32_t)(w2 - 0xDC00));
    *i += 4;
    return 1;
  }
  if (w1 >= 0xDC00 && w1 <= 0xDFFF) return 0; /* lone low surrogate */
  *cp = w1;
  *i += 2;
  return 1;
}

size_t zutf16_to_utf8(void *dst, size_t cap, const void *src, size_t n) {
  const unsigned char *p = src;
  size_t i = 0, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZUTF16_MAX * 2u) return SIZE_MAX;
  if (n % 2 != 0) return SIZE_MAX;
  while (i < n) {
    uint32_t cp;
    if (!zutf16__take_unit(p, n, &i, &cp)) return SIZE_MAX;
    len = zutf16__emit_utf8(dst, cap, len, cp);
  }
  return len;
}

size_t zutf16_units_from_utf8(const void *src, size_t n) {
  size_t bytes = zutf16_from_utf8(NULL, 0, src, n);
  return bytes == SIZE_MAX ? SIZE_MAX : bytes / 2;
}

size_t zutf8_bytes_from_utf16(const void *src, size_t n) {
  return zutf16_to_utf8(NULL, 0, src, n);
}
