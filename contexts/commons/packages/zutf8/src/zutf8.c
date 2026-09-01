/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: UTF-8 validate/decode/encode (see the header for the rules). */
#include "zutf8/zutf8.h"

static bool is_cont(unsigned char b) { return (b & 0xC0u) == 0x80u; }

zutf8_status zutf8_decode_n(const char *str, size_t len, uint32_t *cp_out,
                            size_t *consumed_out) {
  if (consumed_out)
    *consumed_out = 0;
  if (!str || !cp_out)
    return ZUTF8_INVALID;
  if (!len)
    return ZUTF8_TRUNCATED;

  const unsigned char b0 = (unsigned char)str[0];
  if (b0 <= 0x7Fu) {
    *cp_out = b0;
    if (consumed_out)
      *consumed_out = 1;
    return ZUTF8_OK;
  }

  /* Sequence length and the legal range for the second byte, which is
   * where the overlong / surrogate / >U+10FFFF exclusions live. */
  size_t n;
  unsigned char lo, hi;
  if (b0 >= 0xC2u && b0 <= 0xDFu) {
    n = 2;
    lo = 0x80u;
    hi = 0xBFu;
  } else if (b0 == 0xE0u) {
    n = 3;
    lo = 0xA0u; /* exclude overlong */
    hi = 0xBFu;
  } else if (b0 == 0xEDu) {
    n = 3;
    lo = 0x80u;
    hi = 0x9Fu; /* exclude UTF-16 surrogates */
  } else if (b0 >= 0xE1u && b0 <= 0xEFu) {
    n = 3;
    lo = 0x80u;
    hi = 0xBFu;
  } else if (b0 == 0xF0u) {
    n = 4;
    lo = 0x90u; /* exclude overlong */
    hi = 0xBFu;
  } else if (b0 == 0xF4u) {
    n = 4;
    lo = 0x80u;
    hi = 0x8Fu; /* exclude above U+10FFFF */
  } else if (b0 >= 0xF1u && b0 <= 0xF3u) {
    n = 4;
    lo = 0x80u;
    hi = 0xBFu;
  } else {
    return ZUTF8_INVALID; /* 0x80..0xC1, 0xF5..0xFF */
  }

  if (len < n)
    return ZUTF8_TRUNCATED;
  const unsigned char b1 = (unsigned char)str[1];
  if (b1 < lo || b1 > hi)
    return ZUTF8_INVALID;
  for (size_t i = 2; i < n; i++) {
    if (!is_cont((unsigned char)str[i]))
      return ZUTF8_INVALID;
  }

  uint32_t cp;
  switch (n) {
  case 2:
    cp = ((uint32_t)(b0 & 0x1Fu) << 6) | (uint32_t)(b1 & 0x3Fu);
    break;
  case 3:
    cp = ((uint32_t)(b0 & 0x0Fu) << 12) | ((uint32_t)(b1 & 0x3Fu) << 6) |
         (uint32_t)(str[2] & 0x3Fu);
    break;
  default:
    cp = ((uint32_t)(b0 & 0x07u) << 18) | ((uint32_t)(b1 & 0x3Fu) << 12) |
         ((uint32_t)(str[2] & 0x3Fu) << 6) | (uint32_t)(str[3] & 0x3Fu);
    break;
  }
  *cp_out = cp;
  if (consumed_out)
    *consumed_out = n;
  return ZUTF8_OK;
}

bool zutf8_validate_n(const char *str, size_t len) {
  if (!str)
    return !len;
  size_t pos = 0;
  while (pos < len) {
    uint32_t cp;
    size_t used;
    if (zutf8_decode_n(str + pos, len - pos, &cp, &used) != ZUTF8_OK)
      return false;
    pos += used;
  }
  return true;
}

bool zutf8_validate(const char *str) {
  if (!str)
    return false;
  size_t len = 0;
  while (str[len])
    len++;
  return zutf8_validate_n(str, len);
}

size_t zutf8_encode(uint32_t cp, char out[4]) {
  if (cp >= 0xD800u && cp <= 0xDFFFu)
    return 0; /* UTF-16 surrogates have no UTF-8 encoding */
  if (cp > 0x10FFFFu)
    return 0;
  if (cp <= 0x7Fu) {
    if (out)
      out[0] = (char)cp;
    return 1;
  }
  if (cp <= 0x7FFu) {
    if (out) {
      out[0] = (char)(0xC0u | (cp >> 6));
      out[1] = (char)(0x80u | (cp & 0x3Fu));
    }
    return 2;
  }
  if (cp <= 0xFFFFu) {
    if (out) {
      out[0] = (char)(0xE0u | (cp >> 12));
      out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
      out[2] = (char)(0x80u | (cp & 0x3Fu));
    }
    return 3;
  }
  if (out) {
    out[0] = (char)(0xF0u | (cp >> 18));
    out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (cp & 0x3Fu));
  }
  return 4;
}

size_t zutf8_count_n(const char *str, size_t len) {
  if (!str)
    return len ? SIZE_MAX : 0;
  size_t pos = 0, count = 0;
  while (pos < len) {
    uint32_t cp;
    size_t used;
    if (zutf8_decode_n(str + pos, len - pos, &cp, &used) != ZUTF8_OK)
      return SIZE_MAX;
    pos += used;
    count++;
  }
  return count;
}
