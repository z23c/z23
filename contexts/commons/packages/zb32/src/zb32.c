/* zb32 — RFC 4648 base32. See include/zb32/zb32.h. */
#include "zb32/zb32.h"

#include <stdint.h>

static const char ZB32__ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static size_t zb32__emit(char *dst, size_t cap, size_t len, char c) {
  if (dst != NULL && len + 1 < cap) dst[len] = c;
  return len + 1;
}

size_t zb32_encoded_len(size_t n) {
  if (n > ZB32_MAX) return SIZE_MAX;
  return ((n + 4) / 5) * 8;
}

size_t zb32_encode(char *dst, size_t cap, const void *src, size_t n) {
  const unsigned char *p = src;
  size_t i = 0, len = 0;
  if (p == NULL && n != 0) return SIZE_MAX;
  if (n > ZB32_MAX) return SIZE_MAX;
  while (i < n) {
    unsigned char b[5] = {0, 0, 0, 0, 0};
    size_t have = n - i, out_chars;
    size_t k;
    if (have > 5) have = 5;
    for (k = 0; k < have; k++) b[k] = p[i + k];
    i += have;
    /* 5 bytes -> 8 chars; have bytes -> ceil(have*8/5) chars */
    out_chars = (have * 8 + 4) / 5;
    {
      uint64_t acc = 0;
      for (k = 0; k < 5; k++) acc = (acc << 8) | b[k];
      for (k = 0; k < 8; k++) {
        char c = k < out_chars
                     ? ZB32__ALPHA[(acc >> (35 - 5 * k)) & 31]
                     : '=';
        len = zb32__emit(dst, cap, len, c);
      }
    }
  }
  if (dst != NULL && cap > 0) dst[len < cap ? len : cap - 1] = '\0';
  return len;
}

static int zb32__val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

/* Padding count for a block that decoded `have` source bytes:
 * have 1->6 pads, 2->4, 3->3, 4->1, 5->0. */
size_t zb32_decode(void *dst, size_t cap, const char *src, size_t n) {
  unsigned char *d = dst;
  size_t i = 0, len = 0;
  if (src == NULL && n != 0) return SIZE_MAX;
  if (n > (ZB32_MAX / 5 + 1) * 8) return SIZE_MAX;
  if (n % 8 != 0) return SIZE_MAX;
  while (i < n) {
    uint64_t acc = 0;
    size_t pads = 0, vals = 0, k;
    size_t pad_start = SIZE_MAX;
    for (k = 0; k < 8; k++) {
      char c = src[i + k];
      if (c == '=') {
        if (pad_start == SIZE_MAX) pad_start = k;
        pads++;
      } else {
        int v = zb32__val(c);
        if (v < 0) return SIZE_MAX;
        if (pad_start != SIZE_MAX) return SIZE_MAX; /* char after pad */
        acc = (acc << 5) | (uint64_t)v;
        vals++;
      }
    }
    /* pad shape: have bytes -> out chars: 1->2, 2->4, 3->5, 4->7, 5->8 */
    if (pads != 0) {
      size_t have;
      if (i + 8 != n) return SIZE_MAX; /* padding only in final block */
      switch (vals) {
      case 2: have = 1; break;
      case 4: have = 2; break;
      case 5: have = 3; break;
      case 7: have = 4; break;
      default: return SIZE_MAX;
      }
      if (pads != 8 - ((have * 8 + 4) / 5)) return SIZE_MAX;
      /* Canonical form: the discarded low bits must be zero. */
      {
        size_t extra = vals * 5 - have * 8;
        uint64_t body;
        if ((acc & ((UINT64_C(1) << extra) - 1)) != 0) return SIZE_MAX;
        body = acc >> extra;
        for (k = 0; k < have; k++) {
          unsigned char b =
              (unsigned char)(body >> ((have - 1 - k) * 8));
          if (d != NULL && len < cap) d[len] = b;
          len++;
        }
      }
    } else {
      for (k = 0; k < 5; k++) {
        unsigned char b = (unsigned char)(acc >> ((4 - k) * 8));
        if (d != NULL && len < cap) d[len] = b;
        len++;
      }
    }
    i += 8;
  }
  return len;
}

size_t zb32_decoded_len(const char *src, size_t n) {
  return zb32_decode(NULL, 0, src, n);
}
