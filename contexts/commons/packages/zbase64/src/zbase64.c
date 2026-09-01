/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RFC 4648 Base64 (see the header for the strictness contract). */
#include "zbase64/zbase64.h"

static const char k_std[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char k_url[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t zbase64_encode_len(size_t len) {
  return ((len + 2u) / 3u) * 4u;
}

size_t zbase64_decode_cap(size_t len) {
  return (len / 4u + 1u) * 3u;
}

static bool encode_with(const char *alpha, const uint8_t *in, size_t len,
                        char *out, size_t cap) {
  if (!out)
    return false;
  size_t need = zbase64_encode_len(len);
  if (cap < need + 1u)
    return false;
  if (len && !in)
    return false;
  size_t o = 0, i = 0;
  while (i + 3u <= len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                 (uint32_t)in[i + 2];
    out[o++] = alpha[(v >> 18) & 63u];
    out[o++] = alpha[(v >> 12) & 63u];
    out[o++] = alpha[(v >> 6) & 63u];
    out[o++] = alpha[v & 63u];
    i += 3u;
  }
  size_t rem = len - i;
  if (rem == 1) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = alpha[(v >> 18) & 63u];
    out[o++] = alpha[(v >> 12) & 63u];
    out[o++] = '=';
    out[o++] = '=';
  } else if (rem == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = alpha[(v >> 18) & 63u];
    out[o++] = alpha[(v >> 12) & 63u];
    out[o++] = alpha[(v >> 6) & 63u];
    out[o++] = '=';
  }
  out[o] = '\0';
  return true;
}

bool zbase64_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
  return encode_with(k_std, in, len, out, cap);
}

bool zbase64url_encode(const uint8_t *in, size_t len, char *out,
                       size_t cap) {
  return encode_with(k_url, in, len, out, cap);
}

/* Decode table builder value: 0..63 valid sextet, 64 padding, 65 invalid. */
#define B64_PAD 64u
#define B64_BAD 65u

static void build_table(const char *alpha, uint8_t tab[256]) {
  for (size_t i = 0; i < 256; i++)
    tab[i] = B64_BAD;
  for (uint8_t i = 0; i < 64; i++)
    tab[(uint8_t)alpha[i]] = i;
  tab[(uint8_t)'='] = B64_PAD;
}

static bool decode_with(const char *alpha, bool padding_required,
                        const char *in, size_t len, uint8_t *out,
                        size_t cap, size_t *out_len) {
  if (out_len)
    *out_len = 0;
  if (!out || !out_len)
    return false;
  if (len && !in)
    return false;
  uint8_t tab[256];
  build_table(alpha, tab);

  /* For the padded (standard) form the input length must be a multiple
   * of four; for the URL-safe form trailing padding is optional. */
  size_t pad = 0;
  while (pad < len && in[len - 1u - pad] == '=')
    pad++;
  if (pad > 2u)
    return false;
  if (padding_required) {
    if (len % 4u != 0)
      return false;
  } else if (pad && len % 4u != 0) {
    return false; /* padded but not a full group */
  }
  size_t body = len - pad;
  if (!padding_required && body % 4u == 1u)
    return false; /* one leftover sextet can never be canonical */

  size_t o = 0;
  uint32_t acc = 0;
  unsigned bits = 0;
  size_t i = 0;
  for (; i < body; i++) {
    uint8_t v = tab[(uint8_t)in[i]];
    if (v >= B64_PAD)
      return false;
    acc = (acc << 6) | v;
    bits += 6u;
    if (bits >= 8u) {
      bits -= 8u;
      if (o == cap)
        return false;
      out[o++] = (uint8_t)(acc >> bits);
    }
  }
  /* Leftover bits: must be exactly the zero padding of the final partial
   * group (2 chars -> 4 bits, 3 chars -> 2 bits, none for full groups). */
  if (bits && (acc & ((1u << bits) - 1u)) != 0)
    return false;
  if (padding_required) {
    /* Canonical padding: the pad count must match the leftover shape. */
    size_t rem = body % 4u;
    if ((rem == 2u && pad != 2u) || (rem == 3u && pad != 1u) ||
        (rem == 0u && pad != 0u) || rem == 1u)
      return false;
  }
  *out_len = o;
  return true;
}

bool zbase64_decode(const char *in, size_t len, uint8_t *out, size_t cap,
                    size_t *out_len) {
  return decode_with(k_std, true, in, len, out, cap, out_len);
}

bool zbase64url_decode(const char *in, size_t len, uint8_t *out, size_t cap,
                       size_t *out_len) {
  return decode_with(k_url, false, in, len, out, cap, out_len);
}
