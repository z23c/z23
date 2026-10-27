/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RFC 4648 Base64 (see the header for the strictness contract). */
#include "zbase64/zbase64.h"

static const char k_std[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char k_url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t zbase64_encode_len(size_t len) {
  size_t groups = len / 3u + (len % 3u != 0);
  if (groups > SIZE_MAX / 4u)
    return SIZE_MAX;
  return groups * 4u;
}

size_t zbase64_decode_cap(size_t len) {
  return (len / 4u + 1u) * 3u;
}

static bool encode_with(const char *alpha, const uint8_t *in, size_t len,
                        char *out, size_t cap) {
  if (!out)
    return false;
  size_t need = zbase64_encode_len(len);
  if (need == SIZE_MAX || cap < need + 1u)
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

static bool decode_padding_matches(size_t rem, size_t pad) {
  if (!pad) return true;
  switch (rem) {
  case 2: return pad == 2;
  case 3: return pad == 1;
  default: return false;
  }
}

static bool decode_shape_valid(size_t len, size_t pad,
                               bool padding_required) {
  if (pad > 2u) return false;
  if ((padding_required || pad) && len % 4u != 0) return false;
  size_t rem = (len - pad) % 4u;
  return rem != 1u && decode_padding_matches(rem, pad);
}

static size_t decode_tail_size(size_t rem) {
  return rem == 2u ? 1u : rem == 3u ? 2u : 0u;
}

static bool decode_tail_canonical(size_t rem, uint8_t last) {
  switch (rem) {
  case 2: return (last & 15u) == 0;
  case 3: return (last & 3u) == 0;
  default: return true;
  }
}

static bool decode_symbols_valid(const char *alpha, const char *in,
                                 size_t body, size_t rem) {
  uint8_t tab[256];
  build_table(alpha, tab);
  uint8_t last = 0;
  for (size_t i = 0; i < body; i++) {
    last = tab[(uint8_t)in[i]];
    if (last >= B64_PAD) return false;
  }
  return decode_tail_canonical(rem, last);
}

/* Reject before any writes: a failed decode reports out_len=0. */
static bool decode_input_valid(const char *alpha, bool padding_required,
                               const char *in, size_t len, size_t cap) {
  if (!in) return false;
  size_t pad = 0;
  while (pad < len && in[len - 1u - pad] == '=') pad++;
  if (!decode_shape_valid(len, pad, padding_required)) return false;
  size_t body = len - pad;
  size_t rem = body % 4u;
  size_t need = body / 4u * 3u + decode_tail_size(rem);
  if (need > cap) return false;
  return decode_symbols_valid(alpha, in, body, rem);
}

/* Count the trailing '=' padding characters of the input. */
static size_t decode_count_padding(const char *in, size_t len) {
  size_t pad = 0;
  while (pad < len && in[len - 1u - pad] == '=')
    pad++;
  return pad;
}

/* Pad-count and group-length rules for the chosen strictness. */
static bool decode_group_shape_ok(bool padding_required, size_t len,
                                  size_t pad) {
  if (pad > 2u)
    return false;
  if (padding_required) {
    if (len % 4u != 0)
      return false;
  } else if (pad && len % 4u != 0) {
    return false; /* padded but not a full group */
  }
  if (!padding_required && (len - pad) % 4u == 1u)
    return false; /* one leftover sextet can never be canonical */
  return true;
}

/* Stream-decode the body sextets into out; *written gets the byte count. */
static bool decode_body_stream(const uint8_t tab[256], const char *in,
                               size_t body, uint8_t *out, size_t cap,
                               size_t *written) {
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
  *written = o;
  return true;
}

/* Canonical padding: the pad count must match the leftover shape. */
static bool decode_pad_canonical(size_t body, size_t pad) {
  size_t rem = body % 4u;
  if ((rem == 2u && pad != 2u) || (rem == 3u && pad != 1u) ||
      (rem == 0u && pad != 0u) || rem == 1u)
    return false;
  return true;
}

static bool decode_with(const char *alpha, bool padding_required,
                        const char *in, size_t len, uint8_t *out,
                        size_t cap, size_t *out_len) {
  if (out_len)
    *out_len = 0;
  if (!out || !out_len)
    return false;
  if (len && !decode_input_valid(alpha, padding_required, in, len, cap))
    return false;
  uint8_t tab[256];
  build_table(alpha, tab);

  /* For the padded (standard) form the input length must be a multiple
   * of four; for the URL-safe form trailing padding is optional. */
  size_t pad = decode_count_padding(in, len);
  if (!decode_group_shape_ok(padding_required, len, pad))
    return false;
  size_t body = len - pad;
  size_t o = 0;
  if (!decode_body_stream(tab, in, body, out, cap, &o))
    return false;
  if (padding_required && !decode_pad_canonical(body, pad))
    return false;
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
