/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * secp256k1 adversarial vector corpus — the shared input surface for the
 * differential oracle (tests/harness/src/test_secp256k1_differential.c) and the
 * libFuzzer harness (tools/fuzz/fuzz_ecdsa.c).
 *
 * Header-only so both the test binary and the fuzz binary build the SAME
 * corpus from the SAME code: a vector added here is exercised by both, and
 * the fuzzer's seed corpus is literally the oracle's vector list (dumped by
 * `ZCL_SECP_DUMP_SEEDS=<dir> test_parallel --only=secp256k1_differential`).
 *
 * Vectors are BUILT, not baked: r/s/pubkey material is derived at runtime
 * from a fixed private key through the production signer, then mutated into
 * the adversarial shapes. That keeps the corpus honest — every "valid"
 * baseline really is one, and every mutation really is a mutation OF it.
 *
 * The flat wire form (secp_vector_encode / secp_vector_decode) is what the
 * fuzzer consumes, so a fuzzer-found divergence is replayable as a vector.
 */

#ifndef ZCL_TEST_SECP256K1_CORPUS_H
#define ZCL_TEST_SECP256K1_CORPUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SECP_VEC_MAX_PUB  96
#define SECP_VEC_MAX_MSG  72
#define SECP_VEC_MAX_SIG  160
#define SECP_VEC_MAX      64

/* One differential input. `pub`/`msg`/`sig` are raw untrusted byte strings —
 * deliberately NOT struct pubkey / struct uint256, because half the point is
 * to feed lengths and encodings the typed structs cannot represent. */
struct secp_vector {
    char     name[56];
    uint8_t  pub[SECP_VEC_MAX_PUB];
    size_t   publen;
    uint8_t  msg[SECP_VEC_MAX_MSG];
    size_t   msglen;
    uint8_t  sig[SECP_VEC_MAX_SIG];
    size_t   siglen;
};

struct secp_corpus {
    struct secp_vector v[SECP_VEC_MAX];
    size_t             n;
};

/* secp256k1 group order n, big-endian. Published curve constant (SEC 2 v2
 * §2.4.1) — external ground truth, not this codebase's own output. */
static const uint8_t SECP_ORDER_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };

/* Compressed serialization of the secp256k1 base point G (SEC 2 v2 §2.4.1).
 * G_y is even, hence the 0x02 prefix. Used as an EXTERNAL known answer for
 * scalar-1 public-key derivation. */
static const uint8_t SECP_G_COMPRESSED[33] = {
    0x02,
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98 };

/* ── big-endian 256-bit helpers (test-local, no consensus reach) ───────── */

static inline void secp_be256_sub(uint8_t out[32], const uint8_t a[32],
                                  const uint8_t b[32])
{
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)a[i] - (int)b[i] - borrow;
        borrow = d < 0;
        out[i] = (uint8_t)(d & 0xFF);
    }
}

static inline void secp_be256_add_u8(uint8_t out[32], const uint8_t a[32],
                                     uint8_t k)
{
    unsigned carry = k;
    for (int i = 31; i >= 0; i--) {
        unsigned s = (unsigned)a[i] + carry;
        out[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
}

/* ── minimal DER encoder for an ECDSA (r, s) pair ─────────────────────────
 * Emits the canonical form: SEQUENCE { INTEGER r, INTEGER s } with minimal
 * length octets and a 0x00 pad only when the leading byte has bit 7 set.
 * `pad_r`/`pad_s` force an EXTRA leading zero so the caller can build the
 * non-minimal (BIP66-illegal) encodings the oracle needs. Returns the length
 * written, or 0 if it would not fit. */
static inline size_t secp_der_int(uint8_t *out, const uint8_t v[32],
                                  bool force_pad)
{
    size_t off = 0;
    while (off < 31 && v[off] == 0)
        off++;
    size_t len = 32 - off;
    bool pad = force_pad || (v[off] & 0x80) != 0;
    size_t w = 0;
    out[w++] = 0x02;
    out[w++] = (uint8_t)(len + (pad ? 1 : 0));
    if (pad)
        out[w++] = 0x00;
    memcpy(out + w, v + off, len);
    return w + len;
}

static inline size_t secp_der_encode(uint8_t *out, size_t cap,
                                     const uint8_t r[32], const uint8_t s[32],
                                     bool pad_r, bool pad_s)
{
    uint8_t body[80];
    size_t b = secp_der_int(body, r, pad_r);
    b += secp_der_int(body + b, s, pad_s);
    if (b + 2 > cap)
        return 0;
    out[0] = 0x30;
    out[1] = (uint8_t)b;
    memcpy(out + 2, body, b);
    return b + 2;
}

/* ── flat wire form (fuzzer input / seed file) ────────────────────────────
 * [u8 publen][pub][u8 msglen][msg][u8 siglen_hi][u8 siglen_lo][sig]
 * Deliberately length-prefixed so a fuzzer bit-flip in a length field is
 * itself an interesting input rather than a decode abort. */

static inline size_t secp_vector_encode(const struct secp_vector *v,
                                        uint8_t *out, size_t cap)
{
    size_t need = 1 + v->publen + 1 + v->msglen + 2 + v->siglen;
    if (need > cap)
        return 0;
    size_t w = 0;
    out[w++] = (uint8_t)v->publen;
    memcpy(out + w, v->pub, v->publen); w += v->publen;
    out[w++] = (uint8_t)v->msglen;
    memcpy(out + w, v->msg, v->msglen); w += v->msglen;
    out[w++] = (uint8_t)(v->siglen >> 8);
    out[w++] = (uint8_t)(v->siglen & 0xFF);
    memcpy(out + w, v->sig, v->siglen); w += v->siglen;
    return w;
}

/* Returns false on any truncation or over-length field. Never reads past
 * data[len). */
static inline bool secp_vector_decode(struct secp_vector *v,
                                      const uint8_t *data, size_t len)
{
    memset(v, 0, sizeof(*v));
    size_t p = 0;
    if (len < 1) return false;
    v->publen = data[p++];
    if (v->publen > SECP_VEC_MAX_PUB || len - p < v->publen) return false;
    memcpy(v->pub, data + p, v->publen); p += v->publen;

    if (len - p < 1) return false;
    v->msglen = data[p++];
    if (v->msglen > SECP_VEC_MAX_MSG || len - p < v->msglen) return false;
    memcpy(v->msg, data + p, v->msglen); p += v->msglen;

    if (len - p < 2) return false;
    v->siglen = ((size_t)data[p] << 8) | data[p + 1];
    p += 2;
    if (v->siglen > SECP_VEC_MAX_SIG || len - p < v->siglen) return false;
    memcpy(v->sig, data + p, v->siglen);
    return true;
}

static inline struct secp_vector *secp_corpus_push(struct secp_corpus *c,
                                                   const char *name)
{
    if (c->n >= SECP_VEC_MAX)
        return NULL;
    struct secp_vector *v = &c->v[c->n++];
    memset(v, 0, sizeof(*v));
    snprintf(v->name, sizeof(v->name), "%s", name);
    return v;
}

#endif /* ZCL_TEST_SECP256K1_CORPUS_H */
