/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Differential oracle for the ChaCha20 vector tiers: arm64 NEON, x86-64 SSE2
 * four-block, AVX2 eight-block and AVX-512F sixteen-block must stay
 * byte-identical to the portable block function. x86-64 AUTO is promoted only
 * as far as the bench-simd receipts justify (ZCL_CHACHA20_AUTO_X86_64_TIER). */

/* ACCEL-ORACLE: core/modules/crypto/src/chacha20poly1305.c */

#define _POSIX_C_SOURCE 200809L

#include "crypto/chacha20poly1305.h"
#include "crypto/simd_dispatch.h"
#include "platform/clock.h"

#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t chacha_rng = UINT64_C(0x243f6a8885a308d3);

static uint64_t chacha_rng_next(void)
{
    uint64_t x = chacha_rng;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    chacha_rng = x;
    return x * UINT64_C(0x2545f4914f6cdd1d);
}

static void chacha_rng_fill(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(chacha_rng_next() >> 17);
}

static uint64_t chacha_now_ns(void)
{
    int64_t now = clock_now_monotonic_ns();
    return now > 0 ? (uint64_t)now : 0;
}

struct chacha_once_probe {
    _Atomic unsigned *ready;
    _Atomic bool *start;
    bool available;
};

static void *chacha_once_probe_main(void *arg)
{
    struct chacha_once_probe *probe = arg;
    atomic_fetch_add_explicit(probe->ready, 1u, memory_order_release);
    while (!atomic_load_explicit(probe->start, memory_order_acquire))
        sched_yield();
    probe->available = chacha20_vector4_available();
    return NULL;
}

static int parity_case(const uint8_t key[32], const uint8_t nonce[12],
                       uint32_t counter, const uint8_t *plain, size_t len)
{
    uint8_t ref[4096], got[4096], inplace[4096];
    if (len > sizeof ref) return 1;
    chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
    if (!chacha20_encrypt(key, counter, nonce, plain, len, ref)) return 1;
    chacha20_select_impl(CHACHA20_IMPL_VECTOR4);
    if (!chacha20_encrypt(key, counter, nonce, plain, len, got)) return 1;
    memcpy(inplace, plain, len);
    if (!chacha20_encrypt(key, counter, nonce, inplace, len, inplace)) return 1;
    return memcmp(ref, got, len) != 0 || memcmp(ref, inplace, len) != 0;
}

#define CHACHA_CALLER_MAX_PLAIN 65520u
#define CHACHA_CALLER_MAX_AAD      85u
static uint8_t chacha_caller_plain[CHACHA_CALLER_MAX_PLAIN];
static uint8_t chacha_caller_sealed[CHACHA_CALLER_MAX_PLAIN +
                                    POLY1305_TAG_SIZE];
static uint8_t chacha_caller_opened[CHACHA_CALLER_MAX_PLAIN];
static uint8_t chacha_caller_aad[CHACHA_CALLER_MAX_AAD];

static bool bytes_are(const uint8_t *bytes, size_t len, uint8_t value)
{
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != value) return false;
    return true;
}

static int caller_open_case(const uint8_t key[32], const uint8_t nonce[12],
                            size_t plen, size_t aad_len)
{
    for (size_t i = 0; i < plen; i++)
        chacha_caller_plain[i] = (uint8_t)(i * 131u + 17u);
    for (size_t i = 0; i < aad_len; i++)
        chacha_caller_aad[i] = (uint8_t)(i * 47u + 11u);
    chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
    if (!chacha20poly1305_encrypt(
            chacha_caller_plain, plen, chacha_caller_aad, aad_len,
            nonce, key, chacha_caller_sealed))
        return 1;

    const enum chacha20_impl impls[2] = {
        CHACHA20_IMPL_PORTABLE, CHACHA20_IMPL_VECTOR4 };
    for (size_t tier = 0; tier < 2; tier++) {
        (void)chacha20_select_impl(impls[tier]);
        memset(chacha_caller_opened, 0xa5, plen);
        if (!chacha20poly1305_decrypt(
                chacha_caller_sealed, plen + POLY1305_TAG_SIZE,
                chacha_caller_aad, aad_len, nonce, key,
                chacha_caller_opened) ||
            memcmp(chacha_caller_opened, chacha_caller_plain, plen) != 0)
            return 1;

        const size_t mutation_offsets[2] = {plen / 2u, plen};
        for (size_t mutation = 0; mutation < 2; mutation++) {
            size_t offset = mutation_offsets[mutation];
            chacha_caller_sealed[offset] ^= 1u;
            memset(chacha_caller_opened, 0xa5, plen);
            bool accepted = chacha20poly1305_decrypt(
                chacha_caller_sealed, plen + POLY1305_TAG_SIZE,
                chacha_caller_aad, aad_len, nonce, key,
                chacha_caller_opened);
            chacha_caller_sealed[offset] ^= 1u;
            if (accepted ||
                !bytes_are(chacha_caller_opened, plen, 0xa5))
                return 1;
        }
        if (aad_len > 0) {
            chacha_caller_aad[0] ^= 1u;
            memset(chacha_caller_opened, 0xa5, plen);
            bool accepted = chacha20poly1305_decrypt(
                chacha_caller_sealed, plen + POLY1305_TAG_SIZE,
                chacha_caller_aad, aad_len, nonce, key,
                chacha_caller_opened);
            chacha_caller_aad[0] ^= 1u;
            if (accepted ||
                !bytes_are(chacha_caller_opened, plen, 0xa5))
                return 1;
        }
    }
    return 0;
}

/* RFC 8439 published vectors. Every hex string is copied from
 * https://www.rfc-editor.org/rfc/rfc8439.txt and decoded at run time. */

/* Sections 2.4.2 (key, nonce, counter 1, ciphertext) and 2.8.2 (plaintext). */
static const char *const rfc_k242_hex =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    ;
static const char *const rfc_n242_hex =
    "000000000000004a00000000"
    ;
static const char *const rfc_c242_hex =
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42874d"
    ;
/* Sections 2.4.2 and 2.8.2 plaintext: "Ladies and Gentlemen ..." (114 bytes). */
static const char *const rfc_p114_hex =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e"
    ;
/* Section 2.5.2: key material (r || s) and tag for the 34-byte message below. */
static const char *const rfc_k252_hex =
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    ;
static const char *const rfc_t252_hex =
    "a8061dc1305136c6c22b8baf0c0127a9"
    ;
static const char rfc_msg_text[] = "Cryptographic Forum Research Group";
/* Section 2.6.2: key, nonce, counter 0 and the 32-byte one-time key. */
static const char *const rfc_k262_hex =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    ;
static const char *const rfc_n262_hex =
    "000000000001020304050607"
    ;
static const char *const rfc_otk262_hex =
    "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"
    ;
/* Section 2.8.2: key, nonce (fixed || IV), AAD, ciphertext and tag. */
static const char *const rfc_k282_hex =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    ;
static const char *const rfc_n282_hex =
    "070000004041424344454647"
    ;
static const char *const rfc_aad282_hex =
    "50515253c0c1c2c3c4c5c6c7"
    ;
static const char *const rfc_c282_hex =
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
    ;
static const char *const rfc_t282_hex =
    "1ae10b594f09e26a7e902ecbd0600691"
    ;
/* Appendix A.5: key, nonce, AAD, ciphertext, received tag and plaintext. */
static const char *const rfc_ka5_hex =
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
    ;
static const char *const rfc_na5_hex =
    "000000000102030405060708"
    ;
static const char *const rfc_aada5_hex =
    "f33388860000000000004e91"
    ;
static const char *const rfc_ca5_hex =
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
    "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
    "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
    "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
    "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
    "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
    "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
    "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
    "a6ad5cb4022b02709b"
    ;
static const char *const rfc_ta5_hex =
    "eead9d67890cbb22392336fea1851f38"
    ;
static const char *const rfc_pa5_hex =
    "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
    "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
    "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
    "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
    "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
    "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
    "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
    "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
    "726573732e2fe2809d"
    ;

static const enum chacha20_impl rfc_tiers[2] = {
    CHACHA20_IMPL_PORTABLE, CHACHA20_IMPL_VECTOR4 };

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Decodes exactly out_len bytes; any length or digit mismatch is refused. */
static bool hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2u) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static int rfc_report(const char *name, bool ok)
{
    printf("chacha20_isa_parity: RFC 8439 %s... %s\n",
           name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool rfc_2_4_2_ok(void)
{
    uint8_t key[32], nonce[12], plain[114], want[114], got[114];
    if (!hex_decode(rfc_k242_hex, key, sizeof key) ||
        !hex_decode(rfc_n242_hex, nonce, sizeof nonce) ||
        !hex_decode(rfc_p114_hex, plain, sizeof plain) ||
        !hex_decode(rfc_c242_hex, want, sizeof want))
        return false;
    for (size_t t = 0; t < 2; t++) {
        chacha20_select_impl(rfc_tiers[t]);
        if (!chacha20_encrypt(key, 1u, nonce, plain, sizeof plain, got) ||
            memcmp(got, want, sizeof got) != 0)
            return false;
    }
    return true;
}

static bool rfc_2_5_2_ok(void)
{
    uint8_t key[32], want[16], tag[16];
    if (!hex_decode(rfc_k252_hex, key, sizeof key) ||
        !hex_decode(rfc_t252_hex, want, sizeof want))
        return false;
    poly1305_mac((const uint8_t *)rfc_msg_text, strlen(rfc_msg_text),
                 key, tag);
    return memcmp(tag, want, sizeof tag) == 0;
}

static bool rfc_2_6_2_ok(void)
{
    static const uint8_t zero[32] = {0};
    uint8_t key[32], nonce[12], want[32], got[32];
    if (!hex_decode(rfc_k262_hex, key, sizeof key) ||
        !hex_decode(rfc_n262_hex, nonce, sizeof nonce) ||
        !hex_decode(rfc_otk262_hex, want, sizeof want))
        return false;
    for (size_t t = 0; t < 2; t++) {
        chacha20_select_impl(rfc_tiers[t]);
        /* Keystream of counter 0 is the one-time Poly1305 key. */
        if (!chacha20_encrypt(key, 0u, nonce, zero, sizeof zero, got) ||
            memcmp(got, want, sizeof got) != 0)
            return false;
    }
    return true;
}

struct rfc_aead_282 {
    uint8_t key[32], nonce[12], aad[12], plain[114], sealed[130];
};

static bool rfc_load_282(struct rfc_aead_282 *v)
{
    return hex_decode(rfc_k282_hex, v->key, sizeof v->key) &&
           hex_decode(rfc_n282_hex, v->nonce, sizeof v->nonce) &&
           hex_decode(rfc_aad282_hex, v->aad, sizeof v->aad) &&
           hex_decode(rfc_p114_hex, v->plain, sizeof v->plain) &&
           hex_decode(rfc_c282_hex, v->sealed, 114) &&
           hex_decode(rfc_t282_hex, v->sealed + 114, 16);
}

/* True only when open refuses and leaves every plaintext byte untouched. */
static bool rfc_open_refused(const uint8_t *sealed, size_t sealed_len,
                             const uint8_t *aad, const uint8_t nonce[12],
                             const uint8_t key[32])
{
    uint8_t opened[114];
    memset(opened, 0xa5, sizeof opened);
    bool accepted = chacha20poly1305_decrypt(sealed, sealed_len, aad, 12,
                                             nonce, key, opened);
    return !accepted && bytes_are(opened, sizeof opened, 0xa5);
}

static bool rfc_2_8_2_seal_ok(const struct rfc_aead_282 *v)
{
    uint8_t got[130], opened[114];
    for (size_t t = 0; t < 2; t++) {
        chacha20_select_impl(rfc_tiers[t]);
        if (!chacha20poly1305_encrypt(v->plain, sizeof v->plain,
                                      v->aad, sizeof v->aad,
                                      v->nonce, v->key, got) ||
            memcmp(got, v->sealed, sizeof got) != 0)
            return false;
        if (!chacha20poly1305_decrypt(v->sealed, sizeof v->sealed,
                                      v->aad, sizeof v->aad,
                                      v->nonce, v->key, opened) ||
            memcmp(opened, v->plain, sizeof opened) != 0)
            return false;
    }
    return true;
}

static bool rfc_2_8_2_tamper_ok(const struct rfc_aead_282 *v)
{
    uint8_t sealed[130], aad[12];
    for (size_t t = 0; t < 2; t++) {
        chacha20_select_impl(rfc_tiers[t]);
        memcpy(sealed, v->sealed, sizeof sealed);
        sealed[129] ^= 1u;
        if (!rfc_open_refused(sealed, sizeof sealed, v->aad, v->nonce,
                              v->key))
            return false;
        memcpy(sealed, v->sealed, sizeof sealed);
        sealed[57] ^= 1u;
        if (!rfc_open_refused(sealed, sizeof sealed, v->aad, v->nonce,
                              v->key))
            return false;
        memcpy(aad, v->aad, sizeof aad);
        aad[0] ^= 1u;
        if (!rfc_open_refused(v->sealed, sizeof v->sealed, aad, v->nonce,
                              v->key))
            return false;
    }
    return true;
}

static bool rfc_empty_round_trip_ok(const struct rfc_aead_282 *v)
{
    static const uint8_t none[1] = {0};
    uint8_t sealed[16], opened[1];
    for (size_t t = 0; t < 2; t++) {
        chacha20_select_impl(rfc_tiers[t]);
        if (!chacha20poly1305_encrypt(none, 0, none, 0, v->nonce, v->key,
                                      sealed) ||
            !chacha20poly1305_decrypt(sealed, sizeof sealed, none, 0,
                                      v->nonce, v->key, opened))
            return false;
        sealed[15] ^= 1u;
        if (chacha20poly1305_decrypt(sealed, sizeof sealed, none, 0,
                                     v->nonce, v->key, opened))
            return false;
    }
    return true;
}

struct rfc_a5 {
    uint8_t key[32], nonce[12], aad[12], sealed[281], plain[265];
};

static bool rfc_load_a5(struct rfc_a5 *v)
{
    return hex_decode(rfc_ka5_hex, v->key, sizeof v->key) &&
           hex_decode(rfc_na5_hex, v->nonce, sizeof v->nonce) &&
           hex_decode(rfc_aada5_hex, v->aad, sizeof v->aad) &&
           hex_decode(rfc_ca5_hex, v->sealed, 265) &&
           hex_decode(rfc_ta5_hex, v->sealed + 265, 16) &&
           hex_decode(rfc_pa5_hex, v->plain, sizeof v->plain);
}

static bool rfc_a5_ok(const struct rfc_a5 *v)
{
    uint8_t opened[265];
    for (size_t t = 0; t < 2; t++) {
        chacha20_select_impl(rfc_tiers[t]);
        if (!chacha20poly1305_decrypt(v->sealed, sizeof v->sealed,
                                      v->aad, sizeof v->aad,
                                      v->nonce, v->key, opened) ||
            memcmp(opened, v->plain, sizeof opened) != 0)
            return false;
    }
    return true;
}

static int rfc8439_vectors(void)
{
    struct rfc_aead_282 v282;
    struct rfc_a5 a5;
    int fails = 0;
    fails += rfc_report("2.4.2 ChaCha20 encryption", rfc_2_4_2_ok());
    fails += rfc_report("2.5.2 Poly1305 tag", rfc_2_5_2_ok());
    fails += rfc_report("2.6.2 Poly1305 key generation", rfc_2_6_2_ok());
    bool loaded = rfc_load_282(&v282);
    fails += rfc_report("2.8.2 AEAD seal and open",
                        loaded && rfc_2_8_2_seal_ok(&v282));
    fails += rfc_report("2.8.2 flipped tag, ciphertext and AAD refused",
                        loaded && rfc_2_8_2_tamper_ok(&v282));
    fails += rfc_report("empty AAD and plaintext round-trip",
                        loaded && rfc_empty_round_trip_ok(&v282));
    fails += rfc_report("A.5 AEAD decryption",
                        rfc_load_a5(&a5) && rfc_a5_ok(&a5));
    return fails;
}

/* ---- AVX2 / AVX-512F wide-tier parity (ChaCha20 8- and 16-block tiers) ---- */

#define WIDE_BUF 8448u
#define WIDE_SENTINEL 0xa5u
#define WIDE_GUARD 32u
#define WIDE_NO_PLANT ((size_t)-1)

static uint8_t wide_plain[WIDE_BUF], wide_ref[WIDE_BUF];
static uint8_t wide_got[WIDE_BUF], wide_inp[WIDE_BUF];

struct wide_case {
    const uint8_t *key;
    const uint8_t *nonce;
    uint32_t counter;
    size_t len;
    size_t in_off;
    size_t out_off;
    size_t plant; /* byte of the tier output to corrupt, or WIDE_NO_PLANT */
};

static bool wide_tier_expected(enum chacha20_impl tier)
{
    if (tier == CHACHA20_IMPL_AVX2) return simd_host_has_avx2();
    if (tier == CHACHA20_IMPL_AVX512) return simd_host_has_avx512f();
    return true;
}

static const char *wide_tier_name(enum chacha20_impl tier)
{
    if (tier == CHACHA20_IMPL_AVX2) return "avx2";
    if (tier == CHACHA20_IMPL_AVX512) return "avx512";
    return "vector4";
}

static bool wide_guard_intact(const uint8_t *p, size_t len)
{
    for (size_t i = 0; i < WIDE_GUARD; i++)
        if (p[len + i] != WIDE_SENTINEL) return false;
    return true;
}

static bool wide_fits(const struct wide_case *c)
{
    return c->len + c->in_off + WIDE_GUARD <= WIDE_BUF &&
           c->len + c->out_off + WIDE_GUARD <= WIDE_BUF;
}

/* Sentinel-fill the output and the in-place buffer, and copy the input into it. */
static void wide_seed(const struct wide_case *c, const uint8_t *in,
                      uint8_t *inp, uint8_t *ref, uint8_t *got)
{
    memset(ref, WIDE_SENTINEL, c->len + WIDE_GUARD);
    memset(got, WIDE_SENTINEL, c->len + WIDE_GUARD);
    memcpy(inp, in, c->len);
    memset(inp + c->len, WIDE_SENTINEL, WIDE_GUARD);
}

/* Compare the portable reference with the tier's accept flags and bytes. */
static int wide_compare_bytes(const struct wide_case *c, bool ok_ref,
                              bool ok_got, bool ok_in, const uint8_t *in,
                              const uint8_t *ref, const uint8_t *got,
                              const uint8_t *inp)
{
    int diffs = 0;
    if (ok_ref != ok_got || ok_ref != ok_in) diffs++;
    if (ok_ref && ok_got && memcmp(ref, got, c->len) != 0) diffs++;
    if (ok_ref && ok_in && memcmp(ref, inp, c->len) != 0) diffs++;
    if (!ok_ref && (memcmp(ref, got, c->len) != 0 ||
                    memcmp(inp, in, c->len) != 0)) diffs++;
    return diffs;
}

/* One differential case: portable vs `tier`, out-of-place into unaligned
 * buffers and exactly in place. Counts every divergence (bytes, accept/refuse,
 * a write past the end, or output written on a refusal). */
static int wide_case(enum chacha20_impl tier, const struct wide_case *c)
{
    int diffs = 0;
    uint8_t *in = wide_plain + c->in_off, *inp = wide_inp + c->in_off;
    uint8_t *ref = wide_ref + c->out_off, *got = wide_got + c->out_off;
    if (!wide_fits(c)) return 1;
    wide_seed(c, in, inp, ref, got);

    chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
    bool ok_ref = chacha20_encrypt(c->key, c->counter, c->nonce, in, c->len, ref);
    if (chacha20_select_impl(tier) != (int)tier) return 1;
    bool ok_got = chacha20_encrypt(c->key, c->counter, c->nonce, in, c->len, got);
    bool ok_in = chacha20_encrypt(c->key, c->counter, c->nonce, inp, c->len, inp);
    if (ok_got && c->plant < c->len) got[c->plant] ^= 1u;

    diffs += wide_compare_bytes(c, ok_ref, ok_got, ok_in, in, ref, got, inp);
    if (!wide_guard_intact(got, c->len) || !wide_guard_intact(inp, c->len))
        diffs++;
    return diffs;
}

static int wide_case_simple(enum chacha20_impl tier, const uint8_t *key,
                            const uint8_t *nonce, uint32_t counter, size_t len)
{
    struct wide_case c = {
        .key = key, .nonce = nonce, .counter = counter, .len = len,
        .in_off = (len * 5u) % 7u, .out_off = (len * 3u) % 11u,
        .plant = WIDE_NO_PLANT };
    return wide_case(tier, &c);
}

static int wide_sweep_lengths(enum chacha20_impl tier, const uint8_t *key,
                              const uint8_t *nonce)
{
    static const uint32_t counters[] = {0u, 1u, 7u, 0xdeadbee0u, 0x7fffffffu};
    static const size_t extra[] = {1536u, 2047u, 2048u, 2111u, 2112u, 2113u,
                                   3072u, 4096u, 8000u};
    int diffs = 0;
    for (size_t k = 0; k < sizeof counters / sizeof counters[0]; k++)
        for (size_t len = 0; len <= 1100; len++)
            diffs += wide_case_simple(tier, key, nonce, counters[k], len);
    for (size_t i = 0; i < sizeof extra / sizeof extra[0]; i++)
        diffs += wide_case_simple(tier, key, nonce, 1u, extra[i]);
    return diffs;
}

/* Counters 2^32-1-k: lane counters cross the wrap, and the tier must refuse
 * exactly where portable does, handing the last blocks to narrower code. */
static int wide_sweep_wrap(enum chacha20_impl tier, const uint8_t *key,
                           const uint8_t *nonce)
{
    static const size_t extra[] = {1536u, 2048u, 2112u, 2113u, 4096u};
    int diffs = 0;
    for (uint32_t k = 0; k <= 40u; k++) {
        uint32_t counter = UINT32_MAX - k;
        /* Only up to just past the exhaustion boundary: every refused case logs. */
        size_t top = ((size_t)k + 3u) * 64u;
        for (size_t len = 0; len <= 1100 && len <= top; len++)
            diffs += wide_case_simple(tier, key, nonce, counter, len);
        for (size_t i = 0; k > 20u && i < sizeof extra / sizeof extra[0]; i++)
            diffs += wide_case_simple(tier, key, nonce, counter, extra[i]);
    }
    return diffs;
}

static int wide_sweep_random(enum chacha20_impl tier)
{
    int diffs = 0;
    uint8_t key[32], nonce[12];
    for (int trial = 0; trial < 1500; trial++) {
        chacha_rng_fill(key, sizeof key);
        chacha_rng_fill(nonce, sizeof nonce);
        chacha_rng_fill(wide_plain, sizeof wide_plain);
        uint64_t r = chacha_rng_next();
        uint32_t counter = (uint32_t)chacha_rng_next();
        if ((r & 15u) == 0u) counter = UINT32_MAX - (uint32_t)((r >> 8) % 70u);
        size_t len = (size_t)(chacha_rng_next() % 4097u);
        diffs += wide_case_simple(tier, key, nonce, counter, len);
    }
    return diffs;
}

/* RFC 7539 section 2.3.2 block vector, reached through chacha20_encrypt of
 * zeros so the wide kernels (not only the scalar block) produce block 1. */
static int wide_rfc_vector(enum chacha20_impl tier)
{
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00 };
    static const uint8_t want[64] = {
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
        0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
        0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e };
    uint8_t key[32], zeros[1100], out[1100], block[64];
    int diffs = 0;
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)i;
    memset(zeros, 0, sizeof zeros);
    if (chacha20_select_impl(tier) != (int)tier) return 1;
    if (!chacha20_encrypt(key, 1u, nonce, zeros, sizeof zeros, out)) return 1;
    if (memcmp(out, want, sizeof want) != 0) diffs++;
    for (uint32_t b = 0; b < sizeof zeros / 64u; b++) {
        chacha20_block(key, 1u + b, nonce, block);
        if (memcmp(out + (size_t)b * 64u, block, 64) != 0) diffs++;
    }
    return diffs;
}

static int wide_aead_parity(enum chacha20_impl tier, const uint8_t *key,
                            const uint8_t *nonce)
{
    static const size_t lens[] = {0,1,15,16,17,63,64,65,255,256,257,511,512,
                                  513,564,1023,1024,1025,1536,2048,4096};
    static uint8_t ref[4096 + 16], got[4096 + 16], opened[4096];
    int diffs = 0;
    chacha_rng_fill(wide_plain, 4096);
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        size_t len = lens[i];
        chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
        bool a = chacha20poly1305_encrypt(wide_plain, len, wide_plain, 17,
                                          nonce, key, ref);
        if (chacha20_select_impl(tier) != (int)tier) return 1;
        bool b = chacha20poly1305_encrypt(wide_plain, len, wide_plain, 17,
                                          nonce, key, got);
        bool c = b && chacha20poly1305_decrypt(got, len + 16, wide_plain, 17,
                                               nonce, key, opened);
        if (!a || !b || !c || memcmp(ref, got, len + 16) != 0 ||
            memcmp(opened, wide_plain, len) != 0) diffs++;
        if (len > 0) {
            got[len / 2] ^= 1u;
            if (chacha20poly1305_decrypt(got, len + 16, wide_plain, 17, nonce,
                                         key, opened)) diffs++;
            got[len / 2] ^= 1u;
        }
    }
    return diffs;
}

/* AUTO must produce bytes identical to portable and report a tier that is
 * available (or portable). */
static int wide_auto_equals_portable(const uint8_t *key, const uint8_t *nonce)
{
    int diffs = 0;
    int tier = chacha20_select_impl(CHACHA20_IMPL_AUTO);
    if (tier != chacha20_auto_impl()) diffs++;
    if (tier != CHACHA20_IMPL_PORTABLE &&
        !chacha20_tier_available((enum chacha20_impl)tier)) diffs++;
    chacha_rng_fill(wide_plain, 1200);
    for (size_t len = 0; len <= 1100; len++) {
        chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
        (void)chacha20_encrypt(key, 3u, nonce, wide_plain, len, wide_ref);
        chacha20_select_impl(CHACHA20_IMPL_AUTO);
        (void)chacha20_encrypt(key, 3u, nonce, wide_plain, len, wide_got);
        if (memcmp(wide_ref, wide_got, len) != 0) diffs++;
    }
    return diffs;
}

/* Teeth: the same comparator must see a single planted corrupted byte, at the
 * first, a middle and the last byte, for lengths that reach each kernel. */
static int wide_teeth(enum chacha20_impl tier, const uint8_t *key,
                      const uint8_t *nonce)
{
    static const size_t lens[] = {1u, 64u, 513u, 1100u, 2112u};
    int missed = 0;
    chacha_rng_fill(wide_plain, sizeof wide_plain);
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        const size_t plants[3] = {0u, lens[i] / 2u, lens[i] - 1u};
        for (size_t p = 0; p < 3; p++) {
            struct wide_case c = {
                .key = key, .nonce = nonce, .counter = 5u, .len = lens[i],
                .in_off = 1u, .out_off = 3u, .plant = plants[p] };
            if (wide_case(tier, &c) == 0) missed++;
        }
    }
    return missed;
}

static int wide_check(const char *what, int diffs)
{
    if (diffs == 0) { printf("OK\n"); return 0; }
    printf("FAIL (%s: %d)\n", what, diffs);
    return 1;
}

static int wide_tier_suite(enum chacha20_impl tier, const uint8_t *key,
                           const uint8_t *nonce)
{
    int failures = 0;
    const char *name = wide_tier_name(tier);
    if (!chacha20_tier_available(tier)) {
        if (wide_tier_expected(tier)) {
            printf("chacha20_isa_parity: %s tier usable on this host... FAIL (KAT disabled it)\n", name);
            return 1;
        }
        printf("chacha20_isa_parity: %s tier SKIPPED (host lacks it)\n", name);
        return 0;
    }
    printf("chacha20_isa_parity: %s RFC 7539 block 1 via encrypt... ", name);
    failures += wide_check("rfc", wide_rfc_vector(tier));
    printf("chacha20_isa_parity: %s every length 0..1100 + large, counters, unaligned, in-place... ", name);
    failures += wide_check("lengths", wide_sweep_lengths(tier, key, nonce));
    printf("chacha20_isa_parity: %s counters 2^32-1-k cross wrap, refusal matches portable... ", name);
    failures += wide_check("wrap", wide_sweep_wrap(tier, key, nonce));
    printf("chacha20_isa_parity: %s randomized keys/nonces/counters x1500... ", name);
    failures += wide_check("random", wide_sweep_random(tier));
    printf("chacha20_isa_parity: %s AEAD seal/open + tamper... ", name);
    failures += wide_check("aead", wide_aead_parity(tier, key, nonce));
    printf("chacha20_isa_parity: %s teeth: planted one-byte divergence is caught... ", name);
    failures += wide_check("teeth-missed", wide_teeth(tier, key, nonce));
    return failures;
}

static int chacha20_isa_wide_tiers(const uint8_t *key, const uint8_t *nonce)
{
    static const enum chacha20_impl tiers[] = {
        CHACHA20_IMPL_VECTOR4, CHACHA20_IMPL_AVX2, CHACHA20_IMPL_AVX512 };
    int failures = 0;
    for (size_t i = 0; i < sizeof tiers / sizeof tiers[0]; i++)
        failures += wide_tier_suite(tiers[i], key, nonce);
    printf("chacha20_isa_parity: AUTO equals portable bytes, resolves to a usable tier... ");
    failures += wide_check("auto", wide_auto_equals_portable(key, nonce));
    chacha20_select_impl(CHACHA20_IMPL_AUTO);
    return failures;
}

/* Reported timing only (not a promotion gate): portable vs vector4 on 64 KiB. */
static int chacha20_isa_bench_report(const uint8_t key[32],
                                     const uint8_t nonce[12])
{
    int failures = 0;
    printf("chacha20_isa_parity: reported benchmark (not a promotion gate)... ");
    static uint8_t bench_in[65520], bench_out[65520];
    chacha_rng_fill(bench_in, sizeof bench_in);
    uint64_t ns[2];
    const enum chacha20_impl impl[2] = {
        CHACHA20_IMPL_PORTABLE, CHACHA20_IMPL_VECTOR4 };
    for (int pass = 0; pass < 2; pass++) {
        chacha20_select_impl(impl[pass]);
        uint64_t start = chacha_now_ns();
        for (int i = 0; i < 256; i++)
            if (!chacha20_encrypt(key, 1u, nonce, bench_in,
                                  sizeof bench_in, bench_out)) failures++;
        ns[pass] = chacha_now_ns() - start;
    }
    printf("portable=%llu ns vector4=%llu ns speedup=%.2fx\n",
           (unsigned long long)ns[0], (unsigned long long)ns[1],
           ns[1] ? (double)ns[0] / (double)ns[1] : 0.0);
    return failures;
}

/* Concurrent first callers of the one-time KAT must all agree on the tier. */
static int chacha20_isa_concurrent_kat(void)
{
    int failures = 0;
    printf("chacha20_isa_parity: concurrent first KAT callers converge... ");
    enum { NPROBES = 16 };
    pthread_t threads[NPROBES];
    struct chacha_once_probe probes[NPROBES];
    _Atomic unsigned ready = 0;
    _Atomic bool start = false;
    int created = 0;
    for (int i = 0; i < NPROBES; i++) {
        probes[i] = (struct chacha_once_probe){
            .ready = &ready, .start = &start, .available = false };
        if (pthread_create(&threads[i], NULL, chacha_once_probe_main,
                           &probes[i]) != 0)
            break;
        created++;
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) <
           (unsigned)created)
        sched_yield();
    atomic_store_explicit(&start, true, memory_order_release);
    bool converged = created == NPROBES;
    for (int i = 0; i < created; i++) {
        if (pthread_join(threads[i], NULL) != 0)
            converged = false;
    }
    for (int i = 1; i < created; i++)
        if (probes[i].available != probes[0].available)
            converged = false;
#if defined(__aarch64__) || defined(__x86_64__) || defined(_M_X64)
    if (created == 0 || !probes[0].available)
        converged = false;
#endif
    if (converged) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

int test_chacha20_isa_parity(void)
{
    printf("\n=== chacha20_isa_parity (portable vs four-block differential oracle) ===\n");
    int failures = 0;
    uint8_t key[32], nonce[12], plain[4096];
    chacha_rng_fill(key, sizeof key);
    chacha_rng_fill(nonce, sizeof nonce);
    chacha_rng_fill(plain, sizeof plain);

    failures += chacha20_isa_concurrent_kat();

    printf("chacha20_isa_parity: compiled=%s KAT-usable=%s AUTO=%s\n",
           chacha20_vector4_compiled() ? "yes" : "no",
           chacha20_vector4_available() ? "yes" : "no",
           chacha20_select_impl(CHACHA20_IMPL_AUTO) != CHACHA20_IMPL_PORTABLE
               ? chacha20_implementation() : "portable");
#if defined(__aarch64__) || defined(__x86_64__) || defined(_M_X64)
    if (!chacha20_vector4_compiled() ||
        !chacha20_vector4_available()) {
        printf("chacha20_isa_parity: mandatory-ABI vector tier unavailable... FAIL\n");
        failures++;
    }
#endif
    {
        /* x86-64 AUTO takes the widest KAT-verified tier (AVX-512F > AVX2 >
         * SSE2) under ZCL_CHACHA20_AUTO_X86_64_TIER; every other target keeps
         * AUTO portable (Apple arm64 switch unchanged). */
        int want_auto = CHACHA20_IMPL_PORTABLE;
#if defined(__x86_64__)
        for (int t = CHACHA20_IMPL_AVX512;
             t > CHACHA20_IMPL_PORTABLE && want_auto == CHACHA20_IMPL_PORTABLE; t--)
            if (chacha20_tier_available((enum chacha20_impl)t)) want_auto = t;
#endif
        bool uses = want_auto != CHACHA20_IMPL_PORTABLE;
        if (chacha20_select_impl(CHACHA20_IMPL_AUTO) != want_auto ||
            chacha20_auto_uses_vector4() != uses ||
            (!uses && strcmp(chacha20_implementation(), "portable C") != 0) ||
            (uses && strcmp(chacha20_implementation(), "portable C") == 0)) {
            printf("chacha20_isa_parity: AUTO does not match the benchmarked promotion... FAIL\n");
            failures++;
        }
    }

    printf("chacha20_isa_parity: complete RFC 7539 block vector... ");
    {
        static const uint8_t kat_nonce[12] = {
            0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00 };
        static const uint8_t want[64] = {
            0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
            0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
            0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
            0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e };
        uint8_t kat_key[32], got[64];
        for (size_t i = 0; i < sizeof kat_key; i++) kat_key[i] = (uint8_t)i;
        chacha20_block(kat_key, 1u, kat_nonce, got);
        if (memcmp(got, want, sizeof want) == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chacha20_isa_parity: every length 0..1024, out-of-place + in-place... ");
    {
        int diffs = 0;
        for (size_t len = 0; len <= 1024; len++)
            diffs += parity_case(key, nonce, 7u, plain, len);
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: randomized parity x2000 (0..4096 bytes)... ");
    {
        int diffs = 0;
        for (int trial = 0; trial < 2000; trial++) {
            size_t len = (size_t)(chacha_rng_next() % 4097u);
            chacha_rng_fill(plain, len);
            diffs += parity_case(key, nonce,
                                 (uint32_t)chacha_rng_next() & UINT32_C(0x00ffffff),
                                 plain, len);
        }
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: counter exhaustion refuses before output... ");
    {
        uint8_t out[193], before[193];
        memset(out, 0x5a, sizeof out); memcpy(before, out, sizeof out);
        chacha20_select_impl(CHACHA20_IMPL_VECTOR4);
        bool max64 = chacha20_encrypt(key, UINT32_MAX, nonce, plain, 64, out);
        memset(out, 0x5a, sizeof out);
        bool max65 = chacha20_encrypt(key, UINT32_MAX, nonce, plain, 65, out);
        bool unchanged65 = memcmp(out, before, sizeof out) == 0;
        memset(out, 0x5a, sizeof out);
        bool near192 = chacha20_encrypt(key, UINT32_MAX - 2u, nonce,
                                        plain, 192, out);
        memset(out, 0x5a, sizeof out);
        bool near193 = chacha20_encrypt(key, UINT32_MAX - 2u, nonce,
                                        plain, 193, out);
        bool unchanged193 = memcmp(out, before, sizeof out) == 0;
        if (max64 && !max65 && unchanged65 && near192 && !near193 && unchanged193)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chacha20_isa_parity: complete AEAD parity at caller boundaries... ");
    {
        static const size_t lens[] = {0,1,7,15,16,17,63,64,65,255,256,257,
                                      564,585,1536,2048,4096};
        uint8_t ref[4096 + 16], got[4096 + 16], opened[4096];
        int diffs = 0;
        for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            size_t len = lens[i];
            chacha20_select_impl(CHACHA20_IMPL_PORTABLE);
            bool a = chacha20poly1305_encrypt(plain, len, plain, 17, nonce,
                                               key, ref);
            chacha20_select_impl(CHACHA20_IMPL_VECTOR4);
            bool b = chacha20poly1305_encrypt(plain, len, plain, 17, nonce,
                                               key, got);
            bool c = b && chacha20poly1305_decrypt(got, len + 16, plain, 17,
                                                    nonce, key, opened);
            if (!a || !b || !c || memcmp(ref, got, len + 16) != 0 ||
                memcmp(opened, plain, len) != 0) diffs++;
        }
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    printf("chacha20_isa_parity: caller-shaped opens authenticate before output... ");
    {
        static const struct { size_t plen, aad_len; } shapes[] = {
            {564u, 0u}, {1536u, 7u}, {65520u, 85u},
        };
        int diffs = 0;
        for (size_t i = 0; i < sizeof shapes / sizeof shapes[0]; i++)
            diffs += caller_open_case(key, nonce, shapes[i].plen,
                                      shapes[i].aad_len);
        if (diffs == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diffs); failures++; }
    }

    failures += rfc8439_vectors();

    failures += chacha20_isa_bench_report(key, nonce);
    failures += chacha20_isa_wide_tiers(key, nonce);
    chacha20_select_impl(CHACHA20_IMPL_AUTO);
    printf("chacha20_isa_parity: %d failure(s)\n", failures);
    return failures;
}
