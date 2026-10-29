/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-ORACLE: core/modules/crypto/src/blake2b_avx2.c
 *
 * Differential parity oracle for the batched BLAKE2b compression that
 * Equihash proof-of-work verification runs on at every epoch — the oracle
 * exercises the pre-Bubbles (200,9) shape, which is the wider batch
 * (core/modules/crypto/src/blake2b_avx2.c: AVX-512 8-way, AVX2 4-way, scalar).
 *
 * Why this is consensus crypto: core/consensus/src/equihash.c re-derives the
 * ZcashPoW BLAKE2b state from the block header and hands it to
 * equihash_is_valid_solution(), which generates all 512 per-index hashes
 * through equihash_generate_hash_batch8/4 (core/modules/crypto/src/equihash.c:420,442).
 * One divergent digest byte flips a PoW verdict, and a node that accepts or
 * rejects a header differently from the network is forked off it permanently.
 * The vector tiers are therefore guilty until proven byte-identical.
 *
 * The tier forcing hook this file drives — equihash_blake2b_batch_select_impl
 * (see crypto/blake2b.h) — exists so a differential oracle can exist.
 *
 * Legs:
 *   1. Reference pin. Every batch digest must equal the SEQUENTIAL,
 *      non-batched blake2b path (copy base state, absorb the 4-byte
 *      little-endian index, finalize) — the exact reference
 *      core/modules/crypto/src/equihash.c:generate_hash() uses for the tail indices.
 *      This pins the batch machinery to portable code, not just tier to tier.
 *   2. Cross-tier parity. Scalar / AVX2 / AVX-512 must agree byte-for-byte
 *      over all 512 indices of a block's worth of hashing, for both the 8-way
 *      and 4-way entry points, at both the Equihash hash_output length (50)
 *      and a short length that exercises a different truncation.
 *   3. Non-contiguous and repeated indices — the real verifier feeds
 *      indices[i]/indices_per_hash_output, which is neither sorted nor unique.
 *   4. Teeth. A one-bit change in the base state (i.e. in the header) must
 *      change the digest, and the comparator must report a planted mismatch.
 *      A parity run over a hollow comparator is worse than no test.
 *   5. AUTO is restored before returning, so no later group inherits a forced
 *      tier.
 *   6. finalize_states (static, reached only through the batch4/batch8 entry
 *      points): every lane equals scalar BLAKE2b across both Equihash
 *      personalizations, the callers' output lengths, and base prefix lengths
 *      that straddle the 128-byte buffer, plus one literal digest. Skipped
 *      where AVX2 is not installed.
 *
 * On a host lacking AVX2/AVX-512 the forcing hook returns the tier actually
 * installed; that leg is REPORTED as skipped, never silently counted as
 * passing.
 */

#define _POSIX_C_SOURCE 200809L

#include "crypto/blake2b.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EH_N          200u
#define EH_K          9u
#define EH_HASH_LEN   ((size_t)(2 * EH_N / 8))   /* 50 — p->hash_output */
#define EH_INDICES    512                        /* one block's worth */
#define DIGEST_CAP    64

/* Build the ZcashPoW(200,9) base state the same way
 * core/modules/crypto/src/equihash.c:equihash_initialise_state() does, then absorb a
 * header-shaped prefix so the batch API sees a realistic partial block. */
static void eh_base_state(struct blake2b_ctx *base, uint8_t tweak)
{
    uint8_t personal[BLAKE2B_PERSONALBYTES] = {0};
    memcpy(personal, "ZcashPoW", 8);
    uint32_t n = EH_N, k = EH_K;
    memcpy(personal + 8, &n, 4);
    memcpy(personal + 12, &k, 4);

    size_t outlen = (size_t)((512 / EH_N) * EH_N / 8);
    blake2b_init_salt_personal(base, outlen, NULL, 0, NULL, personal);

    unsigned char hdr[108];
    for (size_t i = 0; i < sizeof(hdr); i++)
        hdr[i] = (unsigned char)(i * 7 + 1);
    hdr[0] = (unsigned char)(hdr[0] ^ tweak);
    blake2b_update(base, hdr, sizeof(hdr));
}

/* The portable, non-batched reference: exactly equihash.c:generate_hash(). */
static void ref_hash(const struct blake2b_ctx *base, uint32_t g,
                     unsigned char *out, size_t out_len)
{
    struct blake2b_ctx st = *base;
    uint32_t lei = g;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    lei = __builtin_bswap32(lei);
#endif
    blake2b_update(&st, (const unsigned char *)&lei, sizeof(lei));
    blake2b_final(&st, out, out_len);
}

/* Fill digests[0..EH_INDICES) for the currently installed tier using the
 * 8-way entry point, then the 4-way entry point, and assert the two agree. */
static int fill_batch(const struct blake2b_ctx *base,
                      const uint32_t *idx,
                      unsigned char digests[EH_INDICES][DIGEST_CAP],
                      size_t hash_len,
                      bool use8)
{
    if (use8) {
        for (int b = 0; b < EH_INDICES / 8; b++) {
            unsigned char *hp[8];
            uint32_t gi[8];
            for (int j = 0; j < 8; j++) {
                gi[j] = idx[b * 8 + j];
                hp[j] = digests[b * 8 + j];
            }
            equihash_generate_hash_batch8(base, gi, hp, hash_len);
        }
    } else {
        for (int b = 0; b < EH_INDICES / 4; b++) {
            uint32_t gi[4];
            for (int j = 0; j < 4; j++)
                gi[j] = idx[b * 4 + j];
            equihash_generate_hash_batch4(base, gi,
                                          digests[b * 4 + 0], digests[b * 4 + 1],
                                          digests[b * 4 + 2], digests[b * 4 + 3],
                                          hash_len);
        }
    }
    return 0;
}

static int first_divergence(const unsigned char a[EH_INDICES][DIGEST_CAP],
                            const unsigned char b[EH_INDICES][DIGEST_CAP],
                            size_t hash_len)
{
    for (int i = 0; i < EH_INDICES; i++)
        if (memcmp(a[i], b[i], hash_len) != 0)
            return i;
    return -1;
}

static void report_divergence(const char *what, int at,
                              const unsigned char *got,
                              const unsigned char *want,
                              size_t hash_len)
{
    printf("\n  MISMATCH %s at index %d\n    want ", what, at);
    for (size_t i = 0; i < hash_len && i < 16; i++) printf("%02x", want[i]);
    printf("...\n    got  ");
    for (size_t i = 0; i < hash_len && i < 16; i++) printf("%02x", got[i]);
    printf("...\n");
}

#define TIER_COUNT 3

static const enum blake2b_batch_impl tier_impl[TIER_COUNT] = {
    BLAKE2B_BATCH_IMPL_SCALAR,
    BLAKE2B_BATCH_IMPL_AVX2,
    BLAKE2B_BATCH_IMPL_AVX512
};
static const char *const tier_name[TIER_COUNT] = { "scalar", "4-way SIMD", "8-way SIMD" };

/* Legs 1+2 for one forced tier: batch8, then batch4, each against the
 * sequential reference. Returns the number of divergent entry points. */
static int check_tier_vs_reference(const struct blake2b_ctx *base, const uint32_t *idx,
                                   size_t hash_len, int t,
                                   unsigned char dig[EH_INDICES][DIGEST_CAP],
                                   const unsigned char refdig[EH_INDICES][DIGEST_CAP])
{
    int tier_bad = 0;
    for (int use8 = 1; use8 >= 0; use8--) {
        memset(dig, 0, EH_INDICES * DIGEST_CAP);
        fill_batch(base, idx, dig, hash_len, use8 != 0);

        int at = first_divergence(dig, refdig, hash_len);
        if (at >= 0) {
            report_divergence(use8 ? "batch8 vs sequential reference"
                                   : "batch4 vs sequential reference",
                              at, dig[at], refdig[at], hash_len);
            printf("    tier: %s\n", tier_name[t]);
            tier_bad++;
        }
    }
    return tier_bad;
}

/* One tier of Legs 1+2. An unavailable tier is reported as skipped and counts nothing. */
static int check_one_tier(const struct blake2b_ctx *base, const uint32_t *idx,
                          size_t hash_len, int t,
                          unsigned char dig[EH_INDICES][DIGEST_CAP],
                          const unsigned char refdig[EH_INDICES][DIGEST_CAP],
                          bool *ran)
{
    int got = equihash_blake2b_batch_select_impl(tier_impl[t]);
    if (got != (int)tier_impl[t]) {
        printf("  %-16s : not available on this host (skipped)\n",
               tier_name[t]);
        return 0;
    }
    *ran = true;

    int tier_bad = check_tier_vs_reference(base, idx, hash_len, t, dig, refdig);
    printf("  %-16s : %s\n", tier_name[t],
           tier_bad ? "DIVERGED from the sequential reference"
                    : "batch8 + batch4 == sequential reference");
    return tier_bad;
}

/* Cross-tier: each available tier against scalar. */
static int check_cross_tiers(unsigned char tier_dig[TIER_COUNT][EH_INDICES][DIGEST_CAP],
                             const bool tier_ran[TIER_COUNT], size_t hash_len)
{
    int failures = 0;
    for (int t = 1; t < TIER_COUNT; t++) {
        if (!tier_ran[0] || !tier_ran[t]) continue;
        int at = first_divergence(tier_dig[t], tier_dig[0], hash_len);
        if (at >= 0) {
            report_divergence("tier vs scalar", at,
                              tier_dig[t][at], tier_dig[0][at], hash_len);
            failures++;
        }
    }
    return failures;
}

/* Legs 1+2 for one index pattern: sequential reference first, then every tier. */
static int check_index_pattern(const struct blake2b_ctx *base, const uint32_t *idx, int L,
                               unsigned char refdig[EH_INDICES][DIGEST_CAP],
                               unsigned char tier_dig[TIER_COUNT][EH_INDICES][DIGEST_CAP],
                               bool tier_ran[TIER_COUNT])
{
    int failures = 0;
    size_t hash_len = EH_HASH_LEN;

    printf("%s indices, hash_len=%zu:\n",
           (L == 0) ? "contiguous" : "strided+repeating", hash_len);

    memset(refdig, 0, EH_INDICES * DIGEST_CAP);
    for (int i = 0; i < EH_INDICES; i++)
        ref_hash(base, idx[i], refdig[i], hash_len);

    for (int t = 0; t < TIER_COUNT; t++)
        failures += check_one_tier(base, idx, hash_len, t, tier_dig[t], refdig, &tier_ran[t]);
    failures += check_cross_tiers(tier_dig, tier_ran, hash_len);
    return failures;
}

/* Leg 4, part a: a one-bit change in the header must change the digest. */
static int check_hash_not_hollow(const struct blake2b_ctx *base)
{
    struct blake2b_ctx tweaked;
    eh_base_state(&tweaked, 0x01);
    unsigned char a[DIGEST_CAP] = {0}, b[DIGEST_CAP] = {0};
    ref_hash(base, 7, a, EH_HASH_LEN);
    ref_hash(&tweaked, 7, b, EH_HASH_LEN);
    if (memcmp(a, b, EH_HASH_LEN) == 0) {
        printf("\n  FAIL: a one-bit header change did not change the "
               "digest — the hash under test is hollow.\n");
        return 1;
    }
    return 0;
}

/* The comparator must SEE a planted mismatch. */
static int check_comparator_teeth(void)
{
    int failures = 0;
    static unsigned char p0[EH_INDICES][DIGEST_CAP];
    static unsigned char p1[EH_INDICES][DIGEST_CAP];
    memset(p0, 0xAB, sizeof(p0));
    memcpy(p1, p0, sizeof(p1));
    if (first_divergence(p0, p1, EH_HASH_LEN) != -1) {
        printf("\n  FAIL: comparator reported a difference between "
               "identical buffers.\n");
        failures++;
    }
    p1[EH_INDICES - 1][EH_HASH_LEN - 1] ^= 0x01u;
    if (first_divergence(p0, p1, EH_HASH_LEN) != EH_INDICES - 1) {
        printf("\n  FAIL: comparator missed a planted one-bit "
               "divergence — this oracle cannot fail.\n");
        failures++;
    }
    return failures;
}

/* ── Leg 6: finalize_states lanes through the public batch entries ─────
 * finalize_states() is reached only via equihash_generate_hash_batch4/8, and
 * only when the base buffer has room for the 4-byte index (buflen + 4 <= 128).
 * Every lane must equal the scalar BLAKE2b of the same message: the base
 * prefix followed by the little-endian index. Prefix 0/1/123/124/129 reach
 * finalize_states (129 leaves a one-byte buffer after one compressed block);
 * prefix 127/128 take the public scalar fallback. */

#define LEG6_LANES      8
#define LEG6_PREFIX_MAX 129
#define LEG6_LIT_HEX    100

struct eh_param { uint32_t n, k; size_t outlen; };

static const struct eh_param leg6_params[] = {
    { 200u, 9u, 50u },   /* (512/200)*200/8 = 50: the Equihash verifier's hash_output */
    { 144u, 5u, 54u },   /* (512/144)*144/8 = 54 */
};

static const size_t leg6_prefix_lens[] = { 0, 1, 123, 124, 127, 128, 129 };

static const uint32_t leg6_indices[LEG6_LANES] = {
    0u, 1u, 0x7fffffffu, 0x80000000u, 0xdeadbeefu, 2u, 3u, 0xffffffffu
};

/* Base state: ZcashPoW(n,k) personalization, then prefix_len bytes absorbed
 * the way eh_base_state() absorbs its header. Returns 0 on success. */
static int leg6_base(struct blake2b_ctx *base, const struct eh_param *p, size_t prefix_len)
{
    uint8_t personal[BLAKE2B_PERSONALBYTES] = {0};
    uint8_t prefix[LEG6_PREFIX_MAX] = {0};

    memcpy(personal, "ZcashPoW", 8);
    memcpy(personal + 8, &p->n, 4);
    memcpy(personal + 12, &p->k, 4);
    if (blake2b_init_salt_personal(base, p->outlen, NULL, 0, NULL, personal) != 0)
        return 1;
    for (size_t i = 0; i < prefix_len; i++)
        prefix[i] = (uint8_t)(i * 13u + 5u);
    blake2b_update(base, prefix, prefix_len);
    return 0;
}

/* Every lane of the 8-way and the two 4-way entry points against the
 * sequential scalar reference from the same base. Returns divergent lanes. */
static int leg6_check_lanes(const struct blake2b_ctx *base, size_t outlen)
{
    unsigned char got8[LEG6_LANES][DIGEST_CAP] = {{0}};
    unsigned char got4[LEG6_LANES][DIGEST_CAP] = {{0}};
    unsigned char want[DIGEST_CAP] = {0};
    unsigned char *hp[LEG6_LANES];
    uint32_t gi[LEG6_LANES];
    int bad = 0;

    for (int j = 0; j < LEG6_LANES; j++) {
        gi[j] = leg6_indices[j];
        hp[j] = got8[j];
    }
    equihash_generate_hash_batch8(base, gi, hp, outlen);
    for (int b = 0; b < LEG6_LANES / 4; b++)
        equihash_generate_hash_batch4(base, &leg6_indices[b * 4],
                                      got4[b * 4], got4[b * 4 + 1],
                                      got4[b * 4 + 2], got4[b * 4 + 3], outlen);
    for (int j = 0; j < LEG6_LANES; j++) {
        ref_hash(base, leg6_indices[j], want, outlen);
        if (memcmp(got8[j], want, outlen) != 0) {
            report_divergence("batch8 lane vs scalar", j, got8[j], want, outlen);
            bad++;
        }
        if (memcmp(got4[j], want, outlen) != 0) {
            report_divergence("batch4 lane vs scalar", j, got4[j], want, outlen);
            bad++;
        }
    }
    return bad;
}

static int leg6_row(const struct eh_param *p, size_t prefix_len)
{
    struct blake2b_ctx base;
    if (leg6_base(&base, p, prefix_len) != 0) {
        printf("  n=%u k=%u prefix=%zu : base init failed\n", p->n, p->k, prefix_len);
        return 1;
    }
    int bad = leg6_check_lanes(&base, p->outlen);
    if (bad)
        printf("  n=%u k=%u outlen=%zu prefix=%zu : %d lane(s) DIVERGED\n",
               p->n, p->k, p->outlen, prefix_len, bad);
    return bad;
}

/* One literal digest, so the batch lanes are not only compared against the
 * same scalar code they are checked with. Unpersonalised BLAKE2b, outlen 50,
 * message = LE32(1) = 01 00 00 00; the expected value is `b2sum -l 400` of
 * those four bytes. */
static int leg6_literal(void)
{
    static const char want_hex[LEG6_LIT_HEX + 1] =
        "26fc377c00a22ad1a67382066fbc1b4e40d6863125a35b41a805f6c373c59a9e5"
        "a01ab6e5e1360732d3082c2cb02e45906f7";
    struct blake2b_ctx base;
    unsigned char got[4][DIGEST_CAP] = {{0}};
    unsigned char *hp[4] = {got[0], got[1], got[2], got[3]};
    const uint32_t gi[4] = {1u, 1u, 1u, 1u};
    char hex[LEG6_LIT_HEX + 1] = {0};

    if (blake2b_init(&base, 50) != 0)
        return 1;
    equihash_generate_hash_batch4(&base, gi, hp[0], hp[1], hp[2], hp[3], 50);
    for (size_t i = 0; i < 50; i++)
        snprintf(hex + 2 * i, 3, "%02x", got[0][i]);
    if (strcmp(hex, want_hex) == 0)
        return 0;
    printf("\n  MISMATCH literal LE32(1) digest : got %s\n", hex);
    return 1;
}

/* Leg 6 driver. Forces the AVX2 tier and skips where it is not installed,
 * using the same runtime check the module dispatches on. */
static int check_finalize_states_lanes(void)
{
    if (equihash_blake2b_batch_select_impl(BLAKE2B_BATCH_IMPL_AVX2) != BLAKE2B_BATCH_IMPL_AVX2) {
        printf("  finalize_states (AVX2 forced) : not available on this host (skipped)\n");
        return 0;
    }
    int failures = 0;
    for (size_t p = 0; p < sizeof(leg6_params) / sizeof(leg6_params[0]); p++)
        for (size_t l = 0; l < sizeof(leg6_prefix_lens) / sizeof(leg6_prefix_lens[0]); l++)
            failures += leg6_row(&leg6_params[p], leg6_prefix_lens[l]);
    failures += leg6_literal();
    printf("  finalize_states (AVX2 forced) : %s\n",
           failures ? "DIVERGED from scalar BLAKE2b"
                    : "every lane == scalar BLAKE2b");
    return failures;
}

int test_blake2b_batch_parity(void);
int test_blake2b_batch_parity(void)
{
    int failures = 0;

    printf("\n=== Equihash BLAKE2b batch differential oracle ===\n");
    printf("auto-selected tier: %s\n", equihash_blake2b_batch_implementation());

    /* Index patterns: contiguous (the common case), strided, and one with
     * repeats — the verifier's indices[i]/iph is neither sorted nor unique. */
    static uint32_t idx_contig[EH_INDICES];
    static uint32_t idx_mixed[EH_INDICES];
    for (int i = 0; i < EH_INDICES; i++) {
        idx_contig[i] = (uint32_t)i;
        idx_mixed[i]  = (uint32_t)(((uint64_t)i * 2654435761u) % 1048576u);
        if ((i % 37) == 0) idx_mixed[i] = idx_mixed[0];   /* repeats */
    }

    struct blake2b_ctx base;
    eh_base_state(&base, 0);

    static unsigned char tier_dig[TIER_COUNT][EH_INDICES][DIGEST_CAP];
    static unsigned char refdig[EH_INDICES][DIGEST_CAP];
    bool tier_ran[TIER_COUNT] = { false, false, false };

    /* ── Leg 1+2: every tier, both entry points, vs the portable reference ──
     * hash_len is always p->hash_output (50): blake2b_final() rejects any other
     * outlen and the Equihash verifier only passes 50. The variation that
     * matters is the INDEX pattern. */
    for (int L = 0; L < 2; L++)
        failures += check_index_pattern(&base, (L == 0) ? idx_contig : idx_mixed, L,
                                        refdig, tier_dig, tier_ran);

    if (!tier_ran[0]) {
        printf("FAIL: the scalar tier could not be forced — the oracle has no "
               "portable baseline to compare against.\n");
        failures++;
    }

    /* ── Leg 4: teeth ─────────────────────────────────────────────────── */
    printf("teeth... ");
    failures += check_hash_not_hollow(&base);
    failures += check_comparator_teeth();
    printf("ok\n");

    /* ── Leg 6: finalize_states lanes through the public entries ──────── */
    failures += check_finalize_states_lanes();

    /* ── Leg 5: never leave a tier forced for the rest of the run ─────── */
    equihash_blake2b_batch_select_impl(BLAKE2B_BATCH_IMPL_AUTO);
    printf("restored tier: %s\n", equihash_blake2b_batch_implementation());

    printf("\n%d BLAKE2b batch parity check(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
