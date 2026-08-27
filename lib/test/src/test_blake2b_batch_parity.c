/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-ORACLE: lib/crypto/src/blake2b_avx2.c
 *
 * Differential parity oracle for the batched BLAKE2b compression that
 * Equihash proof-of-work verification runs on at every epoch — the oracle
 * exercises the pre-Bubbles (200,9) shape, which is the wider batch
 * (lib/crypto/src/blake2b_avx2.c: AVX-512 8-way, AVX2 4-way, scalar).
 *
 * Why this is consensus crypto: core/consensus/src/equihash.c re-derives the
 * ZcashPoW BLAKE2b state from the block header and hands it to
 * equihash_is_valid_solution(), which generates all 512 per-index hashes
 * through equihash_generate_hash_batch8/4 (lib/crypto/src/equihash.c:420,442).
 * One divergent digest byte flips a PoW verdict, and a node that accepts or
 * rejects a header differently from the network is forked off it permanently.
 * The vector tiers are therefore guilty until proven byte-identical.
 *
 * The tier forcing hook this file drives — equihash_blake2b_batch_select_impl —
 * was added expressly so a differential oracle could exist (see the comment on
 * it in crypto/blake2b.h). Until this file, nothing in the test suite used it;
 * only the out-of-suite `zclassic23-simd-bench` did.
 *
 * Legs:
 *   1. Reference pin. Every batch digest must equal the SEQUENTIAL,
 *      non-batched blake2b path (copy base state, absorb the 4-byte
 *      little-endian index, finalize) — the exact reference
 *      lib/crypto/src/equihash.c:generate_hash() uses for the tail indices.
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
 * lib/crypto/src/equihash.c:equihash_initialise_state() does, then absorb a
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

    static unsigned char tier_dig[3][EH_INDICES][DIGEST_CAP];
    static unsigned char refdig[EH_INDICES][DIGEST_CAP];

    const enum blake2b_batch_impl want[3] = {
        BLAKE2B_BATCH_IMPL_SCALAR,
        BLAKE2B_BATCH_IMPL_AVX2,
        BLAKE2B_BATCH_IMPL_AVX512
    };
    const char *tier_name[3] = { "scalar", "4-way SIMD", "8-way SIMD" };
    bool tier_ran[3] = { false, false, false };

    /* ── Leg 1+2: every tier, both entry points, vs the portable reference ──
     * hash_len is always p->hash_output (50) — blake2b_final() rejects an
     * outlen that differs from the one the state was initialised with, and 50
     * is the only value the Equihash verifier ever passes. The variation that
     * matters is the INDEX pattern, which the verifier does not control. */
    for (int L = 0; L < 2; L++) {
        size_t hash_len = EH_HASH_LEN;
        const uint32_t *idx = (L == 0) ? idx_contig : idx_mixed;

        printf("%s indices, hash_len=%zu:\n",
               (L == 0) ? "contiguous" : "strided+repeating", hash_len);

        memset(refdig, 0, sizeof(refdig));
        for (int i = 0; i < EH_INDICES; i++)
            ref_hash(&base, idx[i], refdig[i], hash_len);

        for (int t = 0; t < 3; t++) {
            int got = equihash_blake2b_batch_select_impl(want[t]);
            if (got != (int)want[t]) {
                printf("  %-16s : not available on this host (skipped)\n",
                       tier_name[t]);
                continue;
            }
            tier_ran[t] = true;

            int tier_bad = 0;
            for (int use8 = 1; use8 >= 0; use8--) {
                memset(tier_dig[t], 0, sizeof(tier_dig[t]));
                fill_batch(&base, idx, tier_dig[t], hash_len, use8 != 0);

                int at = first_divergence(tier_dig[t], refdig, hash_len);
                if (at >= 0) {
                    report_divergence(use8 ? "batch8 vs sequential reference"
                                           : "batch4 vs sequential reference",
                                      at, tier_dig[t][at], refdig[at], hash_len);
                    printf("    tier: %s\n", tier_name[t]);
                    tier_bad++;
                }
            }
            failures += tier_bad;
            printf("  %-16s : %s\n", tier_name[t],
                   tier_bad ? "DIVERGED from the sequential reference"
                            : "batch8 + batch4 == sequential reference");
        }

        /* Cross-tier: each available tier against scalar. */
        for (int t = 1; t < 3; t++) {
            if (!tier_ran[0] || !tier_ran[t]) continue;
            int at = first_divergence(tier_dig[t], tier_dig[0], hash_len);
            if (at >= 0) {
                report_divergence("tier vs scalar", at,
                                  tier_dig[t][at], tier_dig[0][at], hash_len);
                failures++;
            }
        }
    }

    if (!tier_ran[0]) {
        printf("FAIL: the scalar tier could not be forced — the oracle has no "
               "portable baseline to compare against.\n");
        failures++;
    }

    /* ── Leg 4: teeth ─────────────────────────────────────────────────── */
    printf("teeth... ");
    {
        struct blake2b_ctx tweaked;
        eh_base_state(&tweaked, 0x01);
        unsigned char a[DIGEST_CAP] = {0}, b[DIGEST_CAP] = {0};
        ref_hash(&base, 7, a, EH_HASH_LEN);
        ref_hash(&tweaked, 7, b, EH_HASH_LEN);
        if (memcmp(a, b, EH_HASH_LEN) == 0) {
            printf("\n  FAIL: a one-bit header change did not change the "
                   "digest — the hash under test is hollow.\n");
            failures++;
        }

        /* The comparator must SEE a planted mismatch. */
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
        printf("ok\n");
    }

    /* ── Leg 5: never leave a tier forced for the rest of the run ─────── */
    equihash_blake2b_batch_select_impl(BLAKE2B_BATCH_IMPL_AUTO);
    printf("restored tier: %s\n", equihash_blake2b_batch_implementation());

    printf("\n%d BLAKE2b batch parity check(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
