/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * THE 4-way lane-parallel Keccak-f[1600] permutation. One implementation,
 * shared by both batched SHA3 surfaces:
 *
 *   sha3_avx512.c   — SHA3-512 x4 keystream (file-transfer frame cipher)
 *   sha3_256_x4.c   — SHA3-256 x4 batch    (snapshot manifest / Merkle layers)
 *
 * It used to be two: each file carried its own copy, and they had drifted into
 * different instruction selections for identical math — one spelled the lane
 * rotate as shift|shift|or and chi as andnot+xor, the other used vprolq and
 * vpternlogq. Same bytes out, 1.5x apart in speed, with nothing to make the
 * slower copy notice. Deleting the copy is what keeps them equal.
 *
 * Geometry: st[25], each __m512i holding 8 independent Keccak instances in its
 * 8 uint64 slots; callers drive the low 4 and leave slots 4..7 zero (they are
 * inert — every step is lane-parallel, so a dead slot only ever produces
 * another dead slot). There is NO cross-lane shuffle anywhere in here, which is
 * exactly why this shape wins on a double-pumped 512-bit unit while a
 * single-stream AVX-512 Keccak (dominated by the cross-lane pi gather) loses.
 *
 * Kept `static inline` in a header rather than exported from a .c file so each
 * absorb loop still inlines the permutation and keeps the state in registers;
 * an out-of-line call would spill 25 zmm registers per block.
 *
 * The target attribute lets this compile into the shipped -march=x86-64-v3
 * baseline. Callers must confirm keccak_x4_available() first.
 *
 * arm64 carries the same contract on NEON: a uint64x2_t holds TWO batched
 * instances, so the four instances live as a PAIR of uint64x2_t per Keccak
 * word — the mirror of "4 of the 8 uint64 slots of each __m512i". Every step
 * stays lane-parallel (no cross-slot shuffle); the permutation is written over
 * one 25-word 2-lane state and applied to both halves, so each half keeps all
 * 25 vectors in registers instead of spilling a 50-vector working set. EOR3
 * (FEAT_SHA3) plays the role of vpternlogq imm 0x96 in theta. */

#ifndef ZCL_CRYPTO_KECCAK_X4_INTERNAL_H
#define ZCL_CRYPTO_KECCAK_X4_INTERNAL_H

/* keccak_x4_available() — the CPUID + XCR0 gate every caller must pass before
 * reaching the permutation below — is declared in crypto/sha3.h beside the
 * batched surfaces it gates, and defined in keccak_x4.c. */
#include "crypto/sha3.h"

#include <stdbool.h>
#include <stdint.h>

#if defined(__x86_64__)

#include <immintrin.h>

__attribute__((target("avx512f,avx512vl,avx512dq")))
static inline void keccak_x4_permute(__m512i st[25])
{
    static const uint64_t RNDC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };

    /* vprolq: one instruction per lane rotate. */
    #define ROL4(x, n) _mm512_rol_epi64((x), (n))

    for (int round = 0; round < 24; ++round) {
        /* theta — column parity via 3-input XOR (vpternlogq imm 0x96) */
        __m512i bc0 = _mm512_ternarylogic_epi64(_mm512_xor_si512(st[0], st[5]),
                                                _mm512_xor_si512(st[10], st[15]), st[20], 0x96);
        __m512i bc1 = _mm512_ternarylogic_epi64(_mm512_xor_si512(st[1], st[6]),
                                                _mm512_xor_si512(st[11], st[16]), st[21], 0x96);
        __m512i bc2 = _mm512_ternarylogic_epi64(_mm512_xor_si512(st[2], st[7]),
                                                _mm512_xor_si512(st[12], st[17]), st[22], 0x96);
        __m512i bc3 = _mm512_ternarylogic_epi64(_mm512_xor_si512(st[3], st[8]),
                                                _mm512_xor_si512(st[13], st[18]), st[23], 0x96);
        __m512i bc4 = _mm512_ternarylogic_epi64(_mm512_xor_si512(st[4], st[9]),
                                                _mm512_xor_si512(st[14], st[19]), st[24], 0x96);

        __m512i t;
        t = _mm512_xor_si512(bc4, ROL4(bc1, 1));
        st[0] = _mm512_xor_si512(st[0], t); st[5] = _mm512_xor_si512(st[5], t);
        st[10] = _mm512_xor_si512(st[10], t); st[15] = _mm512_xor_si512(st[15], t);
        st[20] = _mm512_xor_si512(st[20], t);
        t = _mm512_xor_si512(bc0, ROL4(bc2, 1));
        st[1] = _mm512_xor_si512(st[1], t); st[6] = _mm512_xor_si512(st[6], t);
        st[11] = _mm512_xor_si512(st[11], t); st[16] = _mm512_xor_si512(st[16], t);
        st[21] = _mm512_xor_si512(st[21], t);
        t = _mm512_xor_si512(bc1, ROL4(bc3, 1));
        st[2] = _mm512_xor_si512(st[2], t); st[7] = _mm512_xor_si512(st[7], t);
        st[12] = _mm512_xor_si512(st[12], t); st[17] = _mm512_xor_si512(st[17], t);
        st[22] = _mm512_xor_si512(st[22], t);
        t = _mm512_xor_si512(bc2, ROL4(bc4, 1));
        st[3] = _mm512_xor_si512(st[3], t); st[8] = _mm512_xor_si512(st[8], t);
        st[13] = _mm512_xor_si512(st[13], t); st[18] = _mm512_xor_si512(st[18], t);
        st[23] = _mm512_xor_si512(st[23], t);
        t = _mm512_xor_si512(bc3, ROL4(bc0, 1));
        st[4] = _mm512_xor_si512(st[4], t); st[9] = _mm512_xor_si512(st[9], t);
        st[14] = _mm512_xor_si512(st[14], t); st[19] = _mm512_xor_si512(st[19], t);
        st[24] = _mm512_xor_si512(st[24], t);

        /* rho + pi — a fixed rotate of each word plus a rename of the 25
         * registers; the word index does the permuting, so no lane moves. */
        t = st[1];
        __m512i tmp;
        tmp = st[10]; st[10] = ROL4(t, 1);  t = tmp;
        tmp = st[7];  st[7]  = ROL4(t, 3);  t = tmp;
        tmp = st[11]; st[11] = ROL4(t, 6);  t = tmp;
        tmp = st[17]; st[17] = ROL4(t, 10); t = tmp;
        tmp = st[18]; st[18] = ROL4(t, 15); t = tmp;
        tmp = st[3];  st[3]  = ROL4(t, 21); t = tmp;
        tmp = st[5];  st[5]  = ROL4(t, 28); t = tmp;
        tmp = st[16]; st[16] = ROL4(t, 36); t = tmp;
        tmp = st[8];  st[8]  = ROL4(t, 45); t = tmp;
        tmp = st[21]; st[21] = ROL4(t, 55); t = tmp;
        tmp = st[24]; st[24] = ROL4(t, 2);  t = tmp;
        tmp = st[4];  st[4]  = ROL4(t, 14); t = tmp;
        tmp = st[15]; st[15] = ROL4(t, 27); t = tmp;
        tmp = st[23]; st[23] = ROL4(t, 41); t = tmp;
        tmp = st[19]; st[19] = ROL4(t, 56); t = tmp;
        tmp = st[13]; st[13] = ROL4(t, 8);  t = tmp;
        tmp = st[12]; st[12] = ROL4(t, 25); t = tmp;
        tmp = st[2];  st[2]  = ROL4(t, 43); t = tmp;
        tmp = st[20]; st[20] = ROL4(t, 62); t = tmp;
        tmp = st[14]; st[14] = ROL4(t, 18); t = tmp;
        tmp = st[22]; st[22] = ROL4(t, 39); t = tmp;
        tmp = st[9];  st[9]  = ROL4(t, 61); t = tmp;
        tmp = st[6];  st[6]  = ROL4(t, 20); t = tmp;
        st[1] = ROL4(t, 44);

        /* chi — new[x] = s[x] ^ (~s[x+1] & s[x+2]), one vpternlogq imm 0xD2 */
        for (int j = 0; j < 25; j += 5) {
            __m512i s0 = st[j], s1 = st[j+1], s2 = st[j+2];
            __m512i s3 = st[j+3], s4 = st[j+4];
            st[j]   = _mm512_ternarylogic_epi64(s0, s1, s2, 0xD2);
            st[j+1] = _mm512_ternarylogic_epi64(s1, s2, s3, 0xD2);
            st[j+2] = _mm512_ternarylogic_epi64(s2, s3, s4, 0xD2);
            st[j+3] = _mm512_ternarylogic_epi64(s3, s4, s0, 0xD2);
            st[j+4] = _mm512_ternarylogic_epi64(s4, s0, s1, 0xD2);
        }

        /* iota */
        st[0] = _mm512_xor_si512(st[0], _mm512_set1_epi64((long long)RNDC[round]));
    }
    #undef ROL4
}

#elif defined(__aarch64__)

#include <arm_neon.h>

/* EOR3 is FEAT_SHA3's three-input XOR — the arm64 counterpart of vpternlogq
 * imm 0x96 in theta. Compile-time guarded so the same source still builds for
 * an armv8-a target whose baseline lacks the SHA3 extension (a plain
 * two-input fold there; nothing changes byte-wise). Whether the tier is
 * reached at all is decided at RUNTIME by the probe in keccak_x4.c. */
#if defined(__ARM_FEATURE_SHA3)
#define X4_EOR3(a, b, c) veor3q_u64((a), (b), (c))
#else
#define X4_EOR3(a, b, c) veorq_u64(veorq_u64((a), (b)), (c))
#endif

/* rotl64 across both 64-bit slots: SHL then SRI (shift-right-and-insert). SRI
 * writes the low 64-n bits of (x >> (64-n)) over exactly the zero lanes the
 * SHL left, so the pair is the whole rotate — the counterpart of vprolq.
 * Every caller rotates by 1..63, which both immediates allow. */
#define X4_ROL(x, n) vsriq_n_u64(vshlq_n_u64((x), (n)), (x), 64 - (n))

/* The permutation over ONE 2-lane state: st[w] is Keccak word w of two
 * independent instances (slot 0 and slot 1 of the vector). Register budget is
 * the reason this is 2 lanes rather than 4: 25 uint64x2_t fit in the 32
 * ASIMD registers with room for the theta/chi temporaries, the way 25 __m512i
 * fit in the 32 zmm registers on x86. */
static inline void keccak_x2_permute(uint64x2_t st[25])
{
    static const uint64_t RNDC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };

    for (int round = 0; round < 24; ++round) {
        /* theta — column parity of the five columns via two EOR3 folds */
        uint64x2_t bc0 = X4_EOR3(X4_EOR3(st[0], st[5], st[10]), st[15], st[20]);
        uint64x2_t bc1 = X4_EOR3(X4_EOR3(st[1], st[6], st[11]), st[16], st[21]);
        uint64x2_t bc2 = X4_EOR3(X4_EOR3(st[2], st[7], st[12]), st[17], st[22]);
        uint64x2_t bc3 = X4_EOR3(X4_EOR3(st[3], st[8], st[13]), st[18], st[23]);
        uint64x2_t bc4 = X4_EOR3(X4_EOR3(st[4], st[9], st[14]), st[19], st[24]);

        uint64x2_t t;
        t = veorq_u64(bc4, X4_ROL(bc1, 1));
        st[0] = veorq_u64(st[0], t); st[5] = veorq_u64(st[5], t);
        st[10] = veorq_u64(st[10], t); st[15] = veorq_u64(st[15], t);
        st[20] = veorq_u64(st[20], t);
        t = veorq_u64(bc0, X4_ROL(bc2, 1));
        st[1] = veorq_u64(st[1], t); st[6] = veorq_u64(st[6], t);
        st[11] = veorq_u64(st[11], t); st[16] = veorq_u64(st[16], t);
        st[21] = veorq_u64(st[21], t);
        t = veorq_u64(bc1, X4_ROL(bc3, 1));
        st[2] = veorq_u64(st[2], t); st[7] = veorq_u64(st[7], t);
        st[12] = veorq_u64(st[12], t); st[17] = veorq_u64(st[17], t);
        st[22] = veorq_u64(st[22], t);
        t = veorq_u64(bc2, X4_ROL(bc4, 1));
        st[3] = veorq_u64(st[3], t); st[8] = veorq_u64(st[8], t);
        st[13] = veorq_u64(st[13], t); st[18] = veorq_u64(st[18], t);
        st[23] = veorq_u64(st[23], t);
        t = veorq_u64(bc3, X4_ROL(bc0, 1));
        st[4] = veorq_u64(st[4], t); st[9] = veorq_u64(st[9], t);
        st[14] = veorq_u64(st[14], t); st[19] = veorq_u64(st[19], t);
        st[24] = veorq_u64(st[24], t);

        /* rho + pi — same fixed rotate-and-rename walk as the x86 tier; the
         * word index does the permuting, so no slot moves. */
        t = st[1];
        uint64x2_t tmp;
        tmp = st[10]; st[10] = X4_ROL(t, 1);  t = tmp;
        tmp = st[7];  st[7]  = X4_ROL(t, 3);  t = tmp;
        tmp = st[11]; st[11] = X4_ROL(t, 6);  t = tmp;
        tmp = st[17]; st[17] = X4_ROL(t, 10); t = tmp;
        tmp = st[18]; st[18] = X4_ROL(t, 15); t = tmp;
        tmp = st[3];  st[3]  = X4_ROL(t, 21); t = tmp;
        tmp = st[5];  st[5]  = X4_ROL(t, 28); t = tmp;
        tmp = st[16]; st[16] = X4_ROL(t, 36); t = tmp;
        tmp = st[8];  st[8]  = X4_ROL(t, 45); t = tmp;
        tmp = st[21]; st[21] = X4_ROL(t, 55); t = tmp;
        tmp = st[24]; st[24] = X4_ROL(t, 2);  t = tmp;
        tmp = st[4];  st[4]  = X4_ROL(t, 14); t = tmp;
        tmp = st[15]; st[15] = X4_ROL(t, 27); t = tmp;
        tmp = st[23]; st[23] = X4_ROL(t, 41); t = tmp;
        tmp = st[19]; st[19] = X4_ROL(t, 56); t = tmp;
        tmp = st[13]; st[13] = X4_ROL(t, 8);  t = tmp;
        tmp = st[12]; st[12] = X4_ROL(t, 25); t = tmp;
        tmp = st[2];  st[2]  = X4_ROL(t, 43); t = tmp;
        tmp = st[20]; st[20] = X4_ROL(t, 62); t = tmp;
        tmp = st[14]; st[14] = X4_ROL(t, 18); t = tmp;
        tmp = st[22]; st[22] = X4_ROL(t, 39); t = tmp;
        tmp = st[9];  st[9]  = X4_ROL(t, 61); t = tmp;
        tmp = st[6];  st[6]  = X4_ROL(t, 20); t = tmp;
        st[1] = X4_ROL(t, 44);

        /* chi — new[x] = s[x] ^ (~s[x+1] & s[x+2]): BIC + EOR, no three-input
         * form on NEON (FEAT_SHA3 adds EOR3, not an AND3). */
        for (int j = 0; j < 25; j += 5) {
            uint64x2_t s0 = st[j], s1 = st[j+1], s2 = st[j+2];
            uint64x2_t s3 = st[j+3], s4 = st[j+4];
            st[j]   = veorq_u64(s0, vbicq_u64(s2, s1));
            st[j+1] = veorq_u64(s1, vbicq_u64(s3, s2));
            st[j+2] = veorq_u64(s2, vbicq_u64(s4, s3));
            st[j+3] = veorq_u64(s3, vbicq_u64(s0, s4));
            st[j+4] = veorq_u64(s4, vbicq_u64(s1, s0));
        }

        /* iota */
        st[0] = veorq_u64(st[0], vdupq_n_u64(RNDC[round]));
    }
}

/* The 4-lane entry point callers share with the x86 tier. Four instances
 * cannot be carried as ONE 25-entry array of 2-word groups the way the x86
 * tier carries a single st[25]: `uint64x2_t st[25][2]` is a flat 50-vector
 * array in memory, so passing st[0] to a function expecting 25 words walks
 * words 12 and 13 of half 1 and never touches half 0's tail. The state is
 * therefore two explicit 25-word arrays: st_a[w] is Keccak word w of
 * instances 0 and 1 (vector slot k = instance k), st_b[w] the same for
 * instances 2 and 3. Both halves run the identical 2-lane permutation — a
 * dead instance only ever produces another dead instance, exactly as on x86. */
static inline void keccak_x4_permute_neon(uint64x2_t st_a[25], uint64x2_t st_b[25])
{
    keccak_x2_permute(st_a);
    keccak_x2_permute(st_b);
}

#undef X4_ROL
#undef X4_EOR3

#endif /* __x86_64__ / __aarch64__ */

#endif /* ZCL_CRYPTO_KECCAK_X4_INTERNAL_H */
