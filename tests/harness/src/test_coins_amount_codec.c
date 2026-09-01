/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton
 *
 * test_coins_amount_codec.c — pedantic unit tests for the pure amount
 * (de)compression codec in domain/consensus/coins_math.c:
 *
 *     uint64_t coins_math_compress_amount(uint64_t n);
 *     uint64_t coins_math_decompress_amount(uint64_t x);
 *
 * This is the variable-base-10 codec the coin-database serializer uses
 * to pack output amounts on disk. It is consensus-adjacent: a change to
 * the bit layout silently corrupts every serialized UTXO and breaks
 * cross-implementation interop with Bitcoin Core's CTxOutCompressor /
 * CompressAmount(). The codec is therefore frozen forever, and these
 * tests pin its exact byte-for-byte behavior.
 *
 * Behaviors pinned (one int test_*(void) entrypoint each — the harness
 * allows exactly one TEST_CASE per function):
 *
 *   1. Roundtrip invariant: decompress(compress(x)) == x for every x in
 *      [0, MAX_MONEY] (exhaustive low band + deterministic full-range
 *      sweep + the exact MAX_MONEY boundary).
 *   2. Boundary exponents: the compressed code at each 9/10/90/100/...
 *      decimal-exponent transition equals a hand-verified golden value,
 *      proving the codec selects the exact trailing-zero exponent.
 *   3. Digit preservation: for n = d * 10^e (d in [1,9], e in [0,9]) the
 *      compressed code carries d and e recoverably; cross-checked against
 *      the closed-form  compress(d*10^e) == 1 + (d-1)*10 + e  for e<9, an
 *      independent derivation that does not call the implementation.
 *   4. Regression seal: a 128-value deterministic corpus is cross-checked
 *      against an INDEPENDENT in-test reference reimplementation of the
 *      codec (the canonical Bitcoin Core CompressAmount algorithm) and,
 *      separately, against the core/modules/coins compress_amount() forwarder to
 *      pin that the thin wrapper stays a pure pass-through.
 *
 * No allocation, no I/O — the codec is a pure total function of inputs. */

#include "test/test_core.h"
#include "encoding/utilmoneystr.h"
#include "coins/compressor.h"

#include "domain/consensus/coins_math.h"

/* ── Independent reference reimplementation (behavior #4 seal) ──────────
 * This is a from-scratch transcription of the canonical Bitcoin Core
 * CompressAmount / DecompressAmount algorithm. It deliberately does NOT
 * call coins_math_*; if the production codec ever diverges from the
 * canonical algorithm, the seal test below catches it. */
static uint64_t ref_compress_amount(uint64_t n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (int)(n % 10);
        n /= 10;
        return 1 + (n * 9 + (uint64_t)d - 1) * 10 + (uint64_t)e;
    }
    return 1 + (n - 1) * 10 + 9;
}

static uint64_t ref_decompress_amount(uint64_t x)
{
    if (x == 0)
        return 0;
    x--;
    int e = (int)(x % 10);
    x /= 10;
    uint64_t n = 0;
    if (e < 9) {
        int d = (int)(x % 9) + 1;
        x /= 9;
        n = x * 10 + (uint64_t)d;
    } else {
        n = x + 1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}

/* MAX_MONEY is 21e6 * COIN == 2.1e15 (fits a uint64 comfortably). */
#define CODEC_MAX_MONEY ((uint64_t)MAX_MONEY)

/* ─────────────────────────────────────────────────────────────────────
 * Behavior 1 — roundtrip invariant over [0, MAX_MONEY].
 *
 * decompress(compress(x)) == x must hold for every representable amount.
 * We prove it three ways: exhaustively over a dense low band (where most
 * real outputs live), via a deterministic multiplicative/additive walk
 * that scatters across the whole money range, and at the exact endpoints
 * 0, 1, and MAX_MONEY.
 * ───────────────────────────────────────────────────────────────────── */
int test_coins_amount_codec_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("coins_amount_codec: decompress(compress(x))==x over [0,MAX_MONEY]")
    {
        /* Endpoints first — these are the values most likely to be
         * special-cased wrong. */
        ASSERT(coins_math_compress_amount(0) == 0);
        ASSERT(coins_math_decompress_amount(0) == 0);
        ASSERT(coins_math_decompress_amount(coins_math_compress_amount(0)) == 0);
        ASSERT(coins_math_decompress_amount(coins_math_compress_amount(1)) == 1);

        /* MAX_MONEY itself must round-trip (and its compressed form is a
         * fixed, verified constant — 2.1e15 strips 14 trailing zeros to
         * 21, d=1 e=8 path -> code 21000000). */
        ASSERT(coins_math_compress_amount(CODEC_MAX_MONEY) == 21000000ULL);
        ASSERT(coins_math_decompress_amount(
                   coins_math_compress_amount(CODEC_MAX_MONEY))
               == CODEC_MAX_MONEY);

        /* Exhaustive dense low band: every value [0, 300000]. This is the
         * region where e is small and the (n*9 + d - 1) packing is most
         * exercised. */
        for (uint64_t x = 0; x <= 300000ULL; x++) {
            uint64_t c = coins_math_compress_amount(x);
            uint64_t d = coins_math_decompress_amount(c);
            ASSERT(d == x);
        }

        /* Deterministic full-range scatter walk: x -> 7*x + 3 visits a
         * spread of magnitudes from 1 up to and past MAX_MONEY without
         * being a multiple of any nice power of ten, so it stresses the
         * generic (non-trailing-zero) packing path. */
        for (uint64_t x = 1; x <= CODEC_MAX_MONEY; x = x * 7ULL + 3ULL) {
            uint64_t c = coins_math_compress_amount(x);
            uint64_t d = coins_math_decompress_amount(c);
            ASSERT(d == x);
        }

        /* Every exact power of ten and 5*power within range round-trips —
         * these hit the trailing-zero stripping loop at every e. */
        uint64_t p = 1;
        for (int e = 0; e <= 15; e++) {
            if (p > CODEC_MAX_MONEY)
                break;
            ASSERT(coins_math_decompress_amount(
                       coins_math_compress_amount(p)) == p);
            uint64_t five = 5ULL * p;
            if (five <= CODEC_MAX_MONEY)
                ASSERT(coins_math_decompress_amount(
                           coins_math_compress_amount(five)) == five);
            p *= 10ULL;
        }
    }
    TEST_END;
    return failures;
}

/* ─────────────────────────────────────────────────────────────────────
 * Behavior 2 — boundary exponents.
 *
 * The codec strips trailing decimal zeros and stores the count as an
 * exponent. At each transition (9->10, 90->100, 900->1000, ... up to
 * 9*10^18) the compressed code must equal a hand-verified golden value,
 * proving the EXACT exponent was selected. These constants were computed
 * by hand from the canonical algorithm and are frozen forever.
 * ───────────────────────────────────────────────────────────────────── */
int test_coins_amount_codec_boundary_exponents(void)
{
    int failures = 0;
    TEST_CASE("coins_amount_codec: exact compressed code at exponent transitions")
    {
        /* Golden (amount -> compressed) pairs straddling the
         * one-trailing-zero boundaries. Verified against the canonical
         * algorithm. */
        struct { uint64_t n; uint64_t c; } golden[] = {
            /* single significant digit 9, then its *10 sibling */
            { 9ULL,        81ULL  },   /* d=9 e=0 */
            { 10ULL,       2ULL   },   /* d=1 e=1 */
            { 90ULL,       82ULL  },   /* d=9 e=1 */
            { 100ULL,      3ULL   },   /* d=1 e=2 */
            { 900ULL,      83ULL  },   /* d=9 e=2 */
            { 1000ULL,     4ULL   },   /* d=1 e=3 */
            { 9000ULL,     84ULL  },   /* d=9 e=3 */
            { 10000ULL,    5ULL   },   /* d=1 e=4 */
            { 90000ULL,    85ULL  },   /* d=9 e=4 */
            { 100000ULL,   6ULL   },   /* d=1 e=5 */
            { 900000ULL,   86ULL  },   /* d=9 e=5 */
            { 1000000ULL,  7ULL   },   /* d=1 e=6 */
            { 9000000ULL,  87ULL  },   /* d=9 e=6 */
            { 10000000ULL, 8ULL   },   /* d=1 e=7 */
            { 90000000ULL, 88ULL  },   /* d=9 e=7 */
            { 100000000ULL, 9ULL  },   /* d=1 e=8 (== 1 COIN)        */
            { 900000000ULL, 89ULL },   /* d=9 e=8 */
            /* e == 9 saturation branch: nine trailing zeros stops the
             * strip loop; the residual magnitude is carried verbatim. */
            { 1000000000ULL,  10ULL  },  /* 10^9  -> residual 1,  e=9 */
            { 9000000000ULL,  90ULL  },  /* 9*10^9 -> residual 9, e=9 */
            { 10000000000ULL, 100ULL },  /* 10^10 -> residual 10, e=9 */
            { 90000000000ULL, 900ULL },  /* 9*10^10 residual 90,  e=9 */
            /* the high end of the requested band: 9 * 10^18 */
            { 9000000000000000000ULL, 90000000000ULL },
        };
        const size_t ng = sizeof(golden) / sizeof(golden[0]);

        for (size_t i = 0; i < ng; i++) {
            uint64_t got = coins_math_compress_amount(golden[i].n);
            ASSERT(got == golden[i].c);
            /* And it must round-trip back to the original amount. */
            ASSERT(coins_math_decompress_amount(got) == golden[i].n);
        }

        /* Adjacency proof: each clean power of ten compresses to a code
         * strictly smaller than its non-power neighbor, because the
         * single-digit/trailing-zero form occupies the lowest codes. The
         * power-of-ten codes 2..9 are exactly the e index plus one. */
        ASSERT(coins_math_compress_amount(10ULL) == 2ULL);
        ASSERT(coins_math_compress_amount(100ULL) == 3ULL);
        ASSERT(coins_math_compress_amount(1000ULL) == 4ULL);
        ASSERT(coins_math_compress_amount(100ULL) <
               coins_math_compress_amount(99ULL));  /* 3 < 891 */
        ASSERT(coins_math_compress_amount(99ULL) == 891ULL);
    }
    TEST_END;
    return failures;
}

/* ─────────────────────────────────────────────────────────────────────
 * Behavior 3 — digit preservation.
 *
 * For n = d * 10^e with d in [1,9] and e in [0,9] the codec must encode
 * the leading digit d and the exponent e recoverably. For the e<9 path
 * the canonical algorithm collapses to the closed form
 *
 *      compress(d * 10^e) == 1 + (d - 1) * 10 + e
 *
 * which lets us recover  e = (c - 1) % 10  and  d = (c - 1) / 10 + 1
 * WITHOUT calling the implementation — an independent oracle. We assert
 * both the forward closed form and the recovered (d,e).
 * ───────────────────────────────────────────────────────────────────── */
int test_coins_amount_codec_digit_preservation(void)
{
    int failures = 0;
    TEST_CASE("coins_amount_codec: compress(d*10^e) carries d and e recoverably")
    {
        for (int d = 1; d <= 9; d++) {
            uint64_t p = 1;
            for (int e = 0; e <= 9; e++) {
                uint64_t n = (uint64_t)d * p;
                uint64_t c = coins_math_compress_amount(n);

                if (e < 9) {
                    /* Closed-form independent expectation. */
                    uint64_t expect = 1ULL + (uint64_t)(d - 1) * 10ULL
                                      + (uint64_t)e;
                    ASSERT(c == expect);

                    /* Recover d and e from the code with no reference to
                     * the implementation; they must match the inputs. */
                    uint64_t body = c - 1ULL;
                    int rec_e = (int)(body % 10ULL);
                    int rec_d = (int)(body / 10ULL) + 1;
                    ASSERT(rec_e == e);
                    ASSERT(rec_d == d);
                } else {
                    /* e == 9 saturation path: the exponent maxes out and
                     * the residual digit d is carried as magnitude.
                     * compress(d * 10^9) == 1 + (d-1)*10 + 9. */
                    uint64_t expect = 1ULL + (uint64_t)(d - 1) * 10ULL + 9ULL;
                    ASSERT(c == expect);
                }

                /* Whatever path: round-trip must reconstruct n exactly. */
                ASSERT(coins_math_decompress_amount(c) == n);
                p *= 10ULL;
            }
        }

        /* Distinctness: all 90 codes for (d in 1..9, e in 0..8) are
         * unique. If the codec ever conflated a digit and an exponent
         * (e.g. dropped a +1) two inputs would collide. We check the
         * full 9x9 grid maps to 81 distinct codes. */
        uint64_t codes[81];
        size_t k = 0;
        for (int d = 1; d <= 9; d++) {
            uint64_t p = 1;
            for (int e = 0; e <= 8; e++) {
                codes[k++] = coins_math_compress_amount((uint64_t)d * p);
                p *= 10ULL;
            }
        }
        for (size_t i = 0; i < k; i++)
            for (size_t j = i + 1; j < k; j++)
                ASSERT(codes[i] != codes[j]);
    }
    TEST_END;
    return failures;
}

/* ─────────────────────────────────────────────────────────────────────
 * Behavior 4 — regression seal against an independent reference.
 *
 * A 128-value deterministic corpus (powers/near-powers, COIN multiples,
 * primes, max-money neighbors, a deterministic LCG scatter) is checked
 * against:
 *   (a) the INDEPENDENT in-test reference reimplementation of the
 *       canonical CompressAmount/DecompressAmount — the true seal; and
 *   (b) the core/modules/coins compress_amount()/decompress_amount() forwarders,
 *       pinning that those thin wrappers stay pure pass-throughs of the
 *       domain function (a divergence there is also a regression).
 * ───────────────────────────────────────────────────────────────────── */
int test_coins_amount_codec_regression_seal(void)
{
    int failures = 0;
    TEST_CASE("coins_amount_codec: 128-value corpus matches independent reference")
    {
        uint64_t corpus[128];
        size_t n = 0;

        /* Fixed anchors: every power of ten 10^0..10^15, their *3 and *7
         * non-trailing-zero neighbors, COIN/CENT, and money-range edges. */
        uint64_t p = 1;
        for (int e = 0; e <= 15 && n < 100; e++) {
            corpus[n++] = p;
            corpus[n++] = 3ULL * p + 1ULL;
            corpus[n++] = 7ULL * p - 1ULL;
            p *= 10ULL;
        }
        corpus[n++] = 0ULL;
        corpus[n++] = 1ULL;
        corpus[n++] = (uint64_t)COIN;            /* 1 ZCL            */
        corpus[n++] = (uint64_t)CENT;            /* 0.01 ZCL         */
        corpus[n++] = (uint64_t)COIN + 1ULL;
        corpus[n++] = (uint64_t)COIN - 1ULL;
        corpus[n++] = 50ULL * (uint64_t)COIN;    /* a block subsidy  */
        corpus[n++] = CODEC_MAX_MONEY;
        corpus[n++] = CODEC_MAX_MONEY - 1ULL;
        corpus[n++] = CODEC_MAX_MONEY / 2ULL;
        corpus[n++] = 123456789ULL;
        corpus[n++] = 999999999ULL;

        /* Deterministic LCG fills the remainder of the 128-slot corpus
         * (Numerical-Recipes constants), reduced into the money range so
         * every value is a valid amount. */
        uint64_t lcg = 0x9E3779B97F4A7C15ULL;
        while (n < 128) {
            lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
            corpus[n++] = lcg % (CODEC_MAX_MONEY + 1ULL);
        }

        /* The seal: domain codec == independent reference, both
         * directions, for all 128 values. */
        for (size_t i = 0; i < n; i++) {
            uint64_t x = corpus[i];
            uint64_t cd = coins_math_compress_amount(x);
            uint64_t cr = ref_compress_amount(x);
            ASSERT(cd == cr);

            uint64_t dd = coins_math_decompress_amount(cd);
            uint64_t dr = ref_decompress_amount(cr);
            ASSERT(dd == dr);

            /* And, since x is a real amount, the round-trip recovers it. */
            ASSERT(dd == x);

            /* Forwarder identity: the core/modules/coins wrappers must remain
             * pure pass-throughs of the domain function. */
            ASSERT(compress_amount(x) == cd);
            ASSERT(decompress_amount(cd) == dd);
        }

        /* Belt-and-braces: a handful of decompress-domain values that are
         * NOT in the image of compress still match the reference exactly
         * (decompress is a total function). */
        uint64_t raw[] = { 2ULL, 11ULL, 81ULL, 891ULL, 100000ULL,
                           10000000000ULL, 0xFFFFFFFFULL };
        for (size_t i = 0; i < sizeof(raw) / sizeof(raw[0]); i++) {
            ASSERT(coins_math_decompress_amount(raw[i])
                   == ref_decompress_amount(raw[i]));
        }
    }
    TEST_END;
    return failures;
}
