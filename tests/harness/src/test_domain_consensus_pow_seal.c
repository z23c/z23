/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Regression-seal unit tests for domain/consensus/verify.c:
 *   domain_consensus_verify_pow_solution()
 *
 * These tests pin three properties of the pure PoW validator:
 *
 *   1. REGRESSION SEAL — the domain verdict must agree with the legacy
 *      bool-returning CheckProofOfWork() across a matrix of
 *      (nBits, hash, powLimit) tuples that bracket the comparison
 *      boundaries: target exactly at the powLimit floor, hash == target
 *      (exact equality boundary, must be ACCEPTED since the rule is
 *      hash <= target), and hash one unit below / above the target.
 *
 *   2. MALFORMED TARGET — the three rejection inputs that all decode to
 *      ERR_POW_TARGET_INVALID (fNegative, fOverflow, bnTarget==0) each
 *      fire independently, with that exact code.
 *
 *   3. DETERMINISM — the same (hash, nBits, params) yields the same
 *      verdict on repeated evaluation; the function is never flaky.
 *
 * Target arithmetic used below (verified against
 * arith_uint256_set_compact in core/math/src/arith_uint256.c):
 *
 *   nBits 0x03123456 -> size=3, word=0x123456, target = 0x123456.
 *   uint256 is little-endian (data[0] = LSB), so a hash whose value is
 *   0x123456 has data[0]=0x56, data[1]=0x34, data[2]=0x12. Changing
 *   data[0] by +/-1 walks the hash one unit across the target.
 */

#include "test/test_core.h"

#include "domain/consensus/verify.h"
#include "chain/pow.h"        /* legacy CheckProofOfWork — the seal oracle */
#include "consensus/params.h"
#include "core/uint256.h"

#include <string.h>

/* ── fixtures ──────────────────────────────────────────────────────── */

/* powLimit = 2^224 - 1 (Bitcoin-style easy target): far above any nBits
 * used here, so the work floor never trips and we isolate hash<=target. */
static void seal_make_easy_params(struct consensus_params *out)
{
    memset(out, 0, sizeof(*out));
    for (int i = 4; i < 32; i++) out->powLimit.data[i] = 0xff;
}

/* A uint256 holding the small numeric value `v` (LSB in data[0]). */
static struct uint256 seal_hash_value(uint32_t v)
{
    struct uint256 h;
    memset(&h, 0, sizeof(h));
    h.data[0] = (uint8_t)(v & 0xff);
    h.data[1] = (uint8_t)((v >> 8) & 0xff);
    h.data[2] = (uint8_t)((v >> 16) & 0xff);
    h.data[3] = (uint8_t)((v >> 24) & 0xff);
    return h;
}

/* nBits whose decoded target is exactly 0x123456. */
#define SEAL_NBITS_TARGET_0x123456 0x03123456u
#define SEAL_TARGET_VALUE          0x00123456u

/* ── 1. Regression seal vs legacy CheckProofOfWork ─────────────────── */
/* For every boundary tuple, the domain verdict (r.ok) and the legacy
 * bool wrapper must agree, AND each tuple must land on its precise
 * expected verdict (so the assertions are not vacuously self-consistent). */
int test_domain_consensus_pow_seal_matrix(void)
{
    int failures = 0;

    TEST_CASE("pow seal: domain verdict == legacy CheckProofOfWork on boundary matrix")
        struct consensus_params p;
        seal_make_easy_params(&p);

        /* (hash_value, expected_ok) tuples around target 0x123456. */
        struct { uint32_t hv; bool expect_ok; const char *why; } cases[] = {
            { SEAL_TARGET_VALUE - 1, true,  "hash one below target" },
            { SEAL_TARGET_VALUE,     true,  "hash == target (equality boundary)" },
            { SEAL_TARGET_VALUE + 1, false, "hash one above target" },
            { 0u,                    true,  "hash zero (minimum)" },
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct uint256 h = seal_hash_value(cases[i].hv);

            struct zcl_result r = domain_consensus_verify_pow_solution(
                    &h, SEAL_NBITS_TARGET_0x123456, &p);
            bool legacy = CheckProofOfWork(h, SEAL_NBITS_TARGET_0x123456, &p);

            /* The seal: the two engines must agree, every tuple. */
            ASSERT(r.ok == legacy);
            /* Anchor to the intended verdict so the seal can't pass by
             * both engines being wrong in the same direction. */
            ASSERT(r.ok == cases[i].expect_ok);

            /* The one rejection in the matrix must carry the
             * hash-above-target code, not some other rejection. */
            if (!cases[i].expect_ok)
                ASSERT(r.code == DOMAIN_CONSENSUS_ERR_POW_HASH_ABOVE_TARGET);
        }
    TEST_END
    return failures;
}

/* ── 1b. Target exactly at the powLimit floor ──────────────────────── */
/* When the decoded target == powLimit, the comparison `target > powLimit`
 * is false, so the floor is INCLUSIVE: a target sitting exactly on the
 * floor is accepted (not BELOW_MIN). A target one unit above the floor
 * IS below the minimum work and must be rejected. Both must match the
 * legacy wrapper. */
int test_domain_consensus_pow_seal_powlimit_floor(void)
{
    int failures = 0;

    TEST_CASE("pow seal: target at powLimit floor is inclusive, above floor rejected")
        /* powLimit = 0x123456 exactly (== the decoded target of
         * SEAL_NBITS_TARGET_0x123456). data is little-endian. */
        struct consensus_params p;
        memset(&p, 0, sizeof(p));
        p.powLimit.data[0] = 0x56;
        p.powLimit.data[1] = 0x34;
        p.powLimit.data[2] = 0x12;

        /* hash 0 keeps the hash<=target branch satisfied, isolating the
         * floor comparison. */
        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));

        /* target == powLimit -> accepted (floor inclusive). */
        struct zcl_result on_floor = domain_consensus_verify_pow_solution(
                &zero, SEAL_NBITS_TARGET_0x123456, &p);
        ASSERT(on_floor.ok);
        ASSERT(CheckProofOfWork(zero, SEAL_NBITS_TARGET_0x123456, &p) == on_floor.ok);

        /* target = 0x123457 (one unit above floor) -> below minimum work. */
        struct zcl_result above = domain_consensus_verify_pow_solution(
                &zero, 0x03123457u, &p);
        ASSERT(!above.ok);
        ASSERT(above.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_BELOW_MIN);
        ASSERT(CheckProofOfWork(zero, 0x03123457u, &p) == above.ok);
    TEST_END
    return failures;
}

/* ── 2. Malformed target: three rejection paths fire independently ─── */
/* set_compact reports fNegative, fOverflow; and a zero word yields
 * bnTarget==0. The validator collapses all three to a single code,
 * ERR_POW_TARGET_INVALID. Pin that each distinct malformed input both
 * decodes via its own predicate and lands on that code (never a
 * different rejection, never accepted). */
int test_domain_consensus_pow_seal_malformed_paths(void)
{
    int failures = 0;

    TEST_CASE("pow seal: fNegative / fOverflow / zero-target each -> ERR_POW_TARGET_INVALID")
        struct consensus_params p;
        seal_make_easy_params(&p);
        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));

        /* (a) bnTarget == 0: nBits=0 decodes word=0 -> target zero. */
        struct zcl_result r_zero = domain_consensus_verify_pow_solution(
                &zero, 0x00000000u, &p);
        ASSERT(!r_zero.ok);
        ASSERT(r_zero.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID);

        /* (b) fNegative: size=2, word=0x800001 (sign bit set, word != 0). */
        struct zcl_result r_neg = domain_consensus_verify_pow_solution(
                &zero, 0x02800001u, &p);
        ASSERT(!r_neg.ok);
        ASSERT(r_neg.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID);

        /* (c) fOverflow: size=255 (>34) with word != 0 -> overflow. */
        struct zcl_result r_ovf = domain_consensus_verify_pow_solution(
                &zero, 0xff000001u, &p);
        ASSERT(!r_ovf.ok);
        ASSERT(r_ovf.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID);

        /* Cross-check: the legacy wrapper rejects all three too, so the
         * seal holds on the malformed inputs as well. */
        ASSERT(CheckProofOfWork(zero, 0x00000000u, &p) == false);
        ASSERT(CheckProofOfWork(zero, 0x02800001u, &p) == false);
        ASSERT(CheckProofOfWork(zero, 0xff000001u, &p) == false);

        /* Independence: the three malformed codes are TARGET_INVALID and
         * NOT confused with the below-min or hash-above codes. A valid
         * control (well-formed nBits, easy powLimit, hash 0) is accepted,
         * proving the rejections above are about the target, not a
         * blanket reject. */
        struct zcl_result r_ok = domain_consensus_verify_pow_solution(
                &zero, SEAL_NBITS_TARGET_0x123456, &p);
        ASSERT(r_ok.ok);
        ASSERT(r_ok.code == 0);
        ASSERT(r_zero.code != DOMAIN_CONSENSUS_ERR_POW_TARGET_BELOW_MIN);
        ASSERT(r_zero.code != DOMAIN_CONSENSUS_ERR_POW_HASH_ABOVE_TARGET);
    TEST_END
    return failures;
}

/* ── 3. Determinism: same input -> same verdict, never flaky ───────── */
/* Re-evaluate a fixed accept tuple and a fixed reject tuple many times;
 * every iteration must reproduce both the ok flag and the exact code.
 * A non-deterministic validator (uninitialised scratch, data race in the
 * pure path) would surface here. */
int test_domain_consensus_pow_seal_deterministic(void)
{
    int failures = 0;

    TEST_CASE("pow seal: repeated evaluation is byte-for-byte deterministic")
        struct consensus_params p;
        seal_make_easy_params(&p);

        struct uint256 accept_hash = seal_hash_value(SEAL_TARGET_VALUE);     /* == target */
        struct uint256 reject_hash = seal_hash_value(SEAL_TARGET_VALUE + 1); /* > target  */

        /* Establish the reference verdicts once. */
        struct zcl_result ref_ok = domain_consensus_verify_pow_solution(
                &accept_hash, SEAL_NBITS_TARGET_0x123456, &p);
        struct zcl_result ref_no = domain_consensus_verify_pow_solution(
                &reject_hash, SEAL_NBITS_TARGET_0x123456, &p);

        /* Sanity: the reference verdicts are the ones we expect. */
        ASSERT(ref_ok.ok && ref_ok.code == 0);
        ASSERT(!ref_no.ok && ref_no.code == DOMAIN_CONSENSUS_ERR_POW_HASH_ABOVE_TARGET);

        for (int i = 0; i < 1024; i++) {
            struct zcl_result a = domain_consensus_verify_pow_solution(
                    &accept_hash, SEAL_NBITS_TARGET_0x123456, &p);
            struct zcl_result b = domain_consensus_verify_pow_solution(
                    &reject_hash, SEAL_NBITS_TARGET_0x123456, &p);

            ASSERT(a.ok == ref_ok.ok);
            ASSERT(a.code == ref_ok.code);
            ASSERT(b.ok == ref_no.ok);
            ASSERT(b.code == ref_no.code);

            /* And the legacy seal stays in lock-step every iteration. */
            ASSERT(CheckProofOfWork(accept_hash, SEAL_NBITS_TARGET_0x123456, &p) == a.ok);
            ASSERT(CheckProofOfWork(reject_hash, SEAL_NBITS_TARGET_0x123456, &p) == b.ok);
        }
    TEST_END
    return failures;
}
