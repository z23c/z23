/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/verify.{c,h}.
 *
 * The point of these tests is the *interface*: we prove that the
 * domain validator returns precise typed errors via zcl_result,
 * independently of the legacy bool-returning CheckProofOfWork it
 * delegates to during Epoch I.
 */

#include "test/test_core.h"

#include "domain/consensus/verify.h"
#include "consensus/params.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

#define DCV_CHECK(name, expr) do { \
    printf("domain_consensus_verify: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a synthetic consensus_params with a generous powLimit so we
 * can isolate the target/hash comparisons. powLimit = 0x00000000ffff..ff
 * (Bitcoin-style easy target) is far above any realistic nBits. */
static void make_easy_params(struct consensus_params *out)
{
    memset(out, 0, sizeof(*out));
    /* powLimit = 2^224 - 1: easy target, anything below it is fine. */
    for (int i = 4; i < 32; i++) out->powLimit.data[i] = 0xff;
}

int test_domain_consensus_verify(void)
{
    int failures = 0;

    /* null-arg guard returns the documented code. */
    {
        struct zcl_result r = domain_consensus_verify_pow_solution(
                NULL, 0x1d00ffff, NULL);
        DCV_CHECK("null args -> ERR_NULL_ARG",
                  !r.ok && r.code == DOMAIN_CONSENSUS_ERR_NULL_ARG);
    }

    /* nBits = 0 is malformed (target=0 after decompression). */
    {
        struct consensus_params p;
        make_easy_params(&p);
        struct uint256 zero = {0};
        struct zcl_result r = domain_consensus_verify_pow_solution(
                &zero, 0, &p);
        DCV_CHECK("nBits=0 -> ERR_POW_TARGET_INVALID",
                  !r.ok && r.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID);
    }

    /* Negative bit pattern (0x00800000 in compact) is malformed. */
    {
        struct consensus_params p;
        make_easy_params(&p);
        struct uint256 zero = {0};
        /* compact 0x01800000 represents -0; CheckProofOfWork rejects via
         * fNegative path. */
        struct zcl_result r = domain_consensus_verify_pow_solution(
                &zero, 0x01800000, &p);
        DCV_CHECK("negative mantissa -> ERR_POW_TARGET_INVALID",
                  !r.ok && r.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_INVALID);
    }

    /* A very strict powLimit + a much larger target means the target
     * is below the work floor (target > powLimit numerically means
     * easier than allowed).
     *
     * uint256 stores bytes little-endian: data[0] is LSB, data[31] is
     * MSB. powLimit.data[0] = 0x01 makes powLimit = 1 (numerically), so
     * any non-trivial nBits decompresses to a target far above that. */
    {
        struct consensus_params p;
        memset(&p, 0, sizeof(p));
        p.powLimit.data[0] = 0x01;
        struct uint256 zero = {0};
        struct zcl_result r = domain_consensus_verify_pow_solution(
                &zero, 0x1d00ffff, &p);
        DCV_CHECK("nBits below powLimit -> ERR_POW_TARGET_BELOW_MIN",
                  !r.ok && r.code == DOMAIN_CONSENSUS_ERR_POW_TARGET_BELOW_MIN);
    }

    /* Hash > target. Build a target that is small, hash whose top
     * byte is large. */
    {
        struct consensus_params p;
        make_easy_params(&p);
        /* nBits 0x1c00ffff: 24-bit target shifted left 4 bytes. */
        struct uint256 hash;
        memset(&hash, 0, sizeof(hash));
        hash.data[31] = 0xff; /* big-endian: high byte makes hash large */
        struct zcl_result r = domain_consensus_verify_pow_solution(
                &hash, 0x1c00ffff, &p);
        DCV_CHECK("hash > target -> ERR_POW_HASH_ABOVE_TARGET",
                  !r.ok && r.code == DOMAIN_CONSENSUS_ERR_POW_HASH_ABOVE_TARGET);
    }

    /* Valid: a zero hash always satisfies any positive target. */
    {
        struct consensus_params p;
        make_easy_params(&p);
        struct uint256 zero = {0};
        struct zcl_result r = domain_consensus_verify_pow_solution(
                &zero, 0x1d00ffff, &p);
        DCV_CHECK("hash=0 vs easy target -> OK", r.ok);
    }

    return failures;
}
