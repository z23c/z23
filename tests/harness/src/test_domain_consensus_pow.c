/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/pow.{c,h}.
 *
 * These tests pin the pure PoW difficulty arithmetic. They DO NOT go
 * through the chain/ wrapper for the contract checks: they exercise
 * the typed zcl_result API directly. For the regression seal, we
 * deliberately cross-check the wrapper (core/modules/chain/src/pow.c) against
 * the new domain function across a representative set of inputs so
 * any drift in either side is caught immediately.
 */

#include "test/test_core.h"

#include "domain/consensus/pow.h"
#include "chain/pow.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

#define DCP_CHECK(name, expr) do { \
    printf("domain_consensus_pow: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_domain_consensus_pow(void)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    /* --- error-path / contract tests --- */

    /* block_proof: null out -> typed error. */
    {
        struct zcl_result r = domain_consensus_block_proof(0x1d00ffff, NULL);
        DCP_CHECK("block_proof null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_POW_ERR_NULL_OUT);
    }

    /* increase_difficulty_by: null params -> typed error. */
    {
        uint32_t out = 0;
        struct zcl_result r = domain_consensus_increase_difficulty_by(
                0x1d00ffff, 2, NULL, &out);
        DCP_CHECK("increase_difficulty_by null params -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS);
    }

    /* increase_difficulty_by: null out -> typed error. */
    {
        struct zcl_result r = domain_consensus_increase_difficulty_by(
                0x1d00ffff, 2, params, NULL);
        DCP_CHECK("increase_difficulty_by null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_POW_ERR_NULL_OUT);
    }

    /* increase_difficulty_by: zero divisor -> typed error. */
    {
        uint32_t out = 0;
        struct zcl_result r = domain_consensus_increase_difficulty_by(
                0x1d00ffff, 0, params, &out);
        DCP_CHECK("increase_difficulty_by zero divisor -> ERR_BAD_DIVISOR",
                  !r.ok && r.code == DOMAIN_CONSENSUS_POW_ERR_BAD_DIVISOR);
    }

    /* calculate_next_work_required: null params -> typed error. */
    {
        struct arith_uint256 avg;
        arith_uint256_set_u64(&avg, 1);
        uint32_t out = 0;
        struct zcl_result r = domain_consensus_calculate_next_work_required(
                avg, 1000, 0, NULL, 100, &out);
        DCP_CHECK("calculate_next_work_required null params -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS);
    }

    /* calculate_next_work_required: null out -> typed error. */
    {
        struct arith_uint256 avg;
        arith_uint256_set_u64(&avg, 1);
        struct zcl_result r = domain_consensus_calculate_next_work_required(
                avg, 1000, 0, params, 100, NULL);
        DCP_CHECK("calculate_next_work_required null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_POW_ERR_NULL_OUT);
    }

    /* --- value tests (pin known points on the curve) --- */

    /* block_proof for nBits=0: legacy returns zero (target is 0). */
    {
        struct arith_uint256 work;
        struct zcl_result r = domain_consensus_block_proof(0, &work);
        DCP_CHECK("block_proof n_bits=0 -> OK, work=0",
                  r.ok && arith_uint256_is_zero(&work));
    }

    /* block_proof for a normal nBits gives non-zero work. */
    {
        struct arith_uint256 work;
        struct zcl_result r = domain_consensus_block_proof(0x1d00ffff, &work);
        DCP_CHECK("block_proof n_bits=0x1d00ffff -> OK, work>0",
                  r.ok && !arith_uint256_is_zero(&work));
    }

    /* block_proof: overflow nBits (0xff exponent) -> work=0 (benign). */
    {
        struct arith_uint256 work;
        /* exponent=0xff with non-zero mantissa overflows. */
        struct zcl_result r = domain_consensus_block_proof(0xff000001, &work);
        DCP_CHECK("block_proof overflow n_bits -> OK, work=0",
                  r.ok && arith_uint256_is_zero(&work));
    }

    /* increase_difficulty_by: dividing the powLimit target by 256 must
     * still clamp at powLimit (since /256 makes it tighter, clamp is a
     * no-op for this direction). Result must be a valid compact target. */
    {
        struct arith_uint256 pow_limit;
        uint256_to_arith(&pow_limit, &params->powLimit);
        uint32_t pow_limit_bits = arith_uint256_get_compact(&pow_limit, false);

        uint32_t out = 0;
        struct zcl_result r = domain_consensus_increase_difficulty_by(
                pow_limit_bits, 256, params, &out);
        DCP_CHECK("increase_difficulty_by /256 -> OK, tighter target",
                  r.ok && out != 0);
    }

    /* --- regression seal: domain function must match the legacy
     * wrapper for every sampled input. If anyone "improves" either
     * side, the test shouts. --- */

    /* block_proof vs GetBlockProof. */
    {
        uint32_t bits_samples[] = {
            0x1d00ffff,   /* "easy" Bitcoin-era target */
            0x1e00ffff,   /* slightly harder */
            0x1f07ffff,   /* ZClassic powLimit mantissa */
            0x1c4d4d4d,   /* arbitrary */
            0x20100000,   /* high exponent, low mantissa */
            0,            /* zero: malformed -> work=0 */
            0xff000001,   /* overflow: malformed -> work=0 */
            0x00ffffff,   /* zero exponent variant */
        };
        int n = (int)(sizeof(bits_samples) / sizeof(bits_samples[0]));
        bool all_match = true;
        for (int i = 0; i < n; i++) {
            struct arith_uint256 domain_work;
            struct zcl_result r = domain_consensus_block_proof(
                    bits_samples[i], &domain_work);
            struct block_index bi;
            block_index_init(&bi);
            bi.nBits = bits_samples[i];
            struct arith_uint256 legacy_work = GetBlockProof(&bi);
            if (!r.ok ||
                arith_uint256_compare(&domain_work, &legacy_work) != 0) {
                printf("\n  MISMATCH block_proof n_bits=0x%08x\n",
                       bits_samples[i]);
                all_match = false;
            }
        }
        DCP_CHECK("block_proof matches GetBlockProof across samples",
                  all_match);
    }

    /* increase_difficulty_by vs IncreaseDifficultyBy. */
    {
        struct {
            uint32_t bits;
            int64_t mult;
        } samples[] = {
            { 0x1d00ffff, 2   },
            { 0x1d00ffff, 4   },
            { 0x1d00ffff, 128 },
            { 0x1d00ffff, 256 },
            { 0x1e00ffff, 2   },
            { 0x1f07ffff, 2   },
            { 0x1f07ffff, 1024 },
        };
        int n = (int)(sizeof(samples) / sizeof(samples[0]));
        bool all_match = true;
        for (int i = 0; i < n; i++) {
            uint32_t domain_out = 0;
            struct zcl_result r = domain_consensus_increase_difficulty_by(
                    samples[i].bits, samples[i].mult, params, &domain_out);
            uint32_t legacy_out = IncreaseDifficultyBy(
                    samples[i].bits, samples[i].mult, params);
            if (!r.ok || domain_out != legacy_out) {
                printf("\n  MISMATCH increase_difficulty_by bits=0x%08x mult=%lld "
                       "domain=0x%08x legacy=0x%08x\n",
                       samples[i].bits, (long long)samples[i].mult,
                       domain_out, legacy_out);
                all_match = false;
            }
        }
        DCP_CHECK("increase_difficulty_by matches IncreaseDifficultyBy "
                  "across samples", all_match);
    }

    /* calculate_next_work_required vs CalculateNextWorkRequired.
     * Sample across timespan extremes: way-too-fast (clamps to min),
     * way-too-slow (clamps to max), normal. */
    {
        struct arith_uint256 avg;
        arith_uint256_set_compact(&avg, 0x1d00ffff, NULL, NULL);

        int64_t avgTs = consensus_averaging_window_timespan(params, 100000);
        struct {
            int64_t last;
            int64_t first;
            int     height;
        } samples[] = {
            /* normal: actual ≈ avg. */
            { 1000000 + avgTs, 1000000, 100000 },
            /* way too fast: clamps at min. */
            { 1000000 + 1,     1000000, 100000 },
            /* way too slow: clamps at max. */
            { 1000000 + 10 * avgTs, 1000000, 100000 },
            /* near-zero spread. */
            { 1000000,         1000000, 100000 },
            /* large negative spread (defensive — first > last). */
            { 1000000,         2000000, 100000 },
        };
        int n = (int)(sizeof(samples) / sizeof(samples[0]));
        bool all_match = true;
        for (int i = 0; i < n; i++) {
            uint32_t domain_out = 0;
            struct zcl_result r = domain_consensus_calculate_next_work_required(
                    avg, samples[i].last, samples[i].first, params,
                    samples[i].height, &domain_out);
            uint32_t legacy_out = CalculateNextWorkRequired(
                    avg, samples[i].last, samples[i].first, params,
                    samples[i].height);
            if (!r.ok || domain_out != legacy_out) {
                printf("\n  MISMATCH calculate_next_work_required "
                       "last=%lld first=%lld domain=0x%08x legacy=0x%08x\n",
                       (long long)samples[i].last,
                       (long long)samples[i].first,
                       domain_out, legacy_out);
                all_match = false;
            }
        }
        DCP_CHECK("calculate_next_work_required matches "
                  "CalculateNextWorkRequired across samples", all_match);
    }

    return failures;
}
