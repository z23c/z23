/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure PoW difficulty arithmetic. Replays from (n_bits / target /
 * timespan, params). No clock, RNG, allocation, or I/O. */

#include "domain/consensus/pow.h"

#include "consensus/params.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"

struct zcl_result domain_consensus_block_proof(
        uint32_t n_bits,
        struct arith_uint256 *out_work)
{
    if (!out_work)
        return ZCL_ERR(DOMAIN_CONSENSUS_POW_ERR_NULL_OUT,
                       "block_proof: null out_work for n_bits=0x%08x", n_bits);

    uint32_t exponent = n_bits >> 24;
    uint32_t mantissa = n_bits & 0x00ffffffU;
    if (exponent >= 28 && exponent <= 32 &&
        mantissa > 0 && mantissa <= 0x007fffffU) {
        /* With target = m * 2^s, floor(2^256/(target+1))
         * equals floor((2^(256-s)-1)/m): the removed fraction
         * cannot bridge the next integer, even when m divides 2^(256-s). */
        unsigned shift = 256 - 8 * (exponent - 3);
        arith_uint256_set_u64(out_work,
                ((UINT64_C(1) << shift) - 1) / mantissa);
        return ZCL_OK;
    }

    bool fNegative = false;
    bool fOverflow = false;
    struct arith_uint256 bnTarget;
    arith_uint256_set_compact(&bnTarget, n_bits, &fNegative, &fOverflow);

    /* Benign-malformed: legacy GetBlockProof returns zero for any
     * unusable target so the chainwork accumulator can keep stepping.
     * We preserve that here — error is signalled only on contract
     * violations (null pointer). */
    if (fNegative || fOverflow || arith_uint256_is_zero(&bnTarget)) {
        arith_uint256_set_zero(out_work);
        return ZCL_OK;
    }

    /* 2**256 / (bnTarget+1) == ~bnTarget / (bnTarget+1) + 1.
     * This identity avoids needing a 257-bit intermediate. */
    struct arith_uint256 notTarget;
    arith_uint256_complement(&notTarget, &bnTarget);

    struct arith_uint256 one;
    arith_uint256_set_u64(&one, 1);

    struct arith_uint256 targetPlusOne;
    arith_uint256_add(&targetPlusOne, &bnTarget, &one);

    struct arith_uint256 result;
    arith_uint256_div(&result, &notTarget, &targetPlusOne);
    arith_uint256_add(&result, &result, &one);

    *out_work = result;
    return ZCL_OK;
}

struct zcl_result domain_consensus_increase_difficulty_by(
        uint32_t n_bits,
        int64_t multiplier,
        const struct consensus_params *params,
        uint32_t *out_bits)
{
    if (!params)
        return ZCL_ERR(DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS,
                       "increase_difficulty_by: null params");
    if (!out_bits)
        return ZCL_ERR(DOMAIN_CONSENSUS_POW_ERR_NULL_OUT,
                       "increase_difficulty_by: null out_bits");
    if (multiplier == 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_POW_ERR_BAD_DIVISOR,
                       "increase_difficulty_by: zero multiplier");

    struct arith_uint256 target;
    arith_uint256_set_compact(&target, n_bits, NULL, NULL);

    struct arith_uint256 div;
    arith_uint256_set_u64(&div, (uint64_t)multiplier);
    struct arith_uint256 result;
    arith_uint256_div(&result, &target, &div);
    target = result;

    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &params->powLimit);
    if (arith_uint256_compare(&target, &pow_limit) > 0)
        target = pow_limit;

    *out_bits = arith_uint256_get_compact(&target, false);
    return ZCL_OK;
}

struct zcl_result domain_consensus_calculate_next_work_required(
        struct arith_uint256 bn_avg,
        int64_t last_block_time,
        int64_t first_block_time,
        const struct consensus_params *params,
        int next_height,
        uint32_t *out_bits)
{
    if (!params)
        return ZCL_ERR(DOMAIN_CONSENSUS_POW_ERR_NULL_PARAMS,
                       "calculate_next_work_required: null params");
    if (!out_bits)
        return ZCL_ERR(DOMAIN_CONSENSUS_POW_ERR_NULL_OUT,
                       "calculate_next_work_required: null out_bits");

    int64_t avgTimespan = consensus_averaging_window_timespan(params, next_height);
    int64_t minTimespan = consensus_min_actual_timespan(params, next_height);
    int64_t maxTimespan = consensus_max_actual_timespan(params, next_height);

    int64_t nActualTimespan = last_block_time - first_block_time;
    nActualTimespan = avgTimespan + (nActualTimespan - avgTimespan) / 4;

    if (nActualTimespan < minTimespan)
        nActualTimespan = minTimespan;
    if (nActualTimespan > maxTimespan)
        nActualTimespan = maxTimespan;

    struct arith_uint256 bnPowLimit;
    uint256_to_arith(&bnPowLimit, &params->powLimit);

    struct arith_uint256 avgTs, actTs;
    arith_uint256_set_u64(&avgTs, (uint64_t)avgTimespan);
    arith_uint256_set_u64(&actTs, (uint64_t)nActualTimespan);

    struct arith_uint256 bnNew;
    arith_uint256_div(&bnNew, &bn_avg, &avgTs);
    struct arith_uint256 bnResult;
    arith_uint256_mul(&bnResult, &bnNew, &actTs);
    bnNew = bnResult;

    if (arith_uint256_compare(&bnNew, &bnPowLimit) > 0)
        bnNew = bnPowLimit;

    *out_bits = arith_uint256_get_compact(&bnNew, false);
    return ZCL_OK;
}
