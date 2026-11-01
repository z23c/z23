/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Epoch-I thin wrapper. The pure PoW difficulty arithmetic lives in
 * domain/consensus/pow.{h,c}; this file preserves the legacy
 * uint32_t-returning / bool-returning signatures so existing callers
 * stay unchanged while the domain functions return a typed zcl_result.
 *
 * The CheckProofOfWork() bool wrapper delegates to
 * domain_consensus_verify_pow_solution() in domain/consensus/verify.c
 * (which has been mirroring this logic since the verify extraction). */

#include "chain/pow.h"
#include "domain/consensus/pow.h"
#include "domain/consensus/verify.h"
#include "util/util.h"
#include <limits.h>

unsigned int IncreaseDifficultyBy(unsigned int nBits, int64_t multiplier,
                                  const struct consensus_params *params)
{
    uint32_t out = 0;
    struct zcl_result r = domain_consensus_increase_difficulty_by(
            (uint32_t)nBits, multiplier, params, &out);
    if (!r.ok) {
        /* Preserve legacy fail-safe: on any contract violation, return
         * the input nBits unchanged. The domain function already
         * captured the precise reason in zcl_result. */
        LogPrintf("IncreaseDifficultyBy: %s\n",
                  r.message[0] ? r.message : "(no message)");
        return nBits;
    }
    return out;
}

/* True when the upgrade-fork difficulty window applies at nHeight. */
static bool pow_in_upgrade_difficulty_window(const struct consensus_params *params,
                                            int nHeight)
{
    return params->scaleDifficultyAtUpgradeFork &&
           ((nHeight >= params->vUpgrades[UPGRADE_DIFFADJ].nActivationHeight &&
             nHeight < params->vUpgrades[UPGRADE_DIFFADJ].nActivationHeight + params->nPowAveragingWindow) ||
            (nHeight >= params->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight &&
             nHeight < params->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight + params->nPowAveragingWindow));
}

/* On a lateness-ramp match, sets *out_work to that target and returns true. */
static bool pow_upgrade_fork_ramp_work(const struct block_index *pindexLast,
                                      const struct block_header *pblock,
                                      const struct consensus_params *params,
                                      int nHeight,
                                      unsigned int nProofOfWorkLimit,
                                      unsigned int *out_work)
{
    *out_work = 0;
    int64_t spacing = consensus_pow_target_spacing(params, nHeight);
    if (pblock && block_header_get_time(pblock) >
        block_index_get_time(pindexLast) + spacing * 12) {
        *out_work = nProofOfWorkLimit;
        return true;
    } else if (pblock && block_header_get_time(pblock) >
               block_index_get_time(pindexLast) + spacing * 6) {
        *out_work = IncreaseDifficultyBy(nProofOfWorkLimit, 128, params);
        return true;
    } else if (pblock && block_header_get_time(pblock) >
               block_index_get_time(pindexLast) + spacing * 2) {
        *out_work = IncreaseDifficultyBy(nProofOfWorkLimit, 256, params);
        return true;
    }
    return false;
}

/* True when min-difficulty blocks are enabled and this block is over 6 spacings late. */
static bool pow_min_difficulty_blocks_allow_limit(const struct block_index *pindexLast,
                                                 const struct block_header *pblock,
                                                 const struct consensus_params *params)
{
    if (params->nPowAllowMinDifficultyEnabled &&
        pindexLast->nHeight >= params->nPowAllowMinDifficultyBlocksAfterHeight) {
        int64_t spacing = consensus_pow_target_spacing(params, pindexLast->nHeight + 1);
        if (pblock && block_header_get_time(pblock) >
            block_index_get_time(pindexLast) + spacing * 6)
            return true;
    }
    return false;
}

unsigned int GetNextWorkRequired(const struct block_index *pindexLast,
                                 const struct block_header *pblock,
                                 const struct consensus_params *params)
{
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &params->powLimit);
    unsigned int nProofOfWorkLimit = arith_uint256_get_compact(&pow_limit, false);

    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    int nHeight = pindexLast->nHeight + 1;

    if (pow_in_upgrade_difficulty_window(params, nHeight)) {
        unsigned int scaled = 0;
        if (pow_upgrade_fork_ramp_work(pindexLast, pblock, params, nHeight,
                                      nProofOfWorkLimit, &scaled))
            return scaled;
    }

    if (pow_min_difficulty_blocks_allow_limit(pindexLast, pblock, params))
        return nProofOfWorkLimit;

    /* Validate averaging window is positive — zero would cause division by zero */
    if (params->nPowAveragingWindow <= 0)
        return nProofOfWorkLimit;

    const struct block_index *pindexFirst = pindexLast;
    struct arith_uint256 bnTot;
    arith_uint256_set_zero(&bnTot);
    for (int i = 0; pindexFirst && i < params->nPowAveragingWindow; i++) {
        struct arith_uint256 bnTmp;
        arith_uint256_set_compact(&bnTmp, pindexFirst->nBits, NULL, NULL);
        struct arith_uint256 sum;
        arith_uint256_add(&sum, &bnTot, &bnTmp);
        bnTot = sum;
        pindexFirst = pindexFirst->pprev;
    }

    if (pindexFirst == NULL)
        return nProofOfWorkLimit;

    struct arith_uint256 bnAvg;
    struct arith_uint256 window;
    arith_uint256_set_u64(&window, (uint64_t)params->nPowAveragingWindow);
    arith_uint256_div(&bnAvg, &bnTot, &window);

    return CalculateNextWorkRequired(bnAvg,
        block_index_get_median_time_past(pindexLast),
        block_index_get_median_time_past(pindexFirst),
        params, pindexLast->nHeight + 1);
}

unsigned int CalculateNextWorkRequired(struct arith_uint256 bnAvg,
                                       int64_t nLastBlockTime,
                                       int64_t nFirstBlockTime,
                                       const struct consensus_params *params,
                                       int nextHeight)
{
    uint32_t out = 0;
    struct zcl_result r = domain_consensus_calculate_next_work_required(
            bnAvg, nLastBlockTime, nFirstBlockTime, params, nextHeight, &out);
    if (!r.ok) {
        /* Preserve legacy fail-safe: fall back to powLimit-as-compact
         * if anything went wrong (null params/out). The domain function
         * already captured the precise reason. */
        LogPrintf("CalculateNextWorkRequired: %s\n",
                  r.message[0] ? r.message : "(no message)");
        if (params) {
            struct arith_uint256 pow_limit;
            uint256_to_arith(&pow_limit, &params->powLimit);
            return arith_uint256_get_compact(&pow_limit, false);
        }
        return 0;
    }
    return out;
}

bool CheckProofOfWork(struct uint256 hash, unsigned int nBits,
                      const struct consensus_params *params)
{
    struct zcl_result r =
        domain_consensus_verify_pow_solution(&hash, (uint32_t)nBits, params);
    if (!r.ok) {
        LogPrintf("CheckProofOfWork(): %s\n",
                  r.message[0] ? r.message : "rejected");
        return false;
    }
    return true;
}

struct arith_uint256 GetBlockProof(const struct block_index *block)
{
    struct arith_uint256 work;
    arith_uint256_set_zero(&work);
    if (!block)
        return work;
    (void)domain_consensus_block_proof(block->nBits, &work);
    return work;
}

int64_t GetBlockProofEquivalentTime(const struct block_index *to,
                                    const struct block_index *from,
                                    const struct block_index *tip,
                                    const struct consensus_params *params)
{
    struct arith_uint256 r;
    int sign = 1;
    if (arith_uint256_compare(&to->nChainWork, &from->nChainWork) > 0) {
        arith_uint256_sub(&r, &to->nChainWork, &from->nChainWork);
    } else {
        arith_uint256_sub(&r, &from->nChainWork, &to->nChainWork);
        sign = -1;
    }

    struct arith_uint256 spacing;
    arith_uint256_set_u64(&spacing,
        (uint64_t)consensus_pow_target_spacing(params, tip->nHeight));

    struct arith_uint256 tmp;
    arith_uint256_mul(&tmp, &r, &spacing);

    struct arith_uint256 proof = GetBlockProof(tip);
    arith_uint256_div(&r, &tmp, &proof);

    if (arith_uint256_bits(&r) > 63)
        return sign * INT64_MAX;

    return sign * (int64_t)arith_uint256_get_low64(&r);
}
