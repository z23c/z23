/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Bounded canonical block size checks for the isolated research profile. */
#ifndef ZCL_RESEARCH_BLOCK_SIZE_H
#define ZCL_RESEARCH_BLOCK_SIZE_H

#include "chain/chainparams.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "util/safe_alloc.h"
#include <stdlib.h>

enum research_block_size_verdict {
    RESEARCH_BLOCK_SIZE_OK,
    RESEARCH_BLOCK_SIZE_EXCEEDED,
    RESEARCH_BLOCK_SIZE_UNAVAILABLE
};

#define RESEARCH_BLOCK_SIZE_LIMIT 200000u

/* Zero means the selected parameters cannot be classified. */
static inline size_t research_block_size_limit(const struct chain_params *params)
{
    const struct chain_research_descriptor *profile =
        chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!params || !profile)
        return 0;
    return uint256_eq(&params->consensus.hashGenesisBlock,
                      &profile->chain->consensus.hashGenesisBlock)
        ? RESEARCH_BLOCK_SIZE_LIMIT : MAX_BLOCK_SIZE;
}

/* Ordinary chains retain their existing validation; the research profile
 * serializes into a fixed-capacity buffer to bound memory usage. */
static inline enum research_block_size_verdict research_block_size_check(
    const struct chain_params *params, const struct block *block)
{
    size_t limit = research_block_size_limit(params);
    if (!limit || !block)
        return RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    if (limit != RESEARCH_BLOCK_SIZE_LIMIT)
        return RESEARCH_BLOCK_SIZE_OK;
    if (block->header.nSolutionSize > MAX_SOLUTION_SIZE)
        return RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    unsigned char *bytes = zcl_malloc(limit + 1, "research block size");
    if (!bytes)
        return RESEARCH_BLOCK_SIZE_UNAVAILABLE;
    struct byte_stream s = {
        .data = bytes, .size = 0, .capacity = limit + 1,
        .read_pos = 0, .error = false, .owns_data = false
    };
    bool ok = block_serialize(block, &s);
    bool exceeded = s.error || s.size > limit;
    free(bytes);
    if (exceeded)
        return RESEARCH_BLOCK_SIZE_EXCEEDED;
    return ok ? RESEARCH_BLOCK_SIZE_OK : RESEARCH_BLOCK_SIZE_UNAVAILABLE;
}
#endif
