/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Bounded canonical block size checks for the isolated research profile. */
#ifndef ZCL_RESEARCH_BLOCK_SIZE_H
#define ZCL_RESEARCH_BLOCK_SIZE_H

#include "chain/chainparams.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "services/research_rules.h"
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

/* The coarse ceiling a caller may apply before any rule is resolved: the
 * historical MAX_BLOCK_SIZE, under which a block that is valid under
 * either state of the research block-cap rule always fits. Zero means the
 * selected parameters cannot be classified. */
static inline size_t research_block_size_ceiling(const struct chain_params *params)
{
    return research_block_size_limit(params) ? MAX_BLOCK_SIZE : 0;
}

/* The exact limit that governs a candidate whose parent resolved to
 * `rules`: the research limit once the block-cap rule is active on that
 * parent's branch, otherwise the coarse ceiling. The cap applies to the
 * research chain only, whatever a resolved state says. */
static inline size_t research_block_size_limit_for(const struct chain_params *params,
                                                   const struct research_rules_state *rules)
{
    bool capped = params && rules && rules->active[RESEARCH_RULE_BLOCK_CAP] &&
                  research_block_size_limit(params) == RESEARCH_BLOCK_SIZE_LIMIT;
    return capped ? RESEARCH_BLOCK_SIZE_LIMIT : research_block_size_ceiling(params);
}

/* Classify `block` against one explicit limit. Ordinary chains retain
 * their existing validation; the research profile serializes into a
 * fixed-capacity buffer to bound memory usage. */
static inline enum research_block_size_verdict research_block_size_check_under(
    const struct chain_params *params, const struct block *block, size_t limit)
{
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

/* The research limit whatever the resolved rules say. Callers that can
 * resolve the rules of a candidate's parent use
 * research_block_size_limit_for and research_block_size_check_under. */
static inline enum research_block_size_verdict research_block_size_check(
    const struct chain_params *params, const struct block *block)
{
    return research_block_size_check_under(params, block,
                                           research_block_size_limit(params));
}
#endif
