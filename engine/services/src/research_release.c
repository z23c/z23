/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood selected release activation schedule. */

#include "services/research_release.h"

#include "chain/chainparams.h"

struct zcl_result research_release_read(int *overwinter_height,
                                        int *sapling_height)
{
    const struct chain_research_descriptor *d;

    if (!overwinter_height || !sapling_height)
        return ZCL_ERR(-1, "Missing release schedule");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research release missing");
    *overwinter_height = 0;
    *sapling_height = 0;
    return ZCL_OK;
}
