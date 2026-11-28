/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read Ironwood Overwinter and Sapling activation heights. */

#include "services/research_schedule.h"

#include "chain/chainparams.h"

struct zcl_result research_schedule_read(int *overwinter_height,
                                         int *sapling_height)
{
    const struct chain_research_descriptor *d;
    const struct consensus_params *consensus;

    if (!overwinter_height || !sapling_height)
        return ZCL_ERR(-1, "Missing schedule");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research schedule missing");
    consensus = &d->chain->consensus;
    *overwinter_height = consensus->vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    *sapling_height = consensus->vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    return ZCL_OK;
}
