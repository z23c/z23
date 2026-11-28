/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal block spacing. */

#include "services/research_spacing.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

struct zcl_result research_spacing_read(int height,
                                        struct research_spacing_view *out)
{
    const struct chain_research_descriptor *d;
    const struct consensus_params *c;
    struct research_spacing_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing spacing");
    if (height < 0)
        return ZCL_ERR(-3, "Spacing height refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research spacing missing");
    c = &d->chain->consensus;
    got.spacing = consensus_pow_target_spacing(c, height);
    got.adjust_up = (int)c->nPowMaxAdjustUp;
    got.adjust_down = (int)c->nPowMaxAdjustDown;
    got.min_difficulty = 0;
    if (c->nPowAllowMinDifficultyEnabled &&
        height >= c->nPowAllowMinDifficultyBlocksAfterHeight)
        got.min_difficulty = 1;
    got.mine_on_demand = 0;
    if (d->chain->fMineBlocksOnDemand)
        got.mine_on_demand = 1;
    *out = got;
    return ZCL_OK;
}
