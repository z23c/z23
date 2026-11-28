/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal work floor. */

#include "services/research_floor.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

static void copy_floor(unsigned char *dst, const unsigned char *src)
{
    int i;

    for (i = 0; i < 32; i++)
        dst[i] = src[i];
}

struct zcl_result research_floor_read(struct research_floor_view *out)
{
    const struct chain_research_descriptor *d;
    const struct consensus_params *c;
    struct research_floor_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing floor");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research floor missing");
    c = &d->chain->consensus;
    copy_floor(got.work_floor, c->nMinimumChainWork.data);
    copy_floor(got.pow_limit, c->powLimit.data);
    got.scale_at_fork = 0;
    if (c->scaleDifficultyAtUpgradeFork)
        got.scale_at_fork = 1;
    *out = got;
    return ZCL_OK;
}
