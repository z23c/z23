/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal coinbase maturity. */

#include "services/research_maturity.h"

#include "chain/chainparams.h"
#include "consensus/consensus.h"

struct zcl_result research_maturity_read(int *blocks)
{
    const struct chain_research_descriptor *d;

    if (!blocks)
        return ZCL_ERR(-1, "Missing maturity");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research maturity missing");
    *blocks = COINBASE_MATURITY;
    return ZCL_OK;
}
