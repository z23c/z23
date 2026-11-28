/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal block subsidy. */

#include "services/research_subsidy.h"

#include "chain/chainparams.h"
#include "chain/subsidy.h"

struct zcl_result research_subsidy_read(int height,
                                        struct research_subsidy_view *out)
{
    const struct chain_research_descriptor *d;
    struct research_subsidy_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing subsidy");
    if (height < 0)
        return ZCL_ERR(-3, "Subsidy height refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research subsidy missing");
    got.subsidy = get_block_subsidy(height, &d->chain->consensus);
    got.slow_start = d->chain->consensus.nSubsidySlowStartInterval;
    got.pre_halving = d->chain->consensus.nPreButtercupSubsidyHalvingInterval;
    got.post_halving = d->chain->consensus.nPostButtercupSubsidyHalvingInterval;
    got.coinbase_protected = 0;
    if (d->chain->consensus.fCoinbaseMustBeProtected)
        got.coinbase_protected = 1;
    *out = got;
    return ZCL_OK;
}
