/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal upgrade quorum. */

#include "services/research_quorum.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

struct zcl_result research_quorum_read(struct research_quorum_view *out)
{
    const struct chain_research_descriptor *d;
    const struct consensus_params *c;
    struct research_quorum_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing quorum");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research quorum missing");
    c = &d->chain->consensus;
    got.window = c->nMajorityWindow;
    got.enforce = c->nMajorityEnforceBlockUpgrade;
    got.reject = c->nMajorityRejectBlockOutdated;
    *out = got;
    return ZCL_OK;
}
