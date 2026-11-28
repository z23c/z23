/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal acceptance policy. */

#include "services/research_policy.h"

#include "chain/chainparams.h"

struct zcl_result research_policy_read(struct research_policy_view *out)
{
    const struct chain_research_descriptor *d;
    struct research_policy_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing policy");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research policy missing");
    got.require_standard = 0;
    if (d->chain->fRequireStandard)
        got.require_standard = 1;
    got.mining_requires_peers = 0;
    if (d->chain->fMiningRequiresPeers)
        got.mining_requires_peers = 1;
    *out = got;
    return ZCL_OK;
}
