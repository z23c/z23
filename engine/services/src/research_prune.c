/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal prune policy. */

#include "services/research_prune.h"

#include "chain/chainparams.h"

#include <string.h>

struct zcl_result research_prune_read(struct research_prune_view *out)
{
    const struct chain_research_descriptor *d;
    struct research_prune_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing prune");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research prune missing");
    memset(&got, 0, sizeof got);
    got.prune_after = d->chain->nPruneAfterHeight;
    got.consistency_checks = d->chain->fDefaultConsistencyChecks ? 1 : 0;
    *out = got;
    return ZCL_OK;
}
