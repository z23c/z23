/* purpose: Identify networks eligible for ballot RPCs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_CONTROLLERS_BALLOT_NETWORK_H
#define ZCL_CONTROLLERS_BALLOT_NETWORK_H

#include "chain/chainparams.h"
#include <string.h>

/* Ordinary test networks retain their existing identity rule. A research
 * network must be the exact descriptor selected in this process. */
static inline bool ballot_network_eligible(const struct chain_params *cp)
{
    if (!cp) return false;
    if (!strcmp(cp->strNetworkID, "test") || !strcmp(cp->strNetworkID, "regtest"))
        return true;
    const struct chain_research_descriptor *selected = chain_research_profile_current();
    return selected && selected == chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD) &&
        cp == selected->chain;
}

#endif
