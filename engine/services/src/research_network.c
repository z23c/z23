/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood network id and founders-reward count. */

#include "services/research_network.h"

#include "chain/chainparams.h"

#include <string.h>

_Static_assert(sizeof(((struct chain_params *)0)->strNetworkID) == 16,
               "network id cap matches the chain field");

struct zcl_result research_network_read(char *network_id, size_t network_id_cap,
                                        size_t *founders_count)
{
    const struct chain_research_descriptor *d;
    const char *id;
    size_t n;

    if (!network_id || !founders_count)
        return ZCL_ERR(-1, "Missing network");
    if (network_id_cap == 0)
        return ZCL_ERR(-2, "Network cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-3, "Research network missing");
    id = d->chain->strNetworkID;
    n = strlen(id);
    if (n == 0 || n + 1 > network_id_cap)
        return ZCL_ERR(-4, "Network id refused");
    *founders_count = d->chain->nFoundersRewardAddresses;
    memcpy(network_id, id, n + 1);
    return ZCL_OK;
}
