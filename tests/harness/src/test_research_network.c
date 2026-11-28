/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood network id and an empty founders reward. */

#include "services/research_network.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int network_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_network: %s\n", cond);
        return 1;
    }
    return 0;
}

static int id_still_marked(const char *id)
{
    return id[0] == 'X' && id[1] == 'X' && id[2] == 'X' && id[3] == 'X';
}

static int refuse_short(void)
{
    char id[4];
    size_t founders = 99;
    struct zcl_result r;

    memset(id, 'X', sizeof id);
    r = research_network_read(id, sizeof id, &founders);
    if (network_check("short id refused", !r.ok &&
                      strcmp(r.message, "Network id refused") == 0))
        return 1;
    return network_check("short id writes nothing",
                         founders == 99 && id_still_marked(id));
}

static int read_published(const struct chain_params *main)
{
    char id[16];
    size_t founders = 99;
    struct zcl_result r;

    memset(id, 0, sizeof id);
    r = research_network_read(id, sizeof id, &founders);
    if (network_check("network read ok", r.ok))
        return 1;
    printf("network_id=%s\n", id);
    printf("founders_count=%zu\n", founders);
    printf("main_network_id=%s\n", main->strNetworkID);
    printf("main_founders_count=%zu\n", main->nFoundersRewardAddresses);
    if (network_check("network id", strcmp(id, "ironwood") == 0))
        return 1;
    if (network_check("no founders reward", founders == 0))
        return 1;
    if (network_check("main network differs",
                      strcmp(main->strNetworkID, id) != 0))
        return 1;
    return network_check("main founders differ",
                         main->nFoundersRewardAddresses != founders);
}

int test_research_network(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    current = chain_research_profile_current();
    if (network_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_short() || read_published(main))
        return 1;
    if (network_check("read does not select",
                      chain_params_get() == main &&
                      !chain_research_profile_current()))
        return 1;
    printf("research_network: ironwood network id pinned\n");
    return 0;
}
