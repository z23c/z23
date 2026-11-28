/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal coinbase maturity. */

#include "services/research_maturity.h"

#include "chain/chainparams.h"
#include "consensus/consensus.h"

#include <stdio.h>
#include <string.h>

static int maturity_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_maturity: %s\n", cond);
        return 1;
    }
    return 0;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_maturity_read(NULL);

    return maturity_check("null maturity refused",
                          !r.ok && strcmp(r.message, "Missing maturity") == 0);
}

static int read_published(void)
{
    int blocks = -1;
    int minted = 1;
    int first;
    int early;

    if (maturity_check("maturity read ok", research_maturity_read(&blocks).ok))
        return 1;
    first = minted + blocks;
    early = first - 1 - minted;
    printf("coinbase_maturity=%d\n", blocks);
    printf("first_spendable=%d\n", first);
    printf("immature_span=%d\n", early);
    if (maturity_check("maturity matches constant", blocks == COINBASE_MATURITY))
        return 1;
    if (maturity_check("maturity published", blocks == 100))
        return 1;
    if (maturity_check("first spendable published", first == 101))
        return 1;
    return maturity_check("prior block is immature", early == 99);
}

int test_research_maturity(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (maturity_check("lookup starts unselected",
                       main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_published())
        return 1;
    if (maturity_check("read does not select",
                       chain_params_get() == main &&
                       !chain_research_profile_current()))
        return 1;
    printf("research_maturity: ironwood coinbase maturity pinned\n");
    return 0;
}
