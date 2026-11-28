/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal prune policy. */

#include "services/research_prune.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int prune_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_prune: %s\n", cond);
        return 1;
    }
    return 0;
}

static uint64_t expect_prune(const struct chain_params *chain)
{
    return chain->nPruneAfterHeight;
}

static int expect_checks(const struct chain_params *chain)
{
    return chain->fDefaultConsistencyChecks ? 1 : 0;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_prune_read(NULL);

    return prune_check("null prune refused",
                       !r.ok && strcmp(r.message, "Missing prune") == 0);
}

static int read_one(struct research_prune_view *out)
{
    return prune_check("prune read ok", research_prune_read(out).ok);
}

static int pin_rehearsal(const struct chain_params *chain,
                         const struct research_prune_view *out)
{
    uint64_t prune_after = expect_prune(chain);
    int checks = expect_checks(chain);

    printf("prune_after=%llu\n", (unsigned long long)out->prune_after);
    printf("consistency_checks=%d\n", out->consistency_checks);
    if (prune_check("prune matches descriptor", out->prune_after == prune_after))
        return 1;
    if (prune_check("checks match descriptor", out->consistency_checks == checks))
        return 1;
    if (prune_check("rehearsal prune is 1000", out->prune_after == 1000))
        return 1;
    return prune_check("rehearsal checks are on", out->consistency_checks == 1);
}

static int main_differs(const struct chain_params *main,
                        const struct research_prune_view *iron)
{
    uint64_t prune_after = expect_prune(main);
    int checks = expect_checks(main);

    printf("main_prune_after=%llu\n", (unsigned long long)prune_after);
    printf("main_consistency_checks=%d\n", checks);
    if (prune_check("main prune is 100000",
                    prune_after == 100000 && prune_after != iron->prune_after))
        return 1;
    return prune_check("main checks are off",
                       checks == 0 && checks != iron->consistency_checks);
}

int test_research_prune(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_prune_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (prune_check("lookup starts unselected",
                    main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_one(&out) || pin_rehearsal(d->chain, &out))
        return 1;
    if (main_differs(main, &out))
        return 1;
    if (prune_check("read does not select",
                    chain_params_get() == main &&
                    !chain_research_profile_current()))
        return 1;
    printf("research_prune: ironwood rehearsal prune policy pinned\n");
    return 0;
}
