/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal acceptance policy. */

#include "services/research_policy.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int policy_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_policy: %s\n", cond);
        return 1;
    }
    return 0;
}

static int flag_of(int enabled)
{
    return enabled ? 1 : 0;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_policy_read(NULL);

    return policy_check("null policy refused",
                        !r.ok && strcmp(r.message, "Missing policy") == 0);
}

static int read_one(struct research_policy_view *out)
{
    return policy_check("policy read ok", research_policy_read(out).ok);
}

static int pin_rehearsal(const struct chain_params *chain,
                         const struct research_policy_view *out)
{
    int standard = flag_of(chain->fRequireStandard);
    int peers = flag_of(chain->fMiningRequiresPeers);

    printf("require_standard=%d\n", out->require_standard);
    printf("mining_requires_peers=%d\n", out->mining_requires_peers);
    if (policy_check("standard matches descriptor", out->require_standard == standard))
        return 1;
    if (policy_check("peers match descriptor", out->mining_requires_peers == peers))
        return 1;
    if (policy_check("nonstandard transactions admitted", out->require_standard == 0))
        return 1;
    return policy_check("solo mining admitted", out->mining_requires_peers == 0);
}

static int main_differs(const struct chain_params *main,
                        const struct research_policy_view *iron)
{
    int standard = flag_of(main->fRequireStandard);
    int peers = flag_of(main->fMiningRequiresPeers);

    printf("main_require_standard=%d\n", standard);
    printf("main_mining_requires_peers=%d\n", peers);
    if (policy_check("main requires standard",
                     standard == 1 && standard != iron->require_standard))
        return 1;
    return policy_check("main mining requires peers",
                        peers == 1 && peers != iron->mining_requires_peers);
}

int test_research_policy(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_policy_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (policy_check("lookup starts unselected",
                     main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_one(&out) || pin_rehearsal(d->chain, &out))
        return 1;
    if (main_differs(main, &out))
        return 1;
    if (policy_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_policy: ironwood rehearsal policy pinned\n");
    return 0;
}
