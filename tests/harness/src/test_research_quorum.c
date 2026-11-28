/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal upgrade quorum. */

#include "services/research_quorum.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

#include <stdio.h>
#include <string.h>

static int quorum_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_quorum: %s\n", cond);
        return 1;
    }
    return 0;
}

static int expect_window(const struct consensus_params *c)
{
    return c->nMajorityWindow;
}

static int expect_enforce(const struct consensus_params *c)
{
    return c->nMajorityEnforceBlockUpgrade;
}

static int expect_reject(const struct consensus_params *c)
{
    return c->nMajorityRejectBlockOutdated;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_quorum_read(NULL);

    return quorum_check("null quorum refused",
                        !r.ok && strcmp(r.message, "Missing quorum") == 0);
}

static int read_one(struct research_quorum_view *out)
{
    return quorum_check("quorum read ok", research_quorum_read(out).ok);
}

static int pin_rehearsal(const struct consensus_params *c,
                         const struct research_quorum_view *out)
{
    int window = expect_window(c);
    int enforce = expect_enforce(c);
    int reject = expect_reject(c);

    printf("quorum_window=%d\n", out->window);
    printf("quorum_enforce=%d\n", out->enforce);
    printf("quorum_reject=%d\n", out->reject);
    if (quorum_check("window matches descriptor", out->window == window))
        return 1;
    if (quorum_check("enforce matches descriptor", out->enforce == enforce))
        return 1;
    if (quorum_check("reject matches descriptor", out->reject == reject))
        return 1;
    if (quorum_check("rehearsal window is 1000", out->window == 1000))
        return 1;
    if (quorum_check("rehearsal enforce is 750", out->enforce == 750))
        return 1;
    if (quorum_check("rehearsal reject is 950", out->reject == 950))
        return 1;
    return quorum_check("window is not the enforce count",
                        out->window != out->enforce);
}

static int main_differs(const struct consensus_params *main,
                        const struct research_quorum_view *iron)
{
    int window = expect_window(main);
    int enforce = expect_enforce(main);
    int reject = expect_reject(main);

    printf("main_quorum_window=%d\n", window);
    printf("main_quorum_enforce=%d\n", enforce);
    printf("main_quorum_reject=%d\n", reject);
    if (quorum_check("main window is 4000",
                     window == 4000 && window != iron->window))
        return 1;
    if (quorum_check("main enforce matches rehearsal",
                     enforce == 750 && enforce == iron->enforce))
        return 1;
    return quorum_check("main reject matches rehearsal",
                        reject == 950 && reject == iron->reject);
}

int test_research_quorum(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_quorum_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (quorum_check("lookup starts unselected",
                     main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_one(&out) ||
        pin_rehearsal(&d->chain->consensus, &out))
        return 1;
    if (main_differs(&main->consensus, &out))
        return 1;
    if (quorum_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_quorum: ironwood rehearsal upgrade quorum pinned\n");
    return 0;
}
