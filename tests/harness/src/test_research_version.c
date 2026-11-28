/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal upgrade versions. */

#include "services/research_version.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int version_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_version: %s\n", cond);
        return 1;
    }
    return 0;
}

static int expect_version(const struct chain_params *chain, enum upgrade_index idx)
{
    return chain->consensus.vUpgrades[idx].nProtocolVersion;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_version_read(NULL);

    return version_check("null version refused",
                         !r.ok && strcmp(r.message, "Missing version") == 0);
}

static int read_one(struct research_version_view *out)
{
    return version_check("version read ok", research_version_read(out).ok);
}

static int pin_rehearsal(const struct chain_params *chain,
                         const struct research_version_view *out)
{
    int overwinter = expect_version(chain, UPGRADE_OVERWINTER);
    int sapling = expect_version(chain, UPGRADE_SAPLING);
    int bubbles = expect_version(chain, UPGRADE_BUBBLES);
    int diffadj = expect_version(chain, UPGRADE_DIFFADJ);
    int buttercup = expect_version(chain, UPGRADE_BUTTERCUP);

    printf("version_overwinter=%d\n", out->overwinter);
    printf("version_sapling=%d\n", out->sapling);
    printf("version_bubbles=%d\n", out->bubbles);
    printf("version_diffadj=%d\n", out->diffadj);
    printf("version_buttercup=%d\n", out->buttercup);
    if (version_check("overwinter matches descriptor", out->overwinter == overwinter))
        return 1;
    if (version_check("sapling matches descriptor", out->sapling == sapling))
        return 1;
    if (version_check("bubbles matches descriptor", out->bubbles == bubbles))
        return 1;
    if (version_check("diffadj matches descriptor", out->diffadj == diffadj))
        return 1;
    if (version_check("buttercup matches descriptor", out->buttercup == buttercup))
        return 1;
    if (version_check("rehearsal overwinter is 170003", out->overwinter == 170003))
        return 1;
    if (version_check("rehearsal sapling is 170006", out->sapling == 170006))
        return 1;
    if (version_check("rehearsal bubbles is 170008", out->bubbles == 170008))
        return 1;
    if (version_check("rehearsal diffadj is 170009", out->diffadj == 170009))
        return 1;
    return version_check("rehearsal buttercup is 170010", out->buttercup == 170010);
}

static int main_one(const char *label, int got, int expect, int iron)
{
    printf("%s=%d\n", label, got);
    return version_check(label, got == expect && got != iron);
}

static int main_differs(const struct chain_params *main,
                        const struct research_version_view *iron)
{
    if (main_one("main_version_overwinter",
                 expect_version(main, UPGRADE_OVERWINTER), 170005, iron->overwinter))
        return 1;
    if (main_one("main_version_sapling",
                 expect_version(main, UPGRADE_SAPLING), 170007, iron->sapling))
        return 1;
    if (main_one("main_version_bubbles",
                 expect_version(main, UPGRADE_BUBBLES), 170009, iron->bubbles))
        return 1;
    if (main_one("main_version_diffadj",
                 expect_version(main, UPGRADE_DIFFADJ), 170010, iron->diffadj))
        return 1;
    return main_one("main_version_buttercup",
                    expect_version(main, UPGRADE_BUTTERCUP), 170011, iron->buttercup);
}

int test_research_version(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_version_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (version_check("lookup starts unselected",
                      main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_one(&out) || pin_rehearsal(d->chain, &out))
        return 1;
    if (main_differs(main, &out))
        return 1;
    if (version_check("read does not select",
                      chain_params_get() == main &&
                      !chain_research_profile_current()))
        return 1;
    printf("research_version: ironwood rehearsal upgrade versions pinned\n");
    return 0;
}
