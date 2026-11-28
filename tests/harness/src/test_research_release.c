/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood selected release activation schedule. */

#include "services/research_release.h"

#include "chain/chainparams.h"
#include "services/research_schedule.h"

#include <stdio.h>
#include <string.h>

static int release_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_release: %s\n", cond);
        return 1;
    }
    return 0;
}

static int heights_are(int overwinter, int sapling, int expect)
{
    return overwinter == expect && sapling == expect;
}

static int refuse_missing(void)
{
    int overwinter = -2;
    int sapling = -2;
    struct zcl_result r;

    r = research_release_read(&overwinter, NULL);
    if (release_check("missing sapling refused",
                      !r.ok &&
                      strcmp(r.message, "Missing release schedule") == 0 &&
                      overwinter == -2))
        return 1;
    r = research_release_read(NULL, &sapling);
    return release_check("missing overwinter refused",
                         !r.ok &&
                         strcmp(r.message, "Missing release schedule") == 0 &&
                         sapling == -2);
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    int overwinter = -2;
    int sapling = -2;
    int rehearsal_overwinter = -2;
    int rehearsal_sapling = -2;
    int expect;
    int main_overwinter;
    int main_sapling;
    int sealed_overwinter;
    int sealed_sapling;

    if (release_check("release read ok",
                      research_release_read(&overwinter, &sapling).ok))
        return 1;
    if (release_check("rehearsal read ok",
                      research_schedule_read(&rehearsal_overwinter,
                                             &rehearsal_sapling).ok))
        return 1;
    expect = NETWORK_UPGRADE_NO_ACTIVATION + 1;
    printf("release_overwinter=%d\n", overwinter);
    printf("release_sapling=%d\n", sapling);
    printf("rehearsal_overwinter=%d\n", rehearsal_overwinter);
    printf("rehearsal_sapling=%d\n", rehearsal_sapling);
    if (release_check("release matches genesis",
                      heights_are(overwinter, sapling, expect)))
        return 1;
    if (release_check("release published", overwinter == 0 && sapling == 0))
        return 1;
    if (release_check("rehearsal stays disabled",
                      heights_are(rehearsal_overwinter, rehearsal_sapling,
                                  NETWORK_UPGRADE_NO_ACTIVATION)))
        return 1;
    if (!d || !d->chain)
        return 1;
    sealed_overwinter =
        d->chain->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    sealed_sapling =
        d->chain->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    if (release_check("descriptor stays disabled",
                      heights_are(sealed_overwinter, sealed_sapling,
                                  NETWORK_UPGRADE_NO_ACTIVATION)))
        return 1;
    main_overwinter =
        main->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    main_sapling =
        main->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    printf("main_overwinter_differs=%d\n", main_overwinter != overwinter);
    printf("main_sapling_differs=%d\n", main_sapling != sapling);
    if (release_check("main overwinter differs", main_overwinter != overwinter))
        return 1;
    return release_check("main sapling differs", main_sapling != sapling);
}

int test_research_release(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (release_check("lookup starts unselected",
                      main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_published(main, d))
        return 1;
    if (release_check("read does not select",
                      chain_params_get() == main &&
                      !chain_research_profile_current()))
        return 1;
    printf("research_release: ironwood selected schedule pinned\n");
    return 0;
}
