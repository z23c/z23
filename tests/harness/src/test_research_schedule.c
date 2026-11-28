/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin disabled Ironwood Overwinter and Sapling activation heights. */

#include "services/research_schedule.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int schedule_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_schedule: %s\n", cond);
        return 1;
    }
    return 0;
}

static int refuse_missing(void)
{
    int overwinter = 99;
    struct zcl_result r;

    r = research_schedule_read(&overwinter, NULL);
    if (schedule_check("missing sapling refused", !r.ok &&
                       strcmp(r.message, "Missing schedule") == 0))
        return 1;
    return schedule_check("missing sapling writes nothing", overwinter == 99);
}

static int read_published(const struct chain_params *main)
{
    int overwinter = 99;
    int sapling = 99;
    struct zcl_result r;
    int main_overwinter;
    int main_sapling;

    r = research_schedule_read(&overwinter, &sapling);
    if (schedule_check("schedule read ok", r.ok))
        return 1;
    printf("overwinter_height=%d\n", overwinter);
    printf("sapling_height=%d\n", sapling);
    main_overwinter = main->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight;
    main_sapling = main->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    printf("main_overwinter_differs=%d\n", main_overwinter != overwinter);
    printf("main_sapling_differs=%d\n", main_sapling != sapling);
    if (schedule_check("overwinter disabled",
                       overwinter == NETWORK_UPGRADE_NO_ACTIVATION))
        return 1;
    if (schedule_check("sapling disabled",
                       sapling == NETWORK_UPGRADE_NO_ACTIVATION))
        return 1;
    if (schedule_check("main overwinter differs", main_overwinter != overwinter))
        return 1;
    return schedule_check("main sapling differs", main_sapling != sapling);
}

int test_research_schedule(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    current = chain_research_profile_current();
    if (schedule_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_missing() || read_published(main))
        return 1;
    if (schedule_check("read does not select",
                       chain_params_get() == main &&
                       !chain_research_profile_current()))
        return 1;
    printf("research_schedule: ironwood upgrade heights pinned\n");
    return 0;
}
