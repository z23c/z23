/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin Ironwood Equihash 48,5 after the mainnet Bubbles height. */

#include "services/research_pow.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int pow_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_pow: %s\n", cond);
        return 1;
    }
    return 0;
}

static void mark_pow(struct research_pow *p)
{
    p->bubbles_height = 99;
    p->diffadj_height = 99;
    p->buttercup_height = 99;
    p->equihash_n = 7;
    p->equihash_k = 7;
}

static int still_marked(const struct research_pow *p)
{
    return p->bubbles_height == 99 && p->diffadj_height == 99 &&
           p->buttercup_height == 99 && p->equihash_n == 7 && p->equihash_k == 7;
}

static int refuse_height(void)
{
    struct research_pow p;
    struct zcl_result r;

    mark_pow(&p);
    r = research_pow_read(-1, &p);
    if (pow_check("negative height refused", !r.ok &&
                  strcmp(r.message, "Pow height refused") == 0))
        return 1;
    return pow_check("negative height writes nothing", still_marked(&p));
}

static int check_disabled(const struct research_pow *p)
{
    if (pow_check("bubbles disabled",
                  p->bubbles_height == NETWORK_UPGRADE_NO_ACTIVATION))
        return 1;
    if (pow_check("diffadj disabled",
                  p->diffadj_height == NETWORK_UPGRADE_NO_ACTIVATION))
        return 1;
    return pow_check("buttercup disabled",
                     p->buttercup_height == NETWORK_UPGRADE_NO_ACTIVATION);
}

static int read_published(const struct chain_params *main)
{
    struct research_pow p;
    struct zcl_result r;
    unsigned main_n;
    unsigned main_k;
    const int height = 585318;

    mark_pow(&p);
    r = research_pow_read(height, &p);
    if (pow_check("pow read ok", r.ok))
        return 1;
    printf("bubbles_height=%d\n", p.bubbles_height);
    printf("diffadj_height=%d\n", p.diffadj_height);
    printf("buttercup_height=%d\n", p.buttercup_height);
    printf("equihash_n=%u\n", p.equihash_n);
    printf("equihash_k=%u\n", p.equihash_k);
    main_n = chain_params_equihash_n(main, height);
    main_k = chain_params_equihash_k(main, height);
    printf("main_equihash_n=%u\n", main_n);
    printf("main_equihash_k=%u\n", main_k);
    if (check_disabled(&p))
        return 1;
    if (pow_check("ironwood equihash n", p.equihash_n == 48))
        return 1;
    if (pow_check("ironwood equihash k", p.equihash_k == 5))
        return 1;
    if (pow_check("main equihash n differs", main_n != p.equihash_n))
        return 1;
    return pow_check("main equihash k differs", main_k != p.equihash_k);
}

int test_research_pow(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    current = chain_research_profile_current();
    if (pow_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_height() || read_published(main))
        return 1;
    if (pow_check("read does not select",
                  chain_params_get() == main &&
                  !chain_research_profile_current()))
        return 1;
    printf("research_pow: ironwood equihash stays 48,5\n");
    return 0;
}
