/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal work floor. */

#include "services/research_floor.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

#include <stdio.h>
#include <string.h>

static int floor_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_floor: %s\n", cond);
        return 1;
    }
    return 0;
}

static int flag_of(int enabled)
{
    return enabled ? 1 : 0;
}

static int all_zero(const unsigned char *p)
{
    int i;

    for (i = 0; i < 32; i++)
        if (p[i] != 0)
            return 0;
    return 1;
}

/* Regtest, and therefore Ironwood, publishes an all-0x0f proof ceiling. */
static int limit_easy(const unsigned char *p)
{
    int i;

    for (i = 0; i < 32; i++)
        if (p[i] != 0x0f)
            return 0;
    return 1;
}

static int same_bytes(const unsigned char *a, const unsigned char *b)
{
    int i;

    for (i = 0; i < 32; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

static void print_lead(const char *name, unsigned char b)
{
    static const char hexd[] = "0123456789abcdef";

    printf("%s=%c%c\n", name, hexd[b / 16], hexd[b % 16]);
}

static int refuse_missing(void)
{
    struct zcl_result r = research_floor_read(NULL);

    return floor_check("null floor refused",
                       !r.ok && strcmp(r.message, "Missing floor") == 0);
}

static int read_one(struct research_floor_view *out)
{
    return floor_check("floor read ok", research_floor_read(out).ok);
}

static int pin_rehearsal(const struct consensus_params *c,
                         const struct research_floor_view *out)
{
    int scale = flag_of(c->scaleDifficultyAtUpgradeFork);

    printf("work_floor_zero=%d\n", all_zero(out->work_floor));
    printf("scale_at_fork=%d\n", out->scale_at_fork);
    printf("pow_limit_easy=%d\n", limit_easy(out->pow_limit));
    print_lead("pow_limit_lead", out->pow_limit[0]);
    if (floor_check("floor matches descriptor",
                    same_bytes(out->work_floor, c->nMinimumChainWork.data)))
        return 1;
    if (floor_check("limit matches descriptor",
                    same_bytes(out->pow_limit, c->powLimit.data)))
        return 1;
    if (floor_check("rehearsal work floor is zero", all_zero(out->work_floor)))
        return 1;
    if (floor_check("rehearsal proof ceiling is easy", limit_easy(out->pow_limit)))
        return 1;
    return floor_check("upgrade fork does not rescale",
                       out->scale_at_fork == scale && scale == 0);
}

static int main_differs(const struct consensus_params *main,
                        const struct research_floor_view *iron)
{
    int scale = flag_of(main->scaleDifficultyAtUpgradeFork);
    int zero = all_zero(main->nMinimumChainWork.data);
    int easy = limit_easy(main->powLimit.data);

    printf("main_work_floor_zero=%d\n", zero);
    printf("main_scale_at_fork=%d\n", scale);
    printf("main_pow_limit_easy=%d\n", easy);
    print_lead("main_pow_limit_lead", main->powLimit.data[0]);
    if (floor_check("main work floor is set",
                    zero == 0 && !same_bytes(iron->work_floor,
                                             main->nMinimumChainWork.data)))
        return 1;
    if (floor_check("main proof ceiling differs",
                    easy == 0 && !same_bytes(iron->pow_limit, main->powLimit.data)))
        return 1;
    return floor_check("main rescales at an upgrade fork",
                       scale == 1 && scale != iron->scale_at_fork);
}

int test_research_floor(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_floor_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (floor_check("lookup starts unselected",
                    main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_one(&out) ||
        pin_rehearsal(&d->chain->consensus, &out))
        return 1;
    if (main_differs(&main->consensus, &out))
        return 1;
    if (floor_check("read does not select",
                    chain_params_get() == main &&
                    !chain_research_profile_current()))
        return 1;
    printf("research_floor: ironwood rehearsal work floor pinned\n");
    return 0;
}
