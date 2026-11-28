/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal block spacing. */

#include "services/research_spacing.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

#include <stdio.h>
#include <string.h>

static int spacing_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_spacing: %s\n", cond);
        return 1;
    }
    return 0;
}

static int64_t expect_spacing(const struct consensus_params *c, int height)
{
    int activation = c->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;

    if (activation != NETWORK_UPGRADE_NO_ACTIVATION && height >= activation)
        return POST_BUTTERCUP_POW_TARGET_SPACING;
    return PRE_BUTTERCUP_POW_TARGET_SPACING;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_spacing_read(0, NULL);

    return spacing_check("null spacing refused",
                         !r.ok && strcmp(r.message, "Missing spacing") == 0);
}

static int refuse_negative(void)
{
    struct research_spacing_view out;
    struct zcl_result r;

    out.spacing = -7;
    out.adjust_up = -7;
    out.adjust_down = -7;
    out.min_difficulty = -7;
    out.mine_on_demand = -7;
    r = research_spacing_read(-1, &out);
    if (spacing_check("negative height refused",
                      !r.ok && strcmp(r.message, "Spacing height refused") == 0))
        return 1;
    return spacing_check("negative height leaves outputs",
                         out.spacing == -7 && out.adjust_up == -7 &&
                         out.adjust_down == -7 && out.min_difficulty == -7 &&
                         out.mine_on_demand == -7);
}

static int read_one(int height, struct research_spacing_view *out)
{
    return spacing_check("spacing read ok", research_spacing_read(height, out).ok);
}

static int pin_bounds(const struct research_spacing_view *out)
{
    if (spacing_check("adjust up published", out->adjust_up == 0))
        return 1;
    if (spacing_check("adjust down published", out->adjust_down == 0))
        return 1;
    if (spacing_check("minimum difficulty allowed", out->min_difficulty == 1))
        return 1;
    return spacing_check("mines on demand", out->mine_on_demand == 1);
}

static int pin_height(const struct consensus_params *c, int height,
                      const char *label)
{
    struct research_spacing_view out;
    int64_t expect = expect_spacing(c, height);

    if (read_one(height, &out))
        return 1;
    printf("%s=%lld\n", label, (long long)out.spacing);
    if (spacing_check(label, out.spacing == expect))
        return 1;
    if (spacing_check("pre spacing published",
                      expect == PRE_BUTTERCUP_POW_TARGET_SPACING && expect == 150))
        return 1;
    return pin_bounds(&out);
}

static int main_min_off(const struct chain_params *main, int height, int iron_min)
{
    int enabled = 0;
    int allow = 0;
    int after = main->consensus.nPowAllowMinDifficultyBlocksAfterHeight;

    if (main->consensus.nPowAllowMinDifficultyEnabled)
        enabled = 1;
    if (enabled && height >= after)
        allow = 1;
    printf("main_min_difficulty=%d\n", allow);
    if (spacing_check("main minimum difficulty flag off", enabled == 0))
        return 1;
    if (spacing_check("main minimum difficulty height disabled", after == -1))
        return 1;
    return spacing_check("main minimum difficulty stays off",
                         allow == 0 && allow != iron_min);
}

static int main_differs(const struct chain_params *main, int height,
                        const struct research_spacing_view *iron)
{
    int64_t spacing = consensus_pow_target_spacing(&main->consensus, height);
    int up = (int)main->consensus.nPowMaxAdjustUp;
    int down = (int)main->consensus.nPowMaxAdjustDown;
    int demand = 0;

    if (main->fMineBlocksOnDemand)
        demand = 1;
    printf("main_spacing_at_buttercup=%lld\n", (long long)spacing);
    printf("main_adjust_up=%d\n", up);
    printf("main_adjust_down=%d\n", down);
    if (spacing_check("main spacing is post buttercup",
                      spacing == POST_BUTTERCUP_POW_TARGET_SPACING &&
                      spacing == 75 && spacing != iron->spacing))
        return 1;
    if (spacing_check("main adjust up differs", up == 16 && up != iron->adjust_up))
        return 1;
    if (spacing_check("main adjust down differs",
                      down == 32 && down != iron->adjust_down))
        return 1;
    if (main_min_off(main, height, iron->min_difficulty))
        return 1;
    return spacing_check("main does not mine on demand",
                         demand == 0 && demand != iron->mine_on_demand);
}

int test_research_spacing(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_spacing_view out;
    int buttercup;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (spacing_check("lookup starts unselected",
                      main && d && d->chain && !current))
        return 1;
    buttercup = main->consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;
    if (spacing_check("main buttercup height", buttercup == 707000))
        return 1;
    if (spacing_check("rehearsal buttercup stays disabled",
                      d->chain->consensus.vUpgrades[UPGRADE_BUTTERCUP]
                          .nActivationHeight == NETWORK_UPGRADE_NO_ACTIVATION))
        return 1;
    if (refuse_missing() || refuse_negative())
        return 1;
    if (pin_height(&d->chain->consensus, 0, "spacing_height0"))
        return 1;
    if (pin_height(&d->chain->consensus, buttercup, "spacing_after_main_buttercup"))
        return 1;
    if (read_one(buttercup, &out) || main_differs(main, buttercup, &out))
        return 1;
    if (spacing_check("read does not select",
                      chain_params_get() == main &&
                      !chain_research_profile_current()))
        return 1;
    printf("research_spacing: ironwood rehearsal block spacing pinned\n");
    return 0;
}
