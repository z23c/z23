/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal block subsidy. */

#include "services/research_subsidy.h"

#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/amount.h"

#include <stdio.h>
#include <string.h>

static int subsidy_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_subsidy: %s\n", cond);
        return 1;
    }
    return 0;
}

static int64_t full_reward(void)
{
    return ((int64_t)COIN * 25) / 2;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_subsidy_read(1, NULL);

    return subsidy_check("null subsidy refused",
                         !r.ok && strcmp(r.message, "Missing subsidy") == 0);
}

static int refuse_negative(void)
{
    struct research_subsidy_view out;
    struct zcl_result r;

    out.subsidy = -7;
    out.slow_start = -7;
    out.pre_halving = -7;
    out.post_halving = -7;
    out.coinbase_protected = -7;
    r = research_subsidy_read(-1, &out);
    if (subsidy_check("negative height refused",
                      !r.ok && strcmp(r.message, "Subsidy height refused") == 0))
        return 1;
    return subsidy_check("negative height leaves outputs",
                         out.subsidy == -7 && out.slow_start == -7 &&
                         out.pre_halving == -7 && out.post_halving == -7 &&
                         out.coinbase_protected == -7);
}

static int read_one(int height, struct research_subsidy_view *out)
{
    return subsidy_check("subsidy read ok", research_subsidy_read(height, out).ok);
}

static int pin_schedule(const struct research_subsidy_view *out)
{
    if (subsidy_check("slow start published", out->slow_start == 0))
        return 1;
    if (subsidy_check("pre halving matches regtest",
                      out->pre_halving == PRE_BUTTERCUP_REGTEST_HALVING_INTERVAL))
        return 1;
    if (subsidy_check("pre halving published", out->pre_halving == 150))
        return 1;
    if (subsidy_check("post halving matches regtest",
                      out->post_halving == POST_BUTTERCUP_REGTEST_HALVING_INTERVAL))
        return 1;
    if (subsidy_check("post halving published", out->post_halving == 300))
        return 1;
    return subsidy_check("transparent coinbase allowed",
                         out->coinbase_protected == 0);
}

static int pin_amount(int height, int64_t expect, const char *label)
{
    struct research_subsidy_view out;

    if (read_one(height, &out))
        return 1;
    printf("%s=%lld\n", label, (long long)out.subsidy);
    if (subsidy_check(label, out.subsidy == expect))
        return 1;
    return pin_schedule(&out);
}

static int pin_amounts(void)
{
    int64_t full = full_reward();

    if (subsidy_check("full reward published", full == 1250000000LL))
        return 1;
    if (subsidy_check("halved reward published", full / 2 == 625000000LL))
        return 1;
    if (pin_amount(0, full, "subsidy_height0"))
        return 1;
    if (pin_amount(1, full, "subsidy_height1"))
        return 1;
    if (pin_amount(PRE_BUTTERCUP_REGTEST_HALVING_INTERVAL - 1, full,
                   "subsidy_before_halving"))
        return 1;
    return pin_amount(PRE_BUTTERCUP_REGTEST_HALVING_INTERVAL, full / 2,
                      "subsidy_at_halving");
}

static int buttercup_disabled(const struct chain_research_descriptor *d)
{
    int height = d->chain->consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;

    return subsidy_check("buttercup stays disabled",
                         height == NETWORK_UPGRADE_NO_ACTIVATION);
}

static int main_differs(const struct chain_params *main,
                        const struct research_subsidy_view *out)
{
    int slow = main->consensus.nSubsidySlowStartInterval;
    int pre = main->consensus.nPreButtercupSubsidyHalvingInterval;
    int protected_flag = 0;

    if (main->consensus.fCoinbaseMustBeProtected)
        protected_flag = 1;
    printf("main_slow_start=%d\n", slow);
    printf("main_pre_halving=%d\n", pre);
    printf("main_coinbase_protected=%d\n", protected_flag);
    if (subsidy_check("main slow start differs", slow == 2 && slow != out->slow_start))
        return 1;
    if (subsidy_check("main halving differs",
                      pre == PRE_BUTTERCUP_HALVING_INTERVAL && pre != out->pre_halving))
        return 1;
    return subsidy_check("main protection differs",
                         protected_flag == 1 && protected_flag != out->coinbase_protected);
}

int test_research_subsidy(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_subsidy_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (subsidy_check("lookup starts unselected",
                      main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || refuse_negative() || buttercup_disabled(d) || pin_amounts())
        return 1;
    if (read_one(0, &out) || main_differs(main, &out))
        return 1;
    if (subsidy_check("read does not select",
                      chain_params_get() == main &&
                      !chain_research_profile_current()))
        return 1;
    printf("research_subsidy: ironwood rehearsal subsidy pinned\n");
    return 0;
}
