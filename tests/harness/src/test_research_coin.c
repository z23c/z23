/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal coin identity. */

#include "services/research_coin.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int coin_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_coin: %s\n", cond);
        return 1;
    }
    return 0;
}

static const char *expect_units(const struct chain_params *chain)
{
    return chain->strCurrencyUnits;
}

static unsigned expect_bip44(const struct chain_params *chain)
{
    return chain->bip44CoinType;
}

static int refuse_missing(void)
{
    struct zcl_result r = research_coin_read(NULL);

    return coin_check("null coin refused",
                      !r.ok && strcmp(r.message, "Missing coin") == 0);
}

static int read_one(struct research_coin_view *out)
{
    return coin_check("coin read ok", research_coin_read(out).ok);
}

static int pin_rehearsal(const struct chain_params *chain,
                         const struct research_coin_view *out)
{
    const char *units = expect_units(chain);
    unsigned bip44 = expect_bip44(chain);

    printf("coin_units=%s\n", out->units);
    printf("coin_bip44=%u\n", (unsigned)out->bip44);
    if (coin_check("units match descriptor", strcmp(out->units, units) == 0))
        return 1;
    if (coin_check("bip44 matches descriptor", out->bip44 == bip44))
        return 1;
    if (coin_check("rehearsal unit is REG", strcmp(out->units, "REG") == 0))
        return 1;
    return coin_check("rehearsal bip44 is 1", out->bip44 == 1);
}

static int main_differs(const struct chain_params *main,
                        const struct research_coin_view *iron)
{
    const char *units = expect_units(main);
    unsigned bip44 = expect_bip44(main);

    printf("main_coin_units=%s\n", units);
    printf("main_coin_bip44=%u\n", bip44);
    if (coin_check("main unit is ZCL",
                   strcmp(units, "ZCL") == 0 && strcmp(units, iron->units) != 0))
        return 1;
    return coin_check("main bip44 is 147",
                      bip44 == 147 && bip44 != iron->bip44);
}

int test_research_coin(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;
    struct research_coin_view out;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (coin_check("lookup starts unselected",
                   main && d && d->chain && !current))
        return 1;
    if (refuse_missing() || read_one(&out) || pin_rehearsal(d->chain, &out))
        return 1;
    if (main_differs(main, &out))
        return 1;
    if (coin_check("read does not select",
                   chain_params_get() == main &&
                   !chain_research_profile_current()))
        return 1;
    printf("research_coin: ironwood rehearsal coin identity pinned\n");
    return 0;
}
