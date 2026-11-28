/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood rehearsal coin identity. */

#include "services/research_coin.h"

#include "chain/chainparams.h"

#include <string.h>

static void copy_units(char *dst, const char *src)
{
    int i;

    for (i = 0; i < 7; i++) {
        dst[i] = src[i];
        if (src[i] == '\0')
            return;
    }
    dst[7] = '\0';
}

struct zcl_result research_coin_read(struct research_coin_view *out)
{
    const struct chain_research_descriptor *d;
    struct research_coin_view got;

    if (!out)
        return ZCL_ERR(-1, "Missing coin");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-2, "Research coin missing");
    memset(&got, 0, sizeof got);
    copy_units(got.units, d->chain->strCurrencyUnits);
    got.bip44 = d->chain->bip44CoinType;
    *out = got;
    return ZCL_OK;
}
