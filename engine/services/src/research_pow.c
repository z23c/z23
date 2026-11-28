/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read Ironwood later-upgrade heights and Equihash parameters. */

#include "services/research_pow.h"

#include "chain/chainparams.h"

struct zcl_result research_pow_read(int height, struct research_pow *out)
{
    const struct chain_research_descriptor *d;
    const struct chain_params *chain;
    const struct consensus_params *consensus;

    if (!out)
        return ZCL_ERR(-1, "Missing pow");
    if (height < 0)
        return ZCL_ERR(-2, "Pow height refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-3, "Research pow missing");
    chain = d->chain;
    consensus = &chain->consensus;
    out->bubbles_height = consensus->vUpgrades[UPGRADE_BUBBLES].nActivationHeight;
    out->diffadj_height = consensus->vUpgrades[UPGRADE_DIFFADJ].nActivationHeight;
    out->buttercup_height = consensus->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;
    out->equihash_n = chain_params_equihash_n(chain, height);
    out->equihash_k = chain_params_equihash_k(chain, height);
    return ZCL_OK;
}
