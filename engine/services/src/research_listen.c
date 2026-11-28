/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood listen port, seed count, and payment namespace. */

#include "services/research_listen.h"

#include "chain/chainparams.h"

#include <string.h>

struct zcl_result research_listen_read(int *listen_port, size_t *seed_count,
                                       char *payment_hrp, size_t payment_hrp_cap)
{
    const struct chain_research_descriptor *d;
    const char *hrp;
    size_t n;
    if (!listen_port || !seed_count || !payment_hrp)
        return ZCL_ERR(-1, "Missing listen identity");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain || !d->base)
        return ZCL_ERR(-2, "Research listen identity missing");
    hrp = d->chain->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS];
    n = strlen(hrp);
    if (n == 0 || n + 1 > payment_hrp_cap)
        return ZCL_ERR(-3, "Payment namespace refused");
    *seed_count = d->chain->nSeeds + d->chain->nFixedSeeds + d->chain->nOnionSeeds;
    *listen_port = d->chain->nDefaultPort;
    memcpy(payment_hrp, hrp, n + 1);
    return ZCL_OK;
}
