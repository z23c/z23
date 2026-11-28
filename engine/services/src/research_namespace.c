/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood address namespace without selecting a chain. */

#include "services/research_namespace.h"

#include "chain/chainparams.h"

#include <string.h>

_Static_assert(RESEARCH_NAMESPACE_HRP_CAP == MAX_BECH32_HRP_LEN,
               "namespace cap matches the chain HRP cap");
_Static_assert(RESEARCH_NAMESPACE_HRP_COUNT == BECH32_MAX_TYPES,
               "namespace covers every bech32 HRP");
_Static_assert(RESEARCH_NAMESPACE_PREFIX_LEN == MAX_BASE58_PREFIX_LEN,
               "namespace prefix matches the chain prefix width");

struct zcl_result research_namespace_read(struct research_namespace *out,
                                          size_t hrp_cap)
{
    const struct chain_research_descriptor *d;
    const struct chain_params *chain;
    const unsigned char *prefix;
    size_t prefix_len;
    size_t i;

    if (!out)
        return ZCL_ERR(-1, "Missing namespace");
    if (hrp_cap == 0 || hrp_cap > RESEARCH_NAMESPACE_HRP_CAP)
        return ZCL_ERR(-2, "Namespace cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-3, "Research namespace missing");
    chain = d->chain;
    for (i = 0; i < RESEARCH_NAMESPACE_HRP_COUNT; i++) {
        size_t n = strlen(chain->bech32HRPs[i]);
        if (n == 0 || n + 1 > hrp_cap)
            return ZCL_ERR(-4, "Namespace refused");
    }
    prefix = chain->base58Prefixes[B58_PUBKEY_ADDRESS];
    prefix_len = chain->base58PrefixLengths[B58_PUBKEY_ADDRESS];
    if (prefix_len != RESEARCH_NAMESPACE_PREFIX_LEN)
        return ZCL_ERR(-5, "Pubkey prefix refused");
    for (i = 0; i < RESEARCH_NAMESPACE_HRP_COUNT; i++) {
        size_t n = strlen(chain->bech32HRPs[i]);
        memcpy(out->hrp[i], chain->bech32HRPs[i], n + 1);
    }
    memcpy(out->pubkey_prefix, prefix, prefix_len);
    return ZCL_OK;
}
