/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood transport identity. */

#include "services/research_transport.h"

#include "chain/chainparams.h"

#include <string.h>

struct zcl_result research_transport_read(unsigned char *magic, size_t magic_cap,
                                         int *rpc_port, char *datadir,
                                         size_t datadir_cap)
{
    const struct chain_research_descriptor *d;
    const char *name;
    size_t name_len;

    if (!magic || !rpc_port || !datadir)
        return ZCL_ERR(-1, "Missing transport");
    if (magic_cap < MESSAGE_START_SIZE)
        return ZCL_ERR(-2, "Magic cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain || !d->base || !d->base->strDataDir)
        return ZCL_ERR(-3, "Research transport missing");
    name = d->base->strDataDir;
    name_len = strlen(name);
    if (datadir_cap <= name_len)
        return ZCL_ERR(-4, "Datadir cap refused");
    memcpy(magic, d->chain->pchMessageStart, MESSAGE_START_SIZE);
    *rpc_port = d->base->nRPCPort;
    memcpy(datadir, name, name_len + 1);
    return ZCL_OK;
}
