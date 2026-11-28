/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Derive the Ironwood message start. */

#include "services/research_magic.h"

#include "chain/chainparams.h"
#include "sha3/sha3.h"

#include <string.h>

static const char magic_label[] = "Z23/Ironwood/testnet/transport/v1";

_Static_assert(MESSAGE_START_SIZE == 4, "message start is four bytes");

struct zcl_result research_magic_read(unsigned char *magic, size_t magic_cap)
{
    const struct chain_research_descriptor *d;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];

    if (!magic)
        return ZCL_ERR(-1, "Missing magic");
    if (magic_cap < MESSAGE_START_SIZE)
        return ZCL_ERR(-2, "Magic cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain)
        return ZCL_ERR(-3, "Research magic missing");
    sha3_256((const unsigned char *)magic_label, sizeof magic_label - 1,
             digest);
    memcpy(magic, digest, MESSAGE_START_SIZE);
    return ZCL_OK;
}
