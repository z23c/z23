/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis merkle root. */

#include "services/research_merkle.h"

#include "chain/chainparams.h"
#include "primitives/block.h"

#include <string.h>

enum { MERKLE_OFF = 36, MERKLE_LEN = 32 };

_Static_assert(4 + 32 == MERKLE_OFF, "merkle follows version and parent");
_Static_assert(MERKLE_OFF + MERKLE_LEN + 32 + 4 + 4 + 32 == BLOCK_HEADER_SIZE,
               "merkle sits inside the fixed header");

struct zcl_result research_merkle_read(unsigned char *raw, size_t raw_cap)
{
    const struct chain_research_descriptor *d;

    if (!raw)
        return ZCL_ERR(-1, "Missing merkle");
    if (raw_cap < MERKLE_LEN)
        return ZCL_ERR(-2, "Merkle cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->genesis_wire || d->genesis_wire_len < MERKLE_OFF + MERKLE_LEN)
        return ZCL_ERR(-3, "Research merkle missing");
    memcpy(raw, d->genesis_wire + MERKLE_OFF, MERKLE_LEN);
    return ZCL_OK;
}
