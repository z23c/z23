/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis block hash. */

#include "services/research_blockhash.h"

#include "chain/chainparams.h"
#include "core/hash.h"
#include "primitives/block.h"

#include <string.h>

enum { HASH_LEN = 32, ONE_BYTE_COMPACT = 253 };

_Static_assert(BLOCK_HEADER_SIZE == 140, "solution follows the fixed header");
_Static_assert(HASH_LEN == SHA256_OUTPUT_SIZE, "block hash is one SHA-256");

struct zcl_result research_blockhash_read(unsigned char *raw, size_t raw_cap)
{
    const struct chain_research_descriptor *d;
    unsigned int n;
    size_t prefix;
    unsigned char hash[HASH_LEN];

    if (!raw)
        return ZCL_ERR(-1, "Missing blockhash");
    if (raw_cap < HASH_LEN)
        return ZCL_ERR(-2, "Blockhash cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->genesis_wire || d->genesis_wire_len <= BLOCK_HEADER_SIZE)
        return ZCL_ERR(-3, "Research blockhash missing");
    n = d->genesis_wire[BLOCK_HEADER_SIZE];
    if (n >= ONE_BYTE_COMPACT)
        return ZCL_ERR(-4, "Solution length refused");
    prefix = (size_t)BLOCK_HEADER_SIZE + 1u + n;
    if (prefix > d->genesis_wire_len)
        return ZCL_ERR(-3, "Research blockhash missing");
    hash256((const unsigned char *)d->genesis_wire, prefix, hash);
    memcpy(raw, hash, HASH_LEN);
    return ZCL_OK;
}
