/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis header fields. */

#include "services/research_header.h"

#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "primitives/block.h"

#include <string.h>

enum {
    HEADER_PREV = 4,
    HEADER_SAPLING = 68,
    HEADER_TIME = 100,
    HEADER_BITS = 104,
    HEADER_NONCE = 108
};

_Static_assert(HEADER_PREV + 32 + 32 + 32 == HEADER_TIME,
               "time follows version, parent, merkle, and sapling root");
_Static_assert(HEADER_TIME + 4 == HEADER_BITS, "bits follow time");
_Static_assert(HEADER_BITS + 4 == HEADER_NONCE, "nonce follows bits");
_Static_assert(HEADER_NONCE + 32 == BLOCK_HEADER_SIZE,
               "nonce ends the fixed header prefix");

struct zcl_result research_header_read(struct research_header *out)
{
    const struct chain_research_descriptor *d;
    const uint8_t *w;
    struct research_header tmp;

    if (!out)
        return ZCL_ERR(-1, "Missing header");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->genesis_wire || d->genesis_wire_len < BLOCK_HEADER_SIZE)
        return ZCL_ERR(-2, "Research header missing");
    w = d->genesis_wire;
    memset(&tmp, 0, sizeof tmp);
    tmp.version = zcl_read_i32_le(w);
    memcpy(tmp.prev, w + HEADER_PREV, 32);
    memcpy(tmp.sapling_root, w + HEADER_SAPLING, 32);
    tmp.time = zcl_read_u32_le(w + HEADER_TIME);
    tmp.bits = zcl_read_u32_le(w + HEADER_BITS);
    memcpy(tmp.nonce, w + HEADER_NONCE, 32);
    *out = tmp;
    return ZCL_OK;
}
