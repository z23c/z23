/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis solution length. */

#include "services/research_solution.h"

#include "chain/chainparams.h"
#include "primitives/block.h"

#include <stddef.h>

enum { ONE_BYTE_COMPACT = 253 };

_Static_assert(BLOCK_HEADER_SIZE == 140, "solution follows the fixed header");

struct zcl_result research_solution_read(unsigned int *solution_len,
                                        unsigned int *tx_count)
{
    const struct chain_research_descriptor *d;
    unsigned int n;
    unsigned int txs;
    size_t tx_off;

    if (!solution_len || !tx_count)
        return ZCL_ERR(-1, "Missing solution");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->genesis_wire || d->genesis_wire_len <= BLOCK_HEADER_SIZE)
        return ZCL_ERR(-2, "Research solution missing");
    n = d->genesis_wire[BLOCK_HEADER_SIZE];
    if (n >= ONE_BYTE_COMPACT)
        return ZCL_ERR(-3, "Solution length refused");
    tx_off = (size_t)BLOCK_HEADER_SIZE + 1u + n;
    if (d->genesis_wire_len <= tx_off)
        return ZCL_ERR(-2, "Research solution missing");
    txs = d->genesis_wire[tx_off];
    if (txs >= ONE_BYTE_COMPACT)
        return ZCL_ERR(-4, "Transaction count refused");
    *solution_len = n;
    *tx_count = txs;
    return ZCL_OK;
}
