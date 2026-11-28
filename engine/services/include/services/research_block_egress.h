/* purpose: Serialize checked blocks for the selected research network. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Checked, bounded block serialization for the isolated research network. */
#ifndef ZCL_RESEARCH_BLOCK_EGRESS_H
#define ZCL_RESEARCH_BLOCK_EGRESS_H

#include "domain/consensus/check_block.h"
#include "services/research_block_size.h"

/* Call only on a freshly disk-decoded block on the selected research network:
 * legacy cached txids must still describe their decoded transactions. Pass an
 * empty output stream. On success it owns the buffer; failure leaves it unchanged. */
static inline bool research_block_egress(const struct chain_params *params,
                                         const struct block *block,
                                         struct byte_stream *out)
{
    const struct chain_research_descriptor *profile =
        chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!profile || chain_research_profile_current() != profile ||
        params != profile->chain || !block || !out ||
        block->header.nSolutionSize > MAX_SOLUTION_SIZE ||
        block->num_vtx > MAX_BLOCK_TRANSACTIONS ||
        (block->num_vtx && !block->vtx))
        return false;
    unsigned char *bytes = zcl_malloc(MAX_BLOCK_SIZE, "research block egress");
    if (!bytes)
        return false;
    struct byte_stream staged = {
        .data = bytes, .size = 0, .capacity = MAX_BLOCK_SIZE,
        .read_pos = 0, .error = false, .owns_data = false
    };
    bool ok = research_block_write_for_size(block, &staged) && !staged.error &&
        domain_consensus_check_block_merkle_root(block, NULL, 0, NULL).ok;
    if (!ok) {
        free(bytes);
        return false;
    }
    staged.owns_data = true;
    *out = staged;
    return true;
}
#endif
