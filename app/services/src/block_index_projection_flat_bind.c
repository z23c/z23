/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Semantic coverage proof for binding a complete flat block-index snapshot
 * to the event-derived projection's dirty journal. */

#include "services/block_index_loader.h"

#include "chain/chain.h"
#include "storage/block_index_projection.h"
#include "validation/main_state.h"

#include <string.h>

/* Shutdown has already drained block-index writers. The projection mutex
 * stabilizes its rows while this callback point-reads the quiescent map that
 * was just serialized into the SHA3-bound flat snapshot. */
static bool flat_state_covers_projection_row(
    const uint8_t hash[32], const struct disk_block_index *row, void *user)
{
    struct main_state *state = user;
    struct uint256 key;
    memcpy(key.data, hash, sizeof(key.data));
    struct block_index *flat = block_map_find(&state->map_block_index, &key);
    if (!flat || flat->nHeight != row->nHeight)
        return false;

    if ((row->nStatus & BLOCK_HAVE_DATA) &&
        (!(flat->nStatus & BLOCK_HAVE_DATA) || flat->nFile < 0))
        return false;
    if (flat->nTx == 0 && row->nTx > 0)
        return false;
    return (flat->nStatus & BLOCK_VALID_MASK) >=
           (row->nStatus & BLOCK_VALID_MASK);
}

bool block_index_projection_bind_saved_flat_state(
    struct block_index_projection *bip,
    const struct block_index_flat_identity *identity,
    struct main_state *state)
{
    return bip && identity && state &&
        block_index_projection_bind_flat_if_covered(
            bip, identity->payload_sha3, identity->payload_size,
            identity->row_count, flat_state_covers_projection_row, state);
}
