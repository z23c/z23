/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bind a saved flat block-index snapshot only when it semantically
 *          covers every persisted projection row. */
// one-result-type-ok:flat-projection-coverage — the sole bool export is a
// fail-closed semantic predicate over already-persisted shutdown state.
/* Semantic coverage proof for binding a complete flat block-index snapshot
 * to the event-derived projection's dirty journal. */

#include "services/block_index_loader.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "storage/block_index_projection.h"
#include "validation/main_state.h"

#include <string.h>

/* Per-bind context: the quiescent map plus the chain params, resolved once
 * instead of once per row. */
struct flat_cover_ctx {
    struct main_state *state;
    const struct chain_params *cp;
};

/* The strict map match for an admittable row: present at the same height with
 * its data/tx/validity not behind the projection row. */
static bool flat_row_matches(const struct flat_cover_ctx *ctx,
                             const uint8_t hash[32],
                             const struct disk_block_index *row)
{
    struct uint256 key;
    memcpy(key.data, hash, sizeof(key.data));
    struct block_index *flat = block_map_find(&ctx->state->map_block_index, &key);
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

/* Shutdown has already drained block-index writers. The projection mutex
 * stabilizes its rows while this callback point-reads the quiescent map that
 * was just serialized into the SHA3-bound flat snapshot.
 *
 * A row the loaders' admission gate refuses (flat loader snapshot loader via
 * block_index_row_admit, projection top-up via topup_row_admitted) is
 * correctly absent from the flat snapshot and the map, so it is not a
 * coverage gap. Same predicate, no quarantine side effects. The result is
 * "!admissible || match"; both terms are side-effect free (block_map_find is
 * a read-locked lookup, block_index_row_admissible only hashes against the
 * PoW target), so the cheap map match runs first and the PoW check only runs
 * for rows that do not match. */
static bool flat_state_covers_projection_row(
    const uint8_t hash[32], const struct disk_block_index *row, void *user)
{
    const struct flat_cover_ctx *ctx = user;
    if (flat_row_matches(ctx, hash, row))
        return true;
    return !block_index_row_admissible(row->nHeight, hash, row->hashPrev.data,
                                       row->nBits, ctx->cp, NULL);
}

bool block_index_projection_bind_saved_flat_state(
    struct block_index_projection *bip,
    const struct block_index_flat_identity *identity,
    struct main_state *state)
{
    struct flat_cover_ctx ctx = { .state = state, .cp = chain_params_get() };
    return bip && identity && state &&
        block_index_projection_bind_flat_if_covered(
            bip, identity->payload_sha3, identity->payload_size,
            identity->row_count, flat_state_covers_projection_row, &ctx);
}
