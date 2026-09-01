/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Resolve a hash-bound body owner for reducer stages. */

#include "jobs/stage_body_index.h"

#include "chain/chain.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

struct block_index *stage_body_index_at(struct main_state *ms, int height)
{
    if (!ms || height < 0)
        return NULL;

    struct block_index *canonical =
        active_chain_at(&ms->chain_active, height);
    if (!canonical && ms->pindex_best_header &&
        height <= ms->pindex_best_header->nHeight)
        canonical = block_index_get_ancestor(ms->pindex_best_header, height);
    if (!canonical || !canonical->phashBlock)
        return NULL;
    if (block_index_status_load(canonical) & BLOCK_HAVE_DATA)
        return canonical;

    struct block_index *body =
        block_map_find(&ms->map_block_index, canonical->phashBlock);
    if (!body || body->nHeight != height ||
        !(block_index_status_load(body) & BLOCK_HAVE_DATA) ||
        (block_index_status_load(body) & BLOCK_FAILED_MASK))
        return canonical;
    return body;
}
