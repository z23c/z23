/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure refresh policy for the block-piece manifest served to sync peers. */

#include "net/fast_sync.h"
#include "validation/chainstate.h"

bool block_piece_manifest_should_refresh(
                                 const struct active_chain *chain,
                                 bool has_cached,
                                 const struct block_piece_manifest *cached,
                                 int32_t built_at_height,
                                 int32_t tip_height,
                                 int32_t refresh_interval)
{
    if (!has_cached || !cached || !chain)
        return true;
    if (cached->start_height < 1 || cached->end_height < cached->start_height)
        return true;
    if (refresh_interval <= 0 ||
        (int64_t)tip_height - (int64_t)built_at_height >= refresh_interval)
        return true;
    if (cached->start_height == 1)
        return false;

    const struct block_index *predecessor =
        active_chain_at(chain, cached->start_height - 1);
    return predecessor && predecessor->phashBlock &&
           (predecessor->nStatus & BLOCK_HAVE_DATA) != 0;
}
