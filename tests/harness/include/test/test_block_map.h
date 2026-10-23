/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Test fixture insert for the keyless block_map: the map's key IS
 * index->hashBlock, so a fixture that keeps its hashes in a side array must
 * write the key into the node before publishing it (production does the same
 * in every caller).  Behaviour-preserving for tests: the hash argument stays
 * the lookup key, the node merely carries it too.
 */
#ifndef TEST_BLOCK_MAP_H
#define TEST_BLOCK_MAP_H

#include "chain/chain.h"
#include "validation/chainstate.h"

static inline bool test_block_map_insert(struct block_map *m,
                                         const struct uint256 *hash,
                                         struct block_index *index)
{
    if (index && hash && hash != &index->hashBlock)
        index->hashBlock = *hash;
    return block_map_insert(m, hash, index);
}

#endif
