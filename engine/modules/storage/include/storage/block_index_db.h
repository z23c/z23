/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_STORAGE_BLOCK_INDEX_DB_H
#define ZCL_STORAGE_BLOCK_INDEX_DB_H

#include "chain/chain.h"
#include "core/serialize.h"
#include "storage/txdb.h"
#include "validation/chainstate.h"
#include <stdbool.h>
#include <stdint.h>

struct disk_block_index {
    struct uint256 hashPrev;
    int nHeight;
    unsigned int nStatus;
    unsigned int nTx;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    int64_t nCachedBranchId;

    struct uint256 hashSproutAnchor;
    int32_t nVersion;
    struct uint256 hashMerkleRoot;
    struct uint256 hashFinalSaplingRoot;
    uint32_t nTime;
    uint32_t nBits;
    struct uint256 nNonce;
    unsigned char nSolution[MAX_SOLUTION_SIZE];
    size_t nSolutionSize;

    int64_t nSproutValue;
    bool has_sprout_value;
    int64_t nSaplingValue;
};

static inline void disk_block_index_init(struct disk_block_index *d)
{
    memset(d, 0, sizeof(*d));
    d->nCachedBranchId = OPTIONAL_NONE;
    d->nFile = -1;
}

bool disk_block_index_serialize(const struct disk_block_index *d,
                                struct byte_stream *s);
bool disk_block_index_deserialize(struct disk_block_index *d,
                                  struct byte_stream *s);
void disk_block_index_get_hash(const struct disk_block_index *d,
                               struct uint256 *out);

bool block_tree_db_write_block_index(struct block_tree_db *btdb,
                                     const struct disk_block_index *d);

/* Same as block_tree_db_write_block_index, but issues the underlying
 * LevelDB write with WriteOptions{.sync=true} so the write is durable
 * before this call returns.
 *
 * Used by the tip-advance path so kill -9 cannot leave the LevelDB
 * block_index lagging coins.db / node.db. Per-block fsync costs
 * ~1-2 ms on a warm disk; only call this from the tip-advance path,
 * not from snapshot/legacy-import bulk loaders. */
bool block_tree_db_write_block_index_sync(struct block_tree_db *btdb,
                                          const struct disk_block_index *d);

bool block_tree_db_read_block_index(struct block_tree_db *btdb,
                                    const struct uint256 *hash,
                                    struct disk_block_index *out);

typedef struct block_index *(*insert_block_index_fn)(void *ctx,
                                                      const struct uint256 *hash);

bool block_tree_db_load_block_index_guts(struct block_tree_db *btdb,
                                         insert_block_index_fn insert_fn,
                                         void *ctx);

#endif
