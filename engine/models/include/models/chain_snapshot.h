/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ChainSnapshot — composes BlockData, BlockIndexStore, and ChainstateStore
 * into a single legacy import operation.
 *
 * Relationships:
 *   ChainSnapshot has_one :block_data
 *   ChainSnapshot has_one :index (leveldb_store)
 *   ChainSnapshot has_one :chainstate (leveldb_store)
 *
 * Pattern:
 *   struct chain_snapshot snap = { .src_dir = legacy, .dst_dir = c23 };
 *   if (chain_snapshot_validate(&snap))
 *       chain_snapshot_save(&snap);
 */

#ifndef ZCL_MODELS_CHAIN_SNAPSHOT_H
#define ZCL_MODELS_CHAIN_SNAPSHOT_H

#include "models/block_data.h"
#include "models/leveldb_store.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct chain_snapshot {
    const char *src_dir;
    const char *dst_dir;

    /* Owned path buffers for child models */
    char blocks_src[512];
    char blocks_dst[512];
    char index_src[512];
    char index_dst[512];
    char cs_src[512];
    char cs_dst[512];

    /* has_one :block_data */
    struct block_data blocks;

    /* has_one :block_index (leveldb_store) */
    struct leveldb_store index;

    /* has_one :chainstate (leveldb_store) */
    struct leveldb_store chainstate;

    /* Aggregate validation */
    bool src_valid;

    /* Legacy compatibility accessors */
    int src_block_files;
    int64_t src_blocks_bytes;
    int64_t src_chainstate_bytes;
    bool src_has_index;
    bool copy_blocks_ok;
    bool copy_index_ok;
    bool copy_chainstate_ok;
    int files_copied;
};

/* Validates all three child models */
bool chain_snapshot_validate(struct chain_snapshot *snap);

/* Saves all three child models */
bool chain_snapshot_save(struct chain_snapshot *snap);

#endif
