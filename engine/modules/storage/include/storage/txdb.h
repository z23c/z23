/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_STORAGE_TXDB_H
#define ZCL_STORAGE_TXDB_H

#include "storage/dbwrapper.h"
#include "validation/chainstate.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_DB_CACHE_MB 450
#define MAX_DB_CACHE_MB 16384
#define MIN_DB_CACHE_MB 4

struct block_tree_db {
    struct db_wrapper db;
};

bool block_tree_db_open(struct block_tree_db *btdb, const char *path,
                        size_t cache_size, bool memory, bool wipe);
void block_tree_db_close(struct block_tree_db *btdb);

bool block_tree_db_write_reindexing(struct block_tree_db *btdb, bool reindexing);
bool block_tree_db_read_reindexing(struct block_tree_db *btdb, bool *reindexing);

bool block_tree_db_read_tx_index(struct block_tree_db *btdb,
                                  const struct uint256 *txid,
                                  struct disk_tx_pos *pos);

bool block_tree_db_write_tx_index(struct block_tree_db *btdb,
                                   const struct uint256 *txids,
                                   const struct disk_tx_pos *positions,
                                   size_t count);

bool block_tree_db_write_flag(struct block_tree_db *btdb,
                               const char *name, bool value);
bool block_tree_db_read_flag(struct block_tree_db *btdb,
                              const char *name, bool *value);

#endif
