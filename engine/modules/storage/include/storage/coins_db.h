/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_STORAGE_COINS_DB_H
#define ZCL_STORAGE_COINS_DB_H

#include "coins/coins_view.h"
#include "storage/dbwrapper.h"
#include <stdbool.h>

#define DEFAULT_DB_CACHE 450
#define MAX_DB_CACHE 16384
#define MIN_DB_CACHE 4

struct coins_view_db {
    struct db_wrapper db;
    struct coins_view view;
};

bool coins_view_db_open(struct coins_view_db *cvdb, const char *path,
                        size_t cache_size, bool memory, bool wipe);
void coins_view_db_close(struct coins_view_db *cvdb);

bool coins_view_db_get_coins(struct coins_view_db *cvdb,
                             const struct uint256 *txid,
                             struct coins *out);
bool coins_view_db_have_coins(struct coins_view_db *cvdb,
                              const struct uint256 *txid);
bool coins_view_db_get_best_block(struct coins_view_db *cvdb,
                                  struct uint256 *hash);
bool coins_view_db_batch_write(struct coins_view_db *cvdb,
                               struct coins_map *map_coins,
                               const struct uint256 *hash_block);

#endif
