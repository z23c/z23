/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_WALLET_DB_H
#define ZCL_WALLET_DB_H

#include "storage/dbwrapper.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "script/script.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

struct wallet_db {
    struct db_wrapper db;
    bool open;
};

bool wallet_db_open(struct wallet_db *wdb, const char *path);
void wallet_db_close(struct wallet_db *wdb);

bool wallet_db_read_keys(struct wallet_db *wdb, struct wallet *w);

bool wallet_db_read_txs(struct wallet_db *wdb, struct wallet *w);

bool wallet_db_read_scan_height(struct wallet_db *wdb, int *height);

bool wallet_db_read_sapling_seed(struct wallet_db *wdb, uint8_t seed[32]);
bool wallet_db_read_sapling_keys(struct wallet_db *wdb, struct wallet *w);

bool wallet_db_read_scripts(struct wallet_db *wdb, struct wallet *w);

#endif
