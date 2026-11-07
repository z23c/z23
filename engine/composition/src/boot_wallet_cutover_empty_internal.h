/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Checked shielded-empty proof for wallet cutover startup and publication. */
#ifndef ZCL_BOOT_WALLET_CUTOVER_EMPTY_INTERNAL_H
#define ZCL_BOOT_WALLET_CUTOVER_EMPTY_INTERNAL_H
#include <stdbool.h>
#include <sqlite3.h>
struct wallet;
struct wallet_sqlite;
/* Caller holds the connection mutex and wallet's sapling_keys.cs. The load
 * result must belong to this wallet's actual startup read. This read-only
 * check joins any existing transaction and never starts or commits one. */
bool boot_wallet_cutover_shielded_empty_locked(struct wallet_sqlite *ws,
    sqlite3 *db, const struct wallet *wallet, bool sapling_load_ok);
#endif
