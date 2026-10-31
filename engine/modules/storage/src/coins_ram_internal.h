/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_ram private cross-TU contract: the declarations that coins_ram.c
 * exports to coins_ram_boot_reconcile.c. Not part of storage/coins_ram.h.
 */
#ifndef ZCL_STORAGE_COINS_RAM_INTERNAL_H
#define ZCL_STORAGE_COINS_RAM_INTERNAL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Delete replay-domain rows at or above want_cursor (defined in coins_ram.c). */
bool coins_ram_purge_replay_tail(sqlite3 *db, int64_t want_cursor);

#endif /* ZCL_STORAGE_COINS_RAM_INTERNAL_H */
