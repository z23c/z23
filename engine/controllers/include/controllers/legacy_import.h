/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_DB_LEGACY_IMPORT_H
#define ZCL_DB_LEGACY_IMPORT_H

#include "models/database.h"
#include <stdbool.h>

struct wallet;

/* Import wallet data from a legacy (C++) node's data directory.
 * Reads block files directly — no LevelDB, no RPC, no legacy code.
 *
 * legacy_datadir: path to legacy node's data dir (e.g. ~/.zclassic)
 * ndb:            our SQLite database for storing results
 * w:              our wallet with private keys
 * sapling_scan:   also trial-decrypt shielded outputs (slow, ~10min)
 *
 * Returns the number of wallet transactions found, or -1 on error. */
int legacy_import(const char *legacy_datadir,
                  struct node_db *ndb,
                  struct wallet *w,
                  bool sapling_scan);

#endif
