/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * legacy_import_service — Service-grade orchestration for importing wallet
 * data from a legacy (C++) ZClassic node's raw block files.
 *
 * This is the orchestration core extracted out of the legacy_import
 * Controller (engine/controllers/src/legacy_import.c). The Controller is now a
 * thin shim that validates arguments and delegates to this Service. The work
 * itself is Service/Job-grade: a multi-pass mmap block-file scan plus a
 * Sapling trial-decryption walk that drives a multi-threaded import loop.
 *
 * No LevelDB, no chain index, no RPC. Reads block files directly:
 *   Pass 1: parallel mmap raw byte scan for P2PKH/P2SH wallet patterns
 *   Pass 2: walk matched files, deserialize blocks, extract transparent txns
 *   Pass 3: parallel filter + serial trial decryption for Sapling notes
 *
 * The legacy node should be stopped to avoid partial block reads.
 *
 * This path is a live recovery primitive (cold-import / legacy-attach). Do
 * NOT alter the import logic — the cold-import / legacy-attach byte format is
 * a stable contract. */

#ifndef ZCL_LEGACY_IMPORT_SERVICE_H
#define ZCL_LEGACY_IMPORT_SERVICE_H

#include "models/database.h"
#include <stdbool.h>

struct wallet;

/* Run the legacy block-file import orchestration.
 *
 * legacy_datadir: path to legacy node's data dir (e.g. ~/.zclassic)
 * ndb:            our SQLite database for storing results (must be open)
 * w:              our wallet with private keys
 * sapling_scan:   also trial-decrypt shielded outputs (slow, ~10min)
 *
 * Returns the number of wallet transactions found, or -1 on error.
 *
 * Callers should reach for this through the legacy_import() Controller entry
 * (controllers/legacy_import.h); this header exposes the orchestration entry
 * for the thin Controller shim and any future Service-level driver. */
int legacy_import_service_run(const char *legacy_datadir,
                              struct node_db *ndb,
                              struct wallet *w,
                              bool sapling_scan);

#endif /* ZCL_LEGACY_IMPORT_SERVICE_H */
