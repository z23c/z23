/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Import wallet data from a legacy (C++) ZClassic node's block files.
 *
 * This Controller is a thin entry point. The orchestration core — the
 * multi-pass mmap block-file scan, the Sapling trial-decryption walk, and the
 * multi-threaded import driving loop — is Service/Job-grade work and lives in
 * the Service shape (engine/services/src/legacy_import_service.c). The public
 * legacy_import() symbol is preserved here, at its original include path
 * (controllers/legacy_import.h), so every existing caller is unchanged; it
 * now delegates straight into legacy_import_service_run().
 *
 * No LevelDB, no chain index, no RPC. The legacy node should be stopped to
 * avoid partial block reads.
 *
 * RECOVERY-PRIMITIVE NOTE: this path is the live cold-import / legacy-attach
 * recovery primitive. The relocation below is behavior-preserving — the
 * import logic is unchanged, only its housing. */

#include "controllers/legacy_import.h"
#include "services/legacy_import_service.h"

/* --- Main entry point (thin Controller shim) --- */

int legacy_import(const char *legacy_datadir,
                  struct node_db *ndb,
                  struct wallet *w,
                  bool sapling_scan)
{
    return legacy_import_service_run(legacy_datadir, ndb, w, sapling_scan);
}
