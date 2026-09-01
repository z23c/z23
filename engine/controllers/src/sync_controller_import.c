/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* sync_controller_import: thin wrapper over the UTXO import Service.
 *
 * The parallel LevelDB → SQLite UTXO import orchestration (turbo scope,
 * recovery_policy wipe gate, decoder/writer thread pipeline + chunk
 * ring-buffer, LevelDB reader loop, validation loop, cleanup) lives in
 * engine/services/src/node_db_import_service.c, which speaks struct zcl_result
 * (Law 2). This controller is dumb glue: it keeps the node_db_sync_import_utxos()
 * name + `int rows-or--1` contract so its callers do not change, and adapts the
 * Service's result back to that int — on success it returns the imported-row
 * count, on failure -1 (the reason was already logged + travels in the
 * result). */

#include "controllers/sync_controller.h"
#include "services/node_db_import_service.h"

struct node_db;
struct coins_view_db;

int node_db_sync_import_utxos(struct node_db *ndb,
                               struct coins_view_db *cvdb)
{
    int rows = -1;
    struct zcl_result r = node_db_import_service_run(ndb, cvdb, &rows);
    return r.ok ? rows : -1;
}
