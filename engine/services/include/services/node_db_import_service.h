/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* node_db_import_service: parallel LevelDB → SQLite UTXO import.
 *
 * Reader thread feeds a ring buffer; N decoder threads deserialize
 * coins-format entries; a single writer thread bulk-inserts into the
 * utxos table.
 *
 * This Service owns the import orchestration (turbo scope, recovery_policy
 * wipe gate, DB_TXN_SCOPE, decoder/writer thread pipeline + chunk
 * ring-buffer, LevelDB reader loop, validation loop, cleanup). It is
 * consensus-adjacent (§3 coins-wedge recovery surface): the import writes
 * the UTXO set, so its behavior is byte-identical to the controller body
 * it was relocated from.
 *
 * The Service speaks struct zcl_result (Law 2). The legacy `int rows-or--1`
 * contract its callers expect is preserved by the thin wrapper
 * node_db_sync_import_utxos() in
 * engine/controllers/src/sync_controller_import.c, which maps the result back. */

#ifndef ZCL_SERVICES_NODE_DB_IMPORT_SERVICE_H
#define ZCL_SERVICES_NODE_DB_IMPORT_SERVICE_H

#include "util/result.h"

struct node_db;
struct coins_view_db;

/* Import the full UTXO set from chainstate LevelDB into SQLite.
 * Iterates all 'c'-prefixed entries, decodes compressed outputs,
 * and bulk-inserts into the utxos table with address indexing.
 *
 * Returns struct zcl_result (Law 2: the failure reason travels with the
 * failure). On success (.ok) the number of UTXO outputs imported is written
 * to *out_rows (may be 0 for an empty set); out_rows may be NULL if the
 * caller does not need the count. */
struct zcl_result node_db_import_service_run(struct node_db *ndb,
                                             struct coins_view_db *cvdb,
                                             int *out_rows);

#endif /* ZCL_SERVICES_NODE_DB_IMPORT_SERVICE_H */
