/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Consensus snapshot export service.
 *
 * Exports public consensus tables from node.db to consensus_snapshot.db.
 * SECURITY: excludes wallet_keys, wallet_utxos, wallet_sapling_keys,
 * wallet_sapling_notes, node_state, and other private operator tables.
 */

#ifndef ZCL_SERVICES_CONSENSUS_SNAPSHOT_EXPORT_SERVICE_H
#define ZCL_SERVICES_CONSENSUS_SNAPSHOT_EXPORT_SERVICE_H

#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Export with an explicit locally verified chain-state binding. There is
 * deliberately no unbound producer: only the sovereign boot publisher may
 * mint re-serving provenance for these bytes. */
struct zcl_result consensus_snapshot_export_service_run_bound(
    const char *datadir, int32_t state_height,
    const uint8_t state_block_hash[32]);

/* Verify the durable LOCAL-export proof for consensus_snapshot.db.  This
 * re-hashes the artifact on first use, caches only an inode/stat-bound success,
 * and always rechecks the stamped block against the current local node.db.
 * A downloaded file has no stamp and fails closed. */
struct zcl_result consensus_snapshot_export_artifact_check(
    const char *datadir, int32_t current_sovereign_height);

#endif /* ZCL_SERVICES_CONSENSUS_SNAPSHOT_EXPORT_SERVICE_H */
