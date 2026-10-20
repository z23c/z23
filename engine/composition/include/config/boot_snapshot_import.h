/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Import a downloaded consensus_snapshot.db into the running node.db.
 *
 * The snapshot file is produced by tools/export_snapshot.c and shipped
 * over the P2P file_service as file_index=254. It carries the public
 * consensus tables (utxos, blocks, transactions, ...) plus a tiny
 * _snapshot_meta(key=height, ...) row. It does NOT carry node.db's
 * node_state table, so we derive the snapshot height from
 * _snapshot_meta, look up the block hash at that height in the
 * snapshot's own blocks table, and then write coins_best_block into
 * the running node.db.node_state ourselves.
 *
 * The function is shared between two boot call sites:
 *   - boot.c (pre-restore probe, Wave 11): observes the snapshot before
 *     any chain-tip promotion so downstream CSR promotion and
 *     chain_restore_finalize see the imported anchor as ground truth.
 *   - boot_services.c (legacy late call site, retained as a safety net
 *     for the file-service P2P receive path where the snapshot only
 *     becomes available after services have started).
 *
 * After this returns true:
 *   - main.utxos is populated from the snapshot.
 *   - node_state["coins_best_block"] holds the snapshot tip hash.
 *   - progress.kv coins_kv is reseeded from main.utxos.
 *   - coins_applied_height, utxo_sha3, and trusted stage cursors are clamped
 *     to the snapshot height through the shared reindex epilogue.
 *
 * Pre-commit failure rolls back the mirror and pending record together.
 * A co-committed snapshot_import_pending.v1 record binds post-commit recovery
 * to the exact mirror commitment and authority generation, independently of
 * the source file. Boot resumes that operation before ordinary restoration;
 * conflicting or advanced state stops boot with preservation guidance.
 */

#ifndef ZCL_BOOT_SNAPSHOT_IMPORT_H
#define ZCL_BOOT_SNAPSHOT_IMPORT_H

#include <stdbool.h>
#include <stdint.h>
#include "base/result.h"

struct node_db;

enum boot_snapshot_first_outcome {
    BOOT_SNAPSHOT_FIRST_DEFERRED,
    BOOT_SNAPSHOT_FIRST_NO_SOURCE,
    BOOT_SNAPSHOT_FIRST_INSTALLED_PRESERVED,
    BOOT_SNAPSHOT_FIRST_STATE_PRESERVED,
    BOOT_SNAPSHOT_FIRST_IMPORTED,
    BOOT_SNAPSHOT_FIRST_IMPORT_FAILED,
};

/* These import/preparation entry points are boot-only: callers must keep
 * reducer, replay and other coin writers quiescent until they return.
 * Recovery serializes shared progress-store SQL with its recursive mutex;
 * that mutex does not replace the boot ordering requirement for node.db.
 *
 * Shared boot ordering before coins-view restoration. A closed progress store
 * defers successfully; committed-install recovery refusals stop boot. Snapshot
 * absence and import failures retain the existing nonfatal IBD fallback. */
struct zcl_result boot_prepare_snapshot_first(struct node_db *ndb,
    const char *datadir, enum boot_snapshot_first_outcome *outcome);

bool boot_import_snapshot_db(struct node_db *ndb,
                              const char *snapshot_path,
                              int64_t *out_utxo_count,
                              int64_t *out_snap_height,
                              uint8_t out_best_hash[32]);

/* True also on malformed/unreadable pending evidence: callers must stop boot
 * rather than continue IBD over a committed, incomplete snapshot import. */
bool boot_snapshot_import_pending_or_error(struct node_db *ndb);

#endif
