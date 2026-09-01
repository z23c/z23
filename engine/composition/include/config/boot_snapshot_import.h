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
 * On pre-commit failure: the UTXO write is rolled back atomically and the
 * prior coins_best_block (if any) is restored. On post-commit authority
 * epilogue failure the function returns false after paging/logging; boot must
 * not treat the snapshot as a complete fast rebuild.
 */

#ifndef ZCL_BOOT_SNAPSHOT_IMPORT_H
#define ZCL_BOOT_SNAPSHOT_IMPORT_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;

bool boot_import_snapshot_db(struct node_db *ndb,
                              const char *snapshot_path,
                              int64_t *out_utxo_count,
                              int64_t *out_snap_height,
                              uint8_t out_best_hash[32]);

#endif
