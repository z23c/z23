/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * utxo_snapshot_inmem — in-memory implementation of utxo_snapshot_port.
 *
 * Single-writer, multi-reader. The mutator owns the writer role; any
 * reader (native command, RPC, or explorer) calls lookup() concurrently.
 *
 * This adapter is the reference implementation: simple, exhaustively
 * tested, no persistence. It is used by:
 *   - tests that need a real port behind validate_block / chain_advance
 *   - the shadow path during Epoch I (UTXO set is rebuilt in memory
 *     each restart from the block_log_port replay)
 *
 * A future persistent adapter (LMDB or similar) can be swapped under
 * the same port interface without touching the use cases.
 *
 * Concurrency: a single mutex protects the set + the undo log. Reads
 * acquire briefly; the mutator writes under the same lock. The
 * snapshot is internally consistent because all changes happen via
 * apply_diff/revert_tip, which are themselves serialized.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_UTXO_SNAPSHOT_INMEM_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_UTXO_SNAPSHOT_INMEM_H

#include "ports/utxo_snapshot_port.h"

struct utxo_snapshot_inmem;

/* Create an empty in-memory snapshot. tip_height() returns
 * UINT32_MAX until the first apply_diff. */
struct zcl_result utxo_snapshot_inmem_open(
        struct utxo_snapshot_inmem **out_handle,
        struct utxo_snapshot_port *out_port);

void utxo_snapshot_inmem_close(struct utxo_snapshot_inmem *h);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_UTXO_SNAPSHOT_INMEM_H */
