/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: shared persisted schema contract for the derived UTXO cursor. */
#ifndef ZCL_STORAGE_UTXO_MIRROR_SCHEMA_H
#define ZCL_STORAGE_UTXO_MIRROR_SCHEMA_H

/* node.db node_state key for the derived utxos projection's NEXT height to
 * apply. Cursor n covers rows at heights strictly below n; it is not the
 * last-applied height. An explicit cursor zero admits no nonnegative rows.
 * The producer persists a native int64_t as an eight-byte BLOB, not a wire
 * endian integer. Offline readers must know the producer byte order and
 * validate type/length/range before decoding. Missing state is not proof of
 * a persisted zero cursor. Cursor equality never proves branch, generation
 * or coherent capture, and this read model is never consensus authority. */
#define UTXO_MIRROR_SYNC_CURSOR_KEY "utxos_mirror_height"

/* Optional 32-byte hash of the block at cursor - 1, committed with the cursor
 * and mirror rows. Missing state means branch identity is unknown, never that
 * two branches match. The hash uses the authority delta's internal byte order. */
#define UTXO_MIRROR_BRANCH_HASH_KEY "utxos_mirror_branch_hash"

#endif
