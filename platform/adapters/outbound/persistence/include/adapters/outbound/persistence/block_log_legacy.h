/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * block_log_legacy — read-only block_log_port adapter backed by a
 * legacy zclassicd / Bitcoin Core data directory.
 *
 * Open path:
 *   1. Open `<datadir>/blocks/index/` via blocks_index_legacy_reader to
 *      build a height-indexed (hash, nFile, nDataPos, nStatus) array.
 *      The legacy LevelDB must be unlocked — typical use is reading a
 *      *snapshot* of zclassicd's data dir while zclassicd is running.
 *   2. Open `<datadir>/blocks/` via blocks_mmap_reader for zero-copy
 *      access to blk*.dat payloads.
 *   3. Build a small hash → height side-map so read_by_hash is O(1).
 *
 * Contract notes:
 *   - append() always returns BLOCK_LOG_ERR_NOT_SUPPORTED. This adapter
 *     is the legacy "primary" the shadow path diffs against; nothing
 *     should ever be writing through it.
 *   - read_at_height / read_by_hash return pointers into the bmr LRU
 *     window — valid until the next port call. Callers that need
 *     persistence must memcpy.
 *   - iter_from walks heights sequentially. The callback receives the
 *     same LRU pointer; it must consume bytes synchronously.
 *   - tip_height returns UINT32_MAX if the height map is empty.
 *
 * Concurrency:
 *   - All methods are NOT thread-safe. Drive it from a single thread
 *     (the use case caller). The shadow soak runs single-threaded.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_LOG_LEGACY_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_LOG_LEGACY_H

#include "ports/block_log_port.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block_log_legacy;

/* Open a read-only legacy block_log view. `datadir` must contain a
 * `blocks/` subdirectory (with the blocks/index/ LevelDB inside it,
 * per zclassicd layout).
 *
 * On success: returns ZCL_OK; *out_handle owns the opened readers,
 * and *out_port is a populated block_log_port struct (the caller may
 * copy the struct, but the `self` pointer remains owned by the
 * handle).
 *
 * On failure: returns a non-OK zcl_result with one of:
 *   - BLOCK_LOG_ERR_NOT_FOUND : datadir missing or no blocks/index
 *   - BLOCK_LOG_ERR_IO        : LevelDB locked (zclassicd running) or
 *                               mmap_reader open failed
 *   - BLOCK_LOG_ERR_CORRUPT   : couldn't iterate the index records
 *
 * The handle owns its readers and side-map; close releases everything. */
struct zcl_result block_log_legacy_open(const char *datadir,
                                        struct block_log_legacy **out_handle,
                                        struct block_log_port *out_port);

void block_log_legacy_close(struct block_log_legacy *h);

/* Diagnostic: how many height slots were loaded from the index. */
size_t block_log_legacy_loaded_count(const struct block_log_legacy *h);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_LOG_LEGACY_H */
