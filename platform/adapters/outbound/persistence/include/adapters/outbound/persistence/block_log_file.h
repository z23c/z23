/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * block_log_file — file-backed implementation of block_log_port.
 *
 * On-disk layout (under <dir>/):
 *   blocks.log  — record stream:
 *                 [magic 4 "ZBLK"][hash 32][len_le 4][bytes len]
 *                 Records are written append-only; offsets are stable.
 *   blocks.idx  — side index, parallel records:
 *                 [height_le 4][hash 32][offset_le 8]
 *                 One entry per appended block, in append order.
 *
 * Crash safety:
 *   - append() fsyncs the log before writing the index entry, and
 *     fsyncs the index before returning OK. A power-cut between those
 *     two fsyncs leaves the log with a record that the index doesn't
 *     know about; on the next open() we scan the unindexed tail of the
 *     log and rebuild the missing index entries before returning the
 *     port handle. A power-cut mid-record (partial write) is detected
 *     by len-vs-file-size and truncated on open.
 *
 * Idempotency:
 *   - append(h, hash, bytes) is a no-op if hash is already present and
 *     the stored bytes match exactly. If hash is present and bytes
 *     differ, the function returns BLOCK_LOG_ERR_CORRUPT — a
 *     consensus-level event the caller must surface.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_LOG_FILE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_LOG_FILE_H

#include "ports/block_log_port.h"
#include "util/result.h"

struct block_log_file;

/* Open or create a block log under <dir>. Creates the directory if
 * missing. On success populates `out_port` with a fully-formed
 * block_log_port whose `self` is the underlying block_log_file
 * handle. Caller closes via block_log_file_close(handle).
 *
 * Recovery: if a previous run crashed between writing a log record
 * and the matching index entry, this call rebuilds the missing index
 * tail before returning. A partial (torn) record at the end of either
 * file is truncated. Returns BLOCK_LOG_ERR_CORRUPT if the on-disk
 * state is inconsistent in a way that can't be repaired locally
 * (e.g. magic bytes wrong on a fully-written record). */
struct zcl_result block_log_file_open(const char *dir,
                                      struct block_log_file **out_handle,
                                      struct block_log_port *out_port);

/* Close the handle and release internal buffers. Safe to call with
 * NULL. */
void block_log_file_close(struct block_log_file *handle);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_LOG_FILE_H */
