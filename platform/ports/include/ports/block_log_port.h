/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * block_log_port — append-only, content-addressed block log.
 *
 * This is the irreducible storage primitive of the node. Every block
 * the node accepts is appended to this log under its block hash.
 * Everything else — UTXO set, header chain index, mempool — is a
 * derived projection rebuildable by replaying this log.
 *
 * Contract:
 *   - Appends are idempotent: appending a block whose hash already
 *     exists in the log is a no-op that returns BLOCK_LOG_OK.
 *   - Bytes written are durable when append() returns BLOCK_LOG_OK
 *     (the adapter is responsible for fsync ordering).
 *   - Reads return the exact bytes that were appended; no truncation,
 *     no padding, no reorder.
 *   - The log is the source of truth. If a higher layer's in-memory
 *     view disagrees with the log, the log wins.
 */

#ifndef ZCL_PORTS_BLOCK_LOG_PORT_H
#define ZCL_PORTS_BLOCK_LOG_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

/* Block hash. 32 bytes, little-endian as on the wire. */
struct block_hash {
    uint8_t bytes[32];
};

/* Block log error codes. Returned via zcl_result.code when the
 * result is not OK. */
enum block_log_err {
    BLOCK_LOG_ERR_IO            = 1,  /* disk error, see errno via adapter logs */
    BLOCK_LOG_ERR_CORRUPT       = 2,  /* checksum or framing mismatch on read */
    BLOCK_LOG_ERR_NOT_FOUND     = 3,  /* lookup miss */
    BLOCK_LOG_ERR_TOO_LARGE     = 4,  /* block bytes exceed configured max */
    BLOCK_LOG_ERR_CLOSED        = 5,  /* port handle no longer valid */
    BLOCK_LOG_ERR_NOT_SUPPORTED = 6,  /* operation not supported by this adapter
                                       * (e.g. append() on a read-only view). */
};

/* Iteration callback. Return true to continue, false to stop early.
 * The bytes buffer is valid only for the duration of the call;
 * callers must copy if they want to keep them. */
typedef bool (*block_log_iter_fn)(uint32_t height,
                                  const struct block_hash *hash,
                                  const uint8_t *bytes,
                                  size_t len,
                                  void *user_data);

struct block_log_port {
    void *self;

    /* Append a block. Idempotent on (hash, bytes). If hash is already
     * present and the stored bytes match, returns OK. If hash is
     * present and bytes differ, returns BLOCK_LOG_ERR_CORRUPT (the
     * adapter MUST detect this — it is a consensus-level event). */
    struct zcl_result (*append)(void *self,
                                uint32_t height,
                                const struct block_hash *hash,
                                const uint8_t *bytes,
                                size_t len);

    /* Look up a block by hash. On hit, sets *bytes_out and *len_out to
     * a buffer owned by the adapter (valid until the next port call
     * on the same handle). On miss, returns BLOCK_LOG_ERR_NOT_FOUND. */
    struct zcl_result (*read_by_hash)(void *self,
                                      const struct block_hash *hash,
                                      const uint8_t **bytes_out,
                                      size_t *len_out);

    /* Look up the block at a given height in the active chain.
     * (Adapters typically maintain a small height→offset index for
     * this — it is a side index over the content-addressed log.) */
    struct zcl_result (*read_at_height)(void *self,
                                        uint32_t height,
                                        const uint8_t **bytes_out,
                                        size_t *len_out);

    /* Current tip height as recorded in the log's side index. Returns
     * UINT32_MAX if the log is empty. */
    uint32_t (*tip_height)(void *self);

    /* Iterate blocks from start_height forward in active-chain order.
     * The callback may stop iteration by returning false. */
    struct zcl_result (*iter_from)(void *self,
                                   uint32_t start_height,
                                   block_log_iter_fn cb,
                                   void *user_data);
};

#endif /* ZCL_PORTS_BLOCK_LOG_PORT_H */
