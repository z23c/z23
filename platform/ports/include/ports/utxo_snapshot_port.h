/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * utxo_snapshot_port — single-writer, multi-reader UTXO set.
 *
 * The UTXO set is a derived projection of the block log. It exists
 * only as a performance cache: looking up a coin should be O(log N)
 * or better, not O(blocks). Every block validated by the mutator
 * mutates this set; readers see consistent snapshots via the port.
 *
 * Concurrency model:
 *   - One writer (the mutator) calls apply_diff().
 *   - Many readers (native commands, RPC, explorer, wallet scan) call lookup().
 *   - Snapshots are read-consistent: a reader sees the set as of
 *     the snapshot tip it was opened against.
 *
 * Crash safety:
 *   - apply_diff() commits durably to the underlying adapter (LMDB,
 *     LSM, etc.) by the time it returns OK.
 *   - On restart, the snapshot must be consistent with the block log
 *     up to commit_at_height; everything above is replayed by the
 *     mutator from the log.
 */

#ifndef ZCL_PORTS_UTXO_SNAPSHOT_PORT_H
#define ZCL_PORTS_UTXO_SNAPSHOT_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ports/block_log_port.h"   /* struct block_hash */
#include "util/result.h"

enum utxo_snapshot_err {
    UTXO_ERR_IO              = 1,
    UTXO_ERR_NOT_FOUND       = 2,
    UTXO_ERR_DOUBLE_SPEND    = 3,   /* apply_diff tried to spend a coin that's already spent */
    UTXO_ERR_UNKNOWN_OUTPOINT= 4,   /* apply_diff tried to spend a coin that doesn't exist */
    UTXO_ERR_TIP_MISMATCH    = 5,   /* apply_diff at wrong tip (caller's view stale) */
    UTXO_ERR_CLOSED          = 6,
};

/* Outpoint: a reference to a specific output of a specific transaction. */
struct utxo_outpoint {
    uint8_t txid[32];
    uint32_t vout;
};

/* A coin (UTXO record). */
struct utxo_coin {
    uint64_t value_zat;        /* amount in zatoshi */
    uint32_t height;           /* block height where created */
    bool is_coinbase;
    uint32_t script_pubkey_len;
    const uint8_t *script_pubkey;   /* lifetime owned by adapter snapshot */
};

/* A diff to apply to the UTXO set when accepting one block. The
 * spends MUST exist in the set; the creates MUST NOT collide. The
 * adapter enforces both as part of apply_diff(). */
struct utxo_diff {
    uint32_t target_height;            /* block height being applied */
    const struct block_hash *target_block;

    /* Coins removed by this block (transaction inputs). */
    const struct utxo_outpoint *spends;
    size_t spends_len;

    /* Coins created by this block (transaction outputs). */
    const struct utxo_outpoint *creates;
    const struct utxo_coin *creates_coin;   /* parallel array */
    size_t creates_len;
};

struct utxo_snapshot_port {
    void *self;

    /* Read the coin at outpoint as of the current tip snapshot. Returns
     * UTXO_ERR_NOT_FOUND if absent (already spent or never created). */
    struct zcl_result (*lookup)(void *self,
                                const struct utxo_outpoint *op,
                                struct utxo_coin *coin_out);

    /* Apply one block's diff atomically. The caller (mutator) is the
     * single writer. The adapter rejects with UTXO_ERR_TIP_MISMATCH if
     * diff->target_height is not (current_tip_height + 1). */
    struct zcl_result (*apply_diff)(void *self,
                                    const struct utxo_diff *diff);

    /* Revert the topmost block's diff (reorg support). */
    struct zcl_result (*revert_tip)(void *self,
                                    uint32_t expected_height);

    /* Current tip height of the snapshot. UINT32_MAX if empty. */
    uint32_t (*tip_height)(void *self);

    /* Current tip block hash. Undefined if tip_height() == UINT32_MAX. */
    void (*tip_hash)(void *self, struct block_hash *out);

    /* SHA3-256 commitment over the entire UTXO set in canonical order.
     * Used by snapshot sync and by the diff-with-legacy comparison. */
    struct zcl_result (*sha3_commitment)(void *self,
                                         uint8_t out_digest[32]);
};

#endif /* ZCL_PORTS_UTXO_SNAPSHOT_PORT_H */
