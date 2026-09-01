/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure lock-time arithmetic. Replays from (tx, height_or_time)
 * scalars alone — no clock, no RNG, no I/O, no globals.
 *
 * Three predicates extracted from
 * core/modules/validation/include/validation/contextual_check_tx.h:
 *
 *   is_final_tx           — BIP65/BIP113 finality boundary
 *   is_expired_tx         — Overwinter expiry boundary
 *   is_expiring_soon_tx   — mempool eviction policy
 *
 * The legacy header now forwards to these. Signatures stay `bool`
 * (not zcl_result) because the only failure mode is "NULL tx", and
 * the callers (check_block.c REJECT_UNLESS, mempool eviction) are
 * tight loops where a richer error type would just be discarded.
 *
 * The wrappers in core/modules/validation/ remain consensus-critical: they
 * compose these scalars with the impure chain-state reads
 * (block_index_get_median_time_past, active tip height) that the
 * domain layer must not touch. */

#include "domain/consensus/locktime.h"

#include "primitives/transaction.h"

bool domain_consensus_tx_is_final(const struct transaction *tx,
                                   int n_block_height,
                                   int64_t n_block_time)
{
    if (!tx)
        return false;

    /* nLockTime == 0 is the universal "no lock-time" sentinel. */
    if (tx->lock_time == 0)
        return true;

    /* Pick the comparison domain (height vs unix time) based on the
     * lock_time itself, matching legacy zclassicd / Bitcoin Core
     * IsFinalTx semantics exactly. */
    int64_t lt = (int64_t)tx->lock_time;
    int64_t cutoff = (lt < DOMAIN_CONSENSUS_LOCKTIME_THRESHOLD)
                       ? (int64_t)n_block_height
                       : n_block_time;
    if (lt < cutoff)
        return true;

    /* Even past the boundary, a tx is final if every input opts out
     * of replacement (sequence == 0xFFFFFFFF). */
    for (size_t i = 0; i < tx->num_vin; i++) {
        if (!tx_in_is_final(&tx->vin[i]))
            return false;
    }
    return true;
}

bool domain_consensus_tx_is_expired(const struct transaction *tx,
                                     int n_height)
{
    if (!tx)
        return false;
    if (tx->expiry_height == 0 || transaction_is_coinbase(tx))
        return false;
    /* STRICT greater-than, matching zclassicd's IsExpiredTx exactly
     * (zclassic-cpp/src/main.cpp:788 `nBlockHeight > tx.nExpiryHeight`).
     * A tx is valid in the block AT its expiry_height and only expires
     * the block AFTER. Using `>=` here would expire it one block early
     * and reject a block zclassicd accepts → permanent consensus fork. */
    return (uint32_t)n_height > tx->expiry_height;
}

bool domain_consensus_tx_is_expiring_soon(const struct transaction *tx,
                                           int n_next_block_height)
{
    return domain_consensus_tx_is_expired(
            tx, n_next_block_height + DOMAIN_CONSENSUS_TX_EXPIRING_SOON_THRESHOLD);
}
