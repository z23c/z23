/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/locktime.h — pure transaction lock-time arithmetic.
 *
 * Three context-free predicates over a single `struct transaction`,
 * given the height/time scalars the caller already computed:
 *
 *   - domain_consensus_tx_is_final(tx, n_block_height, n_block_time)
 *
 *     Legacy `is_final_tx`. Returns true iff the tx is final at the
 *     given (height, time) — `lock_time == 0`, OR `lock_time` is below
 *     the appropriate threshold (height when lock_time < 5e8, otherwise
 *     wall-clock time / MTP), OR every input has `sequence == 0xFFFFFFFF`.
 *
 *     This is the BIP65 / BIP113 boundary: `check_block` computes the
 *     median-time-past of the previous tip and passes it as
 *     `n_block_time` so the predicate becomes monotone in the chain
 *     rather than spoofable by the next block's timestamp.
 *
 *   - domain_consensus_tx_is_expired(tx, n_height)
 *
 *     Legacy `is_expired_tx`. Returns true iff the tx is an Overwinter+
 *     tx with `expiry_height != 0` and `n_height > expiry_height`.
 *     Coinbases never expire. The (height_or_time) input here is the
 *     block-height of the block we're considering this tx for.
 *
 *   - domain_consensus_tx_is_expiring_soon(tx, n_next_block_height)
 *
 *     Legacy `is_expiring_soon_tx`. True if `tx_is_expired` at
 *     `n_next_block_height + TX_EXPIRING_SOON_THRESHOLD`.
 *
 * What's NOT here (deliberately left in core/modules/validation/):
 *   - reading the active chain tip / MTP / wall clock (the caller
 *     hands us the already-computed height + time as scalars)
 *   - network-upgrade activation rules
 *   - JoinSplit / Sapling / ECDSA crypto verification
 *   - validation_state population (REJECT_*) — that's the wrapper's job
 *
 * Pure: no clock, no RNG, no I/O, no globals. Replays from the
 * `tx` + scalar inputs alone. Returns plain `bool` to preserve the
 * exact legacy ABI used by check_block.c (REJECT_UNLESS) and
 * test_chain.c / test_validation.c / test_bip113_bip65.c.
 *
 * Layering: depends only on primitives/transaction.h. No chainparams,
 * no consensus/upgrades, no callbacks into lib/.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_LOCKTIME_H
#define ZCL_DOMAIN_CONSENSUS_LOCKTIME_H

#include <stdbool.h>
#include <stdint.h>

struct transaction;

/* Below this lock_time threshold, lock_time is interpreted as a block
 * height; at or above, as a unix timestamp (seconds). 5e8 → year 1985,
 * comfortably below any real wall-clock value but well above any real
 * block height. The threshold is universal Bitcoin consensus, not
 * runtime-mutable, so it lives in the pure header. */
#define DOMAIN_CONSENSUS_LOCKTIME_THRESHOLD 500000000LL

/* The expiry-soon horizon (in blocks) used for mempool eviction. Pure
 * consensus-adjacent policy; the legacy header exposed the same
 * literal as TX_EXPIRING_SOON_THRESHOLD. */
#define DOMAIN_CONSENSUS_TX_EXPIRING_SOON_THRESHOLD 3

/* Is `tx` final at the given (n_block_height, n_block_time)?
 *
 * Mirrors zclassicd main.cpp / Bitcoin Core IsFinalTx exactly:
 *
 *   if (tx.nLockTime == 0)                          return true;
 *   if (tx.nLockTime < threshold(tx.nLockTime, h, t)) return true;
 *   for each input: if !final(input)                return false;
 *   return true;
 *
 * where the threshold flips between block-height and unix-time based
 * on whether lock_time itself is below LOCKTIME_THRESHOLD (5e8).
 *
 * NULL `tx` returns false (defensive — the legacy inline crashed; we
 * choose "not final" which is the conservative answer for any caller
 * that reaches us with a null pointer through a bug). */
bool domain_consensus_tx_is_final(const struct transaction *tx,
                                   int n_block_height,
                                   int64_t n_block_time);

/* Is `tx` expired at the given block height?
 *
 * Coinbase txs and txs with expiry_height==0 never expire.
 * Otherwise: (uint32_t)n_height > tx->expiry_height (strict, matching
 * zclassicd IsExpiredTx — a tx is still valid in the block AT its
 * expiry_height).
 *
 * NULL `tx` returns false. */
bool domain_consensus_tx_is_expired(const struct transaction *tx,
                                     int n_height);

/* Is `tx` going to be expired within the soon-threshold window?
 * Equivalent to `tx_is_expired(tx, n_next_block_height + 3)`.
 *
 * NULL `tx` returns false. */
bool domain_consensus_tx_is_expiring_soon(const struct transaction *tx,
                                           int n_next_block_height);

#endif /* ZCL_DOMAIN_CONSENSUS_LOCKTIME_H */
