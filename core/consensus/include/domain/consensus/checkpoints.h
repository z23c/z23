/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/checkpoints.h — pure checkpoint matching.
 *
 * The hardcoded checkpoint list is a tiny static table of
 * (height, hash) entries that pins specific historical blocks
 * against deep-reorg or spoofed-chain attacks. Walking that
 * table is a pure function of its inputs — no clock, no RNG,
 * no I/O, no state reads.
 *
 * What lives here:
 *   - hash_at_height        : "does the table pin a hash at H?"
 *   - last_height           : "what is the deepest pinned height?"
 *   - validate_header       : "is (height, hash) consistent with the table?"
 *   - total_blocks_estimate : "highest pinned height" (the table's stored value)
 *   - progress_at_now       : verification-progress fraction, given a
 *                             caller-supplied wall-clock `now_unix`.
 *
 * What's NOT here (and why):
 *   - `checkpoints_guess_verification_progress`
 *       Reads the wall clock via `platform_time_wall_time_t()`. The clock
 *       is a port, not a domain primitive — so the lib/ wrapper holds onto
 *       that single line and forwards to the pure `progress_at_now`. This
 *       is exactly the split the hexagonal cut requires.
 *   - `get_sha3_utxo_checkpoint`
 *       Returns a pointer to a file-scope static struct. It's pure in the
 *       function-call sense (no side effects, same result each time), but
 *       it's a registry/lookup specific to a single global table, not a
 *       reusable predicate — there's nothing to test that wouldn't be a
 *       trivial identity check, and the table value is verified at the
 *       integration level (gettxoutsetinfo SHA3). Stays in core/modules/chain.
 *
 * Layering: this header only depends on chain/checkpoints.h (for the
 * `struct checkpoint_data` and `struct checkpoint_entry` definitions,
 * which are pure data carriers) and core/uint256.h. No util, no clock,
 * no platform.
 *
 * Pure / replayable: every function in this header is a pure function
 * of its inputs. Calling with identical inputs always yields identical
 * outputs and writes (to `out_hash` only).
 *
 * Background: zclassicd src/checkpoints.cpp::CheckBlock / GetTotalBlocksEstimate
 * / GuessVerificationProgress are the historic source-of-truth.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_CHECKPOINTS_H
#define ZCL_DOMAIN_CONSENSUS_CHECKPOINTS_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct checkpoint_data;
struct uint256;

/* True iff `data` pins a checkpoint at `height`. On a hit, writes
 * the pinned hash to `*out_hash`. On a miss (no checkpoint at that
 * height — the 99.99% case for non-checkpoint heights), returns
 * false and leaves `*out_hash` untouched.
 *
 * NULL `data` or NULL `out_hash` -> false (no crash). The wrapper in
 * core/modules/chain logs a LOG_FAIL on NULL args; the domain layer treats
 * NULL as "no pin found" so callers can compose this safely.
 *
 * O(n) linear scan over data->nEntries. The list is tiny (single
 * digits on mainnet) so this is the right shape; if it ever grows,
 * convert to a binary search keyed on `height`. */
bool domain_consensus_checkpoints_hash_at_height(
        const struct checkpoint_data *data,
        int height,
        struct uint256 *out_hash);

/* The highest height pinned in `data`, or -1 if the table is empty
 * or `data` is NULL. Used by deep-reorg refusal and the
 * "IsInitialBlockDownload" predicates. Defensive linear scan
 * (entries are stored ascending in practice, but we don't trust
 * that here). */
int domain_consensus_checkpoints_last_height(
        const struct checkpoint_data *data);

/* Header-validation entry point. Returns true if (height, hash) is
 * consistent with the checkpoint table:
 *   - no checkpoint at `height`      -> true (nothing to check)
 *   - checkpoint hit and hashes equal -> true
 *   - checkpoint hit and hashes differ -> false (fork attempt)
 *
 * Degenerate inputs (NULL data or NULL hash) -> true. The lib/
 * wrapper preserves this contract so the existing `fCheckpointsEnabled`
 * gating in callers is unchanged. */
bool domain_consensus_checkpoints_validate_header(
        const struct checkpoint_data *data,
        int height,
        const struct uint256 *hash);

/* The "total blocks" estimate is just the deepest pinned height
 * (a stored property of the table). Returns 0 if the table is
 * empty or `data` is NULL. */
int domain_consensus_checkpoints_total_blocks_estimate(
        const struct checkpoint_data *data);

/* Pure verification-progress estimate at a caller-supplied
 * wall-clock time `now_unix_sec`.
 *
 * Mirrors zclassicd's GuessVerificationProgress exactly: it
 * combines three quantities to produce a 0..1 fraction —
 *   - `nChainTx` of the block (cheap-work counter to here)
 *   - `data->nTransactionsLastCheckpoint` (cheap-work counter at last cp)
 *   - `data->fTransactionsPerDay` and the elapsed real time to estimate
 *     the expensive (post-checkpoint) work that remains.
 *
 * `fSigchecks` toggles the post-checkpoint signature-check cost
 * multiplier (5x) — true for normal validation, false for
 * `-nobgvalidation` runs.
 *
 * Replayable: the clock has been lifted to a parameter, so this
 * function is pure. The lib/ wrapper reads `platform_time_wall_time_t()`
 * and forwards.
 *
 * Degenerate inputs:
 *   - `data` NULL   -> 0.0 (the wrapper's old behaviour was to deref;
 *                      the new defence here surfaces a clean 0.0).
 *   - `pindex_chain_tx == 0` and `pindex_time_seconds == 0`
 *                   -> the wrapper treats this as "no block yet" and
 *                      returns 0.0 to match the lib's old NULL-pindex path.
 *     Pure inputs alone don't know "pindex was NULL" — that's a
 *     wrapper-layer concern, communicated here via the all-zero
 *     sentinel (a legal value for the genesis-progress case is
 *     defined by the math itself).
 */
double domain_consensus_checkpoints_progress_at_now(
        const struct checkpoint_data *data,
        uint64_t pindex_chain_tx,
        int64_t  pindex_time_seconds,
        int64_t  now_unix_sec,
        bool     fSigchecks);

#endif /* ZCL_DOMAIN_CONSENSUS_CHECKPOINTS_H */
