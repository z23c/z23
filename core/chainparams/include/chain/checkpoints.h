/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_CHECKPOINTS_H
#define ZCL_CHECKPOINTS_H

#include "chain/chain.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

struct checkpoint_entry {
    int height;
    struct uint256 hash;
};

struct checkpoint_data {
    const struct checkpoint_entry *entries;
    int nEntries;
    int64_t nTimeLastCheckpoint;
    int64_t nTransactionsLastCheckpoint;
    double fTransactionsPerDay;
};

/* Estimated total block count for the chain, taken as the height of the
 * last (highest) checkpoint entry. Returns 0 if `data` is NULL or has no
 * entries. This is a lower-bound progress denominator, not a consensus
 * value. Source: src/checkpoints.c ->
 * domain/consensus/src/checkpoints.c
 * (domain_consensus_checkpoints_total_blocks_estimate). */
int checkpoints_get_total_blocks_estimate(const struct checkpoint_data *data);

/* Fraction of chain verification work completed at `pindex`, in [0.0,
 * 1.0], for UI/sync-progress display (not consensus). Models work as
 * cheap pre-last-checkpoint transactions plus expensive post-checkpoint
 * ones, extrapolating the remaining tail from `fTransactionsPerDay` and
 * the wall-clock gap to now; `fSigchecks` weights signature-checking
 * work 5x. Reads `pindex->nChainTx` and the block time, plus a single
 * wall-clock read held in this wrapper.
 *
 * Contract: a NULL `pindex` returns 0.0 (handled here, before the clock
 * read); a degenerate/zero denominator also returns 0.0 rather than
 * NaN/inf. Source: src/checkpoints.c ->
 * domain/consensus/src/checkpoints.c
 * (domain_consensus_checkpoints_progress_at_now). */
double checkpoints_guess_verification_progress(
    const struct checkpoint_data *data,
    const struct block_index *pindex, bool fSigchecks);

/* ── Enforcement helpers ────────────────────────────────────
 *
 * These wrap the exact-height checkpoint policy in a testable
 * API. Callers in `contextual_check_block_header` use
 * `checkpoints_validate_header()`; other code (RPC, tests)
 * can use the lower-level lookups.
 */

/* Returns true and writes `*out_hash` if a checkpoint exists
 * at `height`. Returns false if there is no checkpoint at that
 * height. O(nEntries) linear scan — the list is tiny (single
 * digits). */
bool checkpoints_hash_at_height(const struct checkpoint_data *data,
                                 int height,
                                 struct uint256 *out_hash);

/* Returns the highest checkpoint height, or -1 if there are
 * no checkpoints. Used by the "IsInitialBlockDownload" and
 * "deep reorg refusal" predicates. */
int checkpoints_last_height(const struct checkpoint_data *data);

/* Header-validation entry point. Returns true if (height, hash)
 * is consistent with the checkpoint data:
 *   - if no checkpoint exists at `height` → true (nothing to
 *     check)
 *   - if a checkpoint exists and `hash` matches → true
 *   - otherwise → false (fork attempt)
 *
 * Callers are free to ignore this when `fCheckpointsEnabled`
 * is false (e.g. in test fixtures or explicit re-scan modes). */
bool checkpoints_validate_header(const struct checkpoint_data *data,
                                  int height,
                                  const struct uint256 *hash);

/* SHA3 UTXO checkpoint — compiled-in commitment that a new node
 * can verify its UTXO set against without trusting any peer.
 * Verified bit-for-bit against zclassicd reference implementation. */
struct sha3_utxo_checkpoint {
    int32_t  height;            /* block height */
    uint8_t  block_hash[32];    /* block hash at height (hex in source) */
    uint8_t  sha3_hash[32];     /* SHA3-256 over canonical UTXO set */
    uint64_t utxo_count;        /* number of UTXOs */
    int64_t  total_supply;      /* total transparent supply in zatoshi */
};

/* Returns the latest hardcoded SHA3 UTXO checkpoint, or NULL if none.
 * In production this always returns the compiled-in g_sha3_checkpoint. */
const struct sha3_utxo_checkpoint *get_sha3_utxo_checkpoint(void);

/* Test-only seam: install a checkpoint that get_sha3_utxo_checkpoint()
 * returns instead of the compiled-in one. Used by the snapshot-bind
 * tests to assert the anchor-root gate at a scaled-down fixture height
 * whose locally-computed commitment IS the override's sha3_hash by
 * construction (the same utxo_commitment path that derived the real
 * checkpoint). NULL = no override = production behavior. The pointer is
 * borrowed (not copied); the caller keeps it valid until reset. */
void checkpoints_set_sha3_override_for_test(const struct sha3_utxo_checkpoint *cp);
void checkpoints_reset_sha3_override_for_test(void);

/* ROM state checkpoint ("shielded ROM keystone") — the COMPLETE-state
 * extension of the transparent-only sha3_utxo_checkpoint above. ZClassic
 * headers commit neither the UTXO set nor the shielded anchor/nullifier
 * state, so this compiled-in commitment pins ALL of it at one height: the
 * transparent coins set (same values as the sha3_utxo_checkpoint) PLUS the
 * Sprout/Sapling anchor history, both commitment-tree frontier roots, and
 * the full nullifier history. A from-genesis fold that reproduces every
 * field byte-identically has independently re-derived the complete chain
 * state at `height` without trusting any peer or borrowed artifact.
 *
 * Digest preimages are the bundle-canonical ones (mirrored byte-for-byte
 * by tools/rom_two_builder_compare.c and by the production codec
 * engine/modules/storage/src/consensus_state_bundle_codec.c):
 *   anchor_digest    — SHA3-256 over domain
 *                      "zcl.consensus_state_bundle.v1/anchors" (NUL included),
 *                      rows in the combined bundle-canonical order
 *                      (pool ASC, then anchor ASC; pool 0 = Sprout from
 *                      sprout_anchors, pool 1 = Sapling from sapling_anchors);
 *                      row preimage = pool(1) | root(32) | height LE8 |
 *                      tree_len LE4 | tree bytes.
 *   nullifier_digest — SHA3-256 over domain
 *                      "zcl.consensus_state_bundle.v1/nullifiers" (NUL
 *                      included), rows ORDER BY pool,nf;
 *                      row preimage = pool(1) | nf(32) | height LE8.
 *   *_frontier_root  — per pool, the anchor (tree root) at the maximum
 *                      recorded height; *_frontier_height is that height
 *                      (can lag `height`: blocks with no shielded activity
 *                      append no anchor row).
 *   rom_state_root   — the single folded commitment: SHA3-256 over domain
 *                      "zcl.rom_state_checkpoint.v1/root" (NUL included),
 *                      then the fields in pinned order: height LE8 |
 *                      block_hash | utxo_root | utxo_count LE8 |
 *                      total_supply LE8 | anchor_digest | anchor_count LE8 |
 *                      sprout_frontier_root | sprout_frontier_height LE8 |
 *                      sapling_frontier_root | sapling_frontier_height LE8 |
 *                      nullifier_digest | nullifier_count LE8.
 *   utxo_root        — the same value as sha3_utxo_checkpoint.sha3_hash
 *                      (bare SHA3-256 over the canonical (txid,vout) coin
 *                      records); duplicated here so the complete state rides
 *                      one struct.
 *
 * All 32-byte arrays are in internal byte order (same convention as
 * sha3_utxo_checkpoint.block_hash: the hex comment reads in display order,
 * the bytes are stored as hashed). */
struct rom_state_checkpoint {
    int32_t  height;                  /* block height of the commitment */
    uint8_t  block_hash[32];          /* block hash at height (hex in source) */
    uint8_t  utxo_root[32];           /* == sha3_utxo_checkpoint.sha3_hash */
    uint64_t utxo_count;              /* == sha3_utxo_checkpoint.utxo_count */
    int64_t  total_supply;            /* == sha3_utxo_checkpoint.total_supply */
    uint8_t  anchor_digest[32];       /* combined anchors fold (see above) */
    uint64_t anchor_count;            /* total anchor rows, both pools */
    uint8_t  sprout_frontier_root[32];/* Sprout tree root at max Sprout height */
    int64_t  sprout_frontier_height;  /* that max Sprout anchor height */
    uint8_t  sapling_frontier_root[32];/* Sapling tree root at max Sapling h */
    int64_t  sapling_frontier_height; /* that max Sapling anchor height */
    uint8_t  nullifier_digest[32];    /* combined nullifiers fold (see above) */
    uint64_t nullifier_count;         /* total nullifier rows, both pools */
    uint8_t  rom_state_root[32];      /* folded complete-state root (above) */
};

/* Returns the compiled-in ROM state checkpoint (the shielded keystone), or
 * the installed test override. Production always returns the compiled-in
 * g_rom_state_checkpoint. */
const struct rom_state_checkpoint *get_rom_state_checkpoint(void);

/* Test-only seam mirroring checkpoints_set_sha3_override_for_test: install a
 * checkpoint that get_rom_state_checkpoint() returns instead of the
 * compiled-in one. NULL = no override = production behavior. The pointer is
 * borrowed (not copied); the caller keeps it valid until reset. */
void checkpoints_set_rom_state_override_for_test(
    const struct rom_state_checkpoint *cp);
void checkpoints_reset_rom_state_override_for_test(void);

#endif
