/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet Sapling extension (Sapling Lane C) — an in-sim Sapling
 * note-commitment tree so the deterministic harness can drive a REAL
 * shielded send (t->z, z->z) through the production Groth16 verifier.
 *
 * The harness mints only through the same connect_block/contextual_check
 * consensus code as the live node; this header adds three sim-local
 * capabilities, none of which touch a consensus predicate:
 *
 *   1. An incremental Sapling merkle tree (sapling/incremental_merkle_tree)
 *      owned by the simnet. simnet_enable_sapling_tree() allocates + inits
 *      it; from then on every mint (simnet_mint_txs / simnet_mint_coinbase*)
 *      appends the block's shielded-output note commitments (cm) IN ORDER and
 *      stamps header.hashFinalSaplingRoot with the REAL current tree root
 *      (extends Lane A's empty-root stamp to a live, non-empty tree). The
 *      append is rollback-safe: it is committed only if connect_block accepts
 *      the block.
 *
 *   2. simnet_enable_contextual_check() flips on a REAL
 *      contextual_check_transaction(nHeight, dosLevel=100) call inside the mint
 *      path for every shielded tx, so the Sapling spend/output Groth16 proofs +
 *      binding signature are verified by the same consensus function the live
 *      node reaches (validation/contextual_check_tx.c) — not a bespoke check.
 *
 *   3. Anchor + witness accessors so the harness can build a z->z spend: the
 *      anchor is the current tree root; the witness authenticates a specific
 *      leaf (its Merkle path feeds the spend prover).
 *
 * A spend's (anchor, witness, position) triple must be consistent: the note's
 * cm sits at `position`, the witness folds up to `anchor`, and the anchor is a
 * root at/after the note's append. The Groth16 spend proof enforces this; the
 * verifier does not separately check the anchor is a known historical root
 * (that is chainstate's job — see sapling.h sapling_check_spend).
 */

#ifndef ZCL_SIM_SIMNET_SAPLING_H
#define ZCL_SIM_SIMNET_SAPLING_H

#include "sim/simnet.h"
#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct incremental_witness;

/* Allocate + initialize the sim's live Sapling note-commitment tree (depth
 * 32, Pedersen — the consensus tree). Idempotent: a second call is a no-op
 * and returns true. After this, mints maintain the tree and stamp the real
 * root into every post-Sapling-activation block header. Returns false (and
 * logs) on OOM or an uninitialized sim. */
bool simnet_enable_sapling_tree(struct simnet *s);

/* Turn on (or off) the REAL contextual_check_transaction drive inside the mint
 * path. With it on, minting a block containing Sapling spend/output
 * descriptions verifies their Groth16 proofs + binding signature through the
 * production consensus verifier; a bad proof makes the mint fail. Requires the
 * Sapling verifying keys to be loaded (sapling_init_params) — otherwise the
 * fail-closed verifier rejects. No-op (logs) on an uninitialized sim. */
void simnet_enable_contextual_check(struct simnet *s, bool on);

/* Copy the current Sapling tree root (the anchor a spend proves membership
 * against) into `out`. Returns false if the tree is not enabled. */
bool simnet_sapling_tree_root(const struct simnet *s, struct uint256 *out);

/* Number of note commitments appended to the tree so far (== the index the
 * NEXT appended note will occupy). Returns 0 if the tree is not enabled. */
size_t simnet_sapling_tree_size(const struct simnet *s);

/* Initialize `w` to track the authentication path of the LAST note commitment
 * appended to the tree (its position == simnet_sapling_tree_size()-1). Call
 * immediately after the mint that appended the target note and before any
 * later note is appended (this minimal harness needs no witness replay).
 * Returns false (and logs) if the tree is not enabled or is empty. */
bool simnet_sapling_witness_last(const struct simnet *s,
                                 struct incremental_witness *w);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_SAPLING_H */
