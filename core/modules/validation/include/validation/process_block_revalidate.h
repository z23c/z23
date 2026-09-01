/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * process_block_revalidate — evidence-based failed-block revalidation.
 *
 * The wedge class this function exists to extinct
 * ------------------------------------------------
 * `find_most_work_chain` (`core/modules/validation/src/process_block_core.c:363`)
 * skips every block_index entry with BLOCK_FAILED_VALID set. Once a block
 * gets that bit — even if the original rejection was a transient race
 * (e.g., snapshot import competing with connect_block on a UTXO miss
 * that was actually recoverable) — there is NO existing code path that
 * can clear it based on subsequent peer or mirror evidence. The chain
 * stops at that height until an operator manually intervenes, even when an
 * independent local authority disagrees with the failure mark. Nothing in
 * the base chain-selection path consults that disagreement to clear the bit.
 *
 * This function adds that consult.
 *
 * The verify-never-trust contract
 * --------------------------------
 * Clearing BLOCK_FAILED_VALID is a consensus-relevant operation. The
 * only safe trigger is **cryptographic agreement between ≥2 independent
 * oracles on the same block hash at the same height**:
 *
 *   1. `quorum_oracle_probe(height, &qr)` queries
 *      QO_SRC_LOCAL  (our active_chain — won't help here; we don't have it)
 *      QO_SRC_ZCLASSICD (legacy node via JSON-RPC)
 *      QO_SRC_PEER (recent peer header votes)
 *
 *   2. We require `qr.verdict == QO_VERDICT_QUORUM_MATCH` AND
 *      `qr.winning_hash_hex` equal to OUR pindex's hash (exact
 *      32-byte SHA256d). Two independent sources must agree on the
 *      same hash we already have a block_index entry for. Anything
 *      less and we leave BLOCK_FAILED_VALID set — EXCEPT the
 *      single-source local-authority pathway in 2b.
 *
 *   2b. Pathway (B) — single-source local authority (personal-stack
 *      sovereignty). On a personal stack zclassicd IS the local
 *      authority, so we also clear when ALL of: zclassicd is present and
 *      returns a hash equal to our pindex's; QO_SRC_LOCAL has no vote
 *      (we genuinely have no opinion, not a bug); and the active tip is
 *      strictly below the target height (so LOCAL silence is structural).
 *      This accepts a single agreeing source by design; verification is
 *      still preserved because connect_block fully re-validates the block
 *      before it can be committed (see the implementation's evidence_path
 *      "local_authority_zclassicd"). Implemented in
 *      process_block_revalidate.c step 3, pathway (B).
 *
 *   3. On agreement: clear BLOCK_FAILED_VALID on the pindex and
 *      BLOCK_FAILED_CHILD on every descendant whose only failure-mark
 *      came from this ancestor. Persist via
 *      `block_tree_db_write_block_index_sync` so the clear survives a
 *      crash. Then trigger `activation_request_connect()` with the new
 *      source class ACTIVATION_SRC_REVALIDATE.
 *
 *   4. If the reducer's validation pass re-runs and the block IS actually
 *      valid, the chain advances naturally. If it re-fails, the reducer
 *      re-marks BLOCK_FAILED_VALID with the fresh state — no consensus rule
 *      changes, no validation skipping.
 *
 * Why this is NOT "skip verification"
 * ------------------------------------
 * The bit we clear means "we previously failed to validate this block."
 * Clearing it does NOT skip future validation — it makes the block
 * eligible for validation again. The re-run is a full `connect_block`
 * with all of Equihash + scripts + Sapling. The oracle agreement is
 * the precondition for re-attempting; it is not a substitute for the
 * check itself.
 *
 * The lint review for this code path:
 *   - No new "skip-validation" flag introduced.
 *   - Every revalidate path runs the full validator.
 *   - Quorum agreement is a 2-oracle requirement, not 1-oracle.
 *   - Without quorum, the bit stays set.
 *
 * Threading
 * ---------
 * Intended to be called from the `chain.coord_escalation` supervisor
 * child's `on_stall` callback (period 60s, stall threshold 900s). The
 * supervisor thread runs ONE on_stall at a time per child; concurrency
 * across children is bounded. The actual block_index nStatus mutation
 * + persistence is done under the activation controller's mutex
 * (acquired by `activation_request_connect`). Direct callers must NOT
 * already hold that mutex.
 */

#ifndef ZCL_VALIDATION_PROCESS_BLOCK_REVALIDATE_H
#define ZCL_VALIDATION_PROCESS_BLOCK_REVALIDATE_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct uint256;

/* Result enum — every revalidation attempt returns exactly one value.
 * Names are stable for logging / metrics / event-stream consumers. */
enum reval_result {
    REVAL_NOT_ATTEMPTED        = 0, /* prereqs unmet (NULL ms, etc.) */
    REVAL_NO_FAILURE           = 1, /* pindex doesn't have BLOCK_FAILED_VALID;
                                       caller didn't need us */
    REVAL_HEIGHT_NOT_FOUND     = 2, /* no failed pindex at this height */
    REVAL_EVIDENCE_INSUFFICIENT= 3, /* quorum_oracle returned no quorum */
    REVAL_EVIDENCE_DISAGREES   = 4, /* quorum agrees on a DIFFERENT hash
                                       than our failed pindex — we're on a
                                       fork; leave FAILED, let reorg handle */
    REVAL_PERSIST_FAILED       = 5, /* couldn't write cleared status to disk */
    REVAL_CONNECT_FAILED       = 6, /* cleared, retried, still invalid;
                                       re-marked FAILED with new state */
    REVAL_RECOVERED            = 7, /* cleared, retried, valid; chain can
                                       advance on the next tick */
};

const char *reval_result_name(enum reval_result r);

/* The function. See header preamble for the verification contract.
 *
 * Inputs:
 *   target_height: height in the block_index to look for a FAILED
 *                  pindex. Caller typically passes (active_chain_tip + 1).
 *   ms:            chainstate root. Required (non-NULL).
 *   out_hash:      optional. Filled with the pindex hash that was
 *                  evaluated (whether or not revalidation succeeded).
 *                  NULL OK.
 *
 * Returns one of the enum values above. Never aborts. Safe to call
 * repeatedly across supervisor ticks. Idempotent on REVAL_NO_FAILURE
 * and REVAL_RECOVERED. */
enum reval_result process_block_revalidate(int target_height,
                                            struct main_state *ms,
                                            struct uint256 *out_hash);

#endif /* ZCL_VALIDATION_PROCESS_BLOCK_REVALIDATE_H */
