/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_install_verify_receipt.h — durable "this exact immutable
 * bundle already passed the deterministic content-verify pass under this
 * exact verifying binary" receipt.
 *
 * The full content verify (config/consensus_state_bundle_validate.c's
 * validate_coins/validate_anchors/validate_nullifiers deep scans, plus the
 * whole-file PRAGMA integrity_check) is a pure function of two inputs: the
 * bundle's exact bytes (bundle_sha3_256) and the exact verifying code that
 * runs it (the verifier's build-epoch digest, see
 * consensus_state_producer_receipt_current_binary_epoch()). Given identical
 * inputs the deterministic scan always reproduces the identical verdict, so a
 * receipt that pins both keys durably lets a later admission attempt on the
 * same unchanged artifact skip re-running the O(bundle-size) scan.
 *
 * This receipt is content-verification authority ONLY. It never substitutes
 * for, weakens, or is consulted by the publication CAS / selected-chain
 * binding / activation admission decision — those always re-run in full on
 * every attempt. Losing or never having a receipt only costs a slower
 * re-verify, never a correctness or authority gap: lookup fails soft (missing
 * file, wrong key, or a corrupt/unreadable store are all "no receipt, verify
 * in full"), and store() is best-effort (a write failure only costs a future
 * re-verify, never the just-completed ADMIT/VERIFIED decision it followed).
 *
 * One receipt file per datadir (this seam is only ever consulted for the ONE
 * bundle currently being admitted/activated there); a receipt for a different
 * bundle hash or a different verifier epoch is simply not a match and is
 * treated as absent.
 */

#ifndef ZCL_CONFIG_CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_H
#define ZCL_CONFIG_CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_H

#include <stdbool.h>
#include <stdint.h>

/* Fixed on-disk record name inside the borrowed datadir directory capability
 * (see consensus_state_artifact_evidence_open()'s datadir_fd contract). */
#define CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_NAME \
    "install-verify-receipt.v1"

/* Look up a receipt in the directory capability `dir_fd`. Returns true only
 * when a well-formed, self-consistent receipt exists AND its
 * (bundle_sha3_256, verifier_epoch) pair exactly matches the arguments; on a
 * match *out_age_us is the receipt's age (>= 0, clamped). Any other outcome
 * (dir_fd < 0, no file, wrong key, truncated/tampered/unreadable record) is
 * reported as false — "no receipt" — never as a distinguishable error; the
 * caller's only correct reaction to false is "run the full content verify". */
bool consensus_state_install_verify_receipt_lookup(
    int dir_fd, const uint8_t bundle_sha3_256[32],
    const uint8_t verifier_epoch[32], int64_t *out_age_us);

/* Persist a receipt for (bundle_sha3_256, verifier_epoch) into the directory
 * capability `dir_fd`, to be honored by a later lookup() for the same exact
 * pair. Call only after the deterministic content verify has actually
 * succeeded end-to-end. Best-effort: a write failure is logged and does not
 * report to the caller as an error — the content verify this follows already
 * succeeded and stands regardless; only a future re-verify is at stake. */
void consensus_state_install_verify_receipt_store(
    int dir_fd, const uint8_t bundle_sha3_256[32],
    const uint8_t verifier_epoch[32]);

#endif /* ZCL_CONFIG_CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_H */
