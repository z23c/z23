/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mint_skip_crypto — the OFFLINE FAST-MINT crypto pass-through toggle.
 *
 * The `-mint-anchor-fast` boot mode (honored ONLY together with -mint-anchor)
 * folds the on-disk block BODIES genesis..anchor through the staged pipeline,
 * but PASSES THROUGH the two crypto stages (script_validate's per-input ECDSA
 * verify_script loop and proof_validate's Groth16/Ed25519/PHGR13/binding-sig
 * verification) WITHOUT running them. The state-transition stage (utxo_apply)
 * is UNCHANGED, so the folded coins_kv set is identical to the full-validated
 * fold — the set of coins is a pure function of WHICH outputs exist and WHICH
 * are spent (the bodies + the state rules), not of the signature/proof witness.
 *
 * EVIDENCE LIMIT — the terminal checkpoint assertion proves that the resulting
 * transparent coin set has the compiled SHA3/count/supply. It does NOT prove
 * the skipped signatures or shielded proofs, does not establish complete
 * historical anchors/nullifiers, and never makes this a full validation replay.
 * Fast output therefore remains checkpoint-fold evidence until separately
 * combined with the required shielded-history and publication proofs. It is
 * NOT sound for validating the chain and NEVER gates a running node's
 * accept/reject decision.
 *
 * MECHANISM — a process-global atomic bool. Both crypto step bodies read it
 * once per height; when ON they write `checkpoint_fold`/ok=true, never
 * `verified`. That status propagates through UTXO application and is excluded
 * from serving validity, H*, tip finalization, repairs, and the canonical
 * exporter. Coin application remains byte-identical; its authority posture does
 * not.
 *
 * NORMAL-BOOT INVARIANT: the toggle defaults to OFF. A normal boot NEVER calls
 * mint_skip_crypto_set, so `if (mint_skip_crypto_get())` is provably never true
 * and every height runs REAL crypto — byte-identical to today. The setter is
 * called ONLY from the mint driver TUs (engine/composition/src/boot_mint_anchor.c via
 * engine/composition/src/boot_refold_staged.c::boot_mint_anchor_reset), gated under
 * ctx->mint_anchor, and the -mint-anchor process is a one-shot that never
 * starts P2P/RPC and _exit()s after the mint. Enforced by the lint gate
 * tools/lint/check_mint_skip_crypto_offline_only.sh + test_mint_skip_crypto.
 *
 * This module changes NO validation rule for a running node — it only controls
 * whether the offline mint re-derives the (already-once-validated) crypto
 * verdict while producing a fingerprint-certified set.
 */

#ifndef ZCL_JOBS_MINT_SKIP_CRYPTO_H
#define ZCL_JOBS_MINT_SKIP_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

/* Exact durable success evidence carried between the crypto/state stages.
 * INVALID includes missing/non-TEXT/unknown/embedded-NUL values. */
enum mint_validation_evidence {
    MINT_VALIDATION_EVIDENCE_INVALID = 0,
    MINT_VALIDATION_EVIDENCE_VERIFIED,
    MINT_VALIDATION_EVIDENCE_CHECKPOINT_FOLD,
};

enum mint_validation_evidence mint_validation_evidence_parse(
    const void *bytes, size_t size);
enum mint_validation_evidence mint_validation_evidence_expected(bool skip);
const char *mint_validation_evidence_status(
    enum mint_validation_evidence evidence);

/* Set the OFFLINE FAST-MINT crypto pass-through. true => script_validate and
 * proof_validate skip their per-block crypto and write a checkpoint_fold row.
 * ONLY the -mint-anchor driver (gated under ctx->mint_anchor) calls this; a
 * normal boot never does. */
void mint_skip_crypto_set(bool skip);

/* Read the toggle. Cheap atomic read — safe from any stage thread. Returns
 * false (run REAL crypto) when unset (the default). */
bool mint_skip_crypto_get(void);

#endif /* ZCL_JOBS_MINT_SKIP_CRYPTO_H */
