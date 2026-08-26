/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ContextualCheckTransaction — height-aware transaction validation.
 * 16 checks matching zclassicd main.cpp:935-1098 exactly.
 *
 * Verifies: network upgrade rules, expiry, JoinSplit signatures,
 * Sapling Groth16 proofs, Sprout proofs, binding signatures. */

#include "validation/contextual_check_tx.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "domain/consensus/sapling_structural.h"
#include "validation/sighash.h"
#include "crypto/ed25519.h"
#include "sapling/sapling.h"
#include "sapling/sprout.h"
#include "sapling/bn254.h"
#include "core/serialize.h"
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"

/* Default: -1 (verify everything). Set by boot.c from -deferproofvalidationbelow flag. */
_Atomic int g_deferred_proof_validation_below_height = -1;

/* Convenience: REJECT_IF with variable DoS level (many checks use dosLevel) */
#define REJECT_IF_DOS(cond, state, dos, reason) \
    REJECT_IF(cond, state, dos, reason)

/* Would this transaction's shielded components be proof-verified at
 * nHeight, i.e. does the deferral policy leave the expensive checks on? */
static bool proofs_are_in_scope(const struct transaction *tx, int nHeight)
{
    if (g_deferred_proof_validation_below_height >= 0 &&
        nHeight <= g_deferred_proof_validation_below_height)
        return false;
    return tx->num_joinsplit > 0 || tx->num_shielded_spend > 0 ||
           tx->num_shielded_output > 0;
}

bool contextual_check_tx_proofs_unverifiable(const struct transaction *tx,
                                             int nHeight)
{
    if (!tx || !proofs_are_in_scope(tx, nHeight))
        return false;

    /* Sapling spend/output proofs and Sprout Groth16 JoinSplit proofs are
     * all gated by the one params_loaded latch (params_init.c installs
     * sapling_spend_vk, sapling_output_vk and the sprout Groth16 VK
     * together and clears them together). */
    if (!sapling_params_loaded())
        return true;

    /* PHGR13 is NOT covered by that latch. Its key is a separate file and,
     * off mainnet, params_init.c publishes params_loaded==true even when
     * sprout-verifying.key failed to load. A pre-Sapling JoinSplit would
     * then fail-close on a NULL phgr_vk and read as a forged proof. */
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        if (!tx->v_joinsplit[i].use_groth && !sprout_phgr_vk_loaded())
            return true;
    }
    return false;
}

/* The original body, unchanged in every consensus respect. Returns false
 * for BOTH a genuine reject and a local inability to check; the two local
 * sites set *local_fault so the typed wrapper can tell them apart.
 *
 * NOTE: this stays a bool-returning function on purpose. The REJECT_IF /
 * REJECT_UNLESS macros expand to `return validation_state_dos(...)`, which
 * yields `false`. In an enum-returning function that `false` would silently
 * convert to 0 == CONTEXTUAL_CHECK_PASS and turn every macro reject into an
 * ACCEPT. Keeping the macros inside a bool function makes that mistake
 * unrepresentable. */
static bool contextual_check_transaction_impl(
                                   const struct transaction *tx,
                                   struct validation_state *state,
                                   const struct consensus_params *params,
                                   int nHeight,
                                   int dosLevel,
                                   bool *local_fault)
{
    *local_fault = false;

    /* ── Pure height-aware Sapling/Overwinter structural checks ──
     * Delegates to domain/consensus/sapling_structural. Translates
     * the typed zcl_result + (reject_reason, dos) pair back into the
     * legacy `validation_state` byte-identically (reject_reason
     * strings and DoS scores are tx-relay-visible). Mirrors the
     * REJECT_IF/REJECT_IF_DOS expansion exactly: each macro called
     * validation_state_dos(state, dos, false, REJECT_INVALID, reason,
     * false, NULL). */
    {
        struct domain_consensus_sapling_structural_failure f = {0};
        struct zcl_result r =
            domain_consensus_check_transaction_sapling_structural(
                tx, params, nHeight, dosLevel, &f);
        if (!r.ok) {
            const char *reason = f.reject_reason ? f.reject_reason : "";
            return validation_state_dos(state, f.dos, false, REJECT_INVALID,
                                        reason, false, NULL);
        }
    }

    /* ── Overwinter expiry (uses domain locktime predicate) ───
     * Left in the wrapper because the dosLevel branch depends on
     * is_expired_tx(tx, nHeight - 1), which composes the pure
     * locktime predicate with caller context. Reject string and
     * DoS-score branching are byte-identical to the legacy code.
     *
     * Reads consensus_network_upgrade_active lazily so we don't
     * compute it on every tx — only the post-Overwinter expiry path
     * needs it now. */
    bool overwinterActive = consensus_network_upgrade_active(
        params, nHeight, UPGRADE_OVERWINTER);
    if (overwinterActive) {
        if (is_expired_tx(tx, nHeight)) {
            int expiredDosLevel = is_expired_tx(tx, nHeight - 1) ? dosLevel : 0;
            REJECT_IF_DOS(true, state, expiredDosLevel, "tx-overwinter-expired");
        }
    }

    /* ── Defer expensive shielded proofs below the local policy height ── */
    bool skip_proofs = (g_deferred_proof_validation_below_height >= 0 &&
                        nHeight <= g_deferred_proof_validation_below_height);

    /* ── Can we actually CHECK the shielded proofs? ────────────────
     * Placed here deliberately: AFTER the structural and expiry rules, so
     * a transaction that is genuinely malformed or expired still earns a
     * real REJECT (we surrender no genuine verdict we were able to reach),
     * and BEFORE the sighash and proof arithmetic, so a node with no
     * verifying keys installed does strictly LESS work per shielded
     * transaction than it did before, not more.
     *
     * Without this the verifiers below fail-close on a NULL VK and the
     * result is byte-identical to a forged proof, so an honest peer
     * relaying a valid shielded transaction during our boot window was
     * charged ban-score for our missing keys. */
    if (contextual_check_tx_proofs_unverifiable(tx, nHeight)) {
        *local_fault = true;
        /* DoS score 0: any caller still reading state->dos rather than the
         * verdict must not be able to charge this to a peer either. */
        return validation_state_dos(state, 0, false, REJECT_INVALID,
                                    "shielded-verify-unavailable",
                                    false, NULL);
    }

    /* Compute sighash for shielded verification */
    struct uint256 data_to_be_signed;
    uint256_set_null(&data_to_be_signed);

    if (!skip_proofs &&
        (tx->num_joinsplit > 0 || tx->num_shielded_spend > 0 ||
         tx->num_shielded_output > 0))
    {
        uint32_t branch_id = consensus_current_epoch_branch_id(nHeight, params);
        struct script empty_script;
        empty_script.size = 0;
        struct sighash_type ht;
        ht.raw = 1; /* SIGHASH_ALL */
        /* Written out rather than REJECT_UNLESS so the local-fault flag is
         * set on the same edge that produces the reject. This call cannot be
         * steered by the sender: nIn is NOT_AN_INPUT (which bypasses the
         * range check) and hash_type is SIGHASH_ALL (which bypasses the
         * SIGHASH_SINGLE bound), so the only remaining failure modes are
         * ours. Same reason string and DoS score as before. */
        if (!signature_hash(&empty_script, tx, NOT_AN_INPUT, ht, 0,
                            branch_id, NULL, &data_to_be_signed)) {
            *local_fault = true;
            return validation_state_dos(state, 100, false, REJECT_INVALID,
                                        "error-computing-signature-hash",
                                        false, NULL);
        }
    }

    /* ── JoinSplit Ed25519 signature ────────────────────────── */
    if (!skip_proofs && tx->num_joinsplit > 0) {
        REJECT_UNLESS(ed25519_verify(tx->joinsplit_sig, data_to_be_signed.data,
                                     32, tx->joinsplit_pubkey.data),
                      state, 100, "bad-txns-joinsplit-signature");
    }

    /* ── Sapling Groth16 spend/output proofs + binding sig ──── */
    if (!skip_proofs &&
        (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0)) {
        /* zcl_calloc failure — memory pressure on THIS node, nothing the
         * sender did. Same reason string and DoS score as before; the flag
         * is what stops it being charged to the peer. */
        void *sctx = zclassic_sapling_verification_ctx_init();
        if (!sctx) {
            *local_fault = true;
            return validation_state_dos(state, 100, false, REJECT_INVALID,
                                        "sapling-verification-ctx-init-failed",
                                        false, NULL);
        }

        for (size_t i = 0; i < tx->num_shielded_spend; i++) {
            const struct spend_description *sd = &tx->v_shielded_spend[i];
            if (!zclassic_sapling_check_spend(
                    sctx, sd->cv.data, sd->anchor.data,
                    sd->nullifier.data, sd->rk.data,
                    sd->zkproof, sd->spend_auth_sig,
                    data_to_be_signed.data)) {
                zclassic_sapling_verification_ctx_free(sctx);
                return validation_state_dos(state, 100, false, REJECT_INVALID,
                    "bad-txns-sapling-spend-description-invalid", false, NULL);
            }
        }

        for (size_t i = 0; i < tx->num_shielded_output; i++) {
            const struct output_description *od = &tx->v_shielded_output[i];
            if (!zclassic_sapling_check_output(
                    sctx, od->cv.data, od->cm.data,
                    od->ephemeral_key.data, od->zkproof)) {
                zclassic_sapling_verification_ctx_free(sctx);
                return validation_state_dos(state, 100, false, REJECT_INVALID,
                    "bad-txns-sapling-output-description-invalid", false, NULL);
            }
        }

        if (!zclassic_sapling_final_check(
                sctx, tx->value_balance,
                tx->binding_sig, data_to_be_signed.data)) {
            zclassic_sapling_verification_ctx_free(sctx);
            return validation_state_dos(state, 100, false, REJECT_INVALID,
                "bad-txns-sapling-binding-sig-invalid", false, NULL);
        }

        zclassic_sapling_verification_ctx_free(sctx);
    }

    /* ── Sprout JoinSplit zk-SNARK proofs (Groth16 + PHGR13) ── */
    for (size_t i = 0; !skip_proofs && i < tx->num_joinsplit; i++) {
        const struct js_description *js = &tx->v_joinsplit[i];

        uint8_t h_sig[32];
        sprout_h_sig(js->random_seed.data, js->nullifiers[0].data,
                     js->nullifiers[1].data, tx->joinsplit_pubkey.data,
                     h_sig);

        if (js->use_groth) {
            REJECT_UNLESS(sprout_verify_groth16(js->proof,
                    js->anchor.data, h_sig,
                    js->macs[0].data, js->macs[1].data,
                    js->nullifiers[0].data, js->nullifiers[1].data,
                    js->commitments[0].data, js->commitments[1].data,
                    (uint64_t)js->vpub_old, (uint64_t)js->vpub_new),
                          state, 100, "bad-txns-joinsplit-proof-invalid");
        } else {
            REJECT_UNLESS(sprout_verify_phgr13(js->proof,
                    js->anchor.data, h_sig,
                    js->macs[0].data, js->macs[1].data,
                    js->nullifiers[0].data, js->nullifiers[1].data,
                    js->commitments[0].data, js->commitments[1].data,
                    (uint64_t)js->vpub_old, (uint64_t)js->vpub_new),
                          state, 100, "bad-txns-joinsplit-phgr13-invalid");
        }
    }

    return true;
}

enum contextual_check_verdict contextual_check_transaction_verdict(
                                   const struct transaction *tx,
                                   struct validation_state *state,
                                   const struct consensus_params *params,
                                   int nHeight,
                                   int dosLevel)
{
    bool local_fault = false;
    if (contextual_check_transaction_impl(tx, state, params, nHeight,
                                          dosLevel, &local_fault))
        return CONTEXTUAL_CHECK_PASS;

    return local_fault ? CONTEXTUAL_CHECK_UNVERIFIABLE
                       : CONTEXTUAL_CHECK_REJECT;
}

bool contextual_check_transaction(const struct transaction *tx,
                                   struct validation_state *state,
                                   const struct consensus_params *params,
                                   int nHeight,
                                   int dosLevel)
{
    return contextual_check_transaction_verdict(tx, state, params, nHeight,
                                                dosLevel)
           == CONTEXTUAL_CHECK_PASS;
}
