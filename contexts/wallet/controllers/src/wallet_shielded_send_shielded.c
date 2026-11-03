/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * z_sendmany shielded-spend branch (z->z, z->t): spend selected notes,
 * build spend/output descriptions, sign, and broadcast. */

#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_activity.h"
#include "controllers/wallet_spend_gate.h"
#include "controllers/wallet_private_broadcast.h"
#include "jobs/reducer_frontier.h"
#include "validation/chainstate.h"
#include "wallet/wallet_lock.h"
#include "services/sapling_tip_root_blocker.h"
#include "util/blocker.h"

/* Select notes until the running total covers target; returns the running
 * total through notes_total and the selected count through num_sel_notes. */
static void z_sendmany_shielded_select_notes(
    const struct db_sapling_note *notes, int num_notes, int64_t target,
    struct db_sapling_note *selected_notes, size_t *num_sel_notes,
    int64_t *notes_total)
{
        for (int i = 0; i < num_notes; i++) {
            selected_notes[(*num_sel_notes)++] = notes[i];
            *notes_total += notes[i].value;
            if (*notes_total >= target) break;
        }
}

/* The one test of a note's stored witness, used by z_sendmany and the wallet
 * summary; the depth rule is wallet_note_classify, applied by both. Returns 0 when the witness is present, at the authoritative
 * tip and deserializes; 1 when missing; 2 when stale (*height is the stored
 * witness height); 3 when it cannot be deserialized. The decoded witness goes
 * to `out` when it is not NULL. */
int wallet_note_witness_status(struct node_db *ndb, const uint8_t txid[32],
                               uint32_t output_index, int authoritative_tip,
                               struct incremental_witness *out, int *height)
{
    struct incremental_witness scratch;
    struct incremental_merkle_tree dummy_tree;
    uint8_t *wblob = NULL;
    size_t wlen = 0;
    int wheight = 0;

    if (!db_sapling_note_load_witness(ndb, txid, output_index, &wblob, &wlen,
                                      &wheight) || !wblob)
        return 1;
    if (height)
        *height = wheight;
    if (wheight != authoritative_tip) {
        free(wblob);
        return 2;
    }
    sapling_tree_init(&dummy_tree);
    struct byte_stream ws;
    stream_init_from_data(&ws, wblob, wlen);
    bool ok = incremental_witness_deserialize(
        out ? out : &scratch, &ws, SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
        dummy_tree.combine, dummy_tree.uncommitted);
    free(wblob);
    return ok ? 0 : 3;
}

enum {
    Z_SENDMANY_WITNESS_TREE_UNVERIFIED = 4,
    Z_SENDMANY_WITNESS_ROOT_MISMATCH = 5
};

/* Phone rule: a note witness root must equal the header Sapling root at the
 * witness height (the external tip). A mismatch would fail on the network;
 * refuse on the device before any proving. */
static bool z_sendmany_shielded_header_root_ok(
    const struct main_state *ms, int tip, struct incremental_witness *witness)
{
    struct uint256 root;
    incremental_witness_root(witness, &root);
    return wallet_spend_gate_witness_root_ok(ms, tip, root.data);
}

/* Load and deserialize the witness of every selected note. Returns 0 on
 * success; otherwise 1 (not available), 2 (stale) or 3 (deserialize failed),
 * (or Z_SENDMANY_WITNESS_ROOT_MISMATCH under the phone rule: a witness root
 * differs from the header root),
 * with the failing note index in *fail_i and, for 2 (stale) only, the
 * stored witness height in *fail_height.
 * On failure the witnesses array is already freed. */
static int z_sendmany_shielded_load_witnesses(
    struct wallet_rpc_context *ctx,
    const struct db_sapling_note *selected_notes, size_t num_sel_notes,
    struct incremental_witness *witnesses,
    int authoritative_tip, size_t *fail_i, int *fail_height,
    const struct main_state *ms, int32_t spend_floor)
{
        for (size_t i = 0; i < num_sel_notes; i++) {
            int wheight = 0;
            int st = wallet_note_witness_status(
                ctx->node_db, selected_notes[i].txid,
                selected_notes[i].output_index, authoritative_tip,
                &witnesses[i], &wheight);
            if (st != 0) {
                free(witnesses);
                *fail_i = i;
                if (st == 2)
                    *fail_height = wheight;
                return st;
            }
            if (spend_floor != WALLET_SPEND_NO_FLOOR &&
                !z_sendmany_shielded_header_root_ok(ms, authoritative_tip,
                                                    &witnesses[i])) {
                free(witnesses);
                *fail_i = i;
                return Z_SENDMANY_WITNESS_ROOT_MISMATCH;
            }
        }
        return 0;
}

/* The refusal text for a witness load status, NULL when the load succeeded. */
static const char *z_sendmany_shielded_witness_refusal(int wstat)
{
    switch (wstat) {
    case 1: return "Witness not available (run rescanwitnesses)";
    case 2: return "Witness stale (run rescanwitnesses)";
    case 3: return "Failed to deserialize witness";
    case Z_SENDMANY_WITNESS_TREE_UNVERIFIED:
        return "Shielded spends are refused: the block index has no Sapling "
               "root at the tip";
    case Z_SENDMANY_WITNESS_ROOT_MISMATCH:
        return "Error: spend refused — spend-after-checkpoint check failed: "
               "anchor_root_mismatch";
    default: return NULL;
    }
}

/* Return the index of the first witness (from 1) whose root differs from the
 * anchor, storing that root in wroot; returns 0 when all roots match. */
static size_t z_sendmany_shielded_first_root_mismatch(
    struct incremental_witness *witnesses, size_t num_sel_notes,
    const uint8_t *anchor, struct uint256 *wroot)
{
        for (size_t vi = 1; vi < num_sel_notes; vi++) {
            incremental_witness_root(&witnesses[vi], wroot);
            if (memcmp(wroot->data, anchor, 32) != 0)
                return vi;
        }
        return 0;
}

/* Build one spend description per selected note. Returns an error string or
 * NULL on success. */
static const char *z_sendmany_shielded_build_spends(
    struct wallet_tx *wtx, void *proving_ctx,
    const struct sapling_key_entry *from_z_key,
    const struct db_sapling_note *selected_notes, size_t num_sel_notes,
    struct incremental_witness *witnesses, const uint8_t *anchor,
    uint8_t (*spend_ars)[32])
{
        const char *spend_err = NULL;

        for (size_t i = 0; i < num_sel_notes; i++) {
            struct spend_description *sd = &wtx->tx.v_shielded_spend[i];

            uint8_t witness_path[1 + 32 * 33];
            size_t witness_path_len = 0;
            if (!incremental_witness_merkle_path(&witnesses[i],
                    witness_path, &witness_path_len)) {
                spend_err = "Failed to extract Merkle path";
                break;
            }

            uint64_t position = incremental_tree_size(&witnesses[i].tree) - 1;

            if (!sapling_build_spend_with_ctx(
                    proving_ctx,
                    from_z_key->xsk.expsk.ask,
                    from_z_key->xsk.expsk.nsk,
                    selected_notes[i].diversifier,
                    selected_notes[i].pk_d,
                    selected_notes[i].rcm,
                    (uint64_t)selected_notes[i].value,
                    position,
                    anchor,
                    witness_path, witness_path_len,
                    sd->cv.data, sd->nullifier.data,
                    sd->rk.data, sd->zkproof,
                    spend_ars[i])) {
                spend_err = "Failed to build spend proof (anchor mismatch?)";
                break;
            }

            memcpy(sd->anchor.data, anchor, 32);
        }
        return spend_err;
}

/* Build the shielded output descriptions (recipients plus change). Returns an
 * error string or NULL on success. */
static const char *z_sendmany_shielded_build_outputs(
    struct wallet_tx *wtx, void *proving_ctx,
    const struct sapling_key_entry *from_z_key,
    const uint8_t (*z_diversifiers)[11], const uint8_t (*z_pk_ds)[32],
    const int64_t *z_amounts, const uint8_t (*z_memos)[512],
    const bool *z_has_memo, size_t num_z_out,
    int64_t shielded_change, size_t total_z_outs)
{
        const char *spend_err = NULL;

            wtx->tx.v_shielded_output = zcl_calloc(total_z_outs,
                sizeof(struct output_description), "shielded_outputs");
            if (!wtx->tx.v_shielded_output) {
                /* leave num_shielded_output 0; shielded_cleanup frees
                 * proving_ctx/witnesses/tx and reports the error. */
                wtx->tx.num_shielded_output = 0;
                spend_err = "Out of memory (shielded outputs)";
                return spend_err;
            }
            wtx->tx.num_shielded_output = total_z_outs;

            uint8_t ovk[32];
            memcpy(ovk, from_z_key->xfvk.fvk.ovk, 32);

            for (size_t i = 0; i < num_z_out && !spend_err; i++) {
                struct output_description *od = &wtx->tx.v_shielded_output[i];
                if (!sapling_build_output_with_ctx(
                        proving_ctx, ovk,
                        z_diversifiers[i], z_pk_ds[i],
                        (uint64_t)z_amounts[i],
                        z_has_memo[i] ? z_memos[i] : NULL,
                        od->cv.data, od->cm.data, od->ephemeral_key.data,
                        od->enc_ciphertext, od->out_ciphertext, od->zkproof))
                    spend_err = "Failed to build Sapling output";
            }

            if (!spend_err && shielded_change > 0) {
                struct output_description *od =
                    &wtx->tx.v_shielded_output[num_z_out];
                if (!sapling_build_output_with_ctx(
                        proving_ctx, ovk,
                        from_z_key->diversifier, from_z_key->pk_d,
                        (uint64_t)shielded_change, NULL,
                        od->cv.data, od->cm.data, od->ephemeral_key.data,
                        od->enc_ciphertext, od->out_ciphertext, od->zkproof))
                    spend_err = "Failed to build change output";
            }
        return spend_err;
}

/* The witnesses must all produce one anchor, and that anchor must be the
 * Sapling root the chain's own header at the authoritative tip commits to. A
 * zero or missing header root cannot vouch for a witness. Returns the refusal
 * text or NULL, and sets anchor on success. */
static const char *z_sendmany_shielded_anchor_refusal(
    const struct wallet_rpc_context *ctx,
    struct incremental_witness *witnesses, size_t num, int tip,
    uint8_t anchor[32])
{
    static const uint8_t zeros[32] = {0};
    struct uint256 w0root, wroot;
    incremental_witness_root(&witnesses[0], &w0root);
    memcpy(anchor, w0root.data, 32);
    if (z_sendmany_shielded_first_root_mismatch(witnesses, num, anchor,
                                                &wroot) != 0)
        return "Witness roots inconsistent (run rescanwitnesses)";
    const struct block_index *bi = ctx->main_state && tip >= 0
        ? active_chain_at(&ctx->main_state->chain_active, tip) : NULL;
    if (!bi || memcmp(bi->hashFinalSaplingRoot.data, zeros, 32) == 0)
        return "Shielded spend refused: the chain has no Sapling root at the "
               "tip to check the witnesses against";
    if (memcmp(bi->hashFinalSaplingRoot.data, anchor, 32) != 0)
        return "Shielded spend refused: the witness root does not match the "
               "chain's Sapling root at the tip (run rescanwitnesses)";
    return NULL;
}

const char *z_sendmany_shielded_witness_gate(
    struct wallet_rpc_context *ctx, const struct db_sapling_note *selected,
    size_t num, int authoritative_tip,
    struct incremental_witness **witnesses_out, uint8_t anchor[32],
    size_t *fail_i, int *fail_height, int32_t spend_floor)
{
    *witnesses_out = NULL;
    if (blocker_exists(BLOCKER_ID_SAPLING_TIP_ROOT_MISSING))
        return z_sendmany_shielded_witness_refusal(
            Z_SENDMANY_WITNESS_TREE_UNVERIFIED);
    struct incremental_witness *witnesses = zcl_calloc(
        num, sizeof(struct incremental_witness), "sapling_witnesses");
    if (!witnesses)
        return "Out of memory";
    int wstat = z_sendmany_shielded_load_witnesses(
        ctx, selected, num, witnesses, authoritative_tip, fail_i, fail_height,
        ctx->main_state, spend_floor);
    if (wstat == Z_SENDMANY_WITNESS_ROOT_MISMATCH)
        sovereignty_spend_rule_note_verdict("anchor_root_mismatch");
    if (wstat != 0)
        return z_sendmany_shielded_witness_refusal(wstat);
    const char *refusal = z_sendmany_shielded_anchor_refusal(
        ctx, witnesses, num, authoritative_tip, anchor);
    if (refusal) {
        free(witnesses);
        return refusal;
    }
    *witnesses_out = witnesses;
    return NULL;
}

/* value_balance = sum(spend) - sum(output) */
static int64_t z_sendmany_shielded_value_balance(
    const struct db_sapling_note *selected_notes, size_t num_sel_notes,
    const int64_t *z_amounts, size_t num_z_out, int64_t shielded_change)
{
            int64_t spend_total = 0;
            for (size_t i = 0; i < num_sel_notes; i++)
                spend_total += selected_notes[i].value;
            int64_t output_total = 0;
            for (size_t i = 0; i < num_z_out; i++)
                output_total += z_amounts[i];
            if (shielded_change > 0)
                output_total += shielded_change;
            return spend_total - output_total;
}

/* Compute the sighash and produce the spend-auth and binding signatures.
 * Returns an error string or NULL on success. */
static const char *z_sendmany_shielded_sign(
    struct wallet_tx *wtx, void *proving_ctx,
    const struct sapling_key_entry *from_z_key, const struct chain_params *cp,
    int height, size_t num_sel_notes, uint8_t (*spend_ars)[32])
{
        const char *spend_err = NULL;
            uint32_t branch_id = consensus_current_epoch_branch_id(
                height + 1, &cp->consensus);
            struct sighash_type ht;
            ht.raw = SIGHASH_ALL;
            struct precomputed_tx_data txdata;
            precompute_tx_data(&wtx->tx, &txdata);

            struct script empty_script;
            empty_script.size = 0;
            struct uint256 sighash;
            if (!signature_hash(&empty_script, &wtx->tx, NOT_AN_INPUT, ht, 0,
                                branch_id, &txdata, &sighash))
                spend_err = "Binding sighash computation failed";

            for (size_t i = 0; i < num_sel_notes && !spend_err; i++) {
                /* rsk = ask + ar in Jubjub scalar field (Fs, NOT Fr).
                 * ask and ar are Fs scalars — using Fr addition would
                 * produce a wrong result since Fr.p != Fs.p. */
                uint8_t rsk[32];
                struct fs ask_fs, ar_fs, rsk_fs;
                fs_from_bytes(&ask_fs, from_z_key->xsk.expsk.ask);
                fs_from_bytes(&ar_fs, spend_ars[i]);
                fs_add(&rsk_fs, &ask_fs, &ar_fs);
                fs_to_bytes(rsk, &rsk_fs);
                memory_cleanse(&ask_fs, sizeof(ask_fs));
                memory_cleanse(&ar_fs, sizeof(ar_fs));
                memory_cleanse(&rsk_fs, sizeof(rsk_fs));

                if (!redjubjub_sign(rsk, sighash.data, 32,
                                    wtx->tx.v_shielded_spend[i].spend_auth_sig,
                                    5 /* GEN_SPENDING_KEY */))
                    spend_err = "Spend auth signature failed";
                memory_cleanse(rsk, 32);
            }

            if (!spend_err &&
                !zclassic_sapling_binding_sig(proving_ctx,
                    wtx->tx.value_balance, sighash.data, wtx->tx.binding_sig))
                spend_err = "Binding signature failed";
        return spend_err;
}

/* Load the key's unspent notes, reconcile them with the canonical chain and
 * keep the ones the wallet summary calls spendable. Returns the count, or -1
 * with the error set on result. */
static int z_sendmany_shielded_load_notes(
    struct wallet_rpc_context *ctx, const struct chain_params *cp,
    const struct sapling_key_entry *from_z_key, int min_conf, int32_t spend_floor,
    struct db_sapling_note *notes, struct json_value *result)
{
    if (min_conf < 0) {
        json_set_str(result, "Invalid minconf");
        LOG_ERR("wallet_shielded", "z_sendmany: invalid minconf");
    }
    /* Preserve the precise view-only/no-funds diagnostic before requiring
     * live chain authority. This is only a capability probe; actual coin
     * selection re-reads the notes after canonical reconciliation. */
    int num_notes = db_sapling_note_list_unspent_for_ivk(
        ctx->node_db, from_z_key->ivk, notes, 256);
    if (num_notes <= 0) {
        char from_addr[128] = "";
        if (sapling_encode_payment_address(
                from_z_key->diversifier, from_z_key->pk_d,
                cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                from_addr, sizeof(from_addr)) &&
            db_sapling_note_count_unspent_view_for_address(
                ctx->node_db, from_addr) > 0) {
            json_set_str(result,
                         "view-only balance synced from zclassicd");
            LOG_ERR("wallet_shielded",
                     "z_sendmany: view-only zclassicd balance is not spendable");
        }
        json_set_str(result, "No unspent shielded notes for this address");
        LOG_ERR("wallet_shielded", "z_sendmany: no unspent notes for from z-address");
    }

    size_t reconciled = 0;
    if (!node_db_reconcile_canonical_sapling_notes(
            ctx->node_db, ctx->main_state, ctx->datadir, &reconciled)) {
        json_set_str(result,
                     "Canonical shielded note state is unavailable");
        LOG_ERR("wallet_shielded",
                 "z_sendmany: canonical note reconciliation failed");
    }
    num_notes = db_sapling_note_list_unspent_for_ivk(
        ctx->node_db, from_z_key->ivk, notes, 256);
    if (num_notes <= 0) {
        json_set_str(result, "No unspent shielded notes for this address");
        LOG_ERR("wallet_shielded",
                 "z_sendmany: no notes remain after canonical reconciliation");
    }

    /* The inputs are the notes the wallet summary calls spendable
     * (wallet_note_is_spendable), taken before the per-send cap, with
     * min_conf as an extra confirmation floor: a note that fails is
     * skipped, so the send accepts what the summary reports. */
    num_notes = wallet_send_spendable_notes(
        ctx, from_z_key->ivk, min_conf, spend_floor, notes,
        WALLET_SEND_MAX_NOTES);
    if (num_notes < 0) {
        json_set_str(result, "Spendable note state is unavailable");
        LOG_ERR("wallet_shielded",
                 "z_sendmany: spendable note filter failed");
    }
    /* Phone rule: the loader above dropped every note received at or below
     * the floor, before the 256-note cap. */
    if (num_notes == 0 && spend_floor != WALLET_SPEND_NO_FLOOR) {
        json_set_str(result, wallet_spend_gate_no_notes_text(spend_floor));
        LOG_ERR("wallet_shielded",
                 "z_sendmany: no notes remain above the spend floor");
    }
    return num_notes;
}

/* Check the wallet database, load and select the spendable notes covering the
 * target plus fee, and refuse when proving is unavailable. */
static bool z_sendmany_shielded_select_inputs(
    struct wallet_rpc_context *ctx, const struct chain_params *cp,
    const struct sapling_key_entry *from_z_key, int64_t total_amount,
    int min_conf, int32_t spend_floor,
    struct db_sapling_note selected_notes[256], size_t *num_sel_notes,
    int64_t *notes_total, int64_t *fee, struct json_value *result)
{
        *num_sel_notes = 0;
        *notes_total = 0;
        *fee = 0;

        if (!wallet_ctx_db_ready(ctx)) {
            json_set_str(result,
                         "Shielded wallet database is unavailable; send aborted");
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: shielded spend requires an open node.db");
            return false;
        }

        *fee = ctx->wallet->default_fee;

        struct db_sapling_note notes[256];
        int num_notes = z_sendmany_shielded_load_notes(
            ctx, cp, from_z_key, min_conf, spend_floor, notes, result);
        if (num_notes < 0)
            return false;

        /* Coin selection: pick notes until we have enough */
        z_sendmany_shielded_select_notes(notes, num_notes, total_amount + *fee,
                                         selected_notes, num_sel_notes,
                                         notes_total);
        if (*notes_total < total_amount + *fee)
            return wallet_spend_gate_short_funds(
                result, spend_floor, total_amount + *fee, *notes_total,
                "shielded", "Insufficient shielded funds");

        /* Wallet proving is a capability, not an assumption. The backend is
         * exposed only after a real Spend + Output + binding bundle passes the
         * independent consensus verifier at parameter-load time. Note lookup
         * above is read-only and preserves the more specific no-funds/view-only
         * diagnostics; fail here before witness/proof work or spent-state
         * mutation. */
        if (!sapling_proving_available()) {
            char err[320];
            snprintf(err, sizeof(err),
                     "Shielded proving unavailable (backend=%s, status=%s)",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
            json_set_str(result, err);
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: refusing shielded spend: backend=%s status=%s",
                         zclassic_sapling_prover_backend(),
                         zclassic_sapling_prover_status());
            return false;
        }
        return true;
}

/* Initialise the transaction, fill its transparent outputs, and set up the
 * proving context and spend-description array. */
static bool z_sendmany_shielded_prepare_tx_and_prover(
    struct wallet_tx *wtx, struct incremental_witness *witnesses,
    const struct tx_destination *t_dests, const int64_t *t_amounts,
    size_t num_t_out, size_t num_z_out, size_t num_sel_notes, int height,
    void **proving_ctx, struct json_value *result)
{
        *proving_ctx = NULL;
        memset(wtx, 0, sizeof(*wtx));
        transaction_init(&wtx->tx);

        wtx->tx.overwintered = true;
        wtx->tx.version = SAPLING_TX_VERSION;
        wtx->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        wtx->tx.expiry_height = (uint32_t)(height + 20);

        /* Allocate transparent outputs if any */
        size_t total_t_out_shielded = num_t_out;
        if (total_t_out_shielded > 0 || num_z_out > 0) {
            if (!transaction_alloc(&wtx->tx, 0, total_t_out_shielded)) {
                free(witnesses);
                json_set_str(result, "Transaction allocation failed");
                LOG_ERROR_IN("z_sendmany_shielded_with_key",
                             "wallet_shielded",
                             "z_sendmany: transaction_alloc failed for %zu t-outputs (shielded path)",
                             total_t_out_shielded);
                return false;
            }
        }

        /* Fill transparent outputs (for z→t) */
        for (size_t i = 0; i < num_t_out; i++) {
            struct script dest_script;
            script_for_destination(&dest_script, &t_dests[i]);
            wtx->tx.vout[i].value = t_amounts[i];
            wtx->tx.vout[i].script_pub_key = dest_script;
        }

        /* Init proving context */
        *proving_ctx = zclassic_sapling_proving_ctx_init();
        if (!*proving_ctx) {
            free(witnesses);
            transaction_free(&wtx->tx);
            char err[320];
            snprintf(err, sizeof(err),
                     "Failed to init proving context (backend=%s, status=%s)",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
            json_set_str(result, err);
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: sapling_proving_ctx_init failed (shielded spend path)");
            return false;
        }

        /* Build spend descriptions */
        wtx->tx.v_shielded_spend = zcl_calloc(num_sel_notes, sizeof(struct spend_description), "shielded_spends");
        if (!wtx->tx.v_shielded_spend) {
            /* num_shielded_spend left 0 so transaction_free won't walk a NULL
             * array. proving_ctx was init'd above; free it too. */
            zclassic_sapling_proving_ctx_free(*proving_ctx);
            free(witnesses);
            transaction_free(&wtx->tx);
            json_set_str(result, "Out of memory (shielded spends)");
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: calloc v_shielded_spend failed for %zu notes",
                         num_sel_notes);
            return false;
        }
        wtx->tx.num_shielded_spend = num_sel_notes;
        return true;
}

/* Commit the signed transaction, persist it, reserve the spent notes and
 * relay it; sets the txid on result on success. */
static bool z_sendmany_shielded_commit_and_relay(
    struct wallet_rpc_context *ctx, struct wallet_tx *wtx,
    struct json_value *result)
{
        /* The old shielded-spend branch bypassed every mempool check with
         * tx_mempool_add_unchecked(), ignored its return, and marked notes
         * spent even when admission failed. Use the same consensus gate and
         * rollback contract as every transparent wallet send. */
        struct zcl_result commit = wallet_commit_from_context(ctx, wtx);
        if (!commit.ok) {
            transaction_free(&wtx->tx);
            json_set_str(result, commit.message);
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: shielded commit rejected (code=%d): %s",
                         commit.code, commit.message);
            return false;
        }

        /* Persist the wallet transaction through node.db's single-writer lane
         * before network relay. A failed durability step unwinds wallet and
         * mempool state. */
        struct zcl_result persisted =
            wallet_persist_commit_before_relay(ctx, wtx);
        if (!persisted.ok) {
            transaction_free(&wtx->tx);
            json_set_str(result, persisted.message);
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: pre-relay durability failed (code=%d): %s",
                         persisted.code, persisted.message);
            return false;
        }

        /* Reserve the selected notes before broadcast — by their
         * stored nullifier, keyed to the new txid — both in SQLite (so the next
         * db_sapling_note_list_unspent_for_ivk selection excludes them) and in
         * the in-memory wallet. Without this, a second z_sendmany issued before
         * this tx confirms re-selects the SAME notes and produces a conflicting
         * transaction (double-spend of the user's own notes), so neither send
         * confirms and the funds appear stuck. This mirrors the transparent
         * path, which marks UTXOs spent at broadcast (wallet_commit_transaction
         * + node_db_sync_wallet_tx). */
        if (!node_db_sync_wallet_sapling_spends(ctx->node_db, &wtx->tx)) {
            struct zcl_result compensated =
                wallet_rollback_persisted_commit(ctx, wtx);
            transaction_free(&wtx->tx);
            if (!compensated.ok) {
                json_set_str(result, compensated.message);
                LOG_ERROR_IN("z_sendmany_shielded_with_key",
                             "wallet_shielded",
                             "z_sendmany: note reservation and durable compensation "
                             "failed (code=%d): %s",
                             compensated.code, compensated.message);
                return false;
            }
            json_set_str(result, "Cannot reserve shielded notes; send aborted");
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: atomic wallet-note reservation failed");
            return false;
        }
        if (ctx->wallet)
            wallet_mark_sapling_nullifiers_spent(ctx->wallet, &wtx->tx);

        /* node.db's wallet projection is rebuildable; report a write failure,
         * but the authoritative private wallet transaction + note reservation
         * are already durable before relay. */
        if (!node_db_sync_wallet_tx(ctx->node_db, &wtx->tx, ctx->wallet, 0))
            LOG_WARN_IN("z_sendmany_shielded_with_key",
                        "wallet_shielded",
                        "z_sendmany: wallet projection write failed after durable reservation");

        if (!wallet_send_relay(ctx, wtx)) {
            json_set_str(result, wallet_send_relay_failure_text());
            transaction_free(&wtx->tx);
            LOG_ERROR_IN("z_sendmany_shielded_with_key",
                         "wallet_shielded",
                         "z_sendmany: private broadcast not queued");
            return false;
        }

        char txid_hex[65];
        uint256_get_hex(&wtx->tx.hash, txid_hex);
        json_set_str(result, txid_hex);

        transaction_free(&wtx->tx);
        return true;
}

/* Body of the shielded spend. `from_z_key` is the caller's private copy of the
 * keystore entry, never a pointer into the keystore. */
static bool z_sendmany_shielded_with_key(
    struct wallet_rpc_context *ctx,
    const struct chain_params *cp,
    const struct sapling_key_entry *from_z_key,
    int64_t total_amount,
    const struct tx_destination *t_dests, const int64_t *t_amounts,
    size_t num_t_out,
    const uint8_t (*z_diversifiers)[11], const uint8_t (*z_pk_ds)[32],
    const int64_t *z_amounts, const uint8_t (*z_memos)[512],
    const bool *z_has_memo, size_t num_z_out, int min_conf,
    struct wallet_tx *prepared, struct json_value *result,
    int32_t spend_floor)
{
        struct db_sapling_note selected_notes[256];
        size_t num_sel_notes = 0;
        int64_t notes_total = 0;
        int64_t fee = 0;

        if (!z_sendmany_shielded_select_inputs(
                ctx, cp, from_z_key, total_amount, min_conf, spend_floor,
                selected_notes, &num_sel_notes, &notes_total, &fee, result))
            return false;

        /* Witnesses are maintained incrementally by connect_block and bulk_blocks.
         * The gate loads them at the authoritative tip and checks the anchor
         * they produce against the chain's own Sapling root. */
        uint8_t anchor[32];
        struct incremental_witness *witnesses = NULL;
        int authoritative_tip = reducer_frontier_external_tip_height();
        size_t i = 0;
        int wheight = 0;
        const char *wrefusal = z_sendmany_shielded_witness_gate(
            ctx, selected_notes, num_sel_notes, authoritative_tip,
            &witnesses, anchor, &i, &wheight, spend_floor);
        if (wrefusal) {
            json_set_str(result, wrefusal);
            LOG_FAIL("wallet_shielded", // wallet-log-ok:note-index-label
                     "z_sendmany: witness refused: %s height=%d "
                     "authoritative_tip=%d note=%zu",
                     wrefusal, wheight, authoritative_tip, i);
        }

        /* Build transaction */
        struct wallet_tx wtx;
        int height = ctx->wallet->best_block_height;

        void *proving_ctx = NULL;
        if (!z_sendmany_shielded_prepare_tx_and_prover(
                &wtx, witnesses, t_dests, t_amounts, num_t_out, num_z_out,
                num_sel_notes, height, &proving_ctx, result))
            return false;

        uint8_t spend_ars[256][32]; /* ar values for spend_auth_sig */

        const char *spend_err = NULL;

        spend_err = z_sendmany_shielded_build_spends(
            &wtx, proving_ctx, from_z_key, selected_notes, num_sel_notes,
            witnesses, anchor, spend_ars);

        if (spend_err) goto shielded_cleanup;

        /* Build shielded output descriptions */
        int64_t shielded_change = notes_total - total_amount - fee;
        size_t total_z_outs = num_z_out + (shielded_change > 0 ? 1 : 0);

        if (total_z_outs > 0)
            spend_err = z_sendmany_shielded_build_outputs(
                &wtx, proving_ctx, from_z_key, z_diversifiers, z_pk_ds,
                z_amounts, z_memos, z_has_memo, num_z_out, shielded_change,
                total_z_outs);

        if (spend_err) goto shielded_cleanup;

        /* Set value_balance = sum(spend) - sum(output) */
        wtx.tx.value_balance = z_sendmany_shielded_value_balance(
            selected_notes, num_sel_notes, z_amounts, num_z_out,
            shielded_change);

        /* Compute sighash for spend_auth_sig and binding_sig */
        transaction_compute_hash(&wtx.tx);

        spend_err = z_sendmany_shielded_sign(&wtx, proving_ctx, from_z_key, cp,
                                             height, num_sel_notes, spend_ars);

shielded_cleanup:
        zclassic_sapling_proving_ctx_free(proving_ctx);
        memory_cleanse(spend_ars, sizeof(spend_ars));

        if (spend_err) {
            free(witnesses);
            transaction_free(&wtx.tx);
            json_set_str(result, spend_err);
            LOG_FAIL("wallet_shielded", "z_sendmany: shielded spend failed: %s", spend_err);
        }

        free(witnesses);

        /* Broadcast */
        transaction_compute_hash(&wtx.tx);
        wtx.time_received = GetTime();
        wtx.from_me = true;
        wtx.used = true;

        if (prepared) {
            *prepared = wtx;
            return true;
        }

        return z_sendmany_shielded_commit_and_relay(ctx, &wtx, result);
}

/* Shielded-spend path (from-address is a zaddr): spend selected notes,
 * build spend/output descriptions, sign, broadcast. Recipients have
 * already been parsed into the transparent/shielded output arrays by
 * the caller. Returns
 * true on success (txid set on result) or false on error (error string
 * set on result).
 *
 * `from_z_key` points into the keystore. The wallet can lock at any moment,
 * which cleanses the entry's spending key in place, so this copies the entry
 * under the keystore mutex before any proof work and signs only with the copy.
 * The mutex is not held across proving. The copy is cleansed on every exit. */
bool z_sendmany_shielded(
    struct wallet_rpc_context *ctx,
    const struct chain_params *cp,
    const struct sapling_key_entry *from_z_key,
    int64_t total_amount,
    const struct tx_destination *t_dests, const int64_t *t_amounts,
    size_t num_t_out,
    const uint8_t (*z_diversifiers)[11], const uint8_t (*z_pk_ds)[32],
    const int64_t *z_amounts, const uint8_t (*z_memos)[512],
    const bool *z_has_memo, size_t num_z_out, int min_conf,
    struct wallet_tx *prepared, struct json_value *result,
    int32_t spend_floor)
{
    struct sapling_key_entry key_copy;
    if (!ctx || !ctx->wallet ||
        !sapling_keystore_copy_entry(&ctx->wallet->sapling_keys, from_z_key,
                                     &key_copy)) {
        bool locked = !ctx || !ctx->wallet || wallet_lock_is_locked();
        json_set_str(result, locked
            ? "Error: wallet is locked - run walletunlock before spending"
            : "Error: the spending key for this address could not be "
              "decrypted (damaged stored key); funds at other addresses "
              "are unaffected");
        LOG_FAIL("wallet_shielded",
                 "z_sendmany: refused, spending key not resident (%s)",
                 locked ? "wallet locked" : "stored key unreadable");
    }
    bool ok = z_sendmany_shielded_with_key(
        ctx, cp, &key_copy, total_amount, t_dests, t_amounts, num_t_out,
        z_diversifiers, z_pk_ds, z_amounts, z_memos, z_has_memo, num_z_out,
        min_conf, prepared, result, spend_floor);
    memory_cleanse(&key_copy, sizeof(key_copy));
    return ok;
}
