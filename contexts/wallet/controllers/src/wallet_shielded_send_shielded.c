/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * z_sendmany shielded-spend branch (z->z, z->t): spend selected notes,
 * build spend/output descriptions, sign, and broadcast. */

#include "controllers/wallet_shielded_internal.h"
#include "jobs/reducer_frontier.h"

/* Shielded-spend path (from-address is a zaddr): spend selected notes,
 * build spend/output descriptions, sign, broadcast. Recipients have
 * already been parsed into the transparent/shielded output arrays by
 * the caller. Returns
 * true on success (txid set on result) or false on error (error string
 * set on result). */
bool z_sendmany_shielded(
    struct wallet_rpc_context *ctx,
    const struct chain_params *cp,
    const struct sapling_key_entry *from_z_key,
    int64_t total_amount,
    const struct tx_destination *t_dests, const int64_t *t_amounts,
    size_t num_t_out,
    const uint8_t (*z_diversifiers)[11], const uint8_t (*z_pk_ds)[32],
    const int64_t *z_amounts, const uint8_t (*z_memos)[512],
    const bool *z_has_memo, size_t num_z_out,
    struct wallet_tx *prepared, struct json_value *result)
{
        if (!wallet_ctx_db_ready(ctx)) {
            json_set_str(result,
                         "Shielded wallet database is unavailable; send aborted");
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: shielded spend requires an open node.db");
        }

        int64_t fee = ctx->wallet->default_fee;

        /* Preserve the precise view-only/no-funds diagnostic before requiring
         * live chain authority. This is only a capability probe; actual coin
         * selection re-reads the notes after canonical reconciliation. */
        struct db_sapling_note notes[256];
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
                LOG_FAIL("wallet_shielded",
                         "z_sendmany: view-only zclassicd balance is not spendable");
            }
            json_set_str(result, "No unspent shielded notes for this address");
            LOG_FAIL("wallet_shielded", "z_sendmany: no unspent notes for from z-address");
        }

        size_t reconciled = 0;
        if (!node_db_reconcile_canonical_sapling_notes(
                ctx->node_db, ctx->main_state, ctx->datadir, &reconciled)) {
            json_set_str(result,
                         "Canonical shielded note state is unavailable");
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: canonical note reconciliation failed");
        }
        num_notes = db_sapling_note_list_unspent_for_ivk(
            ctx->node_db, from_z_key->ivk, notes, 256);
        if (num_notes <= 0) {
            json_set_str(result, "No unspent shielded notes for this address");
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: no notes remain after canonical reconciliation");
        }

        /* Coin selection: pick notes until we have enough */
        struct db_sapling_note selected_notes[256];
        size_t num_sel_notes = 0;
        int64_t notes_total = 0;
        for (int i = 0; i < num_notes; i++) {
            selected_notes[num_sel_notes++] = notes[i];
            notes_total += notes[i].value;
            if (notes_total >= total_amount + fee) break;
        }
        if (notes_total < total_amount + fee) {
            json_set_str(result, "Insufficient shielded funds");
            LOG_FAIL("wallet_shielded", "z_sendmany: insufficient shielded funds: have=%lld need=%lld",
                     (long long)notes_total, (long long)(total_amount + fee));
        }

        /* Wallet proving is a capability, not an assumption. The backend is
         * exposed only after a real Spend + Output + binding bundle passes the
         * independent consensus verifier at parameter-load time. Note lookup
         * above is read-only and preserves the more specific no-funds/view-only
         * diagnostics; fail here before witness/proof work or spent-state
         * mutation. */
        if (!zclassic_sapling_prover_is_ready()) {
            char err[320];
            snprintf(err, sizeof(err),
                     "Shielded proving unavailable (backend=%s, status=%s)",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
            json_set_str(result, err);
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: refusing shielded spend: backend=%s status=%s",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
        }

        /* Witnesses are maintained incrementally by connect_block and bulk_blocks.
         * Load them directly — they are already at chain tip. */
        uint8_t anchor[32];
        struct incremental_witness *witnesses = zcl_calloc(num_sel_notes,
            sizeof(struct incremental_witness), "sapling_witnesses");
        if (!witnesses) {
            json_set_str(result, "Out of memory");
            LOG_FAIL("wallet_shielded", "z_sendmany: calloc witnesses failed for %zu notes", num_sel_notes);
        }
        struct incremental_merkle_tree dummy_tree;
        sapling_tree_init(&dummy_tree);

        int authoritative_tip = reducer_frontier_external_tip_height();
        for (size_t i = 0; i < num_sel_notes; i++) {
            uint8_t *wblob = NULL;
            size_t wlen = 0;
            int wheight = 0;
            if (!db_sapling_note_load_witness(ctx->node_db,
                    selected_notes[i].txid, selected_notes[i].output_index,
                    &wblob, &wlen, &wheight) || !wblob) {
                free(witnesses);
                json_set_str(result, "Witness not available (run rescanwitnesses)");
                LOG_FAIL("wallet_shielded", "z_sendmany: witness not available for note %zu", i);
            }
            if (wheight != authoritative_tip) {
                free(wblob); free(witnesses);
                json_set_str(result,
                             "Witness stale (run rescanwitnesses)");
                LOG_FAIL("wallet_shielded",
                         "z_sendmany: witness height=%d authoritative_tip=%d note=%zu",
                         wheight, authoritative_tip, i);
            }
            struct byte_stream ws;
            stream_init_from_data(&ws, wblob, wlen);
            if (!incremental_witness_deserialize(&witnesses[i], &ws,
                    SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
                    dummy_tree.combine, dummy_tree.uncommitted)) {
                free(wblob); free(witnesses);
                json_set_str(result, "Failed to deserialize witness");
                LOG_FAIL("wallet_shielded", "z_sendmany: witness deserialize failed for note %zu", i);
            }
            free(wblob);
        }

        /* Anchor = witness root at chain tip.
         * All witnesses share the same tree state, so use witness[0]'s root. */
        {
            struct uint256 w0root;
            incremental_witness_root(&witnesses[0], &w0root);
            memcpy(anchor, w0root.data, 32);
        }

        /* Verify ALL witness roots match the anchor */
        for (size_t vi = 1; vi < num_sel_notes; vi++) {
            struct uint256 wroot;
            incremental_witness_root(&witnesses[vi], &wroot);
            if (memcmp(wroot.data, anchor, 32) != 0) {
                char ah[65], wh[65];
                uint256_get_hex((const struct uint256 *)anchor, ah);
                uint256_get_hex(&wroot, wh);
                free(witnesses);
                json_set_str(result, "Witness roots inconsistent (run rescanwitnesses)");
                LOG_FAIL("wallet_shielded", "z_sendmany: witness %zu root differs from witness 0 "
                    "w0=%s w%zu=%s", vi, ah, vi, wh);
            }
        }

        /* Build transaction */
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        transaction_init(&wtx.tx);

        int height = ctx->wallet->best_block_height;
        wtx.tx.overwintered = true;
        wtx.tx.version = SAPLING_TX_VERSION;
        wtx.tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        wtx.tx.expiry_height = (uint32_t)(height + 20);

        /* Allocate transparent outputs if any */
        size_t total_t_out_shielded = num_t_out;
        if (total_t_out_shielded > 0 || num_z_out > 0) {
            if (!transaction_alloc(&wtx.tx, 0, total_t_out_shielded)) {
                free(witnesses);
                json_set_str(result, "Transaction allocation failed");
                LOG_FAIL("wallet_shielded", "z_sendmany: transaction_alloc failed for %zu t-outputs (shielded path)", total_t_out_shielded);
            }
        }

        /* Fill transparent outputs (for z→t) */
        for (size_t i = 0; i < num_t_out; i++) {
            struct script dest_script;
            script_for_destination(&dest_script, &t_dests[i]);
            wtx.tx.vout[i].value = t_amounts[i];
            wtx.tx.vout[i].script_pub_key = dest_script;
        }

        /* Init proving context */
        void *proving_ctx = zclassic_sapling_proving_ctx_init();
        if (!proving_ctx) {
            free(witnesses);
            transaction_free(&wtx.tx);
            json_set_str(result, "Failed to init proving context");
            LOG_FAIL("wallet_shielded", "z_sendmany: sapling_proving_ctx_init failed (shielded spend path)");
        }

        /* Build spend descriptions */
        wtx.tx.v_shielded_spend = zcl_calloc(num_sel_notes, sizeof(struct spend_description), "shielded_spends");
        if (!wtx.tx.v_shielded_spend) {
            /* num_shielded_spend left 0 so transaction_free won't walk a NULL
             * array. proving_ctx was init'd above; free it too. */
            zclassic_sapling_proving_ctx_free(proving_ctx);
            free(witnesses);
            transaction_free(&wtx.tx);
            json_set_str(result, "Out of memory (shielded spends)");
            LOG_FAIL("wallet_shielded", "z_sendmany: calloc v_shielded_spend failed for %zu notes", num_sel_notes);
        }
        wtx.tx.num_shielded_spend = num_sel_notes;

        uint8_t spend_ars[256][32]; /* ar values for spend_auth_sig */

        const char *spend_err = NULL;

        for (size_t i = 0; i < num_sel_notes; i++) {
            struct spend_description *sd = &wtx.tx.v_shielded_spend[i];

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

        if (spend_err) goto shielded_cleanup;

        /* Build shielded output descriptions */
        int64_t shielded_change = notes_total - total_amount - fee;
        size_t total_z_outs = num_z_out + (shielded_change > 0 ? 1 : 0);

        if (total_z_outs > 0) {
            wtx.tx.v_shielded_output = zcl_calloc(total_z_outs,
                sizeof(struct output_description), "shielded_outputs");
            if (!wtx.tx.v_shielded_output) {
                /* leave num_shielded_output 0; shielded_cleanup frees
                 * proving_ctx/witnesses/tx and reports the error. */
                wtx.tx.num_shielded_output = 0;
                spend_err = "Out of memory (shielded outputs)";
                goto shielded_cleanup;
            }
            wtx.tx.num_shielded_output = total_z_outs;

            uint8_t ovk[32];
            memcpy(ovk, from_z_key->xfvk.fvk.ovk, 32);

            for (size_t i = 0; i < num_z_out && !spend_err; i++) {
                struct output_description *od = &wtx.tx.v_shielded_output[i];
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
                    &wtx.tx.v_shielded_output[num_z_out];
                if (!sapling_build_output_with_ctx(
                        proving_ctx, ovk,
                        from_z_key->diversifier, from_z_key->pk_d,
                        (uint64_t)shielded_change, NULL,
                        od->cv.data, od->cm.data, od->ephemeral_key.data,
                        od->enc_ciphertext, od->out_ciphertext, od->zkproof))
                    spend_err = "Failed to build change output";
            }
        }

        if (spend_err) goto shielded_cleanup;

        /* Set value_balance = sum(spend) - sum(output) */
        {
            int64_t spend_total = 0;
            for (size_t i = 0; i < num_sel_notes; i++)
                spend_total += selected_notes[i].value;
            int64_t output_total = 0;
            for (size_t i = 0; i < num_z_out; i++)
                output_total += z_amounts[i];
            if (shielded_change > 0)
                output_total += shielded_change;
            wtx.tx.value_balance = spend_total - output_total;
        }

        /* Compute sighash for spend_auth_sig and binding_sig */
        transaction_compute_hash(&wtx.tx);

        {
            uint32_t branch_id = consensus_current_epoch_branch_id(
                height + 1, &cp->consensus);
            struct sighash_type ht;
            ht.raw = SIGHASH_ALL;
            struct precomputed_tx_data txdata;
            precompute_tx_data(&wtx.tx, &txdata);

            struct script empty_script;
            empty_script.size = 0;
            struct uint256 sighash;
            if (!signature_hash(&empty_script, &wtx.tx, NOT_AN_INPUT, ht, 0,
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
                                    wtx.tx.v_shielded_spend[i].spend_auth_sig,
                                    5 /* GEN_SPENDING_KEY */))
                    spend_err = "Spend auth signature failed";
                memory_cleanse(rsk, 32);
            }

            if (!spend_err &&
                !zclassic_sapling_binding_sig(proving_ctx,
                    wtx.tx.value_balance, sighash.data, wtx.tx.binding_sig))
                spend_err = "Binding signature failed";
        }

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

        /* The old shielded-spend branch bypassed every mempool check with
         * tx_mempool_add_unchecked(), ignored its return, and marked notes
         * spent even when admission failed. Use the same consensus gate and
         * rollback contract as every transparent wallet send. */
        struct zcl_result commit = wallet_commit_from_context(ctx, &wtx);
        if (!commit.ok) {
            transaction_free(&wtx.tx);
            json_set_str(result, commit.message);
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: shielded commit rejected (code=%d): %s",
                     commit.code, commit.message);
        }

        /* Persist the wallet transaction through node.db's single-writer lane
         * before network relay. A failed durability step unwinds wallet and
         * mempool state. */
        struct zcl_result persisted =
            wallet_persist_commit_before_relay(ctx, &wtx);
        if (!persisted.ok) {
            transaction_free(&wtx.tx);
            json_set_str(result, persisted.message);
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: pre-relay durability failed (code=%d): %s",
                     persisted.code, persisted.message);
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
        if (!node_db_sync_wallet_sapling_spends(ctx->node_db, &wtx.tx)) {
            struct zcl_result compensated =
                wallet_rollback_persisted_commit(ctx, &wtx);
            transaction_free(&wtx.tx);
            if (!compensated.ok) {
                json_set_str(result, compensated.message);
                LOG_FAIL("wallet_shielded",
                         "z_sendmany: note reservation and durable compensation "
                         "failed (code=%d): %s",
                         compensated.code, compensated.message);
            }
            json_set_str(result, "Cannot reserve shielded notes; send aborted");
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: atomic wallet-note reservation failed");
        }
        if (ctx->wallet)
            wallet_mark_sapling_nullifiers_spent(ctx->wallet, &wtx.tx);

        /* node.db's wallet projection is rebuildable; report a write failure,
         * but the authoritative private wallet transaction + note reservation
         * are already durable before relay. */
        if (!node_db_sync_wallet_tx(ctx->node_db, &wtx.tx, ctx->wallet, 0))
            LOG_WARN("wallet_shielded",
                     "z_sendmany: wallet projection write failed after durable reservation");

        if (ctx->connman)
            connman_relay_transaction(ctx->connman, &wtx.tx.hash);

        char txid_hex[65];
        uint256_get_hex(&wtx.tx.hash, txid_hex);
        json_set_str(result, txid_hex);

        transaction_free(&wtx.tx);
        return true;
}
