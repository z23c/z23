/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * z_sendmany RPC handler for transparent and shielded sends (t->t, t->z,
 * z->z, z->t). The shielded-spend branch lives in z_sendmany_shielded();
 * transparent-spend handling stays inline with the RPC validation flow. */

#include "controllers/wallet_shielded_internal.h"
#include "wallet/wallet_lock.h"


/* Sapling-vs-transparent routing for one address, against the ACTIVE chain's
 * bech32 HRP rather than a hardcoded mainnet "zs1". Every network mints a
 * different human-readable part (main "zs", testnet "ztestsapling", regtest
 * "zregtestsapling"), and sapling_decode_payment_address() ignores the HRP
 * entirely, so the prefix test here is the ONLY thing deciding which branch a
 * recipient takes. With the literal, a regtest z-recipient fell into the
 * transparent branch and z_sendmany died on "Invalid transparent address" —
 * i.e. no shielded payment could be made on any isolated fixture.
 *
 * The trailing '1' is bech32's separator, so "zs" cannot swallow a
 * hypothetical "zsfoo1..." address. Refusing (returning false) is always the
 * safe direction: the address then has to decode as transparent or the send
 * is refused outright. */
bool wallet_addr_is_sapling(const char *addr)
{
    const struct chain_params *cp = chain_params_get();
    if (!addr || !cp)
        return false;
    const char *hrp = cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS];
    size_t hrp_len = hrp ? strlen(hrp) : 0;
    if (hrp_len == 0)
        return false;
    return strncmp(addr, hrp, hrp_len) == 0 && addr[hrp_len] == '1';
}


static bool z_sendmany_run(const struct json_value *params, bool help,
                           struct wallet_tx *prepared,
                           struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "z_sendmany \"fromaddress\" [{\"address\":\"...\",\"amount\":...,\"memo\":\"...\"},...]\n"
        "\nSend from a transparent or shielded address to multiple recipients.\n"
        "Supports t→t, t→z, z→z, and z→t transactions.\n");

    /* Sovereign guard (docs/work/shielded-history-importer.md §5.3):
     * refuse a spend (t->t, t->z, z->t, z->z — this handler covers all four)
     * while the tip is release_assisted (borrowed shielded history, not
     * self-folded). Wallet viewing, balance, and receive stay unaffected —
     * only this spend entry is gated. */
    {
        char sov_reason[96] = {0};
        if (!sovereignty_guard_allow("wallet_spend", sov_reason,
                                     sizeof(sov_reason))) {
            json_set_str(result, "Error: spend refused — tip is "
                                 "release_assisted (borrowed shielded "
                                 "history, not self-folded)");
            LOG_FAIL("wallet_shielded", "z_sendmany: refused — %s",
                     sov_reason);
        }
    }

    /* At-rest lock gate (wallet_lock): an encrypted wallet with no passphrase
     * loaded cannot spend — its spending keys are not decryptable/resident.
     * Covers all four flows (t->t, t->z, z->t, z->z) this handler serves.
     * Wallet-local key handling: no tx bytes / proof / consensus effect. */
    {
        struct zcl_result lk = wallet_lock_spend_guard();
        if (!lk.ok) {
            json_set_str(result, "Error: wallet is locked — run "
                                 "walletunlock before spending");
            LOG_FAIL("wallet_shielded", "z_sendmany: refused — wallet locked "
                     "(code=%d)", lk.code);
        }
    }

    if (json_size(params) < 2) {
        json_set_str(result, "Expected at least 2 parameter(s)");
        LOG_FAIL("wallet_shielded", "z_sendmany: expected 2+ params, got %zu", json_size(params));
    }

    ENSURE_WALLET(result);

    const char *from_addr = json_get_str(json_at(params, 0));
    const struct json_value *recipients = json_at(params, 1);
    if (!from_addr || !recipients || recipients->type != JSON_ARR || json_size(recipients) == 0) {
        json_set_str(result, "Invalid parameters");
        LOG_FAIL("wallet_shielded", "z_sendmany: invalid from_addr or recipients array");
    }

    /* Is the from address transparent or Sapling? Decided against the active
     * chain's HRP (wallet_addr_is_sapling), not a mainnet literal. */
    bool from_is_shielded = wallet_addr_is_sapling(from_addr);

    /* Verify we own the from address */
    const struct chain_params *cp = chain_params_get();

    /* For shielded from: decode the z-address, find key, validate ownership */
    uint8_t from_z_diversifier[11];
    uint8_t from_z_pk_d[32];
    const struct sapling_key_entry *from_z_key = NULL;

    struct tx_destination from_dest;
    if (from_is_shielded) {
        if (!sapling_decode_payment_address(from_addr, from_z_diversifier, from_z_pk_d)) {
            json_set_str(result, "Invalid shielded from address");
            LOG_FAIL("wallet_shielded", "z_sendmany: cannot decode shielded from address %s", from_addr);
        }
        from_z_key = sapling_keystore_find_by_address(
            &ctx->wallet->sapling_keys, from_z_diversifier, from_z_pk_d);
        if (!from_z_key) {
            json_set_str(result, "Shielded from address not in wallet");
            LOG_FAIL("wallet_shielded", "z_sendmany: shielded from addr not found in keystore");
        }
        memset(&from_dest, 0, sizeof(from_dest));
    } else if (!wallet_decode_address(from_addr, &from_dest)) {
        json_set_str(result, "Invalid from address");
        LOG_FAIL("wallet_shielded", "z_sendmany: decode_destination failed for from=%s", from_addr);
    }

    /* Parse recipients */
    size_t num_recip = json_size(recipients);
    if (num_recip > 50) {
        json_set_str(result, "Too many recipients");
        LOG_FAIL("wallet_shielded", "z_sendmany: too many recipients (%zu > 50)", num_recip);
    }

    /* Separate into transparent and shielded outputs */
    struct tx_destination t_dests[50];
    int64_t t_amounts[50];
    size_t num_t_out = 0;

    uint8_t z_diversifiers[50][11];
    uint8_t z_pk_ds[50][32];
    int64_t z_amounts[50];
    uint8_t z_memos[50][512];
    bool z_has_memo[50];
    size_t num_z_out = 0;
    int64_t total_amount = 0;

    for (size_t i = 0; i < num_recip; i++) {
        const struct json_value *r = json_at(recipients, i);
        if (!r || r->type != JSON_OBJ) {
            json_set_str(result, "Invalid recipient");
            LOG_FAIL("wallet_shielded", "z_sendmany: recipient %zu is not a JSON object", i);
        }
        const char *addr = json_get_str(json_get(r, "address"));
        int64_t amount = parse_amount(json_get(r, "amount"));
        if (!addr || amount <= 0) {
            json_set_str(result, "Invalid recipient address or amount");
            LOG_FAIL("wallet_shielded", "z_sendmany: recipient %zu has invalid addr or amount=%lld", i, (long long)amount);
        }
        total_amount += amount;

        if (wallet_addr_is_sapling(addr)) {
            /* Sapling shielded output */
            if (!sapling_decode_payment_address(addr,
                    z_diversifiers[num_z_out], z_pk_ds[num_z_out])) {
                json_set_str(result, "Invalid Sapling address");
                LOG_FAIL("wallet_shielded", "z_sendmany: cannot decode sapling recipient addr=%s", addr);
            }
            z_amounts[num_z_out] = amount;
            /* Parse memo if present. "memo_hex" carries an arbitrary BINARY
             * memo (hex-encoded, <=1024 hex chars → <=512 bytes) — used by the
             * on-chain ZMSG channel whose header bytes are not printable text;
             * "memo" is the plain-UTF-8 form. memo_hex wins if both are given. */
            const struct json_value *memohex_val = json_get(r, "memo_hex");
            const char *memohex = memohex_val ? json_get_str(memohex_val) : NULL;
            const struct json_value *memo_val = json_get(r, "memo");
            if (memohex && memohex[0]) {
                size_t hlen = strlen(memohex);
                if (hlen % 2 != 0 || hlen > 1024) {
                    json_set_str(result, "Invalid memo_hex (even-length hex, <=1024 chars)");
                    LOG_FAIL("wallet_shielded", "z_sendmany: bad memo_hex len=%zu", hlen);
                }
                memset(z_memos[num_z_out], 0xF6, 512);
                size_t got = ParseHex(memohex, z_memos[num_z_out], 512);
                if (got != hlen / 2) {
                    json_set_str(result, "Invalid memo_hex (non-hex characters)");
                    LOG_FAIL("wallet_shielded", "z_sendmany: memo_hex parse got=%zu want=%zu", got, hlen / 2);
                }
                z_has_memo[num_z_out] = true;
            } else if (memo_val && json_get_str(memo_val)) {
                /* A TEXT memo is zero-padded, not 0xF6-padded. 0xF6 is the
                 * "no memo" sentinel (a memo of 0xF6 then zeros); for a UTF-8
                 * memo the spec pads with 0x00, and every reader in this tree
                 * treats 0x00 as the text terminator. Padding text with 0xF6
                 * produced "<text>" immediately followed by 0xF6, which the
                 * store's order-binding matcher (memo[len] must be NUL or ';',
                 * db_store_received_payment_for_memo) rejects — so a buyer who
                 * typed the memo exactly as the payment page instructs was
                 * never credited. memo_hex is untouched: binary callers (the
                 * on-chain ZMSG codec) own their own padding. */
                const char *memo_str = json_get_str(memo_val);
                size_t memo_len = strlen(memo_str);
                if (memo_len > 512) memo_len = 512;
                memset(z_memos[num_z_out], 0x00, 512);
                memcpy(z_memos[num_z_out], memo_str, memo_len);
                z_has_memo[num_z_out] = true;
            } else {
                z_has_memo[num_z_out] = false;
            }
            num_z_out++;
        } else {
            /* Transparent output */
            if (!wallet_decode_address(addr, &t_dests[num_t_out])) {
                json_set_str(result, "Invalid transparent address");
                LOG_FAIL("wallet_shielded", "z_sendmany: cannot decode transparent recipient addr=%s", addr);
            }
            t_amounts[num_t_out] = amount;
            num_t_out++;
        }
    }

    /* ── Shielded spend path (z→z, z→t) ──────────────────────────── */
    if (from_is_shielded) {
        return z_sendmany_shielded(ctx, cp, from_z_key, total_amount,
                                   t_dests, t_amounts, num_t_out,
                                   z_diversifiers, z_pk_ds, z_amounts,
                                   z_memos, z_has_memo, num_z_out, prepared,
                                   result);
    }


    /* ── Transparent spend path (t→t, t→z) ─────────────────────── */

    /* Shielding (t→z) needs a Sapling OUTPUT description, and an output
     * description carries its own Groth16 proof — so it needs the proving
     * backend exactly as a shielded spend does. Refuse here, before coin
     * selection allocates anything and before any spent-state is touched, and
     * name the backend + status so a build with no proving backend explains
     * itself instead of surfacing a bare "Failed to init proving context"
     * hundreds of lines later. Pure t→t sends are unaffected. */
    if (num_z_out > 0 && !zclassic_sapling_prover_is_ready()) {
        char err[320];
        snprintf(err, sizeof(err),
                 "Shielded proving unavailable (backend=%s, status=%s)",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        json_set_str(result, err);
        LOG_FAIL("wallet_shielded",
                 "z_sendmany: refusing t->z shielding: backend=%s status=%s",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
    }

    /* Select coins from SQLite model layer, restricted to the from-address.
     * Pushing the address hash into the SQL WHERE (rather than selecting
     * globally then post-filtering) ensures a fully funded from-address is
     * never falsely rejected because higher-value coins on OTHER addresses
     * crowded out a value-DESC global selection window. */
    int64_t fee = ctx->wallet->default_fee;
    int tip = active_chain_height(&ctx->main_state->chain_active);

    uint8_t from_addr_hash[20];
    if (from_dest.type == DEST_KEY_ID)
        memcpy(from_addr_hash, from_dest.id.key.id.data, 20);
    else if (from_dest.type == DEST_SCRIPT_ID)
        memcpy(from_addr_hash, from_dest.id.script.hash.data, 20);
    else {
        json_set_str(result, "Unsupported from address type");
        LOG_FAIL("wallet_shielded", "z_sendmany: unsupported from_dest type %d", from_dest.type);
    }

    struct db_wallet_utxo db_selected[256];
    size_t num_selected = 0;
    int64_t selected_value = 0;

    if (wallet_ctx_db_ready(ctx)) {
        int n_sel = db_wallet_utxo_select_coins_for_address(ctx->node_db,
            total_amount + fee, tip, from_addr_hash, db_selected, 256);
        for (int i = 0; i < n_sel; i++) {
            num_selected++;
            selected_value += db_selected[i].value;
        }
    }

    if (selected_value < total_amount + fee) {
        for (size_t i = 0; i < num_selected; i++)
            db_wallet_utxo_free(&db_selected[i]);
        json_set_str(result, "Insufficient funds from specified address");
        LOG_FAIL("wallet_shielded", "z_sendmany: insufficient transparent funds: have=%lld need=%lld",
                 (long long)selected_value, (long long)(total_amount + fee));
    }

    /* Build transaction */
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    transaction_init(&wtx.tx);

    int height = tip;
    wtx.tx.overwintered = true;
    wtx.tx.version = SAPLING_TX_VERSION;
    wtx.tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    wtx.tx.expiry_height = (uint32_t)(height + 20);

    /* Transparent outputs: recipients + change */
    int64_t change = selected_value - total_amount - fee;
    size_t total_t_out = num_t_out + (change > 0 ? 1 : 0);

    if (!transaction_alloc(&wtx.tx, num_selected, total_t_out)) {
        json_set_str(result, "Transaction allocation failed");
        LOG_FAIL("wallet_shielded", "z_sendmany: transaction_alloc failed for %zu inputs, %zu outputs",
                 num_selected, total_t_out);
    }

    /* Fill transparent outputs */
    for (size_t i = 0; i < num_t_out; i++) {
        struct script dest_script;
        script_for_destination(&dest_script, &t_dests[i]);
        wtx.tx.vout[i].value = t_amounts[i];
        wtx.tx.vout[i].script_pub_key = dest_script;
    }

    /* Change output — send back to the FROM address (no keypool needed) */
    if (change > 0) {
        struct pubkey change_pk;
        bool got_key = wallet_get_key_from_pool(ctx->wallet, &change_pk);
        if (!got_key) {
            /* Keypool exhausted — use the from_address as change address */
            struct tx_destination change_dest = from_dest;
            struct script change_script;
            script_for_destination(&change_script, &change_dest);
            wtx.tx.vout[num_t_out].value = change;
            wtx.tx.vout[num_t_out].script_pub_key = change_script;
        } else {
            struct key_id change_kid = pubkey_get_id(&change_pk);
            struct tx_destination change_dest;
            change_dest.type = DEST_KEY_ID;
            change_dest.id.key = change_kid;
            struct script change_script;
            script_for_destination(&change_script, &change_dest);
            wtx.tx.vout[num_t_out].value = change;
            wtx.tx.vout[num_t_out].script_pub_key = change_script;
        }
    }

    /* value_balance = -(sum of shielded outputs) for shielding (negative = transparent→shielded) */
    int64_t shielded_total = 0;
    for (size_t i = 0; i < num_z_out; i++)
        shielded_total += z_amounts[i];
    wtx.tx.value_balance = -shielded_total;

    /* Build Sapling output descriptions */
    if (num_z_out > 0) {
        wtx.tx.v_shielded_output = zcl_calloc(num_z_out, sizeof(struct output_description), "shielded_outputs");
        if (!wtx.tx.v_shielded_output) {
            transaction_free(&wtx.tx);
            json_set_str(result, "Allocation failed");
            LOG_FAIL("wallet_shielded", "z_sendmany: calloc shielded_output failed for %zu outputs", num_z_out);
        }
        wtx.tx.num_shielded_output = num_z_out;

        /* Get OVK from sapling keystore */
        uint8_t ovk[32];
        zcl_mutex_lock(&ctx->wallet->sapling_keys.cs);
        if (ctx->wallet->sapling_keys.num_keys > 0) {
            memcpy(ovk, ctx->wallet->sapling_keys.keys[0].xfvk.fvk.ovk, 32);
            zcl_mutex_unlock(&ctx->wallet->sapling_keys.cs);
        } else {
            zcl_mutex_unlock(&ctx->wallet->sapling_keys.cs);
            GetRandBytes(ovk, 32);
        }

        /* Use Sapling proving context for output proofs + binding sig.
         * The declarations come from sapling/sapling_prover.h via
         * wallet_shielded_internal.h. */
        void *proving_ctx = zclassic_sapling_proving_ctx_init();
        if (!proving_ctx) {
            /* Every other error return below this point frees the selected
             * UTXO rows; this one used to leak them. The readiness precheck
             * above makes reaching here rare, not impossible. */
            for (size_t j = 0; j < num_selected; j++)
                db_wallet_utxo_free(&db_selected[j]);
            transaction_free(&wtx.tx);
            char err[320];
            snprintf(err, sizeof(err),
                     "Failed to init proving context (backend=%s, status=%s)",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
            json_set_str(result, err);
            LOG_FAIL("wallet_shielded",
                     "z_sendmany: sapling_proving_ctx_init failed (transparent spend path): backend=%s status=%s",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
        }

        for (size_t i = 0; i < num_z_out; i++) {
            struct output_description *od = &wtx.tx.v_shielded_output[i];

            if (!sapling_build_output_with_ctx(
                    proving_ctx,
                    ovk, z_diversifiers[i], z_pk_ds[i],
                    (uint64_t)z_amounts[i],
                    z_has_memo[i] ? z_memos[i] : NULL,
                    od->cv.data, od->cm.data, od->ephemeral_key.data,
                    od->enc_ciphertext, od->out_ciphertext, od->zkproof)) {
                zclassic_sapling_proving_ctx_free(proving_ctx);
                transaction_free(&wtx.tx);
                json_set_str(result, "Failed to build Sapling output");
                LOG_FAIL("wallet_shielded", "z_sendmany: sapling_build_output failed for output %zu", i);
            }
        }

        /* Fill transparent inputs from SQLite model (needed for sighash) */
        for (size_t i = 0; i < num_selected; i++) {
            memcpy(wtx.tx.vin[i].prevout.hash.data, db_selected[i].txid, 32);
            wtx.tx.vin[i].prevout.n = db_selected[i].vout;
            wtx.tx.vin[i].sequence = UINT32_MAX - 1;
        }

        /* Sign transparent inputs */
        zcl_mutex_lock(&ctx->wallet->cs);
        for (size_t i = 0; i < num_selected; i++) {
            /* Reconstruct prevout script from SQLite data */
            struct script prev_script;
            script_init(&prev_script);
            if (db_selected[i].script && db_selected[i].script_len > 0) {
                memcpy(prev_script.data, db_selected[i].script,
                       db_selected[i].script_len);
                prev_script.size = db_selected[i].script_len;
            }

            struct tx_destination prev_dest;
            if (!script_extract_destination(&prev_script, &prev_dest)) {
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Cannot determine input destination");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: script_extract_destination failed for input %zu (t->z path)", i);
            }

            struct privkey skey;
            if (!keystore_get_key(&ctx->wallet->keystore, &prev_dest.id.key, &skey)) {
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Private key not available");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: private key not found for input %zu (t->z path)", i);
            }

            struct pubkey spk;
            privkey_get_pubkey(&skey, &spk);

            uint32_t branch_id = consensus_current_epoch_branch_id(height + 1, &cp->consensus);
            struct sighash_type ht;
            ht.raw = SIGHASH_ALL;
            struct precomputed_tx_data txdata;
            precompute_tx_data(&wtx.tx, &txdata);

            struct uint256 sighash;
            if (!signature_hash(&prev_script, &wtx.tx,
                                (unsigned int)i, ht, db_selected[i].value,
                                branch_id, &txdata, &sighash)) {
                memory_cleanse(skey.vch, 32);
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Sighash computation failed");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: signature_hash failed for input %zu (t->z path)", i);
            }

            unsigned char sig[SIGNATURE_SIZE + 1];
            size_t siglen = 0;
            if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
                memory_cleanse(skey.vch, 32);
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Signing failed");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: privkey_sign failed for input %zu (t->z path)", i);
            }
            sig[siglen++] = 0x01;

            struct script *ss = &wtx.tx.vin[i].script_sig;
            ss->size = 0;
            ss->data[ss->size++] = (unsigned char)siglen;
            memcpy(&ss->data[ss->size], sig, siglen);
            ss->size += siglen;
            ss->data[ss->size++] = (unsigned char)spk.size;
            memcpy(&ss->data[ss->size], spk.vch, spk.size);
            ss->size += spk.size;

            memory_cleanse(skey.vch, 32);
        }
        zcl_mutex_unlock(&ctx->wallet->cs);

        /* Compute binding signature using Sapling proving context */
        transaction_compute_hash(&wtx.tx);

        uint32_t branch_id = consensus_current_epoch_branch_id(height + 1, &cp->consensus);
        struct sighash_type ht;
        ht.raw = SIGHASH_ALL;
        struct precomputed_tx_data txdata;
        precompute_tx_data(&wtx.tx, &txdata);

        struct script empty_script;
        empty_script.size = 0;
        struct uint256 binding_sighash;
        if (!signature_hash(&empty_script, &wtx.tx, NOT_AN_INPUT, ht, 0,
                            branch_id, &txdata, &binding_sighash)) {
            zclassic_sapling_proving_ctx_free(proving_ctx);
            transaction_free(&wtx.tx);
            json_set_str(result, "Binding sighash computation failed");
            LOG_FAIL("wallet_shielded", "z_sendmany: binding signature_hash failed (t->z path)");
        }

        if (!zclassic_sapling_binding_sig(proving_ctx,
                                               wtx.tx.value_balance,
                                               binding_sighash.data,
                                               wtx.tx.binding_sig)) {
            zclassic_sapling_proving_ctx_free(proving_ctx);
            transaction_free(&wtx.tx);
            json_set_str(result, "Binding signature failed");
            LOG_FAIL("wallet_shielded", "z_sendmany: binding_sig failed, value_balance=%lld", (long long)wtx.tx.value_balance);
        }
        zclassic_sapling_proving_ctx_free(proving_ctx);
    } else {
        /* No shielded outputs — just transparent */
        for (size_t i = 0; i < num_selected; i++) {
            memcpy(wtx.tx.vin[i].prevout.hash.data, db_selected[i].txid, 32);
            wtx.tx.vin[i].prevout.n = db_selected[i].vout;
            wtx.tx.vin[i].sequence = UINT32_MAX - 1;
        }

        zcl_mutex_lock(&ctx->wallet->cs);
        for (size_t i = 0; i < num_selected; i++) {
            struct script prev_script;
            script_init(&prev_script);
            if (db_selected[i].script && db_selected[i].script_len > 0) {
                memcpy(prev_script.data, db_selected[i].script,
                       db_selected[i].script_len);
                prev_script.size = db_selected[i].script_len;
            }

            struct tx_destination prev_dest;
            if (!script_extract_destination(&prev_script, &prev_dest)) {
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Cannot determine input destination");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: script_extract_destination failed for input %zu (t->t path)", i);
            }

            struct privkey skey;
            if (!keystore_get_key(&ctx->wallet->keystore, &prev_dest.id.key, &skey)) {
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Private key not available");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: private key not found for input %zu (t->t path)", i);
            }

            struct pubkey spk;
            privkey_get_pubkey(&skey, &spk);
            uint32_t branch_id = consensus_current_epoch_branch_id(height + 1, &cp->consensus);
            struct sighash_type ht;
            ht.raw = SIGHASH_ALL;
            struct precomputed_tx_data txdata;
            precompute_tx_data(&wtx.tx, &txdata);

            struct uint256 sighash;
            if (!signature_hash(&prev_script, &wtx.tx,
                                (unsigned int)i, ht, db_selected[i].value,
                                branch_id, &txdata, &sighash)) {
                memory_cleanse(skey.vch, 32);
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Sighash computation failed");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: signature_hash failed for input %zu (t->t path)", i);
            }

            unsigned char sig[SIGNATURE_SIZE + 1];
            size_t siglen = 0;
            if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
                memory_cleanse(skey.vch, 32);
                zcl_mutex_unlock(&ctx->wallet->cs);
                transaction_free(&wtx.tx);
                json_set_str(result, "Signing failed");
                for (size_t j = 0; j < num_selected; j++)
                    db_wallet_utxo_free(&db_selected[j]);
                LOG_FAIL("wallet_shielded", "z_sendmany: privkey_sign failed for input %zu (t->t path)", i);
            }
            sig[siglen++] = 0x01;

            struct script *ss = &wtx.tx.vin[i].script_sig;
            ss->size = 0;
            ss->data[ss->size++] = (unsigned char)siglen;
            memcpy(&ss->data[ss->size], sig, siglen);
            ss->size += siglen;
            ss->data[ss->size++] = (unsigned char)spk.size;
            memcpy(&ss->data[ss->size], spk.vch, spk.size);
            ss->size += spk.size;

            memory_cleanse(skey.vch, 32);
        }
        zcl_mutex_unlock(&ctx->wallet->cs);
    }

    /* Free SQLite UTXO data — no longer needed after building inputs */
    for (size_t i = 0; i < num_selected; i++)
        db_wallet_utxo_free(&db_selected[i]);

    transaction_compute_hash(&wtx.tx);
    wtx.time_received = GetTime();
    wtx.from_me = true;
    wtx.used = true;

    /* Persist the wallet keystore (which may hold a freshly-minted change key)
     * to disk BEFORE broadcast — abort the send on flush failure so we never
     * relay a tx whose RAM-only change key isn't durable (see rpc_sendtoaddress). */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_sqlite_flush_r(ctx->wallet_db, ctx->wallet);
        if (!fr.ok) {
            transaction_free(&wtx.tx);
            json_set_str(result, "Cannot persist change key before broadcast — send aborted");
            LOG_FAIL("wallet", "z_sendmany: pre-broadcast key flush failed "
                                "(code=%d): %s", fr.code, fr.message);
        }
    }

    if (prepared) {
        *prepared = wtx;
        return true;
    }

    struct zcl_result commit = wallet_commit_from_context(ctx, &wtx);
    if (!commit.ok) {
        json_set_str(result, commit.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet_shielded", "z_sendmany: wallet commit failed "
                                    "(code=%d): %s", commit.code,
                                    commit.message);
    }

    struct zcl_result persisted =
        wallet_persist_commit_before_relay(ctx, &wtx);
    if (!persisted.ok) {
        json_set_str(result, persisted.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet_shielded",
                 "z_sendmany: pre-relay durability failed (code=%d): %s",
                 persisted.code, persisted.message);
    }

    if (wallet_ctx_db_ready(ctx))
        node_db_sync_wallet_tx(ctx->node_db, &wtx.tx, ctx->wallet, 0);

    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &wtx.tx.hash);

    char txid[65];
    uint256_get_hex(&wtx.tx.hash, txid);
    json_set_str(result, txid);
    transaction_free(&wtx.tx);
    return true;
}

bool rpc_z_sendmany(const struct json_value *params, bool help,
                    struct json_value *result)
{
    return z_sendmany_run(params, help, NULL, result);
}

bool z_sendmany_prepare(const struct json_value *params,
                        struct wallet_tx *prepared,
                        struct json_value *result)
{
    if (!prepared || !result)
        LOG_FAIL("wallet_shielded", "z_sendmany_prepare: NULL output");
    memset(prepared, 0, sizeof(*prepared));
    return z_sendmany_run(params, false, prepared, result);
}
