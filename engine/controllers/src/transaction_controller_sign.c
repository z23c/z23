/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * signrawtransaction RPC and per-input transparent signing helpers. */

#include "controllers/transaction_controller_internal.h"

struct rawtx_sign_overlay {
    struct privkey *keys;
    size_t num_keys;
    struct script *scripts;
    size_t num_scripts;
};

static void rawtx_sign_overlay_free(struct rawtx_sign_overlay *overlay)
{
    if (!overlay) return;
    if (overlay->keys) {
        memory_cleanse(overlay->keys,
                       overlay->num_keys * sizeof(*overlay->keys));
        free(overlay->keys);
    }
    free(overlay->scripts);
    memset(overlay, 0, sizeof(*overlay));
}

static bool rawtx_sign_get_key(const struct basic_keystore *wallet_ks,
                               const struct rawtx_sign_overlay *overlay,
                               const struct key_id *wanted,
                               struct privkey *key_out)
{
    if (overlay) {
        for (size_t i = 0; i < overlay->num_keys; i++) {
            struct pubkey pk;
            if (privkey_get_pubkey(&overlay->keys[i], &pk)) {
                struct key_id have = pubkey_get_id(&pk);
                if (memcmp(have.id.data, wanted->id.data,
                           sizeof(have.id.data)) == 0) {
                    *key_out = overlay->keys[i];
                    return true;
                }
            }
        }
    }
    return wallet_ks && keystore_get_key(wallet_ks, wanted, key_out);
}

static bool rawtx_sign_get_script(const struct basic_keystore *wallet_ks,
                                  const struct rawtx_sign_overlay *overlay,
                                  const struct uint160 *wanted,
                                  struct script *script_out)
{
    if (overlay) {
        for (size_t i = 0; i < overlay->num_scripts; i++) {
            struct script_id sid;
            script_id_from_script(&sid, &overlay->scripts[i]);
            if (memcmp(sid.hash.data, wanted->data,
                       sizeof(sid.hash.data)) == 0) {
                *script_out = overlay->scripts[i];
                return true;
            }
        }
    }
    return wallet_ks && keystore_get_cscript(wallet_ks, wanted, script_out);
}

static bool sign_one_input(struct transaction *tx, unsigned int idx,
                           const struct script *script_pub_key,
                           int64_t amount, uint32_t branch_id,
                           struct basic_keystore *wallet_ks,
                           const struct rawtx_sign_overlay *overlay)
{
    enum txnouttype type;
    unsigned char solutions[20][65];
    size_t solution_sizes[20];
    size_t num_solutions = 0;

    const struct script *signing_script = script_pub_key;
    struct script redeem;
    bool is_p2sh = false;

    if (!script_solver(script_pub_key, &type, solutions, solution_sizes,
                       &num_solutions))
        LOG_FAIL("tx", "sign_one_input: script_solver failed for input %u", idx);

    if (type == TX_SCRIPTHASH) {
        struct uint160 script_hash;
        memcpy(script_hash.data, solutions[0], 20);
        if (!rawtx_sign_get_script(wallet_ks, overlay, &script_hash, &redeem))
            LOG_FAIL("tx", "sign_one_input: P2SH redeem script not found for input %u", idx);
        is_p2sh = true;
        signing_script = &redeem;
        if (!script_solver(&redeem, &type, solutions, solution_sizes,
                           &num_solutions))
            LOG_FAIL("tx", "sign_one_input: script_solver failed on redeem script for input %u", idx);
    }

    struct sighash_type ht;
    ht.raw = SIGHASH_ALL;
    struct precomputed_tx_data txdata;
    precompute_tx_data(tx, &txdata);

    struct uint256 sighash;
    if (!signature_hash(signing_script, tx, idx, ht, amount,
                        branch_id, &txdata, &sighash))
        LOG_FAIL("tx", "sign_one_input: signature_hash failed for input %u", idx);

    struct script *ss = &tx->vin[idx].script_sig;
    ss->size = 0;

    if (type == TX_PUBKEYHASH) {
        struct key_id kid;
        memcpy(kid.id.data, solutions[0], 20);
        struct privkey skey;
        if (!rawtx_sign_get_key(wallet_ks, overlay, &kid, &skey))
            LOG_FAIL("tx", "sign_one_input: private key not found for P2PKH input %u", idx);
        struct pubkey spk;
        privkey_get_pubkey(&skey, &spk);

        unsigned char sig[SIGNATURE_SIZE + 1];
        size_t siglen = 0;
        if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
            memory_cleanse(skey.vch, 32);
            LOG_FAIL("tx", "sign_one_input: privkey_sign failed for P2PKH input %u", idx);
        }
        memory_cleanse(skey.vch, 32);
        sig[siglen++] = 0x01; /* SIGHASH_ALL */

        ss->data[ss->size++] = (unsigned char)siglen;
        memcpy(&ss->data[ss->size], sig, siglen);
        ss->size += siglen;
        ss->data[ss->size++] = (unsigned char)spk.size;
        memcpy(&ss->data[ss->size], spk.vch, spk.size);
        ss->size += spk.size;
    } else if (type == TX_MULTISIG) {
        /* script_solver returns the decoded small integer m, not OP_m.
         * Subtracting the opcode base here made every threshold negative,
         * emitted no signatures, and still reported the input complete. */
        int n_required = solutions[0][0];
        int n_keys = (int)num_solutions - 2;

        ss->data[ss->size++] = OP_0; /* dummy for CHECKMULTISIG bug */

        int sigs_added = 0;
        for (int k = 0; k < n_keys && sigs_added < n_required; k++) {
            struct pubkey pk;
            pubkey_set(&pk, solutions[k + 1], solution_sizes[k + 1]);
            struct key_id kid = pubkey_get_id(&pk);
            struct privkey skey;
            if (!rawtx_sign_get_key(wallet_ks, overlay, &kid, &skey))
                continue;

            unsigned char sig[SIGNATURE_SIZE + 1];
            size_t siglen = 0;
            if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
                memory_cleanse(skey.vch, 32);
                continue;
            }
            memory_cleanse(skey.vch, 32);
            sig[siglen++] = 0x01;

            ss->data[ss->size++] = (unsigned char)siglen;
            memcpy(&ss->data[ss->size], sig, siglen);
            ss->size += siglen;
            sigs_added++;
        }

        if (sigs_added < n_required)
            LOG_FAIL("tx", "sign_one_input: multisig needs %d sigs but only got %d for input %u", n_required, sigs_added, idx);
    } else if (type == TX_PUBKEY) {
        struct pubkey pk;
        pubkey_set(&pk, solutions[0], solution_sizes[0]);
        struct key_id kid = pubkey_get_id(&pk);
        struct privkey skey;
        if (!rawtx_sign_get_key(wallet_ks, overlay, &kid, &skey))
            LOG_FAIL("tx", "sign_one_input: private key not found for P2PK input %u", idx);

        unsigned char sig[SIGNATURE_SIZE + 1];
        size_t siglen = 0;
        if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
            memory_cleanse(skey.vch, 32);
            LOG_FAIL("tx", "sign_one_input: privkey_sign failed for P2PK input %u", idx);
        }
        memory_cleanse(skey.vch, 32);
        sig[siglen++] = 0x01;

        ss->data[ss->size++] = (unsigned char)siglen;
        memcpy(&ss->data[ss->size], sig, siglen);
        ss->size += siglen;
    } else {
        LOG_FAIL("tx", "sign_one_input: unsupported script type %d for input %u", (int)type, idx);
    }

    if (is_p2sh) {
        size_t push_len = redeem.size;
        if (push_len < 76) {
            ss->data[ss->size++] = (unsigned char)push_len;
        } else if (push_len <= 0xff) {
            ss->data[ss->size++] = OP_PUSHDATA1;
            ss->data[ss->size++] = (unsigned char)push_len;
        } else {
            ss->data[ss->size++] = OP_PUSHDATA2;
            ss->data[ss->size++] = (unsigned char)(push_len & 0xff);
            ss->data[ss->size++] = (unsigned char)(push_len >> 8);
        }
        memcpy(&ss->data[ss->size], redeem.data, push_len);
        ss->size += push_len;
    }

    return true;
}

bool rpc_signrawtransaction(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    struct rawtx_context *ctx = rawtx_ctx();
    RPC_HELP(help, result,
        "signrawtransaction \"hexstring\" "
        "( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\","
        "\"amount\":n},...] [\"privatekey\",...] sighashtype )\n"
        "Sign inputs for raw transaction.\n"
        "Arguments:\n"
        "1. \"hexstring\"   (string, required) The transaction hex\n"
        "2. \"prevtxs\"     (array, optional) Previous outputs being spent\n"
        "3. \"privkeys\"    (array, optional) Private keys for signing\n"
        "4. \"sighashtype\" (string, optional, default=ALL)");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 4);
    const char *hex_str = rpc_require_str(&p, 0, "hexstring");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    struct transaction tx;
    transaction_init(&tx);
    if (!decode_hex_tx(&tx, hex_str)) {
        transaction_free(&tx);
        json_set_str(result, "TX decode failed");
        return false;
    }

    /* Supplemental keys/scripts are request-local. Never insert caller-
     * supplied material into the live wallet keystore: signrawtransaction is
     * a composition operation, not an import-key/import-script mutation. */
    struct rawtx_sign_overlay overlay = {0};

    if (json_size(params) >= 3) {
        const struct json_value *privkeys = json_at(params, 2);
        if (privkeys && privkeys->type == JSON_ARR) {
            size_t key_cap = json_size(privkeys);
            if (key_cap > 256) key_cap = 256;
            overlay.keys = zcl_calloc(key_cap ? key_cap : 1,
                                      sizeof(*overlay.keys),
                                      "rawtx_sign_keys");
            if (!overlay.keys) {
                transaction_free(&tx);
                json_set_str(result, "Out of memory");
                LOG_FAIL("tx", "signrawtransaction: key overlay allocation failed");
            }
            const struct chain_params *cp = chain_params_get();
            size_t sec_pfx_len;
            const unsigned char *sec_pfx = chain_params_base58_prefix(
                cp, B58_SECRET_KEY, &sec_pfx_len);
            for (size_t i = 0; i < key_cap; i++) {
                const struct json_value *kv = json_at(privkeys, i);
                if (!kv || kv->type != JSON_STR) continue;
                struct privkey pk = {0};
                if (decode_secret(json_get_str(kv), sec_pfx, sec_pfx_len, &pk))
                    overlay.keys[overlay.num_keys++] = pk;
                memory_cleanse(pk.vch, 32);
            }
        }
    }

    /* Collect prevout scriptPubKeys and amounts from param 2 */
    struct {
        struct uint256 txid;
        uint32_t vout;
        struct script script_pub_key;
        int64_t amount;
        bool valid;
    } prevouts[256];
    size_t num_prevouts = 0;

    if (json_size(params) >= 2) {
        const struct json_value *prev_arr = json_at(params, 1);
        if (prev_arr && prev_arr->type == JSON_ARR) {
            for (size_t i = 0; i < json_size(prev_arr) && num_prevouts < 256; i++) {
                const struct json_value *po = json_at(prev_arr, i);
                if (!po || po->type != JSON_OBJ) continue;

                const struct json_value *tid = json_get(po, "txid");
                const struct json_value *vn = json_get(po, "vout");
                const struct json_value *spk = json_get(po, "scriptPubKey");
                if (!tid || !vn || !spk) continue;

                parse_hash_str(json_get_str(tid), &prevouts[num_prevouts].txid);
                prevouts[num_prevouts].vout = (uint32_t)json_get_int(vn);

                const char *spk_hex = json_get_str(spk);
                if (!spk_hex) continue;
                size_t spk_len = strlen(spk_hex) / 2;
                if (spk_len > MAX_SCRIPT_SIZE) spk_len = MAX_SCRIPT_SIZE;
                unsigned char spk_bytes[MAX_SCRIPT_SIZE];
                ParseHex(spk_hex, spk_bytes, spk_len);
                prevouts[num_prevouts].script_pub_key.size = spk_len;
                memcpy(prevouts[num_prevouts].script_pub_key.data,
                       spk_bytes, spk_len);

                const struct json_value *amt = json_get(po, "amount");
                prevouts[num_prevouts].amount = amt ?
                    (int64_t)(json_get_real(amt) * (double)ZATOSHI_PER_ZCL + 0.5) : 0;
                prevouts[num_prevouts].valid = true;

                /* Keep caller-supplied redeem scripts request-local too. */
                const struct json_value *rs = json_get(po, "redeemScript");
                if (rs && rs->type == JSON_STR) {
                    if (!overlay.scripts) {
                        size_t script_cap = json_size(prev_arr);
                        if (script_cap > 256) script_cap = 256;
                        overlay.scripts = zcl_calloc(
                            script_cap ? script_cap : 1,
                            sizeof(*overlay.scripts), "rawtx_sign_scripts");
                        if (!overlay.scripts) {
                            rawtx_sign_overlay_free(&overlay);
                            transaction_free(&tx);
                            json_set_str(result, "Out of memory");
                            LOG_FAIL("tx", "signrawtransaction: script overlay allocation failed");
                        }
                    }
                    struct script redeem = {0};
                    const char *rs_hex = json_get_str(rs);
                    if (!rs_hex) continue;
                    size_t rs_len = strlen(rs_hex) / 2;
                    if (rs_len > MAX_SCRIPT_SIZE) rs_len = MAX_SCRIPT_SIZE;
                    ParseHex(rs_hex, redeem.data, rs_len);
                    redeem.size = rs_len;
                    overlay.scripts[overlay.num_scripts++] = redeem;
                }

                num_prevouts++;
            }
        }
    }

    int tip_height = ctx->main_state ?
        active_chain_height(&ctx->main_state->chain_active) : 0;
    uint32_t branch_id = consensus_current_epoch_branch_id(
        tip_height + 1, &chain_params_get()->consensus);

    bool all_complete = true;
    struct json_value errors = {0};
    json_set_array(&errors);

    for (unsigned int i = 0; i < tx.num_vin; i++) {
        const struct script *prev_script = NULL;
        int64_t prev_amount = 0;

        /* Find scriptPubKey for this input */
        for (size_t j = 0; j < num_prevouts; j++) {
            if (prevouts[j].valid &&
                uint256_cmp(&tx.vin[i].prevout.hash, &prevouts[j].txid) == 0 &&
                tx.vin[i].prevout.n == prevouts[j].vout) {
                prev_script = &prevouts[j].script_pub_key;
                prev_amount = prevouts[j].amount;
                break;
            }
        }

        /* Try SQLite UTXO index first (instant) */
        if (!prev_script && rawtx_node_db() && rawtx_node_db()->open) {
            struct db_utxo u;
            if (db_utxo_find(rawtx_node_db(), tx.vin[i].prevout.hash.data,
                             tx.vin[i].prevout.n, &u) && num_prevouts < 256) {
                prevouts[num_prevouts].txid = tx.vin[i].prevout.hash;
                prevouts[num_prevouts].vout = tx.vin[i].prevout.n;
                prevouts[num_prevouts].script_pub_key.size = u.script_len;
                if (u.script_len <= MAX_SCRIPT_SIZE)
                    memcpy(prevouts[num_prevouts].script_pub_key.data,
                           u.script, u.script_len);
                prevouts[num_prevouts].amount = u.value;
                prevouts[num_prevouts].valid = true;
                prev_script = &prevouts[num_prevouts].script_pub_key;
                prev_amount = prevouts[num_prevouts].amount;
                num_prevouts++;
                db_utxo_free(&u);
            }
        }

        /* Fall back to coins DB (LevelDB) */
        if (!prev_script && ctx->coins_tip) {
            if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
                    "signrawtransaction", "Chainstate lookup")) {
                json_free(&errors);
                rawtx_sign_overlay_free(&overlay);
                transaction_free(&tx);
                return false;
            }
            struct coins entry;
            coins_init(&entry);
            if (coins_view_cache_get_coins(ctx->coins_tip,
                    &tx.vin[i].prevout.hash, &entry)) {
                if (tx.vin[i].prevout.n < entry.num_vout &&
                    !tx_out_is_null(&entry.vout[tx.vin[i].prevout.n])) {
                    if (num_prevouts < 256) {
                        prevouts[num_prevouts].txid = tx.vin[i].prevout.hash;
                        prevouts[num_prevouts].vout = tx.vin[i].prevout.n;
                        prevouts[num_prevouts].script_pub_key =
                            entry.vout[tx.vin[i].prevout.n].script_pub_key;
                        prevouts[num_prevouts].amount =
                            entry.vout[tx.vin[i].prevout.n].value;
                        prevouts[num_prevouts].valid = true;
                        prev_script = &prevouts[num_prevouts].script_pub_key;
                        prev_amount = prevouts[num_prevouts].amount;
                        num_prevouts++;
                    }
                }
                coins_free(&entry);
            }
        }

        if (!prev_script) {
            struct json_value err = {0};
            json_set_object(&err);
            json_push_kv_int(&err, "vout", (int64_t)i);
            json_push_kv_str(&err, "error", "Input not found or already spent");
            json_push_back(&errors, &err);
            json_free(&err);
            all_complete = false;
            continue;
        }


        if (!sign_one_input(&tx, i, prev_script, prev_amount,
                            branch_id, ctx->keystore, &overlay)) {
            struct json_value err = {0};
            json_set_object(&err);
            json_push_kv_int(&err, "vout", (int64_t)i);
            json_push_kv_str(&err, "error", "Unable to sign input");
            json_push_back(&errors, &err);
            json_free(&err);
            all_complete = false;
        }
    }

    transaction_compute_hash(&tx);

    json_set_object(result);
    char *hex = zcl_malloc(2 * 1024 * 1024, "tx_hex_buf");
    if (hex) {
        size_t hex_len = encode_hex_tx(&tx, hex, 2 * 1024 * 1024);
        hex[hex_len] = '\0';
        json_push_kv_str(result, "hex", hex);
        free(hex);
    }
    json_push_kv_bool(result, "complete", all_complete);
    if (!all_complete)
        json_push_kv(result, "errors", &errors);

    json_free(&errors);
    rawtx_sign_overlay_free(&overlay);
    transaction_free(&tx);
    return true;
}
