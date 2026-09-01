/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ZSLP command service — command-side workflow helpers. */

#include "services/zslp_command_service.h"
#include "models/zslp.h"
#include "zslp/slp.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "core/uint256.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "validation/sighash.h"
#include "validation/txmempool.h"
#include "wallet/keystore.h"
#include "wallet/wallet.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ZSLP_DUST_ZAT 546
#define ZSLP_MAX_WALLET_COINS 4096

static void zslp_command_token_id_wire(const uint8_t internal[32],
                                       struct uint256 *wire)
{
    for (int i = 0; i < 32; i++)
        wire->data[i] = internal[31 - i];
}

static bool zslp_command_add_selected(struct coin_entry *selected,
                                      size_t *num_selected,
                                      const struct coin_entry *coin,
                                      int64_t *zcl_value)
{
    if (!selected || !num_selected || !coin || !coin->wtx || !zcl_value ||
        *num_selected >= ZSLP_MAX_WALLET_COINS)
        LOG_FAIL("zslp_cmd", "add_selected: invalid/full selection");
    int64_t value = coin->wtx->tx.vout[coin->i].value;
    if (value < 0 || *zcl_value > INT64_MAX - value)
        LOG_FAIL("zslp_cmd", "add_selected: transparent value overflow");
    selected[(*num_selected)++] = *coin;
    *zcl_value += value;
    return true;
}

static struct zcl_result zslp_command_add_fee_inputs(
    const struct coin_entry *available, size_t num_available,
    struct coin_entry *selected, size_t *num_selected, int64_t *selected_value,
    int64_t target)
{
    for (size_t i = 0; i < num_available && *selected_value < target; i++) {
        struct slp_output_metadata meta;
        if (!available[i].spendable ||
            slp_classify_tx_output(&available[i].wtx->tx,
                                   (uint32_t)available[i].i, &meta))
            continue;
        if (!zslp_command_add_selected(selected, num_selected, &available[i],
                                       selected_value))
            return ZCL_ERR(-1, "add_fee_inputs: selection failed");
    }
    if (*selected_value < target)
        return ZCL_ERR(-2, "add_fee_inputs: insufficient non-token ZCL for fee");
    return ZCL_OK;
}

static void zslp_command_set_opreturn(struct tx_out *out,
                                      const uint8_t *script, size_t script_len)
{
    memset(out, 0, sizeof(*out));
    out->script_pub_key.size = script_len;
    memcpy(out->script_pub_key.data, script, script_len);
}

struct zcl_result zslp_command_prepare_with_op_return(
    struct wallet *wallet, struct wallet_tx *wtx,
    const uint8_t *op_script, size_t script_len)
{
    const struct chain_params *cp;
    size_t old_nout;
    struct tx_out *new_vout;
    int height;
    uint32_t branch_id;

    if (!wallet || !wtx || !op_script || script_len == 0 ||
        script_len > MAX_SCRIPT_SIZE)
        return ZCL_ERR(-1, "prepare_with_op_return: NULL argument or empty script");

    old_nout = wtx->tx.num_vout;
    if (old_nout == SIZE_MAX)
        return ZCL_ERR(-2, "prepare_with_op_return: output count overflow");
    new_vout = tx_out_array_alloc(old_nout + 1, "zslp op_return vouts");
    if (!new_vout)
        return ZCL_ERR(-3, "prepare_with_op_return: allocation failed for %zu vouts",
                 old_nout + 1);

    new_vout[0].value = 0;
    new_vout[0].script_pub_key.size = script_len;
    memcpy(new_vout[0].script_pub_key.data, op_script, script_len);
    for (size_t i = 0; i < old_nout; i++)
        new_vout[i + 1] = wtx->tx.vout[i];
    free(wtx->tx.vout);
    wtx->tx.vout = new_vout;
    wtx->tx.num_vout = old_nout + 1;

    cp = chain_params_get();
    height = wallet->best_block_height;
    branch_id = consensus_current_epoch_branch_id(height + 1, &cp->consensus);

    zcl_mutex_lock(&wallet->cs);
    for (size_t i = 0; i < wtx->tx.num_vin; i++) {
        struct wallet_tx *prev_wtx = NULL;
        struct tx_destination prev_dest;
        struct privkey skey;
        struct pubkey spk;
        struct sighash_type ht;
        struct precomputed_tx_data txdata;
        struct uint256 sighash;
        unsigned char sig[SIGNATURE_SIZE + 1];
        size_t siglen = 0;
        struct script *ss;
        const struct tx_out *prev_out;

        for (size_t j = 0; j < wallet->num_wallet_tx; j++) {
            if (uint256_eq(&wallet->map_wallet[j].tx.hash,
                           &wtx->tx.vin[i].prevout.hash)) {
                prev_wtx = &wallet->map_wallet[j];
                break;
            }
        }
        if (!prev_wtx)
            continue;

        prev_out = &prev_wtx->tx.vout[wtx->tx.vin[i].prevout.n];
        if (!script_extract_destination(&prev_out->script_pub_key, &prev_dest))
            continue;
        if (!keystore_get_key(&wallet->keystore, &prev_dest.id.key, &skey))
            continue;

        privkey_get_pubkey(&skey, &spk);
        ht.raw = SIGHASH_ALL;
        precompute_tx_data(&wtx->tx, &txdata);
        if (!signature_hash(&prev_out->script_pub_key, &wtx->tx,
                            (unsigned int)i, ht, prev_out->value,
                            branch_id, &txdata, &sighash)) {
            memory_cleanse(skey.vch, 32);
            continue;
        }
        if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
            memory_cleanse(skey.vch, 32);
            continue;
        }
        sig[siglen++] = 0x01;

        ss = &wtx->tx.vin[i].script_sig;
        ss->size = 0;
        ss->data[ss->size++] = (unsigned char)siglen;
        memcpy(&ss->data[ss->size], sig, siglen);
        ss->size += siglen;
        ss->data[ss->size++] = (unsigned char)spk.size;
        memcpy(&ss->data[ss->size], spk.vch, spk.size);
        ss->size += spk.size;
        memory_cleanse(skey.vch, 32);
    }
    zcl_mutex_unlock(&wallet->cs);

    transaction_compute_hash(&wtx->tx);
    return ZCL_OK;
}

struct zcl_result zslp_command_commit_with_op_return(struct wallet *wallet,
                                        struct wallet_tx *wtx,
                                        const struct wallet_tx_admission *admission,
                                        const uint8_t *op_script,
                                        size_t script_len)
{
    if (!admission)
        return ZCL_ERR(-1, "commit_with_op_return: admission is required");
    struct zcl_result prepared = zslp_command_prepare_with_op_return(
        wallet, wtx, op_script, script_len);
    if (!prepared.ok)
        return ZCL_ERR(-2, "commit_with_op_return: %s", prepared.message);
    struct zcl_result commit =
        wallet_commit_transaction(wallet, wtx, admission);
    if (!commit.ok)
        return ZCL_ERR(-3, "commit_with_op_return: %s", commit.message);
    return ZCL_OK;
}

struct zcl_result zslp_command_build_genesis_base_tx(struct wallet *wallet,
                                        struct wallet_tx *wtx,
                                        int64_t *fee_paid,
                                        const char **tx_error)
{
    struct pubkey our_pk;
    struct key_id our_kid;
    struct tx_destination our_dest;
    struct tx_destination dests[2];
    int64_t vals[2] = { 546, 546 };

    if (!wallet || !wtx || !fee_paid)
        return ZCL_ERR(-1, "build_genesis_base_tx: NULL argument");
    if (!wallet_get_key_from_pool(wallet, &our_pk))
        return ZCL_ERR(-2, "build_genesis_base_tx: wallet_get_key_from_pool failed");

    our_kid = pubkey_get_id(&our_pk);
    our_dest.type = DEST_KEY_ID;
    our_dest.id.key = our_kid;
    dests[0] = our_dest;
    dests[1] = our_dest;
    if (!wallet_create_transaction_multi(wallet, dests, vals, 2, wtx,
                                         fee_paid, tx_error))
        return ZCL_ERR(-3, "build_genesis_base_tx: %s",
                 (tx_error && *tx_error) ? *tx_error : "wallet_create_transaction_multi failed");
    return ZCL_OK;
}

struct zcl_result zslp_command_build_send_base_tx(struct wallet *wallet,
                                     const char *to_addr,
                                     struct wallet_tx *wtx,
                                     int64_t *fee_paid,
                                     const char **tx_error)
{
    struct tx_destination dest;
    int64_t vals[1] = { 546 };

    if (!wallet || !to_addr || !wtx || !fee_paid)
        return ZCL_ERR(-1, "build_send_base_tx: NULL argument");
    if (!zslp_service_decode_transparent_destination(to_addr, &dest).ok)
        return ZCL_ERR(-2, "build_send_base_tx: invalid address %s", to_addr);
    if (!wallet_create_transaction_multi(wallet, &dest, vals, 1, wtx,
                                         fee_paid, tx_error))
        return ZCL_ERR(-3, "build_send_base_tx: %s",
                 (tx_error && *tx_error) ? *tx_error : "wallet_create_transaction_multi failed");
    return ZCL_OK;
}

struct zcl_result zslp_command_build_token_send_tx(
    struct wallet *wallet, const uint8_t token_id[32], const char *to_addr,
    uint64_t amount, struct wallet_tx *wtx, int64_t *fee_paid,
    const char **tx_error)
{
    if (!wallet || !token_id || !to_addr || !wtx || !fee_paid || !tx_error ||
        amount == 0)
        return ZCL_ERR(-1, "build_token_send_tx: invalid argument");

    struct tx_destination recipient;
    if (!zslp_service_decode_transparent_destination(to_addr, &recipient).ok)
        return ZCL_ERR(-2, "build_token_send_tx: invalid recipient address");

    struct coin_entry available[ZSLP_MAX_WALLET_COINS];
    size_t num_available = 0;
    wallet_available_coins_ex(wallet, available, &num_available,
                              ZSLP_MAX_WALLET_COINS, true, false, true);

    struct coin_entry selected[ZSLP_MAX_WALLET_COINS];
    size_t num_selected = 0;
    int64_t selected_zcl = 0;
    uint64_t selected_tokens = 0;
    struct tx_destination token_change_dest;
    bool have_token_change_dest = false;

    for (size_t i = 0; i < num_available && selected_tokens < amount; i++) {
        struct slp_output_metadata meta;
        if (!available[i].spendable ||
            !slp_classify_tx_output(&available[i].wtx->tx,
                                    (uint32_t)available[i].i, &meta) ||
            meta.role != SLP_OUTPUT_TOKEN ||
            memcmp(meta.token_id, token_id, 32) != 0)
            continue;
        if (UINT64_MAX - selected_tokens < meta.amount)
            return ZCL_ERR(-3, "build_token_send_tx: token input overflow");
        if (!have_token_change_dest) {
            const struct tx_out *prev =
                &available[i].wtx->tx.vout[available[i].i];
            if (!script_extract_destination(&prev->script_pub_key,
                                            &token_change_dest))
                return ZCL_ERR(-4, "build_token_send_tx: token input has no address");
            have_token_change_dest = true;
        }
        if (!zslp_command_add_selected(selected, &num_selected, &available[i],
                                       &selected_zcl))
            return ZCL_ERR(-5, "build_token_send_tx: selection failed");
        selected_tokens += meta.amount;
    }
    if (selected_tokens < amount)
        return ZCL_ERR(-6, "build_token_send_tx: insufficient confirmed token balance");

    uint64_t token_change = selected_tokens - amount;
    struct uint256 wire_token_id;
    zslp_command_token_id_wire(token_id, &wire_token_id);
    uint64_t quantities[2] = { amount, token_change };
    int quantity_count = token_change > 0 ? 2 : 1;
    uint8_t op_script[256];
    size_t op_len = slp_build_send(op_script, sizeof(op_script),
                                   &wire_token_id, quantities, quantity_count);
    if (op_len == 0)
        return ZCL_ERR(-7, "build_token_send_tx: SLP script build failed");

    struct tx_out outputs[3];
    memset(outputs, 0, sizeof(outputs));
    zslp_command_set_opreturn(&outputs[0], op_script, op_len);
    outputs[1].value = ZSLP_DUST_ZAT;
    script_for_destination(&outputs[1].script_pub_key, &recipient);
    size_t num_outputs = 2;
    if (token_change > 0) {
        outputs[2].value = ZSLP_DUST_ZAT;
        script_for_destination(&outputs[2].script_pub_key,
                               &token_change_dest);
        num_outputs++;
    }

    int64_t output_value = ZSLP_DUST_ZAT * (int64_t)(num_outputs - 1);
    int64_t fee = wallet_default_fee(wallet);
    if (fee < 0 || output_value > INT64_MAX - fee)
        return ZCL_ERR(-8, "build_token_send_tx: fee overflow");
    struct zcl_result funded = zslp_command_add_fee_inputs(
        available, num_available, selected, &num_selected, &selected_zcl,
        output_value + fee);
    if (!funded.ok)
        return funded;

    if (!wallet_create_transaction_selected(wallet, selected, num_selected,
                                             outputs, num_outputs, wtx,
                                             fee_paid, tx_error))
        return ZCL_ERR(-9, "build_token_send_tx: %s",
                       *tx_error ? *tx_error : "wallet build failed");
    return ZCL_OK;
}

struct zcl_result zslp_command_build_token_burn_tx(
    struct wallet *wallet, const uint8_t token_id[32], uint64_t amount,
    struct wallet_tx *wtx, int64_t *fee_paid, const char **tx_error)
{
    if (!wallet || !token_id || amount == 0 || !wtx || !fee_paid || !tx_error)
        return ZCL_ERR(-1, "build_token_burn_tx: invalid argument");

    struct coin_entry available[ZSLP_MAX_WALLET_COINS];
    size_t num_available = 0;
    wallet_available_coins_ex(wallet, available, &num_available,
                              ZSLP_MAX_WALLET_COINS, true, false, true);
    struct coin_entry selected[ZSLP_MAX_WALLET_COINS];
    size_t num_selected = 0;
    int64_t selected_zcl = 0;
    uint64_t selected_tokens = 0;
    struct tx_destination change_dest;
    bool have_change_dest = false;

    for (size_t i = 0; i < num_available && selected_tokens < amount; i++) {
        struct slp_output_metadata meta;
        if (!available[i].spendable ||
            !slp_classify_tx_output(&available[i].wtx->tx,
                                    (uint32_t)available[i].i, &meta) ||
            meta.role != SLP_OUTPUT_TOKEN ||
            memcmp(meta.token_id, token_id, 32) != 0)
            continue;
        if (UINT64_MAX - selected_tokens < meta.amount)
            return ZCL_ERR(-2, "build_token_burn_tx: token input overflow");
        const struct tx_out *prev =
            &available[i].wtx->tx.vout[available[i].i];
        if (!have_change_dest &&
            !script_extract_destination(&prev->script_pub_key, &change_dest))
            return ZCL_ERR(-3,
                "build_token_burn_tx: token input has no change address");
        have_change_dest = true;
        if (!zslp_command_add_selected(selected, &num_selected, &available[i],
                                       &selected_zcl))
            return ZCL_ERR(-4, "build_token_burn_tx: selection failed");
        selected_tokens += meta.amount;
    }
    if (selected_tokens < amount)
        return ZCL_ERR(-5,
            "build_token_burn_tx: insufficient confirmed token balance");

    uint64_t token_change = selected_tokens - amount;
    struct uint256 wire_token_id;
    zslp_command_token_id_wire(token_id, &wire_token_id);
    uint64_t quantities[1] = { token_change };
    uint8_t op_script[256];
    size_t op_len = slp_build_send(op_script, sizeof(op_script),
                                   &wire_token_id, quantities, 1);
    if (op_len == 0)
        return ZCL_ERR(-6, "build_token_burn_tx: SLP script build failed");

    struct tx_out outputs[2];
    memset(outputs, 0, sizeof(outputs));
    zslp_command_set_opreturn(&outputs[0], op_script, op_len);
    size_t num_outputs = 1;
    int64_t output_value = 0;
    if (token_change > 0) {
        outputs[1].value = ZSLP_DUST_ZAT;
        script_for_destination(&outputs[1].script_pub_key, &change_dest);
        num_outputs = 2;
        output_value = ZSLP_DUST_ZAT;
    }
    int64_t fee = wallet_default_fee(wallet);
    if (fee < 0 || output_value > INT64_MAX - fee)
        return ZCL_ERR(-7, "build_token_burn_tx: fee overflow");
    struct zcl_result funded = zslp_command_add_fee_inputs(
        available, num_available, selected, &num_selected, &selected_zcl,
        output_value + fee);
    if (!funded.ok) return funded;
    if (!wallet_create_transaction_selected(wallet, selected, num_selected,
                                             outputs, num_outputs, wtx,
                                             fee_paid, tx_error))
        return ZCL_ERR(-8, "build_token_burn_tx: %s",
                       *tx_error ? *tx_error : "wallet build failed");
    return ZCL_OK;
}

struct zcl_result zslp_command_build_token_genesis_tx(
    struct wallet *wallet, const char *ticker, const char *name,
    uint8_t decimals, uint64_t initial_supply, struct wallet_tx *wtx,
    int64_t *fee_paid, const char **tx_error)
{
    if (!wallet || !ticker || !name || !wtx || !fee_paid || !tx_error ||
        initial_supply == 0 || decimals > 9)
        return ZCL_ERR(-1, "build_token_genesis_tx: invalid argument");

    uint8_t op_script[256];
    size_t op_len = slp_build_genesis(op_script, sizeof(op_script), ticker,
                                      name, "", NULL, decimals, 2,
                                      initial_supply);
    if (op_len == 0)
        return ZCL_ERR(-2, "build_token_genesis_tx: SLP script build failed");

    struct pubkey owner_pk;
    if (!wallet_get_key_from_pool(wallet, &owner_pk))
        return ZCL_ERR(-3, "build_token_genesis_tx: cannot get owner address");
    struct tx_destination owner = {
        .type = DEST_KEY_ID,
        .id.key = pubkey_get_id(&owner_pk),
    };

    struct tx_out outputs[3];
    memset(outputs, 0, sizeof(outputs));
    zslp_command_set_opreturn(&outputs[0], op_script, op_len);
    outputs[1].value = ZSLP_DUST_ZAT;
    script_for_destination(&outputs[1].script_pub_key, &owner);
    outputs[2].value = ZSLP_DUST_ZAT;
    script_for_destination(&outputs[2].script_pub_key, &owner);

    struct coin_entry available[ZSLP_MAX_WALLET_COINS];
    size_t num_available = 0;
    wallet_available_coins(wallet, available, &num_available,
                           ZSLP_MAX_WALLET_COINS, true, false);
    struct coin_entry selected[ZSLP_MAX_WALLET_COINS];
    size_t num_selected = 0;
    int64_t selected_zcl = 0;
    int64_t fee = wallet_default_fee(wallet);
    if (fee < 0 || (int64_t)(2 * ZSLP_DUST_ZAT) > INT64_MAX - fee)
        return ZCL_ERR(-4, "build_token_genesis_tx: fee overflow");
    struct zcl_result funded = zslp_command_add_fee_inputs(
        available, num_available, selected, &num_selected, &selected_zcl,
        2 * ZSLP_DUST_ZAT + fee);
    if (!funded.ok)
        return funded;
    if (!wallet_create_transaction_selected(wallet, selected, num_selected,
                                             outputs, 3, wtx, fee_paid,
                                             tx_error))
        return ZCL_ERR(-5, "build_token_genesis_tx: %s",
                       *tx_error ? *tx_error : "wallet build failed");
    return ZCL_OK;
}

struct zcl_result zslp_command_build_token_mint_tx(
    struct wallet *wallet, const uint8_t token_id[32], const char *to_addr,
    uint64_t amount, struct wallet_tx *wtx, int64_t *fee_paid,
    const char **tx_error)
{
    if (!wallet || !token_id || !to_addr || !wtx || !fee_paid || !tx_error ||
        amount == 0)
        return ZCL_ERR(-1, "build_token_mint_tx: invalid argument");

    struct tx_destination recipient;
    if (!zslp_service_decode_transparent_destination(to_addr, &recipient).ok)
        return ZCL_ERR(-2, "build_token_mint_tx: invalid recipient address");

    struct coin_entry available[ZSLP_MAX_WALLET_COINS];
    size_t num_available = 0;
    wallet_available_coins_ex(wallet, available, &num_available,
                              ZSLP_MAX_WALLET_COINS, true, false, true);
    struct coin_entry selected[ZSLP_MAX_WALLET_COINS];
    size_t num_selected = 0;
    int64_t selected_zcl = 0;
    struct tx_destination baton_dest;
    bool found_baton = false;

    for (size_t i = 0; i < num_available; i++) {
        struct slp_output_metadata meta;
        if (!available[i].spendable ||
            !slp_classify_tx_output(&available[i].wtx->tx,
                                    (uint32_t)available[i].i, &meta) ||
            meta.role != SLP_OUTPUT_MINT_BATON ||
            memcmp(meta.token_id, token_id, 32) != 0)
            continue;
        const struct tx_out *prev =
            &available[i].wtx->tx.vout[available[i].i];
        if (!script_extract_destination(&prev->script_pub_key, &baton_dest))
            return ZCL_ERR(-3, "build_token_mint_tx: baton has no address");
        if (!zslp_command_add_selected(selected, &num_selected, &available[i],
                                       &selected_zcl))
            return ZCL_ERR(-4, "build_token_mint_tx: baton selection failed");
        found_baton = true;
        break;
    }
    if (!found_baton)
        return ZCL_ERR(-5, "build_token_mint_tx: wallet does not control the confirmed mint baton");

    struct uint256 wire_token_id;
    zslp_command_token_id_wire(token_id, &wire_token_id);
    uint8_t op_script[256];
    size_t op_len = slp_build_mint(op_script, sizeof(op_script),
                                   &wire_token_id, 2, amount);
    if (op_len == 0)
        return ZCL_ERR(-6, "build_token_mint_tx: SLP script build failed");

    struct tx_out outputs[3];
    memset(outputs, 0, sizeof(outputs));
    zslp_command_set_opreturn(&outputs[0], op_script, op_len);
    outputs[1].value = ZSLP_DUST_ZAT;
    script_for_destination(&outputs[1].script_pub_key, &recipient);
    outputs[2].value = ZSLP_DUST_ZAT;
    script_for_destination(&outputs[2].script_pub_key, &baton_dest);

    int64_t fee = wallet_default_fee(wallet);
    if (fee < 0 || (int64_t)(2 * ZSLP_DUST_ZAT) > INT64_MAX - fee)
        return ZCL_ERR(-7, "build_token_mint_tx: fee overflow");
    struct zcl_result funded = zslp_command_add_fee_inputs(
        available, num_available, selected, &num_selected, &selected_zcl,
        2 * ZSLP_DUST_ZAT + fee);
    if (!funded.ok)
        return funded;

    if (!wallet_create_transaction_selected(wallet, selected, num_selected,
                                             outputs, 3, wtx, fee_paid,
                                             tx_error))
        return ZCL_ERR(-8, "build_token_mint_tx: %s",
                       *tx_error ? *tx_error : "wallet build failed");
    return ZCL_OK;
}

struct zcl_result zslp_command_build_owner_base_tx(struct wallet *wallet,
                                     const char *owner_address,
                                     struct wallet_tx *wtx,
                                     int64_t *fee_paid,
                                     const char **tx_error)
{
    struct tx_destination owner_dest;

    if (!wallet || !owner_address || !wtx || !fee_paid)
        return ZCL_ERR(-1, "build_owner_base_tx: NULL argument");

    if (!zslp_service_decode_transparent_destination(owner_address,
                                                      &owner_dest).ok ||
        owner_dest.type != DEST_KEY_ID) {
        if (tx_error)
            *tx_error = "owner address is not a spendable P2PKH address";
        return ZCL_ERR(-2, "build_owner_base_tx: cannot decode owner "
                            "address '%s' as P2PKH", owner_address);
    }

    zcl_mutex_lock(&wallet->cs);
    int64_t fee = wallet->default_fee;
    int height = wallet->best_block_height;
    bool have_key = keystore_have_key(&wallet->keystore, &owner_dest.id.key);
    zcl_mutex_unlock(&wallet->cs);

    if (!have_key) {
        if (tx_error)
            *tx_error = "wallet does not control the name owner's "
                        "private key";
        return ZCL_ERR(-3, "build_owner_base_tx: wallet lacks owner key "
                            "for '%s'", owner_address);
    }

    struct coin_entry available[4096];
    size_t num_available = 0;
    wallet_available_coins(wallet, available, &num_available, 4096, true,
                           false);

    const struct coin_entry *picked = NULL;
    int64_t picked_value = 0;
    for (size_t i = 0; i < num_available; i++) {
        const struct tx_out *out =
            &available[i].wtx->tx.vout[available[i].i];
        struct tx_destination d;
        if (!script_extract_destination(&out->script_pub_key, &d))
            continue;
        if (d.type != DEST_KEY_ID)
            continue;
        if (memcmp(d.id.key.id.data, owner_dest.id.key.id.data, 20) != 0)
            continue;
        if (out->value < 546 + fee)
            continue;
        picked = &available[i];
        picked_value = out->value;
        break;
    }
    if (!picked) {
        if (tx_error)
            *tx_error = "no spendable coin controlled by the name owner "
                        "address";
        return ZCL_ERR(-4, "build_owner_base_tx: no funded coin under "
                            "'%s'", owner_address);
    }

    const struct chain_params *cp = chain_params_get();
    int epoch = consensus_current_epoch(height, &cp->consensus);

    memset(wtx, 0, sizeof(*wtx));
    transaction_init(&wtx->tx);
    if (epoch >= UPGRADE_SAPLING) {
        wtx->tx.overwintered = true;
        wtx->tx.version = SAPLING_TX_VERSION;
        wtx->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        wtx->tx.expiry_height = (uint32_t)(height + 20);
    } else if (epoch >= UPGRADE_OVERWINTER) {
        wtx->tx.overwintered = true;
        wtx->tx.version = OVERWINTER_TX_VERSION;
        wtx->tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        wtx->tx.expiry_height = (uint32_t)(height + 20);
    }

    int64_t change = picked_value - 546 - fee;
    size_t num_out = change > 0 ? 2 : 1;
    if (!transaction_alloc(&wtx->tx, 1, num_out)) {
        if (tx_error)
            *tx_error = "transaction allocation failed";
        return ZCL_ERR(-5, "build_owner_base_tx: transaction_alloc(1,%zu) "
                            "failed", num_out);
    }

    struct script dest_script;
    script_for_destination(&dest_script, &owner_dest);
    wtx->tx.vout[0].value = 546;
    wtx->tx.vout[0].script_pub_key = dest_script;
    if (num_out == 2) {
        wtx->tx.vout[1].value = change;
        wtx->tx.vout[1].script_pub_key = dest_script;
    }

    wtx->tx.vin[0].prevout.hash = picked->wtx->tx.hash;
    wtx->tx.vin[0].prevout.n = picked->i;
    wtx->tx.vin[0].sequence = UINT32_MAX - 1;

    *fee_paid = fee;
    return ZCL_OK;
}

static bool zslp_command_pick_token_id(const char *broadcast_txid,
                                       const struct zslp_token_create_request *req,
                                       char token_id_out[ZSLP_TOKEN_KEY_MAX + 1])
{
    const char *token_id = broadcast_txid;

    if (!req || !token_id_out)
        LOG_FAIL("zslp_cmd", "pick_token_id: NULL argument");
    if (!token_id || token_id[0] == '\0')
        token_id = req->ticker;
    if (!token_id || token_id[0] == '\0')
        LOG_FAIL("zslp_cmd", "pick_token_id: no txid and no ticker fallback");

    snprintf(token_id_out, ZSLP_TOKEN_KEY_MAX + 1, "%s", token_id);
    return true;
}

struct zcl_result zslp_command_finalize_genesis(const char *datadir,
                                   const char *broadcast_txid,
                                   const struct zslp_token_create_request *req,
                                   char token_id_out[ZSLP_TOKEN_KEY_MAX + 1])
{
    sqlite3 *db = NULL;
    bool owns_db = false;
    const char *validation_error;

    if (!datadir || !req || !token_id_out)
        return ZCL_ERR(-1, "finalize_genesis: NULL argument");

    validation_error = zslp_service_validate_create_request(req);
    if (validation_error)
        return ZCL_ERR(-2, "finalize_genesis: validation failed: %s",
                 validation_error);
    if (!zslp_command_pick_token_id(broadcast_txid, req, token_id_out))
        return ZCL_ERR(-3, "finalize_genesis: pick_token_id failed");
    ZCL_CHECK(zslp_service_open_db(datadir, &db, &owns_db));

    struct zcl_result store_res = zslp_service_store_token(
        db, token_id_out, req->ticker, req->name,
        req->decimals, (int64_t)req->initial_supply);
    if (!store_res.ok) {
        zslp_service_close_db(db, owns_db);
        return store_res;
    }
    zslp_service_close_db(db, owns_db);
    return ZCL_OK;
}

struct zcl_result zslp_command_credit_transfer(const char *datadir,
                                  const struct zslp_token_transfer_request *req)
{
    sqlite3 *db = NULL;
    bool owns_db = false;
    const char *validation_error;

    if (!datadir || !req)
        return ZCL_ERR(-1, "credit_transfer: NULL argument");

    validation_error = zslp_service_validate_transfer_request(req);
    if (validation_error)
        return ZCL_ERR(-2, "credit_transfer: validation failed: %s",
                 validation_error);
    ZCL_CHECK(zslp_service_open_db(datadir, &db, &owns_db));
    struct zcl_result credit_res = zslp_service_credit_balance(
        db, req->token_id, req->recipient_addr, req->amount);
    if (!credit_res.ok) {
        zslp_service_close_db(db, owns_db);
        return credit_res;
    }
    zslp_service_close_db(db, owns_db);
    return ZCL_OK;
}
