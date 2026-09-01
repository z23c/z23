/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Transparent wallet multisig and multi-recipient send RPC handlers:
 * createmultisig, sendmany, and addmultisigaddress. */

#include "controllers/wallet_controller_internal.h"
#include "controllers/sovereignty_controller.h"

bool rpc_createmultisig(const struct json_value *params, bool help,
                                struct json_value *result)
{
    RPC_HELP(help, result,
        "createmultisig nrequired [\"key\",...]\n"
        "Creates a multi-signature address with n required of m keys.\n"
        "Returns JSON with \"address\" and \"redeemScript\".");

    if (json_size(params) < 2) {
        json_set_str(result, "Expected at least 2 parameter(s)");
        LOG_FAIL("wallet", "createmultisig: expected at least 2 params, got %zu", json_size(params));
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    int n_required = (int)rpc_require_int(&p, 0, "nrequired");
    const struct json_value *keys_arr = json_at(params, 1);
    if (!keys_arr || keys_arr->type != JSON_ARR || json_size(keys_arr) == 0) {
        json_set_str(result, "keys must be a non-empty array");
        LOG_FAIL("wallet", "createmultisig: keys must be a non-empty array");
    }

    size_t n_keys = json_size(keys_arr);
    if (n_required < 1 || n_required > (int)n_keys || n_keys > 16) {
        json_set_str(result, "Invalid nrequired or too many keys");
        LOG_FAIL("wallet", "createmultisig: invalid nrequired=%d for %zu keys", n_required, n_keys);
    }

    struct pubkey pks[16];
    for (size_t i = 0; i < n_keys; i++) {
        const char *hex = json_get_str(json_at(keys_arr, i));
        if (!hex) {
            json_set_str(result, "Invalid key in array");
            LOG_FAIL("wallet", "createmultisig: NULL key at index %zu", i);
        }
        size_t hex_len = strlen(hex);
        if (hex_len != 66 && hex_len != 130) {
            json_set_str(result, "Invalid public key length");
            LOG_FAIL("wallet", "createmultisig: bad key length %zu at index %zu", hex_len, i);
        }
        unsigned char buf[65];
        size_t buf_len = ParseHex(hex, buf, sizeof(buf));
        if (buf_len != 33 && buf_len != 65) {
            json_set_str(result, "Invalid hex in key");
            LOG_FAIL("wallet", "createmultisig: invalid hex at index %zu", i);
        }
        pubkey_set(&pks[i], buf, buf_len);
        if (!pubkey_is_valid(&pks[i])) {
            json_set_str(result, "Invalid public key (not a valid EC point)");
            LOG_FAIL("wallet", "createmultisig: invalid EC point at index %zu", i);
        }
    }

    struct script redeem;
    script_for_multisig(&redeem, n_required, pks, n_keys);

    struct script_id sid;
    script_id_from_script(&sid, &redeem);

    struct tx_destination dest;
    dest.type = DEST_SCRIPT_ID;
    dest.id.script = sid;
    char addr[128];
    wallet_encode_destination(&dest, addr, sizeof(addr));

    char redeem_hex[MAX_SCRIPT_SIZE * 2 + 1];
    HexStr(redeem.data, redeem.size, false, redeem_hex, sizeof(redeem_hex));

    json_set_object(result);
    json_push_kv_str(result, "address", addr);
    json_push_kv_str(result, "redeemScript", redeem_hex);
    return true;
}

bool rpc_sendmany(const struct json_value *params, bool help,
                          struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "sendmany \"\" {\"address\":amount,...}\n"
        "Send to multiple addresses in one transaction.\n"
        "First argument must be \"\" (empty string).\n"
        "Second argument is a JSON object of address:amount pairs.");

    /* This is a distinct wallet broadcast entry point from sendtoaddress and
     * z_sendmany, so it must carry the same sovereign-state gate itself. A
     * typed wrapper cannot repair an unguarded RPC because a cookie holder
     * can invoke the RPC directly. Fire before wallet and parameter checks,
     * exactly like the other two spend surfaces. */
    {
        char sov_reason[96] = {0};
        if (!sovereignty_guard_allow("wallet_spend", sov_reason,
                                     sizeof(sov_reason))) {
            json_set_str(result, "Error: spend refused — tip is "
                                 "release_assisted (borrowed shielded "
                                 "history, not self-folded)");
            LOG_FAIL("wallet", "sendmany: refused — %s", sov_reason);
        }
    }

    if (json_size(params) < 2) {
        json_set_str(result, "Expected at least 2 parameter(s)");
        LOG_FAIL("wallet", "sendmany: expected at least 2 params, got %zu", json_size(params));
    }

    ENSURE_WALLET(result);

    const struct json_value *amounts = json_at(params, 1);
    if (!amounts || amounts->type != JSON_OBJ) {
        json_set_str(result, "amounts must be a JSON object");
        LOG_FAIL("wallet", "sendmany: amounts param is not a JSON object");
    }

    struct tx_destination dests[256];
    int64_t values[256];
    size_t n = 0;

    for (size_t i = 0; i < json_size(amounts) && n < 256; i++) {
        const char *addr = amounts->keys ? amounts->keys[i] : NULL;
        const struct json_value *val = json_at(amounts, i);
        if (!addr || !val) continue;

        if (!wallet_decode_address(addr, &dests[n])) {
            json_set_str(result, "Invalid address");
            LOG_FAIL("wallet", "sendmany: invalid address at index %zu", i);
        }

        values[n] = parse_amount(val);
        if (values[n] <= 0) {
            json_set_str(result, "Invalid amount");
            LOG_FAIL("wallet", "sendmany: invalid amount at index %zu", i);
        }
        n++;
    }

    if (n == 0) {
        json_set_str(result, "No recipients");
        LOG_FAIL("wallet", "sendmany: no recipients specified");
    }

    struct wallet_tx wtx;
    int64_t fee = 0;
    const char *error = NULL;
    if (!wallet_create_transaction_multi(ctx->wallet, dests, values, n,
                                          &wtx, &fee, &error)) {
        json_set_str(result, error ? error : "Transaction creation failed");
        LOG_FAIL("wallet", "sendmany: create multi-tx failed (%zu recipients): %s", n, error ? error : "unknown");
    }

    struct zcl_result commit = wallet_commit_from_context(ctx, &wtx);
    if (!commit.ok) {
        json_set_str(result, commit.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet", "sendmany: commit transaction failed (%zu recipients, "
                           "code=%d): %s", n, commit.code, commit.message);
    }

    struct zcl_result persisted =
        wallet_persist_commit_before_relay(ctx, &wtx);
    if (!persisted.ok) {
        json_set_str(result, persisted.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet", "sendmany: pre-relay durability failed "
                           "(code=%d): %s", persisted.code,
                           persisted.message);
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

bool rpc_addmultisigaddress(const struct json_value *params, bool help,
                                     struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "addmultisigaddress nrequired [\"key\",...]\n"
        "Add a multisig address to the wallet.\n"
        "Each key is a hex-encoded public key.\n"
        "The redeem script is stored in the wallet for spending.");

    if (json_size(params) < 2) {
        json_set_str(result, "Expected at least 2 parameter(s)");
        LOG_FAIL("wallet", "addmultisigaddress: expected at least 2 params, got %zu", json_size(params));
    }

    ENSURE_WALLET(result);

    struct rpc_params p;
    rpc_params_init(&p, params);
    int n_required = (int)rpc_require_int(&p, 0, "nrequired");
    const struct json_value *keys_arr = json_at(params, 1);
    if (!keys_arr || keys_arr->type != JSON_ARR || json_size(keys_arr) == 0) {
        json_set_str(result, "keys must be a non-empty array");
        LOG_FAIL("wallet", "addmultisigaddress: keys must be a non-empty array");
    }

    size_t n_keys = json_size(keys_arr);
    if (n_required < 1 || n_required > (int)n_keys || n_keys > 16) {
        json_set_str(result, "Invalid nrequired or too many keys");
        LOG_FAIL("wallet", "addmultisigaddress: invalid nrequired=%d for %zu keys", n_required, n_keys);
    }

    struct pubkey pks[16];
    for (size_t i = 0; i < n_keys; i++) {
        const char *hex = json_get_str(json_at(keys_arr, i));
        if (!hex) {
            json_set_str(result, "Invalid key in array");
            LOG_FAIL("wallet", "addmultisigaddress: NULL key at index %zu", i);
        }
        unsigned char buf[65];
        size_t buf_len = ParseHex(hex, buf, sizeof(buf));
        if (buf_len != 33 && buf_len != 65) {
            json_set_str(result, "Invalid public key");
            LOG_FAIL("wallet", "addmultisigaddress: bad key length %zu at index %zu", buf_len, i);
        }
        pubkey_set(&pks[i], buf, buf_len);
        if (!pubkey_is_valid(&pks[i])) {
            json_set_str(result, "Invalid public key (not a valid EC point)");
            LOG_FAIL("wallet", "addmultisigaddress: invalid EC point at index %zu", i);
        }
    }

    struct script redeem;
    script_for_multisig(&redeem, n_required, pks, n_keys);

    /* Store redeem script in wallet keystore */
    if (!keystore_add_cscript(&ctx->wallet->keystore, &redeem)) {
        json_set_str(result, "Failed to store redeem script (keystore full)");
        LOG_FAIL("wallet", "addmultisigaddress: keystore_add_cscript failed "
                           "(nrequired=%d, %zu keys)", n_required, n_keys);
    }

    struct script_id sid;
    script_id_from_script(&sid, &redeem);

    /* Persist script to wallet DB */
    if (ctx->wallet_db)
        wallet_sqlite_write_script(ctx->wallet_db, &sid.hash, &redeem);

    struct tx_destination dest;
    dest.type = DEST_SCRIPT_ID;
    dest.id.script = sid;
    char addr[128];
    wallet_encode_destination(&dest, addr, sizeof(addr));

    char redeem_hex[MAX_SCRIPT_SIZE * 2 + 1];
    HexStr(redeem.data, redeem.size, false, redeem_hex, sizeof(redeem_hex));

    json_set_object(result);
    json_push_kv_str(result, "address", addr);
    json_push_kv_str(result, "redeemScript", redeem_hex);
    return true;
}
