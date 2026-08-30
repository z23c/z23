/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Shielded key/viewing-key import-export and memo lookup RPC handlers. */

#include "base/hex.h"
#include "controllers/wallet_shielded_internal.h"

bool rpc_z_exportkey(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_exportkey \"zaddr\"\n"
        "\nReveals the spending key for a Sapling z-address.\n"
        "The key can be imported into another wallet with z_importkey.\n"
        "\nArguments:\n"
        "1. \"zaddr\"  (string, required) The z-address\n"
        "\nResult:\n"
        "\"key\"  (string) The spending key (bech32 encoded)\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *addr_str = rpc_require_str(&p, 0, "zaddr");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_exportkey: invalid params"); }

    ENSURE_WALLET(result);

    uint8_t z_d[11], z_pkd[32];
    if (!sapling_decode_payment_address(addr_str, z_d, z_pkd)) {
        json_set_str(result, "Invalid Sapling address");
        LOG_FAIL("wallet_shielded", "z_exportkey: invalid sapling address %s", addr_str);
    }

    const struct sapling_key_entry *ke =
        sapling_keystore_find_by_address(&ctx->wallet->sapling_keys, z_d, z_pkd);
    if (!ke) {
        json_set_str(result, "Wallet does not hold spending key for this z-address");
        LOG_FAIL("wallet_shielded", "z_exportkey: spending key not found for address %s", addr_str);
    }

    const struct chain_params *cp = chain_params_get();
    char encoded[512];
    if (!sapling_encode_extended_spending_key(&ke->xsk,
            cp->bech32HRPs[BECH32_SAPLING_EXTENDED_SPEND_KEY],
            encoded, sizeof(encoded))) {
        json_set_str(result, "Failed to encode spending key");
        LOG_FAIL("wallet_shielded", "z_exportkey: sapling_encode_extended_spending_key failed");
    }

    json_set_str(result, encoded);
    memory_cleanse(encoded, sizeof(encoded));
    return true;
}

bool rpc_z_importkey(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_importkey \"key\" ( rescan startHeight )\n"
        "\nImports a Sapling spending key (as returned by z_exportkey).\n"
        "\nArguments:\n"
        "1. \"key\"          (string, required) The spending key (bech32)\n"
        "2. rescan           (string, optional, default=\"whenkeyisnew\")\n"
        "                    \"yes\", \"no\", or \"whenkeyisnew\"\n"
        "3. startHeight      (numeric, optional, default=0) Start rescan height\n"
        "\nExamples:\n"
        "  z_importkey \"secret-extended-key-main1...\"\n"
        "  z_importkey \"secret-extended-key-main1...\" whenkeyisnew 500000\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 3);
    const char *key_str = rpc_require_str(&p, 0, "key");
    const char *rescan_str = rpc_permit_str(&p, 1, "rescan", "whenkeyisnew");
    int start_height = (int)rpc_permit_int(&p, 2, "startHeight", 0);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_importkey: invalid params"); }

    ENSURE_WALLET(result);

    /* Parse rescan option */
    bool do_rescan = true;
    bool ignore_existing = true;
    if (strcmp(rescan_str, "no") == 0) {
        do_rescan = false;
        ignore_existing = false;
    } else if (strcmp(rescan_str, "yes") == 0) {
        do_rescan = true;
        ignore_existing = false;
    }

    /* Decode spending key */
    struct zip32_xsk xsk;
    if (!sapling_decode_extended_spending_key(key_str, &xsk)) {
        json_set_str(result, "Invalid spending key");
        LOG_FAIL("wallet_shielded", "z_importkey: failed to decode spending key");
    }

    /* Import into keystore */
    if (!sapling_keystore_import_xsk(&ctx->wallet->sapling_keys, &xsk)) {
        memory_cleanse(&xsk, sizeof(xsk));
        if (ignore_existing) {
            json_set_null(result);
            return true;
        }
        json_set_str(result, "Key already exists in wallet");
        LOG_FAIL("wallet_shielded", "z_importkey: key already exists in wallet");
    }
    memory_cleanse(&xsk, sizeof(xsk));

    /* Persist to wallet DB. A failed write on imported material leaves
     * the spending key in memory but not on disk — user cannot recover
     * after restart. Return the error so they know. */
    if (ctx->wallet_db) {
        struct sapling_keystore *sks = &ctx->wallet->sapling_keys;
        if (sks->has_seed) {
            if (!wallet_sqlite_write_sapling_seed(ctx->wallet_db, sks->seed)) {
                json_set_str(result,
                    "Error: failed to persist Sapling seed. Key NOT imported. "
                    "Check getwalletinfo.persistence and node.log.");
                LOG_FAIL("wallet_shielded", "z_importkey: sapling_seed flush failed");
            }
        }
        if (!wallet_sqlite_write_sapling_key(ctx->wallet_db,
                sks->keys[sks->num_keys - 1].child_index,
                &sks->keys[sks->num_keys - 1])) {
            json_set_str(result,
                "Error: failed to persist Sapling key. Key NOT imported. "
                "Check getwalletinfo.persistence and node.log.");
            LOG_FAIL("wallet_shielded", "z_importkey: sapling_key flush failed");
        }
        wallet_backup_service_on_key_change();
    }

    if (do_rescan && ctx->main_state) {
        wallet_rescan(ctx->wallet, &ctx->main_state->chain_active,
                      start_height, -1, ctx->datadir);
    }

    json_set_null(result);
    return true;
}

bool rpc_z_exportviewingkey(const struct json_value *params, bool help,
                                     struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_exportviewingkey \"zaddr\"\n"
        "\nReveals the viewing key for a Sapling z-address.\n"
        "A viewing key allows seeing incoming transactions but not spending.\n"
        "\nArguments:\n"
        "1. \"zaddr\"  (string, required) The z-address\n"
        "\nResult:\n"
        "\"vkey\"  (string) The viewing key (bech32 encoded)\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *addr_str = rpc_require_str(&p, 0, "zaddr");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_exportviewingkey: invalid params"); }

    ENSURE_WALLET(result);

    uint8_t z_d[11], z_pkd[32];
    if (!sapling_decode_payment_address(addr_str, z_d, z_pkd)) {
        json_set_str(result, "Invalid Sapling address");
        LOG_FAIL("wallet_shielded", "z_exportviewingkey: invalid sapling address %s", addr_str);
    }

    const struct sapling_key_entry *ke =
        sapling_keystore_find_by_address(&ctx->wallet->sapling_keys, z_d, z_pkd);
    if (!ke) {
        json_set_str(result,
            "Wallet does not hold key for this z-address");
        LOG_FAIL("wallet_shielded", "z_exportviewingkey: key not found for address %s", addr_str);
    }

    const struct chain_params *cp = chain_params_get();
    char encoded[512];
    if (!sapling_encode_extended_full_viewing_key(&ke->xfvk,
            cp->bech32HRPs[BECH32_SAPLING_FULL_VIEWING_KEY],
            encoded, sizeof(encoded))) {
        json_set_str(result, "Failed to encode viewing key");
        LOG_FAIL("wallet_shielded", "z_exportviewingkey: sapling_encode_extended_full_viewing_key failed");
    }

    json_set_str(result, encoded);
    return true;
}

bool rpc_z_getmemo(const struct json_value *params, bool help,
                            struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_getmemo \"txid\" ( outindex )\n"
        "\nReturns the memo attached to a shielded note.\n"
        "\nArguments:\n"
        "1. \"txid\"      (string, required) Transaction ID\n"
        "2. outindex    (numeric, optional, default=0) Output index\n"
        "\nResult:\n"
        "{\n"
        "  \"txid\": \"hex\",\n"
        "  \"outindex\": n,\n"
        "  \"memo\": \"text or hex\",\n"
        "  \"memo_hex\": \"raw hex\",\n"
        "  \"memo_bytes\": n\n"
        "}\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *txid_str = rpc_require_str(&p, 0, "txid");
    int outindex = (int)rpc_permit_int(&p, 1, "outindex", 0);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_getmemo: invalid params"); }

    ENSURE_WALLET(result);

    if (!ctx->node_db) {
        json_set_str(result, "Database not available");
        LOG_FAIL("wallet_shielded", "z_getmemo: node_db is NULL");
    }

    uint8_t txid[32];
    if (!zcl_is_hex_string(txid_str, 64)) {
        json_set_str(result, "Invalid txid (expected 64-char hex)");
        LOG_FAIL("wallet_shielded", "z_getmemo: txid not 64 hex chars: '%s'",
                 txid_str ? txid_str : "(null)");
    }
    uint8_t txid_be[32];
    zcl_hex_decode(txid_str, txid_be, 32);
    for (int i = 0; i < 32; i++)
        txid[i] = txid_be[31 - i];

    struct db_sapling_note notes[16];
    int count = db_wallet_tx_notes(ctx->node_db, txid, notes, 16);
    if (count <= 0) {
        json_set_str(result, "No shielded notes found for this txid");
        LOG_FAIL("wallet_shielded", "z_getmemo: no notes found for txid=%s", txid_str);
    }

    struct db_sapling_note *found = NULL;
    for (int i = 0; i < count; i++) {
        if ((int)notes[i].output_index == outindex) {
            found = &notes[i];
            break;
        }
    }
    if (!found) {
        json_set_str(result, "No note at specified output index");
        LOG_FAIL("wallet_shielded", "z_getmemo: no note at outindex=%d for txid=%s", outindex, txid_str);
    }

    json_set_object(result);
    json_push_kv_str(result, "txid", txid_str);
    json_push_kv_int(result, "outindex", outindex);

    /* Find meaningful memo bytes (strip trailing 0xf6 padding and zeroes) */
    size_t memo_end = 0;
    bool has_content = false;
    for (size_t j = 0; j < found->memo_len && j < 512; j++) {
        if (found->memo[j] != 0 && found->memo[j] != 0xf6) {
            memo_end = j + 1;
            has_content = true;
        }
    }

    if (has_content) {
        /* Text representation if printable */
        if (found->memo[0] >= 0x20 && found->memo[0] < 0x7f) {
            size_t len = 0;
            while (len < memo_end && found->memo[len] >= 0x20)
                len++;
            char memo_str[513];
            memcpy(memo_str, found->memo, len);
            memo_str[len] = '\0';
            json_push_kv_str(result, "memo", memo_str);
        }

        /* Always include hex */
        char hex[1025];
        for (size_t j = 0; j < memo_end; j++)
            snprintf(hex + j * 2, 3, "%02x", found->memo[j]);
        hex[memo_end * 2] = '\0';
        json_push_kv_str(result, "memo_hex", hex);
        json_push_kv_int(result, "memo_bytes", (int64_t)memo_end);
    } else {
        json_push_kv_str(result, "memo", "(empty)");
        json_push_kv_int(result, "memo_bytes", 0);
    }

    return true;
}
