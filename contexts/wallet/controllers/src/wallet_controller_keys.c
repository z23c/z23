/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Transparent wallet key/address import-export RPC handlers: dumpprivkey,
 * importprivkey, and importaddress. */

#include "controllers/wallet_controller_internal.h"

bool wallet_rpc_set_secret_string(struct json_value *result, char *secret,
                                  size_t secret_size, bool encoded)
{
    if (encoded) json_set_str(result, secret);
    memory_cleanse(secret, secret_size);
    return encoded;
}

bool rpc_dumpprivkey(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "dumpprivkey \"address\"\n"
        "Reveals the private key corresponding to 'address'.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *addr_str = rpc_require_str(&p, 0, "address");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "dumpprivkey: invalid params"); }

    ENSURE_WALLET(result);

    struct tx_destination dest;
    if (!wallet_decode_address(addr_str, &dest)) {
        json_set_str(result, "Invalid address");
        LOG_FAIL("wallet", "dumpprivkey: invalid address %s", addr_str);
    }

    if (dest.type != DEST_KEY_ID) {
        json_set_str(result, "Address does not refer to a key");
        LOG_FAIL("wallet", "dumpprivkey: address %s is not a key (type=%d)", addr_str, dest.type);
    }

    struct privkey key;
    if (!wallet_dump_key(ctx->wallet, &dest.id.key, &key)) {
        json_set_str(result, "Private key for address is not known");
        LOG_FAIL("wallet", "dumpprivkey: private key not found for %s", addr_str);
    }

    const struct chain_params *cp = chain_params_get();
    size_t sec_pfx_len;
    const unsigned char *sec_pfx = chain_params_base58_prefix(
        cp, B58_SECRET_KEY, &sec_pfx_len);

    char wif[128];
    bool ok = encode_secret(&key, sec_pfx, sec_pfx_len, wif, sizeof(wif));
    memory_cleanse(key.vch, 32);

    if (!wallet_rpc_set_secret_string(result, wif, sizeof(wif), ok)) {
        json_set_str(result, "Encoding failed");
        LOG_FAIL("wallet", "dumpprivkey: WIF encoding failed for %s", addr_str);
    }

    return true;
}

/* Verify that wallet_sqlite_write_key_r actually persisted the given key.
 * Returns true if the row was found and the stored privkey matches the
 * supplied one exactly. Returns false on any deviation. */
static bool wallet_readback_key(struct wallet_sqlite *ws,
                                 const struct pubkey *pk,
                                 const struct privkey *want)
{
    if (!ws || !pk || !want) return false;

    struct privkey got;
    privkey_init(&got);
    struct zcl_result rr = wallet_sqlite_read_single_key(ws, pk, &got);
    if (!rr.ok) return false;

    bool ok = got.fValid && memcmp(got.vch, want->vch, 32) == 0;
    memory_cleanse(got.vch, 32);
    return ok;
}

bool rpc_importprivkey(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "importprivkey \"privkey\" ( \"label\" )\n"
        "\nAdds a private key and instantly indexes UTXOs from SQLite.\n"
        "\nArguments:\n"
        "1. \"privkey\"     (string, required) The private key (WIF format)\n"
        "2. \"label\"       (string, optional) An optional label\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *wif = rpc_require_str(&p, 0, "privkey");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "importprivkey: invalid params"); }

    ENSURE_WALLET(result);

    const struct chain_params *cp = chain_params_get();
    size_t sec_pfx_len;
    const unsigned char *sec_pfx = chain_params_base58_prefix(
        cp, B58_SECRET_KEY, &sec_pfx_len);

    struct privkey key;
    if (!decode_secret(wif, sec_pfx, sec_pfx_len, &key)) {
        json_set_str(result, "Invalid private key encoding");
        LOG_FAIL("wallet", "importprivkey: invalid WIF encoding");
    }

    /* Derive pubkey FIRST so we can persist (and roll back) without
     * touching the keystore on a bad input. */
    struct pubkey pk;
    if (!privkey_get_pubkey(&key, &pk)) {
        memory_cleanse(key.vch, 32);
        json_set_str(result, "Failed to derive public key");
        LOG_FAIL("wallet", "importprivkey: failed to derive pubkey from privkey");
    }

    /* Persist BEFORE mutating the keystore. If the write fails we have
     * not touched wallet state — simply error out. */
    if (ctx->wallet_db) {
        struct zcl_result wr = wallet_sqlite_write_key_r(ctx->wallet_db, &pk, &key);
        if (!wr.ok) {
            memory_cleanse(key.vch, 32);
            json_set_str(result,
                "Error: wallet persistence failed. Key NOT imported. "
                "Check getwalletinfo.persistence and node.log.");
            LOG_FAIL("wallet", "importprivkey: wallet_sqlite_write_key_r "
                                "failed (code=%d): %s", wr.code, wr.message);
        }

        /* Readback: prove the write hit disk with the bytes we asked
         * for. A passing write + failing readback would silently lose
         * the key. */
        if (!wallet_readback_key(ctx->wallet_db, &pk, &key)) {
            memory_cleanse(key.vch, 32);
            json_set_str(result,
                "Error: wallet persistence readback mismatch. Key NOT imported. "
                "Check getwalletinfo.persistence and node.log.");
            LOG_FAIL("wallet", "importprivkey: readback mismatch after write_key");
        }
    }

    /* Persistence is verified — now it is safe to surface the key in
     * the keystore. A failure here (keystore full) rolls back the
     * just-persisted row so the two stay in sync. */
    if (!wallet_import_key(ctx->wallet, &key)) {
        if (ctx->wallet_db) {
            /* Best-effort: delete the row we just wrote. Failure is
             * tracked by the canary on next boot. */
            struct zcl_result dr = wallet_sqlite_delete_key_r(ctx->wallet_db,
                                                              &pk);
            if (!dr.ok)
                LOG_WARN("wallet", "importprivkey: best-effort key rollback "
                         "failed (code=%d): %s", dr.code, dr.message);
        }
        memory_cleanse(key.vch, 32);
        json_set_str(result, "Error adding key to wallet");
        LOG_FAIL("wallet", "importprivkey: failed to add key to wallet (keystore full?)");
    }

    if (ctx->wallet->time_first_key == 0)
        ctx->wallet->time_first_key = GetTime();

    /* Trigger JSON backup of the fresh wallet state. */
    if (ctx->wallet_db)
        wallet_backup_service_on_key_change();

    memory_cleanse(key.vch, 32);

    /* Instant UTXO index lookup — no rescan needed.
     * Hash160(pubkey) → query utxos table → copy to wallet_utxos. */
    uint8_t addr_hash[20];
    hash160(pk.vch, pk.size, addr_hash);

    if (ctx->node_db) {
        struct db_utxo utxos[512];
        int found = db_utxo_list_for_address(ctx->node_db, addr_hash,
                                              utxos, 512);
        for (int i = 0; i < found; i++) {
            struct db_utxo full;
            if (!db_utxo_find(ctx->node_db, utxos[i].txid, utxos[i].vout,
                              &full))
                continue;

            struct db_wallet_utxo wu;
            memset(&wu, 0, sizeof(wu));
            memcpy(wu.txid, full.txid, 32);
            wu.vout = full.vout;
            wu.value = full.value;
            memcpy(wu.address_hash, addr_hash, 20);
            wu.script = full.script;
            wu.script_len = full.script_len;
            wu.height = full.height;
            wu.is_coinbase = full.is_coinbase;

            db_wallet_utxo_save(ctx->node_db, &wu);
            db_utxo_free(&full);
        }

        int64_t bal = db_utxo_balance_for_address(ctx->node_db, addr_hash);
        printf("importprivkey: %d UTXOs, balance %.8f ZCL (instant)\n",
               found, (double)bal / 1e8);
    }

    json_set_null(result);
    return true;
}

bool rpc_importaddress(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "importaddress \"address\"\n"
        "\nWatch a transparent address without importing its private key.\n"
        "Tracks balance and transactions but cannot spend.\n"
        "\nArguments:\n"
        "1. \"address\"     (string, required) The transparent address\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *addr_str = rpc_require_str(&p, 0, "address");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "importaddress: invalid params"); }

    ENSURE_WALLET(result);

    struct tx_destination dest;
    if (!wallet_decode_address(addr_str, &dest)) {
        json_set_str(result, "Invalid address");
        LOG_FAIL("wallet", "importaddress: invalid address %s", addr_str);
    }

    if (dest.type != DEST_KEY_ID) {
        json_set_str(result, "Only transparent P2PKH addresses supported");
        LOG_FAIL("wallet", "importaddress: address %s is not P2PKH (type=%d)", addr_str, dest.type);
    }

    /* Already have the private key? Skip — nothing to do. */
    if (keystore_have_key(&ctx->wallet->keystore, &dest.id.key)) {
        json_set_str(result, "Address already in wallet with private key");
        LOG_FAIL("wallet", "importaddress: address %s already has private key", addr_str);
    }

    /* Add as watch-only to keystore. */
    zcl_mutex_lock(&ctx->wallet->cs);
    bool ok = keystore_add_watch_only_id(&ctx->wallet->keystore, &dest.id.key);
    zcl_mutex_unlock(&ctx->wallet->cs);

    if (!ok) {
        json_set_str(result, "Error: watch-only keystore full");
        LOG_FAIL("wallet", "importaddress: watch-only keystore full for %s", addr_str);
    }

    /* Persist to wallet DB. On failure, roll back the keystore add
     * so user state doesn't diverge from disk. */
    if (ctx->wallet_db) {
        if (!wallet_sqlite_write_watch_only(ctx->wallet_db,
                                             dest.id.key.id.data, addr_str)) {
            zcl_mutex_lock(&ctx->wallet->cs);
            (void)keystore_remove_watch_only(&ctx->wallet->keystore, &dest.id.key);
            zcl_mutex_unlock(&ctx->wallet->cs);
            json_set_str(result,
                "Error: wallet persistence failed. Watch-only address NOT saved. "
                "Check getwalletinfo.persistence and node.log.");
            LOG_FAIL("wallet", "importaddress: wallet_sqlite_write_watch_only failed "
                                "for %s — rolled back keystore", addr_str);
        }
        wallet_backup_service_on_key_change();
    }

    /* Instant UTXO index lookup — same as importprivkey. */
    uint8_t addr_hash[20];
    memcpy(addr_hash, dest.id.key.id.data, 20);

    int found = 0;
    int64_t bal = 0;
    if (ctx->node_db) {
        struct db_utxo utxos[512];
        found = db_utxo_list_for_address(ctx->node_db, addr_hash,
                                          utxos, 512);
        for (int i = 0; i < found; i++) {
            struct db_utxo full;
            if (!db_utxo_find(ctx->node_db, utxos[i].txid, utxos[i].vout,
                              &full))
                continue;

            struct db_wallet_utxo wu;
            memset(&wu, 0, sizeof(wu));
            memcpy(wu.txid, full.txid, 32);
            wu.vout = full.vout;
            wu.value = full.value;
            memcpy(wu.address_hash, addr_hash, 20);
            wu.script = full.script;
            wu.script_len = full.script_len;
            wu.height = full.height;
            wu.is_coinbase = full.is_coinbase;

            db_wallet_utxo_save(ctx->node_db, &wu);
            db_utxo_free(&full);
        }

        bal = db_utxo_balance_for_address(ctx->node_db, addr_hash);
    }

    printf("importaddress: %s watch-only, %d UTXOs, balance %.8f ZCL\n",
           addr_str, found, (double)bal / 1e8);

    json_set_object(result);
    json_push_kv_str(result, "address", addr_str);
    json_push_kv_bool(result, "watch_only", true);
    json_push_kv_int(result, "utxos", found);
    json_push_kv_real(result, "balance", (double)bal / 1e8);
    return true;
}

/* Reject a batch request the durable-address contract cannot serve: no
 * output buffer, a zero or oversized count, or nowhere to write a refusal. */
static bool wallet_direct_batch_args_invalid(
    char (*addresses)[WALLET_DIRECT_ADDRESS_MAX], size_t count,
    char *err_out, size_t err_max)
{
    return !addresses || count == 0 ||
        count > WALLET_DIRECT_ADDRESS_BATCH_MAX || !err_out || err_max == 0;
}

/* An address may only be created when the wallet database is present and
 * open — never from RAM alone. */
static bool wallet_direct_backend_unavailable(struct wallet_rpc_context *ctx)
{
    return !ctx->wallet_db || !ctx->wallet_db->open;
}

/* A legacy (non-HD) wallet draws receive addresses from the keypool, so an
 * empty persisted pool must be topped up before any address is minted. */
static bool wallet_direct_keypool_needs_topup(struct wallet_rpc_context *ctx,
                                              bool direct_generated)
{
    return !direct_generated &&
        wallet_key_pool_persisted_size(ctx->wallet) == 0;
}

/* Flush the just-topped-up keypool so no unpersisted address can be handed
 * out. With no database there is nothing to flush; `flush_out` receives the
 * flush result. */
static bool wallet_direct_topup_flush_ok(struct wallet_rpc_context *ctx,
                                         struct zcl_result *flush_out)
{
    if (!ctx->wallet_db)
        return true;
    *flush_out = wallet_flush_from_context(ctx);
    return flush_out->ok;
}

/* Undo a partial directly generated batch: drop the keys already added. */
static void wallet_direct_remove_generated_keys(struct wallet_rpc_context *ctx,
                                                const struct key_id *generated,
                                                size_t generated_count)
{
    for (size_t i = 0; i < generated_count; i++)
        (void)wallet_remove_key(ctx->wallet, &generated[i]);
}

/* Draw `count` receive addresses from the keypool, recording the key id
 * behind each one. On the first miss, report the partial count through
 * `*generated_count`, refuse into `err_out` and undo the keys a directly
 * generating wallet already produced. Returns true once the whole batch is
 * drawn. */
static bool wallet_direct_generate_addresses(
    struct wallet_rpc_context *ctx,
    char (*addresses)[WALLET_DIRECT_ADDRESS_MAX], size_t count,
    struct key_id *generated, size_t *generated_count,
    bool direct_generated, char *err_out, size_t err_max)
{
    size_t drawn = 0;
    for (; drawn < count; drawn++) {
        if (wallet_get_new_address_with_key_id(
                ctx->wallet, addresses[drawn], WALLET_DIRECT_ADDRESS_MAX,
                &generated[drawn]))
            continue;
        *generated_count = drawn;
        (void)snprintf(err_out, err_max,
                       "durable keypool ran out after %zu of %zu addresses",
                       drawn, count);
        if (direct_generated)
            wallet_direct_remove_generated_keys(ctx, generated, drawn);
        return false;
    }
    *generated_count = drawn;
    return true;
}

/* Write one freshly generated key as an encrypted row, then prove it is on
 * disk by reading it back. `wr_out` receives the write result, including the
 * refusal used when the key disappeared from the keystore. Returns true only
 * when the key is durable. */
static bool wallet_direct_write_and_verify_key(
    struct wallet_rpc_context *ctx, const struct key_id *kid,
    struct pubkey *pk, struct zcl_result *wr_out)
{
    struct privkey key;
    privkey_init(&key);
    bool have = keystore_get_key(
            &ctx->wallet->keystore, kid, &key) &&
        keystore_get_pubkey(&ctx->wallet->keystore, kid, pk);
    *wr_out = have
        ? wallet_sqlite_write_key_r(ctx->wallet_db, pk, &key)
        : ZCL_ERR(-1, "generated key disappeared before persistence");
    bool verified = wr_out->ok && wallet_readback_key(
        ctx->wallet_db, pk, &key);
    memory_cleanse(key.vch, sizeof(key.vch));
    return verified;
}

/* Remove the generated keys that never became durable, starting at
 * `first_unpersisted`. Returns how many keys were removed. */
static size_t wallet_direct_remove_unpersisted_suffix(
    struct wallet_rpc_context *ctx, const struct key_id *generated,
    size_t first_unpersisted, size_t generated_count)
{
    size_t removed = 0;
    for (size_t j = first_unpersisted; j < generated_count; j++)
        removed += wallet_remove_key(ctx->wallet, &generated[j]) ? 1 : 0;
    return removed;
}

/* Persist each key of a directly generated batch as its own encrypted row,
 * verifying every row by readback. Returns true when the whole batch is
 * durable. On the first failure the unpersisted suffix is removed from
 * memory and `*failed_at`, `*removed` and `*wr_out` describe the failure so
 * the caller can refuse and log it. */
static bool wallet_direct_persist_generated_keys(
    struct wallet_rpc_context *ctx,
    const struct key_id *generated, size_t generated_count,
    bool direct_generated, size_t *failed_at, size_t *removed,
    struct zcl_result *wr_out)
{
    if (!ctx->wallet_db || !direct_generated)
        return true;
    for (size_t i = 0; i < generated_count; i++) {
        struct pubkey pk;
        if (wallet_direct_write_and_verify_key(ctx, &generated[i], &pk,
                                               wr_out))
            continue;
        *failed_at = i + 1;
        *removed = wallet_direct_remove_unpersisted_suffix(
            ctx, generated, i + (wr_out->ok ? 1 : 0), generated_count);
        return false;
    }
    return true;
}

/* A legacy batch consumes pre-persisted keys, so the reduced pool must be
 * flushed before any address is returned. `flush_out` receives the flush
 * result. Returns true when the reduced pool is durable or there was
 * nothing to flush. */
static bool wallet_direct_persist_keypool_consumption(
    struct wallet_rpc_context *ctx, bool direct_generated,
    struct zcl_result *flush_out)
{
    if (!ctx->wallet_db || direct_generated)
        return true;
    *flush_out = wallet_flush_from_context(ctx);
    return flush_out->ok;
}

/* Mint a receive address that is DURABLE before it is handed out, writing the
 * refusal into `err_out` instead of an RPC result so both the RPC and the
 * direct C API can share it. The durability discipline is the whole point of
 * the function and must not be reimplemented by callers: an address returned
 * but not persisted loses every coin paid to it on the next restart. */
bool wallet_direct_getnewaddresses(
    char (*addresses)[WALLET_DIRECT_ADDRESS_MAX], size_t count,
    char *err_out, size_t err_max)
{
    struct wallet_rpc_context *ctx = wallet_ctx();

    if (wallet_direct_batch_args_invalid(addresses, count, err_out, err_max))
        return false;
    memset(addresses, 0, count * WALLET_DIRECT_ADDRESS_MAX);
    err_out[0] = '\0';

    if (!ctx->wallet) {
        (void)snprintf(err_out, err_max, "Wallet not loaded");
        LOG_FAIL("wallet", "new_durable_address: wallet not loaded");
    }
    if (wallet_direct_backend_unavailable(ctx)) {
        (void)snprintf(err_out, err_max,
            "wallet durability backend unavailable; address not created");
        LOG_FAIL("wallet",
                 "new_durable_address: refusing RAM-only receive address");
    }

    bool direct_generated = wallet_has_hd(ctx->wallet);
    if (wallet_direct_keypool_needs_topup(ctx, direct_generated)) {
        if (!wallet_top_up_key_pool(ctx->wallet, DEFAULT_KEYPOOL_SIZE)) {
            (void)snprintf(err_out, err_max, "keypool top-up failed");
            LOG_FAIL("wallet", "new_durable_address: keypool top-up failed");
        }
        int64_t pool_generation =
            wallet_key_pool_generation_ceiling(ctx->wallet);
        struct zcl_result topup_flush;
        if (!wallet_direct_topup_flush_ok(ctx, &topup_flush)) {
            (void)snprintf(err_out, err_max,
                "wallet persistence failed. No unpersisted keypool "
                "address was returned.");
            LOG_FAIL("wallet",
                     "new_durable_address: keypool durability failed "
                     "(code=%d): %s",
                     topup_flush.code, topup_flush.message);
        }
        wallet_key_pool_mark_persisted_through(
            ctx->wallet, pool_generation);
    }

    struct key_id generated[WALLET_DIRECT_ADDRESS_BATCH_MAX];
    size_t generated_count = 0;
    if (!wallet_direct_generate_addresses(ctx, addresses, count, generated,
                                          &generated_count, direct_generated,
                                          err_out, err_max)) {
        memset(addresses, 0, count * WALLET_DIRECT_ADDRESS_MAX);
        LOG_FAIL("wallet",
                 "new_durable_addresses: keypool ran out at %zu/%zu",
                 generated_count, count);
    }

    /* Persist only the fresh keys BEFORE handing out any address. A full
     * wallet flush re-encrypts every historical key; at hundreds of keys that
     * took longer than a block interval and made the money snapshot stale.
     * Each row write is encrypted and read back. On failure, keep any already
     * durable keys as harmless unused receive keys and remove only the exact
     * unpersisted suffix from memory. */
    size_t failed_at = 0;
    size_t removed = 0;
    struct zcl_result persist_wr;
    if (!wallet_direct_persist_generated_keys(ctx, generated,
                                              generated_count,
                                              direct_generated, &failed_at,
                                              &removed, &persist_wr)) {
        memset(addresses, 0, count * WALLET_DIRECT_ADDRESS_MAX);
        (void)snprintf(err_out, err_max,
            "incremental key persistence failed at %zu of %zu",
            failed_at, generated_count);
        LOG_FAIL("wallet",
                 "new_durable_addresses: incremental persist failed "
                 "at=%zu/%zu removed_unpersisted=%zu code=%d: %s",
                 failed_at, generated_count, removed, persist_wr.code,
                 persist_wr.message);
    }

    /* A legacy address consumes a pre-persisted key. The private key was
     * already durable, but its removal from the unused pool is new state: if
     * that membership survives a restart the same address can be handed out
     * twice. Persist the reduced pool before returning any address. */
    struct zcl_result pool_flush;
    if (!wallet_direct_persist_keypool_consumption(ctx, direct_generated,
                                                   &pool_flush)) {
        memset(addresses, 0, count * WALLET_DIRECT_ADDRESS_MAX);
        (void)snprintf(err_out, err_max,
                       "keypool consumption persistence failed");
        LOG_FAIL("wallet",
                 "new_durable_addresses: keypool consumption flush "
                 "failed code=%d: %s",
                 pool_flush.code, pool_flush.message);
    }

    /* Success: one coalesced backup trigger for the whole durable batch. */
    if (ctx->wallet_db)
        wallet_backup_service_on_key_change();

    return true;
}

bool wc_new_durable_address(char *addr_out, size_t addr_max,
                            char *err_out, size_t err_max)
{
    if (!addr_out || addr_max < 80)
        return false;
    char addresses[1][WALLET_DIRECT_ADDRESS_MAX];
    if (!wallet_direct_getnewaddresses(addresses, 1, err_out, err_max)) {
        addr_out[0] = '\0';
        return false;
    }
    (void)snprintf(addr_out, addr_max, "%s", addresses[0]);
    return true;
}

bool wallet_direct_getnewaddress(char *addr_out, size_t addr_max,
                                 char *err_out, size_t err_max)
{
    return wc_new_durable_address(addr_out, addr_max, err_out, err_max);
}
