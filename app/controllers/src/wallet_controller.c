/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/wallet_controller_internal.h"
#include "controllers/wallet_shielded_controller.h"
#include "controllers/wallet_diagnostic_controller.h"
#include "controllers/wallet_rescan_controller.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/agent_session_controller.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/yardsale_wallet_controller.h"
#include "wallet/wallet_lock.h"
void rpc_wallet_set_state(struct wallet *w, struct main_state *ms,
                          const char *datadir, struct wallet_sqlite *wdb,
                          struct tx_mempool *mempool,
                          struct connman *connman)
{
    wallet_rpc_context_set_base(w, ms, datadir, wdb, mempool, connman);
}

void rpc_wallet_set_node_db(struct node_db *ndb)
{
    wallet_rpc_context_set_node_db(ndb);
}

void rpc_wallet_set_coins_tip(struct coins_view_cache *tip)
{
    wallet_rpc_context_set_coins_tip(tip);
}

static bool rpc_getnewaddress(const struct json_value *params, bool help,
                               struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getnewaddress\n"
        "Returns a new ZClassic address for receiving payments.");

    ENSURE_WALLET(result);

    char addr[128];
    char err[256];
    if (!wc_new_durable_address(addr, sizeof(addr), err, sizeof(err))) {
        char msg[300];
        (void)snprintf(msg, sizeof(msg), "Error: %s",
                       err[0] ? err : "address not created");
        json_set_str(result, msg);
        LOG_FAIL("wallet", "getnewaddress: %s", err[0] ? err : "failed");
    }

    json_set_str(result, addr);
    return true;
}

static bool rpc_getbalance(const struct json_value *params, bool help,
                            struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getbalance\n"
        "Returns the total available balance.");

    ENSURE_WALLET(result);

    /* The in-memory wallet is updated directly from each finalized block;
     * wallet_utxos is an asynchronous durable projection and can briefly lag
     * that exact state. Read the same locked source the coin selector uses so
     * confirmation, history, and balance become visible together. */
    int64_t balance = wallet_transparent_spendable_balance(ctx);
    char buf[32];
    format_amount(balance, buf, sizeof(buf));
    json_set_str(result, buf);
    return true;
}

static bool rpc_getunconfirmedbalance(const struct json_value *params,
                                       bool help, struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getunconfirmedbalance\n"
        "Returns the unconfirmed balance.");

    ENSURE_WALLET(result);

    int64_t balance = wallet_get_unconfirmed_balance(ctx->wallet);
    char buf[32];
    format_amount(balance, buf, sizeof(buf));
    json_set_str(result, buf);
    return true;
}

static bool rpc_getwalletinfo(const struct json_value *params, bool help,
                               struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getwalletinfo\n"
        "Returns wallet state info.");

    ENSURE_WALLET(result);

    json_set_object(result);
    char bal[32], ubal[32], ibal[32], fee[32];
    /* Use the finalized in-memory wallet, not its asynchronous wallet_utxos
     * projection, so the summary cannot report a stale balance immediately
     * after saying a transaction is confirmed. */
    int64_t balance = wallet_transparent_spendable_balance(ctx);
    format_amount(balance, bal, sizeof(bal));
    format_amount(wallet_get_unconfirmed_balance(ctx->wallet), ubal, sizeof(ubal));
    format_amount(wallet_get_immature_balance(ctx->wallet), ibal, sizeof(ibal));
    format_amount(ctx->wallet->default_fee, fee, sizeof(fee));
    json_push_kv_str(result, "balance", bal);
    json_push_kv_str(result, "unconfirmed_balance", ubal);
    json_push_kv_str(result, "immature_balance", ibal);
    json_push_kv_int(result, "txcount", (int64_t)wallet_history_count());
    json_push_kv_int(result, "keypoolsize", (int64_t)ctx->wallet->key_pool_size);
    json_push_kv_str(result, "paytxfee", fee);

    /* Persistence health block. Aggregates the canary status + a live
     * count query so operators and tooling can see at a glance whether
     * the wallet storage is healthy.
     *
     *   healthy = open && canary_ok && count known && !mismatch && no corrupt rows
     *
     * A false value here means the persistence-abort paths would fire
     * on the next restart — surface it before the user sends funds to
     * an address that won't survive reboot. */
    sqlite3 *wallet_sqlite_handle = (ctx->wallet_db && ctx->wallet_db->open)
                                      ? ctx->wallet_db->db
                                      : NULL;
    struct wallet_persistence_health h = wallet_persistence_get_health(
        wallet_sqlite_handle, (int)ctx->wallet->keystore.num_keys);

    struct json_value persistence = {0};
    json_init(&persistence);
    json_set_object(&persistence);
    json_push_kv_bool(&persistence, "healthy",
                       h.open && h.canary_ok && h.row_count >= 0 &&
                       !h.mismatch && h.corrupt_rows == 0);
    json_push_kv_bool(&persistence, "open",              h.open);
    json_push_kv_bool(&persistence, "canary_ok",         h.canary_ok);
    json_push_kv_int (&persistence, "canary_last_ok_ts", h.canary_last_ok_ts);
    json_push_kv_int (&persistence, "row_count",         h.row_count);
    json_push_kv_int (&persistence, "keystore_count",    h.keystore_count);
    json_push_kv_bool(&persistence, "mismatch",          h.mismatch);
    json_push_kv_int (&persistence, "corrupt_rows",      h.corrupt_rows);
    json_push_kv_str (&persistence, "last_error",        h.last_error);
    json_push_kv(result, "persistence", &persistence);

    /* Encryption-at-rest lock posture (wallet_lock). Surfaces whether the
     * wallet wraps keys at rest and whether it is currently unlocked, so an
     * operator sees at a glance that a spend will be refused until unlock. */
    struct json_value lock = {0};
    json_init(&lock);
    json_set_object(&lock);
    wallet_lock_status_json(&lock);
    json_push_kv(result, "lock", &lock);

    wallet_readiness_append_sapling(result);
    return true;
}

/* ── Encryption-at-rest lock/unlock surface ──────────────────────────── *
 *
 * A locked wallet cannot spend even when sync-trust permits WALLET_SPEND.
 * The passphrase is NEVER logged or echoed. */

static bool rpc_walletlockstatus(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result, "walletlockstatus\n"
        "Report wallet encryption-at-rest lock state (no secrets).");
    json_set_object(result);
    wallet_lock_status_json(result);
    return true;
}

static bool rpc_walletlock(const struct json_value *params, bool help,
                           struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result, "walletlock\n"
        "Lock the wallet: scrub the loaded passphrase and wipe decrypted "
        "spending keys from RAM. Spending is refused until walletunlock.");
    ENSURE_WALLET(result);
    wallet_lock_lock(ctx->wallet);
    json_set_object(result);
    wallet_lock_status_json(result);
    return true;
}

static bool rpc_walletunlock(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "walletunlock \"passphrase\"\n"
        "Unlock the wallet: cache the passphrase and reload decrypted keys.");
    ENSURE_WALLET(result);

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *pass = rpc_require_str(&p, 0, "passphrase");
    int64_t timeout = rpc_permit_int(&p, 1, "timeout_seconds", 300);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        /* Never echo the passphrase — the error body names only the arg. */
        LOG_FAIL("wallet", "walletunlock: invalid params");
    }

    struct zcl_result r = wallet_lock_unlock(ctx->wallet, ctx->wallet_db, pass);
    if (!r.ok) {
        json_set_str(result, "Error: wallet unlock failed "
                             "(wrong passphrase or no encrypted keys)");
        LOG_FAIL("wallet", "walletunlock: code=%d", r.code);
    }
    struct zcl_result armed =
        wallet_lock_arm_timeout(ctx->wallet, (uint32_t)timeout);
    if (!armed.ok) {
        json_set_str(result, "Error: wallet unlock timeout invalid");
        LOG_FAIL("wallet", "walletunlock: timer code=%d", armed.code);
    }
    json_set_object(result);
    wallet_lock_status_json(result);
    json_push_kv_int(result, "auto_lock_seconds", timeout);
    return true;
}

static bool rpc_walletencrypt(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "walletencrypt \"passphrase\"\n"
        "Wrap every plaintext wallet secret under the passphrase, then lock.");
    ENSURE_WALLET(result);
    if (!ctx->wallet_db || !ctx->wallet_db->open) {
        json_set_str(result, "Error: wallet persistence unavailable");
        LOG_FAIL("wallet", "walletencrypt: wallet db unavailable");
    }
    if (wallet_lock_encrypted_at_rest()) {
        json_set_str(result, "Error: wallet is already encrypted at rest");
        LOG_FAIL("wallet", "walletencrypt: already encrypted");
    }
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *pass = rpc_require_str(&p, 0, "passphrase");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("wallet", "walletencrypt: invalid passphrase argument");
    }
    struct zcl_result unlocked =
        wallet_lock_unlock(ctx->wallet, ctx->wallet_db, pass);
    if (!unlocked.ok) {
        json_set_str(result, "Error: wallet encryption setup failed");
        LOG_FAIL("wallet", "walletencrypt: unlock code=%d", unlocked.code);
    }
    struct zcl_result migrated =
        wallet_sqlite_migrate_transparent_keys_r(ctx->wallet_db, ctx->wallet);
    if (!migrated.ok) {
        wallet_lock_lock(ctx->wallet);
        json_set_str(result, "Error: wallet key encryption transaction failed");
        LOG_FAIL("wallet", "walletencrypt: key migration code=%d",
                 migrated.code);
    }
    struct zcl_result scrubbed =
        wallet_sqlite_scrub_plaintext_r(ctx->wallet_db);
    if (!scrubbed.ok) {
        wallet_lock_lock(ctx->wallet);
        json_set_str(result, "Error: wallet encryption transaction failed");
        LOG_FAIL("wallet", "walletencrypt: scrub code=%d", scrubbed.code);
    }
    wallet_lock_note_encrypted_at_rest();
    wallet_lock_lock(ctx->wallet);
    json_set_object(result);
    wallet_lock_status_json(result);
    json_push_kv_bool(result, "encrypted", true);
    return true;
}

static bool rpc_listunspent(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "listunspent ( minconf maxconf )\n"
        "Returns array of unspent transaction outputs.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 2);
    int min_conf = (int)rpc_permit_int(&p, 0, "minconf", 1);
    int max_conf = (int)rpc_permit_int(&p, 1, "maxconf", 9999999);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "listunspent: invalid params"); }

    ENSURE_WALLET(result);
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "listunspent", "Chainstate lookup"))
        return false;


    int tip = active_chain_height(&ctx->main_state->chain_active);

    json_set_array(result);

    /* SQLite model layer — authoritative UTXO source */
    if (wallet_ctx_db_ready(ctx)) {
        struct db_wallet_utxo utxos[4096];
        int n = db_wallet_utxo_list_unspent(ctx->node_db, utxos, 4096);
        for (int i = 0; i < n; i++) {
            int h = utxos[i].height;
            /* Fix height=0: look up real height from global UTXO index */
            if (h <= 0) {
                struct db_utxo global;
                if (db_utxo_find(ctx->node_db, utxos[i].txid,
                                  utxos[i].vout, &global)) {
                    h = global.height;
                    db_utxo_free(&global);
                }
            }
            int confs = (h > 0) ? tip - h + 1 : 0;
            if (confs < min_conf || confs > max_conf)
                continue;
            if (utxos[i].is_coinbase && confs < 100)
                continue;

            struct json_value entry = {0};
            json_init(&entry);
            json_set_object(&entry);

            struct uint256 txid_u;
            memcpy(txid_u.data, utxos[i].txid, 32);
            char txid_hex[65];
            uint256_get_hex(&txid_u, txid_hex);
            json_push_kv_str(&entry, "txid", txid_hex);
            json_push_kv_int(&entry, "vout", (int64_t)utxos[i].vout);

            /* Decode address from script */
            if (utxos[i].script && utxos[i].script_len > 0 &&
                utxos[i].script_len <= MAX_SCRIPT_SIZE) {
                struct script sc;
                script_init(&sc);
                memcpy(sc.data, utxos[i].script, utxos[i].script_len);
                sc.size = utxos[i].script_len;
                struct tx_destination dest;
                if (script_extract_destination(&sc, &dest)) {
                    char addr[128];
                    if (wallet_encode_destination(&dest, addr, sizeof(addr)))
                        json_push_kv_str(&entry, "address", addr);
                }
            }

            char amt_buf[32];
            format_amount(utxos[i].value, amt_buf, sizeof(amt_buf));
            json_push_kv_real(&entry, "amount", strtod(amt_buf, NULL));
            json_push_kv_int(&entry, "confirmations", (int64_t)confs);
            json_push_kv_bool(&entry, "spendable", true);
            json_push_kv_bool(&entry, "solvable", true);

            json_push_back(result, &entry);
            json_free(&entry);
            db_wallet_utxo_free(&utxos[i]);
        }
        return true;
    }

    /* Fallback: in-memory wallet */
    struct coin_entry coins[4096];
    size_t num_coins = 0;
    wallet_available_coins(ctx->wallet, coins, &num_coins, 4096,
                           min_conf > 0, false);
    for (size_t i = 0; i < num_coins; i++) {
        if (coins[i].depth < min_conf || coins[i].depth > max_conf)
            continue;

        struct json_value entry = {0};
        json_init(&entry);
        json_set_object(&entry);

        char txid[65];
        uint256_get_hex(&coins[i].wtx->tx.hash, txid);
        json_push_kv_str(&entry, "txid", txid);
        json_push_kv_int(&entry, "vout", (int64_t)coins[i].i);

        const struct tx_out *out = &coins[i].wtx->tx.vout[coins[i].i];
        struct tx_destination dest;
        if (script_extract_destination(&out->script_pub_key, &dest)) {
            char addr[128];
            if (wallet_encode_destination(&dest, addr, sizeof(addr)))
                json_push_kv_str(&entry, "address", addr);
        }

        char amt_buf[32];
        format_amount(out->value, amt_buf, sizeof(amt_buf));
        json_push_kv_real(&entry, "amount", strtod(amt_buf, NULL));
        json_push_kv_int(&entry, "confirmations", (int64_t)coins[i].depth);
        json_push_kv_bool(&entry, "spendable", coins[i].spendable);
        json_push_kv_bool(&entry, "solvable", coins[i].solvable);

        json_push_back(result, &entry);
        json_free(&entry);
    }

    return true;
}

static bool rpc_sendtoaddress(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "sendtoaddress \"address\" amount\n"
        "Send an amount to a given address.");

    /* Sovereign guard (same doctrine as rpc_z_sendmany): refuse the spend
     * while the tip is release_assisted (borrowed shielded history, not
     * self-folded). This RPC backs core.wallet.transaction.send and
     * vault.send — leaving it ungated would bypass the z_sendmany gate.
     * Fires before wallet/param checks, identically to z_sendmany. */
    {
        char sov_reason[96] = {0};
        if (!sovereignty_guard_allow("wallet_spend", sov_reason,
                                     sizeof(sov_reason))) {
            json_set_str(result, "Error: spend refused — tip is "
                                 "release_assisted (borrowed shielded "
                                 "history, not self-folded)");
            LOG_FAIL("wallet", "sendtoaddress: refused — %s", sov_reason);
        }
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 2, 2);
    const char *addr_str = rpc_require_str(&p, 0, "address");
    int64_t amount = rpc_require_amount(&p, 1, "amount");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "sendtoaddress: invalid params"); }

    ENSURE_WALLET(result);

    /* At-rest lock gate: a locked wallet cannot spend even when sync-trust
     * would permit WALLET_SPEND (the passphrase is not loaded, so its keys
     * are not decryptable/resident). Wallet-local only — no consensus effect. */
    {
        struct zcl_result lk = wallet_lock_spend_guard();
        if (!lk.ok) {
            json_set_str(result, "Error: wallet is locked — run "
                                 "walletunlock before spending");
            LOG_FAIL("wallet", "sendtoaddress: refused — wallet locked (code=%d)",
                     lk.code);
        }
    }

    if (amount <= 0) {
        json_set_str(result, "Invalid amount");
        LOG_FAIL("wallet", "sendtoaddress: invalid amount %lld", (long long)amount);
    }

    struct tx_destination dest;
    if (!wallet_decode_address(addr_str, &dest)) {
        json_set_str(result, "Invalid address");
        LOG_FAIL("wallet", "sendtoaddress: invalid address %s", addr_str);
    }

    struct wallet_tx wtx;
    int64_t fee = 0;
    const char *error = NULL;
    if (!wallet_create_transaction(ctx->wallet, &dest, amount,
                                    &wtx, &fee, &error)) {
        json_set_str(result, error ? error : "Transaction creation failed");
        LOG_FAIL("wallet", "sendtoaddress: create tx failed: %s", error ? error : "unknown");
    }

    /* Persist the wallet keystore (which now holds the freshly-minted change
     * key) to disk BEFORE broadcasting. The change key is RAM-only until this
     * flush; a flush failure (disk full / I/O error) AFTER broadcast would put
     * a tx on the wire that pays change to a key absent from disk — permanently
     * unspendable on restart. Treat a pre-broadcast flush failure as a hard
     * error and abort the send (write-ahead the key, like zclassicd). */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_flush_from_context(ctx);
        if (!fr.ok) {
            transaction_free(&wtx.tx);
            json_set_str(result, "Cannot persist change key before broadcast — send aborted");
            LOG_FAIL("wallet", "sendtoaddress: pre-broadcast key flush failed "
                               "(code=%d): %s", fr.code, fr.message);
        }
    }

    struct zcl_result commit = wallet_commit_from_context(ctx, &wtx);
    if (!commit.ok) {
        json_set_str(result, commit.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet", "sendtoaddress: commit transaction failed "
                           "(code=%d): %s", commit.code, commit.message);
    }

    struct zcl_result persisted =
        wallet_persist_commit_before_relay(ctx, &wtx);
    if (!persisted.ok) {
        json_set_str(result, persisted.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet", "sendtoaddress: pre-relay durability failed "
                           "(code=%d): %s", persisted.code,
                           persisted.message);
    }

    if (wallet_ctx_db_ready(ctx))
        node_db_sync_wallet_tx(ctx->node_db, &wtx.tx, ctx->wallet, 0);

    /* Relay to peers */
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &wtx.tx.hash);

    char txid[65];
    uint256_get_hex(&wtx.tx.hash, txid);
    json_set_str(result, txid);
    transaction_free(&wtx.tx);
    return true;
}

/* ── Direct C API for wallet view controller ──────────────── */

bool wallet_direct_sendtoaddress(const char *address, int64_t amount_sat,
                                  char *txid_out, size_t txid_out_size,
                                  char *error_out, size_t error_out_size)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)txid_out_size; /* always 65 bytes for hex txid */
    /* Sovereign guard, same as both RPC send paths. Fires first. This covers
     * the web-UI form's TRANSPARENT branch only — its shielded branch reaches
     * z_sendmany over wv_rpc_call without passing through here, so
     * serve_send_confirm (wallet_view_send.c) carries the guard for the form
     * as a whole, ahead of the transparent/shielded split. */
    {
        char sov_reason[96] = {0};
        if (!sovereignty_guard_allow("wallet_spend", sov_reason,
                                     sizeof(sov_reason))) {
            snprintf(error_out, error_out_size,
                     "Spend refused — tip is release_assisted (borrowed "
                     "shielded history, not self-folded)");
            LOG_FAIL("wallet", "direct_sendtoaddress: refused — %s",
                     sov_reason);
        }
    }
    if (!ctx->wallet) {
        snprintf(error_out, error_out_size, "Wallet not loaded");
        LOG_FAIL("wallet", "direct_sendtoaddress: wallet not loaded");
    }
    /* At-rest lock gate, same as both RPC send paths: the explorer/web-UI
     * send form must honor walletlock identically. */
    {
        struct zcl_result lk = wallet_lock_spend_guard();
        if (!lk.ok) {
            snprintf(error_out, error_out_size,
                     "Wallet is locked — run walletunlock before spending");
            LOG_FAIL("wallet",
                     "direct_sendtoaddress: refused — wallet locked (code=%d)",
                     lk.code);
        }
    }
    if (amount_sat <= 0) {
        snprintf(error_out, error_out_size, "Invalid amount");
        LOG_FAIL("wallet", "direct_sendtoaddress: invalid amount %lld", (long long)amount_sat);
    }

    struct tx_destination dest;
    if (!wallet_decode_address(address, &dest)) {
        snprintf(error_out, error_out_size, "Invalid address");
        LOG_FAIL("wallet", "direct_sendtoaddress: invalid address %s", address);
    }

    struct wallet_tx wtx;
    int64_t fee = 0;
    const char *err = NULL;
    if (!wallet_create_transaction(ctx->wallet, &dest, amount_sat, &wtx, &fee, &err)) {
        snprintf(error_out, error_out_size, "%s", err ? err : "Transaction creation failed");
        LOG_FAIL("wallet", "direct_sendtoaddress: create tx failed: %s", err ? err : "unknown");
    }

    /* Persist the change key BEFORE broadcast (see rpc_sendtoaddress): abort
     * the send if the keystore flush fails, so we never broadcast a tx whose
     * RAM-only change key isn't durable. */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_flush_from_context(ctx);
        if (!fr.ok) {
            transaction_free(&wtx.tx);
            snprintf(error_out, error_out_size,
                     "Cannot persist change key before broadcast — send aborted");
            LOG_FAIL("wallet", "direct_sendtoaddress: pre-broadcast key flush "
                               "failed (code=%d): %s", fr.code, fr.message);
        }
    }

    struct zcl_result commit = wallet_commit_from_context(ctx, &wtx);
    if (!commit.ok) {
        snprintf(error_out, error_out_size, "%s", commit.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet", "direct_sendtoaddress: commit transaction failed "
                           "(code=%d): %s", commit.code, commit.message);
    }

    struct zcl_result persisted =
        wallet_persist_commit_before_relay(ctx, &wtx);
    if (!persisted.ok) {
        snprintf(error_out, error_out_size, "%s", persisted.message);
        transaction_free(&wtx.tx);
        LOG_FAIL("wallet", "direct_sendtoaddress: pre-relay durability failed "
                           "(code=%d): %s", persisted.code,
                           persisted.message);
    }

    if (wallet_ctx_db_ready(ctx))
        node_db_sync_wallet_tx(ctx->node_db, &wtx.tx, ctx->wallet, 0);
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &wtx.tx.hash);

    uint256_get_hex(&wtx.tx.hash, txid_out);
    transaction_free(&wtx.tx);
    return true;
}

static bool rpc_rescanblockchain(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "rescanblockchain ( start_height stop_height )\n"
        "\nRescan the local blockchain for wallet transactions.\n"
        "\nArguments:\n"
        "1. start_height  (numeric, optional, default=0) Block height to start\n"
        "2. stop_height   (numeric, optional, default=tip) Block height to stop\n"
        "\nResult:\n"
        "{\n"
        "  \"start_height\": n,\n"
        "  \"stop_height\": n,\n"
        "  \"blocks_scanned\": n,        (bodies actually read off disk)\n"
        "  \"blocks_missing_data\": n,   (indexed but no block body here)\n"
        "  \"blocks_read_failed\": n,\n"
        "  \"blocks_no_index\": n,\n"
        "  \"outputs_found\": n,\n"
        "  \"shielded_notes_found\": n,\n"
        "  \"shielded_txs_unscanned\": n,\n"
        "  \"sapling_key_count\": n,\n"
        "  \"shielded_scan_skipped\": bool,\n"
        "  \"coverage_ok\": bool,\n"
        "  \"blocker\": \"NAME\"          (only when coverage_ok is false)\n"
        "}\n"
        "\nA zero outputs_found with coverage_ok=false does NOT mean the\n"
        "wallet is empty — this node could not read those blocks.\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 2);
    int start_height = (int)rpc_permit_int(&p, 0, "start_height", 0);
    int stop_height = (int)rpc_permit_int(&p, 1, "stop_height", -1);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "rescanblockchain: invalid params"); }

    ENSURE_WALLET(result);

    if (!ctx->main_state) {
        json_set_str(result, "Chain state not initialized");
        LOG_FAIL("wallet", "rescanblockchain: chain state not initialized");
    }
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "rescanblockchain",
            "Chainstate lookup"))
        return false;

    int tip = active_chain_height(&ctx->main_state->chain_active);
    if (stop_height < 0 || stop_height > tip)
        stop_height = tip;
    if (start_height < 0)
        start_height = 0;

    if (start_height > tip) {
        json_set_str(result, "start_height exceeds chain tip");
        LOG_FAIL("wallet", "rescanblockchain: start_height %d exceeds tip %d", start_height, tip);
    }

    struct wallet_rescan_report rep;
    wallet_rescan_report(ctx->wallet, &ctx->main_state->chain_active,
                         start_height, stop_height, ctx->datadir, &rep);
    wallet_rescan_report_to_json(result, &rep);
    return true;
}

static bool rpc_keypoolrefill(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "keypoolrefill ( newsize )\nFills the keypool.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    unsigned int new_size = (unsigned int)rpc_permit_int(&p, 0, "newsize", DEFAULT_KEYPOOL_SIZE);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "keypoolrefill: invalid params"); }

    ENSURE_WALLET(result);
    if (!ctx->wallet_db || !ctx->wallet_db->open) {
        json_set_str(result,
            "Error: wallet durability backend unavailable; keypool unchanged");
        LOG_FAIL("wallet", "keypoolrefill: refusing RAM-only keypool");
    }

    if (!wallet_top_up_key_pool(ctx->wallet, new_size)) {
        json_set_str(result, "Error refilling keypool");
        LOG_FAIL("wallet", "keypoolrefill: failed to refill keypool (size=%u)", new_size);
    }
    int64_t pool_generation =
        wallet_key_pool_generation_ceiling(ctx->wallet);

    /* Flush the fresh keypool entries. If persistence fails the
     * keypool indices still point into the keystore, but the on-disk
     * rows won't exist — on next restart the node would hand out a
     * pre-existing address twice. Log and error; canary will flag
     * the daemon as unhealthy and operator can intervene. */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_flush_from_context(ctx);
        if (!fr.ok) {
            json_set_str(result,
                "Error: keypool refilled in memory but persistence flush failed. "
                "Check getwalletinfo.persistence and node.log.");
            LOG_FAIL("wallet", "keypoolrefill: wallet_sqlite_flush_r failed "
                                "(new_size=%u, code=%d): %s",
                                new_size, fr.code, fr.message);
        }
        wallet_key_pool_mark_persisted_through(
            ctx->wallet, pool_generation);
        wallet_backup_service_on_keypool_topup();
    } else {
        wallet_key_pool_mark_persisted_through(
            ctx->wallet, pool_generation);
    }

    json_set_null(result);
    return true;
}

#if defined(_WIN32) && defined(__clang__)
/* Prevent Windows whole-program inlining: the child registrars otherwise
 * produce a roughly 1.6 MiB frame and trip the native PE stack probe. */
__attribute__((optnone))
#elif defined(_WIN32) && defined(__GNUC__)
__attribute__((optimize("no-inline", "no-inline-functions", "no-inline-small-functions")))
#endif
void register_wallet_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "wallet", "getnewaddress",        rpc_getnewaddress,        false },
        { "wallet", "getbalance",           rpc_getbalance,           false },
        { "wallet", "getunconfirmedbalance", rpc_getunconfirmedbalance, false },
        { "wallet", "getwalletinfo",        rpc_getwalletinfo,        false },
        { "wallet", "listunspent",          rpc_listunspent,          false },
        { "wallet", "sendtoaddress",        rpc_sendtoaddress,        false },
        { "wallet", "dumpprivkey",          rpc_dumpprivkey,          false },
        { "wallet", "importprivkey",        rpc_importprivkey,        false },
        { "wallet", "importaddress",       rpc_importaddress,        false },
        { "wallet", "setlabel",             rpc_setlabel,             false },
        { "wallet", "getaddressesbylabel",  rpc_getaddressesbylabel,  false },
        { "wallet", "listlabels",           rpc_listlabels,           false },
        { "wallet", "keypoolrefill",        rpc_keypoolrefill,        false },
        { "wallet", "listtransactions",     rpc_listtransactions,     false },
        { "wallet", "gettransaction",       rpc_gettransaction,       false },
        { "wallet", "rescanblockchain",     rpc_rescanblockchain,     false },
        { "wallet", "sendmany",             rpc_sendmany,             false },
        { "wallet", "createmultisig",       rpc_createmultisig,       false },
        { "wallet", "addmultisigaddress",   rpc_addmultisigaddress,   false },
        { "wallet", "walletlock",           rpc_walletlock,           false },
        { "wallet", "walletunlock",         rpc_walletunlock,         false },
        { "wallet", "walletencrypt",        rpc_walletencrypt,        false },
        { "wallet", "walletlockstatus",     rpc_walletlockstatus,     false },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);

    /* Register shielded and diagnostic sub-controllers */
    register_wallet_shielded_rpc_commands(t);
    register_wallet_diagnostic_rpc_commands(t);
    register_wallet_rescan_rpc_commands(t);
    register_vault_intent_rpc_commands(t);
    /* The yardsale wallet glue (yardsale.seller.arm|disarm|status,
     * yardsale.buy) rides the wallet family for the same reason: the
     * wallet, the seller profile, and the pending-buy table all live in
     * this process (app/services/src/yardsale_wallet_service*.c). */
    register_yardsale_wallet_rpc_commands(t);
    /* Agent spend grants ride the wallet family because that is what they
     * bound. The node is the SINGLE writer of agent_sessions and this method
     * is how the CLI's policy gates reach it — they run in a process with no
     * node.db. Needs no state wiring: the service resolves node.db through
     * app_runtime. See controllers/agent_session_controller.h. */
    register_agent_session_rpc_commands(t);
}
