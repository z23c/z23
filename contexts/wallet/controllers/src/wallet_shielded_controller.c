/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Sapling shielded wallet RPC controller: registration plus address, balance,
 * and listing handlers. z_sendmany lives in wallet_shielded_send.c; key
 * import/export and memo lookup live in wallet_shielded_keys.c. Shared
 * includes, wallet_ctx(), and handler declarations live in
 * controllers/wallet_shielded_internal.h. */

#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_shield_address.h"
#include "wallet/wallet_lock.h"

/* Decode a 512-byte Sapling memo into a JSON field on `entry`, matching the
 * three former inline copies in z_listunspent / z_listreceivedbyaddress /
 * z_listallnotes. 0x00 and 0xf6 are padding/sentinel bytes (0xf6 marks an
 * empty memo). If no meaningful byte is present, nothing is added. If the
 * first byte is printable ASCII the memo is emitted as text under "memo"
 * (bytes up to the first 0x00 or 0xf6, the canonical text terminator);
 * otherwise it is hex-encoded under "memo_hex" with trailing padding stripped.
 * memo_len bounds the scan (callers without a length pass 512). */
void wallet_memo_to_json(struct json_value *entry,
                                const uint8_t *memo, size_t memo_len)
{
    size_t bound = memo_len < 512 ? memo_len : 512;
    size_t end = 0; /* one past the last meaningful (non-padding) byte */
    for (size_t j = 0; j < bound; j++)
        if (memo[j] != 0 && memo[j] != 0xf6)
            end = j + 1;
    if (end == 0)
        return; /* empty / all-padding memo */

    if (memo[0] >= 0x20 && memo[0] < 0x7f) {
        size_t len = 0;
        while (len < bound && memo[len] != 0 && memo[len] != 0xf6)
            len++;
        char memo_str[513];
        memcpy(memo_str, memo, len);
        memo_str[len] = '\0';
        json_push_kv_str(entry, "memo", memo_str);
    } else {
        char hex[1025];
        for (size_t j = 0; j < end; j++)
            snprintf(hex + j * 2, 3, "%02x", memo[j]);
        hex[end * 2] = '\0';
        json_push_kv_str(entry, "memo_hex", hex);
    }
}

bool rpc_z_getnewaddress(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "z_getnewaddress\n"
        "\nReturns a new Sapling shielded address.\n"
        "\nResult:\n"
        "\"address\"  (string) The new z-address\n");

    ENSURE_WALLET(result);
    if (!ctx->wallet_db || !ctx->wallet_db->open) {
        json_set_str(result,
            "Error: wallet durability backend unavailable; address not created");
        LOG_FAIL("wallet_shielded",
                 "z_getnewaddress: refusing RAM-only receive address");
    }

    /* A locked wallet has no seed in memory. Refuse before the keystore can
     * mint a replacement seed and overwrite the stored one. */
    {
        struct zcl_result lk = wallet_lock_spend_guard();
        if (!lk.ok || ctx->wallet->sapling_keys.locked) {
            json_set_str(result, "Error: wallet is locked - run walletunlock "
                                 "before creating addresses");
            LOG_FAIL("wallet_shielded",
                     "z_getnewaddress: refused, wallet locked (code=%d)",
                     lk.code);
        }
    }

    uint8_t diversifier[11];
    uint8_t pk_d[32];
    struct sapling_address_undo undo;
    if (!sapling_keystore_new_address_transactional(&ctx->wallet->sapling_keys,
                                          diversifier, pk_d, &undo)) {
        json_set_str(result, "Failed to generate Sapling address");
        LOG_FAIL("wallet_shielded", "sapling_keystore_new_address failed");
    }

    const struct chain_params *cp = chain_params_get();
    char addr[128];
    if (!sapling_encode_payment_address(diversifier, pk_d,
            cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            addr, sizeof(addr))) {
        (void)sapling_keystore_rollback_address(
            &ctx->wallet->sapling_keys, &undo);
        json_set_str(result, "Failed to encode address");
        LOG_FAIL("wallet_shielded", "sapling_encode_payment_address failed for HRP=%s", // wallet-log-ok:bech32-hrp-constant
                 cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS]);
    }

    /* Flush seed + child + next_child in one wallet transaction through the
     * node.db single-writer lane. If durability fails, remove exactly the
     * child appended above; the undo helper refuses to erase a concurrently
     * appended child. Never return an address absent from durable storage. */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_flush_from_context(ctx);
        if (!fr.ok) {
            bool rolled_back = sapling_keystore_rollback_address(
                &ctx->wallet->sapling_keys, &undo);
            json_set_str(result,
                "Error: failed to persist Sapling address. Address NOT saved. "
                "Check getwalletinfo.persistence and node.log.");
            LOG_FAIL("wallet_shielded",
                     "z_getnewaddress: atomic wallet flush failed "
                     "(code=%d rollback=%d): %s",
                     fr.code, (int)rolled_back, fr.message);
        }
        wallet_backup_service_on_key_change();
    }

    json_set_str(result, addr);
    return true;
}

#ifdef ZCL_TESTING
static bool g_receive_fault_after_reserve;

void wallet_receive_fault_after_reserve_for_test(bool on)
{
    g_receive_fault_after_reserve = on;
}
#endif

bool rpc_z_getreceiveaddress(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "z_getreceiveaddress\n"
        "\nReturns the next unused diversified Sapling address of the wallet\n"
        "account. The index is recorded in the wallet database before the\n"
        "address is returned, so an address is never returned twice. Works\n"
        "while the wallet is locked: it needs viewing material only.\n"
        "\nResult:\n"
        "\"address\"  (string) The new z-address\n");

    ENSURE_WALLET(result);
    if (!ctx->wallet_db || !ctx->wallet_db->open) {
        json_set_str(result,
            "Error: wallet durability backend unavailable; address not issued");
        LOG_FAIL("wallet_shielded",
                 "z_getreceiveaddress: refusing an address with no durable index");
    }

    /* Deliberately no wallet_lock_spend_guard(): the address comes from the
     * account's incoming viewing key and diversifier key, both resident while
     * locked. No seed or spending key is read or written. */
    struct sapling_key_entry acct;
    if (!sapling_keystore_copy_receive_account(&ctx->wallet->sapling_keys, &acct)) {
        json_set_str(result, "Error: the wallet has no shielded account");
        LOG_FAIL("wallet_shielded",
                 "z_getreceiveaddress: keystore holds no account");
    }

    uint8_t diversifier[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    struct zcl_result reserved = wallet_reserve_diversifier_from_context(
        ctx, &acct, diversifier, pk_d);
    memory_cleanse(&acct, sizeof(acct));
    if (!reserved.ok) {
        json_set_str(result, reserved.code == WALLET_RESERVE_CATCHING_UP
            ? "Error: the node is catching up; a new address is available "
              "when it is in sync"
            : "Error: failed to record the address index. Address NOT issued.");
        LOG_FAIL("wallet_shielded",
                 "z_getreceiveaddress: index not recorded (code=%d): %s",
                 reserved.code, reserved.message);
    }
#ifdef ZCL_TESTING
    if (g_receive_fault_after_reserve) {
        json_set_str(result, "Error: simulated failure after the index write");
        LOG_FAIL("wallet_shielded", "z_getreceiveaddress: simulated failure");
    }
#endif

    const struct chain_params *cp = chain_params_get();
    char addr[128];
    if (!sapling_encode_payment_address(diversifier, pk_d,
            cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            addr, sizeof(addr))) {
        json_set_str(result, "Failed to encode address");
        LOG_FAIL("wallet_shielded",
                 "z_getreceiveaddress: address encoding failed");
    }
    json_set_str(result, addr);
    return true;
}

bool rpc_z_listaddresses(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "z_listaddresses\n"
        "\nReturns all Sapling z-addresses in the wallet.\n");

    ENSURE_WALLET(result);

    json_set_array(result);
    const struct chain_params *cp = chain_params_get();

    for (size_t i = 0; i < ctx->wallet->sapling_keys.num_keys; i++) {
        if (!ctx->wallet->sapling_keys.keys[i].used) continue;
        char addr[128];
        if (sapling_encode_payment_address(
                ctx->wallet->sapling_keys.keys[i].diversifier,
                ctx->wallet->sapling_keys.keys[i].pk_d,
                cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                addr, sizeof(addr))) {
            struct json_value s = {0};
            json_init(&s);
            json_set_str(&s, addr);
            json_push_back(result, &s);
            json_free(&s);
        }
    }

    return true;
}

static bool wallet_sapling_address_balance(struct wallet_rpc_context *ctx,
        const uint8_t z_d[11], const uint8_t z_pkd[32], int minconf,
        struct json_value *result)
{
    /* SQLite is the authoritative shielded-note store (z_gettotalbalance /
     * z_listunspent read it). The in-memory note array is a strict subset
     * post-restart (no load-from-DB path) and its `confirms` field is never
     * populated, so trusting it here under-reported the balance and ignored
     * minconf. Always derive the per-address balance from the DB with a
     * minconf-aware query. */
    if (!wallet_ctx_db_ready(ctx)) return wallet_balance_unavailable(result);
    int64_t balance = 0;
    const struct sapling_key_entry *ske =
        sapling_keystore_find_by_owned_address(&ctx->wallet->sapling_keys, z_d, z_pkd);
    if (ske) {
        int tip = ctx->wallet->best_block_height;
        if (tip == 0 && ctx->main_state)
            tip = active_chain_height(&ctx->main_state->chain_active);
        if (minconf > 0 && tip == 0) {
            tip = db_wallet_chain_tip_height(ctx->node_db);
            if (tip < 0) return wallet_balance_unavailable(result);
        }
        balance = db_sapling_note_balance_for_diversifier_minconf(
            ctx->node_db, ske->ivk, z_d, tip, minconf);
        if (balance < 0) return wallet_balance_unavailable(result);
    }
    char buf[32];
    format_amount(balance, buf, sizeof(buf));
    json_set_str(result, buf);
    return true;
}

bool rpc_z_getbalance(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_getbalance \"address\" ( minconf )\n"
        "\nReturns the balance for a taddr or zaddr.\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *addr_str = rpc_require_str(&p, 0, "address");
    int minconf = (int)rpc_permit_int(&p, 1, "minconf", 1);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_getbalance: invalid params"); }

    ENSURE_WALLET(result);
    if (wallet_readiness_get(ctx->wallet).state != WALLET_READINESS_READY) {
        json_set_str(result, "Wallet balance unavailable during cutover");
        return false;
    }

    /* Check if Sapling address */
    uint8_t z_d[11], z_pkd[32];
    if (sapling_decode_payment_address(addr_str, z_d, z_pkd)) {
        return wallet_sapling_address_balance(ctx, z_d, z_pkd, minconf, result);
    }

    /* Transparent address — sum UTXOs */
    struct tx_destination dest;
    if (!wallet_decode_address(addr_str, &dest)) {
        json_set_str(result, "Invalid address");
        LOG_FAIL("wallet_shielded", "z_getbalance: decode_destination failed");
    }

    int64_t balance = 0;
    struct coin_entry coins[4096];
    size_t num_coins = 0;
    wallet_available_coins(ctx->wallet, coins, &num_coins, 4096,
                            minconf > 0, false);

    struct script addr_script;
    addr_script.size = 0;
    script_for_destination(&addr_script, &dest);

    for (size_t i = 0; i < num_coins; i++) {
        const struct tx_out *out = &coins[i].wtx->tx.vout[coins[i].i];
        if (out->script_pub_key.size == addr_script.size &&
            memcmp(out->script_pub_key.data, addr_script.data,
                   addr_script.size) == 0) {
            if (coins[i].depth >= minconf)
                balance += out->value;
        }
    }

    char buf[32];
    format_amount(balance, buf, sizeof(buf));
    json_set_str(result, buf);
    return true;
}

/* z_listunspent: list unspent Sapling notes */
bool rpc_z_listunspent(const struct json_value *params, bool help,
                               struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_listunspent ( minconf maxconf )\n"
        "\nReturns list of unspent shielded notes.\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    int minconf = (int)rpc_permit_int(&p, 0, "minconf", 0);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_listunspent: invalid params"); }

    ENSURE_WALLET(result);
    if (wallet_readiness_get(ctx->wallet).state != WALLET_READINESS_READY) {
        json_set_str(result, "Wallet funds unavailable during cutover");
        return false;
    }

    json_set_array(result);

    /* Always read from SQLite (authoritative source for shielded notes).
     * Load ALL unspent notes (no 256-cap that would silently truncate the
     * list below the reported balance). */
    if (ctx->node_db) {
        struct db_sapling_note *db_notes = NULL;
        int count = db_sapling_note_list_unspent_alloc(ctx->node_db, &db_notes);
        if (count < 0)
            count = 0;
        const struct chain_params *cp = chain_params_get();
        const char *z_hrp = cp
            ? cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS]
            : "zs";
        int chain_h = ctx->wallet->best_block_height;
        if (chain_h == 0 && ctx->main_state)
            chain_h = active_chain_height(&ctx->main_state->chain_active);
        if (chain_h == 0 && wallet_ctx_db_ready(ctx)) {
            int db_height = db_block_max_height_any_status(ctx->node_db);
            if (db_height >= 0)
                chain_h = db_height;
        }
        for (int i = 0; i < count; i++) {
            struct db_sapling_note *n = &db_notes[i];
            int confirms = chain_h - n->block_height + 1;
            if (confirms < minconf)
                continue;

            struct json_value entry = {0};
            json_init(&entry);
            json_set_object(&entry);

            char txid_hex[65];
            wallet_txid_hex_le(n->txid, txid_hex);
            json_push_kv_str(&entry, "txid", txid_hex);
            json_push_kv_int(&entry, "outindex", n->output_index);

            char z_addr[128];
            sapling_encode_payment_address(n->diversifier, n->pk_d,
                                            z_hrp, z_addr, sizeof(z_addr));
            json_push_kv_str(&entry, "address", z_addr);

            char amount_buf[32];
            format_amount(n->value, amount_buf, sizeof(amount_buf));
            json_push_kv_str(&entry, "amount", amount_buf);

            json_push_kv_int(&entry, "confirmations", (int64_t)confirms);
            json_push_kv_int(&entry, "block_height", (int64_t)n->block_height);

            wallet_memo_to_json(&entry, n->memo, n->memo_len);

            json_push_back(result, &entry);
            json_free(&entry);
        }
        free(db_notes);
    }
    return true;
}

struct wallet_owned_balances {
    int64_t shielded;
    int64_t encumbered;
};

static bool wallet_read_owned_balances(struct node_db *db, void *context)
{
    struct wallet_owned_balances *balances = context;
    int64_t shielded = db_sapling_note_balance(db);
    int64_t t_locked = db_wallet_utxo_encumbered_balance(db);
    int64_t z_locked = db_sapling_note_encumbered_balance(db);
    if (shielded < 0 || t_locked < 0 || z_locked < 0 || t_locked > INT64_MAX - z_locked)
        return false;
    balances->shielded = shielded;
    balances->encumbered = t_locked + z_locked;
    return true;
}

bool rpc_z_gettotalbalance(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_gettotalbalance ( minconf )\n"
        "\nReturn the total value of funds stored in the wallet.\n"
        "\nResult:\n"
        "{\n"
        "  \"transparent\": \"x.xxxx\",\n"
        "  \"private\": \"x.xxxx\",\n"
        "  \"total\": \"x.xxxx\"\n"
        "}\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    (void)rpc_permit_int(&p, 0, "minconf", 1);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_gettotalbalance: invalid params"); }

    ENSURE_WALLET(result);
    if (wallet_readiness_get(ctx->wallet).state != WALLET_READINESS_READY) {
        json_set_str(result, "Wallet balance unavailable during cutover");
        return false;
    }

    /* Transparent state is finalized in the locked wallet before the
     * wallet_utxos SQLite projection runs. Reading that exact state prevents
     * a confirmed transaction from leaving total balance stale. */
    struct wallet_balance_freshness freshness;
    int64_t t_balance = wallet_transparent_spendable_balance_diagnose(
        ctx, &freshness);

    /* Shielded balance: always from SQLite (authoritative source) */
    if (t_balance < 0 || !wallet_ctx_db_ready(ctx)) return wallet_balance_unavailable(result);
    struct wallet_owned_balances balances;
    if (!wallet_db_read_snapshot(ctx->node_db, wallet_read_owned_balances, &balances))
        return wallet_balance_unavailable(result);
    int64_t z_balance = balances.shielded;
    int64_t encumbered = balances.encumbered;

    /* A reorg can resurrect an outgoing transaction into the mempool. Its
     * inputs remain ours but are deliberately unavailable for a second spend.
     * Report them as encumbered ownership so total money never vanishes while
     * keeping both spendable balances conservative. */
    if (t_balance > INT64_MAX - z_balance || t_balance + z_balance > INT64_MAX - encumbered)
        return wallet_balance_unavailable(result);
    int64_t total = t_balance + z_balance + encumbered;

    char t_str[32], z_str[32], enc_str[32], tot_str[32];
    format_amount(t_balance, t_str, sizeof(t_str));
    format_amount(z_balance, z_str, sizeof(z_str));
    format_amount(encumbered, enc_str, sizeof(enc_str));
    format_amount(total, tot_str, sizeof(tot_str));

    json_set_object(result);
    json_push_kv_str(result, "transparent", t_str);
    json_push_kv_str(result, "private", z_str);
    json_push_kv_str(result, "encumbered", enc_str);
    json_push_kv_str(result, "total", tot_str);
    json_push_kv_str(result, "transparent_source",
                     freshness.source ? freshness.source : "unavailable");
    json_push_kv_bool(result, "transparent_sources_agree",
                      freshness.sources_agree);
    json_push_kv_int(result, "wallet_height", freshness.wallet_height);
    json_push_kv_int(result, "chain_height", freshness.chain_height);
    json_push_kv_int(result, "memory_confirmed_transactions",
                     (int64_t)freshness.memory_confirmed_txs);
    json_push_kv_int(result, "durable_confirmed_transactions",
                     freshness.durable_confirmed_txs);
    return true;
}

/* The tip a received note's confirmations are counted against: the wallet's
 * best block, else the active chain, else the database. A tip the database
 * cannot give is a failed read only when minconf needs it to filter. */
static bool wallet_received_tip(struct wallet_rpc_context *ctx, int minconf,
                                int *tip)
{
    *tip = ctx->wallet->best_block_height;
    if (*tip == 0 && ctx->main_state)
        *tip = active_chain_height(&ctx->main_state->chain_active);
    if (*tip == 0) {
        int db_tip = db_wallet_chain_tip_height(ctx->node_db);
        if (db_tip >= 0)
            *tip = db_tip;
        else if (minconf > 0)
            return false;
    }
    return true;
}

static void wallet_received_entry_push(struct json_value *result,
                                       const struct db_sapling_note *n,
                                       int confirms)
{
    struct json_value entry = {0};
    json_init(&entry);
    json_set_object(&entry);

    char txid[65];
    wallet_txid_hex_le(n->txid, txid);
    json_push_kv_str(&entry, "txid", txid);
    json_push_kv_int(&entry, "outindex", n->output_index);
    char amt[32];
    format_amount(n->value, amt, sizeof(amt));
    json_push_kv_real(&entry, "amount", strtod(amt, NULL));
    json_push_kv_int(&entry, "confirmations", confirms);
    json_push_kv_bool(&entry, "change", false);
    json_push_kv_bool(&entry, "spent", n->is_spent);
    /* The database memo is zero-padded to the full 512 bytes the memory copy
     * always carried, so the memo fields come out the same. */
    wallet_memo_to_json(&entry, n->memo, 512);

    json_push_back(result, &entry);
    json_free(&entry);
}

/* Load every note row, spent or not, with room for rows that land while the
 * count is taken. More rows than that, or any read failure, is NULL with
 * *count -1: the caller reports it rather than a shorter list. */
static struct db_sapling_note *wallet_received_load(struct node_db *ndb,
                                                    int *count)
{
    size_t cap = (size_t)db_sapling_note_count_all(ndb) + 64;
    struct db_sapling_note *notes =
        zcl_calloc(cap, sizeof(*notes), "z_listreceivedbyaddress_notes");
    *count = -1;
    if (!notes)
        return NULL;
    *count = db_sapling_note_list_all_checked(ndb, notes, cap);
    if (*count < 0) {
        free(notes);
        return NULL;
    }
    return notes;
}

bool rpc_z_listreceivedbyaddress(const struct json_value *params,
                                          bool help, struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_listreceivedbyaddress \"address\" ( minconf )\n"
        "\nReturn a list of amounts received by a zaddr.\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *addr_str = rpc_require_str(&p, 0, "address");
    int minconf = (int)rpc_permit_int(&p, 1, "minconf", 1);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet_shielded", "z_listreceivedbyaddress: invalid params"); }

    ENSURE_WALLET(result);
    if (wallet_readiness_get(ctx->wallet).state != WALLET_READINESS_READY) {
        json_set_str(result, "Wallet funds unavailable during cutover");
        return false;
    }

    uint8_t z_d[11], z_pkd[32];
    if (!sapling_decode_payment_address(addr_str, z_d, z_pkd)) {
        json_set_str(result, "Not a valid Sapling address");
        LOG_FAIL("wallet_shielded", "z_listreceivedbyaddress: invalid sapling address");
    }

    /* SQLite is the authoritative shielded-note store: the in-memory array
     * holds only notes seen since this process started, and its confirms
     * field is never populated. Answer from the database; an unreadable
     * database is an explicit error, never a shorter list. */
    if (!wallet_ctx_db_ready(ctx)) return wallet_balance_unavailable(result);
    int tip = 0;
    if (!wallet_received_tip(ctx, minconf, &tip))
        return wallet_balance_unavailable(result);
    int count = 0;
    struct db_sapling_note *notes = wallet_received_load(ctx->node_db, &count);
    if (count < 0)
        return wallet_balance_unavailable(result);

    json_set_array(result);
    for (int i = 0; i < count; i++) {
        const struct db_sapling_note *n = &notes[i];
        if (memcmp(n->diversifier, z_d, 11) != 0 ||
            memcmp(n->pk_d, z_pkd, 32) != 0)
            continue;
        int confirms = tip - n->block_height + 1;
        if (confirms < 0)
            confirms = 0;
        if (confirms < minconf)
            continue;
        wallet_received_entry_push(result, n, confirms);
    }
    free(notes);
    return true;
}

/* z_listallnotes: list all shielded notes (spent + unspent) with memos */
bool rpc_z_listallnotes(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "z_listallnotes\n"
        "\nReturns all shielded notes (spent and unspent) with memos.\n");

    (void)params;
    ENSURE_WALLET(result);
    if (wallet_readiness_get(ctx->wallet).state != WALLET_READINESS_READY) {
        json_set_str(result, "Wallet funds unavailable during cutover");
        return false;
    }

    if (!ctx->node_db) {
        json_set_str(result, "Database not available");
        LOG_FAIL("wallet_shielded", "z_listallnotes: node_db is NULL");
    }

    struct db_sapling_note notes[512];
    int count = db_sapling_note_list_all(ctx->node_db, notes, 512);

    int chain_h = 0;
    if (ctx->main_state)
        chain_h = active_chain_height(&ctx->main_state->chain_active);

    json_set_array(result);
    for (int i = 0; i < count; i++) {
        struct db_sapling_note *n = &notes[i];

        struct json_value entry = {0};
        json_init(&entry);
        json_set_object(&entry);

        char txid_hex[65];
        wallet_txid_hex_le(n->txid, txid_hex);
        json_push_kv_str(&entry, "txid", txid_hex);
        json_push_kv_int(&entry, "outindex", n->output_index);

        char z_addr[128];
        sapling_encode_payment_address(n->diversifier, n->pk_d,
                                        "zs", z_addr, sizeof(z_addr));
        json_push_kv_str(&entry, "address", z_addr);

        char amount_buf[32];
        format_amount(n->value, amount_buf, sizeof(amount_buf));
        json_push_kv_str(&entry, "amount", amount_buf);

        int confirms = chain_h > 0 ? chain_h - n->block_height + 1 : 0;
        json_push_kv_int(&entry, "confirmations", (int64_t)confirms);
        json_push_kv_int(&entry, "block_height", (int64_t)n->block_height);
        json_push_kv_bool(&entry, "spent", n->is_spent);

        if (n->is_spent) {
            char spent_hex[65];
            wallet_txid_hex_le(n->spent_txid, spent_hex);
            json_push_kv_str(&entry, "spent_by", spent_hex);
        }

        wallet_memo_to_json(&entry, n->memo, n->memo_len);

        json_push_back(result, &entry);
        json_free(&entry);
    }
    return true;
}

void register_wallet_shielded_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "wallet", "z_getnewaddress",     rpc_z_getnewaddress,      false },
        { "wallet", "z_getreceiveaddress", rpc_z_getreceiveaddress,  false },
        { "wallet", "z_listaddresses",     rpc_z_listaddresses,      false },
        { "wallet", "z_sendmany",          rpc_z_sendmany_checkpoint,         false },
        { "wallet", "z_shieldaddress",     rpc_z_shieldaddress,      false },
        { "wallet", "z_getbalance",        rpc_z_getbalance,         false },
        { "wallet", "z_gettotalbalance",   rpc_z_gettotalbalance,    false },
        { "wallet", "z_listunspent",       rpc_z_listunspent,        false },
        { "wallet", "z_listreceivedbyaddress", rpc_z_listreceivedbyaddress, false },
        { "wallet", "z_exportkey",         rpc_z_exportkey,          false },
        { "wallet", "z_importkey",         rpc_z_importkey,          false },
        { "wallet", "z_exportviewingkey",  rpc_z_exportviewingkey,   false },
        { "wallet", "z_getmemo",           rpc_z_getmemo,            false },
        { "wallet", "z_listallnotes",      rpc_z_listallnotes,       false },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
