/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * z_sendmany RPC handler for transparent and shielded sends (t->t, t->z,
 * z->z, z->t). The shielded-spend branch lives in z_sendmany_shielded();
 * transparent-spend handling stays inline with the RPC validation flow. */

#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_spend_gate.h"
#include "controllers/wallet_private_broadcast.h"
#include "wallet/wallet_lock.h"
#include "controllers/wallet_send_once.h"


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

enum z_sendmany_memo_status {
    Z_SENDMANY_MEMO_OK = 0,
    Z_SENDMANY_MEMO_BAD_LEN,
    Z_SENDMANY_MEMO_BAD_HEX
};

/* Memo of one Sapling recipient into memo[512]. Leaves *has_memo untouched on
 * a failure status; *hlen / *got are the values the caller logs. */
static int z_sendmany_parse_memo(const struct json_value *r, uint8_t *memo,
                                 bool *has_memo, size_t *hlen, size_t *got)
{
    /* Parse memo if present. "memo_hex" carries an arbitrary BINARY
     * memo (hex-encoded, <=1024 hex chars → <=512 bytes) — used by the
     * on-chain ZMSG channel whose header bytes are not printable text;
     * "memo" is the plain-UTF-8 form. memo_hex wins if both are given. */
    const struct json_value *memohex_val = json_get(r, "memo_hex");
    const char *memohex = memohex_val ? json_get_str(memohex_val) : NULL;
    const struct json_value *memo_val = json_get(r, "memo");
    if (memohex && memohex[0]) {
        *hlen = strlen(memohex);
        if (*hlen % 2 != 0 || *hlen > 1024)
            return Z_SENDMANY_MEMO_BAD_LEN;
        memset(memo, 0xF6, 512);
        *got = ParseHex(memohex, memo, 512);
        if (*got != *hlen / 2)
            return Z_SENDMANY_MEMO_BAD_HEX;
        *has_memo = true;
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
        memset(memo, 0x00, 512);
        memcpy(memo, memo_str, memo_len);
        *has_memo = true;
    } else {
        *has_memo = false;
    }
    return Z_SENDMANY_MEMO_OK;
}

/* Coin selection rows for the from-address; *num_selected / *selected_value
 * accumulate onto the caller's initial values. */
static void z_sendmany_select_coins(struct wallet_rpc_context *ctx,
                                    int64_t target, int tip, int32_t floor,
                                    const uint8_t *from_addr_hash,
                                    struct db_wallet_utxo *db_selected,
                                    size_t *num_selected,
                                    int64_t *selected_value)
{
    if (wallet_ctx_db_ready(ctx)) {
        int n_sel = db_wallet_utxo_select_coins_for_address_above(
            ctx->node_db, target, tip, from_addr_hash, floor, db_selected,
            256);
        for (int i = 0; i < n_sel; i++) {
            (*num_selected)++;
            *selected_value += db_selected[i].value;
        }
    }
}

static void z_sendmany_fill_t_outputs(struct wallet_rpc_context *ctx,
                                      struct wallet_tx *wtx,
                                      const struct tx_destination *t_dests,
                                      const int64_t *t_amounts,
                                      size_t num_t_out, int64_t change,
                                      const struct tx_destination *from_dest)
{
    /* Fill transparent outputs */
    for (size_t i = 0; i < num_t_out; i++) {
        struct script dest_script;
        script_for_destination(&dest_script, &t_dests[i]);
        wtx->tx.vout[i].value = t_amounts[i];
        wtx->tx.vout[i].script_pub_key = dest_script;
    }

    /* Change output — send back to the FROM address (no keypool needed) */
    if (change > 0) {
        struct pubkey change_pk;
        bool got_key = wallet_get_key_from_pool(ctx->wallet, &change_pk);
        if (!got_key) {
            /* Keypool exhausted — use the from_address as change address */
            struct tx_destination change_dest = *from_dest;
            struct script change_script;
            script_for_destination(&change_script, &change_dest);
            wtx->tx.vout[num_t_out].value = change;
            wtx->tx.vout[num_t_out].script_pub_key = change_script;
        } else {
            struct key_id change_kid = pubkey_get_id(&change_pk);
            struct tx_destination change_dest;
            change_dest.type = DEST_KEY_ID;
            change_dest.id.key = change_kid;
            struct script change_script;
            script_for_destination(&change_script, &change_dest);
            wtx->tx.vout[num_t_out].value = change;
            wtx->tx.vout[num_t_out].script_pub_key = change_script;
        }
    }
}

void z_sendmany_get_ovk(struct wallet_rpc_context *ctx, uint8_t *ovk)
{
    zcl_mutex_lock(&ctx->wallet->sapling_keys.cs);
    if (ctx->wallet->sapling_keys.num_keys > 0) {
        memcpy(ovk, ctx->wallet->sapling_keys.keys[0].xfvk.fvk.ovk, 32);
        zcl_mutex_unlock(&ctx->wallet->sapling_keys.cs);
    } else {
        zcl_mutex_unlock(&ctx->wallet->sapling_keys.cs);
        GetRandBytes(ovk, 32);
    }
}

/* Sapling output descriptions for the t->z path; *fail_idx is the output that
 * failed to build (set only when false is returned). */
bool z_sendmany_build_outputs(void *proving_ctx, struct wallet_tx *wtx,
                                     const uint8_t *ovk,
                                     uint8_t (*z_diversifiers)[11],
                                     uint8_t (*z_pk_ds)[32],
                                     const int64_t *z_amounts,
                                     uint8_t (*z_memos)[512],
                                     const bool *z_has_memo,
                                     size_t num_z_out, size_t *fail_idx)
{
    for (size_t i = 0; i < num_z_out; i++) {
        struct output_description *od = &wtx->tx.v_shielded_output[i];

        if (!sapling_build_output_with_ctx(
                proving_ctx,
                ovk, z_diversifiers[i], z_pk_ds[i],
                (uint64_t)z_amounts[i],
                z_has_memo[i] ? z_memos[i] : NULL,
                od->cv.data, od->cm.data, od->ephemeral_key.data,
                od->enc_ciphertext, od->out_ciphertext, od->zkproof)) {
            *fail_idx = i;
            return false;
        }
    }
    return true;
}

void z_sendmany_fill_inputs(struct wallet_tx *wtx,
                                   const struct db_wallet_utxo *db_selected,
                                   size_t num_selected)
{
    for (size_t i = 0; i < num_selected; i++) {
        memcpy(wtx->tx.vin[i].prevout.hash.data, db_selected[i].txid, 32);
        wtx->tx.vin[i].prevout.n = db_selected[i].vout;
        wtx->tx.vin[i].sequence = UINT32_MAX - 1;
    }
}

/* Signs every selected transparent input under wallet->cs. The lock is
 * released, and the private key wiped once it was loaded, before any
 * failure status returns;
 * *fail_idx is the failing input (set only on a failure status). */
int z_sendmany_sign_inputs(struct wallet_rpc_context *ctx,
                                  const struct chain_params *cp,
                                  struct wallet_tx *wtx,
                                  const struct db_wallet_utxo *db_selected,
                                  size_t num_selected, int height,
                                  size_t *fail_idx)
{
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
            *fail_idx = i;
            return Z_SENDMANY_SIGN_NO_DEST;
        }

        struct privkey skey;
        if (!keystore_get_key(&ctx->wallet->keystore, &prev_dest.id.key, &skey)) {
            zcl_mutex_unlock(&ctx->wallet->cs);
            *fail_idx = i;
            return Z_SENDMANY_SIGN_NO_KEY;
        }

        struct pubkey spk;
        privkey_get_pubkey(&skey, &spk);

        uint32_t branch_id = consensus_current_epoch_branch_id(height + 1, &cp->consensus);
        struct sighash_type ht;
        ht.raw = SIGHASH_ALL;
        struct precomputed_tx_data txdata;
        precompute_tx_data(&wtx->tx, &txdata);

        struct uint256 sighash;
        if (!signature_hash(&prev_script, &wtx->tx,
                            (unsigned int)i, ht, db_selected[i].value,
                            branch_id, &txdata, &sighash)) {
            memory_cleanse(skey.vch, 32);
            zcl_mutex_unlock(&ctx->wallet->cs);
            *fail_idx = i;
            return Z_SENDMANY_SIGN_SIGHASH;
        }

        unsigned char sig[SIGNATURE_SIZE + 1];
        size_t siglen = 0;
        if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
            memory_cleanse(skey.vch, 32);
            zcl_mutex_unlock(&ctx->wallet->cs);
            *fail_idx = i;
            return Z_SENDMANY_SIGN_SIGN;
        }
        sig[siglen++] = 0x01;

        struct script *ss = &wtx->tx.vin[i].script_sig;
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
    return Z_SENDMANY_SIGN_OK;
}


/* The key a shielded from address names: the wallet account for the literal
 * "account", else the key owning the address, whichever of its diversified
 * addresses it is. Sets `result` and returns false when there is none. */
static bool z_sendmany_shielded_from(struct wallet_rpc_context *ctx,
                                     const char *from_addr, bool from_account,
                                     const struct sapling_key_entry **key_out,
                                     struct json_value *result)
{
    const struct sapling_key_entry *key = NULL;
    if (from_account) {
        struct sapling_key_entry account;
        if (sapling_keystore_copy_account(&ctx->wallet->sapling_keys, &account))
            key = sapling_keystore_find_by_ivk(&ctx->wallet->sapling_keys,
                                               account.ivk);
        memory_cleanse(&account, sizeof(account));
        if (!key) {
            json_set_str(result, "The wallet has no shielded account");
            LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: no account key");
            return false;
        }
    } else {
        uint8_t diversifier[11], pk_d[32];
        if (!sapling_decode_payment_address(from_addr, diversifier, pk_d)) {
            json_set_str(result, "Invalid shielded from address");
            LOG_ERROR_IN("z_sendmany_run", "wallet_shielded",
                     "z_sendmany: cannot decode shielded from address");
            return false;
        }
        key = sapling_keystore_find_by_owned_address(
            &ctx->wallet->sapling_keys, diversifier, pk_d);
        if (!key) {
            json_set_str(result, "Shielded from address not in wallet");
            LOG_ERROR_IN("z_sendmany_run", "wallet_shielded",
                     "z_sendmany: shielded from addr not found in keystore");
            return false;
        }
    }
    *key_out = key;
    return true;
}

/* The optional third parameter, minconf: an extra confirmation floor on top of
 * the depth the wallet summary requires, never a way around it. Absent is 0.
 * False, with *min_conf set to -1, when present but not a non-negative
 * integer; z_sendmany_shielded rejects a negative floor. */
bool z_sendmany_minconf(const struct json_value *params, int *min_conf)
{
    *min_conf = 0;
    if (json_size(params) < 3)
        return true;
    const struct json_value *v = json_at(params, 2);
    if (!v || v->type != JSON_INT || json_get_int(v) < 0 ||
        json_get_int(v) > 1000000) {
        *min_conf = -1;
        return false;
    }
    *min_conf = (int)json_get_int(v);
    return true;
}

/* Admit a finished transaction to the wallet and pool, make it durable, sync
 * it into node.db, relay it and answer its txid. Frees wtx->tx on every
 * return. */
bool z_sendmany_admit_relay(struct wallet_rpc_context *ctx,
                            struct wallet_tx *wtx, struct json_value *result)
{
    struct zcl_result commit = wallet_commit_from_context(ctx, wtx);
    if (!commit.ok) {
        json_set_str(result, commit.message);
        transaction_free(&wtx->tx);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: wallet commit failed "
                                    "(code=%d): %s", commit.code,
                                    commit.message);
        return false;
    }

    struct zcl_result persisted =
        wallet_persist_commit_before_relay(ctx, wtx);
    if (!persisted.ok) {
        json_set_str(result, persisted.message);
        transaction_free(&wtx->tx);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded",
                 "z_sendmany: pre-relay durability failed (code=%d): %s",
                 persisted.code, persisted.message);
        return false;
    }

    if (wallet_ctx_db_ready(ctx))
        node_db_sync_wallet_tx(ctx->node_db, &wtx->tx, ctx->wallet, 0);

    if (!wallet_send_relay(ctx, wtx)) {
        json_set_str(result, wallet_send_relay_failure_text());
        transaction_free(&wtx->tx);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: private broadcast not queued");
        return false;
    }

    char txid[65];
    uint256_get_hex(&wtx->tx.hash, txid);
    json_set_str(result, txid);
    transaction_free(&wtx->tx);
    return true;
}

/* Recipient outputs and running totals of one z_sendmany call, filled before
 * the spend path is chosen. */
struct z_sendmany_outs {
    struct tx_destination t_dests[50];
    int64_t t_amounts[50];
    size_t num_t_out;

    uint8_t z_diversifiers[50][11];
    uint8_t z_pk_ds[50][32];
    int64_t z_amounts[50];
    uint8_t z_memos[50][512];
    bool z_has_memo[50];
    size_t num_z_out;
    int64_t total_amount;
};

/* Coin selection of the transparent spend path. */
struct z_sendmany_sel {
    struct db_wallet_utxo db_selected[256];
    size_t num_selected;
    int64_t selected_value;
};

/* Why a recipient or a spend step failed. A LOG_FAIL that names a
 * wallet-private field stays in z_sendmany_run (the wallet log-privacy ratchet
 * pins it there), so the helper records the reason here and run logs it. */
enum z_sendmany_why {
    Z_SENDMANY_WHY_NONE = 0,
    Z_SENDMANY_WHY_BAD_AMOUNT,
    Z_SENDMANY_WHY_BAD_SAPLING,
    Z_SENDMANY_WHY_BAD_TRANSPARENT,
    Z_SENDMANY_WHY_BINDING
};

struct z_sendmany_fail {
    enum z_sendmany_why why;
    size_t index;
    const char *addr;
    int64_t amount;
    int64_t value_balance;
};

/* Argument shape of a z_sendmany call: a from-address and a recipients array,
 * with a live wallet to spend from. */
static bool z_sendmany_check_args(const struct json_value *params,
                                  struct json_value *result,
                                  const char **from_addr,
                                  const struct json_value **recipients)
{
    if (json_size(params) < 2) {
        json_set_str(result, "Expected at least 2 parameter(s)");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: expected 2+ params, got %zu", json_size(params));
        return false;
    }

    ENSURE_WALLET(result);

    const char *addr = json_get_str(json_at(params, 0));
    const struct json_value *recip = json_at(params, 1);
    if (!addr || !recip || recip->type != JSON_ARR || json_size(recip) == 0) {
        json_set_str(result, "Invalid parameters");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: invalid from_addr or recipients array");
        return false;
    }
    *from_addr = addr;
    *recipients = recip;
    return true;
}

/* Sovereign guard and at-rest lock gate, before any spend is built. */
static bool z_sendmany_gate_spend(struct wallet_rpc_context *ctx,
                                  bool checkpoint_rule, int32_t *spend_floor,
                                  struct json_value *result)
{
    /* Only the registered z_sendmany handler may use the phone rule
     * (-spend-after-checkpoint); in-process callers keep the strict guard
     * and stay refused. */
    if (!wallet_spend_gate_for_send(ctx, checkpoint_rule, spend_floor,
                                    result))
        return false;

    /* At-rest lock gate (wallet_lock): an encrypted wallet with no passphrase
     * loaded cannot spend — its spending keys are not decryptable/resident.
     * Covers all four flows (t->t, t->z, z->t, z->z) this handler serves.
     * Wallet-local key handling: no tx bytes / proof / consensus effect. */
    {
        struct zcl_result lk = wallet_lock_spend_guard();
        if (!lk.ok) {
            json_set_str(result, "Error: wallet is locked — run "
                                 "walletunlock before spending");
            LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: refused — wallet locked "
                     "(code=%d)", lk.code);
            return false;
        }
    }
    return true;
}

/* One Sapling recipient: its decoded payment address, amount and memo. */
static bool z_sendmany_add_sapling(const struct json_value *r, const char *addr,
                                   int64_t amount, struct z_sendmany_outs *o,
                                   struct json_value *result,
                                   struct z_sendmany_fail *f)
{
    /* Sapling shielded output */
    if (!sapling_decode_payment_address(addr,
            o->z_diversifiers[o->num_z_out], o->z_pk_ds[o->num_z_out])) {
        json_set_str(result, "Invalid Sapling address");
        f->why = Z_SENDMANY_WHY_BAD_SAPLING;
        return false;
    }
    o->z_amounts[o->num_z_out] = amount;
    size_t hlen = 0;
    size_t got = 0;
    int memo_st = z_sendmany_parse_memo(r, o->z_memos[o->num_z_out],
                                        &o->z_has_memo[o->num_z_out],
                                        &hlen, &got);
    if (memo_st == Z_SENDMANY_MEMO_BAD_LEN) {
        json_set_str(result, "Invalid memo_hex (even-length hex, <=1024 chars)");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: bad memo_hex len=%zu", hlen);
        return false;
    }
    if (memo_st == Z_SENDMANY_MEMO_BAD_HEX) {
        json_set_str(result, "Invalid memo_hex (non-hex characters)");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: memo_hex parse got=%zu want=%zu", got, hlen / 2);
        return false;
    }
    o->num_z_out++;
    return true;
}

/* One transparent recipient. */
static bool z_sendmany_add_transparent(const char *addr, int64_t amount,
                                       struct z_sendmany_outs *o,
                                       struct json_value *result,
                                       struct z_sendmany_fail *f)
{
    /* Transparent output */
    if (!wallet_decode_address(addr, &o->t_dests[o->num_t_out])) {
        json_set_str(result, "Invalid transparent address");
        f->why = Z_SENDMANY_WHY_BAD_TRANSPARENT;
        return false;
    }
    o->t_amounts[o->num_t_out] = amount;
    o->num_t_out++;
    return true;
}

/* One recipient object: its amount joins the total, then it becomes a Sapling
 * or a transparent output. A failure that names a wallet-private field is
 * left to the caller, through *f. */
static bool z_sendmany_add_recipient(const struct json_value *r, size_t i,
                                     struct z_sendmany_outs *o,
                                     struct json_value *result,
                                     struct z_sendmany_fail *f)
{
    if (!r || r->type != JSON_OBJ) {
        json_set_str(result, "Invalid recipient");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: recipient %zu is not a JSON object", i);
        return false;
    }
    const char *addr = json_get_str(json_get(r, "address"));
    int64_t amount = parse_amount(json_get(r, "amount"));
    f->index = i;
    f->addr = addr;
    f->amount = amount;
    if (!addr || amount <= 0) {
        json_set_str(result, "Invalid recipient address or amount");
        f->why = Z_SENDMANY_WHY_BAD_AMOUNT;
        return false;
    }
    o->total_amount += amount;

    if (wallet_addr_is_sapling(addr))
        return z_sendmany_add_sapling(r, addr, amount, o, result, f);
    return z_sendmany_add_transparent(addr, amount, o, result, f);
}

/* The recipients array: at most 50 entries, each added in order. */
static bool z_sendmany_collect_recipients(const struct json_value *recipients,
                                          struct z_sendmany_outs *o,
                                          struct json_value *result,
                                          struct z_sendmany_fail *f)
{
    /* Parse recipients */
    size_t num_recip = json_size(recipients);
    if (num_recip > 50) {
        json_set_str(result, "Too many recipients");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: too many recipients (%zu > 50)", num_recip);
        return false;
    }

    /* Separate into transparent and shielded outputs */
    o->num_t_out = 0;
    o->num_z_out = 0;
    o->total_amount = 0;
    for (size_t i = 0; i < num_recip; i++) {
        if (!z_sendmany_add_recipient(json_at(recipients, i), i, o, result, f)) {
            return false; // raw-return-ok:fail-record-logged-by-z_sendmany_run
        }
    }
    return true;
}

/* ── Shielded spend path (z→z, z→t) ──────────────────────────── */
static bool z_sendmany_spend_shielded(struct wallet_rpc_context *ctx,
                                      const struct chain_params *cp,
                                      const struct sapling_key_entry *from_z_key,
                                      struct z_sendmany_outs *o,
                                      const struct json_value *params,
                                      struct wallet_tx *prepared,
                                      struct json_value *result,
                                      int32_t spend_floor)
{
    int min_conf = 0;
    (void)z_sendmany_minconf(params, &min_conf);
    return z_sendmany_shielded(ctx, cp, from_z_key, o->total_amount,
                               o->t_dests, o->t_amounts, o->num_t_out,
                               o->z_diversifiers, o->z_pk_ds, o->z_amounts,
                               o->z_memos, o->z_has_memo, o->num_z_out,
                               min_conf, prepared, result, spend_floor);
}

/* Shielding (t→z) needs a Sapling OUTPUT description, and an output
 * description carries its own Groth16 proof — so it needs the proving
 * backend exactly as a shielded spend does. Refuse here, before coin
 * selection allocates anything and before any spent-state is touched, and
 * name the backend + status so a build with no proving backend explains
 * itself instead of surfacing a bare "Failed to init proving context"
 * hundreds of lines later. Pure t→t sends are unaffected. */
static bool z_sendmany_check_proving(size_t num_z_out,
                                     struct json_value *result)
{
    if (num_z_out > 0 && !sapling_proving_available()) {
        char err[320];
        snprintf(err, sizeof(err),
                 "Shielded proving unavailable (backend=%s, status=%s)",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        json_set_str(result, err);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded",
                 "z_sendmany: refusing t->z shielding: backend=%s status=%s",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        return false;
    }
    return true;
}

/* Coin selection restricted to the from-address. */
static bool z_sendmany_select(struct wallet_rpc_context *ctx,
                              const struct tx_destination *from_dest,
                              int64_t target, int tip, int32_t floor,
                              struct z_sendmany_sel *sel,
                              struct json_value *result)
{
    uint8_t from_addr_hash[20];
    if (from_dest->type == DEST_KEY_ID)
        memcpy(from_addr_hash, from_dest->id.key.id.data, 20);
    else if (from_dest->type == DEST_SCRIPT_ID)
        memcpy(from_addr_hash, from_dest->id.script.hash.data, 20);
    else {
        json_set_str(result, "Unsupported from address type");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: unsupported from_dest type %d", from_dest->type);
        return false;
    }

    z_sendmany_select_coins(ctx, target, tip, floor, from_addr_hash,
                            sel->db_selected, &sel->num_selected,
                            &sel->selected_value);
    return true;
}

/* Initialise the transaction shell: header fields and the input/output
 * allocation. */
static bool z_sendmany_begin_tx(struct wallet_tx *wtx, int height,
                                size_t num_selected, size_t total_t_out,
                                struct json_value *result)
{
    memset(wtx, 0, sizeof(*wtx));
    transaction_init(&wtx->tx);
    wtx->tx.overwintered = true;
    wtx->tx.version = SAPLING_TX_VERSION;
    wtx->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    wtx->tx.expiry_height = (uint32_t)(height + 20);

    if (!transaction_alloc(&wtx->tx, num_selected, total_t_out)) {
        json_set_str(result, "Transaction allocation failed");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: transaction_alloc failed for %zu inputs, %zu outputs",
                 num_selected, total_t_out);
        return false;
    }
    return true;
}

/* Sapling output descriptions array for the shielded outputs. */
static bool z_sendmany_alloc_z_outs(struct wallet_tx *wtx, size_t num_z_out,
                                    struct json_value *result)
{
    wtx->tx.v_shielded_output = zcl_calloc(num_z_out, sizeof(struct output_description), "shielded_outputs");
    if (!wtx->tx.v_shielded_output) {
        transaction_free(&wtx->tx);
        json_set_str(result, "Allocation failed");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: calloc shielded_output failed for %zu outputs", num_z_out);
        return false;
    }
    wtx->tx.num_shielded_output = num_z_out;
    return true;
}

/* Proving context for the output proofs and the binding signature. */
static bool z_sendmany_prover_init(struct wallet_tx *wtx,
                                   struct z_sendmany_sel *sel,
                                   struct json_value *result,
                                   void **proving_ctx)
{
    *proving_ctx = zclassic_sapling_proving_ctx_init();
    if (!*proving_ctx) {
        /* Every other error return below this point frees the selected
         * UTXO rows; this one used to leak them. The readiness precheck
         * above makes reaching here rare, not impossible. */
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        transaction_free(&wtx->tx);
        char err[320];
        snprintf(err, sizeof(err),
                 "Failed to init proving context (backend=%s, status=%s)",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        json_set_str(result, err);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded",
                 "z_sendmany: sapling_proving_ctx_init failed (transparent spend path): backend=%s status=%s",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
        return false;
    }
    return true;
}

/* Output proofs for the Sapling recipients. */
static bool z_sendmany_prove_outs(void *proving_ctx, struct wallet_tx *wtx,
                                  const uint8_t *ovk, struct z_sendmany_outs *o,
                                  size_t *i, struct json_value *result)
{
    if (!z_sendmany_build_outputs(proving_ctx, wtx, ovk, o->z_diversifiers,
                                  o->z_pk_ds, o->z_amounts, o->z_memos,
                                  o->z_has_memo, o->num_z_out, i)) {
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Failed to build Sapling output");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: sapling_build_output failed for output %zu", *i);
        return false;
    }
    return true;
}

/* Signs the transparent inputs of a t->z send. */
static bool z_sendmany_sign_tz(struct wallet_rpc_context *ctx,
                               const struct chain_params *cp,
                               struct wallet_tx *wtx,
                               struct z_sendmany_sel *sel, int height,
                               void *proving_ctx, size_t *i,
                               struct json_value *result)
{
    /* Sign transparent inputs */
    int sign_st = z_sendmany_sign_inputs(ctx, cp, wtx, sel->db_selected,
                                         sel->num_selected, height, i);
    if (sign_st == Z_SENDMANY_SIGN_NO_DEST) {
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Cannot determine input destination");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: script_extract_destination failed for input %zu (t->z path)", *i);
        return false;
    }
    if (sign_st == Z_SENDMANY_SIGN_NO_KEY) {
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Private key not available");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: private key not found for input %zu (t->z path)", *i);
        return false;
    }
    if (sign_st == Z_SENDMANY_SIGN_SIGHASH) {
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Sighash computation failed");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: signature_hash failed for input %zu (t->z path)", *i);
        return false;
    }
    if (sign_st == Z_SENDMANY_SIGN_SIGN) {
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Signing failed");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: privkey_sign failed for input %zu (t->z path)", *i);
        return false;
    }
    return true;
}

/* Binding signature over the finished shielded value balance. */
static bool z_sendmany_bind_shielded(const struct chain_params *cp,
                                     struct wallet_tx *wtx, int height,
                                     void *proving_ctx,
                                     struct json_value *result,
                                     struct z_sendmany_fail *f)
{
    /* Compute binding signature using Sapling proving context */
    transaction_compute_hash(&wtx->tx);

    uint32_t branch_id = consensus_current_epoch_branch_id(height + 1, &cp->consensus);
    struct sighash_type ht;
    ht.raw = SIGHASH_ALL;
    struct precomputed_tx_data txdata;
    precompute_tx_data(&wtx->tx, &txdata);

    struct script empty_script;
    empty_script.size = 0;
    struct uint256 binding_sighash;
    if (!signature_hash(&empty_script, &wtx->tx, NOT_AN_INPUT, ht, 0,
                        branch_id, &txdata, &binding_sighash)) {
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Binding sighash computation failed");
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: binding signature_hash failed (t->z path)");
        return false;
    }

    if (!zclassic_sapling_binding_sig(proving_ctx,
                                           wtx->tx.value_balance,
                                           binding_sighash.data,
                                           wtx->tx.binding_sig)) {
        f->why = Z_SENDMANY_WHY_BINDING;
        f->value_balance = wtx->tx.value_balance;
        zclassic_sapling_proving_ctx_free(proving_ctx);
        transaction_free(&wtx->tx);
        json_set_str(result, "Binding signature failed");
        return false;
    }
    zclassic_sapling_proving_ctx_free(proving_ctx);
    return true;
}

/* t->z: Sapling outputs, their proofs, the transparent inputs and the binding
 * signature. */
static bool z_sendmany_sign_shielded(struct wallet_rpc_context *ctx,
                                     const struct chain_params *cp,
                                     struct wallet_tx *wtx,
                                     struct z_sendmany_outs *o,
                                     struct z_sendmany_sel *sel, int height,
                                     struct json_value *result,
                                     struct z_sendmany_fail *f)
{
    if (!z_sendmany_alloc_z_outs(wtx, o->num_z_out, result)) {
        return false; // raw-return-ok:callee-logs
    }

    /* Get OVK from sapling keystore */
    uint8_t ovk[32];
    z_sendmany_get_ovk(ctx, ovk);

    /* Use Sapling proving context for output proofs + binding sig.
     * The declarations come from sapling/sapling_prover.h via
     * wallet_shielded_internal.h. */
    void *proving_ctx = NULL;
    if (!z_sendmany_prover_init(wtx, sel, result, &proving_ctx)) {
        return false; // raw-return-ok:callee-logs
    }

    size_t i = 0;
    if (!z_sendmany_prove_outs(proving_ctx, wtx, ovk, o, &i, result)) {
        return false; // raw-return-ok:callee-logs
    }

    /* Fill transparent inputs from SQLite model (needed for sighash) */
    z_sendmany_fill_inputs(wtx, sel->db_selected, sel->num_selected);

    /* Sign transparent inputs */
    if (!z_sendmany_sign_tz(ctx, cp, wtx, sel, height, proving_ctx, &i, result)) {
        return false; // raw-return-ok:callee-logs
    }
    return z_sendmany_bind_shielded(cp, wtx, height, proving_ctx, result, f);
}

/* t->t: the transparent inputs only. */
static bool z_sendmany_sign_transparent(struct wallet_rpc_context *ctx,
                                        const struct chain_params *cp,
                                        struct wallet_tx *wtx,
                                        struct z_sendmany_sel *sel, int height,
                                        struct json_value *result)
{
    /* No shielded outputs — just transparent */
    z_sendmany_fill_inputs(wtx, sel->db_selected, sel->num_selected);

    size_t i = 0;
    int sign_st = z_sendmany_sign_inputs(ctx, cp, wtx, sel->db_selected,
                                         sel->num_selected, height, &i);
    if (sign_st == Z_SENDMANY_SIGN_NO_DEST) {
        transaction_free(&wtx->tx);
        json_set_str(result, "Cannot determine input destination");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: script_extract_destination failed for input %zu (t->t path)", i);
        return false;
    }
    if (sign_st == Z_SENDMANY_SIGN_NO_KEY) {
        transaction_free(&wtx->tx);
        json_set_str(result, "Private key not available");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: private key not found for input %zu (t->t path)", i);
        return false;
    }
    if (sign_st == Z_SENDMANY_SIGN_SIGHASH) {
        transaction_free(&wtx->tx);
        json_set_str(result, "Sighash computation failed");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: signature_hash failed for input %zu (t->t path)", i);
        return false;
    }
    if (sign_st == Z_SENDMANY_SIGN_SIGN) {
        transaction_free(&wtx->tx);
        json_set_str(result, "Signing failed");
        for (size_t j = 0; j < sel->num_selected; j++)
            db_wallet_utxo_free(&sel->db_selected[j]);
        LOG_ERROR_IN("z_sendmany_run", "wallet_shielded", "z_sendmany: privkey_sign failed for input %zu (t->t path)", i);
        return false;
    }
    return true;
}

/* Persists the keystore, then admits or prepares the finished transaction. */
static bool z_sendmany_finish_tx(struct wallet_rpc_context *ctx,
                                 struct wallet_tx *wtx,
                                 struct z_sendmany_sel *sel,
                                 struct wallet_tx *prepared,
                                 struct json_value *result)
{
    /* Free SQLite UTXO data — no longer needed after building inputs */
    for (size_t i = 0; i < sel->num_selected; i++)
        db_wallet_utxo_free(&sel->db_selected[i]);

    transaction_compute_hash(&wtx->tx);
    wtx->time_received = GetTime();
    wtx->from_me = true;
    wtx->used = true;

    /* Persist the wallet keystore (which may hold a freshly-minted change key)
     * to disk BEFORE broadcast — abort the send on flush failure so we never
     * relay a tx whose RAM-only change key isn't durable (see rpc_sendtoaddress). */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_sqlite_flush_r(ctx->wallet_db, ctx->wallet);
        if (!fr.ok) {
            transaction_free(&wtx->tx);
            json_set_str(result, "Cannot persist change key before broadcast — send aborted");
            LOG_ERROR_IN("z_sendmany_run", "wallet", "z_sendmany: pre-broadcast key flush failed "
                                "(code=%d): %s", fr.code, fr.message);
            return false;
        }
    }

    if (prepared) {
        *prepared = *wtx;
        return true;
    }

    return z_sendmany_admit_relay(ctx, wtx, result);
}

/* Builds the transaction once the coins are selected: the transparent outputs
 * and change, then the t->z or the t->t inputs, then the finish. */
static bool z_sendmany_build_transparent(struct wallet_rpc_context *ctx,
                                         const struct chain_params *cp,
                                         const struct tx_destination *from_dest,
                                         struct z_sendmany_outs *o,
                                         struct z_sendmany_sel *sel, int tip,
                                         int64_t fee,
                                         struct wallet_tx *prepared,
                                         struct json_value *result,
                                         struct z_sendmany_fail *f)
{
    /* Build transaction */
    struct wallet_tx wtx;
    int height = tip;

    /* Transparent outputs: recipients + change */
    int64_t change = sel->selected_value - o->total_amount - fee;
    size_t total_t_out = o->num_t_out + (change > 0 ? 1 : 0);
    if (!z_sendmany_begin_tx(&wtx, height, sel->num_selected, total_t_out,
                             result))
        return false;

    z_sendmany_fill_t_outputs(ctx, &wtx, o->t_dests, o->t_amounts,
                              o->num_t_out, change, from_dest);

    /* value_balance = -(sum of shielded outputs) for shielding (negative = transparent→shielded) */
    int64_t shielded_total = 0;
    for (size_t i = 0; i < o->num_z_out; i++)
        shielded_total += o->z_amounts[i];
    wtx.tx.value_balance = -shielded_total;

    /* Build Sapling output descriptions */
    if (o->num_z_out > 0) {
        if (!z_sendmany_sign_shielded(ctx, cp, &wtx, o, sel, height, result,
                                      f))
            return false;
    } else if (!z_sendmany_sign_transparent(ctx, cp, &wtx, sel, height,
                                            result)) {
        return false;
    }
    return z_sendmany_finish_tx(ctx, &wtx, sel, prepared, result);
}

/* Transparent spend path (t→t, t→z): select the from-address coins, then build,
 * sign and admit the transaction. */
static bool z_sendmany_spend_transparent(struct wallet_rpc_context *ctx,
                                         const struct chain_params *cp,
                                         const struct tx_destination *from_dest,
                                         struct z_sendmany_outs *o,
                                         struct wallet_tx *prepared,
                                         struct json_value *result,
                                         int32_t spend_floor,
                                         struct z_sendmany_fail *f)
{
    /* ── Transparent spend path (t→t, t→z) ─────────────────────── */

    if (!z_sendmany_check_proving(o->num_z_out, result)) {
        return false; // raw-return-ok:callee-logs
    }

    /* Select coins from SQLite model layer, restricted to the from-address.
     * Pushing the address hash into the SQL WHERE (rather than selecting
     * globally then post-filtering) ensures a fully funded from-address is
     * never falsely rejected because higher-value coins on OTHER addresses
     * crowded out a value-DESC global selection window. */
    int64_t fee = ctx->wallet->default_fee;
    int tip = active_chain_height(&ctx->main_state->chain_active);

    struct z_sendmany_sel sel;
    sel.num_selected = 0;
    sel.selected_value = 0;
    if (!z_sendmany_select(ctx, from_dest, o->total_amount + fee, tip,
                           spend_floor, &sel, result))
        return false;

    if (sel.selected_value < o->total_amount + fee) {
        for (size_t i = 0; i < sel.num_selected; i++)
            db_wallet_utxo_free(&sel.db_selected[i]);
        /* With a phone-rule floor nothing at or below it was considered and
         * nothing is spent partly; the shortfall is not logged. */
        return wallet_spend_gate_short_funds(
            result, spend_floor, o->total_amount + fee, sel.selected_value,
            "transparent", "Insufficient funds from specified address");
    }
    return z_sendmany_build_transparent(ctx, cp, from_dest, o, &sel, tip, fee,
                                        prepared, result, f);
}

static bool z_sendmany_run(const struct json_value *params, bool help,
                           struct wallet_tx *prepared,
                           struct json_value *result, bool checkpoint_rule)
{
    struct wallet_rpc_context send_view;
    struct wallet_rpc_context *ctx = wallet_send_view_unless_prepared(wallet_ctx(), &send_view, prepared);
    RPC_HELP(help, result,
        "z_sendmany \"fromaddress\" [{\"address\":\"...\",\"amount\":...,\"memo\":\"...\"},...]\n"
        "\nSend from a transparent or shielded address to multiple recipients.\n"
        "Supports t→t, t→z, z→z, and z→t transactions.\n");

    /* Sovereign guard (docs/node/shielded-history-importer.md §5.3):
     * refuse a spend (t->t, t->z, z->t, z->z — this handler covers all four)
     * while the tip is release_assisted (borrowed shielded history, not
     * self-folded). Wallet viewing, balance, and receive stay unaffected —
     * only this spend entry is gated. */
    int32_t spend_floor = WALLET_SPEND_NO_FLOOR;
    if (!z_sendmany_gate_spend(ctx, checkpoint_rule, &spend_floor, result)) {
        return false; // raw-return-ok:callee-logs
    }

    const char *from_addr = NULL;
    const struct json_value *recipients = NULL;
    if (!z_sendmany_check_args(params, result, &from_addr, &recipients)) {
        return false; // raw-return-ok:callee-logs
    }

    /* Is the from address transparent or Sapling? Decided against the active
     * chain's HRP (wallet_addr_is_sapling), not a mainnet literal. */
    /* The literal "account" names the wallet account: the send selects from
     * every spendable note of its viewing key, whichever of its diversified
     * addresses received them. */
    bool from_account = strcmp(from_addr, "account") == 0;
    bool from_is_shielded = from_account || wallet_addr_is_sapling(from_addr);

    /* Verify we own the from address */
    const struct chain_params *cp = chain_params_get();

    /* For shielded from: decode the z-address, find key, validate ownership */
    const struct sapling_key_entry *from_z_key = NULL;

    struct tx_destination from_dest;
    if (from_is_shielded) {
        if (!z_sendmany_shielded_from(ctx, from_addr, from_account, &from_z_key,
                                      result))
            return false;
        memset(&from_dest, 0, sizeof(from_dest));
    } else if (!wallet_decode_address(from_addr, &from_dest)) {
        json_set_str(result, "Invalid from address");
        LOG_FAIL("wallet_shielded", "z_sendmany: decode_destination failed for from=%s", from_addr);
    }

    struct z_sendmany_outs outs;
    struct z_sendmany_fail f = { .why = Z_SENDMANY_WHY_NONE };
    if (!z_sendmany_collect_recipients(recipients, &outs, result, &f)) {
        if (f.why == Z_SENDMANY_WHY_BAD_AMOUNT)
            LOG_FAIL("wallet_shielded", "z_sendmany: recipient %zu has invalid addr or amount=%lld", f.index, (long long)f.amount);
        if (f.why == Z_SENDMANY_WHY_BAD_SAPLING)
            LOG_FAIL("wallet_shielded", "z_sendmany: cannot decode sapling recipient addr=%s", f.addr);
        if (f.why == Z_SENDMANY_WHY_BAD_TRANSPARENT)
            LOG_FAIL("wallet_shielded", "z_sendmany: cannot decode transparent recipient addr=%s", f.addr);
        return false;
    }

    /* ── Shielded spend path (z→z, z→t) ──────────────────────────── */
    if (from_is_shielded)
        return z_sendmany_spend_shielded(ctx, cp, from_z_key, &outs, params,
                                         prepared, result, spend_floor);

    if (!z_sendmany_spend_transparent(ctx, cp, &from_dest, &outs, prepared,
                                      result, spend_floor, &f)) {
        if (f.why == Z_SENDMANY_WHY_BINDING)
            LOG_FAIL("wallet_shielded", "z_sendmany: binding_sig failed, value_balance=%lld", (long long)f.value_balance);
        return false;
    }
    return true;
}

static bool z_sendmany_plain(const struct json_value *params, bool help,
                             struct json_value *result)
{
    return z_sendmany_run(params, help, NULL, result, false);
}

static bool z_sendmany_checkpoint_plain(const struct json_value *params,
                                        bool help, struct json_value *result)
{
    return z_sendmany_run(params, help, NULL, result, true);
}

bool rpc_z_sendmany(const struct json_value *params, bool help,
                    struct json_value *result)
{
    return wallet_send_once_dispatch(params, help, z_sendmany_plain, result);
}

/* The registered z_sendmany handler (and so core.wallet.shielded.send, which
 * calls it through the RPC table): the only entry that honours the phone
 * rule. It keeps the send-once record of the plain handler. */
bool rpc_z_sendmany_checkpoint(const struct json_value *params, bool help,
                               struct json_value *result)
{
    return wallet_send_once_dispatch(params, help, z_sendmany_checkpoint_plain,
                                     result);
}

bool z_sendmany_prepare(const struct json_value *params,
                        struct wallet_tx *prepared,
                        struct json_value *result)
{
    if (!prepared || !result)
        LOG_FAIL("wallet_shielded", "z_sendmany_prepare: NULL output");
    memset(prepared, 0, sizeof(*prepared));
    return z_sendmany_run(params, false, prepared, result, false);
}
