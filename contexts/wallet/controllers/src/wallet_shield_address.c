/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z_shieldaddress: sweep one public address into the wallet's own newest
 * shielded address with no transparent output. See
 * controllers/wallet_shield_address.h for the parameters and refusal codes.
 *
 * The coin set, the fee and the destination are all decided here, never by the
 * caller. A keyed call reads the coins again at build time and refuses with
 * PLAN_TOKEN_MISMATCH when they differ from the plan it was given, so a coin
 * that arrived or matured in between can never change what is sent. Logs carry
 * no address, amount, key or txid. */

#include "controllers/wallet_shield_address.h"

#include "controllers/wallet_send_once.h"
#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_spend_gate.h"
#include "wallet/wallet_lock.h"

#define SHIELD_TAG "wallet_shield"
#define SHIELD_EXPIRY_BLOCKS 20

enum shield_param {
    SHIELD_P_FROM = 0,
    SHIELD_P_TO = 1,
    SHIELD_P_FEE = WALLET_SEND_ONCE_FEE_PARAM,
    SHIELD_P_KEY = WALLET_SEND_ONCE_KEY_PARAM,
    SHIELD_P_INPUTS = 5,
    SHIELD_P_TOTAL = 6
};

void wallet_shield_plan_free(struct wallet_shield_plan *plan)
{
    if (!plan)
        return;
    for (size_t i = 0; i < plan->count; i++)
        db_wallet_utxo_free(&plan->coins[i]);
    plan->count = 0;
}

/* A refusal. While planning it is an answer ({"state":"refused",...}); inside
 * a keyed call it is a failure whose text starts with the code, which the
 * send-once layer reports as released (nothing was sent). */
static bool shield_refuse(struct json_value *result, bool plan_only,
                          const char *code, const char *text,
                          int64_t maturing)
{
    LOG_WARN(SHIELD_TAG, "refused: %s", code);
    if (plan_only) {
        json_set_object(result);
        (void)json_push_kv_str(result, "state", "refused");
        (void)json_push_kv_str(result, "code", code);
        (void)json_push_kv_str(result, "message", text);
        (void)json_push_kv_int(result, "maturing_zat", maturing);
        return true;
    }
    char msg[256];
    (void)snprintf(msg, sizeof(msg), "%s: %s", code, text);
    json_set_str(result, msg);
    return false;
}

/* The account's newest address when no receive address was ever issued: the
 * last used keystore entry that shares its incoming viewing key. */
static bool shield_keystore_latest(struct sapling_keystore *sks,
                                   const struct sapling_key_entry *acct,
                                   struct wallet_shield_plan *p)
{
    bool found = false;
    zcl_mutex_lock(&sks->cs);
    for (size_t i = sks->num_keys; i > 0 && !found; i--) {
        const struct sapling_key_entry *k = &sks->keys[i - 1];
        if (!k->used || memcmp(k->ivk, acct->ivk, sizeof(acct->ivk)) != 0)
            continue;
        memcpy(p->to_diversifier, k->diversifier, sizeof(p->to_diversifier));
        memcpy(p->to_pk_d, k->pk_d, sizeof(p->to_pk_d));
        found = true;
    }
    zcl_mutex_unlock(&sks->cs);
    return found;
}

/* The destination: the receive address the wallet most recently issued for
 * the account (z_getreceiveaddress), else its newest keystore address. Both
 * are the account's own, so the funds are found by its viewing key. Creates
 * and writes nothing. */
static bool shield_resolve_to(struct wallet_rpc_context *ctx,
                              struct wallet_shield_plan *p)
{
    struct sapling_key_entry acct;
    if (!sapling_keystore_copy_account(&ctx->wallet->sapling_keys, &acct))
        return false;
    bool found = ctx->wallet_db &&
                 wallet_sqlite_diversifier_latest(ctx->wallet_db, &acct,
                                                  p->to_diversifier,
                                                  p->to_pk_d);
    if (!found)
        found = shield_keystore_latest(&ctx->wallet->sapling_keys, &acct, p);
    memory_cleanse(&acct, sizeof(acct));
    const struct chain_params *cp = chain_params_get();
    return found && cp &&
           sapling_encode_payment_address(
               p->to_diversifier, p->to_pk_d,
               cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], p->to,
               sizeof(p->to));
}

/* The source: the named public key address, or the one with the largest mature
 * total. Only a key-hash address can be swept; the address is re-encoded so the
 * plan holds the canonical text. */
static bool shield_resolve_from(struct wallet_rpc_context *ctx,
                                const char *from,
                                struct wallet_shield_plan *p,
                                struct json_value *result)
{
    memset(&p->from_dest, 0, sizeof(p->from_dest));
    if (from && from[0]) {
        if (!wallet_decode_address(from, &p->from_dest)) {
            json_set_str(result, "Invalid from address");
            LOG_FAIL(SHIELD_TAG, "from address does not decode");
        }
        if (p->from_dest.type != DEST_KEY_ID) {
            json_set_str(result, "Only a public key address can be shielded");
            LOG_FAIL(SHIELD_TAG, "from address is not a key address");
        }
        memcpy(p->from_hash, p->from_dest.id.key.id.data, 20);
        p->have_from = true;
    } else if (db_wallet_utxo_largest_address(ctx->node_db, p->tip, p->floor,
                                              p->from_hash)) {
        p->from_dest.type = DEST_KEY_ID;
        memcpy(p->from_dest.id.key.id.data, p->from_hash, 20);
        p->have_from = true;
    }
    if (p->have_from &&
        !wallet_encode_destination(&p->from_dest, p->from, sizeof(p->from))) {
        json_set_str(result, "Cannot encode the from address");
        LOG_FAIL(SHIELD_TAG, "from address does not encode");
    }
    return true;
}

static bool shield_select(struct wallet_rpc_context *ctx,
                          struct wallet_shield_plan *p,
                          struct json_value *result)
{
    int n = db_wallet_utxo_select_all_for_address(
        ctx->node_db, p->tip, p->from_hash, p->floor, p->coins,
        WALLET_SHIELD_MAX_INPUTS, &p->remaining);
    if (n < 0 || !db_wallet_utxo_immature_for_address(
                     ctx->node_db, p->tip, p->from_hash, p->floor,
                     &p->maturing)) {
        wallet_shield_plan_free(p);
        json_set_str(result, "Cannot read the wallet coins");
        LOG_FAIL(SHIELD_TAG, "coin selection failed");
    }
    p->count = (size_t)n;
    for (size_t i = 0; i < p->count; i++) {
        p->total += p->coins[i].value;
        if (p->coins[i].is_coinbase)
            p->coinbase_count++;
    }
    if (!MoneyRange(p->total)) {
        wallet_shield_plan_free(p);
        json_set_str(result, "Coin total out of range");
        LOG_FAIL(SHIELD_TAG, "coin total out of range");
    }
    return true;
}

enum wallet_shield_load wallet_shield_load(struct wallet_rpc_context *ctx,
                                           const char *from,
                                           struct wallet_shield_plan *p,
                                           struct json_value *result)
{
    if (!wallet_ctx_db_ready(ctx) || !ctx->main_state || !ctx->wallet) {
        json_set_str(result, "Wallet database unavailable");
        LOG_RETURN(WALLET_SHIELD_LOAD_ERROR, SHIELD_TAG,
                   "wallet or database unavailable");
    }
    p->tip = active_chain_height(&ctx->main_state->chain_active);
    p->fee = ctx->wallet->default_fee;
    if (!shield_resolve_to(ctx, p))
        return WALLET_SHIELD_LOAD_NO_ADDRESS;
    if (!shield_resolve_from(ctx, from, p, result))
        return WALLET_SHIELD_LOAD_ERROR;
    if (p->have_from && !shield_select(ctx, p, result))
        return WALLET_SHIELD_LOAD_ERROR;
    return WALLET_SHIELD_LOAD_OK;
}

bool wallet_shield_assemble(const struct wallet_shield_plan *p,
                            struct wallet_tx *wtx, struct json_value *result)
{
    memset(wtx, 0, sizeof(*wtx));
    transaction_init(&wtx->tx);
    wtx->tx.overwintered = true;
    wtx->tx.version = SAPLING_TX_VERSION;
    wtx->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    wtx->tx.expiry_height = (uint32_t)(p->tip + SHIELD_EXPIRY_BLOCKS);
    if (!transaction_alloc(&wtx->tx, p->count, 0)) {
        json_set_str(result, "Transaction allocation failed");
        LOG_FAIL(SHIELD_TAG, "transaction_alloc failed");
    }
    z_sendmany_fill_inputs(wtx, p->coins, p->count);
    wtx->tx.value_balance = -(p->total - p->fee);
    return true;
}

/* Why the sweep cannot be built right now, or NULL. */
static const char *shield_unviable(const struct wallet_shield_plan *p,
                                   const char **text)
{
    if (p->total <= p->fee) {
        *text = "The public funds are too small to move after the fee";
        return WALLET_SHIELD_NOTHING;
    }
    if (!sapling_proving_available()) {
        *text = "Shielded proving is unavailable on this node";
        return WALLET_SHIELD_NO_PROVER;
    }
    return NULL;
}

static void shield_plan_json(const struct wallet_shield_plan *p,
                             struct json_value *result)
{
    json_set_object(result);
    (void)json_push_kv_str(result, "state", "plan");
    (void)json_push_kv_str(result, "from", p->from);
    (void)json_push_kv_str(result, "to", p->to);
    (void)json_push_kv_int(result, "input_count", (int64_t)p->count);
    (void)json_push_kv_int(result, "coinbase_input_count",
                           (int64_t)p->coinbase_count);
    (void)json_push_kv_int(result, "total_zat", p->total);
    (void)json_push_kv_int(result, "fee_zat", p->fee);
    (void)json_push_kv_int(result, "amount_zat", p->total - p->fee);
    (void)json_push_kv_int(result, "remaining_inputs", (int64_t)p->remaining);
    (void)json_push_kv_int(result, "maturing_zat", p->maturing);
}

/* The coins and destination read now must be the ones the plan named. */
static bool shield_matches(const struct wallet_shield_plan *p,
                           const struct json_value *params,
                           struct json_value *result)
{
    const struct json_value *to = json_at(params, SHIELD_P_TO);
    const struct json_value *n = json_at(params, SHIELD_P_INPUTS);
    const struct json_value *t = json_at(params, SHIELD_P_TOTAL);
    const char *to_s = to ? json_get_str(to) : NULL;
    if (!to_s || !n || n->type != JSON_INT || !t || t->type != JSON_INT) {
        json_set_str(result, "Invalid parameters");
        LOG_FAIL(SHIELD_TAG, "missing plan bindings");
    }
    if (strcmp(to_s, p->to) != 0 || json_get_int(n) != (int64_t)p->count ||
        json_get_int(t) != p->total)
        return shield_refuse(result, false, WALLET_SHIELD_CHANGED,
                             "The public funds changed since the plan; "
                             "nothing was sent", 0);
    return true;
}

static bool shield_sign_failed(struct json_value *result, int status)
{
    static const char *const text[] = {
        [Z_SENDMANY_SIGN_NO_DEST] = "Cannot determine input destination",
        [Z_SENDMANY_SIGN_NO_KEY] = "Private key not available",
        [Z_SENDMANY_SIGN_SIGHASH] = "Sighash computation failed",
        [Z_SENDMANY_SIGN_SIGN] = "Signing failed",
    };
    json_set_str(result, text[status]);
    LOG_FAIL(SHIELD_TAG, "input signing failed (status %d)", status);
}

/* Binding signature over the finished transaction. */
static bool shield_bind(void *proving_ctx, const struct chain_params *cp,
                        const struct wallet_shield_plan *p,
                        struct wallet_tx *wtx, struct json_value *result)
{
    transaction_compute_hash(&wtx->tx);
    uint32_t branch_id =
        consensus_current_epoch_branch_id(p->tip + 1, &cp->consensus);
    struct sighash_type ht;
    ht.raw = SIGHASH_ALL;
    struct precomputed_tx_data txdata;
    precompute_tx_data(&wtx->tx, &txdata);
    struct script empty_script;
    empty_script.size = 0;
    struct uint256 sighash;
    if (!signature_hash(&empty_script, &wtx->tx, NOT_AN_INPUT, ht, 0,
                        branch_id, &txdata, &sighash) ||
        !zclassic_sapling_binding_sig(proving_ctx, wtx->tx.value_balance,
                                      sighash.data, wtx->tx.binding_sig)) {
        json_set_str(result, "Binding signature failed");
        LOG_FAIL(SHIELD_TAG, "binding signature failed");
    }
    return true;
}

/* The one Sapling output, the input signatures and the binding signature. */
static bool shield_prove_with(struct wallet_rpc_context *ctx,
                              void *proving_ctx, const uint8_t *ovk,
                              const struct wallet_shield_plan *p,
                              struct wallet_tx *wtx, struct json_value *result)
{
    const struct chain_params *cp = chain_params_get();
    uint8_t div[1][11], pk_d[1][32], memo[1][512] = {{0}};
    bool has_memo[1] = { false };
    int64_t amount = p->total - p->fee;
    size_t fail = 0;
    memcpy(div[0], p->to_diversifier, sizeof(div[0]));
    memcpy(pk_d[0], p->to_pk_d, sizeof(pk_d[0]));
    if (!z_sendmany_build_outputs(proving_ctx, wtx, ovk, div, pk_d, &amount,
                                  memo, has_memo, 1, &fail)) {
        json_set_str(result, "Failed to build Sapling output");
        LOG_FAIL(SHIELD_TAG, "sapling output build failed");
    }
    int st = z_sendmany_sign_inputs(ctx, cp, wtx, p->coins, p->count, p->tip,
                                    &fail);
    if (st != Z_SENDMANY_SIGN_OK)
        return shield_sign_failed(result, st);
    return shield_bind(proving_ctx, cp, p, wtx, result);
}

static bool shield_prove(struct wallet_rpc_context *ctx,
                         const struct wallet_shield_plan *p,
                         struct wallet_tx *wtx, struct json_value *result)
{
    wtx->tx.v_shielded_output =
        zcl_calloc(1, sizeof(struct output_description), "shielded_outputs");
    if (!wtx->tx.v_shielded_output) {
        json_set_str(result, "Allocation failed");
        LOG_FAIL(SHIELD_TAG, "shielded output allocation failed");
    }
    wtx->tx.num_shielded_output = 1;
    uint8_t ovk[32];
    z_sendmany_get_ovk(ctx, ovk);
    void *proving_ctx = zclassic_sapling_proving_ctx_init();
    if (!proving_ctx) {
        memory_cleanse(ovk, sizeof(ovk));
        json_set_str(result, "Failed to init proving context");
        LOG_FAIL(SHIELD_TAG, "proving context init failed");
    }
    bool ok = shield_prove_with(ctx, proving_ctx, ovk, p, wtx, result);
    zclassic_sapling_proving_ctx_free(proving_ctx);
    memory_cleanse(ovk, sizeof(ovk));
    return ok;
}

/* The key must be resident before the slow part starts. */
static bool shield_key_present(struct wallet_rpc_context *ctx,
                               const struct wallet_shield_plan *p,
                               struct json_value *result)
{
    zcl_mutex_lock(&ctx->wallet->cs);
    bool have = keystore_have_key(&ctx->wallet->keystore, &p->from_dest.id.key);
    zcl_mutex_unlock(&ctx->wallet->cs);
    if (!have) {
        json_set_str(result, "Private key not available");
        LOG_FAIL(SHIELD_TAG, "no private key for the source address");
    }
    return true;
}

bool wallet_shield_build(struct wallet_rpc_context *ctx,
                         const struct wallet_shield_plan *p,
                         struct wallet_tx *wtx, struct json_value *result)
{
    if (!shield_key_present(ctx, p, result) ||
        !wallet_shield_assemble(p, wtx, result))
        return false;
    if (!shield_prove(ctx, p, wtx, result)) {
        transaction_free(&wtx->tx);
        return false;
    }
    transaction_compute_hash(&wtx->tx);
    wtx->time_received = GetTime();
    wtx->from_me = true;
    wtx->used = true;
    return true;
}

/* Build, sign, admit and relay the sweep; answers the txid. */
static bool shield_send(struct wallet_rpc_context *ctx,
                        const struct wallet_shield_plan *p,
                        struct json_value *result)
{
    struct wallet_tx wtx;
    if (!wallet_shield_build(ctx, p, &wtx, result))
        return false;
    return z_sendmany_admit_relay(ctx, &wtx, result);
}

/* Plan and keyed commit share the load and the viability checks. */
static bool shield_execute(struct wallet_rpc_context *ctx,
                           const struct json_value *params, bool keyed,
                           struct wallet_shield_plan *p,
                           struct json_value *result)
{
    const struct json_value *from = json_at(params, SHIELD_P_FROM);
    enum wallet_shield_load ld = wallet_shield_load(
        ctx, from ? json_get_str(from) : NULL, p, result);
    if (ld == WALLET_SHIELD_LOAD_NO_ADDRESS)
        return shield_refuse(result, !keyed, WALLET_SHIELD_NO_ADDRESS,
                             "The wallet has no private address yet", 0);
    if (ld != WALLET_SHIELD_LOAD_OK)
        return false;
    if (keyed && !shield_matches(p, params, result))
        return false;
    const char *text = NULL;
    const char *code = shield_unviable(p, &text);
    if (code)
        return shield_refuse(result, !keyed, code, text, p->maturing);
    if (!keyed) {
        shield_plan_json(p, result);
        return true;
    }
    return shield_send(ctx, p, result);
}

static bool shield_lock_ok(struct json_value *result)
{
    struct zcl_result lk = wallet_lock_spend_guard();
    if (lk.ok)
        return true;
    json_set_str(result, "Error: wallet is locked — run walletunlock before "
                         "spending");
    LOG_FAIL(SHIELD_TAG, "refused: wallet locked (code=%d)", lk.code);
}

static bool shield_run(const struct json_value *params, bool help,
                       struct json_value *result)
{
    RPC_HELP(help, result,
        "z_shieldaddress \"from\"|null \"to\" null fee key input_count total\n"
        "\nMoves every mature coin of one public address into the wallet's "
        "newest\nshielded address in one transaction with no transparent "
        "output. Without a\nkey it only plans. With a key it runs once.\n");
    struct wallet_rpc_context *ctx = wallet_ctx();
    const struct json_value *kv = json_at(params, SHIELD_P_KEY);
    bool keyed = kv && !json_is_null(kv);
    int32_t floor = WALLET_SPEND_NO_FLOOR;
    if (!wallet_spend_gate_for_send(ctx, true, &floor, result))
        return false;
    if (keyed && !shield_lock_ok(result))
        return false;
    ENSURE_WALLET(result);
    struct wallet_shield_plan *p = zcl_calloc(1, sizeof(*p), "shield_plan");
    if (!p) {
        json_set_str(result, "Allocation failed");
        LOG_FAIL(SHIELD_TAG, "plan allocation failed");
    }
    p->floor = floor;
    bool ok = shield_execute(ctx, params, keyed, p, result);
    wallet_shield_plan_free(p);
    free(p);
    return ok;
}

bool rpc_z_shieldaddress(const struct json_value *params, bool help,
                         struct json_value *result)
{
    return wallet_send_once_dispatch(params, help, shield_run, result);
}
