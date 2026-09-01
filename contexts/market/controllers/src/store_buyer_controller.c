/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BUYER RPC surface. See controllers/store_buyer_controller.h for the
 * shape of the contract; all of the actual buying lives in
 * engine/services/src/store_buyer.c. This file parses params, calls one service
 * function, and renders the answer. */

#include "controllers/store_buyer_controller.h"
#include "controllers/wallet_shielded_controller.h"
/* wallet_direct_sendtoaddress — the transparent spend, in-process for the same
 * reason z_sendmany is: no crash window between "value left the wallet" and
 * "the purchase row knows". */
#include "controllers/wallet_controller.h"
#include "services/store_buyer.h"
#include "json/json.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define SBC_TAG "store_buyer_rpc"

/* Bounded copy of the node's data directory. Set once at service wiring; the
 * pointer the caller passes is boot-owned and may outlive nothing in
 * particular, so the string is copied rather than aliased. */
static char g_datadir[1024];

void rpc_store_buyer_set_state(const char *datadir)
{
    (void)snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
}

/* Render a refusal as a SUCCESSFUL call reporting a refusal: {ok:false,
 * code, message}. Always returns true — the distinction the caller needs is
 * "the node said no, here is the code" versus "the node did not answer", and
 * folding a refusal into an RPC error would destroy it. */
static bool sbc_refuse(struct json_value *result, int st,
                       const char *detail)
{
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", false);
    (void)json_push_kv_str(result, "code", store_buyer_status_code(st));
    (void)json_push_kv_str(result, "message", store_buyer_status_message(st));
    if (detail && detail[0])
        (void)json_push_kv_str(result, "detail", detail);
    return true;
}

static bool sbc_ok(struct json_value *result)
{
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "code", "OK");
    return true;
}

/* The data directory, or NULL when nothing was wired. */
static const char *sbc_datadir(void)
{
    return g_datadir[0] ? g_datadir : NULL;
}

/* Render one purchase row into `into`. */
static void sbc_push_purchase(struct json_value *into,
                              const struct db_store_purchase *p)
{
    (void)json_push_kv_int(into, "purchase_id", p->id);
    (void)json_push_kv_int(into, "order_id", p->order_id);
    (void)json_push_kv_int(into, "product_id", p->product_id);
    (void)json_push_kv_str(into, "product_name", p->product_name);
    (void)json_push_kv_str(into, "token_id", p->token_id);
    (void)json_push_kv_str(into, "payment_address", p->payment_addr);
    (void)json_push_kv_str(into, "customer_address", p->customer_addr);
    (void)json_push_kv_str(into, "memo", p->memo);
    (void)json_push_kv_int(into, "amount_zatoshi", p->amount_zatoshi);
    (void)json_push_kv_str(into, "stage", store_purchase_stage_name(p->stage));
    (void)json_push_kv_bool(into, "has_file", p->has_content_hash);
    (void)json_push_kv_str(into, "output_path", p->output_path);
    (void)json_push_kv_str(into, "operation_id", p->operation_id);
    (void)json_push_kv_str(into, "last_error", p->last_error);
    (void)json_push_kv_int(into, "created_at", p->created_at);
    (void)json_push_kv_int(into, "updated_at", p->updated_at);
}

/* ── storebuy_catalog ───────────────────────────────────────────────── */

enum { SBC_CATALOG_MAX = 64, SBC_LIST_MAX = 64 };

static bool rpc_storebuy_catalog(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result,
            "storebuy_catalog\n"
            "\nProducts this node's store currently offers.\n"
            "\nResult: {ok, products:[{product_id, name, token_id, "
            "price_zatoshi, tokens_per_purchase, has_file}]}\n");
        return true;
    }
    const char *datadir = sbc_datadir();
    if (!datadir)
        return sbc_refuse(result, STORE_BUYER_ERR_DB, "no data directory wired");

    struct store_buyer_offer offers[SBC_CATALOG_MAX];
    size_t n = 0;
    struct zcl_result r =
        store_buyer_catalog(datadir, offers, SBC_CATALOG_MAX, &n);
    if (!r.ok)
        return sbc_refuse(result, r.code, r.message);

    sbc_ok(result);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_int(&row, "product_id", offers[i].product_id);
        (void)json_push_kv_str(&row, "name", offers[i].name);
        (void)json_push_kv_str(&row, "token_id", offers[i].token_id);
        (void)json_push_kv_int(&row, "price_zatoshi", offers[i].price_zatoshi);
        (void)json_push_kv_int(&row, "tokens_per_purchase",
                               offers[i].tokens_per_purchase);
        (void)json_push_kv_bool(&row, "has_file", offers[i].has_content);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(result, "products", &arr);
    json_free(&arr);
    return true;
}

/* ── storebuy_order ─────────────────────────────────────────────────── */

static bool rpc_storebuy_order(const struct json_value *params, bool help,
                               struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "storebuy_order product_id \"customer_address\" [\"output_path\"]"
            " [\"payment_kind\"]\n"
            "\nPlace an order through the store's real order route: CSRF\n"
            "token, proof-of-work puzzle and pending-order caps all apply.\n"
            "\nArguments:\n"
            "1. product_id       (numeric) an active product\n"
            "2. customer_address (string) transparent address the merchant\n"
            "                    mints access tokens to\n"
            "3. output_path      (string, optional) where the purchased file\n"
            "                    will be written when it is collected\n"
            "4. payment_kind     (string, optional) \"shielded\" (default) or\n"
            "                    \"transparent\". A transparent order is the\n"
            "                    only kind a build with no Sapling proving\n"
            "                    backend can pay, and is bound by its\n"
            "                    one-time address instead of a memo\n"
            "\nResult: {ok, purchase_id, order_id, payment_address, memo,\n"
            "         amount_zatoshi}\n");
        return help;
    }
    const char *datadir = sbc_datadir();
    if (!datadir)
        return sbc_refuse(result, STORE_BUYER_ERR_DB, "no data directory wired");

    int64_t product_id = json_get_int(json_at(params, 0));
    const char *addr = json_get_str(json_at(params, 1));
    const char *out_path = json_size(params) >= 3
                               ? json_get_str(json_at(params, 2)) : NULL;
    const char *kind = json_size(params) >= 4
                           ? json_get_str(json_at(params, 3)) : NULL;
    /* Only the exact word opts in; anything else stays shielded rather than
     * guessing what an unrecognised kind meant. */
    bool transparent = kind && strcmp(kind, "transparent") == 0;

    struct store_buyer_order placed;
    struct zcl_result r =
        store_buyer_order(datadir, product_id, addr, out_path, transparent,
                          &placed);
    if (!r.ok)
        return sbc_refuse(result, r.code, r.message);

    sbc_ok(result);
    (void)json_push_kv_int(result, "purchase_id", placed.purchase_id);
    (void)json_push_kv_int(result, "order_id", placed.order_id);
    (void)json_push_kv_str(result, "payment_address", placed.payment_addr);
    (void)json_push_kv_str(result, "memo", placed.memo);
    (void)json_push_kv_int(result, "amount_zatoshi", placed.amount_zatoshi);
    return true;
}

/* ── storebuy_pay ───────────────────────────────────────────────────── */

/* Build z_sendmany's params array: [from, [{address, amount, memo_hex}]].
 * The amount is passed as a decimal STRING, not a double: parse_amount
 * parses a string exactly, so a price in zatoshi survives the round trip
 * without ever becoming a binary float. */
static void sbc_build_send_params(struct json_value *out,
                                  const struct store_buyer_payment *pay)
{
    char amount[32];
    (void)snprintf(amount, sizeof(amount), "%lld.%08lld",
                   (long long)(pay->amount_zatoshi / 100000000),
                   (long long)(pay->amount_zatoshi % 100000000));

    struct json_value from, recip, arr;
    json_init(&from);
    json_set_str(&from, pay->from_addr);
    json_init(&recip);
    json_set_object(&recip);
    (void)json_push_kv_str(&recip, "address", pay->to_addr);
    (void)json_push_kv_str(&recip, "amount", amount);
    (void)json_push_kv_str(&recip, "memo_hex", pay->memo_hex);
    json_init(&arr);
    json_set_array(&arr);
    (void)json_push_back(&arr, &recip);

    json_set_array(out);
    (void)json_push_back(out, &from);
    (void)json_push_back(out, &arr);

    json_free(&from);
    json_free(&recip);
    json_free(&arr);
}

/* z_sendmany's refusal text, mapped back onto the buyer's vocabulary so the
 * caller sees INSUFFICIENT_FUNDS rather than a sentence. Coin selection is
 * z_sendmany's job; this only translates its verdict. */
static enum store_buyer_status sbc_classify_send_error(const char *msg)
{
    if (!msg)
        return STORE_BUYER_ERR_DELIVERY_FAILED;
    if (strstr(msg, "Insufficient funds"))
        return STORE_BUYER_ERR_INSUFFICIENT_FUNDS;
    if (strstr(msg, "release_assisted") || strstr(msg, "refused — tip"))
        return STORE_BUYER_ERR_SPEND_REFUSED;
    if (strstr(msg, "proving") || strstr(msg, "prover"))
        return STORE_BUYER_ERR_PROVER_UNAVAILABLE;
    return STORE_BUYER_ERR_DELIVERY_FAILED;
}

static bool rpc_storebuy_pay(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "storebuy_pay purchase_id \"from_address\"\n"
            "\nPay a purchase with a shielded payment carrying the order's\n"
            "memo, so the merchant can bind the payment to the order.\n"
            "\nRefuses, by name, before any value moves: on mainnet, with no\n"
            "Sapling proving backend, when the node's spend guard is closed,\n"
            "when the wallet cannot cover the amount, and when the purchase\n"
            "was already paid.\n"
            "\nArguments:\n"
            "1. purchase_id  (numeric)\n"
            "2. from_address (string) transparent or shielded funding address\n"
            "\nResult: {ok, purchase_id, operation_id, amount_zatoshi, memo_hex}\n");
        return help;
    }
    const char *datadir = sbc_datadir();
    if (!datadir)
        return sbc_refuse(result, STORE_BUYER_ERR_DB, "no data directory wired");

    int64_t purchase_id = json_get_int(json_at(params, 0));
    const char *from = json_get_str(json_at(params, 1));

    struct store_buyer_payment pay;
    struct zcl_result r =
        store_buyer_prepare_payment(datadir, purchase_id, from, &pay);
    if (!r.ok) {
        ZCL_IGNORE_RESULT(store_buyer_fail(datadir, purchase_id, r.code,
                                           r.message),
                          "the refusal is already being returned to the "
                          "caller; failing to annotate the row must not "
                          "replace it with a different reason");
        return sbc_refuse(result, r.code, r.message);
    }

    /* Two spends, one per order-address type, and the ORDER picks which:
     *
     *   z-address -> z_sendmany carrying the order memo (needs a prover)
     *   t-address -> a plain signed t->t spend, bound by the one-time address
     *
     * A transparent output has nowhere to put a memo, which is exactly why the
     * merchant mints a fresh address per transparent order — see
     * store_confirmed_payment. Both callees run the node's spend guard and
     * broadcast; both hand back an identifier we persist before answering. */
    struct json_value send_result;
    char tx_txid[80] = "";
    char tx_error[256] = "";
    const char *opid = NULL;
    const char *why = NULL;
    bool sent;

    json_init(&send_result);
    if (wallet_addr_is_sapling(pay.to_addr)) {
        struct json_value send_params;
        json_init(&send_params);
        sbc_build_send_params(&send_params, &pay);
        sent = rpc_z_sendmany(&send_params, false, &send_result);
        json_free(&send_params);
        /* z_sendmany answers with a bare string: txid on success, reason on
         * refusal. */
        if (sent)
            opid = json_get_str(&send_result);
        else
            why = json_get_str(&send_result);
    } else {
        sent = wallet_direct_sendtoaddress(pay.to_addr, pay.amount_zatoshi,
                                           tx_txid, sizeof(tx_txid),
                                           tx_error, sizeof(tx_error));
        if (sent)
            opid = tx_txid;
        else
            why = tx_error;
    }

    if (!sent) {
        enum store_buyer_status mapped = sbc_classify_send_error(why);
        LOG_WARN(SBC_TAG, "pay: purchase %lld — send refused: %s",
                 (long long)purchase_id, why ? why : "(no reason given)");
        ZCL_IGNORE_RESULT(store_buyer_fail(datadir, purchase_id, mapped, why),
                          "the send refusal is already being returned to the "
                          "caller; failing to annotate the row must not "
                          "replace it with a different reason");
        bool refused = sbc_refuse(result, mapped, why);
        json_free(&send_result);
        return refused;
    }

    struct zcl_result rec =
        store_buyer_record_payment(datadir, purchase_id, opid);
    if (!rec.ok) {
        /* The payment WAS submitted. Say so loudly rather than reporting a
         * clean failure: the money is gone and the row did not record it,
         * and the merchant's reconcile will still credit the order — by memo
         * for a shielded one, by the one-time address for a transparent one —
         * so a later status call recovers the purchase. */
        LOG_WARN(SBC_TAG, "pay: purchase %lld submitted operation %s but the "
                 "purchase row would not persist — the order will still be "
                 "credited by its order bind; re-run status to recover it",
                 (long long)purchase_id, opid ? opid : "(none)");
    }

    sbc_ok(result);
    (void)json_push_kv_int(result, "purchase_id", purchase_id);
    (void)json_push_kv_str(result, "operation_id", opid ? opid : "");
    (void)json_push_kv_int(result, "amount_zatoshi", pay.amount_zatoshi);
    (void)json_push_kv_str(result, "memo_hex", pay.memo_hex);
    (void)json_push_kv_bool(result, "recorded", rec.ok);
    json_free(&send_result);
    return true;
}

/* ── storebuy_status ────────────────────────────────────────────────── */

static bool rpc_storebuy_status(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "storebuy_status [purchase_id]\n"
            "\nWith a purchase_id: that purchase, re-checked against the\n"
            "merchant's current view (the stage advances to `paid` once the\n"
            "merchant has credited the order).\n"
            "Without one: every purchase this node has made, newest first,\n"
            "plus how many are still owed something.\n");
        return true;
    }
    const char *datadir = sbc_datadir();
    if (!datadir)
        return sbc_refuse(result, STORE_BUYER_ERR_DB, "no data directory wired");

    if (params && json_size(params) >= 1) {
        int64_t purchase_id = json_get_int(json_at(params, 0));
        struct store_buyer_state state;
        struct zcl_result r =
            store_buyer_refresh(datadir, purchase_id, &state);
        if (!r.ok)
            return sbc_refuse(result, r.code, r.message);
        sbc_ok(result);
        sbc_push_purchase(result, &state.purchase);
        (void)json_push_kv_bool(result, "merchant_order_found",
                                state.merchant_order_found);
        (void)json_push_kv_int(result, "merchant_order_status",
                               state.merchant_order_status);
        (void)json_push_kv_int(result, "confirmed_zatoshi",
                               state.confirmed_zatoshi);
        (void)json_push_kv_int(result, "tip_height", state.tip_height);
        (void)json_push_kv_bool(result, "ready_to_collect",
                                state.ready_to_collect);
        return true;
    }

    struct db_store_purchase rows[SBC_LIST_MAX];
    size_t n = 0;
    struct zcl_result r =
        store_buyer_list(datadir, rows, SBC_LIST_MAX, &n);
    if (!r.ok)
        return sbc_refuse(result, r.code, r.message);

    sbc_ok(result);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    int unfinished = 0;
    for (size_t i = 0; i < n; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        sbc_push_purchase(&row, &rows[i]);
        (void)json_push_back(&arr, &row);
        json_free(&row);
        if (rows[i].stage == STORE_PURCHASE_CREATED ||
            rows[i].stage == STORE_PURCHASE_PAYING ||
            rows[i].stage == STORE_PURCHASE_PAID)
            unfinished++;
    }
    (void)json_push_kv(result, "purchases", &arr);
    json_free(&arr);
    (void)json_push_kv_int(result, "count", (int64_t)n);
    (void)json_push_kv_int(result, "unfinished", unfinished);
    return true;
}

/* ── storebuy_collect ───────────────────────────────────────────────── */

static bool rpc_storebuy_collect(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "storebuy_collect purchase_id [\"output_path\"]\n"
            "\nDownload a paid purchase through the store's token gate,\n"
            "verify the bytes against the product's content hash, and only\n"
            "then write them. A hash mismatch writes nothing at all.\n"
            "\nRe-polls the merchant first, so a purchase paid before a\n"
            "restart is collected without a separate status call.\n"
            "\nResult: {ok, purchase_id, output_path, bytes, content_hash}\n");
        return help;
    }
    const char *datadir = sbc_datadir();
    if (!datadir)
        return sbc_refuse(result, STORE_BUYER_ERR_DB, "no data directory wired");

    int64_t purchase_id = json_get_int(json_at(params, 0));
    const char *out_path = json_size(params) >= 2
                               ? json_get_str(json_at(params, 1)) : NULL;

    struct store_buyer_delivery got;
    struct zcl_result r =
        store_buyer_collect(datadir, purchase_id, out_path, &got);
    if (!r.ok)
        return sbc_refuse(result, r.code, r.message);

    char hex[65];
    for (int i = 0; i < 32; i++)
        (void)snprintf(hex + i * 2, 3, "%02x", got.content_hash[i]);

    sbc_ok(result);
    (void)json_push_kv_int(result, "purchase_id", purchase_id);
    (void)json_push_kv_str(result, "output_path", got.output_path);
    (void)json_push_kv_int(result, "bytes", got.bytes);
    (void)json_push_kv_str(result, "content_hash", hex);
    (void)json_push_kv_bool(result, "hash_verified", got.hash_verified);
    return true;
}

/* ── Registration ───────────────────────────────────────────────────── */

void register_store_buyer_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "store", "storebuy_catalog", rpc_storebuy_catalog, true },
        { "store", "storebuy_order",   rpc_storebuy_order,   false },
        { "store", "storebuy_pay",     rpc_storebuy_pay,     false },
        { "store", "storebuy_status",  rpc_storebuy_status,  true },
        { "store", "storebuy_collect", rpc_storebuy_collect, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
