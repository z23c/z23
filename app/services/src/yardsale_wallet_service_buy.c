/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the yardsale wallet glue — the BUY half (plan: wallet coin
 * selection + exact expiring plan; commit: one wallet key per input and
 * yardsale_buyer_begin). Sibling of yardsale_wallet_service.c (E1
 * file-size split); shared helpers come through
 * services/yardsale_wallet_internal.h. */

#include "services/yardsale_wallet_service.h"
#include "services/yardsale_wallet_internal.h"

#include "base/hex.h"
#include "json/json.h"
#include "keys/pubkey.h"
#include "script/script.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "zswap/zswap_ceremony.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Build the exact buyer accept from wallet selection. On insufficient
 * funds the refusal body names required/available/shortfall sats. */
static enum yardsale_wallet_status yw_build_buyer_accept(
    struct wallet *w, const struct zswap_yardsale_ad *ad,
    struct zswap_buyer_accept *buyer, struct json_value *out)
{
    int64_t fee = wallet_default_fee(w);
    if (fee <= 0)
        return yw_fail(out, YARDSALE_WALLET_ERR_FEE,
                       "the wallet fee is not a positive amount");
    if (ad->quote.zcl_amount > (uint64_t)(INT64_MAX - fee))
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
                       "the sign's price overflows the money range");
    int64_t target = (int64_t)ad->quote.zcl_amount + fee;

    struct coin_entry *avail = zcl_malloc(
        YW_COIN_CAP * sizeof(*avail), "yardsale_buy_coins");
    if (!avail)
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "coin inventory allocation failed");
    size_t na = 0;
    wallet_available_coins(w, avail, &na, YW_COIN_CAP, true, false);
    struct coin_entry chosen[ZSWAP_MAX_BUYER_INPUTS];
    size_t nc = 0;
    int64_t value = 0;
    bool funded = wallet_select_coins(w, avail, na, target, chosen, &nc,
                                      ZSWAP_MAX_BUYER_INPUTS, &value);
    free(avail);
    if (!funded || nc == 0) {
        int64_t available = yw_available_ordinary(w);
        int64_t shortfall = target - available;
        enum yardsale_wallet_status st = yw_fail(
            out, YARDSALE_WALLET_ERR_INSUFFICIENT,
            "confirmed ordinary wallet balance cannot cover the price "
            "plus the network fee");
        json_push_kv_int(out, "required_sats", target);
        json_push_kv_int(out, "available_sats", available);
        json_push_kv_int(out, "shortfall_sats",
                         shortfall > 0 ? shortfall : 0);
        return st;
    }

    memset(buyer, 0, sizeof(*buyer));
    buyer->num_inputs = nc;
    for (size_t i = 0; i < nc; i++) {
        const struct tx_out *txout = &chosen[i].wtx->tx.vout[chosen[i].i];
        if (!script_is_p2pkh(&txout->script_pub_key))
            return yw_fail(out, YARDSALE_WALLET_ERR_SCRIPT_TYPE,
                           "a selected ZCL input is not P2PKH — the "
                           "ceremony signs P2PKH inputs only");
        struct zswap_swap_input *in = &buyer->inputs[i];
        memcpy(in->txid, chosen[i].wtx->tx.hash.data, 32);
        in->vout = (uint32_t)chosen[i].i;
        in->value_sats = txout->value;
        in->script_len = (uint16_t)txout->script_pub_key.size;
        memcpy(in->script_pub_key, txout->script_pub_key.data,
               txout->script_pub_key.size);
    }
    if (!wallet_get_new_address(w, buyer->token_recv_address,
                                sizeof(buyer->token_recv_address)) ||
        !wallet_get_new_change_address(w, buyer->change_address,
                                       sizeof(buyer->change_address)))
        return yw_fail(out, YARDSALE_WALLET_ERR_ADDRESS,
                       "the wallet could not derive the token "
                       "receive/change addresses");
    buyer->fee_sats = (uint64_t)fee;
    buyer->deadline_unix = ad->quote.expires_unix;
    if (zswap_buyer_accept_validate(buyer) != ZSWAP_ASSEMBLY_OK)
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
                       "the assembled buyer accept failed validation");
    return YARDSALE_WALLET_OK;
}

static enum yardsale_wallet_status yw_buy_commit(
    struct wallet *w, struct node_db *ndb, struct yw_plan *p,
    const uint8_t ad_root[32], int64_t now_unix, struct json_value *out)
{
    if (!p->exists)
        return yw_fail(out, YARDSALE_WALLET_ERR_PLAN_NOT_FOUND,
                       "no plan names this sign — run without "
                       "confirm first and inspect the exact terms");
    if (now_unix >= p->row.expires_unix) {
        if (!yw_plan_mark(p, ndb, YARDSALE_PLAN_STATE_EXPIRED, NULL).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                           "the plan ledger could not record the "
                           "expiry");
        return yw_fail(out, YARDSALE_WALLET_ERR_PLAN_EXPIRED,
                       "the plan lifetime elapsed — no buy was "
                       "begun");
    }

    uint8_t raw[YW_PAYLOAD_RAW_MAX];
    size_t raw_len = 0;
    uint8_t root[32];
    struct zswap_buyer_accept buyer;
    if (!yw_payload_decode(p->row.payload_hex, raw, sizeof(raw),
                           &raw_len).ok ||
        !yw_parse_buyer_payload(raw, raw_len, root, &buyer).ok)
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "the stored plan payload failed to parse");

    struct zswap_yardsale_ad ad;
    if (!yw_live_ad(root, now_unix, &ad).ok)
        return yw_fail(out, YARDSALE_WALLET_ERR_AD_UNKNOWN,
                       "the sign expired or left this node's yardsale "
                       "— the ceremony is dead and no buy was begun");

    /* Every planned input must still be a confirmed spendable wallet
     * coin with the exact planned script and value. */
    for (size_t i = 0; i < buyer.num_inputs; i++) {
        struct coin_entry coin;
        bool seen = false;
        memset(&coin, 0, sizeof(coin));
        if (!yw_find_coin(w, buyer.inputs[i].txid,
                          buyer.inputs[i].vout, false, &coin, &seen).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_INPUT_CONFLICT,
                           "a planned ZCL input is no longer a "
                           "confirmed spendable wallet coin");
        const struct tx_out *txout =
            &coin.wtx->tx.vout[buyer.inputs[i].vout];
        if (txout->value != buyer.inputs[i].value_sats ||
            txout->script_pub_key.size != buyer.inputs[i].script_len ||
            memcmp(txout->script_pub_key.data,
                   buyer.inputs[i].script_pub_key,
                   buyer.inputs[i].script_len) != 0)
            return yw_fail(out, YARDSALE_WALLET_ERR_INPUT_CONFLICT,
                           "a planned ZCL input changed since "
                           "planning");
    }

    /* One wallet key per input, caller's order — the completion maps
     * them back onto the canonically sorted vin by outpoint. */
    struct privkey keys[ZSWAP_MAX_BUYER_INPUTS];
    memset(keys, 0, sizeof(keys));
    for (size_t i = 0; i < buyer.num_inputs; i++) {
        struct key_id kid;
        yw_script_key_id(buyer.inputs[i].script_pub_key, &kid);
        if (!wallet_dump_key(w, &kid, &keys[i])) {
            memory_cleanse(keys, sizeof(keys));
            return yw_fail(out, YARDSALE_WALLET_ERR_KEY_MISSING,
                           "the wallet holds no key for a planned "
                           "ZCL input");
        }
    }
    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    const struct yardsale_wallet_ceremony_port *port = yw_ceremony_port();
    if (!port) {
        memory_cleanse(keys, sizeof(keys));
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "the ceremony port is unwired — no buy was begun");
    }
    int e = port->buyer_begin(
        &ad.quote, &buyer, keys, buyer.num_inputs, now_unix,
        wire, sizeof(wire), &wire_len);
    memory_cleanse(keys, sizeof(keys));
    if (e != 0) { /* 0 == YARDSALE_OK (the controller's enum rides as int) */
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "the ceremony refused the buy: %s",
                 port->buyer_error_string(e));
        return yw_fail(out, YARDSALE_WALLET_ERR_CEREMONY, msg);
    }

    struct zcl_result marked =
        yw_plan_mark(p, ndb, YARDSALE_PLAN_STATE_COMMITTED, "begun");
    if (!marked.ok) {
        return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                       "the buy is flooded but the plan ledger could "
                       "not record the commit");
    }
    char root_hex[65];
    zcl_hex_encode(ad_root, 32, root_hex);
    json_set_object(out);
    yw_render_plan_head(out, YARDSALE_PLAN_KIND_BUY, p->plan_root_hex,
                        p->request_hex, p->row.expires_unix);
    json_push_kv_str(out, "stage", "committed");
    json_push_kv_bool(out, "committed", true);
    json_push_kv_bool(out, "idempotent_replay", false);
    json_push_kv_str(out, "result", "begun");
    json_push_kv_str(out, "quote_root", root_hex);
    json_push_kv_int(out, "pending_buys",
                     port->pending_count(now_unix));
    json_push_kv_int(out, "accept_wire_bytes", (int64_t)wire_len);
    json_push_kv_str(out, "flooded_to", ZSWAP_MSG_ACCEPT);
    return YARDSALE_WALLET_OK;
}

enum yardsale_wallet_status yardsale_wallet_buy(
    struct wallet *w, struct node_db *ndb,
    const uint8_t ad_root[32], bool confirm, int64_t now_unix,
    struct json_value *out)
{
    if (!w || !ad_root || now_unix <= 0 || !out)
        return yw_fail(out, YARDSALE_WALLET_ERR_ARGS,
                       "wallet, sign root, and time are required");
    if (!ndb || !ndb->open)
        return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                       "node.db is unavailable — the plan ledger cannot "
                       "persist");

    struct yw_plan p;
    memset(&p, 0, sizeof(p));
    yw_plan_identity(&p, YARDSALE_PLAN_KIND_BUY, ad_root, 32, NULL, 0);
    p.exists = db_yardsale_plan_find_by_request(ndb, p.request_hex, &p.row);

    /* Idempotent replay of a committed buy — never a second begin...
     * unless the ceremony itself recorded the buy as FAILED: a buy whose
     * partial was refused, whose seller's token input failed the
     * chain-content check, or which never broadcast is not committed in
     * any sense that should pin the buyer's plan forever. Reopen the row
     * to PLANNED and fall through, where the ordinary plan/confirm paths
     * re-verify the ad, the coins, and the terms before anything re-arms.
     * Unknown/in-flight/completed outcomes (and an unwired port) keep the
     * conservative answer: the replay stays committed. */
    if (p.exists &&
        strcmp(p.row.state, YARDSALE_PLAN_STATE_COMMITTED) == 0) {
        const struct yardsale_wallet_ceremony_port *port =
            yw_ceremony_port();
        if (port && port->buy_outcome &&
            port->buy_outcome(ad_root) == 2 /* BUY_OUTCOME_FAILED */) {
            /* The reopen carries no result string — the plan ledger only
             * attaches results to COMMITTED rows; the failure trace lives
             * in the log. */
            LOG_WARN("yardsale", "buy replay on a ceremony-FAILED root "
                     "%s — reopening the committed plan for re-arming",
                     p.request_hex);
            if (!yw_plan_mark(&p, ndb, YARDSALE_PLAN_STATE_PLANNED,
                              NULL).ok) {
                return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                               "the ceremony failed but the plan ledger "
                               "could not record the reopen");
            }
            p.exists = db_yardsale_plan_find_by_request(ndb,
                                                        p.request_hex,
                                                        &p.row);
        } else {
            char root_hex[65];
            zcl_hex_encode(ad_root, 32, root_hex);
            json_set_object(out);
            yw_render_plan_head(out, YARDSALE_PLAN_KIND_BUY,
                                p.plan_root_hex, p.request_hex,
                                p.row.expires_unix);
            json_push_kv_str(out, "stage", "committed");
            json_push_kv_bool(out, "committed", true);
            json_push_kv_bool(out, "idempotent_replay", true);
            json_push_kv_str(out, "result", p.row.result);
            json_push_kv_str(out, "quote_root", root_hex);
            return YARDSALE_WALLET_OK;
        }
    }

    if (confirm)
        return yw_buy_commit(w, ndb, &p, ad_root, now_unix, out);

    /* Plan stage: an unexpired PLANNED row is the same plan. */
    if (p.exists &&
        strcmp(p.row.state, YARDSALE_PLAN_STATE_PLANNED) == 0 &&
        now_unix < p.row.expires_unix) {
        uint8_t raw[YW_PAYLOAD_RAW_MAX];
        size_t raw_len = 0;
        uint8_t root[32];
        struct zswap_buyer_accept buyer;
        if (!yw_payload_decode(p.row.payload_hex, raw, sizeof(raw),
                               &raw_len).ok ||
            !yw_parse_buyer_payload(raw, raw_len, root, &buyer).ok)
            return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                           "the stored plan payload failed to parse");
        struct zswap_yardsale_ad ad;
        json_set_object(out);
        yw_render_plan_head(out, YARDSALE_PLAN_KIND_BUY, p.plan_root_hex,
                            p.request_hex, p.row.expires_unix);
        json_push_kv_str(out, "stage", "plan");
        json_push_kv_bool(out, "committed", false);
        yw_render_buyer_terms(out, &buyer,
                              yw_live_ad(root, now_unix, &ad).ok
                                  ? &ad : NULL);
        json_push_kv_str(out, "confirm_hint",
                         "re-run with \"confirm\":true before "
                         "plan_expires_unix to flood the accept");
        return YARDSALE_WALLET_OK;
    }

    /* Fresh plan (first request, or an expired row being re-planned). */
    struct zswap_yardsale_ad ad;
    if (!yw_live_ad(ad_root, now_unix, &ad).ok)
        return yw_fail(out, YARDSALE_WALLET_ERR_AD_UNKNOWN,
                       "no live sign with that root in this node's "
                       "yardsale");
    struct zswap_buyer_accept buyer;
    enum yardsale_wallet_status st =
        yw_build_buyer_accept(w, &ad, &buyer, out);
    if (st != YARDSALE_WALLET_OK)
        return st;

    uint8_t ser[YW_PAYLOAD_RAW_MAX];
    size_t ser_len = 0;
    if (zswap_buyer_accept_serialize(&buyer, ser, sizeof(ser),
                                     &ser_len) != ZSWAP_ASSEMBLY_OK)
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "the buyer accept failed canonical serialization");
    uint8_t raw[YW_PAYLOAD_RAW_MAX];
    if (32 + ser_len > sizeof(raw))
        return yw_fail(out, YARDSALE_WALLET_ERR_INTERNAL,
                       "the plan payload exceeds its bound");
    memcpy(raw, ad_root, 32);
    memcpy(raw + 32, ser, ser_len);
    char payload_hex[YARDSALE_PLAN_PAYLOAD_HEX_MAX];
    zcl_hex_encode(raw, 32 + ser_len, payload_hex);
    if (!yw_plan_store(&p, ndb, YARDSALE_PLAN_KIND_BUY, payload_hex,
                       now_unix).ok)
        return yw_fail(out, YARDSALE_WALLET_ERR_DB,
                       "the plan ledger could not persist the plan");

    json_set_object(out);
    yw_render_plan_head(out, YARDSALE_PLAN_KIND_BUY, p.plan_root_hex,
                        p.request_hex, p.row.expires_unix);
    json_push_kv_str(out, "stage", "plan");
    json_push_kv_bool(out, "committed", false);
    yw_render_buyer_terms(out, &buyer, &ad);
    json_push_kv_str(out, "confirm_hint",
                     "re-run with \"confirm\":true before "
                     "plan_expires_unix to flood the accept");
    return YARDSALE_WALLET_OK;
}
