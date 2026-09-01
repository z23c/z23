/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict ZSLP readiness, quantity, burn, and validity rendering. */

#include "zslp_controller_internal.h"

#include "controllers/zslp_controller.h"
#include "config/runtime.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zslp.h"
#include "models/zslp_validity.h"
#include "primitives/transaction.h"
#include "services/zslp_command_service.h"
#include "util/log_macros.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <string.h>

bool zslp_controller_validity_ready(struct json_value *result,
                                    const char *verb)
{
    struct node_db *ndb = app_runtime_node_db();
    int32_t tip = reducer_frontier_provable_tip_cached();
    int32_t cursor = -1;
    if (zslp_validity_is_caught_up(ndb, tip, &cursor))
        return true;
    if (result) {
        char error[192];
        snprintf(error, sizeof(error),
                 "Error: strict ZSLP validity is not caught up "
                 "(cursor=%d provable_tip=%d)", cursor, tip);
        json_set_str(result, error);
    }
    LOG_ERROR("zslp", "%s: strict validity not ready cursor=%d tip=%d",
              verb, cursor, tip);
    return false;
}

bool zslp_controller_parse_amount(const struct json_value *value,
                                  uint64_t *amount_out)
{
    if (!value || !amount_out)
        LOG_FAIL("zslp", "parse_amount: null argument");
    if (value->type == JSON_INT) {
        int64_t raw = json_get_int(value);
        if (raw <= 0)
            LOG_FAIL("zslp", "parse_amount: non-positive amount %lld",
                     (long long)raw);
        *amount_out = (uint64_t)raw;
        return true;
    }
    const char *s = json_get_str(value);
    if (!s || !s[0])
        LOG_FAIL("zslp", "parse_amount: quantity must be decimal text");
    uint64_t parsed = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < '0' || *p > '9')
            LOG_FAIL("zslp", "parse_amount: non-decimal quantity");
        unsigned digit = (unsigned)(*p - '0');
        if (parsed > (UINT64_MAX - digit) / 10)
            LOG_FAIL("zslp", "parse_amount: quantity overflow");
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0)
        LOG_FAIL("zslp", "parse_amount: zero quantity");
    *amount_out = parsed;
    return true;
}

void zslp_controller_render_validity(struct json_value *out,
                                     const struct db_zslp_token_info *token)
{
    struct uint256 token_id;
    uint256_set_hex(&token_id, token->token_id);
    struct zslp_token_validity_summary strict;
    if (!uint256_is_null(&token_id) && zslp_validity_token_summary(
            app_runtime_node_db(), token_id.data, &strict)) {
        json_push_kv_str(out, "validity", "VALID_HISTORY_ONLY");
        json_push_kv_int(out, "validated_height", strict.validated_height);
        int32_t tip = reducer_frontier_provable_tip_cached();
        int64_t confirmations = strict.validated_height >= 0 &&
                                tip >= strict.validated_height
            ? (int64_t)tip - strict.validated_height + 1 : 0;
        json_push_kv_int(out, "confirmations", confirmations);
        json_push_kv_int(out, "strict_total_minted", strict.total_minted);
        json_push_kv_int(out, "strict_total_burned", strict.total_burned);
        json_push_kv_int(out, "circulating_supply", strict.circulating_supply);
        json_push_kv_bool(out, "mint_baton_active", strict.baton_active);
    } else {
        json_push_kv_str(out, "validity", "UNKNOWN");
    }
}

void zslp_controller_render_transfer(
    struct json_value *out, const struct db_zslp_transfer_info *xfer)
{
    json_set_object(out);
    json_push_kv_str(out, "txid", xfer->txid);
    json_push_kv_str(out, "token_id", xfer->token_id);
    json_push_kv_int(out, "block_height", xfer->block_height);
    json_push_kv_int(out, "tx_type", xfer->tx_type);
    json_push_kv_int(out, "amount", xfer->amount);
    json_push_kv_int(out, "vout", xfer->vout);
    if (xfer->to_addr_hex[0])
        json_push_kv_str(out, "to_addr_hex", xfer->to_addr_hex);
}

bool zslp_controller_require_token(const char *token_key,
                                   struct json_value *result)
{
    if (token_key && zslp_service_validate_token_key(token_key).ok)
        return true;
    if (result)
        json_set_str(result, "token_id must be alphanumeric or 64-char hex");
    return false; // raw-return-ok:error body set for request validation
}

bool zslp_controller_require_address(const char *addr, bool strict_chain_addr,
                                     struct json_value *result)
{
    if (addr && zslp_service_validate_recipient_addr(addr,
                                                      strict_chain_addr).ok)
        return true;
    if (result)
        json_set_str(result, "address is invalid");
    return false; // raw-return-ok:error body set for request validation
}

bool zslp_burn_with_receipt(const char *datadir, const char *token_id_hex,
                            uint64_t amount, struct zslp_tx_receipt *receipt)
{
    if (receipt) memset(receipt, 0, sizeof(*receipt));
    struct wallet *wallet = zslp_controller_wallet();
    struct tx_mempool *mempool = zslp_controller_mempool();
    if (!zslp_controller_datadir(datadir) || !wallet || !mempool || amount == 0)
        LOG_FAIL("zslp", "burn: wallet context or amount unavailable");
    if (!zslp_controller_validity_ready(NULL, "zslp_burn"))
        return false; // raw-return-ok:readiness helper logged the refusal
    struct uint256 token_id;
    uint256_set_hex(&token_id, token_id_hex);
    if (uint256_is_null(&token_id))
        LOG_FAIL("zslp", "burn: invalid token id");

    struct wallet_tx wtx;
    int64_t fee_paid = 0;
    const char *tx_error = NULL;
    struct zcl_result built = zslp_command_build_token_burn_tx(
        wallet, token_id.data, amount, &wtx, &fee_paid, &tx_error);
    if (!built.ok)
        LOG_FAIL("zslp", "burn: tx build failed: %s",
                 tx_error ? tx_error : built.message);
    char validity_reason[96];
    if (!zslp_validity_inputs_match(app_runtime_node_db(), &wtx.tx,
                                    token_id.data, ZSLP_LEDGER_TOKEN,
                                    validity_reason,
                                    sizeof(validity_reason))) {
        transaction_free(&wtx.tx);
        LOG_FAIL("zslp", "burn: selected inputs are not VALID: %s",
                 validity_reason);
    }
    char txid[65], publish_error[256] = {0};
    if (!zslp_controller_publish(&wtx, txid, publish_error,
                                 sizeof(publish_error))) {
        transaction_free(&wtx.tx);
        return false; // raw-return-ok:publisher logged the failure
    }
    if (receipt) {
        snprintf(receipt->txid, sizeof(receipt->txid), "%s", txid);
        receipt->fee_paid = fee_paid;
        receipt->broadcast = true;
    }
    transaction_free(&wtx.tx);
    return true;
}
