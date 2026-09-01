/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private-address, idempotent liquidity fanout plan preparation. */

#include "controllers/vault_intent_controller.h"

#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/vault_intent.h"
#include "services/wallet_money_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VIF_MAX_OUTPUTS 50
#define VIF_MAX_INPUTS 128
#define VIF_COIN_CAP 4096

static pthread_mutex_t g_vif_mutex = PTHREAD_MUTEX_INITIALIZER;

static void vif_error(struct json_value *result, const char *code,
                      const char *message)
{
    vault_intent_error_response(result, code, message);
}

static bool vif_continue_plan(const struct json_value *plan,
                              struct json_value *result)
{
    struct json_value params, copy;
    json_init(&params); json_set_array(&params);
    json_init(&copy); json_copy(&copy, plan);
    bool appended = json_push_back(&params, &copy);
    json_free(&copy);
    if (!appended) {
        json_free(&params);
        vif_error(result, "OUT_OF_MEMORY", "could not stage fanout plan input");
        return true;
    }
    bool handled = vault_intent_plan_transparent_fanout_continuation(
        &params, result);
    json_free(&params);
    return handled;
}

static void vif_internal_key(const char *scope, const char *user_key,
                             char out[VAULT_INTENT_IDEMPOTENCY_MAX + 1])
{
    static const uint8_t domain[] = "vault-fanout-idempotency-v1";
    struct sha3_256_ctx hash;
    uint8_t digest[32]; char hex[65];
    sha3_256_init(&hash);
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, (const uint8_t *)scope, strlen(scope));
    sha3_256_write(&hash, (const uint8_t *)user_key, strlen(user_key));
    sha3_256_finalize(&hash, digest);
    HexStr(digest, sizeof(digest), false, hex, sizeof(hex));
    (void)snprintf(out, VAULT_INTENT_IDEMPOTENCY_MAX + 1,
                   "fanout-%.57s", hex);
}

static void vif_render(struct json_value *result,
                       const struct vault_intent_row *row,
                       size_t output_count, int64_t output_value_zat,
                       bool idempotent)
{
    char plan_id[65], digest[65];
    HexStr(row->plan_id, 32, false, plan_id, sizeof(plan_id));
    HexStr(row->digest, 32, false, digest, sizeof(digest));
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "plan_id", plan_id);
    (void)json_push_kv_str(result, "plan_digest", digest);
    (void)json_push_kv_str(result, "state",
                           vault_intent_state_name(row->state));
    (void)json_push_kv_str(result, "wallet_scope", row->wallet_scope);
    (void)json_push_kv_int(result, "created_at", row->created_at);
    (void)json_push_kv_int(result, "expires_at", row->expires_at);
    (void)json_push_kv_int(result, "output_count", (int64_t)output_count);
    (void)json_push_kv_int(result, "output_value_zat", output_value_zat);
    (void)json_push_kv_int(result, "outputs_total_zat",
                           row->recipient_value_zat);
    (void)json_push_kv_int(result, "preparation_maximum_fee_zat",
                           row->max_fee_zat);
    (void)json_push_kv_int(result, "reserved_zat", row->reserved_zat);
    (void)json_push_kv_bool(result, "idempotent_plan", idempotent);
    (void)json_push_kv_bool(result, "automatic", false);
    (void)json_push_kv_bool(result, "owner_commit_required", true);
    (void)json_push_kv_str(result, "commit_command", "vault.intent.commit");
    (void)json_push_kv_str(result, "backup_before_commit_command",
                           "core.wallet.backup.now");
    (void)json_push_kv_str(result, "commit_prerequisite",
        "fresh encrypted backup after fanout destination creation");
    (void)json_push_kv_str(result, "route", "transparent");
    (void)json_push_kv_str(result, "privacy",
        "PUBLIC_AFTER_COMMIT: output values and transaction graph are visible");
}

static bool vif_preflight(struct wallet_rpc_context *ctx, const char *scope,
                          int64_t outputs_total_zat,
                          struct json_value *result)
{
    struct wallet_money_snapshot money; memset(&money, 0, sizeof(money));
    struct zcl_result mr = wallet_money_snapshot_build(
        ctx->node_db, ctx->main_state, scope, &money);
    int64_t fee = wallet_default_fee(ctx->wallet);
    if (!mr.ok || !money.complete || strcmp(money.status, "CURRENT") != 0) {
        vif_error(result, "MONEY_STATE_NOT_CURRENT",
                  mr.ok ? money.reason : mr.message);
        return false;
    }
    if (fee < 0 || outputs_total_zat > INT64_MAX - fee) {
        vif_error(result, "FEE_INVALID", "wallet fanout fee is invalid");
        return false;
    }
    int64_t reservation = outputs_total_zat + fee;
    int64_t available = money.confirmed_zat >= money.intent_reserved_zat
        ? money.confirmed_zat - money.intent_reserved_zat : 0;
    if (reservation > available ||
        (strcmp(scope, "dev") == 0 &&
         reservation > money.agent_available_zat)) {
        vif_error(result, strcmp(scope, "dev") == 0
            ? "DEVELOPMENT_RESERVE_OR_LAB_CAP"
            : "INSUFFICIENT_CONFIRMED_FUNDS",
            "fanout outputs plus maximum fee exceed current custody allocation");
        return false;
    }

    struct coin_entry *coins = zcl_malloc(
        VIF_COIN_CAP * sizeof(*coins), "fanout_preflight_coins");
    if (!coins) {
        vif_error(result, "OUT_OF_MEMORY", "coin preflight allocation failed");
        return false;
    }
    struct coin_entry selected[VIF_MAX_INPUTS];
    size_t coin_count = 0, selected_count = 0;
    int64_t selected_value = 0;
    wallet_available_coins(ctx->wallet, coins, &coin_count, VIF_COIN_CAP,
                           true, false);
    bool funded = wallet_select_coins(ctx->wallet, coins, coin_count,
        reservation, selected, &selected_count, VIF_MAX_INPUTS,
        &selected_value);
    free(coins);
    if (!funded || selected_count == 0) {
        vif_error(result, "INSUFFICIENT_TRANSPARENT_FUNDS",
                  "confirmed transparent inputs cannot fund this fanout");
        return false;
    }
    return true;
}

bool vault_intent_fanout_plan_rpc(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    if (help) {
        json_set_str(result, "vault_intent_fanout_plan {wallet_scope,recipient_value_zat,maximum_fee_zat,concurrency,idempotency_key}\n");
        return true;
    }
    const struct json_value *input = json_at(params, 0);
    const char *scope = input && input->type == JSON_OBJ
        ? json_get_str(json_get(input, "wallet_scope")) : NULL;
    const char *user_key = input && input->type == JSON_OBJ
        ? json_get_str(json_get(input, "idempotency_key")) : NULL;
    int64_t recipient = input && input->type == JSON_OBJ
        ? json_get_int(json_get(input, "recipient_value_zat")) : 0;
    int64_t maximum_fee = input && input->type == JSON_OBJ
        ? json_get_int(json_get(input, "maximum_fee_zat")) : -1;
    int64_t concurrency = input && input->type == JSON_OBJ
        ? json_get_int(json_get(input, "concurrency")) : 0;
    if (!wallet_money_scope_valid(scope)) {
        vif_error(result, "WALLET_SCOPE_REQUIRED",
                  "wallet_scope must explicitly be dev, prod, or test");
        return true;
    }
    if (!vault_intent_idempotency_key_valid(user_key)) {
        vif_error(result, "IDEMPOTENCY_KEY_REQUIRED",
                  "idempotency_key must be 1..64 printable characters");
        return true;
    }
    if (recipient <= 0 || maximum_fee < 0 || concurrency < 2 ||
        concurrency > VIF_MAX_OUTPUTS || recipient > INT64_MAX - maximum_fee) {
        vif_error(result, "INVALID_FANOUT",
                  "positive recipient_value_zat, non-negative maximum_fee_zat, and concurrency 2..50 are required");
        return true;
    }
    int64_t output_value = recipient + maximum_fee;
    if (!MoneyRange(output_value) ||
        output_value > INT64_MAX / concurrency ||
        !MoneyRange(output_value * concurrency)) {
        vif_error(result, "INVALID_FANOUT", "fanout amount is out of range");
        return true;
    }
    int64_t outputs_total = output_value * concurrency;
    char internal_key[VAULT_INTENT_IDEMPOTENCY_MAX + 1];
    vif_internal_key(scope, user_key, internal_key);

    if (pthread_mutex_lock(&g_vif_mutex) != 0)
        LOG_FAIL("vault_intent_fanout", "fanout mutex lock failed");
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!vault_intent_context_ready(ctx, result)) {
        (void)pthread_mutex_unlock(&g_vif_mutex);
        return true;
    }
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(ctx->node_db, scope,
            VAULT_INTENT_TRANSPARENT_APPLICATION, internal_key, &existing)) {
        bool same = existing.recipient_value_zat == outputs_total &&
            vault_intent_transparent_shape_matches(
                &existing, (size_t)concurrency, output_value);
        if (same)
            vif_render(result, &existing, (size_t)concurrency,
                       output_value, true);
        else
            vif_error(result, "IDEMPOTENCY_CONFLICT",
                      "that idempotency key already names a different fanout");
        (void)pthread_mutex_unlock(&g_vif_mutex);
        return true;
    }
    if (!vif_preflight(ctx, scope, outputs_total, result)) {
        (void)pthread_mutex_unlock(&g_vif_mutex);
        return true;
    }

    struct json_value plan, effects;
    json_init(&plan); json_set_object(&plan);
    json_init(&effects); json_set_array(&effects);
    (void)json_push_kv_str(&plan, "wallet_scope", scope);
    (void)json_push_kv_str(&plan, "route", "transparent");
    (void)json_push_kv_str(&plan, "idempotency_key", internal_key);
    char addresses[VIF_MAX_OUTPUTS][WALLET_DIRECT_ADDRESS_MAX];
    char why[192];
    bool addresses_ready = wallet_direct_getnewaddresses(
        addresses, (size_t)concurrency, why, sizeof(why));
    for (int64_t i = 0; i < concurrency; i++) {
        char amount[32];
        if (!addresses_ready)
            break;
        (void)snprintf(amount, sizeof(amount), "%lld.%08lld",
            (long long)(output_value / COIN),
            (long long)(output_value % COIN));
        struct json_value effect; json_init(&effect); json_set_object(&effect);
        (void)json_push_kv_str(&effect, "asset", "ZCL");
        (void)json_push_kv_str(&effect, "to", addresses[i]);
        (void)json_push_kv_str(&effect, "amount", amount);
        addresses_ready = json_push_back(&effects, &effect);
        json_free(&effect);
        if (!addresses_ready)
            break;
    }
    if (!addresses_ready) {
        json_free(&effects); json_free(&plan);
        vif_error(result, "DURABLE_ADDRESS_FAILED",
                  why[0] ? why
                         : "could not persist every private fanout destination");
        (void)pthread_mutex_unlock(&g_vif_mutex);
        return true;
    }
    (void)json_push_kv(&plan, "effects", &effects);
    json_free(&effects);
    (void)vif_continue_plan(&plan, result);
    json_free(&plan);

    const char *plan_hex = json_get_bool(json_get(result, "ok"))
        ? json_get_str(json_get(result, "plan_id")) : NULL;
    uint8_t plan_id[32];
    struct vault_intent_row row;
    if (!plan_hex || strlen(plan_hex) != 64 || !IsHex(plan_hex) ||
        ParseHex(plan_hex, plan_id, sizeof(plan_id)) != sizeof(plan_id) ||
        !vault_intent_find(ctx->node_db, plan_id, &row)) {
        if (json_get_bool(json_get(result, "ok")))
            vif_error(result, "PLAN_LOOKUP_FAILED",
                      "fanout plan was not recoverable after creation");
        (void)pthread_mutex_unlock(&g_vif_mutex);
        return true;
    }
    vif_render(result, &row, (size_t)concurrency, output_value, false);
    (void)pthread_mutex_unlock(&g_vif_mutex);
    return true;
}
