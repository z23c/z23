/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared canonical parsing and binding for durable vault intents. */

#include "controllers/vault_intent_controller.h"

#include "base/serialize_le.h"
#include "chain/chain.h"
#include "controllers/wallet_helpers.h"
#include "core/amount.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/vault_intent.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

struct vic_error_contract {
    const char *code;
    const char *current_state;
    bool retryable;
    bool human_action_required;
    const char *next_action;
};

static const char k_repeat_plan[] =
    "repeat commit with the same plan_id";
static const char k_repeat_idempotency[] =
    "repeat the same call with the same idempotency_key";
static const char k_wait_status[] =
    "run z23 status; after the blocker clears, repeat the same call with the same identity";
static const char k_wallet_repair[] =
    "run z23 status and complete its wallet next_action before repeating the same call";
static const char k_replan[] =
    "inspect intent status, then create a fresh plan with a new idempotency_key";
static const char k_recover[] =
    "do not resend; recover by plan_id and transaction status before any new payment";
static const char k_status_first[] =
    "inspect intent status by plan_id before deciding whether a fresh plan is safe";
static const char k_stop[] =
    "stop and inspect intent status; do not commit or resend this payment";

#define VIC_ERROR(code_, state_, retry_, human_, action_) \
    { (code_), (state_), (retry_), (human_), (action_) }
static const struct vic_error_contract k_vic_error_contracts[] = {
    VIC_ERROR("COMMIT_BUSY", "PLAN_UNCHANGED", true, false, k_repeat_plan),
    VIC_ERROR("PLAN_PERSIST_FAILED", "NOT_CREATED", true, false,
              k_repeat_idempotency),
    VIC_ERROR("DURABLE_ADDRESS_FAILED", "NOT_CREATED", true, false,
              k_repeat_idempotency),
    VIC_ERROR("PLAN_LOOKUP_FAILED", "STATUS_REQUIRED", true, false,
              "repeat the same fanout call with the same idempotency_key; do not use a new key"),
    VIC_ERROR("QUEUE_PERSIST_FAILED", "PLAN_UNCHANGED", true, false,
              "repeat submit with the same plan_id"),
    VIC_ERROR("ASYNC_CAPACITY", "PLAN_UNCHANGED", true, false,
              "repeat submit with the same plan_id"),
    VIC_ERROR("MONEY_STATE_NOT_CURRENT", "BLOCKED", true, false,
              k_wait_status),
    VIC_ERROR("OUT_OF_MEMORY", "BLOCKED", true, false, k_wait_status),
    VIC_ERROR("WALLET_UNAVAILABLE", "BLOCKED", true, false, k_wait_status),
    VIC_ERROR("DATABASE_UNAVAILABLE", "BLOCKED", true, false,
              k_wait_status),
    VIC_ERROR("WALLET_LOCKED", "BLOCKED", true, true,
              "unlock the wallet through stdin, then repeat the same call with the same identity"),
    VIC_ERROR("WITNESS_RESCAN_REQUIRED", "REPLAN_REQUIRED", false, true,
              "run z23 core wallet rescan-witnesses, inspect intent status, then create a fresh plan with a new idempotency_key"),
    VIC_ERROR("WALLET_NOT_ENCRYPTED", "BLOCKED", true, true,
              k_wallet_repair),
    VIC_ERROR("WALLET_PERSISTENCE_UNHEALTHY", "BLOCKED", true, true,
              k_wallet_repair),
    VIC_ERROR("ENCRYPTED_BACKUP_REQUIRED", "BLOCKED", true, true,
              k_wallet_repair),
    VIC_ERROR("SOVEREIGNTY_GATE", "BLOCKED", true, true, k_wallet_repair),
    VIC_ERROR("SHIELDED_HISTORY_INCOMPLETE", "REPLAN_REQUIRED", false, true,
              "repair shielded history, inspect intent status, then create a fresh plan with a new idempotency_key"),
    VIC_ERROR("SHIELDED_AUTHORITY_UNAVAILABLE", "REPLAN_REQUIRED", false,
              true,
              "repair shielded history, inspect intent status, then create a fresh plan with a new idempotency_key"),
    VIC_ERROR("PLAN_EXPIRED", "EXPIRED", false, true,
              "create and review a fresh plan with a new idempotency_key"),
    VIC_ERROR("MONEY_SNAPSHOT_CHANGED", "CONFLICTED", false, true,
              k_replan),
    VIC_ERROR("WALLET_IDENTITY_CHANGED", "CONFLICTED", false, true,
              k_replan),
    VIC_ERROR("INPUT_CONFLICT", "CONFLICTED", false, true, k_replan),
    VIC_ERROR("PREPARED_NOTE_CONFLICT", "CONFLICTED", false, true,
              k_replan),
    VIC_ERROR("PERSISTENCE_FAILED", "RECOVERY_REQUIRED", false, true,
              k_recover),
    VIC_ERROR("PRE_RELAY_DURABILITY_FAILED", "RECOVERY_REQUIRED", false,
              true, k_recover),
    VIC_ERROR("INTENT_STATE_FAILED", "RECOVERY_REQUIRED", true, true,
              "repeat commit with the same plan_id; never create a replacement payment"),
    VIC_ERROR("NOTE_RESERVATION_FAILED", "RECOVERY_REQUIRED", true, true,
              "repeat commit with the same plan_id; never create a replacement payment"),
    VIC_ERROR("SHIELDED_REQUIREMENTS_MISSING", "STATUS_REQUIRED", false,
              true, k_status_first),
    VIC_ERROR("TRANSPARENT_SCRIPT_INVALID", "STATUS_REQUIRED", false, true,
              k_status_first),
    VIC_ERROR("INPUT_VALUE_INVALID", "STATUS_REQUIRED", false, true,
              k_status_first),
    VIC_ERROR("VALUE_BALANCE_INVALID", "STATUS_REQUIRED", false, true,
              k_status_first),
    VIC_ERROR("PLAN_TAMPERED", "FAILED", false, true, k_stop),
    VIC_ERROR("PLAN_DECRYPT_FAILED", "FAILED", false, true, k_stop),
    VIC_ERROR("RAW_TX_CORRUPT", "FAILED", false, true, k_stop),
    VIC_ERROR("TXID_MISMATCH", "FAILED", false, true, k_stop),
    VIC_ERROR("PREPARED_NOTE_MISMATCH", "FAILED", false, true, k_stop),
    VIC_ERROR("EXACT_BUILD_FAILED", "FAILED", false, true, k_stop),
    VIC_ERROR("RECIPIENT_REVALIDATION_FAILED", "FAILED", false, true,
              k_stop),
    VIC_ERROR("PLAN_NOT_FOUND", "NOT_FOUND", false, true,
              "verify wallet_scope and plan_id; do not create a replacement payment until identity is resolved"),
    VIC_ERROR("PLAN_NOT_COMMITTABLE", "PLAN_UNCHANGED", false, true,
              "inspect intent status by plan_id and follow its next_action"),
    VIC_ERROR("PLAN_NOT_SUBMITTABLE", "PLAN_UNCHANGED", false, true,
              "inspect intent status by plan_id and follow its next_action"),
    VIC_ERROR("CANCEL_UNSAFE", "PLAN_UNCHANGED", false, true,
              "inspect intent status by plan_id and follow its next_action"),
    VIC_ERROR("INTENT_NOT_REPUBLISHABLE", "PLAN_UNCHANGED", false, true,
              "inspect intent status by plan_id and follow its next_action"),
    VIC_ERROR("CONFIRM_REQUIRED", "REQUEST_REFUSED", false, true,
              "review the exact plan, then commit with wallet_scope, plan_id, and confirm:true"),
    VIC_ERROR("IDEMPOTENCY_CONFLICT", "REQUEST_REFUSED", false, true,
              "use the original request for that idempotency_key or choose a new key for a different payment"),
};
#undef VIC_ERROR

static const struct vic_error_contract k_vic_default_error = {
    .code = NULL,
    .current_state = "REQUEST_REFUSED",
    .retryable = false,
    .human_action_required = true,
    .next_action = "correct the request and repeat the same call",
};

static const struct vic_error_contract k_vic_mempool_error = {
    .code = NULL,
    .current_state = "STATUS_REQUIRED",
    .retryable = false,
    .human_action_required = true,
    .next_action = k_status_first,
};

void vault_intent_error_response(struct json_value *out, const char *code,
                                 const char *message)
{
    const char *safe_code = code && code[0] ? code : "INTERNAL_ERROR";
    const char *safe_message = message
        ? message : "vault intent request failed";
    const struct vic_error_contract *contract = &k_vic_default_error;
    for (size_t i = 0;
         i < sizeof(k_vic_error_contracts) / sizeof(k_vic_error_contracts[0]);
         i++) {
        if (strcmp(safe_code, k_vic_error_contracts[i].code) == 0) {
            contract = &k_vic_error_contracts[i];
            break;
        }
    }
    if (contract == &k_vic_default_error &&
        strncmp(safe_code, "MEMPOOL_", 8) == 0)
        contract = &k_vic_mempool_error;

    json_set_object(out);
    (void)json_push_kv_bool(out, "ok", false);
    (void)json_push_kv_str(out, "code", safe_code);
    (void)json_push_kv_str(out, "error_code", safe_code);
    (void)json_push_kv_str(out, "message", safe_message);
    (void)json_push_kv_str(out, "current_state", contract->current_state);
    (void)json_push_kv_bool(out, "retryable", contract->retryable);
    (void)json_push_kv_bool(out, "human_action_required",
                            contract->human_action_required);
    (void)json_push_kv_str(out, "next_action", contract->next_action);
}

static void vic_hex(const uint8_t in[32], char out[65])
{
    HexStr(in, 32, false, out, 65);
}

static void vic_chain_hash_hex(const uint8_t in[32], char out[65])
{
    struct uint256 hash;
    memcpy(hash.data, in, sizeof(hash.data));
    uint256_get_hex(&hash, out);
}

static void vic_amount_text(int64_t amount, char out[32])
{
    (void)snprintf(out, 32, "%lld.%08lld",
                   (long long)(amount / COIN),
                   (long long)(amount % COIN));
}

bool vault_intent_chain_confirmation(struct main_state *ms,
                                     const uint8_t block_hash[32],
                                     int32_t *height_out,
                                     int32_t *confirmations_out)
{
    if (!ms || !block_hash || !height_out || !confirmations_out)
        LOG_FAIL("vault_intent", "chain confirmation: NULL argument");

    struct uint256 hash;
    memcpy(hash.data, block_hash, sizeof(hash.data));
    bool found = false;
    int32_t height = -1;
    int32_t confirmations = 0;

    /* Wallet confirmation counters can lag tip advancement. Resolve the
     * recorded block hash against the canonical active chain instead. */
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
    int tip = active_chain_height(&ms->chain_active);
    if (bi && bi->nHeight >= 0 && bi->nHeight <= tip &&
        active_chain_at(&ms->chain_active, bi->nHeight) == bi) {
        height = bi->nHeight;
        confirmations = tip - bi->nHeight + 1;
        found = confirmations > 0;
    }
    zcl_mutex_unlock(&ms->cs_main);

    if (!found)
        return false;
    *height_out = height;
    *confirmations_out = confirmations;
    return true;
}

/* Amounts are text only. This is deliberately not the permissive legacy RPC
 * amount parser: floats can never cross this boundary. */
bool vault_intent_parse_zcl_amount(const char *s, int64_t *out)
{
    if (!s || !out || !s[0] || s[0] == '-' || s[0] == '+')
        return false; // raw-return-ok:predicate
    int64_t whole = 0, frac = 0;
    unsigned decimals = 0;
    bool dot = false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '.' && !dot) { dot = true; continue; }
        if (*p < '0' || *p > '9') return false; // raw-return-ok:predicate
        int digit = *p - '0';
        if (!dot) {
            if (whole > (INT64_MAX - digit) / 10)
                return false; // raw-return-ok:predicate
            whole = whole * 10 + digit;
        } else {
            if (++decimals > 8) return false; // raw-return-ok:predicate
            frac = frac * 10 + digit;
        }
    }
    if (dot && decimals == 0) return false; // raw-return-ok:predicate
    while (decimals++ < 8) frac *= 10;
    if (whole > (INT64_MAX - frac) / COIN)
        return false; // raw-return-ok:predicate
    int64_t amount = whole * COIN + frac;
    if (amount <= 0 || !MoneyRange(amount))
        return false; // raw-return-ok:predicate
    *out = amount;
    return true;
}

bool vault_intent_idempotency_key_valid(const char *key)
{
    if (!key || !key[0] || strlen(key) > VAULT_INTENT_IDEMPOTENCY_MAX)
        return false;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        if (*p < 0x20 || *p > 0x7e)
            return false;
    return true;
}

void vault_intent_digest_payload(const uint8_t *raw, size_t len,
                                 const struct vault_intent_row *row,
                                 uint8_t out[32])
{
    uint8_t height_le[4], expiry_le[8];
    zcl_write_i32_le(height_le, row->anchor_height);
    zcl_write_i64_le(expiry_le, row->expires_at);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)"vault-intent-v1", 15);
    sha3_256_write(&c, raw, len);
    sha3_256_write(&c, height_le, sizeof(height_le));
    sha3_256_write(&c, row->anchor_hash, 32);
    sha3_256_write(&c, expiry_le, sizeof(expiry_le));
    sha3_256_write(&c, (const uint8_t *)row->wallet_scope,
                   strlen(row->wallet_scope));
    sha3_256_write(&c, (const uint8_t *)row->wallet_instance_id,
                   strlen(row->wallet_instance_id));
    sha3_256_write(&c, (const uint8_t *)row->wallet_genesis,
                   strlen(row->wallet_genesis));
    sha3_256_write(&c, row->snapshot_root, 32);
    uint8_t money[2][8];
    zcl_write_i64_le(money[0], row->recipient_value_zat);
    zcl_write_i64_le(money[1], row->max_fee_zat);
    sha3_256_write(&c, (const uint8_t *)money, sizeof(money));
    sha3_256_finalize(&c, out);
}

void vault_intent_render_row(struct wallet_rpc_context *ctx,
                             struct json_value *out,
                             const struct vault_intent_row *row)
{
    char id[65]; vic_hex(row->plan_id, id);
    (void)json_push_kv_str(out, "plan_id", id);
    (void)json_push_kv_str(out, "state",
                           vault_intent_state_name(row->state));
    (void)json_push_kv_int(out, "created_at", row->created_at);
    (void)json_push_kv_int(out, "expires_at", row->expires_at);
    if (row->wallet_scope[0]) {
        char root[65], recipient[32], fee[32], reserved[32];
        vic_hex(row->snapshot_root, root);
        vic_amount_text(row->recipient_value_zat, recipient);
        vic_amount_text(row->max_fee_zat, fee);
        vic_amount_text(row->reserved_zat, reserved);
        (void)json_push_kv_str(out, "wallet_scope", row->wallet_scope);
        (void)json_push_kv_str(out, "wallet_instance_id",
                               row->wallet_instance_id);
        (void)json_push_kv_str(out, "network_genesis", row->wallet_genesis);
        (void)json_push_kv_str(out, "money_snapshot_root", root);
        (void)json_push_kv_str(out, "recipient_value", recipient);
        (void)json_push_kv_str(out, "maximum_fee", fee);
        (void)json_push_kv_str(out, "reserved", reserved);
    }
    if (row->has_txid) {
        char txid[65]; vic_chain_hash_hex(row->txid, txid);
        (void)json_push_kv_str(out, "txid", txid);
    } else {
        struct json_value none; json_init(&none); json_set_null(&none);
        (void)json_push_kv(out, "txid", &none); json_free(&none);
    }
    const bool confirmation_known =
        (row->state == VAULT_INTENT_CONFIRMED ||
         row->state == VAULT_INTENT_FINALIZED ||
         row->state == VAULT_INTENT_REORGED) &&
        row->confirm_height >= 0;
    int64_t confirmations = 0;
    if (ctx && ctx->main_state && confirmation_known &&
        row->state != VAULT_INTENT_REORGED) {
        int tip = active_chain_height(&ctx->main_state->chain_active);
        if (tip >= row->confirm_height)
            confirmations = (int64_t)tip - row->confirm_height + 1;
    }
    (void)json_push_kv_int(out, "confirmations", confirmations);
    if (confirmation_known) {
        (void)json_push_kv_int(out, "confirmed_height", row->confirm_height);
        if (row->has_confirm_hash) {
            char block_hash[65];
            vic_chain_hash_hex(row->confirm_hash, block_hash);
            (void)json_push_kv_str(out, "confirmed_block_hash", block_hash);
        }
    }
    if (row->error_code[0])
        (void)json_push_kv_str(out, "error_code", row->error_code);
}
