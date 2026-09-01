/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable, identity-bound ZSLP transaction intents. */

#include "services/zslp_transaction_intent_service.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/wallet_identity.h"
#include "models/wallet_metadata_crypto.h"
#include "services/zslp_service.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZTI_PLAN_TTL 600LL
#define ZTI_PAYLOAD_MAX 512u
#define ZTI_INPUT_MAX 4096u
#define ZTI_TOKEN_RECIPIENT_DUST_ZAT 546LL

struct zti_payload {
    struct zslp_intent_request request;
    uint8_t txid[32];
    int64_t actual_fee_zat;
};

static bool zti_idempotency_valid(const char *key)
{
    if (!key || !key[0] || strlen(key) > VAULT_INTENT_IDEMPOTENCY_MAX)
        return false;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        if (*p < 0x20 || *p > 0x7e) return false;
    return true;
}

static void zti_intent_digest(const uint8_t *plain, size_t plain_len,
                              const struct vault_intent_row *row,
                              uint8_t out[32])
{
    uint8_t height[4], expiry[8], money[3][8];
    zcl_write_i32_le(height, row->anchor_height);
    zcl_write_i64_le(expiry, row->expires_at);
    zcl_write_i64_le(money[0], row->recipient_value_zat);
    zcl_write_i64_le(money[1], row->max_fee_zat);
    zcl_write_i64_le(money[2], row->reserved_zat);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.zslp.intent.payload.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, plain, plain_len);
    sha3_256_write(&sha, height, sizeof(height));
    sha3_256_write(&sha, row->anchor_hash, 32);
    sha3_256_write(&sha, expiry, sizeof(expiry));
    sha3_256_write(&sha, (const uint8_t *)row->wallet_scope,
                   strlen(row->wallet_scope));
    sha3_256_write(&sha, (const uint8_t *)row->wallet_instance_id,
                   strlen(row->wallet_instance_id));
    sha3_256_write(&sha, (const uint8_t *)row->wallet_genesis,
                   strlen(row->wallet_genesis));
    sha3_256_write(&sha, row->snapshot_root, 32);
    sha3_256_write(&sha, (const uint8_t *)money, sizeof(money));
    sha3_256_write(&sha, row->request_digest, 32);
    sha3_256_finalize(&sha, out);
}

const char *zslp_intent_operation_name(enum zslp_intent_operation operation)
{
    switch (operation) {
    case ZSLP_INTENT_GENESIS: return "genesis";
    case ZSLP_INTENT_MINT: return "mint";
    case ZSLP_INTENT_SEND: return "send";
    case ZSLP_INTENT_BURN: return "burn";
    default: return "unknown";
    }
}

static struct zcl_result zti_runtime_validate(
    const struct zslp_intent_runtime *rt, bool planning, bool committing)
{
    if (!rt || !rt->node_db || !rt->node_db->open || !rt->read_money ||
        rt->tip_height < 0 || !zcl_bytes_any_set(rt->tip_hash, 32) ||
        rt->maximum_fee_zat <= 0 || rt->now_unix <= 0)
        return ZCL_ERR(-1, "ZSLP intent requires current custody and chain runtime");
    if (planning && !rt->prepare)
        return ZCL_ERR(-2, "ZSLP intent planning requires a wallet prepare port");
    if (committing && !rt->publish)
        return ZCL_ERR(-3, "ZSLP intent commit requires a wallet publish port");
    return ZCL_OK;
}

static struct zcl_result zti_request_validate(
    const struct zslp_intent_request *r)
{
    if (!r || (strcmp(r->wallet_scope, "dev") != 0 &&
               strcmp(r->wallet_scope, "prod") != 0) ||
        !zti_idempotency_valid(r->idempotency_key))
        return ZCL_ERR(-4, "scope and idempotency key are required");
    if (r->operation == ZSLP_INTENT_GENESIS) {
        struct zslp_token_create_request create = {
            .ticker = r->ticker, .name = r->name, .decimals = r->decimals,
            .initial_supply = r->supply,
        };
        const char *why = zslp_service_validate_create_request(&create);
        if (why || r->supply == 0)
            return ZCL_ERR(-5, "invalid ZSLP genesis request: %s",
                           why ? why : "supply must be positive");
        return ZCL_OK;
    }
    if (strlen(r->token_id) != 64 ||
        !zslp_service_is_hex_string(r->token_id, 64) || r->units == 0)
        return ZCL_ERR(-6, "token_id must be 64 hex and units must be positive");
    if (r->operation == ZSLP_INTENT_BURN)
        return ZCL_OK;
    if (r->operation != ZSLP_INTENT_MINT &&
        r->operation != ZSLP_INTENT_SEND)
        return ZCL_ERR(-7, "unknown ZSLP intent operation");
    struct zslp_token_transfer_request transfer = {
        .token_id = r->token_id, .recipient_addr = r->recipient,
        .amount = r->units, .strict_chain_addr = true,
    };
    const char *why = zslp_service_validate_transfer_request(&transfer);
    return why ? ZCL_ERR(-8, "invalid ZSLP transfer request: %s", why)
               : ZCL_OK;
}

static struct zcl_result zti_money_current(
    const struct zslp_intent_runtime *rt, const char *scope,
    struct wallet_money_snapshot *money)
{
    struct zcl_result r = rt->read_money(rt->money_ctx, scope, money);
    if (!r.ok) return r;
    if (!money->complete || strcmp(money->status, "CURRENT") != 0)
        return ZCL_ERR(-9, "money state is not current: %s", money->reason);
    if (money->tip_height != rt->tip_height ||
        memcmp(money->tip_hash, rt->tip_hash, 32) != 0)
        return ZCL_ERR(-10, "money snapshot and active tip differ");
    return ZCL_OK;
}

static void zti_request_digest(const struct zslp_intent_request *r,
                               uint8_t out[32])
{
    uint8_t supply_le[8], units_le[8];
    zcl_write_u64_le(supply_le, r->supply);
    zcl_write_u64_le(units_le, r->units);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.zslp.intent.request.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, (const uint8_t *)r->wallet_scope,
                   strlen(r->wallet_scope));
    uint8_t operation = (uint8_t)r->operation;
    sha3_256_write(&sha, &operation, sizeof(operation));
    sha3_256_write(&sha, (const uint8_t *)r->ticker, strlen(r->ticker));
    sha3_256_write(&sha, (const uint8_t *)r->name, strlen(r->name));
    sha3_256_write(&sha, &r->decimals, sizeof(r->decimals));
    sha3_256_write(&sha, supply_le, sizeof(supply_le));
    sha3_256_write(&sha, (const uint8_t *)r->token_id, strlen(r->token_id));
    sha3_256_write(&sha, (const uint8_t *)r->recipient,
                   strlen(r->recipient));
    sha3_256_write(&sha, units_le, sizeof(units_le));
    sha3_256_finalize(&sha, out);
}

static bool zti_write_text(struct byte_stream *s, const char *text,
                           size_t maximum)
{
    size_t len = strlen(text);
    return len <= maximum && len <= UINT8_MAX &&
           stream_write_u8(s, (uint8_t)len) && stream_write(s, text, len);
}

static bool zti_read_text(struct byte_stream *s, char *out, size_t capacity)
{
    uint8_t len = 0;
    if (!stream_read_u8(s, &len) || (size_t)len >= capacity ||
        !stream_read(s, out, len))
        return false;
    out[len] = '\0';
    return true;
}

static bool zti_payload_encode(const struct zti_payload *p, uint8_t *out,
                               size_t capacity, size_t *out_len)
{
    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = stream_write(&s, "ZTI1", 4) &&
        stream_write_u8(&s, (uint8_t)p->request.operation) &&
        zti_write_text(&s, p->request.wallet_scope, 4) &&
        zti_write_text(&s, p->request.ticker, ZSLP_INTENT_TICKER_MAX) &&
        zti_write_text(&s, p->request.name, ZSLP_INTENT_NAME_MAX) &&
        stream_write_u8(&s, p->request.decimals) &&
        stream_write_u64_le(&s, p->request.supply) &&
        zti_write_text(&s, p->request.token_id, 64) &&
        zti_write_text(&s, p->request.recipient, ZSLP_INTENT_ADDRESS_MAX) &&
        stream_write_u64_le(&s, p->request.units) &&
        stream_write(&s, p->txid, 32) &&
        stream_write_i64_le(&s, p->actual_fee_zat);
    if (!ok || s.size > capacity) {
        stream_free(&s);
        return false;
    }
    memcpy(out, s.data, s.size);
    *out_len = s.size;
    stream_free(&s);
    return true;
}

static bool zti_payload_decode(const uint8_t *raw, size_t raw_len,
                               struct zti_payload *p)
{
    memset(p, 0, sizeof(*p));
    struct byte_stream s;
    stream_init_from_data(&s, raw, raw_len);
    uint8_t magic[4], operation = 0;
    bool ok = stream_read(&s, magic, 4) && memcmp(magic, "ZTI1", 4) == 0 &&
        stream_read_u8(&s, &operation) && operation >= ZSLP_INTENT_GENESIS &&
        operation <= ZSLP_INTENT_BURN;
    p->request.operation = (enum zslp_intent_operation)operation;
    ok = ok && zti_read_text(&s, p->request.wallet_scope,
                             sizeof(p->request.wallet_scope)) &&
        zti_read_text(&s, p->request.ticker, sizeof(p->request.ticker)) &&
        zti_read_text(&s, p->request.name, sizeof(p->request.name)) &&
        stream_read_u8(&s, &p->request.decimals) &&
        stream_read_u64_le(&s, &p->request.supply) &&
        zti_read_text(&s, p->request.token_id,
                      sizeof(p->request.token_id)) &&
        zti_read_text(&s, p->request.recipient,
                      sizeof(p->request.recipient)) &&
        stream_read_u64_le(&s, &p->request.units) &&
        stream_read(&s, p->txid, 32) &&
        stream_read_i64_le(&s, &p->actual_fee_zat) &&
        stream_remaining(&s) == 0;
    stream_free(&s);
    return ok;
}

static struct zcl_result zti_payload_open(
    const struct zslp_intent_runtime *rt, const struct vault_intent_row *row,
    struct zti_payload *payload)
{
    uint8_t plain[ZTI_PAYLOAD_MAX];
    size_t plain_len = 0;
    if (!wallet_metadata_decrypt(rt->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len, plain,
            sizeof(plain), &plain_len))
        return ZCL_ERR(-11, "ZSLP intent authentication failed");
    uint8_t digest[32];
    zti_intent_digest(plain, plain_len, row, digest);
    bool ok = memcmp(digest, row->digest, 32) == 0 &&
              zti_payload_decode(plain, plain_len, payload);
    memory_cleanse(plain, sizeof(plain));
    return ok ? ZCL_OK : ZCL_ERR(-12, "ZSLP intent digest or payload is invalid");
}

static void zti_view(const struct vault_intent_row *row,
                     const struct zti_payload *payload,
                     struct zslp_intent_result *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->plan_id, row->plan_id, 32);
    snprintf(out->wallet_scope, sizeof(out->wallet_scope), "%s",
             row->wallet_scope);
    snprintf(out->wallet_instance_id, sizeof(out->wallet_instance_id), "%s",
             row->wallet_instance_id);
    snprintf(out->network_genesis, sizeof(out->network_genesis), "%s",
             row->wallet_genesis);
    out->operation = payload->request.operation;
    if (payload->request.operation == ZSLP_INTENT_GENESIS) {
        struct uint256 token_id;
        memcpy(token_id.data, payload->txid, 32);
        uint256_get_hex(&token_id, out->token_id);
    } else {
        snprintf(out->token_id, sizeof(out->token_id), "%s",
                 payload->request.token_id);
    }
    out->units = payload->request.operation == ZSLP_INTENT_GENESIS
        ? payload->request.supply : payload->request.units;
    out->has_txid = zcl_bytes_any_set(payload->txid, 32);
    memcpy(out->txid, payload->txid, 32);
    out->broadcast = row->state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
                     row->state <= VAULT_INTENT_REORGED;
    out->actual_fee_zat = payload->actual_fee_zat;
    out->maximum_fee_zat = row->max_fee_zat;
    out->reserved_zat = row->reserved_zat;
    out->expires_at = row->expires_at;
    snprintf(out->state, sizeof(out->state), "%s",
             vault_intent_state_name(row->state));
    memcpy(out->snapshot_root, row->snapshot_root, 32);
    memcpy(out->plan_digest, row->digest, 32);
}

struct zcl_result zslp_transaction_intent_plan(
    const struct zslp_intent_runtime *rt,
    const struct zslp_intent_request *request,
    struct zslp_intent_result *out)
{
    ZCL_CHECK(zti_runtime_validate(rt, true, false));
    ZCL_CHECK(zti_request_validate(request));
    if (!out) return ZCL_ERR(-13, "ZSLP intent output is required");
    uint8_t request_digest[32];
    zti_request_digest(request, request_digest);
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            rt->node_db, request->wallet_scope, ZSLP_INTENT_APPLICATION,
            request->idempotency_key, &existing)) {
        if (!existing.has_request_digest ||
            memcmp(existing.request_digest, request_digest, 32) != 0)
            return ZCL_ERR(-14, "idempotency key names a different ZSLP request");
        struct zti_payload payload;
        ZCL_CHECK(zti_payload_open(rt, &existing, &payload));
        zti_view(&existing, &payload, out);
        out->idempotent_replay = true;
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_OK;
    }
    struct wallet_money_snapshot money;
    ZCL_CHECK(zti_money_current(rt, request->wallet_scope, &money));
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX, "zslp_intent_raw");
    struct vault_intent_input *inputs = zcl_malloc(
        ZTI_INPUT_MAX * sizeof(*inputs), "zslp_intent_inputs");
    if (!raw || !inputs) {
        free(raw); free(inputs);
        return ZCL_ERR(-15, "ZSLP intent preparation allocation failed");
    }
    struct zti_payload payload; memset(&payload, 0, sizeof(payload));
    payload.request = *request;
    size_t raw_len = 0, input_count = 0;
    struct zcl_result prepared = rt->prepare(
        rt->prepare_ctx, request, rt->maximum_fee_zat, raw,
        VAULT_INTENT_RAW_MAX, &raw_len, payload.txid,
        &payload.actual_fee_zat, inputs, ZTI_INPUT_MAX, &input_count);
    if (!prepared.ok || raw_len == 0 || input_count == 0 ||
        payload.actual_fee_zat < 0 ||
        payload.actual_fee_zat > rt->maximum_fee_zat ||
        !zcl_bytes_any_set(payload.txid, 32)) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX);
        memory_cleanse(&payload, sizeof(payload));
        free(raw); free(inputs);
        return prepared.ok ? ZCL_ERR(-16, "prepared ZSLP transaction violates its fee/input contract")
                           : prepared;
    }
    int64_t recipient = (request->operation == ZSLP_INTENT_SEND ||
                         request->operation == ZSLP_INTENT_MINT)
        ? ZTI_TOKEN_RECIPIENT_DUST_ZAT : 0;
    if (recipient > INT64_MAX - rt->maximum_fee_zat) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw); free(inputs);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-17, "ZSLP reservation overflow");
    }
    int64_t reserved = recipient + rt->maximum_fee_zat;
    int64_t liquid = money.confirmed_zat - money.intent_reserved_zat;
    if (reserved > liquid || (strcmp(request->wallet_scope, "dev") == 0 &&
                              reserved > money.agent_available_zat)) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw); free(inputs);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-18, "custody allocation cannot reserve ZSLP value plus fee");
    }
    struct vault_intent_row row; memset(&row, 0, sizeof(row));
    if (RAND_bytes(row.plan_id, 32) != 1) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw); free(inputs);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-19, "could not mint ZSLP plan identity");
    }
    row.state = VAULT_INTENT_PLANNED;
    row.route = VAULT_INTENT_ROUTE_TRANSPARENT;
    row.created_at = rt->now_unix;
    row.expires_at = rt->now_unix + ZTI_PLAN_TTL;
    row.updated_at = rt->now_unix;
    row.anchor_height = rt->tip_height;
    memcpy(row.anchor_hash, rt->tip_hash, 32);
    snprintf(row.wallet_scope, sizeof(row.wallet_scope), "%s",
             request->wallet_scope);
    snprintf(row.wallet_instance_id, sizeof(row.wallet_instance_id), "%s",
             money.identity.wallet_instance_id);
    wallet_identity_genesis_hex(&money.identity, row.wallet_genesis);
    memcpy(row.snapshot_root, money.snapshot_root, 32);
    row.has_snapshot_root = true;
    row.recipient_value_zat = recipient;
    row.max_fee_zat = rt->maximum_fee_zat;
    row.reserved_zat = reserved;
    snprintf(row.application_kind, sizeof(row.application_kind), "%s",
             ZSLP_INTENT_APPLICATION);
    snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s",
             request->idempotency_key);
    memcpy(row.request_digest, request_digest, 32);
    row.has_request_digest = true;
    uint8_t plain[ZTI_PAYLOAD_MAX]; size_t plain_len = 0;
    bool encoded = zti_payload_encode(&payload, plain, sizeof(plain), &plain_len);
    bool encrypted = encoded && wallet_metadata_encrypt(
        rt->node_db, row.plan_id, 32, plain, plain_len,
        row.encrypted_payload, sizeof(row.encrypted_payload),
        &row.encrypted_payload_len);
    if (encrypted)
        zti_intent_digest(plain, plain_len, &row, row.digest);
    bool stored = encrypted && vault_intent_reserve_with_raw_inputs(
        rt->node_db, &row, money.confirmed_zat, raw, raw_len, inputs,
        input_count);
    if (stored) {
        struct wallet_money_snapshot refreshed;
        struct zcl_result current = zti_money_current(
            rt, request->wallet_scope, &refreshed);
        stored = current.ok;
        if (stored) {
            memcpy(row.snapshot_root, refreshed.snapshot_root, 32);
            zti_intent_digest(plain, plain_len, &row, row.digest);
            stored = vault_intent_save(rt->node_db, &row);
        }
        if (!stored)
            (void)vault_intent_set_state(rt->node_db, row.plan_id,
                VAULT_INTENT_FAILED, NULL, "SNAPSHOT_BIND_FAILED",
                rt->now_unix);
    }
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(raw, VAULT_INTENT_RAW_MAX);
    memory_cleanse(&payload, sizeof(payload));
    free(raw); free(inputs);
    if (!stored)
        return ZCL_ERR(-20, "ZSLP reservation or exact-input claim conflicted");
    ZCL_CHECK(zti_payload_open(rt, &row, &payload));
    zti_view(&row, &payload, out);
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}

struct zcl_result zslp_transaction_intent_commit(
    const struct zslp_intent_runtime *rt, const char *wallet_scope,
    const uint8_t plan_id[32], struct zslp_intent_result *out)
{
    ZCL_CHECK(zti_runtime_validate(rt, false, true));
    if (!wallet_scope || !plan_id || !out ||
        (strcmp(wallet_scope, "dev") != 0 && strcmp(wallet_scope, "prod") != 0))
        return ZCL_ERR(-21, "explicit scope, plan ID, and output are required");
    (void)vault_intent_expire_due(rt->node_db, rt->now_unix);
    struct vault_intent_row row;
    if (!vault_intent_find(rt->node_db, plan_id, &row) ||
        strcmp(row.application_kind, ZSLP_INTENT_APPLICATION) != 0)
        return ZCL_ERR(-22, "ZSLP intent was not found");
    if (strcmp(row.wallet_scope, wallet_scope) != 0)
        return ZCL_ERR(-23, "wallet scope does not match ZSLP intent");
    struct zti_payload payload;
    ZCL_CHECK(zti_payload_open(rt, &row, &payload));
    if (row.has_txid && row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
        row.state <= VAULT_INTENT_REORGED) {
        zti_view(&row, &payload, out);
        out->idempotent_replay = true;
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_OK;
    }
    if ((row.state != VAULT_INTENT_PLANNED &&
         row.state != VAULT_INTENT_PROVING) || row.expires_at <= rt->now_unix) {
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-24, "ZSLP intent is not committable");
    }
    struct wallet_money_snapshot money;
    struct zcl_result current = zti_money_current(rt, wallet_scope, &money);
    char genesis[65] = {0};
    if (current.ok) wallet_identity_genesis_hex(&money.identity, genesis);
    bool bound = current.ok &&
        strcmp(row.wallet_instance_id, money.identity.wallet_instance_id) == 0 &&
        strcmp(row.wallet_genesis, genesis) == 0 &&
        row.anchor_height == rt->tip_height &&
        memcmp(row.anchor_hash, rt->tip_hash, 32) == 0 &&
        memcmp(row.snapshot_root, money.snapshot_root, 32) == 0;
    if (!bound) {
        (void)vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_CONFLICTED, NULL, "MONEY_SNAPSHOT_CHANGED",
            rt->now_unix);
        memory_cleanse(&payload, sizeof(payload));
        return current.ok ? ZCL_ERR(-25, "wallet identity, tip, or money snapshot changed")
                          : current;
    }
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX, "zslp_intent_commit_raw");
    size_t raw_len = 0;
    if (!raw || !vault_intent_load_raw(rt->node_db, row.plan_id, raw,
                                       VAULT_INTENT_RAW_MAX, &raw_len)) {
        free(raw);
        memory_cleanse(&payload, sizeof(payload));
        (void)vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_CONFLICTED, NULL, "PREPARED_TX_MISSING",
            rt->now_unix);
        return ZCL_ERR(-26, "prepared ZSLP transaction is missing");
    }
    if (row.state == VAULT_INTENT_PLANNED &&
        !vault_intent_claim_commit(rt->node_db, row.plan_id, rt->now_unix)) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-27, "another commit claimed this ZSLP intent");
    }
    struct zcl_result published = rt->publish(
        rt->publish_ctx, raw, raw_len, payload.txid);
    memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw);
    if (!published.ok) {
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-28, "COMMIT_UNCERTAIN: exact ZSLP publication failed: %s",
                       published.message);
    }
    if (!vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_MEMPOOL_ACCEPTED, payload.txid, "", rt->now_unix) ||
        !vault_intent_find(rt->node_db, row.plan_id, &row)) {
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-29, "ZSLP transaction published but durable state is uncertain");
    }
    zti_view(&row, &payload, out);
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}
