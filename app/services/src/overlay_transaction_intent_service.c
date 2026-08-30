/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Reusable custody lifecycle for exact signed overlay transactions. */

#include "services/overlay_transaction_intent_service.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/wallet_identity.h"
#include "models/wallet_metadata_crypto.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OTI_PLAN_TTL 600LL
#define OTI_PAYLOAD_MAX 1024u
#define OTI_INPUT_MAX 4096u

struct oti_payload {
    char operation[OVERLAY_INTENT_OPERATION_MAX + 1];
    uint8_t semantics[OVERLAY_INTENT_SEMANTICS_MAX];
    size_t semantics_len;
    uint8_t txid[32];
    int64_t actual_fee_zat;
};

static bool oti_idempotency_valid(const char *key)
{
    if (!key || !key[0] || strlen(key) > VAULT_INTENT_IDEMPOTENCY_MAX)
        return false;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        if (*p < 0x20 || *p > 0x7e) return false;
    return true;
}

static bool oti_token_valid(const char *text, size_t maximum)
{
    if (!text || !text[0] || strlen(text) > maximum) return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        bool ok = (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
                  *p == '_' || *p == '-' || *p == '.';
        if (!ok) return false;
    }
    return true;
}

static struct zcl_result oti_runtime_validate(
    const struct overlay_intent_runtime *rt, bool planning, bool committing)
{
    if (!rt || !rt->node_db || !rt->node_db->open || !rt->read_money ||
        rt->tip_height < 0 || !zcl_bytes_any_set(rt->tip_hash, 32) ||
        rt->maximum_fee_zat <= 0 || rt->now_unix <= 0)
        return ZCL_ERR(-1, "overlay intent requires current custody and chain runtime");
    if (planning && !rt->prepare)
        return ZCL_ERR(-2, "overlay planning requires a wallet prepare port");
    if (committing && !rt->publish)
        return ZCL_ERR(-3, "overlay commit requires a wallet publish port");
    return ZCL_OK;
}

static struct zcl_result oti_request_validate(
    const struct overlay_intent_request *request)
{
    if (!request || (strcmp(request->wallet_scope, "dev") != 0 &&
                     strcmp(request->wallet_scope, "prod") != 0))
        return ZCL_ERR(-4, "overlay intent requires scope=dev|prod");
    if (!oti_token_valid(request->application_kind,
                         VAULT_INTENT_APPLICATION_MAX) ||
        !oti_token_valid(request->operation, OVERLAY_INTENT_OPERATION_MAX))
        return ZCL_ERR(-5, "overlay application and operation are invalid");
    if (request->semantics_len == 0 ||
        request->semantics_len > OVERLAY_INTENT_SEMANTICS_MAX)
        return ZCL_ERR(-6, "overlay private semantics are missing or too large");
    if (!oti_idempotency_valid(request->idempotency_key))
        return ZCL_ERR(-7, "overlay idempotency key is invalid");
    return ZCL_OK;
}

static struct zcl_result oti_money_current(
    const struct overlay_intent_runtime *rt, const char *scope,
    struct wallet_money_snapshot *money)
{
    struct zcl_result result = rt->read_money(rt->money_ctx, scope, money);
    if (!result.ok) return result;
    if (!money->complete || strcmp(money->status, "CURRENT") != 0)
        return ZCL_ERR(-8, "money state is not current: %s", money->reason);
    if (money->tip_height != rt->tip_height ||
        memcmp(money->tip_hash, rt->tip_hash, 32) != 0)
        return ZCL_ERR(-9, "money snapshot and active tip differ");
    return ZCL_OK;
}

static void oti_hash_text(struct sha3_256_ctx *sha, const char *text)
{
    uint8_t len[2];
    size_t n = strlen(text);
    zcl_write_u16_le(len, (uint16_t)n);
    sha3_256_write(sha, len, sizeof(len));
    sha3_256_write(sha, (const uint8_t *)text, n);
}

static void oti_request_digest(const struct overlay_intent_request *request,
                               uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.overlay.intent.request.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    oti_hash_text(&sha, request->wallet_scope);
    oti_hash_text(&sha, request->application_kind);
    oti_hash_text(&sha, request->operation);
    uint8_t len[2];
    zcl_write_u16_le(len, (uint16_t)request->semantics_len);
    sha3_256_write(&sha, len, sizeof(len));
    sha3_256_write(&sha, request->semantics, request->semantics_len);
    sha3_256_finalize(&sha, out);
}

static void oti_intent_digest(const uint8_t *plain, size_t plain_len,
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
    static const uint8_t domain[] = "zcl.overlay.intent.payload.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, plain, plain_len);
    sha3_256_write(&sha, height, sizeof(height));
    sha3_256_write(&sha, row->anchor_hash, 32);
    sha3_256_write(&sha, expiry, sizeof(expiry));
    oti_hash_text(&sha, row->wallet_scope);
    oti_hash_text(&sha, row->wallet_instance_id);
    oti_hash_text(&sha, row->wallet_genesis);
    oti_hash_text(&sha, row->application_kind);
    sha3_256_write(&sha, row->snapshot_root, 32);
    sha3_256_write(&sha, (const uint8_t *)money, sizeof(money));
    sha3_256_write(&sha, row->request_digest, 32);
    sha3_256_finalize(&sha, out);
}

static bool oti_payload_encode(const struct oti_payload *payload,
                               uint8_t *out, size_t capacity,
                               size_t *out_len)
{
    struct byte_stream stream;
    stream_init(&stream, 768);
    size_t operation_len = strlen(payload->operation);
    bool ok = operation_len <= UINT8_MAX &&
        payload->semantics_len <= UINT16_MAX &&
        stream_write(&stream, "OTI1", 4) &&
        stream_write_u8(&stream, (uint8_t)operation_len) &&
        stream_write(&stream, payload->operation, operation_len) &&
        stream_write_u16_le(&stream, (uint16_t)payload->semantics_len) &&
        stream_write(&stream, payload->semantics, payload->semantics_len) &&
        stream_write(&stream, payload->txid, 32) &&
        stream_write_i64_le(&stream, payload->actual_fee_zat);
    if (!ok || stream.size > capacity) {
        stream_free(&stream);
        return false;
    }
    memcpy(out, stream.data, stream.size);
    *out_len = stream.size;
    stream_free(&stream);
    return true;
}

static bool oti_payload_decode(const uint8_t *raw, size_t raw_len,
                               struct oti_payload *payload)
{
    memset(payload, 0, sizeof(*payload));
    struct byte_stream stream;
    stream_init_from_data(&stream, raw, raw_len);
    uint8_t magic[4], operation_len = 0;
    uint16_t semantics_len = 0;
    bool ok = stream_read(&stream, magic, 4) &&
        memcmp(magic, "OTI1", 4) == 0 &&
        stream_read_u8(&stream, &operation_len) && operation_len > 0 &&
        operation_len < sizeof(payload->operation) &&
        stream_read(&stream, payload->operation, operation_len);
    payload->operation[operation_len] = '\0';
    ok = ok && stream_read_u16_le(&stream, &semantics_len) &&
        semantics_len > 0 && semantics_len <= sizeof(payload->semantics) &&
        stream_read(&stream, payload->semantics, semantics_len) &&
        stream_read(&stream, payload->txid, 32) &&
        stream_read_i64_le(&stream, &payload->actual_fee_zat) &&
        stream_remaining(&stream) == 0;
    payload->semantics_len = semantics_len;
    stream_free(&stream);
    return ok && oti_token_valid(payload->operation,
                                 OVERLAY_INTENT_OPERATION_MAX);
}

static struct zcl_result oti_payload_open(
    const struct overlay_intent_runtime *rt,
    const struct vault_intent_row *row, struct oti_payload *payload)
{
    uint8_t plain[OTI_PAYLOAD_MAX];
    size_t plain_len = 0;
    if (!wallet_metadata_decrypt(rt->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len, plain,
            sizeof(plain), &plain_len))
        return ZCL_ERR(-10, "overlay intent authentication failed");
    uint8_t digest[32];
    oti_intent_digest(plain, plain_len, row, digest);
    bool ok = memcmp(digest, row->digest, 32) == 0 &&
              oti_payload_decode(plain, plain_len, payload);
    memory_cleanse(plain, sizeof(plain));
    return ok ? ZCL_OK
              : ZCL_ERR(-11, "overlay intent digest or payload is invalid");
}

static void oti_view(const struct vault_intent_row *row,
                     const struct oti_payload *payload,
                     struct overlay_intent_result *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->plan_id, row->plan_id, 32);
    snprintf(out->wallet_scope, sizeof(out->wallet_scope), "%s",
             row->wallet_scope);
    snprintf(out->wallet_instance_id, sizeof(out->wallet_instance_id), "%s",
             row->wallet_instance_id);
    snprintf(out->network_genesis, sizeof(out->network_genesis), "%s",
             row->wallet_genesis);
    snprintf(out->application_kind, sizeof(out->application_kind), "%s",
             row->application_kind);
    snprintf(out->operation, sizeof(out->operation), "%s",
             payload->operation);
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

struct zcl_result overlay_transaction_intent_plan(
    const struct overlay_intent_runtime *rt,
    const struct overlay_intent_request *request,
    struct overlay_intent_result *out)
{
    ZCL_CHECK(oti_runtime_validate(rt, true, false));
    ZCL_CHECK(oti_request_validate(request));
    if (!out) return ZCL_ERR(-12, "overlay intent output is required");
    uint8_t request_digest[32];
    oti_request_digest(request, request_digest);
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            rt->node_db, request->wallet_scope, request->application_kind,
            request->idempotency_key, &existing)) {
        if (!existing.has_request_digest ||
            memcmp(existing.request_digest, request_digest, 32) != 0)
            return ZCL_ERR(-13, "idempotency key names a different overlay request");
        struct oti_payload payload;
        ZCL_CHECK(oti_payload_open(rt, &existing, &payload));
        oti_view(&existing, &payload, out);
        out->idempotent_replay = true;
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_OK;
    }
    struct wallet_money_snapshot money;
    ZCL_CHECK(oti_money_current(rt, request->wallet_scope, &money));
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX, "overlay_intent_raw");
    struct vault_intent_input *inputs = zcl_malloc(
        OTI_INPUT_MAX * sizeof(*inputs), "overlay_intent_inputs");
    if (!raw || !inputs) {
        free(raw); free(inputs);
        return ZCL_ERR(-14, "overlay preparation allocation failed");
    }
    struct oti_payload payload; memset(&payload, 0, sizeof(payload));
    snprintf(payload.operation, sizeof(payload.operation), "%s",
             request->operation);
    memcpy(payload.semantics, request->semantics, request->semantics_len);
    payload.semantics_len = request->semantics_len;
    size_t raw_len = 0, input_count = 0;
    struct zcl_result prepared = rt->prepare(
        rt->prepare_ctx, request, rt->maximum_fee_zat, raw,
        VAULT_INTENT_RAW_MAX, &raw_len, payload.txid,
        &payload.actual_fee_zat, inputs, OTI_INPUT_MAX, &input_count);
    if (!prepared.ok || raw_len == 0 || input_count == 0 ||
        payload.actual_fee_zat < 0 ||
        payload.actual_fee_zat > rt->maximum_fee_zat ||
        !zcl_bytes_any_set(payload.txid, 32)) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX);
        memory_cleanse(&payload, sizeof(payload));
        free(raw); free(inputs);
        return prepared.ok
            ? ZCL_ERR(-15, "prepared overlay transaction violates its fee/input contract")
            : prepared;
    }
    int64_t reserved = rt->maximum_fee_zat;
    int64_t liquid = money.confirmed_zat - money.intent_reserved_zat;
    if (reserved > liquid || (strcmp(request->wallet_scope, "dev") == 0 &&
                              reserved > money.agent_available_zat)) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw); free(inputs);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-16, "custody allocation cannot reserve overlay fee");
    }
    struct vault_intent_row row; memset(&row, 0, sizeof(row));
    if (RAND_bytes(row.plan_id, 32) != 1) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw); free(inputs);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-17, "could not mint overlay plan identity");
    }
    row.state = VAULT_INTENT_PLANNED;
    row.route = VAULT_INTENT_ROUTE_TRANSPARENT;
    row.created_at = rt->now_unix;
    row.expires_at = rt->now_unix + OTI_PLAN_TTL;
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
    row.recipient_value_zat = 0;
    row.max_fee_zat = rt->maximum_fee_zat;
    row.reserved_zat = reserved;
    snprintf(row.application_kind, sizeof(row.application_kind), "%s",
             request->application_kind);
    snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s",
             request->idempotency_key);
    memcpy(row.request_digest, request_digest, 32);
    row.has_request_digest = true;
    uint8_t plain[OTI_PAYLOAD_MAX]; size_t plain_len = 0;
    bool encoded = oti_payload_encode(&payload, plain, sizeof(plain), &plain_len);
    bool encrypted = encoded && wallet_metadata_encrypt(
        rt->node_db, row.plan_id, 32, plain, plain_len,
        row.encrypted_payload, sizeof(row.encrypted_payload),
        &row.encrypted_payload_len);
    if (encrypted) oti_intent_digest(plain, plain_len, &row, row.digest);
    bool stored = encrypted && vault_intent_reserve_with_raw_inputs(
        rt->node_db, &row, money.confirmed_zat, raw, raw_len, inputs,
        input_count);
    if (stored) {
        struct wallet_money_snapshot refreshed;
        struct zcl_result current = oti_money_current(
            rt, request->wallet_scope, &refreshed);
        stored = current.ok;
        if (stored) {
            memcpy(row.snapshot_root, refreshed.snapshot_root, 32);
            oti_intent_digest(plain, plain_len, &row, row.digest);
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
        return ZCL_ERR(-18, "overlay reservation or exact-input claim conflicted");
    ZCL_CHECK(oti_payload_open(rt, &row, &payload));
    oti_view(&row, &payload, out);
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}

struct zcl_result overlay_transaction_intent_commit(
    const struct overlay_intent_runtime *rt, const char *application_kind,
    const char *wallet_scope, const uint8_t plan_id[32],
    struct overlay_intent_result *out)
{
    ZCL_CHECK(oti_runtime_validate(rt, false, true));
    if (!application_kind || !wallet_scope || !plan_id || !out ||
        !oti_token_valid(application_kind, VAULT_INTENT_APPLICATION_MAX) ||
        (strcmp(wallet_scope, "dev") != 0 && strcmp(wallet_scope, "prod") != 0))
        return ZCL_ERR(-19, "overlay commit requires application, scope, plan, and output");
    (void)vault_intent_expire_due(rt->node_db, rt->now_unix);
    struct vault_intent_row row;
    if (!vault_intent_find(rt->node_db, plan_id, &row) ||
        strcmp(row.application_kind, application_kind) != 0)
        return ZCL_ERR(-20, "overlay intent was not found for this application");
    if (strcmp(row.wallet_scope, wallet_scope) != 0)
        return ZCL_ERR(-21, "wallet scope does not match overlay intent");
    struct oti_payload payload;
    ZCL_CHECK(oti_payload_open(rt, &row, &payload));
    if (row.has_txid && row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
        row.state <= VAULT_INTENT_REORGED) {
        oti_view(&row, &payload, out);
        out->idempotent_replay = true;
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_OK;
    }
    if ((row.state != VAULT_INTENT_PLANNED &&
         row.state != VAULT_INTENT_PROVING) || row.expires_at <= rt->now_unix) {
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-22, "overlay intent is not committable");
    }
    struct wallet_money_snapshot money;
    struct zcl_result current = oti_money_current(rt, wallet_scope, &money);
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
        return current.ok
            ? ZCL_ERR(-23, "wallet identity, tip, or money snapshot changed")
            : current;
    }
    uint8_t *raw = zcl_malloc(VAULT_INTENT_RAW_MAX, "overlay_intent_commit_raw");
    size_t raw_len = 0;
    if (!raw || !vault_intent_load_raw(rt->node_db, row.plan_id, raw,
                                       VAULT_INTENT_RAW_MAX, &raw_len)) {
        free(raw);
        memory_cleanse(&payload, sizeof(payload));
        (void)vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_CONFLICTED, NULL, "PREPARED_TX_MISSING",
            rt->now_unix);
        return ZCL_ERR(-24, "prepared overlay transaction is missing");
    }
    if (row.state == VAULT_INTENT_PLANNED &&
        !vault_intent_claim_commit(rt->node_db, row.plan_id, rt->now_unix)) {
        memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw);
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-25, "another commit claimed this overlay intent");
    }
    struct zcl_result published = rt->publish(
        rt->publish_ctx, raw, raw_len, payload.txid);
    memory_cleanse(raw, VAULT_INTENT_RAW_MAX); free(raw);
    if (!published.ok) {
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-26, "COMMIT_UNCERTAIN: exact overlay publication failed: %s",
                       published.message);
    }
    if (!vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_MEMPOOL_ACCEPTED, payload.txid, "", rt->now_unix) ||
        !vault_intent_find(rt->node_db, row.plan_id, &row)) {
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-27, "overlay published but durable state is uncertain");
    }
    oti_view(&row, &payload, out);
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}
