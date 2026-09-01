/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable, identity-bound ZBLG transaction planning and publication. */

#include "services/blog_publication_service.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "models/wallet_metadata_crypto.h"
#include "models/znam.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum blog_anchor_error {
    BLOG_ERR_ARGS = -1,
    BLOG_ERR_NAME = -6,
    BLOG_ERR_VERIFY = -5,
    BLOG_ERR_TX = -10,
};

static void write_u16_le(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
}

static uint16_t read_u16_le(const uint8_t in[2])
{
    return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
}

#define BLOG_ANCHOR_PLAN_TTL 600LL
#define BLOG_ANCHOR_PAYLOAD_MAX 256u

struct blog_anchor_plan_payload {
    char blog_name[BLOG_NAME_MAX + 1];
    uint8_t event_id[32];
    uint8_t script[BLOG_ANCHOR_SCRIPT_MAX];
    size_t script_len;
    uint8_t txid[32];
    int64_t actual_fee_zat;
};

static struct zcl_result blog_anchor_runtime_validate(
    const struct blog_anchor_runtime *rt, bool planning, bool committing)
{
    if (!rt || !rt->node_db || !rt->node_db->open || !rt->read_money ||
        rt->tip_height < 0 || !zcl_bytes_any_set(rt->tip_hash, 32) ||
        rt->maximum_fee_zat <= 0 || rt->now_unix <= 0)
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor requires current custody and chain runtime");
    if (planning && !rt->prepare)
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor planning requires a wallet prepare port");
    if (committing && !rt->publish)
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor commit requires a wallet publish port");
    return ZCL_OK;
}

static struct zcl_result blog_anchor_event_verify(
    struct node_db *ndb, const char *blog_name, const uint8_t event_id[32])
{
    struct db_blog_post post;
    if (!db_blog_post_find(ndb, event_id, &post))
        return ZCL_ERR(BLOG_ERR_VERIFY,
                       "Blog anchor event is not stored locally");
    if (strcmp(post.blog_name, blog_name) != 0)
        return ZCL_ERR(BLOG_ERR_NAME,
                       "Blog anchor name does not match the stored event");
    uint8_t payload[BLOG_BODY_MAX + BLOG_TITLE_MAX + BLOG_NAME_MAX +
                    BLOG_SLUG_MAX + 32];
    struct zcl_app_signed_event_v1 event;
    struct zcl_result verified = blog_publication_export_event(
        &post, payload, sizeof(payload), &event);
    if (!verified.ok)
        return ZCL_ERR(BLOG_ERR_VERIFY,
                       "Blog anchor stored event failed signature verification");
    struct znam_entry name;
    if (!db_znam_find(ndb, blog_name, &name) ||
        strcmp(name.owner_address, post.author_address) != 0)
        return ZCL_ERR(BLOG_ERR_NAME,
                       "Blog anchor author is not the current ZNAM owner");
    return ZCL_OK;
}

static void blog_anchor_request_digest(
    const struct blog_anchor_request *request, uint8_t out[32])
{
    static const uint8_t domain[] = "zcl.blog.anchor.request.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, (const uint8_t *)request->wallet_scope,
                   strlen(request->wallet_scope));
    sha3_256_write(&sha, (const uint8_t *)request->blog_name,
                   strlen(request->blog_name));
    sha3_256_write(&sha, request->event_id, 32);
    sha3_256_write(&sha, (const uint8_t *)request->idempotency_key,
                   strlen(request->idempotency_key));
    sha3_256_finalize(&sha, out);
}

static bool blog_anchor_payload_encode(
    const struct blog_anchor_plan_payload *payload, uint8_t *out,
    size_t capacity, size_t *out_len)
{
    size_t name_len = strlen(payload->blog_name);
    size_t needed = 4 + 1 + name_len + 32 + 2 + payload->script_len + 32 + 8;
    if (!out || !out_len || name_len == 0 || name_len > BLOG_NAME_MAX ||
        payload->script_len == 0 ||
        payload->script_len > BLOG_ANCHOR_SCRIPT_MAX || needed > capacity)
        return false;
    size_t off = 0;
    memcpy(out + off, "BAP1", 4); off += 4;
    out[off++] = (uint8_t)name_len;
    memcpy(out + off, payload->blog_name, name_len); off += name_len;
    memcpy(out + off, payload->event_id, 32); off += 32;
    write_u16_le(out + off, (uint16_t)payload->script_len); off += 2;
    memcpy(out + off, payload->script, payload->script_len);
    off += payload->script_len;
    memcpy(out + off, payload->txid, 32); off += 32;
    zcl_write_i64_le(out + off, payload->actual_fee_zat); off += 8;
    *out_len = off;
    return off == needed;
}

static bool blog_anchor_payload_decode(
    const uint8_t *raw, size_t raw_len,
    struct blog_anchor_plan_payload *payload)
{
    if (!raw || !payload || raw_len < 80 || raw_len > BLOG_ANCHOR_PAYLOAD_MAX ||
        memcmp(raw, "BAP1", 4) != 0)
        return false;
    memset(payload, 0, sizeof(*payload));
    size_t off = 4;
    size_t name_len = raw[off++];
    if (name_len == 0 || name_len > BLOG_NAME_MAX ||
        off + name_len + 32 + 2 > raw_len)
        return false;
    memcpy(payload->blog_name, raw + off, name_len); off += name_len;
    payload->blog_name[name_len] = 0;
    memcpy(payload->event_id, raw + off, 32); off += 32;
    payload->script_len = read_u16_le(raw + off); off += 2;
    if (payload->script_len == 0 ||
        payload->script_len > BLOG_ANCHOR_SCRIPT_MAX ||
        off + payload->script_len + 32 + 8 != raw_len)
        return false;
    memcpy(payload->script, raw + off, payload->script_len);
    off += payload->script_len;
    memcpy(payload->txid, raw + off, 32); off += 32;
    payload->actual_fee_zat = zcl_read_i64_le(raw + off); off += 8;
    char parsed_name[BLOG_NAME_MAX + 1];
    uint8_t parsed_event[32];
    return off == raw_len && payload->actual_fee_zat >= 0 &&
        zcl_bytes_any_set(payload->txid, 32) &&
        blog_anchor_script_parse(payload->script, payload->script_len,
                                 parsed_name, parsed_event).ok &&
        strcmp(parsed_name, payload->blog_name) == 0 &&
        memcmp(parsed_event, payload->event_id, 32) == 0;
}

static void blog_anchor_intent_digest(
    const uint8_t *plain, size_t plain_len,
    const struct vault_intent_row *row, uint8_t out[32])
{
    static const uint8_t domain[] = "zcl.blog.anchor.intent.v1";
    uint8_t nums[20];
    zcl_write_i32_le(nums, row->anchor_height);
    zcl_write_i64_le(nums + 4, row->expires_at);
    zcl_write_i64_le(nums + 12, row->reserved_zat);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, plain, plain_len);
    sha3_256_write(&sha, nums, sizeof(nums));
    sha3_256_write(&sha, row->anchor_hash, 32);
    sha3_256_write(&sha, row->snapshot_root, 32);
    sha3_256_write(&sha, row->request_digest, 32);
    sha3_256_write(&sha, (const uint8_t *)row->wallet_instance_id,
                   strlen(row->wallet_instance_id));
    sha3_256_finalize(&sha, out);
}

static struct zcl_result blog_anchor_money_current(
    const struct blog_anchor_runtime *rt, const char *scope,
    struct wallet_money_snapshot *money)
{
    struct zcl_result result = rt->read_money(rt->money_ctx, scope, money);
    if (!result.ok)
        return result;
    if (!money->complete || strcmp(money->status, "CURRENT") != 0)
        return ZCL_ERR(BLOG_ERR_TX, "money state is not current: %s",
                       money->reason);
    if (money->tip_height != rt->tip_height ||
        memcmp(money->tip_hash, rt->tip_hash, 32) != 0)
        return ZCL_ERR(BLOG_ERR_TX,
                       "money snapshot and active tip changed during Blog operation");
    return ZCL_OK;
}

static struct zcl_result blog_anchor_payload_open(
    const struct blog_anchor_runtime *rt, const struct vault_intent_row *row,
    struct blog_anchor_plan_payload *payload)
{
    uint8_t plain[BLOG_ANCHOR_PAYLOAD_MAX];
    size_t plain_len = 0;
    if (!wallet_metadata_decrypt(rt->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len,
            plain, sizeof(plain), &plain_len))
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor plan authentication failed");
    uint8_t digest[32];
    blog_anchor_intent_digest(plain, plain_len, row, digest);
    bool valid = memcmp(digest, row->digest, 32) == 0 &&
        blog_anchor_payload_decode(plain, plain_len, payload);
    memory_cleanse(plain, sizeof(plain));
    return valid ? ZCL_OK : ZCL_ERR(BLOG_ERR_TX,
                                    "Blog anchor plan was changed or corrupted");
}

static void blog_anchor_view(
    const struct vault_intent_row *row,
    const struct blog_anchor_plan_payload *payload,
    struct blog_anchor_transaction_result *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->plan_id, row->plan_id, 32);
    (void)snprintf(out->wallet_scope, sizeof(out->wallet_scope), "%s",
                   row->wallet_scope);
    (void)snprintf(out->blog_name, sizeof(out->blog_name), "%s",
                   payload->blog_name);
    memcpy(out->event_id, payload->event_id, 32);
    memcpy(out->anchor_script, payload->script, payload->script_len);
    out->anchor_script_len = payload->script_len;
    out->event_verified = true;
    out->has_txid = row->has_txid;
    if (row->has_txid)
        memcpy(out->txid, row->txid, 32);
    out->broadcast = row->state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
        row->state <= VAULT_INTENT_REORGED;
    out->actual_fee_zat = payload->actual_fee_zat;
    out->maximum_fee_zat = row->max_fee_zat;
    out->reserved_zat = row->reserved_zat;
    out->expires_at = row->expires_at;
    (void)snprintf(out->state, sizeof(out->state), "%s",
                   vault_intent_state_name(row->state));
}

struct zcl_result blog_publication_anchor_status(
    const struct blog_anchor_runtime *rt, const uint8_t plan_id[32],
    struct blog_anchor_transaction_result *out)
{
    ZCL_CHECK(blog_anchor_runtime_validate(rt, false, false));
    if (!plan_id || !out)
        return ZCL_ERR(BLOG_ERR_ARGS,
                       "Blog anchor status requires plan ID and output");
    (void)vault_intent_expire_due(rt->node_db, rt->now_unix);
    struct vault_intent_row row;
    if (!vault_intent_find(rt->node_db, plan_id, &row) ||
        strcmp(row.application_kind, BLOG_ANCHOR_APPLICATION) != 0)
        return ZCL_ERR(BLOG_ERR_TX, "Blog anchor plan was not found");
    struct blog_anchor_plan_payload payload;
    ZCL_CHECK(blog_anchor_payload_open(rt, &row, &payload));
    blog_anchor_view(&row, &payload, out);
    return ZCL_OK;
}
struct zcl_result blog_publication_anchor_plan(
    const struct blog_anchor_runtime *rt,
    const struct blog_anchor_request *request,
    struct blog_anchor_transaction_result *out)
{
    ZCL_CHECK(blog_anchor_runtime_validate(rt, true, false));
    if (!request || !out ||
        (strcmp(request->wallet_scope, "dev") != 0 &&
         strcmp(request->wallet_scope, "prod") != 0) ||
        !znam_validate_name(request->blog_name) ||
        !zcl_bytes_any_set(request->event_id, 32) ||
        request->idempotency_key[0] == 0 ||
        strlen(request->idempotency_key) > BLOG_ANCHOR_IDEMPOTENCY_MAX)
        return ZCL_ERR(BLOG_ERR_ARGS,
                       "scope, canonical name, event ID, and idempotency key are required");
    uint8_t request_digest[32];
    blog_anchor_request_digest(request, request_digest);
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            rt->node_db, request->wallet_scope, BLOG_ANCHOR_APPLICATION,
            request->idempotency_key, &existing)) {
        if (!existing.has_request_digest ||
            memcmp(existing.request_digest, request_digest, 32) != 0)
            return ZCL_ERR(BLOG_ERR_TX,
                           "idempotency key names a different Blog anchor");
        ZCL_CHECK(blog_publication_anchor_status(rt, existing.plan_id, out));
        out->idempotent_replay = true;
        return ZCL_OK;
    }
    ZCL_CHECK(blog_anchor_event_verify(rt->node_db, request->blog_name,
                                       request->event_id));
    struct wallet_money_snapshot money;
    ZCL_CHECK(blog_anchor_money_current(rt, request->wallet_scope, &money));
    int64_t liquid = money.confirmed_zat - money.intent_reserved_zat;
    if (liquid < rt->maximum_fee_zat ||
        (strcmp(request->wallet_scope, "dev") == 0 &&
         money.agent_available_zat < rt->maximum_fee_zat))
        return ZCL_ERR(BLOG_ERR_TX,
                       "custody allocation cannot reserve the maximum fee");

    struct blog_anchor_plan_payload payload;
    memset(&payload, 0, sizeof(payload));
    (void)snprintf(payload.blog_name, sizeof(payload.blog_name), "%s",
                   request->blog_name);
    memcpy(payload.event_id, request->event_id, 32);
    ZCL_CHECK(blog_anchor_script_build(
        request->blog_name, request->event_id, payload.script,
        sizeof(payload.script), &payload.script_len));
    uint8_t *raw_tx = zcl_malloc(VAULT_INTENT_RAW_MAX,
                                  "blog_anchor_prepared_raw");
    if (!raw_tx)
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor raw transaction allocation failed");
    size_t raw_tx_len = 0;
    struct zcl_result prepared = rt->prepare(
        rt->prepare_ctx, payload.script, payload.script_len,
        rt->maximum_fee_zat, raw_tx, VAULT_INTENT_RAW_MAX, &raw_tx_len,
        payload.txid, &payload.actual_fee_zat);
    if (!prepared.ok || raw_tx_len == 0 ||
        raw_tx_len > VAULT_INTENT_RAW_MAX ||
        !zcl_bytes_any_set(payload.txid, 32) || payload.actual_fee_zat < 0 ||
        payload.actual_fee_zat > rt->maximum_fee_zat) {
        memory_cleanse(raw_tx, VAULT_INTENT_RAW_MAX);
        free(raw_tx);
        return prepared.ok
            ? ZCL_ERR(BLOG_ERR_TX,
                      "prepared Blog transaction exceeded its exact fee contract")
            : prepared;
    }

    struct vault_intent_row row;
    memset(&row, 0, sizeof(row));
    if (RAND_bytes(row.plan_id, 32) != 1) {
        memory_cleanse(raw_tx, VAULT_INTENT_RAW_MAX);
        free(raw_tx);
        return ZCL_ERR(BLOG_ERR_TX, "could not mint Blog anchor plan ID");
    }
    row.state = VAULT_INTENT_PLANNED;
    row.route = VAULT_INTENT_ROUTE_TRANSPARENT;
    row.created_at = rt->now_unix;
    row.expires_at = rt->now_unix + BLOG_ANCHOR_PLAN_TTL;
    row.updated_at = rt->now_unix;
    row.anchor_height = rt->tip_height;
    memcpy(row.anchor_hash, rt->tip_hash, 32);
    (void)snprintf(row.wallet_scope, sizeof(row.wallet_scope), "%s",
                   request->wallet_scope);
    (void)snprintf(row.wallet_instance_id, sizeof(row.wallet_instance_id),
                   "%s", money.identity.wallet_instance_id);
    wallet_identity_genesis_hex(&money.identity, row.wallet_genesis);
    memcpy(row.snapshot_root, money.snapshot_root, 32);
    row.has_snapshot_root = true;
    row.recipient_value_zat = 0;
    row.max_fee_zat = rt->maximum_fee_zat;
    row.reserved_zat = rt->maximum_fee_zat;
    (void)snprintf(row.application_kind, sizeof(row.application_kind), "%s",
                   BLOG_ANCHOR_APPLICATION);
    (void)snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s",
                   request->idempotency_key);
    memcpy(row.request_digest, request_digest, 32);
    row.has_request_digest = true;
    uint8_t plain[BLOG_ANCHOR_PAYLOAD_MAX];
    size_t plain_len = 0;
    bool encoded = blog_anchor_payload_encode(
        &payload, plain, sizeof(plain), &plain_len);
    bool encrypted = encoded && wallet_metadata_encrypt(
        rt->node_db, row.plan_id, 32, plain, plain_len,
        row.encrypted_payload, sizeof(row.encrypted_payload),
        &row.encrypted_payload_len);
    if (encrypted)
        blog_anchor_intent_digest(plain, plain_len, &row, row.digest);
    bool stored = encrypted && vault_intent_reserve_with_raw(
        rt->node_db, &row, money.confirmed_zat, raw_tx, raw_tx_len);
    if (stored) {
        struct wallet_money_snapshot refreshed;
        struct zcl_result current = blog_anchor_money_current(
            rt, request->wallet_scope, &refreshed);
        stored = current.ok;
        if (stored) {
            memcpy(row.snapshot_root, refreshed.snapshot_root, 32);
            blog_anchor_intent_digest(plain, plain_len, &row, row.digest);
            stored = vault_intent_save(rt->node_db, &row);
        }
        if (!stored)
            (void)vault_intent_set_state(rt->node_db, row.plan_id,
                VAULT_INTENT_FAILED, NULL, "SNAPSHOT_BIND_FAILED",
                rt->now_unix);
    }
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(raw_tx, VAULT_INTENT_RAW_MAX);
    free(raw_tx);
    if (!stored)
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor reservation could not be persisted atomically");
    blog_anchor_view(&row, &payload, out);
    return ZCL_OK;
}

struct zcl_result blog_publication_anchor_commit(
    const struct blog_anchor_runtime *rt, const char *wallet_scope,
    const uint8_t plan_id[32], struct blog_anchor_transaction_result *out)
{
    ZCL_CHECK(blog_anchor_runtime_validate(rt, false, true));
    if (!wallet_scope || !plan_id || !out ||
        (strcmp(wallet_scope, "dev") != 0 && strcmp(wallet_scope, "prod") != 0))
        return ZCL_ERR(BLOG_ERR_ARGS,
                       "explicit wallet scope, plan ID, and output are required");
    (void)vault_intent_expire_due(rt->node_db, rt->now_unix);
    struct vault_intent_row row;
    if (!vault_intent_find(rt->node_db, plan_id, &row) ||
        strcmp(row.application_kind, BLOG_ANCHOR_APPLICATION) != 0)
        return ZCL_ERR(BLOG_ERR_TX, "Blog anchor plan was not found");
    if (strcmp(row.wallet_scope, wallet_scope) != 0)
        return ZCL_ERR(BLOG_ERR_TX,
                       "wallet scope does not match Blog anchor plan");
    struct blog_anchor_plan_payload payload;
    ZCL_CHECK(blog_anchor_payload_open(rt, &row, &payload));
    if (row.has_txid && row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
        row.state <= VAULT_INTENT_REORGED) {
        blog_anchor_view(&row, &payload, out);
        out->idempotent_replay = true;
        return ZCL_OK;
    }
    if ((row.state != VAULT_INTENT_PLANNED &&
         row.state != VAULT_INTENT_PROVING) || row.expires_at <= rt->now_unix)
        return ZCL_ERR(BLOG_ERR_TX, "Blog anchor plan is not committable");

    struct wallet_money_snapshot money;
    struct zcl_result current = blog_anchor_money_current(
        rt, wallet_scope, &money);
    char genesis[65] = {0};
    if (current.ok)
        wallet_identity_genesis_hex(&money.identity, genesis);
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
        return current.ok
            ? ZCL_ERR(BLOG_ERR_TX,
                      "wallet identity, tip, or money snapshot changed")
            : current;
    }
    ZCL_CHECK(blog_anchor_event_verify(rt->node_db, payload.blog_name,
                                       payload.event_id));
    uint8_t *raw_tx = zcl_malloc(VAULT_INTENT_RAW_MAX,
                                  "blog_anchor_commit_raw");
    if (!raw_tx)
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog anchor raw transaction allocation failed");
    size_t raw_tx_len = 0;
    if (!vault_intent_load_raw(rt->node_db, row.plan_id, raw_tx,
                               VAULT_INTENT_RAW_MAX, &raw_tx_len)) {
        free(raw_tx);
        (void)vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_CONFLICTED, NULL, "PREPARED_TX_MISSING",
            rt->now_unix);
        return ZCL_ERR(BLOG_ERR_TX,
                       "prepared Blog transaction is missing after restart");
    }
    if (row.state == VAULT_INTENT_PLANNED &&
        !vault_intent_claim_commit(rt->node_db, row.plan_id, rt->now_unix)) {
        memory_cleanse(raw_tx, VAULT_INTENT_RAW_MAX);
        free(raw_tx);
        return ZCL_ERR(BLOG_ERR_TX,
                       "another commit claimed this Blog anchor plan");
    }
    struct zcl_result published = rt->publish(
        rt->publish_ctx, raw_tx, raw_tx_len, payload.txid);
    memory_cleanse(raw_tx, VAULT_INTENT_RAW_MAX);
    free(raw_tx);
    if (!published.ok)
        return ZCL_ERR(BLOG_ERR_TX,
                       "COMMIT_UNCERTAIN: exact Blog transaction publication failed: %s",
                       published.message);
    if (!vault_intent_set_state(rt->node_db, row.plan_id,
            VAULT_INTENT_MEMPOOL_ACCEPTED, payload.txid, "", rt->now_unix) ||
        !vault_intent_find(rt->node_db, row.plan_id, &row))
        return ZCL_ERR(BLOG_ERR_TX,
                       "Blog transaction published but durable intent state is uncertain");
    blog_anchor_view(&row, &payload, out);
    return ZCL_OK;
}
