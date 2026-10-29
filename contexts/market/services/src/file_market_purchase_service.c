/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact, encrypted, idempotent file-market purchase intents. */

#include "services/file_market_purchase_service.h"
#include "base/bytes.h"
#include "services/file_market_purchase_internal.h"

#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/market_download.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "models/wallet_metadata_crypto.h"
#include "sapling/sapling.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "wallet/sapling_keys.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define MP_TTL_SECS 600LL

static void mp_request_digest(const struct market_purchase_request *r,
                              uint8_t out[32])
{
    static const uint8_t domain[] = "zcl.market.purchase.request.v1";
    uint8_t nums[2][4];
    zcl_write_u32_le(nums[0], r->chunk_start);
    zcl_write_u32_le(nums[1], r->chunks_paid);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, (const uint8_t *)r->wallet_scope,
                   strlen(r->wallet_scope));
    sha3_256_write(&sha, r->offer_id, 32);
    sha3_256_write(&sha, (const uint8_t *)nums, sizeof(nums));
    sha3_256_write(&sha, (const uint8_t *)r->source_address,
                   strlen(r->source_address));
    sha3_256_finalize(&sha, out);
}

static bool mp_payload_encode(const struct market_purchase_private_payload *p, uint8_t *out,
                              size_t cap, size_t *out_len)
{
    if (!p || !out || !out_len)
        return false;
    size_t ns = strlen(p->source), nd = strlen(p->seller);
    const size_t needed = 4 + 2 + ns + 2 + nd + 32 + 32 + 4 + 4 + 8 + 8 +
                          32 + 32 + FILE_MARKET_PAYMENT_MEMO_BYTES;
    if (ns == 0 || ns > MARKET_PURCHASE_SOURCE_MAX ||
        nd == 0 || nd > 255 || needed > cap)
        return false;
    size_t off = 0;
    memcpy(out + off, "MPV1", 4); off += 4;
    zcl_write_u16_le(out + off, (uint16_t)ns); off += 2;
    memcpy(out + off, p->source, ns); off += ns;
    zcl_write_u16_le(out + off, (uint16_t)nd); off += 2;
    memcpy(out + off, p->seller, nd); off += nd;
    memcpy(out + off, p->offer_id, 32); off += 32;
    memcpy(out + off, p->network_genesis, 32); off += 32;
    zcl_write_u32_le(out + off, p->chunk_start); off += 4;
    zcl_write_u32_le(out + off, p->chunks_paid); off += 4;
    zcl_write_i64_le(out + off, p->amount_zat); off += 8;
    zcl_write_i64_le(out + off, p->maximum_fee_zat); off += 8;
    memcpy(out + off, p->buyer_seed, 32); off += 32;
    memcpy(out + off, p->buyer_pubkey, 32); off += 32;
    memcpy(out + off, p->memo, FILE_MARKET_PAYMENT_MEMO_BYTES);
    off += FILE_MARKET_PAYMENT_MEMO_BYTES;
    *out_len = off;
    return off == needed;
}

static bool mp_take(const uint8_t *raw, size_t len, size_t *off,
                    void *out, size_t n)
{
    if (!raw || !off || !out || *off > len || n > len - *off)
        return false; // raw-return-ok:pure bounded payload decoder
    memcpy(out, raw + *off, n);
    *off += n;
    return true;
}

static bool mp_decode_source(const uint8_t *raw, size_t len, size_t *off,
                             struct market_purchase_private_payload *p)
{
    uint8_t magic[4], u16[2];
    if (!mp_take(raw, len, off, magic, 4) || memcmp(magic, "MPV1", 4) != 0 ||
        !mp_take(raw, len, off, u16, 2))
        return false; // raw-return-ok:pure bounded payload decoder
    uint16_t ns = zcl_read_u16_le(u16);
    if (ns == 0 || ns > MARKET_PURCHASE_SOURCE_MAX ||
        !mp_take(raw, len, off, p->source, ns))
        return false; // raw-return-ok:pure bounded payload decoder
    p->source[ns] = '\0';
    return true;
}

static bool mp_decode_seller(const uint8_t *raw, size_t len, size_t *off,
                             struct market_purchase_private_payload *p)
{
    uint8_t u16[2];
    if (!mp_take(raw, len, off, u16, 2))
        return false; // raw-return-ok:pure bounded payload decoder
    uint16_t nd = zcl_read_u16_le(u16);
    if (nd == 0 || nd >= sizeof(p->seller) ||
        !mp_take(raw, len, off, p->seller, nd))
        return false; // raw-return-ok:pure bounded payload decoder
    p->seller[nd] = '\0';
    return true;
}

static bool mp_decode_ids_amounts(const uint8_t *raw, size_t len, size_t *off,
                                  struct market_purchase_private_payload *p)
{
    uint8_t nums[24];
    if (!mp_take(raw, len, off, p->offer_id, 32) ||
        !mp_take(raw, len, off, p->network_genesis, 32) ||
        !mp_take(raw, len, off, nums, sizeof(nums)))
        return false; // raw-return-ok:pure bounded payload decoder
    p->chunk_start = zcl_read_u32_le(nums);
    p->chunks_paid = zcl_read_u32_le(nums + 4);
    p->amount_zat = zcl_read_i64_le(nums + 8);
    p->maximum_fee_zat = zcl_read_i64_le(nums + 16);
    return true;
}

static bool mp_decode_secrets(const uint8_t *raw, size_t len, size_t *off,
                              struct market_purchase_private_payload *p)
{
    if (!mp_take(raw, len, off, p->buyer_seed, 32) ||
        !mp_take(raw, len, off, p->buyer_pubkey, 32) ||
        !mp_take(raw, len, off, p->memo, FILE_MARKET_PAYMENT_MEMO_BYTES))
        return false; // raw-return-ok:pure bounded payload decoder
    return true;
}

static bool mp_payload_decode(const uint8_t *raw, size_t len,
                              struct market_purchase_private_payload *p)
{
    if (!raw || !p || len > MARKET_PURCHASE_PAYLOAD_MAX) return false;
    memset(p, 0, sizeof(*p));
    size_t off = 0;
    if (!mp_decode_source(raw, len, &off, p) ||
        !mp_decode_seller(raw, len, &off, p) ||
        !mp_decode_ids_amounts(raw, len, &off, p) ||
        !mp_decode_secrets(raw, len, &off, p))
        return false; // raw-return-ok:pure bounded payload decoder
    return off == len && p->chunks_paid > 0 && p->amount_zat > 0 &&
           p->maximum_fee_zat >= 0 && zcl_bytes_any_set(p->buyer_seed, 32) &&
           zcl_bytes_any_set(p->buyer_pubkey, 32);
}

static void mp_intent_digest(const uint8_t *plain, size_t plain_len,
                             const struct vault_intent_row *row,
                             uint8_t out[32])
{
    static const uint8_t domain[] = "zcl.market.purchase.intent.v1";
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

struct zcl_result market_purchase_runtime_validate(
    const struct market_purchase_runtime *rt, bool needs_money,
    bool committing)
{
    if (!rt || !rt->node_db || !rt->node_db->open || rt->now_unix <= 0)
        return ZCL_ERR(-1, "open purchase database and observation time are required");
    if (needs_money && (!rt->read_money || rt->tip_height < 0 ||
        !zcl_bytes_any_set(rt->tip_hash, 32) || rt->maximum_fee_zat < 0))
        return ZCL_ERR(-1, "complete purchase money runtime is required");
    if (committing && (!rt->send || !rt->check_source))
        return ZCL_ERR(-2, "purchase commit requires source and send ports");
    return ZCL_OK;
}

static struct zcl_result mp_money_current(
    const struct market_purchase_runtime *rt, const char *scope,
    struct wallet_money_snapshot *money)
{
    struct zcl_result r = rt->read_money(rt->money_ctx, scope, money);
    if (!r.ok) return r;
    if (!money->complete || strcmp(money->status, "CURRENT") != 0)
        return ZCL_ERR(-3, "money state is not current: %s", money->reason);
    if (money->tip_height != rt->tip_height ||
        memcmp(money->tip_hash, rt->tip_hash, 32) != 0)
        return ZCL_ERR(-3, "money snapshot and active tip changed during purchase operation");
    return ZCL_OK;
}

static struct zcl_result mp_offer_load(
    const struct market_purchase_runtime *rt, const uint8_t offer_id[32],
    const struct wallet_money_snapshot *money, struct file_offer *offer)
{
    if (!db_file_offer_find_by_id(rt->node_db, offer_id, offer))
        return ZCL_ERR(-4, "authenticated paid offer is absent or invalid");
    enum file_offer_auth_error auth = file_offer_auth_verify_at(
        offer, money->identity.network_genesis, rt->now_unix);
    if (auth != FILE_OFFER_AUTH_OK)
        return ZCL_ERR(-5, "offer is not current for this wallet network: %s",
                       file_offer_auth_error_string(auth));
    return ZCL_OK;
}

void market_purchase_view_from_row(
    const struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    struct market_purchase_view *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->plan_id, row->plan_id, 32);
    memcpy(out->offer_id, payload->offer_id, 32);
    memcpy(out->buyer_pubkey, payload->buyer_pubkey, 32);
    out->chunk_start = payload->chunk_start;
    out->chunks_paid = payload->chunks_paid;
    out->amount_zat = row->recipient_value_zat;
    out->maximum_fee_zat = row->max_fee_zat;
    out->reserved_zat = row->reserved_zat;
    out->expires_at = row->expires_at;
    snprintf(out->wallet_scope, sizeof(out->wallet_scope), "%s",
             row->wallet_scope);
    snprintf(out->state, sizeof(out->state), "%s",
             vault_intent_state_name(row->state));
    out->has_txid = row->has_txid;
    if (row->has_txid) memcpy(out->txid, row->txid, 32);
}

void market_purchase_view_add_download(
    const struct market_download_record *download,
    struct market_purchase_view *out)
{
    if (!download || !out)
        return;
    out->has_download = true;
    snprintf(out->download_state, sizeof(out->download_state), "%s",
             market_download_state_name(download->state));
    out->chunks_received = download->chunks_received;
    out->num_chunks = download->num_chunks;
    out->bytes_received = download->bytes_received;
    out->size_bytes = download->size_bytes;
    out->destination_published =
        download->state == MARKET_DOWNLOAD_COMPLETE;
}

struct zcl_result market_purchase_payload_decrypt(
    const struct market_purchase_runtime *rt, const struct vault_intent_row *row,
    struct market_purchase_private_payload *payload, uint8_t *plain,
    size_t *plain_len)
{
    if (!wallet_metadata_decrypt(rt->node_db, row->plan_id, 32,
            row->encrypted_payload, row->encrypted_payload_len,
            plain, MARKET_PURCHASE_PAYLOAD_MAX, plain_len))
        return ZCL_ERR(-20, "purchase plan authentication failed");
    uint8_t digest[32];
    mp_intent_digest(plain, *plain_len, row, digest);
    if (memcmp(digest, row->digest, 32) != 0 ||
        !mp_payload_decode(plain, *plain_len, payload)) {
        memory_cleanse(plain, MARKET_PURCHASE_PAYLOAD_MAX);
        return ZCL_ERR(-21, "purchase plan digest or payload is invalid");
    }
    return ZCL_OK;
}

static struct zcl_result mp_plan_args_check(
    const struct market_purchase_request *req,
    const struct market_purchase_view *out)
{
    if (!req || !out ||
        (strcmp(req->wallet_scope, "dev") != 0 &&
         strcmp(req->wallet_scope, "prod") != 0) ||
        !zcl_bytes_any_set(req->offer_id, 32) || req->source_address[0] == '\0' ||
        strlen(req->source_address) > MARKET_PURCHASE_SOURCE_MAX ||
        req->chunks_paid == 0 || req->chunk_start > UINT32_MAX - req->chunks_paid ||
        req->idempotency_key[0] == '\0' ||
        strlen(req->idempotency_key) > VAULT_INTENT_IDEMPOTENCY_MAX)
        return ZCL_ERR(-6, "scope, offer, source, range, and idempotency key are required");
    return ZCL_OK;
}

static struct zcl_result mp_plan_replay_guard(
    const struct vault_intent_row *existing, const uint8_t request_digest[32])
{
    if (!existing->has_request_digest ||
        memcmp(existing->request_digest, request_digest, 32) != 0)
        return ZCL_ERR(-7, "idempotency key already names a different purchase");
    if (existing->state == VAULT_INTENT_PROVING && !existing->has_txid)
        return ZCL_ERR(-43, "COMMIT_UNCERTAIN: prior send may have broadcast; reconciliation required");
    if (existing->state == VAULT_INTENT_CONFLICTED ||
        existing->state == VAULT_INTENT_EXPIRED ||
        existing->state == VAULT_INTENT_FAILED)
        return ZCL_ERR(-44, "idempotency key names a terminal purchase plan");
    return ZCL_OK;
}

static struct zcl_result mp_plan_replay(
    const struct market_purchase_runtime *rt,
    const struct vault_intent_row *existing,
    const uint8_t request_digest[32], struct market_purchase_view *out)
{
    ZCL_CHECK(mp_plan_replay_guard(existing, request_digest));
    uint8_t plain[MARKET_PURCHASE_PAYLOAD_MAX]; size_t plain_len = 0;
    struct market_purchase_private_payload payload;
    struct zcl_result decrypted = market_purchase_payload_decrypt(
        rt, existing, &payload, plain, &plain_len);
    if (!decrypted.ok) {
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return decrypted;
    }
    market_purchase_view_from_row(existing, &payload, out);
    out->idempotent_replay = true;
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}

static struct zcl_result mp_plan_amount(
    const struct market_purchase_runtime *rt,
    const struct market_purchase_request *req,
    const struct file_offer *offer, const struct wallet_money_snapshot *money,
    int64_t *amount, int64_t *reserved)
{
    if (!file_market_offer_range_zat(offer, req->chunk_start,
                                     req->chunks_paid, amount))
        return ZCL_ERR(-8, "chunk range is outside the signed offer");
    if (*amount > INT64_MAX - rt->maximum_fee_zat)
        return ZCL_ERR(-9, "recipient value plus fee overflows");
    *reserved = *amount + rt->maximum_fee_zat;
    if (*reserved > money->confirmed_zat - money->intent_reserved_zat ||
        *reserved > money->agent_available_zat)
        return ZCL_ERR(-10, "confirmed custody allocation cannot fund value plus maximum fee");
    return ZCL_OK;
}

static struct zcl_result mp_plan_contract_fill(
    const struct market_purchase_runtime *rt,
    const struct market_purchase_request *req,
    const struct file_offer *offer, int64_t amount,
    struct market_purchase_private_payload *payload)
{
    snprintf(payload->source, sizeof(payload->source), "%s", req->source_address);
    const struct chain_params *params = chain_params_get();
    if (!params || !sapling_encode_payment_address(
            offer->z_addr, offer->z_addr + 11,
            params->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            payload->seller, sizeof(payload->seller)))
        return ZCL_ERR(-12, "signed seller payment address is invalid");
    memcpy(payload->offer_id, offer->offer_id, 32);
    memcpy(payload->network_genesis, offer->network_genesis, 32);
    payload->chunk_start = req->chunk_start;
    payload->chunks_paid = req->chunks_paid;
    payload->amount_zat = amount;
    payload->maximum_fee_zat = rt->maximum_fee_zat;
    return ZCL_OK;
}

static struct zcl_result mp_plan_buyer_fill(
    struct market_purchase_private_payload *payload)
{
    if (RAND_bytes(payload->buyer_seed, 32) != 1)
        return ZCL_ERR(-13, "could not mint encrypted buyer credential");
    uint8_t secret_copy[32];
    ed25519_keypair(payload->buyer_pubkey, secret_copy, payload->buyer_seed);
    memory_cleanse(secret_copy, sizeof(secret_copy));
    return ZCL_OK;
}

static struct zcl_result mp_plan_memo_fill(
    const struct market_purchase_request *req, const struct file_offer *offer,
    int64_t amount, const uint8_t plan_id[32],
    struct market_purchase_private_payload *payload)
{
    struct file_payment memo_contract; memset(&memo_contract, 0,
                                               sizeof(memo_contract));
    memo_contract.version = FILE_MARKET_PAYMENT_VERSION;
    memcpy(memo_contract.network_genesis, offer->network_genesis, 32);
    memcpy(memo_contract.offer_id, offer->offer_id, 32);
    memcpy(memo_contract.txid, plan_id, 32); /* memo excludes txid */
    memo_contract.chunk_start = req->chunk_start;
    memo_contract.chunks_paid = req->chunks_paid;
    memo_contract.amount_zat = amount;
    memcpy(memo_contract.buyer_pubkey, payload->buyer_pubkey, 32);
    if (file_payment_memo_encode(&memo_contract, payload->memo) !=
        FILE_PAYMENT_AUTH_OK) {
        memory_cleanse(payload, sizeof(*payload));
        return ZCL_ERR(-14, "could not encode exact payment memo");
    }
    return ZCL_OK;
}

static struct zcl_result mp_plan_payload_fill(
    const struct market_purchase_runtime *rt,
    const struct market_purchase_request *req,
    const struct file_offer *offer, int64_t amount,
    const uint8_t plan_id[32], struct market_purchase_private_payload *payload)
{
    ZCL_CHECK(mp_plan_contract_fill(rt, req, offer, amount, payload));
    ZCL_CHECK(mp_plan_buyer_fill(payload));
    return mp_plan_memo_fill(req, offer, amount, plan_id, payload);
}

static struct zcl_result mp_plan_set_window(
    const struct market_purchase_runtime *rt, const struct file_offer *offer,
    struct vault_intent_row *row, struct market_purchase_private_payload *payload)
{
    row->state = VAULT_INTENT_PLANNED;
    row->route = VAULT_INTENT_ROUTE_PRIVATE;
    row->created_at = rt->now_unix;
    row->expires_at = rt->now_unix + MP_TTL_SECS;
    if (row->expires_at > offer->expires_unix) row->expires_at = offer->expires_unix;
    if (row->expires_at <= row->created_at) {
        memory_cleanse(payload, sizeof(*payload));
        return ZCL_ERR(-15, "signed offer expires before a plan can be committed");
    }
    return ZCL_OK;
}

static struct zcl_result mp_plan_seal(
    const struct market_purchase_runtime *rt, struct vault_intent_row *row,
    struct market_purchase_private_payload *payload,
    uint8_t *plain, size_t *plain_len)
{
    if (!mp_payload_encode(payload, plain, MARKET_PURCHASE_PAYLOAD_MAX, plain_len) ||
        !wallet_metadata_encrypt(rt->node_db, row->plan_id, 32,
            plain, *plain_len, row->encrypted_payload,
            sizeof(row->encrypted_payload), &row->encrypted_payload_len)) {
        memory_cleanse(plain, MARKET_PURCHASE_PAYLOAD_MAX);
        memory_cleanse(payload, sizeof(*payload));
        return ZCL_ERR(-16, "purchase plan encryption failed");
    }
    return ZCL_OK;
}

static bool mp_plan_persist(
    const struct market_purchase_runtime *rt,
    const struct market_purchase_request *req,
    const struct wallet_money_snapshot *money, struct vault_intent_row *row,
    const uint8_t *plain, size_t plain_len)
{
    bool stored = vault_intent_reserve(rt->node_db, row, money->confirmed_zat);
    if (stored) {
        struct wallet_money_snapshot refreshed;
        struct zcl_result rr = mp_money_current(rt, req->wallet_scope,
                                                &refreshed);
        stored = rr.ok;
        if (stored) {
            memcpy(row->snapshot_root, refreshed.snapshot_root, 32);
            mp_intent_digest(plain, plain_len, row, row->digest);
            stored = vault_intent_save(rt->node_db, row);
        }
        if (!stored)
            (void)vault_intent_set_state(rt->node_db, row->plan_id,
                VAULT_INTENT_FAILED, NULL, "SNAPSHOT_BIND_FAILED", rt->now_unix);
    }
    return stored;
}

static struct zcl_result mp_plan_unstored(
    const struct market_purchase_runtime *rt,
    const struct market_purchase_request *req,
    const uint8_t request_digest[32], struct market_purchase_view *out)
{
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            rt->node_db, req->wallet_scope, MARKET_PURCHASE_APPLICATION,
            req->idempotency_key, &existing) &&
        existing.has_request_digest &&
        memcmp(existing.request_digest, request_digest, 32) == 0)
        return market_purchase_status(rt, existing.plan_id, out);
    return ZCL_ERR(-17, "purchase reservation could not be persisted atomically");
}

struct zcl_result market_purchase_plan(
    const struct market_purchase_runtime *rt,
    const struct market_purchase_request *req,
    struct market_purchase_view *out)
{
    ZCL_CHECK(market_purchase_runtime_validate(rt, true, false));
    ZCL_CHECK(mp_plan_args_check(req, out));
    uint8_t request_digest[32];
    mp_request_digest(req, request_digest);
    struct vault_intent_row existing;
    if (vault_intent_find_application_idempotency(
            rt->node_db, req->wallet_scope, MARKET_PURCHASE_APPLICATION,
            req->idempotency_key, &existing))
        return mp_plan_replay(rt, &existing, request_digest, out);

    struct wallet_money_snapshot money;
    ZCL_CHECK(mp_money_current(rt, req->wallet_scope, &money));
    struct file_offer offer;
    ZCL_CHECK(mp_offer_load(rt, req->offer_id, &money, &offer));
    int64_t amount = 0;
    int64_t reserved = 0;
    ZCL_CHECK(mp_plan_amount(rt, req, &offer, &money, &amount, &reserved));

    struct vault_intent_row row; memset(&row, 0, sizeof(row));
    if (RAND_bytes(row.plan_id, 32) != 1)
        return ZCL_ERR(-11, "could not mint purchase plan identity");
    struct market_purchase_private_payload payload;
    memset(&payload, 0, sizeof(payload));
    ZCL_CHECK(mp_plan_payload_fill(rt, req, &offer, amount, row.plan_id, &payload));
    ZCL_CHECK(mp_plan_set_window(rt, &offer, &row, &payload));
    row.updated_at = rt->now_unix;
    row.anchor_height = rt->tip_height;
    memcpy(row.anchor_hash, rt->tip_hash, 32);
    snprintf(row.wallet_scope, sizeof(row.wallet_scope), "%s", req->wallet_scope);
    snprintf(row.wallet_instance_id, sizeof(row.wallet_instance_id), "%s",
             money.identity.wallet_instance_id);
    wallet_identity_genesis_hex(&money.identity, row.wallet_genesis);
    memcpy(row.snapshot_root, money.snapshot_root, 32);
    row.has_snapshot_root = true;
    row.recipient_value_zat = amount;
    row.max_fee_zat = rt->maximum_fee_zat;
    row.reserved_zat = reserved;
    snprintf(row.application_kind, sizeof(row.application_kind), "%s",
             MARKET_PURCHASE_APPLICATION);
    snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s",
             req->idempotency_key);
    memcpy(row.request_digest, request_digest, 32);
    row.has_request_digest = true;
    uint8_t plain[MARKET_PURCHASE_PAYLOAD_MAX]; size_t plain_len = 0;
    ZCL_CHECK(mp_plan_seal(rt, &row, &payload, plain, &plain_len));
    mp_intent_digest(plain, plain_len, &row, row.digest);
    bool stored = mp_plan_persist(rt, req, &money, &row, plain, plain_len);
    memory_cleanse(plain, sizeof(plain));
    if (!stored) {
        memory_cleanse(&payload, sizeof(payload));
        return mp_plan_unstored(rt, req, request_digest, out);
    }
    market_purchase_view_from_row(&row, &payload, out);
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}

static struct zcl_result mp_claim(
    const struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    struct file_payment *payment)
{
    if (!row->has_txid) return ZCL_ERR(-30, "purchase has no transaction id");
    memset(payment, 0, sizeof(*payment));
    payment->version = FILE_MARKET_PAYMENT_VERSION;
    memcpy(payment->network_genesis, payload->network_genesis, 32);
    memcpy(payment->offer_id, payload->offer_id, 32);
    memcpy(payment->txid, row->txid, 32);
    payment->chunk_start = payload->chunk_start;
    payment->chunks_paid = payload->chunks_paid;
    payment->amount_zat = payload->amount_zat;
    memcpy(payment->buyer_pubkey, payload->buyer_pubkey, 32);
    enum file_payment_auth_error sealed =
        file_payment_auth_seal(payment, payload->buyer_seed);
    return sealed == FILE_PAYMENT_AUTH_OK
        ? ZCL_OK : ZCL_ERR(-31, "payment claim sealing failed: %s",
                           file_payment_auth_error_string(sealed));
}

struct zcl_result market_purchase_status(
    const struct market_purchase_runtime *rt, const uint8_t plan_id[32],
    struct market_purchase_view *out)
{
    ZCL_CHECK(market_purchase_runtime_validate(rt, false, false));
    if (!plan_id || !out) return ZCL_ERR(-32, "plan id and output are required");
    (void)vault_intent_expire_due(rt->node_db, rt->now_unix);
    struct vault_intent_row row;
    if (!vault_intent_find(rt->node_db, plan_id, &row) ||
        strcmp(row.application_kind, MARKET_PURCHASE_APPLICATION) != 0)
        return ZCL_ERR(-33, "market purchase plan not found");
    uint8_t plain[MARKET_PURCHASE_PAYLOAD_MAX]; size_t plain_len = 0;
    struct market_purchase_private_payload payload;
    struct zcl_result decrypted = market_purchase_payload_decrypt(
        rt, &row, &payload, plain, &plain_len);
    if (!decrypted.ok) {
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return decrypted;
    }
    market_purchase_view_from_row(&row, &payload, out);
    if (row.has_txid) {
        struct file_payment payment;
        struct zcl_result claimed = mp_claim(&row, &payload, &payment);
        if (claimed.ok) {
            out->has_claim = true;
            memcpy(out->claim_id, payment.claim_id, 32);
        }
    }
    struct market_download_record download;
    if (db_market_download_find(rt->node_db, row.plan_id, &download))
        market_purchase_view_add_download(&download, out);
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(&payload, sizeof(payload));
    return ZCL_OK;
}

static struct zcl_result mp_commit_args_check(
    const char *wallet_scope, const uint8_t plan_id[32],
    const struct market_purchase_view *out)
{
    if (!wallet_scope || !plan_id || !out ||
        (strcmp(wallet_scope, "dev") != 0 && strcmp(wallet_scope, "prod") != 0))
        return ZCL_ERR(-40, "explicit wallet scope, plan id, and output are required");
    return ZCL_OK;
}

static struct zcl_result mp_commit_find_row(
    const struct market_purchase_runtime *rt, const char *wallet_scope,
    const uint8_t plan_id[32], struct vault_intent_row *row)
{
    (void)vault_intent_expire_due(rt->node_db, rt->now_unix);
    if (!vault_intent_find(rt->node_db, plan_id, row) ||
        strcmp(row->application_kind, MARKET_PURCHASE_APPLICATION) != 0)
        return ZCL_ERR(-41, "market purchase plan not found");
    if (strcmp(row->wallet_scope, wallet_scope) != 0)
        return ZCL_ERR(-42, "wallet scope does not match purchase plan");
    return ZCL_OK;
}

static bool mp_commit_is_replay(const struct vault_intent_row *row)
{
    return row->has_txid && row->state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
           row->state <= VAULT_INTENT_REORGED;
}

static void mp_commit_set_claim(const struct market_purchase_runtime *rt,
                                struct file_payment *payment,
                                struct market_purchase_view *out)
{
    out->has_claim = true;
    memcpy(out->claim_id, payment->claim_id, 32);
    out->payment_notification_queued = rt->notify
        ? rt->notify(rt->notify_ctx, payment) : false;
}

static struct zcl_result mp_commit_replay(
    const struct market_purchase_runtime *rt,
    const struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    struct market_purchase_view *out)
{
    market_purchase_view_from_row(row, payload, out);
    out->idempotent_replay = true;
    struct file_payment payment;
    struct zcl_result claimed = mp_claim(row, payload, &payment);
    if (claimed.ok)
        mp_commit_set_claim(rt, &payment, out);
    return claimed;
}

static struct zcl_result mp_commit_state_check(
    const struct market_purchase_runtime *rt,
    const struct vault_intent_row *row)
{
    if (row->state == VAULT_INTENT_PROVING)
        return ZCL_ERR(-43, "COMMIT_UNCERTAIN: prior send may have broadcast; reconciliation required");
    if (row->state != VAULT_INTENT_PLANNED || row->expires_at <= rt->now_unix)
        return ZCL_ERR(-44, "purchase plan is not committable");
    return ZCL_OK;
}

static struct zcl_result mp_commit_bind_money(
    const struct market_purchase_runtime *rt, const char *wallet_scope,
    struct vault_intent_row *row, struct wallet_money_snapshot *money)
{
    struct zcl_result current = mp_money_current(rt, wallet_scope, money);
    char genesis[65] = {0};
    if (current.ok)
        wallet_identity_genesis_hex(&money->identity, genesis);
    bool bound = current.ok &&
        strcmp(row->wallet_instance_id, money->identity.wallet_instance_id) == 0 &&
        strcmp(row->wallet_genesis, genesis) == 0 &&
        row->anchor_height == rt->tip_height &&
        memcmp(row->anchor_hash, rt->tip_hash, 32) == 0 &&
        memcmp(row->snapshot_root, money->snapshot_root, 32) == 0;
    if (!bound) {
        (void)vault_intent_set_state(rt->node_db, row->plan_id,
            VAULT_INTENT_CONFLICTED, NULL, "MONEY_SNAPSHOT_CHANGED", rt->now_unix);
        return current.ok ? ZCL_ERR(-45, "wallet identity, tip, or money snapshot changed")
                          : current;
    }
    return ZCL_OK;
}

static struct zcl_result mp_commit_check_contract(
    const struct market_purchase_runtime *rt, struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    const struct wallet_money_snapshot *money)
{
    struct file_offer offer;
    struct zcl_result loaded = mp_offer_load(rt, payload->offer_id, money, &offer);
    int64_t exact = 0;
    bool contract_ok = loaded.ok &&
        file_market_offer_range_zat(&offer, payload->chunk_start,
                                    payload->chunks_paid, &exact) &&
        exact == payload->amount_zat && exact == row->recipient_value_zat &&
        payload->maximum_fee_zat == row->max_fee_zat &&
        rt->maximum_fee_zat == row->max_fee_zat;
    if (!contract_ok) {
        (void)vault_intent_set_state(rt->node_db, row->plan_id,
            VAULT_INTENT_CONFLICTED, NULL, "OFFER_CONTRACT_CHANGED", rt->now_unix);
        return loaded.ok ? ZCL_ERR(-46, "signed offer range or amount changed") : loaded;
    }
    return ZCL_OK;
}

static struct zcl_result mp_commit_broadcast(
    const struct market_purchase_runtime *rt, struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload)
{
    struct zcl_result source = rt->check_source(
        rt->source_ctx, payload->source);
    if (!source.ok)
        return source;
    if (!vault_intent_claim_commit(rt->node_db, row->plan_id, rt->now_unix))
        return ZCL_ERR(-47, "another commit claimed this purchase plan");
    uint8_t txid[32];
    struct zcl_result sent = rt->send(rt->send_ctx, payload->source,
        payload->seller, payload->amount_zat, payload->memo, txid);
    if (!sent.ok) {
        (void)vault_intent_set_state(rt->node_db, row->plan_id,
            VAULT_INTENT_FAILED, NULL, "WALLET_SEND_FAILED", rt->now_unix);
        return sent;
    }
    if (!zcl_bytes_any_set(txid, 32) || !vault_intent_set_state(
            rt->node_db, row->plan_id, VAULT_INTENT_MEMPOOL_ACCEPTED,
            txid, "", rt->now_unix) ||
        !vault_intent_find(rt->node_db, row->plan_id, row))
        return ZCL_ERR(-48, "transaction sent but durable purchase state is uncertain");
    return ZCL_OK;
}

static struct zcl_result mp_commit_finish(
    const struct market_purchase_runtime *rt,
    const struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    struct market_purchase_view *out)
{
    struct file_payment payment;
    struct zcl_result claimed = mp_claim(row, payload, &payment);
    if (!claimed.ok)
        return claimed;
    market_purchase_view_from_row(row, payload, out);
    mp_commit_set_claim(rt, &payment, out);
    return ZCL_OK;
}

static struct zcl_result mp_commit_steps(
    const struct market_purchase_runtime *rt, const char *wallet_scope,
    struct vault_intent_row *row,
    const struct market_purchase_private_payload *payload,
    struct market_purchase_view *out)
{
    if (mp_commit_is_replay(row))
        return mp_commit_replay(rt, row, payload, out);
    ZCL_CHECK(mp_commit_state_check(rt, row));
    struct wallet_money_snapshot money;
    ZCL_CHECK(mp_commit_bind_money(rt, wallet_scope, row, &money));
    ZCL_CHECK(mp_commit_check_contract(rt, row, payload, &money));
    ZCL_CHECK(mp_commit_broadcast(rt, row, payload));
    return mp_commit_finish(rt, row, payload, out);
}

struct zcl_result market_purchase_commit(
    const struct market_purchase_runtime *rt, const char *wallet_scope,
    const uint8_t plan_id[32], struct market_purchase_view *out)
{
    ZCL_CHECK(market_purchase_runtime_validate(rt, true, true));
    ZCL_CHECK(mp_commit_args_check(wallet_scope, plan_id, out));
    struct vault_intent_row row;
    ZCL_CHECK(mp_commit_find_row(rt, wallet_scope, plan_id, &row));
    uint8_t plain[MARKET_PURCHASE_PAYLOAD_MAX]; size_t plain_len = 0;
    struct market_purchase_private_payload payload;
    struct zcl_result decrypted = market_purchase_payload_decrypt(
        rt, &row, &payload, plain, &plain_len);
    if (!decrypted.ok) {
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return decrypted;
    }
    struct zcl_result committed = mp_commit_steps(rt, wallet_scope, &row,
                                                 &payload, out);
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(&payload, sizeof(payload));
    return committed;
}
