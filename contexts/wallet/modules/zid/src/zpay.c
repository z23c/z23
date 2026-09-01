/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: encode, decode, and authenticate bounded ZPAY Sapling memos. */

#include "zid/zpay.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <string.h>

#define ZPAY_FLAG_IDENTITY 0x01u
#define ZPAY_FLAG_REPLY    0x02u
#define ZPAY_FLAGS_KNOWN   (ZPAY_FLAG_IDENTITY | ZPAY_FLAG_REPLY)
#define ZPAY_FIXED_PREFIX  91u
#define ZPAY_TRAILER       64u
#define ZPAY_ID_BODY_LEN   36u
#define ZPAY_ID_DOC_LEN    (51u + ZPAY_ID_BODY_LEN + 64u)

static bool zpay_network_valid(uint8_t network)
{
    return network <= ZPAY_NETWORK_REGTEST;
}

static bool zpay_type_valid(uint8_t type)
{
    return type >= ZPAY_MESSAGE_INVOICE && type <= ZPAY_MESSAGE_RECEIPT;
}

static bool zpay_asset_valid(const char *asset, size_t len)
{
    if (!asset || len == 0 || len > ZPAY_ASSET_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)asset[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == ':' || c == '-' || c == '_'))
            return false;
    }
    return true;
}

static void zpay_prefix_digest(uint8_t out[32], const uint8_t *memo,
                               size_t prefix_len)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"ZPAY-envelope-v1", 16);
    sha3_256_write(&ctx, memo, prefix_len);
    sha3_256_finalize(&ctx, out);
}

static bool zpay_prefix_encode(uint8_t out[ZPAY_MEMO_LEN],
                               const struct zpay_envelope *e,
                               bool with_identity, size_t *prefix_len_out)
{
    size_t asset_len = strnlen(e->asset, ZPAY_ASSET_MAX + 1);
    if (!zpay_network_valid(e->network) || !zpay_type_valid(e->message_type) ||
        e->expires_at <= e->created_at ||
        !zpay_asset_valid(e->asset, asset_len))
        return false;

    size_t prefix_len = ZPAY_FIXED_PREFIX + asset_len + ZPAY_TRAILER;
    size_t total_len = prefix_len + (with_identity ? ZPAY_ID_DOC_LEN : 0u);
    if (total_len > ZPAY_MEMO_LEN)
        return false;

    memset(out, ZPAY_PAD_BYTE, ZPAY_MEMO_LEN);
    memcpy(out, "ZPAY", 4);
    out[4] = ZPAY_VERSION;
    out[5] = e->network;
    out[6] = e->message_type;
    out[7] = (with_identity ? ZPAY_FLAG_IDENTITY : 0u) |
             (e->has_reply ? ZPAY_FLAG_REPLY : 0u);
    zcl_write_u16_le(out + 8, (uint16_t)total_len);
    zcl_write_u64_le(out + 10, e->created_at);
    zcl_write_u64_le(out + 18, e->expires_at);
    memcpy(out + 26, e->nonce, 16);
    memcpy(out + 42, e->request_id, 16);
    memcpy(out + 58, e->invoice_digest, 32);
    out[90] = (uint8_t)asset_len;
    memcpy(out + ZPAY_FIXED_PREFIX, e->asset, asset_len);
    size_t off = ZPAY_FIXED_PREFIX + asset_len;
    memcpy(out + off, e->amount_commitment, 32);
    if (e->has_reply)
        memcpy(out + off + 32, e->reply_ref, 32);
    else
        memset(out + off + 32, 0, 32);
    *prefix_len_out = prefix_len;
    return true;
}

bool zpay_memo_encode(uint8_t out[ZPAY_MEMO_LEN],
                      const struct zpay_envelope *e,
                      const uint8_t zid_seed[32])
{
    if (!out || !e)
        LOG_FAIL("zpay", "memo_encode: NULL argument");

    uint8_t memo[ZPAY_MEMO_LEN];
    size_t prefix_len = 0;
    if (!zpay_prefix_encode(memo, e, zid_seed != NULL, &prefix_len))
        LOG_FAIL("zpay", "memo_encode: invalid envelope fields");

    if (zid_seed) {
        uint8_t body[ZPAY_ID_BODY_LEN];
        memcpy(body, "ZPAY", 4);
        zpay_prefix_digest(body + 4, memo, prefix_len);
        struct zid_doc doc;
        if (!zid_doc_sign(&doc, body, sizeof(body), e->created_at,
                          e->expires_at, zid_seed))
            LOG_FAIL("zpay", "memo_encode: identity signing failed");
        size_t written = zid_doc_encode(memo + prefix_len,
                                        ZPAY_MEMO_LEN - prefix_len, &doc);
        if (written != ZPAY_ID_DOC_LEN)
            LOG_FAIL("zpay", "memo_encode: identity encoding failed");
    }

    memcpy(out, memo, sizeof(memo));
    return true;
}

bool zpay_memo_decode(const uint8_t memo[ZPAY_MEMO_LEN],
                      struct zpay_envelope *out)
{
    if (!memo || !out)
        LOG_FAIL("zpay", "memo_decode: NULL argument");
    memset(out, 0, sizeof(*out));

    if (memcmp(memo, "ZPAY", 4) != 0 || memo[4] != ZPAY_VERSION ||
        !zpay_network_valid(memo[5]) || !zpay_type_valid(memo[6]) ||
        (memo[7] & ~(uint8_t)ZPAY_FLAGS_KNOWN) != 0)
        return false;

    uint16_t total_len = zcl_read_u16_le(memo + 8);
    uint8_t asset_len = memo[90];
    size_t prefix_len = ZPAY_FIXED_PREFIX + (size_t)asset_len + ZPAY_TRAILER;
    bool has_identity = (memo[7] & ZPAY_FLAG_IDENTITY) != 0;
    size_t expected_len = prefix_len + (has_identity ? ZPAY_ID_DOC_LEN : 0u);
    if (asset_len == 0 || asset_len > ZPAY_ASSET_MAX ||
        expected_len > ZPAY_MEMO_LEN || total_len != expected_len ||
        !zpay_asset_valid((const char *)memo + ZPAY_FIXED_PREFIX, asset_len))
        return false;
    for (size_t i = total_len; i < ZPAY_MEMO_LEN; i++)
        if (memo[i] != ZPAY_PAD_BYTE)
            return false;

    out->network = memo[5];
    out->message_type = memo[6];
    out->created_at = zcl_read_u64_le(memo + 10);
    out->expires_at = zcl_read_u64_le(memo + 18);
    if (out->expires_at <= out->created_at)
        return false;
    memcpy(out->nonce, memo + 26, 16);
    memcpy(out->request_id, memo + 42, 16);
    memcpy(out->invoice_digest, memo + 58, 32);
    memcpy(out->asset, memo + ZPAY_FIXED_PREFIX, asset_len);
    out->asset[asset_len] = '\0';
    size_t off = ZPAY_FIXED_PREFIX + asset_len;
    memcpy(out->amount_commitment, memo + off, 32);
    out->has_reply = (memo[7] & ZPAY_FLAG_REPLY) != 0;
    memcpy(out->reply_ref, memo + off + 32, 32);
    if (!out->has_reply) {
        uint8_t zero[32] = {0};
        if (memcmp(out->reply_ref, zero, sizeof(zero)) != 0)
            return false;
    }

    out->sender_authentication = ZPAY_SENDER_ANONYMOUS;
    out->has_identity_doc = has_identity;
    if (has_identity &&
        !zid_doc_decode(&out->identity_doc, memo + prefix_len,
                        ZPAY_ID_DOC_LEN))
        return false;
    return true;
}

enum zpay_sender_authentication
zpay_memo_authenticate(const uint8_t memo[ZPAY_MEMO_LEN], uint64_t now_unix,
                       struct zpay_envelope *decoded_out)
{
    struct zpay_envelope local;
    struct zpay_envelope *e = decoded_out ? decoded_out : &local;
    if (!zpay_memo_decode(memo, e))
        return ZPAY_SENDER_ZID_INVALID;
    if (!e->has_identity_doc)
        return ZPAY_SENDER_ANONYMOUS;

    size_t asset_len = strlen(e->asset);
    size_t prefix_len = ZPAY_FIXED_PREFIX + asset_len + ZPAY_TRAILER;
    uint8_t digest[32];
    zpay_prefix_digest(digest, memo, prefix_len);
    bool binding_ok = e->identity_doc.body_len == ZPAY_ID_BODY_LEN &&
                      memcmp(e->identity_doc.body, "ZPAY", 4) == 0 &&
                      memcmp(e->identity_doc.body + 4, digest, 32) == 0;
    bool signature_ok = binding_ok && zid_doc_verify(&e->identity_doc, now_unix);
    e->sender_authentication = signature_ok ? ZPAY_SENDER_ZID_VERIFIED :
                                             ZPAY_SENDER_ZID_INVALID;
    return e->sender_authentication;
}

bool zpay_envelope_is_current(const struct zpay_envelope *e,
                              uint8_t expected_network, uint64_t now_unix)
{
    if (!e || !zpay_network_valid(expected_network))
        return false;
    return e->network == expected_network && e->created_at <= now_unix &&
           now_unix < e->expires_at;
}
