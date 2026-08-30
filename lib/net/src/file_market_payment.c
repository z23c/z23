/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact buyer-signed zfilepay.v1 claim and Sapling memo contracts.
 * A claim is only a locator; app/services reconciles it against confirmed,
 * canonical wallet-note and chain authorities before any byte is unlocked. */

#include "net/file_market.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "core/amount.h"
#include "core/serialize.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "support/cleanse.h"

#include <limits.h>
#include <string.h>

static const uint8_t k_payment_magic[8] =
    {'Z','F','M','P','A','Y','\r','\n'};
static const uint8_t k_payment_memo_magic[8] =
    {'Z','F','M','P','A','Y','M','1'};
static const char k_payment_body_domain[] = "zcl.file.market.payment.v1";
static const char k_payment_id_domain[] = "zcl.file.market.payment.id.v1";

static void payment_put_bytes(uint8_t *wire, size_t *off,
                              const void *src, size_t len)
{
    memcpy(wire + *off, src, len);
    *off += len;
}

static void payment_put_u16(uint8_t *wire, size_t *off, uint16_t value)
{
    zcl_write_u16_le(wire + *off, value);
    *off += 2;
}

static void payment_put_u32(uint8_t *wire, size_t *off, uint32_t value)
{
    zcl_write_u32_le(wire + *off, value);
    *off += 4;
}

static void payment_put_u64(uint8_t *wire, size_t *off, uint64_t value)
{
    zcl_write_u64_le(wire + *off, value);
    *off += 8;
}

static void payment_get_bytes(const uint8_t *wire, size_t *off,
                              void *out, size_t len)
{
    memcpy(out, wire + *off, len);
    *off += len;
}

static uint16_t payment_get_u16(const uint8_t *wire, size_t *off)
{
    uint16_t value = zcl_read_u16_le(wire + *off);
    *off += 2;
    return value;
}

static uint32_t payment_get_u32(const uint8_t *wire, size_t *off)
{
    uint32_t value = zcl_read_u32_le(wire + *off);
    *off += 4;
    return value;
}

static uint64_t payment_get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

static void payment_domain_hash(const char *domain, size_t domain_len,
                                const uint8_t *wire, size_t wire_len,
                                uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
}

const char *file_payment_auth_error_string(
    enum file_payment_auth_error error)
{
    switch (error) {
    case FILE_PAYMENT_AUTH_OK: return "ok";
    case FILE_PAYMENT_AUTH_ERR_NULL: return "null-argument";
    case FILE_PAYMENT_AUTH_ERR_VERSION: return "schema-version";
    case FILE_PAYMENT_AUTH_ERR_WIRE_SIZE: return "wire-size";
    case FILE_PAYMENT_AUTH_ERR_WIRE_MAGIC: return "wire-magic";
    case FILE_PAYMENT_AUTH_ERR_NETWORK: return "network-genesis-zero";
    case FILE_PAYMENT_AUTH_ERR_OFFER_ID: return "offer-id-zero";
    case FILE_PAYMENT_AUTH_ERR_TXID: return "txid-zero";
    case FILE_PAYMENT_AUTH_ERR_RANGE: return "chunk-range-invalid";
    case FILE_PAYMENT_AUTH_ERR_AMOUNT: return "amount-invalid";
    case FILE_PAYMENT_AUTH_ERR_BUYER_KEY: return "buyer-key-zero";
    case FILE_PAYMENT_AUTH_ERR_SIGNATURE: return "signature-invalid";
    case FILE_PAYMENT_AUTH_ERR_KEY_MISMATCH: return "buyer-key-mismatch";
    case FILE_PAYMENT_AUTH_ERR_CLAIM_ID: return "claim-id-mismatch";
    case FILE_PAYMENT_AUTH_ERR_NETWORK_MISMATCH: return "network-mismatch";
    case FILE_PAYMENT_AUTH_ERR_OFFER_MISMATCH: return "offer-mismatch";
    case FILE_PAYMENT_AUTH_ERR_MEMO: return "memo-mismatch";
    }
    return "unknown";
}

static enum file_payment_auth_error payment_fields(
    const struct file_payment *payment, bool require_signature)
{
    if (!payment)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    if (payment->version != FILE_MARKET_PAYMENT_VERSION)
        return FILE_PAYMENT_AUTH_ERR_VERSION;
    if (!zcl_bytes_any_set(payment->network_genesis, 32))
        return FILE_PAYMENT_AUTH_ERR_NETWORK;
    if (!zcl_bytes_any_set(payment->offer_id, 32))
        return FILE_PAYMENT_AUTH_ERR_OFFER_ID;
    if (!zcl_bytes_any_set(payment->txid, 32))
        return FILE_PAYMENT_AUTH_ERR_TXID;
    if (payment->chunks_paid == 0 ||
        payment->chunks_paid > UINT32_MAX - payment->chunk_start)
        return FILE_PAYMENT_AUTH_ERR_RANGE;
    if (payment->amount_zat <= 0 || payment->amount_zat > MAX_MONEY)
        return FILE_PAYMENT_AUTH_ERR_AMOUNT;
    if (!zcl_bytes_any_set(payment->buyer_pubkey, 32))
        return FILE_PAYMENT_AUTH_ERR_BUYER_KEY;
    if (require_signature &&
        !zcl_bytes_any_set(payment->buyer_signature, 64))
        return FILE_PAYMENT_AUTH_ERR_SIGNATURE;
    return FILE_PAYMENT_AUTH_OK;
}

static enum file_payment_auth_error payment_body(
    const struct file_payment *payment,
    uint8_t out[FILE_MARKET_PAYMENT_BODY_BYTES])
{
    if (!out)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    enum file_payment_auth_error error = payment_fields(payment, false);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;

    size_t off = 0;
    payment_put_bytes(out, &off, k_payment_magic, sizeof(k_payment_magic));
    payment_put_u16(out, &off, payment->version);
    payment_put_bytes(out, &off, payment->network_genesis, 32);
    payment_put_bytes(out, &off, payment->offer_id, 32);
    payment_put_bytes(out, &off, payment->txid, 32);
    payment_put_u32(out, &off, payment->chunk_start);
    payment_put_u32(out, &off, payment->chunks_paid);
    payment_put_u64(out, &off, (uint64_t)payment->amount_zat);
    payment_put_bytes(out, &off, payment->buyer_pubkey, 32);
    return off == FILE_MARKET_PAYMENT_BODY_BYTES
        ? FILE_PAYMENT_AUTH_OK : FILE_PAYMENT_AUTH_ERR_WIRE_SIZE;
}

enum file_payment_auth_error file_payment_auth_encode(
    const struct file_payment *payment,
    uint8_t out[FILE_MARKET_PAYMENT_WIRE_BYTES])
{
    if (!out)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    enum file_payment_auth_error error = payment_fields(payment, true);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    error = payment_body(payment, out);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    memcpy(out + FILE_MARKET_PAYMENT_BODY_BYTES,
           payment->buyer_signature, 64);
    return FILE_PAYMENT_AUTH_OK;
}

enum file_payment_auth_error file_payment_auth_decode(
    const uint8_t *wire, size_t wire_len, struct file_payment *out)
{
    if (!wire || !out)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != FILE_MARKET_PAYMENT_WIRE_BYTES)
        return FILE_PAYMENT_AUTH_ERR_WIRE_SIZE;
    if (memcmp(wire, k_payment_magic, sizeof(k_payment_magic)) != 0)
        return FILE_PAYMENT_AUTH_ERR_WIRE_MAGIC;

    size_t off = sizeof(k_payment_magic);
    out->version = payment_get_u16(wire, &off);
    payment_get_bytes(wire, &off, out->network_genesis, 32);
    payment_get_bytes(wire, &off, out->offer_id, 32);
    payment_get_bytes(wire, &off, out->txid, 32);
    out->chunk_start = payment_get_u32(wire, &off);
    out->chunks_paid = payment_get_u32(wire, &off);
    out->amount_zat = (int64_t)payment_get_u64(wire, &off);
    payment_get_bytes(wire, &off, out->buyer_pubkey, 32);
    payment_get_bytes(wire, &off, out->buyer_signature, 64);
    if (off != FILE_MARKET_PAYMENT_WIRE_BYTES) {
        memset(out, 0, sizeof(*out));
        return FILE_PAYMENT_AUTH_ERR_WIRE_SIZE;
    }
    enum file_payment_auth_error error = payment_fields(out, true);
    if (error == FILE_PAYMENT_AUTH_OK)
        error = file_payment_auth_claim_id(out, out->claim_id);
    if (error != FILE_PAYMENT_AUTH_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum file_payment_auth_error file_payment_auth_body_root(
    const struct file_payment *payment, uint8_t out[32])
{
    uint8_t body[FILE_MARKET_PAYMENT_BODY_BYTES];
    if (!out)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    enum file_payment_auth_error error = payment_body(payment, body);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    payment_domain_hash(k_payment_body_domain, sizeof(k_payment_body_domain),
                        body, sizeof(body), out);
    return FILE_PAYMENT_AUTH_OK;
}

enum file_payment_auth_error file_payment_auth_claim_id(
    const struct file_payment *payment, uint8_t out[32])
{
    uint8_t wire[FILE_MARKET_PAYMENT_WIRE_BYTES];
    if (!out)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    enum file_payment_auth_error error = file_payment_auth_encode(payment,
                                                                   wire);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    payment_domain_hash(k_payment_id_domain, sizeof(k_payment_id_domain),
                        wire, sizeof(wire), out);
    return FILE_PAYMENT_AUTH_OK;
}

enum file_payment_auth_error file_payment_auth_seal(
    struct file_payment *payment, const uint8_t buyer_seed[32])
{
    uint8_t derived_pk[32], secret_copy[32], root[32];
    if (!payment || !buyer_seed)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    ed25519_keypair(derived_pk, secret_copy, buyer_seed);
    if (memcmp(derived_pk, payment->buyer_pubkey, 32) != 0) {
        memory_cleanse(secret_copy, sizeof(secret_copy));
        return FILE_PAYMENT_AUTH_ERR_KEY_MISMATCH;
    }
    enum file_payment_auth_error error = payment_fields(payment, false);
    if (error == FILE_PAYMENT_AUTH_OK)
        error = file_payment_auth_body_root(payment, root);
    if (error == FILE_PAYMENT_AUTH_OK) {
        ed25519_sign(payment->buyer_signature, root, sizeof(root), buyer_seed,
                     payment->buyer_pubkey);
        error = file_payment_auth_claim_id(payment, payment->claim_id);
    }
    memory_cleanse(secret_copy, sizeof(secret_copy));
    memory_cleanse(root, sizeof(root));
    return error;
}

enum file_payment_auth_error file_payment_auth_verify(
    const struct file_payment *payment,
    const uint8_t expected_network_genesis[32])
{
    uint8_t root[32], expected_id[32];
    enum file_payment_auth_error error = payment_fields(payment, true);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    if (!expected_network_genesis ||
        memcmp(payment->network_genesis, expected_network_genesis, 32) != 0)
        return FILE_PAYMENT_AUTH_ERR_NETWORK_MISMATCH;
    error = file_payment_auth_body_root(payment, root);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    bool signature_ok = ed25519_verify(payment->buyer_signature, root,
                                       sizeof(root), payment->buyer_pubkey);
    memory_cleanse(root, sizeof(root));
    if (!signature_ok)
        return FILE_PAYMENT_AUTH_ERR_SIGNATURE;
    error = file_payment_auth_claim_id(payment, expected_id);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    return zcl_bytes_any_set(payment->claim_id, 32) &&
           memcmp(expected_id, payment->claim_id, 32) == 0
        ? FILE_PAYMENT_AUTH_OK : FILE_PAYMENT_AUTH_ERR_CLAIM_ID;
}

enum file_payment_auth_error file_payment_auth_verify_for_offer(
    const struct file_payment *payment, const struct file_offer *offer)
{
    if (!payment || !offer)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    if (file_offer_auth_validate(offer) != FILE_OFFER_AUTH_OK ||
        file_offer_auth_verify_signature(offer) != FILE_OFFER_AUTH_OK)
        return FILE_PAYMENT_AUTH_ERR_OFFER_MISMATCH;
    enum file_payment_auth_error error = file_payment_auth_verify(
        payment, offer->network_genesis);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    uint8_t offer_id[32];
    if (file_offer_auth_offer_id(offer, offer_id) != FILE_OFFER_AUTH_OK ||
        memcmp(payment->offer_id, offer_id, 32) != 0)
        return FILE_PAYMENT_AUTH_ERR_OFFER_MISMATCH;
    int64_t exact_amount = 0;
    if (!file_market_offer_range_zat(offer, payment->chunk_start,
                                     payment->chunks_paid, &exact_amount))
        return FILE_PAYMENT_AUTH_ERR_RANGE;
    return payment->amount_zat == exact_amount
        ? FILE_PAYMENT_AUTH_OK : FILE_PAYMENT_AUTH_ERR_AMOUNT;
}

enum file_payment_auth_error file_payment_memo_encode(
    const struct file_payment *payment,
    uint8_t out[FILE_MARKET_PAYMENT_MEMO_BYTES])
{
    if (!out)
        return FILE_PAYMENT_AUTH_ERR_NULL;
    enum file_payment_auth_error error = payment_fields(payment, false);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    memset(out, 0, FILE_MARKET_PAYMENT_MEMO_BYTES);
    size_t off = 0;
    payment_put_bytes(out, &off, k_payment_memo_magic,
                      sizeof(k_payment_memo_magic));
    payment_put_bytes(out, &off, payment->network_genesis, 32);
    payment_put_bytes(out, &off, payment->offer_id, 32);
    payment_put_u32(out, &off, payment->chunk_start);
    payment_put_u32(out, &off, payment->chunks_paid);
    payment_put_u64(out, &off, (uint64_t)payment->amount_zat);
    payment_put_bytes(out, &off, payment->buyer_pubkey, 32);
    return off == FILE_MARKET_PAYMENT_MEMO_BODY_BYTES
        ? FILE_PAYMENT_AUTH_OK : FILE_PAYMENT_AUTH_ERR_MEMO;
}

enum file_payment_auth_error file_payment_memo_verify(
    const struct file_payment *payment, const uint8_t *memo, size_t memo_len)
{
    uint8_t expected[FILE_MARKET_PAYMENT_MEMO_BYTES];
    if (!memo || memo_len != sizeof(expected))
        return FILE_PAYMENT_AUTH_ERR_MEMO;
    enum file_payment_auth_error error = file_payment_memo_encode(payment,
                                                                   expected);
    if (error != FILE_PAYMENT_AUTH_OK)
        return error;
    return memcmp(expected, memo, sizeof(expected)) == 0
        ? FILE_PAYMENT_AUTH_OK : FILE_PAYMENT_AUTH_ERR_MEMO;
}

bool file_payment_serialize(const struct file_payment *payment,
                            struct byte_stream *stream)
{
    uint8_t wire[FILE_MARKET_PAYMENT_WIRE_BYTES];
    if (!stream || file_payment_auth_encode(payment, wire) !=
                       FILE_PAYMENT_AUTH_OK)
        return false;
    return stream_write(stream, wire, sizeof(wire));
}

bool file_payment_deserialize(struct file_payment *payment,
                              struct byte_stream *stream)
{
    uint8_t wire[FILE_MARKET_PAYMENT_WIRE_BYTES];
    if (!payment || !stream || stream_remaining(stream) != sizeof(wire) ||
        !stream_read(stream, wire, sizeof(wire)))
        return false;
    return file_payment_auth_decode(wire, sizeof(wire), payment) ==
           FILE_PAYMENT_AUTH_OK;
}
