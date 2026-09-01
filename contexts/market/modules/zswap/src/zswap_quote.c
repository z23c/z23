/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: zswap_quote.v1 implementation — canonical, domain-separated,
 * exact-binary signed quote wire for atomic ZSLP-token/ZCL P2P swaps. See
 * zswap/zswap_quote.h for the wire layout and semantics. */

#include "zswap/zswap_quote.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t quote_magic[8] = {'Z','S','W','Q','T','E','\r','\n'};

static bool root_nonzero(const uint8_t root[32])
{
    return zcl_bytes_any_set(root, 32);
}

static void put_bytes(uint8_t *wire, size_t *off, const void *src, size_t len)
{
    memcpy(wire + *off, src, len);
    *off += len;
}

static void put_u16(uint8_t *wire, size_t *off, uint16_t value)
{
    zcl_write_u16_le(wire + *off, value);
    *off += 2;
}

static void put_u64(uint8_t *wire, size_t *off, uint64_t value)
{
    zcl_write_u64_le(wire + *off, value);
    *off += 8;
}

static void get_bytes(const uint8_t *wire, size_t *off, void *out, size_t len)
{
    memcpy(out, wire + *off, len);
    *off += len;
}

static uint16_t get_u16(const uint8_t *wire, size_t *off)
{
    uint16_t value = zcl_read_u16_le(wire + *off);
    *off += 2;
    return value;
}

static uint64_t get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

static void quote_root_hash(const char *domain, size_t domain_len,
                            const uint8_t *wire, size_t wire_len,
                            uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
}

const char *zswap_quote_error_string(enum zswap_quote_error error)
{
    switch (error) {
    case ZSWAP_QUOTE_OK: return "ok";
    case ZSWAP_QUOTE_ERR_NULL: return "null-argument";
    case ZSWAP_QUOTE_ERR_VERSION: return "schema-version";
    case ZSWAP_QUOTE_ERR_WIRE_SIZE: return "wire-size";
    case ZSWAP_QUOTE_ERR_WIRE_MAGIC: return "wire-magic";
    case ZSWAP_QUOTE_ERR_ROOT_ZERO: return "root-zero";
    case ZSWAP_QUOTE_ERR_PUBKEY_ZERO: return "pubkey-zero";
    case ZSWAP_QUOTE_ERR_TOKEN_ID_ZERO: return "token-id-zero";
    case ZSWAP_QUOTE_ERR_NONCE: return "nonce-zero";
    case ZSWAP_QUOTE_ERR_AMOUNT: return "amount-zero";
    case ZSWAP_QUOTE_ERR_TIME_ORDER: return "time-order-invalid";
    case ZSWAP_QUOTE_ERR_LIFETIME: return "lifetime-too-long";
    case ZSWAP_QUOTE_ERR_SIGNATURE: return "signature-invalid";
    case ZSWAP_QUOTE_ERR_KEY_MISMATCH: return "key-mismatch";
    case ZSWAP_QUOTE_ERR_NETWORK_MISMATCH: return "network-genesis-mismatch";
    case ZSWAP_QUOTE_ERR_EXPIRED: return "object-expired";
    case ZSWAP_QUOTE_ERR_NOT_YET_VALID: return "not-yet-valid";
    }
    return "unknown";
}

static enum zswap_quote_error quote_fields(const struct zswap_quote_v1 *quote,
                                           bool require_signature)
{
    if (!quote) return ZSWAP_QUOTE_ERR_NULL;
    if (quote->schema_version != ZSWAP_QUOTE_VERSION)
        return ZSWAP_QUOTE_ERR_VERSION;
    if (!root_nonzero(quote->network_genesis_root))
        return ZSWAP_QUOTE_ERR_ROOT_ZERO;
    if (!root_nonzero(quote->seller_pubkey))
        return ZSWAP_QUOTE_ERR_PUBKEY_ZERO;
    if (!root_nonzero(quote->token_id))
        return ZSWAP_QUOTE_ERR_TOKEN_ID_ZERO;
    if (quote->nonce == 0)
        return ZSWAP_QUOTE_ERR_NONCE;
    if (quote->token_amount == 0 || quote->zcl_amount == 0)
        return ZSWAP_QUOTE_ERR_AMOUNT;
    if (quote->issued_unix <= 0 || quote->expires_unix <= quote->issued_unix)
        return ZSWAP_QUOTE_ERR_TIME_ORDER;
    /* A quote is a live for-sale sign with a short fuse: the lifetime
     * cap is structural so seal/encode/decode all refuse a long-lived one. */
    if (quote->expires_unix - quote->issued_unix >
        ZSWAP_QUOTE_MAX_LIFETIME_SECS)
        return ZSWAP_QUOTE_ERR_LIFETIME;
    if (require_signature &&
        !zcl_bytes_any_set(quote->seller_signature,
                       sizeof(quote->seller_signature)))
        return ZSWAP_QUOTE_ERR_SIGNATURE;
    return ZSWAP_QUOTE_OK;
}

enum zswap_quote_error zswap_quote_validate(
    const struct zswap_quote_v1 *quote)
{
    return quote_fields(quote, true);
}

enum zswap_quote_error zswap_quote_validate_at(
    const struct zswap_quote_v1 *quote, int64_t now_unix)
{
    enum zswap_quote_error error = zswap_quote_validate(quote);
    if (error != ZSWAP_QUOTE_OK) return error;
    /* A quote is usable only inside [issued_unix, expires_unix): early use
     * is NOT_YET_VALID, use at or after expiry is EXPIRED. */
    if (now_unix < quote->issued_unix)
        return ZSWAP_QUOTE_ERR_NOT_YET_VALID;
    if (now_unix >= quote->expires_unix)
        return ZSWAP_QUOTE_ERR_EXPIRED;
    return ZSWAP_QUOTE_OK;
}

static enum zswap_quote_error quote_body(
    const struct zswap_quote_v1 *quote,
    uint8_t out[ZSWAP_QUOTE_BODY_BYTES])
{
    enum zswap_quote_error error = quote_fields(quote, false);
    if (error != ZSWAP_QUOTE_OK || !out)
        return out ? error : ZSWAP_QUOTE_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, quote_magic, sizeof(quote_magic));
    put_u16(out, &off, quote->schema_version);
    put_bytes(out, &off, quote->network_genesis_root, 32);
    put_bytes(out, &off, quote->seller_pubkey, 32);
    put_u64(out, &off, quote->nonce);
    put_bytes(out, &off, quote->token_id, 32);
    put_u64(out, &off, quote->token_amount);
    put_u64(out, &off, quote->zcl_amount);
    put_u64(out, &off, (uint64_t)quote->issued_unix);
    put_u64(out, &off, (uint64_t)quote->expires_unix);
    return off == ZSWAP_QUOTE_BODY_BYTES
               ? ZSWAP_QUOTE_OK : ZSWAP_QUOTE_ERR_WIRE_SIZE;
}

enum zswap_quote_error zswap_quote_encode(
    const struct zswap_quote_v1 *quote,
    uint8_t out[ZSWAP_QUOTE_WIRE_BYTES])
{
    enum zswap_quote_error error = zswap_quote_validate(quote);
    if (error != ZSWAP_QUOTE_OK || !out)
        return out ? error : ZSWAP_QUOTE_ERR_NULL;
    error = quote_body(quote, out);
    if (error != ZSWAP_QUOTE_OK) return error;
    memcpy(out + ZSWAP_QUOTE_BODY_BYTES, quote->seller_signature, 64);
    return ZSWAP_QUOTE_OK;
}

enum zswap_quote_error zswap_quote_decode(
    const uint8_t *wire, size_t len, struct zswap_quote_v1 *out)
{
    if (!wire || !out) return ZSWAP_QUOTE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != ZSWAP_QUOTE_WIRE_BYTES)
        return ZSWAP_QUOTE_ERR_WIRE_SIZE;
    if (memcmp(wire, quote_magic, sizeof(quote_magic)) != 0)
        return ZSWAP_QUOTE_ERR_WIRE_MAGIC;
    size_t off = sizeof(quote_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->network_genesis_root, 32);
    get_bytes(wire, &off, out->seller_pubkey, 32);
    out->nonce = get_u64(wire, &off);
    get_bytes(wire, &off, out->token_id, 32);
    out->token_amount = get_u64(wire, &off);
    out->zcl_amount = get_u64(wire, &off);
    out->issued_unix = (int64_t)get_u64(wire, &off);
    out->expires_unix = (int64_t)get_u64(wire, &off);
    get_bytes(wire, &off, out->seller_signature, 64);
    enum zswap_quote_error error = zswap_quote_validate(out);
    if (error != ZSWAP_QUOTE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum zswap_quote_error zswap_quote_body_root(
    const struct zswap_quote_v1 *quote, uint8_t out[32])
{
    uint8_t body[ZSWAP_QUOTE_BODY_BYTES];
    enum zswap_quote_error error = quote_body(quote, body);
    if (error != ZSWAP_QUOTE_OK || !out)
        return out ? error : ZSWAP_QUOTE_ERR_NULL;
    static const char domain[] = ZSWAP_QUOTE_DOMAIN;
    quote_root_hash(domain, sizeof(domain), body, sizeof(body), out);
    return ZSWAP_QUOTE_OK;
}

enum zswap_quote_error zswap_quote_root(
    const struct zswap_quote_v1 *quote, uint8_t out[32])
{
    uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES];
    enum zswap_quote_error error = zswap_quote_encode(quote, wire);
    if (error != ZSWAP_QUOTE_OK || !out)
        return out ? error : ZSWAP_QUOTE_ERR_NULL;
    static const char domain[] = ZSWAP_QUOTE_ROOT_DOMAIN;
    quote_root_hash(domain, sizeof(domain), wire, sizeof(wire), out);
    return ZSWAP_QUOTE_OK;
}

enum zswap_quote_error zswap_quote_seal(
    struct zswap_quote_v1 *quote, const uint8_t seller_secret[32])
{
    if (!quote || !seller_secret)
        return ZSWAP_QUOTE_ERR_NULL;
    if (!root_nonzero(quote->seller_pubkey))
        return ZSWAP_QUOTE_ERR_PUBKEY_ZERO;
    /* The seller public key is re-derived from the supplied secret: a secret
     * that does not produce the claimed pubkey must never seal — the
     * resulting signature would be unverifiable garbage under either key. */
    uint8_t derived_pk[32], derived_sk[32];
    ed25519_keypair(derived_pk, derived_sk, seller_secret);
    if (memcmp(derived_pk, quote->seller_pubkey, 32) != 0)
        return ZSWAP_QUOTE_ERR_KEY_MISMATCH;

    enum zswap_quote_error error = quote_fields(quote, false);
    if (error != ZSWAP_QUOTE_OK) return error;

    uint8_t root[32];
    error = zswap_quote_body_root(quote, root);
    if (error != ZSWAP_QUOTE_OK) return error;

    ed25519_sign(quote->seller_signature, root, sizeof(root), seller_secret,
                 quote->seller_pubkey);
    return ZSWAP_QUOTE_OK;
}

enum zswap_quote_error zswap_quote_verify_at(
    const struct zswap_quote_v1 *quote,
    const uint8_t expected_network_genesis[32], int64_t now_unix)
{
    enum zswap_quote_error error = zswap_quote_validate_at(quote, now_unix);
    if (error != ZSWAP_QUOTE_OK) return error;
    if (!expected_network_genesis ||
        memcmp(quote->network_genesis_root, expected_network_genesis,
               32) != 0)
        return ZSWAP_QUOTE_ERR_NETWORK_MISMATCH;

    uint8_t root[32];
    error = zswap_quote_body_root(quote, root);
    if (error != ZSWAP_QUOTE_OK) return error;
    if (!ed25519_verify(quote->seller_signature, root, sizeof(root),
                        quote->seller_pubkey))
        return ZSWAP_QUOTE_ERR_SIGNATURE;
    return ZSWAP_QUOTE_OK;
}
