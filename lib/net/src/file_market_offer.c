/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical, seller-signed, network-bound paid file-offer contract.
 * Legacy zfilelist offers remain usable only for free ROM artifacts; every
 * paid offer entering the market uses this exact wire and verification path. */

#include "net/file_market.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "core/amount.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "sapling/sapling.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

static const uint8_t k_offer_magic[8] = {'Z','F','M','O','F','F','\r','\n'};
static const char k_body_domain[] = "zcl.file.market.offer.v1";
static const char k_id_domain[] = "zcl.file.market.offer.id.v1";

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

static void put_u32(uint8_t *wire, size_t *off, uint32_t value)
{
    zcl_write_u32_le(wire + *off, value);
    *off += 4;
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

static uint32_t get_u32(const uint8_t *wire, size_t *off)
{
    uint32_t value = zcl_read_u32_le(wire + *off);
    *off += 4;
    return value;
}

static uint64_t get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

static void domain_hash(const char *domain, size_t domain_len,
                        const uint8_t *wire, size_t wire_len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
}

const char *file_offer_auth_error_string(enum file_offer_auth_error error)
{
    switch (error) {
    case FILE_OFFER_AUTH_OK: return "ok";
    case FILE_OFFER_AUTH_ERR_NULL: return "null-argument";
    case FILE_OFFER_AUTH_ERR_VERSION: return "schema-version";
    case FILE_OFFER_AUTH_ERR_WIRE_SIZE: return "wire-size";
    case FILE_OFFER_AUTH_ERR_WIRE_MAGIC: return "wire-magic";
    case FILE_OFFER_AUTH_ERR_NETWORK: return "network-genesis-zero";
    case FILE_OFFER_AUTH_ERR_CONTENT_ROOT: return "content-root-zero";
    case FILE_OFFER_AUTH_ERR_SELLER_KEY: return "seller-key-zero";
    case FILE_OFFER_AUTH_ERR_NONCE: return "nonce-invalid";
    case FILE_OFFER_AUTH_ERR_FILENAME: return "filename-invalid";
    case FILE_OFFER_AUTH_ERR_SIZE: return "size-invalid";
    case FILE_OFFER_AUTH_ERR_CHUNKS: return "chunk-count-invalid";
    case FILE_OFFER_AUTH_ERR_PRICE: return "price-invalid";
    case FILE_OFFER_AUTH_ERR_TOTAL_PRICE: return "total-price-invalid";
    case FILE_OFFER_AUTH_ERR_PAYMENT_ADDRESS: return "payment-address-zero";
    case FILE_OFFER_AUTH_ERR_ENDPOINT: return "endpoint-invalid";
    case FILE_OFFER_AUTH_ERR_TIME: return "time-order-invalid";
    case FILE_OFFER_AUTH_ERR_LIFETIME: return "lifetime-too-long";
    case FILE_OFFER_AUTH_ERR_SIGNATURE: return "signature-invalid";
    case FILE_OFFER_AUTH_ERR_KEY_MISMATCH: return "seller-key-mismatch";
    case FILE_OFFER_AUTH_ERR_NETWORK_MISMATCH: return "network-mismatch";
    case FILE_OFFER_AUTH_ERR_EXPIRED: return "offer-expired";
    case FILE_OFFER_AUTH_ERR_NOT_YET_VALID: return "offer-not-yet-valid";
    }
    return "unknown";
}

static bool price_for_bytes(uint64_t size_bytes, int64_t price_per_mb,
                            int64_t *out_total_zat)
{
    static const uint64_t bytes_per_mb = 1024u * 1024u;
    if (!out_total_zat || size_bytes == 0 || price_per_mb <= 0)
        return false;
    uint64_t price = (uint64_t)price_per_mb;
    uint64_t whole_mb = size_bytes / bytes_per_mb;
    uint64_t remaining_bytes = size_bytes % bytes_per_mb;
    if (whole_mb != 0 && price > (uint64_t)MAX_MONEY / whole_mb)
        return false;
    uint64_t total = whole_mb * price;

    /* remaining_bytes and the price remainder are each < 1 MiB, so their
     * product fits u64. The other product is < price and also fits u64. */
    uint64_t price_whole = price / bytes_per_mb;
    uint64_t price_remainder = price % bytes_per_mb;
    uint64_t remainder_total = remaining_bytes * price_whole;
    uint64_t fractional_numerator = remaining_bytes * price_remainder;
    remainder_total += (fractional_numerator + bytes_per_mb - 1u) /
                       bytes_per_mb;
    if (remainder_total > (uint64_t)MAX_MONEY - total)
        return false;
    total += remainder_total;
    if (total == 0)
        return false;
    *out_total_zat = (int64_t)total;
    return true;
}

bool file_market_offer_total_zat(const struct file_offer *offer,
                                 int64_t *out_total_zat)
{
    return offer && price_for_bytes(offer->size_bytes,
                                    offer->price_per_mb, out_total_zat);
}

bool file_market_offer_range_zat(const struct file_offer *offer,
                                 uint32_t chunk_start,
                                 uint32_t chunks_paid,
                                 int64_t *out_total_zat)
{
    if (!offer || !out_total_zat || chunks_paid == 0 ||
        chunk_start >= offer->num_chunks ||
        chunks_paid > offer->num_chunks - chunk_start)
        return false;

    uint64_t start = (uint64_t)chunk_start * FILE_MARKET_CHUNK_SIZE;
    uint64_t end_chunk = (uint64_t)chunk_start + chunks_paid;
    uint64_t end = end_chunk * FILE_MARKET_CHUNK_SIZE;
    if (start >= offer->size_bytes)
        return false;
    if (end > offer->size_bytes)
        end = offer->size_bytes;
    return price_for_bytes(end - start, offer->price_per_mb,
                           out_total_zat);
}

bool file_offer_auth_version_supported(uint16_t version)
{
    return version == FILE_MARKET_OFFER_VERSION ||
           version == FILE_MARKET_OFFER_VERSION_V2;
}

size_t file_offer_auth_wire_size(uint16_t version)
{
    if (version == FILE_MARKET_OFFER_VERSION)
        return FILE_MARKET_OFFER_WIRE_BYTES;
    if (version == FILE_MARKET_OFFER_VERSION_V2)
        return FILE_MARKET_OFFER_WIRE_BYTES_V2;
    return 0;
}

static size_t offer_body_size(uint16_t version)
{
    if (version == FILE_MARKET_OFFER_VERSION)
        return FILE_MARKET_OFFER_BODY_BYTES;
    if (version == FILE_MARKET_OFFER_VERSION_V2)
        return FILE_MARKET_OFFER_BODY_BYTES_V2;
    return 0;
}

static bool bytes_all_zero(const uint8_t *bytes, size_t len)
{
    return !zcl_bytes_any_set(bytes, len);
}

/* The endpoint half of field validation. v1 wires carry only the clearnet
 * pair; v2 makes the kind explicit and requires the unused half to be
 * zeroed so one signed meaning has exactly one encoding. */
static enum file_offer_auth_error offer_endpoint_fields(
    const struct file_offer *offer)
{
    if (offer->auth_version == FILE_MARKET_OFFER_VERSION)
        return zcl_bytes_any_set(offer->peer_ip, sizeof(offer->peer_ip)) &&
                   offer->peer_port != 0
                   ? FILE_OFFER_AUTH_OK : FILE_OFFER_AUTH_ERR_ENDPOINT;
    /* v2 */
    if (offer->endpoint_type == FILE_MARKET_ENDPOINT_CLEARNET)
        return zcl_bytes_any_set(offer->peer_ip, sizeof(offer->peer_ip)) &&
                   offer->peer_port != 0 &&
                   bytes_all_zero(offer->onion_pubkey,
                                  sizeof(offer->onion_pubkey))
                   ? FILE_OFFER_AUTH_OK : FILE_OFFER_AUTH_ERR_ENDPOINT;
    if (offer->endpoint_type == FILE_MARKET_ENDPOINT_ONION)
        return zcl_bytes_any_set(offer->onion_pubkey,
                             sizeof(offer->onion_pubkey)) &&
                   bytes_all_zero(offer->peer_ip, sizeof(offer->peer_ip)) &&
                   offer->peer_port == 0
                   ? FILE_OFFER_AUTH_OK : FILE_OFFER_AUTH_ERR_ENDPOINT;
    return FILE_OFFER_AUTH_ERR_ENDPOINT;
}

static enum file_offer_auth_error offer_fields(const struct file_offer *offer,
                                                bool require_signature)
{
    struct jub_point payment_key;
    int64_t total_price_zat;
    uint32_t expected_chunks = 0;
    size_t name_len;
    if (!offer)
        return FILE_OFFER_AUTH_ERR_NULL;
    if (!file_offer_auth_version_supported(offer->auth_version))
        return FILE_OFFER_AUTH_ERR_VERSION;
    if (!zcl_bytes_any_set(offer->network_genesis, 32))
        return FILE_OFFER_AUTH_ERR_NETWORK;
    if (!zcl_bytes_any_set(offer->root_hash, 32))
        return FILE_OFFER_AUTH_ERR_CONTENT_ROOT;
    if (!zcl_bytes_any_set(offer->seller_pubkey, 32))
        return FILE_OFFER_AUTH_ERR_SELLER_KEY;
    if (offer->nonce == 0 || offer->nonce > (uint64_t)INT64_MAX)
        return FILE_OFFER_AUTH_ERR_NONCE;
    name_len = strnlen(offer->filename, sizeof(offer->filename));
    if (name_len == 0 || name_len > 255)
        return FILE_OFFER_AUTH_ERR_FILENAME;
    if (offer->size_bytes == 0 || offer->size_bytes > (uint64_t)INT64_MAX)
        return FILE_OFFER_AUTH_ERR_SIZE;
    if (!file_market_num_chunks_for_size(offer->size_bytes,
                                         &expected_chunks) ||
        expected_chunks == 0 || offer->num_chunks != expected_chunks)
        return FILE_OFFER_AUTH_ERR_CHUNKS;
    if (offer->price_per_mb <= 0)
        return FILE_OFFER_AUTH_ERR_PRICE;
    if (!file_market_offer_total_zat(offer, &total_price_zat))
        return FILE_OFFER_AUTH_ERR_TOTAL_PRICE;
    if (!sapling_check_diversifier(offer->z_addr) ||
        !jub_from_bytes(&payment_key, offer->z_addr + 11) ||
        jub_is_identity(&payment_key))
        return FILE_OFFER_AUTH_ERR_PAYMENT_ADDRESS;
    enum file_offer_auth_error endpoint = offer_endpoint_fields(offer);
    if (endpoint != FILE_OFFER_AUTH_OK)
        return endpoint;
    if (offer->issued_unix <= 0 || offer->expires_unix <= offer->issued_unix)
        return FILE_OFFER_AUTH_ERR_TIME;
    if (offer->expires_unix - offer->issued_unix >
        FILE_MARKET_OFFER_MAX_LIFETIME_SECS)
        return FILE_OFFER_AUTH_ERR_LIFETIME;
    if (require_signature &&
        !zcl_bytes_any_set(offer->seller_signature,
                       sizeof(offer->seller_signature)))
        return FILE_OFFER_AUTH_ERR_SIGNATURE;
    return FILE_OFFER_AUTH_OK;
}

enum file_offer_auth_error file_offer_auth_validate(
    const struct file_offer *offer)
{
    return offer_fields(offer, true);
}

enum file_offer_auth_error file_offer_auth_validate_at(
    const struct file_offer *offer, int64_t now_unix)
{
    enum file_offer_auth_error error = file_offer_auth_validate(offer);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    if (now_unix < offer->issued_unix)
        return FILE_OFFER_AUTH_ERR_NOT_YET_VALID;
    if (now_unix >= offer->expires_unix)
        return FILE_OFFER_AUTH_ERR_EXPIRED;
    return FILE_OFFER_AUTH_OK;
}

static enum file_offer_auth_error offer_body(
    const struct file_offer *offer,
    uint8_t out[FILE_MARKET_OFFER_BODY_BYTES_V2], size_t *out_len)
{
    enum file_offer_auth_error error = offer_fields(offer, false);
    if (!out || !out_len)
        return FILE_OFFER_AUTH_ERR_NULL;
    if (error != FILE_OFFER_AUTH_OK)
        return error;

    size_t off = 0;
    size_t name_len = strnlen(offer->filename, sizeof(offer->filename));
    put_bytes(out, &off, k_offer_magic, sizeof(k_offer_magic));
    put_u16(out, &off, offer->auth_version);
    put_bytes(out, &off, offer->network_genesis, 32);
    put_bytes(out, &off, offer->seller_pubkey, 32);
    put_u64(out, &off, offer->nonce);
    put_bytes(out, &off, offer->root_hash, 32);
    put_u64(out, &off, offer->size_bytes);
    put_u32(out, &off, FILE_MARKET_CHUNK_SIZE);
    put_u32(out, &off, offer->num_chunks);
    put_u64(out, &off, (uint64_t)offer->price_per_mb);
    put_bytes(out, &off, offer->z_addr, sizeof(offer->z_addr));
    put_bytes(out, &off, offer->peer_ip, sizeof(offer->peer_ip));
    put_u16(out, &off, offer->peer_port);
    put_u64(out, &off, (uint64_t)offer->issued_unix);
    put_u64(out, &off, (uint64_t)offer->expires_unix);
    out[off++] = (uint8_t)name_len;
    memset(out + off, 0, 255);
    memcpy(out + off, offer->filename, name_len);
    off += 255;
    if (offer->auth_version == FILE_MARKET_OFFER_VERSION_V2) {
        out[off++] = offer->endpoint_type;
        put_bytes(out, &off, offer->onion_pubkey,
                  sizeof(offer->onion_pubkey));
    }
    if (off != offer_body_size(offer->auth_version))
        return FILE_OFFER_AUTH_ERR_WIRE_SIZE;
    *out_len = off;
    return FILE_OFFER_AUTH_OK;
}

enum file_offer_auth_error file_offer_auth_encode_into(
    const struct file_offer *offer, uint8_t *out, size_t out_cap,
    size_t *out_len)
{
    if (!out || !out_len)
        return FILE_OFFER_AUTH_ERR_NULL;
    *out_len = 0;
    enum file_offer_auth_error error = file_offer_auth_validate(offer);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    if (out_cap < file_offer_auth_wire_size(offer->auth_version))
        return FILE_OFFER_AUTH_ERR_WIRE_SIZE;
    size_t body_len = 0;
    error = offer_body(offer, out, &body_len);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    memcpy(out + body_len, offer->seller_signature,
           sizeof(offer->seller_signature));
    *out_len = body_len + sizeof(offer->seller_signature);
    return FILE_OFFER_AUTH_OK;
}

enum file_offer_auth_error file_offer_auth_encode(
    const struct file_offer *offer,
    uint8_t out[FILE_MARKET_OFFER_WIRE_BYTES])
{
    size_t out_len = 0;
    enum file_offer_auth_error error = file_offer_auth_encode_into(
        offer, out, FILE_MARKET_OFFER_WIRE_BYTES, &out_len);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    return out_len == FILE_MARKET_OFFER_WIRE_BYTES
        ? FILE_OFFER_AUTH_OK : FILE_OFFER_AUTH_ERR_WIRE_SIZE;
}

enum file_offer_auth_error file_offer_auth_decode(
    const uint8_t *wire, size_t wire_len, struct file_offer *out)
{
    uint32_t chunk_size;
    uint8_t name_len;
    size_t off;
    if (!wire || !out)
        return FILE_OFFER_AUTH_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < sizeof(k_offer_magic) + 2)
        return FILE_OFFER_AUTH_ERR_WIRE_SIZE;
    if (memcmp(wire, k_offer_magic, sizeof(k_offer_magic)) != 0)
        return FILE_OFFER_AUTH_ERR_WIRE_MAGIC;
    uint16_t version = zcl_read_u16_le(wire + sizeof(k_offer_magic));
    if (!file_offer_auth_version_supported(version))
        return FILE_OFFER_AUTH_ERR_VERSION;
    if (wire_len != file_offer_auth_wire_size(version))
        return FILE_OFFER_AUTH_ERR_WIRE_SIZE;

    off = sizeof(k_offer_magic);
    out->auth_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->network_genesis, 32);
    get_bytes(wire, &off, out->seller_pubkey, 32);
    out->nonce = get_u64(wire, &off);
    get_bytes(wire, &off, out->root_hash, 32);
    out->size_bytes = get_u64(wire, &off);
    chunk_size = get_u32(wire, &off);
    out->num_chunks = get_u32(wire, &off);
    out->price_per_mb = (int64_t)get_u64(wire, &off);
    get_bytes(wire, &off, out->z_addr, sizeof(out->z_addr));
    get_bytes(wire, &off, out->peer_ip, sizeof(out->peer_ip));
    out->peer_port = get_u16(wire, &off);
    out->issued_unix = (int64_t)get_u64(wire, &off);
    out->expires_unix = (int64_t)get_u64(wire, &off);
    name_len = wire[off++];
    if (name_len == 0 || chunk_size != FILE_MARKET_CHUNK_SIZE) {
        memset(out, 0, sizeof(*out));
        return name_len == 0 ? FILE_OFFER_AUTH_ERR_FILENAME
                             : FILE_OFFER_AUTH_ERR_CHUNKS;
    }
    memcpy(out->filename, wire + off, name_len);
    out->filename[name_len] = '\0';
    off += 255;
    if (version == FILE_MARKET_OFFER_VERSION_V2) {
        out->endpoint_type = wire[off++];
        get_bytes(wire, &off, out->onion_pubkey,
                  sizeof(out->onion_pubkey));
    }
    get_bytes(wire, &off, out->seller_signature, 64);
    if (off != wire_len) {
        memset(out, 0, sizeof(*out));
        return FILE_OFFER_AUTH_ERR_WIRE_SIZE;
    }
    enum file_offer_auth_error error = file_offer_auth_validate(out);
    if (error != FILE_OFFER_AUTH_OK) {
        memset(out, 0, sizeof(*out));
        return error;
    }
    error = file_offer_auth_offer_id(out, out->offer_id);
    if (error != FILE_OFFER_AUTH_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum file_offer_auth_error file_offer_auth_body_root(
    const struct file_offer *offer, uint8_t out[32])
{
    uint8_t body[FILE_MARKET_OFFER_BODY_BYTES_V2];
    size_t body_len = 0;
    if (!out)
        return FILE_OFFER_AUTH_ERR_NULL;
    enum file_offer_auth_error error = offer_body(offer, body, &body_len);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    domain_hash(k_body_domain, sizeof(k_body_domain), body, body_len, out);
    return FILE_OFFER_AUTH_OK;
}

enum file_offer_auth_error file_offer_auth_offer_id(
    const struct file_offer *offer, uint8_t out[32])
{
    uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t wire_len = 0;
    if (!out)
        return FILE_OFFER_AUTH_ERR_NULL;
    enum file_offer_auth_error error = file_offer_auth_encode_into(
        offer, wire, sizeof(wire), &wire_len);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    domain_hash(k_id_domain, sizeof(k_id_domain), wire, wire_len, out);
    return FILE_OFFER_AUTH_OK;
}

enum file_offer_auth_error file_offer_auth_seal(
    struct file_offer *offer, const uint8_t seller_seed[32])
{
    uint8_t derived_pk[32], secret_copy[32], root[32];
    if (!offer || !seller_seed)
        return FILE_OFFER_AUTH_ERR_NULL;
    ed25519_keypair(derived_pk, secret_copy, seller_seed);
    if (memcmp(derived_pk, offer->seller_pubkey, 32) != 0) {
        memory_cleanse(secret_copy, sizeof(secret_copy));
        return FILE_OFFER_AUTH_ERR_KEY_MISMATCH;
    }
    enum file_offer_auth_error error = offer_fields(offer, false);
    if (error == FILE_OFFER_AUTH_OK)
        error = file_offer_auth_body_root(offer, root);
    if (error == FILE_OFFER_AUTH_OK) {
        ed25519_sign(offer->seller_signature, root, sizeof(root), seller_seed,
                     offer->seller_pubkey);
        error = file_offer_auth_offer_id(offer, offer->offer_id);
    }
    memory_cleanse(secret_copy, sizeof(secret_copy));
    memory_cleanse(root, sizeof(root));
    return error;
}

enum file_offer_auth_error file_offer_auth_verify_signature(
    const struct file_offer *offer)
{
    uint8_t root[32];
    enum file_offer_auth_error error = file_offer_auth_validate(offer);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    error = file_offer_auth_body_root(offer, root);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    bool ok = ed25519_verify(offer->seller_signature, root, sizeof(root),
                             offer->seller_pubkey);
    memory_cleanse(root, sizeof(root));
    return ok ? FILE_OFFER_AUTH_OK : FILE_OFFER_AUTH_ERR_SIGNATURE;
}

enum file_offer_auth_error file_offer_auth_verify_at(
    const struct file_offer *offer,
    const uint8_t expected_network_genesis[32], int64_t now_unix)
{
    enum file_offer_auth_error error = file_offer_auth_validate_at(
        offer, now_unix);
    if (error != FILE_OFFER_AUTH_OK)
        return error;
    if (!expected_network_genesis ||
        memcmp(offer->network_genesis, expected_network_genesis, 32) != 0)
        return FILE_OFFER_AUTH_ERR_NETWORK_MISMATCH;
    return file_offer_auth_verify_signature(offer);
}
