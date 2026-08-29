/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Strict allocation-free private mesh object offer codec. */

#include "session/mesh_private_object_proto.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "crypto/x25519_safe.h"

#include <string.h>

static const uint8_t offer_magic[8] = {'Z', 'M', 'P', 'O', '1', 0, 0, 0};
static const char offer_signature_domain[] =
    "zcl.mesh.private-object.offer.signature.v1";
static const char offer_root_domain[] = "zcl.mesh.private-object.offer.v1";
static const char offer_request_id_domain[] =
    "zcl.mesh.private-object.offer.request-id.v1";
static const char offer_key_context_domain[] =
    "zcl.mesh.private-object.offer.key-context.v1";
static const char offer_transfer_id_domain[] =
    "zcl.mesh.private-object.transfer-id.v1";

#define OFFER_UNSIGNED_BYTES \
    (MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES - 64u)

static bool bytes_nonzero(const uint8_t *bytes, size_t count)
{
    uint8_t any = 0;
    if (!bytes)
        return false;
    for (size_t i = 0; i < count; i++)
        any |= bytes[i];
    return any != 0;
}

static uint32_t expected_chunks(uint64_t size)
{
    return (uint32_t)(size / MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES +
                      (size % MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES != 0));
}

static bool x25519_public_key_usable(const uint8_t point[32])
{
    static const uint8_t probe_scalar[32] = {
        0x61, 0x93, 0x44, 0x0e, 0xc2, 0x7a, 0x55, 0xb1,
        0x39, 0x70, 0x8d, 0xf4, 0x22, 0xa6, 0x11, 0x5c,
        0x80, 0x37, 0xe9, 0x4b, 0xd3, 0x16, 0x68, 0xfa,
        0x2d, 0x91, 0x0c, 0x77, 0x45, 0xbe, 0x28, 0x6f,
    };
    uint8_t shared[32];
    bool usable = x25519_safe(shared, probe_scalar, point);
    memory_cleanse(shared, sizeof(shared));
    return usable;
}

const char *mesh_private_object_proto_error_string(
    enum mesh_private_object_proto_error error)
{
    switch (error) {
    case MESH_PRIVATE_OBJECT_PROTO_OK: return "ok";
    case MESH_PRIVATE_OBJECT_PROTO_NULL: return "null";
    case MESH_PRIVATE_OBJECT_PROTO_SIZE: return "size";
    case MESH_PRIVATE_OBJECT_PROTO_MAGIC: return "magic";
    case MESH_PRIVATE_OBJECT_PROTO_VERSION_INVALID: return "version";
    case MESH_PRIVATE_OBJECT_PROTO_FLAGS: return "flags";
    case MESH_PRIVATE_OBJECT_PROTO_FIELD: return "field";
    case MESH_PRIVATE_OBJECT_PROTO_TIME: return "time";
    case MESH_PRIVATE_OBJECT_PROTO_LIMIT: return "limit";
    case MESH_PRIVATE_OBJECT_PROTO_CHUNKS: return "chunks";
    case MESH_PRIVATE_OBJECT_PROTO_DENY: return "deny";
    case MESH_PRIVATE_OBJECT_PROTO_KEY_MISMATCH: return "key-mismatch";
    case MESH_PRIVATE_OBJECT_PROTO_SIGNATURE: return "signature";
    case MESH_PRIVATE_OBJECT_PROTO_EXPECTATION: return "expectation";
    }
    return "unknown";
}

static enum mesh_private_object_proto_error offer_shape(
    const struct mesh_private_object_offer_v1 *offer, bool require_request_id,
    bool require_ciphertext_root, bool require_signature)
{
    if (!offer)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    if (offer->version != MESH_PRIVATE_OBJECT_PROTO_VERSION)
        return MESH_PRIVATE_OBJECT_PROTO_VERSION_INVALID;
    if (offer->flags != MESH_PRIVATE_OBJECT_FLAGS_NONE)
        return MESH_PRIVATE_OBJECT_PROTO_FLAGS;
    const uint8_t *critical[] = {
        offer->network_genesis, offer->pairing_id, offer->grant_id,
        offer->source_master_pubkey, offer->source_noise_static,
        offer->source_online_pubkey, offer->target_master_pubkey,
        offer->target_noise_static, offer->transcript_hash,
        offer->plaintext_root, offer->ephemeral_x25519_pubkey,
    };
    for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++)
        if (!bytes_nonzero(critical[i], 32))
            return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    if (offer->connection_generation == 0)
        return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    if (require_request_id && !bytes_nonzero(offer->request_id, 32))
        return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    if (require_ciphertext_root &&
        !bytes_nonzero(offer->ciphertext_root, 32))
        return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    uint32_t chunk_count = expected_chunks(offer->object_size_bytes);
    uint64_t expected_ciphertext = offer->object_size_bytes +
        (uint64_t)chunk_count * MESH_PRIVATE_OBJECT_TAG_BYTES;
    if (offer->object_size_bytes == 0 ||
        offer->object_size_bytes > MESH_PRIVATE_OBJECT_MAX_OBJECT_BYTES ||
        offer->ciphertext_size_bytes != expected_ciphertext ||
        offer->ciphertext_size_bytes >
            MESH_PRIVATE_OBJECT_MAX_CIPHERTEXT_BYTES)
        return MESH_PRIVATE_OBJECT_PROTO_LIMIT;
    if (offer->chunk_size != MESH_PRIVATE_OBJECT_CHUNK_BYTES ||
        offer->chunk_count != chunk_count)
        return MESH_PRIVATE_OBJECT_PROTO_CHUNKS;
    if (!x25519_public_key_usable(offer->ephemeral_x25519_pubkey))
        return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    if (offer->issued_unix == 0 || offer->expires_unix <= offer->issued_unix ||
        offer->expires_unix - offer->issued_unix >
            MESH_PRIVATE_OBJECT_MAX_LIFETIME_SECONDS)
        return MESH_PRIVATE_OBJECT_PROTO_TIME;
    if ((offer->deny_mask & MESH_PRIVATE_OBJECT_DENY_REQUIRED) !=
            MESH_PRIVATE_OBJECT_DENY_REQUIRED ||
        (offer->deny_mask & ~MESH_PRIVATE_OBJECT_DENY_KNOWN) != 0)
        return MESH_PRIVATE_OBJECT_PROTO_DENY;
    if (require_signature && !bytes_nonzero(offer->signature, 64))
        return MESH_PRIVATE_OBJECT_PROTO_SIGNATURE;
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}

static size_t offer_write_unsigned(
    const struct mesh_private_object_offer_v1 *offer,
    uint8_t out[OFFER_UNSIGNED_BYTES])
{
    size_t off = 0;
#define PUT32(field) do { memcpy(out + off, offer->field, 32); off += 32; } while (0)
    memcpy(out + off, offer_magic, sizeof(offer_magic)); off += 8;
    zcl_write_u16_le(out + off, offer->version); off += 2;
    zcl_write_u16_le(out + off, offer->flags); off += 2;
    PUT32(network_genesis);
    PUT32(pairing_id);
    PUT32(grant_id);
    PUT32(source_master_pubkey);
    PUT32(source_noise_static);
    PUT32(source_online_pubkey);
    PUT32(target_master_pubkey);
    PUT32(target_noise_static);
    PUT32(transcript_hash);
    zcl_write_u64_le(out + off, offer->connection_generation); off += 8;
    zcl_write_u64_le(out + off, offer->pairing_revocation_generation); off += 8;
    PUT32(request_id);
    PUT32(plaintext_root);
    PUT32(ciphertext_root);
    zcl_write_u64_le(out + off, offer->object_size_bytes); off += 8;
    zcl_write_u64_le(out + off, offer->ciphertext_size_bytes); off += 8;
    zcl_write_u32_le(out + off, offer->chunk_size); off += 4;
    zcl_write_u32_le(out + off, offer->chunk_count); off += 4;
    PUT32(ephemeral_x25519_pubkey);
    zcl_write_u64_le(out + off, offer->issued_unix); off += 8;
    zcl_write_u64_le(out + off, offer->expires_unix); off += 8;
    zcl_write_u64_le(out + off, offer->deny_mask); off += 8;
#undef PUT32
    return off;
}

static enum mesh_private_object_proto_error offer_signing_root(
    const struct mesh_private_object_offer_v1 *offer, uint8_t out[32])
{
    enum mesh_private_object_proto_error error =
        offer_shape(offer, true, true, false);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    uint8_t wire[OFFER_UNSIGNED_BYTES];
    if (offer_write_unsigned(offer, wire) != sizeof(wire))
        return MESH_PRIVATE_OBJECT_PROTO_SIZE;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)offer_signature_domain,
                   sizeof(offer_signature_domain) - 1u);
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    memory_cleanse(wire, sizeof(wire));
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}

enum mesh_private_object_proto_error
mesh_private_object_offer_request_id_v1_derive(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t grant_nonce[32], uint8_t out[32])
{
    if (!offer || !grant_nonce || !out)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    if (!bytes_nonzero(grant_nonce, 32))
        return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    struct mesh_private_object_offer_v1 material = *offer;
    memset(material.request_id, 0, sizeof(material.request_id));
    memset(material.signature, 0, sizeof(material.signature));
    enum mesh_private_object_proto_error error =
        offer_shape(&material, false, true, false);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK) {
        memory_cleanse(&material, sizeof(material));
        return error;
    }
    uint8_t wire[OFFER_UNSIGNED_BYTES];
    if (offer_write_unsigned(&material, wire) != sizeof(wire)) {
        memory_cleanse(&material, sizeof(material));
        return MESH_PRIVATE_OBJECT_PROTO_SIZE;
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)offer_request_id_domain,
                   sizeof(offer_request_id_domain) - 1u);
    sha3_256_write(&sha, grant_nonce, 32);
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    memory_cleanse(&sha, sizeof(sha));
    memory_cleanse(wire, sizeof(wire));
    memory_cleanse(&material, sizeof(material));
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}

enum mesh_private_object_proto_error
mesh_private_object_offer_key_context_v1(
    const struct mesh_private_object_offer_v1 *offer, uint8_t out[32])
{
    if (!offer || !out)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    enum mesh_private_object_proto_error error =
        offer_shape(offer, false, false, false);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    uint8_t fields[36];
    zcl_write_u16_le(fields, offer->version);
    zcl_write_u16_le(fields + 2, offer->flags);
    zcl_write_u64_le(fields + 4, offer->object_size_bytes);
    zcl_write_u64_le(fields + 12, offer->ciphertext_size_bytes);
    zcl_write_u32_le(fields + 20, offer->chunk_size);
    zcl_write_u32_le(fields + 24, offer->chunk_count);
    zcl_write_u64_le(fields + 28, offer->deny_mask);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)offer_key_context_domain,
                   sizeof(offer_key_context_domain) - 1u);
#define STABLE32(field) sha3_256_write(&sha, offer->field, 32)
    STABLE32(network_genesis);
    STABLE32(pairing_id);
    STABLE32(grant_id);
    STABLE32(source_master_pubkey);
    STABLE32(source_noise_static);
    STABLE32(target_master_pubkey);
    STABLE32(target_noise_static);
    STABLE32(plaintext_root);
    STABLE32(ephemeral_x25519_pubkey);
#undef STABLE32
    sha3_256_write(&sha, fields, sizeof(fields));
    sha3_256_finalize(&sha, out);
    memory_cleanse(&sha, sizeof(sha));
    memory_cleanse(fields, sizeof(fields));
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}

enum mesh_private_object_proto_error
mesh_private_object_offer_transfer_id_v1(
    const struct mesh_private_object_offer_v1 *offer, uint8_t out[32])
{
    if (!offer || !out)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    if (!bytes_nonzero(offer->ciphertext_root, 32))
        return MESH_PRIVATE_OBJECT_PROTO_FIELD;
    uint8_t context[32];
    enum mesh_private_object_proto_error error =
        mesh_private_object_offer_key_context_v1(offer, context);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)offer_transfer_id_domain,
                   sizeof(offer_transfer_id_domain) - 1u);
    sha3_256_write(&sha, context, sizeof(context));
    sha3_256_write(&sha, offer->ciphertext_root, 32);
    sha3_256_finalize(&sha, out);
    memory_cleanse(&sha, sizeof(sha));
    memory_cleanse(context, sizeof(context));
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}

enum mesh_private_object_proto_error mesh_private_object_offer_v1_validate(
    const struct mesh_private_object_offer_v1 *offer)
{
    enum mesh_private_object_proto_error error =
        offer_shape(offer, true, true, true);
    uint8_t root[32];
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    error = offer_signing_root(offer, root);
    bool valid = error == MESH_PRIVATE_OBJECT_PROTO_OK &&
        ed25519_verify(offer->signature, root, sizeof(root),
                       offer->source_online_pubkey);
    memory_cleanse(root, sizeof(root));
    return valid ? MESH_PRIVATE_OBJECT_PROTO_OK
                 : MESH_PRIVATE_OBJECT_PROTO_SIGNATURE;
}

enum mesh_private_object_proto_error mesh_private_object_offer_v1_sign(
    struct mesh_private_object_offer_v1 *offer,
    const uint8_t source_online_seed[32])
{
    if (!offer || !source_online_seed)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    memset(offer->signature, 0, sizeof(offer->signature));
    uint8_t public_key[32], secret[32], root[32];
    ed25519_keypair(public_key, secret, source_online_seed);
    if (memcmp(public_key, offer->source_online_pubkey, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return MESH_PRIVATE_OBJECT_PROTO_KEY_MISMATCH;
    }
    enum mesh_private_object_proto_error error =
        offer_signing_root(offer, root);
    if (error == MESH_PRIVATE_OBJECT_PROTO_OK)
        ed25519_sign(offer->signature, root, sizeof(root), secret, public_key);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error == MESH_PRIVATE_OBJECT_PROTO_OK
               ? mesh_private_object_offer_v1_validate(offer)
               : error;
}

enum mesh_private_object_proto_error mesh_private_object_offer_v1_encode(
    const struct mesh_private_object_offer_v1 *offer,
    uint8_t out[MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES])
{
    if (!out)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    enum mesh_private_object_proto_error error =
        mesh_private_object_offer_v1_validate(offer);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    size_t off = offer_write_unsigned(offer, out);
    memcpy(out + off, offer->signature, 64); off += 64;
    return off == MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES
               ? MESH_PRIVATE_OBJECT_PROTO_OK
               : MESH_PRIVATE_OBJECT_PROTO_SIZE;
}

enum mesh_private_object_proto_error mesh_private_object_offer_v1_decode(
    struct mesh_private_object_offer_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out || !wire)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES)
        return MESH_PRIVATE_OBJECT_PROTO_SIZE;
    if (memcmp(wire, offer_magic, sizeof(offer_magic)) != 0)
        return MESH_PRIVATE_OBJECT_PROTO_MAGIC;
    size_t off = 8;
#define GET32(field) do { memcpy(out->field, wire + off, 32); off += 32; } while (0)
    out->version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    GET32(network_genesis);
    GET32(pairing_id);
    GET32(grant_id);
    GET32(source_master_pubkey);
    GET32(source_noise_static);
    GET32(source_online_pubkey);
    GET32(target_master_pubkey);
    GET32(target_noise_static);
    GET32(transcript_hash);
    out->connection_generation = zcl_read_u64_le(wire + off); off += 8;
    out->pairing_revocation_generation = zcl_read_u64_le(wire + off); off += 8;
    GET32(request_id);
    GET32(plaintext_root);
    GET32(ciphertext_root);
    out->object_size_bytes = zcl_read_u64_le(wire + off); off += 8;
    out->ciphertext_size_bytes = zcl_read_u64_le(wire + off); off += 8;
    out->chunk_size = zcl_read_u32_le(wire + off); off += 4;
    out->chunk_count = zcl_read_u32_le(wire + off); off += 4;
    GET32(ephemeral_x25519_pubkey);
    out->issued_unix = zcl_read_u64_le(wire + off); off += 8;
    out->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    out->deny_mask = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->signature, wire + off, 64); off += 64;
#undef GET32
    enum mesh_private_object_proto_error error =
        off == wire_len ? mesh_private_object_offer_v1_validate(out)
                        : MESH_PRIVATE_OBJECT_PROTO_SIZE;
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum mesh_private_object_proto_error mesh_private_object_offer_v1_root(
    const struct mesh_private_object_offer_v1 *offer, uint8_t out[32])
{
    if (!out)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    memset(out, 0, 32);
    uint8_t wire[MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES];
    enum mesh_private_object_proto_error error =
        mesh_private_object_offer_v1_encode(offer, wire);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)offer_root_domain,
                   sizeof(offer_root_domain) - 1u);
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    memory_cleanse(wire, sizeof(wire));
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}

static bool expected_bytes_match(
    const struct mesh_private_object_offer_v1 *offer,
    const struct mesh_private_object_offer_expectation_v1 *expected)
{
    return memcmp(offer->network_genesis, expected->network_genesis, 32) == 0 &&
        memcmp(offer->pairing_id, expected->pairing_id, 32) == 0 &&
        memcmp(offer->grant_id, expected->grant_id, 32) == 0 &&
        memcmp(offer->source_master_pubkey,
               expected->source_master_pubkey, 32) == 0 &&
        memcmp(offer->source_noise_static,
               expected->source_noise_static, 32) == 0 &&
        memcmp(offer->source_online_pubkey,
               expected->source_online_pubkey, 32) == 0 &&
        memcmp(offer->target_master_pubkey,
               expected->target_master_pubkey, 32) == 0 &&
        memcmp(offer->target_noise_static,
               expected->target_noise_static, 32) == 0 &&
        memcmp(offer->transcript_hash, expected->transcript_hash, 32) == 0 &&
        memcmp(offer->request_id, expected->request_id, 32) == 0 &&
        memcmp(offer->plaintext_root, expected->plaintext_root, 32) == 0 &&
        memcmp(offer->ciphertext_root, expected->ciphertext_root, 32) == 0;
}

enum mesh_private_object_proto_error mesh_private_object_offer_v1_matches(
    const struct mesh_private_object_offer_v1 *offer,
    const struct mesh_private_object_offer_expectation_v1 *expected,
    uint64_t now_unix)
{
    if (!offer || !expected)
        return MESH_PRIVATE_OBJECT_PROTO_NULL;
    enum mesh_private_object_proto_error error =
        mesh_private_object_offer_v1_validate(offer);
    if (error != MESH_PRIVATE_OBJECT_PROTO_OK)
        return error;
    if (now_unix < offer->issued_unix || now_unix >= offer->expires_unix)
        return MESH_PRIVATE_OBJECT_PROTO_TIME;
    if (!expected_bytes_match(offer, expected) ||
        offer->connection_generation != expected->connection_generation ||
        offer->pairing_revocation_generation !=
            expected->pairing_revocation_generation ||
        offer->object_size_bytes != expected->exact_object_size_bytes ||
        offer->ciphertext_size_bytes !=
            expected->exact_ciphertext_size_bytes ||
        (offer->deny_mask & expected->required_deny_mask) !=
            expected->required_deny_mask)
        return MESH_PRIVATE_OBJECT_PROTO_EXPECTATION;
    return MESH_PRIVATE_OBJECT_PROTO_OK;
}
