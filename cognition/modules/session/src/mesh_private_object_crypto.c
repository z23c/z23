/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: X25519/HKDF-SHA3/ChaCha20-Poly1305 private-object chunk codec. */

#include "session/mesh_private_object_crypto.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/hkdf_sha3.h"
#include "crypto/x25519_safe.h"

#include <string.h>

static const uint8_t chunk_key_domain[] =
    "zcl.mesh.private-object.chunk.key.v1";
static const uint8_t chunk_aad_domain[] =
    "zcl.mesh.private-object.chunk.aad.v1";

const char *mesh_private_object_chunk_error_string(
    enum mesh_private_object_chunk_error error)
{
    switch (error) {
    case MESH_PRIVATE_OBJECT_CHUNK_OK: return "ok";
    case MESH_PRIVATE_OBJECT_CHUNK_NULL: return "null";
    case MESH_PRIVATE_OBJECT_CHUNK_OFFER: return "offer";
    case MESH_PRIVATE_OBJECT_CHUNK_INDEX: return "index";
    case MESH_PRIVATE_OBJECT_CHUNK_SIZE: return "size";
    case MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH: return "key-mismatch";
    case MESH_PRIVATE_OBJECT_CHUNK_DH: return "dh";
    case MESH_PRIVATE_OBJECT_CHUNK_KDF: return "kdf";
    case MESH_PRIVATE_OBJECT_CHUNK_AUTH: return "auth";
    }
    return "unknown";
}

enum mesh_private_object_chunk_error mesh_private_object_chunk_shape_v1(
    const struct mesh_private_object_offer_v1 *offer, uint32_t chunk_index,
    uint32_t *plaintext_bytes, uint32_t *sealed_bytes)
{
    if (!offer || !plaintext_bytes || !sealed_bytes)
        return MESH_PRIVATE_OBJECT_CHUNK_NULL;
    *plaintext_bytes = 0;
    *sealed_bytes = 0;
    uint8_t context[32];
    if (mesh_private_object_offer_key_context_v1(offer, context) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return MESH_PRIVATE_OBJECT_CHUNK_OFFER;
    memory_cleanse(context, sizeof(context));
    if (chunk_index >= offer->chunk_count)
        return MESH_PRIVATE_OBJECT_CHUNK_INDEX;
    uint64_t offset =
        (uint64_t)chunk_index * MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES;
    if (offset >= offer->object_size_bytes)
        return MESH_PRIVATE_OBJECT_CHUNK_INDEX;
    uint64_t remaining = offer->object_size_bytes - offset;
    uint32_t plain = remaining > MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES
        ? MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES
        : (uint32_t)remaining;
    *plaintext_bytes = plain;
    *sealed_bytes = plain + MESH_PRIVATE_OBJECT_TAG_BYTES;
    return MESH_PRIVATE_OBJECT_CHUNK_OK;
}

static enum mesh_private_object_chunk_error chunk_key(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t secret[32], const uint8_t peer_public[32], uint8_t out[32],
    uint8_t context[32])
{
    if (mesh_private_object_offer_key_context_v1(offer, context) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return MESH_PRIVATE_OBJECT_CHUNK_OFFER;
    uint8_t shared[32];
    if (!x25519_safe(shared, secret, peer_public)) {
        memory_cleanse(context, 32);
        return MESH_PRIVATE_OBJECT_CHUNK_DH;
    }
    bool derived = hkdf_sha3_256(
        context, 32, shared, sizeof(shared), chunk_key_domain,
        sizeof(chunk_key_domain) - 1u, out, 32);
    memory_cleanse(shared, sizeof(shared));
    if (!derived) {
        memory_cleanse(context, 32);
        memory_cleanse(out, 32);
        return MESH_PRIVATE_OBJECT_CHUNK_KDF;
    }
    return MESH_PRIVATE_OBJECT_CHUNK_OK;
}

static size_t chunk_aad(uint8_t out[sizeof(chunk_aad_domain) + 48],
                        const uint8_t context[32], uint32_t chunk_index,
                        uint32_t plain_len, uint32_t sealed_len,
                        uint32_t chunk_count)
{
    size_t off = 0;
    memcpy(out + off, chunk_aad_domain, sizeof(chunk_aad_domain));
    off += sizeof(chunk_aad_domain);
    memcpy(out + off, context, 32);
    off += 32;
    zcl_write_u32_le(out + off, chunk_index); off += 4;
    zcl_write_u32_le(out + off, plain_len); off += 4;
    zcl_write_u32_le(out + off, sealed_len); off += 4;
    zcl_write_u32_le(out + off, chunk_count); off += 4;
    return off;
}

static void chunk_nonce(uint8_t out[CHACHA20_NONCE_SIZE], uint32_t index)
{
    out[0] = 'Z'; out[1] = 'M'; out[2] = 'P'; out[3] = 'O';
    zcl_write_u64_le(out + 4, index);
}

enum mesh_private_object_chunk_error mesh_private_object_chunk_seal_v1(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t source_ephemeral_secret[32], uint32_t chunk_index,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *sealed, size_t sealed_cap, size_t *sealed_len)
{
    if (!offer || !source_ephemeral_secret || !plaintext || !sealed ||
        !sealed_len)
        return MESH_PRIVATE_OBJECT_CHUNK_NULL;
    *sealed_len = 0;
    uint32_t expected_plain, expected_sealed;
    enum mesh_private_object_chunk_error error =
        mesh_private_object_chunk_shape_v1(
            offer, chunk_index, &expected_plain, &expected_sealed);
    if (error != MESH_PRIVATE_OBJECT_CHUNK_OK)
        return error;
    if (plaintext_len != expected_plain || sealed_cap < expected_sealed)
        return MESH_PRIVATE_OBJECT_CHUNK_SIZE;
    uint8_t public_key[32];
    if (!curve25519_scalarmult_base(public_key, source_ephemeral_secret) ||
        memcmp(public_key, offer->ephemeral_x25519_pubkey, 32) != 0) {
        memory_cleanse(public_key, sizeof(public_key));
        return MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH;
    }
    memory_cleanse(public_key, sizeof(public_key));
    uint8_t key[32], context[32], nonce[CHACHA20_NONCE_SIZE];
    error = chunk_key(offer, source_ephemeral_secret,
                      offer->target_noise_static, key, context);
    if (error != MESH_PRIVATE_OBJECT_CHUNK_OK)
        return error;
    uint8_t aad[sizeof(chunk_aad_domain) + 48];
    size_t aad_len = chunk_aad(aad, context, chunk_index, expected_plain,
                               expected_sealed, offer->chunk_count);
    chunk_nonce(nonce, chunk_index);
    bool ok = chacha20poly1305_encrypt(
        plaintext, plaintext_len, aad, aad_len, nonce, key, sealed);
    memory_cleanse(key, sizeof(key));
    memory_cleanse(context, sizeof(context));
    memory_cleanse(nonce, sizeof(nonce));
    memory_cleanse(aad, sizeof(aad));
    if (!ok)
        return MESH_PRIVATE_OBJECT_CHUNK_AUTH;
    *sealed_len = expected_sealed;
    return MESH_PRIVATE_OBJECT_CHUNK_OK;
}

enum mesh_private_object_chunk_error mesh_private_object_chunk_open_v1(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t target_noise_static_secret[32], uint32_t chunk_index,
    const uint8_t *sealed, size_t sealed_len,
    uint8_t *plaintext, size_t plaintext_cap, size_t *plaintext_len)
{
    if (!offer || !target_noise_static_secret || !sealed || !plaintext ||
        !plaintext_len)
        return MESH_PRIVATE_OBJECT_CHUNK_NULL;
    *plaintext_len = 0;
    uint32_t expected_plain, expected_sealed;
    enum mesh_private_object_chunk_error error =
        mesh_private_object_chunk_shape_v1(
            offer, chunk_index, &expected_plain, &expected_sealed);
    if (error != MESH_PRIVATE_OBJECT_CHUNK_OK)
        return error;
    if (sealed_len != expected_sealed || plaintext_cap < expected_plain)
        return MESH_PRIVATE_OBJECT_CHUNK_SIZE;
    uint8_t public_key[32];
    if (!curve25519_scalarmult_base(
            public_key, target_noise_static_secret) ||
        memcmp(public_key, offer->target_noise_static, 32) != 0) {
        memory_cleanse(public_key, sizeof(public_key));
        return MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH;
    }
    memory_cleanse(public_key, sizeof(public_key));
    uint8_t key[32], context[32], nonce[CHACHA20_NONCE_SIZE];
    error = chunk_key(offer, target_noise_static_secret,
                      offer->ephemeral_x25519_pubkey, key, context);
    if (error != MESH_PRIVATE_OBJECT_CHUNK_OK)
        return error;
    uint8_t aad[sizeof(chunk_aad_domain) + 48];
    size_t aad_len = chunk_aad(aad, context, chunk_index, expected_plain,
                               expected_sealed, offer->chunk_count);
    chunk_nonce(nonce, chunk_index);
    bool ok = chacha20poly1305_decrypt(
        sealed, sealed_len, aad, aad_len, nonce, key, plaintext);
    memory_cleanse(key, sizeof(key));
    memory_cleanse(context, sizeof(context));
    memory_cleanse(nonce, sizeof(nonce));
    memory_cleanse(aad, sizeof(aad));
    if (!ok) {
        memory_cleanse(plaintext, expected_plain);
        return MESH_PRIVATE_OBJECT_CHUNK_AUTH;
    }
    *plaintext_len = expected_plain;
    return MESH_PRIVATE_OBJECT_CHUNK_OK;
}
