/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: End-to-end grant, encryption, root, and offer binding acceptance. */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "models/mesh_capability_grant.h"
#include "session/mesh_private_object_crypto.h"
#include "session/mesh_private_object_root.h"

#include <string.h>

static void grant_pipeline_fill(uint8_t *out, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(seed + i * 29u);
}

static bool grant_pipeline_plaintext_root(
    const uint8_t *first, size_t first_len,
    const uint8_t *last, size_t last_len, uint8_t out[32])
{
    struct mesh_private_object_root_v1 root;
    uint64_t object_size = first_len + last_len;
    uint64_t ciphertext_size = object_size +
        2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
    return mesh_private_object_root_v1_init(
               &root, MESH_PRIVATE_OBJECT_ROOT_PLAINTEXT,
               object_size, ciphertext_size, 2) ==
               MESH_PRIVATE_OBJECT_ROOT_OK &&
           mesh_private_object_root_v1_update(
               &root, 0, first, first_len) ==
               MESH_PRIVATE_OBJECT_ROOT_OK &&
           mesh_private_object_root_v1_update(
               &root, 1, last, last_len) ==
               MESH_PRIVATE_OBJECT_ROOT_OK &&
           mesh_private_object_root_v1_finalize(&root, out) ==
               MESH_PRIVATE_OBJECT_ROOT_OK;
}

static bool grant_pipeline_template(
    struct db_mesh_capability_grant *grant,
    struct mesh_private_object_offer_v1 *offer,
    uint8_t ephemeral_secret[32], uint8_t online_seed[32])
{
    constexpr uint64_t object_size =
        MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 23u;
    constexpr uint64_t ciphertext_size =
        object_size + 2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
    uint8_t pairing_id[32], source_noise_secret[32], target_noise_secret[32];
    uint8_t online_secret[32];
    memset(grant, 0, sizeof(*grant));
    memset(offer, 0, sizeof(*offer));
    grant_pipeline_fill(pairing_id, sizeof(pairing_id), 0x11);
    grant_pipeline_fill(grant->target_master_pubkey, 32, 0x31);
    grant_pipeline_fill(source_noise_secret, 32, 0x51);
    grant_pipeline_fill(target_noise_secret, 32, 0x71);
    grant_pipeline_fill(ephemeral_secret, 32, 0x91);
    grant_pipeline_fill(online_seed, 32, 0xb1);
    zcl_hex_encode(pairing_id, sizeof(pairing_id), grant->pairing_id);
    if (!curve25519_scalarmult_base(
            grant->target_noise_static, target_noise_secret) ||
        !curve25519_scalarmult_base(
            offer->source_noise_static, source_noise_secret) ||
        !curve25519_scalarmult_base(
            offer->ephemeral_x25519_pubkey, ephemeral_secret))
        return false;

    grant->operation = MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE;
    grant->object_size_bytes = object_size;
    grant->ciphertext_size_bytes = ciphertext_size;
    grant->storage_limit_bytes = object_size + ciphertext_size;
    grant->transfer_limit_bytes = ciphertext_size;
    grant->max_chunk_bytes = MESH_CAPABILITY_GRANT_CHUNK_BYTES;
    grant->chunk_count = 2;
    grant->wall_limit_seconds = 60;
    grant_pipeline_fill(grant->nonce, 32, 0xd1);
    grant->deny_mask = MESH_CAPABILITY_DENY_MANDATORY;
    grant->issued_at = 2000;
    grant->not_before = 2100;
    grant->expires_at = 3000;

    offer->version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    grant_pipeline_fill(offer->network_genesis, 32, 0x21);
    memcpy(offer->pairing_id, pairing_id, 32);
    grant_pipeline_fill(offer->source_master_pubkey, 32, 0x41);
    ed25519_keypair(offer->source_online_pubkey, online_secret, online_seed);
    memset(online_secret, 0, sizeof(online_secret));
    memcpy(offer->target_master_pubkey, grant->target_master_pubkey, 32);
    memcpy(offer->target_noise_static, grant->target_noise_static, 32);
    grant_pipeline_fill(offer->transcript_hash, 32, 0xe1);
    offer->connection_generation = 9;
    offer->pairing_revocation_generation = 3;
    offer->object_size_bytes = object_size;
    offer->ciphertext_size_bytes = ciphertext_size;
    offer->chunk_size = MESH_PRIVATE_OBJECT_CHUNK_BYTES;
    offer->chunk_count = 2;
    offer->issued_unix = 2150;
    offer->expires_unix = 2210;
    offer->deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;
    return true;
}

static bool grant_pipeline_seal_root(
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t ephemeral_secret[32], const uint8_t *first,
    size_t first_len, const uint8_t *last, size_t last_len, uint8_t out[32])
{
    uint8_t sealed_first[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
    uint8_t sealed_last[23u + MESH_PRIVATE_OBJECT_TAG_BYTES];
    size_t sealed_first_len = 0, sealed_last_len = 0;
    if (mesh_private_object_chunk_seal_v1(
            offer, ephemeral_secret, 0, first, first_len,
            sealed_first, sizeof(sealed_first), &sealed_first_len) !=
            MESH_PRIVATE_OBJECT_CHUNK_OK ||
        mesh_private_object_chunk_seal_v1(
            offer, ephemeral_secret, 1, last, last_len,
            sealed_last, sizeof(sealed_last), &sealed_last_len) !=
            MESH_PRIVATE_OBJECT_CHUNK_OK)
        return false;
    struct mesh_private_object_root_v1 root;
    return mesh_private_object_root_v1_init(
               &root, MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT,
               offer->object_size_bytes, offer->ciphertext_size_bytes,
               offer->chunk_count) == MESH_PRIVATE_OBJECT_ROOT_OK &&
           mesh_private_object_root_v1_update(
               &root, 0, sealed_first, sealed_first_len) ==
               MESH_PRIVATE_OBJECT_ROOT_OK &&
           mesh_private_object_root_v1_update(
               &root, 1, sealed_last, sealed_last_len) ==
               MESH_PRIVATE_OBJECT_ROOT_OK &&
           mesh_private_object_root_v1_finalize(&root, out) ==
               MESH_PRIVATE_OBJECT_ROOT_OK;
}

static void grant_pipeline_expectation(
    struct mesh_private_object_offer_expectation_v1 *expected,
    const struct mesh_private_object_offer_v1 *offer)
{
    memset(expected, 0, sizeof(*expected));
#define COPY32(field) memcpy(expected->field, offer->field, 32)
    COPY32(network_genesis);
    COPY32(pairing_id);
    COPY32(grant_id);
    COPY32(source_master_pubkey);
    COPY32(source_noise_static);
    COPY32(source_online_pubkey);
    COPY32(target_master_pubkey);
    COPY32(target_noise_static);
    COPY32(transcript_hash);
    COPY32(request_id);
    COPY32(plaintext_root);
    COPY32(ciphertext_root);
#undef COPY32
    expected->connection_generation = offer->connection_generation;
    expected->pairing_revocation_generation =
        offer->pairing_revocation_generation;
    expected->exact_object_size_bytes = offer->object_size_bytes;
    expected->exact_ciphertext_size_bytes = offer->ciphertext_size_bytes;
    expected->required_deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;
}

static int grant_encrypt_offer_pipeline(void)
{
    int failures = 0;
    TEST_CASE("private grant is derived after encryption without a key cycle") {
        static uint8_t first[MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES];
        uint8_t last[23], ephemeral_secret[32], online_seed[32];
        uint8_t context_before[32], context_after[32], grant_id[32];
        const uint8_t zero[32] = {0};
        struct db_mesh_capability_grant grant;
        struct mesh_private_object_offer_v1 offer, tampered;
        struct mesh_private_object_offer_expectation_v1 expected, wrong;
        struct ar_errors errors;
        char derived_id[MESH_CAPABILITY_GRANT_ID_HEX + 1];
        grant_pipeline_fill(first, sizeof(first), 0x17);
        grant_pipeline_fill(last, sizeof(last), 0x37);
        ASSERT(grant_pipeline_template(
            &grant, &offer, ephemeral_secret, online_seed));
        ASSERT(grant_pipeline_plaintext_root(
            first, sizeof(first), last, sizeof(last), grant.plaintext_root));
        memcpy(offer.plaintext_root, grant.plaintext_root, 32);
        ASSERT(memcmp(offer.grant_id, zero, 32) == 0);
        ASSERT(memcmp(offer.ciphertext_root, zero, 32) == 0);

        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &offer, context_before),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(grant_pipeline_seal_root(
            &offer, ephemeral_secret, first, sizeof(first), last,
            sizeof(last), grant.ciphertext_root));
        ASSERT(mesh_capability_grant_id_derive(&grant, grant.grant_id));
        ASSERT(db_mesh_capability_grant_validate(&grant, &errors));
        ASSERT(zcl_hex_decode_lower(grant.grant_id, grant_id, 32));
        memcpy(offer.grant_id, grant_id, 32);
        memcpy(offer.ciphertext_root, grant.ciphertext_root, 32);

        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &offer, context_after),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(context_before, context_after, 32) == 0);
        ASSERT(mesh_capability_grant_id_derive(&grant, derived_id));
        ASSERT_STR_EQ(derived_id, grant.grant_id);
        ASSERT_EQ(mesh_private_object_offer_request_id_v1_derive(
                      &offer, grant.nonce, offer.request_id),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&offer, online_seed),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_validate(&offer),
                  MESH_PRIVATE_OBJECT_PROTO_OK);

        grant_pipeline_expectation(&expected, &offer);
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &expected, 2160),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        wrong = expected;
        wrong.grant_id[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &wrong, 2160),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        wrong = expected;
        wrong.ciphertext_root[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &wrong, 2160),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        tampered = offer;
        tampered.ciphertext_root[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_validate(&tampered),
                  MESH_PRIVATE_OBJECT_PROTO_SIGNATURE);
    } TEST_END
    return failures;
}

int test_mesh_private_object_grant_pipeline(void)
{
    return grant_encrypt_offer_pipeline();
}
