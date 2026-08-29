/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Adversarial acceptance for signed private-object offers. */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "session/mesh_private_object_proto.h"

#include <string.h>

static void fill32(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static bool all_zero(const void *bytes, size_t count)
{
    const uint8_t *p = bytes;
    uint8_t any = 0;
    for (size_t i = 0; i < count; i++)
        any |= p[i];
    return any == 0;
}

static bool make_offer(struct mesh_private_object_offer_v1 *offer,
                       const uint8_t seed[32], const uint8_t grant_nonce[32])
{
    uint8_t secret[32];
    memset(offer, 0, sizeof(*offer));
    offer->version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    offer->flags = MESH_PRIVATE_OBJECT_FLAGS_NONE;
    fill32(offer->network_genesis, 0x01);
    fill32(offer->pairing_id, 0x21);
    fill32(offer->grant_id, 0x41);
    fill32(offer->source_master_pubkey, 0x61);
    fill32(offer->source_noise_static, 0x81);
    ed25519_keypair(offer->source_online_pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
    fill32(offer->target_master_pubkey, 0xa1);
    fill32(offer->target_noise_static, 0xc1);
    fill32(offer->transcript_hash, 0xe1);
    offer->connection_generation = UINT64_C(0x1020304050607080);
    offer->pairing_revocation_generation = 7;
    fill32(offer->plaintext_root, 0x32);
    fill32(offer->ciphertext_root, 0x52);
    offer->object_size_bytes =
        MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 17u;
    offer->ciphertext_size_bytes = offer->object_size_bytes +
                                   2u * MESH_PRIVATE_OBJECT_TAG_BYTES;
    offer->chunk_size = MESH_PRIVATE_OBJECT_CHUNK_BYTES;
    offer->chunk_count = 2;
    fill32(offer->ephemeral_x25519_pubkey, 0x72);
    offer->issued_unix = UINT64_C(1800000000);
    offer->expires_unix = offer->issued_unix + 60;
    offer->deny_mask = MESH_PRIVATE_OBJECT_DENY_REQUIRED;
    if (mesh_private_object_offer_request_id_v1_derive(
            offer, grant_nonce, offer->request_id) !=
        MESH_PRIVATE_OBJECT_PROTO_OK)
        return false;
    return mesh_private_object_offer_v1_sign(offer, seed) ==
           MESH_PRIVATE_OBJECT_PROTO_OK;
}

static void make_expectation(
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

static int roundtrip_and_root(void)
{
    int failures = 0;
    TEST_CASE("private object offer has one canonical signed wire") {
        uint8_t seed[32], grant_nonce[32];
        uint8_t wire[MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES];
        uint8_t again[sizeof(wire)], root[32], decoded_root[32];
        struct mesh_private_object_offer_v1 offer, decoded;
        fill32(seed, 0x55);
        fill32(grant_nonce, 0x15);
        ASSERT(make_offer(&offer, seed, grant_nonce));
        ASSERT_EQ(mesh_private_object_offer_v1_validate(&offer),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_encode(&offer, wire),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_decode(&decoded, wire,
                                                       sizeof(wire)),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_encode(&decoded, again),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(wire, again, sizeof(wire)) == 0);
        ASSERT_EQ(mesh_private_object_offer_v1_root(&offer, root),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_root(&decoded, decoded_root),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(!all_zero(root, sizeof(root)));
        ASSERT(memcmp(root, decoded_root, sizeof(root)) == 0);
    } TEST_END
    return failures;
}

static int strict_wire_and_signature(void)
{
    int failures = 0;
    TEST_CASE("private object offer rejects wire and signature tampering") {
        uint8_t seed[32], other_seed[32], grant_nonce[32];
        uint8_t wire[MESH_PRIVATE_OBJECT_OFFER_V1_WIRE_BYTES + 1];
        struct mesh_private_object_offer_v1 offer, decoded, trial;
        fill32(seed, 0x55);
        fill32(other_seed, 0x75);
        fill32(grant_nonce, 0x15);
        ASSERT(make_offer(&offer, seed, grant_nonce));
        ASSERT_EQ(mesh_private_object_offer_v1_encode(&offer, wire),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_decode(&decoded, wire,
                                                       sizeof(wire) - 2),
                  MESH_PRIVATE_OBJECT_PROTO_SIZE);
        ASSERT(all_zero(&decoded, sizeof(decoded)));
        ASSERT_EQ(mesh_private_object_offer_v1_decode(&decoded, wire,
                                                       sizeof(wire)),
                  MESH_PRIVATE_OBJECT_PROTO_SIZE);
        wire[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_decode(&decoded, wire,
                                                       sizeof(wire) - 1),
                  MESH_PRIVATE_OBJECT_PROTO_MAGIC);
        wire[0] ^= 1;
        wire[100] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_decode(&decoded, wire,
                                                       sizeof(wire) - 1),
                  MESH_PRIVATE_OBJECT_PROTO_SIGNATURE);
        ASSERT(all_zero(&decoded, sizeof(decoded)));

        trial = offer;
        trial.ciphertext_root[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_validate(&trial),
                  MESH_PRIVATE_OBJECT_PROTO_SIGNATURE);
        trial = offer;
        trial.signature[63] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_v1_validate(&trial),
                  MESH_PRIVATE_OBJECT_PROTO_SIGNATURE);
        trial = offer;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, other_seed),
                  MESH_PRIVATE_OBJECT_PROTO_KEY_MISMATCH);
        ASSERT(all_zero(trial.signature, sizeof(trial.signature)));
    } TEST_END
    return failures;
}

static int shape_limits_and_downgrade(void)
{
    int failures = 0;
    TEST_CASE("private object offer rejects unsafe shape and deny downgrade") {
        uint8_t seed[32], grant_nonce[32];
        struct mesh_private_object_offer_v1 offer, trial;
        fill32(seed, 0x55);
        fill32(grant_nonce, 0x15);
        ASSERT(make_offer(&offer, seed, grant_nonce));

        trial = offer; trial.version = 0;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_VERSION_INVALID);
        trial = offer; trial.flags = 1;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_FLAGS);
        trial = offer; memset(trial.grant_id, 0, 32);
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_FIELD);
        trial = offer; trial.connection_generation = 0;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_FIELD);
        trial = offer; trial.object_size_bytes = 0;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_LIMIT);
        trial = offer;
        trial.object_size_bytes = MESH_PRIVATE_OBJECT_MAX_OBJECT_BYTES + 1;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_LIMIT);
        trial = offer; trial.ciphertext_size_bytes--;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_LIMIT);
        trial = offer;
        trial.ciphertext_size_bytes =
            MESH_PRIVATE_OBJECT_MAX_CIPHERTEXT_BYTES + 1;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_LIMIT);
        trial = offer; trial.chunk_size /= 2;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_CHUNKS);
        trial = offer; trial.chunk_count--;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_CHUNKS);
        trial = offer;
        memset(trial.ephemeral_x25519_pubkey, 0, 32);
        trial.ephemeral_x25519_pubkey[0] = 1;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_FIELD);
        trial = offer; trial.expires_unix = trial.issued_unix;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_TIME);
        trial = offer;
        trial.expires_unix = trial.issued_unix +
                             MESH_PRIVATE_OBJECT_MAX_LIFETIME_SECONDS + 1;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_TIME);
        trial = offer; trial.deny_mask &= ~MESH_PRIVATE_OBJECT_DENY_WALLET;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_DENY);
        trial = offer; trial.deny_mask |= UINT64_C(1) << 63;
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, seed),
                  MESH_PRIVATE_OBJECT_PROTO_DENY);
    } TEST_END
    return failures;
}

static int expectation_binding(void)
{
    int failures = 0;
    TEST_CASE("private object offer matches exact grant and live session") {
        uint8_t seed[32], grant_nonce[32], derived[32];
        struct mesh_private_object_offer_v1 offer;
        struct mesh_private_object_offer_expectation_v1 expected, trial;
        fill32(seed, 0x55);
        fill32(grant_nonce, 0x15);
        ASSERT(make_offer(&offer, seed, grant_nonce));
        ASSERT_EQ(mesh_private_object_offer_request_id_v1_derive(
                      &offer, grant_nonce, derived),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(derived, offer.request_id, 32) == 0);
        make_expectation(&expected, &offer);
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &expected, offer.issued_unix),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &expected, offer.expires_unix - 1),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &expected, offer.issued_unix - 1),
                  MESH_PRIVATE_OBJECT_PROTO_TIME);
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &expected, offer.expires_unix),
                  MESH_PRIVATE_OBJECT_PROTO_TIME);

#define WRONG32(field) do { \
    trial = expected; trial.field[0] ^= 1; \
    ASSERT_EQ(mesh_private_object_offer_v1_matches( \
                  &offer, &trial, offer.issued_unix), \
              MESH_PRIVATE_OBJECT_PROTO_EXPECTATION); \
} while (0)
        WRONG32(network_genesis);
        WRONG32(pairing_id);
        WRONG32(grant_id);
        WRONG32(source_master_pubkey);
        WRONG32(source_noise_static);
        WRONG32(source_online_pubkey);
        WRONG32(target_master_pubkey);
        WRONG32(target_noise_static);
        WRONG32(transcript_hash);
        WRONG32(request_id);
        WRONG32(plaintext_root);
        WRONG32(ciphertext_root);
#undef WRONG32
        trial = expected; trial.connection_generation++;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &trial, offer.issued_unix),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        trial = expected; trial.pairing_revocation_generation++;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &trial, offer.issued_unix),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        trial = expected; trial.exact_object_size_bytes++;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &trial, offer.issued_unix),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        trial = expected; trial.exact_ciphertext_size_bytes++;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &trial, offer.issued_unix),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        trial = expected; trial.required_deny_mask |= UINT64_C(1) << 63;
        ASSERT_EQ(mesh_private_object_offer_v1_matches(
                      &offer, &trial, offer.issued_unix),
                  MESH_PRIVATE_OBJECT_PROTO_EXPECTATION);
        uint8_t wrong_nonce[32];
        fill32(wrong_nonce, 0x16);
        ASSERT_EQ(mesh_private_object_offer_request_id_v1_derive(
                      &offer, wrong_nonce, derived),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(derived, offer.request_id, 32) != 0);
    } TEST_END
    return failures;
}

static int stable_reconnect_identity(void)
{
    int failures = 0;
    TEST_CASE("private object transfer identity survives reconnect") {
        uint8_t seed[32], grant_nonce[32];
        uint8_t context[32], transfer[32], trial_context[32], trial_id[32];
        struct mesh_private_object_offer_v1 offer, trial;
        fill32(seed, 0x55);
        fill32(grant_nonce, 0x15);
        ASSERT(make_offer(&offer, seed, grant_nonce));
        ASSERT_EQ(mesh_private_object_offer_key_context_v1(&offer, context),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_transfer_id_v1(&offer, transfer),
                  MESH_PRIVATE_OBJECT_PROTO_OK);

        trial = offer;
        trial.source_online_pubkey[0] ^= 1;
        trial.transcript_hash[0] ^= 1;
        trial.connection_generation++;
        trial.pairing_revocation_generation++;
        trial.issued_unix++;
        trial.expires_unix++;
        trial.request_id[0] ^= 1;
        trial.signature[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &trial, trial_context),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_transfer_id_v1(
                      &trial, trial_id),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(context, trial_context, 32) == 0);
        ASSERT(memcmp(transfer, trial_id, 32) == 0);

        trial.target_master_pubkey[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &trial, trial_context),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(context, trial_context, 32) != 0);
        trial = offer;
        trial.ciphertext_root[0] ^= 1;
        ASSERT_EQ(mesh_private_object_offer_key_context_v1(
                      &trial, trial_context),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_transfer_id_v1(
                      &trial, trial_id),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT(memcmp(context, trial_context, 32) == 0);
        ASSERT(memcmp(transfer, trial_id, 32) != 0);
    } TEST_END
    return failures;
}

int test_mesh_private_object_proto(void)
{
    int failures = 0;
    failures += roundtrip_and_root();
    failures += strict_wire_and_signature();
    failures += shape_limits_and_downgrade();
    failures += expectation_binding();
    failures += stable_reconnect_identity();
    return failures;
}
