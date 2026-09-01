/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Adversarial acceptance for the private mesh status wire codec. */

#include "test/test_core.h"

#include "base/bytes.h"
#include "crypto/ed25519.h"
#include "models/mesh_pairing.h"
#include "session/mesh_status_proto.h"

#include <string.h>

static_assert(MESH_STATUS_CAP_STATUS_READ == MESH_PAIRING_CAP_STATUS_READ,
              "mesh status wire capability must match pairing authority");

static void fill_bytes(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static void make_request(struct mesh_status_request_v1 *request)
{
    memset(request, 0, sizeof(*request));
    request->version = MESH_STATUS_PROTO_VERSION;
    request->flags = MESH_STATUS_PROTO_FLAGS_NONE;
    request->capability = MESH_STATUS_CAP_STATUS_READ;
    fill_bytes(request->request_id, 0x11);
    fill_bytes(request->network_genesis, 0x31);
    fill_bytes(request->target_master_pubkey, 0x51);
    fill_bytes(request->requester_master_pubkey, 0x71);
    fill_bytes(request->requester_noise_static, 0x91);
    fill_bytes(request->pairing_id, 0xb1);
    fill_bytes(request->transcript_hash, 0xd1);
    request->connection_generation = UINT64_C(0x1020304050607080);
    request->issued_unix = UINT64_C(1800000000);
    request->expires_unix = request->issued_unix +
                            MESH_STATUS_MAX_LIFETIME_SECONDS;
}

static bool make_receipt(struct mesh_status_receipt_v1 *receipt,
                         const struct mesh_status_request_v1 *request,
                         enum mesh_status_receipt_status status,
                         const uint8_t *capsule, size_t capsule_len,
                         const uint8_t seed[32])
{
    uint8_t secret[32];

    if (capsule_len > MESH_STATUS_CAPSULE_MAX)
        return false;
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = MESH_STATUS_PROTO_VERSION;
    receipt->flags = MESH_STATUS_PROTO_FLAGS_NONE;
    receipt->status = status;
    memcpy(receipt->request_id, request->request_id, 32);
    if (mesh_status_request_v1_root(request, receipt->request_root) !=
        MESH_STATUS_PROTO_OK)
        return false;
    memcpy(receipt->network_genesis, request->network_genesis, 32);
    memcpy(receipt->pairing_id, request->pairing_id, 32);
    memcpy(receipt->responder_master_pubkey,
           request->target_master_pubkey, 32);
    ed25519_keypair(receipt->responder_online_pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
    fill_bytes(receipt->responder_noise_static, 0x42);
    memcpy(receipt->transcript_hash, request->transcript_hash, 32);
    receipt->connection_generation = request->connection_generation;
    receipt->revocation_generation = 7;
    receipt->observed_unix = request->issued_unix + 1;
    receipt->expires_unix = request->expires_unix;
    receipt->capsule_len = (uint16_t)capsule_len;
    if (capsule_len != 0)
        memcpy(receipt->capsule, capsule, capsule_len);
    if (mesh_status_capsule_v1_root(receipt->capsule, capsule_len,
                                    receipt->capsule_root) !=
        MESH_STATUS_PROTO_OK)
        return false;
    return mesh_status_receipt_v1_sign(receipt, seed) ==
           MESH_STATUS_PROTO_OK;
}

static int request_roundtrip(void)
{
    int failures = 0;

    TEST_CASE("mesh status request canonical roundtrip and root") {
        struct mesh_status_request_v1 request, decoded, changed;
        uint8_t wire[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
        uint8_t reencoded[MESH_STATUS_REQUEST_V1_WIRE_BYTES];
        uint8_t root[32], decoded_root[32], changed_root[32];

        make_request(&request);
        ASSERT_EQ(mesh_status_request_v1_validate(&request),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_request_v1_encode(&request, wire),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_request_v1_encode(&decoded, reencoded),
                  MESH_STATUS_PROTO_OK);
        ASSERT(memcmp(wire, reencoded, sizeof(wire)) == 0);
        ASSERT_EQ(mesh_status_request_v1_root(&request, root),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_request_v1_root(&decoded, decoded_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT(!zcl_bytes_all_zero((const uint8_t *)root, sizeof(root)));
        ASSERT(memcmp(root, decoded_root, sizeof(root)) == 0);

        memcpy(&changed, &decoded, sizeof(changed));
        changed.request_id[0] ^= 0x80;
        ASSERT_EQ(mesh_status_request_v1_root(&changed, changed_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT(memcmp(root, changed_root, sizeof(root)) != 0);
    } TEST_END
    return failures;
}

static int request_strictness(void)
{
    int failures = 0;

    TEST_CASE("mesh status request rejects noncanonical shape and time") {
        struct mesh_status_request_v1 request, decoded, trial;
        uint8_t wire[MESH_STATUS_REQUEST_V1_WIRE_BYTES + 1];
        uint8_t tampered[MESH_STATUS_REQUEST_V1_WIRE_BYTES];

        make_request(&request);
        ASSERT_EQ(mesh_status_request_v1_encode(&request, wire),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, wire,
                                                sizeof(wire) - 2),
                  MESH_STATUS_PROTO_SIZE);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_STATUS_PROTO_SIZE);

        memcpy(tampered, wire, sizeof(tampered));
        tampered[0] ^= 1;
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, tampered,
                                                sizeof(tampered)),
                  MESH_STATUS_PROTO_MAGIC);
        memcpy(tampered, wire, sizeof(tampered));
        tampered[8] = 2;
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, tampered,
                                                sizeof(tampered)),
                  MESH_STATUS_PROTO_VERSION_INVALID);
        memcpy(tampered, wire, sizeof(tampered));
        tampered[10] = 1;
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, tampered,
                                                sizeof(tampered)),
                  MESH_STATUS_PROTO_FLAGS);
        memcpy(tampered, wire, sizeof(tampered));
        tampered[12] = 2;
        ASSERT_EQ(mesh_status_request_v1_decode(&decoded, tampered,
                                                sizeof(tampered)),
                  MESH_STATUS_PROTO_CAPABILITY);

        uint8_t *critical[] = {
            trial.request_id, trial.network_genesis,
            trial.target_master_pubkey, trial.requester_master_pubkey,
            trial.requester_noise_static, trial.pairing_id,
            trial.transcript_hash,
        };
        for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++) {
            memcpy(&trial, &request, sizeof(trial));
            memset(critical[i], 0, 32);
            ASSERT_EQ(mesh_status_request_v1_validate(&trial),
                      MESH_STATUS_PROTO_FIELD);
        }
        memcpy(&trial, &request, sizeof(trial));
        trial.connection_generation = 0;
        ASSERT_EQ(mesh_status_request_v1_validate(&trial),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &request, sizeof(trial));
        trial.issued_unix = 0;
        ASSERT_EQ(mesh_status_request_v1_validate(&trial),
                  MESH_STATUS_PROTO_TIME);
        memcpy(&trial, &request, sizeof(trial));
        trial.expires_unix = trial.issued_unix;
        ASSERT_EQ(mesh_status_request_v1_validate(&trial),
                  MESH_STATUS_PROTO_TIME);
        trial.expires_unix = trial.issued_unix - 1;
        ASSERT_EQ(mesh_status_request_v1_validate(&trial),
                  MESH_STATUS_PROTO_TIME);
        trial.expires_unix = trial.issued_unix +
                             MESH_STATUS_MAX_LIFETIME_SECONDS + 1;
        ASSERT_EQ(mesh_status_request_v1_validate(&trial),
                  MESH_STATUS_PROTO_TIME);
    } TEST_END
    return failures;
}

static int receipt_roundtrips(void)
{
    int failures = 0;

    TEST_CASE("mesh status accepted and refused receipts roundtrip") {
        static const uint8_t capsule[] =
            "{\"schema\":\"zcl.machine.status.v1\",\"ready\":false}";
        struct mesh_status_request_v1 request;
        struct mesh_status_receipt_v1 accepted, refused, decoded;
        uint8_t seed[32], wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        uint8_t reencoded[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        uint8_t root[32], decoded_root[32], capsule_root[32];
        size_t wire_len = 0, reencoded_len = 0;

        make_request(&request);
        fill_bytes(seed, 0x23);
        ASSERT(make_receipt(&accepted, &request, MESH_STATUS_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_status_receipt_v1_validate(&accepted),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_capsule_v1_root(capsule, sizeof(capsule) - 1,
                                              capsule_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT(memcmp(capsule_root, accepted.capsule_root, 32) == 0);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&accepted, &request),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_encode(&accepted, wire, sizeof(wire),
                                                &wire_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(wire_len, mesh_status_receipt_v1_wire_size(&accepted));
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, wire, wire_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_encode(&decoded, reencoded,
                                                sizeof(reencoded),
                                                &reencoded_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(reencoded_len, wire_len);
        ASSERT(memcmp(reencoded, wire, wire_len) == 0);
        ASSERT_EQ(mesh_status_receipt_v1_root(&accepted, root),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_root(&decoded, decoded_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT(memcmp(root, decoded_root, sizeof(root)) == 0);

        ASSERT(make_receipt(&refused, &request, MESH_STATUS_RECEIPT_REVOKED,
                            NULL, 0, seed));
        ASSERT_EQ(mesh_status_receipt_v1_validate(&refused),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&refused, &request),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_encode(&refused, wire, sizeof(wire),
                                                &wire_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(wire_len, MESH_STATUS_RECEIPT_V1_FIXED_BYTES);
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, wire, wire_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_encode(&decoded, reencoded,
                                                sizeof(reencoded),
                                                &reencoded_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(reencoded_len, wire_len);
        ASSERT(memcmp(reencoded, wire, wire_len) == 0);

        uint8_t max_capsule[MESH_STATUS_CAPSULE_MAX];
        memset(max_capsule, 0xa5, sizeof(max_capsule));
        ASSERT(make_receipt(&accepted, &request, MESH_STATUS_RECEIPT_OK,
                            max_capsule, sizeof(max_capsule), seed));
        ASSERT_EQ(mesh_status_receipt_v1_encode(&accepted, wire, sizeof(wire),
                                                &wire_len),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(wire_len, MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES);
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, wire, wire_len),
                  MESH_STATUS_PROTO_OK);
    } TEST_END
    return failures;
}

static int receipt_tamper_and_bounds(void)
{
    int failures = 0;

    TEST_CASE("mesh status receipt rejects tamper and malformed wire") {
        static const uint8_t capsule[] = "{\"ready\":true}";
        struct mesh_status_request_v1 request;
        struct mesh_status_receipt_v1 receipt, decoded, trial;
        uint8_t seed[32], wrong_seed[32];
        uint8_t wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        uint8_t tampered[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;

        make_request(&request);
        fill_bytes(seed, 0x33);
        fill_bytes(wrong_seed, 0x73);
        ASSERT(make_receipt(&receipt, &request, MESH_STATUS_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_status_receipt_v1_encode(&receipt, wire, sizeof(wire),
                                                &wire_len),
                  MESH_STATUS_PROTO_OK);

        memcpy(&trial, &receipt, sizeof(trial));
        trial.signature[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_SIGNATURE);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.capsule[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_CAPSULE_ROOT);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.capsule_root[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_CAPSULE_ROOT);
        memcpy(&trial, &receipt, sizeof(trial));
        memset(trial.signature, 0, sizeof(trial.signature));
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_SIGNATURE);
        memcpy(&trial, &receipt, sizeof(trial));
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, wrong_seed),
                  MESH_STATUS_PROTO_KEY_MISMATCH);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)trial.signature, sizeof(trial.signature)));

        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, wire, wire_len - 1),
                  MESH_STATUS_PROTO_SIZE);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
        memcpy(tampered, wire, wire_len);
        tampered[wire_len] = 0;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, tampered,
                                                wire_len + 1),
                  MESH_STATUS_PROTO_SIZE);
        memcpy(tampered, wire, wire_len);
        tampered[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, tampered, wire_len),
                  MESH_STATUS_PROTO_MAGIC);
        memcpy(tampered, wire, wire_len);
        tampered[12] = 0xff;
        tampered[13] = 0xff;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, tampered, wire_len),
                  MESH_STATUS_PROTO_STATUS);
        memcpy(tampered, wire, wire_len);
        tampered[14] = 0x01;
        tampered[15] = 0x10;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, tampered, wire_len),
                  MESH_STATUS_PROTO_SIZE);
        memcpy(tampered, wire, wire_len);
        tampered[MESH_STATUS_RECEIPT_V1_FIXED_BYTES - 64u] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, tampered, wire_len),
                  MESH_STATUS_PROTO_CAPSULE_ROOT);
        memcpy(tampered, wire, wire_len);
        tampered[wire_len - 1] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&decoded, tampered, wire_len),
                  MESH_STATUS_PROTO_SIGNATURE);

        memcpy(&trial, &receipt, sizeof(trial));
        trial.status = (enum mesh_status_receipt_status)10;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_STATUS);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.version++;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_VERSION_INVALID);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.flags = 1;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_FLAGS);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.capsule_len = 0;
        ASSERT_EQ(mesh_status_capsule_v1_root(NULL, 0, trial.capsule_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_STATUS);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.status = MESH_STATUS_RECEIPT_REVOKED;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_STATUS);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.capsule_len = MESH_STATUS_CAPSULE_MAX + 1;
        ASSERT_EQ(mesh_status_receipt_v1_wire_size(&trial), 0u);
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_SIZE);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.expires_unix = trial.observed_unix;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_TIME);
        trial.expires_unix = trial.observed_unix +
                             MESH_STATUS_MAX_LIFETIME_SECONDS + 1;
        ASSERT_EQ(mesh_status_receipt_v1_validate(&trial),
                  MESH_STATUS_PROTO_TIME);
    } TEST_END
    return failures;
}

static int receipt_request_binding(void)
{
    int failures = 0;

    TEST_CASE("mesh status receipt binds request capsule and session") {
        static const uint8_t capsule[] = "{\"phase\":\"serving\"}";
        struct mesh_status_request_v1 request;
        struct mesh_status_receipt_v1 receipt, trial;
        uint8_t seed[32], original_root[32], changed_root[32];

        make_request(&request);
        fill_bytes(seed, 0x43);
        ASSERT(make_receipt(&receipt, &request, MESH_STATUS_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_status_receipt_v1_root(&receipt, original_root),
                  MESH_STATUS_PROTO_OK);

        memcpy(&trial, &receipt, sizeof(trial));
        trial.capsule[0] ^= 1;
        ASSERT_EQ(mesh_status_capsule_v1_root(trial.capsule,
                                              trial.capsule_len,
                                              trial.capsule_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_root(&trial, changed_root),
                  MESH_STATUS_PROTO_OK);
        ASSERT(memcmp(original_root, changed_root, sizeof(original_root)) != 0);

        memcpy(&trial, &receipt, sizeof(trial));
        trial.request_root[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.request_id[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.network_genesis[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.pairing_id[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.transcript_hash[0] ^= 1;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.connection_generation++;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_FIELD);
        memcpy(&trial, &receipt, sizeof(trial));
        trial.observed_unix = request.issued_unix - 1;
        trial.expires_unix = trial.observed_unix + 1;
        ASSERT_EQ(mesh_status_receipt_v1_sign(&trial, seed),
                  MESH_STATUS_PROTO_OK);
        ASSERT_EQ(mesh_status_receipt_v1_matches_request(&trial, &request),
                  MESH_STATUS_PROTO_TIME);
    } TEST_END
    return failures;
}

int test_mesh_status_proto(void)
{
    int failures = 0;

    failures += request_roundtrip();
    failures += request_strictness();
    failures += receipt_roundtrips();
    failures += receipt_tamper_and_bounds();
    failures += receipt_request_binding();
    return failures;
}
