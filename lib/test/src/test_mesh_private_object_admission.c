/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: End-to-end refusal tests for private-object offer admission. */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "models/mesh_capability_grant.h"
#include "models/mesh_pairing.h"
#include "services/mesh_private_object_admission.h"

#include <stdio.h>
#include <string.h>

struct admission_fixture {
    struct node_db ndb;
    struct db_mesh_pairing pairing;
    struct db_mesh_capability_grant grant;
    struct vcs_zcode_dht_delegation delegation;
    struct mesh_private_object_offer_v1 offer;
    struct v2_transport_snapshot session;
    uint8_t local_master[32];
    uint8_t local_noise[32];
    uint8_t online_seed[32];
};

static void admission_fill(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static bool admission_fixture_open(struct admission_fixture *f,
                                   const char *path)
{
    memset(f, 0, sizeof(*f));
    if (!node_db_open(&f->ndb, path))
        return false;
    uint8_t genesis[32], beacon[32], master_seed[32], online_secret[32];
    uint8_t source_noise_secret[32], target_noise_secret[32];
    uint8_t ephemeral_secret[32];
    admission_fill(genesis, 0x11);
    admission_fill(beacon, 0x31);
    admission_fill(master_seed, 0x51);
    admission_fill(f->online_seed, 0x71);
    admission_fill(source_noise_secret, 0x91);
    admission_fill(target_noise_secret, 0xb1);
    admission_fill(ephemeral_secret, 0xd1);
    uint8_t online_pub[32], source_noise[32], ephemeral_pub[32];
    ed25519_keypair(online_pub, online_secret, f->online_seed);
    memset(online_secret, 0, sizeof(online_secret));
    if (!curve25519_scalarmult_base(source_noise, source_noise_secret) ||
        !curve25519_scalarmult_base(f->local_noise, target_noise_secret) ||
        !curve25519_scalarmult_base(ephemeral_pub, ephemeral_secret) ||
        vcs_zcode_dht_delegation_sign(
            &f->delegation, genesis, online_pub, source_noise, 120, beacon,
            1000, 4000, 7, master_seed) != VCS_ZCODE_DHT_DELEGATION_OK)
        return false;
    admission_fill(f->local_master, 0xf1);

    memcpy(f->pairing.network_genesis, genesis, 32);
    memcpy(f->pairing.peer_master_pubkey,
           f->delegation.doc.master_pubkey, 32);
    memcpy(f->pairing.peer_noise_pubkey, source_noise, 32);
    f->pairing.capability_mask = MESH_PAIRING_CAP_STATUS_READ;
    f->pairing.delegation_sequence = 7;
    f->pairing.paired_at = 2000;
    f->pairing.expires_at = 4000;
    if (!mesh_pairing_id_derive(
            genesis, f->pairing.peer_master_pubkey,
            f->pairing.peer_noise_pubkey, f->pairing.pairing_id) ||
        !db_mesh_pairing_insert(&f->ndb, &f->pairing))
        return false;

    memcpy(f->grant.pairing_id, f->pairing.pairing_id,
           sizeof(f->grant.pairing_id));
    memcpy(f->grant.target_master_pubkey, f->local_master, 32);
    memcpy(f->grant.target_noise_static, f->local_noise, 32);
    f->grant.operation = MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE;
    admission_fill(f->grant.plaintext_root, 0x22);
    admission_fill(f->grant.ciphertext_root, 0x42);
    f->grant.object_size_bytes =
        MESH_CAPABILITY_GRANT_CHUNK_PAYLOAD_BYTES + 3u;
    f->grant.chunk_count = 2;
    f->grant.ciphertext_size_bytes = f->grant.object_size_bytes + 32u;
    f->grant.storage_limit_bytes = f->grant.object_size_bytes +
                                   f->grant.ciphertext_size_bytes;
    f->grant.transfer_limit_bytes = f->grant.ciphertext_size_bytes;
    f->grant.max_chunk_bytes = MESH_CAPABILITY_GRANT_CHUNK_BYTES;
    f->grant.wall_limit_seconds = 200;
    admission_fill(f->grant.nonce, 0x62);
    f->grant.deny_mask = MESH_CAPABILITY_DENY_MANDATORY;
    f->grant.issued_at = 2100;
    f->grant.not_before = 2100;
    f->grant.expires_at = 2600;
    if (!mesh_capability_grant_id_derive(&f->grant, f->grant.grant_id) ||
        !db_mesh_capability_grant_insert(&f->ndb, &f->grant))
        return false;

    f->offer.version = MESH_PRIVATE_OBJECT_PROTO_VERSION;
    memcpy(f->offer.network_genesis, genesis, 32);
    if (!zcl_hex_decode_lower(f->pairing.pairing_id,
                              f->offer.pairing_id, 32) ||
        !zcl_hex_decode_lower(f->grant.grant_id, f->offer.grant_id, 32))
        return false;
    memcpy(f->offer.source_master_pubkey,
           f->delegation.doc.master_pubkey, 32);
    memcpy(f->offer.source_noise_static, source_noise, 32);
    memcpy(f->offer.source_online_pubkey, online_pub, 32);
    memcpy(f->offer.target_master_pubkey, f->local_master, 32);
    memcpy(f->offer.target_noise_static, f->local_noise, 32);
    admission_fill(f->offer.transcript_hash, 0x82);
    f->offer.connection_generation = 9;
    memcpy(f->offer.plaintext_root, f->grant.plaintext_root, 32);
    memcpy(f->offer.ciphertext_root, f->grant.ciphertext_root, 32);
    f->offer.object_size_bytes = f->grant.object_size_bytes;
    f->offer.ciphertext_size_bytes = f->grant.ciphertext_size_bytes;
    f->offer.chunk_size = f->grant.max_chunk_bytes;
    f->offer.chunk_count = f->grant.chunk_count;
    memcpy(f->offer.ephemeral_x25519_pubkey, ephemeral_pub, 32);
    f->offer.issued_unix = 2150;
    f->offer.expires_unix = 2250;
    f->offer.deny_mask = f->grant.deny_mask;
    if (mesh_private_object_offer_request_id_v1_derive(
            &f->offer, f->grant.nonce, f->offer.request_id) !=
            MESH_PRIVATE_OBJECT_PROTO_OK ||
        mesh_private_object_offer_v1_sign(&f->offer, f->online_seed) !=
            MESH_PRIVATE_OBJECT_PROTO_OK)
        return false;
    f->session.established = true;
    memcpy(f->session.remote_static, source_noise, 32);
    memcpy(f->session.transcript_hash, f->offer.transcript_hash, 32);
    f->session.connection_generation = f->offer.connection_generation;
    return true;
}

static int admission_claim_and_refuse(struct admission_fixture *f)
{
    int failures = 0;
    TEST_CASE("private object admission claims once and resumes exactly") {
        struct mesh_private_object_admission admitted, resumed;
        struct zcl_result result = mesh_private_object_admit_offer(
            &f->ndb, &f->offer, &f->session, &f->delegation,
            f->local_master, f->local_noise, 2200, &admitted);
        ASSERT(result.ok);
        ASSERT_EQ(admitted.reason, MESH_PRIVATE_OBJECT_ADMISSION_NEW);
        result = mesh_private_object_admit_offer(
            &f->ndb, &f->offer, &f->session, &f->delegation,
            f->local_master, f->local_noise, 2201, &resumed);
        ASSERT(result.ok);
        ASSERT_EQ(resumed.reason, MESH_PRIVATE_OBJECT_ADMISSION_RESUME);
        ASSERT(memcmp(admitted.transfer_id, resumed.transfer_id, 32) == 0);

        struct mesh_private_object_offer_v1 trial = f->offer;
        uint8_t wrong_nonce[32];
        admission_fill(wrong_nonce, 0xa2);
        ASSERT_EQ(mesh_private_object_offer_request_id_v1_derive(
                      &trial, wrong_nonce, trial.request_id),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        ASSERT_EQ(mesh_private_object_offer_v1_sign(&trial, f->online_seed),
                  MESH_PRIVATE_OBJECT_PROTO_OK);
        result = mesh_private_object_admit_offer(
            &f->ndb, &trial, &f->session, &f->delegation,
            f->local_master, f->local_noise, 2201, &resumed);
        ASSERT(result.ok);
        ASSERT_EQ(resumed.reason, MESH_PRIVATE_OBJECT_ADMISSION_NONCE_MISMATCH);

        struct v2_transport_snapshot wrong_session = f->session;
        wrong_session.transcript_hash[0] ^= 1;
        result = mesh_private_object_admit_offer(
            &f->ndb, &f->offer, &wrong_session, &f->delegation,
            f->local_master, f->local_noise, 2201, &resumed);
        ASSERT(result.ok);
        ASSERT_EQ(resumed.reason,
                  MESH_PRIVATE_OBJECT_ADMISSION_SESSION_MISMATCH);
    } TEST_END
    return failures;
}

int test_mesh_private_object_admission(void)
{
    int failures = 0;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_private_object", "admission");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct admission_fixture fixture;
    if (!admission_fixture_open(&fixture, path)) {
        failures++;
        goto done;
    }
    failures += admission_claim_and_refuse(&fixture);
done:
    if (fixture.ndb.open)
        node_db_close(&fixture.ndb);
    test_rm_rf_recursive(dir);
    return failures;
}
