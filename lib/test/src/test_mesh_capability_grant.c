/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Focused durable private-object grant authority tests. */

#include "test/test_core.h"

#include "models/mesh_capability_grant.h"
#include "models/mesh_pairing.h"

#include <stdio.h>
#include <string.h>

static void capability_fill32(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static bool capability_pairing(struct node_db *ndb,
                               struct db_mesh_pairing *out)
{
    memset(out, 0, sizeof(*out));
    capability_fill32(out->network_genesis, 0x11);
    capability_fill32(out->peer_master_pubkey, 0x22);
    capability_fill32(out->peer_noise_pubkey, 0x33);
    out->capability_mask = MESH_PAIRING_CAP_STATUS_READ;
    out->delegation_sequence = 1;
    out->paired_at = 1000;
    out->expires_at = 5000;
    return mesh_pairing_id_derive(
               out->network_genesis, out->peer_master_pubkey,
               out->peer_noise_pubkey, out->pairing_id) &&
           db_mesh_pairing_insert(ndb, out);
}

static bool capability_grant(const struct db_mesh_pairing *pairing,
                             uint8_t discriminator,
                             struct db_mesh_capability_grant *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->pairing_id, pairing->pairing_id, sizeof(out->pairing_id));
    capability_fill32(out->target_master_pubkey, 0x91);
    capability_fill32(out->target_noise_static, 0xa1);
    out->operation = MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE;
    capability_fill32(out->plaintext_root, discriminator);
    capability_fill32(out->ciphertext_root, (uint8_t)(discriminator + 1));
    out->object_size_bytes =
        MESH_CAPABILITY_GRANT_CHUNK_PAYLOAD_BYTES + 1u;
    out->chunk_count = 2;
    out->ciphertext_size_bytes = out->object_size_bytes +
        (uint64_t)MESH_CAPABILITY_GRANT_CHUNK_TAG_BYTES * out->chunk_count;
    out->storage_limit_bytes =
        out->ciphertext_size_bytes + out->object_size_bytes;
    out->transfer_limit_bytes = out->ciphertext_size_bytes;
    out->max_chunk_bytes = MESH_CAPABILITY_GRANT_CHUNK_BYTES;
    out->wall_limit_seconds = 60;
    capability_fill32(out->nonce, (uint8_t)(discriminator + 2));
    out->deny_mask = MESH_CAPABILITY_DENY_MANDATORY;
    out->issued_at = 2000;
    out->not_before = 2100;
    out->expires_at = 3000;
    return mesh_capability_grant_id_derive(out, out->grant_id);
}

static int exact_and_geometry(struct node_db *ndb,
                              const struct db_mesh_pairing *pairing)
{
    int failures = 0;
    TEST_CASE("mesh capability grant binds target and canonical geometry") {
        struct db_mesh_capability_grant grant, found, trial;
        struct ar_errors errors;
        ASSERT(capability_grant(pairing, 0x41, &grant));
        ASSERT(db_mesh_capability_grant_insert(ndb, &grant));
        ASSERT(db_mesh_capability_grant_insert(ndb, &grant));
        ASSERT(db_mesh_capability_grant_find(ndb, grant.grant_id, &found));
        ASSERT_EQ(found.chunk_count, 2);
        ASSERT_EQ(found.max_chunk_bytes, 65536);
        ASSERT_EQ(found.deny_mask, UINT64_C(255));
        ASSERT(memcmp(found.target_noise_static,
                      grant.target_noise_static, 32) == 0);

        trial = grant;
        trial.target_master_pubkey[0] ^= 1;
        ASSERT(!db_mesh_capability_grant_validate(&trial, &errors));
        trial = grant;
        trial.max_chunk_bytes--;
        ASSERT(mesh_capability_grant_id_derive(&trial, trial.grant_id));
        ASSERT(!db_mesh_capability_grant_validate(&trial, &errors));
        trial = grant;
        trial.ciphertext_size_bytes++;
        trial.storage_limit_bytes++;
        trial.transfer_limit_bytes++;
        ASSERT(mesh_capability_grant_id_derive(&trial, trial.grant_id));
        ASSERT(!db_mesh_capability_grant_validate(&trial, &errors));
        trial = grant;
        trial.storage_limit_bytes--;
        ASSERT(mesh_capability_grant_id_derive(&trial, trial.grant_id));
        ASSERT(!db_mesh_capability_grant_validate(&trial, &errors));
        trial = grant;
        trial.deny_mask &= ~MESH_CAPABILITY_DENY_INSTALL;
        ASSERT(mesh_capability_grant_id_derive(&trial, trial.grant_id));
        ASSERT(!db_mesh_capability_grant_validate(&trial, &errors));

        trial = grant;
        trial.object_size_bytes = MESH_CAPABILITY_GRANT_CHUNK_PAYLOAD_BYTES;
        trial.chunk_count = 1;
        trial.ciphertext_size_bytes = trial.object_size_bytes + 16;
        trial.storage_limit_bytes =
            trial.ciphertext_size_bytes + trial.object_size_bytes;
        trial.transfer_limit_bytes = trial.ciphertext_size_bytes;
        ASSERT(mesh_capability_grant_id_derive(&trial, trial.grant_id));
        ASSERT(db_mesh_capability_grant_validate(&trial, &errors));
    } TEST_END
    return failures;
}

static int claim_complete_restart(struct node_db *ndb, const char *path,
                                  const struct db_mesh_pairing *pairing)
{
    int failures = 0;
    TEST_CASE("mesh capability grant claims, resumes, and completes exactly") {
        struct db_mesh_capability_grant grant, found;
        uint8_t transfer[32], other[32];
        capability_fill32(transfer, 0xc1);
        capability_fill32(other, 0xd1);
        ASSERT(capability_grant(pairing, 0x51, &grant));
        ASSERT(db_mesh_capability_grant_insert(ndb, &grant));
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, grant.grant_id, transfer, 0, 0, 2099),
                  MESH_CAPABILITY_CLAIM_REFUSED);
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, grant.grant_id, transfer, 0, 0, 2200),
                  MESH_CAPABILITY_CLAIM_NEW);
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, grant.grant_id, transfer, 0, 0, 2201),
                  MESH_CAPABILITY_CLAIM_RESUME);
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, grant.grant_id, other, 0, 0, 2201),
                  MESH_CAPABILITY_CLAIM_REFUSED);
        node_db_close(ndb);
        ASSERT(node_db_open(ndb, path));
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, grant.grant_id, transfer, 0, 0, 2202),
                  MESH_CAPABILITY_CLAIM_RESUME);
        ASSERT_EQ(db_mesh_capability_grant_complete(
                      ndb, grant.grant_id, other, 0, 0, 2203),
                  MESH_CAPABILITY_COMPLETE_REFUSED);
        ASSERT_EQ(db_mesh_capability_grant_complete(
                      ndb, grant.grant_id, transfer, 0, 0, 2203),
                  MESH_CAPABILITY_COMPLETE_NEW);
        ASSERT_EQ(db_mesh_capability_grant_complete(
                      ndb, grant.grant_id, transfer, 0, 0, 2204),
                  MESH_CAPABILITY_COMPLETE_REPLAY);
        ASSERT(db_mesh_capability_grant_find(ndb, grant.grant_id, &found));
        ASSERT_EQ(found.claimed_at, 2200);
        ASSERT_EQ(found.consumed_at, 2203);
        ASSERT(db_mesh_capability_grant_revoke(ndb, grant.grant_id, 2205));
        ASSERT_EQ(db_mesh_capability_grant_complete(
                      ndb, grant.grant_id, transfer, 0, 0, 2206),
                  MESH_CAPABILITY_COMPLETE_REFUSED);
    } TEST_END
    return failures;
}

static int revocation_races(struct node_db *ndb,
                            struct db_mesh_pairing *pairing)
{
    int failures = 0;
    TEST_CASE("mesh capability grant revocation wins claim and completion") {
        struct db_mesh_capability_grant revoked, blocked;
        uint8_t transfer[32];
        capability_fill32(transfer, 0xe1);
        ASSERT(capability_grant(pairing, 0x61, &revoked));
        ASSERT(db_mesh_capability_grant_insert(ndb, &revoked));
        ASSERT(db_mesh_capability_grant_revoke(ndb, revoked.grant_id, 2200));
        ASSERT(db_mesh_capability_grant_revoke(ndb, revoked.grant_id, 2300));
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, revoked.grant_id, transfer, 0, 0, 2400),
                  MESH_CAPABILITY_CLAIM_REFUSED);

        ASSERT(capability_grant(pairing, 0x71, &blocked));
        ASSERT(db_mesh_capability_grant_insert(ndb, &blocked));
        ASSERT_EQ(db_mesh_capability_grant_claim(
                      ndb, blocked.grant_id, transfer, 0, 0, 2300),
                  MESH_CAPABILITY_CLAIM_NEW);
        ASSERT(db_mesh_pairing_revoke(ndb, pairing->pairing_id, 2400));
        ASSERT_EQ(db_mesh_capability_grant_complete(
                      ndb, blocked.grant_id, transfer, 0, 0, 2500),
                  MESH_CAPABILITY_COMPLETE_REFUSED);
    } TEST_END
    return failures;
}

int test_mesh_capability_grant(void)
{
    int failures = 0;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_capability", "authority");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb = {0};
    struct db_mesh_pairing pairing;
    if (!node_db_open(&ndb, path) || !capability_pairing(&ndb, &pairing)) {
        failures++;
        goto done;
    }
    failures += exact_and_geometry(&ndb, &pairing);
    failures += claim_complete_restart(&ndb, path, &pairing);
    failures += revocation_races(&ndb, &pairing);
done:
    if (ndb.open)
        node_db_close(&ndb);
    test_rm_rf_recursive(dir);
    return failures;
}
