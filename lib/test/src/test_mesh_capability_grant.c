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
    out->operation = MESH_CAPABILITY_PRIVATE_OBJECT_RECEIVE;
    capability_fill32(out->plaintext_root, discriminator);
    capability_fill32(out->ciphertext_root, (uint8_t)(discriminator + 1));
    out->object_size_bytes = 1000;
    out->ciphertext_size_bytes = 1100;
    out->storage_limit_bytes = 4096;
    out->transfer_limit_bytes = 4096;
    out->chunk_limit = 2;
    out->max_chunk_bytes = 1024;
    out->wall_limit_seconds = 60;
    capability_fill32(out->nonce, (uint8_t)(discriminator + 2));
    out->deny_mask = MESH_CAPABILITY_DENY_MANDATORY;
    out->issued_at = 2000;
    out->not_before = 2100;
    out->expires_at = 3000;
    return mesh_capability_grant_id_derive(out, out->grant_id);
}

int test_mesh_capability_grant(void)
{
    int failures = 0;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_capability", "authority");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb = {0};
    struct db_mesh_pairing pairing;

    TEST("mesh capability grant: exact authority is durable and insert-only") {
        ASSERT(node_db_open(&ndb, path));
        ASSERT(capability_pairing(&ndb, &pairing));
        struct db_mesh_capability_grant grant, found;
        ASSERT(capability_grant(&pairing, 0x41, &grant));
        ASSERT(db_mesh_capability_grant_insert(&ndb, &grant));
        ASSERT(db_mesh_capability_grant_insert(&ndb, &grant));
        ASSERT(db_mesh_capability_grant_find(&ndb, grant.grant_id, &found));
        ASSERT_EQ(found.object_size_bytes, 1000);
        ASSERT_EQ(found.ciphertext_size_bytes, 1100);
        ASSERT_EQ(found.deny_mask, MESH_CAPABILITY_DENY_MANDATORY);

        struct ar_errors errors;
        struct db_mesh_capability_grant widened = grant;
        widened.transfer_limit_bytes++;
        ASSERT(!db_mesh_capability_grant_validate(&widened, &errors));
        widened = grant;
        widened.deny_mask &= ~MESH_CAPABILITY_DENY_WALLET;
        ASSERT(mesh_capability_grant_id_derive(&widened, widened.grant_id));
        ASSERT(!db_mesh_capability_grant_validate(&widened, &errors));
        PASS();
    }

    TEST("mesh capability grant: consume is one-use and survives restart") {
        struct db_mesh_capability_grant grant, found;
        ASSERT(capability_grant(&pairing, 0x51, &grant));
        ASSERT(db_mesh_capability_grant_insert(&ndb, &grant));
        ASSERT(!db_mesh_capability_grant_consume(
            &ndb, grant.grant_id, grant.nonce, 2099));
        uint8_t wrong_nonce[32];
        capability_fill32(wrong_nonce, 0xee);
        ASSERT(!db_mesh_capability_grant_consume(
            &ndb, grant.grant_id, wrong_nonce, 2200));
        ASSERT(db_mesh_capability_grant_consume(
            &ndb, grant.grant_id, grant.nonce, 2200));
        ASSERT(!db_mesh_capability_grant_consume(
            &ndb, grant.grant_id, grant.nonce, 2201));
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT(db_mesh_capability_grant_find(&ndb, grant.grant_id, &found));
        ASSERT_EQ(found.consumed_at, 2200);
        PASS();
    }

    TEST("mesh capability grant: revoke is sticky and pairing revoke wins") {
        struct db_mesh_capability_grant revoked, blocked, found;
        ASSERT(capability_grant(&pairing, 0x61, &revoked));
        ASSERT(db_mesh_capability_grant_insert(&ndb, &revoked));
        ASSERT(db_mesh_capability_grant_revoke(&ndb, revoked.grant_id, 2200));
        ASSERT(db_mesh_capability_grant_revoke(&ndb, revoked.grant_id, 2300));
        ASSERT(db_mesh_capability_grant_find(&ndb, revoked.grant_id, &found));
        ASSERT_EQ(found.revoked_at, 2200);
        ASSERT_EQ(found.revocation_generation, 1);
        ASSERT(!db_mesh_capability_grant_consume(
            &ndb, revoked.grant_id, revoked.nonce, 2400));

        ASSERT(capability_grant(&pairing, 0x71, &blocked));
        ASSERT(db_mesh_capability_grant_insert(&ndb, &blocked));
        ASSERT(db_mesh_pairing_revoke(&ndb, pairing.pairing_id, 2400));
        ASSERT(!db_mesh_capability_grant_consume(
            &ndb, blocked.grant_id, blocked.nonce, 2500));
        PASS();
    }

_test_next:
    if (ndb.open)
        node_db_close(&ndb);
    test_rm_rf_recursive(dir);
    return failures;
}
