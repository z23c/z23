/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves that local machine pairing is explicit, Noise-bound, narrowly
 * scoped, expiring, and durably revoked. */

#include "test/test_core.h"

#include "config/boot_mesh_pairing.h"
#include "base/hex.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "services/mesh_pairing_service.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdio.h>
#include <string.h>

static void mesh_fill32(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* raw-sql-ok:test-fixture -- creates only the connected chain rows required
 * to exercise the production chain-bound pairing verifier. */
static bool mesh_seed_block(struct node_db *ndb, int height,
                            const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    static const char sql[] =
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status,num_tx) "
        "VALUES(?,?,zeroblob(32),4,zeroblob(32),1,1,zeroblob(32),"
        "X'00',zeroblob(32),3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool mesh_fixture(struct node_db *ndb, const char *path,
                         struct vcs_zcode_dht_delegation *delegation,
                         uint8_t fingerprint[32])
{
    if (!node_db_open(ndb, path))
        return false;
    uint8_t genesis[32], beacon[32], tip[32], online[32], noise[32], seed[32];
    mesh_fill32(genesis, 0x11);
    mesh_fill32(beacon, 0x22);
    mesh_fill32(tip, 0x33);
    mesh_fill32(online, 0x44);
    mesh_fill32(noise, 0x55);
    mesh_fill32(seed, 0x66);
    if (!mesh_seed_block(ndb, 0, genesis) ||
        !mesh_seed_block(ndb, ZCL_FINALITY_DEPTH, beacon) ||
        !mesh_seed_block(ndb, 2 * ZCL_FINALITY_DEPTH, tip) ||
        vcs_zcode_dht_delegation_sign(
            delegation, genesis, online, noise, ZCL_FINALITY_DEPTH, beacon,
            1000, 4000, 7, seed) != VCS_ZCODE_DHT_DELEGATION_OK ||
        !v2_identity_public_fingerprint(noise, fingerprint))
        return false;
    struct zid_identity identity = {0};
    memcpy(identity.master_pubkey, delegation->doc.master_pubkey, 32);
    mesh_fill32(identity.anchor_txid, 0x77);
    identity.anchor_height = 0;
    identity.updated_height = 0;
    snprintf(identity.status, sizeof(identity.status), "%s",
             ZID_IDENTITY_STATUS_ACTIVE);
    snprintf(identity.source, sizeof(identity.source), "%s",
             ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    return db_zid_identity_save(ndb, &identity);
}

int test_mesh_pairing(void)
{
    int failures = 0;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "authority");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb = {0};
    struct vcs_zcode_dht_delegation delegation;
    uint8_t fingerprint[32];

    TEST("mesh pairing: explicit Noise-bound acceptance is durable") {
        ASSERT(mesh_fixture(&ndb, path, &delegation, fingerprint));
        struct db_mesh_pairing row;
        uint8_t wrong[32];
        mesh_fill32(wrong, 0x99);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, wrong,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_FINGERPRINT_MISMATCH);
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 0);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, fingerprint, wrong, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_SESSION_MISMATCH);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_OK);
        ASSERT(mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 2500));
        ASSERT(!mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 3000));
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, 2500, &counts));
        ASSERT_EQ(counts.total, 1);
        ASSERT_EQ(counts.active, 1);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 0);
        ASSERT(db_mesh_pairing_count_states(&ndb, 3000, &counts));
        ASSERT_EQ(counts.active, 0);
        ASSERT_EQ(counts.expired, 1);
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2500),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        struct db_mesh_pairing persisted;
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &persisted));
        ASSERT_EQ(persisted.delegation_sequence, 7);
        PASS();
    }

    TEST("mesh pairing: revocation is sticky and cannot resurrect") {
        struct db_mesh_pairing row;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 1);
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, 2600),
                  MESH_PAIRING_OK);
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, 2700),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &row));
        ASSERT_EQ(row.revoked_at, 2600);
        ASSERT_EQ(row.revocation_generation, 1);
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, 2800, &counts));
        ASSERT_EQ(counts.total, 1);
        ASSERT_EQ(counts.active, 0);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 1);
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2800),
                  MESH_PAIRING_ALREADY_REVOKED);
        struct db_mesh_pairing refused;
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &refused),
                  MESH_PAIRING_ALREADY_REVOKED);
        PASS();
    }

    TEST("pairing commands: days default, clamp boundaries, and rejection") {
        ASSERT_EQ(BOOT_MESH_PAIRING_DEFAULT_DAYS, 7);
        ASSERT_EQ(BOOT_MESH_PAIRING_MAX_DAYS, 30);
        ASSERT(boot_mesh_pairing_days_valid(1));
        ASSERT(boot_mesh_pairing_days_valid(30));
        ASSERT(!boot_mesh_pairing_days_valid(0));
        ASSERT(!boot_mesh_pairing_days_valid(-1));
        ASSERT(!boot_mesh_pairing_days_valid(31));
        ASSERT_EQ(boot_mesh_pairing_expiry(10000, 7), 10000 + 7 * 86400);
        ASSERT_EQ(boot_mesh_pairing_expiry(10000, 30), 10000 + 30 * 86400);
        /* The 30-day ceiling lands exactly on the service's own window. */
        ASSERT_EQ(BOOT_MESH_PAIRING_MAX_DAYS * 86400,
                  MESH_PAIRING_MAX_LIFETIME_SECONDS);
        PASS();
    }

    TEST("pairing commands: selector matches addr substring or fingerprint prefix") {
        char fingerprint_hex[65];
        uint8_t fp[32];
        mesh_fill32(fp, 0xab);
        zcl_hex_encode(fp, 32, fingerprint_hex);
        ASSERT(boot_mesh_pairing_selector_matches(
            "168.1", "192.168.1.7:8033", fingerprint_hex));
        ASSERT(boot_mesh_pairing_selector_matches(
            fingerprint_hex, "192.168.1.7:8033", fingerprint_hex));
        fingerprint_hex[20] = '\0'; /* prefix match on the fingerprint hex */
        ASSERT(boot_mesh_pairing_selector_matches(
            fingerprint_hex, "192.168.1.7:8033",
            "ababababababababababababababababababababababababababababababababb"));
        ASSERT(!boot_mesh_pairing_selector_matches(
            "ffff", "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        ASSERT(boot_mesh_pairing_selector_matches(
            NULL, "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        ASSERT(boot_mesh_pairing_selector_matches(
            "", "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        PASS();
    }

    TEST("pairing commands: record state derives from now, revocation wins") {
        struct db_mesh_pairing row = {0};
        row.paired_at = 1000;
        row.expires_at = 3000;
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 2500), "active");
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 3000), "expired");
        row.revoked_at = 2600;
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 2500), "revoked");
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 3500), "revoked");
        PASS();
    }

    TEST("pairing commands: fingerprint decode is canonical lowercase hex") {
        uint8_t out[32];
        ASSERT(boot_mesh_pairing_decode_fingerprint(
            "abababababababababababababababababababababababababababababababab",
            out));
        ASSERT_EQ(out[0], 0xab);
        ASSERT_EQ(out[31], 0xab);
        ASSERT(!boot_mesh_pairing_decode_fingerprint("ab", out));
        ASSERT(!boot_mesh_pairing_decode_fingerprint(
            "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            out));
        ASSERT(!boot_mesh_pairing_decode_fingerprint(NULL, out));
        PASS();
    }

    TEST("pairing commands: every service reason maps to a distinct named code") {
        const enum mesh_pairing_reason reasons[] = {
            MESH_PAIRING_OK, MESH_PAIRING_BAD_ARGUMENT,
            MESH_PAIRING_CAPABILITY_UNAVAILABLE,
            MESH_PAIRING_FINGERPRINT_MISMATCH, MESH_PAIRING_NETWORK_MISMATCH,
            MESH_PAIRING_MASTER_INACTIVE, MESH_PAIRING_BEACON_UNAVAILABLE,
            MESH_PAIRING_BEACON_PROVISIONAL, MESH_PAIRING_DELEGATION_INVALID,
            MESH_PAIRING_WINDOW_INVALID, MESH_PAIRING_ALREADY_REVOKED,
            MESH_PAIRING_IDENTITY_COLLISION, MESH_PAIRING_PERSIST_FAILED,
            MESH_PAIRING_NOT_FOUND, MESH_PAIRING_EXPIRED,
            MESH_PAIRING_SESSION_MISMATCH, MESH_PAIRING_AUTHORITY_CHANGED,
            MESH_PAIRING_CONFIRMATION_INVALID, MESH_PAIRING_PLAN_EXPIRED,
        };
        for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
            const char *code = boot_mesh_pairing_reason_code(reasons[i]);
            ASSERT(code && code[0]);
            for (size_t j = i + 1;
                 j < sizeof(reasons) / sizeof(reasons[0]); j++)
                ASSERT(strcmp(code,
                              boot_mesh_pairing_reason_code(reasons[j])) != 0);
        }
        ASSERT_STR_EQ(
            boot_mesh_pairing_reason_code(MESH_PAIRING_FINGERPRINT_MISMATCH),
            "FINGERPRINT_MISMATCH");
        ASSERT_STR_EQ(boot_mesh_pairing_reason_code(MESH_PAIRING_NOT_FOUND),
                      "NOT_FOUND");
        ASSERT_STR_EQ(
            boot_mesh_pairing_reason_code(MESH_PAIRING_CONFIRMATION_INVALID),
            "CONFIRMATION_INVALID");
        ASSERT_STR_EQ(boot_mesh_pairing_reason_code(MESH_PAIRING_PLAN_EXPIRED),
                      "PLAN_EXPIRED");
        PASS();
    }

_test_next:
    if (ndb.open)
        node_db_close(&ndb);
    test_rm_rf_recursive(dir);
    return failures;
}
