/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: contract coverage for re-running the pairing ceremony. A second
 * `ops mesh pair commit` for the same peer identity is idempotent (unchanged,
 * or a later expiry extends the window, never shortens it); a different scope
 * or delegation sequence under the same pairing id is IDENTITY_COLLISION; a
 * revoked id stays revoked. One peer seen over several transports resolves to
 * one candidate, while different fingerprints stay ambiguous and are named.
 * Called by test_mesh_pairing() with its chain-bound delegation fixture. */

#include "test/test_core.h"

#include "config/boot_mesh_pairing.h"
#include "config/boot_mesh_status.h"
#include "crypto/ed25519.h"
#include "dev/fleet_roles.h"
#include "util/fleet_role_check.h"
#include "models/mesh_pairing.h"
#include "services/mesh_pairing_service.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdio.h>
#include <string.h>

/* The fixture's own signing inputs (test_mesh_pairing.c mesh_fixture), with
 * only the delegation sequence and the master seed varied. */
static bool rerun_delegation(struct vcs_zcode_dht_delegation *out,
                             const uint8_t genesis[32], uint64_t sequence,
                             uint8_t seed_byte)
{
    uint8_t beacon[32], online[32], noise[32], seed[32];
    memset(beacon, 0x22, 32);
    memset(online, 0x44, 32);
    memset(noise, 0x55, 32);
    memset(seed, seed_byte, 32);
    return vcs_zcode_dht_delegation_sign(
               out, genesis, online, noise, ZCL_FINALITY_DEPTH, beacon, 1000,
               4000, sequence, seed) == VCS_ZCODE_DHT_DELEGATION_OK;
}

static enum mesh_pairing_reason rerun_accept(
    struct node_db *ndb, const uint8_t genesis[32],
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t fingerprint[32], uint64_t mask, int64_t now,
    int64_t expires_at, struct db_mesh_pairing *out)
{
    return mesh_pairing_service_accept(
        ndb, genesis, delegation, fingerprint, delegation->noise_static_pubkey,
        true, mask, now, expires_at, out);
}

static int test_rerun_commit(struct node_db *ndb,
                             const struct vcs_zcode_dht_delegation *delegation,
                             const uint8_t fingerprint[32],
                             const uint8_t genesis[32])
{
    int failures = 0;
    struct db_mesh_pairing first, again, stored;
    const uint64_t read = MESH_PAIRING_CAP_STATUS_READ;

    TEST("mesh pairing rerun: identical re-commit returns the record "
         "unchanged") {
        ASSERT_EQ(rerun_accept(ndb, genesis, delegation, fingerprint, read,
                               2000, 3000, &first), MESH_PAIRING_OK);
        /* A later clock and a window that is not longer: the old code
         * compared paired_at and expires_at and refused this. */
        ASSERT_EQ(rerun_accept(ndb, genesis, delegation, fingerprint, read,
                               2100, 3000, &again), MESH_PAIRING_OK);
        ASSERT(strcmp(again.pairing_id, first.pairing_id) == 0);
        ASSERT_EQ(again.paired_at, 2000);
        ASSERT_EQ(again.expires_at, 3000);
        ASSERT_EQ(rerun_accept(ndb, genesis, delegation, fingerprint, read,
                               2200, 2900, &again), MESH_PAIRING_OK);
        ASSERT_EQ(again.expires_at, 3000); /* never shortened */
        ASSERT(db_mesh_pairing_find(ndb, first.pairing_id, &stored));
        ASSERT_EQ(stored.paired_at, 2000);
        ASSERT_EQ(stored.expires_at, 3000);
        PASS();
    }

    TEST("mesh pairing rerun: a later expiry extends the window") {
        ASSERT_EQ(rerun_accept(ndb, genesis, delegation, fingerprint, read,
                               2300, 3500, &again), MESH_PAIRING_OK);
        ASSERT_EQ(again.expires_at, 3500);
        ASSERT_EQ(again.paired_at, 2000);
        ASSERT(db_mesh_pairing_find(ndb, first.pairing_id, &stored));
        ASSERT_EQ(stored.expires_at, 3500);
        ASSERT_EQ(stored.capability_mask, read);
        ASSERT_EQ(stored.delegation_sequence, 7);
        ASSERT(mesh_pairing_allows(&stored, read, 3200));
        PASS();
    }

    TEST("mesh pairing rerun: another scope, sequence or master never "
         "rewrites the record") {
        struct vcs_zcode_dht_delegation resequenced, stranger;
        ASSERT(rerun_delegation(&resequenced, genesis, 8, 0x66));
        ASSERT(rerun_delegation(&stranger, genesis, 7, 0x67));
        ASSERT_EQ(rerun_accept(ndb, genesis, delegation, fingerprint,
                               read | MESH_PAIRING_CAP_TERMINAL_EXEC, 2400,
                               9000, &again), MESH_PAIRING_IDENTITY_COLLISION);
        ASSERT_EQ(rerun_accept(ndb, genesis, &resequenced, fingerprint, read,
                               2400, 9000, &again),
                  MESH_PAIRING_IDENTITY_COLLISION);
        /* A master with no active ZID projection cannot take the slot. */
        ASSERT_EQ(rerun_accept(ndb, genesis, &stranger, fingerprint, read,
                               2400, 9000, &again),
                  MESH_PAIRING_MASTER_INACTIVE);
        ASSERT(db_mesh_pairing_find(ndb, first.pairing_id, &stored));
        ASSERT_EQ(stored.expires_at, 3500);
        ASSERT_EQ(stored.capability_mask, read);
        ASSERT_EQ(stored.delegation_sequence, 7);
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(ndb, 2500, &counts));
        ASSERT_EQ(counts.total, 1);
        PASS();
    }

    TEST("mesh pairing rerun: a revoked id is not revived by a later expiry") {
        ASSERT_EQ(mesh_pairing_service_revoke(ndb, first.pairing_id, 2600),
                  MESH_PAIRING_OK);
        ASSERT_EQ(rerun_accept(ndb, genesis, delegation, fingerprint, read,
                               2700, 9000, &again),
                  MESH_PAIRING_ALREADY_REVOKED);
        ASSERT(db_mesh_pairing_find(ndb, first.pairing_id, &stored));
        ASSERT_EQ(stored.expires_at, 3500);
        ASSERT(!db_mesh_pairing_extend(ndb, first.pairing_id, 9000));
        PASS();
    }
_test_next:
    return failures;
}

static void rerun_session(struct boot_mesh_pairing_session *session,
                          char fill, const char *tail, int64_t last_recv)
{
    memset(session, 0, sizeof(*session));
    memset(session->fingerprint_hex, fill, 64);
    memcpy(session->fingerprint_hex + 4, tail, strlen(tail));
    session->last_recv = last_recv;
}

static int test_rerun_selector(void)
{
    int failures = 0;
    struct boot_mesh_pairing_session sessions[3];
    struct boot_mesh_pairing_resolution resolved;

    TEST("boot_mesh_pairing_resolve: three sessions with one "
         "fingerprint resolve to one candidate") {
        /* onion, public IP, loopback: same peer, different activity. */
        rerun_session(&sessions[0], 'a', "", 100);
        rerun_session(&sessions[1], 'a', "", 300);
        rerun_session(&sessions[2], 'a', "", 200);
        boot_mesh_pairing_resolve(sessions, 3, &resolved);
        ASSERT_EQ(resolved.distinct, 1);
        ASSERT_EQ(resolved.best, 1); /* the most recently active session */
        PASS();
    }

    TEST("boot_mesh_pairing_resolve: two fingerprints under one prefix "
         "stay distinct and are named") {
        rerun_session(&sessions[0], 'a', "1111", 100);
        rerun_session(&sessions[1], 'a', "2222", 300);
        rerun_session(&sessions[2], 'a', "1111", 200);
        ASSERT(boot_mesh_pairing_selector_matches(
            "aaaa", "x", sessions[0].fingerprint_hex));
        ASSERT(boot_mesh_pairing_selector_matches(
            "aaaa", "x", sessions[1].fingerprint_hex));
        boot_mesh_pairing_resolve(sessions, 3, &resolved);
        ASSERT_EQ(resolved.distinct, 2);
        ASSERT(strstr(resolved.shown, "aaaa1111") != NULL);
        ASSERT(strstr(resolved.shown, "aaaa2222") != NULL);
        ASSERT_EQ((int)strlen(resolved.shown),
                  2 * BOOT_MESH_PAIRING_SHORT_FP + 1);
        boot_mesh_pairing_resolve(sessions, 0, &resolved);
        ASSERT_EQ(resolved.distinct, 0);
        PASS();
    }

    TEST("boot_mesh_pairing_resolve: a session with an empty fingerprint is "
         "no candidate and never the best one") {
        rerun_session(&sessions[0], 'a', "", 100);
        rerun_session(&sessions[1], 'a', "", 50);
        memset(&sessions[2], 0, sizeof(sessions[2]));
        sessions[2].last_recv = 900; /* most recent, but unidentified */
        boot_mesh_pairing_resolve(sessions, 3, &resolved);
        ASSERT_EQ(resolved.distinct, 1);
        ASSERT_EQ(resolved.best, 0);
        boot_mesh_pairing_resolve(&sessions[2], 1, &resolved);
        ASSERT_EQ(resolved.distinct, 0);
        PASS();
    }
_test_next:
    return failures;
}


/* The value `ops mesh pair plan` prints for `fleet roles grant --fp=` must be
 * the one the role check derives: grant exactly what was printed, then ask the
 * production checker (tools/dev/fleet_roles_gate.c) about that key. */
static bool rerun_grant(const char *datadir, const uint8_t fp[32])
{
    uint8_t op_pub[32], op_seed[32], op_sk[32];
    memset(op_seed, 0x11, sizeof(op_seed));
    zcl_ed25519_keypair(op_pub, op_sk, op_seed);
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(datadir, &report);
    if (!store)
        return false;
    enum zcl_role_status st = zcl_role_store_grant(
        store, fp, ZCL_ROLE_worker, op_pub, op_seed, 1000, NULL);
    zcl_role_store_close(store);
    return st == ZCL_ROLE_OK;
}

static int test_rerun_role_fp(void)
{
    int failures = 0;
    char dir[256], printed[65], legacy[65], why[ZCL_FLEET_ROLE_WHY_MAX];
    uint8_t key[32], other[32], sk[32], seed[32], fp[32];
    memset(seed, 0x31, sizeof(seed));
    zcl_ed25519_keypair(key, sk, seed);
    memset(seed, 0x32, sizeof(seed));
    zcl_ed25519_keypair(other, sk, seed);
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing_rerun", "role_fp");
    zcl_fleet_role_checker_install(NULL);

    TEST("mesh pairing plan: the printed grant fingerprint is the one the "
         "role check derives") {
        ASSERT(!boot_mesh_pairing_role_fp_hex(key, printed)); /* no checker */
        zcl_fleet_roles_enforcement_start(dir);
        ASSERT(boot_mesh_pairing_role_fp_hex(key, printed));
        ASSERT(boot_mesh_pairing_decode_fingerprint(printed, fp));
        ASSERT(!zcl_fleet_role_allows(key, ZCL_FLEET_LEAF_BOARD_POST, "note",
                                      why, sizeof(why)));
        ASSERT(rerun_grant(dir, fp));
        ASSERT(zcl_fleet_role_allows(key, ZCL_FLEET_LEAF_BOARD_POST, "note",
                                     why, sizeof(why)));
        PASS();
    }

    TEST("mesh pairing plan: the plain domain hash that is not the role "
         "fingerprint grants nothing") {
        /* The legacy display fingerprint hashes the domain without its NUL. */
        boot_mesh_status_key_fingerprint("zcl.fleet_role_fingerprint.v1",
                                         other, legacy);
        ASSERT(boot_mesh_pairing_role_fp_hex(other, printed));
        ASSERT(strcmp(legacy, printed) != 0);
        ASSERT(boot_mesh_pairing_decode_fingerprint(legacy, fp));
        ASSERT(rerun_grant(dir, fp));
        ASSERT(!zcl_fleet_role_allows(other, ZCL_FLEET_LEAF_BOARD_POST,
                                      "note", why, sizeof(why)));
        PASS();
    }
_test_next:
    zcl_fleet_role_checker_install(NULL);
    return failures;
}

int test_mesh_pairing_rerun(struct node_db *ndb,
                            const struct vcs_zcode_dht_delegation *delegation,
                            const uint8_t fingerprint[32],
                            const uint8_t genesis[32])
{
    return test_rerun_commit(ndb, delegation, fingerprint, genesis) +
           test_rerun_selector() + test_rerun_role_fp();
}
