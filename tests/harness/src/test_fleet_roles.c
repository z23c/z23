/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet ROLES: the closed role/grant catalog from
 * engine/composition/roles.def, and the local signed grant/revoke store
 * that binds a key's fingerprint to a role on this node.
 *
 * No clock in this file is ever read from the wall: every row is written
 * with an explicit `now` the test chose, the same way the neighbouring
 * fleet_ledger and fleet_board tests inject time rather than read it.
 */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "dev/fleet_roles.h"

#include <string.h>

/* A deterministic (pubkey, seed) pair, distinct per tag, with no real key
 * material and no real clock involved. */
static void make_key(uint8_t tag, uint8_t pub[32], uint8_t seed[32])
{
    memset(seed, tag, 32);
    uint8_t sk[32];
    zcl_ed25519_keypair(pub, sk, seed);
}

int test_fleet_roles(void)
{
    int failures = 0;
    char root[256];
    test_make_tmpdir(root, sizeof(root), "fleet_roles", "store");

    uint8_t op_pub[32], op_seed[32];
    uint8_t worker_pub[32], worker_seed_unused[32];
    uint8_t stranger_pub[32], stranger_seed_unused[32];
    make_key(0x01, op_pub, op_seed);
    make_key(0x02, worker_pub, worker_seed_unused);
    make_key(0x03, stranger_pub, stranger_seed_unused);

    uint8_t worker_fp[ZCL_ROLE_FP_BYTES];
    uint8_t stranger_fp[ZCL_ROLE_FP_BYTES];
    zcl_role_fingerprint(worker_pub, worker_fp);
    zcl_role_fingerprint(stranger_pub, stranger_fp);

    struct zcl_role_store *store = NULL;

    TEST("fleet roles: the catalog names every declared role and refuses "
         "an unknown one") {
        uint8_t role = 0;
        ASSERT(zcl_role_from_name("operator", &role));
        ASSERT_EQ(role, ZCL_ROLE_OPERATOR);
        ASSERT(zcl_role_from_name("worker", &role));
        ASSERT_STR_EQ(zcl_role_name(role), "worker");
        ASSERT(zcl_role_from_name("observer", &role));
        ASSERT(zcl_role_from_name("landing", &role));
        ASSERT(!zcl_role_from_name("nonexistent-role", &role));
        ASSERT(zcl_role_name(250) == NULL);
    }

    TEST("fleet roles: worker may post board note and result but not wiki, "
         "which is outside its declared kinds") {
        uint8_t role = 0;
        ASSERT(zcl_role_from_name("worker", &role));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.board.post", "note"));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.board.post", "chat"));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.board.post", "result"));
        ASSERT(!zcl_role_leaf_allowed(role, "fleet.board.post", "wiki"));
        /* read everything, including leaves reached through a wildcard */
        ASSERT(zcl_role_leaf_allowed(role, "fleet.wiki.read", NULL));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.wiki.history", NULL));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.ledger.status", NULL));
    }

    TEST("fleet roles: observer is refused every write leaf") {
        uint8_t role = 0;
        ASSERT(zcl_role_from_name("observer", &role));
        ASSERT(!zcl_role_leaf_allowed(role, "fleet.board.post", "note"));
        ASSERT(!zcl_role_leaf_allowed(role, "fleet.experiment.predict", NULL));
        ASSERT(!zcl_role_leaf_allowed(role, "fleet.roles.grant", NULL));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.board.list", NULL));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.wiki.read", NULL));
    }

    TEST("fleet roles: landing may post only kind=result about trains") {
        uint8_t role = 0;
        ASSERT(zcl_role_from_name("landing", &role));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.board.post", "result"));
        ASSERT(!zcl_role_leaf_allowed(role, "fleet.board.post", "note"));
        ASSERT(!zcl_role_leaf_allowed(role, "fleet.board.post", "chat"));
        ASSERT(zcl_role_leaf_allowed(role, "fleet.ledger.status", NULL));
    }

    TEST("fleet roles: a fingerprint is stable and distinguishes keys") {
        uint8_t fp_a[ZCL_ROLE_FP_BYTES], fp_a_again[ZCL_ROLE_FP_BYTES];
        zcl_role_fingerprint(worker_pub, fp_a);
        zcl_role_fingerprint(worker_pub, fp_a_again);
        ASSERT(memcmp(fp_a, fp_a_again, ZCL_ROLE_FP_BYTES) == 0);
        ASSERT(memcmp(fp_a, stranger_fp, ZCL_ROLE_FP_BYTES) != 0);
        char short_a[9], short_b[9];
        zcl_role_fingerprint_short(fp_a, short_a);
        zcl_role_fingerprint_short(stranger_fp, short_b);
        ASSERT_EQ((int)strlen(short_a), 8);
        ASSERT(strcmp(short_a, short_b) != 0);
    }

    TEST("fleet roles: an unknown key is refused on every grant-bearing "
         "leaf, and the operator key is always allowed") {
        struct zcl_role_report report;
        store = zcl_role_store_open(root, &report);
        ASSERT(store != NULL);
        ASSERT_EQ((int)report.status, (int)ZCL_ROLE_OK);
        static const char *const leaves[] = {
            "fleet.board.post", "fleet.experiment.predict",
            "fleet.roles.grant", "fleet.ledger.status",
        };
        for (size_t i = 0; i < sizeof leaves / sizeof leaves[0]; i++) {
            char why[ZCL_ROLE_LEAF_MAX];
            bool ok = zcl_role_check(store, stranger_fp, false, leaves[i],
                                     NULL, why, sizeof why);
            ASSERT(!ok);
            ASSERT(strstr(why, "REFUSED role:") == why);
            ASSERT(strstr(why, leaves[i]) != NULL);
            /* the operator's own key is never looked up in the store */
            ASSERT(zcl_role_check(store, stranger_fp, true, leaves[i], NULL,
                                  NULL, 0));
        }
    }

    TEST("fleet roles: a grant takes effect immediately and its exact "
         "refusal names the key and the leaf") {
        uint64_t seq = 0;
        enum zcl_role_status st =
            zcl_role_store_grant(store, worker_fp, ZCL_ROLE_worker, op_pub,
                                 op_seed, 1000, &seq);
        ASSERT_EQ((int)st, (int)ZCL_ROLE_OK);
        ASSERT_EQ((int)seq, 1);
        ASSERT(zcl_role_store_has_role(store, worker_fp, ZCL_ROLE_worker));
        char why[ZCL_ROLE_LEAF_MAX];
        ASSERT(zcl_role_check(store, worker_fp, false, "fleet.board.post",
                              "note", why, sizeof why));
        ASSERT(!zcl_role_check(store, worker_fp, false, "fleet.board.post",
                               "wiki", why, sizeof why));
        char fp8[9];
        zcl_role_fingerprint_short(worker_fp, fp8);
        char expect[ZCL_ROLE_LEAF_MAX];
        (void)snprintf(expect, sizeof expect,
                       "REFUSED role: key %s has no role granting "
                       "fleet.board.post kind=wiki",
                       fp8);
        ASSERT_STR_EQ(why, expect);
    }

    TEST("fleet roles: a grant a role can never name is refused") {
        uint64_t seq = 0;
        enum zcl_role_status st = zcl_role_store_grant(
            store, worker_fp, ZCL_ROLE_OPERATOR, op_pub, op_seed, 1001, &seq);
        ASSERT_EQ((int)st, (int)ZCL_ROLE_UNKNOWN_ROLE);
    }

    TEST("fleet roles: a revoke takes effect on the very next check") {
        uint64_t seq = 0;
        enum zcl_role_status st =
            zcl_role_store_revoke(store, worker_fp, ZCL_ROLE_worker, op_pub,
                                  op_seed, 2000, &seq);
        ASSERT_EQ((int)st, (int)ZCL_ROLE_OK);
        ASSERT_EQ((int)seq, 2);
        ASSERT(!zcl_role_store_has_role(store, worker_fp, ZCL_ROLE_worker));
        char why[ZCL_ROLE_LEAF_MAX];
        ASSERT(!zcl_role_check(store, worker_fp, false, "fleet.board.post",
                               "note", why, sizeof why));

        /* re-granting re-activates it */
        st = zcl_role_store_grant(store, worker_fp, ZCL_ROLE_worker, op_pub,
                                  op_seed, 3000, &seq);
        ASSERT_EQ((int)st, (int)ZCL_ROLE_OK);
        ASSERT(zcl_role_store_has_role(store, worker_fp, ZCL_ROLE_worker));
    }

    TEST("fleet roles: list reports the newest state per (key, role) and "
         "the store reloads it unchanged after a close") {
        struct zcl_role_entry entries[8];
        size_t n = zcl_role_store_list(store, entries,
                                       sizeof entries / sizeof entries[0]);
        ASSERT_EQ((int)n, 1);
        ASSERT_EQ((int)entries[0].role, (int)ZCL_ROLE_worker);
        ASSERT(entries[0].active);
        ASSERT_EQ((long long)entries[0].changed_at, 3000LL);
        zcl_role_store_close(store);
        store = NULL;

        struct zcl_role_report report;
        struct zcl_role_store *reopened = zcl_role_store_open(root, &report);
        ASSERT(reopened != NULL);
        ASSERT_EQ((int)report.rows, 3);
        ASSERT(zcl_role_store_has_role(reopened, worker_fp, ZCL_ROLE_worker));
        zcl_role_store_close(reopened);
    }

_test_next:
    if (store)
        zcl_role_store_close(store);
    test_rm_rf_recursive(root);
    return failures;
}
