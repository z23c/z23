/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Principal model + authz-recompute invariant tests. Proves that
 * before_validate always recomputes granted_capabilities from role (so a
 * caller can NEVER persist a mask exceeding its role), that the persisted mask
 * equals the role's authz mask for EVERY role, and that validation rejects a
 * malformed address/pubkey/role/status. */

#include "test/test_core.h"

#include "models/database.h"
#include "models/principal.h"
#include "models/authz_policy.h"

#include <stdio.h>
#include <string.h>

static void mk_valid(struct db_principal *p, enum principal_role role)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->address, sizeof(p->address), "t1ExampleAddress0000000000000000000");
    snprintf(p->pubkey_hex, sizeof(p->pubkey_hex), "02%064x", 0x1234u);
    p->key_kind = PRINCIPAL_KEY_SECP256K1;
    p->role = role;
    p->status = PRINCIPAL_STATUS_ACTIVE;
    p->sybil_proof_height = -1;
    p->granted_capabilities = authz_caps_for_role(role);
}

static int test_recompute_invariant(void)
{
    int failures = 0;
    struct node_db ndb;
    TEST("every-role save recompute yields the role's exact mask, never inflated") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        for (int r = PRINCIPAL_ROLE_GUEST; r <= PRINCIPAL_ROLE_OWNER; r++) {
            struct db_principal p;
            mk_valid(&p, (enum principal_role)r);
            snprintf(p.address, sizeof(p.address), "t1role%d00000000000000000000000000", r);
            /* Poison the mask: claim FULL capabilities regardless of role. */
            p.granted_capabilities = ~(uint64_t)0;
            ASSERT(db_principal_save(&ndb, &p));

            struct db_principal got;
            ASSERT(db_principal_find(&ndb, p.address, &got));
            ASSERT_EQ(got.granted_capabilities,
                      authz_caps_for_role((enum principal_role)r));
            if (r != PRINCIPAL_ROLE_OWNER)
                ASSERT(got.granted_capabilities != ~(uint64_t)0);
            ASSERT_EQ((int)got.role, r);
        }
        node_db_close(&ndb);
        PASS();
    } _test_next:;
    return failures;
}

static int test_validation_rejects_malformed(void)
{
    int failures = 0;
    TEST("validation rejects malformed address/pubkey/role/status") {
        struct ar_errors errs;

        struct db_principal bad_addr;
        mk_valid(&bad_addr, PRINCIPAL_ROLE_MEMBER);
        bad_addr.address[0] = '\0';
        ASSERT(!db_principal_validate(&bad_addr, &errs));

        struct db_principal bad_pk;
        mk_valid(&bad_pk, PRINCIPAL_ROLE_MEMBER);
        snprintf(bad_pk.pubkey_hex, sizeof(bad_pk.pubkey_hex), "xyz123");
        ASSERT(!db_principal_validate(&bad_pk, &errs));

        struct db_principal bad_role;
        mk_valid(&bad_role, PRINCIPAL_ROLE_MEMBER);
        bad_role.role = (enum principal_role)99;
        bad_role.granted_capabilities = authz_caps_for_role((enum principal_role)99);
        ASSERT(!db_principal_validate(&bad_role, &errs));

        struct db_principal bad_status;
        mk_valid(&bad_status, PRINCIPAL_ROLE_MEMBER);
        bad_status.status = (enum principal_status)77;
        ASSERT(!db_principal_validate(&bad_status, &errs));

        struct db_principal ok;
        mk_valid(&ok, PRINCIPAL_ROLE_OPERATOR);
        ASSERT(db_principal_validate(&ok, &errs));
        PASS();
    } _test_next:;
    return failures;
}

static int test_overprivileged_mask_rejected(void)
{
    int failures = 0;
    TEST("validate() rejects a granted mask above the role") {
        struct ar_errors errs;
        struct db_principal p;
        mk_valid(&p, PRINCIPAL_ROLE_MEMBER);
        p.granted_capabilities = ~(uint64_t)0;
        ASSERT(!db_principal_validate(&p, &errs));
        PASS();
    } _test_next:;
    return failures;
}

int test_principal_authz(void)
{
    int failures = 0;
    failures += test_recompute_invariant();
    failures += test_validation_rejects_malformed();
    failures += test_overprivileged_mask_rejected();
    printf("=== principal_authz: %d failures ===\n", failures);
    return failures;
}
