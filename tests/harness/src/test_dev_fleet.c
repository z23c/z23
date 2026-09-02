/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pin the deliberately narrow owner boundary in dev.fleet. */

#include "test/test_core.h"

#include "command/native_dev_fleet.h"

int test_dev_fleet(void);
int test_dev_fleet(void)
{
    int failures = 0;

    TEST("fleet: the consensus seal is owner-only") {
        ASSERT(zcl_dev_fleet_gate_owner_only("check-core-seal"));
        PASS();
    }

    TEST("fleet: repository hooks are owner-only") {
        ASSERT(zcl_dev_fleet_gate_owner_only("check-git-hooks-installed"));
        PASS();
    }

    TEST("fleet: ordinary source gates remain worker-fixable") {
        ASSERT(!zcl_dev_fleet_gate_owner_only("check-format"));
        ASSERT(!zcl_dev_fleet_gate_owner_only("check-command-registry"));
        ASSERT(!zcl_dev_fleet_gate_owner_only(NULL));
        PASS();
    }

_test_next:;
    if (failures == 0) printf("test_dev_fleet: all passed\n");
    else printf("test_dev_fleet: %d FAILED\n", failures);
    return failures;
}
