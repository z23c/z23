/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for G11 (tools/command/native_fleet_goals_spend.c): the
 * declared-capability scan grades PARTIAL when no fleet leaf declares the
 * wallet request, FAIL naming the first such leaves, and UNMEASURED with no
 * fleet leaves. Synthetic registries pin each rule; the real catalog must
 * never grade PASS.
 */

#include "test/test_core.h"

#include "command/native_fleet_goals.h"
#include "command/native_fleet_goals_spend.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"

#include <stdint.h>
#include <string.h>

static bool fgs_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static struct zcl_command_spec fgs_leaf(const char *path, uint64_t caps)
{
    struct zcl_command_spec spec = {0};
    spec.path = path;
    spec.mode = ZCL_COMMAND_MODE_SYNC;
    spec.required_capabilities = caps;
    return spec;
}

static int fgs_case_partial(void)
{
    int failures = 0;
    struct zcl_command_spec specs[] = {
        fgs_leaf("fleet.goals", 0),
        fgs_leaf("ops.mesh.status", 0),
    };
    struct zcl_command_registry reg = {.commands = specs, .count = 2};
    TEST("two clean fleet leaves grade PARTIAL as a declared scan, not spend") {
        struct zcl_goal_result r = zcl_goals_spend_measure(&reg);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgs_has(r.evidence, "declared-capability scan of 2 leaves"));
        ASSERT(fgs_has(r.evidence, "not a measurement of actual spend"));
        ASSERT(r.next[0] != '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int fgs_case_fail(void)
{
    int failures = 0;
    struct zcl_command_spec specs[] = {
        fgs_leaf("fleet.goals", 0),
        fgs_leaf("fleet.spend.send", ZCL_COMMAND_CAP_WALLET_REQUEST),
    };
    struct zcl_command_registry reg = {.commands = specs, .count = 2};
    TEST("one wallet-declaring fleet leaf grades FAIL and names it") {
        struct zcl_goal_result r = zcl_goals_spend_measure(&reg);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgs_has(r.evidence, "1 of 2 fleet leaves"));
        ASSERT(fgs_has(r.evidence, "fleet.spend.send"));
        ASSERT(!fgs_has(r.evidence, "fleet.goals"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgs_case_fail_bounded(void)
{
    int failures = 0;
    struct zcl_command_spec specs[] = {
        fgs_leaf("fleet.a.one", ZCL_COMMAND_CAP_WALLET_REQUEST),
        fgs_leaf("fleet.b.two", ZCL_COMMAND_CAP_WALLET_REQUEST),
        fgs_leaf("fleet.c.three", ZCL_COMMAND_CAP_WALLET_REQUEST),
        fgs_leaf("fleet.d.four", ZCL_COMMAND_CAP_WALLET_REQUEST),
    };
    struct zcl_command_registry reg = {.commands = specs, .count = 4};
    TEST("FAIL names the first three wallet leaves, not the rest") {
        struct zcl_goal_result r = zcl_goals_spend_measure(&reg);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgs_has(r.evidence, "4 of 4 fleet leaves"));
        ASSERT(fgs_has(r.evidence, "fleet.a.one, fleet.b.two, fleet.c.three"));
        ASSERT(!fgs_has(r.evidence, "fleet.d.four"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgs_case_unmeasured(void)
{
    int failures = 0;
    struct zcl_command_spec specs[] = {
        /* A branch and an out-of-scope leaf both declare the wallet bit;
         * neither is an in-scope fleet leaf, so nothing is graded. */
        {.path = "fleet", .mode = ZCL_COMMAND_MODE_BRANCH,
         .required_capabilities = ZCL_COMMAND_CAP_WALLET_REQUEST},
        fgs_leaf("zcl.wallet.send", ZCL_COMMAND_CAP_WALLET_REQUEST),
    };
    struct zcl_command_registry empty = {.commands = NULL, .count = 0};
    struct zcl_command_registry none = {.commands = specs, .count = 2};
    TEST("no fleet leaves, or a NULL registry, grades UNMEASURED") {
        ASSERT(zcl_goals_spend_measure(&empty).grade == ZCL_GOAL_UNMEASURED);
        ASSERT(zcl_goals_spend_measure(&none).grade == ZCL_GOAL_UNMEASURED);
        ASSERT(zcl_goals_spend_measure(NULL).grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgs_has(zcl_goals_spend_measure(&none).evidence,
                       "no fleet leaves"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgs_case_real(void)
{
    int failures = 0;
    TEST("real catalog: G11 is never PASS and always carries evidence") {
        struct zcl_goal_result r =
            zcl_goals_spend_measure(zcl_command_catalog());
        ASSERT(r.grade != ZCL_GOAL_PASS);
        ASSERT(r.evidence[0] != '\0');
        ASSERT(r.next[0] != '\0');
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_goals_spend(void);
int test_fleet_goals_spend(void)
{
    int failures = 0;
    failures += fgs_case_partial();
    failures += fgs_case_fail();
    failures += fgs_case_fail_bounded();
    failures += fgs_case_unmeasured();
    failures += fgs_case_real();
    if (failures == 0)
        printf("test_fleet_goals_spend: all passed\n");
    else
        printf("test_fleet_goals_spend: %d FAILED\n", failures);
    return failures;
}
