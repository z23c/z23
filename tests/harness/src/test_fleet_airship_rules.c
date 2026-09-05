/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves what a fleet node's facts are actually worth.
 *
 * engine/composition/fleet_airship_rules.def is the one place that says
 * which fact earns which in-game asset, and tools/lint/
 * check_fleet_airship_rules.sh refuses a table that would pay for a fact
 * a machine reported about itself. That gate reads the file. THIS reads
 * the compiled table and the function the roster actually calls, because
 * a table that grades clean and a build that pays differently is exactly
 * the gap a reward scheme gets exploited through.
 *
 * The roster case is the one the owner asked for: two paired machines,
 * one of them reachable, and the honest answer is one airship — not two,
 * and not one plus whatever the unreachable machine claimed about its own
 * cores.
 */

#include "test/test_core.h"

#include "config/fleet_airship_rules.h"

#include <string.h>

static bool rules_fact_declared(const char *name)
{
    for (size_t i = 0; i < fleet_airship_fact_count(); i++) {
        const struct fleet_airship_fact_v1 *fact = fleet_airship_fact_at(i);

        if (fact && strcmp(fact->name, name) == 0)
            return true;
    }
    return false;
}

static bool rules_asset_declared(const char *name)
{
    for (size_t i = 0; i < fleet_airship_asset_count(); i++) {
        const char *asset = fleet_airship_asset_at(i);

        if (asset && strcmp(asset, name) == 0)
            return true;
    }
    return false;
}

int test_fleet_airship_rules(void)
{
    int failures = 0;

    TEST("airship rules: every compiled rule names a declared fact and a "
         "declared asset, and carries a reason") {
        ASSERT(fleet_airship_rule_count() > 0);
        ASSERT(fleet_airship_fact_count() > 0);
        ASSERT(fleet_airship_asset_count() > 0);
        for (size_t i = 0; i < fleet_airship_rule_count(); i++) {
            const struct fleet_airship_rule_v1 *rule = fleet_airship_rule_at(i);

            ASSERT(rule != NULL);
            ASSERT(rules_fact_declared(rule->fact));
            ASSERT(rules_asset_declared(rule->asset));
            ASSERT(rule->why != NULL && rule->why[0] != '\0');
        }
        ASSERT(fleet_airship_rule_at(fleet_airship_rule_count()) == NULL);
        ASSERT(fleet_airship_fact_at(fleet_airship_fact_count()) == NULL);
        ASSERT(fleet_airship_asset_at(fleet_airship_asset_count()) == NULL);
        PASS();
    }

    TEST("airship rules: no rule that pays anything rests on a fact a "
         "machine reported about itself") {
        size_t paying = 0;

        for (size_t i = 0; i < fleet_airship_rule_count(); i++) {
            const struct fleet_airship_rule_v1 *rule = fleet_airship_rule_at(i);

            if (rule->per_node == 0) {
                /* A zero row is this table's own assertion, not an
                 * observation, and says so. */
                ASSERT_EQ(rule->confidence, FLEET_AIRSHIP_DOCTRINE);
                continue;
            }
            paying++;
            ASSERT_EQ(fleet_airship_verification_of(rule->fact),
                      FLEET_AIRSHIP_PEER_VERIFIED);
            ASSERT_EQ(rule->confidence, FLEET_AIRSHIP_OBSERVED);
        }
        /* A table where nothing pays rewards nothing at all. */
        ASSERT(paying > 0);
        ASSERT(strcmp(fleet_airship_verification_name(
                          FLEET_AIRSHIP_PEER_VERIFIED),
                      "peer_verified") == 0);
        ASSERT(strcmp(fleet_airship_confidence_name(FLEET_AIRSHIP_DOCTRINE),
                      "doctrine") == 0);
        PASS();
    }

    TEST("airship rules: two paired machines with one reachable earn one "
         "airship, and what they say about themselves earns nothing") {
        /* Machine one: a peer reached it. Machine two: nobody did, but it
         * reports a large core count and plenty of free disk. */
        const char *reached[] = {"reachable"};
        const char *unreached_but_boastful[] = {"cpus", "disk_free",
                                                "build_identity"};
        unsigned fleet_airships;

        ASSERT_EQ(fleet_airship_award(reached, 1, "airship"), 1u);
        ASSERT_EQ(fleet_airship_award(unreached_but_boastful, 3, "airship"),
                  0u);
        fleet_airships =
            fleet_airship_award(reached, 1, "airship") +
            fleet_airship_award(unreached_but_boastful, 3, "airship");
        ASSERT_EQ(fleet_airships, 1u);

        /* The self-reported facts do not change the reachable machine's
         * award either: they are not additive, they are worth nothing. */
        const char *reached_and_boastful[] = {"reachable", "cpus", "disk_free",
                                              "build_identity"};
        ASSERT_EQ(fleet_airship_award(reached_and_boastful, 4, "airship"), 1u);
        PASS();
    }

    TEST("airship rules: a second independent path earns an escort, and a "
         "machine reached only once earns none") {
        const char *one_path[] = {"reachable"};
        const char *two_paths[] = {"reachable", "reachable_two_paths"};

        ASSERT_EQ(fleet_airship_award(one_path, 1, "escort"), 0u);
        ASSERT_EQ(fleet_airship_award(two_paths, 2, "escort"), 1u);
        ASSERT_EQ(fleet_airship_award(two_paths, 2, "airship"), 1u);
        PASS();
    }

    TEST("airship rules: an asset nobody declared, a fact nobody declared "
         "and no facts at all each earn nothing") {
        const char *reached[] = {"reachable"};
        const char *invented[] = {"ram_total", "uptime"};

        ASSERT_EQ(fleet_airship_award(reached, 1, "zeppelin"), 0u);
        ASSERT_EQ(fleet_airship_award(invented, 2, "airship"), 0u);
        ASSERT_EQ(fleet_airship_award(NULL, 0, "airship"), 0u);
        ASSERT_EQ(fleet_airship_award(reached, 1, NULL), 0u);
        /* A fact no row declares reads as self-reported, the value that
         * pays nothing — never as verified by default. */
        ASSERT_EQ(fleet_airship_verification_of("ram_total"),
                  FLEET_AIRSHIP_SELF_REPORTED);
        ASSERT_EQ(fleet_airship_verification_of(NULL),
                  FLEET_AIRSHIP_SELF_REPORTED);
        PASS();
    }

_test_next:
    return failures;
}
