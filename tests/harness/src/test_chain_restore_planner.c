/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Isolated tests for the Phase 3 chain_restore_planner extraction. */

#include "test/test_core.h"
#include "services/chain_restore_planner.h"
#include "core/uint256.h"

#include <string.h>

static int g_cases;

#define PLANNER_TEST(name) \
    do { \
        ++g_cases; \
        printf("chain_restore_planner: %s... ", (name)); \
    } while (0)

static int test_null_coins_best_hash(void)
{
    int failures = 0;
    PLANNER_TEST("null coins_best_hash fails and skips activate");
    struct chain_restore_input in = {0};
    struct chain_restore_plan plan;

    chain_restore_plan(&plan, &in);

    ASSERT(plan.next_state == CHAIN_RESTORE_FAILED);
    ASSERT(plan.should_skip_activate == true);
    ASSERT(strstr(plan.reason, "no UTXO state") != NULL);
    PASS();
_test_next:
    return failures;
}

static int test_hash_found_in_index(void)
{
    int failures = 0;
    PLANNER_TEST("hash found in index sets tip/header");
    struct chain_restore_input in = {0};
    uint256_set_hex(&in.coins_best_hash, "0000abcd");
    in.hash_found_in_map = true;
    in.found_height = 500000;
    in.source = CHAIN_RESTORE_SRC_LDB_IMPORT;
    struct chain_restore_plan plan;

    chain_restore_plan(&plan, &in);

    ASSERT(plan.next_state == CHAIN_RESTORE_FOUND_IN_INDEX);
    ASSERT(plan.should_set_chain_tip == true);
    ASSERT(plan.should_set_best_header == true);
    ASSERT(plan.should_create_anchor == false);
    ASSERT(plan.should_skip_activate == true);
    ASSERT(plan.anchor_height == 500000);
    ASSERT(uint256_eq(&plan.anchor_hash, &in.coins_best_hash));
    PASS();
_test_next:
    return failures;
}

static int test_hash_missing_with_utxo_height(void)
{
    int failures = 0;
    PLANNER_TEST("missing hash with utxo height creates anchor");
    struct chain_restore_input in = {0};
    uint256_set_hex(&in.coins_best_hash, "0000abcd");
    in.hash_found_in_map = false;
    in.utxo_max_height = 3072280;
    in.source = CHAIN_RESTORE_SRC_NORMAL_BOOT;
    struct chain_restore_plan plan;

    chain_restore_plan(&plan, &in);

    ASSERT(plan.next_state == CHAIN_RESTORE_ANCHOR_CREATED);
    ASSERT(plan.should_create_anchor == true);
    ASSERT(plan.should_set_snapshot_anchor == true);
    ASSERT(plan.should_set_chain_tip == false);
    ASSERT(plan.should_set_best_header == false);
    ASSERT(plan.should_skip_activate == true);
    ASSERT(plan.anchor_height == 3072280);
    ASSERT(uint256_eq(&plan.anchor_hash, &in.coins_best_hash));
    PASS();
_test_next:
    return failures;
}

static int test_hash_missing_without_height(void)
{
    int failures = 0;
    PLANNER_TEST("missing hash without height awaits p2p");
    struct chain_restore_input in = {0};
    uint256_set_hex(&in.coins_best_hash, "0000abcd");
    in.hash_found_in_map = false;
    in.utxo_max_height = 0;
    struct chain_restore_plan plan;

    chain_restore_plan(&plan, &in);

    ASSERT(plan.next_state == CHAIN_RESTORE_FAILED);
    ASSERT(plan.should_skip_activate == true);
    ASSERT(strstr(plan.reason, "awaiting P2P") != NULL);
    PASS();
_test_next:
    return failures;
}

static int test_source_in_reason(void)
{
    int failures = 0;
    PLANNER_TEST("source influences anchor reason");
    struct chain_restore_input in = {0};
    uint256_set_hex(&in.coins_best_hash, "0000abcd");
    in.hash_found_in_map = false;
    in.utxo_max_height = 100000;
    in.source = CHAIN_RESTORE_SRC_SNAPSHOT;
    struct chain_restore_plan plan;

    chain_restore_plan(&plan, &in);

    ASSERT(plan.next_state == CHAIN_RESTORE_ANCHOR_CREATED);
    ASSERT(strstr(plan.reason, "snapshot") != NULL);
    PASS();
_test_next:
    return failures;
}

int test_chain_restore_planner(void)
{
    int failures = 0;
    g_cases = 0;
    printf("\n=== chain_restore_planner tests ===\n");
    failures += test_null_coins_best_hash();
    failures += test_hash_found_in_index();
    failures += test_hash_missing_with_utxo_height();
    failures += test_hash_missing_without_height();
    failures += test_source_in_reason();
    printf("chain_restore_planner: %d/%d passed, %d failed\n",
           g_cases - failures, g_cases, failures);
    return failures;
}
