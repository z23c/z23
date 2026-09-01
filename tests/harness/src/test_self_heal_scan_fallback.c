/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "event/event.h"
#include "validation/process_block.h"

#include <stdlib.h>

int test_self_heal_scan_fallback(void)
{
    int failures = 0;

    printf("self_heal_scan: dedicated hit/exhausted event names... ");
    if (strcmp(event_type_name(EV_SELF_HEAL_SCAN_HIT),
               "val.self_heal_scan_hit") != 0 ||
        strcmp(event_type_name(EV_SELF_HEAL_SCAN_EXHAUSTED),
               "val.self_heal_scan_exhausted") != 0) {
        printf("FAIL\n");
        failures++;
    } else {
        printf("OK\n");
    }

    printf("self_heal_scan: counters reset and expose depth override... ");
    struct self_heal_scan_stats stats;

    unsetenv("ZCL_SELF_HEAL_SCAN_DEPTH");
    /* counters start at zero in a fresh process; no reset needed. */
    process_block_self_heal_stats_snapshot(&stats);
    bool ok = stats.tx_index_hits == 0 &&
              stats.scan_hits == 0 &&
              stats.scan_exhausted == 0 &&
              stats.scan_blocks_checked_total == 0 &&
              process_block_self_heal_scan_depth_limit() == 250000;

    setenv("ZCL_SELF_HEAL_SCAN_DEPTH", "2000", 1);
    ok = ok && process_block_self_heal_scan_depth_limit() == 250000;

    setenv("ZCL_SELF_HEAL_SCAN_DEPTH", "300000", 1);
    ok = ok && process_block_self_heal_scan_depth_limit() == 300000;

    setenv("ZCL_SELF_HEAL_SCAN_DEPTH", "0", 1);
    ok = ok && process_block_self_heal_scan_depth_limit() == 250000;

    setenv("ZCL_SELF_HEAL_SCAN_DEPTH", "not-a-number", 1);
    ok = ok && process_block_self_heal_scan_depth_limit() == 250000;
    unsetenv("ZCL_SELF_HEAL_SCAN_DEPTH");
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("self_heal_scan: broad disk scan is opt-in... ");
    unsetenv("ZCL_SELF_HEAL_SCAN_ENABLE");
    ok = !process_block_self_heal_scan_enabled();
    setenv("ZCL_SELF_HEAL_SCAN_ENABLE", "1", 1);
    ok = ok && process_block_self_heal_scan_enabled();
    setenv("ZCL_SELF_HEAL_SCAN_ENABLE", "true", 1);
    ok = ok && process_block_self_heal_scan_enabled();
    setenv("ZCL_SELF_HEAL_SCAN_ENABLE", "0", 1);
    ok = ok && !process_block_self_heal_scan_enabled();
    unsetenv("ZCL_SELF_HEAL_SCAN_ENABLE");
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    return failures;
}
