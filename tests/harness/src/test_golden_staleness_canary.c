/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Golden-table staleness canary.
 *
 * test_sha3_windows.c and test_utxo_root_ladder.c tolerate an EMPTY compiled
 * table, so neither notices entries silently dropped from a populated table.
 * This group pins the current coverage as a floor:
 *   - g_sha3_windows_count must equal the pinned count exactly (it only
 *     changes when tools/gen_sha3_windows is deliberately re-run);
 *   - g_utxo_root_ladder_count must be at or above a pinned minimum (it
 *     grows as rungs are minted, so a floor never false-fails on growth).
 * The NIGHTLY tip-coverage-lag check (z23-lint check-golden-freshness,
 * tools/lint/lintc/gate_golden_freshness.c) additionally
 * watches for a table that is never re-minted. */

#include "test/test_core.h"

#include "chain/sha3_windows.h"
#include "chain/utxo_root_ladder.h"

/* Pinned floor: bump ONLY when the golden table is deliberately re-minted
 * (tools/gen_sha3_windows / tools/gen_utxo_root_ladder). */
#define SHA3_WINDOWS_EXPECTED_COUNT   3176
#define UTXO_ROOT_LADDER_EXPECTED_MIN 1

int test_golden_staleness_canary(void)
{
    int failures = 0;

    printf("\n=== test_golden_staleness_canary ===\n");

    printf("golden_staleness_canary: g_sha3_windows_count == pinned expected "
          "(%d)... ", SHA3_WINDOWS_EXPECTED_COUNT);
    if (g_sha3_windows_count == SHA3_WINDOWS_EXPECTED_COUNT) {
        printf("OK\n");
    } else {
        printf("FAIL (count=%zu expected=%d — either a silent coverage drop, "
              "or the table was legitimately re-minted and this pin needs "
              "bumping)\n", g_sha3_windows_count, SHA3_WINDOWS_EXPECTED_COUNT);
        failures++;
    }

    printf("golden_staleness_canary: g_utxo_root_ladder_count >= pinned "
          "minimum (%d)... ", UTXO_ROOT_LADDER_EXPECTED_MIN);
    if (g_utxo_root_ladder_count >= UTXO_ROOT_LADDER_EXPECTED_MIN) {
        printf("OK (count=%zu)\n", g_utxo_root_ladder_count);
    } else {
        printf("FAIL (count=%zu below the pinned floor of %d — a golden "
              "ladder rung silently disappeared)\n",
              g_utxo_root_ladder_count, UTXO_ROOT_LADDER_EXPECTED_MIN);
        failures++;
    }

    if (failures == 0)
        printf("=== test_golden_staleness_canary: all cases passed ===\n");
    else
        printf("=== test_golden_staleness_canary: %d failure(s) ===\n",
              failures);
    return failures;
}
