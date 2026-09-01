/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Golden-table staleness canary (item 2a of the golden immutable-history
 * evidence wiring lane).
 *
 * test_sha3_windows.c and test_utxo_root_ladder.c both deliberately tolerate
 * an EMPTY compiled table (count == 0 is a legitimate "freshly regenerated
 * placeholder, not yet re-minted" state) — that flexibility is the right
 * call for those files' own purpose (exercising the verifier logic itself
 * regardless of how populated the table happens to be), but it means
 * neither file would notice a REGRESSION that silently dropped entries from
 * an already-populated table back toward zero: `make ci` would stay green
 * even though the corroboration coverage the tables exist to provide had
 * quietly evaporated.
 *
 * This group pins the CURRENT compiled coverage as a floor:
 *   - g_sha3_windows_count must equal the pinned expected count exactly —
 *     this table only changes when tools/gen_sha3_windows is deliberately
 *     re-run to extend coverage, an intentional, reviewable event where
 *     bumping the pin below costs one line.
 *   - g_utxo_root_ladder_count must be at or above a pinned minimum — this
 *     table is expected to grow over time as more cross-checked rungs are
 *     minted, so a floor (not an exact match) is the right assertion: it
 *     still catches a silent DROP to fewer rungs than today while never
 *     false-failing on legitimate growth.
 *
 * A regression that drops entries from either compiled table fails HERE,
 * in the hermetic default `make ci` / `make test` run — not just in the
 * NIGHTLY-only tip-coverage-lag check (see check_golden_freshness.sh /
 * `make simnet-nightly`), which additionally watches for the table simply
 * not being re-minted for a very long time even though nothing was ever
 * dropped. */

#include "test/test_core.h"

#include "chain/sha3_windows.h"
#include "chain/utxo_root_ladder.h"

/* Pinned floor — bump ONLY when the corresponding golden table is
 * deliberately re-minted (tools/gen_sha3_windows / tools/gen_utxo_root_
 * ladder) to extend coverage. A silent drop below this value is exactly
 * the coverage-decay class this canary exists to catch. */
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
