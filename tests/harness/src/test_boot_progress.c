/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for util/boot_progress.c — the watchdog-adjacent liveness
 * signal any synchronous boot worker can bump cheaply (see
 * util/boot_progress.h for the WatchdogSec= rationale).
 *
 * The module is two atomics with no lock and no reset hook (by design —
 * see the header: "no init required"), so this test does NOT assume a
 * pristine zero baseline. test_zcl runs every group in one process, and
 * several boot/catchup/sapling-tree code paths call boot_progress_tick()
 * for real, so an earlier group in the same binary may have already
 * ticked it. Instead this test pins the two properties the header
 * actually promises:
 *   - boot_progress_last_label() reflects the most recent boot_progress_tick()
 *     call's label.
 *   - boot_progress_last_us() is a CLOCK_MONOTONIC microsecond stamp: it is
 *     always > 0 once any tick has fired (this file fires one first thing),
 *     and it never goes backward across two ticks (the monotonic-clock
 *     contract, not a real-time-value assumption). */

#include "test/test_core.h"

#include "util/boot_progress.h"

#include <stdio.h>
#include <string.h>

#define BP_CHECK(name, expr) do {                                   \
    printf("boot_progress: %s... ", (name));                        \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

int test_boot_progress(void)
{
    printf("\n=== boot_progress tests ===\n");
    int failures = 0;

    boot_progress_tick("test_boot_progress_label_1");
    int64_t us1 = boot_progress_last_us();
    const char *label1 = boot_progress_last_label();

    BP_CHECK("last_us is positive after a tick", us1 > 0);
    BP_CHECK("last_label reflects the just-ticked label",
             label1 != NULL &&
             strcmp(label1, "test_boot_progress_label_1") == 0);

    /* A second tick with a different label updates both fields, and the
     * monotonic timestamp never regresses. */
    boot_progress_tick("test_boot_progress_label_2");
    int64_t us2 = boot_progress_last_us();
    const char *label2 = boot_progress_last_label();

    BP_CHECK("second tick's timestamp does not go backward", us2 >= us1);
    BP_CHECK("last_label updates to the second tick's label",
             label2 != NULL &&
             strcmp(label2, "test_boot_progress_label_2") == 0);

    /* NULL label: per the header contract, the timestamp still bumps but
     * the label is left unchanged (the pointer is stashed only when
     * non-NULL) — the stale label from the second tick must survive. */
    boot_progress_tick(NULL);
    int64_t us3 = boot_progress_last_us();
    const char *label3 = boot_progress_last_label();

    BP_CHECK("tick(NULL) still bumps the timestamp", us3 >= us2);
    BP_CHECK("tick(NULL) leaves the previous label untouched",
             label3 != NULL &&
             strcmp(label3, "test_boot_progress_label_2") == 0);

    return failures;
}
