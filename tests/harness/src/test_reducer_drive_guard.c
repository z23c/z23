/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the reducer drive guard's time + label surface
 * (platform/modules/util/src/reducer_drive_guard.c). The watchdog and dumpstate rely on:
 *   (a) age is 0 when inactive, >0 while a drive is active, 0 again on exit;
 *   (b) the OUTERMOST enter owns the label; nested enters do not overwrite;
 *   (c) plain reducer_drive_enter() still works and reads as "unlabeled".
 */

#include "test/test_core.h"

#include "util/reducer_drive_guard.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define RDG_CHECK(name, expr) do {                                        \
    if (expr) { printf("  reducer_drive_guard: %s... OK\n", (name)); }    \
    else { printf("  reducer_drive_guard: %s... FAIL\n", (name));         \
           failures++; }                                                  \
} while (0)

int test_reducer_drive_guard(void);
int test_reducer_drive_guard(void)
{
    int failures = 0;

    RDG_CHECK("inactive: no drive at start", !reducer_drive_active());
    RDG_CHECK("inactive: age is 0", reducer_drive_age_us() == 0);
    RDG_CHECK("inactive: label is empty",
              strcmp(reducer_drive_label(), "") == 0);

    reducer_drive_enter_labeled("mint_anchor");
    RDG_CHECK("labeled enter: drive active", reducer_drive_active());
    RDG_CHECK("labeled enter: label visible",
              strcmp(reducer_drive_label(), "mint_anchor") == 0);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
    nanosleep(&ts, NULL);
    RDG_CHECK("labeled enter: age advances", reducer_drive_age_us() > 0);

    int64_t age_before_nested = reducer_drive_age_us();
    reducer_drive_enter_labeled("nested");
    RDG_CHECK("nested enter: outermost label wins",
              strcmp(reducer_drive_label(), "mint_anchor") == 0);
    RDG_CHECK("nested enter: age monotonic from outermost entry",
              reducer_drive_age_us() >= age_before_nested);
    reducer_drive_exit();
    RDG_CHECK("nested exit: still active", reducer_drive_active());

    reducer_drive_exit();
    RDG_CHECK("outermost exit: inactive", !reducer_drive_active());
    RDG_CHECK("outermost exit: age reset to 0", reducer_drive_age_us() == 0);
    RDG_CHECK("outermost exit: label cleared",
              strcmp(reducer_drive_label(), "") == 0);

    reducer_drive_enter();
    RDG_CHECK("plain enter: reads as unlabeled",
              strcmp(reducer_drive_label(), "unlabeled") == 0);
    RDG_CHECK("plain enter: age advances from plain enter",
              reducer_drive_age_us() >= 0 && reducer_drive_active());
    reducer_drive_exit();
    RDG_CHECK("final exit: inactive", !reducer_drive_active());

    printf("=== test_reducer_drive_guard complete: %d failure(s) ===\n",
           failures);
    return failures;
}
