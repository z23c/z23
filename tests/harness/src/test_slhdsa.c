/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: runs the platform/modules/slhdsa self-test (NIST ACVP vectors,
 * round trips, bit-flip rejection, input validation) as a harness group. */

#include "test/test_core.h"

#include <stdio.h>

#define main slhdsa_module_main
#include "../../../platform/modules/slhdsa/tests/test_slhdsa.c"
#undef main

int test_slhdsa(void);
int test_slhdsa(void)
{
    int failures = 0;
    TEST("slhdsa module: NIST vectors, round trips, bit flips, validation") {
        ASSERT(slhdsa_module_main() == 0);
        PASS();
    } _test_next:;
    return failures;
}
