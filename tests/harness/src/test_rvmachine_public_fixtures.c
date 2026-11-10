/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Run the bounded native public guest-fixture observer. */
#include "test/test_core.h"
#include "util/spawn.h"
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
static bool public_fixture_markers(const char *output)
{
    static const char *const lines[] = {
        "PASS descendant holding output is cleaned before leader reap\n",
        "PASS public port T/P/CLOSE and refusals\n",
        "PASS bootstrap --public-pipe-control\n",
        "PASS bootstrap --public-pipe-short\n",
        "PASS bootstrap --public-pipe-extra\n",
        "PASS bootstrap --public-pipe-wrong\n",
        "PASS bootstrap --public-child-failure\n",
        "PASS bootstrap --public-child-cancel\n",
        "PASS bootstrap --public-lost-custody\n",
        "PASS bootstrap --public-postreap-expired\n",
        "PASS bootstrap --public-postreap-clockfail\n"
    };
    for (size_t i = 0; i < sizeof lines / sizeof lines[0]; ++i) {
        if (!strstr(output, lines[i])) {
            fprintf(stderr, "missing public fixture marker: %s", lines[i]);
            return false;
        }
    }
    return true;
}
static bool run_public_fixture_observer(void)
{
    const char *const argv[] = {"build/bin/test-rvmachine-public-fixtures", NULL};
    char output[16384];
    struct zcl_spawn_binary_observation observed = {0};
    struct zcl_result result = zcl_spawn_capture_binary_merged(argv, output,
        sizeof(output) - 1, 60000, &observed);
    if (observed.output_len >= sizeof(output) || observed.overflow) return false;
    output[observed.output_len] = '\0';
    if (memchr(output, '\0', observed.output_len)) return false;
    if (fwrite(output, 1, observed.output_len, stdout) != observed.output_len || fflush(stdout) != 0)
        return false;
    return result.ok && observed.exit_observed && observed.exit_code == 0 &&
        observed.eof && !observed.timed_out && public_fixture_markers(output);
}
#endif

int test_rvmachine_public_fixtures(void);
int test_rvmachine_public_fixtures(void)
{
#if !defined(_WIN32)
    int failures = 0;
    TEST("public guest fixtures: bounded host controls") {
        ASSERT(run_public_fixture_observer());
        PASS();
    } _test_next:;
    return failures;
#else
    fputs("UNOBSERVED: public guest fixture observer unavailable on Windows\n", stderr);
    return 1;
#endif
}
