/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_proof_stress_env — regression for the proof's test-dimension
 * environment.
 *
 * Roughly sixteen registered groups carry a guard shaped exactly like:
 *
 *     if (!getenv("ZCL_STRESS_TESTS")) {
 *         printf("SKIP (set ZCL_STRESS_TESTS=1 to run ...)\n");
 *         return 0;
 *     }
 *
 * (tests/harness/src/test_kill9_recovery.c, test_cold_start_sync.c,
 * test_onion_bootstrap.c, test_chain_advance_atomicity.c, and others — see
 * `git grep -n ZCL_STRESS_TESTS tests/harness/src`). The push proof's test
 * dimension execs its runner with execvp(), which reuses this process's own
 * `environ` — there is no separate envp built per child, so whatever this
 * process last set is exactly what every forked test child inherits. A
 * resident proof daemon forks many cycles from one long-lived process and
 * keeps the environment it started with, so until tools/dev/dev_proof.c set
 * this unconditionally right before launching the test dimension, every one
 * of those guards read absent and every push proof silently admitted a
 * commit having never run its stress lane.
 *
 * Driving one of the real stress groups here would pull a fork-heavy,
 * sleep-driven, or Tor-network fixture into a fast registered group just to
 * watch it NOT print "SKIP (" — too heavy for this tier. Instead this proves
 * the narrower, load-bearing fact directly: calling
 * zcl_dev_proof_test_stress_env_prepare() — the ZCL_TESTING seam onto the
 * exact static helper (dev_proof.c's proof_stress_tests_env_prepare()) that
 * proof_worker() calls right before the test dimension launches — flips the
 * same getenv() every guard above reads, unconditionally, regardless of
 * what the variable held before the call. */

#include "test/test_core.h"

#include "dev_proof.h"

#include <stdlib.h>
#include <string.h>

static int test_dps_absent_becomes_present(void)
{
    int failures = 0;
    TEST_CASE("dev_proof_stress_env: absent before, exec-visible after")
    {
        /* Start from the state a resident daemon's stale first environment
         * would leave: the variable absent, which is exactly the branch
         * every self-skipping group's `if (!getenv("ZCL_STRESS_TESTS"))`
         * takes. */
        (void)unsetenv("ZCL_STRESS_TESTS");
        ASSERT(getenv("ZCL_STRESS_TESTS") == NULL);

        char why[160] = {0};
        ASSERT(zcl_dev_proof_test_stress_env_prepare(why, sizeof(why)));
        ASSERT(why[0] == '\0');

        /* Every self-skip guard in the suite reads exactly this call's
         * effect via getenv("ZCL_STRESS_TESTS"). */
        const char *value = getenv("ZCL_STRESS_TESTS");
        ASSERT(value != NULL);
        ASSERT_STR_EQ(value, "1");
    }
    TEST_END
    (void)unsetenv("ZCL_STRESS_TESTS");
    return failures;
}

static int test_dps_unconditional_overwrite(void)
{
    int failures = 0;
    TEST_CASE("dev_proof_stress_env: unconditional, overwrites a stale value")
    {
        /* A prior tool, or a resident daemon's very first environment,
         * could have exported a falsy value. The proof must not defer to
         * it — the whole point of the fix is that the test dimension no
         * longer depends on what invoked this binary. */
        ASSERT(setenv("ZCL_STRESS_TESTS", "0", 1) == 0);
        ASSERT_STR_EQ(getenv("ZCL_STRESS_TESTS"), "0");

        char why[160] = {0};
        ASSERT(zcl_dev_proof_test_stress_env_prepare(why, sizeof(why)));
        ASSERT_STR_EQ(getenv("ZCL_STRESS_TESTS"), "1");
    }
    TEST_END
    (void)unsetenv("ZCL_STRESS_TESTS");
    return failures;
}

int test_dev_proof_stress_env(void)
{
    int failures = 0;
    failures += test_dps_absent_becomes_present();
    failures += test_dps_unconditional_overwrite();
    return failures;
}
