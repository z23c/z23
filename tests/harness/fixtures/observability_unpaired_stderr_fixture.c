/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture for `test_make_lint_gates` -- intentionally contains an
 * unpaired stderr diagnostic. The observability lint gate should reject
 * this when copied under app/ during the self-test.
 */

#include <stdio.h>

int observability_unpaired_stderr_fixture(void)
{
    fprintf(stderr, "fixture failed silently\n");
    return 0;
}
