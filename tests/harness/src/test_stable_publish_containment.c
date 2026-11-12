/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_stable_publish_exec_args, the shipped translator. The
 * Makefile spelling --self-test must become z23-lint's --selftest, and
 * every other argument must be passed through unchanged. */

#include "test/test_core.h"

#include "stable_publish_containment.h"

#include <string.h>

static int test_stable_publish_containment_cases(void)
{
    int failures = 0;
    TEST("stable publish containment: --self-test is rewritten, other args pass") {
        const char *out[8];
        char *plain[] = {"tool"};
        char *self[] = {"tool", "--self-test"};
        char *extra[] = {"tool", "--self-test", "keep-me"};
        char *other[] = {"tool", "--other", "--self-test"};
        int n;
        n = zcl_stable_publish_exec_args("lint-bin", 1, plain, out, 8);
        ASSERT(n == 3);
        ASSERT(strcmp(out[0], "lint-bin") == 0);
        ASSERT(strcmp(out[1], "check-stable-publish-contained") == 0);
        ASSERT(out[2] == NULL);
        n = zcl_stable_publish_exec_args("lint-bin", 2, self, out, 8);
        ASSERT(n == 4);
        ASSERT(strcmp(out[1], "check-stable-publish-contained") == 0);
        ASSERT(strcmp(out[2], "--selftest") == 0);
        ASSERT(out[3] == NULL);
        n = zcl_stable_publish_exec_args("lint-bin", 3, extra, out, 8);
        ASSERT(n == 5);
        ASSERT(strcmp(out[2], "--selftest") == 0);
        ASSERT(strcmp(out[3], "keep-me") == 0);
        ASSERT(out[4] == NULL);
        n = zcl_stable_publish_exec_args("lint-bin", 3, other, out, 8);
        ASSERT(n == 5);
        ASSERT(strcmp(out[2], "--other") == 0);
        ASSERT(strcmp(out[3], "--self-test") == 0);
        ASSERT(out[4] == NULL);
        ASSERT(zcl_stable_publish_exec_args(NULL, 1, plain, out, 8) < 0);
        ASSERT(zcl_stable_publish_exec_args("lint-bin", 2, self, out, 3) < 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_stable_publish_containment(void);
int test_stable_publish_containment(void)
{
    int failures = test_stable_publish_containment_cases();
    if (failures == 0)
        printf("test_stable_publish_containment: all passed\n");
    else
        printf("test_stable_publish_containment: %d FAILED\n", failures);
    return failures;
}
