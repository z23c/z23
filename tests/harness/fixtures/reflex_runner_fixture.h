/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared identity of the clean-zygote reflex runner proof fixtures.
 *
 * One fixture source (reflex_runner_fixture.c) is compiled once per behavior
 * kind; every image exports the same HOT_FORK descriptor identity so the
 * test (test_reflex_runner.c) binds each request to exactly these values. */
#ifndef ZCL_TESTS_REFLEX_RUNNER_FIXTURE_H
#define ZCL_TESTS_REFLEX_RUNNER_FIXTURE_H

#define ZCL_REFLEX_FIXTURE_OWNER "test.reflex-runner-fixture.v1"
#define ZCL_REFLEX_FIXTURE_SOURCE "tests/harness/fixtures/reflex_runner_fixture.c"
#define ZCL_REFLEX_FIXTURE_OBJECT_ROOT \
    "5e1f0000000000000000000000000000000000000000000000000000000c0de1"
#define ZCL_REFLEX_FIXTURE_STORY "reflex-runner-isolation.v1"
#define ZCL_REFLEX_FIXTURE_STORY_ROOT \
    "5707e00000000000000000000000000000000000000000000000000000000001"
#define ZCL_REFLEX_FIXTURE_FIXTURE_ROOT \
    "f1c7000000000000000000000000000000000000000000000000000000000002"
#define ZCL_REFLEX_FIXTURE_SURFACE "reflex_runner_isolation_probe"

/* What the resident test plants and the candidate must NOT observe. */
#define ZCL_REFLEX_FIXTURE_CANARY_ENV "ZCL_REFLEX_RUNNER_CANARY"
#define ZCL_REFLEX_FIXTURE_PARENT_FD 77
#define ZCL_REFLEX_FIXTURE_CANARY_FILE "/etc/passwd"
#define ZCL_REFLEX_FIXTURE_CANARY_FILE2 "/proc/self/status"

#endif /* ZCL_TESTS_REFLEX_RUNNER_FIXTURE_H */
