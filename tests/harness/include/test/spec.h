/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * User story spec framework — Kathy Sierra "Badass" testing.
 *
 * Core principle: Don't test if the APP works.
 * Test if the USER becomes more capable.
 *
 * FEATURE  = What the user is trying to accomplish
 * STORY    = One moment where the user succeeds or fails
 * GIVEN    = The user's context (what just happened)
 * WHEN     = The user's action
 * THEN     = What the user experiences (not what the code does)
 * EXPECT   = Verify the experience matches intent
 *
 * Usage:
 *   FEATURE("User understands their financial privacy") {
 *       STORY("user immediately sees how private they are") {
 *           GIVEN("user opens the wallet")
 *               GET("/wallet");
 *           THEN("privacy status is the first thing they grasp")
 *               EXPECT(has("% private"));
 *           PASS();
 *       }
 *   } */

#ifndef ZCL_TEST_SPEC_H
#define ZCL_TEST_SPEC_H

#include <stdio.h>
#include <stdbool.h>

static int _spec_pass = 0;
static int _spec_fail = 0;
static bool _spec_story_failed = false;

#define FEATURE(name) \
    printf("\n=== %s ===\n", (name)); \
    if (1)

#define STORY(name) \
    _spec_story_failed = false; \
    printf("  %s... ", (name)); \
    if (1)

#define GIVEN(desc)  /* user's context */
#define WHEN(desc)   /* user's action */
#define THEN(desc)   /* user's experience */

#define EXPECT(cond) do { \
    if (cond) { _spec_pass++; } \
    else { \
        _spec_fail++; _spec_story_failed = true; \
        printf("FAIL\n    %s\n    at %s:%d\n", \
            #cond, __FILE__, __LINE__); \
    } \
} while (0)

#define EXPECT_NOT(cond) do { \
    if (!(cond)) { _spec_pass++; } \
    else { \
        _spec_fail++; _spec_story_failed = true; \
        printf("FAIL (should NOT match)\n    %s\n    at %s:%d\n", \
            #cond, __FILE__, __LINE__); \
    } \
} while (0)

#define PASS() if (!_spec_story_failed) printf("OK\n");

#define SPEC_SUMMARY() \
    printf("\n%d passed, %d failed\n", _spec_pass, _spec_fail)

#define SPEC_FAILURES() (_spec_fail)

#endif
