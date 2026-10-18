/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tor_compiler_id: the Tor provenance manifest compares compiler ids by
 * binary hash when both carry one, and by version text without the driver
 * name otherwise. A recorded "cc (GCC) ..." and a candidate "gcc (GCC) ..."
 * for the same binary must match; anything unprovable must refuse.
 */

#include "test/test_core.h"

#include "../../../tools/tor_compiler_id.h"

#define H1 "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define H2 "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

static int tor_compiler_id_same_hash_other_driver_matches(void)
{
    int failures = 0;

    TEST("tor_compiler_id_same_hash_other_driver_matches") {
        ASSERT(tor_compiler_ids_match(
            H1 " version:cc (GCC) 14.2.1 20250207 triple:x86_64-pc-linux-gnu",
            H1 " version:gcc (GCC) 14.2.1 20250207 triple:x86_64-pc-linux-gnu"));
        PASS();
    } _test_next:;
    return failures;
}

static int tor_compiler_id_different_hash_refuses(void)
{
    int failures = 0;

    TEST("tor_compiler_id_different_hash_refuses") {
        ASSERT(!tor_compiler_ids_match(H1 " version:gcc (GCC) 14.2.1",
                                       H2 " version:gcc (GCC) 14.2.1"));
        PASS();
    } _test_next:;
    return failures;
}

static int tor_compiler_id_hashless_matches_after_driver_word(void)
{
    int failures = 0;

    TEST("tor_compiler_id_hashless_matches_after_driver_word") {
        ASSERT(tor_compiler_ids_match("cc (GCC) 14.2.1 20250207",
                                      "gcc (GCC) 14.2.1 20250207"));
        PASS();
    } _test_next:;
    return failures;
}

static int tor_compiler_id_hashless_other_version_refuses(void)
{
    int failures = 0;

    TEST("tor_compiler_id_hashless_other_version_refuses") {
        ASSERT(!tor_compiler_ids_match("cc (GCC) 14.2.1 20250207",
                                       "gcc (GCC) 14.3.0 20250601"));
        PASS();
    } _test_next:;
    return failures;
}

static int tor_compiler_id_hash_never_matches_hashless(void)
{
    int failures = 0;

    TEST("tor_compiler_id_hash_never_matches_hashless") {
        ASSERT(!tor_compiler_ids_match(H1 " version:gcc (GCC) 14.2.1",
                                       "gcc (GCC) 14.2.1"));
        ASSERT(!tor_compiler_ids_match("gcc (GCC) 14.2.1",
                                       H1 " version:gcc (GCC) 14.2.1"));
        PASS();
    } _test_next:;
    return failures;
}

static int tor_compiler_id_empty_or_garbled_refuses(void)
{
    int failures = 0;

    TEST("tor_compiler_id_empty_or_garbled_refuses") {
        ASSERT(!tor_compiler_ids_match("", ""));
        ASSERT(!tor_compiler_ids_match(NULL, "gcc (GCC) 14.2.1"));
        ASSERT(!tor_compiler_ids_match("gcc", "gcc"));
        ASSERT(!tor_compiler_ids_match("gcc ", "cc "));
        ASSERT(!tor_compiler_ids_match("sha256:zz", "sha256:zz"));
        ASSERT(!tor_compiler_ids_match("sha256:0123", "sha256:0123"));
        ASSERT(!tor_compiler_ids_match(H1 "00", H1 "00"));
        PASS();
    } _test_next:;
    return failures;
}

int test_tor_compiler_id(void)
{
    int failures = 0;
    printf("\n=== Tor compiler id comparison ===\n");
    failures += tor_compiler_id_same_hash_other_driver_matches();
    failures += tor_compiler_id_different_hash_refuses();
    failures += tor_compiler_id_hashless_matches_after_driver_word();
    failures += tor_compiler_id_hashless_other_version_refuses();
    failures += tor_compiler_id_hash_never_matches_hashless();
    failures += tor_compiler_id_empty_or_garbled_refuses();
    printf("Tor compiler id comparison: %d failures\n", failures);
    return failures;
}
