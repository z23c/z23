/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/cleanse.h"

#include <stdint.h>
#include <string.h>

extern void base_foundation_cleanse_probe(uint8_t *buf, size_t len);

static int test_checked_arithmetic(void)
{
    int failures = 0;
    TEST("base checked arithmetic: exact boundaries and cleared failures") {
        size_t sz = 99;
        uint64_t u = 99;
        ASSERT(zcl_size_add(SIZE_MAX - 1, 1, &sz) && sz == SIZE_MAX);
        ASSERT(!zcl_size_add(SIZE_MAX, 1, &sz) && sz == 0);
        ASSERT(zcl_size_mul(SIZE_MAX, 1, &sz) && sz == SIZE_MAX);
        ASSERT(!zcl_size_mul(SIZE_MAX, 2, &sz) && sz == 0);
        ASSERT(zcl_size_mul(0, SIZE_MAX, &sz) && sz == 0);
        ASSERT(zcl_u64_add(UINT64_MAX - 1, 1, &u) && u == UINT64_MAX);
        ASSERT(!zcl_u64_add(UINT64_MAX, 1, &u) && u == 0);
        ASSERT(zcl_u64_mul(UINT64_MAX, 1, &u) && u == UINT64_MAX);
        ASSERT(!zcl_u64_mul(UINT64_MAX, 2, &u) && u == 0);
        ASSERT(zcl_u64_add(1, 2, NULL));
        ASSERT(!zcl_u64_mul(UINT64_MAX, 2, NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_cleanse_cross_tu(void)
{
    int failures = 0;
    TEST("base cleanse: optimized cross-translation-unit store survives") {
        uint8_t secret[97];
        memset(secret, 0xa5, sizeof(secret));
        base_foundation_cleanse_probe(secret, sizeof(secret));
        for (size_t i = 0; i < sizeof(secret); i++)
            ASSERT(secret[i] == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The polarity of these two is the whole reason base/bytes.h exists: 119
 * private copies of this loop disagreed, 13 of them answering the OPPOSITE
 * question under a name that looked the same. These checks pin the two
 * predicates as exact negations, and pin NULL to fail closed in BOTH
 * directions, which is what makes a "reject a zero root" caller also reject
 * a NULL one instead of accepting it. */
static int test_bytes_polarity(void)
{
    int failures = 0;
    TEST("base bytes: all_zero is the exact negation of any_set") {
        uint8_t buf[32];

        /* NULL and zero length: nothing is set, everything is zero. */
        ASSERT(!zcl_bytes_any_set(NULL, 32));
        ASSERT(zcl_bytes_all_zero(NULL, 32));
        ASSERT(!zcl_bytes_any_set(NULL, 0));
        ASSERT(zcl_bytes_all_zero(NULL, 0));
        memset(buf, 0xff, sizeof(buf));
        ASSERT(!zcl_bytes_any_set(buf, 0));
        ASSERT(zcl_bytes_all_zero(buf, 0));

        /* An all-zero buffer. */
        memset(buf, 0, sizeof(buf));
        ASSERT(!zcl_bytes_any_set(buf, sizeof(buf)));
        ASSERT(zcl_bytes_all_zero(buf, sizeof(buf)));

        /* Only the first byte set. */
        memset(buf, 0, sizeof(buf));
        buf[0] = 0x01u;
        ASSERT(zcl_bytes_any_set(buf, sizeof(buf)));
        ASSERT(!zcl_bytes_all_zero(buf, sizeof(buf)));

        /* Only the last byte set — the copies that stopped early still had
         * to reach this one. */
        memset(buf, 0, sizeof(buf));
        buf[sizeof(buf) - 1u] = 0x01u;
        ASSERT(zcl_bytes_any_set(buf, sizeof(buf)));
        ASSERT(!zcl_bytes_all_zero(buf, sizeof(buf)));

        /* Only a middle byte set. */
        memset(buf, 0, sizeof(buf));
        buf[sizeof(buf) / 2u] = 0x80u;
        ASSERT(zcl_bytes_any_set(buf, sizeof(buf)));
        ASSERT(!zcl_bytes_all_zero(buf, sizeof(buf)));
        PASS();
    } _test_next:;
    return failures;
}

/* Every single bit in a 32-byte root, one at a time: no position and no bit
 * within a position is allowed to be missed. */
static int test_bytes_single_bit(void)
{
    int failures = 0;
    TEST("base bytes: a 32-byte buffer with any single bit set is any_set") {
        for (size_t byte = 0; byte < 32u; byte++) {
            for (unsigned bit = 0; bit < 8u; bit++) {
                uint8_t root[32];
                memset(root, 0, sizeof(root));
                root[byte] = (uint8_t)(1u << bit);
                ASSERT(zcl_bytes_any_set(root, sizeof(root)));
                ASSERT(!zcl_bytes_all_zero(root, sizeof(root)));
                /* The negation must hold for this input too. */
                ASSERT(zcl_bytes_all_zero(root, sizeof(root)) !=
                       zcl_bytes_any_set(root, sizeof(root)));
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_base_foundation(void)
{
    return test_checked_arithmetic() + test_cleanse_cross_tu() +
           test_bytes_polarity() + test_bytes_single_bit();
}
