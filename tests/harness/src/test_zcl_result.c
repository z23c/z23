/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for struct zcl_result / ZCL_ERR / ZCL_CHECK.
 * Plan: WALLET_PERSISTENCE_PLAN.md §5.1 / tasks/AGENT_2_WALLET_SQLITE.md D1. */

#include "test/test_core.h"
#include "util/result.h"
#include <string.h>

static struct zcl_result returns_ok(void)
{
    return ZCL_OK;
}

static struct zcl_result returns_err(int code)
{
    return ZCL_ERR(code, "something broke: value=%d label=%s", code, "wallet");
}

static struct zcl_result forwards_with_check(int code)
{
    ZCL_CHECK(returns_err(code));
    return ZCL_OK;  /* unreachable on failure — ZCL_CHECK returns */
}

static int test_zcl_ok_is_ok(void)
{
    int failures = 0;
    TEST("zcl_result: ZCL_OK is ok and code 0") {
        struct zcl_result r = returns_ok();
        ASSERT(r.ok);
        ASSERT(r.code == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_err_populates_fields(void)
{
    int failures = 0;
    TEST("zcl_result: ZCL_ERR populates code, message, file, line") {
        struct zcl_result r = returns_err(-42);
        ASSERT(!r.ok);
        ASSERT(r.code == -42);
        ASSERT(r.source_file != NULL);
        ASSERT(strstr(r.source_file, "test_zcl_result.c") != NULL);
        ASSERT(r.source_line > 0);
        /* Message must contain both the code and the label — proves
         * vsnprintf fed the format args correctly. */
        ASSERT(strstr(r.message, "-42") != NULL);
        ASSERT(strstr(r.message, "wallet") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_check_propagates(void)
{
    int failures = 0;
    TEST("zcl_result: ZCL_CHECK propagates non-ok upward") {
        struct zcl_result r = forwards_with_check(-99);
        ASSERT(!r.ok);
        ASSERT(r.code == -99);
        /* source_file should still point to the original ZCL_ERR
         * site, not the ZCL_CHECK site. */
        ASSERT(strstr(r.source_file, "test_zcl_result.c") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_truncation_visible(void)
{
    int failures = 0;
    TEST("zcl_result: message truncation leaves a visible marker") {
        char big[ZCL_RESULT_MSG_MAX * 2];
        memset(big, 'X', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        struct zcl_result r = ZCL_ERR(-1, "%s", big);
        ASSERT(!r.ok);
        ASSERT(r.message[ZCL_RESULT_MSG_MAX - 1] == '\0');
        ASSERT(strstr(r.message, "truncated") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_empty_message(void)
{
    int failures = 0;
    TEST("zcl_result: empty format still produces a valid struct") {
        struct zcl_result r = ZCL_ERR(-1, "%s", "");
        ASSERT(!r.ok);
        ASSERT(r.message[0] == '\0');
        ASSERT(r.code == -1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_null_format_is_explicit(void)
{
    int failures = 0;
    TEST("zcl_result: NULL format produces an explicit diagnostic") {
        struct zcl_result r = zcl_result_make(-7, __FILE__, __LINE__, NULL);
        ASSERT(!r.ok);
        ASSERT(r.code == -7);
        ASSERT(strstr(r.message, "missing format") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcl_result(void)
{
    int failures = 0;
    failures += test_zcl_ok_is_ok();
    failures += test_zcl_err_populates_fields();
    failures += test_zcl_check_propagates();
    failures += test_zcl_truncation_visible();
    failures += test_zcl_empty_message();
    failures += test_zcl_null_format_is_explicit();
    return failures;
}
