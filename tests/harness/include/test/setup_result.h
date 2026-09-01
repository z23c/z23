/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL_TEST_SETUP — read a zcl_result returned by test FIXTURE SETUP.
 *
 * struct zcl_result is [[nodiscard]] (platform/modules/util/include/util/result.h), so a
 * bare `fixture_open(...);` statement is now a warning. The tempting fix is a
 * `(void)` cast, which C23 accepts — and which would restore exactly the
 * problem the attribute exists to prevent: a fixture that failed to build,
 * followed by a run of assertions that silently test nothing and still print
 * OK.
 *
 * So setup calls go through this macro instead. It reads the result, prints
 * the carried file:line/code/message on failure, and counts the failure so
 * the enclosing test returns non-zero. A broken fixture becomes a red test
 * rather than a green lie.
 *
 * Usage — at the end of the test entry point, fold the counter in:
 *
 *   int test_thing(void) {
 *       int failures = 0;
 *       ZCL_TEST_SETUP(open_fixture(&f));
 *       ...
 *       return failures + ZCL_TEST_SETUP_FAILURES();
 *   }
 *
 * The counter is per-translation-unit (static), which is what we want: each
 * test file folds in its own setup failures.
 */

#ifndef ZCL_TEST_SETUP_RESULT_H
#define ZCL_TEST_SETUP_RESULT_H

#include <stdio.h>

#include "util/result.h"

[[maybe_unused]] static int zcl_test_setup_failure_count;

#define ZCL_TEST_SETUP(res_expr) do {                                     \
    struct zcl_result _zcl_setup_r = (res_expr);                          \
    if (!_zcl_setup_r.ok) {                                               \
        printf("SETUP FAIL %s:%d: %s -> [%s:%d] code=%d %s\n",            \
               __FILE__, __LINE__, #res_expr,                             \
               _zcl_setup_r.source_file, _zcl_setup_r.source_line,        \
               _zcl_setup_r.code, _zcl_setup_r.message);                  \
        zcl_test_setup_failure_count++;                                   \
    }                                                                     \
} while (0)

#define ZCL_TEST_SETUP_FAILURES() (zcl_test_setup_failure_count)

#endif /* ZCL_TEST_SETUP_RESULT_H */
