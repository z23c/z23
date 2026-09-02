/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact daily C23 Git-history parser and refusal tests. */
#include "science/code_growth.h"

#include <stdio.h>
#include <string.h>

#define GROWTH_CHECK(name_, expression_) do {                         \
    bool growth_ok_ = (expression_);                                  \
    printf("code_growth: %s... %s\n", (name_),                       \
           growth_ok_ ? "OK" : "FAIL");                             \
    if (!growth_ok_) failures++;                                      \
} while (0)

int test_code_growth(void)
{
    int failures = 0;
    static const char stream[] =
        "@@0000000000000000000000000000000000000001\t0\n"
        "5\t0\tlib/demo/src/a.c\n"
        "2\t0\tlib/test/src/test_a.c\n"
        "3\t0\ttests/harness/src/test_current.c\n"
        "-\t-\tapp/views/assets/icon.png\n"
        "10\t0\tdocs/not-maintained.c\n"
        "@@0000000000000000000000000000000000000002\t172800\n"
        "3\t1\tlib/demo/src/a.c\n"
        "4\t1\tcontexts/commons/packages/demo/tests/check.c\n";
    struct science_code_growth_history history;
    char error[160];
    bool parsed = science_code_growth_parse(
        stream, sizeof(stream) - 1u, &history, error, sizeof(error));
    GROWTH_CHECK("every UTC day is reconstructed",
                 parsed && history.day_count == 3u &&
                 strcmp(history.days[0].date, "1970-01-01") == 0 &&
                 strcmp(history.days[1].date, "1970-01-02") == 0 &&
                 strcmp(history.days[2].date, "1970-01-03") == 0);
    GROWTH_CHECK("inactive days carry totals without inventing changes",
                 parsed && history.days[1].commits == 0u &&
                 history.days[1].non_test_added == 0u &&
                 history.days[1].non_test_deleted == 0u &&
                 history.days[1].test_added == 0u &&
                 history.days[1].test_deleted == 0u &&
                 history.days[1].non_test_lines == 15u &&
                 history.days[1].test_lines == 5u);
    GROWTH_CHECK("maintained documentation source is counted; binary rows are not",
                 parsed && history.days[0].non_test_added == 15u &&
                 history.days[0].test_added == 5u);
    GROWTH_CHECK("non-test and test totals remain separate",
                 parsed && history.non_test_lines == 17u &&
                 history.test_lines == 8u &&
                 history.days[2].non_test_lines == 17u &&
                 history.days[2].test_lines == 8u);
    GROWTH_CHECK("the day's exact last commit is retained for evidence",
                 parsed && strcmp(history.days[2].head_commit,
                     "0000000000000000000000000000000000000002") == 0);

    static const char underflow[] =
        "@@0000000000000000000000000000000000000001\t0\n"
        "0\t1\tlib/demo/src/a.c\n";
    memset(&history, 0xa5, sizeof(history));
    GROWTH_CHECK("a deletion outside reconstructed history refuses",
                 !science_code_growth_parse(
                     underflow, sizeof(underflow) - 1u, &history,
                     error, sizeof(error)) &&
                 strstr(error, "deletes lines") != NULL);

    static const char malformed[] =
        "@@not-a-commit\t0\n1\t0\tlib/demo/src/a.c\n";
    GROWTH_CHECK("a malformed Git header refuses",
                 !science_code_growth_parse(
                     malformed, sizeof(malformed) - 1u, &history,
                     error, sizeof(error)));
    return failures;
}
