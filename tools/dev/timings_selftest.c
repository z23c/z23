/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: exercise timing report coverage and refusal semantics. */
#define _POSIX_C_SOURCE 200809L
#ifdef ZCL_TIMINGS_STANDALONE
#include "timings.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef void (*render_fn)(struct timings_context *, const struct json_value *, const char *);
static bool sample(render_fn fn, const char *raw, const char *state,
                   const char *expect, const char *reject)
{
    struct json_value v = {0}; char *text = NULL; size_t len = 0;
    if (!json_read(&v, raw, strlen(raw))) return false;
    FILE *f = open_memstream(&text, &len);
    if (!f) { json_free(&v); return false; }
    struct timings_context c = {f, 1, 9};
    fn(&c, &v, state);
    bool ok = fclose(f) == 0 && text && strstr(text, expect) &&
              (!reject || !strstr(text, reject));
    if (!ok) fprintf(stderr, "timings selftest: expected %s; got %s\n", expect, text ? text : "(null)");
    free(text); json_free(&v); return ok;
}
static bool lint_cases(void)
{
    return sample(timings_lint, "{\"gate_count\":1,\"gates\":[]}",
                  "STALE (mtime only)", "STALE", NULL) &&
           sample(timings_lint, "{\"gate_count\":1,\"gates\":[]}",
                  "RECENT (mtime only)", "PARTIAL", NULL);
}
static bool test_cases(void)
{
    return sample(timings_tests,
                  "{\n \"group_count\":4, \"groups_ran\":1, \"groups_cached\":0, \"skipped_count\":3, \"mode\":\"cold\"}",
                  "RECENT (mtime only)", "PARTIAL", NULL) &&
           sample(timings_tests,
                  "{\"group_count\":4,\"groups_ran\":1,\"groups_cached\":3,\"skipped_count\":0,\"mode\":\"cached\"}",
                  "RECENT (mtime only)", "cached 3", "PARTIAL") &&
           sample(timings_tests, "{\"group_count\":4}", "TIMESTAMP UNKNOWN",
                  "coverage UNKNOWN", "all catalog groups") &&
           sample(timings_tests,
                  "{\"group_count\":1,\"groups_ran\":1,\"groups_cached\":0,\"skipped_count\":0,\"jobs\":7}",
                  "RECENT (mtime only)", "all recorded groups", "all catalog groups");
}
static bool other_cases(void)
{
    return sample(timings_devloop,
                  "{\"cases\":[{\"name\":\"no_op\",\"command\":\":\",\"p50_ms\":3},{\"name\":\"real_case\",\"command\":\"make thing\",\"p50_ms\":4242}]}",
                  "RECENT (mtime only)", "UNTRUSTED  no_op", "no_op p50") &&
           sample(timings_devloop,
                  "{\"cases\":[{\"name\":\"real_case\",\"command\":\"make thing\",\"p50_ms\":4242}]}",
                  "RECENT (mtime only)", "real_case p50 4242 ms", NULL) &&
           sample(timings_first_build,
                  "{\"total_seconds\":999,\"clone_source\":\"local\",\"stages\":[{\"name\":\"vendor\",\"seconds\":42,\"rc\":1}]}",
                  "RECENT (mtime only)", "FAILED     vendor", "999 s total") &&
           sample(timings_first_build,
                  "{\"clone_source\":\"local\",\"stages\":[]}", "RECENT (mtime only)",
                  "LOCAL path", NULL) &&
           sample(timings_first_build,
                  "{\"total_seconds\":999,\"stages\":[{\"rc\":-1}]}", "RECENT (mtime only)",
                  "total withheld", "999 s total") &&
           sample(timings_first_build,
                  "{\"total_seconds\":999,\"stages\":[{}]}", "RECENT (mtime only)",
                  "total withheld", "999 s total") &&
           sample(timings_first_build,
                  "{\"generated_at_utc\":\"2026-01-01\",\"stages\":[]}", "TIMESTAMP UNKNOWN",
                  "2026-01-01", NULL) &&
           sample(timings_tests, "{\"jobs\":7}", "TIMESTAMP UNKNOWN", "jobs 7", NULL);
}
int timings_selftest(void)
{
    if (timings_file_selftest() || !lint_cases() || !test_cases() || !other_cases()) return 1;
    puts("timings selftest: PASS"); return 0;
}
#else
_Static_assert(1, "timings selftest belongs to the standalone tool");
#endif
