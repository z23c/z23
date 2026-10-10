/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TEST_VERDICT_JSON_H
#define ZCL_TEST_VERDICT_JSON_H

/* Renderer for build/test-verdict.json (schema zcl.test_verdict.v1), the
 * machine-readable verdict of one test_parallel run. Kept in a header so the
 * runner (test_parallel.c) and its unit test (test_test_group_selector.c) share
 * one implementation; no link dependency on the runner's main() translation
 * unit. Fixed-format snprintf, no JSON library. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "util/log_json.h"

#define TEST_VERDICT_MAX_FAILED_NAMES 64

struct test_verdict_doc {
    const char *mode;               /* "cold" | "cached" */
    size_t groups_total;
    size_t groups_ran;
    size_t groups_cached;
    size_t groups_failed;           /* the full failed count, may exceed names */
    const char *const *failed_names; /* first failed groups; at most 64 used */
    size_t failed_names_count;
    const char *toolkey;
    const char *devbuild_lane;      /* NULL renders as JSON null */
    long long ended_unix;
};

static inline bool test_verdict_append(char *buf, size_t cap, size_t *off,
                                       const char *fmt, ...)
{
    if (*off >= cap)
        return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *off)
        return false;
    *off += (size_t)n;
    return true;
}

/* Appends a JSON string literal (quoted, escaped), or null for a NULL input. */
static inline bool test_verdict_append_str(char *buf, size_t cap, size_t *off,
                                           const char *text)
{
    if (!text)
        return test_verdict_append(buf, cap, off, "null");
    char escaped[512];
    (void)log_json_escape(escaped, sizeof(escaped), text);
    return test_verdict_append(buf, cap, off, "\"%s\"", escaped);
}

/* Renders the document as one JSON object plus a trailing newline. Returns the
 * byte length written, or -1 when the buffer is too small or an argument is
 * missing. Names beyond 64 are dropped and failed_groups_truncated is set
 * whenever groups_failed exceeds the names rendered. */
static inline int test_verdict_json_format(char *buf, size_t cap,
                                           const struct test_verdict_doc *d)
{
    if (!buf || cap == 0 || !d)
        return -1;
    size_t off = 0;
    bool ok = test_verdict_append(buf, cap, &off,
        "{\"schema\":\"zcl.test_verdict.v1\",\"mode\":");
    ok = ok && test_verdict_append_str(buf, cap, &off, d->mode);
    ok = ok && test_verdict_append(buf, cap, &off,
        ",\"groups_total\":%zu,\"groups_ran\":%zu,\"groups_cached\":%zu,"
        "\"groups_failed\":%zu,\"failed_groups\":[",
        d->groups_total, d->groups_ran, d->groups_cached, d->groups_failed);
    size_t shown = d->failed_names_count < TEST_VERDICT_MAX_FAILED_NAMES
        ? d->failed_names_count : TEST_VERDICT_MAX_FAILED_NAMES;
    for (size_t i = 0; ok && i < shown; i++) {
        if (i > 0)
            ok = test_verdict_append(buf, cap, &off, ",");
        ok = ok && test_verdict_append_str(buf, cap, &off, d->failed_names[i]);
    }
    bool truncated = d->groups_failed > shown;
    ok = ok && test_verdict_append(buf, cap, &off,
        "],\"failed_groups_truncated\":%s,\"toolkey\":",
        truncated ? "true" : "false");
    ok = ok && test_verdict_append_str(buf, cap, &off, d->toolkey);
    ok = ok && test_verdict_append(buf, cap, &off, ",\"devbuild_lane\":");
    ok = ok && test_verdict_append_str(buf, cap, &off, d->devbuild_lane);
    ok = ok && test_verdict_append(buf, cap, &off,
        ",\"ended_unix\":%lld}\n", d->ended_unix);
    return ok ? (int)off : -1;
}

#endif /* ZCL_TEST_VERDICT_JSON_H */
