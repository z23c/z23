/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet goal D6, delivery-to-verdict time
 * (tools/command/native_fleet_goals_feedback.c). Every case writes its own
 * landing outcomes ledger under a fresh tmpdir and grades D6 through the
 * public catalog entry point, so the static row and the reader are both
 * exercised. Nothing here reads a live ledger.
 */

#include "test/test_core.h"

#include "command/native_fleet_goals.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FDF_NOW INT64_C(1800000000)
#define FDF_WEEK INT64_C(604800)

static bool fdf_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote && chmod(path, 0600) == 0;
}

static void fdf_options(struct zcl_goals_options *o)
{
    memset(o, 0, sizeof(*o));
    o->now_unix = FDF_NOW;
    o->skip_probes = true;
    o->hosts_given = true;
}

static bool fdf_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static void fdf_iso(int64_t t, char *out, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tm;
    (void)gmtime_r(&tt, &tm);
    (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Appends one ledger row. The submit time is landed_at minus `dur` seconds;
 * landed_at 0 omits the field, as a row written before it existed. */
static void fdf_row(char *buf, size_t cap, int i, const char *state,
                    int64_t landed_at, int64_t dur)
{
    char iso[32];
    size_t used = strlen(buf);
    fdf_iso(landed_at - dur, iso, sizeof(iso));
    if (landed_at > 0)
        (void)snprintf(buf + used, cap - used,
                       "{\"seq\":%d,\"ts\":\"%s\",\"note\":\"n%d\","
                       "\"state\":\"%s\",\"landed_at\":%lld}\n",
                       i, iso, i, state, (long long)landed_at);
    else
        (void)snprintf(buf + used, cap - used,
                       "{\"seq\":%d,\"ts\":\"%s\",\"note\":\"n%d\","
                       "\"state\":\"%s\"}\n",
                       i, iso, i, state);
}

/* `count` landed rows inside the window, one per ten minutes ending an hour
 * before FDF_NOW; row i takes duration dur(i). */
static void fdf_landed(char *buf, size_t cap, int count, int64_t base,
                       int64_t step)
{
    buf[0] = '\0';
    for (int i = 0; i < count; i++)
        fdf_row(buf, cap, i, "landed", FDF_NOW - 3600 - (int64_t)i * 600,
                base + (int64_t)i * step);
}

static int fdf_case_pass(const char *root)
{
    int failures = 0;
    char path[600], text[16384];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fdf_options(&o);
    (void)snprintf(path, sizeof(path), "%s/d6_pass.jsonl", root);
    o.outcomes = path;
    TEST("D6: 20 landed rows in 7 days grade on median and p95; an old row is outside the window") {
        /* durations 30..125 s: median 77 s, p95 120 s, both inside the bar */
        fdf_landed(text, sizeof(text), 20, 30, 5);
        fdf_row(text, sizeof(text), 99, "landed", FDF_NOW - FDF_WEEK - 3600,
                9000);
        ASSERT(fdf_write(path, text));
        r = zcl_goals_measure(&o, "D6");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fdf_has(r.evidence, "20 landed row(s)"));
        ASSERT(fdf_has(r.evidence, "median 77 s"));
        ASSERT(fdf_has(r.evidence, "p95 120 s"));
        ASSERT(fdf_has(r.evidence, "bar 180 s"));
        ASSERT(!fdf_has(r.evidence, "skipped"));
        PASS();
    } _test_next:;
    return failures;
}

static int fdf_case_fail(const char *root)
{
    int failures = 0;
    char path[600], text[16384];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fdf_options(&o);
    (void)snprintf(path, sizeof(path), "%s/d6_fail.jsonl", root);
    o.outcomes = path;
    TEST("D6: a p95 over 180 s grades FAIL and names the p95") {
        /* 15 rows at 60 s and 5 rows at 400 s: the 19th of 20 is 400 s */
        fdf_landed(text, sizeof(text), 15, 60, 0);
        for (int i = 15; i < 20; i++)
            fdf_row(text, sizeof(text), i, "landed",
                    FDF_NOW - 3600 - (int64_t)i * 600, 400);
        ASSERT(fdf_write(path, text));
        r = zcl_goals_measure(&o, "D6");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fdf_has(r.evidence, "p95 400 s"));
        ASSERT(fdf_has(r.evidence, "bar 180 s"));
        PASS();
    } _test_next:;
    return failures;
}

static int fdf_case_empty(const char *root)
{
    int failures = 0;
    char path[600], text[4096];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fdf_options(&o);
    (void)snprintf(path, sizeof(path), "%s/d6_empty.jsonl", root);
    o.outcomes = path;
    TEST("D6: no usable landed row is unmeasured with the reason") {
        text[0] = '\0';
        ASSERT(fdf_write(path, ""));
        r = zcl_goals_measure(&o, "D6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fdf_has(r.evidence, "0 landed row(s)"));
        /* a failed row and a landed row older than the window are not usable */
        fdf_row(text, sizeof(text), 1, "failed", FDF_NOW - 3600, 100);
        fdf_row(text, sizeof(text), 2, "landed", FDF_NOW - FDF_WEEK - 60, 100);
        ASSERT(fdf_write(path, text));
        r = zcl_goals_measure(&o, "D6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fdf_has(r.evidence, "0 landed row(s)"));
        o.outcomes = "/nonexistent/d6/outcomes.jsonl";
        r = zcl_goals_measure(&o, "D6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fdf_has(r.evidence, "missing ledger"));
        PASS();
    } _test_next:;
    return failures;
}

static int fdf_case_malformed(const char *root)
{
    int failures = 0;
    char path[600], text[16384], bad[512];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fdf_options(&o);
    (void)snprintf(path, sizeof(path), "%s/d6_bad.jsonl", root);
    o.outcomes = path;
    TEST("D6: rows without landed_at, with an unreadable ts or a negative duration are skipped and counted") {
        fdf_landed(text, sizeof(text), 20, 60, 0);
        /* no landed_at */
        bad[0] = '\0';
        fdf_row(bad, sizeof(bad), 50, "landed", 0, 60);
        (void)snprintf(text + strlen(text), sizeof(text) - strlen(text), "%s",
                       bad);
        /* unreadable submit time */
        (void)snprintf(bad, sizeof(bad),
                       "{\"seq\":51,\"ts\":\"yesterday\",\"state\":\"landed\","
                       "\"landed_at\":%lld}\n", (long long)(FDF_NOW - 600));
        (void)snprintf(text + strlen(text), sizeof(text) - strlen(text), "%s",
                       bad);
        /* landed_at before the submit time */
        (void)snprintf(bad, sizeof(bad),
                       "{\"seq\":52,\"ts\":\"2026-10-20T00:00:00Z\","
                       "\"state\":\"landed\",\"landed_at\":1700000000}\n");
        (void)snprintf(text + strlen(text), sizeof(text) - strlen(text), "%s",
                       bad);
        ASSERT(fdf_write(path, text));
        r = zcl_goals_measure(&o, "D6");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fdf_has(r.evidence, "20 landed row(s)"));
        ASSERT(fdf_has(r.evidence, "median 60 s"));
        ASSERT(fdf_has(r.evidence, "3 row(s) skipped"));
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_goals_feedback(void);
int test_fleet_goals_feedback(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_goals_feedback", "root");
    failures += fdf_case_pass(root);
    failures += fdf_case_fail(root);
    failures += fdf_case_empty(root);
    failures += fdf_case_malformed(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals_feedback: all passed\n");
    else
        printf("test_fleet_goals_feedback: %d FAILED\n", failures);
    return failures;
}
