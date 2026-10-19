/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.goals (tools/command/native_fleet_goals*.c).
 *
 * Every path a producer reads is overridable and the clock is injected, so
 * the grading logic runs against fixtures built here: a pass, a partial, a
 * fail and an unmeasured row with its reason. The in-process code and wiki
 * probes are skipped; their values depend on the machine.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet_goals.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FGL_NOW INT64_C(1800000000)

static bool fgl_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static void fgl_options(struct zcl_goals_options *o)
{
    memset(o, 0, sizeof(*o));
    o->now_unix = FGL_NOW;
    o->skip_probes = true;
    o->hosts_given = true;
}

static bool fgl_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static int fgl_case_catalog(void)
{
    int failures = 0;
    const struct zcl_goal_row *rows;
    size_t n = zcl_goals_catalog(&rows);
    struct zcl_goals_options o;
    fgl_options(&o);
    TEST("catalog: G1-G13, C1-C8, D1-D8, unique, every row answers") {
        ASSERT(n == 29);
        ASSERT_STR_EQ(rows[0].id, "G1");
        ASSERT_STR_EQ(rows[12].id, "G13");
        ASSERT_STR_EQ(rows[13].id, "C1");
        ASSERT_STR_EQ(rows[28].id, "D8");
        for (size_t i = 0; i < n; i++) {
            struct zcl_goal_result r;
            ASSERT(rows[i].title[0] && rows[i].bar[0]);
            for (size_t j = i + 1; j < n; j++)
                ASSERT(strcmp(rows[i].id, rows[j].id) != 0);
            o.outcomes = "/nonexistent/outcomes.jsonl";
            r = zcl_goals_measure(&o, rows[i].id);
            ASSERT(r.evidence[0] && r.next[0]);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_graders(void)
{
    int failures = 0;
    TEST("graders: each threshold sits where the bar says") {
        ASSERT(zcl_goals_grade_trains(3, 0) == ZCL_GOAL_PASS);
        ASSERT(zcl_goals_grade_trains(2, 0) == ZCL_GOAL_PARTIAL);
        ASSERT(zcl_goals_grade_trains(3, 1) == ZCL_GOAL_PARTIAL);
        ASSERT(zcl_goals_grade_trains(0, 0) == ZCL_GOAL_FAIL);
        ASSERT(zcl_goals_grade_lookup(50) == ZCL_GOAL_PARTIAL);
        ASSERT(zcl_goals_grade_lookup(51) == ZCL_GOAL_FAIL);
        ASSERT(zcl_goals_grade_fresh(0, 3) == ZCL_GOAL_FAIL);
        ASSERT(zcl_goals_grade_fresh(3, 3) == ZCL_GOAL_PARTIAL);
        ASSERT(zcl_goals_grade_claims(0) == ZCL_GOAL_FAIL);
        ASSERT(zcl_goals_grade_claims(1) == ZCL_GOAL_PARTIAL);
        ASSERT(zcl_goals_grade_scripts(0) == ZCL_GOAL_PARTIAL);
        ASSERT(zcl_goals_grade_scripts(1) == ZCL_GOAL_PARTIAL);
        ASSERT_STR_EQ(zcl_goal_grade_name(ZCL_GOAL_UNMEASURED), "unmeasured");
        PASS();
    } _test_next:;
    return failures;
}

#define FGL_ROW(note, state, ts) \
    "{\"tip\":\"t\",\"note\":\"" note "\",\"state\":\"" state \
    "\",\"ts\":\"" ts "\"}\n"

static int fgl_case_trains(const char *root)
{
    int failures = 0;
    char pass[600], fail[600], mixed[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    o.repo = root;
    (void)snprintf(pass, sizeof(pass), "%s/pass.jsonl", root);
    (void)snprintf(mixed, sizeof(mixed), "%s/mixed.jsonl", root);
    (void)snprintf(fail, sizeof(fail), "%s/fail.jsonl", root);
    TEST("G9: three landed trains and no failure pass; a failure or a short "
         "day does not") {
        struct zcl_goal_result r;
        ASSERT(fgl_write(pass,
            FGL_ROW("a", "landed", "2027-01-15T05:13:20Z")
            FGL_ROW("b", "landed", "2027-01-15T06:00:00Z")
            FGL_ROW("b", "landed", "2027-01-15T06:30:00Z")
            FGL_ROW("c", "landed", "2027-01-15T07:43:20Z")
            FGL_ROW("old", "failed", "2027-01-14T04:13:20Z")));
        o.outcomes = pass;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_PASS);
        ASSERT(fgl_has(r.evidence, "3 landed train(s) and 0 failed"));
        ASSERT(fgl_write(mixed,
            FGL_ROW("a", "landed", "2027-01-15T05:13:20Z")
            FGL_ROW("b", "landed", "2027-01-15T06:00:00Z")
            FGL_ROW("c", "landed", "2027-01-15T07:43:20Z")
            FGL_ROW("d", "failed", "2027-01-15T07:00:00Z")));
        o.outcomes = mixed;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "3 landed train(s) and 1 failed"));
        ASSERT(fgl_write(fail,
            FGL_ROW("old", "landed", "2027-01-14T04:13:20Z")));
        o.outcomes = fail;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "0 landed train(s)"));
        ASSERT(fgl_write(fail,
            "{\"note\":\"a\",\"state\":\"landed\"}\n"));
        o.outcomes = fail;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "no readable timestamp"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_missing(const char *root)
{
    int failures = 0;
    char missing[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    o.repo = root;
    (void)snprintf(missing, sizeof(missing), "%s/missing.jsonl", root);
    TEST("G9: a missing ledger is unmeasured and names the file") {
        struct zcl_goal_result r;
        o.outcomes = missing;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "missing ledger"));
        ASSERT(fgl_has(r.evidence, "missing.jsonl"));
        PASS();
    } _test_next:;
    return failures;
}

static void fgl_iso(int64_t t, char *out, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tm;
    (void)gmtime_r(&tt, &tm);
    (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Appends one ledger row; `dimension` may be empty. */
static void fgl_row(char *buf, size_t cap, int i, const char *state,
                    int64_t ts, const char *dimension)
{
    char iso[32];
    size_t used = strlen(buf);
    fgl_iso(ts, iso, sizeof(iso));
    (void)snprintf(buf + used, cap - used,
                   "{\"tip\":\"t\",\"note\":\"n%d\",\"state\":\"%s\","
                   "\"dimension\":\"%s\",\"ts\":\"%s\"}\n",
                   i, state, dimension, iso);
}

/* Twenty groups ten minutes apart ending at FGL_NOW - 60; group `bad`
 * (-1 for none) is a failure carrying `dimension`. */
static void fgl_groups(char *buf, size_t cap, int count, int bad,
                       const char *dimension)
{
    buf[0] = '\0';
    for (int i = 0; i < count; i++)
        fgl_row(buf, cap, i, i == bad ? "failed" : "landed",
                FGL_NOW - 60 - (int64_t)(count - 1 - i) * 600,
                i == bad ? dimension : "");
}

static int fgl_case_stale(const char *root)
{
    int failures = 0;
    char path[600];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fgl_options(&o);
    (void)snprintf(path, sizeof(path), "%s/stale.jsonl", root);
    o.outcomes = path;
    TEST("G9: a ledger older than origin/main is unmeasured, never a failure") {
        ASSERT(fgl_write(path,
            FGL_ROW("a", "landed", "2027-01-15T05:13:20Z")));
        o.origin_tip_unix = FGL_NOW;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "ledger stale since 2027-01-15T05:13:20Z"));
        ASSERT(fgl_has(r.evidence, "read on the lander host"));
        ASSERT(fgl_write(path, ""));
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "ledger stale since never"));
        ASSERT(fgl_write(path,
            FGL_ROW("a", "landed", "2027-01-15T07:43:20Z")));
        o.origin_tip_unix = FGL_NOW - 600;
        r = zcl_goals_measure(&o, "G9");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "1 landed train(s)"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_d7_unmeasured(const char *root)
{
    int failures = 0;
    char path[600], text[16384];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fgl_options(&o);
    (void)snprintf(path, sizeof(path), "%s/d7short.jsonl", root);
    o.outcomes = path;
    TEST("D7: fewer than 20 groups, or a stale ledger, is unmeasured") {
        fgl_groups(text, sizeof(text), 19, -1, "");
        ASSERT(fgl_write(path, text));
        o.origin_tip_unix = FGL_NOW - 60;
        r = zcl_goals_measure(&o, "D7");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "19 landing group(s)"));
        fgl_groups(text, sizeof(text), 20, -1, "");
        ASSERT(fgl_write(path, text));
        o.origin_tip_unix = FGL_NOW + 7200;
        r = zcl_goals_measure(&o, "D7");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "ledger stale since"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_d7_grade(const char *root)
{
    int failures = 0;
    char path[600], text[16384];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fgl_options(&o);
    (void)snprintf(path, sizeof(path), "%s/d7grade.jsonl", root);
    o.outcomes = path;
    TEST("D7: 20 groups grade on unnamed failures and landed spacing") {
        o.origin_tip_unix = FGL_NOW - 60;
        fgl_groups(text, sizeof(text), 20, -1, "");
        ASSERT(fgl_write(path, text));
        r = zcl_goals_measure(&o, "D7");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "0 of the last 20 groups failed without"));
        ASSERT(fgl_has(r.evidence, "median spacing of landed groups 600 s"));
        fgl_groups(text, sizeof(text), 20, 7, "");
        ASSERT(fgl_write(path, text));
        r = zcl_goals_measure(&o, "D7");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "1 of the last 20 groups failed without"));
        fgl_groups(text, sizeof(text), 20, 7, "lint");
        ASSERT(fgl_write(path, text));
        r = zcl_goals_measure(&o, "D7");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "0 of the last 20 groups failed without"));
        fgl_groups(text, sizeof(text), 25, 2, "");
        ASSERT(fgl_write(path, text));
        r = zcl_goals_measure(&o, "D7");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "0 of the last 20 groups failed without"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_files(const char *root)
{
    int failures = 0;
    char none[600], some[600], absent[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    (void)snprintf(none, sizeof(none), "%s/none.txt", root);
    (void)snprintf(some, sizeof(some), "%s/some.txt", root);
    (void)snprintf(absent, sizeof(absent), "%s/absent.txt", root);
    TEST("D8: an empty allowlist still caps at partial, entries are counted, a missing file "
         "is unmeasured") {
        struct zcl_goal_result r;
        ASSERT(fgl_write(none, "# header\n\n# only comments\n"));
        ASSERT(fgl_write(some, "# header\ntools/a.sh\n\ntools/b.sh\n"));
        o.bash_allowlist = none;
        r = zcl_goals_measure(&o, "D8");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        o.bash_allowlist = some;
        r = zcl_goals_measure(&o, "D8");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "2 shell script(s)"));
        o.bash_allowlist = absent;
        r = zcl_goals_measure(&o, "D8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "no shell script allowlist"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_claims(const char *root)
{
    int failures = 0;
    char held[600], empty[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    (void)snprintf(held, sizeof(held), "%s/claims.jsonl", root);
    (void)snprintf(empty, sizeof(empty), "%s/claims_empty.jsonl", root);
    TEST("G13: live leases and legacy rows count, expired leases do not") {
        struct zcl_goal_result r;
        ASSERT(fgl_write(held,
            "{\"worktree\":\"/a\",\"expires_unix\":1800000900}\n"
            "{\"worktree\":\"/b\"}\n"
            "{\"worktree\":\"/c\",\"expires_unix\":1799999000}\n"));
        ASSERT(fgl_write(empty, ""));
        o.claims = held;
        r = zcl_goals_measure(&o, "G13");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "2 live lane claim(s)"));
        o.claims = empty;
        r = zcl_goals_measure(&o, "G13");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        o.claims = "/nonexistent/claims.jsonl";
        r = zcl_goals_measure(&o, "G13");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "/nonexistent/claims.jsonl"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── C rows: newest durable receipt ───────────────────────────────────── */

static bool fgl_soak_hourly(const char *path, int64_t base, int count,
                            int skip_from, int skip_to)
{
    FILE *f = fopen(path, "wb");
    bool ok = f != NULL;
    for (int i = 0; ok && i < count; i++) {
        if (i >= skip_from && i <= skip_to)
            continue;
        ok = fprintf(f,
                 "{\"ts\":%lld,\"soak_height\":3000000,\"zd_height\":3000000,"
                 "\"gap\":0,\"nrestarts\":1,\"active_enter_ts\":%lld,"
                 "\"rss_kb\":1500000,\"binary_sha256\":\"%064d\","
                 "\"security_review_required\":false,"
                 "\"security_posture_ok\":true,\"window_eligible\":true,"
                 "\"ok\":true}\n",
                 (long long)(base + (int64_t)i * 3600),
                 (long long)(base - 500), 0) > 0;
    }
    return f && fclose(f) == 0 && ok;
}

static int fgl_case_receipt_c3(const char *root)
{
    int failures = 0;
    char hist[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    o.repo = ".";
    (void)snprintf(hist, sizeof(hist), "%s/c3_history.jsonl", root);
    o.c3_history = hist;
    TEST("C3: a fresh stopwatch pass passes with its receipt and age; a "
         "product failure fails; a skip or a stale receipt is unmeasured") {
        struct zcl_goal_result r;
        ASSERT(fgl_write(hist,
            "{\"ts\":1799996400,\"verdict\":\"pass\",\"artifact_dir\":"
            "\"/x/run-pass\",\"final_network_tip\":3100000}\n"));
        r = zcl_goals_measure(&o, "C3");
        ASSERT(r.grade == ZCL_GOAL_PASS);
        ASSERT(fgl_has(r.evidence, "receipt run-pass"));
        ASSERT(fgl_has(r.evidence, "age 1 h of 24 h"));
        ASSERT(fgl_write(hist,
            "{\"ts\":1799996400,\"verdict\":\"fail\",\"result_class\":"
            "\"PRODUCT_FAILURE\",\"artifact_dir\":\"/x/run-fail\"}\n"));
        r = zcl_goals_measure(&o, "C3");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "receipt run-fail"));
        ASSERT(fgl_write(hist,
            "{\"ts\":1799996400,\"verdict\":\"skip\",\"result_class\":"
            "\"ENVIRONMENT_BLOCKED\",\"artifact_dir\":\"/x/run-skip\"}\n"));
        r = zcl_goals_measure(&o, "C3");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "not a measurement"));
        ASSERT(fgl_write(hist,
            "{\"ts\":1799800000,\"verdict\":\"pass\",\"artifact_dir\":"
            "\"/x/run-old\",\"final_network_tip\":3100000}\n"));
        r = zcl_goals_measure(&o, "C3");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "stale"));
        ASSERT(fgl_has(r.evidence, "window 24 h"));
        o.c3_history = "/nonexistent/history.jsonl";
        r = zcl_goals_measure(&o, "C3");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "no receipt"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_receipt_c6(const char *root)
{
    int failures = 0;
    char dir[600], file[700];
    struct zcl_goals_options o;
    const int64_t base = FGL_NOW - INT64_C(168) * 3600 - 60;
    fgl_options(&o);
    o.repo = ".";
    (void)snprintf(dir, sizeof(dir), "%s/soak", root);
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", dir);
    o.soak_dir = dir;
    TEST("C6: a covered clean week passes; a hole fails; a short window "
         "stays unmeasured with the hours missing; a stale tail is unmeasured") {
        struct zcl_goal_result r;
        ASSERT(mkdir(dir, 0700) == 0 || access(dir, F_OK) == 0);
        ASSERT(fgl_soak_hourly(file, base, 169, -1, -1));
        r = zcl_goals_measure(&o, "C6");
        ASSERT(r.grade == ZCL_GOAL_PASS);
        ASSERT(fgl_has(r.evidence, "MET over 168.0 h"));
        ASSERT(fgl_has(r.evidence, "evidence.jsonl"));
        ASSERT(fgl_soak_hourly(file, base, 169, 50, 53));
        r = zcl_goals_measure(&o, "C6");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "sampling_hole"));
        ASSERT(fgl_soak_hourly(file, FGL_NOW - 11 * 3600 - 60, 12, -1, -1));
        r = zcl_goals_measure(&o, "C6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "needs 168 h of observation, have 11.0 h"));
        ASSERT(fgl_soak_hourly(file, base - 3 * 86400, 169, -1, -1));
        r = zcl_goals_measure(&o, "C6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "stale"));
        o.soak_dir = "/nonexistent/soak";
        r = zcl_goals_measure(&o, "C6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "needs 168 h of observation, have 0 h"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_receipt_none(void)
{
    int failures = 0;
    struct zcl_goals_options o;
    fgl_options(&o);
    TEST("C1 C2 C4 C5 C7 name the missing receipt producer; C8 names the "
         "observation it lacks; fixtures never read the host ledgers") {
        static const char *const ids[] = {"C1", "C2", "C4", "C5", "C7"};
        struct zcl_goal_result r;
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            r = zcl_goals_measure(&o, ids[i]);
            ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
            ASSERT(fgl_has(r.evidence, "no receipt producer"));
        }
        r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "needs 168 h of observation, have 0 h"));
        r = zcl_goals_measure(&o, "C3");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "skipped"));
        r = zcl_goals_measure(&o, "C6");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "skipped"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_hosts(void)
{
    int failures = 0;
    struct zcl_goals_options o;
    struct zcl_goals_host hosts[2];
    fgl_options(&o);
    memset(hosts, 0, sizeof(hosts));
    (void)snprintf(hosts[0].name, sizeof(hosts[0].name), "alpha");
    (void)snprintf(hosts[0].os, sizeof(hosts[0].os), "Linux");
    (void)snprintf(hosts[1].name, sizeof(hosts[1].name), "beta");
    (void)snprintf(hosts[1].os, sizeof(hosts[1].os), "Darwin");
    TEST("host-set goals: no roster is unmeasured with the reason; hosts come "
         "from the roster, never a fixed list") {
        static const char *const ids[] = {"G1", "G3", "G5", "G6", "G8", "G12"};
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            struct zcl_goal_result r = zcl_goals_measure(&o, ids[i]);
            ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
            ASSERT(fgl_has(r.evidence, "no admitted roster"));
        }
        o.hosts = hosts;
        o.host_count = 2;
        struct zcl_goal_result r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "2 admitted host(s)"));
        r = zcl_goals_measure(&o, "G12");
        ASSERT(fgl_has(r.evidence, "1 of 2 admitted host(s) report Darwin"));
        {
            static struct zcl_goals_host many[33];
            for (size_t i = 0; i < 33; i++)
                (void)snprintf(many[i].name, sizeof(many[i].name), "h%zu", i);
            o.hosts = many;
            o.host_count = 33;
            r = zcl_goals_measure(&o, "G8");
            ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
            ASSERT(fgl_has(r.evidence, "more than 32"));
            o.hosts = hosts;
        }
        o.host_count = 1;
        r = zcl_goals_measure(&o, "G12");
        ASSERT(fgl_has(r.evidence, "none reports Darwin"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_render(void)
{
    int failures = 0;
    TEST("tally and render count every grade once") {
        struct json_value rows, row;
        int64_t counts[4];
        char text[512];
        static const char *const grades[] = {"pass", "fail", "fail",
                                             "unmeasured"};
        json_init(&rows);
        json_set_array(&rows);
        for (size_t i = 0; i < 4; i++) {
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_str(&row, "id", "X");
            (void)json_push_kv_str(&row, "grade", grades[i]);
            (void)json_push_kv_str(&row, "title", "t");
            (void)json_push_kv_str(&row, "evidence", "e");
            (void)json_push_kv_str(&row, "next", "n");
            (void)json_push_back(&rows, &row);
            json_free(&row);
        }
        zcl_goals_tally(&rows, counts);
        ASSERT(counts[ZCL_GOAL_PASS] == 1 && counts[ZCL_GOAL_PARTIAL] == 0);
        ASSERT(counts[ZCL_GOAL_FAIL] == 2 && counts[ZCL_GOAL_UNMEASURED] == 1);
        ASSERT(zcl_goals_render_text(&rows, text, sizeof(text)) > 0);
        ASSERT(fgl_has(text, "unmeasured"));
        json_free(&rows);
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_bound(void)
{
    int failures = 0;
    TEST("the leaf is registered and bound") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), "fleet.goals",
                                      NULL);
        ASSERT(spec != NULL && spec->handler != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int fgl_case_handler(const char *root)
{
    int failures = 0;
    char outcomes[600], allow[600], claims[600];
    (void)snprintf(outcomes, sizeof(outcomes), "%s/h_out.jsonl", root);
    (void)snprintf(allow, sizeof(allow), "%s/h_allow.txt", root);
    (void)snprintf(claims, sizeof(claims), "%s/h_claims.jsonl", root);
    TEST("handler: 29 graded rows, summary equals the row counts, schema set") {
        struct json_value input;
        struct zcl_command_request request;
        struct zcl_command_reply reply;
        const struct json_value *rows, *summary;
        int64_t counts[4], total = 0;
        ASSERT(fgl_write(outcomes, ""));
        ASSERT(fgl_write(allow, "tools/a.sh\n"));
        ASSERT(fgl_write(claims, ""));
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "outcomes", outcomes);
        (void)json_push_kv_str(&input, "bash_allowlist", allow);
        (void)json_push_kv_str(&input, "claims", claims);
        memset(&request, 0, sizeof(request));
        request.input = &input;
        request.spec =
            zcl_command_registry_find(zcl_command_catalog(), "fleet.goals", NULL);
        zcl_command_reply_init(&reply, ZCL_GOALS_SCHEMA);
        zcl_native_handle_fleet_goals(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "schema")),
                      ZCL_GOALS_SCHEMA);
        rows = json_get(&reply.data, "goals");
        summary = json_get(&reply.data, "summary");
        ASSERT(rows && rows->type == JSON_ARR && rows->num_children == 29);
        for (size_t i = 0; i < rows->num_children; i++) {
            const char *grade =
                json_get_str(json_get(&rows->children[i], "grade"));
            ASSERT(grade && (!strcmp(grade, "pass") || !strcmp(grade, "partial") ||
                             !strcmp(grade, "fail") ||
                             !strcmp(grade, "unmeasured")));
            ASSERT(json_get_str(json_get(&rows->children[i], "evidence"))[0]);
        }
        zcl_goals_tally(rows, counts);
        for (int g = 0; g < 4; g++) {
            ASSERT(json_get_int(json_get(summary,
                       zcl_goal_grade_name((enum zcl_goal_grade)g))) == counts[g]);
            total += counts[g];
        }
        ASSERT(total == 29);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static bool fgl_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0;
}

/* A .git skeleton git accepts as a repository, one live claim in its common
 * dir and a one-entry allowlist at the top level. */
static bool fgl_make_checkout(const char *top)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/.git", top);
    if (!fgl_mkdir(top) || !fgl_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/.git/objects", top);
    if (!fgl_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/.git/refs", top);
    if (!fgl_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/.git/HEAD", top);
    if (!fgl_write(path, "ref: refs/heads/main\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/.git/z23-agent-claims.jsonl", top);
    if (!fgl_write(path, "{\"lane\":\"a\",\"expires_unix\":1900000000}\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools", top);
    if (!fgl_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/lint", top);
    if (!fgl_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/lint/bash_allowlist.txt", top);
    return fgl_write(path, "# header\ntools/a.sh\n");
}

/* Measures D8 and G13 with the process cwd set to `dir`, then restores it. */
static bool fgl_measure_in(const char *dir,
                           const struct zcl_goals_options *o,
                           struct zcl_goal_result out[2])
{
    char saved[1024];
    bool entered = getcwd(saved, sizeof(saved)) != NULL && chdir(dir) == 0;
    if (!entered)
        return false;
    out[0] = zcl_goals_measure(o, "D8");
    out[1] = zcl_goals_measure(o, "G13");
    return chdir(saved) == 0;
}

static int fgl_case_checkout(const char *root)
{
    int failures = 0;
    char repo[1024], sub_parent[1024], sub[1024], outside[1024];
    struct zcl_goals_options o;
    struct zcl_goal_result inside[2], outer[2], pinned[2];
    bool made, in_ok, out_ok, pin_ok;
    fgl_options(&o);
    (void)snprintf(repo, sizeof(repo), "%s/checkout", root);
    (void)snprintf(sub_parent, sizeof(sub_parent), "%s/checkout/sub", root);
    (void)snprintf(sub, sizeof(sub), "%s/checkout/sub/dir", root);
    (void)snprintf(outside, sizeof(outside), "%s/outside", root);
    TEST("checkout: from a subdirectory the top level is read; outside any "
         "repo the git rows are unmeasured and name the missing checkout") {
        made = fgl_make_checkout(repo) && fgl_mkdir(sub_parent) &&
               fgl_mkdir(sub) && fgl_mkdir(outside);
        ASSERT(made);
        in_ok = fgl_measure_in(sub, &o, inside);
        (void)setenv("GIT_CEILING_DIRECTORIES", root, 1);
        out_ok = fgl_measure_in(outside, &o, outer);
        o.repo = repo;
        pin_ok = fgl_measure_in(outside, &o, pinned);
        o.repo = NULL;
        (void)unsetenv("GIT_CEILING_DIRECTORIES");
        ASSERT(in_ok && out_ok && pin_ok);
        ASSERT(inside[0].grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(inside[0].evidence, "1 shell script(s)"));
        ASSERT(inside[1].grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(inside[1].evidence, "1 live lane claim(s)"));
        ASSERT(outer[0].grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(outer[0].evidence, "no git checkout"));
        ASSERT(outer[1].grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(outer[1].evidence, "no git checkout"));
        ASSERT(pinned[0].grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(pinned[0].evidence, "1 shell script(s)"));
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_goals(void);
int test_fleet_goals(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_goals", "root");
    failures += fgl_case_catalog();
    failures += fgl_case_graders();
    failures += fgl_case_trains(root);
    failures += fgl_case_missing(root);
    failures += fgl_case_stale(root);
    failures += fgl_case_d7_unmeasured(root);
    failures += fgl_case_d7_grade(root);
    failures += fgl_case_files(root);
    failures += fgl_case_claims(root);
    failures += fgl_case_receipt_c3(root);
    failures += fgl_case_receipt_c6(root);
    failures += fgl_case_receipt_none();
    failures += fgl_case_hosts();
    failures += fgl_case_render();
    failures += fgl_case_bound();
    failures += fgl_case_handler(root);
    failures += fgl_case_checkout(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals: all passed\n");
    else
        printf("test_fleet_goals: %d FAILED\n", failures);
    return failures;
}
