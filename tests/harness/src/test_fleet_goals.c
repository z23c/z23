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
#include "base/hex.h"
#include "models/device_pairing.h"
#include "services/device_identity.h"
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
    return fclose(f) == 0 && wrote && chmod(path, 0600) == 0;
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
        static const char *const ids[] = {"G3", "G5", "G6", "G8", "G12"};
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            struct zcl_goal_result r = zcl_goals_measure(&o, ids[i]);
            ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
            ASSERT(fgl_has(r.evidence, "no admitted roster"));
        }
        o.hosts = hosts;
        o.host_count = 2;
        struct zcl_goal_result r = zcl_goals_measure(&o, "G5");
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

#define FGL_WIKI_OWN "aa11"
#define FGL_WIKI_FOREIGN "bb22"

static bool fgl_wiki_data(struct json_value *v, const char *text)
{
    json_init(v);
    return json_read(v, text, strlen(text));
}

static int fgl_case_wiki(void)
{
    int failures = 0;
    struct json_value fresh, own_only, stale, edge;
    struct zcl_goal_result r;
    TEST("wiki: a fresh foreign row is partial without all-host propagation "
         "and pin evidence; own-only rows, a stale "
         "foreign row or an unknown own host stay partial, unmeasured or fail "
         "as the bar says") {
        ASSERT(fgl_wiki_data(&fresh,
            "{\"posts\":[{\"host\":\"" FGL_WIKI_FOREIGN "\",\"created_at\":1799996400},"
            "{\"host\":\"" FGL_WIKI_OWN "\",\"created_at\":1799999990}]}"));
        r = zcl_goals_wiki_grade(true, "", &fresh, FGL_WIKI_OWN, FGL_NOW, 120);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "answered in 120 ms"));
        ASSERT(fgl_has(r.evidence, "1 row(s) from other hosts, newest 3600 s old"));
        ASSERT(fgl_has(r.evidence, "pinned expiry not probed"));
        ASSERT(fgl_has(r.evidence, "all-host propagation"));
        ASSERT(fgl_wiki_data(&edge,
            "{\"posts\":[{\"host\":\"" FGL_WIKI_FOREIGN "\",\"created_at\":1799913600}]}"));
        r = zcl_goals_wiki_grade(true, "", &edge, FGL_WIKI_OWN, FGL_NOW, 120);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_wiki_data(&own_only,
            "{\"posts\":[{\"host\":\"" FGL_WIKI_OWN "\",\"created_at\":1799999940}]}"));
        r = zcl_goals_wiki_grade(true, "", &own_only, FGL_WIKI_OWN, FGL_NOW, 120);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "0 row(s) from other hosts"));
        ASSERT(fgl_has(r.evidence, "no row from another host"));
        ASSERT(fgl_wiki_data(&stale,
            "{\"posts\":[{\"host\":\"" FGL_WIKI_FOREIGN "\",\"created_at\":1799913599}]}"));
        r = zcl_goals_wiki_grade(true, "", &stale, FGL_WIKI_OWN, FGL_NOW, 120);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "newer than the 86400 s freshness bound"));
        r = zcl_goals_wiki_grade(true, "", &fresh, FGL_WIKI_OWN, FGL_NOW, 10001);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "bar 10000 ms"));
        r = zcl_goals_wiki_grade(false, "fleet board offline", &fresh,
                                 FGL_WIKI_OWN, FGL_NOW, 0);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "wiki list did not answer on this node: fleet board offline"));
        r = zcl_goals_wiki_grade(true, "", &fresh, "", FGL_NOW, 120);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "own host id is unreadable"));
        json_free(&fresh);
        json_free(&edge);
        json_free(&own_only);
        json_free(&stale);
        PASS();
    } _test_next:;
    return failures;
}

/* ── G1: tunnel bench receipt ─────────────────────────────────────────── */

#define FGL_PQFS "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256"

static bool fgl_bench(const char *path, double fwd, double rev, int64_t ts,
                      const char *handshake)
{
    char text[600];
    (void)snprintf(text, sizeof(text),
                   "{\"schema\":\"zcl.tunnel_bench.v1\",\"forward_mib_s\":%.1f,"
                   "\"reverse_mib_s\":%.1f,\"timestamp_unix_ms\":%lld%s%s%s}",
                   fwd, rev, (long long)ts * 1000, handshake ? ",\"outer_handshake\":\"" : "",
                   handshake ? handshake : "", handshake ? "\"" : "");
    return fgl_write(path, text);
}

static int fgl_case_g1(const char *root)
{
    int failures = 0;
    char path[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    (void)snprintf(path, sizeof(path), "%s/bench.json", root);
    o.tunnel_bench = path;
    TEST("G1: absent, malformed and future receipts are unmeasured") {
        struct zcl_goal_result r;
        (void)unlink(path);
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, path));
        ASSERT(fgl_write(path, "{\"schema\":\"other\"}"));
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "not a zcl.tunnel_bench.v1 receipt"));
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW + 60, NULL));
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "future"));
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW - 7 * 86400 - 1, NULL));
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "stale"));
        ASSERT(fgl_bench(path, 76, 98, FGL_NOW - 60, NULL));
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "forward 76.0, reverse 98.0"));
        ASSERT(fgl_bench(path, 400, 149.9, FGL_NOW - 60, FGL_PQFS));
        ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW - 60, FGL_PQFS "x"));
        ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_write(path, "{\"schema\":\"zcl.tunnel_bench.v1\",\"forward_mib_s\":\"900\","
                              "\"reverse_mib_s\":900,\"timestamp_unix_ms\":1799999000000}"));
        ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW - 60, FGL_PQFS));
        ASSERT(chmod(path, 0666) == 0);
        ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_UNMEASURED);
        ASSERT(chmod(path, 0600) == 0);
        ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_PASS);
        {
            char link[700];
            (void)snprintf(link, sizeof(link), "%s.link", path);
            (void)unlink(link);
            ASSERT(symlink(path, link) == 0);
            o.tunnel_bench = link;
            ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_UNMEASURED);
            (void)unlink(link);
            ASSERT(mkfifo(link, 0600) == 0);
            ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_UNMEASURED);
            (void)unlink(link);
            o.tunnel_bench = path;
        }
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW - 7 * 86400, NULL));
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "outer tunnel static PSK, no forward "
                                   "secrecy; PQ only inside ssh"));
        ASSERT(fgl_has(r.evidence, "forward 160.0, reverse 185.0"));
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW - 3600, "static_psk"));
        ASSERT(zcl_goals_measure(&o, "G1").grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_bench(path, 160, 185, FGL_NOW - 3600, FGL_PQFS));
        r = zcl_goals_measure(&o, "G1");
        ASSERT(r.grade == ZCL_GOAL_PASS);
        ASSERT(fgl_has(r.evidence, "1 h old"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── G3: shell routes and grants, offline ─────────────────────────────── */

static bool fgl_grant(const char *home, char route[], size_t cap)
{
    struct device_identity id[2] = {0};
    struct device_pairing_store store;
    struct device_identity_publication_report rep;
    struct db_device_pairing row = {0}, found;
    uint8_t secret[32] = {17}, proposal[32], root[32];
    struct device_pairing_psk_publication pub;
    char dir[600], peer[65], expected[65];
    bool ok;
    (void)snprintf(dir, sizeof(dir), "%s/profile-a", home);
    ok = device_identity_open(&id[0], dir, true, &rep).ok;
    (void)snprintf(dir, sizeof(dir), "%s/profile-b", home);
    ok = ok && device_identity_open(&id[1], dir, true, &rep).ok;
    (void)snprintf(dir, sizeof(dir), "%s/profile-a", home);
    ok = ok && device_identity_pair_store(&id[0], id[1].public_key, &store).ok;
    if (ok) {
        bool first = memcmp(id[0].public_key, id[1].public_key, 32) < 0;
        row.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD;
        row.paired_at = FGL_NOW - 100;
        row.expires_at = FGL_NOW + 600;
        memcpy(row.local_key, id[0].public_key, 32);
        memcpy(row.peer_key, id[1].public_key, 32);
        memcpy(row.profile, store.profile, 32);
        row.host_scope.inbound_port = row.host_scope.outbound_port = 4000;
        row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
        row.host_scope.binding.psk.credential_id[0] = 91;
        row.host_scope.binding.psk.key_epoch = 1;
        memcpy(row.host_scope.binding.psk.endpoint_a, first ? row.local_key : row.peer_key, 32);
        memcpy(row.host_scope.binding.psk.endpoint_b, first ? row.peer_key : row.local_key, 32);
        ok = device_pairing_host_proposal_root(&row, proposal) &&
             db_device_pairing_insert_host_psk(&store, &row, secret, proposal, &pub) &&
             db_device_pairing_inspect(&store, row.peer_key, &found, root);
    }
    zcl_hex_encode(id[1].public_key, 32, peer);
    zcl_hex_encode(root, 32, expected);
    device_identity_close(&id[0]);
    device_identity_close(&id[1]);
    return ok && snprintf(route, cap,
        "{\"directory\":\"%s\",\"peer_key\":\"%s\",\"expected_root\":\"%s\","
        "\"target_port\":4000,\"route_id\":\"fleet-shell\",\"handshake_ms\":2000,"
        "\"session_ms\":60000,\"idle_ms\":30000,\"confirm\":true,"
        "\"route_address\":\"127.0.0.1\",\"route_port\":4001,\"connect_ms\":2000}",
        dir, peer, expected) < (int)cap;
}

/* ── D5: tokens per landed change, from the measured objective ───────── */

static int fgl_case_d5(const char *root)
{
    int failures = 0;
    char ledger[600], outcomes[600];
    struct zcl_goals_options o;
    struct zcl_goal_result r;
    fgl_options(&o);
    (void)snprintf(ledger, sizeof(ledger), "%s/d5_rows.tsv", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/d5_outcomes.jsonl", root);
    o.experiments = ledger;
    o.outcomes = outcomes;
    TEST("D5: no experiment ledger is unmeasured and names the file") {
        (void)unlink(ledger);
        ASSERT(fgl_write(outcomes,
                         "{\"seq\":1,\"ts\":\"2027-01-13T10:00:00Z\","
                         "\"state\":\"landed\"}\n"));
        r = zcl_goals_measure(&o, "D5");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "missing experiment ledger"));
        PASS();
    }
    TEST("D5: a measured tokens_per_landed_commit grades PARTIAL with its "
         "value, not PASS") {
        ASSERT(fgl_write(ledger,
                         "ts\tkind\n"
                         "2027-01-14T10:00:00Z\tresult\tnode1\tid\tverify\t"
                         "unknown\tclaude-opus\tagent-tool\tm\tmedium\t1000\t"
                         "200\t0\t0\t0\t0\t0\tunknown\t0\t0\t0\tfixture\n"));
        r = zcl_goals_measure(&o, "D5");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "1200 tokens per landed commit"));
        PASS();
    }
_test_next:;
    return failures;
}

static int fgl_case_g3(const char *root)
{
    int failures = 0;
    char routes[600], file[700], home[600], route[2400];
    struct zcl_goals_options o;
    struct zcl_goals_host hosts[2] = {{.name = "alpha"}, {.name = "beta"}};
    fgl_options(&o);
    o.hosts = hosts;
    o.host_count = 2;
    (void)snprintf(home, sizeof(home), "%s/g3", root);
    (void)snprintf(routes, sizeof(routes), "%s/routes", home);
    (void)mkdir(home, 0700);
    (void)mkdir(routes, 0700);
    o.shell_routes = routes;
    TEST("G3: no route files fails and names the refusal; a malformed route "
         "fails") {
        struct zcl_goal_result r = zcl_goals_measure(&o, "G3");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "0 of 2"));
        ASSERT(fgl_has(r.evidence, "alpha:route_input_refused"));
        (void)snprintf(file, sizeof(file), "%s/alpha.json", routes);
        ASSERT(fgl_write(file, "{}") && chmod(file, 0600) == 0);
        r = zcl_goals_measure(&o, "G3");
        ASSERT(fgl_has(r.evidence, "alpha:route_input_not_a_client_input"));
        ASSERT(fgl_grant(home, route, sizeof(route)));
        (void)snprintf(file, sizeof(file), "%s/alpha.json", routes);
        ASSERT(fgl_write(file, route) && chmod(file, 0600) == 0);
        r = zcl_goals_measure(&o, "G3");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "1 of 2"));
        ASSERT(fgl_has(r.evidence, "beta:route_input_refused"));
        (void)snprintf(file, sizeof(file), "%s/beta.json", routes);
        ASSERT(fgl_write(file, route) && chmod(file, 0600) == 0);
        r = zcl_goals_measure(&o, "G3");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "2 of 2"));
        ASSERT(fgl_has(r.evidence, "no round trip"));
        o.now_unix = FGL_NOW + 600;
        r = zcl_goals_measure(&o, "G3");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "alpha:grant_expired"));
        {
            char bad[2400];
            char *at = strstr(route, "\"expected_root\":\"");
            ASSERT(at);
            (void)snprintf(bad, sizeof(bad), "%s", route);
            memset(bad + (at - route) + 17, '0', 64);
            (void)snprintf(file, sizeof(file), "%s/alpha.json", routes);
            ASSERT(fgl_write(file, bad) && chmod(file, 0600) == 0);
            r = zcl_goals_measure(&o, "G3");
            ASSERT(r.grade == ZCL_GOAL_FAIL);
            ASSERT(fgl_has(r.evidence, "alpha:grant_root_mismatch"));
            ASSERT(fgl_write(file, route) && chmod(file, 0600) == 0);
        }
        o.now_unix = FGL_NOW - 101;
        r = zcl_goals_measure(&o, "G3");
        ASSERT(fgl_has(r.evidence, "alpha:grant_not_yet_valid"));
        struct zcl_goals_host evil[1] = {{.name = "../escape"}};
        o.now_unix = FGL_NOW;
        o.hosts = evil;
        o.host_count = 1;
        r = zcl_goals_measure(&o, "G3");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgl_has(r.evidence, "route_name_refused"));
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
    failures += fgl_case_g1(root);
    failures += fgl_case_g3(root);
    failures += fgl_case_d5(root);
    failures += fgl_case_render();
    failures += fgl_case_bound();
    failures += fgl_case_wiki();
    failures += fgl_case_handler(root);
    failures += fgl_case_checkout(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals: all passed\n");
    else
        printf("test_fleet_goals: %d FAILED\n", failures);
    return failures;
}
