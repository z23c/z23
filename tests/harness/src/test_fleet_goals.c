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
            ASSERT(strcmp(zcl_goal_grade_name(r.grade), "unmeasured") != 0 ||
                   r.evidence[0]);
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
        ASSERT(zcl_goals_grade_scripts(0) == ZCL_GOAL_PASS);
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

static int fgl_case_files(const char *root)
{
    int failures = 0;
    char none[600], some[600], absent[600];
    struct zcl_goals_options o;
    fgl_options(&o);
    (void)snprintf(none, sizeof(none), "%s/none.txt", root);
    (void)snprintf(some, sizeof(some), "%s/some.txt", root);
    (void)snprintf(absent, sizeof(absent), "%s/absent.txt", root);
    TEST("D8: an empty allowlist passes, entries are counted, a missing file "
         "is unmeasured") {
        struct zcl_goal_result r;
        ASSERT(fgl_write(none, "# header\n\n# only comments\n"));
        ASSERT(fgl_write(some, "# header\ntools/a.sh\n\ntools/b.sh\n"));
        o.bash_allowlist = none;
        r = zcl_goals_measure(&o, "D8");
        ASSERT(r.grade == ZCL_GOAL_PASS);
        o.bash_allowlist = some;
        r = zcl_goals_measure(&o, "D8");
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgl_has(r.evidence, "2 bash script(s)"));
        o.bash_allowlist = absent;
        r = zcl_goals_measure(&o, "D8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgl_has(r.evidence, "no bash allowlist"));
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
    failures += fgl_case_files(root);
    failures += fgl_case_claims(root);
    failures += fgl_case_hosts();
    failures += fgl_case_render();
    failures += fgl_case_bound();
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals: all passed\n");
    else
        printf("test_fleet_goals: %d FAILED\n", failures);
    return failures;
}
