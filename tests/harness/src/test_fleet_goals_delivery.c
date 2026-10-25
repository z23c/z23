/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the D1/D2/D4 delivery readers
 * (tools/command/native_fleet_goals_delivery.c).
 *
 * Every input is a fixture: a temp rows.tsv, a temp outcomes.jsonl and a
 * temp agent meta tree named by $Z23_AGENT_META_ROOT. The bar pins each
 * grade the reader can give: unmeasured, fail, and partial, never pass.
 */

#include "test/test_core.h"

#include "command/native_fleet_goals_delivery.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define FGD_NOW INT64_C(1792886400) /* 2026-10-25T00:00:00Z */
#define FGD_AFTER "2026-10-24T00:00:00Z"
#define FGD_BEFORE "2026-10-23T18:04:59Z"

static char fgd_dir[512];
static int fgd_seq;

static bool fgd_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static FILE *fgd_open(const char *name, const char *header)
{
    char path[640];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/%s", fgd_dir, name);
    f = fopen(path, "wb");
    if (f && header)
        (void)fputs(header, f);
    return f;
}

static void fgd_row(FILE *f, const char *ts, const char *box, const char *task,
                    int tin, int tout, int turns)
{
    (void)fprintf(f,
                  "%s\tresult\t%s\t%s\tc\ts\te\th\tm\tx\t%d\t%d\t0\t0\t0\t%d\t0"
                  "\tunknown\t0\t0\t0\tn\n",
                  ts, box, task, tin, tout, turns);
}

static void fgd_iso(int64_t t, char *buf, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tm;
    (void)gmtime_r(&tt, &tm);
    (void)strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* A fresh, empty agent meta tree for this scenario. */
static void fgd_meta_begin(void)
{
    char dir[640];
    (void)snprintf(dir, sizeof(dir), "%s/meta%d", fgd_dir, ++fgd_seq);
    (void)mkdir(dir, 0700);
    (void)setenv("Z23_AGENT_META_ROOT", dir, 1);
}

static void fgd_meta(const char *id, const char *label)
{
    char path[700];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/meta%d/agent-%s.meta.json", fgd_dir,
                   fgd_seq, id);
    f = fopen(path, "wb");
    if (!f)
        return;
    (void)fprintf(f, "{\"description\":\"%s\"}", label);
    (void)fclose(f);
}

static void fgd_land(FILE *f, const char *lane)
{
    (void)fprintf(f,
                  "{\"state\":\"landed\",\"ts\":\"" FGD_AFTER
                  "\",\"note\":\"%s: reviewed\"}\n",
                  lane);
}

static void fgd_in(struct zcl_goals_delivery_in *in)
{
    static char rows[640], out[640];
    (void)snprintf(rows, sizeof(rows), "%s/rows.tsv", fgd_dir);
    (void)snprintf(out, sizeof(out), "%s/outcomes.jsonl", fgd_dir);
    memset(in, 0, sizeof(*in));
    in->rows_tsv = rows;
    in->outcomes = out;
    in->now = FGD_NOW;
    in->admitted_hosts = 2;
}

#define FGD_HEADER "ts\tkind\tbox\ttask_id\n"

static int fgd_t1(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D1: no ledger and no in-window result rows are unmeasured") {
        r = zcl_goals_delivery_d1(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        f = fgd_open("rows.tsv", FGD_HEADER);
        ASSERT(f != NULL);
        fgd_row(f, FGD_BEFORE, "node1", "old", 0, 0, 0);
        ASSERT(fclose(f) == 0);
        r = zcl_goals_delivery_d1(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t2(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D1: every complete row is partial, never pass; pre-epoch rows and "
         "malformed lines are not counted") {
        f = fgd_open("rows.tsv", FGD_HEADER);
        ASSERT(f != NULL);
        fgd_row(f, FGD_AFTER, "node1", "a", 10, 5, 3);
        fgd_row(f, FGD_AFTER, "node2", "b", 10, 5, 3);
        fgd_row(f, FGD_BEFORE, "node1", "zero_turn_before_epoch", 10, 5, 0);
        (void)fputs("garbage line\n", f);
        (void)fputs("2026-10-24T00:00:00Z\tresult\tnode1\tbad\tc\ts\te\th\tm\tx\t"
                    "x\t1\t0\t0\t0\t1\t0\tu\t0\t0\t0\tn\n",
                    f);
        ASSERT(fclose(f) == 0);
        r = zcl_goals_delivery_d1(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgd_has(r.evidence, "all 2 result rows"));
        ASSERT(fgd_has(r.evidence, "2 box labels"));
        ASSERT(fgd_has(r.evidence, "roster 2"));
        ASSERT(fgd_has(r.evidence, "2 malformed skipped"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t3(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D1: one zero-turn row fails and names its box and task") {
        f = fgd_open("rows.tsv", FGD_HEADER);
        ASSERT(f != NULL);
        fgd_row(f, FGD_AFTER, "node1", "a", 10, 5, 3);
        fgd_row(f, FGD_AFTER, "node2", "zt", 10, 5, 0);
        ASSERT(fclose(f) == 0);
        r = zcl_goals_delivery_d1(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgd_has(r.evidence, "node2 1 of 1 incomplete"));
        ASSERT(fgd_has(r.evidence, "zt"));
        ASSERT(!fgd_has(r.evidence, "node1 "));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t4(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D1: zero tokens fail; rows older than 7 d fall out of the window") {
        f = fgd_open("rows.tsv", FGD_HEADER);
        ASSERT(f != NULL);
        fgd_row(f, FGD_AFTER, "node1", "no_out", 10, 0, 3);
        ASSERT(fclose(f) == 0);
        r = zcl_goals_delivery_d1(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        in.now = FGD_NOW + 10 * 86400;
        r = zcl_goals_delivery_d1(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        PASS();
    } _test_next:;
    return failures;
}


/* Lanes L0..L<n-1>, each landed, each with one write agent w<i> whose result
 * row has turns[i]. */
static void fgd_d2_fixture(const int *turns, size_t n, bool join)
{
    FILE *rows = fgd_open("rows.tsv", FGD_HEADER);
    FILE *out = fgd_open("outcomes.jsonl", NULL);
    char id[32], label[48];
    fgd_meta_begin();
    for (size_t i = 0; rows && out && i < n; i++) {
        (void)snprintf(id, sizeof(id), "w%zu", i);
        (void)snprintf(label, sizeof(label), "write:%s%zu", join ? "L" : "M", i);
        fgd_meta(id, label);
        fgd_row(rows, FGD_AFTER, "node1", id, 10, 5, turns[i]);
        (void)snprintf(label, sizeof(label), "L%zu", i);
        fgd_land(out, label);
    }
    if (rows)
        (void)fclose(rows);
    if (out)
        (void)fclose(out);
}

static int fgd_t5(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D2: median 12 is partial; a pre-epoch row adds nothing") {
        fgd_d2_fixture(low, 3, true);
        f = fopen(in.rows_tsv, "ab");
        ASSERT(f != NULL);
        fgd_row(f, FGD_BEFORE, "node1", "w1", 10, 5, 500);
        ASSERT(fclose(f) == 0);
        r = zcl_goals_delivery_d2(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgd_has(r.evidence, "median 12 requests"));
        ASSERT(fgd_has(r.evidence, "3 of 3 landed"));
        ASSERT(fgd_has(r.evidence, "this host only"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t6(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D2: median 40 fails") {
        fgd_d2_fixture(high, 3, true);
        r = zcl_goals_delivery_d2(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgd_has(r.evidence, "median 40 requests"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t7(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D2: no landed lane joins an agent is unmeasured") {
        fgd_d2_fixture(low, 3, false);
        r = zcl_goals_delivery_d2(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgd_has(r.evidence, "none joins"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t8(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D2: a missing outcomes file is unmeasured") {
        char path[640];
        (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", fgd_dir);
        (void)remove(path);
        r = zcl_goals_delivery_d2(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgd_has(r.evidence, "outcomes"));
        PASS();
    } _test_next:;
    return failures;
}


/* `lanes` deliveries, lane i newest-ordered by i. Lanes at or above
 * lanes - first are first-time: one plain review: label (or a lone review2:
 * when `r2`) and no fix. The others alternate between a write with no review
 * label at all and a review1 + review2 + fix round. */
static void fgd_d4_fixture(size_t lanes, size_t first, bool r2)
{
    FILE *rows = fgd_open("rows.tsv", FGD_HEADER);
    char id[48], label[64], ts[32];
    fgd_meta_begin();
    for (size_t i = 0; rows && i < lanes; i++) {
        bool ok = i >= lanes - first;
        fgd_iso(INT64_C(1792800000) + (int64_t)i * 60, ts, sizeof(ts));
        (void)snprintf(id, sizeof(id), "w%zu", i);
        (void)snprintf(label, sizeof(label), "%s:D%zu", i % 3 ? "write" : "cx", i);
        fgd_meta(id, label);
        fgd_row(rows, ts, "node1", id, 10, 5, 3);
        if (ok) {
            (void)snprintf(id, sizeof(id), "a%zu", i);
            (void)snprintf(label, sizeof(label), "%s:D%zu",
                           r2 ? "review2" : "review", i);
            fgd_meta(id, label);
        } else if (i % 2) {
            (void)snprintf(id, sizeof(id), "a%zu", i);
            (void)snprintf(label, sizeof(label), "review1:D%zu", i);
            fgd_meta(id, label);
            (void)snprintf(id, sizeof(id), "b%zu", i);
            (void)snprintf(label, sizeof(label), "review2:D%zu", i);
            fgd_meta(id, label);
            (void)snprintf(id, sizeof(id), "f%zu", i);
            (void)snprintf(label, sizeof(label), "fix:D%zu", i);
            fgd_meta(id, label);
        }
    }
    if (rows)
        (void)fclose(rows);
}

static int fgd_t9(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D4: 99 deliveries are unmeasured and say how many") {
        fgd_d4_fixture(99, 99, false);
        r = zcl_goals_delivery_d4(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgd_has(r.evidence, "99 deliveries"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t10(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D4: 100 deliveries with 59 first-time fail") {
        fgd_d4_fixture(100, 59, false);
        r = zcl_goals_delivery_d4(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgd_has(r.evidence, "59 of the newest 100"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t11(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D4: 100 with 60 first-time is a partial proxy, never pass") {
        fgd_d4_fixture(100, 60, false);
        r = zcl_goals_delivery_d4(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgd_has(r.evidence, "60 of the newest 100"));
        ASSERT(fgd_has(r.evidence, "proxy"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t12(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D4: only the newest 100 count; an older rejected lane is cut") {
        fgd_d4_fixture(101, 60, false);
        r = zcl_goals_delivery_d4(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgd_has(r.evidence, "60 of the newest 100"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t14(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D4: a lone review2 without a fix still counts as first-time") {
        fgd_d4_fixture(100, 100, true);
        r = zcl_goals_delivery_d4(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgd_has(r.evidence, "100 of the newest 100"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgd_t13(void)
{
    int failures = 0;
    struct zcl_goals_delivery_in in;
    struct zcl_goal_result r;
    FILE *f;
    const int low[] = {10, 12, 14};
    const int high[] = {40, 40, 40};
    (void)f;
    (void)r;
    (void)low;
    (void)high;
    fgd_in(&in);
    TEST("D4: a missing ledger is unmeasured") {
        char path[640];
        (void)snprintf(path, sizeof(path), "%s/rows.tsv", fgd_dir);
        (void)remove(path);
        r = zcl_goals_delivery_d4(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        PASS();
    } _test_next:;
    return failures;
}


int test_fleet_goals_delivery(void);
int test_fleet_goals_delivery(void)
{
    int failures = 0;
    test_make_tmpdir(fgd_dir, sizeof(fgd_dir), "fleet_goals_delivery", "root");
    int (*const tests[])(void) = {fgd_t1, fgd_t2, fgd_t3, fgd_t4, fgd_t5, fgd_t6, fgd_t7, fgd_t8, fgd_t9, fgd_t10, fgd_t11, fgd_t12, fgd_t13, fgd_t14};
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
        failures += tests[i]();
    (void)unsetenv("Z23_AGENT_META_ROOT");
    (void)test_rm_rf_recursive(fgd_dir);
    if (failures == 0)
        printf("test_fleet_goals_delivery: all passed\n");
    else
        printf("test_fleet_goals_delivery: %d FAILED\n", failures);
    return failures;
}
