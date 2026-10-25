/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet goal C8 (tools/command/native_parity_judge.c and
 * rc_c8 in native_fleet_goals_receipts.c): the row is graded from parity.jsonl
 * in the soak evidence dir. A clean 168 h ledger passes, one hash mismatch
 * fails naming the height, and every observation shortfall is unmeasured.
 */

#include "test/test_core.h"

#include "command/native_fleet_goals.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FGP_NOW INT64_C(1800000000)
#define FGP_H 3600

/* One ledger row per hour from `base`; hour `bad` (or -1) mismatches and
 * hours skip_from..skip_to (or -1) are absent. */
static bool fgp_ledger(const char *path, int64_t base, int count, int bad,
                       int skip_from, int skip_to)
{
    FILE *f = fopen(path, "wb");
    bool ok = f != NULL;
    for (int i = 0; ok && i < count; i++) {
        bool mism = i == bad;
        if (i >= skip_from && i <= skip_to)
            continue;
        ok = fprintf(f,
                     "{\"ts\":%lld,\"height\":%d,\"our_hash\":\"%064d\","
                     "\"oracle_hash\":\"%064d\",\"match\":%s,"
                     "\"source\":\"rpc-getblockhash\",\"ok\":true}\n",
                     (long long)(base + (int64_t)i * FGP_H), 3000000 + i, 1,
                     mism ? 2 : 1, mism ? "false" : "true") > 0;
    }
    return f && fclose(f) == 0 && ok;
}

static void fgp_options(struct zcl_goals_options *o, const char *dir)
{
    memset(o, 0, sizeof(*o));
    o->now_unix = FGP_NOW;
    o->skip_probes = true;
    o->hosts_given = true;
    o->repo = ".";
    o->soak_dir = dir;
}

static bool fgp_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static int fgp_case_none(const char *dir)
{
    int failures = 0;
    struct zcl_goals_options o;
    fgp_options(&o, dir);
    TEST("C8: no parity ledger is unmeasured and names the producer") {
        struct zcl_goal_result r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgp_has(r.evidence, "needs 168 h of observation, have 0 h"));
        ASSERT(fgp_has(r.next, "z23 fleet parity sample"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgp_case_pass_fail(const char *dir, const char *file)
{
    int failures = 0;
    struct zcl_goals_options o;
    const int64_t base = FGP_NOW - INT64_C(168) * FGP_H - 60;
    fgp_options(&o, dir);
    TEST("C8: 168 h all matching passes; one mismatch fails with its height "
         "and both hashes") {
        struct zcl_goal_result r;
        ASSERT(fgp_ledger(file, base, 169, -1, -1, -1));
        r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_PASS);
        ASSERT(fgp_has(r.evidence, "MET over 168.0 h"));
        ASSERT(fgp_ledger(file, base, 169, 60, -1, -1));
        r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgp_has(r.evidence, "height_3000060"));
        ASSERT(fgp_has(r.evidence, "0000000000000000000000000000000000000000"
                                   "000000000000000001"));
        ASSERT(fgp_has(r.evidence, "0000000000000000000000000000000000000000"
                                   "000000000000000002"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgp_case_unmeasured(const char *dir, const char *file)
{
    int failures = 0;
    struct zcl_goals_options o;
    const int64_t base = FGP_NOW - INT64_C(168) * FGP_H - 60;
    fgp_options(&o, dir);
    TEST("C8: a 3 h gap, a stale tail and a short clean window are all "
         "unmeasured") {
        struct zcl_goal_result r;
        ASSERT(fgp_ledger(file, base, 169, -1, 50, 52));
        r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgp_has(r.evidence, "sampling_hole"));
        ASSERT(fgp_ledger(file, base - 3 * 86400, 169, -1, -1, -1));
        r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgp_has(r.evidence, "stale"));
        ASSERT(fgp_ledger(file, FGP_NOW - 100 * FGP_H, 101, -1, -1, -1));
        r = zcl_goals_measure(&o, "C8");
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgp_has(r.evidence, "needs 168 h of observation, have 100.0 h"));
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_goals_parity(void);
int test_fleet_goals_parity(void)
{
    int failures = 0;
    char root[512], dir[600], file[700];
    test_make_tmpdir(root, sizeof(root), "fleet_goals_parity", "root");
    (void)snprintf(dir, sizeof(dir), "%s/soak", root);
    (void)snprintf(file, sizeof(file), "%s/parity.jsonl", dir);
    (void)mkdir(dir, 0700);
    failures += fgp_case_none(dir);
    failures += fgp_case_pass_fail(dir, file);
    failures += fgp_case_unmeasured(dir, file);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals_parity: all passed\n");
    else
        printf("test_fleet_goals_parity: %d FAILED\n", failures);
    return failures;
}
