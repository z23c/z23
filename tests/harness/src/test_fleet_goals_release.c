/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the G6 release row
 * (tools/command/native_fleet_goals_release.c). Every case writes a
 * conveyor ledger in an isolated directory and grades it through
 * zcl_goals_release_measure. Nothing is started and no host is probed.
 */

#include "test/test_core.h"

#include "command/native_dev_cx.h"
#include "command/native_fleet_goals_release.h"

#include <stdio.h>
#include <string.h>

static bool fgr_write(const char *path, const char *text)
{
    return cx_write_file(path, text, strlen(text));
}

static void fgr_join(char *out, size_t cap, const char *root, const char *name)
{
    (void)snprintf(out, cap, "%s/%s", root, name);
}

static struct zcl_goal_result fgr_grade(const char *dir, int64_t now,
                                        int64_t behind_max)
{
    struct zcl_goals_release_in in;
    memset(&in, 0, sizeof(in));
    in.state_dir = dir;
    in.admitted_hosts = 3;
    in.now_unix = now;
    in.behind_max = behind_max;
    return zcl_goals_release_measure(&in);
}

static bool fgr_has(const char *evidence, const char *needle)
{
    return evidence && needle && strstr(evidence, needle) != NULL;
}

static int fgr_case_unmeasured(const char *root)
{
    int failures = 0;
    TEST("G6: no ledger and a skipped probe stay unmeasured") {
        struct zcl_goal_result r = zcl_goals_release_measure(NULL);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgr_has(r.evidence, "probe skipped"));
        r = fgr_grade(root, 1790000000, 0);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgr_has(r.evidence, "no release conveyor ledger"));
        ASSERT(fgr_has(r.evidence, "tick.log"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgr_case_failed(const char *root)
{
    int failures = 0;
    char path[600], attempt[600];
    TEST("G6: a failed attempt names its rc and last step") {
        fgr_join(path, sizeof(path), root, "tick.log");
        ASSERT(fgr_write(path,
                         "2026-11-22T00:00:00Z START aaaaaaaa landing_seq=10\n"
                         "2026-11-22T01:00:00Z RELEASED aaaaaaaa\n"
                         "2026-11-22T02:00:00Z START bbbbbbbb landing_seq=11\n"
                         "2026-11-22T03:00:00Z FAILED bbbbbbbb rc=128\n"));
        fgr_join(attempt, sizeof(attempt), root, "release-bbbbbbbb.log");
        ASSERT(fgr_write(attempt,
                         "2026-11-22T02:00:01Z build the release\n"
                         "2026-11-22T03:00:00Z release-run exited 128\n"));
        struct zcl_goal_result r = fgr_grade(root, 1790000000, 0);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgr_has(r.evidence, "rc=128"));
        ASSERT(fgr_has(r.evidence, "release-run exited 128"));
        ASSERT(fgr_has(r.evidence, "bbbbbbbb"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgr_case_behind(const char *root)
{
    int failures = 0;
    char path[600];
    TEST("G6: a conveyor more than the bar behind fails") {
        fgr_join(path, sizeof(path), root, "tick.log");
        ASSERT(fgr_write(path,
                         "2026-11-22T00:00:00Z START aaaaaaaa landing_seq=10\n"
                         "2026-11-22T01:00:00Z RELEASED aaaaaaaa\n"
                         "2026-11-22T02:00:00Z START cccccccc landing_seq=40\n"));
        struct zcl_goal_result r = fgr_grade(root, 1790000000, 12);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgr_has(r.evidence, "landings behind"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgr_case_not_updated(const char *root)
{
    int failures = 0;
    char path[600], attempt[600];
    TEST("G6: a host the release did not update fails") {
        fgr_join(path, sizeof(path), root, "tick.log");
        ASSERT(fgr_write(path,
                         "2026-11-22T00:00:00Z START aaaaaaaa landing_seq=10\n"
                         "2026-11-22T01:00:00Z RELEASED aaaaaaaa\n"));
        fgr_join(attempt, sizeof(attempt), root, "release-aaaaaaaa.log");
        ASSERT(fgr_write(attempt,
                         "2026-11-22T01:00:01Z r2-devfleet CLI NOT updated\n"));
        struct zcl_goal_result r = fgr_grade(root, 1790000000, 12);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgr_has(r.evidence, "did not reach every host"));
        ASSERT(fgr_has(r.evidence, "NOT updated"));
        PASS();
    } _test_next:;
    return failures;
}

static int fgr_case_current(const char *root)
{
    int failures = 0;
    char path[600], attempt[600];
    TEST("G6: a current conveyor is partial and does not probe hosts") {
        fgr_join(path, sizeof(path), root, "tick.log");
        ASSERT(fgr_write(path,
                         "2026-11-22T00:00:00Z START aaaaaaaa landing_seq=10\n"
                         "2026-11-22T01:00:00Z RELEASED aaaaaaaa\n"
                         "2026-11-22T02:00:00Z START cccccccc landing_seq=12\n"
                         "2026-11-22T02:00:01Z CURRENT cccccccc\n"));
        fgr_join(attempt, sizeof(attempt), root, "release-aaaaaaaa.log");
        ASSERT(fgr_write(attempt, "2026-11-22T01:00:01Z swapped the CLI\n"));
        struct zcl_goal_result r = fgr_grade(root, 1790000000, 12);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(fgr_has(r.evidence, "not probed"));
        ASSERT(r.grade != ZCL_GOAL_PASS);
        PASS();
    } _test_next:;
    return failures;
}

static int fgr_case_stopped(const char *root)
{
    int failures = 0;
    char path[600];
    TEST("G6: a stopped conveyor fails and a ledger with no release stays unmeasured") {
        fgr_join(path, sizeof(path), root, "tick.log");
        ASSERT(fgr_write(path, "2026-11-22T04:00:00Z STOPPED\n"));
        struct zcl_goal_result r = fgr_grade(root, 1790000000, 12);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(fgr_has(r.evidence, "not running"));
        ASSERT(fgr_write(path, "2026-11-22T04:00:00Z START dddddddd landing_seq=3\n"));
        r = fgr_grade(root, 1790000000, 12);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(fgr_has(r.evidence, "no RELEASED"));
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_goals_release(void)
{
    int failures = 0;
    char root[512];

    test_make_tmpdir(root, sizeof(root), "fleet_goals_release", "root");
    failures += fgr_case_unmeasured(root);
    failures += fgr_case_failed(root);
    failures += fgr_case_behind(root);
    failures += fgr_case_not_updated(root);
    failures += fgr_case_current(root);
    failures += fgr_case_stopped(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals_release: all passed\n");
    else
        printf("test_fleet_goals_release: %d FAILED\n", failures);
    return failures;
}
