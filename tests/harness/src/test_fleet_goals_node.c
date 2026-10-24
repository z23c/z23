/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the G10 node row of fleet.goals
 * (tools/command/native_fleet_goals_node.c).
 *
 * Every case reads a status-brief fixture written here, or skips the node
 * entirely. The live node is never asked: its answer depends on the machine.
 */

#include "test/test_core.h"

#include "command/native_fleet_goals.h"
#include "command/native_fleet_goals_node.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define GNT_PATH_MAX 512
#define GNT_BUDGET_MS 1500

static bool gnt_write(const char *path, const char *text)
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

static void gnt_join(char *out, size_t cap, const char *root, const char *name)
{
    (void)snprintf(out, cap, "%s/%s", root, name);
}

static struct zcl_goals_node_in gnt_in(const char *brief)
{
    struct zcl_goals_node_in in;
    memset(&in, 0, sizeof(in));
    in.brief_path = brief;
    in.node_budget_ms = GNT_BUDGET_MS;
    return in;
}

static bool gnt_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

/* A served tip within the 2-block target grades partial, never pass; the
 * evidence says this node only and names what was not probed. */
static int gnt_case_partial(const char *root)
{
    int failures = 0;
    char lag0[GNT_PATH_MAX], lag2[GNT_PATH_MAX];
    gnt_join(lag0, sizeof(lag0), root, "node-lag0.json");
    gnt_join(lag2, sizeof(lag2), root, "node-lag2.json");
    TEST("G10: a served tip at the 2-block target grades partial, never pass") {
        struct zcl_goals_node_in in;
        struct zcl_goal_result r;
        ASSERT(gnt_write(lag0,
            "{\"hstar\":100,\"header_height\":100,\"peer_best\":100,"
            "\"rss_mb\":512}\n"));
        in = gnt_in(lag0);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(gnt_has(r.evidence, "this node only"));
        ASSERT(gnt_has(r.evidence, "not probed"));
        ASSERT(gnt_has(r.evidence, "rss 512 MB"));
        ASSERT(r.next[0]);
        ASSERT(gnt_write(lag2,
            "{\"hstar\":100,\"header_height\":102,\"peer_best\":101}\n"));
        in = gnt_in(lag2);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_PARTIAL);
        ASSERT(gnt_has(r.evidence, "2 blocks"));
        PASS();
    } _test_next:;
    return failures;
}

/* A served tip more than 2 blocks behind grades fail with the number. */
static int gnt_case_fail(const char *root)
{
    int failures = 0;
    char lag3[GNT_PATH_MAX], lag5[GNT_PATH_MAX], gap5[GNT_PATH_MAX];
    gnt_join(lag3, sizeof(lag3), root, "node-lag3.json");
    gnt_join(lag5, sizeof(lag5), root, "node-lag5.json");
    gnt_join(gap5, sizeof(gap5), root, "node-gap5.json");
    TEST("G10: a served tip more than 2 blocks behind grades fail with the lag") {
        struct zcl_goals_node_in in;
        struct zcl_goal_result r;
        ASSERT(gnt_write(lag3,
            "{\"hstar\":100,\"header_height\":100,\"peer_best\":103}\n"));
        in = gnt_in(lag3);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(gnt_has(r.evidence, "3 blocks"));
        ASSERT(gnt_write(lag5,
            "{\"hstar\":100,\"header_height\":100,\"peer_best\":105}\n"));
        in = gnt_in(lag5);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(gnt_has(r.evidence, "5 blocks"));
        ASSERT(r.next[0]);
        /* The node's own gap stands when it names no served height. */
        ASSERT(gnt_write(gap5, "{\"gap\":5}\n"));
        in = gnt_in(gap5);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_FAIL);
        ASSERT(gnt_has(r.evidence, "5 blocks"));
        PASS();
    } _test_next:;
    return failures;
}

/* Anything the node cannot answer is unmeasured with its reason, never a
 * guessed grade: a missing file, no served tip, a malformed brief, a skip. */
static int gnt_case_unmeasured(const char *root)
{
    int failures = 0;
    char missing[GNT_PATH_MAX], notip[GNT_PATH_MAX], bad[GNT_PATH_MAX];
    gnt_join(missing, sizeof(missing), root, "node-missing.json");
    gnt_join(notip, sizeof(notip), root, "node-notip.json");
    gnt_join(bad, sizeof(bad), root, "node-bad.json");
    TEST("G10: a missing, tip-less or malformed brief is unmeasured with its reason") {
        struct zcl_goals_node_in in;
        struct zcl_goal_result r;
        in = gnt_in(missing);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(gnt_has(r.evidence, "node-missing.json"));
        ASSERT(r.next[0]);
        ASSERT(gnt_write(notip, "{\"rss_mb\":512}\n"));
        in = gnt_in(notip);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(gnt_has(r.evidence, "served tip"));
        ASSERT(gnt_write(bad, "not a status brief\n"));
        in = gnt_in(bad);
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(gnt_has(r.evidence, "not a JSON object"));
        PASS();
    } _test_next:;
    return failures;
}

/* A skipped run never reads the brief, though it holds a lag-5 tip. */
static int gnt_case_skip(const char *root)
{
    int failures = 0;
    char lag5[GNT_PATH_MAX];
    gnt_join(lag5, sizeof(lag5), root, "node-skip-lag5.json");
    TEST("G10: skip and a null input never ask the node or read the brief") {
        struct zcl_goals_node_in in;
        struct zcl_goal_result r;
        ASSERT(gnt_write(lag5,
            "{\"hstar\":100,\"header_height\":100,\"peer_best\":105}\n"));
        in = gnt_in(lag5);
        in.skip = true;
        r = zcl_goals_node_measure(&in);
        ASSERT(r.grade == ZCL_GOAL_UNMEASURED);
        ASSERT(gnt_has(r.evidence, "skipped"));
        ASSERT(zcl_goals_node_measure(NULL).grade == ZCL_GOAL_UNMEASURED);
        ASSERT_STR_EQ(zcl_goal_grade_name(r.grade), "unmeasured");
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_goals_node(void)
{
    int failures = 0;
    char root[GNT_PATH_MAX];
    test_make_tmpdir(root, sizeof(root), "fleet_goals_node", "root");
    failures += gnt_case_partial(root);
    failures += gnt_case_fail(root);
    failures += gnt_case_unmeasured(root);
    failures += gnt_case_skip(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_goals_node: all passed\n");
    else
        printf("test_fleet_goals_node: %d FAILED\n", failures);
    return failures;
}
