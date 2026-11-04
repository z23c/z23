/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the dev.land driver self-upgrade module
 * (tools/command/native_dev_land_selfupgrade.c). Two fake driver binaries
 * (shell scripts) answer the same read-only decision args: first they agree
 * and the slot pointer switches, then they disagree and it does not. */

#include "test/test_core.h"

#include "command/native_dev_land_selfupgrade.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define SHA_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SHA_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define PLAN_X "rebase=ff train=2,3 route=push"
#define PLAN_Y "rebase=ff train=2 route=push"

static const char *const g_args[] = {"decide", "--seq=7", NULL};

/* An executable that prints a fixed decision whatever its args. */
static bool sul_script(const char *path, const char *decision)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    if (decision[0])
        fprintf(f, "#!/bin/sh\necho '%s'\n", decision);
    else
        fprintf(f, "#!/bin/sh\nexit 0\n");
    return fclose(f) == 0 && chmod(path, 0755) == 0;
}

struct sul_rig {
    char root[512];
    char cur[640];
    char src_x[640];
    char src_y[640];
};

static bool sul_rig_open(struct sul_rig *r)
{
    if (!test_mkdtemp(r->root, sizeof(r->root), "selfupgrade"))
        return false;
    snprintf(r->cur, sizeof(r->cur), "%s/cur.sh", r->root);
    snprintf(r->src_x, sizeof(r->src_x), "%s/x.sh", r->root);
    snprintf(r->src_y, sizeof(r->src_y), "%s/y.sh", r->root);
    return sul_script(r->cur, PLAN_X) && sul_script(r->src_x, PLAN_X) &&
           sul_script(r->src_y, PLAN_Y);
}

static int sul_pure_cases(void)
{
    int failures = 0;
    char out[256];
    TEST("selfupgrade: off unless ZCL_LAND_SELFUPGRADE=1") {
        unsetenv(ZCL_LAND_SELFUPGRADE_ENV);
        ASSERT(!zcl_land_selfupgrade_enabled());
        setenv(ZCL_LAND_SELFUPGRADE_ENV, "yes", 1);
        ASSERT(!zcl_land_selfupgrade_enabled());
        setenv(ZCL_LAND_SELFUPGRADE_ENV, "1", 1);
        ASSERT(zcl_land_selfupgrade_enabled());
        unsetenv(ZCL_LAND_SELFUPGRADE_ENV);
        PASS();
    }
    TEST("selfupgrade: only the driver's own sources trigger") {
        ASSERT(zcl_land_selfupgrade_touches_driver(
            "docs/a.md\ntools/command/native_dev_land_train.c\n"));
        ASSERT(zcl_land_selfupgrade_touches_driver("tools/dev/dev_land_x.c"));
        ASSERT(!zcl_land_selfupgrade_touches_driver(
            "docs/a.md\ntools/command/native_dev_agent.c\n"));
        ASSERT(!zcl_land_selfupgrade_touches_driver(""));
        PASS();
    }
    TEST("selfupgrade: the slot path holds the full sha and nothing else") {
        ASSERT(zcl_land_selfupgrade_slot_path("/r", SHA_A, out, sizeof(out)));
        ASSERT_STR_EQ(out, "/r/slots/" SHA_A "/z23-dev");
        ASSERT(!zcl_land_selfupgrade_slot_path("/r", "abc", out, sizeof(out)));
        ASSERT(!zcl_land_selfupgrade_slot_path(
            "/r", "../../etc/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", out,
            sizeof(out)));
        ASSERT(!zcl_land_selfupgrade_slot_path(
            "/r", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", out,
            sizeof(out)));
        PASS();
    }
_test_next:;
    return failures;
}

static int sul_switch_cases(void)
{
    int failures = 0;
    struct sul_rig r;
    char slot[700], ptr[700];
    if (!sul_rig_open(&r)) {
        printf("selfupgrade: rig failed\n");
        return 1;
    }
    TEST("selfupgrade: agreeing decisions switch the pointer on row N") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_x));
        ASSERT(zcl_land_selfupgrade_slot_path(r.root, SHA_A, slot,
                                              sizeof(slot)));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                    g_args, 2),
                  (int)ZCL_LAND_SU_AGREE);
        ASSERT(!zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                    g_args, 2),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT(zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_STR_EQ(ptr, slot);
        PASS();
    }
    TEST("selfupgrade: a failed row restores the unpinned driver") {
        ASSERT(zcl_land_selfupgrade_row_result(r.root, false));
        ASSERT(!zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        PASS();
    }
    TEST("selfupgrade: a failed row restores the previous pointer") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_B, r.src_x));
        ASSERT(zcl_land_selfupgrade_slot_path(r.root, SHA_B, slot,
                                              sizeof(slot)));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_B,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT(zcl_land_selfupgrade_row_result(r.root, true) == false);
        ASSERT(zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_STR_EQ(ptr, slot);
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_x));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT(zcl_land_selfupgrade_row_result(r.root, false));
        ASSERT(zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_STR_EQ(ptr, slot);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(r.root);
    return failures;
}

static int sul_disagree_cases(void)
{
    int failures = 0;
    struct sul_rig r;
    char ptr[700];
    if (!sul_rig_open(&r)) {
        printf("selfupgrade: rig failed\n");
        return 1;
    }
    TEST("selfupgrade: a disagreeing candidate never switches") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_y));
        for (int i = 0; i < 4; i++)
            ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                        g_args, 2),
                      (int)ZCL_LAND_SU_DISAGREE);
        ASSERT(!zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        PASS();
    }
    TEST("selfupgrade: one disagreement resets the agree count") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_B, r.src_x));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_B,
                                                    g_args, 2),
                  (int)ZCL_LAND_SU_AGREE);
        ASSERT(sul_script(r.cur, PLAN_Y)); /* the current driver changes */
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_B,
                                                    g_args, 2),
                  (int)ZCL_LAND_SU_DISAGREE);
        ASSERT(sul_script(r.cur, PLAN_X));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_B,
                                                    g_args, 2),
                  (int)ZCL_LAND_SU_AGREE);
        ASSERT(!zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        PASS();
    }
    TEST("selfupgrade: a missing slot or empty output is not agreement") {
        const char *sha_c = "cccccccccccccccccccccccccccccccccccccccc";
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, sha_c,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_ERROR);
        ASSERT(sul_script(r.src_x, ""));
        ASSERT(sul_script(r.cur, ""));
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, sha_c, r.src_x));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, sha_c,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_DISAGREE);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(r.root);
    return failures;
}
static bool sul_write_state(const struct sul_rig *r, const char *body)
{
    char path[700];
    FILE *f;
    snprintf(path, sizeof(path), "%s/upgrade.state", r->root);
    f = fopen(path, "w");
    if (!f)
        return false;
    fputs(body, f);
    return fclose(f) == 0;
}

static int sul_durable_cases(void)
{
    int failures = 0;
    struct sul_rig r;
    char slot_a[700], slot_b[700], ptr[700], st[700], body[2048];
    if (!sul_rig_open(&r)) {
        printf("selfupgrade: rig failed\n");
        return 1;
    }
    (void)zcl_land_selfupgrade_slot_path(r.root, SHA_A, slot_a, sizeof(slot_a));
    (void)zcl_land_selfupgrade_slot_path(r.root, SHA_B, slot_b, sizeof(slot_b));
    snprintf(st, sizeof(st), "%s/upgrade.state", r.root);
    TEST("selfupgrade: a state-write failure leaves the pointer unchanged") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_x));
        ASSERT_EQ(mkdir(st, 0700), 0); /* a directory: the state cannot be replaced */
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_ERROR);
        ASSERT(!zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_EQ(rmdir(st), 0);
        PASS();
    }
    TEST("selfupgrade: a crash before the pointer recovers to the real old target") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_B, r.src_x));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_B,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT(!zcl_land_selfupgrade_row_result(r.root, true));
        /* state as the crash left it: trial A and previous B written, the
         * pointer still B */
        snprintf(body, sizeof(body),
                 "candidate=\nmatches=0\nprevious=%s\ntrial=%s\n", slot_b,
                 SHA_A);
        ASSERT(sul_write_state(&r, body));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT(zcl_land_selfupgrade_row_result(r.root, false));
        ASSERT(zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_STR_EQ(ptr, slot_b); /* never the candidate itself */
        PASS();
    }
    TEST("selfupgrade: observe is blocked while a trial is pending") {
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_A,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, SHA_B,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_ERROR);
        ASSERT(zcl_land_selfupgrade_pointer_read(r.root, ptr, sizeof(ptr)));
        ASSERT_STR_EQ(ptr, slot_a);
        ASSERT(!zcl_land_selfupgrade_row_result(r.root, true));
        PASS();
    }
    TEST("selfupgrade: a nonzero exit with the same stdout is a disagree") {
        char bad[700];
        const char *sha_c = "cccccccccccccccccccccccccccccccccccccccc";
        FILE *f;
        snprintf(bad, sizeof(bad), "%s/bad.sh", r.root);
        f = fopen(bad, "w");
        ASSERT(f != NULL);
        fprintf(f, "#!/bin/sh\necho '%s'\nexit 3\n", PLAN_X);
        ASSERT_EQ(fclose(f), 0);
        ASSERT_EQ(chmod(bad, 0755), 0);
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, sha_c, bad));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(r.root, r.cur, sha_c,
                                                    g_args, 1),
                  (int)ZCL_LAND_SU_DISAGREE);
        PASS();
    }
    TEST("selfupgrade: an existing slot must match the source bytes") {
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_x));
        ASSERT(!zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_y));
        ASSERT(truncate(slot_a, 0) == 0);
        ASSERT(zcl_land_selfupgrade_slot_install(r.root, SHA_A, r.src_x));
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(r.root);
    return failures;
}
#endif

int test_dev_land_selfupgrade(void);
int test_dev_land_selfupgrade(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += sul_pure_cases();
    failures += sul_switch_cases();
    failures += sul_disagree_cases();
    failures += sul_durable_cases();
#endif
    if (failures == 0)
        printf("test_dev_land_selfupgrade: all passed\n");
    else
        printf("test_dev_land_selfupgrade: %d FAILED\n", failures);
    return failures;
}
