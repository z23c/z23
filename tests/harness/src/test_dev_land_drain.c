/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: one `drive --prove` invocation keeps draining the
 * queue (the z23-land-step unit runs it with --max_rows=16). Queued rows land
 * back to back with no timer edge between them, a wall-clock budget stops it
 * starting a further row, the first row that does not land stops it, and a
 * second drive still gets DRIVE_BUSY. Part of the test_dev_land group; shared
 * fixtures live in test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)
/* The rig's two rows plus a third child of the second. */
static bool dld_third_row(struct dlx_prove_rig *p, char third[64])
{
    struct dlx_call c;
    bool ok = dlx_commit(p->rig.clone, "third.txt", "three\n", third);
    if (!ok)
        return false;
    dlx_submit(&c, &p->rig, third);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

/* Make every stand-in `make` take two seconds before it builds anything. */
static bool dld_slow_make(const char *path)
{
    char body[4096], slow[4200];
    size_t len = 0;
    const char *rest;
    if (!dlx_slurp(path, body, sizeof(body) - 1, &len))
        return false;
    body[len] = '\0';
    rest = strchr(body, '\n');
    if (!rest)
        return false;
    (void)snprintf(slow, sizeof(slow), "#!/bin/sh\nsleep 2\n%s", rest + 1);
    return dlx_write(path, slow) && chmod(path, 0700) == 0;
}
#endif

static int test_dev_land_drain_three_rows_one_drive(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: one drive lands three queued rows back to back from one lock hold") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char third[64], main_tip[64];
        dlx_isolate("drain_three");
        ASSERT(dlx_prove_rig(&p, "drain_three_rig", DLX_PRODUCER_OK));
        ASSERT(dld_third_row(&p, third));
        ASSERT(dlx_prove_drive(&c, 16) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_EQ(dlx_int(&c, "rows_landed"), 3);
        ASSERT(dlx_arr(&c, "rows") != NULL &&
               dlx_arr(&c, "rows")->num_children == 3);
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 3);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, third);
        /* Drained: the next drive finds nothing to do. */
        ASSERT(dlx_prove_drive(&c, 16) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "idle");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_drain_budget_stops_new_rows(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a drive past its wall-clock budget starts no further row") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char main_tip[64];
        dlx_isolate("drain_budget");
        ASSERT(dlx_prove_rig(&p, "drain_budget_rig", DLX_PRODUCER_OK));
        ASSERT(dld_slow_make(p.make));
        ASSERT_EQ(setenv("ZCL_LAND_DRIVE_BUDGET_S", "1", 1), 0);
        ASSERT(dlx_prove_drive(&c, 16) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_EQ(dlx_int(&c, "rows_landed"), 1);
        ASSERT(dlx_arr(&c, "rows") != NULL &&
               dlx_arr(&c, "rows")->num_children == 1);
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 1);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, p.rig.tip);
        /* The row it left queued is taken by the next drive. */
        ASSERT_EQ(unsetenv("ZCL_LAND_DRIVE_BUDGET_S"), 0);
        ASSERT(dlx_prove_drive(&c, 16) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "rows_landed"), 1);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, p.second);
        PASS();
    }
_test_next:;
    (void)unsetenv("ZCL_LAND_DRIVE_BUDGET_S");
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_drain_stops_after_failed_row(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a draining drive stops after the first row that does not land") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char third[64], before[64], main_tip[64];
        dlx_isolate("drain_stop");
        ASSERT(dlx_prove_rig(&p, "drain_stop_rig", DLX_PRODUCER_BROKEN));
        ASSERT(dld_third_row(&p, third));
        ASSERT(dlx_origin_main(&p.rig, before));
        ASSERT(dlx_prove_drive(&c, 16) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_REFUSED");
        ASSERT(dlx_arr(&c, "rows") != NULL &&
               dlx_arr(&c, "rows")->num_children == 1);
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 1);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, before);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

static int test_dev_land_drain_second_drive_busy(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a second drive gets DRIVE_BUSY while a draining drive holds the lock") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char land[1200], lock[1400];
        dlx_isolate("drain_busy");
        ASSERT(dlx_prove_rig(&p, "drain_busy_rig", DLX_PRODUCER_OK));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(lock, sizeof(lock), "%s/drive.lock", land);
        int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
        ASSERT(dlx_prove_drive(&c, 16) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_BUSY");
        ASSERT(c.reply.error.retryable);
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 0);
        ASSERT(flock(fd, LOCK_UN) == 0 && close(fd) == 0);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_drain_cases(void)
{
    int failures = 0;
    failures += test_dev_land_drain_three_rows_one_drive();
    failures += test_dev_land_drain_budget_stops_new_rows();
    failures += test_dev_land_drain_stops_after_failed_row();
    failures += test_dev_land_drain_second_drive_busy();
    return failures;
}
