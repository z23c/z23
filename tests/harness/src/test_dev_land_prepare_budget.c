/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: the preparation make's progress-aware budget.
 * A build that is still printing or still burning CPU outlives the idle
 * bound; a silent wedged one dies at it; the hard ceiling bounds both; the
 * timeout kills the whole process group; and every success logs its elapsed
 * time. Part of the test_dev_land group (run from
 * test_dev_land_final_plan_preparation); shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)

#include <errno.h>
#include <signal.h>
#include <time.h>

static bool dlb_log_contains(const char *path, const char *text)
{
    size_t len = 0;
    char *body = calloc(270000, 1);
    if (!body) return false;
    bool ok = dlx_slurp(path, body, 269999, &len) && strstr(body, text) != NULL;
    free(body);
    return ok;
}

/* A killed grandchild may linger as an unreaped zombie under a container
 * init that never waits; that is dead, not surviving. */
static bool dlb_pid_gone(long pid)
{
    char path[64], text[512];
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) return true;
    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return true;
    const char *close_paren = fgets(text, sizeof(text), f) ? strrchr(text, ')') : NULL;
    (void)fclose(f);
    return !close_paren || close_paren[2] == 'Z';
}

static int dlb_prints(void)
{
    int failures = 0;
    TEST("land: a make that keeps printing outlives the idle bound") {
        char root[1024], log[1200], why[512];
        test_make_tmpdir(root, sizeof(root), "dev_land", "budget_output");
        snprintf(log, sizeof(log), "%s/attempt.log", root);
        ASSERT(dlx_write_dep(root, "Makefile",
            "progress:\n\t@for i in 1 2 3 4 5 6 7 8; do echo tick$$i; sleep 0.3; done\n"));
        /* 2.4 s of wall clock against a 1 s idle bound. */
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "progress", 1000, 60000,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) == 0);
        ASSERT(dlb_log_contains(log, "target=progress rc=0 timed_out=0 elapsed_ms="));
        ASSERT(!dlb_log_contains(log, "--- preparation output begin ---"));
        PASS();
    } _test_next:;
    return failures;
}

static int dlb_spins(void)
{
    int failures = 0;
    TEST("land: a silent make that keeps using CPU outlives the idle bound") {
        char root[1024], log[1200], why[512];
        test_make_tmpdir(root, sizeof(root), "dev_land", "budget_cpu");
        snprintf(log, sizeof(log), "%s/attempt.log", root);
        ASSERT(dlx_write_dep(root, "Makefile",
            "spin:\n\t@end=$$(( $$(date +%s) + 3 )); "
            "while [ $$(date +%s) -lt $$end ]; do :; done\n"));
        /* At least 2 s of silence against a 0.6 s idle bound. */
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "spin", 600, 60000,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) == 0);
        ASSERT(dlb_log_contains(log, "target=spin rc=0 timed_out=0 elapsed_ms="));
        PASS();
    } _test_next:;
    return failures;
}

static int dlb_wedge(void)
{
    int failures = 0;
    TEST("land: a silent wedged make is killed at the idle bound, group and all") {
        char root[1024], log[1200], why[512], pidpath[1200], pidtext[32] = "";
        size_t len = 0;
        long child;
        test_make_tmpdir(root, sizeof(root), "dev_land", "budget_wedge");
        snprintf(log, sizeof(log), "%s/attempt.log", root);
        snprintf(pidpath, sizeof(pidpath), "%s/child.pid", root);
        ASSERT(dlx_write_dep(root, "Makefile",
            "wedge:\n\t@sleep 300 & echo $$! > child.pid; sleep 300\n"));
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "wedge", 700, 60000,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) != 0);
        ASSERT(dlb_log_contains(log, "timed_out=1"));
        ASSERT(strstr(why, "timed out: idle"));
        ASSERT(dlx_slurp(pidpath, pidtext, sizeof(pidtext) - 1, &len));
        child = strtol(pidtext, NULL, 10);
        ASSERT(child > 1);
        for (int i = 0; i < 40 && !dlb_pid_gone(child); i++)
            (void)nanosleep(&(struct timespec){ .tv_nsec = 50 * 1000 * 1000 }, NULL);
        ASSERT(dlb_pid_gone(child));
        PASS();
    } _test_next:;
    return failures;
}

static int dlb_ceiling(void)
{
    int failures = 0;
    TEST("land: the hard ceiling kills a make that never goes idle") {
        char root[1024], log[1200], why[512];
        test_make_tmpdir(root, sizeof(root), "dev_land", "budget_hard");
        snprintf(log, sizeof(log), "%s/attempt.log", root);
        ASSERT(dlx_write_dep(root, "Makefile",
            "chatty:\n\t@while :; do echo tick; sleep 0.2; done\n"));
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "chatty", 5000, 1500,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) != 0);
        ASSERT(dlb_log_contains(log, "timed_out=1"));
        ASSERT(strstr(why, "timed out: hard ceiling"));
        PASS();
    } _test_next:;
    return failures;
}

int dlx_prepare_budget(void)
{
    return dlb_prints() + dlb_spins() + dlb_wedge() + dlb_ceiling();
}

#endif
