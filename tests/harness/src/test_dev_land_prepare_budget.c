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
#include <sys/wait.h>
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
#if defined(__linux__)
static bool dlb_stat_zombie(long pid, const char *text)
{
    char *end;
    errno = 0;
    long observed_pid = strtol(text, &end, 10);
    if (errno || end == text || observed_pid != pid || strncmp(end, " (", 2))
        return false;
    const char *close_paren = strrchr(end + 2, ')');
    if (!close_paren || strncmp(close_paren, ") Z ", 4))
        return false;
    const char *parent = close_paren + 4;
    if (*parent < '0' || *parent > '9') return false;
    errno = 0;
    (void)strtol(parent, &end, 10);
    return errno == 0 && (*end == ' ' || *end == '\n');
}

static bool dlb_stat_file_zombie(long pid, const char *path)
{
    char text[512];
    FILE *stream = fopen(path, "rb");
    if (!stream) return false;
    size_t length = fread(text, 1, sizeof(text) - 1, stream);
    bool complete = fgetc(stream) == EOF && !ferror(stream);
    if (fclose(stream) != 0) complete = false;
    if (!complete || length == 0 || text[length - 1] != '\n' ||
        memchr(text, '\0', length)) return false;
    text[length] = '\0';
    return dlb_stat_zombie(pid, text);
}
#endif

static bool dlb_pid_gone_at(long pid, const char *path)
{
    if (pid <= 0 || (long)(pid_t)pid != pid) return false;
    if (kill((pid_t)pid, 0) != 0) return errno == ESRCH;
#if defined(__linux__)
    if (dlb_stat_file_zombie(pid, path)) return true;
#else
    (void)path;
#endif
    /* Disappearance during the metadata read is death; unknown metadata is not. */
    return kill((pid_t)pid, 0) != 0 && errno == ESRCH;
}

static bool dlb_pid_gone(long pid)
{
    char path[64];
    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    return dlb_pid_gone_at(pid, path);
}

static int dlb_liveness_metadata(void)
{
    int failures = 0;
    TEST("land: live PID and unknown metadata never prove death") {
        char root[1024], path[1200];
        test_make_tmpdir(root, sizeof(root), "dev_land", "pid_metadata");
        snprintf(path, sizeof(path), "%s/stat", root);
        ASSERT(!dlb_pid_gone((long)getpid()));
        ASSERT(!dlb_pid_gone_at((long)getpid(), path));
        ASSERT(dlx_write_dep(root, "stat", "malformed\n"));
        ASSERT(!dlb_pid_gone_at((long)getpid(), path));
        ASSERT(dlx_write_dep(root, "stat", "1 (wrong PID) Z 0\n"));
        ASSERT(!dlb_pid_gone_at((long)getpid(), path));
        const char *states[] = { "", ")", ") Z", ") Zx 0\n", ") Z \n", ") S 0\n" };
        for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
            char metadata[128];
            snprintf(metadata, sizeof(metadata), "%ld (fixture%s", (long)getpid(), states[i]);
            ASSERT(dlx_write_dep(root, "stat", metadata));
            ASSERT(!dlb_pid_gone_at((long)getpid(), path));
        }
        /* A directory opens on Linux but its read fails; it proves no death. */
        ASSERT(!dlb_pid_gone_at((long)getpid(), root));
        PASS();
    } _test_next:;
    return failures;
}

static int dlb_liveness_child(void)
{
    int failures = 0;
    TEST("land: exited child is recognized without leaking its zombie") {
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) _exit(0);
        siginfo_t observation = {0};
        int observed;
        do {
            observed = waitid(P_PID, (id_t)child, &observation, WEXITED | WNOWAIT);
        } while (observed < 0 && errno == EINTR);
        bool zombie_gone = dlb_pid_gone((long)child);
        int status = 0;
        pid_t reaped;
        do {
            reaped = waitpid(child, &status, 0);
        } while (reaped < 0 && errno == EINTR);
        /* Reap before assertions: a failing observation must not leak a child. */
        ASSERT(observed == 0 && observation.si_pid == child);
        ASSERT(reaped == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
#if defined(__linux__)
        ASSERT(zombie_gone);
#else
        ASSERT(!zombie_gone);
#endif
        ASSERT(dlb_pid_gone((long)child));
        PASS();
    } _test_next:;
    return failures;
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
    return dlb_liveness_metadata() + dlb_liveness_child() +
           dlb_prints() + dlb_spins() + dlb_wedge() + dlb_ceiling();
}

#endif
