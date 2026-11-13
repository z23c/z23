/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: self-test of check-hosted-suite-verdict. Writes five suite logs
 * into a scratch directory and proves the valid cold log passes and four
 * mutations are rejected, then proves the scratch directory is removed when
 * the process is stopped by SIGINT (once and twice), SIGTERM or SIGHUP after
 * a readiness handshake over a pipe.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "gate_hosted_suite_verdict_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

static char g_hsv_fixture_dir[4096];

static int hsv_write_fixture(const char *dir, const char *name,
                             const char *const *lines, size_t n)
{
    char path[4096];
    FILE *f;
    size_t i;
    if (snprintf(path, sizeof path, "%s/%s", dir, name)
        >= (int)sizeof path)
        return -1;
    f = fopen(path, "w");
    if (!f)
        return -1;
    for (i = 0; i < n; i++)
        if (fprintf(f, "%s\n", lines[i]) < 0) {
            fclose(f);
            return -1;
        }
    return fclose(f) == 0 ? 0 : -1;
}

/* The five fixtures, byte-for-byte the script's self-test logs. */
static const char *const k_hsv_fx_good[] = {
    "SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 "
    "groups_cached=0 groups_gated=9 groups_failed=0 self_skips=20 "
    "env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/1041 groups failed, 20 skipped"
};
static const char *const k_hsv_fx_cached[] = {
    "SUITE VERDICT mode=cached groups_total=1050 groups_ran=0 "
    "groups_cached=1041 groups_gated=9 groups_failed=0 self_skips=0 "
    "env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED (CACHED) \xE2\x80\x94 0/1041 groups failed, "
    "0 skipped"
};
static const char *const k_hsv_fx_zero_run[] = {
    "SUITE VERDICT mode=cold groups_total=9 groups_ran=0 "
    "groups_cached=0 groups_gated=9 groups_failed=0 self_skips=0 "
    "env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/0 groups failed, 0 skipped"
};
static const char *const k_hsv_fx_duplicate[] = {
    "SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 "
    "groups_cached=0 groups_gated=9 groups_failed=0 groups_failed=0 "
    "self_skips=20 env_unobserved=0 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/1041 groups failed, 20 skipped"
};
static const char *const k_hsv_fx_unobserved[] = {
    "SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 "
    "groups_cached=0 groups_gated=9 groups_failed=0 self_skips=20 "
    "env_unobserved=1 toolkey=34e55dd75397",
    "ALL TESTS PASSED \xE2\x80\x94 0/1041 groups failed, 20 skipped"
};

/* Creates the fixture directory with the termination signals blocked, so the
 * directory and its registration are never separated by a delivery. */
static int hsv_selftest_dir(void)
{
    char template[4096];
    char *dir;
    if (lsc_install() != 0) {
        hsv_fail("self-test cannot install signal handlers");
        return -1;
    }
    if (snprintf(template, sizeof template,
                 "%s/zcl-hosted-suite-verdict.XXXXXX",
                 env_or("TMPDIR", "/tmp")) >= (int)sizeof template) {
        hsv_fail("self-test cannot build the fixture template path");
        return -1;
    }
    dir = mkdtemp(template);
    if (!dir) {
        hsv_fail("self-test cannot create the fixture directory");
        return -1;
    }
    snprintf(g_hsv_fixture_dir, sizeof g_hsv_fixture_dir, "%s", dir);
    return 0;
}

static int hsv_selftest_fixtures(void)
{
    static const struct {
        const char *name;
        const char *const *lines;
    } fixtures[] = {
        { "good.log", k_hsv_fx_good },
        { "cached.log", k_hsv_fx_cached },
        { "zero-run.log", k_hsv_fx_zero_run },
        { "duplicate.log", k_hsv_fx_duplicate },
        { "unobserved.log", k_hsv_fx_unobserved }
    };
    for (size_t i = 0; i < sizeof fixtures / sizeof fixtures[0]; i++)
        if (hsv_write_fixture(g_hsv_fixture_dir, fixtures[i].name,
                              fixtures[i].lines, 2) != 0) {
            hsv_fail("self-test cannot write fixtures");
            return -1;
        }
    return 0;
}

static bool hsv_fixture_rejects(const char *name)
{
    char path[4096];
    FILE *saved_err = g_hsv_err;
    int rc;
    if (snprintf(path, sizeof path, "%s/%s", g_hsv_fixture_dir, name)
        >= (int)sizeof path)
        return true;
    g_hsv_err = NULL;             /* the script's 2>&1 into the void */
    rc = hsv_check_log(path, NULL);
    g_hsv_err = saved_err;
    return rc != 0;
}

/* Each rejecting mutation keeps the script's exact failure sentence. */
static int hsv_selftest_rejections(void)
{
    static const struct {
        const char *name, *msg;
    } cases[] = {
        { "cached.log", "cached zero-run log was admitted" },
        { "zero-run.log", "cold zero-run log was admitted" },
        { "duplicate.log", "duplicate verdict field was admitted" },
        { "unobserved.log", "environment-unobserved run was admitted" }
    };
    char path[4096];
    /* The valid fixture must pass with stdout discarded (stderr, which a
     * passing run never writes, still flows). */
    if (snprintf(path, sizeof path, "%s/good.log", g_hsv_fixture_dir)
        >= (int)sizeof path) {
        hsv_fail("self-test cannot address the good fixture");
        return -1;
    }
    if (hsv_check_log(path, NULL) != 0) {
        hsv_fail("self-test rejected the valid cold fixture");
        return -1;
    }
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        if (!hsv_fixture_rejects(cases[i].name)) {
            hsv_fail("self-test mutation survived: %s", cases[i].msg);
            return -1;
        }
    return 0;
}

int check_hosted_suite_verdict_run(int argc, char **argv);

/* Exercise the public command's ship policy on real runner-shaped records. */
static int hsv_ship_case(const char *body, bool accepted)
{
    char path[4096];
    if (snprintf(path, sizeof path, "%s/ship.log", g_hsv_fixture_dir) >= (int)sizeof path)
        return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    bool wrote = fputs(body, f) >= 0;
    if (fclose(f) != 0 || !wrote) return -1;
    char *args[] = { "--ship", path };
    FILE *saved = g_hsv_err;
    g_hsv_err = NULL;
    int rc = check_hosted_suite_verdict_run(2, args);
    g_hsv_err = saved;
    return (rc == 0) == accepted ? 0 : -1;
}

#define HSV_SHIP_VERDICT \
    "SUITE VERDICT mode=cold groups_total=1600 groups_ran=1586 " \
    "groups_cached=0 groups_gated=14 groups_failed=0 self_skips=19 " \
    "env_unobserved=4 load_flaky=0 toolkey=34e55dd75397\n"
#define HSV_SHIP_HEAD "ALL TESTS PASSED \xE2\x80\x94 0/1586 groups failed"
#define HSV_ONE_HEAD "ALL TESTS PASSED \xE2\x80\x94 0/1 groups failed\n"

static int hsv_ship_cases(void)
{
    static const struct { const char *body; bool accepted; } cases[] = {
        { "fixture: SOME TESTS FAILED\n" HSV_SHIP_VERDICT HSV_SHIP_HEAD "\n", true },
        { HSV_SHIP_VERDICT HSV_SHIP_VERDICT HSV_SHIP_HEAD "\n", false },
        { HSV_SHIP_HEAD "\nSUITE VERDICT mode=cold", false },
        { "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
          "groups_cached=18446744073709551616 groups_gated=0 groups_failed=0 "
          "self_skips=0 env_unobserved=0 load_flaky=0 toolkey=34e55dd75397\n" HSV_ONE_HEAD, false },
        { "SUITE VERDICT mode=cold groups_total=1 groups_ran=18446744073709551615 "
          "groups_cached=0 groups_gated=2 groups_failed=0 "
          "self_skips=0 env_unobserved=0 load_flaky=0 toolkey=34e55dd75397\n" HSV_ONE_HEAD, false },
        { HSV_SHIP_VERDICT HSV_SHIP_HEAD " [--exact filtered]\n", false },
        { HSV_SHIP_VERDICT HSV_SHIP_HEAD " [--only filtered]\n", false },
        { HSV_SHIP_VERDICT HSV_SHIP_HEAD " [--exact filtered] \t\r\n", false },
        { HSV_SHIP_VERDICT HSV_SHIP_HEAD " [--only filtered]\r\n", false },
        { "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
          "groups_cached=0 groups_gated=0 groups_failed=-1 "
          "self_skips=0 env_unobserved=0 load_flaky=0 toolkey=34e55dd75397\n" HSV_ONE_HEAD, false },
        { "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
          "groups_cached=0 groups_gated=0 groups_failed=0 "
          "self_skips=0 env_unobserved=0 toolkey=34e55dd75397\n" HSV_ONE_HEAD, false },
        { "  image child: ALL TESTS PASSED\n", false }
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        if (hsv_ship_case(cases[i].body, cases[i].accepted) != 0) return -1;
    return 0;
}
#undef HSV_SHIP_VERDICT
#undef HSV_SHIP_HEAD
#undef HSV_ONE_HEAD

/* Exercise the real release wrapper, replacing only its make subprocesses. */
static int hsv_wrapper_make(void)
{
    static const char *const lines[] = {
        "#!/bin/sh",
        "if [ \"$1\" = test-parallel ]; then",
        "  cat \"$HSV_WRAPPER_LOG\" || exit 125",
        "  exit \"$HSV_WRAPPER_RC\"",
        "fi",
        "exit 0"
    };
    char path[4096];
    if (hsv_write_fixture(g_hsv_fixture_dir, "make", lines,
                          sizeof lines / sizeof lines[0]) != 0 ||
        snprintf(path, sizeof path, "%s/make", g_hsv_fixture_dir)
            >= (int)sizeof path || chmod(path, 0700) != 0)
        return -1;
    return 0;
}

static void hsv_wrapper_child(const char *fixture, const char *rc)
{
    char path[8192], log[4096], out[4096];
    lsc_reset_in_child();
    if (setpgid(0, 0) != 0 ||
        snprintf(path, sizeof path, "%s:%s", g_hsv_fixture_dir,
                 env_or("PATH", "/usr/bin:/bin")) >= (int)sizeof path ||
        snprintf(log, sizeof log, "%s/%s", g_hsv_fixture_dir, fixture)
            >= (int)sizeof log ||
        snprintf(out, sizeof out, "%s/wrapper.out", g_hsv_fixture_dir)
            >= (int)sizeof out)
        _exit(125);
    if (setenv("PATH", path, 1) != 0 ||
        setenv("HSV_WRAPPER_LOG", log, 1) != 0 ||
        setenv("HSV_WRAPPER_RC", rc, 1) != 0 ||
        freopen(out, "w", stdout) == NULL || dup2(1, 2) < 0)
        _exit(125);
    unsetenv("GIT_DIR");
    unsetenv("GIT_WORK_TREE");
    if (snprintf(log, sizeof log, "%s/wrapper-lint.log", g_hsv_fixture_dir)
            >= (int)sizeof log ||
        snprintf(out, sizeof out, "%s/wrapper-suite.log", g_hsv_fixture_dir)
            >= (int)sizeof out)
        _exit(125);
    execl("/bin/bash", "bash", "tools/scripts/gate-and-report.sh", log, out,
          (char *)NULL);
    _exit(125);
}

static int hsv_wrapper_wait(pid_t pid)
{
    struct timespec pause = { 0, 10 * 1000 * 1000 };
    int status = 0;
    for (int i = 0; i < 1000 && !lsc_pending(); i++) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (got < 0 && errno != EINTR)
            break;
        nanosleep(&pause, NULL);
    }
    kill(-pid, SIGKILL);
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return -1;
}

static int hsv_wrapper_cases(void)
{
    static const struct { const char *log, *rc; int expected; } cases[] = {
        { "good.log", "0", 0 },
        { "good.log", "7", 2 },
        { "cached.log", "0", 2 },
        { "zero-run.log", "0", 2 },
        { "duplicate.log", "0", 2 },
        { "unobserved.log", "0", 2 }
    };
    if (hsv_wrapper_make() != 0)
        return -1;
    int failed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        pid_t pid = fork();
        if (pid == 0)
            hsv_wrapper_child(cases[i].log, cases[i].rc);
        int got = pid > 0 ? hsv_wrapper_wait(pid) : -1;
        if (got != cases[i].expected) {
            hsv_fail("release wrapper %s runner_rc=%s expected=%d actual=%d",
                     cases[i].log, cases[i].rc, cases[i].expected, got);
            failed = -1;
        }
    }
    return failed;
}

/* Removes the fixture tree with signals blocked, then re-raises a recorded
 * signal under its default disposition. */
static void hsv_cleanup(void)
{
    int sig = lsc_pending();
    lsc_block();
    if (g_hsv_fixture_dir[0]) {
        rap_rm_rf(g_hsv_fixture_dir);
        g_hsv_fixture_dir[0] = '\0';
    }
    if (sig)
        lsc_finish(sig);
}

/* Signal-test child only: report the fixture directory over the pipe, then
 * wait for a signal. */
static void hsv_announce(int ready_fd)
{
    struct timespec ts = { 0, 5 * 1000 * 1000 };
    char line[4100];
    int n = snprintf(line, sizeof line, "%s\n", g_hsv_fixture_dir);
    if (write(ready_fd, line, (size_t)n) != n)
        _exit(2);
    for (int i = 0; i < 4000 && !lsc_pending(); i++)
        nanosleep(&ts, NULL);
}

/* ready_fd is -1 for the command line; the signal test passes a pipe. */
static int hsv_run(int ready_fd)
{
    int failed;
    if (hsv_selftest_dir() != 0)
        return 1;
    lsc_unblock();
    if (ready_fd >= 0)
        hsv_announce(ready_fd);
    if (lsc_pending())
        hsv_cleanup();
    failed = hsv_selftest_fixtures() != 0;
    if (lsc_pending())
        hsv_cleanup();
    if (!failed)
        failed = hsv_selftest_rejections() != 0;
    if (!failed)
        failed = hsv_ship_cases() != 0;
    if (!failed)
        failed = hsv_wrapper_cases() != 0;
    hsv_cleanup();
    if (failed)
        return 1;
    printf("hosted-suite-verdict self-test: PASS "
           "(valid cold + 4 rejecting mutations + 6 release wrapper cases)\n");
    return 0;
}

static int hsv_fail_case(const char *what)
{
    fprintf(stderr, "SELFTEST FAIL: %s\n", what);
    return 1;
}

static int hsv_read_path(int rfd, char *dir, size_t cap)
{
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(rfd, dir + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || dir[used] == '\n')
            break;
        used++;
    }
    dir[used] = '\0';
    return used ? 0 : -1;
}

static int hsv_signal_case(int sig, int times)
{
    int fds[2];
    char dir[4096];
    int st = 0;
    if (pipe(fds) != 0)
        return hsv_fail_case("pipe failed");
    pid_t pid = fork();
    if (pid < 0)
        return hsv_fail_case("fork failed");
    if (pid == 0) {
        close(fds[0]);
        _exit(hsv_run(fds[1]) == 0 ? 3 : 2);
    }
    close(fds[1]);
    int ready = hsv_read_path(fds[0], dir, sizeof dir);
    close(fds[0]);
    for (int i = 0; ready == 0 && i < times; i++)
        kill(pid, sig);
    if (waitpid(pid, &st, 0) != pid || ready != 0)
        return hsv_fail_case("the signal-test child did not finish");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return hsv_fail_case("the stopped process did not re-raise its signal");
    return access(dir, F_OK) == 0
        ? hsv_fail_case("the fixture directory outlived the signal") : 0;
}

static int hsv_signals(void)
{
    return hsv_signal_case(SIGINT, 1) || hsv_signal_case(SIGINT, 2)
        || hsv_signal_case(SIGTERM, 1) || hsv_signal_case(SIGHUP, 1);
}

int check_hosted_suite_verdict_selftest(void)
{
    int rc = hsv_run(-1);
    if (rc == 0)
        rc = hsv_signals();
    return rc;
}
