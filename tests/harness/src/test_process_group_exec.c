/* Copyright 2026 Rhett Creighton - Apache License 2.0.
 *
 * Regression: a local fixture launched through process-group-exec with
 * --die-with-parent must not outlive the shell that launched it. The
 * orphan this pins was real: a journey driver died mid-run, its regtest
 * daemon kept a shared test-safe port, and every later journey on the
 * host failed at bring-up until a human found the holder by hand. The
 * kernel-side parent-death signal closes that class for local fixtures.
 * Remote journey legs cannot use it — their parent is one short ssh
 * session of many — so they take --die-with-lease instead: the launcher
 * stays resident as the group leader and terminates its own group when
 * the driver stops refreshing the lease file on the fixture's host.
 * Ownership stays exact in both modes: the only group either mechanism
 * can end is the one this launcher created, so no pid is ever reused
 * into a kill and no held port ever authorizes termination.
 *
 * Non-Linux POSIX hosts have no PR_SET_PDEATHSIG; there the launcher stays
 * resident as the group leader and supervises the fixture, ending the whole
 * group when its driver dies, so the same reaping contract is observed. The lease mode
 * is fully POSIX and is exercised everywhere. Windows runs the stronger
 * Job Object acceptance binary instead of this group.
 */

#include "test/test_core.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(_WIN32)

static const char *pge_launcher(void)
{
    static const char *candidates[] = {
        "build/bin/process-group-exec", "./build/bin/process-group-exec",
        NULL};
    for (size_t i = 0; candidates[i]; i++)
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    return NULL;
}

/* Run one launcher invocation under a disposable driver process that records
 * the launcher pid. Returns the driver pid; the launcher pid is written to
 * pidfile by the driver. Pure C: the driver forks and execs the launcher
 * directly, with no shell, and then waits on it. */
static pid_t pge_spawn(const char *launcher, const char *flag,
                       const char *pidfile)
{
    pid_t driver = fork();
    if (driver < 0)
        return 0;
    if (driver > 0)
        return driver;
    pid_t child = fork();
    if (child < 0)
        _exit(126);
    if (child == 0) {
        if (flag)
            execl(launcher, launcher, flag, "sleep", "60", (char *)NULL);
        else
            execl(launcher, launcher, "sleep", "60", (char *)NULL);
        _exit(127);
    }
    FILE *f = fopen(pidfile, "w");
    if (!f || fprintf(f, "%ld\n", (long)child) < 0 || fclose(f) != 0) {
        kill(child, SIGKILL);
        _exit(125);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR)
        ;
    _exit(0);
}

/* Like pge_spawn with --die-with-parent, but the fixture is `tee READY` fed
 * from a pipe whose write end the TEST keeps open (returned in *hold): tee
 * creates READY before it reads, so the file proves the fixture itself is
 * running, and it cannot exit on stdin EOF when the driver dies. */
static pid_t pge_spawn_ready(const char *launcher, const char *pidfile,
                             const char *ready, int *hold)
{
    int fds[2];
    if (pipe(fds) != 0)
        return 0;
    pid_t driver = fork();
    if (driver < 0) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }
    if (driver > 0) {
        close(fds[0]);
        *hold = fds[1];
        return driver;
    }
    close(fds[1]);
    pid_t child = fork();
    if (child < 0)
        _exit(126);
    if (child == 0) {
        if (dup2(fds[0], STDIN_FILENO) < 0)
            _exit(126);
        if (fds[0] != STDIN_FILENO)
            close(fds[0]);
        execl(launcher, launcher, "--die-with-parent", "tee", ready,
              (char *)NULL);
        _exit(127);
    }
    close(fds[0]);
    FILE *f = fopen(pidfile, "w");
    if (!f || fprintf(f, "%ld\n", (long)child) < 0 || fclose(f) != 0) {
        kill(child, SIGKILL);
        _exit(125);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR)
        ;
    _exit(0);
}

static int pge_wait_path(const char *path, int seconds)
{
    for (int i = 0; i < seconds * 10; i++) {
        if (access(path, F_OK) == 0)
            return 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
        nanosleep(&ts, NULL); /* real-clock: the fixture is a real process
                               * creating a real file; no seam spans it */
    }
    return access(path, F_OK) == 0;
}

static int pge_read_pid(const char *pidfile, pid_t *out)
{
    FILE *f = fopen(pidfile, "r");
    if (!f)
        return 0;
    long v = 0;
    int ok = fscanf(f, "%ld", &v) == 1 && v > 0;
    fclose(f);
    if (ok)
        *out = (pid_t)v;
    return ok;
}

static int pge_alive(pid_t p)
{
    return p > 0 && (kill(p, 0) == 0 || errno != ESRCH);
}

static int pge_wait_gone(pid_t p, int seconds)
{
    for (int i = 0; i < seconds * 10; i++) {
        if (!pge_alive(p))
            return 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
        nanosleep(&ts, NULL); /* real-clock: observing the kernel deliver a
                               * parent-death SIGTERM to a real child; no
                               * fake-clock seam spans processes */
    }
    return !pge_alive(p);
}

/* True while any process is still a member of process group `group`. */
static int pge_group_alive(pid_t group)
{
    return group > 1 && (kill(-group, 0) == 0 || errno != ESRCH);
}

static int pge_wait_group_alive(pid_t group, int seconds)
{
    for (int i = 0; i < seconds * 10; i++) {
        if (pge_group_alive(group))
            return 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
        nanosleep(&ts, NULL); /* real-clock: the child runs setsid in its own
                               * process; no fake-clock seam spans processes */
    }
    return pge_group_alive(group);
}

static int pge_wait_group_gone(pid_t group, int seconds)
{
    for (int i = 0; i < seconds * 10; i++) {
        if (!pge_group_alive(group))
            return 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
        nanosleep(&ts, NULL); /* real-clock: observing the kernel deliver a
                               * parent-death SIGTERM to a real group; no
                               * fake-clock seam spans processes */
    }
    return !pge_group_alive(group);
}

static int pge_wait_file(const char *pidfile, pid_t *out)
{
    for (int i = 0; i < 50; i++) {
        if (pge_read_pid(pidfile, out))
            return 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
        /* Real /bin/sh fork writing the pidfile through the kernel's
         * filesystem — no injected clock spans processes. */
        nanosleep(&ts, NULL); /* real-clock: real fork+filesystem visibility */
    }
    return 0;
}

/* One --die-with-parent observation. Every resource is released on every
 * path, including a failed expectation: the descriptor, the driver, and any
 * fixture group left running. */
static bool pge_dwp_observe(const char *launcher, const char *dir)
{
    char pidfile[300], ready[320];
    int hold = -1;
    pid_t driver = 0, group = 0;
    bool driver_reaped = false, ok = false;
    if (snprintf(pidfile, sizeof(pidfile), "%s/pid", dir) <= 0 ||
        snprintf(ready, sizeof(ready), "%s/ready", dir) <= 0)
        return false;
    driver = pge_spawn_ready(launcher, pidfile, ready, &hold);
    if (driver <= 0)
        goto out;
    /* The launcher is the leader of its own session and group, so its pid is
     * the group id of the launcher and the fixture it runs: Linux execs the
     * fixture in place, elsewhere the launcher stays resident as the
     * fixture's supervisor. Watching the group observes the fixture itself,
     * not only the launcher. The pid is recorded at fork; the group exists
     * once the launcher has run setsid, so wait for it rather than race. */
    if (!pge_wait_file(pidfile, &group) || !pge_wait_group_alive(group, 5))
        goto out;
    /* The fixture (tee) creates its ready file only once it is running under
     * the launcher; it stays blocked on the pipe this test holds open. */
    if (!pge_wait_path(ready, 10))
        goto out;
    /* The fixture must be living on its own until the driver dies: if it
     * exits independently the reaping below would prove nothing. */
    if (pge_wait_group_gone(group, 1))
        goto out;
    /* Kill the driver exactly as a crashed harness dies. */
    int status = 0;
    if (kill(driver, SIGKILL) != 0 || waitpid(driver, &status, 0) != driver)
        goto out;
    driver_reaped = true;
    ok = pge_wait_group_gone(group, 10);
out:
    /* Closing the held pipe also ends the tee fixture on stdin EOF, so a
     * failed expectation cannot leave it running; no group is signalled by
     * id, which could name a reused id. */
    if (hold >= 0)
        close(hold);
    if (driver > 0 && !driver_reaped) {
        kill(driver, SIGKILL);
        (void)waitpid(driver, &(int){0}, 0);
    }
    unlink(ready);
    unlink(pidfile);
    return ok;
}

static int test_die_with_parent_reaps_fixture(void)
{
    int failures = 0;
    TEST("process-group-exec: --die-with-parent reaps the whole fixture "
         "group when the launching driver dies") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_dwp_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        bool reaped = pge_dwp_observe(launcher, dir);
        rmdir(dir);
        ASSERT(reaped);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_plain_setsid_survives(void)
{
    int failures = 0;
    TEST("process-group-exec: without the flag the fixture survives its "
         "launching shell") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_plain_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char pidfile[300];
        ASSERT(snprintf(pidfile, sizeof(pidfile), "%s/pid", dir) > 0);
        pid_t shell = pge_spawn(launcher, NULL, pidfile);
        ASSERT(shell > 0);
        pid_t fixture = 0;
        ASSERT(pge_wait_file(pidfile, &fixture));
        ASSERT(pge_alive(fixture));
        ASSERT(kill(shell, SIGKILL) == 0);
        int status = 0;
        ASSERT(waitpid(shell, &status, 0) == shell);
        /* Still alive one second later: remote legs depend on this. */
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&ts, NULL); /* real-clock: proving the kernel did NOT send
                               * the parent-death signal requires waiting on
                               * the real scheduler; absence has no seam */
        ASSERT(pge_alive(fixture));
        ASSERT(kill(fixture, SIGTERM) == 0);
        ASSERT(pge_wait_gone(fixture, 5));
        unlink(pidfile);
        rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

/* ── --die-with-lease: remote-leg supervision ─────────────────────────── */

#include <fcntl.h>

/* Refresh a lease file the way the driver's refresher does: create it if
 * the first synchronous touch has not run yet, then bump mtime to now. */
static int pge_touch(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0)
        return 0;
    int ok = close(fd) == 0;
    return ok && utimensat(AT_FDCWD, path, NULL, 0) == 0;
}

/* Spawn a leased launcher under a disposable shell parent. The shell
 * records the supervisor pid (the leased launcher stays resident as the
 * group leader); the supervised command publishes its own pid first. The
 * shell ends with `wait "$p"` — a no-operand wait exits 0 under POSIX and
 * would silently erase the launcher's status — so the shell's exit status
 * IS the launcher's. */
static pid_t pge_spawn_leased(const char *launcher, const char *spec,
                              const char *sup_file, const char *child_file,
                              const char *child_cmd)
{
    char script[2048];
    int n = snprintf(script, sizeof(script),
                     "'%s' --die-with-lease='%s' /bin/sh -c \"echo \\$\\$ > "
                     "'%s'; %s\" & p=$!; echo \"$p\" > '%s'; wait \"$p\"",
                     launcher, spec, child_file, child_cmd, sup_file);
    if (n <= 0 || (size_t)n >= sizeof(script))
        return 0;
    pid_t shell = fork();
    if (shell < 0)
        return 0;
    if (shell == 0) {
        execl("/bin/sh", "sh", "-c", script, (char *)NULL);
        _exit(127);
    }
    return shell;
}

/* Poll for the shell's exit; report the launcher's pass-through status. */
static int pge_wait_status(pid_t p, int seconds, int *exit_code, int *sig)
{
    *exit_code = -1;
    *sig = 0;
    for (int i = 0; i < seconds * 10; i++) {
        int status = 0;
        pid_t rc = waitpid(p, &status, WNOHANG);
        if (rc == p) {
            if (WIFEXITED(status))
                *exit_code = WEXITSTATUS(status);
            if (WIFSIGNALED(status))
                *sig = WTERMSIG(status);
            return 1;
        }
        if (rc < 0 && errno != EINTR)
            return 0;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
        nanosleep(&ts, NULL); /* real-clock: a real supervisor polling a real
                               * file's mtime; no injected clock spans
                               * processes or the filesystem */
    }
    return 0;
}

static int test_lease_stale_reaps_group(void)
{
    int failures = 0;
    TEST("process-group-exec: --die-with-lease reaps the group when the "
         "lease goes stale") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_lease_stale_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char lease[300], sup[300], child[300];
        ASSERT(snprintf(lease, sizeof(lease), "%s/lease", dir) > 0);
        ASSERT(snprintf(sup, sizeof(sup), "%s/sup", dir) > 0);
        ASSERT(snprintf(child, sizeof(child), "%s/child", dir) > 0);
        ASSERT(pge_touch(lease));
        char spec[340];
        ASSERT(snprintf(spec, sizeof(spec), "%s:1", lease) > 0);
        pid_t shell = pge_spawn_leased(launcher, spec, sup, child,
                                       "exec sleep 60");
        ASSERT(shell > 0);
        pid_t supervisor = 0, fixture = 0;
        ASSERT(pge_wait_file(sup, &supervisor));
        ASSERT(pge_wait_file(child, &fixture));
        ASSERT(pge_alive(fixture));
        /* No refresh: the lease crosses its stale window. */
        int code = -1, sig = 0;
        ASSERT(pge_wait_status(shell, 6, &code, &sig));
        ASSERT(pge_wait_gone(fixture, 3));
        ASSERT(code == 128 + SIGTERM); /* child TERMed, status passed through */
        unlink(lease); unlink(sup); unlink(child); rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_lease_fresh_survives_and_cleanup_terminates(void)
{
    int failures = 0;
    TEST("process-group-exec: a refreshed lease keeps the fixture alive; a "
         "group TERM still cleans up") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_lease_fresh_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char lease[300], sup[300], child[300];
        ASSERT(snprintf(lease, sizeof(lease), "%s/lease", dir) > 0);
        ASSERT(snprintf(sup, sizeof(sup), "%s/sup", dir) > 0);
        ASSERT(snprintf(child, sizeof(child), "%s/child", dir) > 0);
        ASSERT(pge_touch(lease));
        char spec[340];
        ASSERT(snprintf(spec, sizeof(spec), "%s:2", lease) > 0);
        pid_t shell = pge_spawn_leased(launcher, spec, sup, child,
                                       "exec sleep 60");
        ASSERT(shell > 0);
        pid_t supervisor = 0, fixture = 0;
        ASSERT(pge_wait_file(sup, &supervisor));
        ASSERT(pge_wait_file(child, &fixture));
        /* Refresh across three stale windows: the fixture must survive. */
        for (int i = 0; i < 6; i++) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 700L * 1000L * 1000L};
            nanosleep(&ts, NULL); /* real-clock: real refresher cadence against the real mtime window */
            ASSERT(pge_touch(lease));
        }
        ASSERT(pge_alive(fixture));
        /* The caller's own cleanup TERMs the group (the supervisor is the
         * setsid leader, so -supervisor is the whole group): the child
         * dies, the supervisor passes its status through and exits. */
        ASSERT(kill(-supervisor, SIGTERM) == 0);
        int code = -1, sig = 0;
        ASSERT(pge_wait_status(shell, 6, &code, &sig));
        ASSERT(!pge_alive(fixture) || pge_wait_gone(fixture, 3));
        ASSERT(code == 128 + SIGTERM);
        unlink(lease); unlink(sup); unlink(child); rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_lease_missing_reaps(void)
{
    int failures = 0;
    TEST("process-group-exec: a lease that never existed fails reaped, not "
         "orphaned") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_lease_missing_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char lease[300], sup[300], child[300];
        ASSERT(snprintf(lease, sizeof(lease), "%s/lease", dir) > 0);
        ASSERT(snprintf(sup, sizeof(sup), "%s/sup", dir) > 0);
        ASSERT(snprintf(child, sizeof(child), "%s/child", dir) > 0);
        char spec[340];
        ASSERT(snprintf(spec, sizeof(spec), "%s:1", lease) > 0);
        /* No touch: the file is absent from the first reading. The
         * supervisor may TERM the group before the child even publishes
         * its pid — that instant reap is the desired behaviour, so the
         * child pidfile is opportunistically checked, never required. */
        pid_t shell = pge_spawn_leased(launcher, spec, sup, child,
                                       "exec sleep 60");
        ASSERT(shell > 0);
        int code = -1, sig = 0;
        ASSERT(pge_wait_status(shell, 6, &code, &sig));
        pid_t fixture = 0;
        if (pge_read_pid(child, &fixture))
            ASSERT(pge_wait_gone(fixture, 3));
        unlink(lease); unlink(sup); unlink(child); rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_lease_grace_escalates_to_kill(void)
{
    int failures = 0;
    TEST("process-group-exec: a TERM-ignoring leased group is SIGKILLed "
         "after the grace") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_lease_grace_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char lease[300], sup[300], child[300];
        ASSERT(snprintf(lease, sizeof(lease), "%s/lease", dir) > 0);
        ASSERT(snprintf(sup, sizeof(sup), "%s/sup", dir) > 0);
        ASSERT(snprintf(child, sizeof(child), "%s/child", dir) > 0);
        ASSERT(pge_touch(lease));
        char spec[340];
        ASSERT(snprintf(spec, sizeof(spec), "%s:1:1", lease) > 0);
        pid_t shell = pge_spawn_leased(launcher, spec, sup, child,
                                       "trap '' TERM; while :; do sleep 0.1; done");
        ASSERT(shell > 0);
        pid_t supervisor = 0, fixture = 0;
        ASSERT(pge_wait_file(sup, &supervisor));
        ASSERT(pge_wait_file(child, &fixture));
        ASSERT(pge_alive(fixture));
        int code = -1, sig = 0;
        ASSERT(pge_wait_status(shell, 8, &code, &sig));
        /* The escalation SIGKILL takes the whole group, supervisor included:
         * the shell's wait reports the launcher as SIGKILLed. */
        ASSERT(sig == SIGKILL || code == 128 + SIGKILL);
        ASSERT(pge_wait_gone(fixture, 3));
        unlink(lease); unlink(sup); unlink(child); rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_lease_passes_through_child_exit(void)
{
    int failures = 0;
    TEST("process-group-exec: a leased child that exits by itself passes "
         "its status through") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_lease_exit_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char lease[300], sup[300], child[300];
        ASSERT(snprintf(lease, sizeof(lease), "%s/lease", dir) > 0);
        ASSERT(snprintf(sup, sizeof(sup), "%s/sup", dir) > 0);
        ASSERT(snprintf(child, sizeof(child), "%s/child", dir) > 0);
        ASSERT(pge_touch(lease));
        char spec[340];
        ASSERT(snprintf(spec, sizeof(spec), "%s:30", lease) > 0);
        pid_t shell = pge_spawn_leased(launcher, spec, sup, child,
                                       "sleep 0.5; exit 9");
        ASSERT(shell > 0);
        int code = -1, sig = 0;
        ASSERT(pge_wait_status(shell, 6, &code, &sig));
        ASSERT(code == 9);
        unlink(lease); unlink(sup); unlink(child); rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_lease_bad_spec_fails_closed(void)
{
    int failures = 0;
    TEST("process-group-exec: a malformed lease spec is a usage error, and "
         "nothing launches") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char dir[] = "test-tmp/pge_lease_bad_XXXXXX";
        ASSERT(mkdtemp(dir) != NULL);
        char lease[300];
        ASSERT(snprintf(lease, sizeof(lease), "%s/lease", dir) > 0);
        /* Specs derived from this run's own scratch dir — every malformed
         * shape the parser must refuse, with no bare /tmp literal. */
        char specs[10][340];
        ASSERT(snprintf(specs[0], sizeof(specs[0]), "%s/no-colon-here", dir) > 0);
        ASSERT(snprintf(specs[1], sizeof(specs[1]), "%s:0", lease) > 0);
        ASSERT(snprintf(specs[2], sizeof(specs[2]), "%s:abc", lease) > 0);
        ASSERT(snprintf(specs[3], sizeof(specs[3]), "%s:5:x", lease) > 0);
        ASSERT(snprintf(specs[4], sizeof(specs[4]), "%s:5:6:7", lease) > 0);
        ASSERT(snprintf(specs[5], sizeof(specs[5]), ":5") > 0);
        /* strtol clamps out-of-range fields to LONG_MAX with errno=ERANGE;
         * the parser must refuse both the clamp and any in-range value
         * that would overflow reap_leased_group's grace_s * 5. */
        ASSERT(snprintf(specs[6], sizeof(specs[6]), "%s:5:99999999999999999999",
                        lease) > 0);
        ASSERT(snprintf(specs[7], sizeof(specs[7]), "%s:5:%ld",
                        lease, LONG_MAX) > 0);
        ASSERT(snprintf(specs[8], sizeof(specs[8]), "%s:99999999999999999999:1",
                        lease) > 0);
        ASSERT(snprintf(specs[9], sizeof(specs[9]), "%s:5:%ld",
                        lease, LONG_MAX / 5 + 1) > 0);
        for (size_t i = 0; i < 10; i++) {
            char line[1024];
            int n = snprintf(line, sizeof(line),
                             "'%s' --die-with-lease='%s' true 2>&1",
                             launcher, specs[i]);
            ASSERT(n > 0 && (size_t)n < sizeof(line));
            FILE *p = popen(line, "r");
            ASSERT(p != NULL);
            while (fgets(line, sizeof(line), p)) {
            }
            int rc = pclose(p);
            ASSERT(rc != 0);
            ASSERT(WIFEXITED(rc) && WEXITSTATUS(rc) == 2);
        }
        rmdir(dir);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_lease_long_stale_accepted(const char *suffix, const char *name)
{
    int failures = 0;
    char dir[] = "test-tmp/pge_lease_long_XXXXXX";
    char lease[300] = "";
    TEST(name) {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        ASSERT(mkdtemp(dir) != NULL);
        int n = snprintf(lease, sizeof(lease), "%s/lease", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(lease));
        FILE *fixture = fopen(lease, "w");
        ASSERT(fixture != NULL);
        ASSERT_EQ(fclose(fixture), 0);
        char line[1024];
        n = snprintf(line, sizeof(line),
                     "'%s' --die-with-lease='%s:%031d1%s' 2>&1",
                     launcher, lease, 0, suffix);
        ASSERT(n > 0 && (size_t)n < sizeof(line));
        /* A parsed spec reaches the missing-command check before supervision. */
        FILE *p = popen(line, "r");
        ASSERT(p != NULL);
        bool got_line = fgets(line, sizeof(line), p) != NULL;
        int rc = pclose(p);
        ASSERT(got_line);
        ASSERT(WIFEXITED(rc) && WEXITSTATUS(rc) == 2);
        ASSERT(strstr(line, "needs COMMAND") != NULL);
        ASSERT(strstr(line, "bad lease spec") == NULL);
        PASS();
    }
    _test_next:;
    if (lease[0])
        (void)unlink(lease);
    (void)rmdir(dir);
    return failures;
}

static int test_unknown_flag_fails_closed(void)
{
    int failures = 0;
    TEST("process-group-exec: an unknown flag is a usage error, never an "
         "executed filename") {
        const char *launcher = pge_launcher();
        ASSERT(launcher != NULL);
        char line[512];
        int n = snprintf(line, sizeof(line), "'%s' --bogus-flag true",
                         launcher);
        ASSERT(n > 0 && (size_t)n < sizeof(line));
        FILE *p = popen(line, "r");
        ASSERT(p != NULL);
        while (fgets(line, sizeof(line), p)) {
        }
        int rc = pclose(p);
        ASSERT(rc != 0);
        int exit_code = WEXITSTATUS(rc);
        ASSERT_EQ(exit_code, 2);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_process_group_exec(void)
{
    int failures = 0;
    failures += test_die_with_parent_reaps_fixture();
    failures += test_plain_setsid_survives();
    failures += test_lease_stale_reaps_group();
    failures += test_lease_fresh_survives_and_cleanup_terminates();
    failures += test_lease_missing_reaps();
    failures += test_lease_grace_escalates_to_kill();
    failures += test_lease_passes_through_child_exit();
    failures += test_lease_bad_spec_fails_closed();
    failures += test_lease_long_stale_accepted("",
        "process-group-exec: long leading-zero stale parses without grace");
    failures += test_lease_long_stale_accepted(":1",
        "process-group-exec: long leading-zero stale parses with grace");
    failures += test_unknown_flag_fails_closed();
    return failures;
}

#else /* _WIN32 */

int test_process_group_exec(void)
{
    int failures = 0;
    TEST("process-group-exec: POSIX parent-death legs covered by the "
         "Windows Job Object acceptance") {
        printf("  SKIP (process-group-exec posix legs) windows host runs "
               "the job-object acceptance binary\n");
        PASS();
    }
    _test_next:;
    return failures;
}

#endif
