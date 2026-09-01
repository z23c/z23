/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression lock for the PRODUCTION fatal-signal handler in
 * platform/modules/util/src/signal_handler.c (fatal_handler / signal_handler_install /
 * signal_handler_set_crash_log), installed live at engine/composition/src/boot.c:527
 * and given a durable crash log at engine/composition/src/boot.c:595.
 *
 * This handler is DISTINCT from the event.c twin (marker "FATAL SIGNAL N",
 * which _exit()s). The boot-installed handler:
 *   (a) emits "[fatal-signal] sig=N ..." + a backtrace_symbols_fd dump to
 *       stderr via async-signal-safe write(2);
 *   (b) MIRRORS the same report to the durable fsync'd crash log opened by
 *       signal_handler_set_crash_log() (signal_handler.c:131-134);
 *   (c) restores SIG_DFL and RE-RAISES (signal_handler.c:140-144), so the
 *       process dies FROM the signal (systemd sees status 128+N) rather than
 *       _exit()'ing — this is the property the event.c twin does NOT have.
 *
 * Until now grep over tests/harness/include/test/ for signal_handler_install / fatal_handler /
 * signal_handler_set_crash_log was EMPTY: this live handler was untested.
 *
 * Idiom mirrors test_event.c:test_crash_handler_stderr_survives_exit and
 * test_postmortem.c: fork, redirect the child's stderr to a temp file, install
 * the handler, raise(SIGABRT), then in the parent assert WIFSIGNALED +
 * WTERMSIG==SIGABRT (proves re-raise, NOT _exit) and scan both the stderr file
 * and the durable crash-log file for the exact marker + >=3 hex frames.
 *
 * Each TEST{} block lives in its own static helper (test_event.c composition
 * pattern): the shared ASSERT macro hardcodes `goto _test_next;`, so a single
 * function cannot host two TEST{} blocks without a duplicate label. */

/* sigaltstack()/SS_DISABLE are XSI/GNU — match the production handler TU
 * (platform/modules/util/src/signal_handler.c:5), which defines _GNU_SOURCE before any
 * include so <signal.h> exposes the alternate-stack API. */
#define _GNU_SOURCE
#include "test/test_core.h"
#include "util/signal_handler.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>

/* Count distinct "0x" hex runs — same metric the event.c twin uses to prove
 * backtrace_symbols_fd emitted real frame addresses ([0x...] / +0x...). */
static int count_hex_frames(const char *buf)
{
    int hits = 0;
    for (const char *p = buf; (p = strstr(p, "0x")) != NULL; ) {
        hits++;
        p += 2;  /* advance past "0x" to avoid an infinite loop */
    }
    return hits;
}

/* Slurp up to cap-1 bytes of a file into buf (NUL-terminated). Returns bytes
 * read, or -1 if the file could not be opened. */
static long slurp_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (long)n;
}

/* The production handler restores SIG_DFL and re-raises, so the child must
 * die FROM SIGABRT (status 128+6), AND leave the marker + backtrace in BOTH
 * the redirected stderr and the durable fsync'd crash log. */
static int test_reraise_and_durable_mirror(void)
{
    int failures = 0;

    TEST("signal_handler: re-raise + marker + >=3 frames in stderr AND crash log") {
        mkdir("./test-tmp", 0700);
        char stderr_path[256];
        char durable_path[256];
        snprintf(stderr_path, sizeof(stderr_path),
                 "./test-tmp/sighandler_stderr_%d.log", (int)getpid());
        snprintf(durable_path, sizeof(durable_path),
                 "./test-tmp/sighandler_durable_%d.log", (int)getpid());
        unlink(stderr_path);
        unlink(durable_path);

        /* Drain inherited stdio so the post-fork child does not re-emit it. */
        fflush(stdout);
        fflush(stderr);

        pid_t pid = fork();
        ASSERT(pid >= 0);

        if (pid == 0) {
            /* CHILD. Open the durable crash log FIRST so the handler's mirror
             * branch (signal_handler.c:131) has a valid g_crash_fd. */
            signal_handler_set_crash_log(durable_path);

            /* Redirect stderr to the temp file before the handler writes. */
            int fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) _exit(42);
            dup2(fd, STDERR_FILENO);
            close(fd);
            /* Silence stdout noise from the child. */
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDOUT_FILENO); close(dn); }

            /* Install AFTER the fork so the parent's disposition is untouched
             * (a later parent-side SIGABRT must not hit this handler). */
            if (signal_handler_install() != 0) _exit(43);

            /* Trigger. The handler must emit, mirror+fsync, restore SIG_DFL,
             * and re-raise -> this process dies from SIGABRT here. */
            raise(SIGABRT);

            /* If we reach here the handler failed to re-raise (a real bug):
             * exit with a distinct code so the parent surfaces it clearly. */
            _exit(99);
        }

        int status = 0;
        pid_t done = waitpid(pid, &status, 0);
        ASSERT(done == pid);

        /* (c) Re-raise, NOT _exit: the child must be SIGNALLED by SIGABRT.
         * If it _exited, WIFSIGNALED is false and this fires — exactly the
         * mutation we want to catch (e.g. someone swapping raise() for _exit). */
        ASSERT(WIFSIGNALED(status));
        ASSERT_EQ(WTERMSIG(status), SIGABRT);

        /* (a) stderr branch: exact marker for sig=6 + a real backtrace. */
        char buf[8192];
        long n = slurp_file(stderr_path, buf, sizeof(buf));
        ASSERT(n > 0);
        ASSERT(strstr(buf, "[fatal-signal] sig=6") != NULL);
        ASSERT(strstr(buf, "[fatal-signal] end") != NULL);
        ASSERT(count_hex_frames(buf) >= 3);

        /* (b) durable mirror branch: the fsync'd crash log carries the SAME
         * marker (proves the g_crash_fd >= 0 mirror at signal_handler.c:132
         * actually ran and survived the hard death). */
        char dbuf[8192];
        long dn2 = slurp_file(durable_path, dbuf, sizeof(dbuf));
        ASSERT(dn2 > 0);
        ASSERT(strstr(dbuf, "[fatal-signal] sig=6") != NULL);
        ASSERT(count_hex_frames(dbuf) >= 3);

        unlink(stderr_path);
        unlink(durable_path);
        PASS();
    } _test_next:;

    return failures;
}

/* SA_ONSTACK structural lock: signal_handler_install() must register an
 * alternate signal stack (signal_handler.c:151-157), otherwise a real
 * stack-overflow SIGSEGV cannot run the handler. We do NOT trigger a real
 * overflow (non-deterministic — the compiler may TCO the recursion, ASAN
 * installs its own SEGV handler, etc.); instead we install in a forked child
 * and assert sigaltstack() now reports a non-disabled, non-empty alt stack.
 * This catches removal of the sigaltstack() call or of SA_ONSTACK. */
static int test_install_alt_stack(void)
{
    int failures = 0;

    TEST("signal_handler: install registers a non-empty alt signal stack (SA_ONSTACK basis)") {
        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            if (signal_handler_install() != 0) _exit(43);
            stack_t cur;
            memset(&cur, 0, sizeof(cur));
            if (sigaltstack(NULL, &cur) != 0) _exit(44);
            if (cur.ss_flags & SS_DISABLE) _exit(45);  /* alt stack must be enabled */
            if (cur.ss_sp == NULL || cur.ss_size == 0) _exit(46);  /* and real */
            _exit(0);
        }
        int status = 0;
        pid_t done = waitpid(pid, &status, 0);
        ASSERT(done == pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;

    return failures;
}

/* SIGPIPE is ordinary I/O backpressure, not a node-fatal crash class. The
 * process-level handler install must ignore it so one missed MSG_NOSIGNAL
 * cannot terminate the node without a postmortem. */
static int test_install_ignores_sigpipe(void)
{
    int failures = 0;

    TEST("signal_handler: install ignores SIGPIPE") {
        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            if (signal_handler_install() != 0) _exit(43);
            if (raise(SIGPIPE) != 0) _exit(44);
            _exit(0);
        }
        int status = 0;
        pid_t done = waitpid(pid, &status, 0);
        ASSERT(done == pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;

    return failures;
}

static volatile sig_atomic_t g_termination_hits;

static void test_termination_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        g_termination_hits++;
}

static void test_displacing_handler(int sig)
{
    (void)sig;
    _exit(91);
}

/* Embedded runtimes share the process signal table. Prove the node can reclaim
 * SIGINT/SIGTERM after a later initializer displaces them, and that the
 * reclaimed sigaction is persistent rather than System-V one-shot. */
static int test_termination_handler_reclaim(void)
{
    int failures = 0;

    TEST("signal_handler: node reclaims persistent termination ownership") {
        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            g_termination_hits = 0;
            if (signal_handler_install_termination(
                    test_termination_handler) != 0)
                _exit(43);

            struct sigaction displaced;
            memset(&displaced, 0, sizeof(displaced));
            displaced.sa_handler = test_displacing_handler;
            sigemptyset(&displaced.sa_mask);
            if (sigaction(SIGINT, &displaced, NULL) != 0 ||
                sigaction(SIGTERM, &displaced, NULL) != 0)
                _exit(44);

            /* Composition-root reclaim after embedded runtime init. */
            if (signal_handler_install_termination(
                    test_termination_handler) != 0)
                _exit(45);
            if (raise(SIGTERM) != 0 || raise(SIGTERM) != 0 ||
                raise(SIGINT) != 0)
                _exit(46);
            if (g_termination_hits != 3)
                _exit(47);
            _exit(0);
        }

        int status = 0;
        pid_t done = waitpid(pid, &status, 0);
        ASSERT(done == pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_util_signal_handler_platform_arm(void)
{
    printf("\n=== util/signal_handler tests ===\n");

    /* Monolith isolation (test_zcl shares one address space): a prior group
     * may leave the node fatal-signal handlers armed or SA_NOCLDWAIT set on
     * SIGCHLD, which would make the children below NOT reap cleanly. Restore
     * the SIG_DFL baseline before forking. */
    test_reset_shared_globals();

    int failures = 0;
    failures += test_reraise_and_durable_mirror();
    failures += test_install_alt_stack();
    failures += test_install_ignores_sigpipe();
    failures += test_termination_handler_reclaim();

    if (failures == 0)
        printf("=== util/signal_handler tests: ALL PASS ===\n\n");
    else
        printf("util/signal_handler: failures=%d\n", failures);
    return failures;
}
#else  /* _WIN32 */
/* Every case in this group installs or exercises a POSIX fatal-signal
 * disposition (sigaction, signal alt stacks, SIGCHLD/SA_NOCLDWAIT semantics)
 * in a forked child — none of which has a Windows analogue. */
static int test_util_signal_handler_platform_arm(void)
{
    printf("util_signal_handler: SKIP (Windows): POSIX signal-disposition "
           "+ fork lane (sigaction/altstack/SIGCHLD) does not exist here\n");
    return 0;
}
#endif

int test_util_signal_handler(void)
{
    return test_util_signal_handler_platform_arm();
}
