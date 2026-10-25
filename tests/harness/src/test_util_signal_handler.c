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
#if defined(__APPLE__)
#include "config/boot.h"
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include <sys/mman.h>
#endif


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

#if defined(__APPLE__)
/* A real-Tor link resolves this symbol; an offline stub has no error
 * subsystem to test. Do not start Tor or touch network/canonical state. */
extern int configure_backtrace_handler(const char *) __attribute__((weak_import));

static int test_darwin_embedded_signal_ownership(void)
{
    int failures = 0;
    if (!app_tor_real_build_linked()) {
        printf("util_signal_handler: SKIP embedded ownership (offline Tor stub)\n");
        return 0;
    }
    TEST("Darwin real Tor error initialization preserves fatal ownership") {
        ASSERT(configure_backtrace_handler != NULL);
        fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            alarm(5);
            if (signal_handler_install() != 0) _exit(70);
            const int signals[] = {SIGABRT, SIGSEGV, SIGBUS, SIGFPE};
            struct sigaction before[4];
            for (size_t i = 0; i < 4; i++)
                if (sigaction(signals[i], NULL, &before[i]) != 0) _exit(71);
            if (configure_backtrace_handler("embedding-test") != 0) _exit(72);
            for (size_t i = 0; i < 4; i++) {
                struct sigaction after;
                if (sigaction(signals[i], NULL, &after) != 0 ||
                    after.sa_sigaction != before[i].sa_sigaction ||
                    after.sa_flags != before[i].sa_flags) _exit(73);
            }
            _exit(0);
        }
        int status = 0;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Each level must survive optimization: the volatile post-call operation
 * prevents tail calls. These are real captured frames, not manufactured PCs. */
static volatile sig_atomic_t darwin_call_returned;
__attribute__((noinline)) static void darwin_crash_leaf(void)
{
    raise(SIGABRT);
    darwin_call_returned++;
}
__attribute__((noinline)) static void darwin_crash_middle(void)
{
    darwin_crash_leaf();
    darwin_call_returned++;
}
static void *darwin_crash_worker(void *arg)
{
    (void)arg;
    stack_t ss;
    if (sigaltstack(NULL, &ss) != 0 || (ss.ss_flags & SS_DISABLE))
        _exit(61);
    darwin_crash_middle();
    return NULL;
}

static int test_darwin_worker_crash(void)
{
    int failures = 0;
    TEST("Darwin registry worker: private altstack and real fatal frames") {
        int output[2];
        ASSERT_EQ(pipe(output), 0);
        fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            close(output[0]);
            if (dup2(output[1], STDERR_FILENO) < 0) _exit(60);
            close(output[1]);
            alarm(5);
            if (signal_handler_install() != 0) _exit(62);
            pthread_t worker;
            if (thread_registry_spawn("fatal-frame-test", darwin_crash_worker,
                                      NULL, &worker) != 0) _exit(63);
            pthread_join(worker, NULL);
            _exit(64);
        }
        close(output[1]);
        int status = 0;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        char report[8192];
        ssize_t bytes = read(output[0], report, sizeof(report) - 1);
        close(output[0]);
        ASSERT(bytes > 0);
        report[bytes] = '\0';
        ASSERT(WIFSIGNALED(status));
        ASSERT_EQ(WTERMSIG(status), SIGABRT);
        ASSERT(strstr(report, "[fatal-signal] end") != NULL);
        int real_frames = 0;
        for (const char *p = report; (p = strstr(p, "frame 0x")) != NULL; p += 8)
            real_frames++;
        ASSERT(real_frames >= 3);
        PASS();
    } _test_next:;
    return failures;
}

static void darwin_invalid_frame_signal(int sig, siginfo_t *info, void *raw)
{
    (void)sig;
    (void)info;
    ucontext_t *uc = raw;
#if defined(__aarch64__)
    __darwin_arm_thread_state64_set_fp(uc->uc_mcontext->__ss, UINTPTR_MAX);
#elif defined(__x86_64__)
    uc->uc_mcontext->__ss.__rbp = UINTPTR_MAX;
#endif
    void *frames[4];
    size_t count = signal_handler_capture_frames(raw, frames, 4);
    /* The interrupted instruction is real; no invalid frame may be read. */
    _exit(count == 1 && frames[0] != NULL &&
          signal_handler_capture_frames(raw, frames, 0) == 0 ? 0 : 65);
}

static int test_darwin_malformed_frame(void)
{
    int failures = 0;
    TEST("Darwin invalid saved frame pointer stops at the interrupted PC") {
        fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            alarm(5);
            if (signal_handler_thread_prepare() != 0) _exit(66);
            struct sigaction sa = {.sa_sigaction = darwin_invalid_frame_signal,
                                  .sa_flags = SA_SIGINFO | SA_ONSTACK};
            sigemptyset(&sa.sa_mask);
            if (sigaction(SIGUSR1, &sa, NULL) != 0) _exit(67);
            raise(SIGUSR1);
            _exit(68);
        }
        int status = 0;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;
    return failures;
}

static void darwin_foreign_signal(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    void *frames[64];
    _exit(signal_handler_capture_frames(context, frames, 64) == 1 ? 0 : 74);
}

static void *darwin_foreign_thread(void *arg)
{
    (void)arg;
    raise(SIGUSR2);
    _exit(75);
}

static int test_darwin_foreign_thread(void)
{
    int failures = 0;
    TEST("Darwin unregistered pthread captures PC only without lazy TLS setup") {
        fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) {
            alarm(5);
            if (signal_handler_install() != 0) _exit(76);
            struct sigaction sa = {.sa_sigaction = darwin_foreign_signal,
                                  .sa_flags = SA_SIGINFO};
            sigemptyset(&sa.sa_mask);
            if (sigaction(SIGUSR2, &sa, NULL) != 0) _exit(77);
            pthread_t foreign;
            if (pthread_create(&foreign, NULL, darwin_foreign_thread, NULL) != 0)
                _exit(78);
            pthread_join(foreign, NULL);
            _exit(79);
        }
        int status = 0;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;
    return failures;
}

static void *darwin_unreadable_frame;

static void darwin_unreadable_hook(int sig, zcl_signal_info_t *info,
                                    void *context, void *arg)
{
    (void)sig;
    (void)info;
    (void)arg;
    ucontext_t *uc = context;
#if defined(__aarch64__)
    __darwin_arm_thread_state64_set_fp(uc->uc_mcontext->__ss,
                                      darwin_unreadable_frame);
#elif defined(__x86_64__)
    uc->uc_mcontext->__ss.__rbp = (uintptr_t)darwin_unreadable_frame;
#endif
}

static void darwin_unreadable_child(const int output[2], const char *durable_path)
{
    close(output[0]);
    if (dup2(output[1], STDERR_FILENO) < 0) _exit(80);
    close(output[1]);
    alarm(5);
    if (signal_handler_install() != 0) _exit(81);
    signal_handler_set_crash_log(durable_path);
    long native_page = sysconf(_SC_PAGESIZE);
    if (native_page <= 0) _exit(82);
    uintptr_t page = (uintptr_t)native_page;
    pthread_t self = pthread_self();
    uintptr_t high = (uintptr_t)pthread_get_stackaddr_np(self);
    size_t bytes = pthread_get_stacksize_np(self);
    uintptr_t current = (uintptr_t)&self;
    if (bytes < 32 * page || high < bytes) _exit(83);
    uintptr_t low = high - bytes;
    uintptr_t protected_page = (low + 8 * page + page - 1) / page * page;
    /* This page is deep inside the stack allocation, well below current
     * frames; the handler uses an independent alternate stack. Child only. */
    if (protected_page < low || protected_page + 17 * page >= current ||
        protected_page + page >= high) _exit(84);
    if (mprotect((void *)protected_page, (size_t)page, PROT_NONE) != 0)
        _exit(85);
    darwin_unreadable_frame = (void *)protected_page;
    signal_handler_set_crash_hook(darwin_unreadable_hook, NULL);
    raise(SIGABRT);
    _exit(86);
}

static int test_darwin_unreadable_frame(void)
{
    int failures = 0;
    TEST("Darwin unreadable in-range FP preserves marker and PC before fail-stop") {
        mkdir("./test-tmp", 0700);
        char durable_path[256];
        snprintf(durable_path, sizeof(durable_path),
                 "./test-tmp/sighandler_unreadable_%d.log", (int)getpid());
        unlink(durable_path);
        int output[2];
        ASSERT_EQ(pipe(output), 0);
        fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            darwin_unreadable_child(output, durable_path);
        close(output[1]);
        int status = 0;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        char report[4096];
        ssize_t bytes = read(output[0], report, sizeof(report) - 1);
        close(output[0]);
        ASSERT(bytes > 0);
        report[bytes] = '\0';
        ASSERT(WIFSIGNALED(status));
        ASSERT(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
        const char *marker = strstr(report, "[fatal-signal] sig=6");
        const char *pc = strstr(report, "frame 0x");
        ASSERT(marker != NULL && pc != NULL && marker < pc);
        /* No completion marker: stack read faulted after primary evidence. */
        ASSERT(strstr(report, "[fatal-signal] end") == NULL);
        FILE *durable = fopen(durable_path, "r");
        ASSERT(durable != NULL);
        size_t length = fread(report, 1, sizeof(report) - 1, durable);
        fclose(durable);
        report[length] = '\0';
        marker = strstr(report, "[fatal-signal] sig=6");
        pc = strstr(report, "frame 0x");
        ASSERT(marker != NULL && pc != NULL && marker < pc);
        ASSERT(strstr(report, "[fatal-signal] end") == NULL);
        unlink(durable_path);
        PASS();
    } _test_next:;
    return failures;
}
#endif

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
            alarm(5);
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
#if defined(__APPLE__)
    failures += test_darwin_embedded_signal_ownership();
    failures += test_darwin_worker_crash();
    failures += test_darwin_malformed_frame();
    failures += test_darwin_foreign_thread();
    failures += test_darwin_unreadable_frame();
#endif
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
