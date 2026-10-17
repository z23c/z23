/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Live acceptance for the confined terminal worker (mesh_terminal_worker):
 * spawn the granted fbsh on a PTY inside its cage and drive it the way the
 * mesh serving layer will — keyboard in, screen out, resize, budgets, and
 * every ending named. The budget cases are the heart: lifetime and idle
 * are enforced with an INJECTED clock (no sleeping on the harness), the
 * byte budgets bite on real frames, and every kill is proven complete by
 * the process-group census returning to zero.
 *
 * Marker discipline: command markers are written quote-split
 * (Z23TER"M"_OK) so the PTY's echo of the raw typed line can never match
 * the executed output (Z23TERM_OK) — a shell that dies before executing
 * cannot fake a pass.
 *
 * fbsh cases SKIP (never fail) when build/bin/fbsh is absent, mirroring
 * test_freebsd_sh and test_terminal_worker_sandbox.
 */

#define _GNU_SOURCE /* pthread/posix bits, if any — must precede includes */

#if defined(__linux__)
#define mesh_terminal_win_env_name tw_fixture_win_env_name
#define mesh_terminal_worker_error_string tw_fixture_error_string
#define mesh_terminal_worker_budget_would_overrun tw_fixture_budget_overrun
#define mesh_terminal_worker_spawn tw_fixture_spawn
#define mesh_terminal_worker_input tw_fixture_input
#define mesh_terminal_worker_output tw_fixture_output
#define mesh_terminal_worker_output_wait_handle tw_fixture_output_wait_handle
#define mesh_terminal_worker_begin_output_close tw_fixture_begin_output_close
#define mesh_terminal_worker_close_wait_handle tw_fixture_close_wait_handle
#define mesh_terminal_worker_budget_wait_handle tw_fixture_budget_wait_handle
#define mesh_terminal_worker_resize tw_fixture_resize
#define mesh_terminal_worker_budget_exceeded tw_fixture_budget_exceeded
#define mesh_terminal_worker_alive tw_fixture_alive
#define mesh_terminal_worker_kill tw_fixture_kill
#define mesh_terminal_worker_testing_order tw_fixture_order
#endif

#include "test/test_core.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#include "session/mesh_terminal_worker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define FBSH_BIN "build/bin/fbsh"

#if defined(__linux__)
#include <dirent.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <signal.h>
#include "platform/os_proc.h"
#include "../../../platform/modules/platform/src/os_proc_fdclose_internal.h"
enum tw_signal_fault { TW_SIGNAL_OK, TW_SIGNAL_BLOCK, TW_SIGNAL_FORK,
                       TW_SIGNAL_RESET, TW_SIGNAL_PARENT_RESTORE };
static enum tw_signal_fault tw_signal_fault;
static bool tw_signal_observe;
static pid_t tw_signal_parent, tw_signal_child;
static unsigned tw_mask_sets;
static volatile sig_atomic_t tw_caught_calls;

static void tw_caught_handler(int number)
{
    (void)number;
    tw_caught_calls++;
}

/* Faults wrap actual source calls in this test twin, not a production hook. */
static int tw_signal_sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
    if (tw_signal_observe && getpid() == tw_signal_parent && set) {
        ++tw_mask_sets;
        if ((tw_signal_fault == TW_SIGNAL_BLOCK && tw_mask_sets == 1) ||
            (tw_signal_fault == TW_SIGNAL_PARENT_RESTORE && tw_mask_sets == 2)) {
            errno = EIO;
            return -1;
        }
    }
    return sigprocmask(how, set, old);
}

static int tw_signal_sigaction(int number, const struct sigaction *action,
                                struct sigaction *old)
{
    if (tw_signal_observe && getpid() != tw_signal_parent &&
        tw_signal_fault == TW_SIGNAL_RESET && number == SIGUSR1 && action) {
        errno = EIO;
        return -1;
    }
    return sigaction(number, action, old);
}

static pid_t tw_signal_fork(void)
{
    if (tw_signal_observe && tw_signal_fault == TW_SIGNAL_FORK) {
        errno = EAGAIN;
        return -1;
    }
    pid_t pid = fork();
    if (tw_signal_observe && pid > 0) tw_signal_child = pid;
    return pid;
}

/* Called only inside the real forked terminal child at the closure seam. */
static bool tw_signal_state_at_closure(void)
{
    if (!tw_signal_observe) return true;
    sigset_t mask;
    struct sigaction caught, ignored;
    return sigprocmask(SIG_SETMASK, NULL, &mask) == 0 &&
        sigismember(&mask, SIGUSR1) == 1 && sigismember(&mask, SIGUSR2) == 1 &&
        sigaction(SIGUSR1, NULL, &caught) == 0 && caught.sa_handler == SIG_DFL &&
        sigaction(SIGUSR2, NULL, &ignored) == 0 && ignored.sa_handler == SIG_IGN;
}

/* The production terminal caller is compiled below. This test-only wrapper
 * selects the real platform fallback without modifying the kernel or rail. */
static bool tw_force_fd_fallback;
static bool tw_scrub_for_test(int report)
{
    if (!tw_signal_state_at_closure()) return false;
    if (!tw_force_fd_fallback) return os_proc_close_inherited_fds_except(report);
    struct stat st;
    if (report <= 2 || fstat(report, &st) != 0) return false;
    const int keep[] = {0, 1, 2, report};
    return os_proc_linux_close_fds_kept(keep, 4u, false);
}
static bool partial_active;
static unsigned partial_writes, partial_polls;
static ssize_t partial_write(int fd, const void *buf, size_t n)
{
    if (!partial_active) return write(fd, buf, n);
    if (++partial_writes == 1) return write(fd, buf, n < 3 ? n : 3);
    errno = EAGAIN;
    return -1;
}
static int partial_poll(struct pollfd *fds, nfds_t n, int timeout)
{
    if (!partial_active) return poll(fds, n, timeout);
    ++partial_polls;
    return 0;
}
static int partial_kill(pid_t pid, int sig)
{
    if (!partial_active) return kill(pid, sig);
    return 0;
}
static bool tw_interrupt_wait;
static unsigned tw_blocking_calls;
static pid_t tw_waited_pid;
static struct mesh_terminal_worker *tw_waiting_worker;
static bool tw_owned_on_retry;
static pid_t tw_fixture_waitpid(pid_t pid, int *status, int options)
{
    if (partial_active) { *status = 0; return pid; }
    if (!tw_interrupt_wait) return waitpid(pid, status, options);
    if (options == WNOHANG) return 0;
    tw_waited_pid = pid;
    if (++tw_blocking_calls == 1) { errno = EINTR; return -1; }
    tw_owned_on_retry = !tw_waiting_worker || tw_waiting_worker->running;
    return waitpid(pid, status, options);
}
/* Compile the production callers with deterministic syscall observations. */
#define sigprocmask tw_signal_sigprocmask
#define sigaction(...) tw_signal_sigaction(__VA_ARGS__)
#define fork tw_signal_fork
#define os_proc_close_inherited_fds_except tw_scrub_for_test
#define write partial_write
#define poll partial_poll
#define kill partial_kill
#define waitpid tw_fixture_waitpid
#include "../../../cognition/modules/session/src/mesh_terminal_worker.c"
#undef sigprocmask
#undef sigaction
#undef fork
#undef os_proc_close_inherited_fds_except
#undef waitpid
#undef kill
#undef poll
#undef write
#endif

static char g_dir[160];
static char g_fbsh[600];

/* Budgets used by the live cases: 4 KiB in, 64 KiB out, 60 s lifetime,
 * 30 s idle. Individual cases override the one under test. */
static void live_config(struct mesh_terminal_worker_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->shell_path = g_fbsh;
    cfg->workdir = g_dir;
    cfg->cols = 80;
    cfg->rows = 24;
    cfg->max_bytes_in = 4096;
    cfg->max_bytes_out = 65536;
    cfg->lifetime_seconds = 60;
    cfg->idle_seconds = 30;
}

static int check(int failures, bool ok, const char *label);

#if defined(__linux__)

static int partial_input_effects(void)
{
    int failures = 0, fds[2];
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0)
        return check(failures, false, "partial input pipe setup");
    struct mesh_terminal_worker w = { .pid = 1, .pgid = 1,
        .master_fd = fds[1], .running = true, .max_bytes_in = 8,
        .last_activity_unix = 10 };
    const uint8_t bytes[] = "abcdefgh";
    partial_active = true;
    partial_writes = partial_polls = 0;
    struct zcl_result r = mesh_terminal_worker_input(&w, bytes, 8, 20);
    failures = check(failures, !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_IO,
                     "partial input reports stalled IO");
    failures = check(failures, w.bytes_in == 3 && w.last_activity_unix == 20 && w.running,
                     "partial input charges accepted prefix and activity");
    uint8_t got[8];
    failures = check(failures, read(fds[0], got, sizeof got) == 3 &&
                     memcmp(got, bytes, 3) == 0 && partial_writes == 2 && partial_polls == 1,
                     "partial input transfers exactly three bytes before timeout");
    r = mesh_terminal_worker_input(&w, bytes, 6, 30);
    failures = check(failures, !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
                     partial_writes == 2 && w.bytes_in == 3 && w.last_activity_unix == 20,
                     "partial input retry refused before another write");
    mesh_terminal_worker_kill(&w);
    partial_active = false;
    close(fds[0]);
    return failures;
}

/* Drain worker output into a rolling buffer until `needle` appears or the
 * deadline passes. Returns true when found. `err` (optional) captures a
 * terminal worker error (BYTE_LIMIT ends the output-budget case with the
 * needle possibly never arriving). On failure the caller can print `saw`. */
static bool drain_until(struct mesh_terminal_worker *w, const char *needle,
                        int timeout_seconds, struct zcl_result *err,
                        char *saw, size_t saw_cap)
{
    char rolling[MESH_TERMINAL_WORKER_IO_CHUNK + 1];
    size_t cap = sizeof rolling - 1;
    size_t fill = 0;
    rolling[0] = '\0';
    time_t deadline = platform_time_wall_time_t() + timeout_seconds;
    while (platform_time_wall_time_t() < deadline) {
        uint8_t chunk[MESH_TERMINAL_WORKER_IO_CHUNK];
        size_t n = 0;
        struct zcl_result r = mesh_terminal_worker_output(
            w, chunk, sizeof chunk, &n,
            (int64_t)platform_time_wall_time_t());
        if (!r.ok && r.code != MESH_TERMINAL_WORKER_ERR_NONE) {
            if (err) *err = r;
            break;
        }
        if (n > 0) {
            size_t append = n;
            if (append > cap)
                append = cap;
            if (fill + append > cap) {
                size_t shift = fill + append - cap;
                if (shift > fill)
                    shift = fill;
                memmove(rolling, rolling + shift, fill - shift);
                fill -= shift;
            }
            memcpy(rolling + fill, chunk, append);
            fill += append;
            rolling[fill] = '\0';
            if (strstr(rolling, needle))
                return true;
            continue;
        }
        usleep(20000);
    }
    if (saw && saw_cap != 0) {
        size_t copy = fill < saw_cap - 1 ? fill : saw_cap - 1;
        memcpy(saw, rolling, copy);
        saw[copy] = '\0';
    }
    return strstr(rolling, needle) != NULL;
}

static bool wait_exit(struct mesh_terminal_worker *w, int timeout_seconds)
{
    time_t deadline = platform_time_wall_time_t() + timeout_seconds;
    while (platform_time_wall_time_t() < deadline) {
        if (!mesh_terminal_worker_alive(w))
            return true;
        usleep(20000);
    }
    return false;
}

#endif

static int check(int failures, bool ok, const char *label)
{
    printf("mesh_terminal_worker: %s... %s\n", label, ok ? "OK" : "FAIL");
    return ok ? failures : failures + 1;
}

#if defined(__linux__)
static int test_interrupted_reaping(void)
{
    int failures = 0, status = 0;
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    failures = check(failures, pid > 0, "reaping fixture fork");
    if (pid < 0) return failures;
    struct mesh_terminal_worker w = {
        .pid = pid, .pgid = pid, .master_fd = -1, .running = true
    };
    tw_interrupt_wait = true;
    tw_blocking_calls = 0;
    tw_waiting_worker = &w;
    tw_owned_on_retry = false;
    mesh_terminal_worker_kill(&w);
    tw_interrupt_wait = false;
    failures = check(failures, tw_blocking_calls >= 2 && tw_owned_on_retry &&
                     !w.running, "kill retries EINTR before releasing ownership");
    pid_t got = waitpid(pid, &status, WNOHANG);
    failures = check(failures, got == -1 && errno == ECHILD,
                     "kill actually reaped the child");
    if (got == 0 && pid > 1) { (void)kill(pid, SIGKILL); (void)tw_wait_settled(pid, &status); }
    return failures;
}
static int test_interrupted_startup_reaping(void)
{
    int failures = 0, status = 0;
    struct mesh_terminal_worker w;
    struct mesh_terminal_worker_config cfg = {
        .shell_path = "/dev/null", .workdir = "/dev/null", .cols = 80,
        .rows = 24, .max_bytes_in = 8, .max_bytes_out = 8, .lifetime_seconds = 1
    };
    tw_waiting_worker = NULL;
    tw_blocking_calls = 0;
    tw_waited_pid = 0;
    tw_interrupt_wait = true;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, 0, &w);
    tw_interrupt_wait = false;
    failures = check(failures, !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG &&
                     !w.running && w.master_fd == -1 && tw_blocking_calls >= 2,
                     "failed startup retries interrupted reap");
    pid_t got = tw_waited_pid > 0 ? waitpid(tw_waited_pid, &status, WNOHANG) : 0;
    failures = check(failures, got == -1 && errno == ECHILD,
                     "failed startup leaves no waitable child");
    if (got == 0 && tw_waited_pid > 0)
        (void)tw_wait_settled(tw_waited_pid, &status);
    return failures;
}
#endif

/* Platform-neutral bookkeeping: geometry_in_bounds and
 * mesh_terminal_worker_budget_would_overrun are pure functions shared by every
 * platform arm (including the Windows ConPTY arm), so no shell or PTY is
 * needed. */
static int test_mesh_terminal_worker_bookkeeping(void)
{
    printf("\n=== mesh terminal worker bookkeeping (platform-neutral) ===\n");
    int failures = 0;

    failures = check(failures, !geometry_in_bounds(0, 24),
                     "geometry: zero cols refused");
    failures = check(failures, !geometry_in_bounds(80, 0),
                     "geometry: zero rows refused");
    failures = check(failures,
                     !geometry_in_bounds(
                         (uint16_t)(MESH_TERMINAL_MAX_COLS + 1), 24),
                     "geometry: cols over proto max refused");
    failures = check(failures,
                     !geometry_in_bounds(
                         80, (uint16_t)(MESH_TERMINAL_MAX_ROWS + 1)),
                     "geometry: rows over proto max refused");
    failures = check(failures,
                     geometry_in_bounds(MESH_TERMINAL_MAX_COLS,
                                        MESH_TERMINAL_MAX_ROWS),
                     "geometry: proto max accepted");
    failures = check(failures, geometry_in_bounds(1, 1),
                     "geometry: 1x1 accepted");

    failures = check(failures,
                     !mesh_terminal_worker_budget_would_overrun(0, 16, 16),
                     "budget: exactly at the cap is not an overrun");
    failures = check(failures,
                     !mesh_terminal_worker_budget_would_overrun(15, 16, 1),
                     "budget: the last byte under the cap fits");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(0, 16, 17),
                     "budget: one byte past an empty cap overruns");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(16, 16, 1),
                     "budget: any byte past an already-full cap overruns");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(17, 16, 0),
                     "budget: already over the cap overruns even on 0 more");
    failures = check(failures,
                     !mesh_terminal_worker_budget_would_overrun(
                         UINT64_MAX - 1, UINT64_MAX, 1),
                     "budget: exact headroom at the top of the range fits "
                     "(no wraparound in max-used)");
    failures = check(failures,
                     mesh_terminal_worker_budget_would_overrun(
                         UINT64_MAX, UINT64_MAX, 1),
                     "budget: no headroom left at the top of the range");

    printf("mesh_terminal_worker bookkeeping: %d failures\n", failures);
    return failures;
}

/* The platform gate: flag off on Windows stays refused; flag on admits
 * Windows with the owner-accepted marker; flag on elsewhere is refused by
 * name; POSIX with the flag off is not gated. */
static int test_mesh_terminal_confinement_gate(void)
{
    const enum mesh_terminal_platform win = MESH_TERMINAL_PLATFORM_WINDOWS;
    const enum mesh_terminal_platform posix = MESH_TERMINAL_PLATFORM_POSIX;
    int failures = 0;
    failures = check(failures,
                     mesh_terminal_confinement_refusal(win, false) != NULL,
                     "windows, flag off: lane refused");
    failures = check(failures,
                     mesh_terminal_confinement_refusal(win, true) == NULL,
                     "windows, flag on: lane admitted");
    failures = check(failures,
                     strcmp(mesh_terminal_confinement_marker(win, true),
                            "unconfined-owner-accepted") == 0,
                     "windows, flag on: owner-accepted marker");
    failures = check(failures,
                     strcmp(mesh_terminal_confinement_marker(win, false),
                            "confined") == 0,
                     "windows, flag off: no unconfined marker");
    failures = check(failures,
                     mesh_terminal_confinement_refusal(posix, true) != NULL,
                     "non-windows, flag on: refused by name");
    failures = check(failures,
                     strcmp(mesh_terminal_confinement_marker(posix, true),
                            "confined") == 0,
                     "non-windows, flag on: never marked unconfined");
    failures = check(failures,
                     mesh_terminal_confinement_refusal(posix, false) == NULL,
                     "non-windows, flag off: not gated");
    return failures;
}

struct shell_path_case {
    enum mesh_terminal_platform platform;
    const char *path;
    bool valid;
    const char *label;
};

/* Table: every row is judged by the grammar it names, on any host. */
static int test_mesh_terminal_shell_path_table(void)
{
    printf("\n=== mesh terminal shell path grammar (platform-neutral) ===\n");
    static const struct shell_path_case cases[] = {
        { MESH_TERMINAL_PLATFORM_POSIX, "/bin/sh", true, "posix absolute" },
        { MESH_TERMINAL_PLATFORM_POSIX, "bin/sh", false, "posix relative" },
        { MESH_TERMINAL_PLATFORM_POSIX, "", false, "posix empty" },
        { MESH_TERMINAL_PLATFORM_POSIX, "C:\\Windows\\cmd.exe", false,
          "posix refuses a drive path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\Windows\\System32\\cmd.exe",
          true, "windows drive path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "d:/Tools/pwsh.EXE", true,
          "windows forward slashes, lower drive, upper suffix" },
        { MESH_TERMINAL_PLATFORM_WINDOWS,
          "C:\\Program Files\\PowerShell\\7\\pwsh.exe", true,
          "windows path with spaces" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "/bin/sh", false,
          "windows refuses a POSIX path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "\\\\host\\share\\sh.exe", false,
          "windows refuses UNC" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "\\\\?\\C:\\sh.exe", false,
          "windows refuses a device prefix" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "sh.exe", false,
          "windows refuses a bare name" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:sh.exe", false,
          "windows refuses a drive-relative path" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "\\sh.exe", false,
          "windows refuses a rooted path with no drive" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\..\\b\\sh.exe", false,
          "windows refuses a parent segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\.\\sh.exe", false,
          "windows refuses a dot segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\\\sh.exe", false,
          "windows refuses an empty segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.exe\\", false,
          "windows refuses a trailing separator" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.exe -NoProfile", false,
          "windows refuses an argument" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\\"sh.exe", false,
          "windows refuses a quote" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.exe:stream.exe", false,
          "windows refuses a stream designator" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\s*.exe", false,
          "windows refuses a wildcard" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a \\sh.exe", false,
          "windows refuses a trailing-space segment" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\sh.bat", false,
          "windows requires an exe image" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\nul.exe", false,
          "windows refuses a reserved device stem" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\COM1.exe", false,
          "windows refuses a reserved stem in any case" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\lpt9.txt.exe", false,
          "windows refuses a reserved stem before the first dot" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\con\\sh.exe", false,
          "windows refuses a reserved directory name" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\com0.exe", true,
          "com0 is not a reserved device" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\a\\console.exe", true,
          "a longer name sharing a reserved prefix is allowed" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "C:\\", false,
          "windows refuses the bare root" },
        { MESH_TERMINAL_PLATFORM_WINDOWS, "", false, "windows empty" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures = check(failures,
                         mesh_terminal_shell_path_valid(
                             cases[i].platform, cases[i].path) ==
                             cases[i].valid,
                         cases[i].label);

    char longpath[MESH_TERMINAL_SHELL_PATH_MAX_POSIX + 16];
    memset(longpath, 'a', sizeof(longpath));
    memcpy(longpath, "C:\\", 3);
    memcpy(longpath + MESH_TERMINAL_SHELL_PATH_MAX_WINDOWS, ".exe", 5);
    failures = check(failures,
                     !mesh_terminal_shell_path_valid(
                         MESH_TERMINAL_PLATFORM_WINDOWS, longpath),
                     "windows refuses an over-long path");
    memset(longpath, 'a', sizeof(longpath));
    longpath[0] = '/';
    longpath[MESH_TERMINAL_SHELL_PATH_MAX_POSIX] = '\0';
    failures = check(failures,
                     !mesh_terminal_shell_path_valid(
                         MESH_TERMINAL_PLATFORM_POSIX, longpath),
                     "posix refuses a path the lane buffer would truncate");
    failures = check(failures,
                     !mesh_terminal_shell_path_valid(
                         MESH_TERMINAL_PLATFORM_POSIX, NULL),
                     "null refused");
    bool sorted = true, has_path = false, leak = false;
    size_t count = 0;
    for (const char *n; (n = mesh_terminal_win_env_name(count)); count++) {
        const char *prev = count ? mesh_terminal_win_env_name(count - 1) : NULL;
        sorted = sorted && (!prev || strcasecmp(prev, n) < 0);
        has_path = has_path || strcmp(n, "PATH") == 0;
        leak = leak || strstr(n, "KEY") || strstr(n, "TOKEN") ||
               strstr(n, "SECRET");
    }
    failures = check(failures, sorted && count == 11 && has_path && !leak,
                     "environment allow-list is sorted, includes PATH, and "
                     "names no credential variable");
    return failures + test_mesh_terminal_confinement_gate();
}

#if !defined(__linux__)

/* The worker must refuse honestly on platforms with no confinement
 * stack — every entry by name, never a simulated success. */
static int test_mesh_terminal_worker_platform_arm(void)
{
    printf("\n=== mesh terminal worker tests ===\n");
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);

    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, 0, &w);
    failures = check(failures,
                     !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                     "spawn refuses honestly (unsupported)");
    uint8_t buf[16];
    size_t n = 99;
    r = mesh_terminal_worker_output(&w, buf, sizeof buf, &n, 0);
    failures = check(failures, !r.ok && n == 0, "output refuses honestly");
    r = mesh_terminal_worker_input(&w, buf, 1, 0);
    failures = check(failures, !r.ok, "input refuses honestly");
    r = mesh_terminal_worker_resize(&w, 80, 24);
    failures = check(failures, !r.ok, "resize refuses honestly");
    failures = check(failures,
                     mesh_terminal_worker_budget_exceeded(&w, 0),
                     "budget_exceeded: no session is over");
    failures = check(failures, !mesh_terminal_worker_alive(&w),
                     "alive: false with no session");
    mesh_terminal_worker_kill(&w); /* no-op */
    printf("mesh_terminal_worker: %d failures (unsupported platform)\n",
           failures);
    return failures;
}

#else /* __linux__ */

/* Live: the shell's exit status reaches the worker record. */
static int live_exit_status(void)
{
    int failures = 0;
    /* ── live: the remote status survives to the worker record ─────── */
    {
        static const struct {
            const char *line;
            int exit_code;
            int signal;
            const char *label;
        } cases[] = {
            { "exit 3\n", 3, 0, "exit 3 -> exit_code 3, no signal" },
            { "kill -KILL $$\n", 137, 9,
              "SIGKILL death -> exit_code 137, signal 9" },
            { "exit 143\n", 143, 0,
              "exit 143 is a code, not a signal" },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct mesh_terminal_worker_config cfg;
            struct mesh_terminal_worker w;
            live_config(&cfg);
            int64_t t0 = (int64_t)platform_time_wall_time_t();
            struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
            failures = check(failures, r.ok, "spawn for exit status");
            if (r.ok) {
                r = mesh_terminal_worker_input(
                    &w, (const uint8_t *)cases[i].line,
                    strlen(cases[i].line), t0 + 1);
                failures = check(failures, r.ok && wait_exit(&w, 5) &&
                                     w.close_reason ==
                                         MESH_TERMINAL_CLOSE_WORKER_EXITED &&
                                     w.exit_code == cases[i].exit_code &&
                                     w.term_signal == cases[i].signal,
                                 cases[i].label);
            }
            mesh_terminal_worker_kill(&w);
        }
    }

    return failures;
}

/* Live: an explicit argv replaces the shell inside the same cage. */
static int live_explicit_argv(void)
{
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    char outside[160];
    char outside_dir[160];
    test_make_tmpdir(outside_dir, sizeof outside_dir, "terminal_worker_live", "outside");
    snprintf(outside, sizeof outside, "%s/leak", outside_dir);
    unlink(outside);
    char script[240];
    snprintf(script, sizeof script, "echo leaked > %s; exit 6", outside);
    const char *const run[] = { g_fbsh, "-c", script, NULL };
    live_config(&cfg);
    cfg.argv = run;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
    failures = check(failures, r.ok, "argv: spawn");
    if (r.ok)
        failures = check(failures, wait_exit(&w, 5) && w.exit_code == 6 &&
                         w.close_reason == MESH_TERMINAL_CLOSE_WORKER_EXITED,
                         "argv: the program ran and its exit code 6 propagates");
    mesh_terminal_worker_kill(&w);
    struct stat st;
    failures = check(failures, stat(outside, &st) != 0,
                     "argv: a write outside the granted workdir is denied");
    unlink(outside);

    static const char *const relative[] = { "fbsh", "-c", "exit 0", NULL };
    static const char *const empty[] = { NULL };
    static const char *const missing[] = { "/nonexistent/z23-prog", NULL };
    static const char *const too_many[] = { "/a", "/a", "/a", "/a", "/a", "/a", "/a", "/a", "/a",
                                            "/a", "/a", "/a", "/a", "/a", "/a", "/a", "/a", NULL };
    static const struct { const char *const *argv; int code; const char *label; } bad[] = {
        { relative, MESH_TERMINAL_WORKER_ERR_CONFIG, "argv: a relative argv[0] -> config" },
        { empty, MESH_TERMINAL_WORKER_ERR_CONFIG, "argv: an empty argv -> config" },
        { too_many, MESH_TERMINAL_WORKER_ERR_CONFIG, "argv: 17 strings -> config" },
        { missing, MESH_TERMINAL_WORKER_ERR_EXEC, "argv: a missing program -> exec, by name" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        live_config(&cfg);
        cfg.argv = bad[i].argv;
        r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, !r.ok && r.code == bad[i].code, bad[i].label);
        mesh_terminal_worker_kill(&w);
    }
    return failures;
}

/* Live: a dynamically linked program runs in the cage (ld.so maps its
 * libraries with file-backed PROT_EXEC mmap); exit codes propagate. */
static int live_dynamic_argv(void)
{
    static const struct { const char *path; int code; } progs[] = {
        { "/usr/bin/true", 0 }, { "/usr/bin/false", 1 },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof progs / sizeof progs[0]; i++) {
        struct stat st;
        if (stat(progs[i].path, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
            /* Every supported Linux host carries these: absence is a red. */
            failures = check(failures, false, "dynamic argv: /usr/bin/true and /usr/bin/false are present");
            continue;
        }
        const char *const run[] = { progs[i].path, NULL };
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.argv = run;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "dynamic argv: spawn");
        if (r.ok)
            failures = check(failures, wait_exit(&w, 5) &&
                             w.term_signal == 0 && w.exit_code == progs[i].code &&
                             w.close_reason == MESH_TERMINAL_CLOSE_WORKER_EXITED,
                             progs[i].code ? "dynamic argv: /usr/bin/false exits 1"
                                           : "dynamic argv: /usr/bin/true exits 0");
        mesh_terminal_worker_kill(&w);
    }
    return failures;
}

/* Signal only a pid or group this test owns: never 0, -1 or init, so a failed
 * fork (-1) or an unset slot (0) can never become a broadcast kill. */
static void kill_owned_group(pid_t pgid)
{
    if (pgid > 1)
        (void)kill(-pgid, SIGKILL);
}

static void kill_owned_pid(pid_t pid, bool reap)
{
    if (pid <= 1)
        return;
    (void)kill(pid, SIGKILL);
    if (reap)
        (void)waitpid(pid, NULL, 0);
}

/* Members of a process group that are still running (zombies awaiting their
 * parent do not count: they are already dead). */
static unsigned group_running(pid_t pgid)
{
    unsigned live = 0;
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    while (proc && (ent = readdir(proc)) != NULL) {
        char path[64], buf[512];
        long pid = strtol(ent->d_name, NULL, 10);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        int fd = open(path, O_RDONLY);
        ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
        if (fd >= 0)
            close(fd);
        const char *after = n > 0 ? (buf[n] = '\0', strrchr(buf, ')')) : NULL;
        char state = 0;
        long ppid = 0, pgrp = 0;
        if (after && sscanf(after + 1, " %c %ld %ld", &state, &ppid, &pgrp) == 3 && pgrp == pgid && state != 'Z')
            live++;
    }
    if (proc)
        closedir(proc);
    return live;
}

/* Live: the leader exits but a child that ignored HUP outlives it. Ending the
 * session must still take the descendant down with the group. */
static int live_orphan_descendant(void)
{
    const char *const run[] = { "/bin/sh", "-c", "trap '' HUP; (kill -KILL $$; while :; do :; done)", NULL };
    struct stat st;
    if (stat(run[0], &st) != 0 || !(st.st_mode & S_IXUSR)) {
        return check(0, false, "orphan: /bin/sh is present");
    }
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);
    cfg.argv = run;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
    failures = check(failures, r.ok, "orphan: spawn");
    if (!r.ok)
        return failures;
    failures = check(failures, wait_exit(&w, 5) && w.term_signal == 9, "orphan: the leader dies while its child runs on");
    /* The leader is pid 1 of its own PID namespace: its death takes every
     * descendant with it, so no orphan can outlive it (the pgid kill below
     * stays as the fallback). */
    unsigned live = group_running(w.pgid);
    for (int i = 0; i < 100 && live; i++) { usleep(20000); /* real-clock: async kernel teardown */ live = group_running(w.pgid); }
    failures = check(failures, live == 0, "orphan: the namespace init dying takes the HUP-ignoring child with it");
    mesh_terminal_worker_kill(&w);
    unsigned left = group_running(w.pgid);
    for (int i = 0; i < 100 && left; i++) {
        usleep(20000); /* real-clock: the kernel finishes the kill asynchronously; no seam */
        left = group_running(w.pgid);
    }
    failures = check(failures, left == 0, "orphan: ending the session kills the descendant");
    if (left)
        kill_owned_group(w.pgid);
    return failures;
}

/* Live: group custody. A leader that exits by itself is NOT reaped until the
 * group is killed: it stays a zombie holding the group id, so the kill cannot
 * reach a recycled, unrelated group; the leader is reaped only after killpg. */
static int live_custody_order(void)
{
    const char *const run[] = { "/bin/sh", "-c", "trap '' HUP; (kill -KILL $$; while :; do :; done)", NULL };
    struct stat st;
    if (stat(run[0], &st) != 0 || !(st.st_mode & S_IXUSR)) {
        return check(0, false, "custody: /bin/sh is present");
    }
    int failures = 0, status = 0;
    uint32_t killpg_seq = 0, reap_seq = 0;
    siginfo_t si = { 0 };
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);
    cfg.argv = run;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, (int64_t)platform_time_wall_time_t(), &w);
    failures = check(failures, r.ok, "custody: spawn");
    if (!r.ok)
        return failures;
    mesh_terminal_worker_testing_order(&killpg_seq, &reap_seq);
    failures = check(failures, wait_exit(&w, 5) && !w.running, "custody: the leader exits by itself");
    unsigned live = group_running(w.pgid);
    for (int i = 0; i < 100 && live; i++) { usleep(20000); /* real-clock: async kernel teardown */ live = group_running(w.pgid); }
    failures = check(failures, live == 0, "custody: the namespace init dying takes its HUP-ignoring child with it");
    bool zombie = waitid(P_PID, (id_t)w.pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == w.pid;
    failures = check(failures, zombie && w.leader_held, "custody: the exited leader is still unreaped, holding the group id");
    mesh_terminal_worker_kill(&w);
    mesh_terminal_worker_testing_order(&killpg_seq, &reap_seq);
    failures = check(failures, killpg_seq != 0 && reap_seq > killpg_seq, "custody: the group is killed, then the leader is reaped");
    failures = check(failures, !w.leader_held && waitpid(w.pid, &status, WNOHANG) == -1 && errno == ECHILD,
                     "custody: the leader was reaped by the kill, exactly once");
    unsigned left = group_running(w.pgid);
    for (int i = 0; i < 100 && left; i++) {
        usleep(20000); /* real-clock: the kernel finishes the kill asynchronously; no seam */
        left = group_running(w.pgid);
    }
    failures = check(failures, left == 0, "custody: the descendant died with the group");
    if (left)
        kill_owned_group(w.pgid);
    return failures;
}

/* Compare logical masks, not opaque sigset_t padding bytes. */
static bool tw_masks_equal(const sigset_t *a, const sigset_t *b)
{
    for (int number = 1; number < NSIG; ++number)
        if (sigismember(a, number) != sigismember(b, number)) return false;
    return true;
}

/* Caller signal state the boundary case perturbs and must give back. */
struct tw_sigfix {
    sigset_t original, chosen;
    struct sigaction old1, old2;
};

static bool tw_sigfix_install(struct tw_sigfix *s)
{
    struct sigaction caught = {.sa_handler = tw_caught_handler};
    struct sigaction ignored = {.sa_handler = SIG_IGN};
    sigemptyset(&caught.sa_mask);
    sigemptyset(&ignored.sa_mask);
    if (sigprocmask(SIG_SETMASK, NULL, &s->original) != 0 ||
        sigaction(SIGUSR1, NULL, &s->old1) != 0 || sigaction(SIGUSR2, NULL, &s->old2) != 0)
        return false;
    s->chosen = s->original;
    sigdelset(&s->chosen, SIGUSR1);
    sigaddset(&s->chosen, SIGUSR2);
    return sigaction(SIGUSR1, &caught, NULL) == 0 && sigaction(SIGUSR2, &ignored, NULL) == 0 &&
           sigprocmask(SIG_SETMASK, &s->chosen, NULL) == 0;
}

static bool tw_sigfix_restore(const struct tw_sigfix *s)
{
    tw_signal_observe = false;
    bool restored = sigaction(SIGUSR1, &s->old1, NULL) == 0;
    restored = sigaction(SIGUSR2, &s->old2, NULL) == 0 && restored;
    return sigprocmask(SIG_SETMASK, &s->original, NULL) == 0 && restored;
}

/* What the spawn outcome must be for the injected fault. */
static int tw_sigfix_outcome(enum tw_signal_fault fault, struct zcl_result result,
                             struct mesh_terminal_worker *w)
{
    int failures = 0;
    if (fault == TW_SIGNAL_OK) {
        failures = check(failures, result.ok, "signal boundary: real spawn");
        if (result.ok)
            failures = check(failures, wait_exit(w, 5) && w->term_signal == 0 && w->exit_code == 0,
                             "signal boundary: post-exec original mask and IGN survive");
        return failures;
    }
    int expected = fault == TW_SIGNAL_RESET ? MESH_TERMINAL_WORKER_ERR_CONFINEMENT :
                                              MESH_TERMINAL_WORKER_ERR_SPAWN;
    failures = check(failures, !result.ok && result.code == expected && !w->running,
                     "signal boundary: injected failure refuses exact stage");
    if (tw_signal_child > 0)
        failures = check(failures, kill(tw_signal_child, 0) < 0 && errno == ESRCH,
                         "signal boundary: refused child reaped");
    return failures;
}

/* The caller's mask and handlers after the spawn. */
static int tw_sigfix_parent_state(enum tw_signal_fault fault, const struct tw_sigfix *s)
{
    sigset_t after;
    struct sigaction got1, got2;
    bool mask_ok = sigprocmask(SIG_SETMASK, NULL, &after) == 0 &&
        (fault == TW_SIGNAL_PARENT_RESTORE ?
         sigismember(&after, SIGUSR1) == 1 && sigismember(&after, SIGUSR2) == 1 :
         tw_masks_equal(&s->chosen, &after));
    int failures = check(0, mask_ok,
                         "signal boundary: parent mask restored unless injected kernel refusal");
    return check(failures, sigaction(SIGUSR1, NULL, &got1) == 0 &&
                 sigaction(SIGUSR2, NULL, &got2) == 0 &&
                 got1.sa_handler == tw_caught_handler && got2.sa_handler == SIG_IGN &&
                 tw_caught_calls == 0, "signal boundary: parent handlers unchanged");
}

/* Every mutation is restored before returning; no signal is sent to the
 * harness. Parent and child state are observed through real system calls. */
static int live_signal_boundary_case(enum tw_signal_fault fault)
{
    struct tw_sigfix s;
    char image[600];
    if (!tw_sigfix_install(&s)) {
        (void)tw_sigfix_restore(&s);
        return check(0, false, "signal boundary: install fixture state");
    }
    int failures = 0;
    if (!test_abs_path("build/fixtures/rcc_child", image, sizeof image)) {
        failures = check(0, false, "signal boundary: trusted fixture path");
    } else {
        const char *const run[] = {image, "signal-state", "", NULL};
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.shell_path = image;
        cfg.argv = run;
        tw_signal_fault = fault;
        tw_signal_parent = getpid();
        tw_signal_child = 0;
        tw_mask_sets = 0;
        tw_caught_calls = 0;
        tw_signal_observe = true;
        struct zcl_result result = mesh_terminal_worker_spawn(
            &cfg, (int64_t)platform_time_wall_time_t(), &w);
        tw_signal_observe = false;
        failures = tw_sigfix_outcome(fault, result, &w);
        mesh_terminal_worker_kill(&w);
        failures += tw_sigfix_parent_state(fault, &s);
    }
    return check(failures, tw_sigfix_restore(&s), "signal boundary: fixture restores caller state");
}


static int live_signal_boundary(void)
{
    int failures = 0;
    for (int fault = TW_SIGNAL_OK; fault <= TW_SIGNAL_PARENT_RESTORE; ++fault)
        failures += live_signal_boundary_case((enum tw_signal_fault)fault);
    return failures;
}


enum tw_nofile { TW_NOFILE_RAISED, TW_NOFILE_HARD_CAP, TW_NOFILE_ERROR };

/* Raises the soft descriptor limit above `want`; `saved` holds the limit to
 * restore. A hard limit at or below `want` cannot be raised by an
 * unprivileged test and is reported apart from a failed system call. */
static enum tw_nofile tw_nofile_above(rlim_t want, struct rlimit *saved)
{
    if (getrlimit(RLIMIT_NOFILE, saved) != 0)
        return TW_NOFILE_ERROR;
    if (saved->rlim_cur > want)
        return TW_NOFILE_RAISED;
    if (saved->rlim_max != RLIM_INFINITY && saved->rlim_max <= want)
        return TW_NOFILE_HARD_CAP;
    struct rlimit raised = *saved;
    raised.rlim_cur = want + 16;
    if (raised.rlim_max != RLIM_INFINITY && raised.rlim_cur > raised.rlim_max)
        raised.rlim_cur = raised.rlim_max;
    return setrlimit(RLIMIT_NOFILE, &raised) == 0 ? TW_NOFILE_RAISED
                                                   : TW_NOFILE_ERROR;
}

/* Real terminal spawn executes the trusted C fdwrite fixture: EBADF tests the
 * descriptor itself, independently of whether Landlock permits proc paths. */
static int live_high_fd_spawn(const char *image, int high, bool fallback)
{
    char fdarg[32];
    int used = snprintf(fdarg, sizeof fdarg, "%d", high);
    if (used < 0 || (size_t)used >= sizeof fdarg)
        return check(0, false, "high inherited fd: encode descriptor");
    const char *const run[] = {image, "fdwrite", fdarg, NULL};
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);
    cfg.shell_path = image;
    cfg.argv = run;
    tw_force_fd_fallback = fallback;
    struct zcl_result result = mesh_terminal_worker_spawn(
        &cfg, (int64_t)platform_time_wall_time_t(), &w);
    tw_force_fd_fallback = false;
    int failures = check(0, result.ok, "high inherited fd: real terminal spawn");
    if (result.ok)
        failures = check(failures, wait_exit(&w, 5) &&
                         w.term_signal == 0 && w.exit_code == EBADF,
                         fallback ? "high inherited fd: forced proc fallback closes FD" :
                                    "high inherited fd: default closure closes FD");
    mesh_terminal_worker_kill(&w);
    return failures;
}

/* The descriptor is planted above 65536 under a raised soft limit, and the
 * caller's limit is restored before the spawn, so a closure bounded by
 * RLIMIT_NOFILE would leave it open and fail the case. */
static int live_high_inherited_fd_closed(bool fallback)
{
    char image[600];
    if (!test_abs_path("build/fixtures/rcc_child", image, sizeof image))
        return check(0, false, "high inherited fd: resolve trusted fixture");
    struct rlimit saved;
    switch (tw_nofile_above(70000, &saved)) {
    case TW_NOFILE_HARD_CAP:
        printf("mesh_terminal_worker: high inherited fd... UNOBSERVED "
               "(descriptor hard limit %llu is not above 70000)\n",
               (unsigned long long)saved.rlim_max);
        return 0;
    case TW_NOFILE_ERROR:
        printf("mesh_terminal_worker: descriptor limit errno=%d\n", errno);
        return check(0, false, "high inherited fd: raise descriptor limit");
    case TW_NOFILE_RAISED:
        break;
    }
    int source = open("/dev/null", O_WRONLY);
    int high = source >= 0 ? fcntl(source, F_DUPFD, 70000) : -1;
    if (source >= 0) close(source);
    int failures = check(0, setrlimit(RLIMIT_NOFILE, &saved) == 0,
                         "high inherited fd: descriptor limit restored");
    if (high < 0)
        return check(failures, false, "high inherited fd: plant above 65536");
    failures += live_high_fd_spawn(image, high, fallback);
    close(high);
    return failures;
}

/* First live child (non-zombie) of `parent` outside group `avoid_pgid` (0: any), by /proc scan; 0 if none. */
static pid_t first_child_of(pid_t parent, pid_t avoid_pgid)
{
    pid_t found = 0;
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    while (proc && !found && (ent = readdir(proc)) != NULL) {
        char path[64], buf[512];
        long pid = strtol(ent->d_name, NULL, 10);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        int fd = open(path, O_RDONLY);
        ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
        if (fd >= 0)
            close(fd);
        const char *after = n > 0 ? (buf[n] = '\0', strrchr(buf, ')')) : NULL;
        char state = 0;
        long ppid = 0;
        if (after && sscanf(after + 1, " %c %ld", &state, &ppid) == 2 && ppid == parent && state != 'Z' && (avoid_pgid == 0 || getpgid((pid_t)pid) != avoid_pgid))
            found = (pid_t)pid;
    }
    if (proc)
        closedir(proc);
    return found;
}

/* Live: the shell runs in its own PID namespace. A same-uid process the test
 * started outside the cage is unaddressable (ESRCH, not EPERM and not 0), the
 * test process itself is too, the shell is pid 1 and still runs its own jobs.
 * A job in a group of its own (set -m) escapes the worker's pgid, so ending
 * the session must still take it down through the namespace init. */
static int live_pid_namespace(void)
{
    int failures = 0;
    struct stat st;
    if (stat("/bin/sh", &st) != 0)
        return check(0, false, "pidns: /bin/sh is present");
    pid_t sibling = fork();
    if (sibling == 0) {
        for (;;)
            pause();
    }
    if (sibling < 0)
        return check(0, false, "pidns: fixture sibling fork");
    char script[512];
    snprintf(script, sizeof script,
             "kill -0 %ld; S=$?; kill -0 %ld; P=$?; "
             "(while :; do :; done) & kill $!; wait $!; J=$?; "
             "set -m; (while :; do :; done) & echo RES self=$$ sib=$S par=$P job=$J; while :; do :; done",
             (long)sibling, (long)getpid());
    const char *const run[] = { "/bin/sh", "-c", script, NULL };
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);
    cfg.argv = run;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, (int64_t)platform_time_wall_time_t(), &w);
    failures = check(failures, r.ok, "pidns: spawn");
    if (r.ok) {
        char saw[256] = { 0 };
        bool res = drain_until(&w, "RES self=2 sib=1 par=1 job=143\r", 5, NULL, saw, sizeof saw);
        if (!res)
            printf("pidns: saw [%s]\n", saw);
        failures = check(failures, res,
                         "pidns: shell is pid 2; outside sibling and supervisor are ESRCH; own job kill works");
        pid_t init = first_child_of(w.pid, 0);
        pid_t shell = init > 0 ? first_child_of(init, 0) : 0;
        pid_t other = shell > 0 ? first_child_of(shell, w.pgid) : 0;
        failures = check(failures, init > 0 && other > 0,
                         "pidns: a job outside the worker's pgid exists");
        mesh_terminal_worker_kill(&w);
        for (int i = 0; i < 100 && other > 0 && kill(other, 0) == 0; i++)
            usleep(20000); /* real-clock: the kernel finishes the teardown asynchronously */
        failures = check(failures, other > 0 && kill(other, 0) != 0,
                         "pidns: ending the session takes the out-of-group job down with the namespace");
        failures = check(failures, kill(sibling, 0) == 0, "pidns: the outside sibling was not touched");
        kill_owned_pid(other, false);
    }
    kill_owned_pid(sibling, true);
    return failures;
}

/* Live: a descriptor the launcher left open without CLOEXEC must not reach the
 * confined program. The shell tests the planted number: a redirect to an open
 * descriptor succeeds, to a closed one it fails. */
static int live_inherited_fd_closed(void)
{
    /* dash's redirect syntax takes one digit, so plant in 3..9 (no O_CLOEXEC:
     * dup2 clears it, on purpose). */
    int planted = -1;
    int src = open("/dev/null", O_RDWR);
    for (int fd = 3; src >= 0 && fd <= 9 && planted < 0; fd++)
        if (fcntl(fd, F_GETFD) < 0 && dup2(src, fd) == fd)
            planted = fd;
    if (src >= 0)
        close(src);
    if (planted < 0)
        return check(0, false, "inherited fd: plant a descriptor");
    char script[160];
    snprintf(script, sizeof script,
             "if { :; } >&%d; then echo FD_STILL_OPEN; "
             "else echo FD_CLOSED; fi", planted);
    const char *const run[] = { "/bin/sh", "-c", script, NULL };
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);
    cfg.argv = run;
    struct zcl_result r = mesh_terminal_worker_spawn(
        &cfg, (int64_t)platform_time_wall_time_t(), &w);
    failures = check(failures, r.ok, "inherited fd: spawn");
    if (r.ok) {
        char saw[256] = "";
        bool closed = drain_until(&w, "FD_CLOSED", 5, NULL, saw, sizeof saw);
        failures = check(failures, closed && !strstr(saw, "FD_STILL_OPEN"),
                         "inherited fd: a launcher descriptor is closed before the shell runs");
    }
    mesh_terminal_worker_kill(&w);
    close(planted);
    return failures;
}

/* Live: 2 MiB of output under the service byte budget. */
static int live_two_mib_output(void)
{
    int failures = 0;
    /* ── live: 2 MiB of output under the service budget ────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_out = UINT64_C(1) << 30; /* the service default */
        cfg.max_bytes_in = UINT64_C(16) << 20;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for 2 MiB output");
        if (r.ok) {
            const uint8_t line[] =
                "a=0123456789abcdef;a=$a$a;a=$a$a;a=$a$a;a=$a$a;a=$a$a;a=$a$a;"
                "i=0;while [ $i -lt 2100 ];do echo $a;i=$((i+1));done;"
                "echo ZZZ$((1+1))END\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1, t0 + 1);
            failures = check(failures, r.ok, "2 MiB command input accepted");
            size_t total = 0, biggest = 0;
            bool end_seen = false, failed = false;
            char tail[16] = "";
            time_t deadline = platform_time_wall_time_t() + 30;
            while (!end_seen && !failed &&
                   platform_time_wall_time_t() < deadline) {
                uint8_t chunk[MESH_TERMINAL_WORKER_IO_CHUNK];
                size_t n = 0;
                r = mesh_terminal_worker_output(
                    &w, chunk, sizeof chunk, &n,
                    (int64_t)platform_time_wall_time_t());
                if (!r.ok && r.code != MESH_TERMINAL_WORKER_ERR_NONE) {
                    failed = true;
                    break;
                }
                if (n == 0) {
                    usleep(2000);
                    continue;
                }
                total += n;
                if (n > biggest)
                    biggest = n;
                char probe[sizeof tail * 2];
                size_t keep = strlen(tail);
                memcpy(probe, tail, keep);
                size_t take = n < sizeof tail - 1 ? n : sizeof tail - 1;
                memcpy(probe + keep, chunk + n - take, take);
                probe[keep + take] = '\0';
                end_seen = strstr(probe, "ZZZ2END") != NULL;
                size_t tl = keep + take < sizeof tail - 1 ? keep + take
                                                          : sizeof tail - 1;
                memmove(tail, probe + keep + take - tl, tl);
                tail[tl] = '\0';
            }
            failures = check(failures, !failed && end_seen,
                             "2 MiB session was not ended by byte-limit");
            failures = check(failures, total >= 2097152 &&
                                 w.close_reason !=
                                     MESH_TERMINAL_CLOSE_BYTE_LIMIT,
                             "2 MiB of output delivered, reason not "
                             "byte-limit");
            failures = check(failures, biggest <= (size_t)(
                                 MESH_TERMINAL_WORKER_IO_CHUNK),
                             "memory bounded: every read fits the fixed "
                             "chunk");
        }
        mesh_terminal_worker_kill(&w);
    }

    return failures;
}

static int test_mesh_terminal_worker_platform_arm(void)
{
    printf("\n=== mesh terminal worker tests ===\n");
    int failures = 0;

    test_make_tmpdir(g_dir, sizeof g_dir, "terminal_worker_live", "live");
    if (!test_abs_path(FBSH_BIN, g_fbsh, sizeof g_fbsh))
        g_fbsh[0] = '\0';
    struct stat st;
    bool fbsh = g_fbsh[0] && stat(FBSH_BIN, &st) == 0 &&
                (st.st_mode & S_IXUSR) != 0;

    /* ── config refusals (by name; no fbsh needed) ─────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        struct zcl_result r = mesh_terminal_worker_spawn(NULL, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_NULL,
                         "spawn(NULL) -> null");
        r = mesh_terminal_worker_spawn(&cfg, 0, NULL);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_NULL,
                         "spawn(out=NULL) -> null");

        static const char *relative = "build/bin/fbsh";
        cfg.shell_path = relative;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "relative shell_path -> config");
        live_config(&cfg);
        static char relative_dir[] = "test-tmp";
        cfg.workdir = relative_dir;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "relative workdir -> config");
        live_config(&cfg);
        cfg.max_bytes_in = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero input budget -> config");
        live_config(&cfg);
        cfg.lifetime_seconds = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero lifetime -> config");
        live_config(&cfg);
        cfg.cols = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero cols -> config");
    }

    if (!fbsh) {
        printf("mesh_terminal_worker: " FBSH_BIN
               " not built — SKIP (live cases need `make fbsh`)\n");
        printf("mesh_terminal_worker: %d failures\n", failures);
        return failures;
    }

    /* ── live: interactive roundtrip + census ──────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn fbsh in the cage");
        if (r.ok) {
            failures = check(failures, w.pid > 0 && w.pgid == w.pid &&
                                         w.master_fd >= 0,
                             "spawn fills pid/pgid/master");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) >= 1,
                             "census sees the session's process group");
            const uint8_t line[] = "echo Z23TER\"M\"_OK\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1, t0 + 1);
            failures = check(failures, r.ok, "input accepted");
            char saw[256] = {0};
            bool found = drain_until(&w, "Z23TERM_OK", 5, NULL,
                                     saw, sizeof saw);
            failures = check(failures, found,
                             "shell executed the typed line (echo output)");
            if (!found) {
                printf("  saw %.200s\n", saw);
                failures = check(failures, mesh_terminal_worker_alive(&w),
                                 "shell was alive during the drain");
            }
            failures = check(failures, w.bytes_in == sizeof line - 1,
                             "input byte accounting");
        }
        mesh_terminal_worker_kill(&w);
        failures = check(failures,
                         os_sandbox_process_group_census(w.pgid) == 0,
                         "kill leaves an empty process group");
        const uint8_t more[] = "x";
        r = mesh_terminal_worker_input(&w, more, 1, t0 + 2);
        failures = check(failures,
                         !r.ok &&
                             r.code == MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                         "input after kill -> not-running");
    }

    /* ── live: natural exit is reaped and named ────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for natural exit");
        if (r.ok) {
            const uint8_t line[] = "exit\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1,
                                           t0 + 1);
            failures = check(failures, r.ok,
                             "exit command input accepted");
            failures = check(failures, wait_exit(&w, 5),
                             "shell exits on `exit`");
            failures = check(failures,
                             !w.running &&
                                 w.close_reason ==
                                     MESH_TERMINAL_CLOSE_WORKER_EXITED &&
                                 w.exit_code == 0,
                             "natural exit named worker-exited (code 0)");
            /* Enforcement after death reports over but keeps the exit's
             * name — reap wins over the timeout checks. */
            bool over = mesh_terminal_worker_budget_exceeded(&w,
                                                             t0 + 100000);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_WORKER_EXITED,
                             "enforce after exit keeps worker-exited");
        }
        mesh_terminal_worker_kill(&w);
    }

    failures += live_exit_status();
    failures += live_explicit_argv();
    failures += live_dynamic_argv();
    failures += live_orphan_descendant();
    failures += live_custody_order();
    failures += live_pid_namespace();
    failures += live_inherited_fd_closed();
    failures += live_high_inherited_fd_closed(false);
    failures += live_high_inherited_fd_closed(true);
    failures += live_signal_boundary();
    failures += live_two_mib_output();

    /* ── live: input byte budget ───────────────────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_in = 16;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for input budget");
        if (r.ok) {
            const uint8_t exact[16] = {0};
            r = mesh_terminal_worker_input(&w, exact, sizeof exact, t0 + 1);
            failures = check(failures, r.ok,
                             "input exactly at budget accepted");
            const uint8_t one[] = "a";
            r = mesh_terminal_worker_input(&w, one, 1, t0 + 2);
            failures = check(failures,
                             !r.ok &&
                                 r.code ==
                                     MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
                                 w.close_reason ==
                                     MESH_TERMINAL_CLOSE_BYTE_LIMIT,
                             "input over budget -> byte-limit");
            failures = check(failures, !mesh_terminal_worker_alive(&w),
                             "budget kill ended the session");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "budget kill emptied the process group");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: output byte budget ──────────────────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_out = 64;
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for output budget");
        if (r.ok) {
            const uint8_t line[] =
                "echo 0123456789012345678901234567890123456789"
                "0123456789012345678901234567890123456789\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1,
                                           t0 + 1);
            failures = check(failures, r.ok,
                             "output-budget command input accepted");
            struct zcl_result err = { .ok = true };
            (void)drain_until(&w, "ZZZ_NEVER", 5, &err, NULL, 0);
            failures = check(failures,
                             !err.ok &&
                                 err.code ==
                                     MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                             "output over budget -> byte-limit");
            failures = check(failures, w.bytes_out > 64,
                             "output bytes were accounted before the kill");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "output budget kill emptied the group");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── lifetime + idle: injected clock, no sleeping ──────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.idle_seconds = 0; /* isolate the lifetime check: at t0+59 the
                               * idle window (30 s) would otherwise fire
                               * first and name the kill idle-timeout */
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for lifetime budget");
        if (r.ok) {
            failures = check(failures,
                             !mesh_terminal_worker_budget_exceeded(&w,
                                                                   t0 + 59),
                             "one tick inside the lifetime still alive");
            bool over = mesh_terminal_worker_budget_exceeded(&w, t0 + 61);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_LIFETIME_LIMIT,
                             "lifetime exceeded -> lifetime-limit");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "lifetime kill emptied the group");
        }
        mesh_terminal_worker_kill(&w);

        live_config(&cfg);
        cfg.idle_seconds = 30; /* unchanged; lifetime stays 60 (> 31) */
        r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for idle budget");
        if (r.ok) {
            failures = check(failures,
                             !mesh_terminal_worker_budget_exceeded(&w,
                                                                   t0 + 29),
                             "one tick inside the idle window alive");
            bool over = mesh_terminal_worker_budget_exceeded(&w, t0 + 31);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_IDLE_TIMEOUT,
                             "idle exceeded -> idle-timeout");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: resize bounds + confinement through the terminal ────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for resize/confinement");
        if (r.ok) {
            r = mesh_terminal_worker_resize(&w, MESH_TERMINAL_MAX_COLS,
                                            MESH_TERMINAL_MAX_ROWS);
            failures = check(failures, r.ok, "resize to proto max");
            r = mesh_terminal_worker_resize(&w, 0, 24);
            failures = check(failures,
                             !r.ok &&
                                 r.code == MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                             "resize zero cols -> geometry");
            r = mesh_terminal_worker_resize(
                &w, (uint16_t)(MESH_TERMINAL_MAX_COLS + 1), 24);
            failures = check(failures,
                             !r.ok &&
                                 r.code == MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                             "resize over max cols -> geometry");

            /* Attack through the shell: cat is NOT granted, so the read
             * cannot happen — and nothing secret may appear on screen. */
            const uint8_t shadow[] = "cat /etc/shadow\n";
            r = mesh_terminal_worker_input(&w, shadow,
                                           sizeof shadow - 1, t0 + 1);
            failures = check(failures, r.ok,
                             "confined attack input accepted");
            struct zcl_result err = { .ok = true };
            (void)drain_until(&w, "not found", 5, &err, NULL, 0);
            (void)err;

            /* The shell must still be alive and working after the
             * refusal — confined is not broken. */
            failures = check(failures, mesh_terminal_worker_alive(&w),
                             "shell survived the refused attack");
            const uint8_t probe[] = "echo A$((6*7))B\n";
            r = mesh_terminal_worker_input(&w, probe, sizeof probe - 1,
                                           t0 + 2);
            failures = check(failures, r.ok, "probe accepted after refusal");
            bool found = drain_until(&w, "A42B", 5, NULL, NULL, 0);
            failures = check(failures, found,
                             "shell still executes after the refusal");
        }
        mesh_terminal_worker_kill(&w);
        failures = check(failures,
                         os_sandbox_process_group_census(w.pgid) == 0,
                         "final kill emptied the group");
    }

    printf("mesh_terminal_worker: %d failures\n", failures);
    return failures;
}

#endif /* __linux__ */

int test_mesh_terminal_worker(void)
{
    int failures = test_mesh_terminal_worker_bookkeeping();
    failures += test_mesh_terminal_shell_path_table();
#if defined(__linux__)
    failures += partial_input_effects();
    failures += test_interrupted_reaping();
    failures += test_interrupted_startup_reaping();
#endif
    failures += test_mesh_terminal_worker_platform_arm();
    return failures;
}
