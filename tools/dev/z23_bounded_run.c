/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Run one local proof executable under a bounded process-tree rail.
 *
 * This deliberately small helper exists because macOS has no standard
 * timeout(1), Windows must never surface a console or crash dialog, and
 * killing only a test's immediate PID can leave descendants alive after a
 * gate reports failure. POSIX children start a new session; Windows children
 * run under a kill-on-close Job Object. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdbool.h>
#include <stdint.h>

/* Shared by both platform parsers: a timeout must be non-zero and fit the
 * 32-bit wait interval. */
static bool timeout_ms_in_range(unsigned long long parsed)
{
    return parsed != 0 && parsed <= UINT32_MAX;
}

#if defined(_WIN32)
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "base/safe_alloc.h"

enum { RUN_TIMEOUT = 124, RUN_INFRA = 125 };

#define Z23_BOUNDED_ERROR_MODE \
    (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)

struct wide_buffer {
    wchar_t *data;
    size_t used;
    size_t capacity;
};

static bool append_wide(struct wide_buffer *buffer, wchar_t value)
{
    if (buffer->used == buffer->capacity) {
        size_t next = buffer->capacity ? buffer->capacity * 2u : 256u;
        if (next < buffer->capacity || next > 32768u)
            return false;
        wchar_t *grown = zcl_realloc(buffer->data, next * sizeof(*grown),
                                     "bounded-run widebuf");
        if (!grown)
            return false;
        buffer->data = grown;
        buffer->capacity = next;
    }
    buffer->data[buffer->used++] = value;
    return true;
}

static bool append_repeated(struct wide_buffer *buffer, wchar_t value,
                           size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!append_wide(buffer, value))
            return false;
    return true;
}

/* One non-backslash cursor value: a quote is preceded by doubled backslashes,
 * a NUL ends the argument (doubled backslashes only when quoted). */
static bool append_argument_char(struct wide_buffer *line, wchar_t value,
                                 size_t slashes, bool quote)
{
    if (value == L'\"')
        return append_repeated(line, L'\\', slashes * 2u + 1u) &&
               append_wide(line, L'\"');
    if (value == 0 && quote)
        slashes *= 2u;
    return append_repeated(line, L'\\', slashes) &&
           (value == 0 || append_wide(line, value));
}

/* CommandLineToArgvW-compatible quoting, including trailing backslashes. */
static bool append_argument(struct wide_buffer *line, const wchar_t *argument)
{
    if (line->used && !append_wide(line, L' '))
        return false;
    bool quote = !argument[0] || wcspbrk(argument, L" \t\n\v\"") != NULL;
    if (quote && !append_wide(line, L'\"'))
        return false;
    size_t slashes = 0;
    for (const wchar_t *cursor = argument;; cursor++) {
        if (*cursor == L'\\') {
            slashes++;
            continue;
        }
        if (!append_argument_char(line, *cursor, slashes, quote))
            return false;
        if (*cursor == 0)
            break;
        slashes = 0;
    }
    return (!quote || append_wide(line, L'\"')) && append_wide(line, 0);
}

static wchar_t *make_command_line(wchar_t *const argv[])
{
    struct wide_buffer line = {0};
    for (size_t i = 0; argv[i]; i++) {
        if (line.used)
            line.used--; /* replace previous NUL */
        if (!append_argument(&line, argv[i])) {
            free(line.data);
            return NULL;
        }
    }
    return line.data;
}

static bool absolute_path(const wchar_t *path)
{
    return path && ((path[0] && path[1] == L':' &&
                     (path[2] == L'\\' || path[2] == L'/')) ||
                    (path[0] == L'\\' && path[1] == L'\\'));
}

static bool parse_timeout_arg(const wchar_t *text, unsigned long long *parsed)
{
    wchar_t *end = NULL;
    errno = 0;
    *parsed = wcstoull(text, &end, 10);
    return !errno && end && !*end && timeout_ms_in_range(*parsed);
}

/* Everything one bounded launch produced, kept so the report and the wait can
 * run after the launch sequence without re-deriving any state. */
struct bounded_launch {
    HANDLE job;
    PROCESS_INFORMATION process;
    bool job_ok;
    DWORD job_error;
    bool started;
    DWORD start_error;
    bool assigned;
    DWORD assign_error;
    bool resumed;
    DWORD resume_error;
};

static void create_kill_job(struct bounded_launch *launch)
{
    launch->job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    launch->job_ok = launch->job && SetInformationJobObject(
        launch->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    launch->job_error = launch->job_ok ? ERROR_SUCCESS : GetLastError();
}

static void launch_suspended(struct bounded_launch *launch,
                             wchar_t *const argv[], wchar_t *line,
                             DWORD previous_thread_mode)
{
    create_kill_job(launch);
    STARTUPINFOW startup = {.cb = sizeof(startup),
                            .dwFlags = STARTF_USESHOWWINDOW,
                            .wShowWindow = SW_HIDE};
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                  CREATE_UNICODE_ENVIRONMENT;
    launch->started = launch->job_ok && CreateProcessW(
        argv[0], line, NULL, NULL, TRUE, flags, NULL, NULL,
        &startup, &launch->process);
    launch->start_error = launch->started ? ERROR_SUCCESS : GetLastError();
    (void)SetThreadErrorMode(previous_thread_mode, NULL);
    launch->assigned = launch->started &&
        AssignProcessToJobObject(launch->job, launch->process.hProcess);
    launch->assign_error = launch->assigned ? ERROR_SUCCESS : GetLastError();
    launch->resumed = launch->assigned &&
        ResumeThread(launch->process.hThread) != (DWORD)-1;
    launch->resume_error = launch->resumed ? ERROR_SUCCESS : GetLastError();
    if (launch->started && !launch->resumed)
        (void)TerminateProcess(launch->process.hProcess, RUN_INFRA);
}

static void report_launch_failure(const struct bounded_launch *launch,
                                  const wchar_t *program)
{
    if (!launch->job_ok)
        fwprintf(stderr,
                 L"z23_bounded_run: Job Object setup failed winerr=%lu\n",
                 (unsigned long)launch->job_error);
    else if (!launch->started)
        fwprintf(stderr,
                 L"z23_bounded_run: CreateProcessW failed path=%ls winerr=%lu\n",
                 program, (unsigned long)launch->start_error);
    else if (!launch->assigned)
        fwprintf(stderr,
                 L"z23_bounded_run: AssignProcessToJobObject failed winerr=%lu\n",
                 (unsigned long)launch->assign_error);
    else if (!launch->resumed)
        fwprintf(stderr,
                 L"z23_bounded_run: ResumeThread failed winerr=%lu\n",
                 (unsigned long)launch->resume_error);
}

static int finish_wait(const struct bounded_launch *launch, DWORD waited)
{
    if (waited == WAIT_TIMEOUT) {
        (void)TerminateJobObject(launch->job, RUN_TIMEOUT);
        (void)WaitForSingleObject(launch->process.hProcess, 5000u);
        return RUN_TIMEOUT;
    }
    if (waited == WAIT_OBJECT_0) {
        DWORD exit_code = RUN_INFRA;
        if (GetExitCodeProcess(launch->process.hProcess, &exit_code))
            return (int)exit_code;
        fwprintf(stderr,
                 L"z23_bounded_run: GetExitCodeProcess failed "
                 L"winerr=%lu\n",
                 (unsigned long)GetLastError());
        return RUN_INFRA;
    }
    fwprintf(stderr,
             L"z23_bounded_run: WaitForSingleObject failed "
             L"result=%lu winerr=%lu\n",
             (unsigned long)waited, (unsigned long)GetLastError());
    return RUN_INFRA;
}

static int wait_for_launch(const struct bounded_launch *launch,
                           uint64_t timeout_ms)
{
    if (!launch->resumed)
        return RUN_INFRA;
    DWORD waited = WaitForSingleObject(launch->process.hProcess,
                                       (DWORD)timeout_ms);
    return finish_wait(launch, waited);
}

static int run_bounded(uint64_t timeout_ms, wchar_t *const argv[])
{
    if (!argv || !argv[0] || timeout_ms == 0 || timeout_ms > UINT32_MAX)
        return RUN_INFRA;
    wchar_t *line = make_command_line(argv);
    if (!line)
        return RUN_INFRA;

    (void)SetErrorMode(GetErrorMode() | Z23_BOUNDED_ERROR_MODE);
    DWORD previous_thread_mode = 0;
    if (!SetThreadErrorMode(Z23_BOUNDED_ERROR_MODE, &previous_thread_mode)) {
        fwprintf(stderr,
                 L"z23_bounded_run: SetThreadErrorMode failed winerr=%lu\n",
                 (unsigned long)GetLastError());
        free(line);
        return RUN_INFRA;
    }

    struct bounded_launch launch = {0};
    launch_suspended(&launch, argv, line, previous_thread_mode);
    report_launch_failure(&launch, argv[0]);
    int result = wait_for_launch(&launch, timeout_ms);

    if (launch.started) {
        CloseHandle(launch.process.hThread);
        CloseHandle(launch.process.hProcess);
    }
    if (launch.job)
        CloseHandle(launch.job); /* kills any descendant the primary left behind */
    free(line);
    return result;
}

static int selftest(const wchar_t *self)
{
    wchar_t *const pass_argv[] = {(wchar_t *)self, L"--selftest-pass", NULL};
    wchar_t *const fail_argv[] = {(wchar_t *)self, L"--selftest-fail", NULL};
    wchar_t *const wait_argv[] = {(wchar_t *)self, L"--selftest-wait", NULL};
    bool ok = run_bounded(1000u, pass_argv) == 0 &&
              run_bounded(1000u, fail_argv) == 23 &&
              run_bounded(50u, wait_argv) == RUN_TIMEOUT;
    wprintf(L"z23_bounded_run: selftest %ls\n", ok ? L"PASS" : L"FAIL");
    return ok ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && wcscmp(argv[1], L"--selftest") == 0)
        return selftest(argv[0]);
    if (argc == 2 && wcscmp(argv[1], L"--selftest-pass") == 0)
        return 0;
    if (argc == 2 && wcscmp(argv[1], L"--selftest-fail") == 0)
        return 23;
    if (argc == 2 && wcscmp(argv[1], L"--selftest-wait") == 0) {
        Sleep(INFINITE);
        return RUN_INFRA;
    }
    if (argc < 3) {
        fwprintf(stderr, L"usage: %ls TIMEOUT_MS ABSOLUTE_PROGRAM [arg ...]\n",
                 argv[0]);
        return RUN_INFRA;
    }
    unsigned long long parsed = 0;
    if (!parse_timeout_arg(argv[1], &parsed) || !absolute_path(argv[2])) {
        fwprintf(stderr,
                 L"z23_bounded_run: invalid timeout or non-absolute program\n");
        return RUN_INFRA;
    }
    return run_bounded((uint64_t)parsed, &argv[2]);
}

#else
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { RUN_TIMEOUT = 124, RUN_INFRA = 125 };

static bool monotonic_ms(uint64_t *out)
{
    struct timespec now;
    if (!out || clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) // platform-ok:standalone proof runner links no platform clock
        return false;
    uint64_t seconds = (uint64_t)now.tv_sec;
    if (seconds > UINT64_MAX / 1000u) return false;
    *out = seconds * 1000u + (uint64_t)now.tv_nsec / 1000000u;
    return true;
}

static void signal_group(pid_t leader, int signal_number)
{
    if (leader > 1 && kill(-leader, signal_number) != 0 && errno != ESRCH)
        fprintf(stderr, "z23_bounded_run: cannot signal process group %ld: %s\n",
                (long)leader, strerror(errno));
}

static void reap_group(pid_t leader)
{
    struct timespec grace = {.tv_nsec = 100000000L};
    signal_group(leader, SIGTERM);
    (void)nanosleep(&grace, NULL);
    signal_group(leader, SIGKILL);
}

/* The claim under test is that a descendant does not SURVIVE the bounded
 * run.  A loaded host may not schedule the tree child within the 100 ms
 * SIGTERM grace; the descendant then dies by group SIGKILL and is reaped by
 * the system reaper on its own schedule.  Poll for dead-and-reaped (kill
 * reports ESRCH) with a bounded deadline: a descendant that genuinely
 * escaped the process group (setsid/daemonize) stays alive and still fails
 * here. */
static bool bounded_run_wait_reaped(pid_t pid, uint64_t timeout_ms)
{
    uint64_t deadline = 0;
    if (!monotonic_ms(&deadline)) return false;
    deadline += timeout_ms;
    for (;;) {
        if (kill(pid, 0) != 0 && errno == ESRCH) return true;
        uint64_t now = 0;
        if (!monotonic_ms(&now) || now >= deadline) return false;
        struct timespec tick = {.tv_nsec = 1000000L};
        (void)nanosleep(&tick, NULL);
    }
}

static int child_status(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return RUN_INFRA;
}

static bool parse_timeout_arg(const char *text, unsigned long long *parsed)
{
    char *end = NULL;
    errno = 0;
    *parsed = strtoull(text, &end, 10);
    return !errno && end && !*end && timeout_ms_in_range(*parsed);
}

/* Forks the session leader; only the child branch execs or exits. */
static pid_t spawn_leader(char *const argv[])
{
    pid_t leader = fork();
    if (leader < 0) {
        fprintf(stderr, "z23_bounded_run: fork failed: %s\n", strerror(errno));
        return leader;
    }
    if (leader == 0) {
        if (setsid() < 0) _exit(RUN_INFRA);
        execv(argv[0], argv);
        _exit(RUN_INFRA);
    }
    return leader;
}

static int wait_for_leader(pid_t leader, uint64_t started, uint64_t timeout_ms)
{
    for (;;) {
        int status = 0;
        pid_t got = waitpid(leader, &status, WNOHANG);
        if (got == leader) {
            /* A test is not allowed to daemonize proof work.  Clean any
             * surviving members even when the session leader exited first. */
            reap_group(leader);
            return child_status(status);
        }
        if (got < 0) {
            if (errno == EINTR) continue;
            reap_group(leader);
            return RUN_INFRA;
        }
        uint64_t now = 0;
        if (!monotonic_ms(&now) || now < started) {
            reap_group(leader);
            (void)waitpid(leader, NULL, 0);
            return RUN_INFRA;
        }
        if (now - started >= timeout_ms) {
            reap_group(leader);
            while (waitpid(leader, NULL, 0) < 0 && errno == EINTR) { }
            return RUN_TIMEOUT;
        }
        struct timespec tick = {.tv_nsec = 1000000L};
        (void)nanosleep(&tick, NULL);
    }
}

static int run_bounded(uint64_t timeout_ms, char *const argv[])
{
    if (!argv || !argv[0] || timeout_ms == 0) return RUN_INFRA;
    pid_t leader = spawn_leader(argv);
    if (leader < 0) return RUN_INFRA;

    uint64_t started = 0;
    if (!monotonic_ms(&started)) {
        reap_group(leader);
        (void)waitpid(leader, NULL, 0);
        return RUN_INFRA;
    }
    return wait_for_leader(leader, started, timeout_ms);
}

static volatile sig_atomic_t selftest_stop;

static void selftest_stop_handler(int signal_number)
{
    (void)signal_number;
    selftest_stop = 1;
}

static int selftest_tree(const char *pid_path)
{
    pid_t descendant = fork();
    if (descendant < 0) return 2;
    if (descendant == 0) {
        for (;;) pause();
    }
    FILE *pid_file = fopen(pid_path, "w");
    bool wrote_pid = pid_file &&
        fprintf(pid_file, "%ld\n", (long)descendant) > 0;
    if (pid_file && fclose(pid_file) != 0) wrote_pid = false;
    if (!wrote_pid) {
        (void)kill(descendant, SIGKILL);
        (void)waitpid(descendant, NULL, 0);
        return 2;
    }
    struct sigaction action = {0};
    action.sa_handler = selftest_stop_handler;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0) return 2;
    while (!selftest_stop) pause();
    while (waitpid(descendant, NULL, 0) < 0 && errno == EINTR) { }
    return 0;
}

static int selftest(const char *self)
{
    char *const pass_argv[] = {(char *)self, "--selftest-pass", NULL};
    char *const fail_argv[] = {(char *)self, "--selftest-fail", NULL};
    char pid_path[] = "/tmp/z23-bounded-run-XXXXXX";
    int pid_fd = mkstemp(pid_path);
    if (pid_fd < 0 || close(pid_fd) != 0) {
        if (pid_fd >= 0) (void)unlink(pid_path);
        return 1;
    }
    char *const tree_argv[] = {
        (char *)self, "--selftest-tree", pid_path, NULL};
    int status = run_bounded(1000u, pass_argv);
    if (status != 0) {
        fprintf(stderr, "z23_bounded_run: selftest pass returned %d (want 0)\n", status);
        (void)unlink(pid_path);
        return 1;
    }
    status = run_bounded(1000u, fail_argv);
    if (status != 23) {
        fprintf(stderr, "z23_bounded_run: selftest fail returned %d (want 23)\n", status);
        (void)unlink(pid_path);
        return 1;
    }
    /* A loaded proof host may schedule the child after the old 250 ms bound.
     * Still require the timeout and descendant reap, but give startup time. */
    status = run_bounded(2000u, tree_argv);
    if (status != RUN_TIMEOUT) {
        fprintf(stderr, "z23_bounded_run: selftest tree returned %d (want %d)\n",
                status, RUN_TIMEOUT);
        (void)unlink(pid_path);
        return 1;
    }
    FILE *pid_file = fopen(pid_path, "r");
    long descendant = 0;
    bool read_pid = pid_file && fscanf(pid_file, "%ld", &descendant) == 1;
    if (pid_file) (void)fclose(pid_file);
    (void)unlink(pid_path);
    if (!read_pid || descendant <= 1 || descendant > INT_MAX) {
        fprintf(stderr, "z23_bounded_run: selftest tree did not record a child pid\n");
        return 1;
    }
    if (!bounded_run_wait_reaped((pid_t)descendant, 2000u)) {
        fprintf(stderr, "z23_bounded_run: selftest tree left child %ld alive\n",
                descendant);
        return 1;
    }
    puts("z23_bounded_run: selftest PASS");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest(argv[0]);
    if (argc == 2 && strcmp(argv[1], "--selftest-pass") == 0) return 0;
    if (argc == 2 && strcmp(argv[1], "--selftest-fail") == 0) return 23;
    if (argc == 3 && strcmp(argv[1], "--selftest-tree") == 0)
        return selftest_tree(argv[2]);
    if (argc < 3) {
        fprintf(stderr, "usage: %s TIMEOUT_MS /absolute/program [arg ...]\n",
                argv[0]);
        return RUN_INFRA;
    }
    unsigned long long parsed = 0;
    if (!parse_timeout_arg(argv[1], &parsed) || argv[2][0] != '/') {
        fprintf(stderr, "z23_bounded_run: invalid timeout or non-absolute program\n");
        return RUN_INFRA;
    }
    return run_bounded((uint64_t)parsed, &argv[2]);
}
#endif
