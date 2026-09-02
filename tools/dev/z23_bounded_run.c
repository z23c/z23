/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Run one local proof executable under a bounded process-tree rail.
 *
 * This deliberately small helper exists because macOS has no standard
 * timeout(1), Windows must never surface a console or crash dialog, and
 * killing only a test's immediate PID can leave descendants alive after a
 * gate reports failure. POSIX children start a new session; Windows children
 * run under a kill-on-close Job Object. */
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
        if (*cursor == L'\"') {
            for (size_t i = 0; i < slashes * 2u + 1u; i++)
                if (!append_wide(line, L'\\'))
                    return false;
            if (!append_wide(line, L'\"'))
                return false;
        } else {
            if (*cursor == 0 && quote)
                slashes *= 2u;
            for (size_t i = 0; i < slashes; i++)
                if (!append_wide(line, L'\\'))
                    return false;
            if (*cursor == 0)
                break;
            if (!append_wide(line, *cursor))
                return false;
        }
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

    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    bool job_ok = job && SetInformationJobObject(
        job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    DWORD job_error = job_ok ? ERROR_SUCCESS : GetLastError();
    STARTUPINFOW startup = {.cb = sizeof(startup),
                            .dwFlags = STARTF_USESHOWWINDOW,
                            .wShowWindow = SW_HIDE};
    PROCESS_INFORMATION process = {0};
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                  CREATE_UNICODE_ENVIRONMENT;
    bool started = job_ok && CreateProcessW(
        argv[0], line, NULL, NULL, TRUE, flags, NULL, NULL,
        &startup, &process);
    DWORD start_error = started ? ERROR_SUCCESS : GetLastError();
    (void)SetThreadErrorMode(previous_thread_mode, NULL);
    bool assigned = started && AssignProcessToJobObject(job, process.hProcess);
    DWORD assign_error = assigned ? ERROR_SUCCESS : GetLastError();
    bool resumed = assigned && ResumeThread(process.hThread) != (DWORD)-1;
    DWORD resume_error = resumed ? ERROR_SUCCESS : GetLastError();
    if (started && !resumed)
        (void)TerminateProcess(process.hProcess, RUN_INFRA);

    if (!job_ok)
        fwprintf(stderr,
                 L"z23_bounded_run: Job Object setup failed winerr=%lu\n",
                 (unsigned long)job_error);
    else if (!started)
        fwprintf(stderr,
                 L"z23_bounded_run: CreateProcessW failed path=%ls winerr=%lu\n",
                 argv[0], (unsigned long)start_error);
    else if (!assigned)
        fwprintf(stderr,
                 L"z23_bounded_run: AssignProcessToJobObject failed winerr=%lu\n",
                 (unsigned long)assign_error);
    else if (!resumed)
        fwprintf(stderr,
                 L"z23_bounded_run: ResumeThread failed winerr=%lu\n",
                 (unsigned long)resume_error);

    int result = RUN_INFRA;
    if (resumed) {
        DWORD waited = WaitForSingleObject(process.hProcess, (DWORD)timeout_ms);
        if (waited == WAIT_TIMEOUT) {
            (void)TerminateJobObject(job, RUN_TIMEOUT);
            (void)WaitForSingleObject(process.hProcess, 5000u);
            result = RUN_TIMEOUT;
        } else if (waited == WAIT_OBJECT_0) {
            DWORD exit_code = RUN_INFRA;
            if (GetExitCodeProcess(process.hProcess, &exit_code))
                result = (int)exit_code;
            else
                fwprintf(stderr,
                         L"z23_bounded_run: GetExitCodeProcess failed "
                         L"winerr=%lu\n",
                         (unsigned long)GetLastError());
        } else {
            fwprintf(stderr,
                     L"z23_bounded_run: WaitForSingleObject failed "
                     L"result=%lu winerr=%lu\n",
                     (unsigned long)waited, (unsigned long)GetLastError());
        }
    }

    if (started) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if (job)
        CloseHandle(job); /* kills any descendant the primary left behind */
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
    wchar_t *end = NULL;
    errno = 0;
    unsigned long long parsed = wcstoull(argv[1], &end, 10);
    if (errno || !end || *end || parsed == 0 || parsed > UINT32_MAX ||
        !absolute_path(argv[2])) {
        fwprintf(stderr,
                 L"z23_bounded_run: invalid timeout or non-absolute program\n");
        return RUN_INFRA;
    }
    return run_bounded((uint64_t)parsed, &argv[2]);
}

#else
#define _POSIX_C_SOURCE 200809L

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

static int child_status(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return RUN_INFRA;
}

static int run_bounded(uint64_t timeout_ms, char *const argv[])
{
    if (!argv || !argv[0] || timeout_ms == 0) return RUN_INFRA;
    pid_t leader = fork();
    if (leader < 0) {
        fprintf(stderr, "z23_bounded_run: fork failed: %s\n", strerror(errno));
        return RUN_INFRA;
    }
    if (leader == 0) {
        if (setsid() < 0) _exit(RUN_INFRA);
        execv(argv[0], argv);
        _exit(RUN_INFRA);
    }

    uint64_t started = 0;
    if (!monotonic_ms(&started)) {
        reap_group(leader);
        (void)waitpid(leader, NULL, 0);
        return RUN_INFRA;
    }
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
    if (run_bounded(1000u, pass_argv) != 0) return 1;
    if (run_bounded(1000u, fail_argv) != 23) return 1;
    if (run_bounded(250u, tree_argv) != RUN_TIMEOUT) {
        (void)unlink(pid_path);
        return 1;
    }
    FILE *pid_file = fopen(pid_path, "r");
    long descendant = 0;
    bool read_pid = pid_file && fscanf(pid_file, "%ld", &descendant) == 1;
    if (pid_file) (void)fclose(pid_file);
    (void)unlink(pid_path);
    if (!read_pid || descendant <= 1 || descendant > INT_MAX ||
        kill((pid_t)descendant, 0) == 0 || errno != ESRCH)
        return 1;
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
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(argv[1], &end, 10);
    if (errno || !end || *end || parsed == 0 || parsed > UINT32_MAX ||
        argv[2][0] != '/') {
        fprintf(stderr, "z23_bounded_run: invalid timeout or non-absolute program\n");
        return RUN_INFRA;
    }
    return run_bounded((uint64_t)parsed, &argv[2]);
}
#endif
