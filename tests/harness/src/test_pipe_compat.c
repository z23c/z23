/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
int test_pipe_compat(void);
#include "platform/pipe_compat.h"
#include <stdio.h>
#if !defined(_WIN32)
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>

#if defined(__APPLE__)
static unsigned injected_sets;
static int injected_fcntl(int fd, int command, ...)
{
    if (command == F_GETNOSIGPIPE) return fcntl(fd, command);
    va_list args;
    va_start(args, command);
    int value = va_arg(args, int);
    va_end(args);
    if (command == F_SETNOSIGPIPE && ++injected_sets == 2) {
        errno = EINTR;
        return -1;
    }
    return fcntl(fd, command, value);
}
#undef ZCLASSIC_PLATFORM_PIPE_COMPAT_H
#define fcntl injected_fcntl
#define platform_pipe_cloexec_nonblock injected_pipe_create
#define platform_pipe_write_error injected_pipe_error
#define platform_pipe_write_nosigpipe injected_pipe_write
#include "platform/pipe_compat.h"
#undef fcntl
#undef platform_pipe_cloexec_nonblock
#undef platform_pipe_write_error
#undef platform_pipe_write_nosigpipe
#endif

static volatile sig_atomic_t signals;

static void observed(int signal_number) { (void)signal_number; signals++; }
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "pipe acceptance line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

static int check_exact_write(int read_fd, int write_fd)
{
    const char payload[] = "exact pipe bytes";
    errno = EDOM;
    CHECK(platform_pipe_write_nosigpipe(write_fd, payload, sizeof(payload)) == (ssize_t)sizeof(payload));
    CHECK(errno == EDOM);
    char received[sizeof(payload)];
    CHECK(read(read_fd, received, sizeof(received)) == (ssize_t)sizeof(received));
    CHECK(memcmp(received, payload, sizeof(payload)) == 0);
    return 0;
}

static int check_broken_pipe(int fd)
{
#if defined(__APPLE__)
    for (int flag = 0; flag <= 1; flag++) {
        CHECK(fcntl(fd, F_SETNOSIGPIPE, flag) == 0);
#endif
        errno = 0;
        CHECK(platform_pipe_write_nosigpipe(fd, "x", 1) == -1 && errno == EPIPE);
        CHECK(signals == 0);
#if defined(__APPLE__)
        CHECK(fcntl(fd, F_GETNOSIGPIPE) == flag);
    }
#endif
    return 0;
}

/* An ignored SIGPIPE creates no pending signal to drain on Linux. The write
 * must still return EPIPE, without changing the caller's signal policy. */
static int check_ignored_pipe(int fd)
{
    struct sigaction ignored = {.sa_handler = SIG_IGN}, previous;
    sigemptyset(&ignored.sa_mask);
    CHECK(sigaction(SIGPIPE, &ignored, &previous) == 0);
    errno = 0;
    ssize_t written = platform_pipe_write_nosigpipe(fd, "x", 1);
    int saved = errno;
    int restored = sigaction(SIGPIPE, &previous, NULL);
    CHECK(restored == 0);
    CHECK(written == -1 && saved == EPIPE);
    return 0;
}

static int check_pending_signal(int fd, const sigset_t *original, const sigset_t *blocked)
{
    sigset_t after, pending;
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0);
    for (int signal_number = 1; signal_number < NSIG; signal_number++)
        CHECK(sigismember(original, signal_number) == sigismember(&after, signal_number));
    CHECK(pthread_sigmask(SIG_BLOCK, blocked, NULL) == 0);
    CHECK(raise(SIGPIPE) == 0);
    CHECK(platform_pipe_write_nosigpipe(fd, "x", 1) == -1 && errno == EPIPE);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    int caught = 0;
    CHECK(sigwait(blocked, &caught) == 0 && caught == SIGPIPE);
    CHECK(pthread_sigmask(SIG_SETMASK, original, NULL) == 0);
    return 0;
}

static int check_pipe_iterations(const sigset_t *original, const sigset_t *blocked)
{
    for (unsigned iteration = 0; iteration < 32; iteration++) {
        int pair[2];
        CHECK(platform_pipe_cloexec_nonblock(pair) == 0);
        CHECK(check_exact_write(pair[0], pair[1]) == 0);
        CHECK(close(pair[0]) == 0);
        CHECK(check_broken_pipe(pair[1]) == 0);
        CHECK(check_ignored_pipe(pair[1]) == 0);
        CHECK(check_pending_signal(pair[1], original, blocked) == 0);
        CHECK(close(pair[1]) == 0);
    }
    CHECK(platform_pipe_write_nosigpipe(-1, "x", 1) == -1 && errno == EBADF);
    return 0;
}

#if defined(__APPLE__)
static int check_restoration_failure(void)
{
    int restored[2];
    CHECK(platform_pipe_cloexec_nonblock(restored) == 0);
    CHECK(fcntl(restored[1], F_SETNOSIGPIPE, 0) == 0);
    injected_sets = 0;
    CHECK(injected_pipe_write(restored[1], "once", 4) == -1 && errno == EIO);
    CHECK(injected_sets == 2);
    char once[8];
    CHECK(read(restored[0], once, sizeof(once)) == 4 && memcmp(once, "once", 4) == 0);
    CHECK(read(restored[0], once, sizeof(once)) == -1 && errno == EAGAIN);
    CHECK(close(restored[0]) == 0 && close(restored[1]) == 0);
    return 0;
}
#endif

static void broken_stderr_child(const sigset_t *blocked)
{
    struct sigaction fatal = {.sa_handler = SIG_DFL};
    sigemptyset(&fatal.sa_mask);
    if (sigaction(SIGPIPE, &fatal, NULL) != 0) _exit(2);
    if (pthread_sigmask(SIG_UNBLOCK, blocked, NULL) != 0) _exit(3);
    int broken[2];
    if (pipe(broken) != 0) _exit(4);
    if (close(broken[0]) != 0 || dup2(broken[1], STDERR_FILENO) != STDERR_FILENO) _exit(5);
    if (close(broken[1]) != 0) _exit(6);
    ssize_t result = platform_pipe_write_nosigpipe(-1, "x", 1);
    _exit(result == -1 && errno == EBADF ? 0 : 7);
}

static int check_broken_stderr(const sigset_t *blocked)
{
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) broken_stderr_child(blocked);
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int check_pipe_behavior(const sigset_t *original, const sigset_t *blocked)
{
    int probe = dup(STDERR_FILENO);
    CHECK(probe >= 0);
    CHECK(close(probe) == 0);
    CHECK(check_pipe_iterations(original, blocked) == 0);
#if defined(__APPLE__)
    CHECK(check_restoration_failure() == 0);
#endif
    CHECK(check_broken_stderr(blocked) == 0);
    int final_probe = dup(STDERR_FILENO);
    CHECK(final_probe == probe);
    CHECK(close(final_probe) == 0);
    CHECK(signals == 0);
    return 0;
}

static int check_posix_pipe_compat(void)
{
    struct sigaction action = {.sa_handler = observed}, previous_action;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGPIPE, &action, &previous_action) == 0);
    sigset_t original, blocked;
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &original) == 0);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    signals = 0;
    int failures = check_pipe_behavior(&original, &blocked);
    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    CHECK(sigaction(SIGPIPE, &previous_action, NULL) == 0);
    if (!failures) puts("pipe compatibility: ALL PASS");
    return failures;
}
#else
static int check_windows_native_pipe_refusal(void)
{
    int descriptors[2] = {17, 19};
    errno = 0;
    if (platform_pipe_cloexec_nonblock(descriptors) != -1 || errno != ENOTSUP ||
        descriptors[0] != -1 || descriptors[1] != -1) {
        fprintf(stderr, "pipe compatibility: Windows native pipe refusal failed\n");
        return 1;
    }
    puts("pipe compatibility: Windows native pipe explicitly refused (ENOTSUP)");
    return 0;
}
#endif

int test_pipe_compat(void)
{
#if defined(_WIN32)
    return check_windows_native_pipe_refusal();
#else
    return check_posix_pipe_compat();
#endif
}
