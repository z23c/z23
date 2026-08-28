/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * spawn — no-shell process-launch primitives. See util/spawn.h for the
 * full contract and the SA_NOCLDWAIT / fork-in-threaded-process notes this
 * implementation depends on. */

#include "util/spawn.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef _WIN32

/* Native package/agent execution stays unavailable until the controller owns
 * a restricted token, kill-on-close Job Object, resource limits, low-integrity
 * filesystem boundary, and network denial. Refuse before opening pipes, logs,
 * or creating a process. */
struct zcl_result zcl_spawn_detached(const char *const argv[],
                                     const char *log_path)
{
    return zcl_spawn_detached_input(argv, NULL, 0, log_path);
}

struct zcl_result zcl_spawn_detached_input(const char *const argv[],
                                           const void *input,
                                           size_t input_len,
                                           const char *log_path)
{
    (void)argv; (void)input; (void)input_len; (void)log_path;
    return ZCL_ERR(-1, "spawn: Windows execution sandbox is not qualified");
}

int zcl_spawn_capture_cancelable(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled)
{
    (void)argv; (void)timeout_ms; (void)should_cancel; (void)cancel_ctx;
    if (buf && cap > 0) buf[0] = '\0';
    if (cancelled) *cancelled = false;
    return -1;
}

int zcl_spawn_capture(const char *const argv[], char *buf, size_t cap,
                      int timeout_ms)
{
    return zcl_spawn_capture_cancelable(argv, buf, cap, timeout_ms,
                                        NULL, NULL, NULL);
}

#else

/* ── Shared helpers (parent-side only — never called between fork/exec) ── */

/* Reap `pid`, tolerating ECHILD (SA_NOCLDWAIT — see util/spawn.h). Retries
 * on EINTR. Returns true if a trustworthy exit status was obtained (written
 * to *status), false otherwise (ECHILD or another wait failure). */
static bool spawn_reap(pid_t pid, int *status)
{
    for (;;) {
        pid_t r = waitpid(pid, status, 0);
        if (r == pid) return true;
        if (r < 0 && errno == EINTR) continue;
        return false;   /* ECHILD (SA_NOCLDWAIT) or another wait failure */
    }
}

/* ── zcl_spawn_detached ──────────────────────────────────────────────── */

/* Child-side only: async-signal-safe setup + exec. Never returns on
 * success. On failure, best-effort writes errno to err_fd (if >= 0) and
 * _exit(127). Only async-signal-safe calls happen in this function. */
static void spawn_grandchild_exec(const char *const argv[],
                                   const char *log_path, int err_fd,
                                   int stdin_fd)
{
    if (stdin_fd >= 0) {
        dup2(stdin_fd, STDIN_FILENO);
        if (stdin_fd > STDERR_FILENO) close(stdin_fd);
    } else {
        int devnull_in = open("/dev/null", O_RDONLY);
        if (devnull_in >= 0) {
            dup2(devnull_in, STDIN_FILENO);
            if (devnull_in > STDERR_FILENO) close(devnull_in);
        }
    }

    int out_fd = log_path ? open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600)
                          : open("/dev/null", O_WRONLY);
    if (out_fd >= 0) {
        dup2(out_fd, STDOUT_FILENO);
        dup2(out_fd, STDERR_FILENO);
        if (out_fd > STDERR_FILENO) close(out_fd);
    }

    execvp(argv[0], (char *const *)argv);

    /* execvp failed — relay errno to the parent via the CLOEXEC pipe. */
    int e = errno;
    ssize_t written = (err_fd >= 0) ? write(err_fd, &e, sizeof(e)) : 0;
    (void)written;   /* best-effort; nothing else safe to do here */
    _exit(127);
}

struct zcl_result zcl_spawn_detached(const char *const argv[],
                                      const char *log_path)
{
    return zcl_spawn_detached_input(argv, NULL, 0, log_path);
}

struct zcl_result zcl_spawn_detached_input(const char *const argv[],
                                            const void *input,
                                            size_t input_len,
                                            const char *log_path)
{
    if (!argv || !argv[0])
        return ZCL_ERR(-1, "zcl_spawn_detached_input: NULL/empty argv");
    if ((!input && input_len != 0) || input_len > ZCL_SPAWN_INPUT_MAX)
        return ZCL_ERR(-1,
                       "zcl_spawn_detached_input: invalid input length %zu",
                       input_len);

    int input_pair[2] = { -1, -1 };
    if (input || input_len > 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, input_pair) != 0)
            return ZCL_ERR(-errno,
                           "zcl_spawn_detached_input: socketpair() failed: %s",
                           strerror(errno));
    }

    int errpipe[2];
    if (pipe(errpipe) != 0) {
        int e = errno;
        if (input_pair[0] >= 0) {
            close(input_pair[0]);
            close(input_pair[1]);
        }
        return ZCL_ERR(-e, "zcl_spawn_detached_input: pipe() failed: %s",
                       strerror(e));
    }
    /* Write end must close-on-exec: a successful grandchild exec closes
     * it automatically (its only copy), which is how the parent learns
     * "exec succeeded" (EOF on read) vs "exec failed" (errno bytes
     * arrive first). */
    if (fcntl(errpipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        int e = errno;
        close(errpipe[0]); close(errpipe[1]);
        if (input_pair[0] >= 0) {
            close(input_pair[0]);
            close(input_pair[1]);
        }
        return ZCL_ERR(-e, "zcl_spawn_detached_input: fcntl(FD_CLOEXEC) failed: %s",
                       strerror(e));
    }

    pid_t child1 = fork();
    if (child1 < 0) {
        int e = errno;
        close(errpipe[0]); close(errpipe[1]);
        if (input_pair[0] >= 0) {
            close(input_pair[0]);
            close(input_pair[1]);
        }
        return ZCL_ERR(-e, "zcl_spawn_detached_input: fork() failed: %s",
                       strerror(e));
    }

    if (child1 == 0) {
        /* First child: become session leader (detach from any controlling
         * tty), then fork the grandchild that actually execs. Only
         * async-signal-safe calls from here to _exit()/exec(). */
        close(errpipe[0]);
        if (input_pair[0] >= 0) close(input_pair[0]);
        setsid();

        pid_t child2 = fork();
        if (child2 < 0) {
            int e = errno;
            ssize_t written = write(errpipe[1], &e, sizeof(e));
            (void)written;
            _exit(127);
        }
        if (child2 == 0) {
            spawn_grandchild_exec(argv, log_path, errpipe[1], input_pair[1]);
            /* unreachable */
        }
        /* Still child1: hand off immediately so the grandchild is
         * reparented to init/subreaper without delay. Do not wait for
         * it — that is the entire point of "detached". */
        close(errpipe[1]);
        if (input_pair[1] >= 0) close(input_pair[1]);
        _exit(0);
    }

    /* Parent. */
    close(errpipe[1]);   /* close our own copy, else read() below never sees EOF */
    if (input_pair[1] >= 0) close(input_pair[1]);

    int status = 0;
    spawn_reap(child1, &status);   /* reap the intermediate child; ECHILD-tolerant */

    int child_errno = 0;
    ssize_t n;
    do {
        n = read(errpipe[0], &child_errno, sizeof(child_errno));
    } while (n < 0 && errno == EINTR);
    close(errpipe[0]);

    if (n == (ssize_t)sizeof(child_errno)) {
        if (input_pair[0] >= 0) close(input_pair[0]);
        return ZCL_ERR(-child_errno,
                       "zcl_spawn_detached_input: execvp(%s) failed: %s",
                       argv[0], strerror(child_errno));
    }
    if (n < 0) {
        int e = errno;
        if (input_pair[0] >= 0) close(input_pair[0]);
        return ZCL_ERR(-e,
                       "zcl_spawn_detached_input: read(errpipe) failed: %s",
                       strerror(e));
    }
    /* n == 0: EOF with no error bytes -> the grandchild's exec succeeded
     * (its CLOEXEC copy of the write end closed as part of exec()). */
    if (input_pair[0] >= 0) {
        const unsigned char *bytes = input;
        size_t sent = 0;
        while (sent < input_len) {
            ssize_t nw = send(input_pair[0], bytes + sent,
                              input_len - sent, MSG_NOSIGNAL);
            if (nw > 0) {
                sent += (size_t)nw;
                continue;
            }
            if (nw < 0 && errno == EINTR) continue;
            int e = nw < 0 ? errno : EIO;
            close(input_pair[0]);
            return ZCL_ERR(-e,
                           "zcl_spawn_detached_input: stdin delivery failed: %s",
                           strerror(e));
        }
        (void)shutdown(input_pair[0], SHUT_WR);
        close(input_pair[0]);
    }
    return ZCL_OK;
}

/* ── zcl_spawn_capture ───────────────────────────────────────────────── */

int zcl_spawn_capture_cancelable(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled)
{
    if (cancelled) *cancelled = false;
    if (!argv || !argv[0] || !buf || cap == 0)
        LOG_ERR("spawn", "bad args (argv=%p buf=%p cap=%zu)",
                (const void *)argv, (void *)buf, cap);
    buf[0] = '\0';

    int outpipe[2];
    if (pipe(outpipe) != 0)
        LOG_ERR("spawn", "pipe() failed: %s", strerror(errno));

    pid_t pid = fork();
    if (pid < 0) {
        close(outpipe[0]); close(outpipe[1]);
        LOG_ERR("spawn", "fork() failed: %s", strerror(errno));
    }

    if (pid == 0) {
        /* Child: only async-signal-safe calls until exec/_exit. */
        setpgid(0, 0);
        close(outpipe[0]);
        dup2(outpipe[1], STDOUT_FILENO);
        if (outpipe[1] != STDOUT_FILENO) close(outpipe[1]);

        int devnull_in = open("/dev/null", O_RDONLY);
        if (devnull_in >= 0) {
            dup2(devnull_in, STDIN_FILENO);
            if (devnull_in > STDERR_FILENO) close(devnull_in);
        }
        int devnull_err = open("/dev/null", O_WRONLY);
        if (devnull_err >= 0) {
            dup2(devnull_err, STDERR_FILENO);
            if (devnull_err > STDERR_FILENO) close(devnull_err);
        }

        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    /* Parent. */
    close(outpipe[1]);
    (void)setpgid(pid, pid); /* child also does this; either side may win */

    size_t used = 0;
    char discard[4096];
    int64_t deadline_ms = (timeout_ms > 0)
                          ? platform_time_monotonic_ms() + timeout_ms : 0;
    bool timed_out = false;
    bool was_cancelled = false;

    for (;;) {
        if (should_cancel && should_cancel(cancel_ctx)) {
            was_cancelled = true;
            break;
        }
        struct pollfd pfd = { .fd = outpipe[0], .events = POLLIN };
        int poll_timeout = -1;
        if (timeout_ms > 0) {
            int64_t remain = deadline_ms - platform_time_monotonic_ms();
            if (remain <= 0) { timed_out = true; break; }
            poll_timeout = (remain > INT_MAX) ? INT_MAX : (int)remain;
        }
        if (should_cancel && (poll_timeout < 0 || poll_timeout > 100))
            poll_timeout = 100;
        int pr = poll(&pfd, 1, poll_timeout);
        if (pr < 0) {
            if (errno == EINTR) continue;
            LOG_WARN("spawn", "poll() failed: %s", strerror(errno));
            break;
        }
        if (pr == 0) {
            if (should_cancel) continue; /* periodic durable-state poll */
            timed_out = true;
            break;
        }

        char *dst = (used < cap - 1) ? buf + used : discard;
        size_t dst_cap = (used < cap - 1) ? (cap - 1 - used) : sizeof(discard);
        ssize_t n = read(outpipe[0], dst, dst_cap);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_WARN("spawn", "read() failed: %s", strerror(errno));
            break;
        }
        if (n == 0) break;   /* EOF: child closed its stdout */
        if (used < cap - 1) used += (size_t)n;
    }
    buf[used] = '\0';
    close(outpipe[0]);

    if (timed_out || was_cancelled) {
        if (kill(-pid, SIGKILL) != 0)
            (void)kill(pid, SIGKILL);
    }
    if (cancelled) *cancelled = was_cancelled;

    int status = 0;
    if (!spawn_reap(pid, &status)) {
        /* ECHILD (SA_NOCLDWAIT) or another wait failure: the output
         * already captured above is still valid; exit status is simply
         * unknown — documented contract in util/spawn.h. */
        return 0;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 0;
}

int zcl_spawn_capture(const char *const argv[], char *buf, size_t cap,
                       int timeout_ms)
{
    return zcl_spawn_capture_cancelable(
        argv, buf, cap, timeout_ms, NULL, NULL, NULL);
}

#endif

/* ── zcl_argv_split ──────────────────────────────────────────────────── */

size_t zcl_argv_split(char *str, const char *argv[], size_t max)
{
    if (!argv || max == 0)
        return 0;
    size_t n = 0;
    if (str) {
        char *p = str;
        while (*p && n < max - 1) {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            if (!*p) break;
            argv[n++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
                p++;
            if (*p) *p++ = '\0';
        }
    }
    argv[n] = NULL;
    return n;
}
