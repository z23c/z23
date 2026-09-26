/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * spawn — no-shell process-launch primitives. See util/spawn.h for the
 * full contract and the SA_NOCLDWAIT / fork-in-threaded-process notes this
 * implementation depends on. */

#define _GNU_SOURCE /* posix_openpt/grantpt/unlockpt/ptsname */

#include "util/spawn.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
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
    return zcl_spawn_capture_observed(argv, buf, cap, timeout_ms, NULL);
}

static int spawn_capture_observed_platform(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    bool *timed_out)
{
    if (timed_out) *timed_out = false;
    return zcl_spawn_capture_cancelable(argv, buf, cap, timeout_ms,
                                        NULL, NULL, NULL);
}

static int spawn_capture_merged_observed_platform(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    bool *timed_out)
{
    (void)argv; (void)timeout_ms;
    if (buf && cap > 0) buf[0] = '\0';
    if (timed_out) *timed_out = false;
    return -1;
}

static int spawn_pty_capture_observed_platform(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    bool *timed_out)
{
    (void)argv; (void)timeout_ms;
    if (buf && cap > 0) buf[0] = '\0';
    if (timed_out) *timed_out = false;
    return -1;
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

static void spawn_capture_kill(pid_t pid)
{
    if (kill(-pid, SIGKILL) != 0)
        (void)kill(pid, SIGKILL);
}

static void spawn_capture_kill_group(pid_t pid, bool anchored)
{
    if (anchored) (void)kill(-pid, SIGKILL);
    else spawn_capture_kill(pid);
}

/* EOF is only an output observation. The child can close stdout before it
 * exits, so retain the drain's original deadline and cancellation callback
 * through the wait. Never start a second timeout budget here. */
static bool spawn_capture_reap(
    pid_t pid, int *status, int64_t deadline_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx,
    bool *timed_out, bool *cancelled, bool anchored)
{
    if (*timed_out || *cancelled) return spawn_reap(pid, status);
    for (;;) {
        if (should_cancel && should_cancel(cancel_ctx)) *cancelled = true;
        if (deadline_ms && platform_time_monotonic_ms() >= deadline_ms)
            *timed_out = true;
        if (*timed_out || *cancelled) {
            spawn_capture_kill_group(pid, anchored);
            return spawn_reap(pid, status);
        }
        pid_t observed = waitpid(pid, status, WNOHANG);
        if (observed == pid) return true;
        if (observed < 0) {
            if (errno == EINTR) continue;
            if (errno != ECHILD)
                LOG_WARN("spawn", "waitpid() after EOF failed: %s", strerror(errno));
            return false;
        }
        (void)poll(NULL, 0, 10);
    }
}

struct spawn_capture_buffer {
    char *bytes;
    size_t limit;
    size_t used;
    struct zcl_spawn_binary_observation *exact;
};

static ssize_t spawn_capture_read(int fd, struct spawn_capture_buffer *capture)
{
    char discard[4096];
    size_t available = capture->limit - capture->used;
    ssize_t n = read(fd, available ? capture->bytes + capture->used : discard,
                     available ? available : sizeof(discard));
    if (n <= 0) return n;
    if (available) capture->used += (size_t)n;
    else if (capture->exact) capture->exact->overflow = true;
    return n;
}

static void spawn_capture_observation(
    struct spawn_capture_buffer *capture, bool eof, bool timed_out,
    bool reaped, int status)
{
    struct zcl_spawn_binary_observation *out = capture->exact;
    if (!out) {
        capture->bytes[capture->used] = '\0';
        return;
    }
    out->output_len = capture->used;
    out->eof = eof;
    out->timed_out = timed_out;
    out->exit_observed = reaped;
    out->exit_code = -1;
    if (!reaped) return;
    if (WIFEXITED(status)) out->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) out->exit_code = 128 + WTERMSIG(status);
}

struct spawn_capture_exit_state {
    bool gone;
    bool observed;
    bool exited_now;
    int64_t started_ms;
};

static bool spawn_capture_exit_observe(
    pid_t pid, struct spawn_capture_exit_state *state, bool anchored)
{
    siginfo_t child_exit = {0};
    int observed = waitid(P_PID, (id_t)pid, &child_exit,
                          WEXITED | WNOHANG | WNOWAIT);
    state->exited_now = observed == 0 && child_exit.si_pid == pid;
    state->gone = observed < 0 && errno == ECHILD;
    if (state->exited_now) state->observed = true;
    if ((state->exited_now || state->gone) && state->started_ms < 0)
        state->started_ms = platform_time_monotonic_ms();
    if (state->started_ms >= 0 &&
        platform_time_monotonic_ms() - state->started_ms >= 25) {
        if ((state->observed || state->gone) && (!state->gone || anchored))
            spawn_capture_kill_group(pid, anchored);
        return true;
    }
    return false;
}

static int spawn_capture_poll_timeout(
    int timeout_ms, int64_t deadline_ms,
    const struct spawn_capture_exit_state *state, bool *timed_out)
{
    int timeout = state->exited_now || state->gone ? 0 : 25;
    if (timeout_ms > 0) {
        int64_t remain = deadline_ms - platform_time_monotonic_ms();
        if (remain <= 0) { *timed_out = true; return 0; }
        if (remain < timeout) timeout = (int)remain;
    }
    return timeout;
}

enum spawn_capture_step { SPAWN_CAPTURE_AGAIN, SPAWN_CAPTURE_STOP,
                          SPAWN_CAPTURE_EOF };

static enum spawn_capture_step spawn_capture_io_step(
    pid_t pid, int fd, int timeout_ms, bool pty_eio_is_eof,
    struct spawn_capture_buffer *capture,
    const struct spawn_capture_exit_state *state, bool anchored)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0) {
        if (errno == EINTR) return SPAWN_CAPTURE_AGAIN;
        LOG_WARN("spawn", "poll() failed: %s", strerror(errno));
        return SPAWN_CAPTURE_STOP;
    }
    if (pr == 0) {
        if (!state->exited_now && !state->gone) return SPAWN_CAPTURE_AGAIN;
        if ((state->observed || state->gone) && (!state->gone || anchored))
            spawn_capture_kill_group(pid, anchored);
        return SPAWN_CAPTURE_STOP;
    }
    ssize_t n = spawn_capture_read(fd, capture);
    if (n < 0) {
        if (errno == EINTR) return SPAWN_CAPTURE_AGAIN;
        if (pty_eio_is_eof && errno == EIO) return SPAWN_CAPTURE_STOP;
        LOG_WARN("spawn", "read() failed: %s", strerror(errno));
        return SPAWN_CAPTURE_STOP;
    }
    return n == 0 ? SPAWN_CAPTURE_EOF : SPAWN_CAPTURE_AGAIN;
}

/* Parent-side bounded drain shared by pipe and PTY capture. A Linux PTY
 * master reports EIO, rather than zero bytes, when its last slave closes;
 * `pty_eio_is_eof` preserves that platform contract without weakening real
 * pipe errors. */
static int spawn_capture_drain(
    pid_t pid, int output_fd, char *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled,
    bool *timed_out_out, bool pty_eio_is_eof,
    struct zcl_spawn_binary_observation *exact, int anchor_write_fd)
{
    struct spawn_capture_buffer capture = {
        .bytes = buf, .limit = exact ? cap : cap - 1, .exact = exact
    };
    bool eof = false;
    int64_t deadline_ms = (timeout_ms > 0)
                          ? platform_time_monotonic_ms() + timeout_ms : 0;
    bool timed_out = false;
    bool was_cancelled = false;
    struct spawn_capture_exit_state exit_state = {.started_ms = -1};

    for (;;) {
        if (should_cancel && should_cancel(cancel_ctx)) {
            was_cancelled = true;
            break;
        }
        /* WNOWAIT keeps the exited child waitable, pinning its original
         * group while buffered output drains. The anchor covers auto-reap. */
        if (spawn_capture_exit_observe(pid, &exit_state,
                                       anchor_write_fd >= 0)) break;
        int poll_timeout = spawn_capture_poll_timeout(
            timeout_ms, deadline_ms, &exit_state, &timed_out);
        if (timed_out) break;
        enum spawn_capture_step step = spawn_capture_io_step(
            pid, output_fd, poll_timeout, pty_eio_is_eof, &capture,
            &exit_state, anchor_write_fd >= 0);
        if (step == SPAWN_CAPTURE_EOF) { eof = true; break; }
        if (step == SPAWN_CAPTURE_STOP) break;
    }

    /* Kill before closing a PTY master: closing the master first raises
     * SIGHUP in the slave's foreground group and would erase the exact
     * timeout observation behind 128+SIGHUP. Pipes do not care about the
     * order, so one ordering preserves both transports. */
    if ((timed_out || was_cancelled) &&
        (!exit_state.gone || anchor_write_fd >= 0)) {
        spawn_capture_kill_group(pid, anchor_write_fd >= 0);
    }
    if (exact && !eof && (!exit_state.gone || anchor_write_fd >= 0))
        spawn_capture_kill_group(pid, anchor_write_fd >= 0);
    close(output_fd);
    int status = 0;
    bool reaped = !exit_state.gone && spawn_capture_reap(
        pid, &status, deadline_ms, should_cancel, cancel_ctx,
        &timed_out, &was_cancelled, anchor_write_fd >= 0);
    if (anchor_write_fd >= 0) close(anchor_write_fd);
    if (cancelled) *cancelled = was_cancelled;
    if (timed_out_out) *timed_out_out = timed_out;
    spawn_capture_observation(&capture, eof, timed_out, reaped, status);

    if (!reaped)
        return 0;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 0;
}

/* Called only in the fork child. The output pipe may occupy a standard
 * descriptor when the caller has closed one; duplicate before opening null. */
static void spawn_capture_child_stdio(int output_fd, bool merge_stderr)
{
    if (setpgid(0, 0) != 0) _exit(126);
    if (dup2(output_fd, STDOUT_FILENO) < 0) _exit(126);
    if (output_fd != STDOUT_FILENO) close(output_fd);
    int input = open("/dev/null", O_RDONLY);
    if (input < 0) _exit(126);
    if (dup2(input, STDIN_FILENO) < 0) _exit(126);
    if (input > STDERR_FILENO) close(input);
    if (merge_stderr) {
        if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) _exit(126);
        return;
    }
    int error = open("/dev/null", O_WRONLY);
    if (error < 0) _exit(126);
    if (dup2(error, STDERR_FILENO) < 0) _exit(126);
    if (error > STDERR_FILENO) close(error);
}

struct spawn_capture_anchor {
    bool enabled;
    int hold[2];
    int ready[2];
    int go[2];
};

static void spawn_capture_anchor_close(struct spawn_capture_anchor *anchor)
{
    int *ends[] = {anchor->hold, anchor->ready, anchor->go};
    for (size_t i = 0; i < 3; i++)
        for (size_t j = 0; j < 2; j++)
            if (ends[i][j] >= 0) close(ends[i][j]);
}

static bool spawn_capture_anchor_prepare(struct spawn_capture_anchor *anchor)
{
    *anchor = (struct spawn_capture_anchor){
        .hold = {-1, -1}, .ready = {-1, -1}, .go = {-1, -1}};
    struct sigaction disposition = {0};
    if (sigaction(SIGCHLD, NULL, &disposition) != 0) return false;
    anchor->enabled = (disposition.sa_flags & SA_NOCLDWAIT) != 0 ||
                      disposition.sa_handler == SIG_IGN;
    if (!anchor->enabled) return true;
    if (pipe(anchor->hold) == 0 && pipe(anchor->ready) == 0 &&
        pipe(anchor->go) == 0)
        return true;
    int saved = errno;
    spawn_capture_anchor_close(anchor);
    errno = saved;
    return false;
}

static void spawn_capture_anchor_wait_child(
    const struct spawn_capture_anchor *anchor, int output_fd)
{
    close(output_fd);
    close(anchor->go[0]);
    char ready = 'r';
    if (write(anchor->ready[1], &ready, 1) != 1) _exit(126);
    close(anchor->ready[1]);
    char discard;
    while (read(anchor->hold[0], &discard, 1) < 0 && errno == EINTR) {}
    _exit(0);
}

static void spawn_capture_anchor_child(
    const struct spawn_capture_anchor *anchor, int output_fd)
{
    if (!anchor->enabled) return;
    close(anchor->hold[1]); close(anchor->ready[0]);
    close(anchor->go[1]);
    if (setpgid(0, 0) != 0) _exit(126);
    pid_t member = fork();
    if (member < 0) _exit(126);
    if (member == 0) spawn_capture_anchor_wait_child(anchor, output_fd);
    close(anchor->hold[0]); close(anchor->ready[1]);
    char go = 0;
    ssize_t received;
    do { received = read(anchor->go[0], &go, 1); }
    while (received < 0 && errno == EINTR);
    close(anchor->go[0]);
    if (received != 1 || go != 'g') _exit(126);
}

static bool spawn_capture_anchor_parent(struct spawn_capture_anchor *anchor)
{
    if (!anchor->enabled) return true;
    close(anchor->hold[0]); anchor->hold[0] = -1;
    close(anchor->ready[1]); anchor->ready[1] = -1;
    char ready = 0;
    ssize_t got;
    do { got = read(anchor->ready[0], &ready, 1); }
    while (got < 0 && errno == EINTR);
    close(anchor->ready[0]); anchor->ready[0] = -1;
    bool started = got == 1 && ready == 'r';
    char go = 'g';
    bool launched = started && write(anchor->go[1], &go, 1) == 1;
    close(anchor->go[0]); anchor->go[0] = -1;
    close(anchor->go[1]); anchor->go[1] = -1;
    return launched;
}

static int spawn_capture_impl(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled,
    bool *timed_out_out, bool merge_stderr,
    struct zcl_spawn_binary_observation *exact)
{
    if (cancelled) *cancelled = false;
    if (timed_out_out) *timed_out_out = false;
    if (!argv || !argv[0] || !buf || cap == 0)
        LOG_ERR("spawn", "bad args (argv=%p buf=%p cap=%zu)",
                (const void *)argv, (void *)buf, cap);
    if (!exact) buf[0] = '\0';

    int outpipe[2];
    if (pipe(outpipe) != 0)
        LOG_ERR("spawn", "pipe() failed: %s", strerror(errno));

    /* With SA_NOCLDWAIT the direct child can disappear before capture sees
     * its exit. A short-lived member of its process group pins that group
     * number until the parent has closed the capture and finished cleanup. */
    struct spawn_capture_anchor anchor;
    if (!spawn_capture_anchor_prepare(&anchor)) {
        int saved = errno;
        close(outpipe[0]); close(outpipe[1]);
        LOG_ERR("spawn", "capture anchor setup failed: %s", strerror(saved));
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(outpipe[0]); close(outpipe[1]);
        spawn_capture_anchor_close(&anchor);
        LOG_ERR("spawn", "fork() failed: %s", strerror(errno));
    }

    if (pid == 0) {
        /* Child: only async-signal-safe calls until exec/_exit. */
        close(outpipe[0]);
        spawn_capture_anchor_child(&anchor, outpipe[1]);
        spawn_capture_child_stdio(outpipe[1], merge_stderr);

        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    /* Parent. */
    close(outpipe[1]);
    (void)setpgid(pid, pid); /* child also does this; either side may win */
    if (!spawn_capture_anchor_parent(&anchor)) {
        spawn_capture_anchor_close(&anchor);
        close(outpipe[0]);
        (void)spawn_reap(pid, NULL);
        LOG_ERR("spawn", "capture group anchor did not start");
    }

    return spawn_capture_drain(
        pid, outpipe[0], buf, cap, timeout_ms, should_cancel, cancel_ctx,
        cancelled, timed_out_out, false, exact,
        anchor.enabled ? anchor.hold[1] : -1);
}

int zcl_spawn_capture_cancelable(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled)
{
    return spawn_capture_impl(argv, buf, cap, timeout_ms, should_cancel,
                              cancel_ctx, cancelled, NULL, false, NULL);
}

static int spawn_capture_observed_platform(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    bool *timed_out)
{
    return spawn_capture_impl(argv, buf, cap, timeout_ms, NULL, NULL, NULL,
                              timed_out, false, NULL);
}

static int spawn_capture_merged_observed_platform(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    bool *timed_out)
{
    return spawn_capture_impl(argv, buf, cap, timeout_ms, NULL, NULL, NULL,
                              timed_out, true, NULL);
}

/* PTY capture is deliberately a transport sibling of pipe capture, not a
 * shell worker. It inherits the exact argv and environment and grants no new
 * authority. The child-side sequence mirrors mesh_terminal_worker: a fresh
 * session, slave as controlling terminal, then stdio and exec. */
static int spawn_pty_capture_observed_platform(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    bool *timed_out)
{
    if (timed_out) *timed_out = false;
    if (!argv || !argv[0] || !buf || cap == 0)
        LOG_ERR("spawn", "bad PTY args (argv=%p buf=%p cap=%zu)",
                (const void *)argv, (void *)buf, cap);
    buf[0] = '\0';

    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0)
        LOG_ERR("spawn", "posix_openpt() failed: %s", strerror(errno));
    (void)fcntl(master, F_SETFD, FD_CLOEXEC);
    if (grantpt(master) != 0 || unlockpt(master) != 0) {
        const int saved = errno;
        close(master);
        LOG_ERR("spawn", "grantpt()/unlockpt() failed: %s", strerror(saved));
    }
    char slave_path[128];
#if defined(__linux__)
    const int name_rc = ptsname_r(master, slave_path, sizeof(slave_path));
    if (name_rc != 0) {
        close(master);
        LOG_ERR("spawn", "ptsname_r() failed: %s", strerror(name_rc));
    }
#else
    /* macOS has the POSIX interface but not ptsname_r. This standalone tool
     * is single-threaded; copy the libc-owned string before fork. */
    const char *name = ptsname(master);
    if (!name || strlen(name) >= sizeof(slave_path)) {
        const int saved = errno;
        close(master);
        LOG_ERR("spawn", "ptsname() failed or returned an over-long path: %s",
                strerror(saved));
    }
    (void)snprintf(slave_path, sizeof(slave_path), "%s", name);
#endif

    pid_t pid = fork();
    if (pid < 0) {
        const int saved = errno;
        close(master);
        LOG_ERR("spawn", "PTY fork() failed: %s", strerror(saved));
    }
    if (pid == 0) {
        /* Child: no allocator, logger, or other shared-process state before
         * exec. Failure stages use conventional 126/127 exit status. */
        close(master);
        if (setsid() < 0)
            _exit(126);
        int slave = open(slave_path, O_RDWR);
        if (slave < 0)
            _exit(126);
        if (ioctl(slave, TIOCSCTTY, 0) < 0)
            _exit(126);
        struct winsize ws = { .ws_col = 80, .ws_row = 24 };
        if (ioctl(slave, TIOCSWINSZ, &ws) < 0)
            _exit(126);
        if (dup2(slave, STDIN_FILENO) < 0 ||
            dup2(slave, STDOUT_FILENO) < 0 ||
            dup2(slave, STDERR_FILENO) < 0)
            _exit(126);
        if (slave > STDERR_FILENO)
            close(slave);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    return spawn_capture_drain(
        pid, master, buf, cap, timeout_ms, NULL, NULL, NULL, timed_out, true,
        NULL, -1);
}

int zcl_spawn_capture(const char *const argv[], char *buf, size_t cap,
                       int timeout_ms)
{
    return zcl_spawn_capture_observed(argv, buf, cap, timeout_ms, NULL);
}

#endif

/* One exact capture for both stderr dispositions: the success predicate
 * and every observation field are the same, so only the child's stderr
 * changes hands. */
static struct zcl_result spawn_capture_binary_impl(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    bool merge_stderr, struct zcl_spawn_binary_observation *out)
{
    if (out) {
        memset(out, 0, sizeof(*out));
        out->exit_code = -1;
    }
    if (!out || !argv || !argv[0] || !buf || cap == 0 || timeout_ms <= 0)
        return ZCL_ERR(-1, "spawn: exact binary capture requires bounded inputs");
#ifdef _WIN32
    (void)merge_stderr;
    return ZCL_ERR(-1, "spawn: Windows binary capture is unavailable");
#else
    int rc = spawn_capture_impl(argv, buf, cap, timeout_ms, NULL, NULL,
                                NULL, NULL, merge_stderr, out);
    if (rc != 0 || out->exit_code != 0 || !out->eof || out->overflow || out->timed_out ||
        !out->exit_observed)
        return ZCL_ERR(-1, "spawn: incomplete binary capture (exit=%d eof=%d overflow=%d timeout=%d observed=%d)",
                       rc, out->eof, out->overflow, out->timed_out,
                       out->exit_observed);
    return ZCL_OK;
#endif
}

struct zcl_result zcl_spawn_capture_binary(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    struct zcl_spawn_binary_observation *out)
{
    return spawn_capture_binary_impl(argv, buf, cap, timeout_ms, false, out);
}

struct zcl_result zcl_spawn_capture_binary_merged(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    struct zcl_spawn_binary_observation *out)
{
    return spawn_capture_binary_impl(argv, buf, cap, timeout_ms, true, out);
}

int zcl_spawn_capture_observed(const char *const argv[], char *buf, size_t cap,
                               int timeout_ms, bool *timed_out)
{
    return spawn_capture_observed_platform(
        argv, buf, cap, timeout_ms, timed_out);
}

int zcl_spawn_capture_merged_observed(const char *const argv[], char *buf,
                                      size_t cap, int timeout_ms,
                                      bool *timed_out)
{
    return spawn_capture_merged_observed_platform(
        argv, buf, cap, timeout_ms, timed_out);
}

int zcl_spawn_pty_capture_observed(const char *const argv[], char *buf,
                                   size_t cap, int timeout_ms,
                                   bool *timed_out)
{
    return spawn_pty_capture_observed_platform(
        argv, buf, cap, timeout_ms, timed_out);
}

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
