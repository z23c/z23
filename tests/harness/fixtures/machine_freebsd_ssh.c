/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bound a PUBLIC SSH fixture's native duplex child transport.
 * This preparation contains no guest launch, credential or server authority. */
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "platform/clock.h"

/* macOS has no /bin/false; the same utility lives in /usr/bin there. */
#ifdef __APPLE__
#define SB_FALSE_PATH "/usr/bin/false"
#else
#define SB_FALSE_PATH "/bin/false"
#endif

enum { SB_CHUNK = 4096, SB_PATTERN = 4097, SB_DIAGNOSTIC = 8192 };
struct ssh_bridge {
    pid_t pid;
    int input, output, error;
    bool exited, output_eof, error_eof, failed;
    int status;
    int wait_error;
    unsigned kill_attempts;
    bool observe_kill_only;
    size_t diagnostic;
    uint8_t pending[SB_CHUNK];
    size_t pending_off, pending_len;
};

static int64_t sb_now_ms(void) { return clock_now_monotonic_ns() / INT64_C(1000000); }

static bool sb_refuse(const char *why)
{
    fprintf(stderr, "PUBLIC_SSH_FD_REFUSED:%s errno=%d\n", why, errno);
    return false;
}

static void sb_init(struct ssh_bridge *b)
{
    memset(b, 0, sizeof(*b));
    b->pid = -1;
    b->input = b->output = b->error = -1;
}

static bool sb_close(int *fd)
{
    int owned = *fd;
    *fd = -1;
    if (owned >= 0 && close(owned) != 0) return sb_refuse("CLOSE");
    return true;
}

static bool sb_pipe(int pair[2])
{
    pair[0] = pair[1] = -1;
    if (pipe(pair) != 0) return sb_refuse("PIPE");
    for (unsigned i = 0; i < 2; i++) {
        if (pair[i] < 3) {
            int held = fcntl(pair[i], F_DUPFD_CLOEXEC, 3);
            if (held < 0) goto fail;
            if (!sb_close(&pair[i])) { close(held); goto fail; }
            pair[i] = held;
        }
        if (fcntl(pair[i], F_SETFD, FD_CLOEXEC) < 0) goto fail;
    }
    return true;
fail:
    (void)sb_close(&pair[0]);
    (void)sb_close(&pair[1]);
    return sb_refuse("PIPE_FLAGS");
}

static bool sb_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return sb_refuse("NONBLOCK");
    return true;
}

static bool sb_actions(posix_spawn_file_actions_t *actions, int pipes[3][2])
{
    for (unsigned i = 0; i < 3; i++) {
        int source = i == 0 ? pipes[i][0] : pipes[i][1];
        int rc = posix_spawn_file_actions_adddup2(actions, source, (int)i);
        if (rc != 0) { errno = rc; return sb_refuse("SPAWN_DUP"); }
    }
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned j = 0; j < 2; j++) {
            int rc = posix_spawn_file_actions_addclose(actions, pipes[i][j]);
            if (rc != 0) { errno = rc; return sb_refuse("SPAWN_CLOSE"); }
        }
    }
    return true;
}

static bool sb_reap(struct ssh_bridge *b)
{
    if (b->pid < 0 || b->exited) return true;
    pid_t got = waitpid(b->pid, &b->status, WNOHANG);
    if (got == 0) return true;
    if (got != b->pid) {
        b->wait_error = errno;
        return sb_refuse("WAIT_STATUS_UNOBSERVED");
    }
    b->exited = true;
    return true;
}

static bool sb_kill_reap(struct ssh_bridge *b)
{
    b->kill_attempts++;
    if (b->observe_kill_only) return sb_refuse("SIGNAL_OBSERVED_NOT_EXECUTED");
    if (kill(b->pid, SIGKILL) != 0 && errno != ESRCH)
        return sb_refuse("OWNED_CHILD_KILL");
    int64_t start = sb_now_ms();
    if (start <= 0 || start > INT64_MAX - 2000) return sb_refuse("REAP_CLOCK");
    while (!b->exited) {
        if (!sb_reap(b)) return false;
        if (b->exited) return true;
        int64_t now = sb_now_ms();
        if (now <= 0 || now >= start + 2000) return sb_refuse("REAP_UNOBSERVED");
        if (poll(NULL, 0, 10) < 0 && errno != EINTR) return sb_refuse("REAP_POLL");
    }
    return true;
}

static bool sb_destroy(struct ssh_bridge *b)
{
    bool ok = sb_close(&b->input);
    ok = sb_close(&b->output) && ok;
    ok = sb_close(&b->error) && ok;
    /* A failed wait loses child custody; never signal a possibly reused PID. */
    if (!sb_reap(b)) return false;
    if (b->pid >= 0 && !b->exited) ok = sb_kill_reap(b) && ok;
    return ok;
}

/* Only a receiver-approved fixed argv may reach this primitive. It creates no
 * process group: the canonical observed parent owns the fixture's whole group.
 * The Mac server has separate remote custody; killing this child does not
 * establish remote cleanup. */
static bool sb_spawn(struct ssh_bridge *b, const char *image, char *const argv[])
{
    int pipes[3][2] = {{-1, -1}, {-1, -1}, {-1, -1}};
    posix_spawn_file_actions_t actions;
    bool initialized = false, ok = false;
    char *const env[] = {"LANG=C", "LC_ALL=C", NULL};
    sb_init(b);
    for (unsigned i = 0; i < 3; i++) if (!sb_pipe(pipes[i])) goto out;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc != 0) { errno = rc; sb_refuse("SPAWN_ACTIONS"); goto out; }
    initialized = true;
    if (!sb_actions(&actions, pipes)) goto out;
    rc = posix_spawn(&b->pid, image, &actions, NULL, argv, env);
    if (rc != 0) { b->pid = -1; errno = rc; sb_refuse("SPAWN"); goto out; }
    b->input = pipes[0][1]; pipes[0][1] = -1;
    b->output = pipes[1][0]; pipes[1][0] = -1;
    b->error = pipes[2][0]; pipes[2][0] = -1;
    ok = sb_nonblock(b->input) && sb_nonblock(b->output) && sb_nonblock(b->error);
out:
    if (initialized) {
        int rc = posix_spawn_file_actions_destroy(&actions);
        if (rc != 0) { errno = rc; ok = sb_refuse("SPAWN_ACTIONS_DESTROY"); }
    }
    for (unsigned i = 0; i < 3; i++) for (unsigned j = 0; j < 2; j++)
        if (!sb_close(&pipes[i][j])) ok = false;
    if (!ok) (void)sb_destroy(b);
    return ok;
}

/* Suitable for a T callback: one bounded syscall, no machine/API reentry.
 * Caller retains every unaccepted suffix, including EINTR and EAGAIN. */
static size_t sb_write(struct ssh_bridge *b, const uint8_t *bytes, size_t n)
{
    if (b->failed || b->input < 0 || b->exited || n == 0) return 0;
    if (n > SB_CHUNK) n = SB_CHUNK;
    ssize_t got = write(b->input, bytes, n);
    if (got >= 0) return (size_t)got;
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return 0;
    int error = errno;
    b->failed = true;
    sb_refuse("WRITE");
    errno = error;
    return 0;
}

/* Outside the machine pump only. Do not overwrite an unaccepted RX suffix. */
static bool sb_read(struct ssh_bridge *b)
{
    if (b->pending_off < b->pending_len || b->output_eof) return true;
    b->pending_off = b->pending_len = 0;
    ssize_t got = read(b->output, b->pending, sizeof(b->pending));
    if (got > 0) { b->pending_len = (size_t)got; return true; }
    if (got == 0) { b->output_eof = true; return true; }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return true;
    b->failed = true;
    return sb_refuse("READ");
}

/* Host transport diagnostics are never mixed into the guest console gate. */
static bool sb_error(struct ssh_bridge *b)
{
    if (b->error_eof) return true;
    char bytes[512];
    ssize_t got = read(b->error, bytes, sizeof(bytes));
    if (got == 0) { b->error_eof = true; return true; }
    if (got < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return sb_refuse("STDERR_READ");
    }
    if ((size_t)got > SB_DIAGNOSTIC - b->diagnostic) return sb_refuse("STDERR_LIMIT");
    b->diagnostic += (size_t)got;
    if (fwrite(bytes, 1, (size_t)got, stderr) != (size_t)got)
        return sb_refuse("STDERR_OUTPUT");
    return true;
}

static bool sb_poll(struct ssh_bridge *b, int64_t deadline, bool want_write)
{
    int64_t now = sb_now_ms();
    if (now <= 0 || now >= deadline) return sb_refuse("EXECUTION_CAP");
    int64_t remaining = deadline - now;
    int wait = remaining > 50 ? 50 : (int)remaining;
    if (b->pending_off < b->pending_len) wait = 0;
    struct pollfd fds[3] = {
        {want_write ? b->input : -1, want_write && b->input >= 0 ? POLLOUT : 0, 0},
        {b->output_eof || b->pending_off < b->pending_len ? -1 : b->output, POLLIN, 0},
        {b->error_eof ? -1 : b->error, POLLIN, 0}
    };
    int got = poll(fds, 3, wait);
    if (got < 0 && errno != EINTR) return sb_refuse("POLL");
    for (unsigned i = 0; i < 3; i++)
        if ((fds[i].revents & POLLNVAL) != 0) return sb_refuse("POLL_FD");
    return sb_reap(b);
}

static uint8_t sb_pattern(size_t i) { return (uint8_t)(i * 73u + 19u); }


struct sb_echo_state {
    uint8_t input[SB_PATTERN];
    size_t sent, received;
    bool short_read;
};

static bool sb_echo_turn(struct ssh_bridge *b, struct sb_echo_state *e)
{
    if (e->sent < sizeof(e->input))
        e->sent += sb_write(b, e->input + e->sent, sizeof(e->input) - e->sent);
    if (e->sent == sizeof(e->input) && b->input >= 0 && !sb_close(&b->input)) return false;
    if (b->failed || !sb_read(b) || !sb_error(b)) return false;
    size_t left = b->pending_len - b->pending_off;
    size_t accepted = left > 97 ? 97 : left;
    if (accepted < left) e->short_read = true;
    if (accepted > sizeof(e->input) - e->received) return sb_refuse("EXTRA_OUTPUT");
    if (memcmp(b->pending + b->pending_off, e->input + e->received, accepted) != 0)
        return sb_refuse("BYTE_MISMATCH");
    e->received += accepted;
    b->pending_off += accepted;
    return true;
}

static bool sb_echo_proof(const struct ssh_bridge *b, const struct sb_echo_state *e)
{
    return e->sent == sizeof(e->input) && e->received == sizeof(e->input) && e->short_read &&
        b->pending_off == b->pending_len && WIFEXITED(b->status) && WEXITSTATUS(b->status) == 0;
}

static bool sb_echo(void)
{
    struct ssh_bridge b;
    char *const argv[] = {"/bin/cat", NULL};
    int64_t start = sb_now_ms();
    if (start <= 0 || start > INT64_MAX - 5000) return sb_refuse("CLOCK_UNAVAILABLE");
    if (!sb_spawn(&b, argv[0], argv)) return false;
    struct sb_echo_state e = {0};
    for (size_t i = 0; i < sizeof(e.input); i++) e.input[i] = sb_pattern(i);
    bool ok = true;
    while (ok && !(b.exited && b.output_eof && b.error_eof)) {
        ok = sb_echo_turn(&b, &e);
        if (ok) ok = sb_poll(&b, start + 5000, e.sent < sizeof(e.input));
    }
    ok = ok && sb_echo_proof(&b, &e);
    if (!ok) sb_refuse("ECHO_PROOF");
    return sb_destroy(&b) && ok;
}

static bool sb_nonzero(void)
{
    struct ssh_bridge b;
    char *const argv[] = {SB_FALSE_PATH, NULL};
    int64_t start = sb_now_ms();
    if (start <= 0 || start > INT64_MAX - 5000) return sb_refuse("CLOCK_UNAVAILABLE");
    if (!sb_spawn(&b, argv[0], argv)) return false;
    bool ok = sb_close(&b.input);
    while (ok && !(b.exited && b.output_eof && b.error_eof))
        ok = sb_read(&b) && sb_error(&b) && b.pending_len == 0 && sb_poll(&b, start + 5000, false);
    ok = ok && WIFEXITED(b.status) && WEXITSTATUS(b.status) != 0;
    if (!ok) sb_refuse("NONZERO_STATUS_PROOF");
    return sb_destroy(&b) && ok;
}

static bool sb_backpressure(void)
{
    int pair[2];
    if (!sb_pipe(pair)) return false;
    struct ssh_bridge b;
    sb_init(&b);
    b.input = pair[1];
    pair[1] = -1;
    bool ok = sb_nonblock(b.input), full = false;
    uint8_t bytes[SB_CHUNK] = {0};
    size_t queued = 0;
    for (unsigned attempt = 0; ok && queued < 1048576 && attempt < 1024; attempt++) {
        size_t accepted = sb_write(&b, bytes, sizeof(bytes));
        if (b.failed) { ok = false; break; }
        if (accepted == 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            full = true;
            break;
        }
        queued += accepted;
    }
    ok = ok && full && sb_write(&b, bytes, 1) == 0 && !b.failed;
    if (!ok) sb_refuse("BACKPRESSURE_PROOF");
    ok = sb_close(&pair[0]) && ok;
    return sb_destroy(&b) && ok;
}

static bool sb_broken_pipe(void)
{
    int pair[2];
    if (!sb_pipe(pair)) return false;
    struct ssh_bridge b;
    sb_init(&b);
    b.input = pair[1];
    bool ok = sb_close(&pair[0]);
    const uint8_t byte = 19;
    if (ok) ok = sb_write(&b, &byte, 1) == 0 && b.failed && errno == EPIPE;
    if (!ok) sb_refuse("EPIPE_PROOF");
    return sb_destroy(&b) && ok;
}

static bool sb_low_stdio(void)
{
    int held = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
    if (held < 0) return sb_refuse("STDIN_SAVE");
    bool ok = close(STDIN_FILENO) == 0;
    if (ok) ok = sb_echo();
    if (dup2(held, STDIN_FILENO) != STDIN_FILENO) ok = sb_refuse("STDIN_RESTORE");
    return sb_close(&held) && ok;
}

static bool sb_lost_child(void)
{
    struct ssh_bridge b;
    char *const argv[] = {SB_FALSE_PATH, NULL};
    int64_t start = sb_now_ms();
    if (start <= 0 || start > INT64_MAX - 5000) return sb_refuse("CLOCK_UNAVAILABLE");
    if (!sb_spawn(&b, argv[0], argv)) return false;
    bool ok = sb_close(&b.input);
    while (ok && !b.exited) ok = sb_poll(&b, start + 5000, false);
    if (!ok) { (void)sb_destroy(&b); return false; }
    /* The actual child is already reaped. Re-querying its recorded PID must
     * refuse ECHILD without a signal; no unrelated PID is supplied. */
    b.exited = false;
    b.observe_kill_only = true;
    ok = !sb_destroy(&b) && b.wait_error == ECHILD && b.kill_attempts == 0;
    if (!ok) sb_refuse("LOST_CHILD_PROOF");
    return ok;
}

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "--selftest") != 0) {
        sb_refuse("ROUTE_UNQUALIFIED");
        return 1;
    }
    /* Pipe writes must produce a named refusal, never kill this observer. */
    struct sigaction action = {.sa_handler = SIG_IGN};
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGPIPE, &action, NULL) != 0)
        return sb_refuse("SIGPIPE_SETUP") ? 0 : 1;
    if (!sb_echo() || !sb_nonzero() || !sb_backpressure() || !sb_broken_pipe() ||
        !sb_low_stdio() || !sb_lost_child()) return 1;
    if (puts("PUBLIC_SSH_NATIVE_FD_PROOF bytes=4097 short_rx=1 cat_exit=0 false_nonzero=1 eagain=1 epipe=1 low_fd=1 lost_child=1") < 0 ||
        fflush(stdout) != 0) return sb_refuse("PROOF_OUTPUT") ? 0 : 1;
    return 0;
}
#else
int main(void) { fputs("UNOBSERVED: native SSH FD fixture unavailable on Windows\n", stderr); return 77; }
#endif
