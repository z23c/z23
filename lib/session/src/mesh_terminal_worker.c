/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker implementation — see the header
 * for the contract. Linux only; the stub refuses by name elsewhere. */

#define _GNU_SOURCE /* ptsname_r, pipe2 — must precede every include */

#include "session/mesh_terminal_worker.h"

#if defined(__linux__)
#include "platform/os_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h> /* struct winsize */
#include <unistd.h>
#endif

/* The default subtree process budget, enforced by the parent's
 * process-group census (RLIMIT_NPROC cannot do this job — it counts the
 * whole uid's tasks — so the census is the only escape-proof accounting).
 * A pipeline, command substitution, and a couple of subshells stay well
 * under it. */
#define MESH_TERMINAL_WORKER_MAX_PROCESSES 32u

/* Child-side failure stages, staged back through the close-on-exec pipe
 * so spawn() can refuse BY NAME instead of "the child went away". */
enum {
    TW_STAGE_TTY = 1,        /* slave open / ctty / winsize / dup2 */
    TW_STAGE_CHDIR = 2,      /* workdir chdir */
    TW_STAGE_CONFINEMENT = 3,/* sandbox enter */
    TW_STAGE_EXEC = 4,       /* execve */
};

const char *mesh_terminal_worker_error_string(
    enum mesh_terminal_worker_error error)
{
    switch (error) {
    case MESH_TERMINAL_WORKER_ERR_NONE: return "ok";
    case MESH_TERMINAL_WORKER_ERR_NULL: return "null";
    case MESH_TERMINAL_WORKER_ERR_CONFIG: return "config";
    case MESH_TERMINAL_WORKER_ERR_PTY: return "pty";
    case MESH_TERMINAL_WORKER_ERR_SPAWN: return "spawn";
    case MESH_TERMINAL_WORKER_ERR_CONFINEMENT: return "confinement";
    case MESH_TERMINAL_WORKER_ERR_EXEC: return "exec";
    case MESH_TERMINAL_WORKER_ERR_TTY: return "tty";
    case MESH_TERMINAL_WORKER_ERR_NOT_RUNNING: return "not-running";
    case MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT: return "byte-limit";
    case MESH_TERMINAL_WORKER_ERR_IO: return "io";
    case MESH_TERMINAL_WORKER_ERR_GEOMETRY: return "geometry";
    case MESH_TERMINAL_WORKER_ERR_UNSUPPORTED: return "unsupported";
    }
    return "unknown";
}

#if !defined(__linux__)

/* Honest refusal on platforms with no Landlock/seccomp cage: never a
 * simulated success, never a degraded shell. */
static struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    (void)cfg; (void)now_unix; (void)out;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static struct zcl_result mesh_terminal_worker_input_platform_arm(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    (void)w; (void)bytes; (void)n; (void)now_unix;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static struct zcl_result mesh_terminal_worker_output_platform_arm(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    (void)w; (void)buf; (void)cap; (void)now_unix;
    if (out_len) *out_len = 0;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    (void)w; (void)cols; (void)rows;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                   "terminal worker requires the Linux confinement stack");
}

static bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    (void)w; (void)now_unix;
    return true; /* no session could ever be started */
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    (void)w;
    return false;
}

static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    (void)w;
}

#else /* __linux__ */

static bool geometry_in_bounds(uint16_t cols, uint16_t rows)
{
    return cols != 0 && cols <= MESH_TERMINAL_MAX_COLS && rows != 0 &&
           rows <= MESH_TERMINAL_MAX_ROWS;
}

/* Record a natural or forced exit; keeps an enforcement reason that a
 * previous call already set (byte-limit, lifetime, ...) — a named kill
 * must never be overwritten by the generic worker-exited. */
static void tw_record_exit(struct mesh_terminal_worker *w, int status)
{
    if (WIFEXITED(status))
        w->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        w->exit_code = 128 + WTERMSIG(status);
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
}

/* Non-blocking reap; returns true when the shell has exited. */
static bool tw_reap(struct mesh_terminal_worker *w)
{
    if (!w->running)
        return true;
    int status = 0;
    pid_t got = waitpid(w->pid, &status, WNOHANG);
    if (got == w->pid) {
        tw_record_exit(w, status);
        return true;
    }
    if (got < 0 && errno == ECHILD) {
        /* Nobody to wait for: treat as exited (should not happen). */
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
        return true;
    }
    return false;
}

/* The child half of spawn: never returns; stages failures by name. */
static void tw_child(const struct mesh_terminal_worker_config *cfg,
                     const char *slave_path, int master, int stage_fd)
{
    /* Nothing here may return into the parent's execution state; every
     * path ends in _exit. */
    close(master);

    if (setsid() < 0)
        goto tty_fail;
    int slave = open(slave_path, O_RDWR);
    if (slave < 0)
        goto tty_fail;
    /* The shell wants a controlling terminal for job control. */
    if (ioctl(slave, TIOCSCTTY, NULL) < 0)
        goto tty_fail;
    struct winsize ws = { .ws_col = cfg->cols, .ws_row = cfg->rows };
    if (ioctl(slave, TIOCSWINSZ, &ws) < 0)
        goto tty_fail;
    if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0)
        goto tty_fail;
    if (slave > STDERR_FILENO)
        close(slave);

    if (chdir(cfg->workdir) < 0) {
        uint8_t stage = TW_STAGE_CHDIR;
        (void)write(stage_fd, &stage, 1);
        _exit(126);
    }

    /* The grant IS the filesystem: the per-terminal workdir (the child's
     * cwd and HOME) plus the one granted shell binary. */
    struct os_sandbox_path_rule rules[2] = {
        { .path = cfg->workdir, .allow_read = true, .allow_write = true,
          .allow_execute = true, .allow_create = true },
        { .path = cfg->shell_path, .allow_read = true,
          .allow_execute = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_terminal_worker_profile(rules, 2);
    if (!os_sandbox_enter(&profile).ok) {
        uint8_t stage = TW_STAGE_CONFINEMENT;
        (void)write(stage_fd, &stage, 1);
        _exit(126);
    }

    /* Deliberately minimal environment: no PATH to leak a search order,
     * HOME/PWD pinned to the grant so no rc file outside it is read. */
    char home[512 + 8], pwd[512 + 8];
    (void)snprintf(home, sizeof home, "HOME=%s", cfg->workdir);
    (void)snprintf(pwd, sizeof pwd, "PWD=%s", cfg->workdir);
    char *const envp[] = { (char *)"TERM=xterm", home, pwd, NULL };
    char *const argv[] = { (char *)cfg->shell_path, NULL };
    execve(cfg->shell_path, argv, envp);

    {
        uint8_t stage = TW_STAGE_EXEC;
        (void)write(stage_fd, &stage, 1);
    }
    _exit(127);

tty_fail:
    {
        uint8_t stage = TW_STAGE_TTY;
        (void)write(stage_fd, &stage, 1);
    }
    _exit(126);
}

static struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    if (!cfg || !out)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "spawn: cfg/out required");
    memset(out, 0, sizeof(*out));
    out->master_fd = -1;
    if (!cfg->shell_path || cfg->shell_path[0] != '/' || !cfg->workdir ||
        cfg->workdir[0] != '/')
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path and workdir must be absolute");
    if (!geometry_in_bounds(cfg->cols, cfg->rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: cols/rows out of proto bounds");
    if (cfg->max_bytes_in == 0 || cfg->max_bytes_out == 0 ||
        cfg->lifetime_seconds == 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: byte and lifetime budgets must be nonzero");
    if (strlen(cfg->workdir) >= 512)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: workdir path too long");

    out->pid = 0;
    out->pgid = 0;
    out->max_bytes_in = cfg->max_bytes_in;
    out->max_bytes_out = cfg->max_bytes_out;
    out->lifetime_seconds = cfg->lifetime_seconds;
    out->idle_seconds = cfg->idle_seconds;
    out->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;

    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "posix_openpt failed errno=%d", errno);
    if (grantpt(master) != 0 || unlockpt(master) != 0) {
        close(master);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "grantpt/unlockpt failed errno=%d", errno);
    }
    char slave_path[128];
    if (ptsname_r(master, slave_path, sizeof(slave_path)) != 0) {
        close(master);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "ptsname failed errno=%d", errno);
    }

    /* The staging pipe tells the parent WHICH named stage failed, and its
     * O_CLOEXEC turns EOF into the exec-succeeded signal. */
    int stage_pipe[2];
    if (pipe2(stage_pipe, O_CLOEXEC) != 0) {
        close(master);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "stage pipe failed errno=%d", errno);
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(master);
        close(stage_pipe[0]);
        close(stage_pipe[1]);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "fork failed errno=%d", errno);
    }
    if (pid == 0) {
        close(stage_pipe[0]);
        tw_child(cfg, slave_path, master, stage_pipe[1]);
        _exit(127); /* unreachable */
    }

    /* Parent: read the staging pipe to EOF — zero bytes means the child
     * execed (the pipe closed with the exec), one byte names the stage
     * that failed. */
    close(stage_pipe[1]);
    uint8_t stage = 0;
    for (;;) {
        ssize_t n = read(stage_pipe[0], &stage, 1);
        if (n > 0)
            break;
        if (n == 0) {
            stage = 0;
            break;
        }
        if (errno != EINTR) {
            stage = 0;
            break;
        }
    }
    close(stage_pipe[0]);

    if (stage != 0) {
        int status = 0;
        (void)waitpid(pid, &status, 0);
        close(master);
        enum mesh_terminal_worker_error code =
            MESH_TERMINAL_WORKER_ERR_SPAWN;
        const char *what = "unknown stage";
        switch (stage) {
        case TW_STAGE_TTY:
            code = MESH_TERMINAL_WORKER_ERR_TTY;
            what = "pty slave/ctty/winsize setup";
            break;
        case TW_STAGE_CHDIR:
            code = MESH_TERMINAL_WORKER_ERR_CONFIG;
            what = "workdir chdir";
            break;
        case TW_STAGE_CONFINEMENT:
            code = MESH_TERMINAL_WORKER_ERR_CONFINEMENT;
            what = "sandbox enter";
            break;
        case TW_STAGE_EXEC:
            code = MESH_TERMINAL_WORKER_ERR_EXEC;
            what = "execve";
            break;
        default:
            break;
        }
        return ZCL_ERR(code, "worker child failed at %s (stage %u)",
                       what, (unsigned)stage);
    }

    /* Best effort: pin the child's group even if setsid lost the race
     * (the child's setsid is authoritative; EACCES just means it already
     * became its own leader). */
    (void)setpgid(pid, pid);

    int flags = fcntl(master, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(master, F_SETFL, flags | O_NONBLOCK);

    out->pid = pid;
    out->pgid = pid; /* setsid() in the child makes pgid == pid */
    out->master_fd = master;
    out->started_unix = now_unix;
    out->last_activity_unix = now_unix;
    out->running = true;
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_input_platform_arm(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    if (!w || (!bytes && n != 0))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: worker/bytes required");
    if (n == 0)
        return ZCL_OK;
    if (!w->running || w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "input: session is over (%s)",
                       mesh_terminal_close_reason_string(w->close_reason));
    if (w->bytes_in > w->max_bytes_in ||
        n > w->max_bytes_in - w->bytes_in) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "input budget %llu exceeded (%llu used, %zu offered)",
                       (unsigned long long)w->max_bytes_in,
                       (unsigned long long)w->bytes_in, n);
    }

    size_t total = 0;
    while (total < n) {
        ssize_t wr = write(w->master_fd, bytes + total, n - total);
        if (wr > 0) {
            total += (size_t)wr;
            continue;
        }
        if (wr < 0 && errno == EINTR)
            continue;
        if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* The shell is not draining: bounded wait, then hand the
             * decision back to the caller — a stalled shell is the
             * lifetime/idle enforcement's kill, not a write error. */
            struct pollfd pfd = { .fd = w->master_fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, 1000);
            if (pr > 0)
                continue;
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input stalled (wrote %zu/%zu)",
                           total, n);
        }
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "pty write failed errno=%d", errno);
    }
    w->bytes_in += total;
    w->last_activity_unix = now_unix;
    return ZCL_OK;
}

static struct zcl_result mesh_terminal_worker_output_platform_arm(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    if (out_len)
        *out_len = 0;
    if (!w || !buf || !out_len)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "output: worker/buf/out_len required");
    if (cap == 0)
        return ZCL_OK;
    if (w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "output: pty closed");

    ssize_t n = read(w->master_fd, buf, cap);
    if (n > 0) {
        *out_len = (size_t)n;
        w->bytes_out += (uint64_t)n;
        w->last_activity_unix = now_unix;
        if (w->bytes_out > w->max_bytes_out) {
            mesh_terminal_worker_kill(w);
            w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                           "output budget %llu exceeded (%llu produced)",
                           (unsigned long long)w->max_bytes_out,
                           (unsigned long long)w->bytes_out);
        }
        return ZCL_OK;
    }
    if (n == 0)
        return ZCL_OK; /* EOF: budget_exceeded() reaps the exit */
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        return ZCL_OK;
    if (errno == EIO)
        return ZCL_OK; /* slave gone: same as EOF for the pump loop */
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                   "pty read failed errno=%d", errno);
}

static struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "resize: worker required");
    if (w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "resize: pty closed");
    if (!geometry_in_bounds(cols, rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                       "resize: cols/rows out of proto bounds");
    struct winsize ws = { .ws_col = cols, .ws_row = rows };
    if (ioctl(w->master_fd, TIOCSWINSZ, &ws) != 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "TIOCSWINSZ failed errno=%d", errno);
    /* The kernel raises SIGWINCH on the foreground group; nothing to
     * forward by hand. */
    return ZCL_OK;
}

static bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    if (!w)
        return true;
    if (tw_reap(w))
        return true;
    if (w->lifetime_seconds != 0 &&
        now_unix - w->started_unix >= (int64_t)w->lifetime_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_LIFETIME_LIMIT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    if (w->idle_seconds != 0 &&
        now_unix - w->last_activity_unix >= (int64_t)w->idle_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_IDLE_TIMEOUT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    /* The subtree process budget: escape-proof because a pgid is
     * inherited across fork and survives reparenting, so a fork bomb
     * inside the cage is visible here the moment it exists. */
    if (os_sandbox_process_group_census(w->pgid) >
        MESH_TERMINAL_WORKER_MAX_PROCESSES) {
        w->close_reason = MESH_TERMINAL_CLOSE_SESSION_LOST;
        mesh_terminal_worker_kill(w);
        return true;
    }
    return false;
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return false;
    tw_reap(w);
    return w->running;
}

static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    if (w->master_fd >= 0) {
        close(w->master_fd);
        w->master_fd = -1;
    }
    if (!w->running)
        return;

    /* Whole GROUP first — the session's process subtree dies together,
     * then the shell itself in case the group signal raced. */
    (void)kill(-w->pgid, SIGKILL);
    (void)kill(w->pid, SIGKILL);

    /* Census-verified teardown: bounded loop so a wedged (D-state) task
     * cannot hang the node, with a blocking reap at the end so no zombie
     * leaks even then. */
    int status = 0;
    for (int i = 0; i < 100; i++) {
        pid_t got = waitpid(w->pid, &status, WNOHANG);
        if (got == w->pid) {
            tw_record_exit(w, status);
            return;
        }
        if (os_sandbox_process_group_census(w->pgid) == 0 && got < 0)
            break;
        usleep(2000);
    }
    pid_t got = waitpid(w->pid, &status, 0);
    if (got == w->pid)
        tw_record_exit(w, status);
    else {
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
    }
}

#endif /* __linux__ */

struct zcl_result mesh_terminal_worker_spawn(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    return mesh_terminal_worker_spawn_platform_arm(cfg, now_unix, out);
}

struct zcl_result mesh_terminal_worker_input(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    return mesh_terminal_worker_input_platform_arm(w, bytes, n, now_unix);
}

struct zcl_result mesh_terminal_worker_output(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    return mesh_terminal_worker_output_platform_arm(
        w, buf, cap, out_len, now_unix);
}

struct zcl_result mesh_terminal_worker_resize(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    return mesh_terminal_worker_resize_platform_arm(w, cols, rows);
}

bool mesh_terminal_worker_budget_exceeded(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    return mesh_terminal_worker_budget_exceeded_platform_arm(w, now_unix);
}

bool mesh_terminal_worker_alive(struct mesh_terminal_worker *w)
{
    return mesh_terminal_worker_alive_platform_arm(w);
}

void mesh_terminal_worker_kill(struct mesh_terminal_worker *w)
{
    mesh_terminal_worker_kill_platform_arm(w);
}
