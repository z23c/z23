/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker implementation — see the header
 * for the contract. Linux uses a PTY; Windows uses ConPTY; the stub
 * refuses by name on every other platform. */

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
#elif defined(_WIN32)
/* ConPTY (CreatePseudoConsole/ResizePseudoConsole/ClosePseudoConsole) and
 * PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE are declared by the mingw-w64 and
 * MSVC headers only once NTDDI_VERSION names the Windows 10 October 2018
 * Update (RS5, NTDDI_WIN10_RS5 == 0x0A000006) or newer. Z23's native
 * baseline is already Windows 10 (ZCL_PLATFORM_CPPFLAGS pins
 * -D_WIN32_WINNT=0x0A00), but <sdkddkver.h> derives a LOWER default
 * NTDDI_VERSION from _WIN32_WINNT alone, which leaves ConPTY undeclared —
 * confirmed against the installed mingw-w64 headers while writing this
 * arm. Pin NTDDI_VERSION explicitly here, the same way
 * platform/modules/platform/src/logical_cpu.c pins its own per-TU
 * _WIN32_WINNT floor, so a standalone TU check (check-windows-cross-syntax
 * compiles this file on its own) sees the same API surface a real build
 * would, and refuse a lower floor set some other way rather than silently
 * compiling against an older, ConPTY-less SDK target. */
#if !defined(NTDDI_VERSION)
#define NTDDI_VERSION 0x0A000006
#elif NTDDI_VERSION < 0x0A000006
#error "mesh_terminal_worker's Windows arm requires NTDDI_WIN10_RS5 (ConPTY) or newer"
#endif
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "util/safe_alloc.h" /* zcl_malloc: checked, logged OOM */
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

/* ── Platform-neutral bookkeeping, shared by every arm below ───────────
 * Pure functions of primitive types, so a Linux-hosted unit test can
 * prove the boundary itself without spawning a shell (or a mingw build)
 * on any host. */

/* Bounds-check requested terminal geometry against the proto's wire
 * limits. Only moved out of the Linux arm (unchanged body, unchanged
 * call sites there) so the Windows arm below can call the same copy
 * instead of a second one drifting from it. Kept non-static: on a
 * platform that is neither Linux nor Windows only the honest-refusal
 * stub arm compiles, which calls neither this nor the budget helper
 * below, and a static function unused in that translation unit is
 * exactly what -Wunused-function (-Werror) exists to catch — the same
 * reason mesh_terminal_worker_budget_would_overrun is not static. */
bool geometry_in_bounds(uint16_t cols, uint16_t rows)
{
    return cols != 0 && cols <= MESH_TERMINAL_MAX_COLS && rows != 0 &&
           rows <= MESH_TERMINAL_MAX_ROWS;
}

/* True when accepting `n` more bytes on top of `used` bytes already
 * charged against `max` would cross the budget. The POSIX arm inlines
 * this exact test in mesh_terminal_worker_input_platform_arm (left
 * byte-for-byte unchanged there, so this copy is genuinely unused in a
 * Linux build's own object — kept non-static, like
 * mesh_terminal_worker_error_string, rather than static+unused, so
 * -Wunused-function never fires there); the Windows arm's input path
 * below calls this one copy, and it is declared in the header so the
 * Linux-hosted unit test can call it directly without a spawned shell or
 * a mingw build. */
bool mesh_terminal_worker_budget_would_overrun(uint64_t used, uint64_t max,
                                               size_t n)
{
    return used > max || n > max - used;
}

#if !defined(__linux__) && !defined(_WIN32)

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

#elif defined(__linux__) /* __linux__ */

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

#elif defined(_WIN32) /* _WIN32 */

/* Every path this worker widens is bounded well under MAX_PATH-class
 * limits by spawn's own refusal below; a fixed stack buffer needs no
 * heap and adds no failure mode beyond "too long", which spawn already
 * refuses by name. */
#define MESH_TERMINAL_WIN_PATH_MAX 512u

/* Windows path shape check, mirroring the POSIX arm's absolute-path
 * refusal (shell_path[0] == '/'): a drive-letter root ("C:\" or "C:/")
 * or a UNC root ("\\server\share"). */
static bool win_path_is_absolute(const char *path)
{
    if (!path || !path[0])
        return false;
    if (path[0] == '\\' && path[1] == '\\')
        return true;
    bool letter = (path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z');
    return letter && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}

static bool win_widen(const char *utf8, wchar_t *out, size_t out_count)
{
    if (!utf8 || !out || out_count == 0)
        return false;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out,
                                (int)out_count);
    return n > 0;
}

/* Append one "KEY=VALUE\0" entry to a CreateProcessW environment block;
 * silently a no-op past `cap` so a caller that sized the block generously
 * (as spawn does) never overruns it. Returns the offset of the NEXT free
 * slot. */
static size_t win_env_put(wchar_t *block, size_t cap, size_t off,
                          const wchar_t *key, const wchar_t *value)
{
    size_t klen = wcslen(key), vlen = wcslen(value);
    if (off + klen + 1u + vlen + 1u > cap)
        return off;
    wmemcpy(block + off, key, klen);
    off += klen;
    block[off++] = L'=';
    wmemcpy(block + off, value, vlen);
    off += vlen;
    block[off++] = L'\0';
    return off;
}

static void tw_win_close(void **handle)
{
    if (!handle)
        return;
    if (*handle && *handle != INVALID_HANDLE_VALUE)
        CloseHandle((HANDLE)*handle);
    *handle = NULL;
}

/* The pipe buffer both directions share: generous headroom over one wire
 * DATA frame's payload (MESH_TERMINAL_DATA_PAYLOAD_MAX, 3072 bytes) so an
 * ordinary mesh_terminal_worker_input() write is never close to the
 * pipe's capacity. Anonymous pipes cannot be opened overlapped (Windows
 * refuses FILE_FLAG_OVERLAPPED on a CreatePipe handle), so this size is
 * mitigation for a synchronous WriteFile rather than a hard bound the way
 * the byte budgets are — see the comment in the input function below for
 * what that leaves unverified. */
#define MESH_TERMINAL_WIN_PIPE_BYTES 65536ul

static struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    if (!cfg || !out)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "spawn: cfg/out required");
    memset(out, 0, sizeof(*out));
    out->master_fd = -1;
    if (!cfg->shell_path || !win_path_is_absolute(cfg->shell_path) ||
        !cfg->workdir || !win_path_is_absolute(cfg->workdir))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path and workdir must be absolute");
    if (!geometry_in_bounds(cfg->cols, cfg->rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: cols/rows out of proto bounds");
    if (cfg->max_bytes_in == 0 || cfg->max_bytes_out == 0 ||
        cfg->lifetime_seconds == 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: byte and lifetime budgets must be nonzero");
    if (strlen(cfg->shell_path) >= MESH_TERMINAL_WIN_PATH_MAX ||
        strlen(cfg->workdir) >= MESH_TERMINAL_WIN_PATH_MAX)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: workdir path too long");

    out->pid = 0;
    out->pgid = 0;
    out->max_bytes_in = cfg->max_bytes_in;
    out->max_bytes_out = cfg->max_bytes_out;
    out->lifetime_seconds = cfg->lifetime_seconds;
    out->idle_seconds = cfg->idle_seconds;
    out->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;

    wchar_t wshell[MESH_TERMINAL_WIN_PATH_MAX];
    wchar_t wworkdir[MESH_TERMINAL_WIN_PATH_MAX];
    if (!win_widen(cfg->shell_path, wshell, MESH_TERMINAL_WIN_PATH_MAX) ||
        !win_widen(cfg->workdir, wworkdir, MESH_TERMINAL_WIN_PATH_MAX))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path/workdir is not valid UTF-8");

    SECURITY_ATTRIBUTES inheritable = { .nLength = sizeof(inheritable),
                                        .bInheritHandle = TRUE };
    HANDLE conin_read = NULL, conin_write = NULL;
    HANDLE conout_read = NULL, conout_write = NULL;
    if (!CreatePipe(&conin_read, &conin_write, &inheritable,
                    (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePipe(input) failed error=%lu", GetLastError());
    if (!CreatePipe(&conout_read, &conout_write, &inheritable,
                    (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES)) {
        CloseHandle(conin_read);
        CloseHandle(conin_write);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePipe(output) failed error=%lu", GetLastError());
    }
    /* Neither of OUR retained ends should be inherited by any child: the
     * pseudoconsole attribute is how the child receives its console, not
     * handle inheritance. */
    (void)SetHandleInformation(conin_write, HANDLE_FLAG_INHERIT, 0);
    (void)SetHandleInformation(conout_read, HANDLE_FLAG_INHERIT, 0);

    HPCON hpc = NULL;
    COORD size = { .X = (SHORT)cfg->cols, .Y = (SHORT)cfg->rows };
    HRESULT hr = CreatePseudoConsole(size, conin_read, conout_write, 0, &hpc);
    /* ConPTY duplicates whichever ends it needs; our copies of the ends it
     * now owns are always closed, success or failure. */
    CloseHandle(conin_read);
    CloseHandle(conout_write);
    if (FAILED(hr)) {
        CloseHandle(conin_write);
        CloseHandle(conout_read);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    }

    SIZE_T attr_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    void *attr_buf = attr_size ? zcl_malloc(attr_size, "mesh_terminal_worker_win_attr_list") : NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)attr_buf;
    bool attrs_ok = attr_buf != NULL;
    if (attrs_ok)
        attrs_ok = InitializeProcThreadAttributeList(attr_list, 1, 0,
                                                      &attr_size) != 0;
    if (attrs_ok)
        attrs_ok = UpdateProcThreadAttribute(
                       attr_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                       hpc, sizeof(hpc), NULL, NULL) != 0;
    if (!attrs_ok) {
        bool alloc_failed = attr_buf == NULL;
        DWORD attr_error = alloc_failed ? 0 : GetLastError();
        if (attr_buf)
            DeleteProcThreadAttributeList(attr_list);
        free(attr_buf);
        ClosePseudoConsole(hpc);
        CloseHandle(conin_write);
        CloseHandle(conout_read);
        if (alloc_failed)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                           "attribute list allocation failed");
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list setup failed error=%lu", attr_error);
    }

    /* Deliberately minimal environment, mirroring the POSIX arm's grant:
     * no inherited PATH to leak a search order. SystemRoot is not a
     * secret (it names the OS install drive, not a user path) and is
     * required for cmd.exe and most console-aware runtimes to initialize
     * at all, so it is read from the broker's own environment rather than
     * guessed. HOME/USERPROFILE/TERM mirror the POSIX grant for a
     * POSIX-shaped shell (e.g. a git-bash or MSYS2 bash.exe) configured as
     * -terminalshell. */
    wchar_t sysroot[MESH_TERMINAL_WIN_PATH_MAX];
    DWORD sysroot_len = GetEnvironmentVariableW(L"SystemRoot", sysroot,
                                                MESH_TERMINAL_WIN_PATH_MAX);
    bool have_sysroot =
        sysroot_len > 0 && sysroot_len < MESH_TERMINAL_WIN_PATH_MAX;

    wchar_t env[4u * MESH_TERMINAL_WIN_PATH_MAX];
    size_t env_cap = sizeof(env) / sizeof(env[0]);
    size_t env_off = 0;
    if (have_sysroot)
        env_off = win_env_put(env, env_cap, env_off, L"SystemRoot", sysroot);
    env_off = win_env_put(env, env_cap, env_off, L"HOME", wworkdir);
    env_off = win_env_put(env, env_cap, env_off, L"USERPROFILE", wworkdir);
    env_off = win_env_put(env, env_cap, env_off, L"TERM", L"xterm");
    if (env_off < env_cap)
        env[env_off++] = L'\0'; /* final NUL terminates the block */

    wchar_t cmdline[MESH_TERMINAL_WIN_PATH_MAX + 2u];
    cmdline[0] = L'"';
    wmemcpy(cmdline + 1, wshell, wcslen(wshell));
    cmdline[1 + wcslen(wshell)] = L'"';
    cmdline[2 + wcslen(wshell)] = L'\0';

    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attr_list;

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    BOOL started = CreateProcessW(wshell, cmdline, NULL, NULL, FALSE, flags,
                                  env, wworkdir, &startup.StartupInfo, &pi);
    DWORD create_error = started ? 0 : GetLastError();

    DeleteProcThreadAttributeList(attr_list);
    free(attr_buf);

    if (!started) {
        ClosePseudoConsole(hpc);
        CloseHandle(conin_write);
        CloseHandle(conout_read);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_EXEC,
                       "CreateProcessW failed error=%lu", create_error);
    }
    CloseHandle(pi.hThread);

    out->pid = (pid_t)pi.dwProcessId;
    out->pgid = out->pid; /* no Windows process-group census yet; see kill */
    out->win_pc = hpc;
    out->win_process = pi.hProcess;
    out->win_input_write = conin_write;
    out->win_output_read = conout_read;
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
    if (!w->running || !w->win_input_write)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "input: session is over (%s)",
                       mesh_terminal_close_reason_string(w->close_reason));
    if (mesh_terminal_worker_budget_would_overrun(w->bytes_in,
                                                  w->max_bytes_in, n)) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "input budget %llu exceeded (%llu used, %zu offered)",
                       (unsigned long long)w->max_bytes_in,
                       (unsigned long long)w->bytes_in, n);
    }

    /* Anonymous pipes cannot be opened overlapped (Windows refuses
     * FILE_FLAG_OVERLAPPED on a CreatePipe handle), so there is no
     * portable non-blocking WriteFile here the way the POSIX arm's
     * O_NONBLOCK fd gives it. MESH_TERMINAL_WIN_PIPE_BYTES gives the pipe
     * generous headroom over one wire frame's payload so an ordinary
     * write completes without the far end needing to drain first; a
     * shell that stops reading its console input entirely (the same
     * pathology the POSIX arm bounds with poll(POLLOUT, 1000ms) and
     * reports as ERR_IO) can still stall this call, and the pump tick
     * with it, on a real box. That risk is UNVERIFIED without one — see
     * the header comment. */
    size_t total = 0;
    while (total < n) {
        DWORD wrote = 0;
        if (!WriteFile((HANDLE)w->win_input_write, bytes + total,
                       (DWORD)(n - total), &wrote, NULL))
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input failed error=%lu (wrote %zu/%zu)",
                           GetLastError(), total, n);
        if (wrote == 0)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input stalled (wrote %zu/%zu)", total, n);
        total += wrote;
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
    if (!w->win_output_read)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "output: pty closed");

    /* PeekNamedPipe first, then read only what is already buffered: the
     * same "check, then take what is there, never wait for more" shape
     * as the POSIX arm's O_NONBLOCK read, and the natural fit for a
     * synchronous 100ms tick that polls every live session in a plain
     * loop. Overlapped ReadFile is not an option on an anonymous pipe
     * (see the input function above) and would in any case need
     * per-worker OVERLAPPED/event state the tick has no slot for;
     * PeekNamedPipe needs none. */
    DWORD available = 0;
    if (!PeekNamedPipe((HANDLE)w->win_output_read, NULL, 0, NULL, &available,
                       NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF)
            return ZCL_OK; /* far end gone: budget_exceeded() reaps the exit */
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "PeekNamedPipe failed error=%lu", err);
    }
    if (available == 0)
        return ZCL_OK;
    DWORD want = (DWORD)cap;
    if (available < want)
        want = available;
    DWORD got = 0;
    if (!ReadFile((HANDLE)w->win_output_read, buf, want, &got, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF)
            return ZCL_OK;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "pty read failed error=%lu", err);
    }
    *out_len = (size_t)got;
    w->bytes_out += (uint64_t)got;
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

static struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "resize: worker required");
    if (!w->win_pc)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "resize: pty closed");
    if (!geometry_in_bounds(cols, rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                       "resize: cols/rows out of proto bounds");
    COORD size = { .X = (SHORT)cols, .Y = (SHORT)rows };
    HRESULT hr = ResizePseudoConsole((HPCON)w->win_pc, size);
    if (FAILED(hr))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "ResizePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    /* The console host raises its own resize signal to the child; nothing
     * to forward by hand, mirroring the POSIX arm's SIGWINCH comment. */
    return ZCL_OK;
}

static bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    if (!w)
        return true;
    if (!w->running)
        return true;
    DWORD code = 0;
    if (w->win_process &&
        GetExitCodeProcess((HANDLE)w->win_process, &code) &&
        code != STILL_ACTIVE) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return true;
    }
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
    /* No Windows process-group census yet (see mesh_terminal_worker_kill
     * below): a fork-bomb-style subtree explosion under the spawned shell
     * is not bounded here the way os_sandbox_process_group_census bounds
     * it on Linux. Open gap, not a silent claim of parity — see the
     * header comment. */
    return false;
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w || !w->running)
        return false;
    DWORD code = 0;
    if (w->win_process && GetExitCodeProcess((HANDLE)w->win_process, &code) &&
        code != STILL_ACTIVE) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return false;
    }
    return w->running;
}

static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    if (w->win_pc) {
        ClosePseudoConsole((HPCON)w->win_pc);
        w->win_pc = NULL;
    }
    tw_win_close(&w->win_input_write);
    tw_win_close(&w->win_output_read);
    if (!w->running) {
        tw_win_close(&w->win_process);
        return;
    }
    if (w->win_process) {
        /* 128 + SIGKILL(9), matching the POSIX arm's forced-kill exit
         * code convention so a caller reading exit_code cannot tell the
         * two arms apart. */
        (void)TerminateProcess((HANDLE)w->win_process, 137);
        DWORD waited = WaitForSingleObject((HANDLE)w->win_process, 2000);
        DWORD code = 0;
        if (waited == WAIT_OBJECT_0 &&
            GetExitCodeProcess((HANDLE)w->win_process, &code))
            w->exit_code = (int)code;
        else
            w->exit_code = 137;
        tw_win_close(&w->win_process);
    }
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
}

#endif /* __linux__ / _WIN32 */

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
