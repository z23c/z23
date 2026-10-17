/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker implementation — see the header
 * for the contract. Linux uses a PTY; Windows uses ConPTY; the stub
 * refuses by name on every other platform. */

#define _GNU_SOURCE /* ptsname_r, pipe2 — must precede every include */

#include "session/mesh_terminal_worker.h"
#include "platform/os_proc.h"
#include "mesh_terminal_worker_spawn.h"

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
/* ConPTY needs NTDDI_VERSION at NTDDI_WIN10_RS5 (0x0A000006) or newer, which
 * <sdkddkver.h> does not derive from _WIN32_WINNT alone. Pin it here (as
 * logical_cpu.c pins its own floor) so the standalone check-windows-cross-syntax
 * compile sees the real API surface, and refuse a lower floor set elsewhere. */
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
#include "platform/process_lifecycle.h"

#include <bcrypt.h>
#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "util/safe_alloc.h" /* zcl_malloc: checked, logged OOM */
#else
#include <unistd.h> /* access (argv refusal) */
#endif

/* The default subtree process budget, enforced by the parent's
 * process-group census (RLIMIT_NPROC cannot do this job — it counts the
 * whole uid's tasks — so the census is the only escape-proof accounting).
 * A pipeline, command substitution, and a couple of subshells stay well
 * under it. */
#define MESH_TERMINAL_WORKER_MAX_PROCESSES 32u


const char *mesh_terminal_worker_error_string(
    enum mesh_terminal_worker_error error)
{
    /* Indexed by -code: ERR_NONE is 0, every failure counts down from -1. */
    static const char *const names[] = {
        "ok", "null", "config", "pty", "spawn", "confinement", "exec", "tty",
        "not-running", "byte-limit", "io", "geometry", "unsupported",
        "job-assign", "pidns-unavailable",
    };
    if (error <= 0 && (size_t)-error < sizeof names / sizeof names[0])
        return names[-error];
    return "unknown";
}

/* ── Platform-neutral bookkeeping, shared by every arm below ───────────
 * Pure functions of primitive types: a Linux unit test proves them with no shell. */

/* True when accepting `n` more bytes on top of `used` already charged against
 * `max` would cross the budget. The Windows input path calls this; the POSIX
 * arm inlines the same test. Non-static and declared in the header so the
 * Linux-hosted unit test reaches it and -Wunused-function stays quiet. */
bool mesh_terminal_worker_budget_would_overrun(uint64_t used, uint64_t max,
                                               size_t n)
{
    return used > max || n > max - used;
}

enum tw_env_source { TW_ENV_PASS, TW_ENV_WORKDIR, TW_ENV_TERM };

struct tw_env_entry {
    const char *name;
    enum tw_env_source source;
};

static const struct tw_env_entry tw_env_table[] = {
    { "APPDATA", TW_ENV_PASS },        { "ComSpec", TW_ENV_PASS },
    { "HOME", TW_ENV_WORKDIR },        { "LOCALAPPDATA", TW_ENV_PASS },
    { "PATH", TW_ENV_PASS },           { "SystemRoot", TW_ENV_PASS },
    { "TEMP", TW_ENV_PASS },           { "TERM", TW_ENV_TERM },
    { "TMP", TW_ENV_PASS },            { "USERPROFILE", TW_ENV_WORKDIR },
    { "windir", TW_ENV_PASS },
};

const char *mesh_terminal_win_env_name(size_t index)
{
    if (index >= sizeof(tw_env_table) / sizeof(tw_env_table[0]))
        return NULL;
    return tw_env_table[index].name;
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
    else if (WIFSIGNALED(status)) {
        w->exit_code = 128 + WTERMSIG(status);
        w->term_signal = WTERMSIG(status);
    }
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
}

#if defined(ZCL_TESTING)
static uint32_t g_tw_seq, g_tw_killpg_seq, g_tw_reap_seq;
#define TW_MARK(v) ((v) = ++g_tw_seq)

void mesh_terminal_worker_testing_order(uint32_t *killpg_seq, uint32_t *reap_seq)
{
    *killpg_seq = g_tw_killpg_seq;
    *reap_seq = g_tw_reap_seq;
    g_tw_killpg_seq = g_tw_reap_seq = 0;
}
#else
#define TW_MARK(v) ((void)0)
#endif

/* Non-blocking look at the leader; true when the shell has exited. WNOWAIT
 * leaves it a zombie that keeps the group id reserved until teardown reaps it. */
static bool tw_reap(struct mesh_terminal_worker *w)
{
    if (!w->running)
        return true;
    siginfo_t si = { 0 };
    int rc = waitid(P_PID, (id_t)w->pid, &si, WEXITED | WNOHANG | WNOWAIT);
    if (rc == 0 && si.si_pid == w->pid) {
        tw_record_exit(w, si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8
                                                   : si.si_status & 0x7f);
        w->leader_held = true;
        return true;
    }
    if (rc < 0 && errno == ECHILD) {
        /* Nobody to wait for: treat as exited (should not happen). */
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
        return true;
    }
    return false;
}

static void tw_slot(volatile pid_t *slot, pid_t v) { if (slot) *slot = v; }

/* A signal interruption does not settle child ownership. */
static pid_t tw_wait_settled(pid_t pid, int *status)
{
    pid_t got;
    do {
        got = waitpid(pid, status, 0);
    } while (got < 0 && errno == EINTR);
    return got;
}

/* The granted binary: an explicit argv names it, otherwise the shell. */
static const char *tw_binary(const struct mesh_terminal_worker_config *cfg)
{
    return cfg->argv ? cfg->argv[0] : cfg->shell_path;
}

#define TW_RULES_MAX 6u

/* The cage's filesystem grants: the workdir read/write, the one binary
 * read/execute, and for an explicit argv the standard library directories
 * that exist, read/execute. For an explicit argv the exec mode is FILE_EXEC,
 * which is not W^X (a written file can be mapped); see os_sandbox.h. */
static size_t tw_grant_rules(const struct mesh_terminal_worker_config *cfg,
                             struct os_sandbox_path_rule *rules)
{
    static const char *const libs[] = { "/lib", "/lib64", "/usr/lib", "/usr/lib64" };
    rules[0] = (struct os_sandbox_path_rule){ .path = cfg->workdir,
        .allow_read = true, .allow_write = true, .allow_execute = true,
        .allow_create = true };
    rules[1] = (struct os_sandbox_path_rule){ .path = tw_binary(cfg),
        .allow_read = true, .allow_execute = true };
    size_t n = 2;
    for (size_t i = 0; cfg->argv && i < sizeof libs / sizeof libs[0]; i++)
        if (access(libs[i], F_OK) == 0)
            rules[n++] = (struct os_sandbox_path_rule){ .path = libs[i],
                .allow_read = true, .allow_execute = true };
    return n;
}

/* Pre-exit stage report: the parent names this failure from its own EOF read. */
[[noreturn]] static void tw_fail(int stage_fd, uint8_t stage, int code)
{
    ssize_t reported = write(stage_fd, &stage, 1);
    (void)reported;
    _exit(code);
}

/* Match exec's caught-handler reset before any descriptor sweep. Signals stay
 * blocked until sandbox setup is complete; explicitly ignored signals retain
 * their existing exec semantics. Reserved libc signal numbers may be EINVAL. */
static bool tw_reset_caught_signals(void)
{
    struct sigaction reset = {.sa_handler = SIG_DFL};
    if (sigemptyset(&reset.sa_mask) != 0) return false;
    for (int number = 1; number < NSIG; ++number) {
        if (number == SIGKILL || number == SIGSTOP) continue;
        struct sigaction current;
        if (sigaction(number, NULL, &current) != 0) {
            if (errno == EINVAL) continue;
            return false;
        }
        if (current.sa_handler != SIG_IGN && current.sa_handler != SIG_DFL &&
            sigaction(number, &reset, NULL) != 0) return false;
    }
    return true;
}

/* The child half of spawn: never returns; stages failures by name. */
static void tw_child(const struct mesh_terminal_worker_config *cfg,
                     const char *slave_path, int master, int stage_fd,
                     const sigset_t *original_mask)
{
    /* Nothing here may return into the parent's execution state; every
     * path ends in _exit. */
    if (!tw_reset_caught_signals())
        tw_fail(stage_fd, TW_STAGE_CONFINEMENT, 126);
    close(master);

    if (!twx_tty_setup(cfg, slave_path)) tw_fail(stage_fd, TW_STAGE_TTY, 126);

    if (!os_proc_close_inherited_fds_except(stage_fd))
        tw_fail(stage_fd, TW_STAGE_CONFINEMENT, 126);

    if (chdir(cfg->workdir) < 0) tw_fail(stage_fd, TW_STAGE_CHDIR, 126);
    /* Own PID namespace: no outside pid is addressable. Fail closed. */
    if (os_sandbox_pidns_enter(stage_fd) != 0) tw_fail(stage_fd, TW_STAGE_PIDNS, 126);

    /* The grant IS the filesystem: the per-terminal workdir (the child's
     * cwd and HOME) plus the one granted binary (and, for an explicit argv,
     * the standard library directories). */
    struct os_sandbox_path_rule rules[TW_RULES_MAX];
    size_t n_rules = tw_grant_rules(cfg, rules);
    struct os_sandbox_profile profile =
        os_sandbox_terminal_worker_profile(rules, n_rules);
    /* An explicit argv may be dynamically linked: let ld.so map libraries
     * (file-backed PROT_EXEC mmap) while anonymous/mprotect exec stays killed. */
    if (cfg->argv) profile.seccomp_deny_exec_mmap = OS_SANDBOX_WX_FILE_EXEC;
    if (!os_sandbox_enter(&profile).ok) tw_fail(stage_fd, TW_STAGE_CONFINEMENT, 126);

    /* Deliberately minimal environment: no PATH to leak a search order,
     * HOME/PWD pinned to the grant so no rc file outside it is read. */
    char home[512 + 8], pwd[512 + 8];
    (void)snprintf(home, sizeof home, "HOME=%s", cfg->workdir);
    (void)snprintf(pwd, sizeof pwd, "PWD=%s", cfg->workdir);
    char *const envp[] = { (char *)"TERM=xterm", home, pwd, NULL };
    char *const default_argv[] = { (char *)cfg->shell_path, NULL };
    char *const *exec_argv = cfg->argv ? (char *const *)cfg->argv : default_argv;
    if (sigprocmask(SIG_SETMASK, original_mask, NULL) != 0)
        tw_fail(stage_fd, TW_STAGE_CONFINEMENT, 126);
    execve(tw_binary(cfg), exec_argv, envp);

    tw_fail(stage_fd, TW_STAGE_EXEC, 127);
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
    out->leader_held = false;
    out->pgid_slot = cfg->pgid_slot;
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

    /* Only this calling thread's mask changes. Blocking before fork prevents
     * an inherited caught handler from opening a descriptor around the sweep. */
    sigset_t blocked, original_mask;
    if (sigfillset(&blocked) != 0 ||
        sigprocmask(SIG_SETMASK, &blocked, &original_mask) != 0) {
        int saved = errno;
        close(master);
        close(stage_pipe[0]);
        close(stage_pipe[1]);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "signal block failed errno=%d", saved);
    }
    pid_t pid = fork();
    int fork_error = errno;
    if (pid == 0) {
        close(stage_pipe[0]);
        tw_child(cfg, slave_path, master, stage_pipe[1], &original_mask);
        _exit(127); /* unreachable */
    }
    int restore_error = sigprocmask(SIG_SETMASK, &original_mask, NULL) == 0 ? 0 : errno;
    if (pid < 0 || restore_error) {
        /* A restore failure cannot discard ownership of a successfully forked
         * child: it is killed and reaped here, never leaked. */
        twx_abandon_child(pid);
        close(master);
        close(stage_pipe[0]);
        close(stage_pipe[1]);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "fork/signal restore failed errno=%d restore_errno=%d",
                       pid < 0 ? fork_error : 0, restore_error);
    }

    /* Parent: read the staging pipe to EOF — zero bytes means the child
     * execed (the pipe closed with the exec), one byte names the stage
     * that failed. */
    close(stage_pipe[1]);
    /* Residual window: a stop before this store sees slot 0 and skips the killpg;
     * the session's SIGKILL then hangs the worker up (see hub_server.c). */
    tw_slot(cfg->pgid_slot, pid);
    uint8_t stage = twx_read_stage(stage_pipe[0]);
    close(stage_pipe[0]);

    if (stage != 0) {
        int status = 0;
        tw_slot(cfg->pgid_slot, 0);
        (void)tw_wait_settled(pid, &status);
        close(master);
        return twx_stage_error(stage);
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
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: worker required");
    if (n == 0)
        return ZCL_OK;
    if (!bytes)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: bytes required");
    if (!w->running || w->master_fd < 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "input: session is over (%s)",
                       mesh_terminal_close_reason_string(w->close_reason));
    if (mesh_terminal_worker_budget_would_overrun(
            w->bytes_in, w->max_bytes_in, n)) {
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
            w->bytes_in += (size_t)wr;
            w->last_activity_unix = now_unix;
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

/* Bounded reap of the leader, then a blocking one so no zombie leaks. */
static void tw_reap_leader(struct mesh_terminal_worker *w)
{
    int status = 0;
    pid_t got = 0;
    for (int i = 0; i < 100; i++) {
        got = waitpid(w->pid, &status, WNOHANG);
        if (got == w->pid || (got < 0 && os_sandbox_process_group_census(w->pgid) == 0))
            break;
        usleep(2000);
    }
    if (got != w->pid)
        got = tw_wait_settled(w->pid, &status);
    TW_MARK(g_tw_reap_seq);
    if (got == w->pid && w->running)
        tw_record_exit(w, status);
    else if (w->running) {
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
    }
    w->leader_held = false;
}

static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    if (w->master_fd >= 0) {
        close(w->master_fd);
        w->master_fd = -1;
    }
    if (!w->running && !w->leader_held)
        return; /* fully reaped: the group id may be anyone's now */

    /* Whole group first, while the leader (running or a zombie) holds the id;
     * only then is the leader reaped. */
    if (w->pgid > 1)
        (void)kill(-w->pgid, SIGKILL);
    TW_MARK(g_tw_killpg_seq);
    tw_slot(w->pgid_slot, 0);
    if (w->running && w->pid > 1)
        (void)kill(w->pid, SIGKILL);
    tw_reap_leader(w);
}

#elif defined(_WIN32) /* _WIN32 */

/* Every path this worker widens is bounded well under MAX_PATH-class
 * limits by spawn's own refusal below; a fixed stack buffer needs no
 * heap and adds no failure mode beyond "too long", which spawn already
 * refuses by name. */
#define MESH_TERMINAL_WIN_PATH_MAX 512u

/* Windows path shape check for the working directory, mirroring the POSIX
 * arm's absolute-path refusal: a drive-letter root ("C:\" or "C:/") or a
 * UNC root ("\\server\share"). The shell image is judged by the stricter
 * mesh_terminal_shell_path_valid. */
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
 * ordinary mesh_terminal_worker_input() write completes without the shell
 * having to drain first. */
#define MESH_TERMINAL_WIN_PIPE_BYTES 65536ul

/* How long one input write may wait for a shell that has stopped reading
 * its console, mirroring the POSIX arm's poll(POLLOUT, 1000 ms). */
#define MESH_TERMINAL_WIN_WRITE_WAIT_MS 1000u

/* Kill-on-close Job Object holding the shell and everything it starts.
 * Closing the last handle, or TerminateJobObject, ends the whole tree, so a
 * shell that forks and exits leaves nothing behind. The live-process limit
 * is the POSIX arm's census budget. */
static HANDLE tw_win_job_create(void)
{
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job)
        return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit =
        MESH_TERMINAL_WORKER_MAX_PROCESSES;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

/* SDDL granting full access to the current user and nobody else. */
static bool tw_win_owner_sddl(wchar_t *out, size_t cap)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    union {
        TOKEN_USER user;
        char raw[256];
    } info;
    DWORD got = 0;
    wchar_t *sid_text = NULL;
    bool ok = GetTokenInformation(token, TokenUser, &info, sizeof(info),
                                  &got) &&
              ConvertSidToStringSidW(info.user.User.Sid, &sid_text) &&
              swprintf(out, cap, L"D:P(A;;GA;;;%ls)", sid_text) > 0;
    if (sid_text)
        LocalFree(sid_text);
    CloseHandle(token);
    return ok;
}

/* A pipe name nobody can predict: process id plus 64 bits from the system
 * generator. */
static bool tw_win_pipe_name(wchar_t *name, size_t cap)
{
    unsigned long random[2];
    if (BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;
    return swprintf(name, cap, L"\\\\.\\pipe\\z23-terminal-%lu-%08lx%08lx",
                    GetCurrentProcessId(), random[0], random[1]) > 0;
}

/* The shell's input pipe: a named pipe opened overlapped on OUR end, so a
 * write can be abandoned after a bounded wait (an anonymous pipe cannot be
 * opened overlapped). The shell's end is a plain synchronous read handle.
 * The pipe has an unpredictable name, one instance, no remote client, and a
 * DACL that admits only the current user. */
static bool tw_win_input_pipe(HANDLE *write_end, HANDLE *read_end)
{
    wchar_t name[96], sddl[160];
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = FALSE };
    if (!tw_win_pipe_name(name, sizeof(name) / sizeof(name[0])) ||
        !tw_win_owner_sddl(sddl, sizeof(sddl) / sizeof(sddl[0])) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
        return false;
    HANDLE server = CreateNamedPipeW(
        name,
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED |
            FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
        (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES, 0, 0, &sa);
    LocalFree(sa.lpSecurityDescriptor);
    if (server == INVALID_HANDLE_VALUE)
        return false;
    HANDLE client = CreateFileW(name, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (client == INVALID_HANDLE_VALUE) {
        CloseHandle(server);
        return false;
    }
    *write_end = server;
    *read_end = client;
    return true;
}

/* Our two retained pipe ends plus the pseudoconsole they feed. */
struct tw_win_pty {
    HPCON console;
    HANDLE input_write;
    HANDLE output_read;
};

static void tw_win_pty_close(struct tw_win_pty *pty)
{
    /* Our pipe ends first: the pseudoconsole host may otherwise block on a
     * reader that will never come. */
    if (pty->input_write)
        CloseHandle(pty->input_write);
    if (pty->output_read)
        CloseHandle(pty->output_read);
    if (pty->console)
        ClosePseudoConsole(pty->console);
    memset(pty, 0, sizeof(*pty));
}

static struct zcl_result tw_win_pty_open(uint16_t cols, uint16_t rows,
                                         struct tw_win_pty *pty)
{
    memset(pty, 0, sizeof(*pty));
    HANDLE conin_read = NULL, conout_write = NULL;
    if (!tw_win_input_pipe(&pty->input_write, &conin_read))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "input pipe failed error=%lu", GetLastError());
    if (!CreatePipe(&pty->output_read, &conout_write, NULL,
                    (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES)) {
        DWORD error = GetLastError();
        CloseHandle(conin_read);
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePipe(output) failed error=%lu", error);
    }
    COORD size = { .X = (SHORT)cols, .Y = (SHORT)rows };
    HRESULT hr =
        CreatePseudoConsole(size, conin_read, conout_write, 0, &pty->console);
    /* ConPTY duplicates whichever ends it needs; our copies of the ends it
     * now owns are always closed, success or failure. */
    CloseHandle(conin_read);
    CloseHandle(conout_write);
    if (FAILED(hr)) {
        pty->console = NULL;
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    }
    return ZCL_OK;
}

/* The shell's environment, drawn only from tw_env_table: nothing else of
 * the node's environment crosses, so no credential or token variable can
 * leak. Variables the node lacks are omitted. The block is sorted because
 * the table is. Caller frees. */
#define MESH_TERMINAL_WIN_ENV_CHARS 65536u
#define MESH_TERMINAL_WIN_ENV_VALUE_CHARS 32768u

static bool tw_win_env_value(const struct tw_env_entry *e,
                             const wchar_t *workdir, wchar_t *scratch,
                             const wchar_t **value)
{
    wchar_t wname[32];
    if (e->source == TW_ENV_WORKDIR)
        *value = workdir;
    else if (e->source == TW_ENV_TERM)
        *value = L"xterm";
    else {
        DWORD n;
        if (!win_widen(e->name, wname, 32))
            return false;
        n = GetEnvironmentVariableW(wname, scratch,
                                    MESH_TERMINAL_WIN_ENV_VALUE_CHARS);
        if (n == 0 || n >= MESH_TERMINAL_WIN_ENV_VALUE_CHARS)
            return false;
        *value = scratch;
    }
    return true;
}

static wchar_t *tw_win_env_build(const wchar_t *workdir)
{
    wchar_t *block = zcl_malloc(MESH_TERMINAL_WIN_ENV_CHARS * sizeof(wchar_t),
                                "mesh_terminal_worker_win_env");
    wchar_t *scratch = zcl_malloc(
        MESH_TERMINAL_WIN_ENV_VALUE_CHARS * sizeof(wchar_t),
        "mesh_terminal_worker_win_env_value");
    size_t off = 0;
    for (size_t i = 0; block && scratch &&
                       i < sizeof(tw_env_table) / sizeof(tw_env_table[0]);
         i++) {
        wchar_t wkey[32];
        const wchar_t *value = NULL;
        if (tw_win_env_value(&tw_env_table[i], workdir, scratch, &value) &&
            win_widen(tw_env_table[i].name, wkey, 32))
            off = win_env_put(block, MESH_TERMINAL_WIN_ENV_CHARS - 1u, off,
                              wkey, value);
    }
    free(scratch);
    if (block && off > 0)
        block[off] = L'\0'; /* final NUL terminates the block */
    else {
        free(block);
        block = NULL;
    }
    return block;
}

/* Start the shell SUSPENDED on the pseudoconsole so the caller can place it
 * in the job before it runs a single instruction. */
static struct zcl_result tw_win_create_shell(HPCON console,
                                             const wchar_t *wshell,
                                             const wchar_t *wworkdir,
                                             wchar_t *cmdline,
                                             PROCESS_INFORMATION *pi)
{
    SIZE_T attr_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    void *attr_buf = attr_size ? zcl_malloc(attr_size, "mesh_terminal_worker_win_attr_list") : NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)attr_buf;
    if (!attr_buf)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list allocation failed");
    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size) ||
        !UpdateProcThreadAttribute(attr_list, 0,
                                   PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   console, sizeof(console), NULL, NULL)) {
        DWORD error = GetLastError();
        free(attr_buf);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list setup failed error=%lu", error);
    }

    wchar_t *env = tw_win_env_build(wworkdir);
    if (!env) {
        DeleteProcThreadAttributeList(attr_list);
        free(attr_buf);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "environment block allocation failed");
    }
    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    /* Do not carry the launcher's redirected standard handles into the
     * shell: NULL slots let its attached pseudoconsole supply the streams. */
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.lpAttributeList = attr_list;
    memset(pi, 0, sizeof(*pi));
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
                  CREATE_SUSPENDED;
    BOOL started = CreateProcessW(wshell, cmdline, NULL, NULL, FALSE, flags,
                                  env, wworkdir, &startup.StartupInfo, pi);
    DWORD error = started ? 0 : GetLastError();
    DeleteProcThreadAttributeList(attr_list);
    free(attr_buf);
    free(env);
    if (!started)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_EXEC,
                       "CreateProcessW failed error=%lu", error);
    return ZCL_OK;
}

/* Put the suspended shell in the job, then let it run. A shell that cannot
 * be contained never runs: it is terminated and the spawn is refused by
 * name. */
static struct zcl_result tw_win_contain_and_resume(HANDLE job,
                                                   PROCESS_INFORMATION *pi)
{
    if (!AssignProcessToJobObject(job, pi->hProcess)) {
        DWORD error = GetLastError();
        (void)TerminateProcess(pi->hProcess, 137);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_JOB_ASSIGN,
                       "job-object-assign: the shell could not join its job "
                       "(the node may run inside a job that forbids "
                       "nesting; start it outside a restrictive job) "
                       "error=%lu", error);
    }
    if (ResumeThread(pi->hThread) == (DWORD)-1) {
        DWORD error = GetLastError();
        (void)TerminateJobObject(job, 137);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "ResumeThread failed error=%lu", error);
    }
    return ZCL_OK;
}

static struct zcl_result tw_win_spawn_config_check(
    const struct mesh_terminal_worker_config *cfg)
{
    const char *image = cfg->argv ? cfg->argv[0] : cfg->shell_path;
    if (!image ||
        !mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_WINDOWS,
                                        image) ||
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
    if (strlen(cfg->workdir) >= MESH_TERMINAL_WIN_PATH_MAX)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: workdir path too long");
    return ZCL_OK;
}

/* Validate arguments before creating a job, console or process. The shared
 * encoder owns quoting and strict UTF-8 conversion. Byte and count bounds
 * keep its input scan and allocation bounded as well. */
static wchar_t *tw_win_command_line(const struct mesh_terminal_worker_config *cfg)
{
    const char *const fallback[] = { cfg->shell_path, NULL };
    const char *const *argv = cfg->argv ? cfg->argv : fallback;
    size_t count = 0, bytes = 0;
    while (count < MESH_TERMINAL_WORKER_ARGV_MAX && argv[count]) {
        size_t n = strnlen(argv[count], 32767u);
        if (n == 32767u || n + 1u > 32767u - bytes)
            return NULL;
        bytes += n + 1u;
        count++;
    }
    if (!count || argv[count])
        return NULL;
    wchar_t *line = platform_process_windows_command_line(argv);
    if (line && wcslen(line) + 1u > 32767u) {
        free(line);
        line = NULL;
    }
    return line;
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
    struct zcl_result checked = tw_win_spawn_config_check(cfg);
    if (!checked.ok)
        return checked;
    wchar_t wshell[MESH_TERMINAL_WIN_PATH_MAX];
    wchar_t wworkdir[MESH_TERMINAL_WIN_PATH_MAX];
    const char *image = cfg->argv ? cfg->argv[0] : cfg->shell_path;
    if (!win_widen(image, wshell, MESH_TERMINAL_WIN_PATH_MAX) ||
        !win_widen(cfg->workdir, wworkdir, MESH_TERMINAL_WIN_PATH_MAX))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path/workdir is not valid UTF-8");

    wchar_t *cmdline = tw_win_command_line(cfg);
    if (!cmdline)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: argv is invalid UTF-8, unterminated or exceeds the command-line budget");

    HANDLE job = tw_win_job_create();
    if (!job) {
        DWORD error = GetLastError();
        free(cmdline);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFINEMENT,
                       "job object setup failed error=%lu", error);
    }
    struct tw_win_pty pty;
    struct zcl_result r = tw_win_pty_open(cfg->cols, cfg->rows, &pty);
    PROCESS_INFORMATION pi;
    if (r.ok)
        r = tw_win_create_shell(pty.console, wshell, wworkdir, cmdline, &pi);
    free(cmdline);
    if (r.ok) {
        r = tw_win_contain_and_resume(job, &pi);
        CloseHandle(pi.hThread);
        if (!r.ok)
            CloseHandle(pi.hProcess);
    }
    if (!r.ok) {
        tw_win_pty_close(&pty);
        CloseHandle(job);
        return r;
    }

    out->pid = (pid_t)pi.dwProcessId;
    out->pgid = out->pid; /* the job is the group; see kill */
    out->win_pc = pty.console;
    out->win_job = job;
    out->win_process = pi.hProcess;
    out->win_input_write = pty.input_write;
    out->win_output_read = pty.output_read;
    out->max_bytes_in = cfg->max_bytes_in;
    out->max_bytes_out = cfg->max_bytes_out;
    out->lifetime_seconds = cfg->lifetime_seconds;
    out->idle_seconds = cfg->idle_seconds;
    out->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
    out->started_unix = now_unix;
    out->last_activity_unix = now_unix;
    out->running = true;
    return ZCL_OK;
}

enum tw_win_write_outcome {
    TW_WIN_WRITE_OK,
    TW_WIN_WRITE_STALLED,
    TW_WIN_WRITE_FAILED
};

/* One overlapped write bounded by MESH_TERMINAL_WIN_WRITE_WAIT_MS. A write
 * still pending at the deadline is cancelled and reports STALLED together
 * with however many bytes the pipe did take; the caller decides, and the
 * session's lifetime/idle enforcement owns any kill. */
static enum tw_win_write_outcome tw_win_write_bounded(
    HANDLE pipe, const uint8_t *bytes, size_t n, DWORD *wrote, DWORD *error)
{
    *wrote = 0;
    *error = 0;
    OVERLAPPED op;
    memset(&op, 0, sizeof(op));
    op.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!op.hEvent) {
        *error = GetLastError();
        return TW_WIN_WRITE_FAILED;
    }
    enum tw_win_write_outcome outcome = TW_WIN_WRITE_OK;
    if (!WriteFile(pipe, bytes, (DWORD)n, NULL, &op) &&
        GetLastError() != ERROR_IO_PENDING) {
        *error = GetLastError();
        outcome = TW_WIN_WRITE_FAILED;
    } else {
        if (WaitForSingleObject(op.hEvent, MESH_TERMINAL_WIN_WRITE_WAIT_MS) !=
            WAIT_OBJECT_0) {
            (void)CancelIoEx(pipe, &op);
            outcome = TW_WIN_WRITE_STALLED;
        }
        if (!GetOverlappedResult(pipe, &op, wrote, TRUE) &&
            outcome == TW_WIN_WRITE_OK) {
            *error = GetLastError();
            outcome = TW_WIN_WRITE_FAILED;
        }
    }
    CloseHandle(op.hEvent);
    return outcome;
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

    /* The POSIX arm's bounded-wait shape: a shell that stops reading its
     * console is an IO refusal after MESH_TERMINAL_WIN_WRITE_WAIT_MS per
     * write, never an unbounded block of the caller's tick. */
    size_t total = 0;
    while (total < n) {
        DWORD wrote = 0, error = 0;
        enum tw_win_write_outcome outcome = tw_win_write_bounded(
            (HANDLE)w->win_input_write, bytes + total, n - total, &wrote,
            &error);
        total += wrote;
        w->bytes_in += wrote;
        if (wrote != 0)
            w->last_activity_unix = now_unix;
        if (outcome == TW_WIN_WRITE_FAILED)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input failed error=%lu (wrote %zu/%zu)",
                           error, total, n);
        if (outcome == TW_WIN_WRITE_STALLED || wrote == 0)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input stalled (wrote %zu/%zu)", total, n);
    }
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
        WaitForSingleObject((HANDLE)w->win_process, 0) == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code)) {
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
    /* The subtree size is bounded by the job's live-process limit rather
     * than a census: a spawn past it fails inside the job. */
    return false;
}

static bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w || !w->running)
        return false;
    DWORD code = 0;
    if (w->win_process &&
        WaitForSingleObject((HANDLE)w->win_process, 0) == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code)) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return false;
    }
    return w->running;
}

/* Release the console side. The job has already ended the shell, and our
 * pipe ends are closed before the pseudoconsole so its host cannot block
 * on a reader that will never come. */
static void tw_win_release_console(struct mesh_terminal_worker *w)
{
    tw_win_close(&w->win_input_write);
    tw_win_close(&w->win_output_read);
    if (w->win_pc) {
        ClosePseudoConsole((HPCON)w->win_pc);
        w->win_pc = NULL;
    }
}

/* Wait (bounded) for the terminated shell and record its exit code. */
static void tw_win_reap(struct mesh_terminal_worker *w)
{
    DWORD code = 0;
    DWORD waited = WaitForSingleObject((HANDLE)w->win_process, 2000);
    if (waited == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code))
        w->exit_code = (int)code;
    else
        w->exit_code = 137;
}

/* Ends the whole process tree: TerminateJobObject takes the shell and every
 * descendant, and closing the kill-on-close job afterwards takes anything
 * that raced it. Safe to call again and after the shell exited on its own,
 * when it still removes the descendants that outlived it. */
static void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    /* 128 + SIGKILL(9), matching the POSIX arm's forced-kill exit code
     * convention so a caller reading exit_code cannot tell the two arms
     * apart. */
    if (w->win_job)
        (void)TerminateJobObject((HANDLE)w->win_job, 137);
    else if (w->running && w->win_process)
        (void)TerminateProcess((HANDLE)w->win_process, 137);
    if (w->running && w->win_process)
        tw_win_reap(w);
    tw_win_release_console(w);
    tw_win_close(&w->win_job);
    tw_win_close(&w->win_process);
    if (!w->running)
        return;
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
}

#endif /* __linux__ / _WIN32 */

/* POSIX grants the one absolute argv image plus standard library directories.
 * Windows validates and encodes argv in its platform arm before creating any
 * handles; its owner-accepted identity policy remains separate. NULL when
 * acceptable here, otherwise the reason. */
static const char *tw_argv_refusal(const struct mesh_terminal_worker_config *cfg,
                                  int *code)
{
    if (!cfg->argv)
        return NULL;
#if defined(_WIN32)
    (void)code;
    return NULL; /* Windows validates and encodes before creating any handles. */
#else
    size_t n = 0;
    while (n <= MESH_TERMINAL_WORKER_ARGV_MAX && cfg->argv[n])
        n++;
    if (n == 0 || n > MESH_TERMINAL_WORKER_ARGV_MAX)
        return "spawn: argv must hold 1..16 strings";
    if (!mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_POSIX, cfg->argv[0]))
        return "spawn: argv[0] must be an absolute path";
    if (access(cfg->argv[0], X_OK) != 0) {
        *code = MESH_TERMINAL_WORKER_ERR_EXEC;
        return "spawn: argv[0] is not an executable file";
    }
    return NULL;
#endif
}

struct zcl_result mesh_terminal_worker_spawn(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    int bad_code = MESH_TERMINAL_WORKER_ERR_CONFIG;
    const char *bad = cfg ? tw_argv_refusal(cfg, &bad_code) : NULL;
    if (bad)
        return ZCL_ERR(bad_code, "%s", bad);
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
