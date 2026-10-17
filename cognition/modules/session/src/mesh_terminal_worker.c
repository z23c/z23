/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker implementation — see the header
 * for the contract. Linux uses a PTY; Windows uses ConPTY; the stub
 * refuses by name on every other platform. */

#define _GNU_SOURCE /* ptsname_r, pipe2 — must precede every include */

#include "session/mesh_terminal_worker.h"
#include "platform/os_proc.h"
#include "mesh_terminal_worker_spawn.h"
#include "mesh_terminal_worker_internal.h"

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
#elif !defined(_WIN32)
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

#endif /* Linux implementation or unsupported-platform refusal */

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

#if !defined(_WIN32)
uintptr_t mesh_terminal_worker_output_wait_handle(struct mesh_terminal_worker *w)
{
    (void)w;
    return 0;

}

struct zcl_result mesh_terminal_worker_begin_output_close(struct mesh_terminal_worker *w)
{
    (void)w;
    return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY, "asynchronous console close unavailable");

}

uintptr_t mesh_terminal_worker_close_wait_handle(struct mesh_terminal_worker *w)
{
    (void)w;
    return 0;

}

uintptr_t mesh_terminal_worker_budget_wait_handle(struct mesh_terminal_worker *w)
{
    (void)w;
    return 0;

}


#endif

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
