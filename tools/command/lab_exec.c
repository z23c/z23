/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Confined child-process runner for the one-file lab.
 *
 * The child applies, in order: process group, descriptor scrub, cwd, scrubbed
 * environment, rlimits, no_new_privs, Landlock, seccomp (the session deny-set
 * minus what the profile needs), then execv. A setup failure travels over a
 * close-on-exec pipe, so the parent distinguishes "could not confine" from "the
 * program failed". The parent drains stdout and stderr to bounded buffers
 * while feeding stdin, and kills the whole process group at the deadline. */
#define _GNU_SOURCE

#include "command/lab_exec.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool lab_proc_init(struct lab_proc *p)
{
    memset(p, 0, sizeof(*p));
    p->out = zcl_calloc(1, LAB_CAPTURE_MAX + 1, "lab.out");
    p->err = zcl_calloc(1, LAB_CAPTURE_MAX + 1, "lab.err");
    if (p->out && p->err)
        return true;
    lab_proc_free(p);
    return false;
}

void lab_proc_free(struct lab_proc *p)
{
    free(p->out);
    free(p->err);
    p->out = NULL;
    p->err = NULL;
}

void lab_proc_reset(struct lab_proc *p)
{
    char *out = p->out, *err = p->err;
    memset(p, 0, sizeof(*p));
    p->out = out;
    p->err = err;
    if (out)
        out[0] = '\0';
    if (err)
        err[0] = '\0';
}

#if defined(__linux__)

#include "platform/clock.h"
#include "platform/os_proc.h"
#include "platform/process_compat.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
    LAB_SETUP_EXIT = 125,
    LAB_DENY_MAX = 96,
    LAB_STACK_BYTES = 8 << 20,
    LAB_TREE_DEPTH = 8,
    LAB_TREE_ENTRIES = 4096
};

static bool g_force_unconfined;
static bool g_no_pidns;
static bool g_no_fd_owner;

/* ── child side ─────────────────────────────────────────────────────── */

static bool lab_nr_kept(int nr, enum lab_profile profile)
{
    if (nr == SYS_execve || nr == SYS_execveat || nr == SYS_clone)
        return false;
#ifdef SYS_clone3
    if (nr == SYS_clone3)
        return false;
#endif
    if (profile == LAB_PROFILE_COMPILE &&
        (nr == SYS_fork || nr == SYS_vfork))
        return false;
    return true;
}

/* The session deny-set with the calls this profile must keep reachable
 * removed: exec for the initial image, clone for threads or the compiler's
 * subprocesses. Returns the count. */
static size_t lab_deny_set(enum lab_profile profile, int *out)
{
    size_t n = 0, session_n = 0;
    const int *session = os_sandbox_session_denied_syscalls(&session_n);
    for (size_t i = 0; i < session_n && n < LAB_DENY_MAX; i++)
        if (lab_nr_kept(session[i], profile))
            out[n++] = session[i];
    return n;
}

static struct zcl_result lab_child_seccomp(enum lab_profile profile)
{
    int denied[LAB_DENY_MAX];
    size_t n = lab_deny_set(profile, denied);
    if (profile == LAB_PROFILE_COMPILE)
        return os_sandbox_seccomp_deny(denied, n, false);
#ifdef SYS_clone3
    static const int enosys[] = { SYS_clone3 };
    struct zcl_result r = os_sandbox_seccomp_deny_ext(
        denied, n, OS_SANDBOX_WX_OFF, enosys, 1, true);
#else
    struct zcl_result r = os_sandbox_seccomp_deny_ext(
        denied, n, OS_SANDBOX_WX_OFF, NULL, 0, true);
#endif
    if (!zcl_result_is_ok(r))
        return r;
    r = os_sandbox_seccomp_guard_signals();
    if (!zcl_result_is_ok(r))
        return r;
    return os_sandbox_seccomp_self_signals_only_ext(
        g_no_fd_owner ? OS_SANDBOX_SELF_SIGNALS_NO_FD_OWNER : 0u);
}

static _Noreturn void lab_child_fail(int report_fd, const char *what)
{
    size_t len = strlen(what);
    ssize_t w = write(report_fd, what, len);
    (void)w;
    _exit(LAB_SETUP_EXIT);
}

static bool lab_child_env(const char *const *env)
{
    if (platform_clear_environment() != 0)
        return false;
    for (size_t i = 0; env && env[i]; i++) {
        const char *eq = strchr(env[i], '=');
        char name[48];
        size_t nl = eq ? (size_t)(eq - env[i]) : 0;
        if (nl == 0 || nl >= sizeof(name))
            return false;
        memcpy(name, env[i], nl);
        name[nl] = '\0';
        if (setenv(name, eq + 1, 1) != 0)
            return false;
    }
    return true;
}

/* An inherited unlimited stack selects the legacy mmap layout, which leaves
 * no room for the AddressSanitizer shadow. */
static bool lab_child_stack(void)
{
    struct rlimit lim = { .rlim_cur = LAB_STACK_BYTES, .rlim_max = LAB_STACK_BYTES };
    struct rlimit cur;
    if (getrlimit(RLIMIT_STACK, &cur) != 0)
        return false;
    if (cur.rlim_max != RLIM_INFINITY && cur.rlim_max < lim.rlim_max)
        lim.rlim_max = lim.rlim_cur = cur.rlim_max;
    return setrlimit(RLIMIT_STACK, &lim) == 0;
}

static void lab_child_limits(const struct lab_spawn *s, int report_fd)
{
    struct os_sandbox_rlimits lim = {
        .as_bytes = s->as_bytes,
        .cpu_seconds = (uint64_t)(s->timeout_ms / 1000u) + 2u,
        .nproc = 4096,
        .fsize_bytes = s->fsize_bytes,
        .nofile = s->nofile,
        .core_bytes = 0,
    };
    if (!lab_child_stack() || !zcl_result_is_ok(os_sandbox_set_rlimits(&lim)))
        lab_child_fail(report_fd, "rlimits could not be applied");
}

/* A node can run non-dumpable, which makes its /proc/self files root-owned
 * inside a new user namespace and the identity map unwritable. The child is
 * a private copy, so it opts back in before entering the namespace. */
static bool lab_enter_pidns(int close_fd)
{
    return prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0 &&
           os_sandbox_pidns_enter(close_fd) == 0;
}

/* Whether a fresh PID namespace can be entered: a throwaway child tries it. */
static bool lab_pidns_probe(void)
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
        _exit(lab_enter_pidns(-1) ? 0 : 1);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* The program becomes pid 2 of its own PID and user namespace (identity uid
 * map): kill(2) resolves in that namespace, so no outside process can be
 * signalled. The wrappers close the report pipe, so EOF still means exec. */
static void lab_child_pidns(const struct lab_spawn *s, int report_fd)
{
    if (s->profile == LAB_PROFILE_RUN && lab_pidns_available() &&
        !lab_enter_pidns(report_fd))
        lab_child_fail(report_fd, "pid namespace could not be entered");
}

static void lab_child_confine(const struct lab_spawn *s, int report_fd)
{
    if (!os_sandbox_no_new_privs())
        lab_child_fail(report_fd, "no_new_privs could not be set");
    if (!s->confine)
        return;
    if (g_force_unconfined)
        lab_child_fail(report_fd, "landlock unavailable (forced by test seam)");
    lab_child_pidns(s, report_fd);
    if (!zcl_result_is_ok(os_sandbox_package_restrict(s->rules, s->n_rules)))
        lab_child_fail(report_fd, "landlock could not be applied");
    if (!zcl_result_is_ok(lab_child_seccomp(s->profile)))
        lab_child_fail(report_fd, "seccomp could not be applied");
}

static void lab_child_stdio(int in_fd, int out_fd, int err_fd, int report_fd)
{
    if (dup2(in_fd, STDIN_FILENO) != STDIN_FILENO ||
        dup2(out_fd, STDOUT_FILENO) != STDOUT_FILENO ||
        dup2(err_fd, STDERR_FILENO) != STDERR_FILENO)
        lab_child_fail(report_fd, "stdio could not be wired");
    if (!os_proc_close_inherited_fds_except(report_fd))
        lab_child_fail(report_fd, "inherited descriptors could not be closed");
}

enum { LAB_P_IN, LAB_P_OUT, LAB_P_ERR, LAB_P_REPORT, LAB_P_COUNT };

struct lab_pipes {
    int fd[LAB_P_COUNT][2];
};

static _Noreturn void lab_child_main(const struct lab_spawn *s,
                                     const struct lab_pipes *p,
                                     const sigset_t *mask)
{
    int report = p->fd[LAB_P_REPORT][1];
    (void)setpgid(0, 0);
    (void)sigprocmask(SIG_SETMASK, mask, NULL);
    (void)signal(SIGPIPE, SIG_DFL);
    lab_child_stdio(p->fd[LAB_P_IN][0], p->fd[LAB_P_OUT][1],
                    p->fd[LAB_P_ERR][1], report);
    if (s->cwd && chdir(s->cwd) != 0)
        lab_child_fail(report, "working directory is not reachable");
    if (!lab_child_env(s->env))
        lab_child_fail(report, "environment could not be scrubbed");
    lab_child_limits(s, report);
    lab_child_confine(s, report);
    execv(s->argv[0], (char *const *)s->argv);
    lab_child_fail(report, "exec failed");
}

/* ── parent side ────────────────────────────────────────────────────── */

static void lab_close_fd(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

static void lab_pipes_close(struct lab_pipes *p)
{
    for (int i = 0; i < LAB_P_COUNT; i++) {
        lab_close_fd(&p->fd[i][0]);
        lab_close_fd(&p->fd[i][1]);
    }
}

static bool lab_pipes_open(struct lab_pipes *p)
{
    for (int i = 0; i < LAB_P_COUNT; i++)
        p->fd[i][0] = p->fd[i][1] = -1;
    for (int i = 0; i < LAB_P_COUNT; i++)
        if (pipe2(p->fd[i], O_CLOEXEC) != 0) {
            lab_pipes_close(p);
            return false;
        }
    return true;
}

static void lab_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Read the setup report: EOF at exec means success, bytes mean failure. */
static bool lab_read_report(int fd, struct lab_proc *out)
{
    ssize_t n;
    do {
        n = read(fd, out->detail, sizeof(out->detail) - 1);
    } while (n < 0 && errno == EINTR);
    if (n > 0)
        out->detail[n] = '\0';
    return n > 0;
}

struct lab_drain {
    int in_fd, out_fd, err_fd;
    const char *in_data;
    size_t in_len, in_off;
    const char *watch_dir;
    uint64_t watch_max;
};

static void lab_capture(int *fd, char *buf, size_t *len, bool *cut)
{
    char chunk[8192];
    ssize_t n = read(*fd, chunk, sizeof(chunk));
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return;
    if (n <= 0) {
        lab_close_fd(fd);
        return;
    }
    size_t room = LAB_CAPTURE_MAX - *len;
    size_t take = (size_t)n < room ? (size_t)n : room;
    memcpy(buf + *len, chunk, take);
    *len += take;
    buf[*len] = '\0';
    if (take < (size_t)n)
        *cut = true;
}

static void lab_feed(struct lab_drain *d)
{
    while (d->in_off < d->in_len) {
        ssize_t n = write(d->in_fd, d->in_data + d->in_off,
                          d->in_len - d->in_off);
        if (n > 0)
            d->in_off += (size_t)n;
        else if (n < 0 && errno == EAGAIN)
            return;
        else if (n < 0 && errno == EINTR)
            continue;
        else
            break;
    }
    lab_close_fd(&d->in_fd);
}

static int64_t lab_now_us(void)
{
    return clock_now_monotonic_ns() / 1000;
}

/* Allocated bytes under the workdir; UINT64_MAX when the tree is too large to
 * count, which a caller treats as over any cap. */
static uint64_t lab_tree_bytes(int dfd, unsigned depth, unsigned *budget)
{
    DIR *dir = fdopendir(dfd);
    uint64_t total = 0;
    struct dirent *e;
    if (!dir) {
        close(dfd);
        return 0;
    }
    while ((e = readdir(dir)) != NULL) {
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (*budget == 0 || depth > LAB_TREE_DEPTH) {
            closedir(dir);
            return UINT64_MAX;
        }
        (*budget)--;
        if (fstatat(dirfd(dir), e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        total += (uint64_t)st.st_blocks * 512u;
        if (S_ISDIR(st.st_mode)) {
            int sub = openat(dirfd(dir), e->d_name,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            uint64_t inner = sub >= 0 ? lab_tree_bytes(sub, depth + 1, budget) : 0;
            total = inner == UINT64_MAX ? inner : total + inner;
        }
        if (total == UINT64_MAX)
            break;
    }
    closedir(dir);
    return total;
}

static bool lab_disk_over(const struct lab_drain *d)
{
    unsigned budget = LAB_TREE_ENTRIES;
    int fd;
    if (!d->watch_dir)
        return false;
    fd = open(d->watch_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return fd >= 0 && lab_tree_bytes(fd, 0, &budget) > d->watch_max;
}

static bool lab_child_exited(pid_t pid)
{
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    return waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 &&
           si.si_pid == pid;
}

/* One poll round; false once the deadline has passed. With both output pipes
 * closed it only sleeps, so a program that closes stdout and spins is still
 * killed at the deadline. */
static bool lab_drain_round(struct lab_drain *d, struct lab_proc *out,
                            int64_t deadline_us)
{
    struct pollfd pfd[3] = {
        { .fd = d->out_fd, .events = POLLIN },
        { .fd = d->err_fd, .events = POLLIN },
        { .fd = d->in_fd, .events = POLLOUT },
    };
    int64_t left = deadline_us - lab_now_us();
    bool piping = d->out_fd >= 0 || d->err_fd >= 0;
    int tick = !piping ? 1 : d->watch_dir ? 20 : 100;
    int ms = (int)((left + 999) / 1000);
    if (left <= 0)
        return false;
    if (poll(pfd, 3, ms > tick ? tick : ms) < 0 && errno != EINTR)
        return false;
    if (d->in_fd >= 0 && pfd[2].revents)
        lab_feed(d);
    if (d->out_fd >= 0 && pfd[0].revents)
        lab_capture(&d->out_fd, out->out, &out->out_len, &out->out_cut);
    if (d->err_fd >= 0 && pfd[1].revents)
        lab_capture(&d->err_fd, out->err, &out->err_len, &out->err_cut);
    return true;
}

static void lab_drain(struct lab_drain *d, struct lab_proc *out, pid_t pid,
                      int64_t deadline_us)
{
    if (d->in_len == 0)
        lab_close_fd(&d->in_fd);
    for (;;) {
        bool piping = d->out_fd >= 0 || d->err_fd >= 0;
        if (!piping && lab_child_exited(pid))
            break;
        if (!lab_drain_round(d, out, deadline_us))
            out->timed_out = true;
        else if (lab_disk_over(d))
            out->disk_exceeded = true;
        if (out->timed_out || out->disk_exceeded) {
            (void)kill(-pid, SIGKILL);
            break;
        }
    }
    lab_close_fd(&d->in_fd);
    lab_close_fd(&d->out_fd);
    lab_close_fd(&d->err_fd);
}

static void lab_reap(pid_t pid, struct lab_proc *out, int64_t t0_us)
{
    int status = 0;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    while (wait4(pid, &status, 0, &ru) < 0 && errno == EINTR) {
    }
    (void)kill(-pid, SIGKILL);
    out->wall_us = lab_now_us() - t0_us;
    out->max_rss_kb = (int64_t)ru.ru_maxrss;
    if (WIFSIGNALED(status))
        out->term_signal = WTERMSIG(status);
    else if (WIFEXITED(status))
        out->exit_code = WEXITSTATUS(status);
}

static void lab_sigpipe_set(int how, sigset_t *old)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    (void)pthread_sigmask(how, &set, old);
}

static void lab_sigpipe_restore(const sigset_t *old)
{
    sigset_t set;
    struct timespec zero = { 0, 0 };
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    while (sigtimedwait(&set, NULL, &zero) > 0) {
    }
    (void)pthread_sigmask(SIG_SETMASK, old, NULL);
}

static void lab_parent_failed(struct lab_pipes *p, pid_t pid,
                              struct lab_proc *out, int64_t t0_us)
{
    out->launch = strstr(out->detail, "exec failed") ? LAB_LAUNCH_FAILED
                                                     : LAB_LAUNCH_UNCONFINED;
    lab_pipes_close(p);
    lab_reap(pid, out, t0_us);
}

static void lab_parent(const struct lab_spawn *s, struct lab_pipes *p,
                       pid_t pid, struct lab_proc *out, int64_t t0_us)
{
    lab_close_fd(&p->fd[LAB_P_IN][0]);
    lab_close_fd(&p->fd[LAB_P_OUT][1]);
    lab_close_fd(&p->fd[LAB_P_ERR][1]);
    lab_close_fd(&p->fd[LAB_P_REPORT][1]);
    if (lab_read_report(p->fd[LAB_P_REPORT][0], out)) {
        lab_parent_failed(p, pid, out, t0_us);
        return;
    }
    out->launch = LAB_LAUNCHED;
    out->detail[0] = '\0';
    struct lab_drain d = {
        .in_fd = p->fd[LAB_P_IN][1], .out_fd = p->fd[LAB_P_OUT][0],
        .err_fd = p->fd[LAB_P_ERR][0], .in_data = s->stdin_data,
        .in_len = s->stdin_len, .watch_dir = s->watch_dir,
        .watch_max = s->watch_max_bytes };
    lab_set_nonblock(d.in_fd);
    lab_set_nonblock(d.out_fd);
    lab_set_nonblock(d.err_fd);
    lab_close_fd(&p->fd[LAB_P_REPORT][0]);
    lab_drain(&d, out, pid, t0_us + (int64_t)s->timeout_ms * 1000);
    lab_reap(pid, out, t0_us);
}

static void lab_spawn_linux(const struct lab_spawn *s, struct lab_proc *out)
{
    (void)lab_pidns_available();
    struct lab_pipes p;
    sigset_t old;
    out->launch = LAB_LAUNCH_FAILED;
    snprintf(out->detail, sizeof(out->detail), "pipe or fork failed");
    if (!lab_pipes_open(&p))
        return;
    lab_sigpipe_set(SIG_BLOCK, &old);
    int64_t t0_us = lab_now_us();
    pid_t pid = fork();
    if (pid == 0) {
        if (!os_proc_bind_parent_death(SIGKILL, (uint64_t)getppid()))
            _exit(LAB_SETUP_EXIT);
        lab_child_main(s, &p, &old);
    }
    if (pid < 0)
        lab_pipes_close(&p);
    else
        lab_parent(s, &p, pid, out, t0_us);
    lab_sigpipe_restore(&old);
}
#endif /* __linux__ */

void lab_test_disable_fd_owner_rules(bool on)
{
#if defined(__linux__)
    g_no_fd_owner = on;
#else
    (void)on;
#endif
}

void lab_test_disable_pidns(bool on)
{
#if defined(__linux__)
    g_no_pidns = on;
#else
    (void)on;
#endif
}

void lab_test_force_confinement_failure(bool on)
{
#if defined(__linux__)
    g_force_unconfined = on;
#else
    (void)on;
#endif
}

int lab_landlock_abi(void)
{
#if defined(__linux__)
    return os_sandbox_landlock_abi();
#else
    return -1;
#endif
}

bool lab_sandbox_available(void)
{
#if defined(__linux__) && defined(__x86_64__)
    return os_sandbox_landlock_abi() >= 1 && os_sandbox_seccomp_supported();
#else
    return false;
#endif
}

bool lab_pidns_available(void)
{
#if defined(__linux__)
    static _Atomic int known;
    if (g_no_pidns)
        return false;
    int k = known;
    if (k == 0) {
        k = lab_pidns_probe() ? 1 : 2;
        known = k;
    }
    return k == 1;
#else
    return false;
#endif
}

bool lab_confinement_available(void)
{
    return lab_sandbox_available();
}

const char *lab_signal_name(int sig)
{
#if defined(__linux__)
    switch (sig) {
    case 0: return "";
    case SIGSEGV: return "SIGSEGV";
    case SIGABRT: return "SIGABRT";
    case SIGFPE: return "SIGFPE";
    case SIGILL: return "SIGILL";
    case SIGBUS: return "SIGBUS";
    case SIGKILL: return "SIGKILL";
    case SIGSYS: return "SIGSYS";
    case SIGXCPU: return "SIGXCPU";
    case SIGXFSZ: return "SIGXFSZ";
    case SIGTRAP: return "SIGTRAP";
    case SIGPIPE: return "SIGPIPE";
    case SIGTERM: return "SIGTERM";
    default: return "SIG?";
    }
#else
    (void)sig;
    return "";
#endif
}

void lab_spawn_run(const struct lab_spawn *s, struct lab_proc *out)
{
#if defined(__linux__)
    lab_spawn_linux(s, out);
#else
    (void)s;
    out->launch = LAB_LAUNCH_UNSUPPORTED;
    snprintf(out->detail, sizeof(out->detail),
             "the lab runs on Linux hosts only");
#endif
}
