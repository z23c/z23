/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox — the Linux terminal-worker cage builders, split out of
 * os_sandbox_linux.c so the general confinement backend stays within its
 * size band. See platform/os_sandbox.h for the design and the ordering
 * invariant; the confined shell itself is cognition/modules/session/src/mesh_terminal_worker.c.
 * Compiled only on Linux (the Makefile filter-outs pair this file with
 * os_sandbox_linux.c); the portable stub carries the same entry points. */

#define _GNU_SOURCE
#include "platform/os_sandbox.h"

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Kernel ABI numbers for syscalls an older libc header set may lack (the same
 * fallbacks os_sandbox_plugin.c carries; 425..427 and 424/434/438 are identical
 * on x86_64 and the generic table). */
#ifdef __NR_io_uring_setup
#define TW_NR_URING_SETUP __NR_io_uring_setup
#define TW_NR_URING_ENTER __NR_io_uring_enter
#define TW_NR_URING_REGISTER __NR_io_uring_register
#else
#define TW_NR_URING_SETUP 425
#define TW_NR_URING_ENTER 426
#define TW_NR_URING_REGISTER 427
#endif
#ifdef __NR_pidfd_open
#define TW_NR_PIDFD_OPEN __NR_pidfd_open
#else
#define TW_NR_PIDFD_OPEN 434
#endif
#ifdef __NR_pidfd_send_signal
#define TW_NR_PIDFD_SEND __NR_pidfd_send_signal
#else
#define TW_NR_PIDFD_SEND 424
#endif
#ifdef __NR_pidfd_getfd
#define TW_NR_PIDFD_GETFD __NR_pidfd_getfd
#else
#define TW_NR_PIDFD_GETFD 438
#endif

/* The terminal worker's deny-set: the session set with the code execution /
 * process creation family (execve/execveat/clone/clone3/fork/vfork) REMOVED —
 * the confined shell must fork/exec its own children, and Landlock bounds
 * what execve can reach. Everything else stays: the socket family (the
 * worker talks to the node ONLY through its pre-opened PTY fds), ptrace /
 * process_vm_*, mount/namespace escape, kernel surface, keyrings, and
 * open_by_handle_at. Added beyond the session set (the plugin profile denies
 * the same, os_sandbox_plugin.c): io_uring (IORING_OP_SOCKET/CONNECT carry a
 * socket past the socket deny), signals aimed at other processes by thread
 * or queue (tkill/tgkill/rt_*sigqueueinfo), the pidfd family (signal or steal
 * a descriptor from the node), and memfd_create (an anonymous executable
 * payload). Plain kill(2) stays for job control but is guarded by a second
 * filter, see os_sandbox_seccomp_guard_signals. */
static const int g_terminal_worker_denied[] = {
    /* the socket family */
    __NR_socket,
#ifdef __NR_socketcall
    __NR_socketcall,
#endif
    __NR_socketpair, __NR_connect, __NR_bind, __NR_listen,
    __NR_accept, __NR_accept4, __NR_setsockopt, __NR_getsockopt,
    /* debugging / cross-process memory */
    __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
    /* mount / namespace escape */
    __NR_mount, __NR_umount2, __NR_pivot_root, __NR_setns, __NR_unshare,
    /* kernel surface */
    __NR_bpf, __NR_kexec_load, __NR_kexec_file_load,
    __NR_init_module, __NR_finit_module, __NR_delete_module,
    __NR_perf_event_open,
    /* keyrings */
    __NR_add_key, __NR_request_key, __NR_keyctl,
    /* handle-based open bypass */
    __NR_open_by_handle_at,
    /* io_uring: socket/connect with no syscall for seccomp to see */
    TW_NR_URING_SETUP, TW_NR_URING_ENTER, TW_NR_URING_REGISTER,
    /* signalling by thread/queue, and the pidfd family */
    __NR_tkill, __NR_tgkill, __NR_rt_sigqueueinfo, __NR_rt_tgsigqueueinfo,
    TW_NR_PIDFD_OPEN, TW_NR_PIDFD_SEND, TW_NR_PIDFD_GETFD,
    /* anonymous in-memory file for an executable payload */
#ifdef __NR_memfd_create
    __NR_memfd_create,
#endif
};

const int *os_sandbox_terminal_worker_denied_syscalls(size_t *count_out)
{
    if (count_out)
        *count_out = sizeof(g_terminal_worker_denied) /
                     sizeof(g_terminal_worker_denied[0]);
    return g_terminal_worker_denied;
}

struct os_sandbox_rlimits os_sandbox_terminal_worker_rlimits(void)
{
    return (struct os_sandbox_rlimits){
        .as_bytes    = (uint64_t)256 * 1024 * 1024,
        .cpu_seconds = 300,
        /* No NPROC clamp: RLIMIT_NPROC counts the whole real uid's tasks,
         * so any fixed ceiling below the uid's live total (the node's own
         * thread pool, a shared dev host) blocks EVERY fork inside the
         * cage — the shell could not even run a pipeline. The shell must
         * fork; the real subtree budget is the responder's process-group
         * census over the session's pgid (see the process-budget block
         * comment in os_sandbox_linux.c), which is load-independent and
         * escape-proof. */
        .nproc       = OS_SANDBOX_RLIMIT_KEEP,
        .fsize_bytes = (uint64_t)1024 * 1024,
        .nofile      = 64,
        .core_bytes  = 0,
    };
}

struct os_sandbox_profile os_sandbox_terminal_worker_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules)
{
    size_t n_denied = 0;
    const int *denied = os_sandbox_terminal_worker_denied_syscalls(&n_denied);
    return (struct os_sandbox_profile){
        .name = "terminal_worker",
        .no_new_privs = true,
        .apply_rlimits = true,
        .rlimits = os_sandbox_terminal_worker_rlimits(),
        .landlock = true,
        .fs_rules = fs_rules,
        .n_fs_rules = n_fs_rules,
        .seccomp = true,
        .denied_syscalls = denied,
        .n_denied = n_denied,
        .seccomp_deny_exec_mmap = true,
        .seccomp_guard_signals = true,
    };
}

/* ── PID namespace for the confined shell ──────────────────────────────── */

static bool pidns_write_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    size_t n = strlen(text);
    ssize_t w = write(fd, text, n);
    int saved = errno;
    close(fd);
    errno = saved;
    return w == (ssize_t)n;
}

/* Identity map: the same uid/gid inside, so file ownership in the workdir is
 * unchanged and the user namespace confers nothing past the PID namespace.
 * setgroups must be denied before an unprivileged gid_map write. */
static bool pidns_map_identity(uid_t uid, gid_t gid)
{
    char line[64];
    if (!pidns_write_file("/proc/self/setgroups", "deny"))
        return false;
    snprintf(line, sizeof line, "%u %u 1\n", (unsigned)gid, (unsigned)gid);
    if (!pidns_write_file("/proc/self/gid_map", line))
        return false;
    snprintf(line, sizeof line, "%u %u 1\n", (unsigned)uid, (unsigned)uid);
    return pidns_write_file("/proc/self/uid_map", line);
}

/* Linux, forked child only (it mutates the caller): unshare a user namespace
 * and write the same identity maps os_sandbox_pidns_enter() writes. */
bool os_sandbox_userns_identity_probe(void)
{
    uid_t uid = getuid(); /* before the unshare: afterwards both read as overflow ids */
    gid_t gid = getgid();
    return unshare(CLONE_NEWUSER) == 0 && pidns_map_identity(uid, gid);
}

/* Mirror a raw wait status as this process's own death: the supervisor's
 * waitpid must see the same signal / exit code the shell produced. */
[[noreturn]] static void pidns_mirror(int status)
{
    if (WIFSIGNALED(status)) {
        (void)signal(WTERMSIG(status), SIG_DFL);
        (void)raise(WTERMSIG(status));
        _exit(128 + WTERMSIG(status));
    }
    _exit(WEXITSTATUS(status));
}

/* The terminal worker forks with every signal blocked (so no inherited handler
 * can open a descriptor around the fd sweep) and only the shell restores the
 * caller mask, right before exec. The two wrapper processes keep the handling
 * they need instead: with the mask left blocked the supervisor could not
 * terminate the tracked process with SIGTERM, and the init could not take its
 * parent-death signal. Both start from an empty mask. */
static bool pidns_unblock_signals(void)
{
    sigset_t none;
    return sigemptyset(&none) == 0 && sigprocmask(SIG_SETMASK, &none, NULL) == 0;
}

/* The supervisor-visible process: it only waits for the namespace init and
 * mirrors how the shell ended (the init reports the shell's raw status over
 * `status_fd`; if the init itself was killed, that death is mirrored). */
[[noreturn]] static void pidns_outer(pid_t init, int status_fd)
{
    if (!pidns_unblock_signals())
        _exit(127);
    int status = 0, shell_status = 0;
    /* Terminal-generated signals reach this process as the session leader and
     * as a member of the foreground group; they are the shell's to handle (a
     * shell that ignores HUP must survive its terminal closing), so this
     * wrapper must not die of them. Set here, after the fork, so the shell
     * does not inherit the ignores. */
    static const int tty_signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU };
    for (size_t i = 0; i < sizeof tty_signals / sizeof tty_signals[0]; i++)
        (void)signal(tty_signals[i], SIG_IGN);
    while (waitpid(init, &status, 0) < 0)
        if (errno != EINTR)
            _exit(127);
    if (WIFSIGNALED(status))
        pidns_mirror(status);
    if (read(status_fd, &shell_status, sizeof shell_status) != (ssize_t)sizeof shell_status)
        _exit(127);
    pidns_mirror(shell_status);
}

/* Pid 1 of the namespace: signals sent from inside the namespace never
 * reach an init (so the shell could not `kill -9 $$` if it were pid 1), so
 * the init is a bare reaper and the shell is its child. It reaps orphans
 * until the shell ends, reports the shell's raw status, and exits, which
 * takes every remaining process in the namespace with it. */
[[noreturn]] static void pidns_init(pid_t shell, int status_fd)
{
    int status = 0;
    pid_t got;
    while ((got = waitpid(-1, &status, 0)) != shell)
        if (got < 0 && errno != EINTR)
            _exit(127);
    if (write(status_fd, &status, sizeof status) != (ssize_t)sizeof status)
        _exit(127);
    _exit(0);
}

/* Arm the init's parent-death signal and close the race around it. getppid()
 * cannot be the re-check here: a process whose parent lives outside its PID
 * namespace always reads ppid 0. Instead the outer process holds the write end
 * of a lifeline pipe for its whole life, so a hang-up on the read end after
 * the prctl means the outer process already died and the signal will never
 * fire. Returns false if the init must exit. */
static bool pidns_arm_parent_death(int lifeline_rd)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
        return false;
    struct pollfd p = { .fd = lifeline_rd, .events = 0 };
    if (poll(&p, 1, 0) < 0 || (p.revents & POLLHUP))
        return false;
    return true;
}

/* The tiny standalone adapter runner also links this module, without os_proc.
 * Clean wrappers require close_range; no procfs or descriptor-census fallback.
 * Retain the setup report until failure-prone cleanup and its barrier finish. */
#if defined(ZCL_TESTING)
static unsigned pidns_fail_stage;
void os_sandbox_test_kit_wrapper_failure(unsigned stage) { pidns_fail_stage = stage; }
#endif
static bool pidns_clean(int status_fd, int gate_fd, int report_fd, unsigned stage)
{
#if defined(ZCL_TESTING)
    if (pidns_fail_stage == stage) { errno = ENOSYS; return false; }
#else
    (void)stage;
#endif
#if defined(SYS_close_range)
    int keep[] = {status_fd, gate_fd, report_fd};
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = i + 1; j < 3; ++j)
            if (keep[j] < keep[i]) { int swap = keep[i]; keep[i] = keep[j]; keep[j] = swap; }
    unsigned next = 0;
    for (size_t i = 0; i < 3; ++i) {
        if (keep[i] < 0 || (unsigned)keep[i] < next) continue;
        if ((unsigned)keep[i] > next && syscall(SYS_close_range, next, (unsigned)keep[i] - 1u, 0u)) return false;
        next = (unsigned)keep[i] + 1u;
    }
    return syscall(SYS_close_range, next, UINT_MAX, 0u) == 0;
#else
    (void)status_fd; (void)gate_fd; (void)report_fd; errno = ENOSYS; return false;
#endif
}

static bool pidns_ack(int fd, bool send)
{
    char byte = 'k'; ssize_t n;
    do { n = send ? write(fd, &byte, 1) : read(fd, &byte, 1); } while (n < 0 && errno == EINTR);
    return n == 1 && byte == 'k';
}

[[noreturn]] static void pidns_setup_fail(int report, pid_t child)
{
    static const char message[] = "kit PID wrapper cleanup or handshake failed";
    if (report >= 0) {
        ssize_t n;
        do { n = write(report, message, sizeof(message) - 1); } while (n < 0 && errno == EINTR);
    }
    if (child > 0) (void)kill(child, SIGKILL);
    _exit(127);
}

[[noreturn]] static void pidns_outer_start(pid_t init, int report, bool clean,
    const int sp[2], const int lp[2])
{
    if (!clean && report >= 0) close(report);
    close(sp[1]); close(lp[0]);
    if (clean) {
        if (!pidns_clean(sp[0], lp[1], report, 1) || !pidns_ack(lp[1], true))
            pidns_setup_fail(report, init);
        if (report >= 0) close(report);
    }
    pidns_outer(init, sp[0]);
}

static void pidns_init_prepare(int report, bool clean, const int lp[2])
{
    close(lp[1]);
    if (clean && !pidns_ack(lp[0], false)) pidns_setup_fail(report, 0);
    if (!pidns_unblock_signals() || !pidns_arm_parent_death(lp[0])) {
        if (clean) pidns_setup_fail(report, 0);
        _exit(1);
    }
    close(lp[0]);
}

[[noreturn]] static void pidns_init_start(pid_t shell, int report, bool clean,
    const int sp[2], const int gate[2])
{
    if (!clean && report >= 0) close(report);
    if (clean) {
        if (!pidns_clean(sp[1], gate[1], report, 2) || !pidns_ack(gate[1], true))
            pidns_setup_fail(report, shell);
        close(gate[1]);
        if (report >= 0) close(report);
    }
    pidns_init(shell, sp[1]);
}

static int pidns_enter(int close_fd, bool clean)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    int sp[2], lp[2], gate[2] = {-1, -1};
    if (pipe2(sp, O_CLOEXEC) != 0)
        return -1;
    if (pipe2(lp, O_CLOEXEC) != 0) {
        close(sp[0]);
        close(sp[1]);
        return -1;
    }
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0 || !pidns_map_identity(uid, gid))
        goto fail;
    pid_t init = fork();
    if (init < 0)
        goto fail;
    if (init > 0) pidns_outer_start(init, close_fd, clean, sp, lp);
    pidns_init_prepare(close_fd, clean, lp);
    if (clean && pipe2(gate, O_CLOEXEC)) goto fail;
    pid_t shell = fork();
    if (shell < 0)
        goto fail;
    if (shell > 0) pidns_init_start(shell, close_fd, clean, sp, gate);
    close(sp[0]);
    close(sp[1]);
    if (clean) {
        close(gate[1]);
        bool ready = pidns_ack(gate[0], false);
        close(gate[0]);
        if (!ready) { errno = EIO; return -1; }
    }
    return 0;
fail:;
    int saved = errno;
    close(sp[0]);
    close(sp[1]);
    close(lp[0]);
    close(lp[1]);
    close(gate[0]); close(gate[1]);
    errno = saved;
    return -1;
}

int os_sandbox_pidns_enter(int close_fd)
{
    return pidns_enter(close_fd, false);
}

int os_sandbox_pidns_enter_clean(int close_fd)
{
    return pidns_enter(close_fd, true);
}
