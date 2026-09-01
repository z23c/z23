/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox — the Linux terminal-worker cage builders, split out of
 * os_sandbox_linux.c so the general confinement backend stays within its
 * size band. See platform/os_sandbox.h for the design and the ordering
 * invariant; the confined shell itself is cognition/modules/session/src/mesh_terminal_worker.c.
 * Compiled only on Linux (the Makefile filter-outs pair this file with
 * os_sandbox_linux.c); the portable stub carries the same entry points. */

#include "platform/os_sandbox.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

/* The terminal worker's deny-set: the session set with the code execution /
 * process creation family (execve/execveat/clone/clone3/fork/vfork) REMOVED —
 * the confined shell must fork/exec its own children, and Landlock bounds
 * what execve can reach. Everything else stays: the socket family (the
 * worker talks to the node ONLY through its pre-opened PTY fds), ptrace /
 * process_vm_*, mount/namespace escape, kernel surface, keyrings, and
 * open_by_handle_at. */
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
    };
}
