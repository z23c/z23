/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox — the confinement profile of one supervised plugin process. See
 * platform/os_sandbox.h for the ordering invariant and docs/dev/PLUGINS.md for the
 * descriptors a plugin receives. The file compiles on every host; the
 * deny-list is populated only on Linux, where os_sandbox_enter() can use it. */

#include "platform/os_sandbox.h"

#include <stddef.h>
#include <stdint.h>

#if defined(__linux__)
#include <sys/syscall.h>

#ifdef __NR_clone3
#define OSP_NR_CLONE3 __NR_clone3
#else
#define OSP_NR_CLONE3 435 /* kernel ABI number, x86_64 and generic */
#endif
#ifdef __NR_io_uring_setup
#define OSP_NR_URING_SETUP __NR_io_uring_setup
#define OSP_NR_URING_ENTER __NR_io_uring_enter
#define OSP_NR_URING_REGISTER __NR_io_uring_register
#else
#define OSP_NR_URING_SETUP 425
#define OSP_NR_URING_ENTER 426
#define OSP_NR_URING_REGISTER 427
#endif

#ifdef __NR_pidfd_open
#define OSP_NR_PIDFD_OPEN __NR_pidfd_open
#else
#define OSP_NR_PIDFD_OPEN 434
#endif
#ifdef __NR_pidfd_send_signal
#define OSP_NR_PIDFD_SEND __NR_pidfd_send_signal
#else
#define OSP_NR_PIDFD_SEND 424
#endif
#ifdef __NR_pidfd_getfd
#define OSP_NR_PIDFD_GETFD __NR_pidfd_getfd
#else
#define OSP_NR_PIDFD_GETFD 438
#endif
#ifdef __NR_fchmodat2
#define OSP_NR_FCHMODAT2 __NR_fchmodat2
#else
#define OSP_NR_FCHMODAT2 452
#endif

/* io_uring can issue socket and connect operations with no syscall seccomp can
 * see, so it is denied outright. The control descriptor stays usable with
 * read, write, sendmsg and recvmsg. */
static const int g_plugin_denied[] = {
    __NR_socket,
#ifdef __NR_socketcall
    __NR_socketcall,
#endif
    __NR_socketpair, __NR_connect, __NR_bind, __NR_listen,
    __NR_accept, __NR_accept4,
    __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
    __NR_mount, __NR_umount2, __NR_pivot_root, __NR_setns, __NR_unshare,
    __NR_bpf, __NR_kexec_load, __NR_kexec_file_load,
    __NR_init_module, __NR_finit_module, __NR_delete_module,
    __NR_perf_event_open,
    __NR_add_key, __NR_request_key, __NR_keyctl,
    __NR_open_by_handle_at,
#ifdef __NR_fork
    __NR_fork,
#endif
#ifdef __NR_vfork
    __NR_vfork,
#endif
    __NR_setsid, __NR_setpgid,
    /* Signalling other processes, the supervisor included. The package leaf
     * profile (os_sandbox_package_linux.c) denies the same set; it keeps that
     * list inside a function, so it cannot be shared. */
    __NR_kill, __NR_tkill, __NR_tgkill, __NR_rt_sigqueueinfo, __NR_rt_tgsigqueueinfo,
    OSP_NR_PIDFD_OPEN, OSP_NR_PIDFD_SEND, OSP_NR_PIDFD_GETFD,
    /* Metadata changes Landlock does not cover: modes, extended attributes and
     * timestamps of files the plugin can reach by descriptor or path. */
#ifdef __NR_chmod
    __NR_chmod,
#endif
    __NR_fchmod, __NR_fchmodat, OSP_NR_FCHMODAT2,
    __NR_setxattr, __NR_lsetxattr, __NR_fsetxattr,
    __NR_removexattr, __NR_lremovexattr, __NR_fremovexattr,
    __NR_utimensat,
#ifdef __NR_utimes
    __NR_utimes,
#endif
#ifdef __NR_futimesat
    __NR_futimesat,
#endif
    OSP_NR_URING_SETUP, OSP_NR_URING_ENTER, OSP_NR_URING_REGISTER,
};
static const int g_plugin_enosys[] = { OSP_NR_CLONE3 };
#define OSP_DENIED_COUNT (sizeof(g_plugin_denied) / sizeof(g_plugin_denied[0]))
#define OSP_ENOSYS_COUNT (sizeof(g_plugin_enosys) / sizeof(g_plugin_enosys[0]))
#else
static const int g_plugin_denied[] = { 0 };
static const int g_plugin_enosys[] = { 0 };
#define OSP_DENIED_COUNT 0u
#define OSP_ENOSYS_COUNT 0u
#endif

/* The terminal-worker resource caps: 256 MiB address space, 300 CPU seconds,
 * 1 MiB files, 64 descriptors, no core dumps. NPROC stays per-uid. */
static struct os_sandbox_rlimits osp_rlimits(void)
{
    return (struct os_sandbox_rlimits){
        .as_bytes = (uint64_t)256 * 1024 * 1024,
        .cpu_seconds = 300,
        .nproc = OS_SANDBOX_RLIMIT_KEEP,
        .fsize_bytes = (uint64_t)1024 * 1024,
        .nofile = 64,
        .core_bytes = 0,
    };
}

struct os_sandbox_profile os_sandbox_plugin_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules)
{
    return (struct os_sandbox_profile){
        .name = "plugin",
        .no_new_privs = true,
        .apply_rlimits = true,
        .rlimits = osp_rlimits(),
        .landlock = true,
        .fs_rules = fs_rules,
        .n_fs_rules = n_fs_rules,
        .seccomp = true,
        .denied_syscalls = g_plugin_denied,
        .n_denied = OSP_DENIED_COUNT,
        .seccomp_deny_exec_mmap = true,
        .enosys_syscalls = g_plugin_enosys,
        .n_enosys = OSP_ENOSYS_COUNT,
        .seccomp_clone_threads_only = true,
    };
}
