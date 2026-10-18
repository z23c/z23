/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Linux package-confinement selection over the Landlock backend. */

#define _GNU_SOURCE
#include "platform/os_sandbox.h"
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#if defined(__has_include)
#  if __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>) \
       && __has_include(<linux/audit.h>)
#    define PKG_HAVE_SECCOMP 1
#    include <linux/seccomp.h>
#    include <linux/filter.h>
#    include <linux/audit.h>
#  endif
#endif

enum os_sandbox_package_confinement
os_sandbox_package_confinement(void)
{
    return os_sandbox_landlock_abi() >= 1
        ? OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP
        : OS_SANDBOX_PACKAGE_CONFINEMENT_NONE;
}

const char *os_sandbox_package_confinement_name(
    enum os_sandbox_package_confinement confinement)
{
    switch (confinement) {
    case OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP:
        return "landlock+seccomp";
    case OS_SANDBOX_PACKAGE_CONFINEMENT_SEATBELT:
        return "seatbelt";
    case OS_SANDBOX_PACKAGE_CONFINEMENT_NONE:
    default:
        return "none";
    }
}

struct zcl_result os_sandbox_package_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
    if (os_sandbox_package_confinement() ==
        OS_SANDBOX_PACKAGE_CONFINEMENT_NONE)
        return ZCL_ERR(OS_SANDBOX_ERR_CONFINEMENT_UNAVAILABLE,
                       "package confinement is unavailable");
    return os_sandbox_landlock_restrict(rules, n_rules);
}

struct zcl_result os_sandbox_package_leaf_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
    ZCL_CHECK(os_sandbox_package_restrict(rules, n_rules));
    static const int denied[] = {
        SYS_clone, SYS_setsid, SYS_setpgid, SYS_kill, SYS_tkill, SYS_tgkill,
        SYS_rt_sigqueueinfo, SYS_rt_tgsigqueueinfo,
#ifdef SYS_pidfd_send_signal
        SYS_pidfd_send_signal,
#endif
#ifdef SYS_pidfd_getfd
        SYS_pidfd_getfd,
#endif
#ifdef SYS_clone3
        SYS_clone3,
#endif
#ifdef SYS_fork
        SYS_fork,
#endif
#ifdef SYS_vfork
        SYS_vfork,
#endif
    };
    return os_sandbox_seccomp_deny(denied, sizeof(denied) / sizeof(denied[0]), false);
}

/* kill(2) guard. Job control needs kill of the shell's own children and jobs,
 * so kill stays allowed, but this STACKED filter answers EPERM for the
 * targets that would reach beyond the cage: pid 0, pid -1, the supervisor
 * (the parent at entry) and its process group, each as +N and -N. The low 32
 * bits of args[0] are compared (kill takes a pid_t). Layout for n compares:
 * 4 arch/nr, 1 kill test, 1 load, n compares, ALLOW, EPERM. An unrelated
 * same-uid positive pid is NOT distinguishable by seccomp: that residual is
 * documented in os_sandbox.h. */
#define PKG_GUARD_N 6u
struct zcl_result os_sandbox_seccomp_guard_signals(void)
{
#ifndef PKG_HAVE_SECCOMP
    return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE,
                   "seccomp headers absent at build time");
#else
    pid_t sup = getppid();
    pid_t sup_pg = getpgid(sup);
    const uint32_t vals[PKG_GUARD_N] = {
        0u, 0xffffffffu, (uint32_t)sup, (uint32_t)-sup,
        (uint32_t)(sup_pg > 0 ? sup_pg : 0),
        (uint32_t)(sup_pg > 0 ? -sup_pg : 0) };
    struct sock_filter f[8 + PKG_GUARD_N];
    size_t k = 0;
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, arch));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64, 1, 0);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0x80000000U);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, nr));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
        (uint32_t)__NR_kill, 0, PKG_GUARD_N + 1u);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, args[0]));
    for (size_t i = 0; i < PKG_GUARD_N; i++)
        f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
            vals[i], (uint8_t)(PKG_GUARD_N - i), 0);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    struct sock_fprog prog = { .len = (unsigned short)k, .filter = f };
    long r = syscall(__NR_seccomp, (long)SECCOMP_SET_MODE_FILTER,
                     (long)SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (r != 0 && errno == ENOSYS)
        r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
    if (r != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "kill guard filter install failed errno=%d (%s)",
                       errno, strerror(errno));
    return ZCL_OK;
#endif
}

/* Signal containment for a program that keeps one process. A positive-pid
 * kill or tgkill is allowed only at the caller's own thread group (what raise,
 * abort and pthread_kill need); tkill, queued signals, pidfd_open,
 * pidfd_send_signal, ptrace and process_vm_{read,write}v answer EPERM. Signals
 * also leave through descriptor ownership (a SIGIO or F_SETSIG signal sent to
 * the owner when a descriptor becomes ready), so the commands that set an
 * owner or a signal number fail EPERM too: fcntl F_SETOWN, F_SETOWN_EX and
 * F_SETSIG, ioctl FIOSETOWN, SIOCSPGRP and TIOCSPGRP. Where a PID namespace
 * cannot be entered, this is what keeps an unrelated same-uid process from
 * being signalled. The caller's pid is captured at install time, so install
 * it after the final fork. x86_64 has no fcntl64.
 *
 * Layout: 0-2 arch, 3 load nr, 4-5 kill and tgkill, 6-13 deny, 14-15 fcntl and
 * ioctl dispatch, 16 ALLOW, 17-21 fcntl cmds, 22-26 ioctl cmds, 27-29 self
 * pid test, 30 EPERM. */
enum {
    PKG_SELF_DENY_N = 8,
    PKG_AT_FCNTL = 17,
    PKG_AT_IOCTL = 22,
    PKG_AT_SELF = 27,
    PKG_AT_EPERM = 30,
    PKG_SELF_LEN = 31
};

#ifdef PKG_HAVE_SECCOMP
static struct sock_filter pkg_ld(unsigned offset)
{
    return (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset);
}

static struct sock_filter pkg_ret(uint32_t what)
{
    return (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, what);
}

/* Jump to index `to` when the loaded word equals `v`; `at` is this index. */
static struct sock_filter pkg_jeq(uint32_t v, size_t at, unsigned to)
{
    return (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, v,
                                        (uint8_t)(to - at - 1u), 0);
}

static size_t pkg_cmd_rows(struct sock_filter *f, size_t k,
                           const uint32_t *cmds, size_t n)
{
    f[k++] = pkg_ld(offsetof(struct seccomp_data, args[1]));
    for (size_t i = 0; i < n; i++, k++)
        f[k] = pkg_jeq(cmds[i], k, PKG_AT_EPERM);
    f[k++] = pkg_ret(SECCOMP_RET_ALLOW);
    return k;
}

static size_t pkg_self_program(struct sock_filter *f, uint32_t self,
                               unsigned flags)
{
    const uint32_t deny[PKG_SELF_DENY_N] = {
        (uint32_t)__NR_tkill, (uint32_t)__NR_rt_sigqueueinfo,
        (uint32_t)__NR_rt_tgsigqueueinfo, (uint32_t)__NR_pidfd_send_signal,
        (uint32_t)__NR_pidfd_open, (uint32_t)__NR_ptrace,
        (uint32_t)__NR_process_vm_readv, (uint32_t)__NR_process_vm_writev };
    const uint32_t fcntl_cmds[] = { F_SETOWN, F_SETSIG, F_SETOWN_EX };
    const uint32_t ioctl_cmds[] = { 0x8901u /* FIOSETOWN */,
                                    0x8902u /* SIOCSPGRP */,
                                    0x5410u /* TIOCSPGRP */ };
    const bool fd_rules = !(flags & OS_SANDBOX_SELF_SIGNALS_NO_FD_OWNER);
    size_t k = 0;
    f[k++] = pkg_ld(offsetof(struct seccomp_data, arch));
    f[k] = pkg_jeq(AUDIT_ARCH_X86_64, k, 3u), k++;
    f[k++] = pkg_ret(0x80000000U);
    f[k++] = pkg_ld(offsetof(struct seccomp_data, nr));
    f[k] = pkg_jeq((uint32_t)__NR_kill, k, PKG_AT_SELF), k++;
    f[k] = pkg_jeq((uint32_t)__NR_tgkill, k, PKG_AT_SELF), k++;
    for (size_t i = 0; i < PKG_SELF_DENY_N; i++, k++)
        f[k] = pkg_jeq(deny[i], k, PKG_AT_EPERM);
    f[k] = pkg_jeq(fd_rules ? (uint32_t)__NR_fcntl : 0xffffffffu, k, PKG_AT_FCNTL), k++;
    f[k] = pkg_jeq(fd_rules ? (uint32_t)__NR_ioctl : 0xffffffffu, k, PKG_AT_IOCTL), k++;
    f[k++] = pkg_ret(SECCOMP_RET_ALLOW);
    k = pkg_cmd_rows(f, k, fcntl_cmds, 3);
    k = pkg_cmd_rows(f, k, ioctl_cmds, 3);
    f[k++] = pkg_ld(offsetof(struct seccomp_data, args[0]));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, self, 0, 1);
    f[k++] = pkg_ret(SECCOMP_RET_ALLOW);
    f[k++] = pkg_ret(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    return k;
}
#endif

struct zcl_result os_sandbox_seccomp_self_signals_only_ext(unsigned flags)
{
#ifndef PKG_HAVE_SECCOMP
    (void)flags;
    return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE,
                   "seccomp headers absent at build time");
#else
    struct sock_filter f[PKG_SELF_LEN];
    size_t k = pkg_self_program(f, (uint32_t)getpid(), flags);
    struct sock_fprog prog = { .len = (unsigned short)k, .filter = f };
    long r = syscall(__NR_seccomp, (long)SECCOMP_SET_MODE_FILTER,
                     (long)SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (r != 0 && errno == ENOSYS)
        r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
    if (r != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "self-signal filter install failed errno=%d (%s)",
                       errno, strerror(errno));
    return ZCL_OK;
#endif
}

struct zcl_result os_sandbox_seccomp_self_signals_only(void)
{
    return os_sandbox_seccomp_self_signals_only_ext(0);
}
