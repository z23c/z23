/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Non-Linux confinement backend. Linux-only guarantees fail closed. */

#include "platform/os_sandbox.h"

#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libproc.h> /* proc_pidinfo: per-process BSD identity and task size */
#include <sys/sysctl.h>
#endif

static char g_requested_profile[64];

static struct zcl_result unavailable(const char *mechanism)
{
    return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                   "%s is unavailable on this operating system", mechanism);
}

void os_sandbox_note_requested(const char *profile_name)
{
    const char *name = profile_name ? profile_name : "";
    size_t len = strlen(name);
    if (len >= sizeof(g_requested_profile))
        len = sizeof(g_requested_profile) - 1u;
    memcpy(g_requested_profile, name, len);
    g_requested_profile[len] = '\0';
}

const char *os_sandbox_requested_profile(void) { return g_requested_profile; }
bool os_sandbox_unconfined(void) { return true; }
bool os_sandbox_active(void) { return false; }
const char *os_sandbox_active_profile_name(void) { return NULL; }
bool os_sandbox_seccomp_supported(void) { return false; }
bool os_sandbox_seccomp_tsync_active(void) { return false; }
const char *os_sandbox_seccomp_install_method(void) { return ""; }
int os_sandbox_landlock_abi(void) { return -1; }
int os_sandbox_landlock_abi_cached(void) { return -1; }
int os_sandbox_landlock_restricted_count(void) { return 0; }
bool os_sandbox_retrofit_join_permitted(void) { return false; }
size_t os_sandbox_fs_grant_count(void) { return 0; }

const char *os_sandbox_fs_grant_at(size_t i, bool *readable, bool *writable)
{
    (void)i;
    if (readable) *readable = false;
    if (writable) *writable = false;
    return NULL;
}

bool os_sandbox_path_is_granted(const char *path, bool need_write)
{
    (void)path;
    (void)need_write;
    return true;
}

size_t os_sandbox_explain_denied_path(const char *path, bool need_write,
                                      char *out, size_t out_size)
{
    (void)path;
    (void)need_write;
    if (out && out_size) out[0] = '\0';
    return 0;
}

bool os_sandbox_no_new_privs(void) { return false; }

struct zcl_result os_sandbox_landlock_restrict(
    const struct os_sandbox_path_rule *rules, size_t count)
{
    (void)rules;
    (void)count;
    return unavailable("Landlock");
}

struct zcl_result os_sandbox_landlock_apply_to_self(void)
{
    return unavailable("Landlock");
}

const int *os_sandbox_session_denied_syscalls(size_t *count)
{
    if (count) *count = 0;
    return NULL;
}

const int *os_sandbox_node_steady_denied_syscalls(size_t *count)
{
    if (count) *count = 0;
    return NULL;
}

const int *os_sandbox_node_confine_allowed_syscalls(size_t *count)
{
    if (count) *count = 0;
    return NULL;
}

const int *os_sandbox_node_confine_serving_allowed_syscalls(size_t *count)
{
    if (count) *count = 0;
    return NULL;
}

struct zcl_result os_sandbox_seccomp_deny(const int *calls, size_t count,
                                          bool deny_exec_mmap)
{
    (void)calls;
    (void)count;
    (void)deny_exec_mmap;
    return unavailable("seccomp");
}

struct zcl_result os_sandbox_seccomp_allow(const int *calls, size_t count)
{
    (void)calls;
    (void)count;
    return unavailable("seccomp");
}

struct os_sandbox_rlimits os_sandbox_session_rlimits(void)
{
    return (struct os_sandbox_rlimits){
        .as_bytes = 256u * 1024u * 1024u,
        .cpu_seconds = OS_SANDBOX_RLIMIT_KEEP,
        .nproc = 1,
        .fsize_bytes = 64u * 1024u * 1024u,
        .nofile = 16,
        .core_bytes = 0,
    };
}

struct zcl_result os_sandbox_set_rlimits(const struct os_sandbox_rlimits *limits)
{
    (void)limits;
    return unavailable("sandbox resource-limit profile");
}

#if defined(__APPLE__)
/* Mirror of the Linux census: one entry per live thread of every process
 * owned by this uid. Linux walks /proc/<pid>/task; Darwin answers the same
 * question from the kernel through sysctl(KERN_PROC_ALL) plus
 * proc_pidinfo(PROC_PIDTBSDINFO, PROC_PIDTASKINFO). Enumeration failure
 * degrades to 0 exactly like the /proc-based path does. */
uint64_t os_sandbox_uid_task_count(void)
{
    const uid_t me = getuid();
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0 || len == 0)
        return 0;
    /* The table can grow between the size probe and the read; over-allocate
     * and let the second call report the smaller, true length. */
    len += 16u * sizeof(struct kinfo_proc);
    struct kinfo_proc *procs = malloc(len); // raw-alloc-ok:sandbox-census-scratch
    if (!procs)
        return 0;
    if (sysctl(mib, 3, procs, &len, NULL, 0) != 0) {
        free(procs);
        return 0;
    }
    size_t count = len / sizeof(procs[0]);
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 0)
            continue;
        struct proc_bsdinfo bsd;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd,
                         sizeof(bsd)) != (int)sizeof(bsd))
            continue;
        if (bsd.pbi_ruid != me)
            continue;
        struct proc_taskinfo task;
        if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task,
                         sizeof(task)) != (int)sizeof(task))
            continue;
        total += task.pti_threadnum;
    }
    free(procs);
    return total;
}
#else
uint64_t os_sandbox_uid_task_count(void) { return 0; }
#endif

uint64_t os_sandbox_nproc_hard_limit(void)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NPROC, &limit) != 0 || limit.rlim_max == RLIM_INFINITY)
        return OS_SANDBOX_RLIMIT_KEEP;
    return (uint64_t)limit.rlim_max;
}

struct os_sandbox_process_budget os_sandbox_process_budget_at(
    uint64_t ceiling, uint64_t required, uint64_t tasks, uint64_t hard)
{
    struct os_sandbox_process_budget budget = {
        .ceiling = ceiling, .requested = ceiling, .hard = hard,
        .uid_tasks = tasks, .required = required,
    };
    if (hard != OS_SANDBOX_RLIMIT_KEEP && hard < budget.ceiling)
        budget.ceiling = hard;
    budget.headroom = budget.ceiling > tasks ? budget.ceiling - tasks : 0;
    budget.admitted = budget.headroom >= required;
    return budget;
}

struct os_sandbox_process_budget os_sandbox_process_budget_live(
    uint64_t ceiling, uint64_t required)
{
    return os_sandbox_process_budget_at(ceiling, required,
                                        os_sandbox_uid_task_count(),
                                        os_sandbox_nproc_hard_limit());
}

uint64_t os_sandbox_process_group_census(pid_t group)
{
#if defined(__APPLE__)
    /* Linux answers this from /proc/<pid>/stat's pgrp field; Darwin keeps
     * the process group inside the same kernel BSD record read for the uid
     * census above (pbi_pgid). Process-granular like Linux. */
    if (group <= 0)
        return 0;
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0 || len == 0)
        return 0;
    len += 16u * sizeof(struct kinfo_proc);
    struct kinfo_proc *procs = malloc(len); // raw-alloc-ok:sandbox-census-scratch
    if (!procs)
        return 0;
    if (sysctl(mib, 3, procs, &len, NULL, 0) != 0) {
        free(procs);
        return 0;
    }
    size_t count = len / sizeof(procs[0]);
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 0)
            continue;
        struct proc_bsdinfo bsd;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd,
                         sizeof(bsd)) != (int)sizeof(bsd))
            continue;
        if ((pid_t)bsd.pbi_pgid == group)
            total++;
    }
    free(procs);
    return total;
#else
    (void)group;
    return 0;
#endif
}

int os_sandbox_session_ns_flags(void) { return 0; }

struct zcl_result os_sandbox_write_userns_maps(pid_t pid, unsigned uid,
                                               unsigned gid)
{
    (void)pid;
    (void)uid;
    (void)gid;
    return unavailable("Linux user namespaces");
}

struct os_sandbox_caps os_sandbox_probe_caps(void)
{
    return (struct os_sandbox_caps){0};
}

bool os_sandbox_userns_available(void) { return false; }

static struct os_sandbox_profile profile(const char *name,
    const struct os_sandbox_path_rule *rules, size_t count)
{
    return (struct os_sandbox_profile){
        .name = name, .fs_rules = rules, .n_fs_rules = count,
        .landlock = true, .seccomp = true,
    };
}

struct os_sandbox_profile os_sandbox_session_child_profile(
    const struct os_sandbox_path_rule *rules, size_t count)
{
    struct os_sandbox_profile value = profile("session_child", rules, count);
    value.no_new_privs = true;
    value.apply_rlimits = true;
    value.rlimits = os_sandbox_session_rlimits();
    return value;
}

struct os_sandbox_profile os_sandbox_node_steady_state_profile(
    const struct os_sandbox_path_rule *rules, size_t count)
{
    return profile("node_steady_state", rules, count);
}

struct os_sandbox_profile os_sandbox_node_confine_profile(
    const struct os_sandbox_path_rule *rules, size_t count)
{
    struct os_sandbox_profile value = profile("node_confine", rules, count);
    value.seccomp_allowlist = true;
    return value;
}

struct os_sandbox_profile os_sandbox_node_confine_serving_profile(
    const struct os_sandbox_path_rule *rules, size_t count)
{
    struct os_sandbox_profile value =
        profile("node_confine_serving", rules, count);
    value.seccomp_allowlist = true;
    return value;
}

struct zcl_result os_sandbox_enter(const struct os_sandbox_profile *value)
{
    if (!value)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "profile==NULL");
    return unavailable("Linux process confinement");
}
