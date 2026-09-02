/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Non-Linux confinement backend. Linux-only guarantees fail closed. */

#include "platform/os_sandbox.h"

#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* struct rlimit / getrlimit / RLIMIT_NPROC are POSIX; Windows has no per-uid
 * process ceiling to read at all (see os_sandbox_nproc_hard_limit below), and
 * <unistd.h> is not part of the Windows C library either, so both headers are
 * pulled in only on the arm that actually has them. */
#if !defined(_WIN32)
#include <sys/resource.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <dlfcn.h>
#include <libproc.h> /* proc_pidinfo: per-process BSD identity and task size */
#include <sys/sysctl.h>
#endif

static char g_requested_profile[64];

static struct zcl_result unavailable(const char *mechanism)
{
#if defined(_WIN32)
    return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                   "%s is unavailable: Windows package/agent execution "
                   "remains disabled until restricted-token, Job Object, "
                   "low-integrity, resource-limit, and network-denial "
                   "sandbox acceptance passes",
                   mechanism);
#else
    return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                   "%s is unavailable on this operating system", mechanism);
#endif
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

enum os_sandbox_package_confinement
os_sandbox_package_confinement(void)
{
#if defined(__APPLE__)
    return OS_SANDBOX_PACKAGE_CONFINEMENT_SEATBELT;
#else
    return OS_SANDBOX_PACKAGE_CONFINEMENT_NONE;
#endif
}

#if defined(__APPLE__)
struct seatbelt_profile_builder {
    char *text;
    size_t length;
    size_t capacity;
};

static bool seatbelt_append(struct seatbelt_profile_builder *builder,
                            const char *text)
{
    size_t add = strlen(text);
    if (add > builder->capacity - builder->length - 1u)
        return false;
    memcpy(builder->text + builder->length, text, add);
    builder->length += add;
    builder->text[builder->length] = '\0';
    return true;
}

static bool seatbelt_append_path(struct seatbelt_profile_builder *builder,
                                 const char *path)
{
    if (!seatbelt_append(builder, " (subpath \"")) return false;
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
        if (*p < 0x20u || *p == 0x7fu) return false;
        if ((*p == '\\' || *p == '"') && !seatbelt_append(builder, "\\"))
            return false;
        char byte[2] = { (char)*p, '\0' };
        if (!seatbelt_append(builder, byte)) return false;
    }
    return seatbelt_append(builder, "\")");
}

static bool seatbelt_add_rule(struct seatbelt_profile_builder *builder,
                              const struct os_sandbox_path_rule *rule)
{
    if (!rule->path || rule->path[0] != '/') return false;
    if (rule->allow_read) {
        if (!seatbelt_append(builder, "(allow file-read*" ) ||
            !seatbelt_append_path(builder, rule->path) ||
            !seatbelt_append(builder, ")"))
            return false;
    }
    if (rule->allow_write) {
        if (!seatbelt_append(builder, "(allow file-write*" ) ||
            !seatbelt_append_path(builder, rule->path) ||
            !seatbelt_append(builder, ")"))
            return false;
    }
    if (rule->allow_execute) {
        if (!seatbelt_append(builder,
                "(allow process-exec file-map-executable") ||
            !seatbelt_append_path(builder, rule->path) ||
            !seatbelt_append(builder, ")"))
            return false;
    }
    return true;
}
#endif

struct zcl_result os_sandbox_package_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
#if defined(__APPLE__)
    static const char prefix[] =
        "(version 1)(deny default)"
        "(deny file-map-executable process-info* nvram* "
        "dynamic-code-generation mach-priv-host-port)"
        "(import \"system.sb\")"
        "(allow process-info* (target self))"
        "(allow file-read-metadata)"
        "(allow process-fork)(allow signal (target self))"
        "(allow sysctl-read)"
        "(allow file-read* (literal \"/\"))";
    /* system.sb admits three narrow networking conveniences. A generic deny
     * loses to those more-specific filters, so revoke each at equal-or-higher
     * specificity as well as denying the remaining network operation set. */
    static const char suffix[] =
        "(deny network*)"
        "(deny network-outbound"
        " (literal \"/private/var/run/syslog\")"
        " (control-name \"com.apple.netsrc\")"
        " (control-name \"com.apple.network.statistics\"))"
        "(deny system-socket"
        " (require-all (socket-domain AF_SYSTEM) (socket-protocol 2))"
        " (socket-domain AF_ROUTE))";
    if (!rules || n_rules == 0 || n_rules > 128u)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                       "Seatbelt wants 1..128 path rules");
    size_t capacity = sizeof(prefix) + sizeof(suffix) + 1u;
    for (size_t i = 0; i < n_rules; ++i) {
        if (!rules[i].path || rules[i].path[0] != '/')
            return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                           "Seatbelt rule %zu is not absolute", i);
        size_t path_length = strlen(rules[i].path);
        if (path_length > 4095u || path_length > (SIZE_MAX - capacity) / 6u)
            return ZCL_ERR(OS_SANDBOX_ERR_TOO_MANY_RULES,
                           "Seatbelt profile size overflow");
        capacity += path_length * 6u + 192u;
    }
    char *profile = zcl_malloc(capacity, "seatbelt-package-profile");
    if (!profile)
        return ZCL_ERR(OS_SANDBOX_ERR_SEATBELT,
                       "Seatbelt profile allocation failed");
    struct seatbelt_profile_builder builder = {
        .text = profile, .length = 0, .capacity = capacity,
    };
    profile[0] = '\0';
    bool built = seatbelt_append(&builder, prefix);
    for (size_t i = 0; built && i < n_rules; ++i)
        built = seatbelt_add_rule(&builder, &rules[i]);
    built = built && seatbelt_append(&builder, suffix);
    if (!built) {
        free(profile);
        return ZCL_ERR(OS_SANDBOX_ERR_SEATBELT,
                       "Seatbelt profile construction failed");
    }
    /* Vendored Tor also exports a function named sandbox_init. A direct link
     * would therefore bind by executable symbol order, not by authority, and
     * can call Tor's logger-dependent initializer in this freshly forked
     * child. Resolve both Apple functions from the exact system dylib handle
     * so this path can only enter Seatbelt. */
    typedef int (*seatbelt_init_fn)(const char *, uint64_t, char **);
    typedef void (*seatbelt_free_error_fn)(char *);
    void *library = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        free(profile);
        return ZCL_ERR(OS_SANDBOX_ERR_SEATBELT,
                       "cannot load system Seatbelt library: %s", dlerror());
    }
    void *init_symbol = dlsym(library, "sandbox_init");
    void *free_symbol = dlsym(library, "sandbox_free_error");
    seatbelt_init_fn seatbelt_init = NULL;
    seatbelt_free_error_fn seatbelt_free_error = NULL;
    if (!init_symbol || !free_symbol || sizeof(init_symbol) != sizeof(seatbelt_init) ||
        sizeof(free_symbol) != sizeof(seatbelt_free_error)) {
        free(profile);
        (void)dlclose(library);
        return ZCL_ERR(OS_SANDBOX_ERR_SEATBELT,
                       "system Seatbelt entry points are unavailable");
    }
    memcpy(&seatbelt_init, &init_symbol, sizeof(seatbelt_init));
    memcpy(&seatbelt_free_error, &free_symbol, sizeof(seatbelt_free_error));
    char *error = NULL;
    int applied = seatbelt_init(profile, 0, &error);
    free(profile);
    if (applied != 0) {
        char detail[192];
        (void)snprintf(detail, sizeof(detail), "%s",
                       error ? error : "unknown Seatbelt error");
        seatbelt_free_error(error);
        (void)dlclose(library);
        return ZCL_ERR(OS_SANDBOX_ERR_SEATBELT,
                       "sandbox_init failed: %s", detail);
    }
    seatbelt_free_error(error);
    (void)dlclose(library);
    return ZCL_OK;
#else
    (void)rules;
    (void)n_rules;
    return ZCL_ERR(OS_SANDBOX_ERR_CONFINEMENT_UNAVAILABLE,
                   "package confinement is unavailable");
#endif
}

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
#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

size_t os_sandbox_explain_denied_path(const char *path, bool need_write,
                                      char *out, size_t out_size)
{
    (void)path;
    (void)need_write;
#if defined(_WIN32)
    static const char reason[] =
        "Windows package/agent sandbox is not qualified";
    size_t length = sizeof(reason) - 1u;
    if (out && out_size) {
        size_t copy = length < out_size - 1u ? length : out_size - 1u;
        memcpy(out, reason, copy);
        out[copy] = '\0';
    }
    return length;
#else
    if (out && out_size) out[0] = '\0';
    return 0;
#endif
}

bool os_sandbox_no_new_privs(void)
{
#if defined(_WIN32)
    return false;
#else
    /* POSIX without prctl(2): there is no no_new_privs bit to arm, so the
     * prerequisite step is vacuously satisfied. Callers that demand real
     * confinement must still probe os_sandbox_active()/os_sandbox_unconfined(). */
    return true;
#endif
}

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

const int *os_sandbox_terminal_worker_denied_syscalls(size_t *count)
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
#if defined(_WIN32)
    return unavailable("seccomp");
#else
    /* seccomp(2) is Linux-only. The worker attestation already records
     * isolation=degraded on non-Linux hosts; skip the filter install so the
     * compiler and tests can still run unconfined. */
    return ZCL_OK;
#endif
}

struct zcl_result os_sandbox_seccomp_allow(const int *calls, size_t count)
{
    (void)calls;
    (void)count;
#if defined(_WIN32)
    return unavailable("seccomp");
#else
    return ZCL_OK;
#endif
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
#if defined(_WIN32)
    (void)limits;
    return unavailable("sandbox resource-limit profile");
#else
    if (!limits)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "limits==NULL");
#define SET_LIMIT(field, resource) do { \
    if (limits->field != OS_SANDBOX_RLIMIT_KEEP) { \
        struct rlimit rl = { \
            .rlim_cur = (rlim_t)limits->field, \
            .rlim_max = (rlim_t)limits->field, \
        }; \
        if (setrlimit((resource), &rl) != 0) \
            return ZCL_ERR(OS_SANDBOX_ERR_RLIMIT, \
                "setrlimit(%s, %llu) failed errno=%d (%s)", \
                #resource, (unsigned long long)limits->field, errno, \
                strerror(errno)); \
    } \
} while (0)
    SET_LIMIT(as_bytes, RLIMIT_AS);
    SET_LIMIT(cpu_seconds, RLIMIT_CPU);
    SET_LIMIT(nproc, RLIMIT_NPROC);
    SET_LIMIT(fsize_bytes, RLIMIT_FSIZE);
    SET_LIMIT(nofile, RLIMIT_NOFILE);
    SET_LIMIT(core_bytes, RLIMIT_CORE);
#undef SET_LIMIT
    return ZCL_OK;
#endif
}

struct os_sandbox_rlimits os_sandbox_terminal_worker_rlimits(void)
{
    return (struct os_sandbox_rlimits){
        .as_bytes = 256u * 1024u * 1024u,
        .cpu_seconds = 300,
        .nproc = 32,
        .fsize_bytes = 1024u * 1024u,
        .nofile = 64,
        .core_bytes = 0,
    };
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
#elif defined(_WIN32)
/* No Windows equivalent of a per-uid /proc walk is implemented here (that is
 * a real design task, not this compile fix). Per the documented contract on
 * os_sandbox_uid_task_count() in platform/os_sandbox.h ("Returns 0 when
 * /proc is unreadable"), 0 already means "could not observe", not "verified
 * zero threads" — but on a platform that can never observe it at all, that
 * distinction is worth spelling out where it can be seen, so log it by name
 * instead of failing silently. */
uint64_t os_sandbox_uid_task_count(void)
{
    LOG_WARN("os_sandbox",
             "uid task census is unavailable on this operating system "
             "(no Windows equivalent implemented); reporting 0, which the "
             "process-budget admission path reads as unobserved load, not "
             "a verified idle host");
    return 0;
}
#else
uint64_t os_sandbox_uid_task_count(void) { return 0; }
#endif

uint64_t os_sandbox_nproc_hard_limit(void)
{
#if defined(_WIN32)
    /* Windows does not charge process/thread creation against a per-uid
     * RLIMIT_NPROC-style ceiling at all, so there is nothing to probe and
     * nothing can fail to be read here: "no such limit exists" is the true
     * answer, not a stand-in for "could not determine it". OS_SANDBOX_
     * RLIMIT_KEEP is exactly that sentinel per its definition in
     * platform/os_sandbox.h ("unlimited or unreadable"). */
    return OS_SANDBOX_RLIMIT_KEEP;
#else
    struct rlimit limit;
    if (getrlimit(RLIMIT_NPROC, &limit) != 0 || limit.rlim_max == RLIM_INFINITY)
        return OS_SANDBOX_RLIMIT_KEEP;
    return (uint64_t)limit.rlim_max;
#endif
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
#elif defined(_WIN32)
    /* No Windows equivalent of a POSIX process-group id is implemented here
     * (that is a real design task, not this compile fix). Same reporting
     * discipline as os_sandbox_uid_task_count above: 0 is the documented
     * "unreadable" sentinel per platform/os_sandbox.h, but log it by name so
     * it is never mistaken for a verified empty group. */
    LOG_WARN("os_sandbox",
             "process-group census is unavailable on this operating system "
             "(no Windows equivalent implemented); reporting 0 for group=%ld",
             (long)group);
    return 0;
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

struct os_sandbox_profile os_sandbox_terminal_worker_profile(
    const struct os_sandbox_path_rule *rules, size_t count)
{
    /* Confinement refuses on non-Linux: os_sandbox_enter() rejects every
     * profile here, so the profile's named fields only document the intent. */
    struct os_sandbox_profile value = profile("terminal_worker", rules, count);
    value.no_new_privs = true;
    value.apply_rlimits = true;
    value.rlimits = os_sandbox_terminal_worker_rlimits();
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
#if defined(_WIN32)
    return unavailable("Windows restricted-token sandbox");
#else
    return unavailable("Linux process confinement");
#endif
}
