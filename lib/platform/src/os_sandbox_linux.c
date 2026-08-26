/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox — Linux backing for the process-confinement builders.
 * See platform/os_sandbox.h for the design, the empirical grounding
 * (docs/work/session-substrate-probes.md), and the ordering invariant.
 *
 * Raw syscalls (prctl, landlock_*, seccomp via prctl, setrlimit, unshare)
 * live here because lib/platform is the blessed raw-OS layer. The Landlock
 * and seccomp header groups are feature-tested with __has_include so a build
 * on an older kernel still COMPILES — the builders degrade at RUNTIME
 * (returning a typed zcl_result), never at compile time. */

#define _GNU_SOURCE

#include "platform/os_sandbox.h"

#include "util/log_macros.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* ── Feature detection (degrade at runtime, not compile-time) ──────────── */

#if defined(__has_include)
#  if __has_include(<linux/landlock.h>)
#    define ZCL_HAVE_LANDLOCK 1
#    include <linux/landlock.h>
#  endif
#  if __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>) \
       && __has_include(<linux/audit.h>)
#    define ZCL_HAVE_SECCOMP 1
#    include <linux/seccomp.h>
#    include <linux/filter.h>
#    include <linux/audit.h>
#  endif
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

/* Landlock syscall numbers — supply fallbacks so the code compiles even where
 * the C library headers predate them (they are stable across arches on the
 * mainline ABI). */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

/* SECCOMP_RET_KILL_PROCESS (kernel >= 4.14). Fall back to the raw value where
 * an older <linux/seccomp.h> only defines SECCOMP_RET_KILL (== kill thread). */
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

/* seccomp(2) mode + TSYNC flag (kernel >= 3.17). The seccomp(2) syscall with
 * SECCOMP_FILTER_FLAG_TSYNC installs the filter on EVERY thread of the calling
 * process atomically — unlike prctl(PR_SET_SECCOMP), which confines only the
 * calling thread and its later descendants. Fallbacks let this compile against
 * a libc predating the seccomp(2) wrapper/flag; on x86_64 __NR_seccomp==317. */
#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif

/* Process-wide "sandbox entered" latch. Set once, never cleared (enter is
 * one-way); a plain bool is safe because enter() is single-threaded. */
static bool g_sandbox_active = false;
static const char *g_active_profile_name = NULL;

/* Which mechanism actually installed the seccomp filter, recorded so the
 * `sandbox` witness can prove thread coverage rather than intent: TSYNC means
 * the filter reached ALL threads atomically; PRCTL means only the caller +
 * later descendants. Atomic because the witness reads it from another thread. */
enum seccomp_install_method {
    SECCOMP_INSTALL_NONE = 0,
    SECCOMP_INSTALL_TSYNC,
    SECCOMP_INSTALL_PRCTL,
};
static _Atomic int g_seccomp_install_method = SECCOMP_INSTALL_NONE;

/* Count of threads that have PROVABLY entered a Landlock domain in this process
 * — incremented once per successful landlock_restrict_self (whether via the
 * original os_sandbox_landlock_restrict() call or a later retrofit join via
 * os_sandbox_landlock_apply_to_self()). Landlock has no TSYNC equivalent and
 * is not retroactive, so this is the honest measure of Landlock thread
 * coverage (as opposed to seccomp, which TSYNC makes total). Children a
 * restricted thread later spawns inherit the domain but are NOT counted here,
 * so this is a conservative floor, never an over-count. */
static _Atomic int g_landlock_restrict_count = 0;

/* The ruleset fd from the most recent successful os_sandbox_landlock_restrict()
 * call, RETAINED (not closed) instead of being closed after that call's own
 * landlock_restrict_self. Why: Landlock's restrict-self only confines the
 * CALLING thread — a ruleset applied by the boot thread does not cover
 * threads that were already running (no TSYNC-style all-thread install
 * exists for Landlock, unlike seccomp). The fd table is shared by every
 * thread of a process, so this same fd number is valid from any of them, and
 * landlock_restrict_self() neither consumes nor requires exclusive use of the
 * fd it is given — multiple threads may each call it with the same ruleset
 * fd to independently join that domain. os_sandbox_landlock_apply_to_self()
 * is the retrofit join primitive that uses it. -1 means "no domain active
 * yet" (sandbox not entered, or Landlock unavailable on this kernel). */
static _Atomic int g_retained_ruleset_fd = -1;

/* Per-thread guard: has THIS thread already joined the retained Landlock
 * domain (via the original restrict call or a retrofit join)? Makes
 * os_sandbox_landlock_apply_to_self() idempotent — calling it every loop
 * iteration of a retrofitted thread costs one branch, not a repeated
 * syscall + wasted domain-stack layer. */
static _Thread_local bool tl_landlock_joined = false;

/* ── Confinement witness state (backs the `confinement` dumper) ────────────
 *
 * os_sandbox_active() alone cannot tell an operator the two things that
 * matter after a failed apply: that confinement was REQUESTED, and where the
 * process can still read/write. These records close that gap, and give any
 * subsystem about to open a path outside the datadir a way to REFUSE with a
 * named reason instead of surfacing a bare EACCES. */

/* The profile name confinement was requested under — COPIED, never aliased,
 * so a caller may pass a stack buffer. "" = never requested. */
static char g_requested_profile[64] = "";

struct sandbox_grant_record {
    char path[OS_SANDBOX_GRANT_PATH_MAX];
    bool allow_read;
    bool allow_write;
};
static struct sandbox_grant_record g_grants[OS_SANDBOX_MAX_RECORDED_GRANTS];
static _Atomic size_t g_grant_count = 0;

/* Latched true once a Landlock domain is enforced in this process. */
static _Atomic bool g_landlock_enforced = false;

/* The ABI observed while BUILDING the domain, cached so nothing has to
 * re-probe later: landlock_create_ruleset(2) is absent from both -confine
 * seccomp allow-sets, so a probe from inside a confined process is a
 * KILL_PROCESS, not an error. -1 = no domain was ever built. */
static _Atomic int g_landlock_abi_cached = -1;

/* Set when the grant set could NOT be recorded faithfully (more rules than
 * OS_SANDBOX_MAX_RECORDED_GRANTS, or a path over the length bound). It forces
 * os_sandbox_path_is_granted() to answer "granted" for everything, so this
 * module never hands a caller a refusal it cannot actually prove. */
static _Atomic bool g_grants_incomplete = false;

/* Cleared when a seccomp ALLOW-list is installed that omits prctl(2) or
 * landlock_restrict_self(2) — the two syscalls a retrofit Landlock join
 * makes. Under such a filter the join is not a failure, it is a process
 * KILL, so the retrofit primitive must refuse to attempt it. */
static _Atomic bool g_retrofit_join_permitted = true;

void os_sandbox_note_requested(const char *profile_name)
{
    if (!profile_name)
        profile_name = "";
    size_t n = strlen(profile_name);
    if (n >= sizeof(g_requested_profile))
        n = sizeof(g_requested_profile) - 1;
    memcpy(g_requested_profile, profile_name, n);
    g_requested_profile[n] = '\0';
}

const char *os_sandbox_requested_profile(void) { return g_requested_profile; }

bool os_sandbox_unconfined(void)
{
    /* Honest across every entry route: a profile may have entered via
     * os_sandbox_enter(), or an individual builder may have been applied
     * directly (the tests, and any future partial adopter). Confined means at
     * least one of the two enforcement mechanisms is live. */
    return !g_sandbox_active &&
           !atomic_load(&g_landlock_enforced) &&
           atomic_load(&g_seccomp_install_method) == SECCOMP_INSTALL_NONE;
}

int os_sandbox_landlock_abi_cached(void)
{
    return atomic_load(&g_landlock_abi_cached);
}

bool os_sandbox_retrofit_join_permitted(void)
{
    return atomic_load(&g_retrofit_join_permitted);
}

size_t os_sandbox_fs_grant_count(void) { return atomic_load(&g_grant_count); }

const char *os_sandbox_fs_grant_at(size_t i, bool *allow_read, bool *allow_write)
{
    if (i >= atomic_load(&g_grant_count))
        return NULL;
    if (allow_read)  *allow_read  = g_grants[i].allow_read;
    if (allow_write) *allow_write = g_grants[i].allow_write;
    return g_grants[i].path;
}

#ifdef ZCL_HAVE_LANDLOCK
/* Stage one grant into slot `idx`. Called from the rule loop BEFORE
 * restrict_self; the count is published only once the domain is live. Guarded
 * because its only call site is inside the same guard — on a build without the
 * Landlock headers no domain can exist, and an unused static is -Werror. */
static void sandbox_grant_stage(size_t idx, const struct os_sandbox_path_rule *r)
{
    if (idx >= OS_SANDBOX_MAX_RECORDED_GRANTS || !r || !r->path) {
        atomic_store(&g_grants_incomplete, true);
        return;
    }
    memset(&g_grants[idx], 0, sizeof(g_grants[idx]));
    char real[PATH_MAX];
    const char *src = realpath(r->path, real) ? real : r->path;
    size_t n = strlen(src);
    if (n >= sizeof(g_grants[idx].path)) {
        atomic_store(&g_grants_incomplete, true);
        return;
    }
    memcpy(g_grants[idx].path, src, n + 1);
    g_grants[idx].allow_read  = r->allow_read;
    g_grants[idx].allow_write = r->allow_write;
}
#endif /* ZCL_HAVE_LANDLOCK */

/* Does one recorded grant cover `path` (already absolute) with at least the
 * requested access? Prefix match anchored at a component boundary so a grant
 * of /x/.zclassic-c23 does not spuriously cover /x/.zclassic-c23-dev. */
static bool sandbox_grant_covers(const struct sandbox_grant_record *g,
                                 const char *path, bool need_write)
{
    if (need_write ? !g->allow_write : !g->allow_read)
        return false;
    size_t gl = strlen(g->path);
    if (gl == 0)
        return false;
    if (gl == 1 && g->path[0] == '/')
        return true;  /* a root grant covers everything beneath it */
    if (strncmp(path, g->path, gl) != 0)
        return false;
    return path[gl] == '\0' || path[gl] == '/';
}

bool os_sandbox_path_is_granted(const char *path, bool need_write)
{
    /* Fail OPEN on every "cannot prove a denial" branch — a caller may turn a
     * false answer into a refusal, so a false must mean provably-outside. */
    if (!atomic_load(&g_landlock_enforced))
        return true;                      /* no filesystem restriction in force */
    if (atomic_load(&g_grants_incomplete))
        return true;                      /* grant set not faithfully recorded */
    if (!path || path[0] != '/')
        return true;                      /* not an absolute path we scope */

    char real[PATH_MAX];
    const char *p = realpath(path, real) ? real : path;

    size_t n = atomic_load(&g_grant_count);
    for (size_t i = 0; i < n; i++)
        if (sandbox_grant_covers(&g_grants[i], p, need_write))
            return true;
    return false;
}

size_t os_sandbox_explain_denied_path(const char *path, bool need_write,
                                      char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return 0;
    out[0] = '\0';
    if (os_sandbox_path_is_granted(path, need_write))
        return 0;

    char grants[320];
    grants[0] = '\0';
    size_t used = 0;
    size_t n = atomic_load(&g_grant_count);
    for (size_t i = 0; i < n && used + 1 < sizeof(grants); i++) {
        int w = snprintf(grants + used, sizeof(grants) - used, "%s%s(%s)",
                         used ? ", " : "", g_grants[i].path,
                         g_grants[i].allow_write ? "rw" : "ro");
        if (w < 0)
            break;
        used += (size_t)w;
        if (used >= sizeof(grants)) {
            used = sizeof(grants) - 1;
            break;
        }
    }

    const char *prof = g_active_profile_name ? g_active_profile_name : "?";
    int w = snprintf(out, out_sz,
                     "confinement: the kernel filesystem restriction (Landlock "
                     "ABI %d, profile '%s') does not grant %s access to '%s'. "
                     "Active grants: [%s]. Restart without the confinement flag "
                     "or extend the grant set to cover this path.",
                     atomic_load(&g_landlock_abi_cached), prof,
                     need_write ? "write" : "read", path ? path : "(null)",
                     grants);
    if (w < 0) {
        out[0] = '\0';
        return 0;
    }
    return strlen(out);
}

bool os_sandbox_active(void) { return g_sandbox_active; }

int os_sandbox_landlock_restricted_count(void)
{
    return atomic_load(&g_landlock_restrict_count);
}

const char *os_sandbox_seccomp_install_method(void)
{
    switch (atomic_load(&g_seccomp_install_method)) {
    case SECCOMP_INSTALL_TSYNC: return "tsync";
    case SECCOMP_INSTALL_PRCTL: return "prctl";
    default:                    return "";
    }
}

bool os_sandbox_seccomp_tsync_active(void)
{
    return atomic_load(&g_seccomp_install_method) == SECCOMP_INSTALL_TSYNC;
}

const char *os_sandbox_active_profile_name(void) { return g_active_profile_name; }

bool os_sandbox_seccomp_supported(void)
{
#ifdef ZCL_HAVE_SECCOMP
    return true;
#else
    return false;
#endif
}

/* ── no_new_privs ──────────────────────────────────────────────────────── */

bool os_sandbox_no_new_privs(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        LOG_FAIL("os_sandbox", "prctl(PR_SET_NO_NEW_PRIVS) failed errno=%d (%s)",
                 errno, strerror(errno));
    /* PR_SET_DUMPABLE(0) also strips ptrace attach from a same-uid process,
     * which is part of the confinement — treat a failure as fatal too. */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        LOG_FAIL("os_sandbox", "prctl(PR_SET_DUMPABLE,0) failed errno=%d (%s)",
                 errno, strerror(errno));
    return true;
}

/* ── Landlock ──────────────────────────────────────────────────────────── */

#ifdef ZCL_HAVE_LANDLOCK
static int ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                             size_t size, uint32_t flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static int ll_add_rule(int ruleset_fd, enum landlock_rule_type type,
                       const void *attr, uint32_t flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
static int ll_restrict_self(int ruleset_fd, uint32_t flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif /* ZCL_HAVE_LANDLOCK */

int os_sandbox_landlock_abi(void)
{
#ifdef ZCL_HAVE_LANDLOCK
    errno = 0;
    int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) return -1;
    return abi;
#else
    return -1;
#endif
}

struct zcl_result os_sandbox_landlock_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
#ifndef ZCL_HAVE_LANDLOCK
    (void)rules;
    (void)n_rules;
    return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                   "Landlock headers absent at build time");
#else
    int abi = os_sandbox_landlock_abi();
    if (abi < 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                       "Landlock unavailable on this kernel (ABI probe failed)");
    if (n_rules > 0 && rules == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "n_rules>0 but rules==NULL");

    /* Handle only the FS accesses this ABI knows about (forward-compatible).
     * ABI 1 introduced the file/dir bits; later ABIs add refer/truncate/net —
     * we do not enforce those here, so we do not need to handle them. The
     * execute/make/remove bits join the handled set ONLY when at least one
     * rule asks for them (allow_execute / allow_create): a handled-but-
     * ungranted right is DENIED everywhere, so handling them unconditionally
     * silently revoked file creation/removal for every pre-existing caller
     * (node -confine profiles never set those flags — test_confine caught
     * this). */
    uint64_t handled = LANDLOCK_ACCESS_FS_READ_FILE |
                       LANDLOCK_ACCESS_FS_WRITE_FILE |
                       LANDLOCK_ACCESS_FS_READ_DIR;
    for (size_t i = 0; i < n_rules; i++) {
        if (rules[i].allow_execute)
            handled |= LANDLOCK_ACCESS_FS_EXECUTE;
        if (rules[i].allow_create)
            handled |= LANDLOCK_ACCESS_FS_MAKE_REG |
                       LANDLOCK_ACCESS_FS_MAKE_DIR |
                       LANDLOCK_ACCESS_FS_REMOVE_FILE |
                       LANDLOCK_ACCESS_FS_REMOVE_DIR;
    }

    struct landlock_ruleset_attr rattr = { .handled_access_fs = handled };
    int ruleset_fd = ll_create_ruleset(&rattr, sizeof(rattr), 0);
    if (ruleset_fd < 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "landlock_create_ruleset failed errno=%d (%s)",
                       errno, strerror(errno));

    for (size_t i = 0; i < n_rules; i++) {
        const struct os_sandbox_path_rule *r = &rules[i];
        if (r->path == NULL) {
            close(ruleset_fd);
            return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                           "path rule %zu has NULL path", i);
        }
        uint64_t allow = 0;
        if (r->allow_read)  allow |= LANDLOCK_ACCESS_FS_READ_FILE |
                                     LANDLOCK_ACCESS_FS_READ_DIR;
        if (r->allow_write) allow |= LANDLOCK_ACCESS_FS_WRITE_FILE;
        if (r->allow_execute) allow |= LANDLOCK_ACCESS_FS_EXECUTE;
        if (r->allow_create)
            allow |= LANDLOCK_ACCESS_FS_MAKE_REG |
                     LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE |
                     LANDLOCK_ACCESS_FS_REMOVE_DIR;
        allow &= handled;

        int path_fd = open(r->path, O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            close(ruleset_fd);
            return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                           "open(O_PATH) %s failed errno=%d (%s)",
                           r->path, errno, strerror(errno));
        }
        /* Directory-only access bits (READ_DIR and the make/remove family)
         * are rejected with EINVAL when the path is a regular FILE (e.g.
         * /proc/self/status, /etc/resolv.conf). Probe the fd and mask the
         * dir-only bits off for a non-directory so a caller can grant either
         * a dir tree or a single file uniformly. */
        struct stat pst;
        if (fstat(path_fd, &pst) == 0 && !S_ISDIR(pst.st_mode))
            allow &= ~(uint64_t)(LANDLOCK_ACCESS_FS_READ_DIR |
                                 LANDLOCK_ACCESS_FS_MAKE_REG |
                                 LANDLOCK_ACCESS_FS_MAKE_DIR |
                                 LANDLOCK_ACCESS_FS_REMOVE_FILE |
                                 LANDLOCK_ACCESS_FS_REMOVE_DIR);
        struct landlock_path_beneath_attr pb = {
            .allowed_access = allow,
            .parent_fd = path_fd,
        };
        int rc = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        close(path_fd);
        if (rc != 0) {
            close(ruleset_fd);
            return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                           "landlock_add_rule %s failed errno=%d (%s)",
                           r->path, errno, strerror(errno));
        }
        /* Stage the grant for the confinement witness. Staging (not
         * publishing) here keeps the visible grant set empty until the domain
         * is actually live — a half-built ruleset restricts nothing. */
        sandbox_grant_stage(i, r);
    }

    if (ll_restrict_self(ruleset_fd, 0) != 0) {
        int e = errno;
        close(ruleset_fd);
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "landlock_restrict_self failed errno=%d (%s) "
                       "(no_new_privs run first?)", e, strerror(e));
    }
    /* Retain (do not close) the ruleset fd — see g_retained_ruleset_fd. Close
     * out any previously-retained fd first (this builder is one-way in
     * practice, but stay leak-safe if a caller ever re-enters). */
    int prev_fd = atomic_exchange(&g_retained_ruleset_fd, ruleset_fd);
    if (prev_fd >= 0)
        close(prev_fd);
    tl_landlock_joined = true;
    atomic_fetch_add(&g_landlock_restrict_count, 1);
    /* Publish the witness: the grant set is only meaningful now that the
     * domain is enforced, and this is the last moment the ABI can be read
     * without re-probing (landlock_create_ruleset is absent from the -confine
     * allow-sets, so a later probe would be SIGSYS-killed, not merely fail). */
    atomic_store(&g_landlock_abi_cached, abi);
    atomic_store(&g_grant_count,
                 n_rules < OS_SANDBOX_MAX_RECORDED_GRANTS
                     ? n_rules : OS_SANDBOX_MAX_RECORDED_GRANTS);
    atomic_store(&g_landlock_enforced, true);
    return ZCL_OK;
#endif
}

struct zcl_result os_sandbox_landlock_apply_to_self(void)
{
#ifndef ZCL_HAVE_LANDLOCK
    return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                   "Landlock headers absent at build time");
#else
    if (tl_landlock_joined)
        return ZCL_OK;  /* idempotent: this thread already holds the domain */

    /* A retrofit join makes exactly two syscalls: prctl(PR_SET_NO_NEW_PRIVS)
     * and landlock_restrict_self(2). Under a seccomp ALLOW-list that omits
     * either — which BOTH -confine allow-sets do today — those are not
     * failures, they are SECCOMP_RET_KILL_PROCESS. Refuse the attempt with a
     * typed non-ok (callers already treat non-ok as "skip and retry later")
     * rather than taking the node down from inside a health-sweep tick. */
    if (!atomic_load(&g_retrofit_join_permitted))
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                       "retrofit Landlock join refused: the active seccomp "
                       "allow-list omits prctl/landlock_restrict_self, so the "
                       "join would be killed rather than fail");

    int fd = atomic_load(&g_retained_ruleset_fd);
    if (fd < 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                       "no active Landlock domain to join (sandbox not "
                       "entered yet, or Landlock unavailable on this kernel)");

    /* no_new_privs is a per-THREAD kernel attribute (task_struct), not
     * process-wide — unlike seccomp's TSYNC install, there is no mechanism
     * that retroactively sets it on sibling threads. A thread spawned before
     * the boot thread's own os_sandbox_no_new_privs() call (exactly the
     * threads this retrofit exists for) never got it set on itself, and
     * landlock_restrict_self(2) requires it (or CAP_SYS_ADMIN) on the CALLING
     * thread. Setting it here is idempotent (prctl(PR_SET_NO_NEW_PRIVS,1) a
     * second time is a harmless no-op) and required for the join to succeed. */
    if (!os_sandbox_no_new_privs())
        return ZCL_ERR(OS_SANDBOX_ERR_NO_NEW_PRIVS,
                       "no_new_privs step failed for retrofit join");

    if (ll_restrict_self(fd, 0) != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "landlock_restrict_self (retrofit join) failed "
                       "errno=%d (%s)", errno, strerror(errno));

    tl_landlock_joined = true;
    atomic_fetch_add(&g_landlock_restrict_count, 1);
    return ZCL_OK;
#endif
}

/* ── seccomp-bpf deny-list ─────────────────────────────────────────────── */

/* The session child's deny-set. Guarded __NR_* so a syscall absent on this
 * arch (e.g. socketcall on x86_64) is simply omitted — never a build break. */
static const int g_session_denied[] = {
    /* code execution / process creation */
    __NR_execve, __NR_execveat,
    __NR_clone,
#ifdef __NR_clone3
    __NR_clone3,
#endif
#ifdef __NR_fork
    __NR_fork,
#endif
#ifdef __NR_vfork
    __NR_vfork,
#endif
    /* the socket family (NEWNET already isolates; belt-and-suspenders — a
     * pre-passed control fd is used via read/write, not a new socket) */
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

const int *os_sandbox_session_denied_syscalls(size_t *count_out)
{
    if (count_out)
        *count_out = sizeof(g_session_denied) / sizeof(g_session_denied[0]);
    return g_session_denied;
}

/* The resident node's deny-set: execution + escape ONLY. Deliberately omits
 * the socket/clone/fork family the session set forbids — a running node opens
 * peer sockets and spawns threads, so those must stay allowed. */
static const int g_node_steady_denied[] = {
    /* code execution */
    __NR_execve, __NR_execveat,
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

const int *os_sandbox_node_steady_denied_syscalls(size_t *count_out)
{
    if (count_out)
        *count_out = sizeof(g_node_steady_denied) /
                     sizeof(g_node_steady_denied[0]);
    return g_node_steady_denied;
}

struct zcl_result os_sandbox_seccomp_deny(const int *denied, size_t n_denied,
                                          bool deny_exec_mmap)
{
#ifndef ZCL_HAVE_SECCOMP
    (void)denied;
    (void)n_denied;
    (void)deny_exec_mmap;
    return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE,
                   "seccomp headers absent at build time");
#else
    if (n_denied > 0 && denied == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "n_denied>0 but denied==NULL");

    /* Upper bound: 4 (arch preamble) + 2 per denied syscall + 5 per W^X
     * syscall (mmap/mprotect/pkey_mprotect) + 2 tail (default allow + kill). */
    enum { WX_SYSCALLS = 3, MAX_FILTER = 512 };
    if (n_denied > (MAX_FILTER - 6 - WX_SYSCALLS * 5) / 2)
        return ZCL_ERR(OS_SANDBOX_ERR_TOO_MANY_RULES,
                       "denied set too large (%zu) for the BPF filter bound",
                       n_denied);

    struct sock_filter filt[MAX_FILTER];
    size_t k = 0;

    /* Arch check: kill on any non-x86_64 caller (a 32-bit compat syscall
     * would otherwise slip a different numbering past the nr comparisons). */
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    filt[k++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* Load the syscall number into the accumulator. */
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

    /* W^X arg-filter: for mmap/mprotect/pkey_mprotect, KILL if the prot arg
     * (args[2]) has PROT_EXEC set. Each block reloads nr afterwards so the
     * subsequent nr comparisons still work. Emitted BEFORE the plain deny
     * comparisons so the accumulator holds nr at entry to each. */
    if (deny_exec_mmap) {
        const int wx[WX_SYSCALLS] = {
            __NR_mmap, __NR_mprotect,
#ifdef __NR_pkey_mprotect
            __NR_pkey_mprotect,
#else
            -1,
#endif
        };
        for (int i = 0; i < WX_SYSCALLS; i++) {
            if (wx[i] < 0) continue;
            /* if nr != wx -> skip the 4-instr check block (land on reload) */
            filt[k++] = (struct sock_filter)BPF_JUMP(
                BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)wx[i], 0, 4);
            /* load low 32 bits of args[2] (prot); PROT_EXEC fits the low word */
            filt[k++] = (struct sock_filter)BPF_STMT(
                BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, args[2]));
            /* if (prot & PROT_EXEC) -> next instr (kill); else skip it */
            filt[k++] = (struct sock_filter)BPF_JUMP(
                BPF_JMP | BPF_JSET | BPF_K, 0x4 /*PROT_EXEC*/, 0, 1);
            filt[k++] = (struct sock_filter)BPF_STMT(
                BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
            /* reload nr for the following comparisons */
            filt[k++] = (struct sock_filter)BPF_STMT(
                BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
        }
    }

    /* Plain deny comparisons: each is 2 instructions (compare, then a RET KILL
     * that is skipped on jf=1 when the syscall does not match). Length-
     * independent, so no distant label arithmetic. */
    for (size_t i = 0; i < n_denied; i++) {
        filt[k++] = (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)denied[i], 0, 1);
        filt[k++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    }

    /* Default: allow. */
    filt[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {
        .len = (unsigned short)k,
        .filter = filt,
    };

    /* Install on ALL threads atomically via seccomp(2)+TSYNC so the filter
     * lands on every already-running thread, not just the caller and its
     * future descendants. Return-value contract (man 2 seccomp):
     *   0        -> installed on every thread (TSYNC succeeded)
     *   > 0      -> the tid of a thread whose existing filter is incompatible;
     *              coverage is NOT total, so fail closed
     *   -1/ENOSYS-> seccomp(2) absent (kernel < 3.17) -> fall back to prctl
     *   -1/other -> genuine failure -> fail closed */
    errno = 0;
    long tsync = syscall(__NR_seccomp, (long)SECCOMP_SET_MODE_FILTER,
                         (long)SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (tsync == 0) {
        atomic_store(&g_seccomp_install_method, SECCOMP_INSTALL_TSYNC);
        return ZCL_OK;
    }
    if (tsync > 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "seccomp(TSYNC) could not synchronise thread tid=%ld "
                       "(incompatible pre-existing filter) — refusing partial "
                       "coverage", tsync);
    if (errno != ENOSYS)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "seccomp(SET_MODE_FILTER, TSYNC) failed errno=%d (%s) "
                       "(no_new_privs run first?)", errno, strerror(errno));

    /* ENOSYS: no seccomp(2) on this kernel — the prctl path still installs the
     * filter on the calling thread + its future descendants (partial coverage,
     * recorded so the witness reports it honestly). */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "prctl(PR_SET_SECCOMP) failed errno=%d (%s) "
                       "(no_new_privs run first?)", errno, strerror(errno));
    atomic_store(&g_seccomp_install_method, SECCOMP_INSTALL_PRCTL);
    return ZCL_OK;
#endif
}

/* ── seccomp-bpf ALLOW-list (the -confine profile) ─────────────────────── */

/* The resident node's -confine allow-set: the empirically-derived steady-state
 * syscalls a booted node needs for status RPC, SELECT-only storage queries,
 * SQLite (WAL) file I/O, malloc, timers, and RNG (derived via the reproducible
 * harness in lib/test/src/test_confine.c — each syscall was added only after a
 * candidate filter KILLed the representative confined ops without it). One line
 * per entry, grouped and commented. Guarded __NR_* so a syscall absent on this
 * arch is simply omitted, never a build break. Everything NOT here is
 * SECCOMP_RET_KILL_PROCESS — notably the socket family, execve/clone, ptrace,
 * mount/namespace, and kernel-surface syscalls are absent by design so a
 * network-facing parser compromise that reaches for them dies loudly.
 *
 * SCOPE CAVEAT: this set is the steady-state baseline for status RPC + storage
 * queries + local file/db work. It intentionally does NOT yet include the
 * socket/connect/accept family, so a node that is actively doing P2P/HTTPS I/O
 * would be SIGSYS-killed under -confine. Widening the set to cover a networking
 * node is a deliberate soak-gated step (strace a live node under load, add the
 * observed socket/epoll/sendmsg set) before -confine's default can flip — see
 * the -confine help text and lib/test/src/test_confine.c. */
static const int g_node_confine_allowed[] = {
    /* ── file I/O ────────────────────────────────────────────────────── */
    __NR_read, __NR_write, __NR_close, __NR_openat, __NR_lseek,
    __NR_pread64, __NR_pwrite64, __NR_readv, __NR_writev,
#ifdef __NR_open
    __NR_open,           /* some glibc paths still use open() not openat() */
#endif
    /* ── stat family ─────────────────────────────────────────────────── */
    __NR_fstat, __NR_newfstatat, __NR_statx,
#ifdef __NR_stat
    __NR_stat,
#endif
#ifdef __NR_lstat
    __NR_lstat,
#endif
    __NR_fstatfs, __NR_statfs,
    /* ── memory (malloc arenas + SQLite mmap) ────────────────────────── */
    __NR_mmap, __NR_munmap, __NR_mprotect, __NR_mremap, __NR_madvise, __NR_brk,
    /* ── sync / concurrency ──────────────────────────────────────────── */
    __NR_futex,
    /* ── time / random ───────────────────────────────────────────────── */
    __NR_clock_gettime, __NR_gettimeofday, __NR_clock_nanosleep, __NR_nanosleep,
    __NR_getrandom,
    /* ── signals (handler install + clean unwind on shutdown) ────────── */
    __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn, __NR_sigaltstack,
    /* ── identity ────────────────────────────────────────────────────── */
    __NR_getpid, __NR_gettid, __NR_getuid, __NR_geteuid, __NR_getgid,
    __NR_getegid,
    /* ── fd control / durability ─────────────────────────────────────── */
    __NR_fcntl, __NR_fsync, __NR_fdatasync, __NR_ftruncate,
    __NR_dup, __NR_dup3,
#ifdef __NR_dup2
    __NR_dup2,
#endif
    /* ── directory / path ops (SQLite journal/WAL rename+unlink) ──────── */
    __NR_getdents64, __NR_readlinkat, __NR_getcwd,
    __NR_unlinkat, __NR_renameat2,
#ifdef __NR_readlink
    __NR_readlink,
#endif
#ifdef __NR_unlink
    __NR_unlink,
#endif
#ifdef __NR_rename
    __NR_rename,
#endif
#ifdef __NR_renameat
    __NR_renameat,
#endif
#ifdef __NR_mkdir
    __NR_mkdir,
#endif
#ifdef __NR_rmdir
    __NR_rmdir,
#endif
#ifdef __NR_access
    __NR_access,
#endif
    __NR_faccessat,
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
    __NR_umask, __NR_fchmod, __NR_chmod, __NR_chdir,
    /* ── scheduling / sysinfo (RSS sampling, thread affinity) ────────── */
    __NR_sched_getaffinity, __NR_sched_yield, __NR_sysinfo,
    __NR_prlimit64, __NR_getrusage, __NR_uname,
    /* ── poll / event loop (HTTPS/RPC reactor, pipe self-wake) ───────── */
    __NR_poll, __NR_ppoll, __NR_epoll_create1, __NR_epoll_ctl,
    __NR_epoll_wait, __NR_epoll_pwait, __NR_pipe2, __NR_eventfd2,
    __NR_restart_syscall,
    /* ── exit ────────────────────────────────────────────────────────── */
    __NR_exit, __NR_exit_group,
};

const int *os_sandbox_node_confine_allowed_syscalls(size_t *count_out)
{
    if (count_out)
        *count_out = sizeof(g_node_confine_allowed) /
                     sizeof(g_node_confine_allowed[0]);
    return g_node_confine_allowed;
}

/* The resident node's -confine=serving allow-set: g_node_confine_allowed
 * (the strict steady set, listed above) PLUS the socket-family syscalls the
 * code actually uses for P2P/HTTPS/onion I/O (verified by a source sweep —
 * `grep -rln` over lib/net, lib/rpc, app/controllers, config/src, src for
 * each call; re-run that sweep before trusting this comment stale). The
 * strict -confine profile deliberately omits sockets entirely (SCOPE CAVEAT
 * above); this profile is the one to pass -confine=serving so a node doing
 * real network I/O is not SIGSYS-killed at its first accept()/recv()/
 * connect() after sr_confine_enter (config/src/boot.c). accept4() is NOT
 * included: the node's listener call sites (net.c, https_server.c,
 * file_service.c, httpserver.c) all use accept(), not accept4() — only
 * tools/zcl_portfwd.c (a separate standalone tool, not linked into the node
 * binary) uses accept4(). sendmsg/recvmsg have no direct node call site
 * today either, but are included per the serving-profile spec (glibc's
 * resolver and future socket-option paths can reach for them) — the
 * confined-serving test proves the currently-used ops still work; if a
 * future syscall need appears, extend this array as test_confine.c fails. */
static const int g_node_confine_serving_allowed[] = {
    /* ── everything the strict steady profile already allows ──────────── */
    __NR_read, __NR_write, __NR_close, __NR_openat, __NR_lseek,
    __NR_pread64, __NR_pwrite64, __NR_readv, __NR_writev,
#ifdef __NR_open
    __NR_open,
#endif
    __NR_fstat, __NR_newfstatat, __NR_statx,
#ifdef __NR_stat
    __NR_stat,
#endif
#ifdef __NR_lstat
    __NR_lstat,
#endif
    __NR_fstatfs, __NR_statfs,
    __NR_mmap, __NR_munmap, __NR_mprotect, __NR_mremap, __NR_madvise, __NR_brk,
    __NR_futex,
    __NR_clock_gettime, __NR_gettimeofday, __NR_clock_nanosleep, __NR_nanosleep,
    __NR_getrandom,
    __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn, __NR_sigaltstack,
    __NR_getpid, __NR_gettid, __NR_getuid, __NR_geteuid, __NR_getgid,
    __NR_getegid,
    __NR_fcntl, __NR_fsync, __NR_fdatasync, __NR_ftruncate,
    __NR_dup, __NR_dup3,
#ifdef __NR_dup2
    __NR_dup2,
#endif
    __NR_getdents64, __NR_readlinkat, __NR_getcwd,
    __NR_unlinkat, __NR_renameat2,
#ifdef __NR_readlink
    __NR_readlink,
#endif
#ifdef __NR_unlink
    __NR_unlink,
#endif
#ifdef __NR_rename
    __NR_rename,
#endif
#ifdef __NR_renameat
    __NR_renameat,
#endif
#ifdef __NR_mkdir
    __NR_mkdir,
#endif
#ifdef __NR_rmdir
    __NR_rmdir,
#endif
#ifdef __NR_access
    __NR_access,
#endif
    __NR_faccessat,
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
    __NR_umask, __NR_fchmod, __NR_chmod, __NR_chdir,
    __NR_sched_getaffinity, __NR_sched_yield, __NR_sysinfo,
    __NR_prlimit64, __NR_getrusage, __NR_uname,
    __NR_poll, __NR_ppoll, __NR_epoll_create1, __NR_epoll_ctl,
    __NR_epoll_wait, __NR_epoll_pwait, __NR_pipe2, __NR_eventfd2,
    __NR_restart_syscall,
    __NR_exit, __NR_exit_group,

    /* ── socket family: the serving-profile addition ───────────────────
     * One entry per syscall, each commented with the subsystem(s) that call
     * it (grep-verified against lib/net + lib/rpc + app/controllers). */
    __NR_socket,     /* net.c listener + connman.c outbound dialer + nat.c +
                       * netbase.c dialer + rom_fetch.c + https_server.c +
                       * file_service.c + httpserver.c (RPC) listen sockets */
    __NR_bind,       /* net.c listener, https_server.c, file_service.c,
                       * httpserver.c (RPC) — bind the listen socket */
    __NR_listen,     /* net.c listener, https_server.c, file_service.c,
                       * httpserver.c (RPC) — mark socket passive */
    __NR_accept,     /* net.c listener, https_server.c, file_service.c,
                       * httpserver.c (RPC) — accept inbound connections;
                       * the code calls accept(), NOT accept4() (confirmed:
                       * the only accept4() call site is the standalone
                       * tools/zcl_portfwd.c, not part of the node binary) */
    __NR_connect,    /* connman.c reactor (outbound peer dial), nat.c
                       * (UPnP/STUN probes), netbase.c dialer, rom_fetch.c
                       * (ROM peer fetch), lib/rpc/legacy_rpc_client.c,
                       * lib/rpc/client.c */
#ifdef __NR_send
    __NR_send,       /* some arches expose a dedicated send() syscall; on
                       * x86_64 glibc's send() is a wrapper over sendto()
                       * (below) — guarded so this stays portable rather than
                       * a build break where __NR_send is absent */
#endif
    __NR_sendto,     /* net.c peer writer, nat.c (UDP UPnP/STUN datagrams),
                       * ws_events.c (websocket event push),
                       * lib/rpc/legacy_rpc_client.c,
                       * app/controllers/rpc_client.c — the raw syscall
                       * behind glibc's send()/sendto() on x86_64 */
    __NR_sendmsg,    /* no direct node call site today (grep-verified); kept
                       * for glibc resolver / future scatter-gather socket
                       * writes — the serving test does not exercise it, add
                       * a real call site + test before trusting coverage */
#ifdef __NR_recv
    __NR_recv,       /* some arches expose a dedicated recv() syscall; on
                       * x86_64 glibc's recv() is a wrapper over recvfrom()
                       * (below) — guarded so this stays portable rather than
                       * a build break where __NR_recv is absent */
#endif
    __NR_recvfrom,   /* rom_fetch.c, connman.c reactor, file_service.c,
                       * nat.c (UDP UPnP/STUN datagrams),
                       * lib/rpc/legacy_rpc_client.c,
                       * app/controllers/rpc_client.c — the raw syscall
                       * behind glibc's recv()/recvfrom() on x86_64 */
    __NR_recvmsg,    /* no direct node call site today (grep-verified); kept
                       * for glibc resolver / future scatter-gather socket
                       * reads — same caveat as sendmsg above */
    __NR_getsockopt, /* netbase.c, rom_fetch.c, file_service.c — SO_ERROR
                       * poll after a non-blocking connect() */
    __NR_setsockopt, /* netbase.c, nat.c, rom_fetch.c, https_server.c,
                       * lib/rpc/legacy_rpc_client.c, lib/rpc/client.c,
                       * lib/rpc/httpserver.c, app/controllers/api_controller.c,
                       * app/controllers/explorer_controller.c,
                       * app/controllers/wallet_view_helpers.c, net.c —
                       * SO_REUSEADDR / TCP_NODELAY / socket timeouts */
    __NR_shutdown,   /* https_server.c, lib/rpc/rpc_timeout.c,
                       * lib/rpc/httpserver.c, file_service.c — half-close
                       * on connection teardown */
    __NR_select,     /* rom_fetch.c, connman.c reactor, file_service.c —
                       * non-blocking connect()/readiness wait (poll/ppoll/
                       * epoll_* already covered the steady set above) */
#ifdef __NR_pselect6
    __NR_pselect6,   /* glibc's select() wrapper does NOT invoke the raw
                       * select syscall on this libc/kernel — it converts the
                       * timeval to a timespec and calls pselect6 instead
                       * (confirmed by strace); the confined-serving test's
                       * select() call SIGSYS-killed without this entry even
                       * with __NR_select present. Keep both: __NR_select is
                       * the spec-named syscall, __NR_pselect6 is what the
                       * libc actually emits. */
#endif
    __NR_getsockname, /* nat.c — read back the local address/port of a
                        * socket (UPnP/STUN local-endpoint discovery); found
                        * by the same source sweep, not in the task's
                        * original enumeration but genuinely called */
};

const int *os_sandbox_node_confine_serving_allowed_syscalls(size_t *count_out)
{
    if (count_out)
        *count_out = sizeof(g_node_confine_serving_allowed) /
                     sizeof(g_node_confine_serving_allowed[0]);
    return g_node_confine_serving_allowed;
}

struct zcl_result os_sandbox_seccomp_allow(const int *allowed, size_t n_allowed)
{
#ifndef ZCL_HAVE_SECCOMP
    (void)allowed;
    (void)n_allowed;
    return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE,
                   "seccomp headers absent at build time");
#else
    if (n_allowed > 0 && allowed == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                       "n_allowed>0 but allowed==NULL");

    /* Record whether a retrofit Landlock join stays SURVIVABLE under this
     * allow-list. The join calls prctl(PR_SET_NO_NEW_PRIVS) then
     * landlock_restrict_self(2); if either is outside the allow-set the join
     * is a process KILL, not an error return, so the retrofit primitive must
     * refuse it. Computed here (the one place that sees the allow-set) rather
     * than hard-coding knowledge of the shipped profiles. */
    {
        bool has_prctl = false, has_restrict_self = false;
        for (size_t i = 0; i < n_allowed; i++) {
            if (allowed[i] == __NR_prctl)                  has_prctl = true;
            if (allowed[i] == __NR_landlock_restrict_self) has_restrict_self = true;
        }
        atomic_store(&g_retrofit_join_permitted, has_prctl && has_restrict_self);
    }

    /* Bound: 4 (arch preamble + nr load) + 2 per allowed syscall + 1 tail
     * (default KILL). Refuse rather than overflow the fixed filter buffer. */
    enum { MAX_FILTER = 512 };
    if (n_allowed > (MAX_FILTER - 5) / 2)
        return ZCL_ERR(OS_SANDBOX_ERR_TOO_MANY_RULES,
                       "allowed set too large (%zu) for the BPF filter bound",
                       n_allowed);

    struct sock_filter filt[MAX_FILTER];
    size_t k = 0;

    /* Arch check: KILL any non-x86_64 (compat) caller — a 32-bit syscall would
     * otherwise slip a different numbering past the nr comparisons. */
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    filt[k++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* Load the syscall number. */
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

    /* For each allowed nr: if it matches, RET ALLOW; else fall through. Each
     * pair is length-independent (2 instructions), so no distant labels. */
    for (size_t i = 0; i < n_allowed; i++) {
        filt[k++] = (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)allowed[i], 0, 1);
        filt[k++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }

    /* Default: KILL the whole process (fail-fast doctrine). */
    filt[k++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    struct sock_fprog prog = {
        .len = (unsigned short)k,
        .filter = filt,
    };

    /* Install on ALL threads atomically via seccomp(2)+TSYNC (same return-value
     * contract as os_sandbox_seccomp_deny — see that function's comment). */
    errno = 0;
    long tsync = syscall(__NR_seccomp, (long)SECCOMP_SET_MODE_FILTER,
                         (long)SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (tsync == 0) {
        atomic_store(&g_seccomp_install_method, SECCOMP_INSTALL_TSYNC);
        return ZCL_OK;
    }
    if (tsync > 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "seccomp(TSYNC) could not synchronise thread tid=%ld "
                       "(incompatible pre-existing filter) — refusing partial "
                       "coverage", tsync);
    if (errno != ENOSYS)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "seccomp(SET_MODE_FILTER, TSYNC) failed errno=%d (%s) "
                       "(no_new_privs run first?)", errno, strerror(errno));

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP,
                       "prctl(PR_SET_SECCOMP) failed errno=%d (%s) "
                       "(no_new_privs run first?)", errno, strerror(errno));
    atomic_store(&g_seccomp_install_method, SECCOMP_INSTALL_PRCTL);
    return ZCL_OK;
#endif
}

/* ── rlimits ───────────────────────────────────────────────────────────── */

struct os_sandbox_rlimits os_sandbox_session_rlimits(void)
{
    return (struct os_sandbox_rlimits){
        .as_bytes    = (uint64_t)256 * 1024 * 1024,
        .cpu_seconds = OS_SANDBOX_RLIMIT_KEEP,   /* caller sets a session budget */
        .nproc       = 1,
        .fsize_bytes = (uint64_t)64 * 1024 * 1024,
        .nofile      = 16,
        .core_bytes  = 0,
    };
}

static struct zcl_result set_one_rlimit(int resource, uint64_t v, const char *name)
{
    if (v == OS_SANDBOX_RLIMIT_KEEP) return ZCL_OK;
    struct rlimit rl = { .rlim_cur = (rlim_t)v, .rlim_max = (rlim_t)v };
    if (setrlimit(resource, &rl) != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_RLIMIT,
                       "setrlimit(%s, %llu) failed errno=%d (%s)",
                       name, (unsigned long long)v, errno, strerror(errno));
    return ZCL_OK;
}

struct zcl_result os_sandbox_set_rlimits(const struct os_sandbox_rlimits *lim)
{
    if (!lim) return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "lim==NULL");
    ZCL_CHECK(set_one_rlimit(RLIMIT_AS,    lim->as_bytes,    "RLIMIT_AS"));
    ZCL_CHECK(set_one_rlimit(RLIMIT_CPU,   lim->cpu_seconds, "RLIMIT_CPU"));
    ZCL_CHECK(set_one_rlimit(RLIMIT_NPROC, lim->nproc,       "RLIMIT_NPROC"));
    ZCL_CHECK(set_one_rlimit(RLIMIT_FSIZE, lim->fsize_bytes, "RLIMIT_FSIZE"));
    ZCL_CHECK(set_one_rlimit(RLIMIT_NOFILE,lim->nofile,      "RLIMIT_NOFILE"));
    ZCL_CHECK(set_one_rlimit(RLIMIT_CORE,  lim->core_bytes,  "RLIMIT_CORE"));
    return ZCL_OK;
}


/* ── process budget ────────────────────────────────────────────────────── */

uint64_t os_sandbox_uid_task_count(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    const uid_t me = getuid();
    uint64_t total = 0;
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        char *end = NULL;
        long pid = strtol(ent->d_name, &end, 10);
        if (!end || *end != '\0' || pid <= 0) continue;
        char tpath[64];
        int n = snprintf(tpath, sizeof(tpath), "/proc/%ld/task", pid);
        if (n <= 0 || (size_t)n >= sizeof(tpath)) continue;
        struct stat st;
        if (stat(tpath, &st) != 0 || st.st_uid != me) continue;
        DIR *tasks = opendir(tpath);
        if (!tasks) continue;
        struct dirent *te;
        while ((te = readdir(tasks)) != NULL)
            if (te->d_name[0] >= '0' && te->d_name[0] <= '9') total++;
        closedir(tasks);
    }
    closedir(proc);
    return total;
}

uint64_t os_sandbox_nproc_hard_limit(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NPROC, &rl) != 0 || rl.rlim_max == RLIM_INFINITY)
        return OS_SANDBOX_RLIMIT_KEEP;
    return (uint64_t)rl.rlim_max;
}

struct os_sandbox_process_budget os_sandbox_process_budget_at(
    uint64_t requested_ceiling, uint64_t required,
    uint64_t uid_tasks, uint64_t hard)
{
    struct os_sandbox_process_budget b = {
        .ceiling   = requested_ceiling,
        .requested = requested_ceiling,
        .hard      = hard,
        .uid_tasks = uid_tasks,
        .headroom  = 0,
        .required  = required,
        .admitted  = false,
    };
    /* setrlimit cannot RAISE a hard limit, so the uid's static NPROC hard
     * limit is the only thing allowed to lower the ceiling. That is host
     * CONFIGURATION, not host LOAD: it does not move while a suite runs. */
    if (hard != OS_SANDBOX_RLIMIT_KEEP && hard < b.ceiling)
        b.ceiling = hard;
    b.headroom = b.ceiling > uid_tasks ? b.ceiling - uid_tasks : 0;
    b.admitted = b.headroom >= required;
    return b;
}

struct os_sandbox_process_budget os_sandbox_process_budget_live(
    uint64_t requested_ceiling, uint64_t required)
{
    return os_sandbox_process_budget_at(requested_ceiling, required,
                                        os_sandbox_uid_task_count(),
                                        os_sandbox_nproc_hard_limit());
}

uint64_t os_sandbox_process_group_census(pid_t pgid)
{
    if (pgid <= 0) return 0;
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    uint64_t total = 0;
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        char *end = NULL;
        long pid = strtol(ent->d_name, &end, 10);
        if (!end || *end != '\0' || pid <= 0) continue;
        char spath[64];
        int n = snprintf(spath, sizeof(spath), "/proc/%ld/stat", pid);
        if (n <= 0 || (size_t)n >= sizeof(spath)) continue;
        int fd = open(spath, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char buf[512];
        ssize_t got = read(fd, buf, sizeof(buf) - 1);
        (void)close(fd);
        if (got <= 0) continue;
        buf[got] = '\0';
        /* This file is "pid (comm) state ppid pgrp ...". comm may contain
         * spaces AND parentheses, so anchor on the LAST ')'. */
        const char *after_comm = strrchr(buf, ')');
        if (!after_comm) continue;
        char state = 0;
        long ppid = 0, pgrp = 0;
        if (sscanf(after_comm + 1, " %c %ld %ld", &state, &ppid, &pgrp) == 3 &&
            pgrp == (long)pgid)
            total++;
    }
    closedir(proc);
    return total;
}
/* ── namespaces ────────────────────────────────────────────────────────── */

int os_sandbox_session_ns_flags(void)
{
    return CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWPID |
           CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
}

static struct zcl_result write_proc_file(pid_t pid, const char *leaf,
                                         const char *content)
{
    char path[64];
    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/%s", leaf);
    else
        snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, leaf);

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return ZCL_ERR(OS_SANDBOX_ERR_USERNS_MAP,
                       "open(%s) failed errno=%d (%s)", path, errno, strerror(errno));
    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    int e = errno;
    close(fd);
    if (w < 0 || (size_t)w != len)
        return ZCL_ERR(OS_SANDBOX_ERR_USERNS_MAP,
                       "write(%s) short/failed w=%zd errno=%d (%s)",
                       path, w, e, strerror(e));
    return ZCL_OK;
}

struct zcl_result os_sandbox_write_userns_maps(pid_t pid, unsigned inside_uid,
                                               unsigned inside_gid)
{
    /* setgroups must be denied before gid_map may be written by an
     * unprivileged process (kernel >= 3.19 requirement). */
    ZCL_CHECK(write_proc_file(pid, "setgroups", "deny"));

    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();
    char buf[64];

    snprintf(buf, sizeof(buf), "%u %u 1\n", inside_uid, (unsigned)outer_uid);
    ZCL_CHECK(write_proc_file(pid, "uid_map", buf));

    snprintf(buf, sizeof(buf), "%u %u 1\n", inside_gid, (unsigned)outer_gid);
    ZCL_CHECK(write_proc_file(pid, "gid_map", buf));
    return ZCL_OK;
}

/* ── capability probe ──────────────────────────────────────────────────── */

/* Child body for the userns probe: unshare a user namespace, report via exit
 * code (0 = worked, 1 = EPERM/other). Runs in a forked child so the calling
 * process is never mutated. */
static int userns_probe_child(void)
{
    if (unshare(CLONE_NEWUSER) == 0) return 0;
    return 1;
}

struct os_sandbox_caps os_sandbox_probe_caps(void)
{
    struct os_sandbox_caps caps = {
        .userns = false,
        .landlock_abi = os_sandbox_landlock_abi(),
#ifdef ZCL_HAVE_SECCOMP
        .seccomp = true,
#else
        .seccomp = false,
#endif
    };

    pid_t pid = fork();
    if (pid == 0) {
        _exit(userns_probe_child());
    } else if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) == pid &&
            WIFEXITED(status) && WEXITSTATUS(status) == 0)
            caps.userns = true;
    } else {
        LOG_WARN("os_sandbox", "fork for userns probe failed errno=%d (%s)",
                 errno, strerror(errno));
    }
    return caps;
}

bool os_sandbox_userns_available(void)
{
    return os_sandbox_probe_caps().userns;
}

/* ── named profiles ────────────────────────────────────────────────────── */

struct os_sandbox_profile os_sandbox_session_child_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules)
{
    size_t n_denied = 0;
    const int *denied = os_sandbox_session_denied_syscalls(&n_denied);
    return (struct os_sandbox_profile){
        .name = "session_child",
        .no_new_privs = true,
        .apply_rlimits = true,
        .rlimits = os_sandbox_session_rlimits(),
        .landlock = true,
        .fs_rules = fs_rules,
        .n_fs_rules = n_fs_rules,
        .seccomp = true,
        .denied_syscalls = denied,
        .n_denied = n_denied,
        .seccomp_deny_exec_mmap = true,
    };
}

struct os_sandbox_profile os_sandbox_node_steady_state_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules)
{
    /* The node runs many threads and legitimately opens fds + peer sockets
     * over its lifetime, so NO nproc=1 and NO AS clamp here, and the NODE
     * deny-set (execution/escape only — keeps socket/clone) instead of the
     * session set. Landlock grants the datadir (path-beneath covers the
     * late-opened <datadir>/ssl + SQLite WAL/shm/tmp). Wired at the late
     * SERVICES_RUNNING boundary via a SYSINIT record in config/src/boot.c. */
    size_t n_denied = 0;
    const int *denied = os_sandbox_node_steady_denied_syscalls(&n_denied);
    return (struct os_sandbox_profile){
        .name = "node_steady_state",
        .no_new_privs = true,
        .apply_rlimits = false,
        .rlimits = {0},
        .landlock = true,
        .fs_rules = fs_rules,
        .n_fs_rules = n_fs_rules,
        .seccomp = true,
        .denied_syscalls = denied,
        .n_denied = n_denied,
        .seccomp_deny_exec_mmap = false,  /* dlopen/JIT-free but keep headroom */
    };
}

struct os_sandbox_profile os_sandbox_node_confine_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules)
{
    /* The strict -confine node profile: Landlock (caller supplies the rw datadir
     * grant + read-only extra-path grants) + a seccomp ALLOW-list (default
     * KILL_PROCESS). No rlimit clamp — the node runs many threads with a large
     * address space. Wired at the late SERVICES_RUNNING boundary via
     * config/src/boot.c (sr_sandbox_enter, -confine branch). */
    size_t n_allowed = 0;
    const int *allowed = os_sandbox_node_confine_allowed_syscalls(&n_allowed);
    return (struct os_sandbox_profile){
        .name = "node_confine",
        .no_new_privs = true,
        .apply_rlimits = false,
        .rlimits = {0},
        .landlock = true,
        .fs_rules = fs_rules,
        .n_fs_rules = n_fs_rules,
        .seccomp = true,
        .denied_syscalls = NULL,
        .n_denied = 0,
        .seccomp_deny_exec_mmap = false,
        .seccomp_allowlist = true,
        .allowed_syscalls = allowed,
        .n_allowed = n_allowed,
    };
}

struct os_sandbox_profile os_sandbox_node_confine_serving_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules)
{
    /* The -confine=serving node profile: identical structure to
     * os_sandbox_node_confine_profile (Landlock + a seccomp ALLOW-list,
     * default KILL_PROCESS), but the allow-set is the serving one — the
     * strict steady set PLUS the socket family a node actively doing P2P/
     * HTTPS/onion I/O needs (net.c listener, connman.c reactor,
     * https_server.c, file_service.c, nat.c, netbase.c dialer,
     * ws_events.c). Wired at the late SERVICES_RUNNING boundary via
     * config/src/boot.c (sr_confine_enter, -confine=serving branch). */
    size_t n_allowed = 0;
    const int *allowed =
        os_sandbox_node_confine_serving_allowed_syscalls(&n_allowed);
    return (struct os_sandbox_profile){
        .name = "node_confine_serving",
        .no_new_privs = true,
        .apply_rlimits = false,
        .rlimits = {0},
        .landlock = true,
        .fs_rules = fs_rules,
        .n_fs_rules = n_fs_rules,
        .seccomp = true,
        .denied_syscalls = NULL,
        .n_denied = 0,
        .seccomp_deny_exec_mmap = false,
        .seccomp_allowlist = true,
        .allowed_syscalls = allowed,
        .n_allowed = n_allowed,
    };
}

/* ── enter (the one-correct-order composer) ────────────────────────────── */

struct zcl_result os_sandbox_enter(const struct os_sandbox_profile *p)
{
    if (!p) return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "profile==NULL");

    /* 1. no_new_privs — unlocks rootless Landlock + seccomp. */
    if (p->no_new_privs && !os_sandbox_no_new_privs())
        return ZCL_ERR(OS_SANDBOX_ERR_NO_NEW_PRIVS,
                       "no_new_privs step failed for profile '%s'",
                       p->name ? p->name : "?");

    /* 2. rlimits — cheap, and cannot be re-raised once seccomp is in. */
    if (p->apply_rlimits)
        ZCL_CHECK(os_sandbox_set_rlimits(&p->rlimits));

    /* 3. Landlock — fds the child needs are already pre-opened by the caller. */
    if (p->landlock)
        ZCL_CHECK(os_sandbox_landlock_restrict(p->fs_rules, p->n_fs_rules));

    /* 4. seccomp LAST — the setup above needs syscalls a deny-list/allow-list
     *    would otherwise have to special-case (openat for Landlock O_PATH,
     *    etc.). An allow-list profile (the -confine mode) installs the strict
     *    default-KILL filter; otherwise the deny-list. */
    if (p->seccomp) {
        if (p->seccomp_allowlist)
            ZCL_CHECK(os_sandbox_seccomp_allow(p->allowed_syscalls,
                                               p->n_allowed));
        else
            ZCL_CHECK(os_sandbox_seccomp_deny(p->denied_syscalls, p->n_denied,
                                              p->seccomp_deny_exec_mmap));
    }

    g_sandbox_active = true;
    g_active_profile_name = p->name;  /* profile literals are static-lifetime */
    return ZCL_OK;
}
