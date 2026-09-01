/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox — composable process-confinement builders (Linux).
 *
 * Why:
 *   The multi-user-server program needs to run an untrusted per-session
 *   child, and Rung 2 of docs/adr/0003-os-substrate-verdict.md wants the
 *   steady-state node to sandbox itself too. Both want the SAME primitives:
 *   drop privileges, scope the filesystem, forbid dangerous syscalls, cap
 *   resources. This header is the single blessed home for those primitives —
 *   platform/modules/platform is the raw-OS layer (the sibling of platform/clock.h and
 *   platform/rng.h), so the direct prctl/landlock/seccomp/setrlimit/clone
 *   syscalls that back these builders belong HERE, not scattered across the
 *   tree (mirrors the check_no_raw_clock_outside_platform.sh doctrine).
 *
 *   Every builder is INDEPENDENTLY callable and testable — you can drop
 *   no_new_privs alone, or Landlock alone — and os_sandbox_enter() composes
 *   a named `struct os_sandbox_profile` in the one correct order.
 *
 * Empirical grounding (docs/work/session-substrate-probes.md, run on the
 * target box: Ubuntu 24.04.3, kernel 6.8.0-111, uid 1000, rootless):
 *   - unprivileged user namespaces WORK (unshare/clone stack CLONE_NEWUSER|…)
 *   - a hand-rolled seccomp-bpf deny-list (no libseccomp) KILLs execve
 *   - Landlock ABI v4, outside-grant open→EACCES, pre-opened fd survives
 *   - prctl(PR_SET_NO_NEW_PRIVS) succeeds
 *
 * Portability / kernel assumptions (all DEGRADE at RUNTIME, never fail to
 * compile — the .c feature-tests headers via __has_include and falls back):
 *   - Landlock: kernel >= 5.13; the ABI version is PROBED at runtime, and an
 *     unavailable Landlock returns a typed zcl_result, never aborts.
 *   - seccomp: PR_SET_SECCOMP filter mode (kernel >= 3.5); SECCOMP_RET_
 *     KILL_PROCESS is preferred (>= 4.14) and falls back where the header
 *     lacks it.
 *   - user namespaces: rootless (CONFIG_USER_NS + unprivileged_userns_clone,
 *     AND the calling process AppArmor-unconfined — see the probes doc). A
 *     capability probe lets callers degrade to the Landlock+seccomp+rlimits
 *     profile on a host that answers EPERM.
 *   - Target of record: kernel 6.8.
 *
 * Thread-safety: these builders MUTATE the calling process/thread state and
 * are one-way (no_new_privs, Landlock restrict_self, seccomp are irreversible
 * by design). Call them from a single-threaded context (typically a freshly
 * forked/cloned child right before it starts its real work), never
 * concurrently.
 */

#ifndef ZCL_PLATFORM_OS_SANDBOX_H
#define ZCL_PLATFORM_OS_SANDBOX_H

#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>  /* pid_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Numeric codes carried in a non-ok struct zcl_result from this module.
 * Callers switch on r.code to decide whether to degrade (e.g. Landlock
 * unavailable) or treat the failure as fatal. */
enum os_sandbox_err {
    OS_SANDBOX_ERR_NONE                 = 0,
    OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE = -1,  /* kernel too old / disabled */
    OS_SANDBOX_ERR_LANDLOCK_SYSCALL     = -2,  /* create/add/restrict failed */
    OS_SANDBOX_ERR_SECCOMP              = -3,  /* prctl(PR_SET_SECCOMP) failed */
    OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE  = -4,  /* built without seccomp headers */
    OS_SANDBOX_ERR_RLIMIT               = -5,  /* setrlimit failed */
    OS_SANDBOX_ERR_NO_NEW_PRIVS         = -6,  /* prctl(PR_SET_NO_NEW_PRIVS) */
    OS_SANDBOX_ERR_USERNS_MAP           = -7,  /* uid/gid map write failed */
    OS_SANDBOX_ERR_INVALID_ARG          = -8,
    OS_SANDBOX_ERR_TOO_MANY_RULES       = -9,  /* filter would overflow bound */
};

/* A single path grant for the Landlock builder: everything BENEATH `path`
 * (the path is opened O_PATH and used as a path-beneath anchor) gets the
 * requested access. Directories should set allow_read to also permit
 * READ_DIR/listing. allow_execute adds LANDLOCK_ACCESS_FS_EXECUTE (running
 * binaries beneath the path); allow_create adds the directory-mutation
 * rights (MAKE_REG/MAKE_DIR/REMOVE_FILE/REMOVE_DIR) a writable working
 * tree needs — allow_write alone is WRITE_FILE (modify existing files),
 * which cannot create new ones. The execute/create flags exist for the
 * external package verifier's build children (slice 6); the node profiles
 * leave both false. */
struct os_sandbox_path_rule {
    const char *path;
    bool        allow_read;
    bool        allow_write;
    bool        allow_execute;
    bool        allow_create;
};

/* The metrics thread's steady-state RSS-sample path, named here (not as a
 * bare string literal in engine/composition/src/boot.c or any other non-platform/modules/platform
 * .c file) so tools/lint/check_proc_self_shim.sh's raw-/proc/self-outside-
 * platform/modules/platform ratchet does not flag the Landlock path-GRANT construction as
 * an unshimmed read — os_sandbox never opens this path itself, it only names
 * it in a struct os_sandbox_path_rule for the boot thread to grant. */
#define OS_SANDBOX_PROC_SELF_STATUS_PATH "/proc/self/status"

/* Same shim treatment for the per-process /proc/self DIRECTORY: named here
 * so a Landlock path-GRANT on the child's own proc entries (e.g. the
 * ZCODE package verifier's sanitizer runs, whose compiler-rt runtimes
 * re-read /proc/self/environ for their flags) is not flagged by
 * tools/lint/check_proc_self_shim.sh — os_sandbox only names the path in a
 * struct os_sandbox_path_rule, it never opens it. */
#define OS_SANDBOX_PROC_SELF_PATH "/proc/self"

/* Sentinel for "leave this resource limit untouched". A real limit of 0
 * (e.g. RLIMIT_CORE = 0 to disable core dumps) is set explicitly; only this
 * sentinel means keep. */
#define OS_SANDBOX_RLIMIT_KEEP UINT64_MAX

/* Resource caps. Any field == OS_SANDBOX_RLIMIT_KEEP is left as-is; every
 * other field lowers the soft (and, where lowered, hard) limit. */
struct os_sandbox_rlimits {
    uint64_t as_bytes;     /* RLIMIT_AS    — total virtual memory           */
    uint64_t cpu_seconds;  /* RLIMIT_CPU   — CPU-seconds (SIGXCPU then KILL) */
    uint64_t nproc;        /* RLIMIT_NPROC — processes for the real uid      */
    uint64_t fsize_bytes;  /* RLIMIT_FSIZE — max file size (SIGXFSZ)         */
    uint64_t nofile;       /* RLIMIT_NOFILE— open fd ceiling                 */
    uint64_t core_bytes;   /* RLIMIT_CORE  — core dump size (0 = disabled)   */
};

/* A named, composable confinement recipe. os_sandbox_enter() applies the
 * enabled builders in the ONE correct order (see the ordering invariant on
 * os_sandbox_enter). Namespaces are NOT part of this struct: they must be
 * entered by the CALLER's clone()/unshare() BEFORE os_sandbox_enter(),
 * because they change the pid/mount/net view the later builders operate in. */
struct os_sandbox_profile {
    const char *name;

    bool no_new_privs;   /* PR_SET_NO_NEW_PRIVS + PR_SET_DUMPABLE(0) */

    bool apply_rlimits;
    struct os_sandbox_rlimits rlimits;

    bool landlock;                              /* apply the fs grants below */
    const struct os_sandbox_path_rule *fs_rules;
    size_t n_fs_rules;

    bool seccomp;                               /* install the deny-list     */
    const int *denied_syscalls;                 /* array of __NR_* values    */
    size_t n_denied;
    bool seccomp_deny_exec_mmap;                /* also W^X: PROT_EXEC mmap/mprotect */

    /* seccomp ALLOW-list mode (the -confine profile). When true, the seccomp
     * step installs an ALLOW-list instead of a deny-list: default action is
     * SECCOMP_RET_KILL_PROCESS and only `allowed_syscalls` are permitted. This
     * is the strictest confinement — an unexpected syscall kills the process
     * loudly (fail-fast). Mutually exclusive with the deny-list fields above:
     * os_sandbox_enter() uses the allow-list when seccomp && seccomp_allowlist. */
    bool seccomp_allowlist;
    const int *allowed_syscalls;                /* array of __NR_* values    */
    size_t n_allowed;
};

/* Runtime capability report. Lets a caller pick the full-namespace profile or
 * degrade to Landlock+seccomp+rlimits without a userns. Never aborts. */
struct os_sandbox_caps {
    bool userns;        /* unshare(CLONE_NEWUSER) succeeds rootless          */
    int  landlock_abi;  /* Landlock ABI version, or <= 0 if unavailable      */
    bool seccomp;       /* seccomp filter mode compiled in + reachable       */
};

/* The session namespace set as a compile-time named constant — available
 * only where <sched.h> (with _GNU_SOURCE) is already included by the caller;
 * otherwise use os_sandbox_session_ns_flags(), which returns the same value.
 * Kept as a macro (not forcing sched.h into this header) so a caller that
 * does not need clone flags is not dragged into _GNU_SOURCE. */
#if defined(CLONE_NEWUSER) && defined(CLONE_NEWNET) && defined(CLONE_NEWPID) \
    && defined(CLONE_NEWNS) && defined(CLONE_NEWIPC) && defined(CLONE_NEWUTS)
#define SANDBOX_SESSION_NS_FLAGS \
    (CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS | \
     CLONE_NEWIPC | CLONE_NEWUTS)
#endif

/* ── Individual builders (each independently callable/testable) ─────────── */

/* prctl(PR_SET_NO_NEW_PRIVS, 1) + prctl(PR_SET_DUMPABLE, 0). Required before
 * a rootless Landlock restrict_self or seccomp filter install. Returns true
 * on success; logs and returns false otherwise. */
bool os_sandbox_no_new_privs(void);

/* Probe the Landlock ABI version (landlock_create_ruleset(NULL,0,VERSION)).
 * Returns the ABI (>= 1) or -1 if Landlock is unavailable on this kernel or
 * this build lacks the headers. Non-mutating. */
int os_sandbox_landlock_abi(void);

/* Build a Landlock ruleset from `rules` and call landlock_restrict_self —
 * ONE-WAY. Only the accesses this kernel's ABI actually handles are enabled
 * (forward-compatible). ORDERING: the caller must open every fd the child
 * will need (PTY master/slave, log fd, control socket) BEFORE calling this —
 * pre-opened fds survive enforcement (probe 4), so they need no path grant.
 * On a kernel without Landlock this returns a non-ok result with code
 * OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE so the caller can DEGRADE (it does not
 * abort). Requires no_new_privs (or CAP_SYS_ADMIN) to have run first. */
struct zcl_result os_sandbox_landlock_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules);

/* The session child's denied-syscall set (execve/execveat, the clone/fork
 * family, the socket family, ptrace/process_vm_*, mount family, bpf, kexec,
 * key management, setns/unshare, module ops, open_by_handle_at,
 * perf_event_open, …). Returns a pointer to a static const array; *count_out
 * receives its length. This is the named SESSION deny-set constant. */
const int *os_sandbox_session_denied_syscalls(size_t *count_out);

/* The RESIDENT NODE's deny-set: execution + namespace/mount/kernel escape only
 * (execve/execveat, ptrace/process_vm_*, mount family, setns/unshare/pivot_root,
 * bpf/kexec/module ops, keyrings, open_by_handle_at, perf_event_open). Unlike
 * the SESSION set it does NOT deny socket/connect/clone — the node legitimately
 * opens peer sockets and spawns threads over its lifetime, so denying those
 * would kill a running node. Returns a static const array; *count_out receives
 * its length. Named the NODE STEADY-STATE deny-set constant. */
const int *os_sandbox_node_steady_denied_syscalls(size_t *count_out);

/* The TERMINAL WORKER's denied-syscall set: the session deny-set MINUS the
 * fork/vfork/clone/clone3/execve/execveat family — the confined shell must
 * spawn and exec its own children, so those are reachable, while Landlock
 * confines exactly what execve can reach (the session tmpdir and the one
 * granted shell binary). The socket/connect family, ptrace/process_vm_*,
 * mount/namespace escape, kernel surface, keyrings, and open_by_handle_at
 * stay denied. Returns a static const array; *count_out receives its
 * length. Named the TERMINAL WORKER deny-set constant. */
const int *os_sandbox_terminal_worker_denied_syscalls(size_t *count_out);

/* Install a hand-rolled seccomp-bpf DENY-list (no libseccomp): every syscall
 * in `denied` returns SECCOMP_RET_KILL_PROCESS; everything else defaults to
 * SECCOMP_RET_ALLOW. A deny-list (not an allow-list) is deliberate — even a
 * do-nothing glibc program touches ~20 syscall names (probe 3). When
 * `deny_exec_mmap` is true, an arg-filter also KILLs mmap/mprotect/
 * pkey_mprotect calls that request PROT_EXEC (W^X). ONE-WAY. Apply AFTER
 * no_new_privs and AFTER every other one-time setup (Landlock, PTY, clone),
 * since those need syscalls the deny-list would otherwise have to special-
 * case. Returns non-ok (never aborts) on failure or if built without the
 * seccomp headers. The filter is installed with the seccomp(2) syscall and
 * SECCOMP_FILTER_FLAG_TSYNC so it lands on EVERY thread of the process
 * atomically (fail-closed if a running thread carries an incompatible filter);
 * only where seccomp(2) is unavailable (kernel < 3.17, ENOSYS) does it fall
 * back to prctl(PR_SET_SECCOMP), which confines the caller + its descendants
 * alone. os_sandbox_seccomp_install_method() reports which path ran. */
struct zcl_result os_sandbox_seccomp_deny(const int *denied, size_t n_denied,
                                          bool deny_exec_mmap);

/* The RESIDENT NODE's -confine ALLOW-list: the empirically-derived steady-state
 * syscall set a booted node needs for status RPC, SELECT-only storage queries,
 * SQLite (WAL) file I/O, malloc, timers, and RNG. Everything NOT in this set is
 * SECCOMP_RET_KILL_PROCESS. Derived by running the representative confined ops
 * under a candidate filter and adding each syscall that killed the process
 * (see tests/harness/src/test_confine.c, the reproducible derivation harness).
 * Deliberately OMITS the socket family, execve/clone, ptrace, mount/namespace,
 * and kernel-surface syscalls — so a network-facing parser compromise that
 * reaches for any of them is killed. Returns a static const array; *count_out
 * receives its length. Named the NODE CONFINE allow-set constant. */
const int *os_sandbox_node_confine_allowed_syscalls(size_t *count_out);

/* The RESIDENT NODE's -confine=serving ALLOW-list: the node_confine steady
 * set (above) PLUS the socket-family syscalls a node that is actively doing
 * P2P/HTTPS/onion I/O needs (socket, bind, listen, accept, connect, send,
 * sendto, sendmsg, recv, recvfrom, recvmsg, getsockopt, setsockopt, shutdown,
 * select). Everything NOT in this set is still SECCOMP_RET_KILL_PROCESS —
 * notably execve/clone, ptrace, mount/namespace, and kernel-surface syscalls
 * stay absent, so a network-facing parser compromise still cannot pivot to
 * code execution or escape, it can just keep talking on sockets it already
 * held. Returns a static const array; *count_out receives its length. Named
 * the NODE CONFINE SERVING allow-set constant. */
const int *os_sandbox_node_confine_serving_allowed_syscalls(size_t *count_out);

/* Install a hand-rolled seccomp-bpf ALLOW-list (no libseccomp): every syscall
 * NOT in `allowed` returns SECCOMP_RET_KILL_PROCESS; the listed ones default to
 * SECCOMP_RET_ALLOW. This is the strict inverse of os_sandbox_seccomp_deny — an
 * unexpected syscall kills the whole process loudly rather than being tolerated.
 * ONE-WAY. Apply AFTER no_new_privs and AFTER every other one-time setup
 * (Landlock, fd opening), since those need syscalls the allow-list would
 * otherwise have to include. The filter prologue checks AUDIT_ARCH_X86_64 and
 * KILLs any 32-bit/compat caller. Installed via seccomp(2)+SECCOMP_FILTER_FLAG_
 * TSYNC so it binds EVERY thread atomically (fail-closed if a running thread
 * carries an incompatible filter); on a kernel without seccomp(2) (ENOSYS) it
 * falls back to prctl(PR_SET_SECCOMP) (caller + descendants only). Returns
 * non-ok (never aborts) on failure or if built without the seccomp headers. */
struct zcl_result os_sandbox_seccomp_allow(const int *allowed, size_t n_allowed);

/* Which mechanism installed the seccomp filter in this process: "tsync" (all
 * threads, via seccomp(2)+TSYNC), "prctl" (caller + descendants only, the
 * kernel-too-old fallback), or "" if no filter has been installed. */
const char *os_sandbox_seccomp_install_method(void);

/* True iff the seccomp filter was installed on every thread atomically via
 * TSYNC — i.e. seccomp coverage is process-total, not just the entering
 * thread's subtree. Backs the `sandbox` witness's seccomp_tsync field. */
bool os_sandbox_seccomp_tsync_active(void);

/* Number of threads that have PROVABLY entered a Landlock domain in this
 * process (one per successful landlock_restrict_self — whether via
 * os_sandbox_landlock_restrict() or a later os_sandbox_landlock_apply_to_
 * self() retrofit join). Unlike seccomp, Landlock has no TSYNC-style
 * all-thread install and is not retroactive, so this is the honest Landlock
 * thread-coverage count. Inherited children of a restricted thread are
 * covered but NOT counted, so this is a conservative floor. Backs the
 * `sandbox` witness's landlock_covered_threads field. */
int os_sandbox_landlock_restricted_count(void);

/* Retrofit primitive: make the CALLING thread join the Landlock domain the
 * most recent os_sandbox_landlock_restrict() call installed (typically the
 * boot thread's os_sandbox_enter(node_steady_state) at SERVICES_RUNNING).
 *
 * Why this is needed: Landlock's restrict-self only ever confines the
 * calling thread — there is no TSYNC-style all-thread install like seccomp
 * has (os_sandbox_seccomp_deny). So a domain entered by the boot thread does
 * NOT retroactively cover threads that were already running at that point.
 * This lets one of those already-running threads close that gap for itself,
 * from inside its own loop, on its own next tick — call it once per
 * iteration; it is a cheap idempotent no-op (a single thread-local branch)
 * after the first successful join on that thread. Threads SPAWNED after
 * os_sandbox_enter() need no such call: Landlock domains are inherited across
 * pthread_create/clone from an already-restricted parent.
 *
 * Also sets no_new_privs on the CALLING thread first: it is a per-thread
 * kernel attribute (unlike seccomp's TSYNC install, nothing retroactively
 * propagates it to sibling threads), and landlock_restrict_self(2) requires
 * it on the calling thread. Idempotent to call twice.
 *
 * Correctness requirement on the CALLER: only call this from a thread whose
 * remaining filesystem accesses (for the rest of the process's life) stay
 * within the grants the active profile's fs_rules cover (steady-state: the
 * datadir tree + the agent-test status dir + OS_SANDBOX_PROC_SELF_STATUS_
 * PATH). A thread that later needs to open a path outside those grants will
 * get EACCES after joining — do not wire this into a thread that does
 * arbitrary/user-configured file I/O, AND do not wire this into a dispatch
 * thread that runs OTHER subsystems' callbacks on its own stack (confining
 * the dispatcher confines every dispatched callback with no per-callback
 * opt-out — see the supervisor note below). Wired today (engine/composition/src/boot.c)
 * into the health-sweep and metrics loops only — each owns its entire loop
 * body and was audited pure, no file I/O beyond the grants above.
 * Deliberately NOT wired into file_service (market transfers read
 * user-configured paths), wallet_backup_service (configurable backup_dir),
 * disk_monitor (probes arbitrary mount paths), event_async (fans out to
 * unaudited observer callbacks), or the supervisor dispatch thread
 * (platform/modules/util/src/supervisor.c:supervisor_thread_main — the SINGLE dispatch
 * thread for every registered supervisor child; it runs every g_contracts[]
 * on_tick handler synchronously on that one thread, across every domain, so
 * confining it would confine every dispatched on_tick, not just an audited
 * one) — those remain the documented Landlock-unconfined-but-seccomp-confined
 * residual.
 *
 * Returns ZCL_OK (including the idempotent no-op case), or non-ok — never
 * fatal, callers should just skip and retry on a later tick — with:
 *
 *   OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE when the join cannot be ATTEMPTED:
 *     either a seccomp ALLOW-list is installed that omits this join's own two
 *     syscalls, prctl(2) and landlock_restrict_self(2), in which case an
 *     attempt would be SECCOMP_RET_KILL_PROCESS rather than an error (BOTH
 *     -confine allow-sets omit them today — see
 *     os_sandbox_retrofit_join_permitted()); or no steady-state Landlock
 *     domain exists yet (os_sandbox_enter() with a Landlock-enabled profile
 *     has not run, or this kernel/build lacks Landlock).
 *
 *   OS_SANDBOX_ERR_LANDLOCK_SYSCALL on a genuine syscall failure.
 *
 * On success, increments the count read by
 * os_sandbox_landlock_restricted_count(). */
struct zcl_result os_sandbox_landlock_apply_to_self(void);

/* The session child's default resource caps: AS≈256 MiB, NPROC=1,
 * FSIZE≈64 MiB, NOFILE=16, CORE=0, CPU=KEEP (caller sets a wall/CPU budget
 * per session). */
struct os_sandbox_rlimits os_sandbox_session_rlimits(void);

/* The terminal worker's resource caps: AS=256 MiB, CPU=300 s, FSIZE=1 MiB,
 * NOFILE=64, CORE=0, NPROC=KEEP. Unlike the session child the worker's
 * shell forks children, and RLIMIT_NPROC is charged against the real uid's
 * TOTAL task count — any fixed ceiling below the uid's live load would
 * block every fork inside the cage. The real process budget is enforced
 * subtree-scoped by the parent's process-group census over the session's
 * pgid (see the process-budget block below). */
struct os_sandbox_rlimits os_sandbox_terminal_worker_rlimits(void);

/* Apply the resource caps in `lim` (fields == OS_SANDBOX_RLIMIT_KEEP are
 * skipped). Returns non-ok on the first setrlimit failure. */
struct zcl_result os_sandbox_set_rlimits(const struct os_sandbox_rlimits *lim);

/* ── process budget ────────────────────────────────────────────────────────
 *
 * RLIMIT_NPROC is charged against the REAL UID, kernel-wide — never against
 * the calling process's subtree. It therefore CANNOT express "this confined
 * child tree may create at most K tasks":
 *
 *   - an absolute value N bounds the subtree at (N - the uid's current task
 *     count), which shrinks as unrelated work of the same uid starts, and
 *     reaches zero (fork -> EAGAIN before the child does anything) on a busy
 *     operator host;
 *   - a value rebased on a snapshot, (uid task count at time T) + margin, is
 *     the SAME load-dependent quantity, merely sampled at a different instant,
 *     and additionally races: every task the uid starts between T and the
 *     child's fork consumes the margin.
 *
 * There is no third option: with a per-uid counter, the subtree's real budget
 * is always (installed limit - concurrent uid load). So RLIMIT_NPROC is a
 * BACKSTOP here, not the action's process budget, and this API keeps the two
 * apart:
 *
 *   - the installed backstop is an ABSOLUTE ceiling that does not sample load
 *     (only the uid's static NPROC hard limit clamps it, since setrlimit
 *     cannot raise a hard limit);
 *   - whether the host has enough headroom left to launch at all is a separate
 *     ADMISSION decision, reported as resource exhaustion rather than folded
 *     into the child's exit status;
 *   - the action's actual process budget is enforced subtree-scoped by the
 *     parent, via os_sandbox_process_group_census() over the child's process
 *     group (a group id is inherited across fork and survives double-fork
 *     reparenting, so a fork bomb cannot escape the census).
 */
struct os_sandbox_process_budget {
    uint64_t ceiling;    /* absolute value to install on RLIMIT_NPROC        */
    uint64_t requested;  /* ceiling the caller asked for, before the clamp   */
    uint64_t hard;       /* the uid's RLIMIT_NPROC hard limit (static)       */
    uint64_t uid_tasks;  /* real uid's task count measured at admission      */
    uint64_t headroom;   /* ceiling - uid_tasks, saturating at 0             */
    uint64_t required;   /* headroom the action needs to launch at all       */
    bool     admitted;   /* headroom >= required                             */
};

/* Current task (thread) count of the real uid — RLIMIT_NPROC's accounting
 * unit. Best-effort /proc scan; entries that vanish mid-scan are skipped, so
 * the result can undercount. Returns 0 when /proc is unreadable. */
uint64_t os_sandbox_uid_task_count(void);

/* The calling process's RLIMIT_NPROC hard limit, or OS_SANDBOX_RLIMIT_KEEP
 * (== UINT64_MAX, i.e. RLIM_INFINITY) when it is unlimited or unreadable. */
uint64_t os_sandbox_nproc_hard_limit(void);

/* Pure policy: decide the backstop and the admission from explicit inputs.
 *
 * INVARIANT (the one the regression test pins): the returned `ceiling` is
 * min(requested, hard) and is INDEPENDENT of `uid_tasks`. Concurrent load of
 * the same uid moves `headroom`/`admitted` — never the installed limit. */
struct os_sandbox_process_budget os_sandbox_process_budget_at(
    uint64_t requested_ceiling, uint64_t required,
    uint64_t uid_tasks, uint64_t hard);

/* os_sandbox_process_budget_at() with the live uid task count and hard
 * limit measured now. */
struct os_sandbox_process_budget os_sandbox_process_budget_live(
    uint64_t requested_ceiling, uint64_t required);

/* Count the live processes whose process GROUP id is `pgid`. Subtree-scoped
 * and load-independent: unrelated work of the same uid is not counted. Used
 * by a parent that put its confined child in its own group (setpgid(0,0)
 * before execve) to enforce the action's real process budget. Returns 0 when
 * /proc is unreadable or the group is empty. */
uint64_t os_sandbox_process_group_census(pid_t pgid);

/* The CLONE_* flag set a session child is cloned with (== SANDBOX_SESSION_NS_
 * FLAGS). Provided as an accessor so callers need not pull in <sched.h>. */
int os_sandbox_session_ns_flags(void);

/* Write the uid/gid maps for a userns child (typically the PARENT calls this
 * for its just-cloned child: writes /proc/<pid>/uid_map + gid_map and
 * /proc/<pid>/setgroups = "deny", which is required before gid_map on modern
 * kernels). `pid` == 0 targets /proc/self. Maps a single id: inside_uid ->
 * the caller's real uid range of length 1 (pass inside_uid = real uid for an
 * identity map, or 65534 for nobody). Returns non-ok on failure. */
struct zcl_result os_sandbox_write_userns_maps(pid_t pid, unsigned inside_uid,
                                               unsigned inside_gid);

/* Probe what confinement this host actually supports, rootless, right now.
 * Forks a throwaway child for the userns probe so the calling process is not
 * mutated. Never aborts. */
struct os_sandbox_caps os_sandbox_probe_caps(void);

/* Convenience: true iff unprivileged user namespaces work here (the Probe-1
 * gate). Thin wrapper over os_sandbox_probe_caps().userns. */
bool os_sandbox_userns_available(void);

/* ── Named profiles (serve both users of the façade) ───────────────────── */

/* The full session-child confinement: no_new_privs + session rlimits +
 * Landlock scoped to `fs_rules` (the caller's per-session directory grants) +
 * the seccomp session deny-list with W^X. Namespaces (SANDBOX_SESSION_NS_
 * FLAGS) are assumed already entered by the caller's clone(). */
struct os_sandbox_profile os_sandbox_session_child_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules);

/* The mesh terminal worker's confinement: no_new_privs + the terminal-worker
 * rlimits + Landlock scoped to `fs_rules` (the per-terminal tmpdir r/w/create/
 * execute plus the one granted shell binary read/execute) + the seccomp
 * TERMINAL WORKER deny-list (session set minus the fork/exec family, so the
 * shell can spawn children) with W^X. Linux only; the stub profile refuses in
 * os_sandbox_enter() like every other profile. */
struct os_sandbox_profile os_sandbox_terminal_worker_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules);

/* The lighter node-self profile (Rung 2, os-substrate-plan §3): no_new_privs
 * + Landlock (datadir grant) + seccomp deny-list, but NO rlimit clamp and NO
 * nproc=1 (the node legitimately runs many threads). Currently a scaffold —
 * not yet wired into boot; here so the façade serves the node too. */
struct os_sandbox_profile os_sandbox_node_steady_state_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules);

/* The strict -confine node profile: no_new_privs + Landlock (rw datadir grant +
 * caller-supplied read-only extra-path grants) + a seccomp ALLOW-list (default
 * KILL_PROCESS, only os_sandbox_node_confine_allowed_syscalls permitted). No
 * rlimit clamp (the node runs many threads and a large address space). Unlike
 * os_sandbox_node_steady_state_profile (a deny-list), this is fail-fast: any
 * syscall outside the allow-set kills the process. Apply at the late
 * activation-ready boundary once all listen sockets/files/threads are up. */
struct os_sandbox_profile os_sandbox_node_confine_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules);

/* The -confine=serving node profile: identical to os_sandbox_node_confine_
 * profile (no_new_privs + Landlock + a seccomp ALLOW-list, fail-fast) except
 * the allow-set is os_sandbox_node_confine_serving_allowed_syscalls — the
 * strict set plus the socket family a node doing real P2P/HTTPS/onion I/O
 * needs at its first accept()/recv()/connect() after entering the strict
 * -confine profile (which omits sockets entirely and SIGSYS-kills a serving
 * node on first use). Apply at the same late activation-ready boundary. */
struct os_sandbox_profile os_sandbox_node_confine_serving_profile(
    const struct os_sandbox_path_rule *fs_rules, size_t n_fs_rules);

/* Apply a profile's enabled builders in the ONE correct order:
 *     1. no_new_privs   (unlocks rootless Landlock + seccomp)
 *     2. rlimits        (cheap, and cannot be re-raised after seccomp)
 *     3. Landlock       (fds the child needs are already pre-opened by caller)
 *     4. seccomp        (LAST — the setup above needs syscalls a deny-list
 *                        would have to special-case)
 * Namespaces are NOT applied here — the caller must have entered them via
 * clone()/unshare() first. ONE-WAY: there is no os_sandbox_exit(). On success
 * os_sandbox_active() reads true thereafter. Returns the first failing
 * builder's non-ok result (with the seccomp step, "failure" can mean the
 * process is already dead — a denied syscall kills it). */
struct zcl_result os_sandbox_enter(const struct os_sandbox_profile *p);

/* True after a successful os_sandbox_enter() in this process. */
bool os_sandbox_active(void);

/* The `name` of the profile that entered, or NULL if none has. Introspection
 * only (backs the `sandbox` dumpstate subsystem). */
const char *os_sandbox_active_profile_name(void);

/* True iff this build was compiled with the seccomp headers (so a seccomp
 * filter install is reachable). Cheap, non-forking — unlike os_sandbox_probe_
 * caps() it does not fork a child. */
bool os_sandbox_seccomp_supported(void);

/* ── Confinement witness: is this process actually confined, and where can
 *    it still read/write? ────────────────────────────────────────────────
 *
 * os_sandbox_active() answers "did a profile enter", which conflates two very
 * different operator situations: confinement was never REQUESTED (the default,
 * and fine) versus confinement WAS requested and the process is running
 * UNCONFINED anyway (the -confine contract's unconfined-but-loud degrade path,
 * engine/composition/src/boot.c:sr_confine_enter). The accessors below separate them and
 * expose the grant set the Landlock domain was actually built from, so an
 * operator (and any subsystem about to open a path outside the datadir) can
 * see the boundary instead of inferring it from an EACCES. */

/* Max fs grants retained for introspection, and the per-grant path bound.
 * Boot's grant builder emits at most 5; the headroom is for future profiles.
 * A grant set that does not FIT is recorded as incomplete, which makes
 * os_sandbox_path_is_granted() answer "granted" for everything (see below). */
#define OS_SANDBOX_MAX_RECORDED_GRANTS 8
#define OS_SANDBOX_GRANT_PATH_MAX      512

/* Record that confinement was REQUESTED under `profile_name`, BEFORE the
 * attempt. Call once from the boot path; the name is copied into static
 * storage (bounded, never allocated). Idempotent — a second call overwrites. */
void os_sandbox_note_requested(const char *profile_name);

/* The Landlock ABI as observed at the moment the domain was built, WITHOUT
 * re-probing. Use this — never os_sandbox_landlock_abi() — from any code that
 * may run after confinement is applied: the probe issues
 * landlock_create_ruleset(2), which is NOT in either -confine seccomp
 * allow-set, so probing from inside a confined process is
 * SECCOMP_RET_KILL_PROCESS. Returns -1 when no domain was ever built. */
int os_sandbox_landlock_abi_cached(void);

/* True iff an os_sandbox_landlock_apply_to_self() retrofit join would be SAFE
 * to attempt right now. It is unsafe when a seccomp ALLOW-list is installed
 * that omits prctl(2) and/or landlock_restrict_self(2) — the join would then
 * be killed by the filter rather than merely failing. Both -confine allow-sets
 * omit them today, so a thread wired to the retrofit join must consult this
 * before calling. Always true when no allow-list is installed. */
bool os_sandbox_retrofit_join_permitted(void);

/* The profile name passed to os_sandbox_note_requested(), or "" if
 * confinement was never requested in this process. */
const char *os_sandbox_requested_profile(void);

/* True iff NEITHER enforcement mechanism is live — no Landlock domain and no
 * seccomp filter — i.e. this process is running wide open. The headline field
 * of the `confinement` witness. True both when confinement was never requested
 * AND when it was requested and failed to apply; compare with
 * os_sandbox_requested_profile() to tell those apart. */
bool os_sandbox_unconfined(void);

/* How many fs grants the active Landlock domain was built from (0 when no
 * Landlock domain is enforced). */
size_t os_sandbox_fs_grant_count(void);

/* The i-th recorded fs grant path (canonicalized at record time), or NULL if
 * `i` is out of range. `allow_read`/`allow_write` (either may be NULL) receive
 * the access the grant carries. */
const char *os_sandbox_fs_grant_at(size_t i, bool *allow_read, bool *allow_write);

/* True iff `path` is inside the active Landlock grant set with at least the
 * requested access — i.e. an open() of it should NOT be refused by the kernel
 * filesystem restriction.
 *
 * Deliberately FAIL-OPEN: returns true when no Landlock domain is enforced,
 * when the grant set could not be recorded faithfully, or when `path` is NULL/
 * relative. A false answer therefore means "provably outside the grants", so a
 * caller may turn it into a refusal without risking a spurious one. This is a
 * pure string predicate over the recorded grant roots plus one best-effort
 * realpath() — it issues no open() and cannot itself trip the sandbox. */
bool os_sandbox_path_is_granted(const char *path, bool need_write);

/* Explain, in operator language, why `path` is outside the active filesystem
 * restriction. Writes a NUL-terminated message into `out` and returns its
 * length; writes "" and returns 0 when the path IS granted (or nothing is
 * enforced), so the call doubles as the predicate:
 *
 *     char why[256];
 *     if (os_sandbox_explain_denied_path(p, false, why, sizeof(why)))
 *         REFUSE("confinement", "%s", why);
 *
 * The message names the restriction interface (Landlock + ABI), the active
 * profile, and the grant that is missing — so the failure is a typed refusal
 * rather than a bare EACCES that names nothing. Never allocates. */
size_t os_sandbox_explain_denied_path(const char *path, bool need_write,
                                      char *out, size_t out_sz);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool confinement_dump_state_json(struct json_value *out, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PLATFORM_OS_SANDBOX_H */
