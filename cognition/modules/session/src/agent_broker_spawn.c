/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Standing the confined child up. This file is where the boundary is BUILT; the
 * rest of the broker only relies on it already being there.
 *
 * THE ONE RULE HERE: every layer is applied by the PARENT, in the forked child,
 * before execve — rlimits, no_new_privs, Landlock and the stage-1 seccomp
 * filter all survive execve, so by the time the agent's own first instruction
 * runs the kernel is already refusing on its behalf. A hostile agent cannot
 * decline to be sandboxed because it is never asked. See the ordering note atop
 * agent_broker.c for why the grant is built after this returns, never before.
 */

#if defined(__linux__)
#define _GNU_SOURCE  /* setgroups, execve with an empty envp */
#endif

#include "session/agent_broker.h"

#include <errno.h>
#include <string.h>
#if defined(__linux__)
#include "base/log_macros.h"
#include "base/result.h"
#include "platform/os_sandbox.h"
#include <fcntl.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#define BROKER_TAG "agent.broker"

/* The child receives the connected socket as this descriptor. Fixed, so the
 * child needs no argument naming it — one less thing on a command line. */
#define AGENT_CHILD_SOCKET_FD 3

/* ── spawning the confined child ────────────────────────────────────────── */

#if !defined(__linux__)
bool agent_broker_spawn_confined(const struct agent_spawn_request *req,
                                 struct agent_spawn_result *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
#if defined(_WIN32)
    /* Validation is pure and remains available, but no valid request may
     * advance into identity, group, path, socket, or process activity until
     * the restricted-token + Job Object sandbox is qualified. */
    if (!req || !result || !req->self_exe || !req->scratch_dir ||
        !req->script || !mvap_param_is_safe(req->script)) {
        errno = EINVAL;
        return false;
    }
#else
    (void)req;
#endif
    errno = ENOTSUP;
    return false;
}
#else

/* Stage-1 seccomp: the confined agent's allow-set PLUS exactly what a fresh
 * program start needs to reach main(). It is wider than stage 2 only in that
 * it permits the ONE execve this path performs and the loader/startup syscalls
 * that follow it — every escape class (sockets, clone, ptrace, mount,
 * namespaces, bpf, keyrings) is absent from both. */
static const int g_stage1_extra[] = {
    __NR_execve,
#ifdef __NR_execveat
    __NR_execveat,
#endif
    __NR_arch_prctl, __NR_set_tid_address, __NR_set_robust_list,
#ifdef __NR_rseq
    __NR_rseq,
#endif
    __NR_prctl,
    /* The child installs stage 2 with seccomp(SECCOMP_SET_MODE_FILTER) — the
     * TSYNC path os_sandbox prefers — and falls back to prctl(PR_SET_SECCOMP)
     * only if that fails. Both must be reachable or the child is SIGSYS-killed
     * for trying to confine itself FURTHER. Granting them costs nothing: a
     * seccomp filter can only ever remove reach, never restore it. */
    __NR_seccomp,
};

/* Landlock stage 1, applied by the PARENT so it is irreversible for the child.
 * The grants are: the child's own scratch directory, its /proc/self, and the
 * read+execute set the dynamic loader needs to start the binary at all. The
 * datadir, the wallet, the RPC cookie, $HOME and /etc are all ABSENT, which is
 * what the adversarial test measures. */
static size_t spawn_build_grants(const struct agent_spawn_request *req,
                                 struct os_sandbox_path_rule *rules,
                                 size_t cap)
{
    size_t n = 0;
    if (n < cap && req->scratch_dir)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = req->scratch_dir, .allow_read = true,
            .allow_write = true, .allow_create = true };
    if (n < cap)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = OS_SANDBOX_PROC_SELF_PATH, .allow_read = true };
    if (n < cap && req->self_exe)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = req->self_exe, .allow_read = true, .allow_execute = true };

    /* The loader set. Each is granted only if it exists, so this stays correct
     * on a host with a different lib layout. */
    static const char *const loader_dirs[] = { "/usr/lib", "/lib", "/lib64" };
    for (size_t i = 0; i < sizeof(loader_dirs) / sizeof(loader_dirs[0]); i++) {
        struct stat st;
        if (n < cap && stat(loader_dirs[i], &st) == 0)
            rules[n++] = (struct os_sandbox_path_rule){
                .path = loader_dirs[i], .allow_read = true,
                .allow_execute = true };
    }
    struct stat st;
    if (n < cap && stat("/etc/ld.so.cache", &st) == 0)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = "/etc/ld.so.cache", .allow_read = true };
    return n;
}

/* Resource caps for the agent: one process (so it cannot fork a helper even if
 * clone were reachable), no core dump (a dump would spill inherited memory to
 * disk), a bounded address space, and a modest fd ceiling.
 *
 * ON THE ADDRESS-SPACE CAP: the confined agent is THIS binary re-executed, and
 * which binary that is depends on who is brokering — the ~20 MB node, or the
 * ~90 MB test binary that proves this boundary. A cap that does not clear the
 * image is not a tight sandbox, it is a startup crash: measured on the test
 * binary, the child SIGSEGVs inside the loader anywhere below ~896 MB, before
 * its first instruction and with no report to say why. The cap exists to stop a
 * runaway allocation, so it is set well clear of the largest image that uses
 * it — shrink it only against a measurement, never against a guess. */
/* The child-side privilege drop. Groups first: dropping the uid before the
 * groups would make setgroups impossible and silently leave supplementary
 * groups behind. EPERM is the expected unprivileged answer at each step and
 * continues; anything else leaves the child privileged with the confinement
 * grant already half-applied, so each failure exits by code. */
static void spawn_drop_privileges(uid_t uid, gid_t gid)
{
    if (setgroups(0, NULL) != 0 && errno != EPERM)
        _exit(91);
    if (setgid(gid) != 0 && errno != EPERM)
        _exit(92);
    if (setuid(uid) != 0 && errno != EPERM)
        _exit(95);
}

static struct os_sandbox_rlimits spawn_rlimits(void)
{
    return (struct os_sandbox_rlimits){
        .as_bytes    = (uint64_t)2048u * 1024u * 1024u,
        .cpu_seconds = 30,
        .nproc       = 1,
        .fsize_bytes = (uint64_t)16u * 1024u * 1024u,
        .nofile      = 32,
        .core_bytes  = 0,
    };
}

/* The spawn argument gate. Each LOG_FAIL below both reports and returns
 * false, so a caller that gets past this helper holds a request that is
 * fully present and whose script token is safe. */
static bool spawn_request_is_valid(const struct agent_spawn_request *req,
                                   struct agent_spawn_result *result)
{
    if (!req || !result || !req->self_exe || !req->scratch_dir || !req->script)
        LOG_FAIL(BROKER_TAG, "null argument to spawn");
    if (!mvap_param_is_safe(req->script))
        LOG_FAIL(BROKER_TAG, "script name '%s' is not a safe token",
                 req->script);
    return true;
}

/* The socket pair the agent will inherit, with the broker end armed for
 * credential passing. */
static bool spawn_open_peer_socket(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        LOG_FAIL(BROKER_TAG, "socketpair failed: %s", strerror(errno));

    /* Before the fork, so every byte the child ever sends arrives with the
     * kernel's own statement of which process sent it. SO_PEERCRED on a pair
     * would name US on both ends and could not tell the two apart. */
    int passcred = 1;
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &passcred,
                   sizeof(passcred)) != 0) {
        (void)close(sv[0]);
        (void)close(sv[1]);
        LOG_FAIL(BROKER_TAG, "SO_PASSCRED on the broker end failed: %s",
                 strerror(errno));
    }
    return true;
}

/* The child end of the pair, moved onto the fixed descriptor. */
static void spawn_child_claim_socket(int sock)
{
    if (sock != AGENT_CHILD_SOCKET_FD) {
        if (dup2(sock, AGENT_CHILD_SOCKET_FD) < 0)
            _exit(90);
        (void)close(sock);
    }
    /* The socket must survive execve; everything else must not. */
    (void)fcntl(AGENT_CHILD_SOCKET_FD, F_SETFD, 0);
}

/* The requested uid/gid drop, then the rlimits and no_new_privs that must
 * be in place before execve. */
static void spawn_child_apply_identity_and_limits(
    const struct agent_spawn_request *req)
{
    /* uid drop, when this process has the authority to do one. */
    if (req->confined_uid != 0 && req->confined_uid != geteuid())
        spawn_drop_privileges(req->confined_uid, req->confined_gid);

    struct os_sandbox_rlimits lim = spawn_rlimits();
    if (!zcl_result_is_ok(os_sandbox_set_rlimits(&lim)))
        _exit(93);
    if (!os_sandbox_no_new_privs())
        _exit(94);
}

/* The Landlock domain, built from spawn_build_grants' rules. */
static void spawn_child_apply_landlock(const struct agent_spawn_request *req)
{
    struct os_sandbox_path_rule rules[8];
    size_t n = spawn_build_grants(req, rules, 8);
    struct zcl_result lr = os_sandbox_landlock_restrict(rules, n);
    /* A kernel without Landlock degrades loudly rather than pretending:
     * the child reports landlock_applied=false at handshake and the
     * operator sees it in `metaverse agent status`. */
    if (!zcl_result_is_ok(lr) && lr.code != OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE)
        _exit(95);
}

/* Copies the confined allow-set out and extends it with g_stage1_extra. */
static void spawn_child_install_stage1_seccomp(void)
{
    size_t n_base = 0;
    const int *base = agent_confined_allowed_syscalls(&n_base);
    size_t n_extra = sizeof(g_stage1_extra) / sizeof(g_stage1_extra[0]);
    int stage1[320];
    if (n_base + n_extra > sizeof(stage1) / sizeof(stage1[0]))
        _exit(96);
    memcpy(stage1, base, n_base * sizeof(int));
    memcpy(stage1 + n_base, g_stage1_extra, n_extra * sizeof(int));
    struct zcl_result sr = os_sandbox_seccomp_allow(stage1,
                                                    n_base + n_extra);
    if (!zcl_result_is_ok(sr) && sr.code != OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE)
        _exit(97);
}

/* execve into the confined agent; never returns. */
static void spawn_child_exec_agent(const struct agent_spawn_request *req)
{
    /* argv carries the mode, the script name, the scratch dir and, when the
     * broker set one, the canary path to probe. envp is EMPTY — that is
     * what makes /proc/<pid>/environ carry nothing of the operator's
     * session, and no grant material exists in either. The canary is an
     * instruction to TRY a path, not permission to reach it: the Landlock
     * domain built above decides that, and it was built before this line. */
    char *argv[6];
    size_t a = 0;
    argv[a++] = (char *)req->self_exe;
    argv[a++] = (char *)"--metaverse-agent-confined";
    argv[a++] = (char *)req->script;
    argv[a++] = (char *)req->scratch_dir;
    if (req->canary && req->canary[0])
        argv[a++] = (char *)req->canary;
    argv[a] = NULL;
    char *const envp[] = { NULL };
    execve(req->self_exe, argv, envp);
    _exit(98);
}

/* The forked child's whole path from close(sv[0]) to execve, in the order
 * the boundary requires; never returns. */
static void spawn_confined_child(const struct agent_spawn_request *req,
                                 int sv[2])
{
    (void)close(sv[0]);
    spawn_child_claim_socket(sv[1]);
    spawn_child_apply_identity_and_limits(req);
    spawn_child_apply_landlock(req);
    spawn_child_install_stage1_seccomp();
    spawn_child_exec_agent(req);
}

bool agent_broker_spawn_confined(const struct agent_spawn_request *req,
                                 struct agent_spawn_result *result)
{
    if (!spawn_request_is_valid(req, result))
        return false;
    memset(result, 0, sizeof(*result));

    int sv[2];
    if (!spawn_open_peer_socket(sv))
        return false;

    pid_t pid = fork();
    if (pid < 0) {
        (void)close(sv[0]);
        (void)close(sv[1]);
        LOG_FAIL(BROKER_TAG, "fork failed: %s", strerror(errno));
    }

    if (pid == 0) {
        /* ── the child, still our code, still trusted ─────────────────── */
        spawn_confined_child(req, sv);
    }

    (void)close(sv[1]);
    result->pid  = pid;
    result->sock = sv[0];
    return true;
}
#endif
