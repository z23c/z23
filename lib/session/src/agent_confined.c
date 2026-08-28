/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The confined agent: the UNTRUSTED side of the boundary.
 *
 * Everything in this file runs after the broker has already sandboxed it (see
 * the ordering note atop agent_broker.c). Nothing here is load-bearing for
 * security — the kernel is already refusing on this process's behalf — so this
 * file is free to be deliberately HOSTILE. The `hostile`, `execprobe` and
 * `sockprobe` scripts below do exactly what a compromised agent would do: reach
 * for the datadir, the wallet, the RPC cookie, an arbitrary file, a new socket,
 * and a new program. Each one is expected to FAIL, and the failure mode is
 * recorded so the test can assert it came from the kernel (EACCES / SIGSYS)
 * rather than from this code politely declining.
 *
 * That is the point: a boundary you only test with a well-behaved client is not
 * a boundary, it is an agreement.
 *
 * The one thing this file must NOT do is call a syscall outside the allow-list
 * on a normal path — that would SIGSYS-kill the agent for a benign reason and
 * make a real denial indistinguishable from a bug. Notably it must never call
 * os_sandbox_landlock_abi(): that probe issues landlock_create_ruleset(2),
 * which is absent from the allow-set. The Landlock ABI is reported by the
 * broker, which built the domain and knows it.
 */

#define _GNU_SOURCE  /* execve/socket probes — must precede every include */

#include "session/agent_broker.h"

#include "base/log_macros.h"
#include "base/result.h"
#include "platform/os_sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define AGENT_TAG "agent.confined"
#define AGENT_CHILD_SOCKET_FD 3

#if defined(_WIN32)

const int *agent_confined_allowed_syscalls(size_t *count_out)
{
    if (count_out)
        *count_out = 0;
    return NULL;
}

bool agent_confined_enter(const char *scratch_dir, uid_t want_uid,
                          gid_t want_gid, struct agent_confine_report *out)
{
    (void)scratch_dir;
    (void)want_uid;
    (void)want_gid;
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->landlock_abi = -1;
    out->uid_posture = AGENT_CONFINE_UID_UNKNOWN;
    snprintf(out->seccomp_method, sizeof(out->seccomp_method), "%s",
             "windows-sandbox-unqualified");
    errno = ENOTSUP;
    return false;
}

int agent_confined_mode_main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    errno = ENOTSUP;
    return 126;
}

#else

/* The confined agent's allow-list IS the node's strict -confine allow-set. That
 * set was empirically derived and is regression-covered by test_confine, and it
 * already omits every escape class this boundary cares about: execve/execveat,
 * the whole socket family, clone/fork, ptrace/process_vm_*, mount/setns/
 * unshare/pivot_root, bpf/kexec/module ops, keyrings, open_by_handle_at.
 * Reusing it rather than deriving a second, parallel list means one set to keep
 * correct instead of two that can drift apart.
 *
 * openat IS permitted, deliberately. The filesystem boundary is Landlock's job,
 * so a forbidden open must fail as an attributable EACCES an operator can read
 * — not as an unattributable SIGSYS that names no path. */
const int *agent_confined_allowed_syscalls(size_t *count_out)
{
    return os_sandbox_node_confine_allowed_syscalls(count_out);
}

/* ── observation, not assertion ─────────────────────────────────────────── */

/* Try to open `path` read-only. Returns 0 when it OPENED (a hole), or the
 * errno that refused it. */
static int probe_open(const char *path)
{
    if (!path || !path[0])
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)close(fd);
        return 0;
    }
    return errno;
}

static const char *errno_name(int e)
{
    switch (e) {
    case 0:       return "OPENED";
    case EACCES:  return "EACCES";
    case EPERM:   return "EPERM";
    case ENOENT:  return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case -1:      return "SKIPPED";
    default:      return "OTHER";
    }
}

bool agent_confined_enter(const char *scratch_dir, uid_t want_uid,
                          gid_t want_gid, struct agent_confine_report *out)
{
    (void)want_gid;
    if (!out)
        LOG_FAIL(AGENT_TAG, "null report");
    memset(out, 0, sizeof(*out));

    out->ran_as_uid = getuid();
    out->ran_as_gid = getgid();
    out->landlock_abi = -1;      /* the broker reports this; probing here dies */

    /* Did a uid switch actually happen? Compare against the owner of the
     * scratch directory, which the BROKER created — no argv word needed, and
     * it is an observation rather than a claim. `want_uid` is only a hint for
     * the case where the broker named a target. */
    struct stat st;
    if (scratch_dir && stat(scratch_dir, &st) == 0) {
        if (st.st_uid != out->ran_as_uid)
            out->uid_posture = AGENT_CONFINE_SEPARATE_UID;
        else
            out->uid_posture = AGENT_CONFINE_SAME_UID;
    } else if (want_uid != 0 && want_uid == out->ran_as_uid) {
        out->uid_posture = AGENT_CONFINE_SEPARATE_UID;
    } else {
        out->uid_posture = AGENT_CONFINE_UID_UNKNOWN;
    }

    /* rlimits: the broker set NPROC=1 and CORE=0 before exec. Read them back
     * rather than assuming the call succeeded. */
    struct rlimit rl;
    out->rlimits_applied = getrlimit(RLIMIT_NPROC, &rl) == 0 && rl.rlim_cur <= 1;

    /* Landlock: measured, not assumed. If a canonical outside path is refused
     * with EACCES then a domain is enforced on this process. */
    int e = probe_open("/etc/passwd");
    out->landlock_applied = (e == EACCES);
    out->fs_grants = 0;

    /* Stage 2: narrow the seccomp filter to drop the execve the broker had to
     * leave open for the one exec that started us. Filters stack, so this can
     * only ever remove reach. A failure here is not fatal — stage 1 is already
     * installed and is the boundary — but it IS reported. */
    size_t n = 0;
    const int *allowed = agent_confined_allowed_syscalls(&n);
    struct zcl_result sr = os_sandbox_seccomp_allow(allowed, n);
    out->seccomp_applied = zcl_result_is_ok(sr);
    snprintf(out->seccomp_method, sizeof(out->seccomp_method), "%s",
             os_sandbox_seccomp_install_method());
    return true;
}

/* ── the self-report the broker reads back ──────────────────────────────── */

/* Read this process's own environ and cmdline and report their SIZE and
 * whether a marker appears. The macro spelling of the /proc/self path is the
 * one lib/platform blesses, so the raw-/proc/self ratchet stays clean. */
static size_t read_own_proc(const char *leaf, char *buf, size_t cap)
{
    char path[64];
    snprintf(path, sizeof(path), "%s/%s", OS_SANDBOX_PROC_SELF_PATH, leaf);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t got = read(fd, buf, cap - 1);
    (void)close(fd);
    if (got <= 0) {
        buf[0] = '\0';
        return 0;
    }
    /* environ and cmdline are NUL-separated; render them printable so the
     * report is greppable. */
    for (ssize_t i = 0; i < got; i++)
        if (buf[i] == '\0')
            buf[i] = ' ';
    buf[got] = '\0';
    return (size_t)got;
}

static void write_report(const char *scratch_dir,
                         const struct agent_confine_report *rep,
                         const char *canary, int canary_errno,
                         const char *extra)
{
    if (!scratch_dir)
        return;
    char env[4096] = { 0 }, cmd[1024] = { 0 };
    size_t env_len = read_own_proc("environ", env, sizeof(env));
    size_t cmd_len = read_own_proc("cmdline", cmd, sizeof(cmd));

    char path[512];
    snprintf(path, sizeof(path), "%s/agent_report.json", scratch_dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;

    char doc[6144];
    int n = snprintf(doc, sizeof(doc),
        "{\"pid\":%d,\"uid\":%u,\"gid\":%u,\"euid\":%u,"
        "\"uid_posture\":\"%s\",\"landlock_applied\":%s,"
        "\"seccomp_applied\":%s,\"seccomp_method\":\"%s\","
        "\"rlimits_applied\":%s,\"environ_bytes\":%zu,\"cmdline_bytes\":%zu,"
        "\"environ\":\"%s\",\"cmdline\":\"%s\","
        "\"canary\":\"%s\",\"canary_result\":\"%s\"%s%s}\n",
        (int)getpid(), (unsigned)rep->ran_as_uid, (unsigned)rep->ran_as_gid,
        (unsigned)geteuid(),
        rep->uid_posture == AGENT_CONFINE_SEPARATE_UID ? "separate_uid"
            : rep->uid_posture == AGENT_CONFINE_SAME_UID ? "same_uid"
                                                         : "unknown",
        rep->landlock_applied ? "true" : "false",
        rep->seccomp_applied ? "true" : "false", rep->seccomp_method,
        rep->rlimits_applied ? "true" : "false", env_len, cmd_len, env, cmd,
        canary ? canary : "", errno_name(canary_errno),
        extra ? "," : "", extra ? extra : "");
    if (n > 0 && (size_t)n < sizeof(doc)) {
        if (write(fd, doc, (size_t)n) != n)
            LOG_WARN(AGENT_TAG, "short write of %s", path);
    }
    (void)close(fd);
}

/* ── the typed client ───────────────────────────────────────────────────── */

static bool client_call(int fd, const struct mvap_request *req,
                        struct mvap_response *resp)
{
    uint8_t out[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t n = mvap_request_encode(req, out, sizeof(out));
    if (n == 0)
        LOG_FAIL(AGENT_TAG, "could not encode a %s request",
                 mvap_verb_name(req->verb));

    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, out + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            LOG_FAIL(AGENT_TAG, "write to the broker failed: %s",
                     strerror(errno));
        }
        sent += (size_t)w;
    }

    uint8_t prefix[MVAP_FRAME_PREFIX];
    size_t got = 0;
    while (got < sizeof(prefix)) {
        ssize_t r = read(fd, prefix + got, sizeof(prefix) - got);
        if (r == 0)
            LOG_FAIL(AGENT_TAG, "broker closed the connection");
        if (r < 0) {
            if (errno == EINTR)
                continue;
            LOG_FAIL(AGENT_TAG, "read from the broker failed: %s",
                     strerror(errno));
        }
        got += (size_t)r;
    }
    uint32_t rec = mvap_frame_length(prefix, sizeof(prefix));
    if (rec == 0)
        LOG_FAIL(AGENT_TAG, "broker declared an out-of-bounds frame");

    uint8_t buf[MVAP_MAX_FRAME];
    got = 0;
    while (got < rec) {
        ssize_t r = read(fd, buf + got, rec - got);
        if (r == 0)
            LOG_FAIL(AGENT_TAG, "broker closed mid-frame");
        if (r < 0) {
            if (errno == EINTR)
                continue;
            LOG_FAIL(AGENT_TAG, "read from the broker failed: %s",
                     strerror(errno));
        }
        got += (size_t)r;
    }
    if (!mvap_response_decode(buf, rec, resp))
        LOG_FAIL(AGENT_TAG, "broker response did not decode");

    /* stdout is the demo transcript; the broker's own log is separate. */
    printf("agent: %-16s request_id=%u -> %s %s\n", mvap_verb_name(resp->verb),
           resp->request_id, mvap_status_name(resp->status), resp->body);
    (void)fflush(stdout);
    return true;
}

static void req_init(struct mvap_request *r, uint32_t verb, uint32_t id)
{
    memset(r, 0, sizeof(*r));
    r->verb = verb;
    r->request_id = id;
}

/* ── the scripts ────────────────────────────────────────────────────────── */

/* Probe every asset the confined agent must NOT be able to reach directly.
 * Each result is the kernel's errno, so the test can require EACCES (a
 * Landlock refusal) rather than accepting ENOENT (which would prove only that
 * the file happened to be missing). */
static void script_hostile(int fd, const char *scratch_dir, const char *canary,
                           const struct agent_confine_report *rep)
{
    static const char *const targets[] = {
        "/etc/passwd", "/etc/shadow", "/root", "/home",
    };
    char extra[1024];
    size_t off = 0;
    off += (size_t)snprintf(extra + off, sizeof(extra) - off, "\"probes\":{");
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        int e = probe_open(targets[i]);
        off += (size_t)snprintf(extra + off, sizeof(extra) - off,
                                "%s\"%s\":\"%s\"", i ? "," : "", targets[i],
                                errno_name(e));
        if (off >= sizeof(extra))
            break;
    }
    if (off < sizeof(extra))
        (void)snprintf(extra + off, sizeof(extra) - off, "}");

    int ce = probe_open(canary);
    write_report(scratch_dir, rep, canary, ce, extra);

    /* Ask for a property the grant does not cover, and an action it does not
     * allow. Both must be refused by the BROKER even though the wire accepted
     * them — the agent is allowed to ask; it is not allowed to be answered. */
    struct mvap_request req;
    struct mvap_response resp;
    req_init(&req, MVAP_VERB_INSPECT, 9001);
    agent_broker_fixture_property_id(1, req.property_id);
    (void)client_call(fd, &req, &resp);

    req_init(&req, MVAP_VERB_TRANSFER, 9002);
    agent_broker_fixture_property_id(0, req.property_id);
    (void)snprintf(req.param, sizeof(req.param), "someone-else");
    (void)client_call(fd, &req, &resp);
}

static void script_inspect(int fd, const char *scratch_dir, const char *canary,
                           const struct agent_confine_report *rep)
{
    write_report(scratch_dir, rep, canary, probe_open(canary), NULL);

    struct mvap_request req;
    struct mvap_response resp;
    req_init(&req, MVAP_VERB_INSPECT, 1);
    agent_broker_fixture_property_id(0, req.property_id);
    (void)client_call(fd, &req, &resp);

    req_init(&req, MVAP_VERB_LIST, 2);
    req.kind = MVAP_KIND_CONTENT;
    (void)client_call(fd, &req, &resp);

    req_init(&req, MVAP_VERB_HOST, 3);
    agent_broker_fixture_property_id(0, req.property_id);
    (void)client_call(fd, &req, &resp);

    /* Same request_id twice: the second must return the FIRST outcome and mint
     * no second receipt. */
    req_init(&req, MVAP_VERB_HOST, 3);
    agent_broker_fixture_property_id(0, req.property_id);
    (void)client_call(fd, &req, &resp);
}

int agent_confined_mode_main(int argc, char **argv)
{
    /* argv: <exe> --metaverse-agent-confined <script> <scratch-dir> [canary] */
    if (argc < 4) {
        (void)fprintf(stderr,  // obs-ok:confined-child-no-event-bus
                      "usage: %s --metaverse-agent-confined <script> "
                      "<scratch-dir> [canary-path]\n",
                      argc > 0 ? argv[0] : "zclassic23");
        return 2;
    }
    const char *script  = argv[2];
    const char *scratch = argv[3];
    const char *canary  = argc > 4 ? argv[4] : "";

    if (!mvap_param_is_safe(script)) {
        (void)fprintf(stderr, "confined agent: script '%s' is not a safe token\n",  // obs-ok:confined-child-no-event-bus
                      script);
        return 2;
    }

    struct agent_confine_report rep;
    if (!agent_confined_enter(scratch, 0, 0, &rep))
        return 3;

    /* The two probes that END the process cannot share a run with anything
     * else — a SIGSYS kill has no "and then". They are their own scripts. */
    if (strcmp(script, "execprobe") == 0) {
        write_report(scratch, &rep, canary, probe_open(canary), NULL);
        char *const a[] = { (char *)"/bin/sh", NULL };
        char *const e[] = { NULL };
        execve("/bin/sh", a, e);
        /* Reached only if execve was neither seccomp-killed nor Landlock
         * refused: that is a HOLE, and the exit code says so. */
        (void)fprintf(stderr, "confined agent: execve survived, errno=%d (%s)\n",  // obs-ok:confined-child-no-event-bus
                      errno, errno_name(errno));
        return errno == EACCES || errno == EPERM ? 40 : 41;
    }
    if (strcmp(script, "sockprobe") == 0) {
        write_report(scratch, &rep, canary, probe_open(canary), NULL);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0) {
            (void)close(s);
            return 42;                    /* the allow-list let socket() through */
        }
        return 43;                        /* refused, but not killed */
    }

    int fd = AGENT_CHILD_SOCKET_FD;
    if (strcmp(script, "hostile") == 0)
        script_hostile(fd, scratch, canary, &rep);
    else
        script_inspect(fd, scratch, canary, &rep);

    (void)close(fd);
    return 0;
}

#endif
