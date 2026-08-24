/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The closed S4 benchmark/reproduction executor (see the header
 *          for the contract: observation, never truth; registry fixed
 *          actions only; confinement or refusal). */

#include "services/zcode_benchmark_executor.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/clock.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#include "vcs/vcs_object.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXEC_PATH_MAX 4096

static const uint8_t result_v1_magic[8] = {'Z','C','B','E','N','C','\r','\n'};
static const uint8_t result_v2_magic[8] = {'Z','C','B','E','N','2','\r','\n'};

static bool exec_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static bool exec_root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

/* ── CAS load helpers (load raw + parse + rederived-root agreement) ──── */

static bool exec_cas_load(const char *workspace, const uint8_t root[32],
                          uint8_t **wire, size_t *wire_len)
{
    return vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

static bool exec_load_study(const char *workspace, const uint8_t root[32],
                            struct vcs_zcode_study_spec_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = exec_cas_load(workspace, root, &wire, &len) &&
        vcs_zcode_study_spec_parse(wire, len, out) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_validate(out) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_root(out, checked) == VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked, root, 32) == 0;
    free(wire);
    return ok;
}

static bool exec_load_task(const char *workspace, const uint8_t root[32],
                           struct vcs_zcode_task_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = exec_cas_load(workspace, root, &wire, &len) &&
        vcs_zcode_task_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, root, 32) == 0;
    free(wire);
    return ok;
}

/* Load one candidate with parse + rederived-root agreement. */
static bool exec_load_candidate(const char *workspace, const uint8_t root[32],
                                struct vcs_zcode_candidate_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = exec_cas_load(workspace, root, &wire, &len) &&
        vcs_zcode_candidate_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, root, 32) == 0;
    free(wire);
    return ok;
}

static bool exec_load_method(const char *workspace, const uint8_t root[32],
                             struct vcs_zcode_benchmark_method_v1 *out,
                             uint8_t *wire_out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = exec_cas_load(workspace, root, &wire, &len) &&
        len == VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES &&
        vcs_zcode_benchmark_method_parse(wire, len, out) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_method_validate(out) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_method_root(out, checked) ==
            VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked, root, 32) == 0;
    if (ok && wire_out)
        memcpy(wire_out, wire, VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES);
    free(wire);
    return ok;
}

static bool exec_load_policy(const char *workspace, const uint8_t root[32],
                             struct vcs_zcode_environment_policy_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = exec_cas_load(workspace, root, &wire, &len) &&
        vcs_zcode_environment_policy_v1_parse(wire, len, out) ==
            VCS_ZCODE_RECEIPT_OK &&
        vcs_zcode_environment_policy_v1_root(out, checked) ==
            VCS_ZCODE_RECEIPT_OK &&
        memcmp(checked, root, 32) == 0;
    free(wire);
    return ok;
}

/* ── fixed resource policy parsing ("cpu=1,memory_mb=4096,timeout_s=600,
 *    network=0" — closed keys, strict grammar, fail closed) ──────────── */

struct exec_resource_limits {
    uint64_t cpu_seconds;
    uint64_t memory_mb;
    uint64_t timeout_s;
    bool network_allowed;
};

static bool exec_policy_parse(const char *policy,
                              struct exec_resource_limits *out)
{
    if (!policy || !out) return false;
    memset(out, 0, sizeof(*out));
    char buf[256];
    if (strlen(policy) >= sizeof(buf)) return false;
    (void)snprintf(buf, sizeof(buf), "%s", policy);
    bool have_cpu = false, have_mem = false, have_timeout = false,
         have_network = false;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq || eq == tok || !eq[1]) return false;
        *eq = '\0';
        char *end = NULL;
        unsigned long long value = strtoull(eq + 1, &end, 10);
        if (!end || *end != '\0') return false;
        if (strcmp(tok, "cpu") == 0 && value >= 1 && value <= 86400) {
            out->cpu_seconds = value;
            have_cpu = true;
        } else if (strcmp(tok, "memory_mb") == 0 && value >= 1 &&
                   value <= (1ull << 20)) {
            out->memory_mb = value;
            have_mem = true;
        } else if (strcmp(tok, "timeout_s") == 0 && value >= 1 &&
                   value <= 86400) {
            out->timeout_s = value;
            have_timeout = true;
        } else if (strcmp(tok, "network") == 0 && value <= 1) {
            out->network_allowed = value == 1;
            have_network = true;
        } else {
            return false; /* closed key set */
        }
    }
    return have_cpu && have_mem && have_timeout && have_network;
}

/* ── the confined runner (fixed kernel: SHA3-256 over the payload) ───── */

struct exec_run_job {
    const uint8_t *payload;
    size_t payload_len;
    uint64_t warmup;
    uint64_t measured;
    int sample_fd;     /* pre-opened pipe write end */
    struct exec_resource_limits limits;
    const char *bench_dir;
};

/* Child-side entry. Only async-safe-ish calls after fork; the payload is
 * inherited across fork and the samples leave over the pre-opened pipe
 * (fork is copy-on-write, so the pipe — not shared memory — carries them
 * back), which means the child needs NO filesystem at all: Landlock gets
 * a read-only grant on the bench dir it never uses, and any fs escape
 * attempt is a loud EACCES. */
/* Write-all helper for the child; false on any short write. */
static bool exec_child_flush(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, buf + done, len - done);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

static void exec_runner_child(const struct exec_run_job *job)
{
    struct os_sandbox_path_rule rules[] = {
        { .path = job->bench_dir, .allow_read = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = job->limits.memory_mb * 1024u * 1024u;
    profile.rlimits.cpu_seconds = job->limits.cpu_seconds;
    profile.rlimits.nproc = 1;
    profile.rlimits.fsize_bytes = 1024u * 1024u;
    /* KEEP the parent's nofile: the child inherits every parent fd across
     * fork and os_sandbox_enter applies rlimits BEFORE creating the
     * Landlock ruleset fd, so the session default (16) fails EMFILE under
     * any real parent (sqlite + pipes alone exceed it). The confinement
     * boundary is Landlock + seccomp + the cpu/memory/timeout policy, not
     * the fd ceiling. */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok)
        _exit(70);
    volatile uint8_t sink = 0;
    uint8_t digest[32];
    for (uint64_t i = 0; i < job->warmup; i++) {
        struct sha3_256_ctx sha;
        sha3_256_init(&sha);
        sha3_256_write(&sha, job->payload, job->payload_len);
        sha3_256_finalize(&sha, digest);
        sink ^= digest[0];
    }
    /* Samples leave over the pre-opened pipe as little-endian u64s, then
     * one sink byte so the kernel is never dead code. */
    uint8_t outbuf[4096];
    size_t outlen = 0;
    for (uint64_t i = 0; i < job->measured; i++) {
        int64_t t0 = clock_now_monotonic_ns();
        struct sha3_256_ctx sha;
        sha3_256_init(&sha);
        sha3_256_write(&sha, job->payload, job->payload_len);
        sha3_256_finalize(&sha, digest);
        int64_t t1 = clock_now_monotonic_ns();
        sink ^= digest[0];
        uint64_t sample = t1 > t0 ? (uint64_t)(t1 - t0) : 0;
        zcl_write_u64_le(outbuf + outlen, sample);
        outlen += 8;
        if (outlen == sizeof(outbuf)) {
            if (!exec_child_flush(job->sample_fd, outbuf, outlen))
                _exit(72);
            outlen = 0;
        }
    }
    uint8_t marker = sink;
    if (!exec_child_flush(job->sample_fd, outbuf, outlen) ||
        !exec_child_flush(job->sample_fd, &marker, 1))
        _exit(72);
    _exit(0);
}

/* Parent side: fork the confined child, collect exactly 8*measured+1
 * bytes, enforce the wall-clock timeout, and report the child verdict.
 * samples must point at a parent buffer of `measured` entries. */
static struct zcl_result exec_runner_fork(const char *bench_dir,
                                          const uint8_t *payload,
                                          size_t payload_len,
                                          uint64_t warmup, uint64_t measured,
                                          const struct exec_resource_limits *limits,
                                          uint64_t *samples)
{
    int fds[2];
    if (pipe(fds) != 0)
        return ZCL_ERR(-1, "executor-run-pipe-failed");
    struct exec_run_job job = {
        .payload = payload, .payload_len = payload_len,
        .warmup = warmup, .measured = measured, .sample_fd = fds[1],
        .limits = *limits, .bench_dir = bench_dir,
    };
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return ZCL_ERR(-1, "executor-run-fork-failed");
    }
    if (pid == 0) {
        close(fds[0]);
        exec_runner_child(&job);
        _exit(71); /* unreachable: the child always _exit()s */
    }
    close(fds[1]);
    size_t expect = 8u * (size_t)measured + 1u;
    uint8_t *buf = zcl_malloc(expect, "zcode.bench.pipe");
    const int64_t deadline =
        clock_now_monotonic_ns() + (int64_t)limits->timeout_s * 1000000000ll;
    /* Collect the child's bytes while it runs (a large sample count exceeds
     * the pipe buffer, so reading only after waitpid would deadlock), with
     * the wall-clock deadline armed on the reads too: a child that hangs
     * without writing dies by the same timeout as one that hangs
     * computing. */
    size_t got = 0;
    bool overflow = false, eof = false, timed_out = false;
    if (buf) {
        while (!eof && !overflow && !timed_out) {
            struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
            int64_t remain_ms = (deadline - clock_now_monotonic_ns()) / 1000000;
            if (remain_ms <= 0) { timed_out = true; break; }
            int pr = poll(&pfd, 1, remain_ms > INT32_MAX ? INT32_MAX : (int)remain_ms);
            if (pr < 0 && errno == EINTR) continue;
            if (pr < 0) break;
            if (pr == 0) { timed_out = true; break; }
            uint8_t chunk[8192];
            ssize_t r = read(fds[0], chunk, sizeof(chunk));
            if (r < 0 && errno == EINTR) continue;
            if (r == 0) { eof = true; break; }
            if (r < 0) break;
            for (ssize_t i = 0; i < r; i++) {
                if (got < expect) buf[got] = chunk[i];
                got++;
            }
            overflow = got > expect;
        }
    }
    close(fds[0]);
    int status = 0;
    if (timed_out) {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        free(buf);
        return ZCL_ERR(-1, "executor-run-timeout");
    }
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (w < 0 && errno != EINTR) break;
        if (clock_now_monotonic_ns() > deadline) {
            kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            free(buf);
            return ZCL_ERR(-1, "executor-run-timeout");
        }
        platform_sleep_ms(1);
    }
    /* The child's own verdict outranks the byte count: a killed or failed
     * child is a killed/failed RUN, not a protocol mismatch. */
    if (!WIFEXITED(status)) {
        free(buf);
        return ZCL_ERR(-1, "executor-run-child-killed: signal %d",
                       WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    }
    if (WEXITSTATUS(status) != 0) {
        free(buf);
        return ZCL_ERR(-1, "executor-run-child-failed: exit %d",
                       WEXITSTATUS(status));
    }
    if (overflow || got != expect) {
        free(buf);
        return ZCL_ERR(-1, "executor-run-protocol-error");
    }
    /* The pipe carried the samples (fork is copy-on-write); the final
     * marker byte is the kernel's dead-code sink. */
    for (uint64_t i = 0; i < measured; i++)
        samples[i] = zcl_read_u64_le(buf + 8u * i);
    free(buf);
    return ZCL_OK;
}
/* ── the sandbox canary self-check (escape-suite pattern) ────────────── */

static int exec_canary_fs(const char *bench_dir)
{
    char probe[EXEC_PATH_MAX];
    int n = snprintf(probe, sizeof(probe), "%s/selfcheck.probe", bench_dir);
    if (n <= 0 || (size_t)n >= sizeof(probe)) return 71;
    struct os_sandbox_path_rule rules[] = {
        { .path = bench_dir, .allow_read = true, .allow_write = true,
          .allow_create = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile too: the canary inherits the parent's fds across fork and
     * rlimits apply before the Landlock ruleset fd exists (see the runner
     * child for why the session default of 16 fails EMFILE). */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok) return 70;
    if (!os_sandbox_active()) return 71;
    int in = open(probe, O_CREAT | O_RDWR, 0600);
    if (in < 0) return 72; /* granted dir must stay usable */
    close(in);
    int out = open("/etc/passwd", O_RDONLY);
    if (out >= 0) {
        close(out);
        return 73; /* escape: outside the grant */
    }
    if (errno != EACCES) return 74;
    return 0;
}

static int exec_canary_socket(const char *bench_dir)
{
    struct os_sandbox_path_rule rules[] = {
        { .path = bench_dir, .allow_read = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile too: the canary inherits the parent's fds across fork and
     * rlimits apply before the Landlock ruleset fd exists (see the runner
     * child for why the session default of 16 fails EMFILE). */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok) return 70;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    (void)s;
    return 6; /* reached only if socket was not denied */
}

static int exec_canary_exec(const char *bench_dir)
{
    struct os_sandbox_path_rule rules[] = {
        { .path = bench_dir, .allow_read = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile too: the canary inherits the parent's fds across fork and
     * rlimits apply before the Landlock ruleset fd exists (see the runner
     * child for why the session default of 16 fails EMFILE). */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok) return 70;
    execve("/bin/true", (char *const[]){ "/bin/true", NULL },
           (char *const[]){ NULL });
    return 5; /* reached only if exec was not denied */
}

typedef int (*exec_canary_fn)(const char *);

static bool exec_canary_wait(pid_t pid, int *status)
{
    for (;;) {
        pid_t w = waitpid(pid, status, 0);
        if (w == pid) return true;
        if (w < 0 && errno == EINTR) continue;
        return false;
    }
}

struct zcl_result zcode_benchmark_executor_sandbox_selfcheck(
    const char *bench_dir)
{
    if (!bench_dir)
        return ZCL_ERR(-1, "selfcheck: no bench dir");
    if (os_sandbox_landlock_abi() < 1 || !os_sandbox_seccomp_supported())
        return ZCL_ERR(-1, "confinement backend unavailable");
    static const struct {
        exec_canary_fn fn;
        const char *name;
    } canaries[] = {
        { exec_canary_fs, "fs-grant" },
        { exec_canary_socket, "socket-deny" },
        { exec_canary_exec, "exec-deny" },
    };
    for (size_t i = 0; i < sizeof(canaries) / sizeof(canaries[0]); i++) {
        pid_t pid = fork();
        if (pid < 0)
            return ZCL_ERR(-1, "canary fork failed");
        if (pid == 0)
            _exit(canaries[i].fn(bench_dir));
        int status = 0;
        if (!exec_canary_wait(pid, &status))
            return ZCL_ERR(-1, "canary wait failed");
        bool ok;
        if (i == 0) {
            ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        } else {
            ok = WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS;
        }
        if (!ok)
            return ZCL_ERR(-1, "canary %s: unexpected status %#x",
                           canaries[i].name, (unsigned)status);
    }
    char probe[EXEC_PATH_MAX];
    int n = snprintf(probe, sizeof(probe), "%s/selfcheck.probe", bench_dir);
    if (n > 0 && (size_t)n < sizeof(probe))
        (void)unlink(probe);
    return ZCL_OK;
}

/* ── shared run context ──────────────────────────────────────────────── */

struct exec_context {
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_benchmark_method_v1 method;
    struct vcs_zcode_environment_policy_v1 policy;
    struct vcs_zcode_hardware_profile_v1 profile;
    struct vcs_zcode_benchmark_workload_v1_view workload;
    uint8_t study_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t method_root[32];
    uint8_t method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
    uint8_t *workload_wire;
    size_t workload_wire_len;
};

static void exec_context_free(struct exec_context *ctx)
{
    free(ctx->workload_wire);
    ctx->workload_wire = NULL;
}

/* Load and cross-check every CAS input the run dereferences. Any missing
 * or disagreeing object is a refusal naming the root kind. */
static struct zcl_result exec_context_load(
    const struct zcode_benchmark_execute_request *req, bool is_repro,
    const struct vcs_zcode_benchmark_result_v1 *original,
    struct exec_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    if (is_repro) {
        memcpy(ctx->study_root, original->study_root, 32);
        memcpy(ctx->task_root, original->task_root, 32);
        memcpy(ctx->candidate_root, original->candidate_root, 32);
    } else {
        if (!exec_hex32(req->study_root_hex, ctx->study_root) ||
            !exec_hex32(req->task_root_hex, ctx->task_root) ||
            !exec_hex32(req->candidate_root_hex, ctx->candidate_root))
            return ZCL_ERR(-1, "executor-root-hex-invalid");
    }
    if (!exec_hex32(req->method_root_hex, ctx->method_root))
        return ZCL_ERR(-1, "executor-method-root-invalid");
    if (!exec_load_study(req->workspace, ctx->study_root, &ctx->study))
        return ZCL_ERR(-1, "executor-study-not-in-cas");
    if (!exec_load_task(req->workspace, ctx->task_root, &ctx->task))
        return ZCL_ERR(-1, "executor-task-not-in-cas");
    if (!exec_load_candidate(req->workspace, ctx->candidate_root,
                             &ctx->candidate))
        return ZCL_ERR(-1, "executor-candidate-not-in-cas");
    if (!exec_load_method(req->workspace, ctx->method_root, &ctx->method,
                          ctx->method_wire))
        return ZCL_ERR(-1, "executor-method-not-in-cas");
    if (!exec_load_policy(req->workspace, ctx->study.environment_policy_root,
                          &ctx->policy))
        return ZCL_ERR(-1, "executor-environment-policy-not-in-cas");
    /* The candidate build graph must agree with the study's recipe pins:
     * same source, dependency lock, and toolchain roots, and the candidate
     * must descend from the task. */
    uint8_t task_root[32], candidate_root[32];
    if (vcs_zcode_task_root(&ctx->task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(&ctx->candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(ctx->task.goal_root, ctx->study_root, 32) != 0 ||
        memcmp(ctx->candidate.task_root, task_root, 32) != 0 ||
        memcmp(ctx->candidate.base_source_root, ctx->task.source_root,
               32) != 0 ||
        memcmp(ctx->study.source_root, ctx->task.source_root, 32) != 0 ||
        memcmp(ctx->study.dependency_lock_root,
               ctx->task.dependency_lock_root, 32) != 0 ||
        memcmp(ctx->study.toolchain_capsule_root,
               ctx->task.toolchain_capsule_root, 32) != 0)
        return ZCL_ERR(-1, "executor-build-graph-mismatch");
    /* The workload payload the method pins must be in CAS. */
    size_t len = 0;
    uint8_t *wire = NULL;
    if (!exec_cas_load(req->workspace, ctx->method.workload_root, &wire,
                       &len))
        return ZCL_ERR(-1, "executor-workload-not-in-cas");
    uint8_t checked[32];
    if (vcs_zcode_benchmark_workload_v1_parse(wire, len, &ctx->workload) !=
            VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_benchmark_workload_v1_root(wire, len, checked) !=
            VCS_ZCODE_RECEIPT_OK ||
        memcmp(checked, ctx->method.workload_root, 32) != 0) {
        free(wire);
        return ZCL_ERR(-1, "executor-workload-invalid");
    }
    ctx->workload_wire = wire;
    ctx->workload_wire_len = len;
    /* Capture the environment and enforce the study's policy against it —
     * a violating host is rejected here, never silently kept. */
    if (!vcs_zcode_hardware_profile_capture(&ctx->profile, req->now))
        return ZCL_ERR(-1, "executor-profile-capture-failed");
    if (!vcs_zcode_environment_policy_v1_accepts(&ctx->policy,
                                                 &ctx->profile))
        return ZCL_ERR(-1, "executor-environment-mismatch");
    return ZCL_OK;
}

/* Derive the executed fixed action. The canonical binding is ALWAYS
 * computed under c23.benchmark.v1 descriptors — a reproduction reruns the
 * SAME fixed action, so original and reproduced results share the action
 * root (the S1 comparator requires exactly that). */
static struct zcl_result exec_action_derive(
    const struct zcode_benchmark_execute_request *req,
    const struct exec_context *ctx, struct vcs_build_action_v1 *action,
    uint8_t action_root[32])
{
    memset(action, 0, sizeof(*action));
    const char *workdir = NULL, *output = NULL, *policy = NULL;
    if (!vcs_build_action_v1_descriptors(VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
                                         &workdir, &output, &policy) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action->flags_sha3) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action->environment_sha3))
        return ZCL_ERR(-1, "executor-action-registry-failed");
    memcpy(action->source_cas_sha3, ctx->candidate.candidate_source_root, 32);
    memcpy(action->input_root_sha3, ctx->method.workload_root, 32);
    memcpy(action->toolchain_capsule_sha3, ctx->study.toolchain_capsule_root,
           32);
    {
        /* source_sha256 slot holds SHA3-256 of the exact candidate wire. */
        uint8_t *cwire = NULL;
        size_t clen = 0;
        if (!exec_cas_load(req->workspace, ctx->candidate_root, &cwire,
                           &clen))
            return ZCL_ERR(-1, "executor-candidate-not-in-cas");
        vcs_source_manifest_id(cwire, clen, action->source_sha256);
        free(cwire);
    }
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action->profile, sizeof(action->profile), "science");
    (void)snprintf(action->virtual_workdir, sizeof(action->virtual_workdir),
                   "%s", workdir);
    (void)snprintf(action->declared_outputs, sizeof(action->declared_outputs),
                   "%s", output);
    (void)snprintf(action->resource_policy, sizeof(action->resource_policy),
                   "%s", policy);
    action->sequence = req->action_sequence;
    if (!vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action, action_root))
        return ZCL_ERR(-1, "executor-action-root-failed");
    return ZCL_OK;
}

static int exec_u64_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* ── stage 1: the confined run ───────────────────────────────────────── */

struct zcl_result zcode_benchmark_executor_run(
    const struct zcode_benchmark_execute_request *req,
    struct zcode_benchmark_run_out *out)
{
    if (!req || !req->workspace || !out || req->now <= 0 ||
        req->challenge_block_height == 0 ||
        !exec_root_nonzero(req->challenge_block_hash) ||
        req->result_sequence == 0 || req->action_sequence == 0)
        return ZCL_ERR(-1, "executor-input-invalid");
    memset(out, 0, sizeof(*out));
    bool is_repro = req->original_result_root_hex != NULL;
    const char *kind = req->action_kind && req->action_kind[0]
                           ? req->action_kind
                           : VCS_BUILD_ACTION_KIND_BENCHMARK_V1;
    /* The closed registry gate: anything that is not a registered fixed
     * action — a free-form shell string included — dies here; of the
     * registered kinds only the two benchmark kinds may execute. */
    if (vcs_build_action_v1_work_kind(kind) == 0)
        return ZCL_ERR(-1, "executor-action-unregistered");
    if (is_repro) {
        if (strcmp(kind, VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1) != 0)
            return ZCL_ERR(-1, "executor-reproduction-kind-required");
        if (!exec_root_nonzero(req->reproducer_pubkey) ||
            req->reproduction_sequence == 0)
            return ZCL_ERR(-1, "executor-reproduction-input-invalid");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_BENCHMARK_V1) != 0) {
        return ZCL_ERR(-1, "executor-action-kind-closed");
    }
    out->is_reproduction = is_repro;

    struct vcs_zcode_benchmark_result_v1 original;
    if (is_repro) {
        uint8_t original_root[32];
        if (!exec_hex32(req->original_result_root_hex, original_root))
            return ZCL_ERR(-1, "executor-original-root-invalid");
        uint8_t *wire = NULL, checked[32];
        size_t len = 0;
        bool ok = exec_cas_load(req->workspace, original_root, &wire, &len);
        if (ok) {
            /* The landed S1 comparator binds v1 roots: a reproduction may
             * only target a v1 original wire. */
            ok = len == VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES &&
                memcmp(wire, result_v1_magic, sizeof(result_v1_magic)) == 0;
        }
        if (ok)
            ok = vcs_zcode_benchmark_result_parse(wire, len, &original) ==
                    VCS_ZCODE_SCIENCE_OK &&
                vcs_zcode_benchmark_result_validate(&original) ==
                    VCS_ZCODE_SCIENCE_OK &&
                vcs_zcode_benchmark_result_root(&original, checked) ==
                    VCS_ZCODE_SCIENCE_OK &&
                memcmp(checked, original_root, 32) == 0;
        free(wire);
        if (!ok)
            return ZCL_ERR(-1, "executor-original-not-v1-in-cas");
    }

    struct exec_context ctx;
    struct zcl_result loaded = exec_context_load(req, is_repro,
                                                 is_repro ? &original : NULL,
                                                 &ctx);
    if (!loaded.ok) {
        exec_context_free(&ctx);
        return loaded;
    }
    uint8_t action_root[32];
    struct zcl_result derived =
        exec_action_derive(req, &ctx, &out->action, action_root);
    if (!derived.ok) {
        exec_context_free(&ctx);
        return derived;
    }
    if (is_repro && memcmp(action_root, original.action_root, 32) != 0) {
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-action-mismatch");
    }

    /* Confinement: self-check first, refuse on any failure, then run the
     * fixed action under the kind's fixed resource policy. */
    char bench_dir[EXEC_PATH_MAX];
    int n = snprintf(bench_dir, sizeof(bench_dir), "%s/.zvcs/bench",
                     req->workspace);
    if (n <= 0 || (size_t)n >= sizeof(bench_dir)) {
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-bench-dir-invalid");
    }
    if (mkdir(bench_dir, 0700) != 0 && errno != EEXIST) {
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-bench-dir-failed");
    }
    struct zcl_result (*selfcheck)(const char *) =
        req->hooks && req->hooks->sandbox_selfcheck
            ? req->hooks->sandbox_selfcheck
            : zcode_benchmark_executor_sandbox_selfcheck;
    struct zcl_result check = selfcheck(bench_dir);
    if (!check.ok) {
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-sandbox-selfcheck-failed: %s",
                       check.message);
    }
    /* The reproduce kind selects its own registry policy text; the two
     * registry policies are textually identical today but are distinct
     * symbols, so select via a table to keep the distinction explicit
     * without a duplicated-branch ternary. */
    static const char *const exec_policy_by_kind[2] = {
        VCS_BUILD_BENCHMARK_RESOURCE_POLICY_V1,
        VCS_BUILD_BENCHMARK_REPRODUCE_RESOURCE_POLICY_V1,
    };
    const char *policy_text = exec_policy_by_kind[is_repro ? 1 : 0];
    struct exec_resource_limits limits;
    if (!exec_policy_parse(policy_text, &limits) || limits.network_allowed) {
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-resource-policy-invalid");
    }
    uint64_t measured = ctx.method.measured_samples;
    uint64_t *samples =
        zcl_malloc(8u * (size_t)measured, "zcode.bench.samples");
    if (!samples) {
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-samples-alloc-failed");
    }
    struct zcl_result ran = exec_runner_fork(
        bench_dir, ctx.workload.payload, (size_t)ctx.workload.payload_len,
        ctx.method.warmup_samples, measured, &limits, samples);
    if (!ran.ok) {
        /* Crash discipline: nothing was stored, nothing is admitted. */
        free(samples);
        exec_context_free(&ctx);
        return ran;
    }

    /* Compose the artifacts. */
    uint64_t *sorted =
        zcl_malloc(8u * (size_t)measured, "zcode.bench.sorted");
    if (!sorted) {
        free(samples);
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-sorted-alloc-failed");
    }
    memcpy(sorted, samples, 8u * (size_t)measured);
    qsort(sorted, (size_t)measured, 8, exec_u64_cmp);
    uint8_t status = ctx.workload.payload_len == 0
                         ? VCS_ZCODE_BENCHMARK_NULL_RESULT
                         : VCS_ZCODE_BENCHMARK_OBSERVED;

    uint8_t profile_wire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES];
    if (vcs_zcode_hardware_profile_serialize(&ctx.profile, profile_wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_hardware_profile_root(&ctx.profile,
                                        out->hardware_profile_root) !=
            VCS_ZCODE_SCIENCE_OK) {
        free(sorted);
        free(samples);
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-profile-serialize-failed");
    }
    struct vcs_zcode_raw_sample_manifest_v1 manifest;
    memset(&manifest, 0, sizeof(manifest));
    manifest.schema_version = VCS_ZCODE_RAW_SAMPLE_MANIFEST_VERSION;
    memcpy(manifest.method_root, ctx.method_root, 32);
    memcpy(manifest.workload_root, ctx.method.workload_root, 32);
    manifest.warmup_samples = ctx.method.warmup_samples;
    manifest.measured_samples = measured;
    memcpy(manifest.timer_source, ctx.profile.timer_source,
           sizeof(manifest.timer_source));
    uint8_t manifest_wire[VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES];
    if (vcs_zcode_raw_sample_manifest_v1_serialize(&manifest,
                                                   manifest_wire) !=
            VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_raw_sample_manifest_v1_root(&manifest,
                                              out->manifest_root) !=
            VCS_ZCODE_RECEIPT_OK) {
        free(sorted);
        free(samples);
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-manifest-failed");
    }
    size_t payload_wire_len =
        VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES + 8u * (size_t)measured;
    uint8_t *payload_wire =
        zcl_malloc(payload_wire_len, "zcode.bench.payload_wire");
    if (!payload_wire ||
        vcs_zcode_sample_payload_v1_serialize(samples, measured,
                                              payload_wire,
                                              payload_wire_len) !=
            VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_sample_payload_v1_root(payload_wire, payload_wire_len,
                                         out->sample_payload_root) !=
            VCS_ZCODE_RECEIPT_OK) {
        free(payload_wire);
        free(sorted);
        free(samples);
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-sample-payload-failed");
    }
    memset(&out->evidence, 0, sizeof(out->evidence));
    out->evidence.schema_version = VCS_ZCODE_BENCHMARK_EVIDENCE_VERSION;
    memcpy(out->evidence.action_root, action_root, 32);
    memcpy(out->evidence.manifest_root, out->manifest_root, 32);
    memcpy(out->evidence.sample_payload_root, out->sample_payload_root, 32);
    out->evidence.min_ns = sorted[0];
    out->evidence.median_ns = sorted[measured / 2u];
    out->evidence.max_ns = sorted[measured - 1u];
    out->evidence.status = status;
    out->evidence.isolation = VCS_ZCODE_BENCHMARK_ISOLATION_FULL;
    uint8_t evidence_wire[VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES];
    if (vcs_zcode_benchmark_evidence_v1_serialize(&out->evidence,
                                                  evidence_wire) !=
            VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_benchmark_evidence_v1_root(&out->evidence,
                                             out->evidence_root) !=
            VCS_ZCODE_RECEIPT_OK) {
        free(payload_wire);
        free(sorted);
        free(samples);
        exec_context_free(&ctx);
        return ZCL_ERR(-1, "executor-evidence-failed");
    }

    /* Compose the result wire(s). */
    if (!is_repro) {
        struct vcs_zcode_benchmark_result_v2 *r = &out->result;
        memset(r, 0, sizeof(*r));
        r->schema_version = VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION;
        memcpy(r->study_root, ctx.study_root, 32);
        memcpy(r->task_root, ctx.task_root, 32);
        memcpy(r->candidate_root, ctx.candidate_root, 32);
        memcpy(r->action_root, action_root, 32);
        memcpy(r->achieved_environment_root, out->hardware_profile_root, 32);
        memcpy(r->raw_sample_root, out->manifest_root, 32);
        memcpy(r->evidence_root, out->evidence_root, 32);
        r->status = status;
        r->challenge_block_height = req->challenge_block_height;
        memcpy(r->challenge_block_hash, req->challenge_block_hash, 32);
        r->sequence = req->result_sequence;
        r->started_unix = req->now;
        r->finished_unix = req->now;
        memcpy(r->method_root, ctx.method_root, 32);
        memcpy(r->hardware_profile_root, out->hardware_profile_root, 32);
        if (vcs_zcode_benchmark_result_v2_serialize(r, out->result_wire) !=
                VCS_ZCODE_SCIENCE_OK ||
            vcs_zcode_benchmark_result_v2_root(r, out->result_root) !=
                VCS_ZCODE_SCIENCE_OK) {
            free(payload_wire);
            free(sorted);
            free(samples);
            exec_context_free(&ctx);
            return ZCL_ERR(-1, "executor-result-compose-failed");
        }
        out->result_wire_len = VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES;
        memcpy(out->method_wire, ctx.method_wire,
               sizeof(out->method_wire));
        memcpy(out->profile_wire, profile_wire, sizeof(out->profile_wire));
    } else {
        struct vcs_zcode_benchmark_result_v1 *r = &out->reproduced;
        memset(r, 0, sizeof(*r));
        r->schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(r->study_root, ctx.study_root, 32);
        memcpy(r->task_root, ctx.task_root, 32);
        memcpy(r->candidate_root, ctx.candidate_root, 32);
        memcpy(r->action_root, action_root, 32);
        memcpy(r->achieved_environment_root, out->hardware_profile_root, 32);
        memcpy(r->raw_sample_root, out->manifest_root, 32);
        memcpy(r->evidence_root, out->evidence_root, 32);
        r->status = status;
        r->challenge_block_height = req->challenge_block_height;
        memcpy(r->challenge_block_hash, req->challenge_block_hash, 32);
        r->sequence = req->result_sequence;
        r->started_unix = req->now;
        r->finished_unix = req->now;
        if (vcs_zcode_benchmark_result_serialize(r, out->reproduced_wire) !=
                VCS_ZCODE_SCIENCE_OK ||
            vcs_zcode_benchmark_result_root(r, out->reproduced_root) !=
                VCS_ZCODE_SCIENCE_OK) {
            free(payload_wire);
            free(sorted);
            free(samples);
            exec_context_free(&ctx);
            return ZCL_ERR(-1, "executor-result-compose-failed");
        }
        out->result_wire_len = VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES;
        /* The verdict compares the two sample distributions under the
         * method's tolerance: a slower candidate is a CONTRADICTED
         * observation, never an execution failure. */
        struct vcs_zcode_benchmark_evidence_v1 original_evidence;
        uint8_t *ewire = NULL, echecked[32];
        size_t elen = 0;
        bool eok = exec_cas_load(req->workspace, original.evidence_root,
                                 &ewire, &elen) &&
            vcs_zcode_benchmark_evidence_v1_parse(ewire, elen,
                                                  &original_evidence) ==
                VCS_ZCODE_RECEIPT_OK &&
            vcs_zcode_benchmark_evidence_v1_root(&original_evidence,
                                                 echecked) ==
                VCS_ZCODE_RECEIPT_OK &&
            memcmp(echecked, original.evidence_root, 32) == 0;
        free(ewire);
        if (!eok) {
            free(payload_wire);
            free(sorted);
            free(samples);
            exec_context_free(&ctx);
            return ZCL_ERR(-1, "executor-original-evidence-not-in-cas");
        }
        uint64_t a = original_evidence.median_ns, b = out->evidence.median_ns;
        uint64_t lo = a < b ? a : b;
        uint64_t delta = a > b ? a - b : b - a;
        if (lo == 0) {
            out->verdict = VCS_ZCODE_REPRODUCTION_INCONCLUSIVE;
        } else {
            uint64_t deviation_ppm = delta * 1000000u / lo;
            out->verdict = deviation_ppm <= ctx.method.tolerance_ppm
                               ? VCS_ZCODE_REPRODUCTION_REPLICATED
                               : VCS_ZCODE_REPRODUCTION_CONTRADICTED;
        }
        struct vcs_zcode_reproduction_v1 *rep = &out->reproduction;
        memset(rep, 0, sizeof(*rep));
        rep->schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(rep->study_root, ctx.study_root, 32);
        if (!exec_hex32(req->original_result_root_hex,
                        rep->original_result_root) ||
            !exec_root_nonzero(rep->original_result_root)) {
            free(payload_wire);
            free(sorted);
            free(samples);
            exec_context_free(&ctx);
            return ZCL_ERR(-1, "executor-original-root-invalid");
        }
        memcpy(rep->reproduced_result_root, out->reproduced_root, 32);
        memcpy(rep->comparison_policy_root, ctx.method_root, 32);
        memcpy(rep->original_environment_root,
               original.achieved_environment_root, 32);
        memcpy(rep->reproduced_environment_root,
               out->hardware_profile_root, 32);
        memcpy(rep->reproducer_pubkey, req->reproducer_pubkey, 32);
        rep->verdict = out->verdict;
        rep->sequence = req->reproduction_sequence;
        rep->created_unix = req->now;
        if (vcs_zcode_reproduction_serialize(rep, out->reproduction_wire) !=
                VCS_ZCODE_SCIENCE_OK ||
            vcs_zcode_reproduction_root(rep, out->reproduction_root) !=
                VCS_ZCODE_SCIENCE_OK) {
            free(payload_wire);
            free(sorted);
            free(samples);
            exec_context_free(&ctx);
            return ZCL_ERR(-1, "executor-reproduction-compose-failed");
        }
    }

    /* Store the auxiliary objects. The finished evidence wire itself
     * enters CAS only via the S3 confirm:true commit — except the
     * reproduced v1 wire, which the landed admission path cannot carry
     * (work.commit admits v2 results and reproductions only) and which is
     * therefore stored here, addressed by its v1 root, exactly like the
     * S3 evidence fixtures. */
    bool stored =
        vcs_object_put_addressed(req->workspace, out->hardware_profile_root,
                                 profile_wire, sizeof(profile_wire)) &&
        vcs_object_put_addressed(req->workspace, out->manifest_root,
                                 manifest_wire, sizeof(manifest_wire)) &&
        vcs_object_put_addressed(req->workspace, out->sample_payload_root,
                                 payload_wire, payload_wire_len) &&
        vcs_object_put_addressed(req->workspace, out->evidence_root,
                                 evidence_wire, sizeof(evidence_wire)) &&
        (!is_repro ||
         vcs_object_put_addressed(req->workspace, out->reproduced_root,
                                  out->reproduced_wire,
                                  sizeof(out->reproduced_wire)));
    free(payload_wire);
    free(sorted);
    free(samples);
    exec_context_free(&ctx);
    if (!stored)
        return ZCL_ERR(-1, "executor-artifact-store-failed");
    return ZCL_OK;
}

/* ── stage 2: admission via the landed S3 plan/commit path ───────────── */

struct zcl_result zcode_benchmark_executor_admit(
    struct node_db *ndb, const char *workspace,
    const struct zcode_benchmark_run_out *run, bool confirm, int64_t now,
    struct zcode_benchmark_execute_out *out)
{
    if (!ndb || !workspace || !run || !out || now <= 0)
        return ZCL_ERR(-1, "executor-admit-input-invalid");
    memset(out, 0, sizeof(*out));
    out->run = *run;
    if (!run->is_reproduction) {
        ZCL_CHECK(zcode_science_work_plan(
            ndb, workspace, run->result_wire, run->result_wire_len,
            run->method_wire, sizeof(run->method_wire), run->profile_wire,
            sizeof(run->profile_wire), &run->action, now, &out->plan));
        if (!confirm) return ZCL_OK;
        ZCL_CHECK(zcode_science_work_commit(ndb, workspace, run->result_wire,
                                            run->result_wire_len,
                                            &run->action, true, now,
                                            &out->commit));
        out->committed = true;
        return ZCL_OK;
    }
    ZCL_CHECK(zcode_science_work_plan(
        ndb, workspace, run->reproduction_wire,
        sizeof(run->reproduction_wire), NULL, 0, NULL, 0, NULL, now,
        &out->plan));
    if (!confirm) return ZCL_OK;
    ZCL_CHECK(zcode_science_work_commit(ndb, workspace,
                                        run->reproduction_wire,
                                        sizeof(run->reproduction_wire), NULL,
                                        true, now, &out->commit));
    out->committed = true;
    return ZCL_OK;
}

struct zcl_result zcode_benchmark_execute(
    struct node_db *ndb, const struct zcode_benchmark_execute_request *req,
    struct zcode_benchmark_execute_out *out)
{
    if (!req || !out) return ZCL_ERR(-1, "executor-input-invalid");
    struct zcode_benchmark_run_out run;
    ZCL_CHECK(zcode_benchmark_executor_run(req, &run));
    return zcode_benchmark_executor_admit(ndb, req->workspace, &run,
                                          req->confirm, req->now, out);
}

/* ── receipt verification (tamper → root mismatch → rejection) ───────── */

static struct zcl_result exec_verify_samples(
    const char *workspace, const uint8_t action_root[32], uint8_t status,
    const uint8_t raw_sample_root[32], const uint8_t evidence_root[32],
    const uint8_t method_root[32],
    const struct vcs_zcode_benchmark_method_v1 *method_or_null)
{
    struct vcs_zcode_raw_sample_manifest_v1 manifest;
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = exec_cas_load(workspace, raw_sample_root, &wire, &len) &&
        vcs_zcode_raw_sample_manifest_v1_parse(wire, len, &manifest) ==
            VCS_ZCODE_RECEIPT_OK &&
        vcs_zcode_raw_sample_manifest_v1_root(&manifest, checked) ==
            VCS_ZCODE_RECEIPT_OK &&
        memcmp(checked, raw_sample_root, 32) == 0;
    free(wire);
    if (!ok)
        return ZCL_ERR(-1, "receipt-manifest-root-mismatch");
    if (method_or_null &&
        (memcmp(manifest.method_root, method_root, 32) != 0 ||
         memcmp(manifest.workload_root, method_or_null->workload_root,
                32) != 0 ||
         manifest.measured_samples != method_or_null->measured_samples ||
         manifest.warmup_samples != method_or_null->warmup_samples))
        return ZCL_ERR(-1, "receipt-manifest-method-mismatch");
    struct vcs_zcode_benchmark_evidence_v1 evidence;
    wire = NULL;
    ok = exec_cas_load(workspace, evidence_root, &wire, &len) &&
        vcs_zcode_benchmark_evidence_v1_parse(wire, len, &evidence) ==
            VCS_ZCODE_RECEIPT_OK &&
        vcs_zcode_benchmark_evidence_v1_root(&evidence, checked) ==
            VCS_ZCODE_RECEIPT_OK &&
        memcmp(checked, evidence_root, 32) == 0;
    free(wire);
    if (!ok)
        return ZCL_ERR(-1, "receipt-evidence-root-mismatch");
    if (memcmp(evidence.action_root, action_root, 32) != 0 ||
        memcmp(evidence.manifest_root, raw_sample_root, 32) != 0 ||
        evidence.status != status)
        return ZCL_ERR(-1, "receipt-evidence-binding-mismatch");
    struct vcs_zcode_sample_payload_v1_view view;
    wire = NULL;
    ok = exec_cas_load(workspace, evidence.sample_payload_root, &wire,
                       &len) &&
        vcs_zcode_sample_payload_v1_parse(wire, len, &view) ==
            VCS_ZCODE_RECEIPT_OK &&
        vcs_zcode_sample_payload_v1_root(wire, len, checked) ==
            VCS_ZCODE_RECEIPT_OK &&
        memcmp(checked, evidence.sample_payload_root, 32) == 0;
    if (!ok) {
        free(wire);
        return ZCL_ERR(-1, "receipt-sample-payload-root-mismatch");
    }
    if (view.count != manifest.measured_samples) {
        free(wire);
        return ZCL_ERR(-1, "receipt-sample-count-mismatch");
    }
    uint64_t *sorted = zcl_malloc(8u * (size_t)view.count, "receipt.sorted");
    if (!sorted) {
        free(wire);
        return ZCL_ERR(-1, "receipt-sorted-alloc-failed");
    }
    for (uint64_t i = 0; i < view.count; i++)
        if (!vcs_zcode_sample_payload_v1_sample_at(&view, i, &sorted[i])) {
            free(sorted);
            free(wire);
            return ZCL_ERR(-1, "receipt-sample-read-failed");
        }
    free(wire);
    qsort(sorted, (size_t)view.count, 8, exec_u64_cmp);
    bool stats_ok = sorted[0] == evidence.min_ns &&
        sorted[view.count / 2u] == evidence.median_ns &&
        sorted[view.count - 1u] == evidence.max_ns;
    free(sorted);
    if (!stats_ok)
        return ZCL_ERR(-1, "receipt-evidence-stats-mismatch");
    return ZCL_OK;
}

struct zcl_result zcode_benchmark_executor_verify_receipt(
    const char *workspace, const char *result_root_hex)
{
    if (!workspace || !result_root_hex)
        return ZCL_ERR(-1, "receipt-input-invalid");
    uint8_t root[32], checked[32];
    if (!exec_hex32(result_root_hex, root))
        return ZCL_ERR(-1, "receipt-root-invalid");
    uint8_t *wire = NULL;
    size_t len = 0;
    if (!exec_cas_load(workspace, root, &wire, &len))
        return ZCL_ERR(-1, "receipt-result-not-in-cas");
    if (len == VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES &&
        memcmp(wire, result_v2_magic, sizeof(result_v2_magic)) == 0) {
        struct vcs_zcode_benchmark_result_v2 result;
        bool ok = vcs_zcode_benchmark_result_v2_parse(wire, len, &result) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_validate(&result) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_root(&result, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, root, 32) == 0;
        free(wire);
        if (!ok)
            return ZCL_ERR(-1, "receipt-result-root-mismatch");
        struct vcs_zcode_benchmark_method_v1 method;
        if (!exec_load_method(workspace, result.method_root, &method, NULL))
            return ZCL_ERR(-1, "receipt-method-root-mismatch");
        struct vcs_zcode_hardware_profile_v1 profile;
        wire = NULL;
        ok = exec_cas_load(workspace, result.hardware_profile_root, &wire,
                           &len) &&
            vcs_zcode_hardware_profile_parse(wire, len, &profile) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_hardware_profile_root(&profile, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, result.hardware_profile_root, 32) == 0;
        free(wire);
        if (!ok)
            return ZCL_ERR(-1, "receipt-profile-root-mismatch");
        if (memcmp(result.achieved_environment_root,
                   result.hardware_profile_root, 32) != 0)
            return ZCL_ERR(-1, "receipt-environment-binding-mismatch");
        return exec_verify_samples(workspace, result.action_root,
                                   result.status, result.raw_sample_root,
                                   result.evidence_root, result.method_root,
                                   &method);
    }
    if (len == VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES &&
        memcmp(wire, result_v1_magic, sizeof(result_v1_magic)) == 0) {
        struct vcs_zcode_benchmark_result_v1 result;
        bool ok = vcs_zcode_benchmark_result_parse(wire, len, &result) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_validate(&result) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_root(&result, checked) ==
                VCS_ZCODE_SCIENCE_OK &&
            memcmp(checked, root, 32) == 0;
        free(wire);
        if (!ok)
            return ZCL_ERR(-1, "receipt-result-root-mismatch");
        return exec_verify_samples(workspace, result.action_root,
                                   result.status, result.raw_sample_root,
                                   result.evidence_root, NULL, NULL);
    }
    free(wire);
    return ZCL_ERR(-1, "receipt-result-kind-unknown");
}
