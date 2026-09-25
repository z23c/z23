/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Clean-zygote reflex runner process and its confined candidate child.
 *
 * This translation unit runs only inside the runner: a fresh exec of the
 * resident's own image with an empty environment, stdio on /dev/null and one
 * control socket. It never reads configuration, a datadir, keys or the
 * environment. See devloop_reflex_runner.h for the whole contract.
 *
 * Child ordering is the security argument, so it is spelled out:
 *   1. parent-death signal + parent identity check
 *   2. close every descriptor except the sealed image and the report pipe
 *   3. rlimits (core 0, fsize 0, nofile small, AS/cpu bounded)
 *   4. no_new_privs, Landlock deny-all, seccomp session deny-list, then the
 *      runner/leaf layers (io_uring, pidfd, userfaultfd, kcmp,
 *      process_madvise, kill family, setsid/setpgid) — no W^X yet
 *   5. re-hash the sealed image and compare
 *   6. map it through /proc/self/fd/N (constructors run HERE, confined)
 *   7. second seccomp layer: PROT_EXEC mmap/mprotect denied (W^X)
 *   8. run the story / frozen KAT, write one fixed-size report, _exit
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* pipe2, SO_PEERCRED/struct ucred, MSG_CMSG_CLOEXEC */
#endif

#include "devloop_reflex_runner_wire.h"

#include "base/hex.h"
#include "command/native_dev_hotswap.h"
#include "crypto/sha256.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include "platform/os_sandbox.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* Generic-table numbers (identical on every Linux arch) for libc headers that
 * predate them, so the deny layer can never silently omit io_uring or pidfd
 * and the startup probe always tests the real syscall. */
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_register
#define SYS_io_uring_register 427
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#endif

#if defined(__linux__)

extern char **environ;

uint32_t zcl_reflex_env_count(void)
{
    uint32_t count = 0;
    for (char **e = environ; e && *e; e++)
        count++;
    return count;
}

static bool fd_kept(int fd, const int *keep, size_t keep_count)
{
    for (size_t i = 0; i < keep_count; i++)
        if (keep[i] == fd) return true;
    return false;
}

uint32_t zcl_reflex_count_fds_except(const int *keep, size_t keep_count)
{
    uint32_t count = 0;
    for (int fd = 0; fd < 1024; fd++)
        if (!fd_kept(fd, keep, keep_count) && fcntl(fd, F_GETFD) >= 0)
            count++;
    return count;
}

bool zcl_reflex_sha256_fd(int fd, char out[65])
{
    if (fd < 0 || !out || lseek(fd, 0, SEEK_SET) < 0) return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) { sha256_write(&ctx, buf, (size_t)n); continue; }
        if (n == 0) break;
        if (errno != EINTR) return false;
    }
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return lseek(fd, 0, SEEK_SET) == 0;
}

/* ── report frames, validation, bounded reap (pre-hardening forms) ─────── */

#if defined(ZCL_TESTING)
static bool g_close_range_enabled = true;
void zcl_reflex_testing_use_close_range(bool enabled)
{
    g_close_range_enabled = enabled;
}
void zcl_reflex_testing_set_fd_dir(const char *path) { (void)path; }
#endif

/* Today's acceptance: one blob of the right total length, no order check. */
enum zcl_reflex_frames_status zcl_reflex_frames_parse(
    const uint8_t *bytes, size_t len, struct zcl_reflex_frames *out)
{
    memset(out, 0, sizeof(*out));
    if (len != sizeof(out->preload) + sizeof(out->observation))
        return out->status = ZCL_REFLEX_FRAMES_TRUNCATED;
    memcpy(&out->preload, bytes, sizeof(out->preload));
    memcpy(&out->observation, bytes + sizeof(out->preload),
           sizeof(out->observation));
    out->preload_present = out->observation_present = true;
    return out->status = ZCL_REFLEX_FRAMES_OK;
}

const char *zcl_reflex_frames_reason(enum zcl_reflex_frames_status status)
{
    return status == ZCL_REFLEX_FRAMES_OK ? "" : "report incomplete";
}

/* Today's resident uses report strings without checking them. */
const char *zcl_reflex_preload_invalid(const struct zcl_reflex_preload_frame *f)
{
    (void)f;
    return NULL;
}

const char *zcl_reflex_observation_invalid(
    const struct zcl_reflex_observation_frame *f)
{
    (void)f;
    return NULL;
}

/* Today's reap: wait without a deadline. */
void zcl_reflex_reap_bounded(pid_t child, int64_t deadline_us,
                             struct zcl_reflex_reap *out)
{
    (void)deadline_us;
    memset(out, 0, sizeof(*out));
    out->exit_code = -1;
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    out->reaped = waited == child;
    if (out->reaped && WIFEXITED(status)) out->exit_code = WEXITSTATUS(status);
    if (out->reaped && WIFSIGNALED(status)) out->signal = WTERMSIG(status);
}

/* ── descriptor hygiene ─────────────────────────────────────────────────── */

static bool close_span(unsigned lo, unsigned hi)
{
    if (lo > hi) return true;
#ifdef SYS_close_range
#if defined(ZCL_TESTING)
    if (g_close_range_enabled)
#endif
    if (syscall(SYS_close_range, lo, hi, 0) == 0) return true;
#endif
    unsigned cap = hi > 65535u ? 65535u : hi;
    for (unsigned fd = lo; fd <= cap; fd++)
        (void)close((int)fd);
    return true;
}

bool zcl_reflex_close_all_except(const int *keep, size_t keep_count)
{
    int sorted[8];
    if (!keep || keep_count == 0 || keep_count > 8) return false;
    memcpy(sorted, keep, keep_count * sizeof(int));
    for (size_t i = 1; i < keep_count; i++)
        for (size_t j = i; j > 0 && sorted[j - 1] > sorted[j]; j--) {
            int t = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = t;
        }
    unsigned lo = 0;
    for (size_t i = 0; i < keep_count; i++) {
        if (sorted[i] < 0) return false;
        if ((unsigned)sorted[i] > lo) (void)close_span(lo, (unsigned)sorted[i] - 1u);
        lo = (unsigned)sorted[i] + 1u;
    }
    return close_span(lo, ~0u);
}

static bool write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) { p += n; len -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

/* ── confined child ─────────────────────────────────────────────────────── */

struct child_ctx {
    const struct zcl_reflex_request *request;
    struct zcl_reflex_child_report *report;
    int64_t load_started_us;
    int64_t story_started_us;
};

static void child_note(struct zcl_reflex_child_report *report,
                       const char *stage, const char *error)
{
    (void)snprintf(report->stage, sizeof(report->stage), "%s", stage);
    if (error && !report->error[0])
        (void)snprintf(report->error, sizeof(report->error), "%s", error);
}

static bool child_rlimits(uint32_t timeout_ms)
{
    struct os_sandbox_rlimits lim = {
        .as_bytes = UINT64_C(4) << 30,
        .cpu_seconds = (uint64_t)timeout_ms / 1000u + 2u,
        .nproc = OS_SANDBOX_RLIMIT_KEEP,
        .fsize_bytes = 0,
        .nofile = 16,
        .core_bytes = 0,
    };
    return os_sandbox_set_rlimits(&lim).ok;
}

/* Kernel surfaces the shared session deny-set does not name. The runner
 * installs this layer before it serves anything (fail-closed), and every
 * candidate child inherits it across fork. io_uring executes socket, connect
 * and openat as ring operations that never pass through the seccomp syscall
 * filter, so a ring would reopen the network the session set closes.
 * pidfd_open/pidfd_getfd/kcmp/process_madvise and ptrace/process_vm_* reach
 * into other processes; userfaultfd is an exploitation primitive. The runner
 * itself uses none of them. */
static const int g_runner_denied[] = {
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup,
#endif
#ifdef SYS_io_uring_enter
    SYS_io_uring_enter,
#endif
#ifdef SYS_io_uring_register
    SYS_io_uring_register,
#endif
#ifdef SYS_pidfd_open
    SYS_pidfd_open,
#endif
#ifdef SYS_pidfd_getfd
    SYS_pidfd_getfd,
#endif
#ifdef SYS_userfaultfd
    SYS_userfaultfd,
#endif
#ifdef SYS_kcmp
    SYS_kcmp,
#endif
#ifdef SYS_process_madvise
    SYS_process_madvise,
#endif
    SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev,
};

/* The candidate leaf additionally signals nothing and never leaves its
 * session: kill/tkill/tgkill would let candidate bytes SIGKILL any same-uid
 * process (the runner, the resident, a node). The runner keeps kill() — it
 * must kill a child at the deadline — so these are leaf-only. */
static const int g_leaf_denied[] = {
#ifdef SYS_pidfd_send_signal
    SYS_pidfd_send_signal,
#endif
    SYS_kill, SYS_tkill, SYS_tgkill, SYS_rt_sigqueueinfo,
    SYS_rt_tgsigqueueinfo, SYS_setsid, SYS_setpgid,
};

/* Every candidate leaf's syscall filters: the shared session deny-set, the
 * runner layer again (already inherited; re-installing keeps the leaf
 * self-sufficient if a future runner variant ever skipped it) and the
 * leaf-only signalling layer. The runner's startup probes use exactly this. */
static bool child_install_filters(void)
{
    size_t denied_count = 0;
    const int *denied = os_sandbox_session_denied_syscalls(&denied_count);
    return os_sandbox_seccomp_deny(denied, denied_count, false).ok &&
        os_sandbox_seccomp_deny(g_runner_denied, sizeof(g_runner_denied) /
                                sizeof(g_runner_denied[0]), false).ok &&
        os_sandbox_seccomp_deny(g_leaf_denied, sizeof(g_leaf_denied) /
                                sizeof(g_leaf_denied[0]), false).ok;
}

static bool child_confine(struct zcl_reflex_child_report *report,
                          const struct zcl_reflex_request *request,
                          int image_fd, int report_fd, int runner_pid)
{
    const int keep[] = {image_fd, report_fd};
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != runner_pid)
        return child_note(report, "parent", "runner parent identity lost"),
               false;
    if (!zcl_reflex_close_all_except(keep, 2))
        return child_note(report, "fds", "descriptor close failed"), false;
    if (!child_rlimits(request->timeout_ms))
        return child_note(report, "rlimits", "rlimit lowering failed"), false;
    if (!os_sandbox_no_new_privs())
        return child_note(report, "no_new_privs", "no_new_privs failed"), false;
    if (!os_sandbox_landlock_restrict(NULL, 0).ok)
        return child_note(report, "landlock", "Landlock deny-all unavailable"),
               false;
    /* os_sandbox retains the Landlock ruleset descriptor for thread retrofit
     * joins; this single-threaded child never joins, so the candidate must
     * not see it either. */
    if (!zcl_reflex_close_all_except(keep, 2))
        return child_note(report, "fds", "ruleset close failed"), false;
    if (!child_install_filters())
        return child_note(report, "seccomp", "seccomp deny-lists unavailable"),
               false;
    report->env_count = zcl_reflex_env_count();
    report->inherited_fd_count = zcl_reflex_count_fds_except(keep, 2);
    report->resident_canary_seen = zcl_reflex_resident_canary;
    return true;
}

/* Second layer, installed after the mapping exists and before any candidate
 * function runs: no new executable memory for the rest of the child's life. */
static bool child_install_wx(struct zcl_reflex_child_report *report)
{
    report->wx_installed = os_sandbox_seccomp_deny(NULL, 0, true).ok;
    if (!report->wx_installed)
        child_note(report, "wx", "W^X seccomp layer unavailable");
    return report->wx_installed;
}

static bool text_eq(const char *candidate, const char *expected)
{
    return candidate && strcmp(candidate, expected) == 0;
}

static bool child_descriptor_matches(
    const struct zcl_hotfork_capsule_v1 *capsule,
    const struct zcl_reflex_request *request)
{
    return capsule && capsule->abi_version == ZCL_HOTFORK_CAPSULE_ABI_V1 &&
        capsule->descriptor_size == sizeof(*capsule) &&
        text_eq(capsule->owner_id, request->owner_id) &&
        text_eq(capsule->source_tu, request->source_tu) &&
        text_eq(capsule->candidate_object_root,
                request->candidate_object_root) &&
        text_eq(capsule->story_id, request->story_id) &&
        text_eq(capsule->story_root, request->story_root) &&
        text_eq(capsule->story_fixture_root, request->story_fixture_root) &&
        capsule->run_story;
}

static bool child_hotfork_visit(
    const struct zcl_hotfork_capsule_v1 *capsule, void *opaque)
{
    struct child_ctx *ctx = opaque;
    struct zcl_reflex_child_report *report = ctx->report;
    report->dlopen_us = platform_time_monotonic_us() - ctx->load_started_us;
    report->descriptor_valid = child_descriptor_matches(capsule, ctx->request);
    if (!report->descriptor_valid)
        return child_note(report, "descriptor",
                          "HOT_FORK descriptor binding mismatch"), false;
    if (!child_install_wx(report)) return false;
    report->candidate_executed = true;
    child_note(report, "story", NULL);
    int64_t started = platform_time_monotonic_us();
    report->story_ok = capsule->run_story(&report->observation);
    report->story_us = platform_time_monotonic_us() - started;
    return report->story_ok;
}

static void child_run_hotfork(struct child_ctx *ctx, int image_fd)
{
    struct zcl_reflex_child_report *report = ctx->report;
    char err[160] = {0};
    ctx->load_started_us = platform_time_monotonic_us();
    (void)zcl_hotswap_hotfork_visit_fd(
        image_fd, ctx->request->expected_sha256, child_hotfork_visit, ctx,
        report->runtime_module_sha256, err, sizeof(err));
    report->hash_verified = strcmp(report->runtime_module_sha256,
                                   ctx->request->expected_sha256) == 0;
    if (err[0]) child_note(report, "load", err);
}

static bool child_service_loaded(void *opaque, char *why, size_t why_sz)
{
    struct child_ctx *ctx = opaque;
    struct zcl_reflex_child_report *report = ctx->report;
    report->dlopen_us = platform_time_monotonic_us() - ctx->load_started_us;
    report->descriptor_valid = true;
    if (!child_install_wx(report)) {
        (void)snprintf(why, why_sz, "%s", report->error);
        return false;
    }
    report->candidate_executed = true;
    child_note(report, "story", NULL);
    ctx->story_started_us = platform_time_monotonic_us();
    return true;
}

static void child_run_shadow(struct child_ctx *ctx, int image_fd)
{
    struct zcl_reflex_child_report *report = ctx->report;
    ctx->load_started_us = platform_time_monotonic_us();
    report->hash_verified =
        zcl_reflex_sha256_fd(image_fd, report->runtime_module_sha256) &&
        strcmp(report->runtime_module_sha256,
               ctx->request->expected_sha256) == 0;
    if (!report->hash_verified) {
        child_note(report, "hash", "sealed image digest mismatch in child");
        return;
    }
    bool ok = zcl_native_hotswap_service_probe_fd(
        image_fd, child_service_loaded, ctx, &report->service);
    if (ctx->story_started_us)
        report->story_us = platform_time_monotonic_us() - ctx->story_started_us;
    const struct zcl_hotswap_service_report *svc = &report->service;
    report->story_ok = ok && svc->recognized && svc->ok && svc->probed &&
        svc->verify_only && !svc->activated;
    if (!report->story_ok)
        child_note(report, svc->stage[0] ? svc->stage : "probe",
                   svc->error[0] ? svc->error : "frozen KAT rejected");
}

[[noreturn]] void zcl_reflex_runner_child_main(
    const struct zcl_reflex_request *request, int image_fd, int report_fd,
    int runner_pid)
{
    struct zcl_reflex_child_report report = {
        .magic = ZCL_REFLEX_REPORT_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
    };
    report.start_us = platform_time_monotonic_us();
    report.sandboxed = child_confine(&report, request, image_fd, report_fd,
                                     runner_pid);
    report.confine_us = platform_time_monotonic_us() - report.start_us;
    struct child_ctx ctx = {.request = request, .report = &report};
    if (report.sandboxed && request->mode == ZCL_REFLEX_MODE_HOT_FORK)
        child_run_hotfork(&ctx, image_fd);
    else if (report.sandboxed && request->mode == ZCL_REFLEX_MODE_HOT_SHADOW)
        child_run_shadow(&ctx, image_fd);
    else if (report.sandboxed)
        child_note(&report, "mode", "unknown reflex mode");
    bool wrote = write_all(report_fd, &report, sizeof(report));
    _exit(wrote ? 0 : 125);
}

/* ── runner process ─────────────────────────────────────────────────────── */

static void frame_head(struct zcl_reflex_frame_head *head, uint32_t kind,
                       uint32_t size, uint64_t sequence)
{
    head->magic = ZCL_REFLEX_WIRE_MAGIC;
    head->abi = ZCL_REFLEX_WIRE_ABI;
    head->kind = kind;
    head->size = size;
    head->sequence = sequence;
}

static bool runner_send(const void *frame, size_t len)
{
    ssize_t n;
    do {
        n = send(ZCL_REFLEX_RUNNER_CONTROL_FD, frame, len, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    return n == (ssize_t)len;
}

static bool runner_peer_is_parent(void)
{
    struct ucred cred = {0};
    socklen_t cred_len = sizeof(cred);
    int type = 0;
    socklen_t type_len = sizeof(type);
    return getsockopt(ZCL_REFLEX_RUNNER_CONTROL_FD, SOL_SOCKET, SO_PEERCRED,
                      &cred, &cred_len) == 0 &&
        getsockopt(ZCL_REFLEX_RUNNER_CONTROL_FD, SOL_SOCKET, SO_TYPE, &type,
                   &type_len) == 0 &&
        type == SOCK_SEQPACKET && cred.pid > 1 && cred.pid == getppid();
}

/* Receives one datagram and at most one descriptor. Returns 1 with a frame,
 * 0 on orderly EOF, -1 on a malformed datagram (any descriptor closed). */
static int runner_recv(void *frame, size_t len, int *fd_out)
{
    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    struct iovec iov = {.iov_base = frame, .iov_len = len};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
                         .msg_control = control.buf,
                         .msg_controllen = sizeof(control.buf)};
    *fd_out = -1;
    ssize_t n;
    do {
        n = recvmsg(ZCL_REFLEX_RUNNER_CONTROL_FD, &msg, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    if (n == 0) return 0;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
        c->cmsg_len == CMSG_LEN(sizeof(int)))
        memcpy(fd_out, CMSG_DATA(c), sizeof(int));
    if (n < 0 || (size_t)n != len || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        if (*fd_out >= 0) (void)close(*fd_out);
        *fd_out = -1;
        return -1;
    }
    return 1;
}

static bool request_strings_terminated(const struct zcl_reflex_request *r)
{
    return memchr(r->expected_sha256, 0, sizeof(r->expected_sha256)) &&
        memchr(r->owner_id, 0, sizeof(r->owner_id)) &&
        memchr(r->source_tu, 0, sizeof(r->source_tu)) &&
        memchr(r->candidate_object_root, 0, sizeof(r->candidate_object_root)) &&
        memchr(r->story_id, 0, sizeof(r->story_id)) &&
        memchr(r->story_root, 0, sizeof(r->story_root)) &&
        memchr(r->story_fixture_root, 0, sizeof(r->story_fixture_root));
}

static bool request_valid(const struct zcl_reflex_request *r)
{
    return r->head.magic == ZCL_REFLEX_WIRE_MAGIC &&
        r->head.abi == ZCL_REFLEX_WIRE_ABI &&
        r->head.kind == ZCL_REFLEX_FRAME_REQUEST &&
        r->head.size == sizeof(*r) &&
        (r->mode == ZCL_REFLEX_MODE_HOT_FORK ||
         r->mode == ZCL_REFLEX_MODE_HOT_SHADOW) &&
        r->timeout_ms > 0 && r->timeout_ms <= 60000u &&
        request_strings_terminated(r) && strlen(r->expected_sha256) == 64;
}

static void reply_error(struct zcl_reflex_reply *reply, const char *error)
{
    if (!reply->error[0])
        (void)snprintf(reply->error, sizeof(reply->error), "%s", error);
}

/* The runner's own proof of what it hands to the child: the seals that make
 * the bytes immutable are present, and the digest is the requested one. */
static bool runner_verify_image(int image_fd,
                                const struct zcl_reflex_request *request,
                                struct zcl_reflex_reply *reply)
{
    const int want = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW;
    int seals = fcntl(image_fd, F_GET_SEALS);
    reply->seals_verified = seals >= 0 && (seals & want) == want;
    if (!reply->seals_verified)
        return reply_error(reply, "candidate image is not a sealed memfd"),
               false;
    if (!zcl_reflex_sha256_fd(image_fd, reply->runner_sha256) ||
        strcmp(reply->runner_sha256, request->expected_sha256) != 0)
        return reply_error(reply, "sealed image digest mismatch in runner"),
               false;
    return true;
}

struct collect_state {
    int report_fd;
    int64_t deadline_us;
    size_t have;
    bool eof;
    bool control_closed;
};

/* One poll step. Returns false when collection is over. */
static bool runner_collect_step(struct collect_state *st,
                                struct zcl_reflex_reply *reply)
{
    int64_t remaining = st->deadline_us - platform_time_monotonic_us();
    if (remaining <= 0) { reply->timed_out = true; return false; }
    struct pollfd pfd[2] = {
        {.fd = st->report_fd, .events = POLLIN},
        {.fd = ZCL_REFLEX_RUNNER_CONTROL_FD, .events = POLLIN},
    };
    int wait_ms = (int)((remaining + 999) / 1000);
    int ready = poll(pfd, 2, wait_ms);
    if (ready < 0) return errno == EINTR;
    if (pfd[1].revents) {
        struct zcl_reflex_frame_head cancel;
        int fd = -1;
        int got = runner_recv(&cancel, sizeof(cancel), &fd);
        if (fd >= 0) (void)close(fd);
        st->control_closed = got == 0;
        reply->cancelled = true;
        return false;
    }
    if (!pfd[0].revents) return true;
    uint8_t *dst = (uint8_t *)&reply->report;
    ssize_t n = st->have < sizeof(reply->report)
        ? read(st->report_fd, dst + st->have, sizeof(reply->report) - st->have)
        : read(st->report_fd, &(uint8_t){0}, 1);
    if (n > 0 && st->have < sizeof(reply->report)) st->have += (size_t)n;
    if (n == 0) st->eof = true;
    return n > 0 || (n < 0 && errno == EINTR);
}

static void runner_reap(pid_t child, struct zcl_reflex_reply *reply)
{
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    reply->child_exit_code = -1;
    if (waited == child && WIFEXITED(status))
        reply->child_exit_code = WEXITSTATUS(status);
    if (waited == child && WIFSIGNALED(status))
        reply->child_signal = WTERMSIG(status);
}

/* Fork, collect, kill at deadline, reap. Returns false only when the resident
 * closed the control socket mid-candidate (the runner then exits). */
static bool runner_execute(const struct zcl_reflex_request *request,
                           int image_fd, struct zcl_reflex_reply *reply)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return reply_error(reply, "report pipe unavailable"), true;
    int64_t started = platform_time_monotonic_us();
    int runner_pid = (int)getpid();
    pid_t child = fork();
    if (child == 0) {
        (void)close(pipefd[0]);
        zcl_reflex_runner_child_main(request, image_fd, pipefd[1], runner_pid);
    }
    (void)close(pipefd[1]);
    if (child < 0) {
        (void)close(pipefd[0]);
        return reply_error(reply, "candidate fork failed"), true;
    }
    struct collect_state st = {
        .report_fd = pipefd[0],
        .deadline_us = started + (int64_t)request->timeout_ms * 1000,
    };
    while (!st.eof && runner_collect_step(&st, reply)) {}
    if (!st.eof) (void)kill(child, SIGKILL);
    (void)close(pipefd[0]);
    runner_reap(child, reply);
    reply->report_complete = st.have == sizeof(reply->report) &&
        reply->report.magic == ZCL_REFLEX_REPORT_MAGIC &&
        reply->report.abi == ZCL_REFLEX_WIRE_ABI;
    if (reply->report_complete && reply->report.start_us >= started)
        reply->fork_us = reply->report.start_us - started;
    reply->total_us = platform_time_monotonic_us() - started;
    return !st.control_closed;
}

/* One request/reply turn. Returns false when the runner should exit. */
static bool runner_serve_one(void)
{
    struct zcl_reflex_request request;
    int image_fd = -1;
    int got = runner_recv(&request, sizeof(request), &image_fd);
    if (got == 0) return false;
    struct zcl_reflex_reply reply = {0};
    frame_head(&reply.head, ZCL_REFLEX_FRAME_REPLY, sizeof(reply),
               got > 0 ? request.head.sequence : 0);
    reply.child_exit_code = -1;
    bool keep_running = true;
    if (got < 0 || image_fd < 0 || !request_valid(&request))
        reply_error(&reply, "malformed reflex request");
    else if (runner_verify_image(image_fd, &request, &reply))
        keep_running = runner_execute(&request, image_fd, &reply);
    if (image_fd >= 0) (void)close(image_fd);
    return runner_send(&reply, sizeof(reply)) && keep_running;
}

static bool runner_enter(void)
{
    const int keep[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                        ZCL_REFLEX_RUNNER_CONTROL_FD};
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    return prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && runner_peer_is_parent() &&
        os_sandbox_no_new_privs() && zcl_reflex_close_all_except(keep, 4) &&
        chdir("/") == 0 && sigaction(SIGPIPE, &ignore, NULL) == 0 &&
        os_sandbox_seccomp_deny(g_runner_denied, sizeof(g_runner_denied) /
                                sizeof(g_runner_denied[0]), false).ok;
}

/* Before serving, prove the leaf filters bite on THIS kernel: one disposable
 * child per surface enters exactly the candidate filter stack and makes the
 * call. Only death by SIGSYS counts; a runner whose filters let any probe
 * through refuses to say hello, so the resident reports the runner
 * unavailable instead of running candidates behind a hollow filter. */
[[noreturn]] static void runner_probe_child(unsigned which)
{
    unsigned char params[120] = {0}; /* struct io_uring_params, zeroed */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || !child_install_filters())
        _exit(2);
    if (which == 0) (void)syscall(SYS_io_uring_setup, 8u, params);
    else if (which == 1) (void)syscall(SYS_pidfd_open, getppid(), 0u);
    else (void)kill(getppid(), 0);
    _exit(0);
}

static uint32_t runner_deny_probes(void)
{
    uint32_t killed = 0;
    for (unsigned which = 0; which < ZCL_REFLEX_DENY_PROBES; which++) {
        pid_t child = fork();
        if (child == 0) runner_probe_child(which);
        int status = 0;
        pid_t waited = -1;
        if (child > 0)
            do { waited = waitpid(child, &status, 0); }
            while (waited < 0 && errno == EINTR);
        if (waited == child && WIFSIGNALED(status) &&
            WTERMSIG(status) == SIGSYS)
            killed++;
    }
    return killed;
}

static int runner_main(void)
{
    if (!runner_enter()) return 3;
    uint32_t probes_killed = runner_deny_probes();
    if (probes_killed != ZCL_REFLEX_DENY_PROBES) return 5;
    const int keep[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                        ZCL_REFLEX_RUNNER_CONTROL_FD};
    struct zcl_reflex_hello hello = {
        .pid = (int32_t)getpid(),
        .env_count = zcl_reflex_env_count(),
        .fd_count = zcl_reflex_count_fds_except(keep, 4),
        .resident_canary_seen = zcl_reflex_resident_canary,
        .deny_probes_killed = probes_killed,
    };
    frame_head(&hello.head, ZCL_REFLEX_FRAME_HELLO, sizeof(hello), 0);
    if (!runner_send(&hello, sizeof(hello))) return 4;
    while (runner_serve_one()) {}
    return 0;
}

#endif /* __linux__ */

bool zcl_reflex_runner_dispatch(int argc, char **argv, int *rc)
{
    if (argc != 2 || !argv || !argv[1] ||
        strcmp(argv[1], ZCL_REFLEX_RUNNER_ARGV1) != 0 || !rc)
        return false;
#if defined(__linux__)
    *rc = runner_main();
#else
    *rc = 2;
#endif
    return true;
}

void zcl_reflex_runner_exit_if_requested(int argc, char **argv)
{
    int rc = 0;
    if (zcl_reflex_runner_dispatch(argc, argv, &rc))
        exit(rc);
}
