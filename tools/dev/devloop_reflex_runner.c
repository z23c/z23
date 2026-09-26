/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Resident-side client of the clean-zygote reflex runner.
 *
 * The resident spawns the runner lazily by exec of its own image (never a
 * fork that survives into candidate execution), keeps it warm, seals each
 * candidate into a memfd, and relays one fixed-size request per candidate.
 * Candidate bytes never execute in this process. See devloop_reflex_runner.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* MSG_CMSG_CLOEXEC, F_DUPFD_CLOEXEC */
#endif

#include "devloop_reflex_runner_wire.h"

#include "devloop.h"
#include "base/log_macros.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include "hotswap/hotswap_sealed_image.h"
#include "platform/process_compat.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#endif

volatile uint64_t zcl_reflex_resident_canary;

#define REFLEX_GREEN_SLOTS 64u
#define REFLEX_HELLO_TIMEOUT_MS 5000
#define REFLEX_REPLY_GRACE_MS 2000

struct reflex_green_slot {
    char source_tu[256];
    char root[65];
};

static pthread_mutex_t g_green_mu = PTHREAD_MUTEX_INITIALIZER;
static struct reflex_green_slot g_green[REFLEX_GREEN_SLOTS];
static size_t g_green_count;

static void reflex_green_record(const char *source_tu, const char *root)
{
    pthread_mutex_lock(&g_green_mu);
    size_t slot = g_green_count;
    for (size_t i = 0; i < g_green_count; i++)
        if (strcmp(g_green[i].source_tu, source_tu) == 0) slot = i;
    if (slot == g_green_count && g_green_count < REFLEX_GREEN_SLOTS)
        g_green_count++;
    if (slot < REFLEX_GREEN_SLOTS) {
        (void)snprintf(g_green[slot].source_tu,
                       sizeof(g_green[slot].source_tu), "%s", source_tu);
        (void)snprintf(g_green[slot].root, sizeof(g_green[slot].root), "%s",
                       root);
    }
    pthread_mutex_unlock(&g_green_mu);
}

bool zcl_reflex_runner_last_green(const char *source_tu, char out[65])
{
    bool found = false;
    if (!source_tu || !out) return false;
    pthread_mutex_lock(&g_green_mu);
    for (size_t i = 0; i < g_green_count && !found; i++)
        if (strcmp(g_green[i].source_tu, source_tu) == 0) {
            (void)snprintf(out, 65, "%s", g_green[i].root);
            found = true;
        }
    pthread_mutex_unlock(&g_green_mu);
    return found;
}

static bool lower_hex64(const char *s)
{
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static void outcome_reason(struct zcl_reflex_runner_outcome *out,
                           const char *reason)
{
    if (!out->reason[0])
        (void)snprintf(out->reason, sizeof(out->reason), "%s", reason);
}

#if defined(__linux__)

struct reflex_runner_state {
    pid_t pid;
    int control_fd;
    uint64_t sequence;
    struct zcl_reflex_hello hello;
};

static pthread_mutex_t g_runner_mu = PTHREAD_MUTEX_INITIALIZER;
static struct reflex_runner_state g_runner = {.pid = -1, .control_fd = -1};

static void runner_reset_locked(void)
{
    if (g_runner.control_fd >= 0) (void)close(g_runner.control_fd);
    if (g_runner.pid > 0) {
        (void)kill(g_runner.pid, SIGKILL);
        pid_t waited;
        do { waited = waitpid(g_runner.pid, NULL, 0); }
        while (waited < 0 && errno == EINTR);
    }
    g_runner.pid = -1;
    g_runner.control_fd = -1;
}

void zcl_reflex_runner_shutdown(void)
{
    pthread_mutex_lock(&g_runner_mu);
    runner_reset_locked();
    pthread_mutex_unlock(&g_runner_mu);
}

/* Between fork and exec in a possibly multithreaded resident: only
 * descriptor syscalls and the exec itself. The runner inherits exactly
 * stdio on /dev/null and the control socket at the fixed descriptor. */
[[noreturn]] static void runner_exec_child(int exe_fd, int sock_fd,
                                           int null_fd)
{
    int exe = fcntl(exe_fd, F_DUPFD_CLOEXEC, 16);
    int sock = fcntl(sock_fd, F_DUPFD_CLOEXEC, 16);
    int null = fcntl(null_fd, F_DUPFD_CLOEXEC, 16);
    if (exe < 0 || sock < 0 || null < 0 ||
        dup2(null, STDIN_FILENO) < 0 || dup2(null, STDOUT_FILENO) < 0 ||
        dup2(null, STDERR_FILENO) < 0 ||
        dup2(sock, ZCL_REFLEX_RUNNER_CONTROL_FD) < 0)
        _exit(127);
    const int keep[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                        ZCL_REFLEX_RUNNER_CONTROL_FD, exe};
    if (!zcl_reflex_close_all_except(keep, 5)) _exit(127);
    char arg0[] = ZCL_REFLEX_RUNNER_ARGV0;
    char arg1[] = ZCL_REFLEX_RUNNER_ARGV1;
    char *const argv[] = {arg0, arg1, NULL};
    char *const envp[] = {NULL};
    (void)platform_execve_fd(exe, argv, envp);
    _exit(127);
}

static bool control_wait(int fd, int64_t deadline_us)
{
    for (;;) {
        int64_t remaining = deadline_us - platform_time_monotonic_us();
        if (remaining <= 0) return false;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, (int)((remaining + 999) / 1000));
        if (ready > 0) return true;
        if (ready < 0 && errno != EINTR) return false;
    }
}

static bool hello_valid(const struct zcl_reflex_hello *h, ssize_t n,
                        pid_t child)
{
    return n == (ssize_t)sizeof(*h) && h->head.magic == ZCL_REFLEX_WIRE_MAGIC &&
        h->head.abi == ZCL_REFLEX_WIRE_ABI &&
        h->head.kind == ZCL_REFLEX_FRAME_HELLO &&
        h->head.size == sizeof(*h) && h->pid == (int32_t)child;
}

static bool runner_await_hello(struct zcl_reflex_runner_outcome *out)
{
    int64_t deadline = platform_time_monotonic_us() +
        (int64_t)REFLEX_HELLO_TIMEOUT_MS * 1000;
    if (!control_wait(g_runner.control_fd, deadline))
        return outcome_reason(out, "reflex runner did not start (no hello)"),
               false;
    ssize_t n;
    do {
        n = recv(g_runner.control_fd, &g_runner.hello, sizeof(g_runner.hello),
                 0);
    } while (n < 0 && errno == EINTR);
    if (!hello_valid(&g_runner.hello, n, g_runner.pid))
        return outcome_reason(out, "reflex runner hello refused"), false;
    /* The runner must be a clean image: nothing inherited, nothing shared. */
    if (g_runner.hello.env_count != 0 || g_runner.hello.fd_count != 0 ||
        g_runner.hello.resident_canary_seen != 0)
        return outcome_reason(out, "reflex runner is not a clean zygote"),
               false;
    /* Its own startup probes must have seen every kernel-surface filter bite
     * (the runner refuses to say hello otherwise; this re-checks the claim). */
    if (g_runner.hello.deny_probes_killed != ZCL_REFLEX_DENY_PROBES)
        return outcome_reason(out, "reflex runner deny filters not enforced"),
               false;
    return true;
}

static bool runner_fork_exec(int exe_fd, int sv[2], int null_fd)
{
    pid_t child = fork();
    if (child == 0) runner_exec_child(exe_fd, sv[1], null_fd);
    (void)close(sv[1]);
    if (child < 0) {
        (void)close(sv[0]);
        return false;
    }
    g_runner.pid = child;
    g_runner.control_fd = sv[0];
    return true;
}

static bool runner_spawn_locked(struct zcl_reflex_runner_outcome *out)
{
    if (zcl_reflex_resident_canary == 0)
        zcl_reflex_resident_canary =
            ((uint64_t)platform_time_monotonic_us() ^
             ((uint64_t)getpid() << 32)) | 1u;
    int64_t started = platform_time_monotonic_us();
    int exe_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    int sv[2] = {-1, -1};
    bool ok = exe_fd >= 0 && null_fd >= 0 &&
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0 &&
        runner_fork_exec(exe_fd, sv, null_fd);
    if (exe_fd >= 0) (void)close(exe_fd);
    if (null_fd >= 0) (void)close(null_fd);
    if (!ok) {
        LOG_WARN("devloop.reflex", "runner spawn failed: %s", strerror(errno));
        return outcome_reason(out, "reflex runner spawn failed"), false;
    }
    if (!runner_await_hello(out)) {
        LOG_WARN("devloop.reflex", "runner refused: %s", out->reason);
        runner_reset_locked();
        return false;
    }
    out->spawn_us = platform_time_monotonic_us() - started;
    return true;
}

static bool runner_alive_locked(void)
{
    if (g_runner.pid <= 0 || g_runner.control_fd < 0) return false;
    int status = 0;
    pid_t waited = waitpid(g_runner.pid, &status, WNOHANG);
    if (waited == 0) return true;
    g_runner.pid = -1;
    runner_reset_locked();
    return false;
}

static bool runner_ensure_locked(struct zcl_reflex_runner_outcome *out)
{
    out->runner_warm = runner_alive_locked();
    if (!out->runner_warm && !runner_spawn_locked(out)) return false;
    out->runner_pid = (int)g_runner.pid;
    out->runner_env_count = g_runner.hello.env_count;
    out->runner_fd_count = g_runner.hello.fd_count;
    out->runner_deny_probes = g_runner.hello.deny_probes_killed;
    return true;
}

static bool copy_field(char *dst, size_t cap, const char *src)
{
    const char *text = src ? src : "";
    size_t n = strlen(text);
    if (n >= cap) return false;
    memcpy(dst, text, n + 1);
    return true;
}

static bool request_build(const struct zcl_reflex_runner_spec *spec,
                          struct zcl_reflex_request *r)
{
    memset(r, 0, sizeof(*r));
    r->mode = (uint32_t)spec->mode;
    r->timeout_ms = spec->timeout_ms;
#if defined(ZCL_TESTING)
    if (spec->testing_disable_close_range)
        r->testing_flags |= ZCL_REFLEX_TESTING_DISABLE_CLOSE_RANGE;
#endif
    return (spec->mode == ZCL_REFLEX_MODE_HOT_FORK ||
            spec->mode == ZCL_REFLEX_MODE_HOT_SHADOW) &&
        spec->timeout_ms > 0 && spec->timeout_ms <= 60000u &&
        lower_hex64(spec->artifact_sha256) && spec->source_tu &&
        spec->source_tu[0] &&
        copy_field(r->expected_sha256, sizeof(r->expected_sha256),
                   spec->artifact_sha256) &&
        copy_field(r->owner_id, sizeof(r->owner_id), spec->owner_id) &&
        copy_field(r->source_tu, sizeof(r->source_tu), spec->source_tu) &&
        copy_field(r->candidate_object_root, sizeof(r->candidate_object_root),
                   spec->candidate_object_root) &&
        copy_field(r->story_id, sizeof(r->story_id), spec->story_id) &&
        copy_field(r->story_root, sizeof(r->story_root), spec->story_root) &&
        copy_field(r->story_fixture_root, sizeof(r->story_fixture_root),
                   spec->story_fixture_root);
}

/* Copy the artifact into a sealed memfd and prove, from the SEALED bytes,
 * that it is the requested candidate. */
static int seal_artifact(const struct zcl_reflex_runner_spec *spec,
                         struct zcl_reflex_runner_outcome *out)
{
    int64_t started = platform_time_monotonic_us();
    int src = spec->artifact_path
        ? open(spec->artifact_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    if (src < 0)
        return outcome_reason(out, "candidate artifact unreadable"), -1;
    char err[256] = {0};
    int image = hotswap_sealed_image_from_fd(src, err, sizeof(err));
    (void)close(src);
    if (image < 0) return outcome_reason(out, err), -1;
    char got[65] = {0};
    if (!zcl_reflex_sha256_fd(image, got) ||
        strcmp(got, spec->artifact_sha256) != 0) {
        (void)close(image);
        return outcome_reason(out, "sealed candidate digest mismatch"), -1;
    }
    out->seal_us = platform_time_monotonic_us() - started;
    return image;
}

static bool send_request(const struct zcl_reflex_request *r, int image_fd)
{
    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = {.iov_base = (void *)r, .iov_len = sizeof(*r)};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
                         .msg_control = control.buf,
                         .msg_controllen = sizeof(control.buf)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &image_fd, sizeof(int));
    ssize_t n;
    do { n = sendmsg(g_runner.control_fd, &msg, MSG_NOSIGNAL); }
    while (n < 0 && errno == EINTR);
    return n == (ssize_t)sizeof(*r);
}

static void send_cancel(uint64_t sequence)
{
    struct zcl_reflex_frame_head cancel = {
        .magic = ZCL_REFLEX_WIRE_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
        .kind = ZCL_REFLEX_FRAME_CANCEL, .size = sizeof(cancel),
        .sequence = sequence,
    };
    ssize_t n;
    do { n = send(g_runner.control_fd, &cancel, sizeof(cancel), MSG_NOSIGNAL); }
    while (n < 0 && errno == EINTR);
}

static bool reply_valid(const struct zcl_reflex_reply *r, ssize_t n,
                        uint64_t sequence)
{
    return n == (ssize_t)sizeof(*r) && r->head.magic == ZCL_REFLEX_WIRE_MAGIC &&
        r->head.abi == ZCL_REFLEX_WIRE_ABI &&
        r->head.kind == ZCL_REFLEX_FRAME_REPLY &&
        r->head.size == sizeof(*r) && r->head.sequence == sequence;
}

/* Wait for the reply, forwarding a supersede request to the runner (which
 * kills the child and still replies). */
static bool await_reply(uint64_t sequence, uint32_t timeout_ms,
                        struct zcl_reflex_reply *reply)
{
    int64_t deadline = platform_time_monotonic_us() +
        ((int64_t)timeout_ms + REFLEX_REPLY_GRACE_MS) * 1000;
    bool cancel_sent = false;
    for (;;) {
        if (!cancel_sent && zcl_devloop_process_cancel_requested()) {
            send_cancel(sequence);
            cancel_sent = true;
        }
        int64_t step = platform_time_monotonic_us() + 10000;
        if (control_wait(g_runner.control_fd, step < deadline ? step : deadline))
            break;
        if (platform_time_monotonic_us() >= deadline) return false;
    }
    ssize_t n;
    do { n = recv(g_runner.control_fd, reply, sizeof(*reply), 0); }
    while (n < 0 && errno == EINTR);
    return reply_valid(reply, n, sequence);
}

static bool runner_roundtrip(const struct zcl_reflex_runner_spec *spec,
                             struct zcl_reflex_request *request,
                             int image_fd, struct zcl_reflex_reply *reply,
                             struct zcl_reflex_runner_outcome *out)
{
    pthread_mutex_lock(&g_runner_mu);
    bool ok = runner_ensure_locked(out);
    if (ok) {
        request->head = (struct zcl_reflex_frame_head){
            .magic = ZCL_REFLEX_WIRE_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
            .kind = ZCL_REFLEX_FRAME_REQUEST, .size = sizeof(*request),
            .sequence = ++g_runner.sequence,
        };
        ok = send_request(request, image_fd) &&
            await_reply(request->head.sequence, spec->timeout_ms, reply);
        if (!ok) {
            outcome_reason(out, "reflex runner transport failed");
            runner_reset_locked();
        }
    }
    pthread_mutex_unlock(&g_runner_mu);
    return ok;
}

#else /* !__linux__ */

void zcl_reflex_runner_shutdown(void) {}

#endif /* __linux__ */

static bool outcome_story_green(const struct zcl_reflex_runner_spec *spec,
                                const struct zcl_reflex_child_report *r)
{
    if (spec->mode == ZCL_REFLEX_MODE_HOT_SHADOW)
        return r->service.recognized && r->service.ok && r->service.probed &&
            r->service.verify_only && !r->service.activated;
    return r->observation.magic == ZCL_HOTFORK_OBSERVATION_MAGIC &&
        r->observation.checks_run > 0 &&
        r->observation.checks_run == r->observation.checks_passed;
}

/* The runner's own verdict: exact image, both frames well formed, clean exit
 * inside the deadline, and exactly one W^X layer observed past pre-load. */
static bool outcome_process_clean(const struct zcl_reflex_runner_spec *spec,
                                  const struct zcl_reflex_reply *reply)
{
    return reply->frames.status == ZCL_REFLEX_FRAMES_OK &&
        !reply->timed_out && !reply->cancelled && reply->seals_verified &&
        reply->wx_observed && reply->child_exit_code == 0 &&
        reply->child_signal == 0 &&
        strcmp(reply->runner_sha256, spec->artifact_sha256) == 0;
}

/* Pre-load claims plus the observation bits a GREEN story needs. */
static bool outcome_child_confined(const struct zcl_reflex_runner_spec *spec,
                                   const struct zcl_reflex_child_report *r)
{
    return strcmp(r->runtime_module_sha256, spec->artifact_sha256) == 0 &&
        r->hash_verified && r->descriptor_valid && r->sandboxed &&
        r->wx_installed && r->candidate_executed && r->story_ok &&
        r->env_count == 0 && r->inherited_fd_count == 0;
}

static bool reply_digest_ok(const char *s, size_t cap)
{
    if (!memchr(s, '\0', cap)) return false;
    return s[0] == '\0' || lower_hex64(s);
}

/* Every string and flag the resident may touch, checked before any use:
 * the runner's own fields, then each frame the leaf delivered. */
static const char *reply_invalid(const struct zcl_reflex_reply *reply)
{
    const struct zcl_reflex_frames *f = &reply->frames;
    if (!memchr(reply->error, '\0', sizeof(reply->error)))
        return "reflex reply error unterminated";
    if (!reply_digest_ok(reply->runner_sha256, sizeof(reply->runner_sha256)))
        return "reflex reply runner_sha256 is not 64 lowercase hex";
    const char *why = f->preload_present
        ? zcl_reflex_preload_invalid(&f->preload) : NULL;
    if (!why && f->observation_present)
        why = zcl_reflex_observation_invalid(&f->observation);
    return why;
}

static void outcome_take_preload(const struct zcl_reflex_preload_frame *p,
                                 struct zcl_reflex_child_report *r)
{
    r->hash_verified = p->hash_verified == 1u;
    r->sandboxed = p->sandboxed == 1u;
    r->env_count = p->env_count;
    r->inherited_fd_count = p->inherited_fd_count;
    r->resident_canary_seen = p->resident_canary_seen;
    r->start_us = p->start_us;
    r->confine_us = p->confine_us;
    memcpy(r->runtime_module_sha256, p->runtime_module_sha256,
           sizeof(r->runtime_module_sha256));
    memcpy(r->stage, p->stage, sizeof(r->stage));
    memcpy(r->error, p->error, sizeof(r->error));
}

static void outcome_take_observation(
    const struct zcl_reflex_observation_frame *o,
    struct zcl_reflex_child_report *r)
{
    r->story_ok = o->story_ok == 1u;
    r->descriptor_valid = o->descriptor_valid == 1u;
    r->candidate_executed = o->candidate_executed == 1u;
    r->dlopen_us = o->dlopen_us;
    r->story_us = o->story_us;
    r->observation = o->observation;
    r->service = o->service;
    memcpy(r->stage, o->stage, sizeof(r->stage));
    if (!r->error[0]) memcpy(r->error, o->error, sizeof(r->error));
}

static void outcome_copy_reply(const struct zcl_reflex_reply *reply,
                               struct zcl_reflex_runner_outcome *out)
{
    out->available = true;
    out->timed_out = reply->timed_out;
    out->cancelled = reply->cancelled;
    out->seals_verified = reply->seals_verified;
    out->child_exit_code = reply->child_exit_code;
    out->child_signal = reply->child_signal;
    out->fork_us = reply->fork_us;
    out->runner_total_us = reply->total_us;
    out->report.wx_installed = reply->wx_observed;
}

/* Assemble the validated view. Names the first cause: the runner's error,
 * then the leaf's pre-load refusal, then a framing defect, then the story. */
static void outcome_assemble(const struct zcl_reflex_reply *reply,
                             struct zcl_reflex_runner_outcome *out)
{
    const struct zcl_reflex_frames *f = &reply->frames;
    struct zcl_reflex_child_report *r = &out->report;
    memcpy(out->runner_sha256, reply->runner_sha256,
           sizeof(out->runner_sha256));
    if (f->preload_present) {
        outcome_take_preload(&f->preload, r);
        out->confine_us = r->confine_us;
        out->env_inherited_count = r->env_count;
        out->inherited_fd_count = r->inherited_fd_count;
        out->address_space_fresh = zcl_reflex_resident_canary != 0 &&
            r->resident_canary_seen == 0;
    }
    if (f->observation_present) {
        outcome_take_observation(&f->observation, r);
        out->dlopen_us = r->dlopen_us;
        out->story_us = r->story_us;
    }
    out->report_complete = f->status == ZCL_REFLEX_FRAMES_OK;
    if (reply->error[0]) outcome_reason(out, reply->error);
    if (f->preload_present && f->preload.error[0])
        outcome_reason(out, f->preload.error);
    if (!out->report_complete)
        outcome_reason(out, zcl_reflex_frames_reason(
                                (enum zcl_reflex_frames_status)f->status));
    if (r->error[0]) outcome_reason(out, r->error);
}

static void outcome_from_reply(const struct zcl_reflex_runner_spec *spec,
                               const struct zcl_reflex_reply *reply,
                               struct zcl_reflex_runner_outcome *out)
{
    outcome_copy_reply(reply, out);
    const char *invalid = reply_invalid(reply);
    if (invalid) {
        /* Nothing from a malformed reply reaches the outcome but its name. */
        LOG_WARN("devloop.reflex", "runner reply refused: %s", invalid);
        outcome_reason(out, invalid);
        return;
    }
    outcome_assemble(reply, out);
    out->green = outcome_process_clean(spec, reply) &&
        outcome_child_confined(spec, &out->report) &&
        out->address_space_fresh && outcome_story_green(spec, &out->report);
}

bool zcl_reflex_runner_run(const struct zcl_reflex_runner_spec *spec,
                           struct zcl_reflex_runner_outcome *out)
{
    if (!out) LOG_FAIL("devloop.reflex", "outcome is NULL");
    memset(out, 0, sizeof(*out));
    out->child_exit_code = -1;
#if defined(__linux__)
    struct zcl_reflex_request request;
    if (!spec || !request_build(spec, &request))
        return outcome_reason(out, "invalid reflex runner request"), false;
    int image_fd = seal_artifact(spec, out);
    if (image_fd < 0) {
        LOG_WARN("devloop.reflex", "candidate not sealed: %s", out->reason);
        return false;
    }
    struct zcl_reflex_reply reply;
    memset(&reply, 0, sizeof(reply));
    bool ok = runner_roundtrip(spec, &request, image_fd, &reply, out);
    (void)close(image_fd);
    if (!ok) {
        LOG_WARN("devloop.reflex", "runner unavailable: %s", out->reason);
        return false;
    }
    outcome_from_reply(spec, &reply, out);
    if (out->green)
        reflex_green_record(spec->source_tu, spec->artifact_sha256);
    return true;
#else
    (void)spec;
    (void)outcome_from_reply;
    (void)reflex_green_record;
    outcome_reason(out, "clean-zygote reflex runner requires Linux "
                        "(exec + memfd + Landlock + seccomp)");
    return false;
#endif
}
