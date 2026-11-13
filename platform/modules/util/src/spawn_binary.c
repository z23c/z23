/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exact bounded capture validation and private capture pipe support. */
#define _GNU_SOURCE
#include "util/spawn.h"
#include "spawn_binary_internal.h"
#include <string.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
/* Non-Linux fallback is close-on-exec but cannot make pipe creation atomic
 * against unrelated threads that fork before fcntl has completed. */
static bool private_pipe_create(int p[2])
{
#if defined(__linux__)
    return pipe2(p, O_CLOEXEC) == 0;
#else
    if (pipe(p) != 0) return false;
    if (fcntl(p[0], F_SETFD, FD_CLOEXEC) == 0 &&
        fcntl(p[1], F_SETFD, FD_CLOEXEC) == 0) return true;
    int saved = errno;
    close(p[0]); close(p[1]); p[0] = p[1] = -1; errno = saved;
    return false;
#endif
}
bool zcl_spawn_private_pipe(int p[2])
{
    if (!private_pipe_create(p)) return false;
    for (int i = 0; i < 2; i++) {
        if (p[i] > STDERR_FILENO) continue;
        int fd = fcntl(p[i], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        if (fd < 0) {
            int saved = errno;
            close(p[0]); close(p[1]); p[0] = p[1] = -1; errno = saved;
            return false;
        }
        close(p[i]); p[i] = fd;
    }
    return true;
}
#ifdef ZCL_TESTING
static _Thread_local void (*private_hook)(const int *, size_t, void *);
static _Thread_local void *private_context;
void zcl_spawn_evidence_test_prefork(void (*hook)(const int *, size_t, void *), void *context)
{
    private_hook = hook; private_context = context;
}
void zcl_spawn_private_prefork(const int *fds, size_t count)
{
    if (private_hook) private_hook(fds, count, private_context);
}
#endif
#endif

/* One exact capture for both stderr dispositions: the success predicate
 * and every observation field are the same, so only the child's stderr
 * changes hands. */
#if !defined(_WIN32)
static bool spawn_binary_complete(int rc, const struct zcl_spawn_binary_observation *out)
{
    return rc == 0 && out->exit_code == 0 && out->eof && !out->overflow && !out->timed_out && out->exit_observed;
}
#endif
static struct zcl_result spawn_capture_binary_impl(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    bool merge_stderr, struct zcl_spawn_binary_observation *out)
{
    if (out) {
        memset(out, 0, sizeof(*out));
        out->exit_code = -1;
    }
    if (!out || !argv || !argv[0] || !buf || cap == 0 || timeout_ms <= 0)
        return ZCL_ERR(-1, "spawn: exact binary capture requires bounded inputs");
#ifdef _WIN32
    (void)merge_stderr;
    return ZCL_ERR(-1, "spawn: Windows binary capture is unavailable");
#else
    int rc = zcl_spawn_exact_internal(argv, buf, cap, timeout_ms, NULL, NULL,
                                NULL, merge_stderr, out, NULL, NULL, NULL, NULL, NULL);
    if (!spawn_binary_complete(rc, out))
        return ZCL_ERR(-1, "spawn: incomplete binary capture (exit=%d eof=%d overflow=%d timeout=%d observed=%d)",
                       rc, out->eof, out->overflow, out->timed_out,
                       out->exit_observed);
    return ZCL_OK;
#endif
}

static void spawn_observer_clear(bool *cancelled, bool *refused,
    struct zcl_spawn_binary_observation *out, struct zcl_spawn_measure *measure)
{
    if (cancelled) *cancelled = false;
    if (refused) *refused = false;
    if (measure) memset(measure, 0, sizeof(*measure));
    if (out) { memset(out, 0, sizeof(*out)); out->exit_code = -1; }
}
static bool spawn_observer_args(const char *const argv[], const void *buf, size_t cap,
    int timeout_ms, zcl_spawn_bytes_fn observe, const bool *refused,
    const struct zcl_spawn_binary_observation *out)
{
    return out && refused && observe && argv && argv[0] && buf && cap && timeout_ms > 0;
}
#if !defined(_WIN32)
static bool spawn_observer_complete(int rc, const bool *refused, const bool *cancelled,
    const struct zcl_spawn_binary_observation *out, const struct zcl_spawn_measure *measure)
{
    return !*refused && spawn_binary_complete(rc, out) &&
        (!cancelled || !*cancelled) && (!measure || measure->reaped);
}
#endif
struct zcl_result zcl_spawn_capture_binary_observe(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled,
    zcl_spawn_bytes_fn observe, zcl_spawn_end_fn on_end, void *observe_ctx, bool *refused,
    struct zcl_spawn_binary_observation *out, struct zcl_spawn_measure *measure)
{
    spawn_observer_clear(cancelled, refused, out, measure);
    if (!spawn_observer_args(argv, buf, cap, timeout_ms, observe, refused, out))
        return ZCL_ERR(-1, "spawn: observed binary capture requires bounded inputs");
#ifdef _WIN32
    (void)should_cancel; (void)cancel_ctx; (void)on_end; (void)observe_ctx;
    return ZCL_ERR(-1, "spawn: Windows binary capture is unavailable");
#else
    int rc = zcl_spawn_exact_internal(argv, buf, cap, timeout_ms,
        should_cancel, cancel_ctx, cancelled, false, out, measure,
        observe, on_end, observe_ctx, refused);
    if (!spawn_observer_complete(rc, refused, cancelled, out, measure))
        return ZCL_ERR(-1, "spawn: incomplete observed binary capture");
    return ZCL_OK;
#endif
}

struct zcl_result zcl_spawn_capture_binary_cancelable_measured(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled,
    struct zcl_spawn_binary_observation *out, struct zcl_spawn_measure *measure)
{
    if (cancelled) *cancelled = false;
    if (measure) memset(measure, 0, sizeof(*measure));
    if (out) { memset(out, 0, sizeof(*out)); out->exit_code = -1; }
    if (!out || !argv || !argv[0] || !buf || !cap || timeout_ms <= 0)
        return ZCL_ERR(-1, "spawn: exact binary capture requires bounded inputs");
#ifdef _WIN32
    (void)should_cancel; (void)cancel_ctx;
    return ZCL_ERR(-1, "spawn: Windows binary capture is unavailable");
#else
    int rc = zcl_spawn_exact_internal(argv, buf, cap, timeout_ms, should_cancel,
        cancel_ctx, cancelled, false, out, measure, NULL, NULL, NULL, NULL);
    if (!spawn_binary_complete(rc, out) || (cancelled && *cancelled) || (measure && !measure->reaped))
        return ZCL_ERR(-1, "spawn: incomplete cancellable binary capture");
    return ZCL_OK;
#endif
}

struct zcl_result zcl_spawn_capture_binary(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    struct zcl_spawn_binary_observation *out)
{
    return spawn_capture_binary_impl(argv, buf, cap, timeout_ms, false, out);
}

struct zcl_result zcl_spawn_capture_binary_merged(
    const char *const argv[], void *buf, size_t cap, int timeout_ms,
    struct zcl_spawn_binary_observation *out)
{
    return spawn_capture_binary_impl(argv, buf, cap, timeout_ms, true, out);
}
