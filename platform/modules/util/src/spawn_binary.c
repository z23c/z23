/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exact bounded capture validation, using the single process owner in spawn.c. */
#include "util/spawn.h"
#include "spawn_binary_internal.h"
#include <string.h>

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
