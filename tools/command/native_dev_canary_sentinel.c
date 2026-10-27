/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: checked canary sentinel reset and publication with retained directory ownership and file durability.
 */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#if !defined(_WIN32)
#include "platform/file_sync.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum canary_persist_result { CANARY_PERSIST_OK, CANARY_PERSIST_IO,
                             CANARY_PERSIST_UNKNOWN };
struct canary_trace {
    const char *phase;
    int error;
    bool mutated;
};

static void canary_phase(struct canary_trace *trace, const char *phase)
{
    trace->phase = phase;
    errno = 0;
}

#ifdef ZCL_TESTING
static _Thread_local const char *canary_failure;
void zcl_native_canary_sentinel_fail_for_test(const char *phase)
{
    canary_failure = phase;
}
static bool canary_injected(const char *phase)
{
    if (!canary_failure || strcmp(canary_failure, phase) != 0)
        return false;
    canary_failure = NULL;
    errno = EIO;
    return true;
}
#else
static bool canary_injected(const char *phase)
{
    (void)phase;
    return false;
}
#endif

static const char *canary_started_ts(const struct json_value *input, char out[24])
{
    const struct json_value *v = input ? json_get(input, "started_ts") : NULL;
    if (v && v->type == JSON_INT && json_get_int(v) >= 0) {
        (void)snprintf(out, 24, "%lld", (long long)json_get_int(v));
        return out;
    }
    return json_get_str(json_get(input, "started_ts"));
}

static bool canary_decimal(const char *text)
{
    if (!text || !*text || strlen(text) > 20)
        return false;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

static bool canary_stage_name(const char *stage, const char *sentinel)
{
    size_t n = strlen(sentinel);
    return stage && strncmp(stage, sentinel, n) == 0 &&
           strncmp(stage + n, ".tmp.", 5) == 0 &&
           canary_decimal(stage + n + 5);
}

/* Cleanup relies on namespace ownership, not on the old file's contents or write bits. */
static bool canary_owned_entry(const struct stat *status)
{
    return S_ISREG(status->st_mode) && status->st_uid == geteuid() &&
           status->st_nlink == 1;
}

/* Public read access is allowed; only the owner may alter the retained object. */
static bool canary_owned_regular(const struct stat *status)
{
    return canary_owned_entry(status) && (status->st_mode & 022) == 0;
}

static int canary_directory_open(const char *path)
{
    if (!path || path[0] != '/')
        return -1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (fd >= 0 && fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
        status.st_uid == geteuid() && (status.st_mode & 022) == 0)
        return fd;
    if (fd >= 0)
        (void)close(fd);
    return -1;
}

static int canary_file_open(int directory, const char *leaf, bool create, mode_t mode, struct canary_trace *trace)
{
    int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW;
    if (create)
        flags |= O_CREAT | O_EXCL;
    int fd = openat(directory, leaf, flags, mode);
    if (fd >= 0 && create)
        trace->mutated = true;
    struct stat status;
    if (fd >= 0 && fstat(fd, &status) == 0 && canary_owned_regular(&status))
        return fd;
    if (fd >= 0)
        (void)close(fd);
    return -1;
}

static enum canary_persist_result canary_unlink(int directory,
    const char *leaf, struct canary_trace *trace)
{
    canary_phase(trace, "unlink_validate");
    struct stat status;
    if (fstatat(directory, leaf, &status, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? CANARY_PERSIST_OK : CANARY_PERSIST_IO;
    canary_phase(trace, "unlink");
    if (!canary_owned_entry(&status) || unlinkat(directory, leaf, 0) != 0)
        return CANARY_PERSIST_IO;
    trace->mutated = true;
    canary_phase(trace, "unlink_directory_flush");
    return canary_injected("unlink_dir_flush") || platform_file_sync(directory) != 0 ?
        CANARY_PERSIST_UNKNOWN : CANARY_PERSIST_OK;
}

static int canary_lock(int directory, struct canary_trace *trace)
{
    int fd = canary_file_open(directory, ".canary-sentinel.lock", true, 0600, trace);
    if (fd < 0 && errno == EEXIST)
        fd = canary_file_open(directory, ".canary-sentinel.lock", false, 0, trace);
    if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0)
        return fd;
    if (fd >= 0)
        (void)close(fd);
    return -1;
}

static bool canary_write(int fd, const char *bytes, size_t length)
{
    if (canary_injected("write"))
        return false;
    size_t done = 0;
    while (done < length) {
        ssize_t n = write(fd, bytes + done, length - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return true;
}

static bool canary_staged_identity(int directory, int fd, const char *stage)
{
    struct stat opened, named;
    return fstat(fd, &opened) == 0 &&
           fstatat(directory, stage, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
           canary_owned_regular(&named) && opened.st_dev == named.st_dev &&
           opened.st_ino == named.st_ino;
}

static enum canary_persist_result canary_replace(
    int directory, int fd, const char *stage, const char *destination, struct canary_trace *trace)
{
    canary_phase(trace, "file_flush");
    if (canary_injected("file_flush") || platform_file_sync(fd) != 0)
        return CANARY_PERSIST_IO;
    canary_phase(trace, "destination_validate");
    struct stat target;
    if (fstatat(directory, destination, &target, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!canary_owned_regular(&target))
            return CANARY_PERSIST_IO;
    } else if (errno != ENOENT) {
        return CANARY_PERSIST_IO;
    }
    canary_phase(trace, "staged_identity");
    if (!canary_staged_identity(directory, fd, stage))
        return CANARY_PERSIST_IO;
    canary_phase(trace, "rename");
    if (canary_injected("rename") ||
        renameat(directory, stage, directory, destination) != 0)
        return CANARY_PERSIST_IO;
    trace->mutated = true;
    canary_phase(trace, "directory_flush");
    if (canary_injected("dir_flush") || platform_file_sync(directory) != 0)
        return CANARY_PERSIST_UNKNOWN;
    return CANARY_PERSIST_OK;
}

static enum canary_persist_result canary_marker(
    int directory, const char *marker, const char *timestamp, struct canary_trace *trace)
{
    char stage[96], body[24];
    (void)snprintf(stage, sizeof(stage), "%s.tmp", marker);
    (void)snprintf(body, sizeof(body), "%s\n", timestamp);
    enum canary_persist_result removed = canary_unlink(directory, stage, trace);
    if (removed == CANARY_PERSIST_OK)
        removed = canary_unlink(directory, marker, trace);
    if (removed != CANARY_PERSIST_OK)
        return removed;
    canary_phase(trace, "marker_create");
    int fd = canary_file_open(directory, stage, true, 0644, trace);
    if (fd < 0)
        return CANARY_PERSIST_IO;
    canary_phase(trace, "marker_write");
    enum canary_persist_result result = canary_write(fd, body, strlen(body)) ?
        canary_replace(directory, fd, stage, marker, trace) : CANARY_PERSIST_IO;
    int saved_error = errno;
    if (close(fd) != 0 && result == CANARY_PERSIST_OK) {
        trace->phase = "file_close";
        result = CANARY_PERSIST_UNKNOWN;
    } else {
        errno = saved_error;
    }
    if (result != CANARY_PERSIST_OK) {
        const char *failed_phase = trace->phase;
        int failed_error = errno ? errno : EIO;
        (void)canary_unlink(directory, stage, trace);
        trace->phase = failed_phase;
        errno = failed_error;
    }
    return result;
}

static enum canary_persist_result canary_publish(
    int directory, const char *stage, const char *sentinel, struct canary_trace *trace)
{
    canary_phase(trace, "staged_open");
    int fd = canary_file_open(directory, stage, false, 0, trace);
    if (fd < 0)
        return CANARY_PERSIST_IO;
    enum canary_persist_result result =
        canary_replace(directory, fd, stage, sentinel, trace);
    int saved_error = errno;
    if (close(fd) != 0 && result == CANARY_PERSIST_OK) {
        trace->phase = "file_close";
        result = CANARY_PERSIST_UNKNOWN;
    } else {
        errno = saved_error;
    }
    return result;
}

struct canary_input {
    const char *action, *path, *timestamp, *stage;
    bool reset;
    char sentinel[80], marker[80];
    char timestamp_storage[24];
};

static bool canary_track(const char *from)
{
    return from && (strcmp(from, "anchor") == 0 || strcmp(from, "genesis") == 0);
}

static bool canary_input_read(const struct json_value *input,
                              struct canary_input *out)
{
    *out = (struct canary_input){0};
    out->action = json_get_str(json_get(input, "action"));
    out->path = json_get_str(json_get(input, "directory"));
    out->timestamp = canary_started_ts(input, out->timestamp_storage);
    out->stage = json_get_str(json_get(input, "staged"));
    const char *from = json_get_str(json_get(input, "from"));
    const struct json_value *directory = json_get(input, "directory");
    if (!directory || directory->type != JSON_STR || !canary_track(from))
        return false;
    out->reset = strcmp(out->action, "reset") == 0;
    if (!out->reset && strcmp(out->action, "publish") != 0)
        return false;
    (void)snprintf(out->sentinel, sizeof(out->sentinel), "replay_canary_%s.json", from);
    (void)snprintf(out->marker, sizeof(out->marker), ".run_started_%s", from);
    return canary_stage_name(out->stage, out->sentinel) &&
           (!out->reset || canary_decimal(out->timestamp));
}

static enum canary_persist_result canary_reset(
    int directory, const struct canary_input *input, struct canary_trace *trace)
{
    enum canary_persist_result result =
        canary_unlink(directory, input->sentinel, trace);
    if (result == CANARY_PERSIST_OK)
        result = canary_unlink(directory, input->stage, trace);
    if (result == CANARY_PERSIST_OK)
        result = canary_marker(directory, input->marker, input->timestamp, trace);
    return result;
}

static enum canary_persist_result canary_apply(const struct canary_input *input, struct canary_trace *trace)
{
    canary_phase(trace, "directory_open");
    int directory = canary_directory_open(input->path);
    if (directory >= 0)
        canary_phase(trace, "lock");
    int lock = directory >= 0 ? canary_lock(directory, trace) : -1;
    enum canary_persist_result result = CANARY_PERSIST_IO;
    if (lock >= 0) {
        if (input->reset)
            result = canary_reset(directory, input, trace);
        else
            result = canary_publish(directory, input->stage, input->sentinel, trace);
        int saved_error = errno ? errno : EIO;
        const char *saved_phase = trace->phase;
        if (result != CANARY_PERSIST_OK) {
            /* A failed post-rename barrier is not a proven rollback. Invalidate
             * visible verdict evidence best-effort and retain the unknown result. */
            (void)canary_unlink(directory, input->sentinel, trace);
            if (!input->reset)
                (void)canary_unlink(directory, input->stage, trace);
        }
        trace->error = saved_error;
        trace->phase = saved_phase;
        (void)close(lock);
    }
    if (directory >= 0)
        (void)close(directory);
    if (!trace->error)
        trace->error = errno ? errno : EIO;
    return result;
}

static void canary_persist(const struct json_value *input,
                           struct zcl_command_reply *reply)
{
    struct canary_input parsed;
    if (!canary_input_read(input, &parsed)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "CANARY_SENTINEL_INPUT", "validate",
            false, false, "expected fixed track, reset with decimal timestamp or publish with numeric staged leaf", "input");
        return;
    }
    struct canary_trace trace = { .phase = "validate" };
    enum canary_persist_result result = canary_apply(&parsed, &trace);
    if (result != CANARY_PERSIST_OK) {
        char evidence[128];
        (void)snprintf(evidence, sizeof(evidence), "phase=%s errno=%d",
                       trace.phase ? trace.phase : "unknown", trace.error);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "CANARY_SENTINEL_DURABILITY", "persist",
            false, trace.mutated, result == CANARY_PERSIST_UNKNOWN ?
            "namespace changed but durability is unknown; verdict invalidation was best-effort" :
            "canary sentinel persistence failed; no durable result is claimed", evidence);
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_canary_sentinel.v1");
    (void)json_push_kv_str(&reply->data, "action", parsed.action);
    (void)json_push_kv_bool(&reply->data, "durable", true);
}
#endif

void zcl_native_handle_dev_canary_sentinel(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
        ZCL_COMMAND_EXIT_BLOCKED, "CANARY_SENTINEL_UNSUPPORTED", "platform",
        false, false, "the POSIX canary sentinel lifecycle is unavailable on Windows", "platform");
#else
    canary_persist(request ? request->input : NULL, reply);
#endif
}
