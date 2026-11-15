/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: node-free boot status and bounded boot wait. */
#define _GNU_SOURCE
#include "command/native_command.h"
#include "command/native_command_priv.h"
#include "platform/time_compat.h"
#include "util/boot_status.h"
#include "util/log_macros.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#endif

/* ── core.node.bootstatus / core.node.bootwait native leaves ───────────────
 * Pre-RPC boot observability. Both read <datadir>/boot_status.json directly
 * off disk (util/boot_status.h) — NO node contact, NO RPC — so they answer
 * "what boot stage are we at, is it serving yet?" during the exact window
 * (snapshot load / refold / index rebuild) when RPC has not bound and the only
 * alternative was ss/ps/tail node.log. bootstatus is a single read; bootwait
 * polls until serving or a timeout. */

/* Resolve the target datadir: explicit input.datadir wins, else the CLI's
 * --datadir (native command datadir). Returns NULL when neither is set. */
static const char *nc_bootstatus_datadir(const struct zcl_command_request *req)
{
    const char *dd = json_get_str(json_get(req->input, "datadir"));
    if (dd && dd[0])
        return dd;
    const char *datadir = zcl_native_command_datadir();
    if (datadir && datadir[0])
        return datadir;
    return NULL;
}

/* Project a parsed boot_status snapshot into reply->data. */
static void nc_bootstatus_fill(struct zcl_command_reply *reply,
                               const struct boot_status_snapshot *s)
{
    if (s->source_id_sha256[0])
        (void)json_push_kv_str(&reply->data, "source_id_sha256", s->source_id_sha256);
    (void)json_push_kv_str(&reply->data, "phase", s->phase);
    (void)json_push_kv_str(&reply->data, "stage", s->stage);
    (void)json_push_kv_int(&reply->data, "stage_ordinal", s->stage_ordinal);
    (void)json_push_kv_int(&reply->data, "height", s->height);
    (void)json_push_kv_bool(&reply->data, "rpc_bound", s->rpc_bound);
    (void)json_push_kv_bool(&reply->data, "serving", s->serving);
    (void)json_push_kv_int(&reply->data, "started_unix", s->started_unix);
    (void)json_push_kv_int(&reply->data, "updated_unix", s->updated_unix);
    (void)json_push_kv_int(&reply->data, "elapsed_s", s->elapsed_s);
    if (s->activity[0]) {
        (void)json_push_kv_str(&reply->data, "activity", s->activity);
        (void)json_push_kv_int(&reply->data, "progress_current",
                               s->progress_current);
        (void)json_push_kv_int(&reply->data, "progress_target",
                               s->progress_target);
    }
    if (s->blocker[0]) {
        (void)json_push_kv_str(&reply->data, "blocker", s->blocker);
        (void)json_push_kv_str(&reply->data, "blocker_reason",
                               s->blocker_reason);
    }
}

enum nc_boot_owner_state {
    NC_BOOT_OWNER_HELD,
    NC_BOOT_OWNER_FREE,
    NC_BOOT_OWNER_UNKNOWN,
};

/* The beacon survives SIGKILL. Only the node's single-writer lock can turn
 * its last serving observation into current readiness. This probe never
 * creates or changes the pidfile. */
static enum nc_boot_owner_state nc_boot_owner_probe(const char *datadir,
                                                    int *problem)
{
    *problem = 0;
#ifdef _WIN32
    (void)datadir;
    *problem = ENOSYS;
    return NC_BOOT_OWNER_UNKNOWN;
#else
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/zclassic23.pid", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        *problem = ENAMETOOLONG;
        return NC_BOOT_OWNER_UNKNOWN;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        *problem = errno;
        return errno == ENOENT ? NC_BOOT_OWNER_FREE : NC_BOOT_OWNER_UNKNOWN;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
        return NC_BOOT_OWNER_FREE;
    }
    *problem = errno;
    (void)close(fd);
    return *problem == EWOULDBLOCK || *problem == EAGAIN
        ? NC_BOOT_OWNER_HELD : NC_BOOT_OWNER_UNKNOWN;
#endif
}

static bool nc_bootwait_owner_ready(const char *datadir,
                                    struct zcl_command_reply *reply)
{
    int problem;
    enum nc_boot_owner_state owner = nc_boot_owner_probe(datadir, &problem);
    if (owner == NC_BOOT_OWNER_HELD)
        return true;
    if (owner == NC_BOOT_OWNER_UNKNOWN)
        LOG_WARN("core.node.bootwait", "cannot inspect datadir owner lock: %s",
                 strerror(problem));
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        owner == NC_BOOT_OWNER_FREE ? "BOOT_NODE_NOT_RUNNING"
                                    : "BOOT_OWNER_UNVERIFIED",
        "execute", true, false,
        owner == NC_BOOT_OWNER_FREE
            ? "the last beacon says serving, but no node holds the datadir; start the node and retry bootwait"
            : "cannot verify the datadir owner lock; check pidfile access and retry bootwait",
        datadir);
    return false;
}

static void nc_bootwait_serving_reply(const char *datadir, int polls,
                                      const struct boot_status_snapshot *snap,
                                      struct zcl_command_reply *reply)
{
    if (!nc_bootwait_owner_ready(datadir, reply))
        return;
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_int(&reply->data, "polls", polls);
    nc_bootstatus_fill(reply, snap);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_core_node_bootstatus(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = nc_bootstatus_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.node.bootstatus");
        nc_add_describe_next(reply, request->spec->path,
                             "inspect the boot-status datadir input");
        return;
    }

    struct boot_status_snapshot snap;
    char why[192];
    if (!boot_status_read(datadir, &snap, why, sizeof(why))) {
        /* No beacon yet: the node has not started booting (or is a build
         * without the writer). Fail closed (exit 3) — never invent a status. */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "NO_BOOT_STATUS",
                               "execute", true, false,
                               why[0] ? why : "no boot_status.json yet",
                               datadir);
        nc_add_string_next(reply, "core.node.bootwait", "datadir", datadir,
                           "wait for the beacon to appear");
        return;
    }
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    nc_bootstatus_fill(reply, &snap);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* Absent keeps *out; a present key must be a JSON integer in [lo, hi]. */
static bool nc_bootwait_bounded_int(const struct json_value *input,
                                    const char *key, int64_t lo, int64_t hi,
                                    int64_t *out, struct zcl_command_reply *reply)
{
    const struct json_value *v = json_get(input, key);
    if (!v)
        return true;
    int64_t n = v->type == JSON_INT ? json_get_int(v) : lo - 1;
    if (v->type == JSON_INT && n >= lo && n <= hi) {
        *out = n;
        return true;
    }
    char msg[160];
    (void)snprintf(msg, sizeof(msg),
                   "%s must be a JSON integer in the range %lld..%lld", key,
                   (long long)lo, (long long)hi);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                           "normalize", false, false, msg,
                           "core.node.bootwait");
    return false;
}

void zcl_native_handle_core_node_bootwait(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = nc_bootstatus_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.node.bootwait");
        return;
    }

    /* Bounded poll: default 60s budget, 500ms cadence. The CLI front door
     * range-checks these, but zcl_command_registry_execute_json does not, so
     * the handler enforces timeout_ms 1..300000 and heartbeat_ms 100..60000
     * itself, before any datadir read or sleep. */
    int64_t timeout_ms = 60000;
    int64_t poll_ms = 500;
    if (!nc_bootwait_bounded_int(request->input, "timeout_ms", 1, 300000,
                                 &timeout_ms, reply) ||
        !nc_bootwait_bounded_int(request->input, "heartbeat_ms", 100, 60000,
                                 &poll_ms, reply))
        return;

    int64_t t0_ms = platform_time_monotonic_ms();
    struct boot_status_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    snap.stage_ordinal = -1;
    snap.height = -1;
    bool ever_seen = false;
    int polls = 0;

    for (;;) {
        char why[192];
        if (boot_status_read(datadir, &snap, why, sizeof(why))) {
            ever_seen = true;
            if (snap.serving) {
                nc_bootwait_serving_reply(datadir, polls, &snap, reply);
                return;
            }
        }
        polls++;

        int64_t elapsed_ms = platform_time_monotonic_ms() - t0_ms;
        if (elapsed_ms >= timeout_ms)
            break;

        int64_t remain = timeout_ms - elapsed_ms;
        int64_t sleep_ms = poll_ms < remain ? poll_ms : remain;
        struct timespec ts = { .tv_sec = sleep_ms / 1000,
                               .tv_nsec = (sleep_ms % 1000) * 1000000L };
        (void)nanosleep(&ts, NULL);
    }

    /* Timed out: report the last observed state (transiently unavailable). */
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_int(&reply->data, "polls", polls);
    if (ever_seen)
        nc_bootstatus_fill(reply, &snap);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
        "BOOT_WAIT_TIMEOUT", "execute", true, false,
        ever_seen ? "boot not serving before the timeout"
                  : "no boot_status.json before the timeout",
        datadir);
}
