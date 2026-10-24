/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.loop.job.exec: the detached child of dev.loop.job.start. Hidden from agents (the
 * CLI-only `z23-dev dev loop job exec --job_id=<id>` that start spawns). It runs
 * the job's argv in the job's registered worktree through the host build
 * queue, so admission stays with the scheduler, then appends the terminal
 * `rc=<n>` line that dev.loop.job.wait reads. Dev-only; not node-reachable. */

#include "command/native_command.h"
#include "command/native_dev_job.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define JOB_OUT_CAP (16u * 1024u * 1024u)
#define JOB_RUN_TIMEOUT_MS (3 * 60 * 60 * 1000)
#define JOB_RC_TIMEOUT 124
#define JOB_RC_LAUNCH 127

static bool job_pid_write(const char *id)
{
    char dir[ZCL_DEV_JOB_PATH_MAX], path[ZCL_DEV_JOB_PATH_MAX + 8];
    FILE *f;
    int n;
    if (!zcl_dev_job_dir(id, dir, sizeof(dir)))
        return false;
    n = snprintf(path, sizeof(path), "%s/pid", dir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    f = fopen(path, "w");
    if (!f)
        return false;
    (void)fprintf(f, "%ld\n", (long)getpid());
    return fclose(f) == 0;
}

/* devbuild and zgate admit themselves; everything else goes through
 * `<this binary> ops host build --`. */
static bool job_self_admitting(const char *argv0)
{
    const char *base = strrchr(argv0, '/');
    base = base ? base + 1 : argv0;
    return strcmp(base, "devbuild") == 0 || strcmp(base, "zgate") == 0;
}

static bool job_self_exe(char *out, size_t cap)
{
    if (!os_proc_exe_path(out, cap))
        (void)snprintf(out, cap, "z23-dev");
    return true;
}

/* Fill run[] (NULL-terminated) from the handle argv. `exe` backs the
 * wrapper's argv[0]. Returns false when the argv does not fit. */
static bool job_build_argv(const struct json_value *argv, bool direct,
                           const char *exe, const char **run, size_t cap)
{
    size_t n = 0, count = json_size(argv);
    const char *first = count ? zcl_dev_job_str(json_at(argv, 0)) : NULL;
    if (!first)
        return false;
    if (!direct && !job_self_admitting(first)) {
        if (cap < 6)
            return false;
        run[n++] = exe;
        run[n++] = "ops";
        run[n++] = "host";
        run[n++] = "build";
        run[n++] = "--";
    }
    for (size_t i = 0; i < count; i++) {
        const char *s = zcl_dev_job_str(json_at(argv, i));
        if (!s || n + 1 >= cap)
            return false;
        run[n++] = s;
    }
    run[n] = NULL;
    return true;
}

static void job_log_finish(const char *log, const char *out, int rc,
                           bool timed_out)
{
    FILE *f = fopen(log, "a");
    size_t len = out ? strlen(out) : 0;
    if (!f)
        return;
    if (len > 0)
        (void)fwrite(out, 1, len, f);
    if (len > 0 && out[len - 1] != '\n')
        (void)fputc('\n', f);
    if (timed_out)
        (void)fprintf(f, "error: job exceeded %d s and was killed\n",
                      JOB_RUN_TIMEOUT_MS / 1000);
    (void)fprintf(f, "rc=%d\n", rc);
    (void)fclose(f);
}

static int job_run_captured(const struct json_value *handle, bool direct,
                            const char *log)
{
    const struct json_value *argv = json_get(handle, "argv");
    const char *cwd = zcl_dev_job_str(json_get(handle, "cwd"));
    const char *run[ZCL_DEV_JOB_ARGV_MAX + 8];
    char exe[ZCL_DEV_JOB_PATH_MAX];
    bool timed_out = false;
    char *out = zcl_malloc(JOB_OUT_CAP, "dev_job_output");
    int rc;
    if (!out) {
        job_log_finish(log, "error: could not allocate the output buffer",
                       JOB_RC_LAUNCH, false);
        return JOB_RC_LAUNCH;
    }
    (void)job_self_exe(exe, sizeof(exe));
    if (!cwd || !job_build_argv(argv, direct, exe, run,
                                sizeof(run) / sizeof(run[0]))) {
        free(out);
        job_log_finish(log, "error: handle argv or cwd is unusable",
                       JOB_RC_LAUNCH, false);
        return JOB_RC_LAUNCH;
    }
    rc = zcl_spawn_capture_merged_in_dir_observed(
        run, cwd, out, JOB_OUT_CAP, JOB_RUN_TIMEOUT_MS, &timed_out);
    if (rc < 0)
        rc = JOB_RC_LAUNCH;
    if (timed_out)
        rc = JOB_RC_TIMEOUT;
    job_log_finish(log, out, rc, timed_out);
    free(out);
    return rc;
}

int zcl_dev_job_exec_run(const char *id)
{
    struct json_value handle;
    const char *log;
    FILE *f;
    int rc;
    if (!id || !zcl_dev_job_read_handle(id, &handle))
        return -1;
    log = zcl_dev_job_str(json_get(&handle, "log"));
    if (!log || !job_pid_write(id)) {
        json_free(&handle);
        return -1;
    }
    f = fopen(log, "w");
    if (f) {
        (void)fprintf(f, "job %s running\n", id);
        (void)fclose(f);
    }
    rc = job_run_captured(&handle, zcl_dev_job_hooks() &&
                                       zcl_dev_job_hooks()->runner_direct,
                          log);
    json_free(&handle);
    return rc;
}

void zcl_native_handle_dev_job_exec(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *id;
    int rc;
    if (!reply)
        return;
    id = request && request->input
             ? zcl_dev_job_str(json_get(request->input, "job_id"))
             : NULL;
    if (!id || !zcl_dev_job_id_valid(id)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                               "normalize", false, false,
                               "job_id is required: the id dev loop job start returned",
                               "input.job_id");
        return;
    }
    rc = zcl_dev_job_exec_run(id);
    if (rc < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "JOB_UNKNOWN",
                               "exec", false, false,
                               "no readable handle for that job id",
                               "input.job_id");
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "job_id", id);
    (void)json_push_kv_int(&reply->data, "rc", rc);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}
