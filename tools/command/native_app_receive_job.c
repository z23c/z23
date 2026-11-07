/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Capture a trusted build/open CLI in one worker without threading native dispatch. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "command/native_app_receive_job.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <pthread.h>
#include <stdatomic.h>
#include "util/thread_registry.h"

/* app_build_make.c: 60s closure query + 600s build, plus 60s orchestration
 * margin. Other derivation may consume time: expiration is a refusal, never
 * proof of a stuck build. Open: 15s readiness plus 45s validation margin. */
enum { ARJ_BUILD_MS = 720000, ARJ_OPEN_MS = 60000, ARJ_PATH_CAP = 4096 };
struct app_receive_job {
    pthread_t thread;
    bool joined; /* Parent-only; worker never accesses this field. */
    atomic_bool done;
    char *image, *input_arg, *output;
    const char *argv[6];
    int timeout_ms, capture_status;
    struct zcl_spawn_evidence evidence;
};
static void arj_destroy(struct app_receive_job *job)
{
    free(job->image); free(job->input_arg); free(job->output); free(job);
}
static enum app_receive_job_start_result arj_image(struct app_receive_job *job, const char *path)
{
    char self[ARJ_PATH_CAP];
    if (!path) {
        if (!os_proc_self_exe_open_path(self, sizeof(self))) return APP_RECEIVE_JOB_BAD_INPUT;
        path = self;
    }
    size_t n = strnlen(path, ARJ_PATH_CAP);
    if (!n || n >= ARJ_PATH_CAP || path[0] != '/') return APP_RECEIVE_JOB_BAD_INPUT;
    job->image = zcl_malloc(n + 1u, "receive-job/image");
    if (!job->image) return APP_RECEIVE_JOB_NO_MEMORY;
    memcpy(job->image, path, n + 1u); return APP_RECEIVE_JOB_STARTED;
}
static bool arj_buffers(struct app_receive_job *job, const struct json_value *input, size_t n)
{
    static const char prefix[] = "--input=";
    job->input_arg = zcl_malloc(sizeof(prefix) + n, "receive-job/input");
    job->output = zcl_calloc(APP_RECEIVE_JOB_OUTPUT_MAX + 1u, 1, "receive-job/output");
    if (!job->input_arg || !job->output) return false;
    memcpy(job->input_arg, prefix, sizeof(prefix) - 1u);
    return json_write(input, job->input_arg + sizeof(prefix) - 1u, n + 1u) == n;
}
static void *arj_capture(void *context)
{
    struct app_receive_job *job = context;
    job->capture_status = zcl_spawn_capture_evidence(job->argv, job->output,
        APP_RECEIVE_JOB_OUTPUT_MAX + 1u, job->timeout_ms, &job->evidence);
    atomic_store_explicit(&job->done, true, memory_order_release);
    return NULL;
}
static void arj_arguments(struct app_receive_job *job, enum app_receive_job_command command)
{
    job->argv[0] = job->image; job->argv[1] = "app";
    job->argv[2] = command == APP_RECEIVE_JOB_BUILD ? "build" : "open";
    job->argv[3] = job->input_arg; job->argv[4] = "--json"; job->argv[5] = NULL;
    job->timeout_ms = command == APP_RECEIVE_JOB_BUILD ? ARJ_BUILD_MS : ARJ_OPEN_MS;
}
static enum app_receive_job_start_result arj_start(const char *path,
    enum app_receive_job_command command, const struct json_value *input,
    struct app_receive_job **out)
{
    if (!input || input->type != JSON_OBJ ||
        (command != APP_RECEIVE_JOB_BUILD && command != APP_RECEIVE_JOB_OPEN))
        return APP_RECEIVE_JOB_BAD_INPUT;
    size_t n = json_write(input, NULL, 0);
    if (!n || n > APP_RECEIVE_JOB_INPUT_MAX) return APP_RECEIVE_JOB_BAD_INPUT;
    struct app_receive_job *job = zcl_calloc(1, sizeof(*job), "receive-job");
    if (!job) return APP_RECEIVE_JOB_NO_MEMORY;
    atomic_init(&job->done, false);
    enum app_receive_job_start_result image = arj_image(job, path);
    if (image != APP_RECEIVE_JOB_STARTED) { arj_destroy(job); return image; }
    if (!arj_buffers(job, input, n)) { arj_destroy(job); return APP_RECEIVE_JOB_NO_MEMORY; }
    arj_arguments(job, command);
    /* Non-NULL out_tid leaves joining with this job's existing owner. */
    if (thread_registry_spawn("receive-job", arj_capture, job, &job->thread) != 0) {
        arj_destroy(job); return APP_RECEIVE_JOB_THREAD_FAILED;
    }
    *out = job; return APP_RECEIVE_JOB_STARTED;
}
#endif

enum app_receive_job_start_result app_receive_job_start(const char *self_path,
    enum app_receive_job_command command, const struct json_value *input,
    struct app_receive_job **out)
{
    if (!out || *out) return APP_RECEIVE_JOB_BAD_INPUT;
#if defined(_WIN32)
    (void)self_path; (void)command; (void)input;
    return APP_RECEIVE_JOB_UNSUPPORTED;
#else
    return arj_start(self_path, command, input, out);
#endif
}

bool app_receive_job_poll(const struct app_receive_job *job,
    struct app_receive_job_result *result)
{
    if (result) memset(result, 0, sizeof(*result));
#if defined(_WIN32)
    (void)job; return false;
#else
    if (!job || !result || !atomic_load_explicit(&job->done, memory_order_acquire)) return false;
    result->stdout_json = job->output;
    result->stdout_len = (size_t)job->evidence.stdout_observed;
    if (result->stdout_len > APP_RECEIVE_JOB_OUTPUT_MAX) result->stdout_len = APP_RECEIVE_JOB_OUTPUT_MAX;
    result->capture_status = job->capture_status;
    result->evidence = job->evidence;
    result->transport_ok = job->capture_status == 0 && job->evidence.exit_observed &&
        job->evidence.exit_code == 0 && !job->evidence.timed_out &&
        !job->evidence.stdout_truncated && job->evidence.stdout_complete && result->stdout_len > 0;
    return true;
#endif
}

bool app_receive_job_join(struct app_receive_job *job)
{
#if defined(_WIN32)
    (void)job; return false;
#else
    if (!job) return false;
    if (job->joined) return true;
    if (pthread_join(job->thread, NULL) != 0) return false;
    job->joined = true; return true;
#endif
}

bool app_receive_job_join_free(struct app_receive_job **job)
{
    if (!job) return false;
    if (!*job) return true;
#if defined(_WIN32)
    return false;
#else
    if (!atomic_load_explicit(&(*job)->done, memory_order_acquire) ||
        !app_receive_job_join(*job)) return false;
    arj_destroy(*job); *job = NULL; return true;
#endif
}
