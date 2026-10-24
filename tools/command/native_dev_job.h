/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.job.start / dev.job.wait / dev.job.exec internals shared by
 * native_dev_job.c (start, wait) and native_dev_job_exec.c (the detached
 * child). Dev-only; nothing here is node-reachable.
 *
 * A job directory <state root>/devjob/<id>/ holds pointer files only:
 *   handle.json  cwd, argv, head, label, started_unix, log path
 *   pid          the exec child's pid, written by the child when it starts
 * The job's output and its terminal `rc=<n>` line live in the log named by
 * handle.json (<cwd>/build/scratch/job-<id>.log). */
#ifndef ZCL_NATIVE_DEV_JOB_H
#define ZCL_NATIVE_DEV_JOB_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_DEV_JOB_ID_MAX 48
#define ZCL_DEV_JOB_PATH_MAX 4096
#define ZCL_DEV_JOB_ARGV_MAX 64
#define ZCL_DEV_JOB_WAIT_MAX_S 230
#define ZCL_DEV_JOB_TAIL_MAX 40
#define ZCL_DEV_JOB_LINE_MAX 200

enum zcl_dev_job_state {
    ZCL_DEV_JOB_RUNNING,
    ZCL_DEV_JOB_PASSED,
    ZCL_DEV_JOB_FAILED,
    ZCL_DEV_JOB_LOST,
};

/* Test seam. Production leaves leave this NULL. `launch`, when set,
 * replaces the detached `z23-dev dev job exec` spawn; `runner_direct` makes
 * the exec core run the job argv itself instead of through devbuild / the
 * host build queue. `primary_checkout`, when set, names the primary checkout
 * whose worktrees are registered in place of this binary's own repository.
 * None of these is reachable from any command input. */
struct zcl_dev_job_hooks {
    bool (*launch)(const char *job_id);
    bool runner_direct;
    const char *primary_checkout;
};
void zcl_dev_job_set_hooks(const struct zcl_dev_job_hooks *hooks);
const struct zcl_dev_job_hooks *zcl_dev_job_hooks(void);

/* True when the canonical path `log` is under <worktree>/build/scratch/ of a
 * worktree listed for this binary's repository, or under the job state root. */
bool zcl_dev_job_log_allowed(const char *log);

/* The string at v, or NULL when v is missing, not a string, or empty
 * (json_get_str() answers "" there). */
const char *zcl_dev_job_str(const struct json_value *v);

/* <state root>/devjob (created when `create`). */
bool zcl_dev_job_root(char *out, size_t cap, bool create);
bool zcl_dev_job_id_valid(const char *id);
bool zcl_dev_job_dir(const char *id, char *out, size_t cap);

/* Read handle.json of job `id` into *handle (caller json_free()s). */
bool zcl_dev_job_read_handle(const char *id, struct json_value *handle);

/* The last `rc=<n>` line of `log` into *rc. False while there is none. */
bool zcl_dev_job_log_rc(const char *log, int *rc);

/* The last `max` bytes of `path`, NUL-terminated, heap-owned (free()). */
char *zcl_dev_job_read_tail(const char *path, size_t max, size_t *len_out);

/* Classify job `id` from its log, pid file and clock; fills *rc and *pid. */
enum zcl_dev_job_state zcl_dev_job_eval(const char *id,
                                        const struct json_value *handle,
                                        int *rc, long *pid);

/* Pure: classify a job from what is on disk. `started_unix` and `now_unix`
 * give the launch grace for a child that has not written its pid yet. */
enum zcl_dev_job_state zcl_dev_job_classify(bool have_rc, int rc,
                                            long pid, bool pid_alive,
                                            int64_t started_unix,
                                            int64_t now_unix);

/* Run job `id` to completion in this process: write the pid file, run the
 * argv in the handle's cwd (through devbuild / host build admission unless
 * hooks say direct), append the `rc=<n>` line to the log. Returns the
 * job's exit code, or -1 when the handle is unusable. */
int zcl_dev_job_exec_run(const char *id);

#endif
