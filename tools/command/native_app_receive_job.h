/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Own one bounded external CLI capture while native Receive keeps pumping UI. */
#ifndef ZCL_NATIVE_APP_RECEIVE_JOB_H
#define ZCL_NATIVE_APP_RECEIVE_JOB_H
#include "util/spawn.h"
#include <stdbool.h>
#include <stddef.h>
struct json_value;
struct app_receive_job;
enum app_receive_job_command { APP_RECEIVE_JOB_BUILD, APP_RECEIVE_JOB_OPEN };
enum app_receive_job_start_result {
    APP_RECEIVE_JOB_STARTED, APP_RECEIVE_JOB_BAD_INPUT,
    APP_RECEIVE_JOB_NO_MEMORY, APP_RECEIVE_JOB_THREAD_FAILED,
    APP_RECEIVE_JOB_UNSUPPORTED
};
#define APP_RECEIVE_JOB_INPUT_MAX (64u * 1024u)
#define APP_RECEIVE_JOB_OUTPUT_MAX (64u * 1024u)
struct app_receive_job_result {
    const char *stdout_json; /* Borrowed until join_free; parent must parse/validate. */
    size_t stdout_len;
    int capture_status;
    bool transport_ok; /* Observed exit0, complete/untruncated/nonempty stdout only. */
    struct zcl_spawn_evidence evidence; /* Raw bounded stderr tail, not a C string. */
};
/* Parent-only, single owner, no concurrent API calls. *out must be NULL and
 * stays NULL on failure. self_path is an absolute trusted installed CLI, never
 * package input; NULL uses os_proc_self_exe_open_path in the parent. Paths are
 * copied, not cryptographically pinned (Darwin replacement remains possible).
 * Copies bounded object JSON into --input= argv: no secret-bearing input.
 * The caller must already own native consent and pass exact saved identities.
 * Environment is inherited unchanged; caller must keep it stable for launch.
 * No inherited environment mutation, shell, native handler or UI in worker.
 * Windows refuses. This is process-group capture, NOT a sandbox/subreaper;
 * escaped sessions and abrupt owner death are outside its cleanup contract. */
enum app_receive_job_start_result app_receive_job_start(const char *self_path,
    enum app_receive_job_command command, const struct json_value *input,
    struct app_receive_job **out);
/* Clears result first. false = invalid/running; true = capture returned,
 * including failures. Publication uses release/acquire; parent may inspect
 * immutable result without racing the worker. No JSON parsing occurs here. */
bool app_receive_job_poll(const struct app_receive_job *job,
    struct app_receive_job_result *result);
/* Join retains all result storage for parent parsing. Idempotent. May BLOCK
 * until terminal: use after poll in the normal GUI path, or after presentation
 * failure to retain custody (no missing-display responsiveness promise).
 * Never call from the live-view callback. Failure retains the handle. */
bool app_receive_job_join(struct app_receive_job *job);
/* Never detach/cancel. false while running or on join error; retains custody.
 * UI close must keep polling visibly until terminal, then join before freeing.
 * Even after timeout, kernel reap may be delayed; no hard cleanup promise.
 * true for a NULL handle; on successful join frees and sets *job=NULL.
 * Join/free success releases local thread storage only, not proof that every
 * descendant ended or that a timed-out command made no persistent writes. */
bool app_receive_job_join_free(struct app_receive_job **job);
#endif
