/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Share the synchronous owner of an already-consented native commit and its progress window. */
#ifndef ZCL_NATIVE_APP_COMMIT_PROGRESS_H
#define ZCL_NATIVE_APP_COMMIT_PROGRESS_H
#include "command/native_app_confirm.h"
/* Progress cards have no actions; native close still reaches owner.update. */
bool app_commit_progress_ignore_input(void *, const struct zcl_present_input_v1 *,
    uint32_t *, uint32_t *);
struct zcl_command_request;
struct zcl_command_reply;
typedef void (*app_commit_progress_commit)(void *, const struct zcl_command_request *,
    struct zcl_command_reply *);
struct app_commit_progress_labels {
    const char *name, *request_id, *title, *summary, *finishing, *allocation;
    const char *unavailable, *start_failed, *join_failed;
};
struct app_commit_progress_outcome {
    bool started, joined, ui_ok, close_requested;
};
#if defined(ZCL_TESTING)
struct app_commit_progress_test_hooks {
    app_commit_progress_commit commit;
    void *context;
    const char *worker_alloc_label;
    bool refuse_start;
};
#endif
/* Internal only, after native owner consent. Single main owner holds context,
 * request metadata, chain/env and crypto lifecycle stable until return.
 * Commit may mutate context exclusively; UI must not access it.
 * POSIX deep-copies input, joins on every started path, and transfers the whole
 * reply. Permanent join failure AFTER completion retains the handle/job and
 * refuses future starts. Windows preserves synchronous commit.
 * No cancellation/rollback, authorization, retry or continuation policy here. */
struct app_commit_progress_outcome app_commit_progress_run(
    const struct zcl_command_request *, struct zcl_command_reply *,
    app_commit_progress_commit, void *, const struct app_commit_progress_labels *,
    app_confirm_presenter, void *
#if defined(ZCL_TESTING)
    , const struct app_commit_progress_test_hooks *
#endif
);
#endif
