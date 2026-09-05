/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private nonblocking resident-loop start boundary for proof enqueue. */

#ifndef ZCL_TOOLS_NATIVE_DEV_LOOP_COMMAND_H
#define ZCL_TOOLS_NATIVE_DEV_LOOP_COMMAND_H

#include <stdbool.h>
#ifdef ZCL_TESTING
#include <stdint.h>
#endif

struct zcl_command_reply;
struct zcl_command_request;

void zcl_native_handle_dev_loop_start_async(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
bool zcl_native_dev_loop_proof_queue_ready(const char *repo_root);

#ifdef ZCL_TESTING
/* Classifier for the post-wait fresh-start observation. A live watcher that
 * already holds the singleton lock but has not finished the first source
 * snapshot is STARTING (blocked, retryable), not START_FAILED. */
struct zcl_dev_watch_start_wait_reply {
    int status;
    int exit_code;
    const char *code;
    const char *message;
    bool retryable;
};

struct zcl_dev_watch_start_wait_reply
zcl_native_dev_watch_start_wait_classify(
    int64_t pid, bool ready, bool is_watcher, int publish_mode,
    int requested_mode);
#endif

#endif
