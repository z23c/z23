/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private nonblocking resident-loop start boundary for proof enqueue. */

#ifndef ZCL_TOOLS_NATIVE_DEV_LOOP_COMMAND_H
#define ZCL_TOOLS_NATIVE_DEV_LOOP_COMMAND_H

struct zcl_command_reply;
struct zcl_command_request;

void zcl_native_handle_dev_loop_start_async(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#endif
