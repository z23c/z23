/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private dispatch boundary for resident proof commands. */

#ifndef ZCL_TOOLS_NATIVE_DEV_PROOF_COMMAND_H
#define ZCL_TOOLS_NATIVE_DEV_PROOF_COMMAND_H

struct zcl_command_reply;
struct zcl_command_request;

void zcl_native_dev_proof_dispatch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#endif
