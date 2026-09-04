/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private dispatch boundary for resident proof commands. */

#ifndef ZCL_TOOLS_NATIVE_DEV_PROOF_COMMAND_H
#define ZCL_TOOLS_NATIVE_DEV_PROOF_COMMAND_H

struct zcl_command_reply;
struct zcl_command_request;
struct zcl_dev_proof_status;

void zcl_native_dev_proof_dispatch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* The `dev.proof.wait` status/exit-code contract, given an already-resolved
 * status: unconditional (no ZCL_DEV_BUILD dependency), so it is directly
 * regression-testable in a release-shaped test binary. A settled `.failed`
 * marker (FAILED) is a terminal, non-BLOCKED outcome distinct from
 * still-in-flight (RUNNING) or not-yet-requested (MISSING); PASSED emits
 * the receipt with no error. */
void zcl_dev_proof_wait_conclude(struct zcl_command_reply *reply,
                                 const struct zcl_dev_proof_status *status);

#endif
