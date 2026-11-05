/* purpose: Explicit registry-owned retirement of trusted supervised processes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SUPERVISED_RETIREMENT_H
#define ZCL_SUPERVISED_RETIREMENT_H
#include "platform/supervised_process.h"

enum zcl_supervised_retirement_phase {
    ZCL_RETIREMENT_STOPPED, ZCL_RETIREMENT_RUNNING, ZCL_RETIREMENT_DRAINING
};
enum zcl_supervised_retirement_result {
    ZCL_RETIREMENT_REFUSED, ZCL_RETIREMENT_TRANSFERRED
};
enum { ZCL_SUPERVISED_RETIREMENT_SLOTS = 16 };

/* Linux lifecycle host calls begin BEFORE its first launch (including planning,
 * compilation and linking). Library borrowers never begin/stop a global owner
 * per operation. No implicit restart after draining. Registry owns worker join.
 * Fork children refuse before touching inherited locks; a fresh exec is valid. */
bool zcl_supervised_retirement_begin(void);
enum zcl_supervised_retirement_phase zcl_supervised_retirement_phase(void);
/* Stop admission, not custody: preexisting reservations and in-flight starts
 * remain valid and may transfer late. STOPPED requires all slots discharged.
 * Caller then uses thread_registry_join_all with its existing bounded policy.
 * PENDING means keep the service/dependencies alive; never claim CLEAN or reuse
 * campaign scratch/award execution credit based on transfer or draining. */
void zcl_supervised_retirement_request_stop(void);
bool zcl_supervised_retirement_drain(int64_t deadline_ns);
enum platform_supervised_state zcl_supervised_retirement_start(
    struct platform_supervised_process *process, const struct platform_supervised_spec *spec);
enum platform_supervised_state zcl_supervised_retirement_poll(
    struct platform_supervised_process *process);
enum platform_supervised_state zcl_supervised_retirement_stop(
    struct platform_supervised_process *process, int64_t deadline_ns);
/* Handle address is stable from before start through terminal release/transfer.
 * REFUSED preserves that exact caller handle; ACK empties it and transfers the
 * wait/FD obligation, not teardown evidence. Existing exclusive wait/SIGCHLD
 * policy remains mandatory until worker join. Do not cancel the worker.
 * Process exit after ACK uses supervisor EOF/host adoption, not orderly join
 * or CLEAN; supervisor crash remains the base API's custody limitation. */
enum zcl_supervised_retirement_result zcl_supervised_retirement_transfer(
    struct platform_supervised_process *process);
#ifdef ZCL_TESTING
void zcl_supervised_retirement_fixture_refuse(bool refuse);
void zcl_supervised_retirement_fixture_wake_error_once(void);
unsigned zcl_supervised_retirement_fixture_pending(void);
unsigned zcl_supervised_retirement_fixture_reaps(void);
uint64_t zcl_supervised_retirement_fixture_token(const struct platform_supervised_process *process);
/* Pause a preauthorized start before platform launch; fixture owns both FDs. */
void zcl_supervised_retirement_fixture_reservation_gate(int notify_fd, int resume_fd);
#endif
#endif
