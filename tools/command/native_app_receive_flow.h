/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Continue an owner-received copy through explicit preview and Keep choices. */
#ifndef ZCL_NATIVE_APP_RECEIVE_FLOW_H
#define ZCL_NATIVE_APP_RECEIVE_FLOW_H
#include "command/native_app_confirm.h"
struct zcl_command_reply;
/* Called only after successful native Receive. Default Receive never calls
 * this. The original receipt remains in reply->data on every later failure. */
void app_receive_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context);
/* Only after successful native adoption AND personalization. Caller reserves
 * the original receipt plus bounded continuation evidence before mutation
 * (same 16KiB policy as Receive, including retained scratch failure evidence).
 * Preserves original lineage/package fields; Build uses the separately derived
 * selected personal package. Close performs no build/open/Keep. */
void app_adopted_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context);
#ifdef ZCL_TESTING
struct json_value;
struct app_receive_job_result;
/* Serialization-only synthetic observations: invokes the actual compact
 * summary/finish owners, without launching, binding or authorizing anything.
 * Three observations model plan/build/open. Failure models uncertain open;
 * success adds the same compact Keep summary used by the real flow. */
bool app_receive_flow_test_report(struct zcl_command_reply *reply,
    const struct app_receive_job_result *results,
    const struct json_value *const wires[3], bool failed);
#endif
#endif
