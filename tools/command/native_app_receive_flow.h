/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Continue an owner-received copy through explicit preview and Keep choices. */
#ifndef ZCL_NATIVE_APP_RECEIVE_FLOW_H
#define ZCL_NATIVE_APP_RECEIVE_FLOW_H
#include "command/native_app_confirm.h"
struct zcl_command_reply;
struct app_selection;
struct json_value;
/* Borrowed complete build envelope, delivered only after exact preview binding. */
typedef void (*app_receive_build_observer)(void *, const struct json_value *, const struct json_value *, struct zcl_command_reply *);
/* Called only after successful native Receive. Default Receive never calls
 * this. The original receipt remains in reply->data on every later failure. */
void app_receive_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context);
void app_receive_flow_run_observed(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path,
    app_receive_build_observer observer, void *observer_context);
/* `data_budget` is the caller's usable success-data allowance, not the wire budget. */
void app_receive_flow_run_budgeted(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path,
    app_receive_build_observer observer, void *observer_context, size_t data_budget);
/* Reopen an existing trusted received copy's original fork; never receives it again. */
void app_recovered_flow_run(const char *copy_dir, const char *datadir, const uint8_t expected_fork[32],
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
    const char *worker_path, size_t data_budget);
/* Only after successful native adoption AND personalization. Caller reserves
 * the original receipt plus bounded continuation evidence before mutation
 * (same 16KiB policy as Receive, including retained scratch failure evidence).
 * Preserves original lineage/package fields; Build uses the separately derived
 * selected personal package. Close performs no build/open/Keep. */
void app_adopted_flow_run(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context);
void app_saved_draft_flow_run(const struct app_selection *selection,
    struct zcl_command_reply *reply, app_confirm_presenter presenter, void *context,
    const char *worker_path);
#ifdef ZCL_TESTING
void app_receive_flow_run_test(const char *datadir, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *context, const char *worker_path);
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
