/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet` leaves' handlers — the owner's private fleet ledger.
 * Each answers from local files under the datadir and contacts no peer. */

#ifndef ZCL_NATIVE_FLEET_H
#define ZCL_NATIVE_FLEET_H

struct zcl_command_request;
struct zcl_command_reply;

void zcl_native_handle_fleet_ledger_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_ledger_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_usage(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply);
void zcl_native_handle_fleet_vitals_sample(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_FLEET_H */
