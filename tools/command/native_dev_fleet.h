/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only Git/lint-receipt inventory behind `z23 dev fleet`. */

#ifndef ZCL_NATIVE_DEV_FLEET_H
#define ZCL_NATIVE_DEV_FLEET_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>

/* Derive the complete origin main plus agent-branch view rooted at one checkout.
 * No node, datadir, network endpoint, or mutable fleet ledger is consulted. */
bool zcl_dev_fleet_collect(const char *checkout_root,
                           struct json_value *out,
                           char *why, size_t why_size);

/* The intentionally tiny owner boundary used by the renderer and its unit
 * tests. These gates cannot be made green by an ordinary lane worker. */
bool zcl_dev_fleet_gate_owner_only(const char *gate);

/* The orchestrator-facing sibling: one bounded opening packet for the whole
 * fleet. Registered as dev.fleet.start; dev.fleet.truth keeps the per-lane
 * Git/receipt inventory above. */
void zcl_native_handle_dev_fleet_start(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

void zcl_native_handle_dev_fleet(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#endif /* ZCL_NATIVE_DEV_FLEET_H */
