/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Declares the chainstate readiness check for RPC handlers: whether the active
 * chain tip has a block index entry, and a wrapper that writes an internal
 * error into the JSON result when it does not. Implemented in
 * rpc_chainstate_guard.c and included by the wallet diagnostic and controller
 * RPC sources. */

#ifndef ZCL_CONTROLLERS_RPC_CHAINSTATE_GUARD_H
#define ZCL_CONTROLLERS_RPC_CHAINSTATE_GUARD_H

#include <stdbool.h>

struct json_value;
struct main_state;

bool rpc_chainstate_lookup_ready(const struct main_state *ms);
bool rpc_require_chainstate_lookup_ready(const struct main_state *ms,
                                         struct json_value *result,
                                         const char *method,
                                         const char *operation);

#endif
