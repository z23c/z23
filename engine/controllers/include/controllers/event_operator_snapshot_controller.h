/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_EVENT_OPERATOR_SNAPSHOT_CONTROLLER_H
#define ZCL_CONTROLLERS_EVENT_OPERATOR_SNAPSHOT_CONTROLLER_H

#include <stdbool.h>

struct json_value;

/* Read-only, target-owned operator evidence contract.  Collection takes only
 * leaf locks, never two at once; serialization runs after every lock is
 * released. */
bool rpc_operator_snapshot(const struct json_value *params, bool help,
                           struct json_value *result);

#endif
