/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_EVENT_AGENT_SUMMARY_H
#define ZCL_CONTROLLERS_EVENT_AGENT_SUMMARY_H

#include <stdbool.h>

struct json_value;

bool rpc_agent_summary(const struct json_value *params, bool help,
                       struct json_value *result);

#endif
