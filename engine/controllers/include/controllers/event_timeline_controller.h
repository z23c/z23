/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_EVENT_TIMELINE_H
#define ZCL_CONTROLLERS_EVENT_TIMELINE_H

#include <stdbool.h>

struct json_value;

bool rpc_timeline(const struct json_value *params, bool help,
                  struct json_value *result);

#endif
