/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_EVENT_HEALTHCHECK_CONTROLLER_H
#define ZCL_EVENT_HEALTHCHECK_CONTROLLER_H

#include <stdbool.h>

struct json_value;

bool rpc_healthcheck(const struct json_value *params, bool help,
                     struct json_value *result);

#endif /* ZCL_EVENT_HEALTHCHECK_CONTROLLER_H */
