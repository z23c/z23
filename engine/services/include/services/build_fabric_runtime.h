/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Supervision for equal-node requester and executor roles. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H
#define ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H

#include "base/result.h"

#include <stdbool.h>

struct zcl_result build_fabric_runtime_register(bool worker_enabled,
                                                const char *datadir);

struct json_value;
bool build_fabric_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_BUILD_FABRIC_RUNTIME_H */
