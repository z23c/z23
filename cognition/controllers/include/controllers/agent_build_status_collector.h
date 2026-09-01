/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, proof-honest optional tooling status collection. */
#ifndef ZCL_CONTROLLERS_AGENT_BUILD_STATUS_COLLECTOR_H
#define ZCL_CONTROLLERS_AGENT_BUILD_STATUS_COLLECTOR_H

struct json_value;

void agent_collect_optional_status(struct json_value *out,
                                   const char *command,
                                   const char *schema);

#endif /* ZCL_CONTROLLERS_AGENT_BUILD_STATUS_COLLECTOR_H */
