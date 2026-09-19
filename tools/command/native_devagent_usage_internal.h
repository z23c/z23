/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: private seam between dev.agent.outcomes and its usage_log reader
 *          (native_devagent_usage.c).
 */
#ifndef ZCL_NATIVE_DEVAGENT_USAGE_INTERNAL_H
#define ZCL_NATIVE_DEVAGENT_USAGE_INTERNAL_H

#include "command/native_command.h"
#include "json/json.h"

/* When `input` carries usage_log, read it and push a "usage" object onto
 * reply->data; on a bad or unreadable usage_log, fail the reply instead.
 * `model` and `since` are the outcomes filters (NULL when absent). A call
 * without usage_log does nothing. */
void dvu_push_usage(const struct json_value *input, const char *model,
                    const char *since, struct zcl_command_reply *reply);

#endif
