/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: optional bounded dispatch CPU observation for dev.agent.factory. */
#ifndef ZCL_NATIVE_DEV_FACTORY_DISPATCH_H
#define ZCL_NATIVE_DEV_FACTORY_DISPATCH_H
#include <stdbool.h>
struct json_value;
struct zcl_command_reply;
bool zcl_dev_factory_dispatch(const struct json_value *input, double now,
                              double window_s, struct zcl_command_reply *reply);
#endif
