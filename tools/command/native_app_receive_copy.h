/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: bind a received Tasks recipe build to its verified preview offer. */
#ifndef ZCL_NATIVE_APP_RECEIVE_COPY_H
#define ZCL_NATIVE_APP_RECEIVE_COPY_H
#include <stdbool.h>
struct json_value;
struct zcl_command_reply;
#if defined(ZCL_TESTING)
bool zcl_test_receive_plan_accept(const struct zcl_command_reply *verified,
                                  const struct zcl_command_reply *planned,
                                  struct zcl_command_reply *result);
#endif
/* The receive reply is a trusted committed receive, never caller-supplied data. */
bool app_receive_tasks_recipe(const struct zcl_command_reply *receive, const struct json_value *build);
bool app_receive_tasks_preflight(const char *datadir, struct zcl_command_reply *receive);
bool app_receive_tasks_offer(const char *datadir, struct zcl_command_reply *receive,
                             const struct json_value *build);
#endif
