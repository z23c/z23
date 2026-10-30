/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Task-specific brief rendered by `code.guide` when it is given
 * paths, a topic or a budget. */

#ifndef ZCL_TOOLS_COMMAND_NATIVE_CODE_BRIEF_H
#define ZCL_TOOLS_COMMAND_NATIVE_CODE_BRIEF_H

#include "command/native_command.h"

/* Renders zcl.code_guide_brief.v1 into reply->data, at most `budget` bytes of
 * serialized data (default 2048, range 256..8192). Fails the reply with
 * BAD_CODE_GUIDE_INPUT on a malformed input. */
void zcl_code_brief_render(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply);

/* Offers one wiki entry to the lesson ranking pool, holding at most `max`
 * entries. A full pool keeps the newest `max` (by `updated`, ties by slug):
 * the entry replaces the pool's oldest one if it is newer, else it is
 * dropped; max 0 drops every entry. False when an entry that should be kept
 * could not be copied. Exposed for the focused test. */
bool zcl_code_brief_pool_offer(struct json_value *pool, size_t max,
                               const struct json_value *entry);

#endif
