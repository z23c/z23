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

#endif
