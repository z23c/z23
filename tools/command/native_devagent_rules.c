/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.rules — render the compiled agent rule table, whole or
 *          filtered to one checkout situation.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. The rules are DATA, in engine/composition/agent_rules.def, precisely
 * so no agent has to remember them and no second copy can drift. This leaf
 * is the only renderer of that table.
 *
 * SOURCE. Include "../../engine/composition/agent_rules.def" from this file with
 * ZCL_AGENT_SITUATION(id, test_prose) and ZCL_AGENT_RULE(id, situation,
 * value, say) defined locally, twice if convenient. Nothing is read from
 * disk; the table is compiled in and its row order is the report order.
 *
 * INPUT (zcl.agent_rules_input.v1)
 *   cwd        optional string, accepted and ignored here (every dev.agent
 *              leaf takes it so a caller can pass one input shape).
 *   situation  optional string. When present it must be a ZCL_AGENT_SITUATION
 *              id; the rules array is then only the rows whose `when` equals
 *              it. When absent every row is reported.
 *
 * OUTPUT (zcl.agent_rules.v1) on ok=true
 *   leaf        "dev.agent.rules"
 *   situations  array of {id, test} — every ZCL_AGENT_SITUATION row, always
 *               complete and never filtered.
 *   rules       array of {id, when, value, say} in table order, filtered when
 *               `situation` was given.
 *   count       number of elements in rules.
 *   source      "engine/composition/agent_rules.def"
 *   topics      ["push_target","commit_scope","gate_command","gate_skip",
 *                "force_push","history"] — in that order.
 *
 * FAILURE. A `situation` that is not a declared ZCL_AGENT_SITUATION id is
 * ok=false, status "UNKNOWN_SITUATION", with a message naming the value and
 * the declared ids. An empty result set is never reported as success.
 *
 * PROCESS RULE. This leaf runs no process at all. If it ever needs Git, use
 * zcl_spawn_capture() from util/spawn.h; popen(), system() and a shell
 * command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_rules.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The rule table is REACHABLE from here -- the include below is the exact
 * line the implementation expands with real macros. Expanded with both
 * X-macros empty it emits no tokens, so the stub proves the path compiles
 * without yet answering anything. */
#define ZCL_AGENT_SITUATION(id_, test_prose_)
#define ZCL_AGENT_RULE(id_, situation_, value_, say_)
#include "../../engine/composition/agent_rules.def"
#undef ZCL_AGENT_RULE
#undef ZCL_AGENT_SITUATION

#define DVR_LEAF "dev.agent.rules"

void zcl_native_handle_dev_agent_rules(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVR_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.rules is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_rules.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_rules.c");
    reply->error.human_action_required = true;
}
