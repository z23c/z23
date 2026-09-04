/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.situation — decide whether this directory is a
 *          standalone clone or one linked worktree among several, and report
 *          the exact Git facts the verdict was made from.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Every rule an agent follows in a Z23 checkout branches on this one
 * fact, and an agent that guesses wrong pushes from a lane worktree or opens
 * a side branch on a standalone clone. The test is one line of shell that
 * nobody remembers, so it becomes a command.
 *
 * INPUT (zcl.agent_situation_input.v1)
 *   cwd    optional string. Directory to run Git in. Default: the process
 *          working directory.
 *
 * OUTPUT (zcl.agent_situation.v1) on ok=true
 *   leaf             "dev.agent.situation"
 *   situation        "standalone" | "shared_checkout_lane"
 *   git_dir          `git rev-parse --git-dir`, exactly as Git prints it
 *   git_common_dir   `git rev-parse --git-common-dir`, exactly as Git prints it
 *   worktree         `git rev-parse --show-toplevel`
 *   branch           `git rev-parse --abbrev-ref HEAD`, or "" when HEAD is
 *                    detached (Git prints "HEAD" there; report "" instead)
 *   head             `git rev-parse HEAD`, 40 lowercase hex characters
 *   test             the ZCL_AGENT_SITUATION test_prose of the ANSWERED
 *                    situation, verbatim from engine/composition/agent_rules.def
 *
 * RULE. situation is "standalone" when git_dir and git_common_dir are the
 * same path and "shared_checkout_lane" otherwise. Compare what Git printed:
 * a linked worktree answers a path under <common>/worktrees/<name>, so the
 * two strings differ. Trailing newlines from Git are stripped before
 * anything is compared or reported.
 *
 * FAILURE. Any Git invocation that does not exit 0 is ok=false, status
 * "GIT_FAILED", with a message naming the failing argv (the whole command
 * line, so the reader can rerun it). Nothing else in this file may report
 * a Git failure as a situation.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_situation.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVS_LEAF "dev.agent.situation"

void zcl_native_handle_dev_agent_situation(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVS_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.situation is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_situation.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_situation.c");
    reply->error.human_action_required = true;
}
