/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.start — the whole opening read for a lane in one call:
 *          situation, the rules that apply in it, the base ref, the state of
 *          the worktree, the named files, and the next actions.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. A lane's first five minutes are five separate shell recipes an agent
 * composes by hand and often skips. One call replaces them, and it is the
 * command whose answer decides everything the lane does next.
 *
 * INPUT (zcl.agent_start_input.v1)
 *   cwd    optional string. Directory to run Git in. Default: the process
 *          working directory.
 *   files  optional array of path strings the lane intends to own.
 *   base   optional string. Default "origin/main".
 *
 * OUTPUT (zcl.agent_start.v1) on ok=true
 *   leaf       "dev.agent.start"
 *   situation  the SAME object dev.agent.situation reports: {situation,
 *              git_dir, git_common_dir, worktree, branch, head, test}.
 *              Recompute it here; do not call another handler.
 *   rules      the rows of engine/composition/agent_rules.def whose `when`
 *              equals this checkout's situation, each {id, when, value, say}.
 *              Include the .def from this file with its two X-macros defined
 *              locally.
 *   base       {ref, head, base_known}. head is 40 hex when
 *              `git rev-parse --verify <ref>` succeeds; otherwise head is ""
 *              and base_known is false. A base that does not exist here is
 *              NOT a failure — a fresh fixture or a clone with no remote is
 *              the ordinary case.
 *   worktree   {dirty_tracked, untracked, hooks_path, hooks_armed}
 *                dirty_tracked  count of tracked files with any change
 *                               (`git status --porcelain` rows that are not
 *                               untracked)
 *                untracked      count of untracked rows ("?? ")
 *                hooks_path     `git config core.hooksPath`, or "" when unset
 *                hooks_armed    true exactly when hooks_path is non-empty
 *   files      array of {path, exists}, one per requested path, in the order
 *              given. exists is decided against the resolved cwd.
 *   next       array of strings, the ordered next actions. It ALWAYS contains
 *              "make lint-fast", and when the situation is
 *              "shared_checkout_lane" it also contains
 *              "commit on your lane branch; do not push".
 *
 * SCOPE RULE. Do NOT call the code.tests handler or any other leaf's handler.
 * This file answers on its own so it can be implemented, reviewed and
 * replaced alone.
 *
 * FAILURE. Any Git invocation that does not exit 0 — except the base-ref
 * probe, which is answered with base_known=false — is ok=false, status
 * "GIT_FAILED", with a message naming the failing argv.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_start.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVT_LEAF "dev.agent.start"

void zcl_native_handle_dev_agent_start(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.start is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_start.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_start.c");
    reply->error.human_action_required = true;
}
