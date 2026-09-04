/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.done — one hand-back verdict for the current branch, with
 *          every false condition named instead of collapsed into one word.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. "The lane is done" is four separate Git questions, and a lane that
 * answers three of them reports finished while its work is uncommitted,
 * unsigned, or sitting on main. Asking all four in one place is the only way
 * the answer stays honest.
 *
 * INPUT (zcl.agent_done_input.v1)
 *   cwd   optional string. Directory to run Git in. Default: the process
 *         working directory.
 *   base  optional string. Default "origin/main".
 *
 * OUTPUT (zcl.agent_done.v1) on ok=true
 *   leaf        "dev.agent.done"
 *   ready       bool, see RULE
 *   head        `git rev-parse HEAD`, 40 hex
 *   branch      `git rev-parse --abbrev-ref HEAD`, "" when detached
 *   ahead       number of commits in base..HEAD
 *   tree_clean  bool: no tracked change AND no untracked file outside build/.
 *               An untracked path under build/ is build output and never makes
 *               the tree dirty.
 *   unsigned    array of SHORT SHAs (as `git log --format=%h` prints them) of
 *               the commits in base..HEAD whose `git log --format=%G?` is "N".
 *   reasons     array of strings, one per FALSE condition, from this exact
 *               vocabulary: "tree_dirty", "no_commits_ahead",
 *               "unsigned_commits", "on_main". Empty when ready is true.
 *
 * RULE. ready is true only when tree_clean is true AND ahead >= 1 AND
 * unsigned is empty AND branch is not "main". Each failing conjunct
 * contributes its own reason; do not stop at the first.
 *
 * FAILURE. Any Git invocation that does not exit 0 is ok=false, status
 * "GIT_FAILED", with a message naming the failing argv. A base ref that does
 * not resolve is a GIT_FAILED, not a silent ahead=0.
 *
 * NOTE FOR THE IMPLEMENTER. A fixture commit made with
 * `-c commit.gpgsign=false` is unsigned and `%G?` prints N for it, which is
 * exactly what the test relies on.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_done.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVD_LEAF "dev.agent.done"

void zcl_native_handle_dev_agent_done(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVD_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.done is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_done.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_done.c");
    reply->error.human_action_required = true;
}
