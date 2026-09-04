/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.triage — bin every local branch as land, rebase or
 *          delete from Git alone, so a checkout with a hundred lane branches
 *          can be cleared without opening any of them.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Branches accumulate faster than anyone reads them, and the only three
 * useful answers — it merges, it needs a rebase, it is already gone — are
 * each a different pair of Git commands. One call answers for every branch.
 *
 * INPUT (zcl.agent_triage_input.v1)
 *   cwd            optional string. Directory to run Git in. Default: the
 *                  process working directory.
 *   base           optional string. Default "origin/main".
 *   max_age_days   optional int. Default 14.
 *   limit          optional int. Default 200.
 *
 * SCAN. `git for-each-ref refs/heads` — every LOCAL branch except "main".
 * Nothing under refs/remotes is inspected and no ref is ever written.
 *
 * PER BRANCH
 *   branch                the short name
 *   head                  short SHA, as `git rev-parse --short` prints it
 *   ahead                 commits in base..branch
 *   behind                commits in branch..base
 *   last_commit_age_days  whole days between the branch head's commit time
 *                         and now
 *   merge_clean           bool: `git merge-tree --write-tree <base> <branch>`
 *                         exits 0
 *   bin                   see RULE
 *
 * RULE, in this order:
 *   "delete"  when ahead == 0, OR when last_commit_age_days > max_age_days
 *             AND behind > 500;
 *   else "land"   when merge_clean;
 *   else "rebase".
 *
 * OUTPUT (zcl.agent_triage.v1) on ok=true
 *   leaf       "dev.agent.triage"
 *   branches   array of the per-branch objects above, at most `limit` of them
 *   counts     {land, rebase, delete} over the REPORTED branches
 *   base       the base ref used
 *   truncated  bool, true when more than `limit` branches were found
 *
 * FAILURE. Any Git invocation that does not exit 0 is ok=false, status
 * "GIT_FAILED", with a message naming the failing argv — EXCEPT
 * `git merge-tree`, whose non-zero exit is the merge_clean=false answer and
 * never a failure.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_triage.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVG_LEAF "dev.agent.triage"

void zcl_native_handle_dev_agent_triage(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVG_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.triage is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_triage.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_triage.c");
    reply->error.human_action_required = true;
}
