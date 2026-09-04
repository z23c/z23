/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.ceiling — refuse a working tree whose diff outgrew the
 *          scope it was given, before it is committed rather than after it is
 *          reviewed.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. A unit asked to edit one file that quietly edits six, or rewrites the
 * one it was given, is the most expensive failure in a parallel lane: it
 * collides with every sibling and cannot be reviewed as one change. The
 * scope is stated up front, so it can be MEASURED up front.
 *
 * INPUT (zcl.agent_ceiling_input.v1)
 *   cwd            optional string. Directory to run Git in. Default: the
 *                  process working directory.
 *   base           REQUIRED string, a ref.
 *   requested      REQUIRED array of path strings, the files the change was
 *                  allowed to touch. Paths are compared exactly as Git prints
 *                  them, relative to the worktree top level.
 *   ceiling_lines  optional int. Default 80.
 *
 * SCAN. `git diff --numstat <base>` gives added/deleted per changed file
 * against the WORKING TREE (not the index, not HEAD). Every untracked file
 * (`git ls-files --others --exclude-standard`) is additionally counted as a
 * changed file whose added is its line count and whose deleted is 0.
 *
 * PER FILE
 *   path
 *   added          lines added
 *   deleted        lines deleted
 *   requested      bool: the path is in the `requested` array
 *   new_file       bool: the path does not exist at `base`
 *   rewrite        bool: deleted * 2 > the file's line count AT BASE
 *                  (`git show <base>:<path>`). Always false for a new file.
 *   over_ceiling   bool: added + deleted > ceiling_lines
 *
 * VERDICT
 *   ok=true, status "WITHIN_CEILING" only when EVERY changed file is
 *   requested, no file is a rewrite, and no file is over_ceiling.
 *   Otherwise ok=false, status "CEILING_EXCEEDED", with
 *   violations:[{path, reason}] where reason is exactly one of
 *   "unrequested", "rewrite", "over_ceiling". A file that breaks more than
 *   one rule contributes one violation per broken rule, in that order.
 *
 * OUTPUT (zcl.agent_ceiling.v1), on success AND on CEILING_EXCEEDED
 *   leaf     "dev.agent.ceiling"
 *   files    array of the per-file objects above
 *   summary  {changed, unrequested, rewrites, over_ceiling} — counts of files
 *   base     the base ref used
 *
 * FAILURE. A missing `base` or a missing/empty `requested` is ok=false,
 * status "BAD_INPUT". Any Git invocation that does not exit 0 is ok=false,
 * status "GIT_FAILED", with a message naming the failing argv — EXCEPT
 * `git show <base>:<path>` for a path absent at base, which is the
 * new_file=true answer.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_ceiling.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVL_LEAF "dev.agent.ceiling"

void zcl_native_handle_dev_agent_ceiling(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVL_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.ceiling is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_ceiling.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_ceiling.c");
    reply->error.human_action_required = true;
}
