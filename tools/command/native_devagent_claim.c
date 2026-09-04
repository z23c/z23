/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.claim — record this worktree's exclusive interest in a
 *          set of files as one ledger line beside the shared object store, so
 *          two lanes on one checkout cannot silently edit the same file.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Several agents work one Z23 checkout at once through linked
 * worktrees. They share an object store, a stash stack and a filesystem; the
 * only thing they do not share is a record of who is editing what. This is
 * that record, and it lives where every worktree can see it.
 *
 * INPUT (zcl.agent_claim_input.v1)
 *   cwd      optional string. Directory to run Git in. Default: the process
 *            working directory.
 *   story    string, non-empty. What the claim is FOR.
 *   files    array of path strings, non-empty unless release is true.
 *   release  optional bool, default false.
 *
 * LEDGER. <git_common_dir>/z23-agent-claims.jsonl — resolve the directory
 * with `git rev-parse --git-common-dir` so every linked worktree on one
 * checkout writes the SAME file. One JSON object per line, newline
 * terminated, appended in claim order:
 *
 *   {"ts":"<ISO-8601 UTC>","worktree":"<toplevel>","branch":"<branch>",
 *    "story":"<story>","files":["<path>", ...]}
 *
 *   ts        ISO-8601 UTC, e.g. 2026-09-04T18:22:07Z
 *   worktree  `git rev-parse --show-toplevel`
 *   branch    `git rev-parse --abbrev-ref HEAD`, "" when detached
 *
 * SEMANTICS. A claim is LIVE while its line exists in the ledger.
 *   - A claim whose files intersect a live claim from a DIFFERENT worktree is
 *     refused: ok=false, status "CLAIM_OVERLAP", plus
 *     conflicts:[{file, worktree, story}], one entry per offending file.
 *     Nothing is written on refusal.
 *   - A claim from the SAME worktree REPLACES that worktree's own line, so
 *     re-claiming is idempotent and never overlaps itself.
 *   - release=true removes every line whose worktree is this one and reports
 *     released (count). `files` may be empty and `story` is not required to
 *     match anything.
 *   - The rewrite must be whole-file: read every line, drop the ones being
 *     replaced or released, append the new line, write the file back.
 *
 * OUTPUT (zcl.agent_claim.v1) on ok=true
 *   leaf     "dev.agent.claim"
 *   claimed  array of the file paths now claimed by this worktree (empty on
 *            a release)
 *   ledger   absolute path of the ledger file
 *   live     number of live claim lines in the ledger after the write
 *   released number of lines removed, present on a release
 *
 * FAILURE. A missing or empty `story`, or an empty `files` when release is
 * false, is ok=false, status "BAD_INPUT", with a message naming which one.
 * Any Git invocation that does not exit 0 is ok=false, status "GIT_FAILED",
 * with a message naming the failing argv.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_claim.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVC_LEAF "dev.agent.claim"

void zcl_native_handle_dev_agent_claim(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVC_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.claim is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_claim.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_claim.c");
    reply->error.human_action_required = true;
}
