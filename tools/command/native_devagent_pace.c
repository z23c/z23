/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.pace — read a headless executor run log and report what
 *          the run actually DID, so "it exited 0" can never be mistaken for
 *          "it wrote something".
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. An executor that exits 0 having written no file is the single most
 * common way a lane reports success and delivers nothing, and an executor
 * that reads thirty files before its first edit has already spent its budget.
 * Both are visible in the run's own log and in nothing else.
 *
 * INPUT (zcl.agent_pace_input.v1)
 *   cwd  optional string. Directory a relative `log` is resolved against.
 *        Default: the process working directory.
 *   log  REQUIRED string, the path to the run log.
 *
 * LOG GRAMMAR, verified against the real opencode headless logs in
 * ~/.local/state/zclassic23/scratch/northstar/oc_*.out. Every marker is
 * wrapped in ANSI SGR escapes ("\x1b[0m" before and after the glyph), so
 * EVERY line must have its escape sequences stripped BEFORE it is matched:
 * remove ESC '[' <parameter and intermediate bytes> <final byte in @..~>,
 * and remove a bare ESC that starts no recognized sequence. Match on the
 * stripped line only.
 *
 * A stripped line is a TOOL LINE when it begins with any of:
 *   "$ "  a shell tool call; the rest of the line is the command
 *   "\xe2\x86\x92 "  (U+2192 RIGHTWARDS ARROW) a read-shaped tool call,
 *                    e.g. "Read <path>", "Skill <name>"
 *   "\xe2\x86\x90 "  (U+2190 LEFTWARDS ARROW) a write-shaped tool call,
 *                    e.g. "Edit <path>", "Write <path>"
 *   "\xe2\x9c\xb1 "  (U+2731 HEAVY ASTERISK) a search tool call,
 *                    e.g. "Grep ...", "Glob ..."
 *
 * A tool line is an EDIT LINE when it begins with the U+2190 marker followed
 * by "Edit " or "Write "; the remainder of the line is the edited PATH.
 *
 * The exit code is carried by the LAST stripped line matching
 * "rc=<integer> DONE".
 *
 * OUTPUT (zcl.agent_pace.v1) on ok=true
 *   leaf                    "dev.agent.pace"
 *   tool_calls              total tool lines
 *   calls_before_first_edit tool lines strictly before the first edit line;
 *                           equals tool_calls when there was no edit
 *   edits                   number of edit lines
 *   files_edited            array of DISTINCT edited paths, first-seen order
 *   commits                 number of "$ " lines whose command contains
 *                           "git commit"
 *   rc                      the recorded exit code, or -1 when no
 *                           "rc=<n> DONE" line is present
 *   no_edit                 bool: edits == 0
 *   pace_ok                 bool: an edit happened within the first 10 tool
 *                           calls, i.e. edits > 0 AND
 *                           calls_before_first_edit <= 9
 *   verdict                 "WROTE_NOTHING" when no_edit;
 *                           "SLOW_START" when edits > 0 and not pace_ok;
 *                           "PACED" otherwise
 *   log                     the resolved log path that was read
 *
 * FAILURE. A missing or empty `log` is ok=false, status "BAD_INPUT". A log
 * that cannot be opened is ok=false, status "LOG_UNREADABLE", with a message
 * naming the resolved path. An empty log is a valid read: tool_calls 0,
 * verdict "WROTE_NOTHING", rc -1.
 *
 * PROCESS RULE. This leaf runs no process. If it ever needs one, use
 * zcl_spawn_capture() from util/spawn.h; popen(), system() and a shell
 * command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_pace.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVP_LEAF "dev.agent.pace"

void zcl_native_handle_dev_agent_pace(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DVP_LEAF);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "NOT_IMPLEMENTED", "resolve", false, false,
        "dev.agent.pace is a scaffold stub with no behavior yet",
        "tools/command/native_devagent_pace.c carries the contract");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "implement tools/command/native_devagent_pace.c");
    reply->error.human_action_required = true;
}
