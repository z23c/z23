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
 * Implement this file only; the test tools/harness/src/test_devagent_pace.c
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

/* Every line the fixtures and real logs can produce comfortably fits; this
 * is a diagnostic-scale cap, not a protocol limit. */
#define DVP_LINE_CAP 8192
/* Distinct edited files this leaf can track in one run. */
#define DVP_MAX_FILES 4096

/* Strip ANSI escape sequences from `in` into `out` (size cap), returning the
 * stripped length. Recognizes ESC '[' <bytes 0x30-0x3f>* <bytes 0x20-0x2f>*
 * <final byte 0x40-0x7e> (a CSI/SGR sequence) and drops a bare ESC that
 * starts nothing recognized. */
static size_t dvp_strip_ansi(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0';) {
        unsigned char c = (unsigned char)in[i];
        if (c == 0x1b) {
            if (in[i + 1] == '[') {
                size_t j = i + 2;
                while (in[j] != '\0' &&
                       (unsigned char)in[j] >= 0x30 &&
                       (unsigned char)in[j] <= 0x3f)
                    j++;
                while (in[j] != '\0' &&
                       (unsigned char)in[j] >= 0x20 &&
                       (unsigned char)in[j] <= 0x2f)
                    j++;
                if (in[j] != '\0' && (unsigned char)in[j] >= 0x40 &&
                    (unsigned char)in[j] <= 0x7e) {
                    i = j + 1;
                    continue;
                }
            }
            /* Bare ESC, or an incomplete/unrecognized sequence: drop just
             * the ESC byte and keep scanning from the next byte. */
            i++;
            continue;
        }
        if (o + 1 < cap)
            out[o++] = (char)c;
        i++;
    }
    if (cap > 0)
        out[o < cap ? o : cap - 1] = '\0';
    return o;
}

static bool dvp_starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* Trim a trailing '\n'/'\r' in place. */
static void dvp_chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

struct dvp_files {
    char paths[DVP_MAX_FILES][PATH_MAX];
    size_t count;
};

static void dvp_files_add(struct dvp_files *files, const char *path)
{
    for (size_t i = 0; i < files->count; i++) {
        if (strcmp(files->paths[i], path) == 0)
            return;
    }
    if (files->count < DVP_MAX_FILES) {
        (void)snprintf(files->paths[files->count], PATH_MAX, "%s", path);
        files->count++;
    }
}

void zcl_native_handle_dev_agent_pace(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *cwd = NULL;
    const char *log = NULL;
    char resolved[PATH_MAX];
    FILE *f;
    char raw[DVP_LINE_CAP];
    char line[DVP_LINE_CAP];
    long long tool_calls = 0, calls_before_first_edit = -1, edits = 0;
    long long commits = 0, rc = -1;
    struct dvp_files files;
    struct json_value files_arr, item;

    if (!reply)
        return;

    (void)json_push_kv_str(&reply->data, "leaf", DVP_LEAF);

    if (request && request->input) {
        const struct json_value *v;
        v = json_get(request->input, "cwd");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            cwd = json_get_str(v);
        v = json_get(request->input, "log");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            log = json_get_str(v);
    }

    if (!log) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT", "resolve",
                               false, false, "log is required and must be a non-empty string",
                               "tools/command/native_devagent_pace.c");
        return;
    }

    if (log[0] == '/' || !cwd || !cwd[0])
        (void)snprintf(resolved, sizeof(resolved), "%s", log);
    else
        (void)snprintf(resolved, sizeof(resolved), "%s/%s", cwd, log);

    f = fopen(resolved, "rb");
    if (!f) {
        char msg[PATH_MAX + 64];
        (void)snprintf(msg, sizeof(msg), "cannot open log: %s", resolved);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "LOG_UNREADABLE",
                               "resolve", false, false, msg,
                               "tools/command/native_devagent_pace.c");
        return;
    }

    files.count = 0;

    while (fgets(raw, sizeof(raw), f)) {
        size_t len = dvp_strip_ansi(raw, line, sizeof(line));
        (void)len;
        dvp_chomp(line);

        if (dvp_starts_with(line, "$ ")) {
            tool_calls++;
            if (strstr(line + 2, "git commit") != NULL)
                commits++;
            continue;
        }
        if (dvp_starts_with(line, "\xe2\x86\x92 ")) {
            tool_calls++;
            continue;
        }
        if (dvp_starts_with(line, "\xe2\x9c\xb1 ")) {
            tool_calls++;
            continue;
        }
        if (dvp_starts_with(line, "\xe2\x86\x90 ")) {
            const char *rest = line + strlen("\xe2\x86\x90 ");
            tool_calls++;
            if (dvp_starts_with(rest, "Edit ") ||
                dvp_starts_with(rest, "Write ")) {
                const char *path = strchr(rest, ' ');
                path = path ? path + 1 : rest;
                if (calls_before_first_edit < 0)
                    calls_before_first_edit = tool_calls - 1;
                edits++;
                dvp_files_add(&files, path);
            }
            continue;
        }

        {
            long long parsed_rc;
            int consumed = 0;
            if (sscanf(line, "rc=%lld DONE%n", &parsed_rc, &consumed) == 1 &&
                consumed > 0 && line[consumed] == '\0')
                rc = parsed_rc;
        }
    }
    (void)fclose(f);

    if (calls_before_first_edit < 0)
        calls_before_first_edit = tool_calls;

    json_init(&files_arr);
    json_set_array(&files_arr);
    json_init(&item);
    for (size_t i = 0; i < files.count; i++) {
        json_set_str(&item, files.paths[i]);
        (void)json_push_back(&files_arr, &item);
    }
    json_free(&item);

    (void)json_push_kv_int(&reply->data, "tool_calls", tool_calls);
    (void)json_push_kv_int(&reply->data, "calls_before_first_edit",
                           calls_before_first_edit);
    (void)json_push_kv_int(&reply->data, "edits", edits);
    (void)json_push_kv(&reply->data, "files_edited", &files_arr);
    (void)json_push_kv_int(&reply->data, "commits", commits);
    (void)json_push_kv_int(&reply->data, "rc", rc);
    (void)json_push_kv_bool(&reply->data, "no_edit", edits == 0);
    {
        bool pace_ok = edits > 0 && calls_before_first_edit <= 9;
        const char *verdict = edits == 0 ? "WROTE_NOTHING"
                              : !pace_ok  ? "SLOW_START"
                                          : "PACED";
        (void)json_push_kv_bool(&reply->data, "pace_ok", pace_ok);
        (void)json_push_kv_str(&reply->data, "verdict", verdict);
    }
    (void)json_push_kv_str(&reply->data, "log", resolved);

    json_free(&files_arr);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
