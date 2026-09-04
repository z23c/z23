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
#include <time.h>

#define DVC_LEAF "dev.agent.claim"
#define DVC_LEDGER_NAME "z23-agent-claims.jsonl"
#define DVC_LINE_CAP 8192

/* ── git via the only allowed rail ──────────────────────────────────────── */

static bool dvc_git(const char *cwd, const char *const args[],
                    char *out, size_t cap, char *why, size_t whycap)
{
    const char *argv[24];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = cwd;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    out[0] = '\0';
    int rc = zcl_spawn_capture(argv, out, cap, 30000);
    if (rc != 0) {
        size_t used = 0;
        for (size_t i = 0; argv[i] && used + 2 < whycap; i++)
            used += (size_t)snprintf(why + used, whycap - used, "%s%s",
                                     i ? " " : "", argv[i]);
        return false;
    }
    /* Trim the trailing newline git appends. */
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
    return true;
}

/* ── tiny JSON string escape (paths and stories are trusted-ish, but the
 *    ledger is a machine-readable format; escape the mandatory pair) ────── */

static bool dvc_json_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    for (const char *p = in; *p; p++) {
        char tmp[8];
        const char *rep = NULL;
        if (*p == '"' || *p == '\\') {
            tmp[0] = '\\';
            tmp[1] = *p;
            tmp[2] = '\0';
            rep = tmp;
        } else if ((unsigned char)*p < 0x20) {
            (void)snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)*p);
            rep = tmp;
        } else {
            tmp[0] = *p;
            tmp[1] = '\0';
            rep = tmp;
        }
        size_t rl = strlen(rep);
        if (used + rl + 1 > cap)
            return false;
        memcpy(out + used, rep, rl);
        used += rl;
    }
    out[used] = '\0';
    return true;
}

/* Extract the string value of `"key":"..."` from one ledger line. */
static bool dvc_line_str(const char *line, const char *key,
                         char *out, size_t cap)
{
    char pat[64];
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    size_t used = 0;
    while (*p && *p != '"') {
        if (used + 2 > cap)
            return false;
        if (*p == '\\' && p[1]) {
            out[used++] = p[1];
            p += 2;
        } else {
            out[used++] = *p++;
        }
    }
    out[used] = '\0';
    return true;
}

/* Does the files array on this ledger line contain `path`? */
static bool dvc_line_has_file(const char *line, const char *path)
{
    const char *p = strstr(line, "\"files\":[");
    if (!p)
        return false;
    p += strlen("\"files\":[");
    while (*p && *p != ']') {
        if (*p != '"') {
            p++;
            continue;
        }
        p++;
        char item[DVC_LINE_CAP / 4];
        size_t used = 0;
        while (*p && *p != '"') {
            if (used + 2 < sizeof(item)) {
                if (*p == '\\' && p[1]) {
                    item[used++] = p[1];
                    p += 2;
                    continue;
                }
                item[used++] = *p;
            }
            p++;
        }
        item[used] = '\0';
        if (*p == '"')
            p++;
        if (strcmp(item, path) == 0)
            return true;
    }
    return false;
}

/* ── input accessors ────────────────────────────────────────────────────── */

static const char *dvc_cwd(const struct zcl_command_request *request)
{
    if (!request || !request->input)
        return ".";
    const struct json_value *v = json_get(request->input, "cwd");
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return ".";
}

void zcl_native_handle_dev_agent_claim(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "dev.agent.claim requires an input document",
                               "request.input was missing");
        return;
    }

    const bool release = json_get(request->input, "release") &&
                         json_get(request->input, "release")->type == JSON_BOOL &&
                         json_get_bool(json_get(request->input, "release"));

    /* story: required, non-empty. */
    const struct json_value *storyv = json_get(request->input, "story");
    const char *story = storyv && storyv->type == JSON_STR
                            ? json_get_str(storyv)
                            : NULL;
    if (!story || !story[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "story is required and must be non-empty",
                               "input.story missing or empty");
        return;
    }

    /* files: required, non-empty unless release. */
    const struct json_value *filesv = json_get(request->input, "files");
    if (!filesv || filesv->type != JSON_ARR) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "files is required and must be an array",
                               "input.files missing or wrong type");
        return;
    }
    if (!release && filesv->num_children == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "files must be non-empty unless release is true",
                               "input.files was empty");
        return;
    }

    const char *cwd = dvc_cwd(request);
    char why[512];

    /* git facts. */
    char common_dir[PATH_MAX];
    {
        const char *args[] = {"rev-parse", "--git-common-dir", NULL};
        char out[PATH_MAX];
        if (!dvc_git(cwd, args, out, sizeof(out), why, sizeof(why))) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                                   "git", false, false,
                                   "git rev-parse --git-common-dir failed",
                                   why);
            return;
        }
        if (out[0] == '/')
            (void)snprintf(common_dir, sizeof(common_dir), "%s", out);
        else
            (void)snprintf(common_dir, sizeof(common_dir), "%s/%s", cwd, out);
    }

    char toplevel[PATH_MAX];
    {
        const char *args[] = {"rev-parse", "--show-toplevel", NULL};
        if (!dvc_git(cwd, args, toplevel, sizeof(toplevel), why,
                     sizeof(why))) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                                   "git", false, false,
                                   "git rev-parse --show-toplevel failed",
                                   why);
            return;
        }
    }

    char branch[256];
    {
        const char *args[] = {"rev-parse", "--abbrev-ref", "HEAD", NULL};
        if (!dvc_git(cwd, args, branch, sizeof(branch), why, sizeof(why))) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                                   "git", false, false,
                                   "git rev-parse --abbrev-ref HEAD failed",
                                   why);
            return;
        }
        if (strcmp(branch, "HEAD") == 0)
            branch[0] = '\0';
    }

    char ledger[PATH_MAX + 64];
    (void)snprintf(ledger, sizeof(ledger), "%s/%s", common_dir,
                   DVC_LEDGER_NAME);

    /* Read every existing line. */
    static char lines[256][DVC_LINE_CAP];
    size_t nlines = 0;
    {
        FILE *f = fopen(ledger, "r");
        if (f) {
            while (nlines < 256 &&
                   fgets(lines[nlines], DVC_LINE_CAP, f)) {
                size_t len = strlen(lines[nlines]);
                while (len > 0 && (lines[nlines][len - 1] == '\n' ||
                                   lines[nlines][len - 1] == '\r'))
                    lines[nlines][--len] = '\0';
                if (len > 0)
                    nlines++;
            }
            (void)fclose(f);
        }
    }

    if (release) {
        /* Drop every line whose worktree is this one. */
        size_t kept = 0, released = 0;
        for (size_t i = 0; i < nlines; i++) {
            char wt[PATH_MAX];
            if (dvc_line_str(lines[i], "worktree", wt, sizeof(wt)) &&
                strcmp(wt, toplevel) == 0) {
                released++;
                continue;
            }
            if (kept != i)
                memcpy(lines[kept], lines[i], DVC_LINE_CAP);
            kept++;
        }
        FILE *f = fopen(ledger, "wb");
        if (!f) {
            (void)snprintf(why, sizeof(why), "cannot write %s", ledger);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                                   "ledger", false, false,
                                   "failed to rewrite the claim ledger", why);
            return;
        }
        for (size_t i = 0; i < kept; i++)
            (void)fprintf(f, "%s\n", lines[i]);
        (void)fclose(f);

        (void)json_push_kv_str(&reply->data, "leaf", DVC_LEAF);
        {
            struct json_value arr;
            json_init(&arr);
            json_set_array(&arr);
            (void)json_push_kv(&reply->data, "claimed", &arr);
            json_free(&arr);
        }
        (void)json_push_kv_str(&reply->data, "ledger", ledger);
        (void)json_push_kv_int(&reply->data, "live", (long long)kept);
        (void)json_push_kv_int(&reply->data, "released", (long long)released);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
        return;
    }

    /* Claim path: check overlap against every OTHER worktree's live line. */
    struct json_value conflicts;
    json_init(&conflicts);
    json_set_array(&conflicts);
    size_t nconf = 0;
    for (size_t i = 0; i < nlines; i++) {
        char wt[PATH_MAX], lstory[512];
        if (!dvc_line_str(lines[i], "worktree", wt, sizeof(wt)))
            continue;
        if (strcmp(wt, toplevel) == 0)
            continue; /* our own line: replaced, never conflicts */
        (void)dvc_line_str(lines[i], "story", lstory, sizeof(lstory));
        for (size_t j = 0; j < filesv->num_children; j++) {
            const struct json_value *fv = &filesv->children[j];
            const char *path = fv && fv->type == JSON_STR ? json_get_str(fv)
                                                          : NULL;
            if (!path)
                continue;
            if (!dvc_line_has_file(lines[i], path))
                continue;
            struct json_value entry;
            json_init(&entry);
            json_set_object(&entry);
            (void)json_push_kv_str(&entry, "file", path);
            (void)json_push_kv_str(&entry, "worktree", wt);
            (void)json_push_kv_str(&entry, "story", lstory);
            (void)json_push_back(&conflicts, &entry);
            json_free(&entry);
            nconf++;
        }
    }
    if (nconf > 0) {
        (void)json_push_kv(&reply->data, "conflicts", &conflicts);
        json_free(&conflicts);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "CLAIM_OVERLAP",
                               "claim", false, false,
                               "files already claimed by another worktree",
                               "see conflicts in the reply data");
        return;
    }
    json_free(&conflicts);

    /* Whole-file rewrite: keep lines from other worktrees, drop our own
     * (replaced), append the new line. */
    char esc_story[1024], esc_wt[PATH_MAX + 8], esc_br[512];
    if (!dvc_json_escape(story, esc_story, sizeof(esc_story)) ||
        !dvc_json_escape(toplevel, esc_wt, sizeof(esc_wt)) ||
        !dvc_json_escape(branch, esc_br, sizeof(esc_br))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "escape", false, false,
                               "story or paths too large to record",
                               "input exceeded the ledger line budget");
        return;
    }

    size_t kept = 0;
    for (size_t i = 0; i < nlines; i++) {
        char wt[PATH_MAX];
        if (dvc_line_str(lines[i], "worktree", wt, sizeof(wt)) &&
            strcmp(wt, toplevel) == 0)
            continue; /* replaced by this claim */
        if (kept != i)
            memcpy(lines[kept], lines[i], DVC_LINE_CAP);
        kept++;
    }

    char ts[40];
    {
        time_t now = time(NULL);
        struct tm tm_utc;
        gmtime_r(&now, &tm_utc);
        (void)strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    }

    char newline[DVC_LINE_CAP];
    size_t used = (size_t)snprintf(newline, sizeof(newline),
                                   "{\"ts\":\"%s\",\"worktree\":\"%s\","
                                   "\"branch\":\"%s\",\"story\":\"%s\","
                                   "\"files\":[",
                                   ts, esc_wt, esc_br, esc_story);
    bool overflow = used >= sizeof(newline);
    for (size_t j = 0; j < filesv->num_children && !overflow; j++) {
        const struct json_value *fv = &filesv->children[j];
        const char *path = fv && fv->type == JSON_STR ? json_get_str(fv) : "";
        char esc_path[1024];
        if (!dvc_json_escape(path ? path : "", esc_path, sizeof(esc_path))) {
            overflow = true;
            break;
        }
        int w = snprintf(newline + used, sizeof(newline) - used, "%s\"%s\"",
                         j ? "," : "", esc_path);
        if (w < 0 || (size_t)w >= sizeof(newline) - used)
            overflow = true;
        else
            used += (size_t)w;
    }
    if (overflow ||
        (size_t)snprintf(newline + used, sizeof(newline) - used, "]}") >=
            sizeof(newline) - used) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "escape", false, false,
                               "claim line too large for the ledger format",
                               "input exceeded the ledger line budget");
        return;
    }

    FILE *f = fopen(ledger, "wb");
    if (!f) {
        (void)snprintf(why, sizeof(why), "cannot write %s", ledger);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED",
                               "ledger", false, false,
                               "failed to rewrite the claim ledger", why);
        return;
    }
    for (size_t i = 0; i < kept; i++)
        (void)fprintf(f, "%s\n", lines[i]);
    (void)fprintf(f, "%s\n", newline);
    (void)fclose(f);

    (void)json_push_kv_str(&reply->data, "leaf", DVC_LEAF);
    {
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        for (size_t j = 0; j < filesv->num_children; j++) {
            const struct json_value *fv = &filesv->children[j];
            if (fv && fv->type == JSON_STR && json_get_str(fv)) {
                struct json_value item;
                json_init(&item);
                json_set_str(&item, json_get_str(fv));
                (void)json_push_back(&arr, &item);
                json_free(&item);
            }
        }
        (void)json_push_kv(&reply->data, "claimed", &arr);
        json_free(&arr);
    }
    (void)json_push_kv_str(&reply->data, "ledger", ledger);
    (void)json_push_kv_int(&reply->data, "live", (long long)kept + 1);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}
