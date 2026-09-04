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
 * Implement this file only; the test tools/harness/src/test_devagent_triage.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "platform/clock.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DVG_LEAF "dev.agent.triage"

#define DVG_OUT_CAP 65536
#define DVG_LINE_CAP (DVG_OUT_CAP + 128)
#define DVG_MAX_BRANCHES 4096
#define DVG_TIMEOUT_MS 30000

static void dvg_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static void dvg_join_argv(const char *const argv[], char *line, size_t cap)
{
    size_t used = 0;
    if (cap == 0)
        return;
    line[0] = '\0';
    for (size_t i = 0; argv[i]; i++) {
        int w = snprintf(line + used, cap - used, "%s%s",
                         used == 0 ? "" : " ", argv[i]);
        if (w < 0 || (size_t)w >= cap - used)
            return;
        used += (size_t)w;
    }
}

/* Run one git command in `dir` (NULL/empty means the process cwd) through
 * the only allowed process rail. `line` always receives the joined argv, so
 * a failure names exactly what to rerun. */
static int dvg_git(const char *dir, const char *const args[], char *out,
                   size_t cap, char *line, size_t linecap)
{
    const char *argv[16];
    size_t n = 0;

    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0])) {
            (void)snprintf(line, linecap, "git <internal argv overflow>");
            out[0] = '\0';
            return -1;
        }
        argv[n++] = args[i];
    }
    argv[n] = NULL;

    dvg_join_argv(argv, line, linecap);
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, DVG_TIMEOUT_MS);
}

static void dvg_git_failed(struct zcl_command_reply *reply, const char *line,
                           int rc)
{
    char msg[DVG_LINE_CAP + 64];
    (void)snprintf(msg, sizeof(msg),
                   "git invocation failed (exit status %d): %s", rc, line);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "spawn",
                           false, false, msg,
                           "tools/command/native_devagent_triage.c");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "rerun: %s", line);
}

/* Count non-empty lines in `text` (git rev-list --count already returns a
 * single integer line, but a count-of-lines helper doubles as the parser). */
static long long dvg_parse_ll(const char *text)
{
    char *end = NULL;
    long long v = strtoll(text, &end, 10);
    if (end == text)
        return 0;
    return v;
}

struct dvg_branch_names {
    char names[DVG_MAX_BRANCHES][256];
    size_t count;
};

/* Parse `git for-each-ref --format=%(refname:short) refs/heads` output: one
 * branch name per line, excluding "main". */
static void dvg_parse_refs(const char *out, struct dvg_branch_names *names)
{
    const char *p = out;
    names->count = 0;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && len < sizeof(names->names[0])) {
            char buf[256];
            memcpy(buf, p, len);
            buf[len] = '\0';
            if (strcmp(buf, "main") != 0 &&
                names->count < DVG_MAX_BRANCHES) {
                (void)snprintf(names->names[names->count], sizeof(names->names[0]),
                              "%s", buf);
                names->count++;
            }
        }
        if (!nl)
            break;
        p = nl + 1;
    }
}

void zcl_native_handle_dev_agent_triage(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *cwd = NULL;
    const char *base = "origin/main";
    long long max_age_days = 14;
    long long limit = 200;
    char out[DVG_OUT_CAP];
    char line[DVG_LINE_CAP];
    int rc;
    struct dvg_branch_names names;
    struct json_value branches_arr, row, counts;
    long long land = 0, rebase = 0, del = 0;
    bool truncated;
    time_t now;

    if (!reply)
        return;

    (void)json_push_kv_str(&reply->data, "leaf", DVG_LEAF);

    if (request && request->input) {
        const struct json_value *v;
        v = json_get(request->input, "cwd");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            cwd = json_get_str(v);
        v = json_get(request->input, "base");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            base = json_get_str(v);
        v = json_get(request->input, "max_age_days");
        if (v && v->type == JSON_INT)
            max_age_days = json_get_int(v);
        v = json_get(request->input, "limit");
        if (v && v->type == JSON_INT)
            limit = json_get_int(v);
    }
    if (limit <= 0)
        limit = 200;

    {
        static const char *const argv_refs[] = {
            "for-each-ref", "--format=%(refname:short)", "refs/heads", NULL};
        rc = dvg_git(cwd, argv_refs, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            dvg_git_failed(reply, line, rc);
            return;
        }
    }
    dvg_parse_refs(out, &names);

    truncated = (long long)names.count > limit;

    json_init(&branches_arr);
    json_set_array(&branches_arr);
    json_init(&row);

    now = (time_t)(clock_now_wall_ms() / 1000);

    for (size_t i = 0; i < names.count && (long long)i < limit; i++) {
        const char *branch = names.names[i];
        char head[128];
        long long ahead = 0, behind = 0, age_days = 0;
        bool merge_clean;
        char range_ahead[300], range_behind[300];

        {
            const char *argv_head[] = {"rev-parse", "--short", branch, NULL};
            rc = dvg_git(cwd, argv_head, head, sizeof(head), line, sizeof(line));
            if (rc != 0) {
                dvg_git_failed(reply, line, rc);
                json_free(&row);
                json_free(&branches_arr);
                return;
            }
            dvg_strip(head);
        }

        (void)snprintf(range_ahead, sizeof(range_ahead), "%s..%s", base, branch);
        {
            const char *argv_ahead[] = {"rev-list", "--count", range_ahead,
                                        NULL};
            rc = dvg_git(cwd, argv_ahead, out, sizeof(out), line, sizeof(line));
            if (rc != 0) {
                dvg_git_failed(reply, line, rc);
                json_free(&row);
                json_free(&branches_arr);
                return;
            }
            dvg_strip(out);
            ahead = dvg_parse_ll(out);
        }

        (void)snprintf(range_behind, sizeof(range_behind), "%s..%s", branch,
                       base);
        {
            const char *argv_behind[] = {"rev-list", "--count", range_behind,
                                         NULL};
            rc = dvg_git(cwd, argv_behind, out, sizeof(out), line, sizeof(line));
            if (rc != 0) {
                dvg_git_failed(reply, line, rc);
                json_free(&row);
                json_free(&branches_arr);
                return;
            }
            dvg_strip(out);
            behind = dvg_parse_ll(out);
        }

        {
            const char *argv_ct[] = {"log", "-1", "--format=%ct", branch,
                                     NULL};
            rc = dvg_git(cwd, argv_ct, out, sizeof(out), line, sizeof(line));
            if (rc != 0) {
                dvg_git_failed(reply, line, rc);
                json_free(&row);
                json_free(&branches_arr);
                return;
            }
            dvg_strip(out);
            {
                long long committed = dvg_parse_ll(out);
                long long delta = (long long)now - committed;
                age_days = delta > 0 ? delta / 86400 : 0;
            }
        }

        {
            const char *argv_mt[] = {"merge-tree", "--write-tree", base,
                                     branch, NULL};
            rc = dvg_git(cwd, argv_mt, out, sizeof(out), line, sizeof(line));
            merge_clean = rc == 0;
        }

        {
            const char *bin;
            if (ahead == 0 ||
                (age_days > max_age_days && behind > 500))
                bin = "delete";
            else if (merge_clean)
                bin = "land";
            else
                bin = "rebase";

            if (strcmp(bin, "land") == 0)
                land++;
            else if (strcmp(bin, "rebase") == 0)
                rebase++;
            else
                del++;

            json_set_object(&row);
            (void)json_push_kv_str(&row, "branch", branch);
            (void)json_push_kv_str(&row, "head", head);
            (void)json_push_kv_int(&row, "ahead", ahead);
            (void)json_push_kv_int(&row, "behind", behind);
            (void)json_push_kv_int(&row, "last_commit_age_days", age_days);
            (void)json_push_kv_bool(&row, "merge_clean", merge_clean);
            (void)json_push_kv_str(&row, "bin", bin);
            (void)json_push_back(&branches_arr, &row);
        }
    }
    json_free(&row);

    json_init(&counts);
    json_set_object(&counts);
    (void)json_push_kv_int(&counts, "land", land);
    (void)json_push_kv_int(&counts, "rebase", rebase);
    (void)json_push_kv_int(&counts, "delete", del);

    (void)json_push_kv(&reply->data, "branches", &branches_arr);
    (void)json_push_kv(&reply->data, "counts", &counts);
    (void)json_push_kv_str(&reply->data, "base", base);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);

    json_free(&branches_arr);
    json_free(&counts);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
