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

#define DVD_OUT_CAP 65536
#define DVD_LINE_CAP (DVD_OUT_CAP + 128)
#define DVD_TIMEOUT_MS 30000

static void dvd_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static void dvd_join_argv(const char *const argv[], char *line, size_t cap)
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

/* Run one git command through the only allowed process rail. `line` always
 * receives the joined argv, so a failure names exactly what to rerun. */
static int dvd_git(const char *dir, const char *const args[], char *out,
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

    dvd_join_argv(argv, line, linecap);
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, DVD_TIMEOUT_MS);
}

static void dvd_git_failed(struct zcl_command_reply *reply, const char *line,
                           int rc)
{
    char msg[DVD_LINE_CAP + 64];
    (void)snprintf(msg, sizeof(msg),
                   "git invocation failed (exit status %d): %s", rc, line);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "spawn",
                           false, false, msg,
                           "tools/command/native_devagent_done.c");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "rerun: %s", line);
}

/* Does `path` begin with "build/"? Used to decide whether an untracked file
 * is build output rather than lane work. */
static bool dvd_under_build(const char *path)
{
    return strncmp(path, "build/", 6) == 0;
}

void zcl_native_handle_dev_agent_done(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *cwd = NULL;
    const char *base = "origin/main";
    char out[DVD_OUT_CAP];
    char line[DVD_LINE_CAP];
    int rc;

    if (!reply)
        return;

    if (request && request->input) {
        const struct json_value *v;
        v = json_get(request->input, "cwd");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            cwd = json_get_str(v);
        v = json_get(request->input, "base");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            base = json_get_str(v);
    }

    (void)json_push_kv_str(&reply->data, "leaf", DVD_LEAF);

    /* base must resolve: a non-resolving base is a GIT_FAILED, per contract,
     * never a silent ahead=0. */
    {
        const char *argv[] = {"rev-parse", "--verify", base, NULL};
        rc = dvd_git(cwd, argv, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            dvd_git_failed(reply, line, rc);
            return;
        }
    }

    char head[DVD_OUT_CAP];
    {
        const char *argv[] = {"rev-parse", "HEAD", NULL};
        rc = dvd_git(cwd, argv, head, sizeof(head), line, sizeof(line));
        if (rc != 0) {
            dvd_git_failed(reply, line, rc);
            return;
        }
        dvd_strip(head);
    }

    char branch[DVD_OUT_CAP];
    {
        const char *argv[] = {"rev-parse", "--abbrev-ref", "HEAD", NULL};
        rc = dvd_git(cwd, argv, branch, sizeof(branch), line, sizeof(line));
        if (rc != 0) {
            dvd_git_failed(reply, line, rc);
            return;
        }
        dvd_strip(branch);
    }
    const char *branch_reported = strcmp(branch, "HEAD") == 0 ? "" : branch;

    long long ahead = 0;
    {
        char range[512];
        (void)snprintf(range, sizeof(range), "%s..HEAD", base);
        const char *argv[] = {"rev-list", "--count", range, NULL};
        rc = dvd_git(cwd, argv, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            dvd_git_failed(reply, line, rc);
            return;
        }
        dvd_strip(out);
        char *end = NULL;
        ahead = strtoll(out, &end, 10);
        if (end == out)
            ahead = 0;
    }

    /* tree_clean: no tracked change, and no untracked file outside build/. */
    bool tree_clean = true;
    {
        const char *argv[] = {"status", "--porcelain", NULL};
        rc = dvd_git(cwd, argv, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            dvd_git_failed(reply, line, rc);
            return;
        }
        const char *p = out;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len >= 3) {
                bool untracked_row = p[0] == '?' && p[1] == '?';
                const char *path = p + 3;
                char pathbuf[PATH_MAX];
                size_t pathlen = len > 3 ? len - 3 : 0;
                if (pathlen >= sizeof(pathbuf))
                    pathlen = sizeof(pathbuf) - 1;
                memcpy(pathbuf, path, pathlen);
                pathbuf[pathlen] = '\0';

                if (untracked_row) {
                    if (!dvd_under_build(pathbuf))
                        tree_clean = false;
                } else {
                    tree_clean = false;
                }
            }
            if (!nl)
                break;
            p = nl + 1;
        }
    }

    /* unsigned commits in base..HEAD. */
    struct json_value unsigned_arr;
    json_init(&unsigned_arr);
    json_set_array(&unsigned_arr);
    if (ahead > 0) {
        char range[512];
        (void)snprintf(range, sizeof(range), "%s..HEAD", base);
        const char *argv[] = {"log", "--format=%h %G?", range, NULL};
        rc = dvd_git(cwd, argv, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            json_free(&unsigned_arr);
            dvd_git_failed(reply, line, rc);
            return;
        }
        const char *p = out;
        struct json_value item;
        json_init(&item);
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len > 0) {
                char rowbuf[128];
                size_t rowlen = len < sizeof(rowbuf) - 1 ? len : sizeof(rowbuf) - 1;
                memcpy(rowbuf, p, rowlen);
                rowbuf[rowlen] = '\0';
                char *space = strchr(rowbuf, ' ');
                if (space) {
                    *space = '\0';
                    const char *sig = space + 1;
                    if (strcmp(sig, "N") == 0) {
                        json_set_str(&item, rowbuf);
                        (void)json_push_back(&unsigned_arr, &item);
                    }
                }
            }
            if (!nl)
                break;
            p = nl + 1;
        }
        json_free(&item);
    }

    bool ready = tree_clean && ahead >= 1 && unsigned_arr.num_children == 0 &&
                strcmp(branch_reported, "main") != 0;

    struct json_value reasons;
    json_init(&reasons);
    json_set_array(&reasons);
    {
        struct json_value item;
        json_init(&item);
        if (!tree_clean) {
            json_set_str(&item, "tree_dirty");
            (void)json_push_back(&reasons, &item);
        }
        if (ahead < 1) {
            json_set_str(&item, "no_commits_ahead");
            (void)json_push_back(&reasons, &item);
        }
        if (unsigned_arr.num_children != 0) {
            json_set_str(&item, "unsigned_commits");
            (void)json_push_back(&reasons, &item);
        }
        if (strcmp(branch_reported, "main") == 0) {
            json_set_str(&item, "on_main");
            (void)json_push_back(&reasons, &item);
        }
        json_free(&item);
    }

    (void)json_push_kv_bool(&reply->data, "ready", ready);
    (void)json_push_kv_str(&reply->data, "head", head);
    (void)json_push_kv_str(&reply->data, "branch", branch_reported);
    (void)json_push_kv_int(&reply->data, "ahead", ahead);
    (void)json_push_kv_bool(&reply->data, "tree_clean", tree_clean);
    (void)json_push_kv(&reply->data, "unsigned", &unsigned_arr);
    (void)json_push_kv(&reply->data, "reasons", &reasons);

    json_free(&unsigned_arr);
    json_free(&reasons);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
