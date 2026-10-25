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

static const char *dvd_input_string(const struct zcl_command_request *request,
                                    const char *key)
{
    if (!request || !request->input)
        return NULL;
    const struct json_value *v = json_get(request->input, key);
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return NULL;
}

/* Runs one git query whose whole stdout is the answer; on failure the reply
 * is already failed. */
static bool dvd_git_answer(struct zcl_command_reply *reply, const char *cwd,
                           const char *const argv[], char *out, size_t out_sz)
{
    char line[DVD_LINE_CAP];
    int rc = dvd_git(cwd, argv, out, out_sz, line, sizeof(line));
    if (rc != 0)
        dvd_git_failed(reply, line, rc);
    return rc == 0;
}

/* tree_clean: no tracked change, and no untracked file outside build/. */
static bool dvd_porcelain_clean(const char *out)
{
    const char *p = out;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= 3) {
            char pathbuf[PATH_MAX];
            size_t pathlen = len > 3 ? len - 3 : 0;
            if (pathlen >= sizeof(pathbuf))
                pathlen = sizeof(pathbuf) - 1;
            memcpy(pathbuf, p + 3, pathlen);
            pathbuf[pathlen] = '\0';
            bool untracked_row = p[0] == '?' && p[1] == '?';
            if (!untracked_row || !dvd_under_build(pathbuf))
                return false;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return true;
}

/* Adds each "<hash> N" row of `git log --format='%h %G?'` (unsigned) to
 * unsigned_arr. */
static void dvd_collect_unsigned(const char *out, struct json_value *unsigned_arr)
{
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
                if (strcmp(space + 1, "N") == 0) {
                    json_set_str(&item, rowbuf);
                    (void)json_push_back(unsigned_arr, &item);
                }
            }
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    json_free(&item);
}

static void dvd_push_reason(struct json_value *reasons, const char *reason)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, reason);
    (void)json_push_back(reasons, &item);
    json_free(&item);
}

/* base: the "base" input string when present, else "origin/main". */
static const char *dvd_resolve_base(const struct zcl_command_request *request)
{
    const char *base_in = dvd_input_string(request, "base");
    if (base_in)
        return base_in;
    return "origin/main";
}

/* head: `git rev-parse HEAD`, newline-stripped. */
static bool dvd_query_head(struct zcl_command_reply *reply, const char *cwd,
                           char *head, size_t head_sz)
{
    const char *head_argv[] = {"rev-parse", "HEAD", NULL};
    if (!dvd_git_answer(reply, cwd, head_argv, head, head_sz))
        return false;
    dvd_strip(head);
    return true;
}

/* branch: `git rev-parse --abbrev-ref HEAD`, newline-stripped; a detached
 * HEAD reports "" rather than "HEAD". */
static bool dvd_query_branch(struct zcl_command_reply *reply, const char *cwd,
                             char *branch, size_t branch_sz)
{
    const char *branch_argv[] = {"rev-parse", "--abbrev-ref", "HEAD", NULL};
    if (!dvd_git_answer(reply, cwd, branch_argv, branch, branch_sz))
        return false;
    dvd_strip(branch);
    if (strcmp(branch, "HEAD") == 0)
        branch[0] = '\0';
    return true;
}

/* ahead: `git rev-list --count base..HEAD`; an unparseable count is 0. */
static bool dvd_count_ahead(struct zcl_command_reply *reply, const char *cwd,
                            const char *range, long long *ahead_out)
{
    char out[DVD_OUT_CAP];
    const char *count_argv[] = {"rev-list", "--count", range, NULL};
    if (!dvd_git_answer(reply, cwd, count_argv, out, sizeof(out)))
        return false;
    dvd_strip(out);
    char *end = NULL;
    long long ahead = strtoll(out, &end, 10);
    if (end == out)
        ahead = 0;
    *ahead_out = ahead;
    return true;
}

/* unsigned commits in base..HEAD. */
static bool dvd_query_unsigned(struct zcl_command_reply *reply,
                               const char *cwd, const char *range,
                               long long ahead, struct json_value *unsigned_arr)
{
    if (ahead > 0) {
        char out[DVD_OUT_CAP];
        const char *log_argv[] = {"log", "--format=%h %G?", range, NULL};
        if (!dvd_git_answer(reply, cwd, log_argv, out, sizeof(out)))
            return false;
        dvd_collect_unsigned(out, unsigned_arr);
    }
    return true;
}

/* One reason per FALSE conjunct of the ready rule, in contract order. */
static void dvd_collect_reasons(struct json_value *reasons, bool tree_clean,
                                long long ahead, bool has_unsigned,
                                bool on_main)
{
    if (!tree_clean)
        dvd_push_reason(reasons, "tree_dirty");
    if (ahead < 1)
        dvd_push_reason(reasons, "no_commits_ahead");
    if (has_unsigned)
        dvd_push_reason(reasons, "unsigned_commits");
    if (on_main)
        dvd_push_reason(reasons, "on_main");
}

void zcl_native_handle_dev_agent_done(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    char out[DVD_OUT_CAP];

    if (!reply)
        return;

    const char *cwd = dvd_input_string(request, "cwd");
    const char *base = dvd_resolve_base(request);

    (void)json_push_kv_str(&reply->data, "leaf", DVD_LEAF);

    /* base must resolve: a non-resolving base is a GIT_FAILED, per contract,
     * never a silent ahead=0. */
    const char *verify_argv[] = {"rev-parse", "--verify", base, NULL};
    if (!dvd_git_answer(reply, cwd, verify_argv, out, sizeof(out)))
        return;

    char head[DVD_OUT_CAP];
    if (!dvd_query_head(reply, cwd, head, sizeof(head)))
        return;

    char branch[DVD_OUT_CAP];
    if (!dvd_query_branch(reply, cwd, branch, sizeof(branch)))
        return;

    char range[512];
    (void)snprintf(range, sizeof(range), "%s..HEAD", base);
    long long ahead = 0;
    if (!dvd_count_ahead(reply, cwd, range, &ahead))
        return;

    const char *status_argv[] = {"status", "--porcelain", NULL};
    if (!dvd_git_answer(reply, cwd, status_argv, out, sizeof(out)))
        return;
    bool tree_clean = dvd_porcelain_clean(out);

    struct json_value unsigned_arr;
    json_init(&unsigned_arr);
    json_set_array(&unsigned_arr);
    if (!dvd_query_unsigned(reply, cwd, range, ahead, &unsigned_arr)) {
        json_free(&unsigned_arr);
        return;
    }

    bool on_main = strcmp(branch, "main") == 0;
    bool has_unsigned = unsigned_arr.num_children != 0;
    bool ready = tree_clean && ahead >= 1 && !has_unsigned && !on_main;

    struct json_value reasons;
    json_init(&reasons);
    json_set_array(&reasons);
    dvd_collect_reasons(&reasons, tree_clean, ahead, has_unsigned, on_main);

    (void)json_push_kv_bool(&reply->data, "ready", ready);
    (void)json_push_kv_str(&reply->data, "head", head);
    (void)json_push_kv_str(&reply->data, "branch", branch);
    (void)json_push_kv_int(&reply->data, "ahead", ahead);
    (void)json_push_kv_bool(&reply->data, "tree_clean", tree_clean);
    (void)json_push_kv(&reply->data, "unsigned", &unsigned_arr);
    (void)json_push_kv(&reply->data, "reasons", &reasons);

    json_free(&unsigned_arr);
    json_free(&reasons);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
