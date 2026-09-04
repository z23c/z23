/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.start — the whole opening read for a lane in one call:
 *          situation, the rules that apply in it, the base ref, the state of
 *          the worktree, the named files, and the next actions.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. A lane's first five minutes are five separate shell recipes an agent
 * composes by hand and often skips. One call replaces them, and it is the
 * command whose answer decides everything the lane does next.
 *
 * INPUT (zcl.agent_start_input.v1)
 *   cwd    optional string. Directory to run Git in. Default: the process
 *          working directory.
 *   files  optional array of path strings the lane intends to own.
 *   base   optional string. Default "origin/main".
 *
 * OUTPUT (zcl.agent_start.v1) on ok=true
 *   leaf       "dev.agent.start"
 *   situation  the SAME object dev.agent.situation reports: {situation,
 *              git_dir, git_common_dir, worktree, branch, head, test}.
 *              Recompute it here; do not call another handler.
 *   rules      the rows of engine/composition/agent_rules.def whose `when`
 *              equals this checkout's situation, each {id, when, value, say}.
 *              Include the .def from this file with its two X-macros defined
 *              locally.
 *   base       {ref, head, base_known}. head is 40 hex when
 *              `git rev-parse --verify <ref>` succeeds; otherwise head is ""
 *              and base_known is false. A base that does not exist here is
 *              NOT a failure — a fresh fixture or a clone with no remote is
 *              the ordinary case.
 *   worktree   {dirty_tracked, untracked, hooks_path, hooks_armed}
 *                dirty_tracked  count of tracked files with any change
 *                               (`git status --porcelain` rows that are not
 *                               untracked)
 *                untracked      count of untracked rows ("?? ")
 *                hooks_path     `git config core.hooksPath`, or "" when unset
 *                hooks_armed    true exactly when hooks_path is non-empty
 *   files      array of {path, exists}, one per requested path, in the order
 *              given. exists is decided against the resolved cwd.
 *   next       array of strings, the ordered next actions. It ALWAYS contains
 *              "make lint-fast", and when the situation is
 *              "shared_checkout_lane" it also contains
 *              "commit on your lane branch; do not push".
 *
 * SCOPE RULE. Do NOT call the code.tests handler or any other leaf's handler.
 * This file answers on its own so it can be implemented, reviewed and
 * replaced alone.
 *
 * FAILURE. Any Git invocation that does not exit 0 — except the base-ref
 * probe, which is answered with base_known=false — is ok=false, status
 * "GIT_FAILED", with a message naming the failing argv.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_devagent_start.c
 * is the acceptance bar and must not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DVT_LEAF "dev.agent.start"

#define DVT_OUT_CAP 65536
#define DVT_LINE_CAP (DVT_OUT_CAP + 128)
#define DVT_TIMEOUT_MS 30000

static void dvt_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static void dvt_join_argv(const char *const argv[], char *line, size_t cap)
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
static int dvt_git(const char *dir, const char *const args[], char *out,
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

    dvt_join_argv(argv, line, linecap);
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, DVT_TIMEOUT_MS);
}

static void dvt_git_failed(struct zcl_command_reply *reply, const char *line,
                           int rc)
{
    char msg[DVT_LINE_CAP + 64];
    (void)snprintf(msg, sizeof(msg),
                   "git invocation failed (exit status %d): %s", rc, line);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "spawn",
                           false, false, msg,
                           "tools/command/native_devagent_start.c");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "rerun: %s", line);
}

/* ── situation (recomputed here, per SCOPE RULE) ─────────────────────────── */

#define ZCL_AGENT_SITUATION(id_, test_prose_)
#define ZCL_AGENT_RULE(id_, situation_, value_, say_)
#include "../../engine/composition/agent_rules.def"
#undef ZCL_AGENT_RULE
#undef ZCL_AGENT_SITUATION

static bool dvt_build_situation(const char *cwd, struct json_value *out,
                                struct zcl_command_reply *reply,
                                char *situation_id, size_t situation_id_cap)
{
    static const char *const argv_git_dir[] = {"rev-parse", "--git-dir", NULL};
    static const char *const argv_git_common_dir[] = {"rev-parse",
                                                      "--git-common-dir", NULL};
    static const char *const argv_worktree[] = {"rev-parse", "--show-toplevel",
                                                NULL};
    static const char *const argv_branch[] = {"rev-parse", "--abbrev-ref",
                                              "HEAD", NULL};
    static const char *const argv_head[] = {"rev-parse", "HEAD", NULL};

    char git_dir[DVT_OUT_CAP], git_common_dir[DVT_OUT_CAP];
    char worktree[DVT_OUT_CAP], branch[DVT_OUT_CAP], head[DVT_OUT_CAP];
    char line[DVT_LINE_CAP];
    const char *situation, *prose, *branch_reported;
    bool standalone;
    int rc;

    rc = dvt_git(cwd, argv_git_dir, git_dir, sizeof(git_dir), line,
                sizeof(line));
    if (rc != 0) {
        dvt_git_failed(reply, line, rc);
        return false;
    }
    dvt_strip(git_dir);

    rc = dvt_git(cwd, argv_git_common_dir, git_common_dir,
                sizeof(git_common_dir), line, sizeof(line));
    if (rc != 0) {
        dvt_git_failed(reply, line, rc);
        return false;
    }
    dvt_strip(git_common_dir);

    rc = dvt_git(cwd, argv_worktree, worktree, sizeof(worktree), line,
                sizeof(line));
    if (rc != 0) {
        dvt_git_failed(reply, line, rc);
        return false;
    }
    dvt_strip(worktree);

    rc = dvt_git(cwd, argv_branch, branch, sizeof(branch), line, sizeof(line));
    if (rc != 0) {
        dvt_git_failed(reply, line, rc);
        return false;
    }
    dvt_strip(branch);

    rc = dvt_git(cwd, argv_head, head, sizeof(head), line, sizeof(line));
    if (rc != 0) {
        dvt_git_failed(reply, line, rc);
        return false;
    }
    dvt_strip(head);

    standalone = strcmp(git_dir, git_common_dir) == 0;
    situation = standalone ? "standalone" : "shared_checkout_lane";

    prose = "";
#define ZCL_AGENT_SITUATION(id_, test_prose_)                                \
    if (strcmp(#id_, situation) == 0)                                        \
        prose = test_prose_;
#define ZCL_AGENT_RULE(id_, situation_, value_, say_)
#include "../../engine/composition/agent_rules.def"
#undef ZCL_AGENT_RULE
#undef ZCL_AGENT_SITUATION

    branch_reported = strcmp(branch, "HEAD") == 0 ? "" : branch;

    (void)snprintf(situation_id, situation_id_cap, "%s", situation);

    json_set_object(out);
    (void)json_push_kv_str(out, "situation", situation);
    (void)json_push_kv_str(out, "git_dir", git_dir);
    (void)json_push_kv_str(out, "git_common_dir", git_common_dir);
    (void)json_push_kv_str(out, "worktree", worktree);
    (void)json_push_kv_str(out, "branch", branch_reported);
    (void)json_push_kv_str(out, "head", head);
    (void)json_push_kv_str(out, "test", prose);
    return true;
}

/* ── rules filtered to one situation ─────────────────────────────────────── */

static void dvt_build_rules(const char *situation, struct json_value *out)
{
    struct json_value row;
    json_init(&row);
    json_set_array(out);

#define ZCL_AGENT_SITUATION(id_, test_prose_)
#define ZCL_AGENT_RULE(id_, situation_, value_, say_)                        \
    do {                                                                     \
        if (strcmp(#situation_, situation) == 0) {                          \
            json_set_object(&row);                                          \
            (void)json_push_kv_str(&row, "id", #id_);                       \
            (void)json_push_kv_str(&row, "when", #situation_);              \
            (void)json_push_kv_str(&row, "value", value_);                  \
            (void)json_push_kv_str(&row, "say", say_);                      \
            (void)json_push_back(out, &row);                                \
        }                                                                    \
    } while (0);
#include "../../engine/composition/agent_rules.def"
#undef ZCL_AGENT_RULE
#undef ZCL_AGENT_SITUATION

    json_free(&row);
}

/* ── base ref probe ──────────────────────────────────────────────────────── */

static bool dvt_build_base(const char *cwd, const char *ref,
                          struct json_value *out)
{
    const char *argv[] = {"rev-parse", "--verify", ref, NULL};
    char out_buf[DVT_OUT_CAP], line[DVT_LINE_CAP];
    int rc = dvt_git(cwd, argv, out_buf, sizeof(out_buf), line, sizeof(line));
    bool known = rc == 0;
    const char *head = "";
    if (known) {
        dvt_strip(out_buf);
        head = out_buf;
    }
    json_set_object(out);
    (void)json_push_kv_str(out, "ref", ref);
    (void)json_push_kv_str(out, "head", head);
    (void)json_push_kv_bool(out, "base_known", known);
    return true;
}

/* ── worktree state: dirty/untracked counts, hooks ───────────────────────── */

static bool dvt_build_worktree(const char *cwd, struct json_value *out,
                               struct zcl_command_reply *reply)
{
    char status_out[DVT_OUT_CAP];
    char line[DVT_LINE_CAP];
    long long dirty_tracked = 0, untracked = 0;
    int rc;

    {
        const char *argv[] = {"status", "--porcelain", NULL};
        rc = dvt_git(cwd, argv, status_out, sizeof(status_out), line,
                    sizeof(line));
        if (rc != 0) {
            dvt_git_failed(reply, line, rc);
            return false;
        }
    }

    {
        const char *p = status_out;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len >= 2) {
                if (p[0] == '?' && p[1] == '?')
                    untracked++;
                else
                    dirty_tracked++;
            }
            if (!nl)
                break;
            p = nl + 1;
        }
    }

    char hooks_path[DVT_OUT_CAP];
    hooks_path[0] = '\0';
    {
        const char *argv[] = {"config", "core.hooksPath", NULL};
        rc = dvt_git(cwd, argv, hooks_path, sizeof(hooks_path), line,
                    sizeof(line));
        if (rc == 0)
            dvt_strip(hooks_path);
        else
            hooks_path[0] = '\0';
    }

    json_set_object(out);
    (void)json_push_kv_int(out, "dirty_tracked", dirty_tracked);
    (void)json_push_kv_int(out, "untracked", untracked);
    (void)json_push_kv_str(out, "hooks_path", hooks_path);
    (void)json_push_kv_bool(out, "hooks_armed", hooks_path[0] != '\0');
    return true;
}

/* ── named files ─────────────────────────────────────────────────────────── */

static void dvt_build_files(const char *cwd, const struct json_value *files_in,
                           struct json_value *out)
{
    struct json_value row;
    json_init(&row);
    json_set_array(out);

    if (!files_in || files_in->type != JSON_ARR) {
        json_free(&row);
        return;
    }

    for (size_t i = 0; i < files_in->num_children; i++) {
        const struct json_value *fv = &files_in->children[i];
        const char *path = fv && fv->type == JSON_STR ? json_get_str(fv) : "";
        char full[PATH_MAX];
        struct stat st;
        bool exists;

        if (cwd && cwd[0])
            (void)snprintf(full, sizeof(full), "%s/%s", cwd, path ? path : "");
        else
            (void)snprintf(full, sizeof(full), "%s", path ? path : "");
        exists = stat(full, &st) == 0;

        json_set_object(&row);
        (void)json_push_kv_str(&row, "path", path ? path : "");
        (void)json_push_kv_bool(&row, "exists", exists);
        (void)json_push_back(out, &row);
    }

    json_free(&row);
}

/* ── next actions ────────────────────────────────────────────────────────── */

static void dvt_build_next(const char *situation, struct json_value *out)
{
    struct json_value item;
    json_init(&item);
    json_set_array(out);

    json_set_str(&item, "make lint-fast");
    (void)json_push_back(out, &item);

    if (strcmp(situation, "shared_checkout_lane") == 0) {
        json_set_str(&item, "commit on your lane branch; do not push");
        (void)json_push_back(out, &item);
    }

    json_free(&item);
}

void zcl_native_handle_dev_agent_start(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *cwd = NULL;
    const char *base_ref = "origin/main";
    const struct json_value *files_in = NULL;
    char situation_id[64];

    if (!reply)
        return;

    if (request && request->input) {
        const struct json_value *v;
        v = json_get(request->input, "cwd");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            cwd = json_get_str(v);
        v = json_get(request->input, "base");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            base_ref = json_get_str(v);
        v = json_get(request->input, "files");
        if (v && v->type == JSON_ARR)
            files_in = v;
    }

    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF);

    struct json_value situation_obj;
    json_init(&situation_obj);
    if (!dvt_build_situation(cwd, &situation_obj, reply, situation_id,
                             sizeof(situation_id))) {
        json_free(&situation_obj);
        return;
    }

    struct json_value rules_arr;
    json_init(&rules_arr);
    dvt_build_rules(situation_id, &rules_arr);

    struct json_value base_obj;
    json_init(&base_obj);
    (void)dvt_build_base(cwd, base_ref, &base_obj);

    struct json_value worktree_obj;
    json_init(&worktree_obj);
    if (!dvt_build_worktree(cwd, &worktree_obj, reply)) {
        json_free(&situation_obj);
        json_free(&rules_arr);
        json_free(&base_obj);
        json_free(&worktree_obj);
        return;
    }

    struct json_value files_arr;
    json_init(&files_arr);
    dvt_build_files(cwd, files_in, &files_arr);

    struct json_value next_arr;
    json_init(&next_arr);
    dvt_build_next(situation_id, &next_arr);

    (void)json_push_kv(&reply->data, "situation", &situation_obj);
    (void)json_push_kv(&reply->data, "rules", &rules_arr);
    (void)json_push_kv(&reply->data, "base", &base_obj);
    (void)json_push_kv(&reply->data, "worktree", &worktree_obj);
    (void)json_push_kv(&reply->data, "files", &files_arr);
    (void)json_push_kv(&reply->data, "next", &next_arr);

    json_free(&situation_obj);
    json_free(&rules_arr);
    json_free(&base_obj);
    json_free(&worktree_obj);
    json_free(&files_arr);
    json_free(&next_arr);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
