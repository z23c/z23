/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.situation — decide whether this directory is a
 *          standalone clone or one linked worktree among several, and report
 *          the exact Git facts the verdict was made from.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Every rule an agent follows in a Z23 checkout branches on this one
 * fact, and an agent that guesses wrong pushes from a lane worktree or opens
 * a side branch on a standalone clone. The test is one line of shell that
 * nobody remembers, so it becomes a command.
 *
 * INPUT (zcl.agent_situation_input.v1)
 *   cwd    optional string. Directory to run Git in. Default: the process
 *          working directory.
 *
 * OUTPUT (zcl.agent_situation.v1) on ok=true
 *   leaf             "dev.agent.situation"
 *   situation        "standalone" | "shared_checkout_lane"
 *   git_dir          `git rev-parse --git-dir`, exactly as Git prints it
 *   git_common_dir   `git rev-parse --git-common-dir`, exactly as Git prints it
 *   worktree         `git rev-parse --show-toplevel`
 *   branch           `git rev-parse --abbrev-ref HEAD`, or "" when HEAD is
 *                    detached (Git prints "HEAD" there; report "" instead)
 *   head             `git rev-parse HEAD`, 40 lowercase hex characters
 *   test             the ZCL_AGENT_SITUATION test_prose of the ANSWERED
 *                    situation, verbatim from engine/composition/agent_rules.def
 *
 * RULE. situation is "standalone" when git_dir and git_common_dir are the
 * same path and "shared_checkout_lane" otherwise. Compare what Git printed:
 * a linked worktree answers a path under <common>/worktrees/<name>, so the
 * two strings differ. Trailing newlines from Git are stripped before
 * anything is compared or reported.
 *
 * FAILURE. Any Git invocation that does not exit 0 is ok=false, status
 * "GIT_FAILED", with a message naming the failing argv (the whole command
 * line, so the reader can rerun it). Nothing else in this file may report
 * a Git failure as a situation.
 *
 * PROCESS RULE. Run Git only through zcl_spawn_capture() from util/spawn.h.
 * popen(), system() and a shell command string are forbidden and gated.
 *
 * Implement this file only; the test
 * tests/harness/src/test_devagent_situation.c is the acceptance bar and must
 * not be edited.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVS_LEAF "dev.agent.situation"

/* Bounded capture for one rev-parse answer: a single path or a single hex
 * object name per invocation, far below this cap in any real checkout. */
#define DVS_OUT_CAP 4096
/* The joined argv a failure carries: "git", "-C", <dir>, plus rev-parse words. */
#define DVS_LINE_CAP (DVS_OUT_CAP + 128)

/* The shell test each verdict carries, so a reader can rerun the decision
 * instead of trusting the word — the TRUE/FALSE form of the rule above, kept
 * byte-identical with the ZCL_AGENT_SITUATION test_prose in
 * engine/composition/agent_rules.def. The .def is carried inline rather than
 * read at run time because the input names the directory under inspection,
 * which is not necessarily this checkout, so engine/composition/ is not
 * guaranteed to be reachable from here. */
#define DVS_PROSE_STANDALONE \
    "test \"$(git rev-parse --git-dir)\" = \"$(git rev-parse --git-common-dir)\" && echo TRUE"
#define DVS_PROSE_LANE \
    "test \"$(git rev-parse --git-dir)\" = \"$(git rev-parse --git-common-dir)\" || echo FALSE"

/* Strip trailing newlines (and CRs from CRLF) before anything is compared or
 * reported, as the contract requires. */
static void dvs_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

/* Join an argv into one human-rerunnable line. Truncation is acceptable here:
 * the line is a diagnostic, never re-executed. */
static void dvs_join_argv(const char *const argv[], char *line, size_t cap)
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

/* Run one git command through the only allowed process rail. `out` receives
 * raw stdout, bounded by cap. `line` always receives the full space-joined
 * argv, so a failure can name exactly what to rerun. Returns the spawn
 * result: 0 on success, -1 on a launch failure, else the child's status. */
static int dvs_git(const char *dir, const char *const args[],
                   char *out, size_t cap, char *line, size_t linecap)
{
    const char *argv[12];
    size_t n = 0;

    argv[n++] = "git";
    /* No cwd given means no -C: Git then answers in this process's working
     * directory, which is exactly the contract's stated default, with no
     * getcwd() copy needed. */
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

    dvs_join_argv(argv, line, linecap);
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, 30000);
}

/* FAILURE (contract): the one way a Git failure may leave this file. The
 * message and next_action name the whole command line, so the reader can
 * rerun it and see Git's own diagnostic, which we do not capture. */
static void dvs_git_failed(struct zcl_command_reply *reply, const char *line,
                           int rc)
{
    char msg[DVS_LINE_CAP + 64];
    (void)snprintf(msg, sizeof(msg),
                   "git invocation failed (exit status %d): %s", rc, line);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "spawn",
                           false, false, msg,
                           "tools/command/native_devagent_situation.c");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "rerun: %s", line);
}

void zcl_native_handle_dev_agent_situation(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const argv_git_dir[] = {"rev-parse", "--git-dir", NULL};
    static const char *const argv_git_common_dir[] = {"rev-parse",
                                                      "--git-common-dir", NULL};
    static const char *const argv_worktree[] = {"rev-parse", "--show-toplevel",
                                                NULL};
    static const char *const argv_branch[] = {"rev-parse", "--abbrev-ref",
                                              "HEAD", NULL};
    static const char *const argv_head[] = {"rev-parse", "HEAD", NULL};

    char git_dir[DVS_OUT_CAP], git_common_dir[DVS_OUT_CAP];
    char worktree[DVS_OUT_CAP], branch[DVS_OUT_CAP], head[DVS_OUT_CAP];
    char line[DVS_LINE_CAP];
    const char *cwd = NULL;
    const char *situation, *prose, *branch_reported;
    bool standalone;
    int rc;

    if (!reply)
        return;

    /* INPUT (zcl.agent_situation_input.v1): one optional string key, cwd.
     * Absent or empty means the process working directory (handled by
     * omitting -C in dvs_git). */
    if (request && request->input) {
        const struct json_value *v = json_get(request->input, "cwd");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            cwd = json_get_str(v);
    }

    (void)json_push_kv_str(&reply->data, "leaf", DVS_LEAF);

    rc = dvs_git(cwd, argv_git_dir, git_dir, sizeof(git_dir),
                 line, sizeof(line));
    if (rc != 0) {
        dvs_git_failed(reply, line, rc);
        return;
    }
    dvs_strip(git_dir);

    rc = dvs_git(cwd, argv_git_common_dir, git_common_dir,
                 sizeof(git_common_dir), line, sizeof(line));
    if (rc != 0) {
        dvs_git_failed(reply, line, rc);
        return;
    }
    dvs_strip(git_common_dir);

    rc = dvs_git(cwd, argv_worktree, worktree, sizeof(worktree),
                 line, sizeof(line));
    if (rc != 0) {
        dvs_git_failed(reply, line, rc);
        return;
    }
    dvs_strip(worktree);

    rc = dvs_git(cwd, argv_branch, branch, sizeof(branch),
                 line, sizeof(line));
    if (rc != 0) {
        dvs_git_failed(reply, line, rc);
        return;
    }
    dvs_strip(branch);

    rc = dvs_git(cwd, argv_head, head, sizeof(head), line, sizeof(line));
    if (rc != 0) {
        dvs_git_failed(reply, line, rc);
        return;
    }
    dvs_strip(head);

    /* RULE: compare what Git printed, nothing smarter. A linked worktree
     * answers a path under <common>/worktrees/<name>, so the two strings
     * differ; a standalone checkout answers the same path twice. */
    standalone = strcmp(git_dir, git_common_dir) == 0;
    situation = standalone ? "standalone" : "shared_checkout_lane";
    prose = standalone ? DVS_PROSE_STANDALONE : DVS_PROSE_LANE;

    /* Detached HEAD: Git prints "HEAD" for --abbrev-ref; report "" instead. */
    branch_reported = strcmp(branch, "HEAD") == 0 ? "" : branch;

    (void)json_push_kv_str(&reply->data, "situation", situation);
    (void)json_push_kv_str(&reply->data, "git_dir", git_dir);
    (void)json_push_kv_str(&reply->data, "git_common_dir", git_common_dir);
    (void)json_push_kv_str(&reply->data, "worktree", worktree);
    (void)json_push_kv_str(&reply->data, "branch", branch_reported);
    (void)json_push_kv_str(&reply->data, "head", head);
    (void)json_push_kv_str(&reply->data, "test", prose);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
