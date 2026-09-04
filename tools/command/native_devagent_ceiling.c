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
 * VERDICT. The verdict word is reported as the data field `status` on BOTH
 * outcomes, so one reader gets it the same way either way.
 *   ok=true and status "WITHIN_CEILING" only when EVERY changed file is
 *   requested, no file is a rewrite, and no file is over_ceiling.
 *   Otherwise ok=false with the error code "CEILING_EXCEEDED", the same word
 *   in the data field `status`, and
 *   violations:[{path, reason}] where reason is exactly one of
 *   "unrequested", "rewrite", "over_ceiling". A file that breaks more than
 *   one rule contributes one violation per broken rule, in that order.
 *
 * OUTPUT (zcl.agent_ceiling.v1), on success AND on CEILING_EXCEEDED
 *   leaf     "dev.agent.ceiling"
 *   status   "WITHIN_CEILING" or "CEILING_EXCEEDED"
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

#define DVL_OUT_CAP 262144
#define DVL_LINE_CAP (DVL_OUT_CAP + 128)
#define DVL_TIMEOUT_MS 30000
#define DVL_MAX_FILES 4096

static void dvl_join_argv(const char *const argv[], char *line, size_t cap)
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
 * receives the joined argv, so a failure names exactly what to rerun.
 * Returns the spawn result: 0 on success, else non-zero (never treated as a
 * hard failure by the callers that expect a non-zero exit as data). */
static int dvl_git(const char *dir, const char *const args[], char *out,
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

    dvl_join_argv(argv, line, linecap);
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, DVL_TIMEOUT_MS);
}

static void dvl_git_failed(struct zcl_command_reply *reply, const char *line,
                           int rc)
{
    char msg[DVL_LINE_CAP + 64];
    (void)snprintf(msg, sizeof(msg),
                   "git invocation failed (exit status %d): %s", rc, line);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "GIT_FAILED", "spawn",
                           false, false, msg,
                           "tools/command/native_devagent_ceiling.c");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "rerun: %s", line);
}

struct dvl_file {
    char path[PATH_MAX];
    long long added;
    long long deleted;
    bool requested;
    bool new_file;
    bool rewrite;
    bool over_ceiling;
};

static struct dvl_file *dvl_find_or_add(struct dvl_file *files, size_t *n,
                                        const char *path)
{
    for (size_t i = 0; i < *n; i++) {
        if (strcmp(files[i].path, path) == 0)
            return &files[i];
    }
    if (*n >= DVL_MAX_FILES)
        return NULL;
    struct dvl_file *f = &files[*n];
    memset(f, 0, sizeof(*f));
    (void)snprintf(f->path, sizeof(f->path), "%s", path);
    (*n)++;
    return f;
}

static bool dvl_path_in_requested(const struct json_value *requested,
                                  const char *path)
{
    if (!requested)
        return false;
    for (size_t i = 0; i < requested->num_children; i++) {
        const struct json_value *v = &requested->children[i];
        if (v->type == JSON_STR && json_get_str(v) &&
            strcmp(json_get_str(v), path) == 0)
            return true;
    }
    return false;
}

/* Count lines in `text` (git show output). A file ending without a final
 * newline still counts its last line. Empty text is 0 lines. */
static long long dvl_count_lines(const char *text, size_t len)
{
    if (len == 0)
        return 0;
    long long lines = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\n')
            lines++;
    }
    if (text[len - 1] != '\n')
        lines++;
    return lines;
}

void zcl_native_handle_dev_agent_ceiling(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *cwd = NULL;
    const char *base = NULL;
    const struct json_value *requested = NULL;
    long long ceiling_lines = 80;
    char out[DVL_OUT_CAP];
    char line[DVL_LINE_CAP];
    int rc;

    if (!reply)
        return;

    (void)json_push_kv_str(&reply->data, "leaf", DVL_LEAF);

    if (request && request->input) {
        const struct json_value *v;
        v = json_get(request->input, "cwd");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            cwd = json_get_str(v);
        v = json_get(request->input, "base");
        if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
            base = json_get_str(v);
        v = json_get(request->input, "requested");
        if (v && v->type == JSON_ARR)
            requested = v;
        v = json_get(request->input, "ceiling_lines");
        if (v && v->type == JSON_INT)
            ceiling_lines = json_get_int(v);
    }

    if (!base || !base[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "base is required and must be a non-empty ref",
                               "input.base missing or empty");
        return;
    }
    if (!requested || requested->num_children == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BAD_INPUT",
                               "validate", false, false,
                               "requested is required and must be a non-empty "
                               "array of path strings",
                               "input.requested missing or empty");
        return;
    }
    if (ceiling_lines <= 0)
        ceiling_lines = 80;

    static struct dvl_file files[DVL_MAX_FILES];
    size_t nfiles = 0;

    /* `git diff --numstat <base>` against the working tree. */
    {
        const char *argv[] = {"diff", "--numstat", base, NULL};
        rc = dvl_git(cwd, argv, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            dvl_git_failed(reply, line, rc);
            return;
        }
        const char *p = out;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len > 0) {
                char rowbuf[PATH_MAX + 64];
                size_t rowlen = len < sizeof(rowbuf) - 1 ? len : sizeof(rowbuf) - 1;
                memcpy(rowbuf, p, rowlen);
                rowbuf[rowlen] = '\0';

                char *tab1 = strchr(rowbuf, '\t');
                if (tab1) {
                    *tab1 = '\0';
                    char *added_s = rowbuf;
                    char *rest = tab1 + 1;
                    char *tab2 = strchr(rest, '\t');
                    if (tab2) {
                        *tab2 = '\0';
                        char *deleted_s = rest;
                        char *path = tab2 + 1;

                        long long added = strcmp(added_s, "-") == 0
                                             ? 0
                                             : strtoll(added_s, NULL, 10);
                        long long deleted = strcmp(deleted_s, "-") == 0
                                              ? 0
                                              : strtoll(deleted_s, NULL, 10);
                        struct dvl_file *f = dvl_find_or_add(files, &nfiles, path);
                        if (f) {
                            f->added = added;
                            f->deleted = deleted;
                        }
                    }
                }
            }
            if (!nl)
                break;
            p = nl + 1;
        }
    }

    /* Untracked files, each counted as a new file whose added is its line
     * count and deleted is 0. */
    {
        const char *argv[] = {"ls-files", "--others", "--exclude-standard",
                              NULL};
        rc = dvl_git(cwd, argv, out, sizeof(out), line, sizeof(line));
        if (rc != 0) {
            dvl_git_failed(reply, line, rc);
            return;
        }
        const char *p = out;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len > 0 && len < PATH_MAX) {
                char path[PATH_MAX];
                memcpy(path, p, len);
                path[len] = '\0';

                char full[PATH_MAX + 8];
                if (cwd && cwd[0])
                    (void)snprintf(full, sizeof(full), "%s/%s", cwd, path);
                else
                    (void)snprintf(full, sizeof(full), "%s", path);

                FILE *f = fopen(full, "rb");
                long long added = 0;
                if (f) {
                    static char buf[1 << 20];
                    size_t got = fread(buf, 1, sizeof(buf), f);
                    added = dvl_count_lines(buf, got);
                    (void)fclose(f);
                }
                struct dvl_file *df = dvl_find_or_add(files, &nfiles, path);
                if (df) {
                    df->added = added;
                    df->deleted = 0;
                }
            }
            if (!nl)
                break;
            p = nl + 1;
        }
    }

    /* Per file: requested, new_file, rewrite, over_ceiling. */
    for (size_t i = 0; i < nfiles; i++) {
        struct dvl_file *f = &files[i];
        f->requested = dvl_path_in_requested(requested, f->path);
        f->over_ceiling = (f->added + f->deleted) > ceiling_lines;

        /* new_file: does `git show <base>:<path>` fail? A failure here is
         * the new_file=true answer, per contract, never a hard GIT_FAILED. */
        char spec[PATH_MAX + 256];
        (void)snprintf(spec, sizeof(spec), "%s:%s", base, f->path);
        const char *argv[] = {"show", spec, NULL};
        char show_line[DVL_LINE_CAP];
        int show_rc = dvl_git(cwd, argv, out, sizeof(out), show_line,
                              sizeof(show_line));
        if (show_rc != 0) {
            f->new_file = true;
            f->rewrite = false;
        } else {
            f->new_file = false;
            long long base_lines = dvl_count_lines(out, strlen(out));
            f->rewrite = f->deleted * 2 > base_lines;
        }
    }

    /* Verdict + violations. */
    struct json_value violations;
    json_init(&violations);
    json_set_array(&violations);
    long long unrequested_n = 0, rewrites_n = 0, over_ceiling_n = 0;

    for (size_t i = 0; i < nfiles; i++) {
        struct dvl_file *f = &files[i];
        struct json_value entry;
        json_init(&entry);

        if (!f->requested) {
            unrequested_n++;
            json_set_object(&entry);
            (void)json_push_kv_str(&entry, "path", f->path);
            (void)json_push_kv_str(&entry, "reason", "unrequested");
            (void)json_push_back(&violations, &entry);
        }
        if (f->rewrite) {
            rewrites_n++;
            json_set_object(&entry);
            (void)json_push_kv_str(&entry, "path", f->path);
            (void)json_push_kv_str(&entry, "reason", "rewrite");
            (void)json_push_back(&violations, &entry);
        }
        if (f->over_ceiling) {
            over_ceiling_n++;
            json_set_object(&entry);
            (void)json_push_kv_str(&entry, "path", f->path);
            (void)json_push_kv_str(&entry, "reason", "over_ceiling");
            (void)json_push_back(&violations, &entry);
        }
        json_free(&entry);
    }

    struct json_value files_arr;
    json_init(&files_arr);
    json_set_array(&files_arr);
    {
        struct json_value row;
        json_init(&row);
        for (size_t i = 0; i < nfiles; i++) {
            struct dvl_file *f = &files[i];
            json_set_object(&row);
            (void)json_push_kv_str(&row, "path", f->path);
            (void)json_push_kv_int(&row, "added", f->added);
            (void)json_push_kv_int(&row, "deleted", f->deleted);
            (void)json_push_kv_bool(&row, "requested", f->requested);
            (void)json_push_kv_bool(&row, "new_file", f->new_file);
            (void)json_push_kv_bool(&row, "rewrite", f->rewrite);
            (void)json_push_kv_bool(&row, "over_ceiling", f->over_ceiling);
            (void)json_push_back(&files_arr, &row);
        }
        json_free(&row);
    }

    struct json_value summary;
    json_init(&summary);
    json_set_object(&summary);
    (void)json_push_kv_int(&summary, "changed", (long long)nfiles);
    (void)json_push_kv_int(&summary, "unrequested", unrequested_n);
    (void)json_push_kv_int(&summary, "rewrites", rewrites_n);
    (void)json_push_kv_int(&summary, "over_ceiling", over_ceiling_n);

    bool within_ceiling =
        unrequested_n == 0 && rewrites_n == 0 && over_ceiling_n == 0;
    const char *status = within_ceiling ? "WITHIN_CEILING" : "CEILING_EXCEEDED";

    (void)json_push_kv_str(&reply->data, "status", status);
    (void)json_push_kv(&reply->data, "files", &files_arr);
    (void)json_push_kv(&reply->data, "summary", &summary);
    (void)json_push_kv_str(&reply->data, "base", base);

    json_free(&files_arr);
    json_free(&summary);

    if (!within_ceiling) {
        (void)json_push_kv(&reply->data, "violations", &violations);
        json_free(&violations);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "CEILING_EXCEEDED",
                               "resolve", false, false,
                               "the diff outgrew the requested scope",
                               "see violations in the reply data");
        return;
    }
    json_free(&violations);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
