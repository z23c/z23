/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.vcs.ports: read-only answer to "what happens if this contributor
 * branch is applied commit by commit onto a base?".
 *
 * For each non-merge commit in merge-base(base,tip)..tip, oldest first (at
 * most `limit`, default 64, hard cap 256), the leaf renders the commit's patch
 * and classifies it against the running result:
 *
 *   EMPTY     no diff outside the generated docs (docs/CAPABILITY_INVENTORY.jsonl,
 *             docs/dev/CODEBASE_MAP.md), which are always excluded
 *   ON_BASE   the patch reverse-applies cleanly: its change is already present
 *   CONFLICT  the patch does not apply; the commit is skipped
 *   APPLIES   the patch applies and is folded into the running result
 *
 * The running result is a private temporary index file (GIT_INDEX_FILE under
 * a mkdtemp directory this leaf creates and removes). The checkout's index,
 * working tree, refs and config are never written: every git call is a plumbing
 * read or a `git apply --cached` against the private index. git runs through
 * zcl_spawn_capture (no shell); inherited GIT_* routing variables are unset by
 * env(1) so a caller's environment cannot redirect the repository. */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/log_macros.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PT_DEFAULT_LIMIT 64
#define PT_HARD_LIMIT 256
#define PT_REV_MAX 200
#define PT_SUBJECT_MAX 80
#define PT_SHA_MAX 72
#define PT_LIST_CAP (1024u * 1024u)
#define PT_SMALL_CAP 4096u
#define PT_GIT_TIMEOUT_MS 60000
#define PT_ARGV_MAX 48
#define PT_ENV_PATH (PATH_MAX + 32)

enum pt_class { PT_APPLIES, PT_ON_BASE, PT_CONFLICT, PT_EMPTY, PT_CLASS_N };

static const char *const k_pt_class_name[PT_CLASS_N] = {
    "APPLIES", "ON_BASE", "CONFLICT", "EMPTY"};

struct pt_err {
    const char *code;
    const char *field;
    enum zcl_command_exit exit_code;
    char why[160];
};

struct pt_run {
    const char *dir;
    char tmp[PATH_MAX];
    char index[PATH_MAX];
    char patch[PATH_MAX];
    char index_env[PT_ENV_PATH];
    bool tmp_made;
    char base[PT_SHA_MAX];
    char tip[PT_SHA_MAX];
    char merge_base[PT_SHA_MAX];
    struct pt_err err;
};

struct pt_table {
    struct json_value rows;
    int64_t counts[PT_CLASS_N];
    size_t total;
    size_t listed;
};

static void pt_set_err(struct pt_run *run, const char *code, const char *field,
                       enum zcl_command_exit exit_code, const char *why)
{
    run->err.code = code;
    run->err.field = field;
    run->err.exit_code = exit_code;
    (void)snprintf(run->err.why, sizeof(run->err.why), "%s", why);
}

/* Record a typed refusal on `run` and log it; returns false from the caller. */
#define PT_FAIL(run, code, field, exit_code, why)                            \
    do {                                                                     \
        pt_set_err((run), (code), (field), (exit_code), (why));              \
        LOG_FAIL("dev.vcs.ports", "%s: %s", (code), (why));                 \
    } while (0)

#define PT_INVALID(run, code, field, why) \
    PT_FAIL(run, code, field, ZCL_COMMAND_EXIT_INVALID, why)
#define PT_INTERNAL(run, code, why) \
    PT_FAIL(run, code, "", ZCL_COMMAND_EXIT_INTERNAL, why)

static const char *pt_source_dir(const struct zcl_command_request *request)
{
    const char *env;
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

/* ── git spawn ─────────────────────────────────────────────────────────── */

/* Run `git -C dir <args>` under env(1) with the routing variables removed.
 * with_index points GIT_INDEX_FILE at the private index. Returns the child's
 * exit status or -1 when the launch failed or argv would overflow. */
static int pt_git(const struct pt_run *run, bool with_index,
                  const char *const *args, char *out, size_t cap)
{
    static const char *const head[] = {
        "env", "-u", "GIT_DIR", "-u", "GIT_WORK_TREE", "-u", "GIT_INDEX_FILE",
        "-u", "GIT_EXTERNAL_DIFF", "-u", "GIT_DIFF_OPTS",
        "GIT_OPTIONAL_LOCKS=0"};
    const char *argv[PT_ARGV_MAX];
    size_t n = 0;
    char sink[2];
    for (size_t i = 0; i < sizeof(head) / sizeof(head[0]); i++)
        argv[n++] = head[i];
    if (with_index)
        argv[n++] = run->index_env;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = run->dir;
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > PT_ARGV_MAX)
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    if (out && cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                             PT_GIT_TIMEOUT_MS);
}

static void pt_trim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = '\0';
}

/* ── input ─────────────────────────────────────────────────────────────── */

static bool pt_rev_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') || c == '.' || c == '_' || c == '/' ||
           c == '-';
}

static bool pt_rev_valid(const char *s)
{
    if (!s[0] || s[0] == '-' || strlen(s) > PT_REV_MAX)
        return false;
    for (; *s; s++)
        if (!pt_rev_char(*s))
            return false;
    return true;
}

static bool pt_rev_input(struct pt_run *run, const struct json_value *in,
                         const char *key, const char *missing_code,
                         const char **out)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s || !s[0])
        PT_INVALID(run, missing_code, key, "required revision is missing");
    if (!pt_rev_valid(s))
        PT_INVALID(run, "INVALID_REV", key,
                   "revision must match [0-9A-Za-z._/-] and not start with '-'");
    *out = s;
    return true;
}

static bool pt_limit_input(struct pt_run *run, const struct json_value *in,
                           size_t *limit)
{
    const struct json_value *v = in ? json_get(in, "limit") : NULL;
    *limit = PT_DEFAULT_LIMIT;
    if (!v)
        return true;
    if (v->type != JSON_INT || json_get_int(v) < 1)
        PT_INVALID(run, "INVALID_LIMIT", "limit",
                   "limit must be a positive integer");
    if (json_get_int(v) > PT_HARD_LIMIT)
        PT_INVALID(run, "LIMIT_TOO_LARGE", "limit",
                   "limit exceeds the hard cap of 256");
    *limit = (size_t)json_get_int(v);
    return true;
}

/* ── revision resolution ───────────────────────────────────────────────── */

static bool pt_resolve(struct pt_run *run, const char *rev, const char *field,
                       char out[PT_SHA_MAX])
{
    char spec[PT_REV_MAX + 16];
    char buf[PT_SMALL_CAP];
    const char *args[] = {"rev-parse", "--verify", "--quiet", spec, NULL};
    (void)snprintf(spec, sizeof(spec), "%s^{commit}", rev);
    if (pt_git(run, false, args, buf, sizeof(buf)) != 0)
        PT_INVALID(run, "UNRESOLVABLE_REV", field,
                   "revision does not name a commit in this repository");
    pt_trim(buf);
    if (!buf[0] || strlen(buf) >= PT_SHA_MAX)
        PT_INTERNAL(run, "REV_PARSE_FAILED", "git rev-parse returned no id");
    (void)snprintf(out, PT_SHA_MAX, "%s", buf);
    return true;
}

static bool pt_resolve_all(struct pt_run *run, const char *base,
                           const char *tip)
{
    char buf[PT_SMALL_CAP];
    const char *args[] = {"merge-base", run->base, run->tip, NULL};
    if (!pt_resolve(run, base, "base", run->base) ||
        !pt_resolve(run, tip, "tip", run->tip))
        return false;
    if (pt_git(run, false, args, buf, sizeof(buf)) != 0)
        PT_INVALID(run, "NO_MERGE_BASE", "tip",
                   "base and tip share no merge base");
    pt_trim(buf);
    if (!buf[0] || strlen(buf) >= PT_SHA_MAX)
        PT_INTERNAL(run, "MERGE_BASE_FAILED", "git merge-base returned no id");
    (void)snprintf(run->merge_base, sizeof(run->merge_base), "%s", buf);
    return true;
}

/* ── temporary index ───────────────────────────────────────────────────── */

static bool pt_tmp_make(struct pt_run *run)
{
    char gitdir[PATH_MAX];
    const char *args[] = {"rev-parse", "--absolute-git-dir", NULL};
    int n;
    /* The private dir lives inside the repository's own git directory: always
     * writable for a checkout this leaf can read, never part of the work tree. */
    if (pt_git(run, false, args, gitdir, sizeof(gitdir)) != 0)
        PT_INTERNAL(run, "TMPDIR_FAILED", "could not locate the git directory");
    pt_trim(gitdir);
    n = snprintf(run->tmp, sizeof(run->tmp), "%s/z23-port-table-XXXXXX", gitdir);
    if (n < 0 || (size_t)n >= sizeof(run->tmp) || !mkdtemp(run->tmp))
        PT_INTERNAL(run, "TMPDIR_FAILED", "could not create a private temp dir");
    run->tmp_made = true;
    n = snprintf(run->index, sizeof(run->index), "%s/index", run->tmp);
    if (n < 0 || (size_t)n >= sizeof(run->index))
        PT_INTERNAL(run, "TMPDIR_FAILED", "temp index path too long");
    n = snprintf(run->patch, sizeof(run->patch), "%s/patch", run->tmp);
    if (n < 0 || (size_t)n >= sizeof(run->patch))
        PT_INTERNAL(run, "TMPDIR_FAILED", "temp patch path too long");
    (void)snprintf(run->index_env, sizeof(run->index_env),
                   "GIT_INDEX_FILE=%s", run->index);
    return true;
}

static void pt_tmp_drop(struct pt_run *run)
{
    char lock[PATH_MAX + 16];
    if (!run->tmp_made)
        return;
    (void)snprintf(lock, sizeof(lock), "%s.lock", run->index);
    (void)unlink(lock);
    (void)unlink(run->index);
    (void)unlink(run->patch);
    (void)snprintf(lock, sizeof(lock), "%s/index.save", run->tmp);
    (void)unlink(lock);
    (void)rmdir(run->tmp);
    run->tmp_made = false;
}

static bool pt_seed_index(struct pt_run *run)
{
    const char *args[] = {"read-tree", run->base, NULL};
    if (pt_git(run, true, args, NULL, 0) != 0)
        PT_INTERNAL(run, "READ_TREE_FAILED",
                    "could not load the base tree into the temp index");
    return true;
}

/* ── per-commit classification ─────────────────────────────────────────── */

/* Files changed by `sha` outside the always-excluded generated docs, from
 * the leading integer of --shortstat ("" means none). */
static bool pt_count_files(struct pt_run *run, const char *sha, int *files)
{
    char buf[PT_SMALL_CAP];
    const char *args[] = {
        "diff-tree", "--root", "--no-commit-id", "-r", "--no-renames",
        "--shortstat", sha, "--", ":/",
        ":(top,exclude)docs/CAPABILITY_INVENTORY.jsonl",
        ":(top,exclude)docs/dev/CODEBASE_MAP.md", NULL};
    const char *p = buf;
    if (pt_git(run, false, args, buf, sizeof(buf)) != 0)
        PT_INTERNAL(run, "DIFF_FAILED", "git diff-tree --shortstat failed");
    while (*p == ' ')
        p++;
    *files = (*p >= '0' && *p <= '9') ? atoi(p) : 0;
    return true;
}

static bool pt_write_patch(struct pt_run *run, const char *sha)
{
    char out_opt[PATH_MAX + 16];
    const char *args[] = {
        "diff-tree", "--root", "--no-commit-id", "-r", "-p", "--binary",
        "--full-index", "--no-renames", "--no-ext-diff", "--no-textconv",
        "--no-color", "--src-prefix=a/", "--dst-prefix=b/", out_opt, sha, "--",
        ":/", ":(top,exclude)docs/CAPABILITY_INVENTORY.jsonl",
        ":(top,exclude)docs/dev/CODEBASE_MAP.md", NULL};
    (void)snprintf(out_opt, sizeof(out_opt), "--output=%s", run->patch);
    if (pt_git(run, false, args, NULL, 0) != 0)
        PT_INTERNAL(run, "DIFF_FAILED", "git diff-tree could not render a patch");
    return true;
}

/* True when `git apply --cached <mode...> patch` exits 0 on the temp index. */
static bool pt_apply(const struct pt_run *run, bool reverse, bool check_only)
{
    const char *args[10];
    size_t n = 0;
    args[n++] = "apply";
    args[n++] = "--cached";
    args[n++] = "--whitespace=nowarn";
    if (reverse)
        args[n++] = "--reverse";
    if (check_only)
        args[n++] = "--check";
    args[n++] = run->patch;
    args[n] = NULL;
    return pt_git(run, true, args, NULL, 0) == 0;
}

/* The "already present" test: the commit's change reverse-applies cleanly. */
static bool pt_already_present(const struct pt_run *run)
{
    return pt_apply(run, true, true);
}

/* cp(1) through the no-shell spawner: save or restore the temp index. */
static bool pt_cp(const char *from, const char *to)
{
    const char *argv[] = {"cp", "-f", from, to, NULL};
    char sink[2];
    return zcl_spawn_capture(argv, sink, sizeof(sink), PT_GIT_TIMEOUT_MS) == 0;
}

/* Forward apply with a three-way fallback. A conflicting 3-way leaves
 * unmerged entries in the temp index, so the pre-commit copy is restored. */
static bool pt_apply_forward(struct pt_run *run, bool *applied)
{
    char save[PATH_MAX + 16];
    const char *args[] = {"apply", "--cached", "--3way", "--whitespace=nowarn",
                          run->patch, NULL};
    (void)snprintf(save, sizeof(save), "%s/index.save", run->tmp);
    if (!pt_cp(run->index, save))
        PT_INTERNAL(run, "INDEX_SAVE_FAILED", "could not save the temp index");
    *applied = pt_git(run, true, args, NULL, 0) == 0;
    if (!*applied && !pt_cp(save, run->index))
        PT_INTERNAL(run, "INDEX_RESTORE_FAILED",
                    "could not restore the temp index after a conflict");
    (void)unlink(save);
    return true;
}

static bool pt_classify(struct pt_run *run, const char *sha,
                        enum pt_class *cls, int *files)
{
    if (!pt_count_files(run, sha, files))
        return false;
    if (*files == 0) {
        *cls = PT_EMPTY;
        return true;
    }
    if (!pt_write_patch(run, sha))
        return false;
    if (pt_already_present(run)) {
        *cls = PT_ON_BASE;
        return true;
    }
    bool applied = false;
    if (!pt_apply_forward(run, &applied))
        return false;
    *cls = applied ? PT_APPLIES : PT_CONFLICT;
    return true;
}

/* ── rows ──────────────────────────────────────────────────────────────── */

/* Copy at most PT_SUBJECT_MAX bytes of `subject` without splitting a UTF-8
 * sequence. */
static void pt_bound_subject(const char *subject, char out[PT_SUBJECT_MAX + 1])
{
    size_t len = strlen(subject);
    if (len > PT_SUBJECT_MAX) {
        len = PT_SUBJECT_MAX;
        while (len > 0 && ((unsigned char)subject[len] & 0xC0) == 0x80)
            len--;
    }
    memcpy(out, subject, len);
    out[len] = '\0';
}

static bool pt_emit_row(struct pt_run *run, struct pt_table *t,
                        const char *sha, const char *subject,
                        enum pt_class cls, int files)
{
    char bounded[PT_SUBJECT_MAX + 1];
    struct json_value row;
    bool ok;
    pt_bound_subject(subject, bounded);
    json_init(&row);
    json_set_object(&row);
    ok = json_push_kv_str(&row, "sha", sha) &&
         json_push_kv_str(&row, "subject", bounded) &&
         json_push_kv_str(&row, "class", k_pt_class_name[cls]) &&
         json_push_kv_int(&row, "files_changed", files) &&
         json_push_back(&t->rows, &row);
    json_free(&row);
    if (!ok)
        PT_INTERNAL(run, "ROW_ALLOCATION_FAILED", "could not build a table row");
    return true;
}

/* One "sha<TAB>subject" line (already NUL-terminated). */
static bool pt_one(struct pt_run *run, struct pt_table *t, char *line)
{
    char *tab = strchr(line, '\t');
    enum pt_class cls = PT_EMPTY;
    int files = 0;
    if (!tab)
        PT_INTERNAL(run, "LOG_PARSE_FAILED", "commit list line has no subject");
    *tab = '\0';
    if (!pt_classify(run, line, &cls, &files))
        return false;
    t->counts[cls]++;
    return pt_emit_row(run, t, line, tab + 1, cls, files);
}

static bool pt_walk(struct pt_run *run, struct pt_table *t, char *list,
                    size_t limit)
{
    char *line = list;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (t->listed < limit) {
            if (!pt_one(run, t, line))
                return false;
            t->listed++;
        }
        t->total++;
        if (!nl)
            break;
        line = nl + 1;
    }
    return true;
}

static bool pt_range_list(struct pt_run *run, char *list)
{
    char range[2 * PT_SHA_MAX + 8];
    const char *args[] = {"log", "--reverse", "--no-merges",
                          "--no-show-signature", "--format=%H%x09%s", range,
                          NULL};
    (void)snprintf(range, sizeof(range), "%s..%s", run->merge_base, run->tip);
    if (pt_git(run, false, args, list, PT_LIST_CAP) != 0)
        PT_INTERNAL(run, "LOG_FAILED", "git log could not list the range");
    if (strlen(list) + 1 >= PT_LIST_CAP)
        PT_INVALID(run, "RANGE_TOO_LARGE", "tip",
                   "the commit range is larger than this leaf will list");
    return true;
}

/* ── reply ─────────────────────────────────────────────────────────────── */

static bool pt_counts_object(struct json_value *out, const struct pt_table *t)
{
    struct json_value counts;
    bool ok = true;
    json_init(&counts);
    json_set_object(&counts);
    for (int i = 0; ok && i < PT_CLASS_N; i++)
        ok = json_push_kv_int(&counts, k_pt_class_name[i], t->counts[i]);
    ok = ok && json_push_kv(out, "counts", &counts);
    json_free(&counts);
    return ok;
}

static bool pt_fill_reply(struct pt_run *run, struct zcl_command_reply *reply,
                          const struct pt_table *t, size_t limit)
{
    struct json_value *d = &reply->data;
    json_free(d);
    json_init(d);
    json_set_object(d);
    if (!json_push_kv_str(d, "base", run->base) ||
        !json_push_kv_str(d, "tip", run->tip) ||
        !json_push_kv_str(d, "merge_base", run->merge_base) ||
        !json_push_kv_int(d, "total", (int64_t)t->total) ||
        !json_push_kv_int(d, "limit", (int64_t)limit) ||
        !json_push_kv_bool(d, "truncated", t->total > t->listed) ||
        !pt_counts_object(d, t) || !json_push_kv(d, "rows", &t->rows))
        PT_INTERNAL(run, "REPLY_ALLOCATION_FAILED", "could not build the reply");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    return true;
}

static bool pt_build(struct pt_run *run, struct zcl_command_reply *reply,
                     size_t limit)
{
    struct pt_table t;
    char *list = zcl_malloc(PT_LIST_CAP, "dev.vcs.ports range list");
    bool ok;
    memset(&t, 0, sizeof(t));
    json_init(&t.rows);
    json_set_array(&t.rows);
    if (!list)
        PT_INTERNAL(run, "LIST_ALLOCATION_FAILED", "could not allocate the list");
    ok = pt_range_list(run, list) && pt_tmp_make(run) && pt_seed_index(run) &&
         pt_walk(run, &t, list, limit) && pt_fill_reply(run, reply, &t, limit);
    free(list);
    json_free(&t.rows);
    return ok;
}

static bool pt_execute(struct pt_run *run,
                       const struct zcl_command_request *request,
                       struct zcl_command_reply *reply)
{
    const char *base = NULL;
    const char *tip = NULL;
    size_t limit = 0;
    bool ok;
    if (!pt_rev_input(run, request->input, "base", "MISSING_BASE", &base) ||
        !pt_rev_input(run, request->input, "tip", "MISSING_TIP", &tip) ||
        !pt_limit_input(run, request->input, &limit) ||
        !pt_resolve_all(run, base, tip))
        return false;
    ok = pt_build(run, reply, limit);
    pt_tmp_drop(run);
    return ok;
}

void zcl_native_handle_dev_port_table(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    struct pt_run run;
    memset(&run, 0, sizeof(run));
    run.dir = pt_source_dir(request);
    if (pt_execute(&run, request, reply))
        return;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           run.err.exit_code, run.err.code, "port-table",
                           false, false, run.err.why, run.err.field);
}
