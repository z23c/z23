/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.train.* — a native C23 leaf that replaces the interim
 *          ~/.local/state/zclassic23/scratch/northstar/batch_build.sh shell
 *          train builder.
 *
 * dev train build stacks lanes onto main without waiting on lint: it fetches
 * origin, opens a detached worktree at <checkout-parent>/z23-stack<name>,
 * cherry-picks each source's origin/main..HEAD commits oldest-first
 * (skipping doc-regen-only commits by subject), regenerates the generated
 * docs once, and returns — it never runs lint-fast itself. dev train check
 * is the one deliberate synchronous wait. dev train status reads every
 * stack worktree. dev train drop removes one.
 *
 * PROCESS RULE. Git runs only through zcl_spawn_capture() (util/spawn.h).
 * `make` targets run through zcl_devloop_process_run() (tools/dev/devloop.h),
 * the same primitive dev.ff already uses for `make ff`. No popen(),
 * system(), or shell command string appears in this file.
 */

#include "command/native_command.h"

#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVT_LEAF_BUILD "dev.train.build"
#define DVT_LEAF_CHECK "dev.train.check"
#define DVT_LEAF_STATUS "dev.train.status"
#define DVT_LEAF_DROP "dev.train.drop"

/* One captured git answer (a log, a status listing, a rev-list count) is
 * bounded far below this in any real checkout; matches the devloop process
 * output ceiling so the two subprocess rails share one budget. */
#define DVT_OUT_CAP ZCL_DEVLOOP_OUTPUT_MAX
#define DVT_GIT_TIMEOUT_MS 60000
#define DVT_FETCH_TIMEOUT_MS 180000
#define DVT_MAKE_TIMEOUT_MS 300000
#define DVT_CHECK_DEFAULT_TIMEOUT_MS 900000
#define DVT_CHECK_MIN_TIMEOUT_MS 30000
#define DVT_CHECK_MAX_TIMEOUT_MS 3600000

/* ── small shared helpers ─────────────────────────────────────────────── */

static const char *dvt_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

static void dvt_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

/* Parent directory of `path`, portable across '/'  and '\\' separators.
 * "." when path carries no separator (a bare relative name). */
static void dvt_dirname(const char *path, char *out, size_t cap)
{
    size_t len = strlen(path);
    size_t cut = len;
    while (cut > 0 && path[cut - 1] != '/' && path[cut - 1] != '\\')
        cut--;
    if (cut == 0) {
        (void)snprintf(out, cap, "%s", ".");
        return;
    }
    /* Drop exactly one trailing separator, but keep a bare root ("/"). */
    size_t body = cut - 1;
    if (body == 0)
        body = 1;
    if (body >= cap)
        body = cap - 1;
    memcpy(out, path, body);
    out[body] = '\0';
}

/* Only [A-Za-z0-9_.-], 1..63 bytes, no leading '-', no "..": this token is
 * concatenated straight into a sibling directory name, so it must never be
 * able to name a path outside <checkout-parent>/z23-stack<name>. */
static bool dvt_valid_name(const char *name)
{
    if (!name || !name[0] || name[0] == '-')
        return false;
    size_t len = strlen(name);
    if (len > 63)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok)
            return false;
    }
    return strstr(name, "..") == NULL;
}

static void dvt_stack_path(const char *root, const char *name, char *out,
                           size_t cap)
{
    char parent[PATH_MAX];
    dvt_dirname(root, parent, sizeof(parent));
    (void)snprintf(out, cap, "%s/z23-stack%s", parent, name);
}

/* Doc-regen-only commit subjects, skipped during cherry-pick because the
 * build regenerates the same docs once at the end. */
static bool dvt_skip_subject(const char *subject)
{
    static const char *const prefixes[] = {
        "Regenerate the generated docs",
        "Regenerate the capability inventory",
        "Count what the stacked lanes added",
        "Regenerate the catalogs",
        NULL,
    };
    for (size_t i = 0; prefixes[i]; i++) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(subject, prefixes[i], n) == 0)
            return true;
    }
    return false;
}

/* Run one git command. `dir` is passed as `-C <dir>` (omitted when empty).
 * `out`/`out_cap` may be NULL/0 when the caller only wants the exit status.
 * Returns the exit status (0 on success), matching zcl_spawn_capture(). */
static int dvt_git(const char *dir, const char *const args[], char *out,
                   size_t out_cap, int timeout_ms)
{
    const char *argv[20];
    size_t n = 0;
    static char scratch[1];
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (out && out_cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out ? out : scratch,
                             out ? out_cap : sizeof(scratch), timeout_ms);
}

static bool dvt_is_directory(const char *path)
{
    return platform_directory_probe_real(path) ==
           PLATFORM_DIRECTORY_PROBE_OK;
}

/* Gather the conflicted paths (git status --porcelain XY codes with either
 * side unmerged) from `stack_dir` into a fresh JSON array. Caller owns and
 * must json_free() `out`. */
static void dvt_conflict_paths(const char *stack_dir, struct json_value *out)
{
    static const char *const args[] = {"status", "--porcelain", NULL};
    char buf[DVT_OUT_CAP];
    json_init(out);
    json_set_array(out);
    if (dvt_git(stack_dir, args, buf, sizeof(buf), DVT_GIT_TIMEOUT_MS) != 0 &&
        buf[0] == '\0')
        return;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (strlen(line) > 3) {
            char x = line[0], y = line[1];
            bool conflict = x == 'U' || y == 'U' ||
                            (x == 'A' && y == 'A') || (x == 'D' && y == 'D');
            if (conflict) {
                struct json_value item;
                json_init(&item);
                json_set_str(&item, line + 3);
                (void)json_push_back(out, &item);
                json_free(&item);
            }
        }
        line = nl ? nl + 1 : NULL;
    }
}

/* ── build ────────────────────────────────────────────────────────────── */

static void dvt_fail(struct zcl_command_reply *reply, enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           false, message, evidence);
}

void zcl_native_handle_dev_train_build(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)request;
    dvt_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "DEV_BUILD_REQUIRED", "dispatch",
            "stacked-lane construction requires a dev build",
            "make dev-bin, or z23-dev dev train build");
    return;
#else
    const char *name =
        request && request->input ? json_get_str(json_get(request->input, "name")) : NULL;
    const char *sources_csv =
        request && request->input ? json_get_str(json_get(request->input, "sources")) : NULL;
    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF_BUILD);
    if (!dvt_valid_name(name)) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_NAME", "validate",
                "name must be 1-63 bytes of [A-Za-z0-9_.-], not starting "
                "with '-', without \"..\"",
                name ? name : "");
        return;
    }
    if (!sources_csv || !sources_csv[0]) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "NO_SOURCES", "validate",
                "at least one --source is required", "");
        return;
    }
    (void)json_push_kv_str(&reply->data, "name", name);

    const char *root = dvt_source_root(request);
    char stack_dir[PATH_MAX];
    dvt_stack_path(root, name, stack_dir, sizeof(stack_dir));
    (void)json_push_kv_str(&reply->data, "path", stack_dir);

    if (dvt_is_directory(stack_dir)) {
        char next[PATH_MAX + 64];
        (void)snprintf(next, sizeof(next), "dev train drop --name %s", name);
        (void)json_push_kv_str(&reply->data, "next", next);
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "STACK_EXISTS", "prepare", "stack worktree already exists",
                stack_dir);
        return;
    }

    static const char *const fetch_args[] = {"fetch", "-q", "origin", NULL};
    if (dvt_git(root, fetch_args, NULL, 0, DVT_FETCH_TIMEOUT_MS) != 0) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "GIT_FAILED", "fetch", "git fetch origin failed", root);
        return;
    }

    const char *worktree_add_args[] = {"worktree", "add", "--detach",
                                       stack_dir, "origin/main", NULL};
    if (dvt_git(root, worktree_add_args, NULL, 0, DVT_GIT_TIMEOUT_MS) != 0) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "GIT_FAILED", "worktree_add",
                "git worktree add --detach failed", stack_dir);
        return;
    }

    static const char *const submodule_args[] = {"submodule", "-q", "update",
                                                 "--init", NULL};
    if (dvt_git(stack_dir, submodule_args, NULL, 0, DVT_FETCH_TIMEOUT_MS) != 0) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "GIT_FAILED", "submodule_init",
                "git submodule update --init failed; the worktree is left "
                "in place for inspection",
                stack_dir);
        return;
    }

    const char *prime_argv[] = {"make", "-s", "--no-print-directory",
                                "worktree-prime", NULL};
    struct zcl_devloop_process_result prime_result;
    if (!zcl_devloop_process_run(stack_dir, prime_argv, DVT_MAKE_TIMEOUT_MS,
                                 &prime_result) ||
        prime_result.exit_code != 0 || prime_result.timed_out) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "PRIME_FAILED", "worktree_prime",
                "make worktree-prime failed; the worktree is left in place "
                "for inspection",
                stack_dir);
        return;
    }

    struct json_value picked, skipped, warnings;
    json_init(&picked); json_set_array(&picked);
    json_init(&skipped); json_set_array(&skipped);
    json_init(&warnings); json_set_array(&warnings);

    /* sources_csv is newline-joined (the CLI joins repeated --source flags;
     * a raw JSON caller may do the same). Each token is either an existing
     * directory (its own origin/main..HEAD) or a ref name resolved in
     * `root` (its own origin/main..<ref>). */
    char sources_buf[ZCL_COMMAND_MAX_INPUT];
    (void)snprintf(sources_buf, sizeof(sources_buf), "%s", sources_csv);
    char *save = NULL;
    for (char *source = strtok_r(sources_buf, "\n", &save); source;
         source = strtok_r(NULL, "\n", &save)) {
        if (!source[0])
            continue;
        bool source_is_dir = dvt_is_directory(source);
        const char *ref_repo = source_is_dir ? source : root;
        char range[PATH_MAX + 32];
        (void)snprintf(range, sizeof(range), "origin/main..%s",
                      source_is_dir ? "HEAD" : source);
        if (source_is_dir) {
            /* A directory source may be a linked worktree of the SAME
             * repository (the common case: another lane worktree beside
             * this one) or an entirely separate clone. Either way, its
             * commits are not necessarily reachable from stack_dir's object
             * database yet — a linked worktree shares objects already (this
             * fetch is then a fast no-op), a separate clone does not. Fetch
             * its HEAD into stack_dir before cherry-picking anything from
             * it, so `git cherry-pick <sha>` never hits "bad object". */
            const char *fetch_source_args[] = {"fetch", "-q", source, "HEAD",
                                               NULL};
            (void)dvt_git(stack_dir, fetch_source_args, NULL, 0,
                          DVT_FETCH_TIMEOUT_MS);
        }
        const char *log_args[] = {"log", "--reverse",
                                  "--format=%H%x1f%s", range, NULL};
        char log_out[DVT_OUT_CAP];
        if (dvt_git(ref_repo, log_args, log_out, sizeof(log_out),
                    DVT_GIT_TIMEOUT_MS) != 0 || !log_out[0]) {
            struct json_value w;
            json_init(&w);
            char msg[PATH_MAX + 64];
            (void)snprintf(msg, sizeof(msg), "no commits found for %s (%s)",
                          source, range);
            json_set_str(&w, msg);
            (void)json_push_back(&warnings, &w);
            json_free(&w);
            continue;
        }
        char *line_save = NULL;
        for (char *line = strtok_r(log_out, "\n", &line_save); line;
             line = strtok_r(NULL, "\n", &line_save)) {
            char *sep = strchr(line, '\x1f');
            if (!sep)
                continue;
            *sep = '\0';
            const char *sha = line;
            const char *subject = sep + 1;
            if (dvt_skip_subject(subject)) {
                struct json_value item;
                json_init(&item); json_set_object(&item);
                (void)json_push_kv_str(&item, "sha", sha);
                (void)json_push_kv_str(&item, "subject", subject);
                (void)json_push_kv_str(&item, "source", source);
                (void)json_push_back(&skipped, &item);
                json_free(&item);
                continue;
            }
            const char *pick_args[] = {"cherry-pick", sha, NULL};
            int rc = dvt_git(stack_dir, pick_args, NULL, 0, DVT_GIT_TIMEOUT_MS);
            if (rc != 0) {
                struct json_value paths;
                dvt_conflict_paths(stack_dir, &paths);
                (void)json_push_kv_str(&reply->data, "state", "conflict");
                (void)json_push_kv_str(&reply->data, "source", source);
                (void)json_push_kv_str(&reply->data, "sha", sha);
                (void)json_push_kv_str(&reply->data, "subject", subject);
                (void)json_push_kv(&reply->data, "paths", &paths);
                json_free(&paths);
                (void)json_push_kv(&reply->data, "picked", &picked);
                (void)json_push_kv(&reply->data, "skipped", &skipped);
                (void)json_push_kv(&reply->data, "warnings", &warnings);
                json_free(&picked); json_free(&skipped); json_free(&warnings);
                char next[PATH_MAX + 64];
                (void)snprintf(next, sizeof(next),
                              "git -C %s cherry-pick --continue", stack_dir);
                (void)json_push_kv_str(&reply->data, "next", next);
                dvt_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                        ZCL_COMMAND_EXIT_BLOCKED, "CHERRY_PICK_CONFLICT",
                        "cherry_pick",
                        "a real cherry-pick conflict; the stack worktree is "
                        "left mid-cherry-pick",
                        sha);
                return;
            }
            struct json_value item;
            json_init(&item); json_set_object(&item);
            (void)json_push_kv_str(&item, "sha", sha);
            (void)json_push_kv_str(&item, "subject", subject);
            (void)json_push_kv_str(&item, "source", source);
            (void)json_push_back(&picked, &item);
            json_free(&item);
        }
    }

    /* Regenerate the generated docs once, the same targets
     * batch_build.sh used. */
    const char *cap_argv[] = {"make", "-s", "-B", "--no-print-directory",
                              "docs-capability-inventory", NULL};
    const char *api_argv[] = {"make", "-s", "--no-print-directory",
                              "docs-api-reference", NULL};
    struct zcl_devloop_process_result doc_result;
    bool doc_ok =
        zcl_devloop_process_run(stack_dir, cap_argv, DVT_MAKE_TIMEOUT_MS,
                                &doc_result) &&
        doc_result.exit_code == 0 &&
        zcl_devloop_process_run(stack_dir, api_argv, DVT_MAKE_TIMEOUT_MS,
                                &doc_result) &&
        doc_result.exit_code == 0;
    if (!doc_ok) {
        (void)json_push_kv(&reply->data, "picked", &picked);
        (void)json_push_kv(&reply->data, "skipped", &skipped);
        (void)json_push_kv(&reply->data, "warnings", &warnings);
        json_free(&picked); json_free(&skipped); json_free(&warnings);
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "DOC_REGEN_FAILED", "regen_docs",
                "regenerating the generated docs failed", stack_dir);
        return;
    }
    static const char *const diff_args[] = {"diff", "--cached", "--quiet",
                                            NULL};
    static const char *const add_args[] = {"add", "-A", "--", "docs/", NULL};
    (void)dvt_git(stack_dir, add_args, NULL, 0, DVT_GIT_TIMEOUT_MS);
    if (dvt_git(stack_dir, diff_args, NULL, 0, DVT_GIT_TIMEOUT_MS) != 0) {
        static const char *const commit_args[] = {
            "commit", "-q", "-m",
            "Regenerate the generated docs for the stack", NULL};
        (void)dvt_git(stack_dir, commit_args, NULL, 0, DVT_GIT_TIMEOUT_MS);
    }

    static const char *const count_args[] = {"rev-list", "--count",
                                             "origin/main..HEAD", NULL};
    char count_out[64];
    int64_t commits = 0;
    if (dvt_git(stack_dir, count_args, count_out, sizeof(count_out),
                DVT_GIT_TIMEOUT_MS) == 0) {
        dvt_strip(count_out);
        commits = strtoll(count_out, NULL, 10);
    }

    (void)json_push_kv_str(&reply->data, "state", "ok");
    (void)json_push_kv_str(&reply->data, "base", "origin/main");
    (void)json_push_kv_int(&reply->data, "commits", commits);
    (void)json_push_kv(&reply->data, "picked", &picked);
    (void)json_push_kv(&reply->data, "skipped", &skipped);
    (void)json_push_kv(&reply->data, "warnings", &warnings);
    json_free(&picked); json_free(&skipped); json_free(&warnings);
    char next[PATH_MAX + 64];
    (void)snprintf(next, sizeof(next), "dev train check --name %s", name);
    (void)json_push_kv_str(&reply->data, "next", next);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
#endif
}

/* ── check ────────────────────────────────────────────────────────────── */

static void dvt_check_state_path(const char *stack_dir, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/build/train-check.state", stack_dir);
}

static void dvt_check_log_path(const char *stack_dir, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/build/train-check.log", stack_dir);
}

static void dvt_write_check_state(const char *stack_dir, bool ok,
                                  const char *gates_failed_csv,
                                  const char *log_path)
{
    (void)platform_directory_ensure(stack_dir, 0700);
    char build_dir[PATH_MAX];
    (void)snprintf(build_dir, sizeof(build_dir), "%s/build", stack_dir);
    (void)platform_directory_ensure(build_dir, 0700);
    char state_path[PATH_MAX];
    dvt_check_state_path(stack_dir, state_path, sizeof(state_path));
    FILE *f = fopen(state_path, "wb");
    if (!f)
        return;
    (void)fprintf(f, "ok=%d\nlog_path=%s\ngates_failed=%s\n", ok ? 1 : 0,
                 log_path, gates_failed_csv ? gates_failed_csv : "");
    (void)fclose(f);
}

/* Returns true iff a prior check verdict exists on disk. */
static bool dvt_read_check_state(const char *stack_dir, bool *ok,
                                 char *gates_failed_csv, size_t gates_cap,
                                 char *log_path, size_t log_cap)
{
    char state_path[PATH_MAX];
    dvt_check_state_path(stack_dir, state_path, sizeof(state_path));
    FILE *f = fopen(state_path, "rb");
    if (!f)
        return false;
    char line[4096];
    *ok = false;
    if (gates_failed_csv && gates_cap)
        gates_failed_csv[0] = '\0';
    if (log_path && log_cap)
        log_path[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        dvt_strip(line);
        if (strncmp(line, "ok=", 3) == 0)
            *ok = strcmp(line + 3, "1") == 0;
        else if (strncmp(line, "log_path=", 9) == 0 && log_path)
            (void)snprintf(log_path, log_cap, "%s", line + 9);
        else if (strncmp(line, "gates_failed=", 13) == 0 && gates_failed_csv)
            (void)snprintf(gates_failed_csv, gates_cap, "%s", line + 13);
    }
    (void)fclose(f);
    return true;
}

void zcl_native_handle_dev_train_check(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)request;
    dvt_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "DEV_BUILD_REQUIRED", "dispatch",
            "stack lint verification requires a dev build",
            "make dev-bin, or z23-dev dev train check");
    return;
#else
    const char *name =
        request && request->input ? json_get_str(json_get(request->input, "name")) : NULL;
    int64_t timeout_ms = DVT_CHECK_DEFAULT_TIMEOUT_MS;
    if (request && request->input) {
        const struct json_value *t = json_get(request->input, "timeout_ms");
        if (t && t->type == JSON_INT)
            timeout_ms = json_get_int(t);
    }
    if (timeout_ms < DVT_CHECK_MIN_TIMEOUT_MS ||
        timeout_ms > DVT_CHECK_MAX_TIMEOUT_MS)
        timeout_ms = DVT_CHECK_DEFAULT_TIMEOUT_MS;

    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF_CHECK);
    if (!dvt_valid_name(name)) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_NAME", "validate", "name is required", "");
        return;
    }
    const char *root = dvt_source_root(request);
    char stack_dir[PATH_MAX];
    dvt_stack_path(root, name, stack_dir, sizeof(stack_dir));
    if (!dvt_is_directory(stack_dir)) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "STACK_NOT_FOUND", "prepare", "no such stack worktree",
                stack_dir);
        return;
    }

    const char *lock_argv[] = {"tools/dev/checkout-lock.sh", "foreground",
                               "build/.checkout.lock", "--", "make",
                               "--no-print-directory", "lint-fast", NULL};
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run(stack_dir, lock_argv, (int)timeout_ms,
                                 &result)) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "LINT_EXEC_FAILED", "execute", "could not execute lint-fast",
                stack_dir);
        return;
    }

    bool ok = result.exit_code == 0 && !result.timed_out;
    char log_path[PATH_MAX];
    dvt_check_log_path(stack_dir, log_path, sizeof(log_path));
    (void)platform_directory_ensure(stack_dir, 0700);
    char build_dir[PATH_MAX];
    (void)snprintf(build_dir, sizeof(build_dir), "%s/build", stack_dir);
    (void)platform_directory_ensure(build_dir, 0700);
    FILE *logf = fopen(log_path, "wb");
    if (logf) {
        (void)fwrite(result.output, 1, result.output_len, logf);
        (void)fclose(logf);
    }

    struct json_value gates_failed;
    json_init(&gates_failed);
    json_set_array(&gates_failed);
    char gates_csv[4096] = {0};
    size_t gates_csv_len = 0;
    char *save = NULL;
    char output_copy[ZCL_DEVLOOP_OUTPUT_MAX];
    (void)snprintf(output_copy, sizeof(output_copy), "%s", result.output);
    for (char *line = strtok_r(output_copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "FAIL ", 5) != 0)
            continue;
        char gate[256];
        if (sscanf(line + 5, "%255s", gate) != 1)
            continue;
        struct json_value g;
        json_init(&g);
        json_set_str(&g, gate);
        (void)json_push_back(&gates_failed, &g);
        json_free(&g);
        int n = snprintf(gates_csv + gates_csv_len,
                        sizeof(gates_csv) - gates_csv_len, "%s%s",
                        gates_csv_len ? "," : "", gate);
        if (n > 0 && (size_t)n < sizeof(gates_csv) - gates_csv_len)
            gates_csv_len += (size_t)n;
    }

    dvt_write_check_state(stack_dir, ok, gates_csv, log_path);

    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_bool(&reply->data, "ok", ok);
    (void)json_push_kv(&reply->data, "gates_failed", &gates_failed);
    json_free(&gates_failed);
    (void)json_push_kv_str(&reply->data, "log_path", log_path);
    (void)json_push_kv_int(&reply->data, "elapsed_ms", result.elapsed_ms);
    if (ok) {
        char next[PATH_MAX + 64];
        (void)snprintf(next, sizeof(next),
                      "z23-land submit --branch lane/train --head HEAD");
        (void)json_push_kv_str(&reply->data, "next", next);
    } else {
        (void)json_push_kv_str(&reply->data, "next", log_path);
    }
    reply->status = ok ? ZCL_COMMAND_STATUS_PASSED
                       : ZCL_COMMAND_STATUS_FAILED;
    reply->exit_code = ok ? ZCL_COMMAND_EXIT_OK : ZCL_COMMAND_EXIT_FAILED;
#endif
}

/* ── status ───────────────────────────────────────────────────────────── */

void zcl_native_handle_dev_train_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)request;
    dvt_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "DEV_BUILD_REQUIRED", "dispatch", "stack status requires a dev build",
            "make dev-bin, or z23-dev dev train status");
    return;
#else
    const char *name =
        request && request->input ? json_get_str(json_get(request->input, "name")) : NULL;
    const char *root = dvt_source_root(request);
    char parent[PATH_MAX];
    dvt_dirname(root, parent, sizeof(parent));
    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF_STATUS);

    struct json_value stacks;
    json_init(&stacks);
    json_set_array(&stacks);

    struct platform_directory_list children;
    memset(&children, 0, sizeof(children));
    if (platform_directory_list_real_sorted(parent, &children)) {
        for (size_t i = 0; i < children.count; i++) {
            const char *child_name = children.entries[i].name;
            if (strncmp(child_name, "z23-stack", 9) != 0)
                continue;
            const char *stack_name = child_name + 9;
            if (name && name[0] && strcmp(stack_name, name) != 0)
                continue;
            char stack_dir[PATH_MAX];
            (void)snprintf(stack_dir, sizeof(stack_dir), "%s/%s", parent,
                          child_name);

            struct json_value entry;
            json_init(&entry); json_set_object(&entry);
            (void)json_push_kv_str(&entry, "name", stack_name);
            (void)json_push_kv_str(&entry, "path", stack_dir);
            (void)json_push_kv_str(&entry, "base", "origin/main");

            static const char *const count_args[] = {
                "rev-list", "--count", "origin/main..HEAD", NULL};
            char count_out[64];
            int64_t commits = -1;
            if (dvt_git(stack_dir, count_args, count_out, sizeof(count_out),
                        DVT_GIT_TIMEOUT_MS) == 0) {
                dvt_strip(count_out);
                commits = strtoll(count_out, NULL, 10);
            }
            (void)json_push_kv_int(&entry, "commits", commits);

            bool check_ok = false;
            char gates_csv[4096] = {0};
            char log_path[PATH_MAX] = {0};
            bool has_check = dvt_read_check_state(
                stack_dir, &check_ok, gates_csv, sizeof(gates_csv), log_path,
                sizeof(log_path));
            (void)json_push_kv_str(&entry, "check",
                                   has_check ? (check_ok ? "passed" : "failed")
                                             : "unavailable");
            if (has_check)
                (void)json_push_kv_str(&entry, "check_log_path", log_path);

            (void)json_push_back(&stacks, &entry);
            json_free(&entry);
        }
        platform_directory_list_free(&children);
    }

    (void)json_push_kv(&reply->data, "stacks", &stacks);
    json_free(&stacks);

    const char *queue_path = "/.local/state/zclassic23/land/queue.jsonl";
    char home_queue[PATH_MAX];
    const char *home = getenv("HOME");
    if (home && home[0]) {
        (void)snprintf(home_queue, sizeof(home_queue), "%s%s", home,
                      queue_path);
        FILE *q = fopen(home_queue, "rb");
        (void)json_push_kv_bool(&reply->data, "land_queue_present", q != NULL);
        if (q)
            (void)fclose(q);
    } else {
        (void)json_push_kv_bool(&reply->data, "land_queue_present", false);
    }

    reply->status = ZCL_COMMAND_STATUS_PASSED;
#endif
}

/* ── drop ─────────────────────────────────────────────────────────────── */

void zcl_native_handle_dev_train_drop(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)request;
    dvt_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "DEV_BUILD_REQUIRED", "dispatch", "stack removal requires a dev build",
            "make dev-bin, or z23-dev dev train drop");
    return;
#else
    const char *name =
        request && request->input ? json_get_str(json_get(request->input, "name")) : NULL;
    bool force = false;
    if (request && request->input) {
        const struct json_value *f = json_get(request->input, "force");
        if (f && f->type == JSON_BOOL)
            force = json_get_bool(f);
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVT_LEAF_DROP);
    if (!dvt_valid_name(name)) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_NAME", "validate", "name is required", "");
        return;
    }
    const char *root = dvt_source_root(request);
    char stack_dir[PATH_MAX];
    dvt_stack_path(root, name, stack_dir, sizeof(stack_dir));
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "path", stack_dir);
    if (!dvt_is_directory(stack_dir)) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "STACK_NOT_FOUND", "prepare", "no such stack worktree",
                stack_dir);
        return;
    }

    static const char *const count_args[] = {"rev-list", "--count",
                                             "origin/main..HEAD", NULL};
    char count_out[64];
    int64_t commits = 0;
    if (dvt_git(stack_dir, count_args, count_out, sizeof(count_out),
                DVT_GIT_TIMEOUT_MS) == 0) {
        dvt_strip(count_out);
        commits = strtoll(count_out, NULL, 10);
    }
    (void)json_push_kv_int(&reply->data, "unpushed_commits", commits);
    if (commits > 0 && !force) {
        char next[PATH_MAX + 64];
        (void)snprintf(next, sizeof(next), "dev train drop --name %s --force",
                      name);
        (void)json_push_kv_str(&reply->data, "next", next);
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "UNPUSHED_COMMITS",
                "check",
                "stack carries commits origin/main does not have; pass "
                "--force to drop it anyway",
                stack_dir);
        return;
    }

    const char *remove_argv[5];
    size_t m = 0;
    remove_argv[m++] = "worktree";
    remove_argv[m++] = "remove";
    if (force)
        remove_argv[m++] = "--force";
    remove_argv[m++] = stack_dir;
    remove_argv[m] = NULL;
    if (dvt_git(root, remove_argv, NULL, 0, DVT_GIT_TIMEOUT_MS) != 0) {
        dvt_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "GIT_FAILED", "worktree_remove", "git worktree remove failed",
                stack_dir);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
#endif
}

/* ── CLI ──────────────────────────────────────────────────────────────── */

static bool dvt_cli_flag(const char *word, const char *key, const char **value)
{
    size_t klen = strlen(key);
    if (strncmp(word, "--", 2) != 0)
        return false;
    word += 2;
    if (strncmp(word, key, klen) != 0)
        return false;
    if (word[klen] == '=') {
        *value = word + klen + 1;
        return true;
    }
    if (word[klen] == '\0') {
        *value = NULL;
        return true;
    }
    return false;
}

static void dvt_print_json(const struct json_value *data)
{
    char buf[65536];
    size_t needed = json_write(data, buf, sizeof(buf));
    if (needed < sizeof(buf))
        printf("%s\n", buf);
    else
        printf("{\"ok\":false,\"error\":\"result too large to render\"}\n");
}

/* A short human summary of one dev.train.* reply. Every field is optional
 * (each verb populates a different subset of them), so this prints only
 * what is present rather than assuming one leaf's shape. */
static void dvt_human_summary(const struct json_value *data)
{
    const char *name = json_get_str(json_get(data, "name"));
    const char *path = json_get_str(json_get(data, "path"));
    const char *state = json_get_str(json_get(data, "state"));
    const struct json_value *ok_v = json_get(data, "ok");
    const struct json_value *commits_v = json_get(data, "commits");
    const struct json_value *stacks_v = json_get(data, "stacks");
    const char *next = json_get_str(json_get(data, "next"));

    if (name && name[0])
        printf("name:    %s\n", name);
    if (path && path[0])
        printf("path:    %s\n", path);
    if (state && state[0])
        printf("state:   %s\n", state);
    if (ok_v && ok_v->type == JSON_BOOL)
        printf("ok:      %s\n", json_get_bool(ok_v) ? "true" : "false");
    if (commits_v && commits_v->type == JSON_INT)
        printf("commits: %lld\n", (long long)json_get_int(commits_v));
    if (stacks_v && stacks_v->type == JSON_ARR)
        printf("stacks:  %zu\n", stacks_v->num_children);
    if (next && next[0])
        printf("next:    %s\n", next);
}

bool zcl_native_dev_train_cli(const struct zcl_command_spec *spec,
                              const char *const *words, size_t word_count,
                              size_t consumed, int *out_rc)
{
    if (!spec || !out_rc)
        return false;
    *out_rc = ZCL_COMMAND_EXIT_OK;

    char name[64] = {0};
    char sources[ZCL_COMMAND_MAX_INPUT] = {0};
    size_t sources_len = 0;
    int64_t timeout_ms = 0;
    bool force = false, human = false, saw_timeout = false;

    for (size_t i = consumed; i < word_count; i++) {
        const char *w = words[i];
        const char *value = NULL;
        if (dvt_cli_flag(w, "name", &value) && value) {
            (void)snprintf(name, sizeof(name), "%s", value);
        } else if (dvt_cli_flag(w, "source", &value) && value) {
            int n = snprintf(sources + sources_len,
                            sizeof(sources) - sources_len, "%s%s",
                            sources_len ? "\n" : "", value);
            if (n > 0 && (size_t)n < sizeof(sources) - sources_len)
                sources_len += (size_t)n;
        } else if (dvt_cli_flag(w, "timeout", &value) && value) {
            timeout_ms = strtoll(value, NULL, 10);
            saw_timeout = true;
        } else if (dvt_cli_flag(w, "force", &value)) {
            force = true;
        } else if (dvt_cli_flag(w, "human", &value)) {
            human = true;
        } else {
            printf("{\"ok\":false,\"error\":\"unknown flag %s\"}\n", w);
            *out_rc = ZCL_COMMAND_EXIT_INVALID;
            return true;
        }
    }

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (name[0])
        (void)json_push_kv_str(&input, "name", name);
    if (sources_len)
        (void)json_push_kv_str(&input, "sources", sources);
    if (saw_timeout)
        (void)json_push_kv_int(&input, "timeout_ms", timeout_ms);
    if (force)
        (void)json_push_kv_bool(&input, "force", true);

    char why[192];
    if (!zcl_command_registry_input_validate(spec, &input, why, sizeof(why))) {
        printf("{\"ok\":false,\"error\":\"%s\"}\n", why);
        json_free(&input);
        *out_rc = ZCL_COMMAND_EXIT_INVALID;
        return true;
    }

    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.spec = spec;
    request.input = &input;

    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.train.v1");
    if (spec->handler)
        spec->handler(&request, &reply);
    else
        dvt_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "DEV_BUILD_REQUIRED", "dispatch",
                "dev train requires the dev binary", "z23-dev");

    dvt_print_json(&reply.data);
    if (human)
        dvt_human_summary(&reply.data);
    if (reply.status != ZCL_COMMAND_STATUS_PASSED &&
        reply.status != ZCL_COMMAND_STATUS_ACCEPTED)
        fprintf(stderr, "%s: %s (%s)\n", spec->path, reply.error.message,
               reply.error.code);

    *out_rc = (int)reply.exit_code;
    zcl_command_reply_free(&reply);
    json_free(&input);
    return true;
}
