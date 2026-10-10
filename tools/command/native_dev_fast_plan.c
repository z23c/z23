/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.test.fast_plan, the native port of tools/agent_fast_ci.sh
 *          `plan-json`.
 *
 * It maps a changed-file set to the focused test groups, the compile plan
 * and the recommended next command, and reports the same object the shell
 * prints under schema zcl.agent_fast_plan.v1. The changed set comes from the
 * same hint sources, in the same order, as changed_file_hints(): the
 * ZCL_FAST_CHANGED_FILES_FILE and ZCL_FAST_CHANGED_FILES hints, then (unless
 * ZCL_FAST_CHANGED_FILES_ONLY is set) the ZCL_FAST_BASE range and the git
 * diff, index and untracked lists. Group selection runs the compiled
 * AGENT_IMPACT_RULE table through agent_impact_apply_shared_rules.
 *
 * Read-only: the only child process is git, the same one the shell runs.
 *
 * Fail-closed scope. The shell derives two verdicts this leaf does not
 * reproduce, so the leaf refuses rather than guess at them:
 *   - the green-input cache key, which needs the working-tree source
 *     identity (ZCL_FAST_CACHE must be 0/false/no/off/skip);
 *   - the affected-translation-unit compile plan, which needs a compile
 *     scope proof file (ZCL_FAST_COMPILE_SCOPE_PROOF must be unset);
 *   - a runtime impact-rule file override (ZCL_FAST_IMPACT_RULES_FILE must
 *     be unset: the rule table is compiled in). */

#include "command/native_command.h"

#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/glob_match.h"
#include "platform/logical_cpu.h"
#include "util/file_io.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PLAN_SCHEMA "zcl.agent_fast_plan.v1"
#define PLAN_CACHE_SCHEMA "zcl.agent_fast_ci.cache.v4"
#define PLAN_IMPACT_RULES "cognition/controllers/include/controllers/agent_impact_rules.def"
#define PLAN_CACHE_SUBDIR ".cache/zcl-agent-fast-ci"
#define PLAN_GIT_CAP (1u << 20)
#define PLAN_FILE_CAP (1u << 24)
#define PLAN_GIT_TIMEOUT_MS 60000
#define PLAN_JOBS_CAP 16
#define PLAN_JOBS_FALLBACK 8
#define PLAN_CWD_CAP 4096
#define PLAN_TOKEN_SEPS ", \n"

struct plan_list {
    char **items;
    size_t len;
    size_t cap;
};

struct plan_state {
    struct plan_list changed;
    struct plan_list unmapped;
    struct agent_impact_acc groups;
    char jobs[16];
    char compiler[160];
    char cache_tool[16];
    char cache_root[PLAN_CWD_CAP + 64];
    bool only;
    bool faulted;
    enum zcl_command_status status;
    enum zcl_command_exit exit_code;
    const char *code;
    const char *msg;
    const char *evidence;
};

/* ── small helpers ───────────────────────────────────────────────────── */

static const char *plan_env(const char *name)
{
    const char *v = getenv(name);
    return (v && v[0]) ? v : "";
}

static bool plan_fault(struct plan_state *st, enum zcl_command_status status,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *msg, const char *evidence)
{
    if (!st->faulted) {
        st->faulted = true;
        st->status = status;
        st->exit_code = exit_code;
        st->code = code;
        st->msg = msg;
        st->evidence = evidence;
    }
    return false;
}

static bool plan_refuse(struct plan_state *st, const char *msg,
                        const char *evidence)
{
    return plan_fault(st, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                      "NOT_NATIVE_YET", msg, evidence);
}

static bool plan_invalid(struct plan_state *st, const char *msg,
                         const char *evidence)
{
    return plan_fault(st, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                      "INVALID_INPUT", msg, evidence);
}

/* ── string lists (insertion order preserved until plan_list_sort) ───── */

static bool plan_list_push(struct plan_list *l, const char *s)
{
    char *copy;
    size_t n;
    if (!s || !s[0])
        return true;
    if (l->len == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 16;
        char **grown = realloc(l->items, cap * sizeof(*grown)); // raw-alloc-ok:read-only-leaf
        if (!grown)
            return false;
        l->items = grown;
        l->cap = cap;
    }
    n = strlen(s) + 1;
    copy = malloc(n); // raw-alloc-ok:read-only-leaf
    if (!copy)
        return false;
    memcpy(copy, s, n);
    l->items[l->len++] = copy;
    return true;
}

static bool plan_list_has(const struct plan_list *l, const char *s)
{
    for (size_t i = 0; i < l->len; i++)
        if (strcmp(l->items[i], s) == 0)
            return true;
    return false;
}

static void plan_list_push_unique(struct plan_list *l, const char *s)
{
    if (!plan_list_has(l, s))
        (void)plan_list_push(l, s);
}

static int plan_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Byte-order sort and de-duplication: the set semantics of `sort -u`. */
static void plan_list_sort_unique(struct plan_list *l)
{
    size_t out = 0;
    if (l->len == 0)
        return;
    qsort(l->items, l->len, sizeof(*l->items), plan_cmp);
    for (size_t i = 0; i < l->len; i++) {
        if (out > 0 && strcmp(l->items[out - 1], l->items[i]) == 0) {
            free(l->items[i]);
            continue;
        }
        l->items[out++] = l->items[i];
    }
    l->len = out;
}

static void plan_list_free(struct plan_list *l)
{
    for (size_t i = 0; i < l->len; i++)
        free(l->items[i]);
    free(l->items);
    l->items = NULL;
    l->len = 0;
    l->cap = 0;
}

/* ── changed-set hints ───────────────────────────────────────────────── */

/* Split on newlines, as `cat` of a hint file does. */
static bool plan_push_lines(struct plan_list *l, const char *text)
{
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0) {
            char *line = malloc(len + 1); // raw-alloc-ok:read-only-leaf
            if (!line)
                return false;
            memcpy(line, p, len);
            line[len] = '\0';
            if (!plan_list_push(l, line)) {
                free(line);
                return false;
            }
            free(line);
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return true;
}

/* Separator runs: a NUL byte is never a separator, whatever `seps` holds. */
static bool plan_is_sep(char c, const char *seps)
{
    return c != '\0' && strchr(seps, c) != NULL;
}

static const char *plan_skip_seps(const char *p, const char *seps)
{
    while (plan_is_sep(*p, seps))
        p++;
    return p;
}

static const char *plan_token_end(const char *p, const char *seps)
{
    while (*p && !plan_is_sep(*p, seps))
        p++;
    return p;
}

/* Copies [p, end) as one NUL-terminated token and pushes it. */
static bool plan_push_span(struct plan_list *l, const char *p, const char *end)
{
    size_t len = (size_t)(end - p);
    char *tok = malloc(len + 1); // raw-alloc-ok:read-only-leaf
    bool ok;
    if (!tok)
        return false;
    memcpy(tok, p, len);
    tok[len] = '\0';
    ok = plan_list_push(l, tok);
    free(tok);
    return ok;
}

/* Split on the separators of ZCL_FAST_CHANGED_FILES (space, comma, newline). */
static bool plan_push_tokens(struct plan_list *l, const char *text,
                             const char *seps)
{
    const char *p = plan_skip_seps(text, seps);
    while (*p) {
        const char *end = plan_token_end(p, seps);
        if (!plan_push_span(l, p, end))
            return false;
        p = plan_skip_seps(end, seps);
    }
    return true;
}

/* Whole-file read, NUL-terminated. NULL on open or allocation failure, so a
 * hint file is never silently truncated. */
static char *plan_read_file(const char *path, size_t *out_len)
{
    char *buf = NULL;
    size_t len = 0;
    if (!zcl_read_whole_file_text(path, PLAN_FILE_CAP, &buf, &len,
                                  "dev.test.fast_plan"))
        return NULL;
    *out_len = len;
    return buf;
}

static bool plan_hint_file(struct plan_state *st)
{
    const char *path = plan_env("ZCL_FAST_CHANGED_FILES_FILE");
    struct stat sb;
    char *text;
    size_t len = 0;
    bool ok;
    if (!path[0])
        return true;
    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode))
        return plan_invalid(st, "ZCL_FAST_CHANGED_FILES_FILE does not exist",
                            "env:ZCL_FAST_CHANGED_FILES_FILE");
    text = plan_read_file(path, &len);
    if (!text)
        return plan_invalid(st, "ZCL_FAST_CHANGED_FILES_FILE is unreadable",
                            "env:ZCL_FAST_CHANGED_FILES_FILE");
    ok = plan_push_lines(&st->changed, text);
    free(text);
    return ok;
}

/* Runs one git command and adds its stdout lines. A nonzero exit is a
 * failure unless `lenient` (the shell's `|| true` base range). */
static bool plan_git_lines(struct plan_state *st, const char *const argv[],
                           bool lenient)
{
    char *buf = malloc(PLAN_GIT_CAP); // raw-alloc-ok:read-only-leaf
    int rc;
    bool ok;
    if (!buf)
        return plan_invalid(st, "git output buffer unavailable", "git");
    rc = zcl_spawn_capture(argv, buf, PLAN_GIT_CAP, PLAN_GIT_TIMEOUT_MS);
    if (!lenient && rc != 0) {
        free(buf);
        return plan_refuse(st, "git changed-file listing failed", "git");
    }
    if (strlen(buf) >= PLAN_GIT_CAP - 1) {
        free(buf);
        return plan_refuse(st, "git changed-file listing exceeded its cap",
                           "git");
    }
    ok = plan_push_lines(&st->changed, buf);
    free(buf);
    return ok;
}

static bool plan_git_hints(struct plan_state *st)
{
    const char *base = plan_env("ZCL_FAST_BASE");
    const char *diff_base[] = {"git", "diff", "--name-only", NULL, "--", NULL};
    const char *diff_head[] = {"git", "diff", "--name-only", "HEAD", "--", NULL};
    const char *cached[] = {"git", "diff", "--cached", "--name-only", "--", NULL};
    const char *untracked[] = {"git", "ls-files", "--others",
                               "--exclude-standard", NULL};
    char range[512];
    if (base[0]) {
        if (snprintf(range, sizeof(range), "%s...HEAD", base) >=
            (int)sizeof(range))
            return plan_invalid(st, "ZCL_FAST_BASE is too long",
                                "env:ZCL_FAST_BASE");
        diff_base[3] = range;
        if (!plan_git_lines(st, diff_base, true))
            return false;
    }
    return plan_git_lines(st, diff_head, false) &&
           plan_git_lines(st, cached, false) &&
           plan_git_lines(st, untracked, false);
}

static bool plan_parse_only(struct plan_state *st)
{
    const char *v = plan_env("ZCL_FAST_CHANGED_FILES_ONLY");
    if (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "yes") ||
        !strcmp(v, "only")) {
        st->only = true;
        return true;
    }
    if (!strcmp(v, "0") || !strcmp(v, "false") || !strcmp(v, "no") || !v[0]) {
        st->only = false;
        return true;
    }
    return plan_invalid(st, "unknown ZCL_FAST_CHANGED_FILES_ONLY",
                        "env:ZCL_FAST_CHANGED_FILES_ONLY");
}

/* ZCL_FAST_CHANGED_FILES_ONLY needs an explicit hint source to be useful. */
static bool plan_check_only_hints(struct plan_state *st)
{
    if (!st->only || plan_env("ZCL_FAST_CHANGED_FILES_FILE")[0] ||
        plan_env("ZCL_FAST_CHANGED_FILES")[0])
        return true;
    return plan_invalid(st,
                        "ZCL_FAST_CHANGED_FILES_ONLY requires explicit changed-file hints",
                        "env:ZCL_FAST_CHANGED_FILES_ONLY");
}

static bool plan_collect_hints(struct plan_state *st)
{
    if (!plan_parse_only(st) || !plan_check_only_hints(st))
        return false;
    if (!plan_hint_file(st))
        return false;
    if (!plan_push_tokens(&st->changed, plan_env("ZCL_FAST_CHANGED_FILES"),
                          PLAN_TOKEN_SEPS))
        return plan_invalid(st, "changed-file hints out of memory", "heap");
    if (!st->only && !plan_git_hints(st))
        return false;
    plan_list_sort_unique(&st->changed);
    return true;
}

/* ── classification ──────────────────────────────────────────────────── */

static bool plan_glob(const char *pattern, const char *text)
{
    return platform_glob_match(pattern, text, false);
}

/* Mirrors is_transient_lint_fixture(): fixture plants, never real changes. */
static bool plan_is_transient_fixture(const char *file)
{
    return plan_glob("*/_*fixture*.c", file) || plan_glob("_*fixture*.c", file);
}

static bool plan_is_code_like(const char *file)
{
    static const char *const code_globs[] = {
        "*.c", "*.h", "Makefile", "*.mk", "tools/*.sh", "tools/githooks/*",
        "app/*", "engine/application/*", "platform/adapters/*", "config/*",
        "domain/*", "lib/*", "platform/ports/*",
    };
    if (plan_is_transient_fixture(file))
        return false;
    for (size_t i = 0; i < sizeof(code_globs) / sizeof(code_globs[0]); i++)
        if (plan_glob(code_globs[i], file))
            return true;
    return false;
}

/* One changed path: a deleted path maps to the build/lint contract, a live
 * path to its impact rules, and a code-like path with no rule is unmapped. */
static void plan_classify(struct plan_state *st, const char *file)
{
    struct stat sb;
    bool matched;
    if (stat(file, &sb) != 0) {
        agent_impact_add_group(&st->groups, "make_lint_gates");
        return;
    }
    matched = agent_impact_apply_shared_rules(file, &st->groups);
    if (!matched && plan_is_code_like(file))
        plan_list_push_unique(&st->unmapped, file);
}

/* Explicit ZCL_FAST_TESTS groups replace classification entirely. */
#define PLAN_GROUP_SEPS ", :\t\n"

static void plan_add_group(struct plan_state *st, const char *p, size_t len)
{
    char group[ZCL_AGENT_IMPACT_GROUP_MAX];
    if (len >= sizeof(group)) {
        st->groups.groups_lost = true;
        return;
    }
    memcpy(group, p, len);
    group[len] = '\0';
    agent_impact_add_group(&st->groups, group);
}

static void plan_explicit_groups(struct plan_state *st, const char *spec)
{
    const char *p = plan_skip_seps(spec, PLAN_GROUP_SEPS);
    while (*p) {
        const char *end = plan_token_end(p, PLAN_GROUP_SEPS);
        plan_add_group(st, p, (size_t)(end - p));
        p = plan_skip_seps(end, PLAN_GROUP_SEPS);
    }
}

static bool plan_select_groups(struct plan_state *st)
{
    const char *explicit_tests = plan_env("ZCL_FAST_TESTS");
    if (explicit_tests[0]) {
        plan_explicit_groups(st, explicit_tests);
    } else {
        for (size_t i = 0; i < st->changed.len; i++)
            plan_classify(st, st->changed.items[i]);
    }
    if (st->groups.groups_lost)
        return plan_refuse(st, "impact group capacity exceeded", "groups");
    return true;
}

/* ── compiler, jobs and refusals ─────────────────────────────────────── */

static bool plan_exec_on_path(const char *name)
{
    const char *path = getenv("PATH");
    char candidate[PATH_MAX];
    if (!path)
        return false;
    while (*path) {
        const char *end = strchr(path, ':');
        size_t dir_len = end ? (size_t)(end - path) : strlen(path);
        if (dir_len > 0 &&
            (size_t)snprintf(candidate, sizeof(candidate), "%.*s/%s",
                             (int)dir_len, path, name) < sizeof(candidate) &&
            access(candidate, X_OK) == 0)
            return true;
        if (!end)
            break;
        path = end + 1;
    }
    return false;
}

static void plan_compiler(struct plan_state *st)
{
    const char *cc = plan_env("ZCL_FAST_CC");
    if (cc[0]) {
        (void)snprintf(st->compiler, sizeof(st->compiler), "%s", cc);
        if (strstr(cc, "sccache"))
            (void)snprintf(st->cache_tool, sizeof(st->cache_tool), "sccache");
        else if (strstr(cc, "ccache"))
            (void)snprintf(st->cache_tool, sizeof(st->cache_tool), "ccache");
        else
            (void)snprintf(st->cache_tool, sizeof(st->cache_tool), "custom");
        return;
    }
    if (plan_exec_on_path("sccache")) {
        (void)snprintf(st->compiler, sizeof(st->compiler), "sccache cc");
        (void)snprintf(st->cache_tool, sizeof(st->cache_tool), "sccache");
    } else if (plan_exec_on_path("ccache")) {
        (void)snprintf(st->compiler, sizeof(st->compiler), "ccache cc");
        (void)snprintf(st->cache_tool, sizeof(st->cache_tool), "ccache");
    } else {
        (void)snprintf(st->compiler, sizeof(st->compiler), "cc");
        (void)snprintf(st->cache_tool, sizeof(st->cache_tool), "none");
    }
}

/* A positive decimal integer with no sign, space or leading-zero rule. */
static bool plan_positive_int(const char *s)
{
    if (!s[0] || !strcmp(s, "0"))
        return false;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

static bool plan_jobs_from_env(struct plan_state *st, const char *env)
{
    if (!plan_positive_int(env))
        return plan_invalid(st, "ZCL_FAST_JOBS must be a positive integer",
                            "env:ZCL_FAST_JOBS");
    (void)snprintf(st->jobs, sizeof(st->jobs), "%s", env);
    return true;
}

static bool plan_jobs(struct plan_state *st)
{
    const char *env = plan_env("ZCL_FAST_JOBS");
    long n;
    if (env[0])
        return plan_jobs_from_env(st, env);
    n = (long)platform_logical_cpu_count();
    if (n <= 0)
        n = PLAN_JOBS_FALLBACK;
    if (n > PLAN_JOBS_CAP)
        n = PLAN_JOBS_CAP;
    (void)snprintf(st->jobs, sizeof(st->jobs), "%ld", n);
    return true;
}

/* Unset or empty means the shell default, which is enabled. */
static bool plan_cache_disabled(const char *v)
{
    return !strcmp(v, "0") || !strcmp(v, "false") || !strcmp(v, "no") ||
           !strcmp(v, "off") || !strcmp(v, "skip");
}

/* The cache verdict is native only when the cache is disabled. */
static bool plan_check_cache_scope(struct plan_state *st)
{
    if (plan_cache_disabled(plan_env("ZCL_FAST_CACHE")))
        return true;
    return plan_refuse(st,
                       "green-input cache verdict is not native: set ZCL_FAST_CACHE=0",
                       "env:ZCL_FAST_CACHE");
}

static bool plan_check_proof_scope(struct plan_state *st)
{
    const char *proof = plan_env("ZCL_FAST_COMPILE_SCOPE_PROOF");
    struct stat sb;
    if (!proof[0] || stat(proof, &sb) != 0)
        return true;
    return plan_refuse(st,
                       "affected-unit compile plan is not native: unset ZCL_FAST_COMPILE_SCOPE_PROOF",
                       "env:ZCL_FAST_COMPILE_SCOPE_PROOF");
}

static bool plan_check_rules_scope(struct plan_state *st)
{
    if (!plan_env("ZCL_FAST_IMPACT_RULES_FILE")[0])
        return true;
    return plan_refuse(st,
                       "the impact rule table is compiled in: unset ZCL_FAST_IMPACT_RULES_FILE",
                       "env:ZCL_FAST_IMPACT_RULES_FILE");
}

/* Only the cache-disabled plan is native; see the header comment. */
static bool plan_check_scope(struct plan_state *st)
{
    return plan_check_cache_scope(st) && plan_check_proof_scope(st) &&
           plan_check_rules_scope(st);
}

/* Bounds the formatted cache root to the state buffer. */
static bool plan_bound_cache_root(struct plan_state *st, int n)
{
    if (n < 0 || (size_t)n >= sizeof(st->cache_root))
        return plan_invalid(st, "cache root path is too long",
                            "env:ZCL_FAST_CACHE_DIR");
    return true;
}

static bool plan_cache_root(struct plan_state *st)
{
    const char *dir = plan_env("ZCL_FAST_CACHE_DIR");
    char cwd[PLAN_CWD_CAP];
    int n;
    if (dir[0])
        n = snprintf(st->cache_root, sizeof(st->cache_root), "%s", dir);
    else if (!getcwd(cwd, sizeof(cwd)))
        return plan_invalid(st, "working directory unavailable", "getcwd");
    else
        n = snprintf(st->cache_root, sizeof(st->cache_root), "%s/%s", cwd,
                     PLAN_CACHE_SUBDIR);
    return plan_bound_cache_root(st, n);
}

static bool plan_prepare(struct plan_state *st)
{
    if (!plan_check_scope(st))
        return false;
    if (!plan_jobs(st))
        return false;
    plan_compiler(st);
    if (!plan_cache_root(st))
        return false;
    if (!plan_collect_hints(st))
        return false;
    return plan_select_groups(st);
}

/* ── output ──────────────────────────────────────────────────────────── */

static void plan_put_str(struct json_value *o, const char *k, const char *v)
{
    (void)json_push_kv_str(o, k, v);
}

static void plan_put_list(struct json_value *o, const char *k,
                          const struct plan_list *l)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < l->len; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, l->items[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(o, k, &arr);
    json_free(&arr);
}

static void plan_put_groups(struct json_value *o, const char *k,
                            const struct agent_impact_acc *acc)
{
    struct plan_list l = {0};
    for (size_t i = 0; i < acc->groups_len; i++)
        (void)plan_list_push(&l, acc->groups[i]);
    plan_put_list(o, k, &l);
    plan_list_free(&l);
}

static void plan_put_compile_plan(struct json_value *o)
{
    struct json_value cp;
    json_init(&cp);
    json_set_object(&cp);
    plan_put_str(&cp, "schema", "zcl.agent_changed_compile_plan.v2");
    plan_put_str(&cp, "kind", "full_source_inventory");
    plan_put_str(&cp, "target", "fast-compile");
    plan_put_str(&cp, "detail", "compile every current dev source input");
    plan_put_str(&cp, "fallback_reason",
                 "changed-file lists are hint-only and cannot reduce proof scope");
    plan_put_str(&cp, "proof_scope", "full_source_inventory");
    plan_put_str(&cp, "path_hint_role", "classification_only");
    (void)json_push_kv(o, "compile_plan", &cp);
    json_free(&cp);
}

static void plan_put_cache(struct json_value *o, const struct plan_state *st)
{
    struct json_value c;
    json_init(&c);
    json_set_object(&c);
    plan_put_str(&c, "schema", PLAN_CACHE_SCHEMA);
    plan_put_str(&c, "authority", "working_tree_source_id_sha256_plus_mutation_token");
    plan_put_str(&c, "working_tree_source_id_sha256", "");
    plan_put_str(&c, "source_mutation_token", "");
    (void)json_push_kv_bool(&c, "enabled", false);
    (void)json_push_kv_bool(&c, "available", false);
    (void)json_push_kv_bool(&c, "hit", false);
    plan_put_str(&c, "key", "");
    plan_put_str(&c, "record", "");
    plan_put_str(&c, "reason", "disabled_by_ZCL_FAST_CACHE");
    plan_put_str(&c, "root", st->cache_root);
    (void)json_push_kv(o, "green_input_cache", &c);
    json_free(&c);
}

static void plan_put_static_objects(struct json_value *o)
{
    struct json_value sc, lane;
    json_init(&sc);
    json_set_object(&sc);
    plan_put_str(&sc, "fresh_source_tree", "z23 <leaf> [--input=json]");
    plan_put_str(&sc, "dev_linger_lane", "z23-dev <leaf> [--input=json]");
    plan_put_str(&sc, "discover", "z23 discover help | z23 discover search <q>");
    plan_put_str(&sc, "dev_hotswap_probe", "contained_before_dlopen_use_build_test_sim");
    (void)json_push_kv(o, "native_shortcuts", &sc);
    json_free(&sc);

    json_init(&lane);
    json_set_object(&lane);
    (void)json_push_kv_bool(&lane, "runtime_publication", false);
    plan_put_str(&lane, "publication_blocker",
                 "immutable epoch/proof/resident-CAS/rollback transaction incomplete");
    plan_put_str(&lane, "status", "make agent-dev-status");
    plan_put_str(&lane, "stage_without_restart", "make agent-stage-dev");
    plan_put_str(&lane, "hot_swap_restart", "make agent-deploy-fast");
    plan_put_str(&lane, "loop_stage", "ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop");
    plan_put_str(&lane, "loop_deploy", "ZCL_AGENT_LOOP_DEPLOY=dev make agent-loop");
    (void)json_push_kv(o, "dev_lane", &lane);
    json_free(&lane);
}

/* Same recommendation ladder as recommended_plan_command(); the cache is
 * always disabled on this path, so "make fast-ci" is never produced. */
static const char *plan_recommend(const struct plan_state *st)
{
    if (st->unmapped.len)
        return "set ZCL_FAST_TESTS=<group[,group]> or extend " PLAN_IMPACT_RULES;
    if (st->changed.len == 0)
        return "make agent-dev-status";
    return "make agent-loop";
}

static void plan_emit(const struct plan_state *st, struct zcl_command_reply *reply)
{
    struct json_value *o = &reply->data;
    plan_put_str(o, "schema", PLAN_SCHEMA);
    plan_put_str(o, "status", "ok");
    plan_put_str(o, "proof_scope", "full_source_inventory");
    plan_put_str(o, "changed_files_semantics", "hint_only_non_authoritative");
    plan_put_str(o, "compiler", st->compiler);
    plan_put_str(o, "cache_tool", st->cache_tool);
    plan_put_str(o, "jobs", st->jobs);
    plan_put_str(o, "fast_compile_mode", plan_env("ZCL_FAST_COMPILE")[0]
                                             ? plan_env("ZCL_FAST_COMPILE")
                                             : "changed");
    (void)json_push_kv_int(o, "changed_file_count", (int64_t)st->changed.len);
    plan_put_list(o, "changed_files", &st->changed);
    plan_put_groups(o, "test_groups", &st->groups);
    plan_put_list(o, "unmapped_code_changes", &st->unmapped);
    plan_put_compile_plan(o);
    plan_put_cache(o, st);
    plan_put_static_objects(o);
    plan_put_str(o, "live_probe_mode", plan_env("ZCL_FAST_LIVE")[0]
                                           ? plan_env("ZCL_FAST_LIVE")
                                           : "auto");
    plan_put_str(o, "recommended_command", plan_recommend(st));
}

static void plan_reply_fault(const struct plan_state *st,
                             struct zcl_command_reply *reply)
{
    zcl_command_reply_fail(reply, st->status, st->exit_code, st->code,
                           "plan", false, false, st->msg, st->evidence);
}

static void plan_state_init(struct plan_state *st)
{
    memset(st, 0, sizeof(*st));
}

static void plan_state_free(struct plan_state *st)
{
    plan_list_free(&st->changed);
    plan_list_free(&st->unmapped);
}

void zcl_native_handle_dev_fast_plan(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    struct plan_state st;
    (void)request;
    if (!reply)
        return;
    plan_state_init(&st);
    if (!plan_prepare(&st)) {
        plan_reply_fault(&st, reply);
    } else {
        plan_emit(&st, reply);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
    }
    plan_state_free(&st);
}
