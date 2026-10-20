/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land qualify gates -- fetch, rebase, signed tip, regenerated
 *          files, full lint and the affected test groups, in the lane's own
 *          worktree, before `dev land submit` queues it.
 *
 * Verdict rules:
 *   - lint passes only on a zero exit that prints "LINT: all checks passed";
 *   - a test group passes only on a PASS header in the harness output and
 *     no line of its section that begins with "FAIL at". A line that merely
 *     contains "FAIL at" (the net group prints "PARSE FAIL at" on purpose)
 *     is not a verdict; a group with no header has no verdict and fails;
 *   - the affected groups are the routes `code tests` reports for each path
 *     the lane changes relative to origin/main, run in one harness
 *     invocation (t-fast-exact over the whole set) so its workers run them
 *     in parallel; each group still gets its own section log. A selection
 *     that lost groups (a path routing to more than the accumulator holds,
 *     an overlong token, or a truncated path list) is refused, never run
 *     short.
 * Every command's merged output is kept under build/scratch/qualify-*.log in
 * the worktree, and a refusal names the log of the command that failed.
 */

#include "command/native_dev_land_qualify.h"

#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "controllers/agent_impact_rules.h"
#include "platform/logical_cpu.h"
#include "platform/private_directory.h"
#include "util/spawn.h"
#include "test_group_catalog.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DLQ_LOG_CAP (32u * 1024u * 1024u)
#define DLQ_GIT_CAP (1024u * 1024u)
#define DLQ_MAKE_TIMEOUT_MS (90 * 60 * 1000)
#define DLQ_GIT_TIMEOUT_MS (10 * 60 * 1000)
#define DLQ_GROUPS_MAX 256u

struct dlq {
    const char *wt;
    bool exempt;
    char make_jobs[16];
    struct zcl_land_qualify *out;
};

struct dlq_groups {
    size_t count;
    char name[DLQ_GROUPS_MAX][ZCL_AGENT_IMPACT_GROUP_MAX];
};

const char *zcl_dev_land_qualify_refusal(enum zcl_land_qualify_code code)
{
    static const char *const names[] = {
        [ZCL_LAND_QUALIFY_OK] = "ok",
        [ZCL_LAND_QUALIFY_DIRTY_TREE] = "dirty_tree",
        [ZCL_LAND_QUALIFY_FETCH_FAILED] = "fetch_failed",
        [ZCL_LAND_QUALIFY_REBASE_CONFLICT] = "rebase_conflict",
        [ZCL_LAND_QUALIFY_REBASE_FAILED] = "rebase_failed",
        [ZCL_LAND_QUALIFY_GROUP_SELECTION] = "group_selection",
        [ZCL_LAND_QUALIFY_UNSIGNED_TIP] = "unsigned_tip",
        [ZCL_LAND_QUALIFY_STEP_FAILED] = "step_failed",
        [ZCL_LAND_QUALIFY_LINT_FAILED] = "lint_failed",
        [ZCL_LAND_QUALIFY_GROUP_FAILED] = "group_failed",
        [ZCL_LAND_QUALIFY_TREE_CHANGED] = "tree_changed",
    };
    return (unsigned)code < sizeof(names) / sizeof(names[0]) ? names[code]
                                                              : "step_failed";
}

static bool dlq_refuse(struct dlq *q, enum zcl_land_qualify_code code,
                       const char *name, const char *paths)
{
    q->out->code = code;
    if (name)
        (void)snprintf(q->out->name, sizeof(q->out->name), "%s", name);
    if (paths)
        (void)snprintf(q->out->paths, sizeof(q->out->paths), "%s", paths);
    return false;
}

/* git -C wt ARGS..., stdout only. Returns the exit status, -1 on a launch
 * failure. `out` may be NULL when only the status matters. */
static int dlq_git(const struct dlq *q, const char *const *args, char *out,
                   size_t cap)
{
    const char *argv[24];
    char sink[2];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = q->wt;
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    if (out && cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                             DLQ_GIT_TIMEOUT_MS);
}

static void dlq_write_log(struct dlq *q, const char *name, const char *text)
{
    char dir[4096 + 16];
    FILE *f;
    (void)snprintf(dir, sizeof(dir), "%s/build", q->wt);
    (void)platform_private_directory_ensure(dir);
    (void)snprintf(dir, sizeof(dir), "%s/build/scratch", q->wt);
    (void)platform_private_directory_ensure(dir);
    if (snprintf(q->out->log, sizeof(q->out->log), "%s/qualify-%s.log", dir,
                 name) >= (int)sizeof(q->out->log)) {
        q->out->log[0] = '\0';
        return;
    }
    f = fopen(q->out->log, "wb");
    if (!f)
        return;
    (void)fwrite(text, 1, strlen(text), f);
    (void)fclose(f);
}

/* Run argv with merged output, keep it as the step's log and return it in
 * `*text` (owned by the caller, NULL when allocation failed). */
static int dlq_run(struct dlq *q, const char *name, const char *const argv[],
                   char **text)
{
    bool timed_out = false;
    char *buf = (char *)zcl_malloc(DLQ_LOG_CAP, "dev.land.qualify.log");
    int rc;
    *text = buf;
    if (!buf)
        return -1;
    rc = zcl_spawn_capture_merged_observed(argv, buf, DLQ_LOG_CAP,
                                           DLQ_MAKE_TIMEOUT_MS, &timed_out);
    if (timed_out)
        rc = -1;
    dlq_write_log(q, name, buf);
    return rc;
}

/* make -C wt GOALS..., optionally under VENDOR_CC=gcc. */
static int dlq_make(struct dlq *q, const char *log_name,
                    const char *const *goals, bool gcc, char **text)
{
    const char *argv[16];
    size_t n = 0;
    if (gcc) {
        argv[n++] = "env";
        argv[n++] = "VENDOR_CC=gcc";
    }
    argv[n++] = "make";
    argv[n++] = "-C";
    argv[n++] = q->wt;
    if (q->make_jobs[0])
        argv[n++] = q->make_jobs;
    for (size_t i = 0; goals[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = goals[i];
    argv[n] = NULL;
    return dlq_run(q, log_name, argv, text);
}

/* Paths of a `git status --porcelain` listing, space-separated. */
static void dlq_porcelain_paths(const char *text, char *paths, size_t cap)
{
    size_t used = 0;
    paths[0] = '\0';
    for (const char *line = text; line && *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len > 3 && used + len - 3 + 2 < cap)
            used += (size_t)snprintf(paths + used, cap - used, "%s%.*s",
                                     used ? " " : "", (int)(len - 3),
                                     line + 3);
        line = end ? end + 1 : NULL;
    }
}

static bool dlq_generated_path(const char *path, size_t len)
{
    static const char *const generated[] = {
        "docs/CAPABILITY_INVENTORY.jsonl", "docs/dev/CODEBASE_MAP.md",
        "docs/API_REFERENCE.md"
    };
    for (size_t i = 0; i < sizeof(generated) / sizeof(generated[0]); i++) {
        if (strlen(generated[i]) == len && memcmp(generated[i], path, len) == 0)
            return true;
    }
    return false;
}

/* True when every changed path of a porcelain listing is a generated file. */
static bool dlq_only_generated(const char *text)
{
    for (const char *line = text; line && *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len <= 3 || !dlq_generated_path(line + 3, len - 3))
            return false;
        line = end ? end + 1 : NULL;
    }
    return true;
}

static bool dlq_amend(struct dlq *q)
{
    const char *signed_args[] = { "commit", "-q", "-S", "-a", "--amend",
                                  "--no-edit", NULL };
    const char *plain_args[] = { "commit", "-q", "--no-gpg-sign", "-a",
                                 "--amend", "--no-edit",
                                 NULL };
    if (dlq_git(q, q->exempt ? plain_args : signed_args, NULL, 0) != 0)
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "amend", NULL);
    return true;
}

static bool dlq_status(struct dlq *q, char *out, size_t cap)
{
    const char *args[] = { "status", "--porcelain", "--untracked-files=no",
                           NULL };
    if (dlq_git(q, args, out, cap) != 0)
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "git_status", NULL);
    return true;
}

static bool dlq_clean(struct dlq *q)
{
    char status[4096], paths[1024];
    if (!dlq_status(q, status, sizeof(status)))
        return false;
    if (!status[0])
        return true;
    dlq_porcelain_paths(status, paths, sizeof(paths));
    return dlq_refuse(q, ZCL_LAND_QUALIFY_DIRTY_TREE, "worktree", paths);
}

static bool dlq_fetch(struct dlq *q)
{
    const char *args[] = { "fetch", "-q", "origin", NULL };
    if (dlq_git(q, args, NULL, 0) != 0)
        return dlq_refuse(q, ZCL_LAND_QUALIFY_FETCH_FAILED, "origin", NULL);
    return true;
}

/* Rebase onto origin/main when the lane is behind it. A conflict aborts the
 * rebase and names the unmerged paths; resolving them is the author's. A
 * rebase that fails without unmerged paths (a missing signing key, a hook)
 * is a different refusal, so the author is not sent to look for conflicts. */
static bool dlq_rebase(struct dlq *q)
{
    const char *ancestor[] = { "merge-base", "--is-ancestor", "origin/main",
                               "HEAD", NULL };
    const char *signed_args[] = { "rebase", "-q", "--gpg-sign", "origin/main",
                                  NULL };
    const char *plain_args[] = { "rebase", "-q", "origin/main", NULL };
    const char *unmerged[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    const char *abort_args[] = { "rebase", "--abort", NULL };
    char names[1024];
    if (dlq_git(q, ancestor, NULL, 0) == 0)
        return true;
    if (dlq_git(q, q->exempt ? plain_args : signed_args, NULL, 0) == 0)
        return true;
    (void)dlq_git(q, unmerged, names, sizeof(names));
    (void)dlq_git(q, abort_args, NULL, 0);
    for (char *p = names; *p; p++)
        *p = *p == '\n' ? ' ' : *p;
    return names[0] ? dlq_refuse(q, ZCL_LAND_QUALIFY_REBASE_CONFLICT,
                                 "origin/main", names)
                    : dlq_refuse(q, ZCL_LAND_QUALIFY_REBASE_FAILED,
                                 "origin/main", NULL);
}

/* Every commit the lane adds must carry a good signature. */
static bool dlq_signed(struct dlq *q)
{
    const char *args[] = { "log", "origin/main..HEAD", "--format=%G?", NULL };
    char marks[4096];
    if (q->exempt)
        return true;
    if (dlq_git(q, args, marks, sizeof(marks)) != 0 || !marks[0])
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "no_commits", NULL);
    for (const char *p = marks; *p; p++) {
        if (*p != 'G' && *p != '\n')
            return dlq_refuse(q, ZCL_LAND_QUALIFY_UNSIGNED_TIP,
                              "origin/main..HEAD", NULL);
    }
    return true;
}

/* Fold regenerated tracked files into the tip. Anything else that changed
 * is refused: the qualified tree must be the tree that was gated. */
static bool dlq_fold(struct dlq *q)
{
    char status[4096], paths[1024];
    if (!dlq_status(q, status, sizeof(status)))
        return false;
    if (!status[0])
        return true;
    if (dlq_only_generated(status))
        return dlq_amend(q);
    dlq_porcelain_paths(status, paths, sizeof(paths));
    return dlq_refuse(q, ZCL_LAND_QUALIFY_TREE_CHANGED, "worktree", paths);
}

/* The first line of a failing log that names a failure, for the reply. */
static void dlq_first_fail(const char *text, char *out, size_t cap)
{
    out[0] = '\0';
    for (const char *line = text; line && *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (strncmp(line, "FAIL", 4) == 0) {
            (void)snprintf(out, cap, "%.*s", (int)len, line);
            return;
        }
        line = end ? end + 1 : NULL;
    }
}

static bool dlq_line_starts(const char *text, const char *prefix)
{
    size_t n = strlen(prefix);
    for (const char *line = text; line && *line;) {
        if (strncmp(line, prefix, n) == 0)
            return true;
        line = strchr(line, '\n');
        if (line)
            line++;
    }
    return false;
}

/* Regenerate derived files, then build and install what lint needs. */
static bool dlq_prepare(struct dlq *q)
{
    char jobs[16] = "-j1";
    const char *regen[] = { "docs-capability-inventory", NULL };
    const char *build[] = { jobs, "dev-bin", NULL };
    const char *hooks[] = { "install-hooks", NULL };
    const char *ready[] = { "lint-ready", NULL };
    const struct { const char *name; const char *const *goals; } steps[] = {
        { "docs-capability-inventory", regen },
        { "dev-bin", q->make_jobs[0] ? build + 1 : build },
        { "install-hooks", hooks }, { "lint-ready", ready },
    };
    if (!q->make_jobs[0])
        (void)platform_build_jobs_arg(jobs);
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        char *text = NULL;
        int rc = dlq_make(q, steps[i].name, steps[i].goals, false, &text);
        free(text);
        if (rc != 0)
            return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, steps[i].name,
                              NULL);
        if (i == 0 && !dlq_fold(q))
            return false;
    }
    return true;
}

static bool dlq_lint(struct dlq *q)
{
    const char *goals[] = { "lint", NULL };
    char *text = NULL;
    int rc = dlq_make(q, "lint", goals, true, &text);
    bool passed = rc == 0 && text && strstr(text, "LINT: all checks passed");
    if (!passed && text)
        dlq_first_fail(text, q->out->detail, sizeof(q->out->detail));
    free(text);
    return passed ? true
                  : dlq_refuse(q, ZCL_LAND_QUALIFY_LINT_FAILED, "lint", NULL);
}

static bool dlq_complexity(struct dlq *q)
{
    const char *goals[] = { "check-cyclomatic-complexity", NULL };
    char *text = NULL;
    int rc = dlq_make(q, "complexity", goals, false, &text);
    if (rc != 0 && text)
        dlq_first_fail(text, q->out->detail, sizeof(q->out->detail));
    free(text);
    return rc == 0 ? true
                   : dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED,
                                 "check-cyclomatic-complexity", NULL);
}

static bool dlq_group_add(struct dlq_groups *g, const char *name)
{
    char full[ZCL_TEST_GROUP_FULL_MAX];
    if (!zcl_test_group_resolve_exact(name, full) ||
        strlen(full) >= sizeof(g->name[0]))
        return false;
    for (size_t i = 0; i < g->count; i++) {
        if (strcmp(g->name[i], full) == 0)
            return true;
    }
    if (g->count >= DLQ_GROUPS_MAX)
        return false;
    (void)snprintf(g->name[g->count++], sizeof(g->name[0]), "%s", full);
    return true;
}

static int dlq_group_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

#if defined(ZCL_TESTING)
static void (*g_dlq_route)(const char *path, struct agent_impact_acc *acc);
static size_t g_dlq_capture_cap;

void zcl_dev_land_qualify_test_limits(
    void (*route)(const char *path, struct agent_impact_acc *acc),
    size_t capture_cap)
{
    g_dlq_route = route;
    g_dlq_capture_cap = capture_cap;
}
#endif

static void dlq_route(const char *path, struct agent_impact_acc *acc)
{
    bool risk = false;
#if defined(ZCL_TESTING)
    if (g_dlq_route) {
        g_dlq_route(path, acc);
        return;
    }
#endif
    (void)zcl_native_code_route_for_path(path, acc, &risk);
}

static size_t dlq_capture_cap(void)
{
#if defined(ZCL_TESTING)
    if (g_dlq_capture_cap)
        return g_dlq_capture_cap;
#endif
    return DLQ_GIT_CAP;
}

/* Add one path's routed groups. False when the router dropped any. */
static bool dlq_select_path(struct dlq_groups *g, const char *path)
{
    struct agent_impact_acc acc = {0};
    dlq_route(path, &acc);
    if (acc.groups_lost)
        return false;
    for (size_t i = 0; i < acc.groups_len; i++) {
        if (!dlq_group_add(g, acc.groups[i]))
            return false;
    }
    return true;
}

/* The union of the routes for every path the lane changes. A selection that
 * lost groups, or read a truncated path list, is refused rather than run
 * short.
 *
 * zcl_spawn_capture() does not report overflow: it returns the child's exit
 * status (0 here) and silently keeps only the first cap-1 bytes. A capture
 * whose length reaches cap-1 is therefore treated as truncated, which also
 * refuses a list of exactly cap-1 bytes; refusing is the safe side. */
static bool dlq_select(struct dlq *q, struct dlq_groups *g)
{
    const char *args[] = { "diff", "--name-only", "origin/main...HEAD", NULL };
    size_t cap = dlq_capture_cap();
    char *paths = (char *)zcl_malloc(cap, "dev.land.qualify.paths");
    bool ok = true;
    if (!paths || dlq_git(q, args, paths, cap) != 0) {
        free(paths);
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "group_selection",
                          NULL);
    }
    if (strlen(paths) + 1 >= cap) {
        free(paths);
        return dlq_refuse(q, ZCL_LAND_QUALIFY_GROUP_SELECTION,
                          "path_list_truncated", NULL);
    }
    for (char *line = paths; ok && *line;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = '\0';
        if (!dlq_select_path(g, line))
            ok = dlq_refuse(q, ZCL_LAND_QUALIFY_GROUP_SELECTION, "groups_lost",
                            line);
        line = end ? end + 1 : line + strlen(line);
    }
    free(paths);
    qsort(g->name, g->count, sizeof(g->name[0]), dlq_group_cmp);
    return ok;
}

static bool dlq_group_name_ok(const char *name)
{
    if (!name[0])
        return false;
    for (const char *p = name; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '_'))
            return false;
    }
    return true;
}

/* One group's section of the harness output: the text after its
 * "==== NAME (PASS|FAIL, Ns) ====" header up to the next header. */
struct dlq_section {
    char name[ZCL_AGENT_IMPACT_GROUP_MAX];
    bool seen;
    bool passed;
    const char *begin;
    size_t length;
};

/* Parse a header line into its group name and verdict. */
static bool dlq_header(const char *line, size_t len, char *name, size_t cap,
                       bool *passed)
{
    static const char bar[] = "==================== ";
    const size_t n = sizeof(bar) - 1;
    const char *space;
    size_t width;
    if (len <= n || strncmp(line, bar, n) != 0)
        return false;
    space = memchr(line + n, ' ', len - n);
    if (!space)
        return false;
    width = (size_t)(space - line) - n;
    if (width >= cap || (strncmp(space, " (PASS", 6) != 0 &&
                         strncmp(space, " (FAIL", 6) != 0))
        return false;
    *passed = space[2] == 'P';
    memcpy(name, line + n, width);
    name[width] = '\0';
    return true;
}

static struct dlq_section *dlq_section_for(struct dlq_section *sections,
                                           size_t count, const char *header)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(header, sections[i].name) == 0)
            return &sections[i];
    }
    return NULL;
}

/* Split the harness output into per-group sections and apply the verdict
 * rule: a section passes on a PASS header and no line that begins with
 * "FAIL at". */
static void dlq_sections(const char *text, struct dlq_section *sections,
                         size_t count)
{
    struct dlq_section *current = NULL;
    for (const char *line = text; line && *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        char header[ZCL_AGENT_IMPACT_GROUP_MAX];
        bool passed = false;
        if (dlq_header(line, len, header, sizeof(header), &passed)) {
            if (current)
                current->length = (size_t)(line - current->begin);
            current = dlq_section_for(sections, count, header);
            if (current) {
                current->seen = true;
                current->passed = passed;
                current->begin = line;
            }
        } else if (current && strncmp(line, "FAIL at", 7) == 0) {
            current->passed = false;
        }
        line = end ? end + 1 : NULL;
    }
    if (current)
        current->length = strlen(current->begin);
}

static void dlq_section_log(struct dlq *q, const struct dlq_section *s)
{
    char *copy = (char *)zcl_malloc(s->length + 1, "dev.land.qualify.section");
    char log[ZCL_AGENT_IMPACT_GROUP_MAX + 8];
    if (!copy)
        return;
    memcpy(copy, s->begin, s->length);
    copy[s->length] = '\0';
    (void)snprintf(log, sizeof(log), "group-%s", s->name);
    dlq_write_log(q, log, copy);
    dlq_first_fail(copy, q->out->detail, sizeof(q->out->detail));
    free(copy);
}

/* The first group without a passing verdict, in selection order. */
static bool dlq_judge_groups(struct dlq *q, const struct dlq_groups *g,
                             struct dlq_section *sections)
{
    bool all = true;
    for (size_t i = 0; i < g->count; i++) {
        if (sections[i].seen && sections[i].passed)
            continue;
        if (all) {
            if (sections[i].seen)
                dlq_section_log(q, &sections[i]);
            else
                (void)snprintf(q->out->detail, sizeof(q->out->detail), "%s",
                               "no verdict reported for this group");
            dlq_refuse(q, ZCL_LAND_QUALIFY_GROUP_FAILED, sections[i].name,
                       NULL);
        }
        all = false;
        (void)snprintf(q->out->paths + strlen(q->out->paths),
                       sizeof(q->out->paths) - strlen(q->out->paths), "%s%s",
                       q->out->paths[0] ? " " : "", sections[i].name);
    }
    return all;
}

/* All affected groups in one harness invocation: its workers run the groups
 * in parallel and each reports its own verdict. */
static bool dlq_run_groups(struct dlq *q, const struct dlq_groups *g)
{
    struct dlq_section *sections = (struct dlq_section *)zcl_malloc(
        g->count * sizeof(*sections), "dev.land.qualify.sections");
    char *only = (char *)zcl_malloc(g->count * (ZCL_AGENT_IMPACT_GROUP_MAX + 1) + 8,
                                    "dev.land.qualify.only");
    const char *goals[] = { "t-fast-exact", only, NULL };
    char *text = NULL;
    size_t used = 0;
    int rc = -1;
    bool ok = false;
    if (!sections || !only) {
        free(sections);
        free(only);
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "groups", NULL);
    }
    used = (size_t)sprintf(only, "ONLY=");
    for (size_t i = 0; i < g->count; i++) {
        used += (size_t)sprintf(only + used, "%s%s", i ? "," : "", g->name[i]);
        memset(&sections[i], 0, sizeof(sections[i]));
        (void)snprintf(sections[i].name, sizeof(sections[i].name), "%s",
                       g->name[i]);
    }
    rc = dlq_make(q, "groups", goals, false, &text);
    if (text) {
        dlq_sections(text, sections, g->count);
        ok = dlq_judge_groups(q, g, sections);
        if (ok && !(rc == 0 && dlq_line_starts(text, "ALL TESTS PASSED")))
            ok = dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "t-fast-exact",
                            NULL);
    }
    free(text);
    free(sections);
    free(only);
    return ok;
}

/* Name the selected groups in the result, even when none are routed. */
static void dlq_record_groups(struct dlq *q, const struct dlq_groups *g)
{
    size_t used = 0;
    q->out->group_count = g->count;
    q->out->groups[0] = '\0';
    for (size_t i = 0; i < g->count; i++)
        used += (size_t)snprintf(q->out->groups + used,
                                 sizeof(q->out->groups) - used, "%s%s",
                                 i ? " " : "", g->name[i]);
}

static bool dlq_groups_run(struct dlq *q)
{
    struct dlq_groups *g =
        (struct dlq_groups *)zcl_malloc(sizeof(*g), "dev.land.qualify.groups");
    bool ok = g != NULL;
    if (!ok)
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "groups", NULL);
    g->count = 0;
    ok = dlq_select(q, g);
    for (size_t i = 0; ok && i < g->count; i++) {
        if (!dlq_group_name_ok(g->name[i]))
            ok = dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "group_name",
                            g->name[i]);
    }
    if (ok)
        dlq_record_groups(q, g);
    if (ok && g->count > 0)
        ok = dlq_run_groups(q, g);
    free(g);
    return ok;
}

static bool dlq_finish(struct dlq *q)
{
    const char *rev[] = { "rev-parse", "HEAD", NULL };
    const char *sig[] = { "log", "-1", "--format=%G?", NULL };
    char tip[64], mark[16];
    if (dlq_git(q, rev, tip, sizeof(tip)) != 0 || strlen(tip) < 41)
        return dlq_refuse(q, ZCL_LAND_QUALIFY_STEP_FAILED, "rev_parse", NULL);
    if (!q->exempt && (dlq_git(q, sig, mark, sizeof(mark)) != 0 || mark[0] != 'G'))
        return dlq_refuse(q, ZCL_LAND_QUALIFY_UNSIGNED_TIP, "HEAD", NULL);
    (void)snprintf(q->out->tip, sizeof(q->out->tip), "%.40s", tip);
    return true;
}

bool zcl_dev_land_qualify(const char *wt, bool signing_exempt,
                          struct zcl_land_qualify *out)
{
    struct dlq q = { .wt = wt, .exempt = signing_exempt, .out = out };
    memset(out, 0, sizeof(*out));
    /* An explicit admitted cap controls every Make phase, not only dev-bin. */
    if (getenv("ZCL_BUILD_MAX_JOBS") &&
        !platform_build_jobs_arg(q.make_jobs))
        return dlq_refuse(&q, ZCL_LAND_QUALIFY_STEP_FAILED,
                          "ZCL_BUILD_MAX_JOBS", NULL);
    return dlq_clean(&q) && dlq_fetch(&q) && dlq_rebase(&q) &&
           dlq_signed(&q) && dlq_prepare(&q) && dlq_complexity(&q) && dlq_lint(&q) &&
           dlq_groups_run(&q) && dlq_fold(&q) && dlq_finish(&q);
}
