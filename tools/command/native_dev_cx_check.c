/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.cx.check. Verifies one complexity-split unit in a worktree and,
 *          when it passes, applies the baseline tighten there (rows only
 *          deleted). Each failure carries one named code: CX_SCOPE,
 *          CX_COMPILE, CX_BASELINE_ADDED, CX_STILL_OVER, CX_GATE. The metric
 *          is the lane's own build/bin/z23-lint check-cyclomatic-complexity;
 *          nothing is reimplemented and no shell runs. A failed check leaves
 *          the baseline byte-for-byte as it was. Ports cx-swarm's check(). */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_dev_cx.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CK_MAX_FUNCS 32
#define CK_LOG_CAP (256u * 1024u)
#define CK_MAKE_MS 180000
#define CK_CC_MS 300000
#define CK_LINT_MS 300000
#define CK_MAX_INCLUDES 1024
#define CK_SHOW 5

struct cx_check {
    char wt[ZCL_CX_PATH_MAX];
    char file[ZCL_CX_FILE_MAX];
    char lint[ZCL_CX_PATH_MAX];
    char base[ZCL_CX_PATH_MAX];
    char fnbuf[1024];
    const char *fn[CK_MAX_FUNCS];
    size_t nfn;
    char *log;
    char *old_text;
    size_t old_len;
    struct cx_set old_rows, new_rows;
    char detail[1024];
};

typedef const char *(*cx_step_fn)(struct cx_check *);

static void ck_reply_fail(struct zcl_command_reply *reply, const char *code,
                          const char *msg, const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "dev.cx.check", false,
                           false, msg, detail);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_cx_check.v1");
    (void)json_push_kv_str(&reply->data, "verdict", "fail");
    (void)json_push_kv_str(&reply->data, "code", code);
    (void)json_push_kv_str(&reply->data, "detail", detail);
}

/* ── input ───────────────────────────────────────────────────────────────── */

static bool ck_safe_chars(const char *s, const char *extra)
{
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
              (*s >= '0' && *s <= '9') || strchr(extra, *s)))
            return false;
    return true;
}

static bool ck_file_ok(const char *f)
{
    size_t n = strlen(f);
    return n > 2 && n < ZCL_CX_FILE_MAX && f[0] != '/' && !strstr(f, "..") &&
           ck_safe_chars(f, "_./+-") && strcmp(f + n - 2, ".c") == 0;
}

static bool ck_split_funcs(struct cx_check *ck, const char *csv)
{
    if (!csv[0] || snprintf(ck->fnbuf, sizeof(ck->fnbuf), "%s", csv) >=
                       (int)sizeof(ck->fnbuf))
        return false;
    for (char *p = ck->fnbuf; *p;) {
        char *end = p + strcspn(p, ",");
        bool last = *end == '\0';
        *end = '\0';
        if (!*p || !ck_safe_chars(p, "_#") || ck->nfn == CK_MAX_FUNCS)
            return false;
        ck->fn[ck->nfn++] = p;
        p = last ? end : end + 1;
    }
    return ck->nfn > 0;
}

static bool ck_args(const struct json_value *in, struct cx_check *ck,
                    char *wt_in)
{
    const char *wt = in ? json_get_str(json_get(in, "worktree")) : NULL;
    const char *file = in ? json_get_str(json_get(in, "file")) : NULL;
    const char *fns = in ? json_get_str(json_get(in, "functions")) : NULL;
    if (!wt || !wt[0] || !file || !fns || !ck_file_ok(file) ||
        snprintf(wt_in, ZCL_CX_PATH_MAX, "%s", wt) >= ZCL_CX_PATH_MAX)
        return false;
    (void)snprintf(ck->file, sizeof(ck->file), "%s", file);
    return ck_split_funcs(ck, fns);
}

/* worktree must be the top of a git worktree; the lane needs its z23-lint. */
static const char *ck_worktree(struct cx_check *ck, const char *wt_in)
{
    char top[ZCL_CX_PATH_MAX], real_top[PATH_MAX];
    const char *argv[] = {"git", "rev-parse", "--show-toplevel", NULL};
    if (!realpath(wt_in, ck->wt) ||
        cx_run(ck->wt, argv, top, sizeof(top), 30000, false) != 0) {
        (void)snprintf(ck->detail, sizeof(ck->detail), "%s", wt_in);
        return "CX_BAD_WORKTREE";
    }
    top[strcspn(top, "\r\n")] = '\0';
    if (!realpath(top, real_top) || strcmp(real_top, ck->wt) != 0) {
        (void)snprintf(ck->detail, sizeof(ck->detail),
                       "not the top of a git worktree: %s", ck->wt);
        return "CX_BAD_WORKTREE";
    }
    (void)snprintf(ck->lint, sizeof(ck->lint), "%s/build/bin/z23-lint", ck->wt);
    (void)snprintf(ck->base, sizeof(ck->base), "%s/%s", ck->wt,
                   ZCL_CX_BASELINE_REL);
    if (access(ck->lint, X_OK) != 0) {
        (void)snprintf(ck->detail, sizeof(ck->detail),
                       "%s is missing; build it in the lane", ck->lint);
        return "CX_NO_LINT";
    }
    return NULL;
}

/* ── steps ───────────────────────────────────────────────────────────────── */

static void ck_list_paths(struct cx_check *ck, const char *prefix,
                          const char *text)
{
    size_t used = (size_t)snprintf(ck->detail, sizeof(ck->detail), "%s", prefix);
    for (const char *p = text; *p && used < sizeof(ck->detail) - 2;) {
        size_t n = strcspn(p, "\n");
        int w = snprintf(ck->detail + used, sizeof(ck->detail) - used, " %.*s",
                         (int)n, p);
        if (w < 0)
            break;
        used += (size_t)w;
        p += n + (p[n] == '\n' ? 1 : 0);
    }
}

/* Counts the status lines of text; *only is the path of the last one. */
static size_t ck_status_lines(const char *text, const char **only)
{
    size_t lines = 0;
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        if (n >= 4) {
            lines++;
            *only = p + 3;
        }
        p += n + (p[n] ? 1 : 0);
    }
    return lines;
}

/* CX_SCOPE: the working diff must be exactly the one named file. */
static const char *ck_step_scope(struct cx_check *ck)
{
    const char *argv[] = {"git", "-c", "core.quotepath=off", "status",
                          "--porcelain", "-uall", NULL};
    const char *only = NULL;
    size_t lines, flen = strlen(ck->file);
    if (cx_run(ck->wt, argv, ck->log, CK_LOG_CAP, 60000, false) != 0) {
        (void)snprintf(ck->detail, sizeof(ck->detail), "git status failed");
        return "CX_SCOPE";
    }
    lines = ck_status_lines(ck->log, &only);
    if (lines == 1 && strncmp(only - 3, "??", 2) != 0 &&
        strncmp(only, ck->file, flen) == 0 &&
        (only[flen] == '\n' || only[flen] == '\0'))
        return NULL;
    ck_list_paths(ck, lines ? "the diff must touch only the target file; it touches:"
                            : "the diff is empty; edit the target file:",
                  ck->log);
    return "CX_SCOPE";
}

static bool ck_has_include_flag(const char *p, size_t n)
{
    for (size_t i = 0; i + 1 < n; i++)
        if (p[i] == '-' && p[i + 1] == 'I')
            return true;
    return false;
}

/* The last line of text that carries an include flag, copied to inc. */
static bool ck_last_include_line(const char *text, char *inc, size_t cap)
{
    const char *best = NULL;
    size_t best_len = 0;
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        if (ck_has_include_flag(p, n)) {
            best = p;
            best_len = n;
        }
        p += n + (p[n] ? 1 : 0);
    }
    return best && best_len < cap &&
           snprintf(inc, cap, "%.*s", (int)best_len, best) < (int)cap;
}

static bool ck_make_includes(struct cx_check *ck, char *inc, size_t cap)
{
    const char *argv[] = {"make", "-s", "print-includes", NULL};
    return cx_run(ck->wt, argv, ck->log, CK_LOG_CAP, CK_MAKE_MS, false) == 0 &&
           ck_last_include_line(ck->log, inc, cap);
}

/* Appends the whitespace-separated tokens of text (edited in place). */
static size_t ck_tokens(char *text, const char **argv, size_t n, size_t max)
{
    for (char *p = text; *p && n < max;) {
        while (*p == ' ' || *p == '\t')
            *p++ = '\0';
        if (*p)
            argv[n++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
    }
    return n;
}

/* CX_COMPILE: the file builds as C23 with the bridge's flags and the
 * Makefile's own include set (make print-includes). */
static const char *ck_step_compile(struct cx_check *ck)
{
    static const char *const fixed[] = {
        "gcc", "-std=c23", "-c", "-o", "/dev/null", "-O2",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2", "-Wall", "-Wextra",
        "-Werror", "-Wno-format-truncation", "-D_DEFAULT_SOURCE",
        "-DZCL_TESTING"
    };
    const size_t nfixed = sizeof(fixed) / sizeof(*fixed);
    char inc[65536];
    const char *argv[CK_MAX_INCLUDES + 24];
    size_t n = 0;
    if (!ck_make_includes(ck, inc, sizeof(inc))) {
        (void)snprintf(ck->detail, sizeof(ck->detail),
                       "make -s print-includes gave no include flags");
        return "CX_COMPILE";
    }
    for (; n < nfixed; n++)
        argv[n] = fixed[n];
    n = ck_tokens(inc, argv, n, CK_MAX_INCLUDES);
    argv[n++] = "-I./tools";
    argv[n++] = "-I./tools/acme";
    argv[n++] = ck->file;
    argv[n] = NULL;
    if (cx_run(ck->wt, argv, ck->log, CK_LOG_CAP, CK_CC_MS, true) == 0)
        return NULL;
    (void)snprintf(ck->detail, sizeof(ck->detail), "%.900s", ck->log);
    return "CX_COMPILE";
}

/* Runs the tighten and loads both row sets; the old bytes stay in ck so any
 * later failure can put the baseline back exactly. */
static const char *ck_step_tighten(struct cx_check *ck)
{
    const char *argv[] = {ck->lint, "check-cyclomatic-complexity",
                          "--tighten-baseline", NULL};
    char *fresh;
    ck->old_text = cx_read_file(ck->base, &ck->old_len);
    if (!ck->old_text || !cx_set_add_lines(&ck->old_rows, ck->old_text)) {
        (void)snprintf(ck->detail, sizeof(ck->detail), "cannot read %s",
                       ZCL_CX_BASELINE_REL);
        return "CX_GATE";
    }
    (void)cx_run(ck->wt, argv, ck->log, CK_LOG_CAP, CK_LINT_MS, true);
    fresh = cx_read_file(ck->base, NULL);
    if (!fresh || !cx_set_add_lines(&ck->new_rows, fresh)) {
        free(fresh);
        (void)snprintf(ck->detail, sizeof(ck->detail),
                       "cannot read the tightened baseline");
        return "CX_GATE";
    }
    free(fresh);
    return NULL;
}

/* CX_BASELINE_ADDED: any row in the tightened file that was not there. */
static const char *ck_step_added(struct cx_check *ck)
{
    size_t added = 0;
    const char *first = NULL;
    for (size_t i = 0; i < ck->new_rows.n; i++) {
        if (cx_set_has(&ck->old_rows, ck->new_rows.v[i]))
            continue;
        added++;
        if (!first)
            first = ck->new_rows.v[i];
    }
    if (added == 0)
        return NULL;
    (void)snprintf(ck->detail, sizeof(ck->detail),
                   "the change adds complexity baseline rows (%zu), first: %s",
                   added, first);
    return "CX_BASELINE_ADDED";
}

static bool ck_row_listed(const struct cx_check *ck, const struct cx_row *r)
{
    if (strcmp(r->file, ck->file) != 0)
        return false;
    for (size_t k = 0; k < ck->nfn; k++)
        if (strcmp(r->fn, ck->fn[k]) == 0)
            return true;
    return false;
}

/* CX_STILL_OVER: a listed function still has a pinned row. */
static const char *ck_step_still_over(struct cx_check *ck)
{
    size_t used = 0, found = 0;
    for (size_t i = 0; i < ck->new_rows.n; i++) {
        struct cx_row r;
        if (!cx_row_parse(ck->new_rows.v[i], strlen(ck->new_rows.v[i]), &r) ||
            !ck_row_listed(ck, &r))
            continue;
        int w = snprintf(ck->detail + used, sizeof(ck->detail) - used,
                         "%s%s:%d", found ? " " : "", r.fn, r.score);
        found++;
        if (w > 0 && used + (size_t)w < sizeof(ck->detail))
            used += (size_t)w;
    }
    if (!found)
        return NULL;
    (void)snprintf(ck->detail + used, sizeof(ck->detail) - used,
                   " still above %d", ZCL_CX_CAP);
    return "CX_STILL_OVER";
}

static void ck_tail(struct cx_check *ck)
{
    const char *at = ck->log + strlen(ck->log);
    int lines = 0;
    while (at > ck->log && lines < 8) {
        at--;
        lines += *at == '\n' && at[1] != '\0';
    }
    (void)snprintf(ck->detail, sizeof(ck->detail), "%.900s",
                   *at == '\n' ? at + 1 : at);
}

/* CX_GATE: the full complexity gate over the tightened baseline. */
static const char *ck_step_gate(struct cx_check *ck)
{
    const char *argv[] = {ck->lint, "check-cyclomatic-complexity", NULL};
    if (cx_run(ck->wt, argv, ck->log, CK_LOG_CAP, CK_LINT_MS, true) == 0)
        return NULL;
    ck_tail(ck);
    return "CX_GATE";
}

static const cx_step_fn k_steps[] = {
    ck_step_scope, ck_step_compile, ck_step_tighten, ck_step_added,
    ck_step_still_over, ck_step_gate
};

/* ── reply ───────────────────────────────────────────────────────────────── */

static bool ck_pass(struct zcl_command_reply *reply, const struct cx_check *ck)
{
    struct json_value fns, gone, s;
    bool ok = true;
    json_init(&fns);
    json_set_array(&fns);
    json_init(&gone);
    json_set_array(&gone);
    for (size_t i = 0; ok && i < ck->nfn; i++) {
        json_init(&s);
        json_set_str(&s, ck->fn[i]);
        ok = json_push_back(&fns, &s);
        json_free(&s);
    }
    for (size_t i = 0; ok && i < ck->old_rows.n; i++) {
        if (cx_set_has(&ck->new_rows, ck->old_rows.v[i]))
            continue;
        json_init(&s);
        json_set_str(&s, ck->old_rows.v[i]);
        ok = json_push_back(&gone, &s);
        json_free(&s);
    }
    json_set_object(&reply->data);
    ok = ok && json_push_kv_str(&reply->data, "schema", "zcl.dev_cx_check.v1") &&
         json_push_kv_str(&reply->data, "verdict", "pass") &&
         json_push_kv_str(&reply->data, "file", ck->file) &&
         json_push_kv(&reply->data, "functions", &fns) &&
         json_push_kv(&reply->data, "rows_deleted", &gone);
    json_free(&fns);
    json_free(&gone);
    return ok;
}

/* Puts the baseline back; false when the bytes could not be written. */
static bool ck_restore(const struct cx_check *ck)
{
    return !ck->old_text || cx_write_file(ck->base, ck->old_text, ck->old_len);
}

static const char *ck_run_steps(struct cx_check *ck)
{
    for (size_t i = 0; i < sizeof(k_steps) / sizeof(*k_steps); i++) {
        const char *code = k_steps[i](ck);
        if (code)
            return code;
    }
    return NULL;
}

static void ck_free(struct cx_check *ck)
{
    cx_set_free(&ck->old_rows);
    cx_set_free(&ck->new_rows);
    free(ck->old_text);
    free(ck->log);
    free(ck);
}

/* Restores the baseline after a failure; a failed restore is its own code. */
static const char *ck_unwind(struct cx_check *ck, const char *code)
{
    size_t used;
    if (ck_restore(ck))
        return code;
    used = strlen(ck->detail);
    (void)snprintf(ck->detail + used, sizeof(ck->detail) - used,
                   "%s%s was NOT restored; run git checkout on it (was %s)",
                   used ? "; " : "", ZCL_CX_BASELINE_REL, code);
    return "CX_RESTORE_FAILED";
}

void zcl_native_handle_dev_cx_check(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    struct cx_check *ck = zcl_calloc(1, sizeof(*ck), "dev_cx.check");
    char wt_in[ZCL_CX_PATH_MAX];
    const char *code;
    if (ck)
        ck->log = zcl_malloc(CK_LOG_CAP, "dev_cx.check.log");
    if (!ck || !ck->log) {
        ck_reply_fail(reply, "CX_NO_MEMORY", "cannot allocate the check", "");
        if (ck)
            ck_free(ck);
        return;
    }
    if (!ck_args(request ? request->input : NULL, ck, wt_in))
        code = "CX_BAD_INPUT";
    else
        code = ck_worktree(ck, wt_in);
    if (!code)
        code = ck_run_steps(ck);
    if (!code && !ck_pass(reply, ck))
        code = "CX_NO_MEMORY";
    if (code) {
        code = ck_unwind(ck, code);
        ck_reply_fail(reply, code, "dev.cx.check refused the unit",
                      ck->detail[0] ? ck->detail
                                    : "worktree, file (a .c path) and functions "
                                      "(comma list) are required");
    }
    ck_free(ck);
}
