/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-sqlite-step-row — RATCHET (per-file count, shrink-only
 * baseline). Comparing a SQLite step straight to SQLITE_ROW folds every step
 * error (BUSY, LOCKED, IOERR, CORRUPT, INTERRUPT, MISUSE) into "no row", so a
 * failed read becomes "absent", "empty" or "the scan is complete". The fix is
 * ar_step_checked() in platform/modules/util/include/util/ar_step_readonly.h,
 * which returns ZCL_STEP_ROW, ZCL_STEP_DONE or ZCL_STEP_ERROR.
 *
 * Counted shapes, in code only (comments and string/char literals blanked,
 * whitespace including newlines between tokens): a call of sqlite3_step or
 * of its alias AR_STEP_ROW_READONLY compared with == to SQLITE_ROW, on
 * either side; and any use of the activerecord.h macro AR_STEP_ROW, which
 * is that comparison (its own #define is not a use).
 * A step captured into a variable and tested for both ROW and DONE is the
 * other legal shape and is not counted.
 *
 * Scope: *.c and *.h under core engine contexts cognition platform apps
 * tools, skipping any directory named tests, vendor, build or .git and the
 * generated contexts/commons/corpus. Baseline tools/lint/sqlite_step_row_
 * baseline.txt holds `<path> <count>`: a file whose count grows, or a new
 * file, fails; a file whose count shrank (or that is gone) fails until its
 * row is lowered or deleted, so a fixed site cannot leave headroom behind.
 * ZCL_LINT_MODE=UPDATE regenerates the baseline. Exit 0 clean, 1 violation,
 * 2 fatal. Selftest: gate_sqlite_step_row_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_sqlite_step_row_priv.h"
#include "lint_narrow_hook.h"

static const char k_ssr_gate[] = "check-sqlite-step-row";
static const char k_ssr_base_default[] = "tools/lint/sqlite_step_row_baseline.txt";
static const char *const k_ssr_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "apps", "tools",
    NULL
};
static const char *const k_ssr_skip_dirs[] = {
    "tests", "vendor", "build", ".git"
};

enum { SSR_FILE_MAX = 8 << 20, SSR_SCAN_FLOOR = 1000 };

/* ── lexing: blank comments and literals, keep newlines ─────────────────── */

static size_t ssr_skip_literal(char *b, size_t i, size_t n)
{
    char q = b[i];
    b[i++] = ' ';
    while (i < n && b[i] != q) {
        if (b[i] == '\\' && i + 1 < n) {
            b[i++] = ' ';
        }
        if (b[i] != '\n')
            b[i] = ' ';
        i++;
    }
    if (i < n)
        b[i++] = ' ';
    return i;
}

static size_t ssr_skip_block_comment(char *b, size_t i, size_t n)
{
    b[i] = b[i + 1] = ' ';
    i += 2;
    while (i < n && !(b[i] == '*' && i + 1 < n && b[i + 1] == '/')) {
        if (b[i] != '\n')
            b[i] = ' ';
        i++;
    }
    if (i < n)
        b[i++] = ' ';
    if (i < n)
        b[i++] = ' ';
    return i;
}

/* Skip one preprocessing number so C23 digit separators are not mistaken
 * for the start of a character literal. */
static size_t ssr_skip_number(const char *b, size_t i, size_t n)
{
    i++;
    while (i < n) {
        unsigned char c = (unsigned char)b[i];
        if (isalnum(c) || c == '_' || c == '.') {
            i++;
        } else if (c == 0x27 && i + 1 < n &&
                   (isalnum((unsigned char)b[i + 1]) || b[i + 1] == '_')) {
            i += 2;
        } else if ((c == '+' || c == '-') &&
                   (b[i - 1] == 'e' || b[i - 1] == 'E' ||
                    b[i - 1] == 'p' || b[i - 1] == 'P')) {
            i++;
        } else {
            break;
        }
    }
    return i;
}

static int ssr_number_start(const char *b, size_t i, size_t n)
{
    if (i && (isalnum((unsigned char)b[i - 1]) || b[i - 1] == '_'))
        return 0;
    return isdigit((unsigned char)b[i]) ||
           (b[i] == '.' && i + 1 < n && isdigit((unsigned char)b[i + 1]));
}
void ssr_blank(char *b, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (ssr_number_start(b, i, n)) {
            i = ssr_skip_number(b, i, n);
        } else if (b[i] == 0x22 || b[i] == 0x27) {
            i = ssr_skip_literal(b, i, n);
        } else if (b[i] == '/' && i + 1 < n && b[i + 1] == '*') {
            i = ssr_skip_block_comment(b, i, n);
        } else if (b[i] == '/' && i + 1 < n && b[i + 1] == '/') {
            while (i < n && b[i] != '\n')
                b[i++] = ' ';
        } else {
            i++;
        }
    }
}

/* ── matching ────────────────────────────────────────────────────────────── */

static int ssr_ident(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

static const char *ssr_ws(const char *p)
{
    while (*p && isspace((unsigned char)*p))
        p++;
    return p;
}

/* p at a token start; returns the char after the token when it is exactly
 * `tok` (not a prefix of a longer identifier), else NULL. */
static const char *ssr_tok(const char *p, const char *tok)
{
    size_t n = strlen(tok);
    if (strncmp(p, tok, n) != 0 || ssr_ident(p[n]))
        return NULL;
    return p + n;
}

/* p after the call name: skip `( ... )` with nesting; NULL when unbalanced. */
static const char *ssr_call_args(const char *p)
{
    int depth = 0;
    p = ssr_ws(p);
    if (*p != '(')
        return NULL;
    for (; *p; p++) {
        if (*p == '(')
            depth++;
        else if (*p == ')' && --depth == 0)
            return p + 1;
    }
    return NULL;
}

static const char *ssr_step_call(const char *p)
{
    const char *e = ssr_tok(p, "sqlite3_step");
    if (!e)
        e = ssr_tok(p, "AR_STEP_ROW_READONLY");
    return e ? ssr_call_args(e) : NULL;
}

static const char *ssr_eq(const char *p)
{
    p = ssr_ws(p);
    return (p[0] == '=' && p[1] == '=') ? ssr_ws(p + 2) : NULL;
}

/* True when the token before `at` (within buf) is `define`. */
static int ssr_after_define(const char *buf, const char *at)
{
    const char *q = at;
    while (q > buf && (q[-1] == ' ' || q[-1] == '\t'))
        q--;
    return q - buf >= 6 && strncmp(q - 6, "define", 6) == 0 &&
           (q - 6 == buf || !ssr_ident(q[-7]));
}

static int ssr_match_at(const char *buf, const char *p)
{
    const char *e = ssr_step_call(p);
    if (e) {
        e = ssr_eq(e);
        return e && ssr_tok(e, "SQLITE_ROW") != NULL;
    }
    e = ssr_tok(p, "SQLITE_ROW");
    if (e) {
        e = ssr_eq(e);
        return e && ssr_step_call(e) != NULL;
    }
    e = ssr_tok(p, "AR_STEP_ROW");
    return e && *ssr_ws(e) == '(' && !ssr_after_define(buf, p);
}

int ssr_count(const char *buf)
{
    int n = 0;
    for (const char *p = buf; *p; p++) {
        if (ssr_ident(*p) && (p == buf || !ssr_ident(p[-1])) &&
            ssr_match_at(buf, p))
            n++;
    }
    return n;
}

/* ── the walk ────────────────────────────────────────────────────────────── */

static int ssr_skipped_dir(const char *rel, const char *nm)
{
    for (size_t i = 0; i < sizeof k_ssr_skip_dirs / sizeof k_ssr_skip_dirs[0];
         i++)
        if (strcmp(nm, k_ssr_skip_dirs[i]) == 0)
            return 1;
    return strcmp(rel, "contexts/commons/corpus") == 0;
}

static int ssr_is_source(const char *nm)
{
    size_t n = strlen(nm);
    return n > 2 && nm[n - 2] == '.' && (nm[n - 1] == 'c' || nm[n - 1] == 'h');
}

static int ssr_count_file(const char *path, int *out)
{
    FILE *f = fopen(path, "rb");
    static char buf[SSR_FILE_MAX + 1];
    *out = 0;
    if (!f)
        return die("z23-lint: check-sqlite-step-row: cannot read %s\n", path);
    size_t n = fread(buf, 1, SSR_FILE_MAX, f);
    int big = n == SSR_FILE_MAX && fgetc(f) != EOF;
    int err = ferror(f);
    fclose(f);
    if (err || big)
        return die("z23-lint: check-sqlite-step-row: read failed or file "
                   "too large: %s\n", path);
    buf[n] = '\0';
    ssr_blank(buf, n);
    *out = ssr_count(buf);
    return 0;
}

struct ssr_walk { const char *root; struct ssr_set *live; int files; };

static int ssr_walk_dir(struct ssr_walk *w, const char *rel);

static int ssr_walk_entry(struct ssr_walk *w, const char *rel, const char *nm)
{
    char relp[RS_PATH], full[4096];
    struct stat st;
    if (ovf(snprintf(relp, sizeof relp, "%s/%s", rel, nm), sizeof relp) ||
        ovf(snprintf(full, sizeof full, "%s/%s", w->root, relp), sizeof full))
        return die("z23-lint: check-sqlite-step-row: path too long: %s\n", nm);
    if (lstat(full, &st) != 0)
        return die("z23-lint: check-sqlite-step-row: cannot stat %s\n", full);
    if (S_ISDIR(st.st_mode))
        return ssr_skipped_dir(relp, nm) ? 0 : ssr_walk_dir(w, relp);
    if (!S_ISREG(st.st_mode) || !ssr_is_source(nm))
        return 0;
    int count = 0;
    int rc = ssr_count_file(full, &count);
    w->files++;
    return rc ? rc : count > 0 ? ssr_set_put(w->live, relp, count) : 0;
}

static int ssr_walk_dir(struct ssr_walk *w, const char *rel)
{
    char full[4096];
    struct dirent **names = NULL;
    if (ovf(snprintf(full, sizeof full, "%s/%s", w->root, rel), sizeof full))
        return die("z23-lint: check-sqlite-step-row: path too long: %s\n", rel);
    int cnt = scandir(full, &names, NULL, alphasort);
    if (cnt < 0)
        return errno == ENOENT ? 0
             : die("z23-lint: check-sqlite-step-row: cannot scan %s\n", full);
    int rc = 0;
    for (int i = 0; i < cnt; i++) {
        const char *nm = names[i]->d_name;
        if (rc == 0 && strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0)
            rc = ssr_walk_entry(w, rel, nm);
        free(names[i]);
    }
    free(names);
    return rc;
}

int ssr_collect(const char *root, struct ssr_set *live, int *files)
{
    struct ssr_walk w = { root, live, 0 };
    live->n = 0;
    for (size_t i = 0; k_ssr_roots[i]; i++) {
        int rc = ssr_walk_dir(&w, k_ssr_roots[i]);
        if (rc)
            return rc;
    }
    *files = w.files;
    return 0;
}

/* ── the gate ────────────────────────────────────────────────────────────── */

/* ssr_path_form/ssr_under_roots bodies live in the shared narrowing hooks
 * (lint_narrow_hook.h). */

static int ssr_changed_excluded(const char *path)
{
    static const char *const parts[] = { "/tests/", "/vendor/", "/build/", "/.git/" };
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++)
        if (strstr(path, parts[i]) != NULL)
            return 1;
    return strncmp(path, "contexts/commons/corpus/",
                   sizeof "contexts/commons/corpus/" - 1) == 0;
}

static int ssr_changed_file(const char *root, const char *path,
                            struct ssr_set *live, int *files)
{
    char full[4096];
    struct stat st;
    if (ovf(snprintf(full, sizeof full, "%s/%s", root, path), sizeof full))
        return die("z23-lint: check-sqlite-step-row: path too long: %s\n", path);
    if (lstat(full, &st) != 0)
        return errno == ENOENT ? 0
             : die("z23-lint: check-sqlite-step-row: cannot stat %s\n", full);
    if (!S_ISREG(st.st_mode))
        return 0;
    int count = 0;
    int rc = ssr_count_file(full, &count);
    (*files)++;
    return rc ? rc : count > 0 ? ssr_set_put(live, path, count) : 0;
}

/* ── the shared narrowing hooks (lint_narrow_hook.h) ───────────────────── */

struct ssr_narrow {
    const char *root;
    struct ssr_set *live;
    int *files;
};

static int ssr_collect_skip(void *vctx, const char *path)
{
    (void)vctx;
    const char *slash = strrchr(path, '/');
    const char *nm = slash ? slash + 1 : path;
    return !lint_narrow_roots_prefix(path, k_ssr_roots) ||
           ssr_changed_excluded(path) ||
           !ssr_is_source(nm);
}

static int ssr_collect_emit(void *vctx, const char *path)
{
    struct ssr_narrow *c = vctx;
    return ssr_changed_file(c->root, path, c->live, c->files);
}

static const char *g_ssr_narrow_repo;

static int ssr_key_match(const char *key, const char *path)
{
    return strcmp(key, lint_narrow_repo_form(path, g_ssr_narrow_repo)) == 0;
}

static const struct lint_narrow_gate k_ssr_narrow_gate = {
    k_ssr_gate, NULL, lint_narrow_repo_form, NULL, NULL, ssr_collect_skip, 0
};

int ssr_collect_changed(const char *root, const struct lint_changed *ch,
                        struct ssr_set *live, int *files)
{
    char repo[4096];
    struct ssr_narrow ctx = { root, live, files };
    live->n = 0;
    *files = 0;
    return lint_narrow_collect(ch, repo, &k_ssr_narrow_gate, ssr_collect_emit,
                               &ctx);
}

int ssr_base_narrow(struct ssr_set *base, const struct lint_changed *ch)
{
    char repo[4096];
    if (cic_repo_root(repo, sizeof repo) != 0)
        return 2;
    g_ssr_narrow_repo = repo;
    base->n = lint_narrow_filter_keys((const char *const *)ch->path, ch->n,
                                      (const char **)base->rows, base->n,
                                      (int)sizeof base->rows[0], ssr_key_match);
    g_ssr_narrow_repo = NULL;
    return 0;
}

int ssr_narrow_ok(const struct lint_changed *ch, const char *baseline)
{
    return lint_narrow_ok(ch, baseline, &k_ssr_narrow_gate);
}

static int ssr_scan(int narrow, const struct lint_changed *ch,
                    struct ssr_set *live, int *files)
{
    int rc;
    if (narrow) {
        rc = ssr_collect_changed(".", ch, live, files);
        if (rc == 0 && lint_examined_print(*files, 0) < 0)
            rc = 2;
        return rc;
    }
    rc = ssr_collect(".", live, files);
    if (rc)
        return rc;
    return gate_require_scanned(*files, SSR_SCAN_FLOOR, k_ssr_gate,
                                "no .c/.h under core engine contexts cognition "
                                "platform apps tools");
}

int check_sqlite_step_row_run(int argc, char **argv)
{
    static struct ssr_set live, base;
    int files = 0;
    struct lint_changed ch;
    if (lint_changed_bind(&argc, &argv, &ch) != 0)
        return 2;
    const char *mode = clock_mode();
    if (ch.active && strcmp(mode, "UPDATE") == 0) {
        fputs("check-sqlite-step-row: --changed-files cannot rewrite the baseline\n",
              stderr);
        lint_changed_free(&ch);
        return 2;
    }
    int narrow = ssr_narrow_ok(&ch, k_ssr_base_default);
    int rc = ssr_scan(narrow, &ch, &live, &files);
    if (rc == 0 && strcmp(mode, "UPDATE") == 0) {
        lint_changed_free(&ch);
        return ssr_write_baseline(&live, k_ssr_base_default, stdout);
    }
    if (rc == 0)
        rc = ssr_load_baseline(&base, k_ssr_base_default);
    if (rc == 0 && narrow)
        rc = ssr_base_narrow(&base, &ch);
    lint_changed_free(&ch);
    if (rc)
        return rc;
    return ssr_report(&live, &base, k_ssr_base_default, files, stdout);
}
