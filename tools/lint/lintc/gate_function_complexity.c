/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — per-function cyclomatic complexity for the C23
 * lint runtime (check-cyclomatic-complexity). Counts decision points
 * (if/for/while/case keywords, && and || operators, ternary ?) inside each
 * C function definition after stripping comments and string/char literals,
 * and enforces cap 15 against the shrink-only exact-pin baseline at
 * tools/lint/cyclomatic_complexity_baseline.txt.
 *
 * Gate: check-cyclomatic-complexity
 * Metric: M = 1 + decision points per function definition. else, default
 * and goto do not add. A definition opens when { appears at file scope and
 * the declarator head before it ends in ) whose outermost (...) group is
 * preceded by an identifier other than if/for/while/switch; prototypes end
 * in ; and never open a body. Preprocessor lines are lexed for comments
 * and literals but contribute neither decision points nor braces.
 * Baseline semantics (only-gets-simpler ratchet): an over-cap function not
 * pinned fails; a pin whose function grew fails; a pin whose function
 * shrank fails and asks for the ratchet-down; a pin for a function that no
 * longer exists fails as stale. Exact pins pass.
 * Modes (ZCL_LINT_MODE, default RATCHET): WARN reports and exits 0;
 * RATCHET enforces the baseline; FAIL fails every over-cap function and
 * ignores the baseline.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"

enum { CYC_MAX = 15, CYC_NAME = 96, CYC_TOP = 20 };
enum { LX_CODE = 0, LX_LINE, LX_BLOCK, LX_STR, LX_CHR };

static const char k_cyc_base_rel[] =
    "tools/lint/cyclomatic_complexity_baseline.txt";
static const char k_cyc_ls[] = "git ls-files -z -- '*.c'";

/* ── the lexer ───────────────────────────────────────────────────────────
 * One pass over the stripped stream, char by char. Comments and string/char
 * literals are tracked exactly (escapes honoured) so a `?` inside a string
 * or an `if` inside a comment counts nothing. Brace depth finds function
 * bodies; the declarator head is tracked only at file scope. */

struct cyc_lx {
    int state, esc, pp, sol;
    int brace, paren;
    int in_func, m, func_line;
    char func_name[CYC_NAME];
    char tok[CYC_NAME];
    int toklen, tok_ovf;
    char last_tok[CYC_NAME];
    int last_sig;          /* significant char, or 'i' for an identifier */
    int head_ok, head_line;
    char head_name[CYC_NAME];
    char cand[CYC_NAME];
    int cand_ok, cand_line;
    int amp, bar;
};

static int cyc_is_ident(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_';
}

static int cyc_is_kw(const char *t, const char *kw)
{
    return strcmp(t, kw) == 0;
}

static void cyc_tok_end(struct cyc_lx *lx)
{
    if (lx->toklen <= 0)
        return;
    if (!lx->tok_ovf) {
        lx->tok[lx->toklen] = '\0';
        if (lx->in_func && !lx->pp
            && (cyc_is_kw(lx->tok, "if") || cyc_is_kw(lx->tok, "for")
                || cyc_is_kw(lx->tok, "while") || cyc_is_kw(lx->tok, "case")))
            lx->m++;
        memcpy(lx->last_tok, lx->tok, (size_t)lx->toklen + 1);
        lx->last_sig = 'i';
    }
    lx->toklen = 0;
    lx->tok_ovf = 0;
}

struct cyc_emit {
    int (*on_func)(const char *path, const char *name, int line, int m,
                   void *ctx);
    void *ctx;
    const char *path;
};

static int cyc_close_func(struct cyc_lx *lx, const struct cyc_emit *em)
{
    int rc = em->on_func(em->path, lx->func_name, lx->func_line, lx->m,
                         em->ctx);
    lx->in_func = 0;
    return rc;
}

/* The same name may be defined more than once in one file (platform #ifdef
 * variants — the lexer parses every branch on every host, so occurrence
 * order is stable). Repeat definitions are keyed name#2, name#3, ... so a
 * baseline pin stays an exact path:function:M match. The name table is
 * static storage reset per file (the runtime is single-threaded); it must
 * hold every distinct function name in the largest translation unit. */
enum { CYC_OCC_MAX = 8192 };
static char g_occ_names[CYC_OCC_MAX][CYC_NAME];
static int g_occ_count[CYC_OCC_MAX];

struct cyc_occ {
    int (*on_func)(const char *, const char *, int, int, void *);
    void *ctx;
    int n;
};

static int cyc_occ_emit(const char *path, const char *name, int line, int m,
                        void *ctx)
{
    struct cyc_occ *o = ctx;
    int idx = -1;
    for (int i = 0; i < o->n; i++)
        if (strcmp(g_occ_names[i], name) == 0) {
            idx = i;
            break;
        }
    if (idx < 0) {
        if (o->n >= CYC_OCC_MAX || strlen(name) >= CYC_NAME)
            return die("z23-lint: too many function definitions: %s\n",
                       path);
        idx = o->n++;
        memcpy(g_occ_names[idx], name, strlen(name) + 1);
        g_occ_count[idx] = 0;
    }
    g_occ_count[idx]++;
    if (g_occ_count[idx] == 1)
        return o->on_func(path, name, line, m, o->ctx);
    char disp[CYC_NAME + 16];
    if (ovf(snprintf(disp, sizeof disp, "%s#%d", name, g_occ_count[idx]),
            sizeof disp))
        return 2;
    return o->on_func(path, disp, line, m, o->ctx);
}

/* Code-state handlers, one small helper per significant character so no
 * single function carries the whole decision load. */

static void cyc_ident_char(struct cyc_lx *lx, char c)
{
    if (lx->toklen >= 0) {
        if (lx->toklen >= CYC_NAME - 1) {
            lx->tok_ovf = 1;
            lx->toklen = -1;
        } else {
            lx->tok[lx->toklen++] = c;
        }
    }
    lx->sol = 0;
}

static void cyc_c_lparen(struct cyc_lx *lx, int lineno)
{
    if (!lx->pp && lx->brace == 0 && lx->paren == 0) {
        lx->cand_ok = lx->last_sig == 'i'
            && !cyc_is_kw(lx->last_tok, "if")
            && !cyc_is_kw(lx->last_tok, "for")
            && !cyc_is_kw(lx->last_tok, "while")
            && !cyc_is_kw(lx->last_tok, "switch");
        memcpy(lx->cand, lx->last_tok, sizeof lx->cand);
        lx->cand_line = lineno;
    }
    if (!lx->pp)
        lx->paren++;
}

static void cyc_c_rparen(struct cyc_lx *lx)
{
    if (!lx->pp && lx->paren > 0) {
        lx->paren--;
        if (lx->brace == 0 && lx->paren == 0) {
            lx->head_ok = lx->cand_ok;
            memcpy(lx->head_name, lx->cand, sizeof lx->head_name);
            lx->head_line = lx->cand_line;
        }
    }
}

static void cyc_c_lbrace(struct cyc_lx *lx)
{
    if (!lx->pp && lx->brace == 0) {
        if (lx->head_ok && lx->last_sig == ')') {
            lx->in_func = 1;
            lx->m = 1;
            lx->func_line = lx->head_line;
            memcpy(lx->func_name, lx->head_name, sizeof lx->func_name);
        }
        lx->head_ok = 0;
    }
    if (!lx->pp)
        lx->brace++;
}

static int cyc_c_rbrace(struct cyc_lx *lx, const struct cyc_emit *em)
{
    if (lx->pp)
        return 0;
    lx->brace--;
    if (lx->in_func && lx->brace == 0)
        return cyc_close_func(lx, em);
    return 0;
}

static void cyc_c_semi(struct cyc_lx *lx)
{
    if (!lx->pp && lx->brace == 0 && lx->paren == 0)
        lx->head_ok = 0;
}

static void cyc_c_amp(struct cyc_lx *lx)
{
    if (lx->amp && lx->in_func && !lx->pp)
        lx->m++;
    lx->amp = !lx->amp;
    lx->bar = 0;
}

static void cyc_c_bar(struct cyc_lx *lx)
{
    if (lx->bar && lx->in_func && !lx->pp)
        lx->m++;
    lx->bar = !lx->bar;
    lx->amp = 0;
}

static void cyc_c_quest(struct cyc_lx *lx)
{
    if (lx->in_func && !lx->pp)
        lx->m++;
    lx->amp = 0;
    lx->bar = 0;
}

static void cyc_c_other(struct cyc_lx *lx)
{
    lx->amp = 0;
    lx->bar = 0;
    if (!lx->pp && lx->brace == 0 && lx->paren == 0)
        lx->head_ok = 0;
}

static int cyc_punct(struct cyc_lx *lx, const struct cyc_emit *em,
                     char c, int lineno)
{
    switch (c) {
    case '(': cyc_c_lparen(lx, lineno); break;
    case ')': cyc_c_rparen(lx); break;
    case '{': cyc_c_lbrace(lx); break;
    case '}': {
        int rc = cyc_c_rbrace(lx, em);
        if (rc)
            return rc;
        break;
    }
    case ';': cyc_c_semi(lx); break;
    case '&': cyc_c_amp(lx); break;
    case '|': cyc_c_bar(lx); break;
    case '?': cyc_c_quest(lx); break;
    default: cyc_c_other(lx); break;
    }
    lx->last_sig = c;
    return 0;
}

/* Feed one code-state character. Returns 0 or the callback/die rc. */
static int cyc_code_char(struct cyc_lx *lx, const struct cyc_emit *em,
                         char c, int lineno)
{
    if (lx->sol && c == '#')
        lx->pp = 1;
    if (cyc_is_ident((unsigned char)c)) {
        cyc_ident_char(lx, c);
        return 0;
    }
    cyc_tok_end(lx);
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        return 0;
    lx->sol = 0;
    return cyc_punct(lx, em, c, lineno);
}

/* End-of-line: a trailing backslash splices line comments, literals, and
 * preprocessor directives onto the next line; anything else resets them. */
static void cyc_eol(struct cyc_lx *lx, const char *line, ssize_t n)
{
    int bs = 0;
    if (n >= 2 && line[n - 1] == '\n')
        bs = line[n - 2] == '\\';
    else if (n >= 1 && line[n - 1] != '\n')
        bs = line[n - 1] == '\\';
    if (lx->state == LX_LINE && !bs)
        lx->state = LX_CODE;
    if (lx->state == LX_CODE || lx->state == LX_LINE)
        lx->pp = lx->pp && bs;
    lx->sol = 1;
}

/* Block-comment state: only `*` immediately followed by `/` closes (both
 * chars consumed); every other char is comment text. */
static void cyc_feed_block(struct cyc_lx *lx, const char *line, ssize_t n,
                           ssize_t *i, char c)
{
    if (c == '*' && *i + 1 < n && line[*i + 1] == '/') {
        lx->state = LX_CODE;
        (*i)++;
    }
}

/* String/char-literal state: an escape hides the next char; the matching
 * quote closes the literal and counts as a significant character. */
static void cyc_feed_strchr(struct cyc_lx *lx, char c)
{
    if (lx->esc) {
        lx->esc = 0;
        return;
    }
    if (c == '\\') {
        lx->esc = 1;
        return;
    }
    if ((lx->state == LX_STR && c == '"')
        || (lx->state == LX_CHR && c == '\'')) {
        lx->state = LX_CODE;
        lx->last_sig = c;
    }
}

/* Code-state openers: line comment, block comment, string, char. Returns 1
 * when c left the code state (a block-comment opener consumes its * too). */
static int cyc_open_nc(struct cyc_lx *lx, const char *line, ssize_t n,
                       ssize_t *i, char c)
{
    if (c == '/' && *i + 1 < n && line[*i + 1] == '/') {
        lx->state = LX_LINE;
        return 1;
    }
    if (c == '/' && *i + 1 < n && line[*i + 1] == '*') {
        lx->state = LX_BLOCK;
        (*i)++;
        return 1;
    }
    if (c == '"') {
        lx->state = LX_STR;
        return 1;
    }
    if (c == '\'') {
        lx->state = LX_CHR;
        return 1;
    }
    return 0;
}

static int cyc_feed_line(struct cyc_lx *lx, const struct cyc_emit *em,
                         const char *line, ssize_t n, int lineno)
{
    for (ssize_t i = 0; i < n; i++) {
        char c = line[i];
        if (c == '\0')
            continue;
        if (lx->state == LX_BLOCK) {
            cyc_feed_block(lx, line, n, &i, c);
            continue;
        }
        if (lx->state == LX_STR || lx->state == LX_CHR) {
            cyc_feed_strchr(lx, c);
            continue;
        }
        if (lx->state == LX_LINE)
            continue;
        if (cyc_open_nc(lx, line, n, &i, c))
            continue;
        int rc = cyc_code_char(lx, em, c, lineno);
        if (rc)
            return rc;
    }
    cyc_eol(lx, line, n);
    return 0;
}

static int cyc_scan_text(const char *text, const char *path,
                         int (*on_func)(const char *, const char *, int, int,
                                        void *),
                         void *ctx)
{
    struct cyc_lx lx;
    memset(&lx, 0, sizeof lx);
    lx.state = LX_CODE;
    lx.sol = 1;
    struct cyc_occ occ;
    memset(&occ, 0, sizeof occ);
    occ.on_func = on_func;
    occ.ctx = ctx;
    struct cyc_emit em = { cyc_occ_emit, &occ, path };
    int lineno = 1, rc = 0;
    const char *p = text;
    while (*p && rc == 0) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) + 1 : strlen(p);
        char line[8192];
        if (n >= sizeof line)
            return die("z23-lint: line too long: %s\n", path);
        memcpy(line, p, n);
        rc = cyc_feed_line(&lx, &em, line, (ssize_t)n, lineno++);
        p += n;
    }
    if (rc == 0 && lx.in_func)
        rc = cyc_close_func(&lx, &em);
    return rc;
}

/* ── scope ───────────────────────────────────────────────────────────────
 * git ls-files '*.c' from the repo root, minus vendor/, build/, test-tmp/,
 * tests/fixtures/, and anything under a .z23* directory. With
 * ZCL_CYCLOMATIC_ROOT set (the selftest fixture rail), walk that root
 * instead and report paths relative to it. */

struct cyc_walk {
    const char *root;    /* NULL: paths are already repo-relative */
    size_t root_len;
    int (*on_func)(const char *, const char *, int, int, void *);
    void *ctx;
    int files;
};

static int cyc_excluded(const char *p)
{
    return strncmp(p, "vendor/", 7) == 0 || strncmp(p, "build/", 6) == 0
        || strncmp(p, "test-tmp/", 9) == 0
        || strncmp(p, "tests/fixtures/", 15) == 0
        || strncmp(p, ".z23", 4) == 0 || strstr(p, "/.z23") != NULL;
}

static int cyc_scan_open(const char *open_path, const char *rel,
                         struct cyc_walk *w)
{
    FILE *f = fopen(open_path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", open_path);
    struct cyc_lx lx;
    memset(&lx, 0, sizeof lx);
    lx.state = LX_CODE;
    lx.sol = 1;
    struct cyc_occ occ;
    memset(&occ, 0, sizeof occ);
    occ.on_func = w->on_func;
    occ.ctx = w->ctx;
    struct cyc_emit em = { cyc_occ_emit, &occ, rel };
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 1, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        rc = cyc_feed_line(&lx, &em, line, n, lineno++);
        if (rc)
            break;
    }
    if (rc == 0)
        rc = fin(f, line, open_path, 0);
    else
        (void)fin(f, line, open_path, 0);
    if (rc == 0 && lx.in_func)
        rc = cyc_close_func(&lx, &em);
    return rc;
}

static int cyc_on_path(const char *path, void *ctx)
{
    struct cyc_walk *w = ctx;
    if (cyc_excluded(path))
        return 0;
    w->files++;
    return cyc_scan_open(path, path, w);
}

static int cyc_on_walk_file(const char *path, void *ctx)
{
    struct cyc_walk *w = ctx;
    const char *rel = path;
    if (strncmp(path, w->root, w->root_len) == 0 && path[w->root_len] == '/')
        rel = path + w->root_len + 1;
    if (cyc_excluded(rel))
        return 0;
    w->files++;
    return cyc_scan_open(path, rel, w);
}

/* ── the baseline ────────────────────────────────────────────────────────
 * Exact-pin compare is the shared shrink-only ratchet helper in lib.c
 * (lint_base_*; contract in lintc.h). Keys are `path:function`, with the
 * lexer's `function#N` suffix for repeat definitions. */

static struct lint_base g_cyc_pins;

static int cyc_key(char *key, size_t cap, const char *path, const char *name)
{
    return ovf(snprintf(key, cap, "%s:%s", path, name), cap);
}

/* ── the run ───────────────────────────────────────────────────────────── */

struct cyc_acc {
    FILE *out;
    const char *mode;
    int funcs, viol;
    int gt10, gt15, gt20;
    struct cyc_top_ent {
        char path[RS_PATH];
        char name[CYC_NAME];
        int m;
    } top[CYC_TOP];
};

static int cyc_note(struct cyc_acc *a, const char *fmt, const char *path,
                    const char *name, int line, int m, int extra)
{
    a->viol++;
    return fprintf(a->out, fmt, path, line, name, m, extra) < 0
               ? die("z23-lint: write failed\n", "")
               : 0;
}

static void cyc_top_feed(struct cyc_acc *a, const char *path,
                         const char *name, int m)
{
    int i = CYC_TOP - 1;
    if (a->top[i].m >= m && a->top[i].path[0] != '\0')
        return;
    while (i > 0 && (a->top[i - 1].path[0] == '\0' || a->top[i - 1].m < m)) {
        a->top[i] = a->top[i - 1];
        i--;
    }
    snprintf(a->top[i].path, sizeof a->top[i].path, "%s", path);
    snprintf(a->top[i].name, sizeof a->top[i].name, "%s", name);
    a->top[i].m = m;
}

static int cyc_on_func(const char *path, const char *name, int line, int m,
                       void *ctx)
{
    struct cyc_acc *a = ctx;
    a->funcs++;
    if (m > 10)
        a->gt10++;
    if (m > CYC_MAX)
        a->gt15++;
    if (m > 20)
        a->gt20++;
    cyc_top_feed(a, path, name, m);
    char key[LB_KEY];
    if (cyc_key(key, sizeof key, path, name))
        return 2;
    int pinned = lint_base_observe(&g_cyc_pins, key, m) >= 0;
    if (m <= CYC_MAX)
        return 0;
    if (strcmp(a->mode, "FAIL") == 0)
        return cyc_note(a, "%s:%d: %s M=%d exceeds cap %d (FAIL mode: "
                           "baseline ignored)\n",
                        path, name, line, m, CYC_MAX);
    if (!pinned)
        return cyc_note(a, "%s:%d: %s M=%d exceeds cap %d and is not pinned "
                           "in the baseline\n",
                        path, name, line, m, CYC_MAX);
    return 0;
}

/* Dump the captured violation lines from hits to err under a one-line
 * summary plus the re-pin hint. Returns 0 in WARN mode, 1 otherwise, or a
 * die() rc on a write/read failure. */
static int cyc_dump_viol(const struct cyc_acc *a, FILE *hits,
                         const char *mode, FILE *err)
{
    if (fprintf(err, "check_cyclomatic_complexity: %s — %d complexity "
                "violation(s) at cap %d (mode: %s)\n",
                strcmp(mode, "WARN") == 0 ? "WARN" : "FAIL",
                a->viol, CYC_MAX, mode) < 0)
        return die("z23-lint: write failed\n", "");
    if (fseek(hits, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char buf[4096];
    size_t n;
    int wrc = 0;
    while ((n = fread(buf, 1, sizeof buf, hits)) > 0)
        if (fwrite(buf, 1, n, err) != n) {
            wrc = die("z23-lint: write failed\n", "");
            break;
        }
    if (wrc == 0 && ferror(hits))
        wrc = die("z23-lint: read failed\n", "");
    if (wrc == 0
        && fputs("  Fix: split the function under the cap. To re-pin at "
                 "the CURRENT M, regenerate the baseline:\n"
                 "  build/bin/z23-lint check-cyclomatic-complexity "
                 "--write-baseline\n"
                 "  (tools/lint/cyclomatic_complexity_baseline.txt — "
                 "shrink-only ratchet: a pin may never rise, and a\n"
                 "  function that got simpler must be re-pinned lower.)\n",
                 err) < 0)
        wrc = die("z23-lint: write failed\n", "");
    if (wrc)
        return wrc;
    return strcmp(mode, "WARN") == 0 ? 0 : 1;
}

/* --report: distribution summary plus the top-M table. */
static int cyc_report(const struct cyc_acc *a, int files, FILE *out)
{
    int rc2 = fprintf(out, "check_cyclomatic_complexity report: %d "
                      "functions in %d files\n  M>10: %d  M>15: %d  "
                      "M>20: %d\n  top %d by M:\n",
                      a->funcs, files, a->gt10, a->gt15, a->gt20,
                      CYC_TOP) < 0;
    for (int i = 0; !rc2 && i < CYC_TOP && a->top[i].path[0]; i++)
        rc2 = fprintf(out, "    M=%d %s:%s\n", a->top[i].m, a->top[i].path,
                      a->top[i].name) < 0;
    return rc2 ? die("z23-lint: write failed\n", "") : 0;
}

static int cyc_check(const char *root, const char *base_path,
                     const char *mode, int report, FILE *out, FILE *err)
{
    if (!report && lint_base_load(&g_cyc_pins, base_path, err))
        return 2;
    FILE *hits = tmpfile();
    if (!hits)
        return die("z23-lint: tmpfile failed\n", "");
    struct cyc_acc a;
    memset(&a, 0, sizeof a);
    a.out = hits;
    a.mode = mode;
    struct cyc_walk w = {
        root, root ? strlen(root) : 0, cyc_on_func, &a, 0
    };
    int rc;
    if (root)
        rc = walk_src(root, 0, cyc_on_walk_file, &w);
    else
        rc = each_zpath(k_cyc_ls, cyc_on_path, &w);
    if (rc == 0 && strcmp(mode, "FAIL") != 0 && !report) {
        int cv = lint_base_finish(&g_cyc_pins, hits);
        if (cv < 0)
            rc = 2;
        else
            a.viol += cv;
    }
    if (rc) {
        fclose(hits);
        return rc;
    }
    if (report) {
        rc = cyc_report(&a, w.files, out);
        fclose(hits);
        return rc;
    }
    if (a.viol) {
        rc = cyc_dump_viol(&a, hits, mode, err);
        fclose(hits);
        return rc;
    }
    if (fprintf(out, "check_cyclomatic_complexity: OK — %d functions "
                "scanned in %d files, %d baseline pin(s) exact at cap "
                "%d (mode: %s)\n",
                a.funcs, w.files, g_cyc_pins.n, CYC_MAX, mode) < 0) {
        fclose(hits);
        return die("z23-lint: write failed\n", "");
    }
    fclose(hits);
    return 0;
}

static int cyc_mode_valid(const char *m)
{
    return strcmp(m, "WARN") == 0 || strcmp(m, "RATCHET") == 0
        || strcmp(m, "FAIL") == 0;
}

/* --write-baseline: regenerate the baseline from the current scan. Exact
 * path:function:M pins for every over-cap function, sorted; deterministic
 * for a fixed tree. This is the ratchet-upkeep command named in the gate's
 * failure hint — it writes whatever the tree measures TODAY, so raising a
 * pin is possible; review the diff like any baseline change. */
static int cyc_collect_pin(const char *path, const char *name, int line,
                           int m, void *ctx)
{
    int *funcs = ctx;
    (void)line;
    (*funcs)++;
    if (m <= CYC_MAX)
        return 0;
    char key[LB_KEY];
    if (cyc_key(key, sizeof key, path, name))
        return 2;
    return lint_base_pin(&g_cyc_pins, key, m);
}

static const char k_cyc_base_hdr[] =
    "# check-cyclomatic-complexity baseline — every function over the"
    " cyclomatic cap of 15,\n"
    "# pinned at its current M as path:function:M (a repeated definition in"
    " one file keys as\n"
    "# function#2, function#3, ... in scan order). GENERATED — never"
    " hand-edit; regenerate with:\n"
    "#   build/bin/z23-lint check-cyclomatic-complexity --write-baseline\n"
    "# Shrink-only ratchet: an exact pin passes; a function that grew or"
    " shrank past its pin,\n"
    "# or a pin whose function no longer exists, fails the gate.\n";

static int cyc_write_baseline(const char *root, const char *base_path)
{
    g_cyc_pins.n = 0;
    int funcs = 0;
    struct cyc_walk w = {
        root, root ? strlen(root) : 0, cyc_collect_pin, &funcs, 0
    };
    int rc;
    if (root)
        rc = walk_src(root, 0, cyc_on_walk_file, &w);
    else
        rc = each_zpath(k_cyc_ls, cyc_on_path, &w);
    if (rc)
        return rc;
    if (lint_base_write(&g_cyc_pins, base_path, k_cyc_base_hdr))
        return 2;
    return printf("check_cyclomatic_complexity: wrote %d pin(s) to %s "
                  "(%d functions scanned in %d files)\n",
                  g_cyc_pins.n, base_path, funcs, w.files) < 0
               ? die("z23-lint: write failed\n", "")
               : 0;
}

int check_cyclomatic_complexity_run(int argc, char **argv)
{
    int report = 0, write_base = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--report") == 0)
            report = 1;
        else if (strcmp(argv[i], "--write-baseline") == 0)
            write_base = 1;
        else
            return die("usage: z23-lint check-cyclomatic-complexity "
                       "[--report | --write-baseline]\n", "");
    }
    if (report && write_base)
        return die("usage: z23-lint check-cyclomatic-complexity "
                   "[--report | --write-baseline]\n", "");
    const char *mode = env_or("ZCL_LINT_MODE", "RATCHET");
    if (!cyc_mode_valid(mode))
        return die("z23-lint: ZCL_LINT_MODE must be WARN, RATCHET, or FAIL\n",
                   "");
    const char *root = getenv("ZCL_CYCLOMATIC_ROOT");
    if (root && !root[0])
        root = NULL;
    const char *base = getenv("ZCL_CYCLOMATIC_BASELINE");
    char base_buf[4096];
    if (!base || !base[0]) {
        if (root) {
            if (ovf(snprintf(base_buf, sizeof base_buf, "%s/%s", root,
                             k_cyc_base_rel), sizeof base_buf))
                return 2;
            base = base_buf;
        } else {
            base = k_cyc_base_rel;
        }
    }
    if (write_base)
        return cyc_write_baseline(root, base);
    return cyc_check(root, base, mode, report, stdout, stderr);
}

/* ── selftest ──────────────────────────────────────────────────────────── */

struct cyc_st_acc {
    char name[32][CYC_NAME];
    int m[32];
    int n;
};

static int cyc_st_collect(const char *path, const char *name, int line,
                          int m, void *ctx)
{
    struct cyc_st_acc *a = ctx;
    (void)path;
    (void)line;
    if (a->n >= 32 || strlen(name) >= CYC_NAME)
        return die("z23-lint: selftest overflow\n", "");
    memcpy(a->name[a->n], name, strlen(name) + 1);
    a->m[a->n] = m;
    a->n++;
    return 0;
}

/* Scan text; want exactly one function named `name` with metric `m`. */
static int cyc_st_one(const char *text, const char *name, int m)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    if (cyc_scan_text(text, "st.c", cyc_st_collect, &a))
        return 1;
    if (a.n != 1 || strcmp(a.name[0], name) != 0 || a.m[0] != m) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: want %s M=%d, "
                "got n=%d%s\n", name, m, a.n,
                a.n ? "" : " (no function found)");
        return 1;
    }
    return 0;
}

static int cyc_st_none(const char *text)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    if (cyc_scan_text(text, "st.c", cyc_st_collect, &a))
        return 1;
    if (a.n != 0) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: want no "
                "function, got %s\n", a.name[0]);
        return 1;
    }
    return 0;
}

static int cyc_st_metric(void)
{
    int bad = 0;
    /* exactly at the cap passes the cap: 14 decision points -> M=15 */
    bad |= cyc_st_one("int cap15(int x)\n{\n"
                      "    int r = 0;\n"
                      "    if (x > 0) r++;\n    if (x > 1) r++;\n"
                      "    if (x > 2) r++;\n    if (x > 3) r++;\n"
                      "    if (x > 4) r++;\n    if (x > 5) r++;\n"
                      "    if (x > 6) r++;\n    if (x > 7) r++;\n"
                      "    if (x > 8) r++;\n    if (x > 9) r++;\n"
                      "    if (x > 10) r++;\n   if (x > 11) r++;\n"
                      "    if (x > 12) r++;\n   if (x > 13) r++;\n"
                      "    return r;\n}\n", "cap15", 15);
    /* one more decision point -> M=16 */
    bad |= cyc_st_one("int cap16(int x)\n{\n"
                      "    int r = 0;\n"
                      "    if (x > 0) r++;\n    if (x > 1) r++;\n"
                      "    if (x > 2) r++;\n    if (x > 3) r++;\n"
                      "    if (x > 4) r++;\n    if (x > 5) r++;\n"
                      "    if (x > 6) r++;\n    if (x > 7) r++;\n"
                      "    if (x > 8) r++;\n    if (x > 9) r++;\n"
                      "    if (x > 10) r++;\n   if (x > 11) r++;\n"
                      "    if (x > 12) r++;\n   if (x > 13) r++;\n"
                      "    if (x > 14) r++;\n   return r;\n}\n", "cap16", 16);
    /* each of &&, ||, ?, case adds exactly one; else/default/switch none */
    bad |= cyc_st_one("int ops(int a, int b)\n{\n"
                      "    switch (a) {\n"
                      "    case 1:\n"
                      "        return a && b ? 2 : 3;\n"
                      "    default:\n"
                      "        return a || b;\n"
                      "    }\n}\n", "ops", 5);
    bad |= cyc_st_one("int loops(int x)\n{\n"
                      "    for (int i = 0; i < x; i++) {\n"
                      "        while (x > 3)\n"
                      "            x--;\n"
                      "    }\n"
                      "    if (x)\n"
                      "        return 1;\n"
                      "    else\n"
                      "        return 0;\n}\n", "loops", 4);
    /* keywords inside string/char literals and both comment kinds hide */
    bad |= cyc_st_one("int hidden(void)\n{\n"
                      "    const char *s = \"if (x) && y ? z : case 1\";\n"
                      "    const char *q = \"quote \\\" if (y)\";\n"
                      "    char c = '?';\n"
                      "    // if (a) || b ? c : d, case 9:\n"
                      "    /* for (;;) while (1) case 7: && || ? */\n"
                      "    return s[0] == c && q[0] != c;\n}\n",
                      "hidden", 2);
    /* multi-line parameter list, attribute between return type and name */
    bad |= cyc_st_one("static ZCL_MUST_USE int\n"
                      "multi_line(\n"
                      "    int a,\n"
                      "    int b)\n"
                      "{\n"
                      "    return a + b;\n}\n", "multi_line", 1);
    bad |= cyc_st_one("static inline int inl(int x) { return x ? x : 0; }\n",
                      "inl", 2);
    /* prototypes, calls, struct/enum definitions, and initializers open
     * no body */
    bad |= cyc_st_none("int proto(int x);\n"
                       "extern int ext_fn(int);\n"
                       "struct point { int x; int y; };\n"
                       "struct point g_origin = { .x = 0, .y = 0 };\n"
                       "enum { RED, GREEN };\n"
                       "int arr[3] = { 1, 2, 3 };\n");
    bad |= cyc_st_none("typedef int (*cmp_fn)(const void *, const void *);\n");
    /* a repeated definition in one file keys as name#2 in scan order */
    {
        struct cyc_st_acc a;
        memset(&a, 0, sizeof a);
        if (cyc_scan_text("#ifdef ZCL_ALT\n"
                          "int dup_fn(int x) { return x ? 1 : 0; }\n"
                          "#else\n"
                          "int dup_fn(int x) { if (x) return x ? 1 : 0; "
                          "return 0; }\n"
                          "#endif\n", "st.c", cyc_st_collect, &a))
            bad |= 1;
        else if (a.n != 2 || strcmp(a.name[0], "dup_fn") != 0 || a.m[0] != 2
                 || strcmp(a.name[1], "dup_fn#2") != 0 || a.m[1] != 3) {
            fprintf(stderr, "check_cyclomatic_complexity selftest: repeat "
                    "definition keying wrong (n=%d)\n", a.n);
            bad |= 1;
        }
    }
    return bad;
}

static const char k_cyc_st_fn[] =
    "int over_cap(int x)\n"
    "{\n"
    "    int r = 0;\n"
    "    if (x > 0) r++;\n    if (x > 1) r++;\n"
    "    if (x > 2) r++;\n    if (x > 3) r++;\n"
    "    if (x > 4) r++;\n    if (x > 5) r++;\n"
    "    if (x > 6) r++;\n    if (x > 7) r++;\n"
    "    if (x > 8) r++;\n    if (x > 9) r++;\n"
    "    if (x > 10) r++;\n   if (x > 11) r++;\n"
    "    if (x > 12) r++;\n   if (x > 13) r++;\n"
    "    if (x > 14) r++;\n   return r;\n"
    "}\n"
    "int calm(int x)\n"
    "{\n"
    "    return x + 1;\n"
    "}\n";

/* Run cyc_check against the fixture with the given baseline body; assert
 * the return code and (when needle non-NULL) that the captured error names
 * it. */
static int cyc_st_case(const char *root, const char *base_body,
                       const char *mode, int want_rc, const char *needle)
{
    char bpath[8192];
    if (ovf(snprintf(bpath, sizeof bpath, "%s/baseline.txt", root),
            sizeof bpath))
        return 1;
    if (csr_write(bpath, base_body))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = cyc_check(root, bpath, mode, 0, out, err);
    char buf[8192];
    if (csr_slurp(err, buf, sizeof buf)) {
        fclose(out);
        fclose(err);
        return 1;
    }
    fclose(out);
    fclose(err);
    if (rc != want_rc || (needle && strstr(buf, needle) == NULL)) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: mode %s want "
                "rc %d needle '%s'; got rc %d and:\n%s\n",
                mode, want_rc, needle ? needle : "(none)", rc, buf);
        return 1;
    }
    return 0;
}

/* --write-baseline regenerates exact pins: verify the generated file pins
 * the over-cap fixture function, excludes the under-cap one, and passes the
 * gate unchanged. */
static int cyc_st_writeback(const char *root)
{
    char wb[8192];
    if (ovf(snprintf(wb, sizeof wb, "%s/gen_baseline.txt", root), sizeof wb))
        return 1;
    if (cyc_write_baseline(root, wb))
        return 1;
    FILE *g = fopen(wb, "r");
    char body[8192];
    if (!g || csr_slurp(g, body, sizeof body)) {
        if (g)
            fclose(g);
        return 1;
    }
    fclose(g);
    if (strstr(body, "case.c:over_cap:16\n") == NULL
        || strstr(body, "calm") != NULL) {
        fputs("check_cyclomatic_complexity selftest: generated baseline "
              "content wrong\n", stderr);
        return 1;
    }
    FILE *out = tmpfile(), *err = tmpfile();
    int bad = !out || !err || cyc_check(root, wb, "RATCHET", 0, out, err);
    if (bad)
        fputs("check_cyclomatic_complexity selftest: generated baseline "
              "did not pass\n", stderr);
    if (out)
        fclose(out);
    if (err)
        fclose(err);
    return bad;
}

int check_cyclomatic_complexity_selftest(void)
{
    int bad = cyc_st_metric();
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-cyc-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    char src[8192];
    if (ovf(snprintf(src, sizeof src, "%s/case.c", root), sizeof src))
        bad = 1;
    else if (csr_write(src, k_cyc_st_fn))
        bad = 1;
    if (!bad) {
        /* exact pin passes */
        bad |= cyc_st_case(root, "case.c:over_cap:16\n", "RATCHET", 0, NULL);
        /* an unpinned over-cap function fails as new complexity */
        bad |= cyc_st_case(root, "", "RATCHET", 1, "not pinned");
        /* a pin below the current M fails as growth */
        bad |= cyc_st_case(root, "case.c:over_cap:15\n", "RATCHET", 1,
                           "grew M=15 -> M=16");
        /* a pin above the current M fails and asks for the ratchet-down */
        bad |= cyc_st_case(root, "case.c:over_cap:17\n", "RATCHET", 1,
                           "ratchet the baseline entry down to 16");
        /* a pin for a missing function fails as stale */
        bad |= cyc_st_case(root, "case.c:over_cap:16\ncase.c:ghost:20\n",
                           "RATCHET", 1, "stale baseline, delete the line");
        /* a duplicated baseline row fails closed at load */
        bad |= cyc_st_case(root, "case.c:over_cap:16\ncase.c:over_cap:16\n",
                           "RATCHET", 2, "duplicate baseline entry");
        /* a row without :M fails closed at load */
        bad |= cyc_st_case(root, "case.c:over_cap\n", "RATCHET", 2,
                           "malformed baseline M in line");
        /* WARN reports but exits 0 */
        bad |= cyc_st_case(root, "", "WARN", 0, "not pinned");
        /* FAIL mode trips even an exactly pinned function */
        bad |= cyc_st_case(root, "case.c:over_cap:16\n", "FAIL", 1,
                           "baseline ignored");
        bad |= cyc_st_writeback(root);
    }
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_cyclomatic_complexity selftest: OK\n");
}
