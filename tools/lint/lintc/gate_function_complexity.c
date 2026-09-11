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
 * Operators: && and || each add one decision point, and only when the two
 * operator characters are ADJACENT in the source. The pairing is never
 * carried across any other character, so `f(&x); if (a & b)` and
 * `g(&p, &q)` add nothing; a lone & or | (address-of, bitwise), &= and |=,
 * and &&= / ||= add nothing either. Literals and comments are skipped
 * before operator scanning, so && inside a string or a comment is invisible.
 * Preprocessor conditionals: EVERY branch of a #if / #ifdef / #ifndef
 * region is read and every decision point in it is counted, so no branch of
 * real code is ever invisible to the cap. Only the STRUCTURE — brace and
 * paren depth, and the declarator head being assembled — is taken from the
 * FIRST branch: each later branch restarts from the depth the region opened
 * at, and the #endif resumes at the depth the first branch reached. Without
 * that, branches that open or close different numbers of braces would
 * desynchronise the depth and glue the whole rest of the file onto one
 * function. Conditions are never evaluated. A region whose branches do not
 * all end at the same brace and paren depth has no single structure to
 * resume from; rather than silently mis-attribute the code after the
 * #endif, the gate fails on that file and names the #if line. Nesting is a
 * stack, so an inner region resolves before its outer one.
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
#include <unistd.h>
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

/* The structural half of the lexer state: what a preprocessor branch may
 * not leak into the branch after it. The decision count m is deliberately
 * NOT here — decisions accumulate across every branch, so no real branching
 * is hidden from the cap. */
struct cyc_sp {
    int brace, paren;
    int in_func, func_line;
    char func_name[CYC_NAME];
    int head_ok, head_line;
    char head_name[CYC_NAME];
    char cand[CYC_NAME];
    int cand_ok, cand_line;
    int last_sig;
    char last_tok[CYC_NAME];
};

/* One open #if/#ifdef/#ifndef region. */
enum { CYC_PP_MAX = 64 };
struct cyc_reg {
    struct cyc_sp entry;   /* structure where the region opened */
    struct cyc_sp first;   /* structure where its first branch ended */
    int first_done;
    int line;              /* the #if line, for the failure message */
};

struct cyc_lx {
    int state, esc, pp, sol;
    int ppc_depth;         /* #if/#ifdef/#ifndef nesting depth */
    struct cyc_reg reg[CYC_PP_MAX];
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
};

static int cyc_is_ident(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_';
}

/* Characters the lexer must not count: a preprocessor directive line
 * contributes neither braces, parens, nor decision points. */
static int cyc_off(const struct cyc_lx *lx)
{
    return lx->pp;
}

/* ── preprocessor conditionals ───────────────────────────────────────────
 * Decisions come from every branch; structure comes from the first one.
 * #if/#ifdef/#ifndef pushes a region and snapshots the structure; #else and
 * #elif end the running branch and restore the snapshot; #endif ends the
 * last branch and resumes at the structure the first branch reached.
 * Conditions are never evaluated. */
enum { PPC_NONE = 0, PPC_OPEN, PPC_ELSE, PPC_END };

/* Copy the directive word of a `# word ...` line into out. Returns 0 when
 * the line is not a directive. */
static int cyc_pp_word(const char *line, ssize_t n, char *out, size_t cap)
{
    ssize_t i = 0;
    while (i < n && (line[i] == ' ' || line[i] == '\t'))
        i++;
    if (i >= n || line[i] != '#')
        return 0;
    i++;
    while (i < n && (line[i] == ' ' || line[i] == '\t'))
        i++;
    size_t k = 0;
    while (i < n && cyc_is_ident((unsigned char)line[i]) && k + 1 < cap)
        out[k++] = line[i++];
    out[k] = '\0';
    return 1;
}

static int cyc_pp_kind(const char *w)
{
    static const char *const k_open[] = { "if", "ifdef", "ifndef", NULL };
    static const char *const k_else[] = { "else", "elif", "elifdef",
                                          "elifndef", NULL };
    for (int i = 0; k_open[i]; i++)
        if (strcmp(w, k_open[i]) == 0)
            return PPC_OPEN;
    for (int i = 0; k_else[i]; i++)
        if (strcmp(w, k_else[i]) == 0)
            return PPC_ELSE;
    return strcmp(w, "endif") == 0 ? PPC_END : PPC_NONE;
}

static void cyc_sp_save(const struct cyc_lx *lx, struct cyc_sp *s)
{
    s->brace = lx->brace;
    s->paren = lx->paren;
    s->in_func = lx->in_func;
    s->func_line = lx->func_line;
    memcpy(s->func_name, lx->func_name, sizeof s->func_name);
    s->head_ok = lx->head_ok;
    s->head_line = lx->head_line;
    memcpy(s->head_name, lx->head_name, sizeof s->head_name);
    memcpy(s->cand, lx->cand, sizeof s->cand);
    s->cand_ok = lx->cand_ok;
    s->cand_line = lx->cand_line;
    s->last_sig = lx->last_sig;
    memcpy(s->last_tok, lx->last_tok, sizeof s->last_tok);
}

static void cyc_sp_load(struct cyc_lx *lx, const struct cyc_sp *s)
{
    lx->brace = s->brace;
    lx->paren = s->paren;
    lx->in_func = s->in_func;
    lx->func_line = s->func_line;
    memcpy(lx->func_name, s->func_name, sizeof lx->func_name);
    lx->head_ok = s->head_ok;
    lx->head_line = s->head_line;
    memcpy(lx->head_name, s->head_name, sizeof lx->head_name);
    memcpy(lx->cand, s->cand, sizeof lx->cand);
    lx->cand_ok = s->cand_ok;
    lx->cand_line = s->cand_line;
    lx->last_sig = s->last_sig;
    memcpy(lx->last_tok, s->last_tok, sizeof lx->last_tok);
}

static int cyc_pp_fail(const char *path, int line, const char *what)
{
    char msg[1024];
    if (ovf(snprintf(msg, sizeof msg, "%s:%d: %s", path, line, what),
            sizeof msg))
        return 2;
    return die("z23-lint: %s\n", msg);
}

static int cyc_pp_open(struct cyc_lx *lx, const char *path, int lineno)
{
    if (lx->ppc_depth >= CYC_PP_MAX)
        return cyc_pp_fail(path, lineno,
                           "preprocessor conditionals nest too deeply for "
                           "the complexity gate");
    struct cyc_reg *r = &lx->reg[lx->ppc_depth++];
    memset(r, 0, sizeof *r);
    cyc_sp_save(lx, &r->entry);
    r->line = lineno;
    return 0;
}

/* End the branch that is running in the innermost region. The first branch
 * defines the structure the region resumes at; a later branch that ends at
 * a different brace or paren depth leaves the gate no defensible way to
 * attribute what follows the #endif, so it fails the file. */
static int cyc_pp_branch_end(struct cyc_lx *lx, const char *path)
{
    struct cyc_reg *r = &lx->reg[lx->ppc_depth - 1];
    if (!r->first_done) {
        cyc_sp_save(lx, &r->first);
        r->first_done = 1;
        return 0;
    }
    if (lx->brace != r->first.brace || lx->paren != r->first.paren)
        return cyc_pp_fail(path, r->line,
                           "preprocessor branches end at different brace or "
                           "paren depths; balance the branches so the "
                           "complexity gate can attribute the code after "
                           "the #endif");
    return 0;
}

/* Called once per physical line, before the characters are fed, so the
 * directive is classified before the code-state scanner marks it pp. A
 * directive inside a comment or spliced onto a previous line is not one. */
static int cyc_pp_cond(struct cyc_lx *lx, const char *path, const char *line,
                       ssize_t n, int lineno)
{
    char w[16];
    if (lx->state != LX_CODE || lx->pp)
        return 0;
    if (!cyc_pp_word(line, n, w, sizeof w))
        return 0;
    int kind = cyc_pp_kind(w);
    if (kind == PPC_OPEN)
        return cyc_pp_open(lx, path, lineno);
    if (kind == PPC_NONE || lx->ppc_depth == 0)
        return 0;          /* a stray #else/#endif pairs with nothing */
    int rc = cyc_pp_branch_end(lx, path);
    if (rc)
        return rc;
    struct cyc_reg *r = &lx->reg[lx->ppc_depth - 1];
    if (kind == PPC_ELSE) {
        cyc_sp_load(lx, &r->entry);
        return 0;
    }
    cyc_sp_load(lx, &r->first);
    lx->ppc_depth--;
    return 0;
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
        if (lx->in_func && !cyc_off(lx)
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

/* The same name may be defined more than once in one file — an #ifdef/#else
 * variant pair is the common case, and every branch is read (see the
 * header), so both variants are reported and each is measured on its own.
 * A repeat is keyed name#2, name#3, ... in scan order, which is stable on
 * every host because no condition is ever evaluated and no branch is ever
 * skipped, so a baseline pin stays an exact path:function:M match. The name
 * table is
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
    if (!cyc_off(lx) && lx->brace == 0 && lx->paren == 0) {
        lx->cand_ok = lx->last_sig == 'i'
            && !cyc_is_kw(lx->last_tok, "if")
            && !cyc_is_kw(lx->last_tok, "for")
            && !cyc_is_kw(lx->last_tok, "while")
            && !cyc_is_kw(lx->last_tok, "switch");
        memcpy(lx->cand, lx->last_tok, sizeof lx->cand);
        lx->cand_line = lineno;
    }
    if (!cyc_off(lx))
        lx->paren++;
}

static void cyc_c_rparen(struct cyc_lx *lx)
{
    if (!cyc_off(lx) && lx->paren > 0) {
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
    if (!cyc_off(lx) && lx->brace == 0) {
        if (lx->head_ok && lx->last_sig == ')') {
            lx->in_func = 1;
            lx->m = 1;
            lx->func_line = lx->head_line;
            memcpy(lx->func_name, lx->head_name, sizeof lx->func_name);
        }
        lx->head_ok = 0;
    }
    if (!cyc_off(lx))
        lx->brace++;
}

static int cyc_c_rbrace(struct cyc_lx *lx, const struct cyc_emit *em)
{
    if (cyc_off(lx))
        return 0;
    lx->brace--;
    if (lx->in_func && lx->brace == 0)
        return cyc_close_func(lx, em);
    return 0;
}

static void cyc_c_semi(struct cyc_lx *lx)
{
    if (!cyc_off(lx) && lx->brace == 0 && lx->paren == 0)
        lx->head_ok = 0;
}

/* `&&` / `||`: one decision point, and only for two ADJACENT operator
 * characters. A lone `&` or `|` (address-of, bitwise) counts nothing, and
 * nothing is ever paired across an intervening character, so `f(&x); if (a
 * & b)` and `g(&p, &q)` count nothing. `&=` and `|=` are not doubled
 * operators at all; `&&=` / `||=` are rejected by the trailing `=` test.
 * The second operator character is consumed here so `&&&` counts once. */
static void cyc_c_logic(struct cyc_lx *lx, const char *line, ssize_t n,
                        ssize_t *i, char c)
{
    if (*i + 1 >= n || line[*i + 1] != c)
        return;
    (*i)++;
    if (*i + 1 < n && line[*i + 1] == '=')
        return;
    if (lx->in_func && !cyc_off(lx))
        lx->m++;
}

static void cyc_c_quest(struct cyc_lx *lx)
{
    if (lx->in_func && !cyc_off(lx))
        lx->m++;
}

static void cyc_c_other(struct cyc_lx *lx)
{
    if (!cyc_off(lx) && lx->brace == 0 && lx->paren == 0)
        lx->head_ok = 0;
}

struct cyc_span {
    const char *line;
    ssize_t n;
    ssize_t *i;          /* cursor; an operator handler may consume ahead */
    int lineno;
};

static int cyc_punct(struct cyc_lx *lx, const struct cyc_emit *em,
                     const struct cyc_span *s, char c)
{
    switch (c) {
    case '(': cyc_c_lparen(lx, s->lineno); break;
    case ')': cyc_c_rparen(lx); break;
    case '{': cyc_c_lbrace(lx); break;
    case '}': {
        int rc = cyc_c_rbrace(lx, em);
        if (rc)
            return rc;
        break;
    }
    case ';': cyc_c_semi(lx); break;
    case '&':
    case '|': cyc_c_logic(lx, s->line, s->n, s->i, c); break;
    case '?': cyc_c_quest(lx); break;
    default: cyc_c_other(lx); break;
    }
    lx->last_sig = c;
    return 0;
}

/* Feed one code-state character. Returns 0 or the callback/die rc. */
static int cyc_code_char(struct cyc_lx *lx, const struct cyc_emit *em,
                         const struct cyc_span *s, char c)
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
    return cyc_punct(lx, em, s, c);
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
    int pprc = cyc_pp_cond(lx, em->path, line, n, lineno);
    if (pprc)
        return pprc;
    for (ssize_t i = 0; i < n; i++) {
        struct cyc_span s = { line, n, &i, lineno };
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
        int rc = cyc_code_char(lx, em, &s, c);
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

/* Scan text; want exactly two functions, in order, with those metrics. */
static int cyc_st_two(const char *text, const char *n1, int m1,
                      const char *n2, int m2)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    if (cyc_scan_text(text, "st.c", cyc_st_collect, &a))
        return 1;
    if (a.n != 2 || strcmp(a.name[0], n1) != 0 || a.m[0] != m1
        || strcmp(a.name[1], n2) != 0 || a.m[1] != m2) {
        fprintf(stderr, "check_cyclomatic_complexity selftest: want %s M=%d "
                "then %s M=%d, got n=%d (first %s M=%d)\n", n1, m1, n2, m2,
                a.n, a.n ? a.name[0] : "-", a.n ? a.m[0] : 0);
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

/* && and || count once, and only when the two characters are adjacent. */
static int cyc_st_logic_ops(void)
{
    int bad = 0;
    /* address-of and bitwise & never pair: one decision here, the if */
    bad |= cyc_st_one("int amp_addr(int a, int b)\n{\n"
                      "    f(&a);\n"
                      "    g(&a, &b);\n"
                      "    if (a & b) {\n        return 1;\n    }\n"
                      "    return 0;\n}\n", "amp_addr", 2);
    /* a real && is one decision on top of the if */
    bad |= cyc_st_one("int amp_and(int a, int b)\n{\n"
                      "    if (a && b)\n        return 1;\n"
                      "    return 0;\n}\n", "amp_and", 3);
    /* bitwise | never pairs with a later ||; the || is one decision */
    bad |= cyc_st_one("int bar_or(int p, int q, int c, int d)\n{\n"
                      "    int x = p | q;\n"
                      "    if (c || d)\n        return x;\n"
                      "    return 0;\n}\n", "bar_or", 3);
    /* &=, |=, &&= and ||= are not decisions */
    bad |= cyc_st_one("int assign_ops(int a, int b)\n{\n"
                      "    a &= b;\n    a |= b;\n"
                      "    return a;\n}\n", "assign_ops", 1);
    return bad;
}

/* Every branch of a preprocessor conditional is counted; only the brace and
 * paren structure comes from the first branch. */
static int cyc_st_pp_cond(void)
{
    int bad = 0;
    /* branches that each open a brace would desynchronise the depth and
     * swallow every later function; the decisions in both branches count,
     * and the if after the #endif belongs to the function it is written in */
    bad |= cyc_st_two("int split_brace(int x)\n{\n"
                      "#if ZCL_ALT\n"
                      "    if (x > 0) {\n"
                      "#else\n"
                      "    if (x < 0) {\n"
                      "#endif\n"
                      "        x++;\n"
                      "    }\n"
                      "    if (x > 5)\n        x = 5;\n"
                      "    return x;\n}\n"
                      "int after_region(int y)\n{\n"
                      "    if (y)\n        return 1;\n"
                      "    return 0;\n}\n",
                      "split_brace", 4, "after_region", 2);
    /* #if inside #if, in both the first and a later branch: the region
     * stack pairs each #endif with its own opener */
    bad |= cyc_st_two("int nest(int x)\n{\n"
                      "#if A\n"
                      "#if B\n"
                      "    if (x) x++;\n"
                      "#endif\n"
                      "    if (x) x--;\n"
                      "#else\n"
                      "#if C\n"
                      "    if (x) x += 2;\n"
                      "#endif\n"
                      "    if (x) x += 3;\n"
                      "#endif\n"
                      "    return x;\n}\n"
                      "int tail(int y) { if (y) return 1; return 0; }\n",
                      "nest", 5, "tail", 2);
    /* an #elif chain: every arm is measured, the last arm restores the
     * first arm's structure, and the next function is still found */
    bad |= cyc_st_two("int elifs(int x)\n{\n"
                      "#if A\n"
                      "    if (x) x += 1;\n"
                      "#elif B\n"
                      "    if (x) x += 2;\n"
                      "#elifdef C\n"
                      "    if (x) x += 3;\n"
                      "#else\n"
                      "    if (x) x += 4;\n"
                      "#endif\n"
                      "    return x;\n}\n"
                      "int elif_tail(int y) { if (y) return 1; return 0; }\n",
                      "elifs", 5, "elif_tail", 2);
    /* #ifndef with no #else at all: the single branch is the structure */
    bad |= cyc_st_two("int noelse(int x)\n{\n"
                      "#ifndef ZCL_ALT\n"
                      "    if (x) x++;\n"
                      "#endif\n"
                      "    if (x) x--;\n"
                      "    return x;\n}\n"
                      "int noelse_tail(int y) { if (y) return 1; "
                      "return 0; }\n",
                      "noelse", 3, "noelse_tail", 2);
    /* the #else definition of a name is a second definition, keyed name#2 */
    bad |= cyc_st_two("#ifdef ZCL_ALT\n"
                      "int dup_fn(int x) { return x ? 1 : 0; }\n"
                      "#else\n"
                      "int dup_fn(int x) { if (x) return x ? 1 : 0; "
                      "return 0; }\n"
                      "#endif\n", "dup_fn", 2, "dup_fn#2", 3);
    /* a name defined twice outside any conditional still keys as name#2 */
    bad |= cyc_st_two("int twice(int x) { return x ? 1 : 0; }\n"
                      "int twice(int x) { if (x) return 1; return 0; }\n",
                      "twice", 2, "twice#2", 2);
    return bad;
}

/* A `#endif` inside a block comment, a line comment, or a continued string
 * literal is not a directive: honouring one would close the region early,
 * leave the later braces unpaired, and swallow the next function. */
static int cyc_st_pp_hidden(void)
{
    return cyc_st_two("int cmt_pp(int x)\n{\n"
                      "#if ZCL_ALT\n"
                      "    /* #endif */\n"
                      "    /*\n"
                      "#endif\n"
                      "     */\n"
                      "    // #endif\n"
                      "    const char *s = \"\\\n"
                      "#endif\\\n"
                      "\";\n"
                      "    if (x) {\n"
                      "#else\n"
                      "    if (x) {\n"
                      "#endif\n"
                      "        x++;\n"
                      "    }\n"
                      "    return (int)s[x];\n}\n"
                      "int cmt_tail(int y)\n{\n"
                      "    if (y)\n        return 1;\n"
                      "    return 0;\n}\n",
                      "cmt_pp", 3, "cmt_tail", 2);
}

/* Branches that do not end at the same depth have no single structure to
 * resume from. The gate refuses the file instead of silently attributing
 * every later function to this one. */
static int cyc_st_pp_desync(void)
{
    struct cyc_st_acc a;
    memset(&a, 0, sizeof a);
    fputs("check_cyclomatic_complexity selftest: the next z23-lint line is "
          "expected\n", stderr);
    if (cyc_scan_text("int lopsided(int x)\n{\n"
                      "#if ZCL_WIN\n"
                      "    if (x) {\n"
                      "    return 1;\n"
                      "#else\n"
                      "    if (x) { return 2; }\n"
                      "#endif\n"
                      "    return 0;\n}\n"
                      "int swallowed(int y)\n{\n"
                      "    if (y)\n        return 1;\n"
                      "    return 0;\n}\n",
                      "st.c", cyc_st_collect, &a))
        return 0;
    fputs("check_cyclomatic_complexity selftest: unbalanced preprocessor "
          "branches were not refused\n", stderr);
    return 1;
}

static int cyc_st_metric(void)
{
    int bad = cyc_st_logic_ops() | cyc_st_pp_cond() | cyc_st_pp_hidden()
        | cyc_st_pp_desync();
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
