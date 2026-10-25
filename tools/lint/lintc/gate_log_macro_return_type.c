/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-log-macro-return-type of the C23 lint runtime,
 * the replacement for tools/lint/lintc/gate_log_macro_return_type.c. The LOG_*
 * guard macros return from the enclosing function; this gate catches the
 * return-value/type mismatches that compile but invert behavior (LOG_ERR or
 * LOG_NULL inside a bool function, LOG_FAIL inside a non-bool one).
 *
 * Function attribution tracks braces without a preprocessor, so a
 * conditional group is reconciled per group: valid C gives every branch of
 * one #if group the same brace delta, so at #endif the group contributes
 * that common delta, or the raw sum of its branches when they disagree
 * (extern "C" guards, #if 0). Scan roots default to core engine contexts
 * cognition platform tools; build, vendor and .git directories are skipped.
 * Selftest: gate_log_macro_return_type_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_log_macro_return_type_priv.h"

struct lmr_group { long long first, sum, cur; int nbr, aligned; };

struct lmr_file {
    const char *name;
    long long depth;
    int in_block, ret_is_bool;
    struct lmr_buf decl, code, norm, ret, fn;
    struct lmr_group *groups;
    size_t ng, gcap;
    int err;
};

enum lmr_dir { LMR_DIR_NONE, LMR_DIR_IF, LMR_DIR_ELSE, LMR_DIR_ENDIF };

void lmr_buf_free(struct lmr_buf *b)
{
    free(b->p);
    memset(b, 0, sizeof *b);
}

static void lmr_put(struct lmr_buf *b, const char *s, size_t n)
{
    if (b->err)
        return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->n + n + 1)
            nc *= 2;
        char *np = realloc(b->p, nc); // raw-alloc-ok:lint-runtime
        if (!np) {
            b->err = 1;
            return;
        }
        b->p = np;
        b->cap = nc;
    }
    if (n)
        memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void lmr_putf(struct lmr_buf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *tmp = need > 0 ? malloc((size_t)need + 1) : NULL; // raw-alloc-ok:lint-runtime
    if (tmp) {
        (void)vsnprintf(tmp, (size_t)need + 1, fmt, ap2);
        lmr_put(b, tmp, (size_t)need);
    } else if (need > 0) {
        b->err = 1;
    }
    va_end(ap2);
    free(tmp);
}

static int lmr_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int lmr_word(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_';
}

static int lmr_alpha_(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int lmr_upper(char c) { return c >= 'A' && c <= 'Z'; }

static const char *lmr_find(const char *h, size_t hn, const char *nd)
{
    size_t nn = strlen(nd);
    for (size_t i = 0; i + nn <= hn; i++) {
        if (memcmp(h + i, nd, nn) == 0)
            return h + i;
    }
    return NULL;
}

/* End index (past the closing quote) of the literal opening at s[i], or 0. */
static size_t lmr_literal_end(const char *s, size_t n, size_t i, char q)
{
    for (size_t j = i + 1; j < n; j++) {
        if (s[j] == '\\') {
            if (j + 1 >= n)
                return 0;
            j++;
        } else if (s[j] == q) {
            return j + 1;
        }
    }
    return 0;
}

/* Replaces every complete q-quoted literal in b with an empty pair. */
static void lmr_blank_literals(struct lmr_buf *b, char q)
{
    size_t w = 0;
    for (size_t r = 0; r < b->n;) {
        size_t e = b->p[r] == q ? lmr_literal_end(b->p, b->n, r, q) : 0;
        if (e) {
            b->p[w++] = q;
            b->p[w++] = q;
            r = e;
        } else {
            b->p[w++] = b->p[r++];
        }
    }
    b->n = w;
    if (b->p)
        b->p[w] = '\0';
}

/* The line with block comments, // comments and literal bodies removed.
 * in_block carries an open block comment to the next line. */
static void lmr_scrub(int *in_block, const char *line, size_t n, struct lmr_buf *out)
{
    out->n = 0;
    size_t pos = 0;
    while (pos < n) {
        const char *rest = line + pos;
        size_t rl = n - pos;
        if (*in_block) {
            const char *c = lmr_find(rest, rl, "*/");
            if (!c)
                break;
            *in_block = 0;
            pos = (size_t)(c + 2 - line);
            continue;
        }
        const char *open = lmr_find(rest, rl, "/*");
        if (!open) {
            lmr_put(out, rest, rl);
            break;
        }
        lmr_put(out, rest, (size_t)(open - rest));
        const char *close = lmr_find(open + 2, (size_t)(line + n - (open + 2)), "*/");
        if (!close) {
            *in_block = 1;
            break;
        }
        pos = (size_t)(close + 2 - line);
    }
    const char *sl = out->p ? lmr_find(out->p, out->n, "//") : NULL;
    if (sl) {
        out->n = (size_t)(sl - out->p);
        out->p[out->n] = '\0';
    }
    lmr_blank_literals(out, '"');
    lmr_blank_literals(out, '\'');
}

static enum lmr_dir lmr_classify(const char *s, size_t n)
{
    static const struct { const char *w; enum lmr_dir d; } k[] = {
        { "ifdef", LMR_DIR_IF }, { "ifndef", LMR_DIR_IF }, { "if", LMR_DIR_IF },
        { "elif", LMR_DIR_ELSE }, { "else", LMR_DIR_ELSE }, { "endif", LMR_DIR_ENDIF },
    };
    size_t i = lc_skip_ws(s, 0, n);
    if (i >= n || s[i] != '#')
        return LMR_DIR_NONE;
    i = lc_skip_ws(s, i + 1, n);
    size_t e = i;
    while (e < n && lmr_word(s[e]))
        e++;
    for (size_t j = 0; j < sizeof k / sizeof k[0]; j++) {
        if (strlen(k[j].w) == e - i && memcmp(s + i, k[j].w, e - i) == 0)
            return k[j].d;
    }
    return LMR_DIR_NONE;
}

static int lmr_is_pp_line(const char *s, size_t n)
{
    size_t i = lc_skip_ws(s, 0, n);
    return i < n && s[i] == '#';
}

/* Index of the '(' after an all-caps macro name at the start of the line, or 0. */
static size_t lmr_macro_open(const char *s, size_t n)
{
    size_t i = lc_skip_ws(s, 0, n);
    if (i >= n || !lmr_upper(s[i]))
        return 0;
    size_t e = i + 1;
    while (e < n && (lmr_upper(s[e]) || (s[e] >= '0' && s[e] <= '9') || s[e] == '_'))
        e++;
    if (e == i + 1)
        return 0;
    size_t q = lc_skip_ws(s, e, n);
    return q < n && s[q] == '(' ? q : 0;
}

/* An all-caps macro invocation on its own line: NAME ( ... ) with no ; { }. */
static int lmr_is_macro_call(const char *s, size_t n)
{
    size_t q = lmr_macro_open(s, n);
    if (!q)
        return 0;
    size_t last = n;
    while (last > q + 1 && lmr_ws(s[last - 1]))
        last--;
    if (last <= q + 1 || s[last - 1] != ')')
        return 0;
    for (size_t k = q + 1; k < last - 1; k++) {
        if (s[k] == ';' || s[k] == '{' || s[k] == '}')
            return 0;
    }
    return 1;
}

static void lmr_normalize(const char *s, size_t n, struct lmr_buf *out)
{
    out->n = 0;
    int pending = 0;
    for (size_t i = 0; i < n; i++) {
        if (lmr_ws(s[i])) {
            pending = out->n > 0;
            continue;
        }
        if (pending)
            lmr_put(out, " ", 1);
        pending = 0;
        lmr_put(out, s + i, 1);
    }
}

/* Drops a trailing " __attribute__((...))" from the normalized signature. */
static void lmr_cut_attribute(struct lmr_buf *s)
{
    if (s->n < 2 || s->p[s->n - 1] != ')' || s->p[s->n - 2] != ')')
        return;
    for (size_t i = 0; i < s->n; i++) {
        if (s->p[i] != ' ' || strncmp(s->p + i + 1, "__attribute__", 13) != 0)
            continue;
        size_t j = i + 14;
        while (j < s->n && s->p[j] == ' ')
            j++;
        if (j + 3 < s->n && s->p[j] == '(' && s->p[j + 1] == '(') {
            s->n = i;
            s->p[i] = '\0';
            return;
        }
    }
}

static int lmr_not_function_head(const struct lmr_buf *s)
{
    static const char *const k[] = { "if", "for", "while", "switch", "else", "do",
                                     "struct", "enum", "union", "typedef" };
    if (s->n == 0 || s->p[0] == '#' || memchr(s->p, '=', s->n) || memchr(s->p, ';', s->n))
        return 1;
    size_t e = 0;
    while (e < s->n && lmr_word(s->p[e]))
        e++;
    for (size_t j = 0; j < sizeof k / sizeof k[0]; j++) {
        if (strlen(k[j]) == e && memcmp(s->p, k[j], e) == 0)
            return 1;
    }
    return 0;
}

/* The last identifier followed by a parenthesized tail that runs to the end
 * of the signature. Sets its start and end; returns 0 when there is none. */
static int lmr_split_name(const struct lmr_buf *s, size_t *at, size_t *end)
{
    if (s->n < 3 || s->p[s->n - 1] != ')')
        return 0;
    size_t last_bad = 0;
    int have_bad = 0;
    for (size_t i = 0; i < s->n; i++) {
        if (s->p[i] == '{' || s->p[i] == '}') {
            last_bad = i;
            have_bad = 1;
        }
    }
    for (size_t b = s->n - 1; b >= 1; b--) {
        if (!lmr_alpha_(s->p[b]) || lmr_word(s->p[b - 1]))
            continue;
        size_t e = b;
        while (e < s->n && lmr_word(s->p[e]))
            e++;
        size_t q = lc_skip_ws(s->p, e, s->n);
        if (q + 1 < s->n && s->p[q] == '(' && (!have_bad || last_bad < q)) {
            *at = b;
            *end = e;
            return 1;
        }
    }
    return 0;
}

static int lmr_type_is_bool(const char *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        if (!lmr_word(s[i])) {
            i++;
            continue;
        }
        size_t e = i;
        while (e < n && lmr_word(s[e]))
            e++;
        if ((e - i == 4 && memcmp(s + i, "bool", 4) == 0)
            || (e - i == 5 && memcmp(s + i, "_Bool", 5) == 0))
            return 1;
        i = e;
    }
    return 0;
}

static void lmr_reset_fn(struct lmr_file *f)
{
    f->fn.n = 0;
    f->ret.n = 0;
    f->ret_is_bool = 0;
}

/* Sets the current function from the declaration text before an opening
 * brace, or clears it when that text is not a function head. */
static void lmr_enter(struct lmr_file *f, const char *cand, size_t n)
{
    lmr_reset_fn(f);
    lmr_normalize(cand, n, &f->norm);
    size_t at = 0, end = 0;
    if (f->norm.err || lmr_not_function_head(&f->norm))
        return;
    lmr_cut_attribute(&f->norm);
    if (!lmr_split_name(&f->norm, &at, &end))
        return;
    size_t rn = at;
    while (rn > 0 && lmr_ws(f->norm.p[rn - 1]))
        rn--;
    if (rn == 0)
        return;
    lmr_put(&f->ret, f->norm.p, rn);
    lmr_put(&f->fn, f->norm.p + at, end - at);
    f->ret_is_bool = lmr_type_is_bool(f->norm.p, rn);
}

static void lmr_emit(struct lmr_file *f, long long v)
{
    f->depth += v;
    if (f->ng)
        f->groups[f->ng - 1].cur += v;
}

static void lmr_branch(struct lmr_group *g)
{
    if (g->nbr == 0)
        g->first = g->cur;
    else if (g->cur != g->first)
        g->aligned = 0;
    g->sum += g->cur;
    g->nbr++;
}

static void lmr_push_group(struct lmr_file *f)
{
    if (f->ng == f->gcap) {
        size_t nc = f->gcap ? f->gcap * 2 : 16;
        struct lmr_group *np = realloc(f->groups, nc * sizeof *np); // raw-alloc-ok:lint-runtime
        if (!np) {
            f->err = 1;
            return;
        }
        f->groups = np;
        f->gcap = nc;
    }
    f->groups[f->ng++] = (struct lmr_group){ .aligned = 1 };
}

static void lmr_directive(struct lmr_file *f)
{
    enum lmr_dir d = lmr_classify(f->code.p ? f->code.p : "", f->code.n);
    if (d == LMR_DIR_IF) {
        lmr_push_group(f);
    } else if (d == LMR_DIR_ELSE && f->ng) {
        lmr_branch(&f->groups[f->ng - 1]);
        f->groups[f->ng - 1].cur = 0;
    } else if (d == LMR_DIR_ENDIF && f->ng) {
        struct lmr_group g = f->groups[--f->ng];
        lmr_branch(&g);
        lmr_emit(f, g.aligned ? g.first : g.sum);
    }
}

/* Accumulates declaration text at brace depth zero; returns 1 when the line
 * is a bare macro invocation that the caller must not look at further. */
static int lmr_track_decl(struct lmr_file *f)
{
    const char *c = f->code.p ? f->code.p : "";
    size_t n = f->code.n;
    if (lmr_is_pp_line(c, n)) {
        f->decl.n = 0;
    } else {
        if (lmr_is_macro_call(c, n)) {
            f->decl.n = 0;
            return 1;
        }
        lmr_put(&f->decl, c, n);
    }
    const char *brace = memchr(c, '{', n);
    if (brace) {
        const char *d = f->decl.p ? f->decl.p : "";
        const char *cut = memchr(d, '{', f->decl.n);
        lmr_enter(f, d, cut ? (size_t)(cut - d) : f->decl.n);
        f->decl.n = 0;
    } else if (memchr(c, ';', n)) {
        f->decl.n = 0;
    }
    return 0;
}

/* The first LOG_ERR / LOG_NULL call in the line, or NULL. */
static const char *lmr_find_log(const char *s, size_t n, int *is_err)
{
    static const char *const k[] = { "LOG_ERR", "LOG_NULL" };
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && lmr_word(s[i - 1]))
            continue;
        for (int j = 0; j < 2; j++) {
            size_t l = strlen(k[j]);
            if (i + l > n || memcmp(s + i, k[j], l) != 0)
                continue;
            size_t q = lc_skip_ws(s, i + l, n);
            if (q < n && s[q] == '(') {
                *is_err = j == 0;
                return s + i;
            }
        }
    }
    return NULL;
}

static int lmr_has_log_fail(const char *s, size_t n)
{
    for (size_t i = 0; i + 8 <= n; i++) {
        if ((i > 0 && lmr_word(s[i - 1])) || memcmp(s + i, "LOG_FAIL", 8) != 0)
            continue;
        size_t q = lc_skip_ws(s, i + 8, n);
        if (q < n && s[q] == '(')
            return 1;
    }
    return 0;
}

static void lmr_check_logs(struct lmr_file *f, int line_no, struct lmr_buf *bad)
{
    const char *c = f->code.p ? f->code.p : "";
    int is_err = 0;
    if (f->ret_is_bool && lmr_find_log(c, f->code.n, &is_err)) {
        lmr_putf(bad, "  %s:%d: %s returns %s but %s returns %s\n", f->name, line_no,
                 f->fn.p, f->ret.p, is_err ? "LOG_ERR" : "LOG_NULL", is_err ? "-1" : "NULL");
    }
    if (!f->ret_is_bool && lmr_has_log_fail(c, f->code.n)) {
        lmr_putf(bad, "  %s:%d: %s returns %s but LOG_FAIL returns false\n", f->name,
                 line_no, f->fn.p, f->ret.p);
    }
}

static long long lmr_brace_delta(const char *s, size_t n)
{
    long long d = 0;
    for (size_t i = 0; i < n; i++)
        d += (s[i] == '{') - (s[i] == '}');
    return d;
}

static void lmr_line(struct lmr_file *f, const char *raw, size_t rn, int line_no,
                     struct lmr_buf *bad)
{
    lmr_scrub(&f->in_block, raw, rn, &f->code);
    lmr_directive(f);
    if (f->depth == 0 && lmr_track_decl(f))
        return;
    const char *c = f->code.p ? f->code.p : "";
    if (f->fn.n)
        lmr_check_logs(f, line_no, bad);
    long long d = lmr_brace_delta(c, f->code.n);
    if (f->ng)
        f->groups[f->ng - 1].cur += d;
    else
        f->depth += d;
    if (f->depth <= 0) {
        f->depth = 0;
        lmr_reset_fn(f);
        if (memchr(c, '}', f->code.n))
            f->decl.n = 0;
    }
}

int lmr_scan_text(const char *file, const char *text, size_t len, struct lmr_buf *bad)
{
    struct lmr_file f = { .name = file };
    int line_no = 0;
    for (size_t pos = 0; pos < len && !f.err && !bad->err;) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t ln = nl ? (size_t)(nl - (text + pos)) : len - pos;
        lmr_line(&f, text + pos, ln, ++line_no, bad);
        pos += ln + (nl ? 1 : 0);
    }
    int rc = f.err || f.decl.err || f.code.err || f.norm.err || f.ret.err || f.fn.err
        || bad->err;
    lmr_buf_free(&f.decl);
    lmr_buf_free(&f.code);
    lmr_buf_free(&f.norm);
    lmr_buf_free(&f.ret);
    lmr_buf_free(&f.fn);
    free(f.groups);
    return rc ? die("z23-lint: out of memory\n", "") : 0;
}

struct lmr_list { char **v; size_t n, cap; };

static int lmr_list_add(struct lmr_list *l, const char *path)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 256;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    size_t n = strlen(path);
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, path, n + 1);
    l->v[l->n++] = copy;
    return 0;
}

static int lmr_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int lmr_component_skipped(const char *path)
{
    static const char *const k[] = { "build", "vendor", ".git" };
    for (const char *p = path; *p;) {
        const char *e = strchr(p, '/');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        for (size_t j = 0; j < sizeof k / sizeof k[0]; j++) {
            if (strlen(k[j]) == l && memcmp(p, k[j], l) == 0)
                return 1;
        }
        if (!e)
            break;
        p = e + 1;
    }
    return 0;
}

static int lmr_fixture_name(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    size_t n = strlen(base);
    if (base[0] != '_' || n < 2)
        return 0;
    const char *fx = strstr(base + 1, "fixture");
    return fx && (size_t)(fx - base) + 7 + 2 <= n;
}

static int lmr_path_excluded(const char *path)
{
    static const char pre[] = "tests/harness/include/test/";
    const char *p = strncmp(path, "./", 2) == 0 ? path + 2 : path;
    if (lmr_component_skipped(path) || strncmp(p, pre, sizeof pre - 1) == 0
        || strcmp(path, "./platform/modules/util/include/util/log_macros.h") == 0)
        return 1;
    const char *e = getenv("ZCL_LINT_PRODUCTION_SCAN");
    return e && strcmp(e, "1") == 0 && lmr_fixture_name(path);
}

static int lmr_consider(struct lmr_list *l, const char *path)
{
    size_t n = strlen(path);
    struct stat st;
    if (n < 2 || path[n - 2] != '.' || (path[n - 1] != 'c' && path[n - 1] != 'h'))
        return 0;
    if (lmr_path_excluded(path))
        return 0;
    if (stat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (!S_ISREG(st.st_mode))
        return 0;
    return lmr_list_add(l, path);
}

static int lmr_walk(struct lmr_list *l, const char *dir);

static int lmr_entries(struct lmr_list *l, DIR *d, const char *dir)
{
    int rc = 0;
    struct dirent *de;
    while (rc == 0) {
        errno = 0;
        de = readdir(d);
        if (!de) {
            if (errno)
                rc = die("z23-lint: cannot read directory %s\n", dir);
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char path[4096];
        size_t dl = strlen(dir);
        int w = snprintf(path, sizeof path, "%s%s%s", dir, dl && dir[dl - 1] == '/' ? "" : "/", de->d_name);
        struct stat st;
        if (w < 0 || (size_t)w >= sizeof path)
            rc = die("z23-lint: path too long under %s\n", dir);
        else if (lstat(path, &st) != 0)
            rc = die("z23-lint: cannot stat %s\n", path);
        else if (S_ISDIR(st.st_mode))
            rc = lmr_walk(l, path);
        else
            rc = lmr_consider(l, path);
    }
    return rc;
}

static int lmr_walk(struct lmr_list *l, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return die("z23-lint: cannot open directory %s\n", dir);
    int rc = lmr_entries(l, d, dir);
    if (closedir(d) != 0 && rc == 0)
        rc = die("z23-lint: cannot close directory %s\n", dir);
    return rc;
}

static int lmr_collect(struct lmr_list *l, int argc, char **argv)
{
    static const char *const defaults[] = { "core", "engine", "contexts", "cognition", "platform", "tools" };
    size_t n = argc > 0 ? (size_t)argc : sizeof defaults / sizeof defaults[0];
    for (size_t i = 0; i < n; i++) {
        const char *root = argc > 0 ? argv[i] : defaults[i];
        struct stat st;
        if (lstat(root, &st) != 0) {
            fprintf(stderr, "check_log_macro_return_type: cannot stat %s: %s\n", root, strerror(errno));
            return 2;
        }
        int rc = S_ISDIR(st.st_mode) ? lmr_walk(l, root) : lmr_consider(l, root);
        if (rc)
            return rc;
    }
    qsort(l->v, l->n, sizeof l->v[0], lmr_cmp);
    return 0;
}

/* These tests live beside the private traversal functions so the scanner's
 * public surface need not expose directory streams or collection internals. */
int lmr_filesystem_selftest(void)
{
    char tmp[4096], path[4096];
    const char *tmpdir = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(tmpdir)
        || ovf(snprintf(tmp, sizeof tmp, "%s/z23-lmr-scan-XXXXXX",
                        tmpdir), sizeof tmp) || !mkdtemp(tmp))
        return 1;
    struct lmr_list files = { 0 };
    int bad = lmr_walk(&files, tmp) != 0 || files.n != 0;
    if (ovf(snprintf(path, sizeof path, "%s/missing.c", tmp), sizeof path))
        bad = 1;
    else {
        char *roots[] = { path };
        bad |= lmr_collect(&files, 1, roots) != 2;
        bad |= symlink("missing-target", path) != 0;
        bad |= lmr_collect(&files, 1, roots) != 2;
        bad |= unlink(path) != 0;
        bad |= csr_write(path, "int f(void) { return 0; }\n") != 0;
        bad |= lmr_walk(&files, path) != 2; /* opendir on a regular file. */
        bad |= lmr_collect(&files, 1, roots) != 0 || files.n != 1;
    }
    DIR *d = opendir(tmp);
    if (!d)
        bad = 1;
    else {
        /* Existing directory entries paired with a vanished parent exercise
         * the child lstat failure, independently of the root preflight. */
        bad |= lmr_entries(&files, d, path) != 2;
        bad |= closedir(d) != 0;
    }
    d = opendir(tmp);
    if (!d)
        bad = 1;
    else {
        /* Before the first read there are no buffered entries. Invalidating
         * the descriptor forces readdir to distinguish EBADF from EOF. */
        if (close(dirfd(d)) != 0)
            bad = 1;
        else
            bad |= lmr_entries(&files, d, tmp) != 2;
        (void)closedir(d);
    }
    for (size_t i = 0; i < files.n; i++)
        free(files.v[i]);
    free(files.v);
    bad |= rap_rm_rf(tmp) != 0;
    if (bad)
        fputs("check_log_macro_return_type: filesystem SELFTEST FAILED\n", stderr);
    return bad;
}

static int lmr_read(const char *path, struct lmr_buf *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return die("z23-lint: cannot open %s\n", path);
    char chunk[16384];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, fp)) > 0)
        lmr_put(out, chunk, got);
    int bad = ferror(fp) || out->err;
    fclose(fp);
    return bad ? die("z23-lint: cannot read %s\n", path) : 0;
}

static int lmr_scan_all(const struct lmr_list *l, struct lmr_buf *bad)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < l->n; i++) {
        struct lmr_buf text = { 0 };
        rc = lmr_read(l->v[i], &text);
        if (rc == 0)
            rc = lmr_scan_text(l->v[i], text.p ? text.p : "", text.n, bad);
        lmr_buf_free(&text);
    }
    return rc;
}

static int lmr_report(const struct lmr_buf *bad)
{
    if (bad->n == 0) {
        puts("check_log_macro_return_type: clean");
        return 0;
    }
    fputs("FAIL: LOG_* macro return-type mismatches found:\n", stdout);
    fputs(bad->p, stdout);
    fputs("Use LOG_FAIL only in bool-returning functions, LOG_ERR only in int-returning "
          "handlers/functions, and LOG_NULL only in pointer-returning functions.\n", stdout);
    return 1;
}

int check_log_macro_return_type_run(int argc, char **argv)
{
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot enter %s\n", root);
    struct lmr_list files = { 0 };
    struct lmr_buf bad = { 0 };
    int rc = lmr_collect(&files, argc, argv);
    if (rc == 0)
        rc = lmr_scan_all(&files, &bad);
    if (rc == 0)
        rc = lmr_report(&bad);
    for (size_t i = 0; i < files.n; i++)
        free(files.v[i]);
    free(files.v);
    lmr_buf_free(&bad);
    return rc;
}
