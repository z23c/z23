/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The make half of the non-C/H build-input rule: which changed paths the makefiles name where make can change an object with them. */
#include "devloop_facts_make.h"

#include "util/safe_alloc.h"
#include "util/str_suffix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

bool fxm_put(struct fxm_buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t next = b->cap ? b->cap : 256;
        char *g;
        while (next < b->n + n + 1)
            next *= 2;
        if (next > FXM_LINE_MAX ||
            (g = zcl_realloc(b->p, next, "facts_consumer.mk")) == NULL)
            return false;
        b->p = g;
        b->cap = next;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
    return true;
}

bool fxm_ident(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
}

bool fxm_space(char ch)
{
    return ch == ' ' || ch == '\t';
}

/* The next logical line at *at, continuations joined by a space: 0 at the
 * end, -1 when it cannot be held. pos[0] counts the lines read; pos[1] is
 * the first line of this one. */
static int fxm_next_line(struct fxm_buf *line, const char **at, bool *recipe,
                         bool *comment, uint32_t pos[2])
{
    const char *p = *at, *q = p;
    bool more = true;
    if (*p == '\0')
        return 0;
    line->n = 0;
    pos[1] = pos[0] + 1;
    *recipe = *p == '\t';
    while (fxm_space(*q))
        q++;
    *comment = !*recipe && *q == '#';
    while (more) {
        const char *e = strchr(p, '\n');
        size_t n = e != NULL ? (size_t)(e - p) : strlen(p), bs = 0;
        while (bs < n && p[n - 1 - bs] == '\\')
            bs++;
        more = e != NULL && bs % 2 == 1;
        if (!fxm_put(line, p, more ? n - 1 : n) || !fxm_put(line, " ", 1))
            return -1;
        p = e != NULL ? e + 1 : p + n;
        pos[0]++;
    }
    *at = p;
    return 1;
}

static bool fxm_var_add(struct fxm *m, const char *name, size_t n,
                        const char *value, bool many)
{
    struct fxm_var *v;
    if (m->nvars == m->capvars) {
        size_t next = m->capvars ? m->capvars * 2 : 256;
        struct fxm_var *g =
            zcl_realloc(m->vars, next * sizeof(*g), "facts_consumer.mkvars");
        if (g == NULL)
            return false;
        m->vars = g;
        m->capvars = next;
    }
    v = &m->vars[m->nvars];
    v->name = zcl_malloc(n + 1, "facts_consumer.mkvar");
    v->value = value != NULL ? zcl_strdup(value, "facts_consumer.mkval") : NULL;
    v->many = many;
    if (v->name == NULL || (value != NULL && v->value == NULL)) {
        free(v->name);
        free(v->value);
        return false;
    }
    memcpy(v->name, name, n);
    v->name[n] = '\0';
    m->nvars++;
    return true;
}

/* The operator after a variable name: its length, 0 when there is none.
 * *path_like: the value can stand for one word ('+=' and '!=' cannot). */
static size_t fxm_op(const char *p, bool *path_like)
{
    static const char *const ops[] = {":::=", "::=", ":=", "?=", "=", "+=",
                                      "!="};
    for (size_t k = 0; k < sizeof(ops) / sizeof(ops[0]); k++)
        if (strncmp(p, ops[k], strlen(ops[k])) == 0) {
            *path_like = k < 5;
            return strlen(ops[k]);
        }
    return 0;
}

const char *fxm_skip_prefixes(const char *p)
{
    static const char *const pre[] = {"override ", "export ", "private "};
    bool again = true;
    while (again) {
        again = false;
        while (fxm_space(*p))
            p++;
        for (size_t k = 0; k < sizeof(pre) / sizeof(pre[0]); k++)
            if (strncmp(p, pre[k], strlen(pre[k])) == 0) {
                p += strlen(pre[k]);
                again = true;
            }
    }
    return p;
}

/* A definition on a logical line: `define NAME` or `NAME op value`. */
static bool fxm_def(struct fxm *m, char *line, bool *in_define)
{
    const char *p = fxm_skip_prefixes(line), *name, *v;
    size_t n, op;
    bool path_like = false;
    char *end;
    if (strncmp(p, "define", 6) == 0 && fxm_space(p[6])) {
        *in_define = true;
        p = fxm_skip_prefixes(p + 6);
        for (n = 0; fxm_ident(p[n]); n++)
            ;
        return n == 0 || fxm_var_add(m, p, n, NULL, false);
    }
    for (name = p, n = 0; fxm_ident(p[n]); n++)
        ;
    for (p += n; fxm_space(*p); p++)
        ;
    if (n == 0 || (op = fxm_op(p, &path_like)) == 0)
        return true;
    for (v = p + op; fxm_space(*v); v++)
        ;
    end = line + strlen(line);
    while (end > v && fxm_space(end[-1]))
        *--end = '\0';
    if (!path_like || *v == '\0')
        v = NULL;
    return fxm_var_add(m, name, n, v, v != NULL && strpbrk(v, " \t") != NULL);
}

static int fxm_var_cmp(const void *a, const void *b)
{
    const struct fxm_var *x = a, *y = b;
    return strcmp(x->name, y->name);
}

/* Sort by name; a name defined twice has no single value. */
static void fxm_vars_seal(struct fxm *m)
{
    size_t w = 0;
    if (m->nvars > 1)
        qsort(m->vars, m->nvars, sizeof(*m->vars), fxm_var_cmp);
    for (size_t k = 0; k < m->nvars; k++) {
        if (w > 0 && strcmp(m->vars[w - 1].name, m->vars[k].name) == 0) {
            free(m->vars[w - 1].value);
            m->vars[w - 1].value = NULL;
            free(m->vars[k].name);
            free(m->vars[k].value);
            continue;
        }
        m->vars[w++] = m->vars[k];
    }
    m->nvars = w;
}

static const char *fxm_value(const struct fxm *m, const char *name, size_t n)
{
    size_t lo = 0, hi = m->nvars;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int d = strncmp(m->vars[mid].name, name, n);
        if (d == 0 && m->vars[mid].name[n] != '\0')
            d = 1;
        if (d == 0)
            return m->vars[mid].many && !m->lists ? NULL : m->vars[mid].value;
        if (d < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

/* '%' in s[from..] is shell text: FXM_PCT. */
static void fxm_shell_text(struct fxm_buf *b, size_t from)
{
    for (size_t k = from; k < b->n; k++)
        if (b->p[k] == '%')
            b->p[k] = FXM_PCT;
}

/* '%' in b[from..to) is a make pattern, a recipe's too: FXM_OPEN. */
static void fxm_pattern_text(struct fxm_buf *b, size_t from, size_t to)
{
    for (size_t k = from; k < to && k < b->n; k++)
        if (b->p[k] == '%')
            b->p[k] = FXM_OPEN;
}

/* The end of the call argument that starts at s[k] (a ',' outside any
 * reference), or n. */
static size_t fxm_arg_to(const char *s, size_t k, size_t n)
{
    int depth = 0;
    for (; k < n; k++) {
        if (s[k] == '(' || s[k] == '{')
            depth++;
        else if (s[k] == ')' || s[k] == '}')
            depth--;
        else if (s[k] == ',' && depth == 0)
            return k;
    }
    return n;
}

/* A call whose value holds only words its arguments spell: $(foreach)'s
 * and $(call)'s through the variables they read, $(wildcard)'s and
 * $(patsubst)'s through their patterns. */
static bool fxm_passing_call(const char *s, size_t k)
{
    static const char *const fns[] = {
        "if",     "or",       "and",    "strip",  "sort",    "firstword",
        "lastword", "word",   "wordlist", "filter", "filter-out", "foreach",
        "call",   "value",    "eval",   "error",  "info",    "warning",
        "wildcard", "patsubst"};
    for (size_t f = 0; f < sizeof(fns) / sizeof(fns[0]); f++)
        if (strlen(fns[f]) == k && strncmp(s, fns[f], k) == 0)
            return true;
    return false;
}

/* s[0..n) less its surrounding spaces is word. */
static bool fxm_trimmed_is(const char *s, size_t n, const char *word)
{
    while (n > 0 && fxm_space(*s)) {
        s++;
        n--;
    }
    while (n > 0 && fxm_space(s[n - 1]))
        n--;
    return n == strlen(word) && strncmp(s, word, n) == 0;
}

/* t[0..n) between FXM_HIDE_ON and FXM_HIDE_OFF: words of a call's value
 * that never stand alone in it. */
static bool fxm_hidden(struct fxm_buf *out, const char *t, size_t n)
{
    char on = FXM_HIDE_ON, off = FXM_HIDE_OFF;
    return fxm_put(out, &on, 1) && fxm_put(out, t, n) && fxm_put(out, &off, 1) &&
           fxm_put(out, " ", 1);
}

/* $(addprefix P,W) (prefix) or $(addsuffix S,W) after its leading space:
 * P glued before an FXM_OPEN run, or S after one; W's words are joined. */
static bool fxm_join_call(const char *s, size_t k, size_t arg, size_t n,
                          bool prefix, struct fxm_buf *out)
{
    char open = FXM_OPEN;
    return (prefix || fxm_put(out, &open, 1)) &&
           fxm_put(out, s + k + 1, arg - k - 1) &&
           (!prefix || fxm_put(out, &open, 1)) && fxm_put(out, " ", 1) &&
           fxm_hidden(out, s + arg, n - arg);
}

/* s[0..n) expanded FXM_ROUNDS deep into x (y scratch), its surrounding
 * spaces dropped; false when it cannot be, or a reference remains. */
static bool fxm_expand_into(struct fxm *m, const char *s, size_t n,
                            struct fxm_buf *x, struct fxm_buf *y)
{
    bool ok = fxm_put(x, s, n), left = true;
    char *p, *e;
    for (int r = 0; ok && left && r < FXM_ROUNDS; r++) {
        struct fxm_buf t;
        ok = fxm_round(m, x->p, y, &left);
        t = *x;
        *x = *y;
        *y = t;
    }
    if (!ok || left)
        return false;
    for (p = x->p; fxm_space(*p); p++)
        ;
    for (e = p + strlen(p); e > p && fxm_space(e[-1]); e--)
        ;
    memmove(x->p, p, (size_t)(e - p));
    x->p[e - p] = '\0';
    return true;
}

/* The text of the repo file path names ('$' in it FXM_ANY: make does not
 * expand it again); NULL when it is not one literal repo file. */
static uint8_t *fxm_file_text(const struct fxm *m, const char *path, size_t *len)
{
    uint8_t *b = NULL;
    if (*path == '\0' || strpbrk(path, FXM_WILDS) != NULL || *path == '/' ||
        strstr(path, "..") != NULL ||
        !zcl_devloop_facts_read(m->root, NULL, path, "", FXM_FILE_MAX, &b, len))
        return NULL;
    if (memchr(b, '\0', *len) != NULL) {
        free(b);
        return NULL;
    }
    for (size_t k = 0; k < *len; k++)
        b[k] = b[k] == '$' ? (uint8_t)FXM_ANY : b[k];
    return b;
}

/* $(file <PATH) (a, n: its argument text): its arguments and the words of
 * the repo file PATH expands to, read now as make reads it; FXM_OPEN when
 * it names no such file. $(file >..) writes: its value is empty. */
static bool fxm_file_call(struct fxm *m, const char *a, size_t n,
                          struct fxm_buf *out)
{
    struct fxm_buf x = {0}, y = {0};
    uint8_t *b = NULL;
    size_t k = 0, len = 0;
    char open = FXM_OPEN;
    bool ok;
    while (k < n && fxm_space(a[k]))
        k++;
    if (k < n && a[k] == '<' && fxm_expand_into(m, a + k + 1, n - k - 1, &x, &y))
        b = fxm_file_text(m, x.p, &len);
    ok = fxm_put(out, a, n) && fxm_put(out, " ", 1) &&
         (k == n || a[k] != '<' ||
          (b != NULL ? fxm_put(out, (const char *)b, len) : fxm_put(out, &open, 1))) &&
         fxm_put(out, " ", 1);
    free(x.p);
    free(y.p);
    free(b);
    return ok;
}

/* t[0..n) holds a character a name spells (not only '.', '-', runs and
 * separators). */
static bool fxm_literal_char_n(const char *t, size_t n)
{
    for (size_t k = 0; k < n; k++)
        if (fxm_ident(t[k]) && t[k] != '.' && t[k] != '-')
            return true;
    return false;
}


/* A call whose value's words are each a part of one argument word (4:
 * $(notdir), 5: $(basename)), or all of one shape (1: $(dir), ending in
 * '/'; 2: $(suffix), starting with '.'; 3: $(abspath) and $(realpath),
 * starting with '/'); 0 for any other. */
static int fxm_shrink_kind(const char *s, size_t k)
{
    static const char *const fns[] = {"dir", "suffix", "abspath", "notdir",
                                      "basename", "realpath"};
    static const int kind[] = {1, 2, 3, 4, 5, 3};
    for (size_t f = 0; f < sizeof(fns) / sizeof(fns[0]); f++)
        if (strlen(fns[f]) == k && strncmp(s, fns[f], k) == 0)
            return kind[f];
    return 0;
}

/* The last c in w[from..n); n for none. */
static size_t fxm_last(const char *w, size_t from, size_t n, char c)
{
    size_t at = n;
    for (size_t k = from; k < n; k++)
        at = w[k] == c ? k : at;
    return at;
}

/* The first run character (a wildcard or unknown) in w[from..n); n for
 * none. */
static size_t fxm_first_run(const char *w, size_t from, size_t n)
{
    for (size_t k = from; k < n; k++)
        if (strchr(FXM_WILDS, w[k]) != NULL)
            return k;
    return n;
}

/* $(notdir) (kind 4) or $(basename) (kind 5) of the word w[0..n), as a
 * glob: what follows its last '/'; what precedes its last component's
 * '.', or its text up to a run in that component and then any run (the
 * run may hold the '.'). A part no literal text pins is FXM_OPEN. */
static bool fxm_shrink_word(int kind, const char *w, size_t n,
                            struct fxm_buf *out)
{
    size_t slash = fxm_last(w, 0, n, '/'), from = slash < n ? slash + 1 : 0;
    size_t cut;
    char open = FXM_OPEN;
    bool run = false;
    if (kind == 4) {
        w += from;
        n -= from;
    } else if ((cut = fxm_first_run(w, from, n)) < n) {
        n = cut;
        run = true;
    } else {
        n = fxm_last(w, from, n, '.');
    }
    if (n == 0 && !run)
        return true;
    if (!fxm_literal_char_n(w, n))
        return fxm_put(out, &open, 1) && fxm_put(out, " ", 1);
    return fxm_put(out, w, n) && (!run || fxm_put(out, &open, 1)) &&
           fxm_put(out, " ", 1);
}

/* $(dir) and the like (fxm_shrink_kind; a[0..n) its argument text): the
 * arguments hidden (their words name paths, never a goal as they stand),
 * then each word's part (fxm_shrink_word, the arguments expanded a
 * many-word value as its words) or the shape every part has. */
static bool fxm_shrink_call(struct fxm *m, int kind, const char *a, size_t n,
                            struct fxm_buf *out)
{
    static const char *const shape[] = {"", "\x03/ ", ".\x03 ", "/\x03 "};
    struct fxm_buf x = {0}, y = {0};
    char open[] = {FXM_OPEN, ' '};
    bool ok, lists = m->lists;
    if (!fxm_hidden(out, a, n))
        return false;
    if (kind < 4)
        return fxm_put(out, shape[kind], strlen(shape[kind]));
    m->lists = true;
    ok = fxm_expand_into(m, a, n, &x, &y);
    m->lists = lists;
    if (!ok)
        ok = fxm_put(out, open, 2);
    else
        for (const char *p = x.p, *e; ok && *p != '\0'; p = e) {
            while (fxm_sep(*p))
                p++;
            for (e = p; *e != '\0' && !fxm_sep(*e); e++)
                ;
            ok = e == p || fxm_shrink_word(kind, p, (size_t)(e - p), out);
        }
    free(x.p);
    free(y.p);
    return ok;
}

/* The value of the call s[0..n) (its name s[0..k)): its arguments, '%' in
 * a $(shell) argument shell text and in $(patsubst)'s patterns a make
 * pattern; $(addprefix) and $(addsuffix) as fxm_join_call says; a call
 * that makes words its arguments do not spell also yields a lone
 * FXM_OPEN. Words that never stand alone in the value (those a join or a
 * '%' $(patsubst) pattern rewrites) sit between FXM_HIDE_ON and
 * FXM_HIDE_OFF. */
static bool fxm_args_call(const char *s, size_t k, size_t n, size_t arg,
                          struct fxm_buf *out);

static bool fxm_call(struct fxm *m, const char *s, size_t k, size_t n,
                     struct fxm_buf *out)
{
    size_t arg = fxm_arg_to(s, k + 1, n);
    if (!fxm_put(out, " ", 1))
        return false;
    if (k == 4 && strncmp(s, "file", 4) == 0)
        return fxm_file_call(m, s + k + 1, n - k - 1, out);
    if (fxm_shrink_kind(s, k) > 0)
        return fxm_shrink_call(m, fxm_shrink_kind(s, k), s + k + 1, n - k - 1, out);
    if (k == 9 && (strncmp(s, "addprefix", 9) == 0 || strncmp(s, "addsuffix", 9) == 0))
        return fxm_join_call(s, k, arg, n, s[3] == 'p', out);
    return fxm_args_call(s, k, n, arg, out);
}

/* fxm_call for a call whose value is read from its argument text as it
 * stands (arg: the end of its first argument). */
static bool fxm_args_call(const char *s, size_t k, size_t n, size_t arg,
                          struct fxm_buf *out)
{
    size_t to = n, at = out->n;
    char open = FXM_OPEN;
    bool pattern = k == 8 && strncmp(s, "patsubst", 8) == 0;
    if (pattern && fxm_trimmed_is(s + k + 1, arg - k - 1, "%"))
        to = fxm_arg_to(s, arg + 1, n);
    if (!fxm_put(out, s + k + 1, to - k - 1))
        return false;
    if (k == 5 && strncmp(s, "shell", 5) == 0)
        fxm_shell_text(out, at);
    if (pattern)
        fxm_pattern_text(out, at, at + fxm_arg_to(s, arg + 1, n) - k - 1);
    if (to < n)
        return fxm_put(out, " ", 1) && fxm_hidden(out, s + to, n - to);
    if (!fxm_put(out, " ", 1))
        return false;
    return fxm_passing_call(s, k) || (fxm_put(out, &open, 1) && fxm_put(out, " ", 1));
}

/* A substitution reference's value (s[0..n), its ':' at colon): each
 * word that ends as its pattern does, rewritten, as a glob; any other
 * word of the variable's value as it is (an include's many-word value's
 * words; else FXM_ANY, the definition's words being followed, or
 * FXM_OPEN for an automatic variable's). */
static bool fxm_subst_ref(struct fxm *m, const char *s, size_t colon,
                          size_t n, struct fxm_buf *out)
{
    const char *eq = memchr(s + colon, '=', n - colon), *v;
    size_t at, to = (size_t)(eq + 1 - s), k = 0;
    char open = FXM_OPEN, rest = strchr("@<^+*?|%", s[0]) != NULL ? FXM_OPEN : FXM_ANY;
    while (k < colon && fxm_ident(s[k]))
        k++;
    v = k == colon && k > 0 && m->lists ? fxm_value(m, s, k) : NULL;
    if (fxm_trimmed_is(s + colon + 1, (size_t)(eq - s) - colon - 1, "%")) {
        v = NULL; /* every word is rewritten: none stays as it is */
        rest = ' ';
    }
    if (!fxm_put(out, " ", 1) ||
        (memchr(s + to, '%', n - to) == NULL && !fxm_put(out, &open, 1)))
        return false;
    at = out->n;
    if (!fxm_put(out, s + to, n - to))
        return false;
    fxm_pattern_text(out, at, out->n);
    return fxm_put(out, " ", 1) &&
           (v != NULL ? fxm_put(out, v, strlen(v)) : fxm_put(out, &rest, 1)) &&
           fxm_put(out, " ", 1);
}

/* The ':' of a substitution reference s[0..n) ($(X:a=b)): outside any
 * reference, an '=' after it; n for none. */
size_t fxm_subst_colon(const char *s, size_t n)
{
    int depth = 0;
    for (size_t k = 0; k < n; k++) {
        if (s[k] == '(' || s[k] == '{')
            depth++;
        else if (s[k] == ')' || s[k] == '}')
            depth--;
        else if (s[k] == ':' && depth == 0)
            return memchr(s + k, '=', n - k) != NULL ? k : n;
    }
    return n;
}

/* The body of one reference: a call its value (fxm_call), a substitution
 * reference its rewritten words (fxm_subst_ref), an automatic variable
 * FXM_OPEN (a value no text of the makefile spells), a path-like variable
 * its value, anything else FXM_ANY. */
static bool fxm_inner(struct fxm *m, const char *s, size_t n,
                      struct fxm_buf *out)
{
    const char *v;
    size_t k = 0, colon;
    char any = FXM_ANY, open = FXM_OPEN;
    while (k < n && fxm_ident(s[k]))
        k++;
    if (k > 0 && k < n && fxm_space(s[k]))
        return fxm_call(m, s, k, n, out);
    if ((colon = fxm_subst_colon(s, n)) < n)
        return fxm_subst_ref(m, s, colon, n, out);
    if (n > 0 && strchr("@<^+*?|%", s[0]) != NULL)
        return fxm_put(out, &open, 1);
    v = k == n && k > 0 ? fxm_value(m, s, n) : NULL;
    if (v == NULL)
        return fxm_put(out, &any, 1);
    k = out->n;
    if (!fxm_put(out, v, strlen(v)))
        return false;
    /* A many-word value read in place: what its calls only test or print
     * is no word of it. */
    if (m->lists)
        fxm_blank(m, out->p + k);
    return true;
}

/* A call's value is words: one glued to text before or after it is a run
 * of that text's word (FXM_ANY on that side). */
static bool fxm_glued(const char *s, size_t n)
{
    size_t k = 0;
    while (k < n && fxm_ident(s[k]))
        k++;
    return k > 0 && k < n && fxm_space(s[k]);
}

/* The reference at d ('$'): where the text resumes; NULL when out cannot
 * hold it or it does not close (then the text is UNKNOWN). */
/* Past the bracket that closes the bracketed reference at d; NULL when it
 * does not close. */
static const char *fxm_ref_past(const char *d)
{
    char open = d[1], close = open == '(' ? ')' : '}';
    const char *q = d + 2;
    int depth = 1;
    for (; *q != '\0' && depth > 0; q++)
        depth += *q == open ? 1 : *q == close ? -1 : 0;
    return depth > 0 ? NULL : q;
}

/* FXM_ANY into out when glue: a call's value joined to word text. */
static bool fxm_glue(struct fxm_buf *out, bool glue)
{
    char any = FXM_ANY;
    return !glue || fxm_put(out, &any, 1);
}

static const char *fxm_ref(struct fxm *m, const char *d,
                           struct fxm_buf *out)
{
    const char *q;
    bool call;
    size_t n;
    if (d[1] == '\0')
        return d + 1;
    if (d[1] != '(' && d[1] != '{')
        return fxm_inner(m, d + 1, 1, out) ? d + 2 : NULL;
    if ((q = fxm_ref_past(d)) == NULL)
        return NULL;
    n = (size_t)(q - 1 - (d + 2));
    call = fxm_glued(d + 2, n);
    if (!fxm_glue(out, call && out->n > 0 && !fxm_sep(out->p[out->n - 1])) ||
        !fxm_inner(m, d + 2, n, out) ||
        !fxm_glue(out, call && *q != '\0' && !fxm_sep(*q)))
        return NULL;
    return q;
}

/* One expansion round of in into out; *left: a reference remains. */
bool fxm_round(struct fxm *m, const char *in, struct fxm_buf *out,
               bool *left)
{
    const char *p = in;
    out->n = 0;
    if (!fxm_put(out, "", 0))
        return false;
    *left = false;
    while (p != NULL && *p != '\0') {
        const char *d = strchr(p, '$');
        if (d == NULL)
            return fxm_put(out, p, strlen(p));
        if (!fxm_put(out, p, (size_t)(d - p)))
            return false;
        *left = true;
        p = d[1] == '$' ? d + 2 : fxm_ref(m, d, out);
    }
    return p != NULL;
}

/* A glob against a path: '*', '%', '$', FXM_ANY and FXM_OPEN match any run of
 * characters, '/' included; '?' and a '[...]' set match any one character
 * (a superset of the set); a trailing '/' matches a whole directory. */
static bool fxm_run(char ch)
{
    return ch == '*' || ch == '%' || ch == '$' || ch == FXM_ANY || ch == FXM_OPEN;
}

static const char *fxm_one_end(const char *p)
{
    const char *e;
    if (*p == '?')
        return p + 1;
    return *p == '[' && (e = strchr(p + 1, ']')) != NULL ? e + 1 : NULL;
}

bool fxm_glob(const char *p, const char *s)
{
    const char *star = NULL, *back = NULL, *w;
    while (*s != '\0') {
        if (p[0] == '/' && p[1] == '\0' && *s == '/')
            return true;
        if (fxm_run(*p)) {
            star = ++p;
            back = s;
        } else if ((w = fxm_one_end(p)) != NULL || *p == *s) {
            p = w != NULL ? w : p + 1;
            s++;
        } else if (star != NULL) {
            p = star;
            s = ++back;
        } else {
            return false;
        }
    }
    while (fxm_run(*p))
        p++;
    return *p == '\0';
}

static bool fxm_named(const char *t, const char *path)
{
    const char *base = strrchr(path, '/');
    size_t tn = strlen(t), bn;
    base = base != NULL ? base + 1 : path;
    bn = strlen(base);
    if (tn > 1 && t[tn - 1] == '/' && strncmp(path, t, tn) == 0)
        return true;
    /* A directory mention with no trailing slash (the common recipe-argument
     * form: a tool is handed a bare directory and reads whatever is under
     * it) is just as much a directory as one written with a trailing '/':
     * t is an exact path-component prefix of path when the next byte of
     * path after t is '/'. */
    if (tn > 0 && strncmp(path, t, tn) == 0 && path[tn] == '/')
        return true;
    for (const char *h = strstr(t, base); h != NULL; h = strstr(h + 1, base))
        if ((h == t || h[-1] == '/') && !fxm_ident(h[bn]))
            return true;
    return false;
}

static bool fxm_literal_char(const char *t)
{
    return fxm_literal_char_n(t, strlen(t));
}

/* A word as make or the shell would use it: recipe prefixes and a leading
 * "./" dropped; NULL when it holds only references (their definitions are
 * scanned too). */
const char *fxm_word_of(const char *t)
{
    while (*t == '@' || *t == '-' || *t == '+')
        t++;
    if (t[0] == '.' && t[1] == '/')
        t += 2;
    return fxm_literal_char(t) ? t : NULL;
}

/* A glob word names path: the path, or a directory it lives under (with or
 * without a trailing '/'), each also under a root the glob's leading text
 * may spell ($(CURDIR)/tools/x.sh names tools/x.sh). Too long to test: it
 * does. */
static bool fxm_glob_named(const char *t, const char *path)
{
    char buf[4096 + 3];
    size_t n = strlen(path);
    if (n + 3 > sizeof(buf))
        return true;
    buf[0] = '/';
    memcpy(buf + 1, path, n + 1);
    for (size_t k = n + 1; k > 1; k--) {
        char at = buf[k], next = buf[k + 1];
        bool hit;
        if (at != '\0' && at != '/')
            continue;
        buf[k] = '\0';
        hit = fxm_glob(t, buf) || fxm_glob(t, buf + 1);
        buf[k] = at;
        if (!hit && at == '/') {
            buf[k + 1] = '\0';
            hit = fxm_glob(t, buf) || fxm_glob(t, buf + 1);
            buf[k + 1] = next;
        }
        if (hit)
            return true;
    }
    return false;
}

/* Mark every path asked about that t names. */
static bool fxm_token(struct fxm *m, const char *t)
{
    bool glob;
    if ((t = fxm_word_of(t)) == NULL)
        return false;
    glob = strpbrk(t, FXM_WILDS) != NULL;
    for (size_t k = 0; k < m->npaths; k++)
        if (m->want[k] && !m->make[k] &&
            (glob ? fxm_glob_named(t, m->paths[k]) : fxm_named(t, m->paths[k])))
            m->make[k] = true;
    return false;
}

bool fxm_sep(char ch)
{
    return ch != '\0' && strchr(" \t\r\n,(){};|'\"`=<>&!:" "\x04\x05", ch) != NULL;
}

/* fn over every word of s; whether it held for any. */
bool fxm_tokens(struct fxm *m, char *s,
                bool (*fn)(struct fxm *, const char *))
{
    bool any = false;
    while (*s != '\0') {
        char *t, save;
        while (fxm_sep(*s))
            s++;
        for (t = s; *s != '\0' && !fxm_sep(*s); s++)
            ;
        save = *s;
        *s = '\0';
        if (*t != '\0')
            any |= fn(m, t);
        *s = save;
    }
    return any;
}

/* s[0..n) expanded FXM_ROUNDS deep, in one of m's buffers until the next
 * expansion; NULL (and UNKNOWN) when it cannot be held. */
const char *fxm_expand(struct fxm *m, const char *s, size_t n)
{
    struct fxm_buf *in = &m->a, *out = &m->b;
    bool left = true;
    in->n = 0;
    if (!fxm_put(in, s, n)) {
        m->unknown = true;
        return NULL;
    }
    for (int r = 0; left && r < FXM_ROUNDS; r++) {
        struct fxm_buf *t = in;
        if (!fxm_round(m, in->p, out, &left)) {
            m->unknown = true;
            return NULL;
        }
        in = out;
        out = t;
    }
    return in->p;
}

/* ---- make inputs: reading the makefiles ---------------------------------------- */

bool fxm_load(struct fxm *m, const char *rel)
{
    uint8_t *b = NULL;
    size_t n = 0;
    if (fxc_strs_has(&m->files, rel))
        return true;
    if (m->files.n >= FXM_FILES_MAX ||
        !zcl_devloop_facts_read(m->root, NULL, rel, "", FXM_TEXT_MAX, &b, &n))
        return false;
    if (memchr(b, '\0', n) != NULL || !fxc_strs_add(&m->files, rel)) {
        free(b);
        return false;
    }
    m->text[m->files.n - 1] = (char *)b;
    return true;
}

bool fxm_exists(const char *root, const char *rel)
{
    char full[ZCL_DEVLOOP_PATH_MAX * 2];
    struct stat st;
    return snprintf(full, sizeof(full), "%s/%s", root, rel) < (int)sizeof(full) &&
           stat(full, &st) == 0 && S_ISREG(st.st_mode);
}

const char *fxm_strip_dot(const char *w)
{
    while (w[0] == '.' && w[1] == '/' && strlen(w) > 2) {
        w += 2;
        while (*w == '/')
            w++;
    }
    return w;
}

/* A target word of a rule's expanded targets names path: one that spells
 * literal text (a target no text pins, $(1) in a define, is a premise:
 * docs/work/SEMANTIC_MANIFEST.md). */
static bool fxm_names_target(const char *t, const char *path)
{
    char w[ZCL_DEVLOOP_PATH_MAX];
    while (*t != '\0') {
        size_t n = 0;
        while (fxm_space(*t))
            t++;
        while (t[n] != '\0' && !fxm_space(t[n]))
            n++;
        if (n >= sizeof(w))
            return true;
        memcpy(w, t, n);
        w[n] = '\0';
        if (n > 0 && fxm_word_of(w) != NULL && fxm_glob(fxm_strip_dot(w), path))
            return true;
        t += n;
    }
    return false;
}

/* An optional include that does not exist yet but a rule can make (one a
 * define holds, match-anything or .DEFAULT too) is made first, and what it
 * wrote is text no line holds: UNKNOWN. One that exists is read as it
 * stands (docs/work/SEMANTIC_MANIFEST.md). A target-specific value makes
 * nothing. A rule's targets (a define's too) are expanded a many-word
 * value as its words. */
static void fxm_missing_made(struct fxm *m)
{
    m->unknown |= fxm_anything_made(m);
    for (size_t k = 0; !m->unknown && m->missing.n > 0 && k < m->nlines; k++) {
        const struct fxm_line *l = &m->lines[k];
        size_t n = l->from > 0 ? l->from - 1 : 0;
        const char *t;
        fxm_line_computed(m, l);
        if (n == 0 || (l->ctx != FXM_RULE && !(l->ctx == FXM_DEF && l->body)))
            continue;
        m->lists = true;
        t = fxm_expand(m, l->raw, l->raw[n - 1] == '&' ? n - 1 : n);
        m->lists = false;
        m->unknown |= t == NULL;
        if (t != NULL)
            fxm_target_computed(m, l, n, t);
        for (size_t p = 0; t != NULL && !m->unknown && p < m->missing.n; p++)
            m->unknown = fxm_names_target(t, m->missing.v[p]);
    }
}

/* A target word of t may name a depfile: it ends in .d, or in a pattern
 * or a value no text spells. */
static bool fxm_depfile_target(const char *t)
{
    while (*t != '\0') {
        size_t n = 0;
        while (fxm_space(*t))
            t++;
        while (t[n] != '\0' && !fxm_space(t[n]))
            n++;
        if (n > 0 && (strchr("%*?]\x01\x03", t[n - 1]) != NULL ||
                      (n >= 2 && t[n - 2] == '.' && t[n - 1] == 'd')))
            return true;
        t += n;
    }
    return false;
}

/* Pattern text b[0..n), before its %, may begin a built-in rule's source
 * name for base, whose stem is its first sl bytes: RCS, SCCS, s. or the
 * stem. */
static bool fxm_builtin_head(const char *base, size_t sl, const char *b,
                             size_t n)
{
    static const char *const heads[] = {"RCS", "SCCS", "s."};
    for (size_t k = 0; k < sizeof(heads) / sizeof(*heads); k++) {
        size_t h = strlen(heads[k]);
        if (strncmp(b, heads[k], n < h ? n : h) == 0)
            return true;
    }
    return strncmp(b, base, n < sl ? n : sl) == 0;
}

/* b[0..n) is a version-control source of base (bl bytes): s.base, or an
 * RCS or SCCS directory. */
static bool fxm_builtin_vcs(const char *base, size_t bl, const char *b,
                            size_t n)
{
    return (n == bl + 2 && strncmp(b, "s.", 2) == 0 &&
            strncmp(b + 2, base, bl) == 0) ||
           (n == 3 && strncmp(b, "RCS", 3) == 0) ||
           (n == 4 && strncmp(b, "SCCS", 4) == 0);
}

/* Name b[0..n), in makefile base name base's directory, may be a source
 * a GNU make built-in rule remakes base from: the stem (base less its
 * last suffix) alone or with any suffix (a suffix rule, %.out: %,
 * %.c: %.w), base,v, or a version-control source (fxm_builtin_vcs). A
 * pattern (pat) counts when its text before the % may begin one. */
static bool fxm_builtin_name(const char *base, const char *b, size_t n,
                             bool pat)
{
    const char *dot = strrchr(base, '.');
    size_t bl = strlen(base);
    size_t sl = dot != NULL && dot != base ? (size_t)(dot - base) : bl;
    if (pat)
        return fxm_builtin_head(base, sl, b, n);
    if (n == bl && strncmp(b, base, n) == 0)
        return false;
    if (n >= sl && strncmp(b, base, sl) == 0 &&
        (n == sl || b[sl] == '.' || (n > bl && b[bl] == ',')))
        return true;
    return fxm_builtin_vcs(base, bl, b, n);
}

/* Path p[0..n), a target word or a directory entry, may be what a
 * built-in rule remakes makefile mk from (fxm_builtin_name): it sits in
 * mk's directory, or is a pattern that may. */
static bool fxm_builtin_path(const char *mk, const char *p, size_t n)
{
    const char *slash = strrchr(mk, '/');
    const char *pct = memchr(p, '%', n);
    size_t dl = slash != NULL ? (size_t)(slash - mk) + 1 : 0;
    if (pct != NULL && (size_t)(pct - p) <= dl)
        return strncmp(p, mk, (size_t)(pct - p)) == 0;
    if (n <= dl || strncmp(p, mk, dl) != 0 ||
        memchr(p + dl, '/', (pct != NULL ? (size_t)(pct - p) : n) - dl) != NULL)
        return false;
    return fxm_builtin_name(mk + dl, p + dl,
                            (pct != NULL ? (size_t)(pct - p) : n) - dl,
                            pct != NULL);
}

/* A target word of t may be a source a built-in rule remakes a makefile
 * make reads from. */
static bool fxm_builtin_target(const struct fxm *m, const char *t)
{
    while (*t != '\0') {
        const char *w;
        size_t n = 0;
        while (fxm_space(*t))
            t++;
        while (t[n] != '\0' && !fxm_space(t[n]))
            n++;
        w = fxm_strip_dot(t);
        if (w > t + n)
            w = t + n;
        for (size_t f = 0; n > 0 && f < m->files.n; f++)
            if (fxm_builtin_path(m->files.v[f], w, (size_t)(t + n - w)))
                return true;
        t += n;
    }
    return false;
}

/* An entry of makefile mk's directory may be a source a built-in rule
 * remakes mk from; a directory the scan cannot read counts too. */
static bool fxm_builtin_source(const char *root, const char *mk)
{
    char dir[ZCL_DEVLOOP_PATH_MAX * 2], p[ZCL_DEVLOOP_PATH_MAX * 2];
    const char *slash = strrchr(mk, '/');
    int dl = slash != NULL ? (int)(slash - mk) : 0;
    struct dirent *de;
    bool found = false;
    DIR *d;
    if (snprintf(dir, sizeof(dir), "%s/%.*s", root, dl, mk) >= (int)sizeof(dir) ||
        (d = opendir(dir)) == NULL)
        return true;
    while (!found && (de = readdir(d)) != NULL) {
        int n;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        n = snprintf(p, sizeof(p), "%.*s%s%s", dl, mk, dl ? "/" : "",
                     de->d_name);
        found = n < 0 || n >= (int)sizeof(p) ||
                fxm_builtin_path(mk, p, (size_t)n);
    }
    (void)closedir(d);
    return found;
}

/* Rule line l may remake a makefile make reads: its expanded targets name
 * one (a pattern, match-anything or .DEFAULT too), or a source a built-in
 * rule remakes one from, or a depfile while an include names depfiles,
 * or it is computed and its text names one; a line that may be a rule,
 * the same. */
static bool fxm_line_remakes(struct fxm *m, const struct fxm_line *l)
{
    size_t n = l->from > 0 ? l->from - 1 : 0;
    const char *t;
    if (n == 0 || (l->ctx != FXM_RULE && !(l->ctx == FXM_DEF && l->body)))
        return fxm_computed_names(m, l, 0, NULL, &m->files);
    m->lists = true;
    t = fxm_expand(m, l->raw, l->raw[n - 1] == '&' ? n - 1 : n);
    m->lists = false;
    if (t == NULL || fxm_names_target(t, ".DEFAULT") ||
        (m->inc_depfile && fxm_depfile_target(t)))
        return true;
    for (size_t f = 0; f < m->files.n; f++)
        if (fxm_names_target(t, m->files.v[f]))
            return true;
    if (fxm_builtin_target(m, t))
        return true;
    return fxm_computed_names(m, l, n, t, &m->files);
}

/* GNU make remakes each makefile it read that a rule targets and, when
 * one changed, reads them all again (MAKE_RESTARTS set): what the first
 * parse ran, and the recipes that remade it, are then done before any
 * directive of the next. A built-in rule may remake one (a source it
 * reads sits beside it or a rule targets one), and an include
 * outside the tree counts as remade. */
bool fxm_makefiles_remade(struct fxm *m)
{
    if (m->inc_outside)
        return true;
    for (size_t f = 0; f < m->files.n; f++)
        if (fxm_builtin_source(m->root, m->files.v[f]))
            return true;
    for (size_t k = 0; k < m->nlines; k++)
        if (fxm_line_remakes(m, &m->lines[k]))
            return true;
    return false;
}

static bool fxm_is_include(const char *p)
{
    return (strncmp(p, "include", 7) == 0 && fxm_space(p[7])) ||
           (strncmp(p, "-include", 8) == 0 && fxm_space(p[8])) ||
           (strncmp(p, "sinclude", 8) == 0 && fxm_space(p[8]));
}

/* Every definition of one makefile's text; its include lines, once. */
static void fxm_defs(struct fxm *m, size_t f, bool includes)
{
    const char *at = m->text[f];
    bool recipe, comment, in_define = false;
    int r = 0;
    m->pos[0] = 0;
    m->cur_file = (uint32_t)f;
    while (!m->unknown && (r = fxm_next_line(&m->line, &at, &recipe,
                                             &comment, m->pos)) > 0) {
        const char *p = fxm_skip_prefixes(m->line.p);
        if (comment || recipe)
            continue;
        if (in_define) {
            in_define = strncmp(p, "endef", 5) != 0;
            continue;
        }
        if (includes && fxm_is_include(p))
            fxm_include(m, p);
        else if (!includes && !fxm_def(m, m->line.p, &in_define))
            m->unknown = true;
    }
    m->unknown |= r < 0;
}

/* The root makefile make would pick, and every file it includes. */
static void fxm_read_all(struct fxm *m)
{
    static const char *const roots[] = {"GNUmakefile", "makefile", "Makefile"};
    size_t k = 0;
    while (k < 3 && !fxm_exists(m->root, roots[k]))
        k++;
    if (k == 3 || !fxm_load(m, roots[k])) {
        m->unknown = true;
        return;
    }
    for (size_t f = 0; !m->unknown && f < m->files.n; f++) {
        fxm_defs(m, f, false);
        fxm_vars_seal(m);
        fxm_defs(m, f, true);
    }
}

/* ---- make inputs: where each line sits ------------------------------------------ */

static bool fxm_grow(void **v, size_t *cap, size_t n, size_t size)
{
    size_t next;
    void *g;
    if (n < *cap)
        return true;
    next = *cap ? *cap * 2 : 256;
    g = zcl_realloc(*v, next * size, "facts_consumer.mkgrow");
    if (g == NULL)
        return false;
    *v = g;
    *cap = next;
    return true;
}

bool fxm_starts_word(const char *p, const char *w)
{
    size_t n = strlen(w);
    return strncmp(p, w, n) == 0 &&
           (p[n] == '\0' || fxm_space(p[n]) || p[n] == '(');
}

static bool fxm_cond_word(const char *p)
{
    return fxm_starts_word(p, "ifeq") || fxm_starts_word(p, "ifneq") ||
           fxm_starts_word(p, "ifdef") || fxm_starts_word(p, "ifndef") ||
           fxm_starts_word(p, "else") || fxm_starts_word(p, "endif");
}

/* A conditional directive: a later recipe line belongs to the rule before
 * the conditional, unless a branch changed it; then to no rule that can be
 * named. */
static void fxm_cond(struct fxm *m, struct fxm_place *st, const char *p)
{
    bool is_else = fxm_starts_word(p, "else");
    int d = st->depth - 1;
    if (!is_else && !fxm_starts_word(p, "endif")) {
        if (st->depth == FXM_COND_MAX) {
            m->unknown = true;
            return;
        }
        st->open[st->depth] = st->rule;
        st->moved[st->depth++] = false;
        return;
    }
    if (d < 0) {
        m->unknown = true;
        return;
    }
    st->moved[d] |= st->rule != st->open[d];
    if (is_else) {
        st->rule = st->open[d];
        return;
    }
    st->rule = st->moved[d] ? FXM_NONE : st->open[d];
    st->depth--;
}

/* The first character of s from set outside any reference; NULL for none. */
const char *fxm_top(const char *s, const char *set)
{
    int depth = 0;
    for (; *s != '\0'; s++) {
        if (*s == '$') {
            depth += s[1] == '(' || s[1] == '{';
            s += s[1] != '\0';
        } else if (depth > 0) {
            depth += (*s == '(' || *s == '{') - (*s == ')' || *s == '}');
        } else if (strchr(set, *s) != NULL) {
            return s;
        }
    }
    return NULL;
}


/* A definition (its operator first), a rule (*colon at its ':'), a
 * target-specific assignment, or anything else. */
enum fxm_kind fxm_kind_of(const char *s, size_t *colon)
{
    const char *p = fxm_top(s, ":="), *q;
    if (p == NULL)
        return FXM_K_OTHER;
    if (*p == '=' || p[1] == '=' || strncmp(p + 1, ":=", 2) == 0 ||
        strncmp(p + 1, "::=", 3) == 0)
        return FXM_K_DEF;
    *colon = (size_t)(p - s);
    q = fxm_top(p + 1, "=;");
    return q != NULL && *q == '=' ? FXM_K_TSV : FXM_K_RULE;
}

/* The variable p defines into out: "" when its name is computed or longer
 * than out holds. */
void fxm_def_name(const char *p, char *out)
{
    size_t n = 0;
    p = fxm_skip_prefixes(p);
    while (n + 1 < FXM_NAME_MAX && fxm_ident(p[n]))
        n++;
    if (fxm_ident(p[n]) || p[n] == '$')
        n = 0;
    memcpy(out, p, n);
    out[n] = '\0';
}

bool fxm_all_space(const char *s, size_t n)
{
    for (size_t k = 0; k < n; k++)
        if (!fxm_space(s[k]))
            return false;
    return true;
}

/* w[0..n) holds no wildcard, reference or unknown. */
bool fxm_literal_span(const char *w, size_t n)
{
    for (size_t k = 0; k < n; k++)
        if (strchr(FXM_WILDS "\x02", w[k]) != NULL)
            return false;
    return n > 0;
}

/* .PHONY's literal names. */
static void fxm_phony_words(struct fxm *m, const char *s)
{
    char w[FXM_NAME_MAX];
    while (*s != '\0' && !m->unknown) {
        size_t n = 0;
        while (fxm_space(*s))
            s++;
        while (s[n] != '\0' && !fxm_space(s[n]))
            n++;
        if (n > 0 && n < sizeof(w) && fxm_literal_span(s, n)) {
            memcpy(w, s, n);
            w[n] = '\0';
            m->unknown |= !fxc_strs_add(&m->phony, w);
        }
        s += n;
    }
}

/* s[0..n) (a rule's targets) is .PHONY. */
static bool fxm_phony_head(const char *s, size_t n)
{
    const char *p = s;
    while (fxm_space(*p))
        p++;
    return strncmp(p, ".PHONY", 6) == 0 &&
           fxm_all_space(p + 6, (size_t)(s + n - (p + 6)));
}

/* A line a definition holds: text a later $(eval) may read as a .PHONY
 * line (it reaches nothing) or a rule (its targets reach nothing). */
static uint8_t fxm_define_line(struct fxm *m, struct fxm_place *st,
                               const char *s, bool recipe)
{
    size_t colon = 0;
    enum fxm_kind kind;
    st->in_define = !fxm_starts_word(fxm_skip_prefixes(s), "endef");
    if (!st->in_define)
        return FXM_ACTIVE;
    memcpy(m->name, st->define_name, sizeof(m->name));
    if (recipe)
        return FXM_DEF;
    kind = fxm_kind_of(s, &colon);
    if (kind == FXM_K_RULE && fxm_phony_head(s, colon))
        return FXM_QUIET;
    if (kind == FXM_K_RULE || kind == FXM_K_TSV)
        m->from = colon + 1;
    return FXM_DEF;
}

/* A makefile's first rule with a target make can take as the goal of a
 * bare make: one that is no pattern and not led by '.' (unless it holds a
 * '/'), as GNU make picks it. */
static bool fxm_goal_target(const char *t)
{
    while (*t != '\0') {
        size_t n = 0;
        while (fxm_space(*t))
            t++;
        while (t[n] != '\0' && !fxm_space(t[n]))
            n++;
        if (n > 0 && memchr(t, '%', n) == NULL &&
            (*t != '.' || memchr(t, '/', n) != NULL))
            return true;
        t += n;
    }
    return false;
}

/* A rule line: .PHONY's names, or a new rule with its expanded targets. */
static uint8_t fxm_rule(struct fxm *m, struct fxm_place *st, const char *s,
                        size_t colon)
{
    size_t n = colon > 0 && s[colon - 1] == '&' ? colon - 1 : colon;
    const char *t;
    struct fxm_rule *r;
    if (fxm_phony_head(s, n)) {
        if ((t = fxm_expand(m, s + colon + 1, strlen(s + colon + 1))) != NULL)
            fxm_phony_words(m, t);
        return FXM_PHONY;
    }
    if ((t = fxm_expand(m, s, n)) == NULL || m->nrules >= FXM_NONE ||
        !fxm_grow((void **)&m->rules, &m->caprules, m->nrules, sizeof(*r))) {
        m->unknown = true;
        return FXM_ACTIVE;
    }
    r = &m->rules[m->nrules];
    while (fxm_space(*t))
        t++;
    r->reached = !st->goal && fxm_goal_target(t);
    st->goal |= r->reached;
    if ((r->targets = zcl_strdup(t, "facts_consumer.mktgt")) == NULL) {
        m->unknown = true;
        return FXM_ACTIVE;
    }
    st->rule = (uint32_t)m->nrules++;
    return FXM_RULE;
}

static uint8_t fxm_define(struct fxm_place *st, const char *p)
{
    fxm_def_name(p, st->define_name);
    st->in_define = true;
    return FXM_QUIET; /* its body lines are the definition */
}

/* The context of the logical line in m->line (a tab line when recipe); a
 * definition's variable in m->name, and where what the line reaches with
 * starts in m->from. */
static uint8_t fxm_place_line(struct fxm *m, struct fxm_place *st, bool recipe)
{
    const char *s = m->line.p, *p = fxm_skip_prefixes(s);
    size_t colon = 0;
    enum fxm_kind kind;
    m->from = 0;
    m->whole |= strstr(s, ".ONESHELL") != NULL ||
                strstr(s, ".RECIPEPREFIX") != NULL;
    m->second |= strstr(s, ".SECONDEXPANSION") != NULL;
    m->body = st->in_define;
    if (st->in_define)
        return fxm_define_line(m, st, s, recipe);
    if (recipe && st->rule != FXM_NONE)
        return FXM_RECIPE;
    /* A tab line outside a rule is an ordinary line to make too. */
    if (*p == '\0')
        return FXM_ACTIVE; /* blank: the rule goes on */
    if (fxm_cond_word(p)) {
        fxm_cond(m, st, p);
        return FXM_QUIET;
    }
    st->rule = FXM_NONE;
    if (fxm_starts_word(p, "define"))
        return fxm_define(st, p + 6);
    kind = fxm_kind_of(s, &colon);
    if (kind == FXM_K_OTHER)
        return FXM_ACTIVE;
    m->from = kind == FXM_K_DEF ? 0 : colon + 1;
    if (kind == FXM_K_RULE)
        return fxm_rule(m, st, s, colon);
    /* A target-specific value is a definition of its variable. */
    fxm_def_name(s + m->from, m->name);
    return FXM_DEF;
}

/* Keep the line as written and expanded ('%' as shell text in a recipe). */
static void fxm_keep_line(struct fxm *m, uint8_t ctx, uint32_t rule)
{
    struct fxm_line *l;
    const char *t = fxm_expand(m, m->line.p, strlen(m->line.p));
    if (t == NULL ||
        !fxm_grow((void **)&m->lines, &m->caplines, m->nlines, sizeof(*l))) {
        m->unknown = true;
        return;
    }
    l = &m->lines[m->nlines];
    memset(l, 0, sizeof(*l));
    l->ctx = ctx;
    l->rule = rule;
    l->from = m->from < FXM_LINE_MAX ? (uint32_t)m->from : 0;
    l->body = m->body && ctx == FXM_DEF;
    l->at = m->pos[1];
    l->file = m->cur_file;
    l->text = zcl_strdup(t, "facts_consumer.mkline");
    l->raw = zcl_strdup(m->line.p, "facts_consumer.mkraw");
    l->name = zcl_strdup(ctx == FXM_DEF ? m->name : "", "facts_consumer.mkname");
    if (l->text == NULL || l->raw == NULL || l->name == NULL) {
        free(l->text);
        free(l->raw);
        free(l->name);
        m->unknown = true;
        return;
    }
    if (ctx == FXM_RECIPE)
        for (char *c = l->text; *c != '\0'; c++)
            *c = *c == '%' ? FXM_PCT : *c;
    m->nlines++;
}

/* A rule line's recipe past its ';' (`ci: ; $(MAKE) gen all`) is a
 * recipe line of that rule too. */
static void fxm_inline_recipe(struct fxm *m, uint32_t rule)
{
    const char *semi = fxm_top(m->line.p + m->from, ";");
    char *rest;
    if (semi == NULL)
        return;
    if ((rest = zcl_strdup(semi + 1, "facts_consumer.mkinline")) == NULL) {
        m->unknown = true;
        return;
    }
    m->line.n = 0;
    m->unknown |= !fxm_put(&m->line, rest, strlen(rest));
    free(rest);
    m->from = 0;
    if (!m->unknown)
        fxm_keep_line(m, FXM_RECIPE, rule);
}

/* Every logical line of one makefile but its whole-line comments. */
static void fxm_lines_of(struct fxm *m, size_t f)
{
    struct fxm_place st = {.rule = FXM_NONE};
    const char *at = m->text[f];
    bool recipe, comment;
    int r = 0;
    m->pos[0] = 0;
    m->cur_file = (uint32_t)f;
    while (!m->unknown && (r = fxm_next_line(&m->line, &at, &recipe,
                                             &comment, m->pos)) > 0) {
        uint8_t ctx;
        if (comment)
            continue;
        ctx = fxm_place_line(m, &st, recipe);
        if (!m->unknown)
            fxm_keep_line(m, ctx,
                          ctx == FXM_RULE || ctx == FXM_RECIPE ? st.rule
                                                               : FXM_NONE);
        if (!m->unknown && ctx == FXM_RULE)
            fxm_inline_recipe(m, st.rule);
    }
    /* A conditional or a define the file leaves open: make stops. */
    m->unknown |= r < 0 || st.depth != 0 || st.in_define;
    if (f == 0)
        m->root_lines = m->nlines;
}

/* ---- make inputs: variable references ------------------------------------------- */

static void fxm_free(struct fxm *m)
{
    for (size_t k = 0; k < m->files.n; k++)
        free(m->text[k]);
    for (size_t k = 0; k < m->nvars; k++) {
        free(m->vars[k].name);
        free(m->vars[k].value);
    }
    for (size_t k = 0; k < m->nlines; k++) {
        free(m->lines[k].text);
        free(m->lines[k].raw);
        free(m->lines[k].name);
    }
    for (size_t k = 0; k < m->nrules; k++)
        free(m->rules[k].targets);
    free(m->vars);
    free(m->lines);
    free(m->rules);
    free(m->pairs);
    free(m->vnames);
    fxc_strs_free(&m->files);
    fxc_strs_free(&m->phony);
    fxc_strs_free(&m->missing);
    fxc_strs_free(&m->goal_names);
    fxc_strs_free(&m->makers);
    for (size_t k = 0; k < m->nincs; k++)
        free(m->incs[k].path);
    free(m->incs);
    free(m->line.p);
    free(m->a.p);
    free(m->b.p);
}

static bool fxm_makefile_name(const char *path)
{
    const char *b = strrchr(path, '/');
    b = b != NULL ? b + 1 : path;
    return strcmp(b, "GNUmakefile") == 0 || strcmp(b, "makefile") == 0 ||
           strncmp(b, "Makefile", 8) == 0 || zcl_str_has_suffix(b, ".mk") ||
           zcl_str_has_suffix(b, ".make");
}

/* A directory above path, below the root, holds a makefile: a sub-make run
 * there may read the path by a name relative to it. */
static bool fxm_submake(const char *root, const char *path)
{
    static const char *const names[] = {"GNUmakefile", "makefile", "Makefile"};
    char dir[ZCL_DEVLOOP_PATH_MAX], rel[ZCL_DEVLOOP_PATH_MAX + 16];
    if (snprintf(dir, sizeof(dir), "%s", path) >= (int)sizeof(dir))
        return true;
    for (char *s = strrchr(dir, '/'); s != NULL; s = strrchr(dir, '/')) {
        *s = '\0';
        for (size_t k = 0; k < 3; k++)
            if (snprintf(rel, sizeof(rel), "%s/%s", dir, names[k]) >=
                    (int)sizeof(rel) ||
                fxm_exists(root, rel))
                return true;
    }
    return false;
}

void fxm_analyse(struct fxm *m)
{
    fxm_read_all(m);
    for (size_t f = 0; !m->unknown && f < m->files.n; f++)
        fxm_lines_of(m, f);
    fxm_guards(m);
    fxm_missing_made(m);
    if (!m->unknown)
        fxm_makers(m);
    if (!m->unknown)
        fxm_reach(m);
}

void fxm_classify(const char *root, const char *const *paths, const bool *want,
                  bool *make, size_t n,
                  struct zcl_devloop_facts_report *report)
{
    struct fxm m = {.root = root, .paths = paths, .want = want, .make = make,
                    .npaths = n, .report = report};
    for (size_t k = 0; k < n; k++)
        make[k] = want[k] && (fxm_makefile_name(paths[k]) ||
                              fxm_submake(root, paths[k]));
    fxm_analyse(&m);
    for (size_t k = 0; !m.unknown && k < m.nlines; k++)
        if (fxm_live(&m, &m.lines[k]))
            (void)fxm_tokens(&m, m.lines[k].text, fxm_token);
    for (size_t k = 0; k < n; k++)
        make[k] |= want[k] && (m.unknown || fxc_strs_has(&m.files, paths[k]));
    fxm_free(&m);
}
