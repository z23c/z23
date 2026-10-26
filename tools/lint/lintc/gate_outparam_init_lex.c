/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: line lexer for the check-outparam-init-before-return gate — the
 * comment and literal stripper plus the brace-depth function splitter that
 * the shell gate's three awk programs each carried a copy of.
 *
 * One lexer, three modes. OP_MODE_SCAN is the out-parameter scan: string
 * literals become "" and character literals become CH before comments are
 * stripped, whichever of // and slash-star comes first wins, and a one-line
 * definition is not a body. OP_MODE_PUB and OP_MODE_FREE strip // first (the
 * publisher finder and the publish/free analyzer never normalised character
 * literals); OP_MODE_PUB also notes file-scope pointer declarations and
 * accepts a one-line definition. The shell ran each awk over a batch of
 * files without resetting its brace depth at a file boundary in the last two
 * programs; every file here starts from depth 0, which is what the scan
 * program already did since 2026-09-11.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_outparam_init_priv.h"

size_t op_skipws(const char *s, size_t i)
{
    while (s[i] == ' ' || s[i] == '\t')
        i++;
    return i;
}

/* (^|[^A-Za-z0-9_]) in front of position i. */
int op_word_before_ok(const char *s, size_t i)
{
    return i == 0 || !op_idc((unsigned char)s[i - 1]);
}

/* (^|[^A-Za-z0-9_])w([^A-Za-z0-9_]|$) anywhere in s. */
int op_has_word(const char *s, const char *w)
{
    size_t wl = strlen(w);
    for (const char *p = strstr(s, w); p; p = strstr(p + 1, w)) {
        size_t i = (size_t)(p - s);
        if (op_word_before_ok(s, i) && !op_idc((unsigned char)p[wl]))
            return 1;
    }
    return 0;
}

/* line ~ /;[ \t]*$/ */
int op_ends_semi(const char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        n--;
    return n > 0 && s[n - 1] == ';';
}

/* line ~ /[^ \t]/ */
int op_nonblank(const char *s)
{
    for (; *s; s++)
        if (*s != ' ' && *s != '\t')
            return 1;
    return 0;
}

/* gsub(/^[ \t]+|[ \t]+$/, "") in place; returns the new length. */
size_t op_trim(char *s)
{
    size_t a = op_skipws(s, 0), n = strlen(s);
    while (n > a && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        n--;
    memmove(s, s + a, n - a);
    s[n - a] = '\0';
    return n - a;
}

int op_buf_put(struct op_buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        char *np;
        while (cap < b->n + n + 1)
            cap *= 2;
        np = realloc(b->p, cap); // raw-alloc-ok:lint-runtime
        if (!np)
            return die("z23-lint: outparam-init: out of memory\n", "");
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
    return 0;
}

void op_buf_free(struct op_buf *b)
{
    free(b->p);
    memset(b, 0, sizeof *b);
}

const char *op_buf_str(const struct op_buf *b)
{
    return b->p ? b->p : "";
}

static uint32_t op_hash(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

int op_hset_init(struct op_hset *h, int cap)
{
    memset(h, 0, sizeof *h);
    h->cap = cap;
    h->nslot = cap * 2;
    h->nm = calloc((size_t)cap, sizeof *h->nm); // raw-alloc-ok:lint-runtime
    h->slot = calloc((size_t)h->nslot, sizeof *h->slot); // raw-alloc-ok:lint-runtime
    if (!h->nm || !h->slot) {
        op_hset_free(h);
        return die("z23-lint: outparam-init: out of memory\n", "");
    }
    return 0;
}

void op_hset_free(struct op_hset *h)
{
    free(h->nm);
    free(h->slot);
    memset(h, 0, sizeof *h);
}

void op_hset_clear(struct op_hset *h)
{
    h->n = 0;
    if (h->slot)
        memset(h->slot, 0, (size_t)h->nslot * sizeof *h->slot);
}

/* Slot holding s, or the empty slot where it belongs. */
static int op_hset_find(const struct op_hset *h, const char *s)
{
    int i = (int)(op_hash(s) % (uint32_t)h->nslot);
    while (h->slot[i] && strcmp(h->nm[h->slot[i] - 1], s) != 0)
        i = (i + 1) % h->nslot;
    return i;
}

int op_hset_has(const struct op_hset *h, const char *s)
{
    return h->slot && h->slot[op_hset_find(h, s)] != 0;
}

int op_hset_add(struct op_hset *h, const char *s)
{
    size_t n = strlen(s);
    int i;
    if (n >= OP_NAME)
        return die("z23-lint: outparam-init: name longer than %s\n", "127 bytes");
    i = op_hset_find(h, s);
    if (h->slot[i])
        return 0;
    if (h->n >= h->cap)
        return die("z23-lint: outparam-init: %s\n", "string set is full");
    memcpy(h->nm[h->n], s, n + 1);
    h->slot[i] = ++h->n;
    return 0;
}

/* gsub(/Q([^Q\\]|\\.)*Q/, rep): end index of the literal opening at i, or 0
 * when it never closes on this line. */
static size_t op_quote_end(const char *s, size_t n, size_t i, char q)
{
    size_t j = i + 1;
    while (j < n) {
        if (s[j] == q)
            return j + 1;
        if (s[j] == '\\') {
            if (j + 1 >= n)
                return 0;
            j += 2;
        } else {
            j++;
        }
    }
    return 0;
}

static void op_requote(char *s, char q, const char *rep)
{
    size_t n = strlen(s), i = 0, o = 0, rl = strlen(rep);
    while (i < n) {
        size_t e = s[i] == q ? op_quote_end(s, n, i, q) : 0;
        if (e) {
            memcpy(s + o, rep, rl);
            o += rl;
            i = e;
        } else {
            s[o++] = s[i++];
        }
    }
    s[o] = '\0';
}

/* Inside a block comment: drop through the LAST star-slash, or skip the
 * line when there is none. Returns 1 to skip the line. */
static int op_comment_close(struct op_fn *f)
{
    char *s = f->work.p, *last = NULL;
    for (char *p = strstr(s, "*/"); p; p = strstr(p + 1, "*/"))
        last = p;
    if (!last)
        return 1;
    memmove(s, last + 2, strlen(last + 2) + 1);
    f->incomment = 0;
    return 0;
}

/* Consume comment openers left to right. In scan mode a // that comes before
 * the next slash-star ends the line; otherwise only slash-star opens one. */
static void op_openers(struct op_fn *f, int slashes)
{
    char *s = f->work.p;
    for (;;) {
        char *ls = slashes ? strstr(s, "//") : NULL, *lb = strstr(s, "/*"), *cl;
        if (ls && (!lb || ls < lb)) {
            *ls = '\0';
            return;
        }
        if (!lb)
            return;
        cl = strstr(lb, "*/");
        if (!cl) {
            *lb = '\0';
            f->incomment = 1;
            return;
        }
        memmove(lb, cl + 2, strlen(cl + 2) + 1);
    }
}

/* Returns 1 when the whole line sits inside a block comment. */
static int op_strip(struct op_fn *f)
{
    char *s = f->work.p;
    char *c;
    op_requote(s, '"', "\"\"");
    if (f->mode == OP_MODE_SCAN) {
        op_requote(s, '\'', "CH");
    } else {
        c = strstr(s, "//");
        if (c)
            *c = '\0';
    }
    if (f->incomment && op_comment_close(f))
        return 1;
    op_openers(f, f->mode == OP_MODE_SCAN);
    return 0;
}

void op_fn_init(struct op_fn *f, enum op_mode mode, op_emit_fn emit,
                void *ctx, struct op_hset *objs)
{
    memset(f, 0, sizeof *f);
    f->mode = mode;
    f->emit = emit;
    f->ctx = ctx;
    f->objs = objs;
}

void op_fn_free(struct op_fn *f)
{
    op_buf_free(&f->sig);
    op_buf_free(&f->work);
    op_buf_free(&f->full);
    op_buf_free(&f->arena);
    free(f->off);
    free(f->ln);
    f->off = NULL;
    f->ln = NULL;
}

void op_fn_begin(struct op_fn *f, const char *file)
{
    f->file = file;
    f->depth = 0;
    f->incomment = 0;
    f->lineno = 0;
    f->nbody = 0;
    f->fnname[0] = '\0';
    op_buf_clear(&f->sig);
    op_buf_clear(&f->arena);
    if (f->objs)
        op_hset_clear(f->objs);
}

int op_fn_end(const struct op_fn *f)
{
    return f->depth;
}

const char *op_body(const struct op_fn *f, size_t j)
{
    return f->arena.p + f->off[j - 1];
}

long op_body_lineno(const struct op_fn *f, size_t j)
{
    return f->ln[j - 1];
}

static int op_body_push(struct op_fn *f, const char *line)
{
    if (f->nbody >= f->bodycap) {
        size_t cap = f->bodycap ? f->bodycap * 2 : 256;
        size_t *no = realloc(f->off, cap * sizeof *no); // raw-alloc-ok:lint-runtime
        long *nl;
        if (!no)
            return die("z23-lint: outparam-init: out of memory\n", "");
        f->off = no;
        nl = realloc(f->ln, cap * sizeof *nl); // raw-alloc-ok:lint-runtime
        if (!nl)
            return die("z23-lint: outparam-init: out of memory\n", "");
        f->ln = nl;
        f->bodycap = cap;
    }
    f->off[f->nbody] = f->arena.n;
    f->ln[f->nbody] = f->lineno;
    f->nbody++;
    /* the copied NUL stays in the arena as the line terminator */
    return op_buf_put(&f->arena, line, strlen(line) + 1);
}

static void op_reset_body(struct op_fn *f)
{
    f->nbody = 0;
    op_buf_clear(&f->arena);
}

static void op_count_braces(const char *s, int *nb, int *ne)
{
    *nb = 0;
    *ne = 0;
    for (; *s; s++) {
        *nb += *s == '{';
        *ne += *s == '}';
    }
}

/* sigfull in the awk programs: the signature so far plus this line, runs of
 * blanks collapsed to one space and leading spaces dropped. */
static int op_sigfull(struct op_fn *f, const char *line)
{
    char *s;
    size_t i, o = 0;
    op_buf_clear(&f->full);
    if (op_buf_put(&f->full, op_buf_str(&f->sig), f->sig.n)
        || op_buf_put(&f->full, " ", 1)
        || op_buf_put(&f->full, line, strlen(line)))
        return 2;
    s = f->full.p;
    for (i = 0; s[i]; i++) {
        int blank = s[i] == ' ' || s[i] == '\t';
        if (blank && (o == 0 || s[o - 1] == ' '))
            continue;
        s[o++] = blank ? ' ' : s[i];
    }
    s[o] = '\0';
    f->full.n = o;
    return 0;
}

static int op_nonfunc(const char *sf)
{
    return !strchr(sf, '(') || strncmp(sf, "typedef", 7) == 0
        || strncmp(sf, "struct ", 7) == 0 || strncmp(sf, "union ", 6) == 0
        || strncmp(sf, "enum ", 5) == 0;
}

/* match(sigfull, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/) minus the paren, or "?". */
static int op_set_fnname(struct op_fn *f, const char *sf)
{
    size_t i = 0;
    for (; sf[i]; i++) {
        size_t e, k;
        if (!op_id1((unsigned char)sf[i]))
            continue;
        e = i;
        while (op_idc((unsigned char)sf[e]))
            e++;
        k = op_skipws(sf, e);
        if (sf[k] == '(') {
            if (e - i >= OP_NAME)
                return die("z23-lint: outparam-init: function name longer than %s\n",
                           "127 bytes");
            memcpy(f->fnname, sf + i, e - i);
            f->fnname[e - i] = '\0';
            return 0;
        }
        i = e - 1;
    }
    strcpy(f->fnname, "?");
    return 0;
}

static int op_close(struct op_fn *f)
{
    int rc = f->emit(f, f->ctx);
    op_buf_clear(&f->sig);
    op_reset_body(f);
    f->depth = 0;
    return rc;
}

/* Leftmost match of /[A-Za-z_][A-Za-z0-9_]*[ \t]*(\[[^]]*\])?$/ in p: the
 * declared name, without blanks or subscript. */
int op_decl_name(const char *p, char *out, size_t cap)
{
    size_t n = strlen(p);
    for (size_t i = 0; i < n; i++) {
        size_t e = i, k;
        int ok;
        if (!op_id1((unsigned char)p[i]))
            continue;
        while (op_idc((unsigned char)p[e]))
            e++;
        k = op_skipws(p, e);
        ok = k == n;
        if (!ok && p[k] == '[') {
            const char *rb = strchr(p + k + 1, ']');
            ok = rb && (size_t)(rb - p) + 1 == n;
        }
        if (ok) {
            if (e - i >= cap)
                return -1;
            memcpy(out, p + i, e - i);
            out[e - i] = '\0';
            return 1;
        }
        i = e - 1;
    }
    return 0;
}

/* Cut s at the first "<blanks><c>" (sub(/[ \t]*c.*$/, "")). */
static void op_cut_at(char *s, char c)
{
    char *p = strchr(s, c);
    if (!p)
        return;
    while (p > s && (p[-1] == ' ' || p[-1] == '\t'))
        p--;
    *p = '\0';
}

/* A declaration at file scope: remember every pointer-typed object. */
static int op_note_decl(struct op_fn *f, const char *line)
{
    char d[8192], name[OP_NAME];
    int found;
    if (strlen(line) >= sizeof d)
        return die("z23-lint: outparam-init: %s\n", "declaration line too long");
    strcpy(d, line);
    op_cut_at(d, '=');
    op_cut_at(d, ';');
    if (!strchr(d, '*'))
        return 0;
    found = op_decl_name(d, name, sizeof name);
    if (found < 0)
        return die("z23-lint: outparam-init: %s\n", "declared name too long");
    return found ? op_hset_add(f->objs, name) : 0;
}

/* depth == 0 and no brace on the line: a signature piece or a declaration. */
static int op_top_text(struct op_fn *f, const char *line)
{
    if (f->mode == OP_MODE_PUB && op_ends_semi(line) && op_note_decl(f, line))
        return 2;
    if (!op_nonblank(line))
        return 0;
    if (op_ends_semi(line)) {
        op_buf_clear(&f->sig);
        return 0;
    }
    return op_buf_put(&f->sig, " ", 1) || op_buf_put(&f->sig, line, strlen(line));
}

/* The publisher finder's opener: a one-line definition is a whole body. */
static int op_open_pub(struct op_fn *f, const char *line)
{
    if (op_nonfunc(f->full.p)) {
        op_buf_clear(&f->sig);
        op_reset_body(f);
        if (f->depth < 0)
            f->depth = 0;
        return 0;
    }
    op_reset_body(f);
    if (op_set_fnname(f, f->full.p))
        return 2;
    op_buf_clear(&f->sig);
    if (op_buf_put(&f->sig, f->full.p, f->full.n))
        return 2;
    if (f->depth > 0)
        return 0;
    if (op_body_push(f, line))
        return 2;
    return op_close(f);
}

/* The scan and publish/free opener: the body starts on the next line. */
static int op_open_std(struct op_fn *f)
{
    if (f->depth <= 0) {
        op_buf_clear(&f->sig);
        f->depth = 0;
        return 0;
    }
    op_reset_body(f);
    if (op_nonfunc(f->full.p)) {
        op_buf_clear(&f->sig);
        return 0;
    }
    if (op_set_fnname(f, f->full.p))
        return 2;
    op_buf_clear(&f->sig);
    return op_buf_put(&f->sig, f->full.p, f->full.n);
}

/* depth == 0: a signature line, a declaration, or the line that opens one. */
static int op_top_line(struct op_fn *f, const char *line, int nb, int ne)
{
    if (nb == 0)
        return op_top_text(f, line);
    if (op_sigfull(f, line))
        return 2;
    f->depth = nb - ne;
    return f->mode == OP_MODE_PUB ? op_open_pub(f, line) : op_open_std(f);
}

int op_fn_line(struct op_fn *f, const char *raw, size_t len)
{
    int nb, ne, rc;
    f->lineno++;
    if (len > 0 && raw[len - 1] == '\n')
        len--;
    op_buf_clear(&f->work);
    if (op_buf_put(&f->work, raw, len))
        return 2;
    if (op_strip(f))
        return 0;
    op_count_braces(f->work.p, &nb, &ne);
    if (f->depth == 0)
        return op_top_line(f, f->work.p, nb, ne);
    f->depth += nb - ne;
    rc = op_body_push(f, f->work.p);
    if (rc || f->depth > 0)
        return rc;
    return op_close(f);
}

struct op_file_ctx {
    struct op_fn *f;
};

static int op_file_line(void *ctx, const char *line, size_t len)
{
    struct op_file_ctx *c = ctx;
    return op_fn_line(c->f, line, len);
}

int op_fn_file(struct op_fn *f, const char *path, int *final_depth)
{
    struct op_file_ctx c = { f };
    int rc;
    op_fn_begin(f, path);
    rc = lc_each_line(path, op_file_line, &c, 0);
    if (rc == 0)
        *final_depth = op_fn_end(f);
    return rc;
}

int op_feed_text(struct op_fn *f, const char *name, const char *text,
                 int *final_depth)
{
    const char *p = text;
    op_fn_begin(f, name);
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) + 1 : strlen(p);
        int rc = op_fn_line(f, p, n);
        if (rc)
            return rc;
        p += n;
    }
    *final_depth = op_fn_end(f);
    return 0;
}


/* Parameter list of a signature: the text between the first "(" and the last
 * ")" split on every comma, each part trimmed, NUL-separated into out.
 * Returns the part count, 0 when there is no list, -1 on out of memory. */
int op_params(const char *sig, struct op_buf *out)
{
    const char *o = strchr(sig, '('), *c = NULL, *s;
    int n = 0;
    op_buf_clear(out);
    if (!o)
        return 0;
    for (s = strchr(o + 1, ')'); s; s = strchr(s + 1, ')'))
        c = s;
    if (!c || c == o + 1)
        return 0;
    for (s = o + 1;; s++) {
        const char *e = s;
        size_t before = out->n;
        while (e < c && *e != ',')
            e++;
        if (op_buf_put(out, s, (size_t)(e - s)) || op_buf_put(out, "", 1))
            return -1;
        out->n = before + op_trim(out->p + before) + 1;
        n++;
        if (e >= c)
            break;
        s = e;
    }
    return n;
}

const char *op_param_at(const struct op_buf *b, int idx)
{
    const char *p = b->p;
    while (idx-- > 0)
        p += strlen(p) + 1;
    return p;
}
