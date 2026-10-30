/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: phase 1 of check-read-leaf-no-boot-ceremony -- parse the
 * ZCL_COMMAND_*_READ / _COMMAND leaf macros out of every *.def under the
 * declaration dir and emit one READ record per READ leaf that binds a
 * handler. Faithful port of the awk parser in the deleted
 * tools/lint/check_read_leaf_no_boot_ceremony.sh, including the per-macro
 * arity assertions (a macro grammar change aborts LOUD, never reads the
 * wrong handler slot). Used by gate_read_leaf_no_boot_ceremony.c and its
 * selftest.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_read_leaf_no_boot_ceremony_priv.h"

static const char *const k_macros[] = {
    "ZCL_COMMAND_READY_READ",     "ZCL_COMMAND_READY_COMMAND",
    "ZCL_COMMAND_PLANNED_READ",   "ZCL_COMMAND_PLANNED_COMMAND",
    "ZCL_COMMAND_COMPAT_READ",    "ZCL_COMMAND_COMPAT_COMMAND",
    "ZCL_COMMAND_DEV_READ",       "ZCL_COMMAND_DEV_COMMAND",
};

struct rlb_dst {
    int in_comment, in_str, esc, collecting;
    char tok[128];
    char args[RLB_ARGS][RLB_ARG];
    int nargs;
    char mtype[64];
    char startfile[RLB_PATH];
    int startline;
    int depth;
    char cur[RLB_CUR];
    size_t cn, tn;
};

struct rlb_dctx {
    struct rlb_dst st;
    struct rlb_readset *rs;
    struct rlb_fatalset *fs;
    const char *file;
    int lineno, nleaf;
    int rc;
};

struct rlb_wctx {
    char (*v)[RLB_PATH];
    int n, rc;
};

int rlb_isid(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
           (c >= '0' && c <= '9');
}

static int rlb_macro_is(const char *tok)
{
    for (size_t i = 0; i < sizeof k_macros / sizeof k_macros[0]; i++)
        if (!strcmp(k_macros[i], tok))
            return 1;
    return 0;
}

static void rlb_dovf(struct rlb_dctx *d, const char *what, int n)
{
    if (!d->rc) {
        fprintf(stderr, "%s: %s exceeds %d\n", RLB_GATE, what, n);
        d->rc = 2;
    }
}

int rlb_trim(char *dst, size_t cap, const char *src)
{
    size_t b = 0, e = strlen(src), o = 0;
    while (src[b] == ' ' || src[b] == '\t' || src[b] == '\r' || src[b] == '\n')
        b++;
    while (e > b && (src[e - 1] == ' ' || src[e - 1] == '\t' ||
                     src[e - 1] == '\r' || src[e - 1] == '\n'))
        e--;
    if (e - b + 1 > cap)
        return 2;
    while (b < e)
        dst[o++] = src[b++];
    dst[o] = '\0';
    return 0;
}

/* awk literal(): drop backslash-quote pairs, then quotes, then whitespace. */
static int rlb_literal(char *dst, size_t cap, const char *s)
{
    size_t o = 0;
    for (size_t k = 0; s[k]; k++) {
        if (s[k] == '\\' && s[k + 1] == '"') {
            k++;
            continue;
        }
        if (s[k] == '"' || s[k] == ' ' || s[k] == '\t' || s[k] == '\r' ||
            s[k] == '\n')
            continue;
        if (o + 1 >= cap)
            return 2;
        dst[o++] = s[k];
    }
    dst[o] = '\0';
    return 0;
}

static void rlb_fat(struct rlb_dctx *d, const char *msg)
{
    struct rlb_fatalset *fs = d->fs;
    if (fs->n >= RLB_FAT)
        return;
    struct rlb_fatal *f = &fs->v[fs->n++];
    if (ovf(snprintf(f->file, sizeof f->file, "%s", d->st.startfile),
            sizeof f->file) ||
        ovf(snprintf(f->mtype, sizeof f->mtype, "%s", d->st.mtype),
            sizeof f->mtype) ||
        ovf(snprintf(f->msg, sizeof f->msg, "%s", msg), sizeof f->msg))
        d->rc = 2;
    f->line = d->st.startline;
}

static void rlb_curput(struct rlb_dctx *d, char c)
{
    if (d->st.cn + 1 >= sizeof d->st.cur) {
        rlb_dovf(d, "def macro argument", RLB_CUR);
        return;
    }
    d->st.cur[d->st.cn++] = c;
    d->st.cur[d->st.cn] = '\0';
}

static void rlb_tokput(struct rlb_dctx *d, char c)
{
    if (d->st.tn + 1 >= sizeof d->st.tok) {
        rlb_dovf(d, "def token", 128);
        return;
    }
    d->st.tok[d->st.tn++] = c;
    d->st.tok[d->st.tn] = '\0';
}

static void rlb_argpush(struct rlb_dctx *d)
{
    if (d->st.nargs >= RLB_ARGS) {
        rlb_dovf(d, "def macro arguments", RLB_ARGS);
        return;
    }
    if (ovf(snprintf(d->st.args[d->st.nargs++], RLB_ARG, "%s", d->st.cur),
            RLB_ARG)) {
        d->rc = 2;
        return;
    }
    d->st.cn = 0;
    d->st.cur[0] = '\0';
}

static int rlb_want_arity(struct rlb_dctx *d, int n)
{
    if (d->st.nargs == n)
        return 1;
    char msg[512];
    if (ovf(snprintf(msg, sizeof msg,
                     "macro grammar drift: expected %d arguments, parsed %d."
                     " This gate reads a fixed handler slot; re-read the"
                     " macro in engine/composition/src/command_catalog.c and"
                     " fix the arity table here.", n, d->st.nargs),
            sizeof msg))
        return 0;
    rlb_fat(d, msg);
    return 0;
}

/* idx1 is the 1-based handler slot from the awk arity table. */
static void rlb_emit(struct rlb_dctx *d, int idx1)
{
    char h[192], p[256];
    if (rlb_trim(h, sizeof h, d->st.args[idx1 - 1])) {
        rlb_dovf(d, "handler text", 192);
        return;
    }
    if (!h[0] || !strcmp(h, "NULL") || !strcmp(h, "0"))
        return;
    /* args[] is 0-based here; the awk's args[1] (the leaf path) is slot 0. */
    if (rlb_literal(p, sizeof p, d->st.args[0])) {
        rlb_dovf(d, "leaf path", 256);
        return;
    }
    struct rlb_readset *rs = d->rs;
    if (rs->n >= RLB_READS) {
        rlb_dovf(d, "READ leaf records", RLB_READS);
        return;
    }
    struct rlb_read *r = &rs->v[rs->n++];
    if (ovf(snprintf(r->path, sizeof r->path, "%s", p), sizeof r->path) ||
        ovf(snprintf(r->file, sizeof r->file, "%s", d->st.startfile),
            sizeof r->file) ||
        ovf(snprintf(r->handler, sizeof r->handler, "%s", h),
            sizeof r->handler)) {
        d->rc = 2;
        return;
    }
    r->line = d->st.startline;
}

static void rlb_finish_leaf(struct rlb_dctx *d)
{
    const char *m = d->st.mtype;
    d->nleaf++;
    if (!strcmp(m, "ZCL_COMMAND_READY_READ")) {
        if (rlb_want_arity(d, 22))
            rlb_emit(d, 22);
    } else if (!strcmp(m, "ZCL_COMMAND_DEV_READ")) {
        if (rlb_want_arity(d, 22))
            rlb_emit(d, 20);
    } else if (!strcmp(m, "ZCL_COMMAND_COMPAT_READ")) {
        (void)rlb_want_arity(d, 21);
    } else if (!strcmp(m, "ZCL_COMMAND_PLANNED_READ")) {
        (void)rlb_want_arity(d, 20);
    } else if (!strcmp(m, "ZCL_COMMAND_READY_COMMAND")) {
        (void)rlb_want_arity(d, 25);
    } else if (!strcmp(m, "ZCL_COMMAND_DEV_COMMAND")) {
        (void)rlb_want_arity(d, 26);
    } else if (!strcmp(m, "ZCL_COMMAND_PLANNED_COMMAND")) {
        (void)rlb_want_arity(d, 25);
    } else if (!strcmp(m, "ZCL_COMMAND_COMPAT_COMMAND")) {
        (void)rlb_want_arity(d, 26);
    }
}

static void rlb_fx_instr(struct rlb_dctx *d, char c)
{
    if (d->st.collecting)
        rlb_curput(d, c);
    if (d->st.esc)
        d->st.esc = 0;
    else if (c == '\\')
        d->st.esc = 1;
    else if (c == '"')
        d->st.in_str = 0;
}

static void rlb_fx_arg(struct rlb_dctx *d, const char *ln, size_t *i)
{
    char c = ln[*i];
    if (c == '(') {
        d->st.depth++;
        rlb_curput(d, c);
        return;
    }
    if (c == ')') {
        d->st.depth--;
        if (d->st.depth == 0) {
            rlb_argpush(d);
            d->st.collecting = 0;
            rlb_finish_leaf(d);
        } else {
            rlb_curput(d, c);
        }
        return;
    }
    if (c == ',' && d->st.depth == 1) {
        rlb_argpush(d);
        return;
    }
    rlb_curput(d, c);
}

static void rlb_fx_code(struct rlb_dctx *d, const char *ln, size_t *i)
{
    char c = ln[*i];
    if (d->st.collecting) {
        rlb_fx_arg(d, ln, i);
        return;
    }
    if (rlb_isid((unsigned char)c)) {
        rlb_tokput(d, c);
        return;
    }
    if (c == '(' && rlb_macro_is(d->st.tok)) {
        if (ovf(snprintf(d->st.mtype, sizeof d->st.mtype, "%s", d->st.tok),
                sizeof d->st.mtype))
            d->rc = 2;
        if (ovf(snprintf(d->st.startfile, sizeof d->st.startfile, "%s",
                         d->file), sizeof d->st.startfile))
            d->rc = 2;
        d->st.startline = d->lineno;
        d->st.collecting = 1;
        d->st.depth = 1;
        d->st.nargs = 0;
        d->st.cn = 0;
        d->st.cur[0] = '\0';
        d->st.tn = 0;
        d->st.tok[0] = '\0';
        return;
    }
    d->st.tn = 0;
    d->st.tok[0] = '\0';
}

static void rlb_feed(struct rlb_dctx *d, const char *ln)
{
    for (size_t i = 0; ln[i] && !d->rc; i++) {
        char c = ln[i];
        if (d->st.in_comment) {
            if (c == '*' && ln[i + 1] == '/') {
                d->st.in_comment = 0;
                i++;
            }
            continue;
        }
        if (d->st.in_str) {
            rlb_fx_instr(d, c);
            continue;
        }
        if (c == '/' && ln[i + 1] == '*') {
            d->st.in_comment = 1;
            i++;
            continue;
        }
        if (c == '"') {
            d->st.in_str = 1;
            d->st.esc = 0;
            if (d->st.collecting)
                rlb_curput(d, c);
            continue;
        }
        rlb_fx_code(d, ln, &i);
    }
}

static int rlb_def_line(void *ctx, const char *line, size_t len)
{
    struct rlb_dctx *d = ctx;
    char buf[RLB_LINE];
    d->lineno++;
    if (len + 1 >= sizeof buf) {
        fprintf(stderr, "%s: line %d of %s exceeds %d\n", RLB_GATE, d->lineno,
                d->file, RLB_LINE);
        return 2;
    }
    memcpy(buf, line, len);
    buf[len] = '\n';
    buf[len + 1] = '\0';
    rlb_feed(d, buf);
    return d->rc;
}

static int rlb_isdir(const char *p)
{
    struct stat sb;
    return stat(p, &sb) == 0 && S_ISDIR(sb.st_mode);
}

static void rlb_walk_add(struct rlb_wctx *w, const char *rel)
{
    if (w->n >= RLB_DEFS) {
        if (!w->rc) {
            fprintf(stderr, "%s: def file list exceeds %d\n", RLB_GATE,
                    RLB_DEFS);
            w->rc = 2;
        }
        return;
    }
    if (ovf(snprintf(w->v[w->n++], RLB_PATH, "%s", rel), RLB_PATH))
        w->rc = 2;
}

static void rlb_walk(struct rlb_wctx *w, const char *abs, const char *rel)
{
    DIR *dr = opendir(abs);
    if (!dr) {
        if (!w->rc) {
            fprintf(stderr, "%s: cannot read dir %s\n", RLB_GATE, abs);
            w->rc = 2;
        }
        return;
    }
    struct dirent *e;
    while (!w->rc && (e = readdir(dr))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char a[RLB_PATH], r[RLB_PATH];
        if (ovf(snprintf(a, sizeof a, "%s/%s", abs, e->d_name), sizeof a) ||
            ovf(snprintf(r, sizeof r, "%s/%s", rel, e->d_name), sizeof r)) {
            w->rc = 2;
            continue;
        }
        if (rlb_isdir(a))
            rlb_walk(w, a, r);
        else {
            size_t l = strlen(e->d_name);
            if (l > 4 && !strcmp(e->d_name + l - 4, ".def"))
                rlb_walk_add(w, r);
        }
    }
    closedir(dr);
}

static int rlb_rowcmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

int rlb_parse_defs(const char *root, const char *def_dir,
                   struct rlb_readset *rs, int *nleaf, int *ndefs,
                   struct rlb_fatalset *fs)
{
    static char defs[RLB_DEFS][RLB_PATH];
    char abs[RLB_PATH];
    if (ovf(snprintf(abs, sizeof abs, "%s/%s", root, def_dir), sizeof abs))
        return 2;
    struct rlb_wctx w = { defs, 0, 0 };
    rlb_walk(&w, abs, def_dir);
    if (w.rc)
        return w.rc;
    qsort(defs, (size_t)w.n, sizeof defs[0], rlb_rowcmp);
    static struct rlb_dctx d;
    memset(&d, 0, sizeof d);
    d.rs = rs;
    d.fs = fs;
    for (int i = 0; i < w.n && !d.rc; i++) {
        char p[RLB_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", root, defs[i]), sizeof p))
            return 2;
        d.file = defs[i];
        d.lineno = 0;
        memset(&d.st, 0, sizeof d.st);
        int rc = lc_each_line(p, rlb_def_line, &d, 1);
        if (rc == 1) {
            fprintf(stderr, "%s: cannot read %s\n", RLB_GATE, p);
            return 2;
        }
        if (rc)
            return rc;
    }
    if (d.st.collecting && !d.rc)
        rlb_fat(&d, "unterminated macro invocation: EOF with an open"
                    " argument list.");
    *nleaf = d.nleaf;
    *ndefs = w.n;
    return d.rc;
}

int rlb_def_fatal_report(const struct rlb_fatalset *fs)
{
    for (int i = 0; i < fs->n; i++)
        fprintf(stderr, "  %s:%d: %s — %s\n", fs->v[i].file, fs->v[i].line,
                fs->v[i].mtype, fs->v[i].msg);
    fprintf(stderr, "%s: FATAL — command macro grammar drift.\n", RLB_GATE);
    return 2;
}
