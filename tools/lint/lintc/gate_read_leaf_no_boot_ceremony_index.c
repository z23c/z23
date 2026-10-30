/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: phases 2-3 support for check-read-leaf-no-boot-ceremony -- the
 * comment/string-stripping C function indexer (port of the second awk pass
 * of the deleted shell gate) plus the raw-substring scan proving each
 * banned boot-ceremony symbol still exists in the corpus. A function body
 * is a brace block whose pending file-scope signature ends in a close
 * paren; callees are identifier-call tokens collected across body lines
 * with duplicates merged.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_read_leaf_no_boot_ceremony_priv.h"

struct rlb_ictx {
    int in_comment, in_str, in_chr, esc, depth;
    char pend[RLB_PEND];
    size_t pn;
    char fname[192];
    char callees[RLB_CALLEES];
    struct rlb_fnidx *fi;
    int rc;
};

static int rlb_kw(const char *w)
{
    return !strcmp(w, "if") || !strcmp(w, "for") || !strcmp(w, "while") ||
           !strcmp(w, "switch") || !strcmp(w, "return") ||
           !strcmp(w, "sizeof") || !strcmp(w, "defined") || !strcmp(w, "do") ||
           !strcmp(w, "else") || !strcmp(w, "alignof") ||
           !strcmp(w, "_Generic");
}

/* True when raw[i] and raw[i+1] are the two characters a and b. */
static int rlb_pair(const char *raw, size_t i, char a, char b)
{
    return raw[i] == a && raw[i + 1] == b;
}

/* One character inside a string (q = '"') or char (q = '\'') literal. */
static void rlb_lit_char(struct rlb_ictx *t, int *open, char c, char q)
{
    if (t->esc)
        t->esc = 0;
    else if (c == '\\')
        t->esc = 1;
    else if (c == q)
        *open = 0;
}

/* Opens a string or char literal at raw[i] when c is its quote. */
static int rlb_open_lit(struct rlb_ictx *t, char c)
{
    if (c != '"' && c != '\'')
        return 0;
    if (c == '"')
        t->in_str = 1;
    else
        t->in_chr = 1;
    t->esc = 0;
    return 1;
}

/* Strip block/line comments and string/char literals from one line; the
 * in_comment/in_str/in_chr state carries across the lines of one file. */
static size_t rlb_strip(struct rlb_ictx *t, const char *raw, size_t n,
                        char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        char c = raw[i];
        if (t->in_comment) {
            if (rlb_pair(raw, i, '*', '/')) {
                t->in_comment = 0;
                i++;
            }
            continue;
        }
        if (t->in_str) {
            rlb_lit_char(t, &t->in_str, c, '"');
            continue;
        }
        if (t->in_chr) {
            rlb_lit_char(t, &t->in_chr, c, '\'');
            continue;
        }
        if (rlb_pair(raw, i, '/', '*')) {
            t->in_comment = 1;
            i++;
            continue;
        }
        if (rlb_pair(raw, i, '/', '/'))
            break;
        if (rlb_open_lit(t, c))
            continue;
        out[o++] = c;
    }
    out[o] = '\0';
    return o;
}

/* First IDENT( at paren depth 0 in the pending signature text, or 0. */
static int rlb_fnname(char *dst, size_t cap, const char *pend)
{
    int dpt = 0;
    size_t idn = 0;
    char id[192];
    for (size_t i = 0; pend[i]; i++) {
        char c = pend[i];
        if (rlb_isid((unsigned char)c)) {
            if (idn + 1 >= sizeof id)
                return 0;
            id[idn++] = c;
            continue;
        }
        if (c == '(') {
            id[idn] = '\0';
            if (dpt == 0 && idn && !rlb_kw(id)) {
                if (cap < idn + 1)
                    return 0;
                memcpy(dst, id, idn + 1);
                return 1;
            }
            dpt++;
        } else if (c == ')') {
            dpt--;
        }
        idn = 0;
    }
    return 0;
}

static void rlb_cal_add(struct rlb_ictx *t, char *cals, const char *tok)
{
    char pat[200];
    if (ovf(snprintf(pat, sizeof pat, " %s ", tok), sizeof pat)) {
        t->rc = 2;
        return;
    }
    size_t l = strlen(cals);
    if (strstr(cals, pat))
        return;
    if (l + strlen(pat) + 1 > RLB_CALLEES) {
        if (!t->rc) {
            fprintf(stderr, "%s: callees for %s exceed %d\n", RLB_GATE,
                    t->fname, RLB_CALLEES);
            t->rc = 2;
        }
        return;
    }
    strcat(cals, pat);
}

/* Adds every space-separated callee token of src into cals, deduplicated.
 * Callee tokens are shorter than 192 bytes by construction (rlb_scan_body). */
static void rlb_merge(struct rlb_ictx *t, char *cals, const char *src)
{
    char tok[192];
    size_t i = 0;
    while (src[i]) {
        size_t n = 0;
        while (src[i] == ' ')
            i++;
        while (src[i] && src[i] != ' ') {
            if (n + 1 >= sizeof tok) {
                if (!t->rc) {
                    fprintf(stderr, "%s: callee token in %s exceeds %zu\n",
                            RLB_GATE, t->fname, sizeof tok);
                    t->rc = 2;
                }
                return;
            }
            tok[n++] = src[i++];
        }
        tok[n] = '\0';
        if (n)
            rlb_cal_add(t, cals, tok);
    }
}

static char rlb_tmpcal[RLB_CALLEES];

/* Appends the merged callee string in rlb_tmpcal to the pool; returns its
 * offset, or (size_t)-1 when the pool is full. */
static size_t rlb_pool_put(struct rlb_ictx *t)
{
    struct rlb_fnidx *fi = t->fi;
    size_t l = strlen(rlb_tmpcal) + 1;
    if (fi->pool_n + l > RLB_POOL) {
        if (!t->rc) {
            fprintf(stderr, "%s: callee pool exceeds %u\n", RLB_GATE,
                    (unsigned)RLB_POOL);
            t->rc = 2;
        }
        return (size_t)-1;
    }
    size_t off = fi->pool_n;
    memcpy(fi->pool + off, rlb_tmpcal, l);
    fi->pool_n += l;
    return off;
}

static void rlb_fn_add(struct rlb_ictx *t)
{
    struct rlb_fnidx *fi = t->fi;
    struct rlb_fn *f = NULL;
    fi->ndef++;
    for (int i = 0; i < fi->n && !f; i++)
        if (!strcmp(fi->v[i].name, t->fname))
            f = &fi->v[i];
    if (!f && fi->n >= RLB_FNS) {
        if (!t->rc) {
            fprintf(stderr, "%s: function index exceeds %d\n", RLB_GATE,
                    RLB_FNS);
            t->rc = 2;
        }
        return;
    }
    if (f) {
        snprintf(rlb_tmpcal, sizeof rlb_tmpcal, "%s", fi->pool + f->off);
    } else {
        f = &fi->v[fi->n];
        if (ovf(snprintf(f->name, sizeof f->name, "%s", t->fname),
                sizeof f->name)) {
            t->rc = 2;
            return;
        }
        rlb_tmpcal[0] = '\0';
        fi->n++;
    }
    rlb_merge(t, rlb_tmpcal, t->callees);
    size_t off = t->rc ? (size_t)-1 : rlb_pool_put(t);
    if (off != (size_t)-1)
        f->off = off;
}

static void rlb_flush(struct rlb_ictx *t)
{
    if (t->fname[0] && !t->rc)
        rlb_fn_add(t);
    t->fname[0] = '\0';
    t->callees[0] = '\0';
}

static void rlb_pendput(struct rlb_ictx *t, char c)
{
    if (t->pn + 1 >= sizeof t->pend) {
        if (!t->rc) {
            fprintf(stderr, "%s: pending signature exceeds %d\n", RLB_GATE,
                    RLB_PEND);
            t->rc = 2;
        }
        return;
    }
    t->pend[t->pn++] = c;
    t->pend[t->pn] = '\0';
}

static void rlb_open_brace(struct rlb_ictx *t)
{
    if (t->depth == 0) {
        size_t l = t->pn;
        while (l && (t->pend[l - 1] == ' ' || t->pend[l - 1] == '\t'))
            l--;
        if (l && t->pend[l - 1] == ')') {
            char nm[192];
            if (rlb_fnname(nm, sizeof nm, t->pend)) {
                if (ovf(snprintf(t->fname, sizeof t->fname, "%s", nm),
                        sizeof t->fname))
                    t->rc = 2;
                t->callees[0] = '\0';
            }
        }
        t->pn = 0;
        t->pend[0] = '\0';
    }
    t->depth++;
}

static void rlb_scan_body(struct rlb_ictx *t, const char *buf)
{
    size_t i = 0;
    while (buf[i]) {
        if (!rlb_isid((unsigned char)buf[i]) || isdigit((unsigned char)buf[i])) {
            i++;
            continue;
        }
        size_t j = i;
        while (rlb_isid((unsigned char)buf[j]))
            j++;
        if (buf[j] == '(') {
            char tok[192];
            size_t l = j - i;
            if (l + 1 > sizeof tok) {
                i = j + 1;
                continue;
            }
            memcpy(tok, buf + i, l);
            tok[l] = '\0';
            if (!rlb_kw(tok))
                rlb_cal_add(t, t->callees, tok);
            i = j + 1;
        } else {
            i = j;
        }
    }
}

static int rlb_idx_chars(struct rlb_ictx *t, const char *s, char *buf,
                         size_t *bn)
{
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '{') {
            rlb_open_brace(t);
            continue;
        }
        if (c == '}') {
            t->depth--;
            if (t->depth <= 0) {
                t->depth = 0;
                rlb_flush(t);
                t->pn = 0;
                t->pend[0] = '\0';
            }
            continue;
        }
        if (t->depth == 0) {
            if (c == ';') {
                t->pn = 0;
                t->pend[0] = '\0';
            } else {
                rlb_pendput(t, c);
            }
            continue;
        }
        if (*bn + 1 >= RLB_LINE) {
            if (!t->rc) {
                fprintf(stderr, "%s: body line exceeds %d\n", RLB_GATE,
                        RLB_LINE);
                t->rc = 2;
            }
            return 2;
        }
        buf[(*bn)++] = c;
    }
    buf[*bn] = '\0';
    return t->rc;
}

static int rlb_idx_line(void *ctx, const char *line, size_t len)
{
    struct rlb_ictx *t = ctx;
    char raw[RLB_LINE], code[RLB_LINE], buf[RLB_LINE];
    if (len && line[len - 1] == '\n')
        len--; /* awk records carry no newline */
    if (len + 2 >= sizeof raw) {
        fprintf(stderr, "%s: line in %s exceeds %d\n", RLB_GATE, t->fname,
                RLB_LINE);
        return 2;
    }
    memcpy(raw, line, len);
    raw[len] = '\0';
    size_t n = rlb_strip(t, raw, len, code);
    code[n] = ' ';
    code[n + 1] = '\0';
    size_t bn = 0;
    if (rlb_idx_chars(t, code, buf, &bn))
        return 2;
    if (t->depth > 0 && t->fname[0])
        rlb_scan_body(t, buf);
    return t->rc;
}

static int rlb_index_path(const char *root, const char *rel,
                          struct rlb_fnidx *fi)
{
    static struct rlb_ictx t;
    memset(&t, 0, sizeof t);
    t.fi = fi;
    char path[RLB_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    int rc = lc_each_line(path, rlb_idx_line, &t, 1);
    if (rc == 1) {
        fprintf(stderr, "%s: cannot read %s\n", RLB_GATE, path);
        return 2;
    }
    if (rc)
        return rc;
    rlb_flush(&t);
    return t.rc;
}

int rlb_index_paths(const char *root, const char *const *paths, int n,
                    struct rlb_fnidx *fi)
{
    for (int i = 0; i < n; i++) {
        int rc = rlb_index_path(root, paths[i], fi);
        if (rc)
            return rc;
    }
    return 0;
}

static char rlb_banbuf[RLB_FILEBUF];

/* Raw substring scan for "<banned>(" in one corpus file, mirroring the
 * git grep -F existence check of the shell original. */
int rlb_banned_scan_file(const char *root, const char *rel,
                         unsigned char found[RLB_NBAN])
{
    char path[RLB_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", RLB_GATE, path);
        return 2;
    }
    size_t n = fread(rlb_banbuf, 1, sizeof rlb_banbuf - 1, f);
    int more = fgetc(f) != EOF;
    fclose(f);
    if (more) {
        fprintf(stderr, "%s: %s exceeds %u bytes\n", RLB_GATE, rel,
                (unsigned)sizeof rlb_banbuf);
        return 2;
    }
    rlb_banbuf[n] = '\0';
    for (int k = 0; k < RLB_NBAN; k++) {
        if (found[k])
            continue;
        char pat[160];
        if (ovf(snprintf(pat, sizeof pat, "%s(", rlb_banned[k]), sizeof pat))
            return 2;
        if (strstr(rlb_banbuf, pat))
            found[k] = 1;
    }
    return 0;
}
