/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shell-grammar tokeniser and line reader for the
 * check-pipefail-status-pipe gate (see gate_pipefail_status_pipe.c).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_pipefail_status_pipe_priv.h"

int psp_err2(const char *what, const char *arg, long n)
{
    fprintf(stderr, PSP_GATE ": %s%s%s exceeds %ld\n", what, arg ? ": " : "",
            arg ? arg : "", n);
    return 2;
}

/* ── line reader: fgets with a fail-closed line cap ──────────────────── */
int psp_each_line(const char *path, int (*cb)(void *, const char *,
                                                     size_t), void *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    static char buf[PSP_LINE];
    int rc = 0;
    while (fgets(buf, sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n + 1 >= sizeof buf && buf[n - 1] != '\n') {
            fprintf(stderr, PSP_GATE ": %s: line exceeds %d bytes\n", path,
                    PSP_LINE);
            rc = 2;
            break;
        }
        rc = cb(ctx, buf, n);
        if (rc)
            break;
    }
    if (!rc && ferror(f)) {
        fprintf(stderr, PSP_GATE ": read error on %s\n", path);
        rc = 2;
    }
    fclose(f);
    return rc;
}

static int psp_pf_cb(void *ctx, const char *line, size_t n)
{
    (void)n;
    if (strstr(line, "pipefail")) {
        *(int *)ctx = 1;
        return 1;
    }
    return 0;
}

static int psp_has_pipefail(const char *path)
{
    int hit = 0;
    int rc = psp_each_line(path, psp_pf_cb, &hit);
    if (hit)
        return 1;
    if (rc) {
        if (rc == 1)
            fprintf(stderr, PSP_GATE ": cannot read %s\n", path);
        return -1;
    }
    return 0;
}

/* ── the tokeniser (port of the awk scanner) ─────────────────────────── */
struct psp_tok {
    char stmt[PSP_STMT];
    size_t slen;
    long stmt_line, lineno;
    int insq, indq;
    char hd_delim[128];
    int hd_tabs;
    long count, first_line;
    const char *path;
};

static void psp_reset_stmt(struct psp_tok *t)
{
    t->stmt[0] = '\0';
    t->slen = 0;
    t->stmt_line = 0;
}

static int psp_is_grep_cmd(const char *s)
{
    static const char *const names[] = { "grep", "egrep", "fgrep",
                                         "gate_grep" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        size_t l = strlen(names[i]);
        if (strncmp(s, names[i], l) == 0 &&
            (s[l] == ' ' || s[l] == '\t' || s[l] == '\0'))
            return 1;
    }
    return 0;
}

/* word matches ^-[A-Za-z]*q[A-Za-z]*$ */
static int psp_flag_has_q(const char *w)
{
    if (w[0] != '-' || w[1] == '\0')
        return 0;
    int q = 0;
    for (const char *p = w + 1; *p; p++) {
        if (!isalpha((unsigned char)*p))
            return 0;
        if (*p == 'q')
            q = 1;
    }
    return q;
}

/* true when a word after the command is a single-dash flag cluster with q */
static int psp_stage_has_q(const char *p)
{
    char word[PSP_STAGE];
    int first = 1;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        size_t w = 0;
        while (*p && *p != ' ' && *p != '\t' && w + 1 < sizeof word)
            word[w++] = *p++;
        word[w] = '\0';
        if (!first && psp_flag_has_q(word))
            return 1;
        first = 0;
    }
    return 0;
}

static void psp_stage_check(struct psp_tok *t, char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
    size_t o = 0;
    while (s[o] == ' ' || s[o] == '\t')
        o++;
    if (!psp_is_grep_cmd(s + o) || !psp_stage_has_q(s + o))
        return;
    t->count++;
    if (t->first_line == 0)
        t->first_line = t->stmt_line;
}

static int psp_flush(struct psp_tok *t)
{
    if (t->slen == 0) {
        t->stmt_line = 0;
        return 0;
    }
    /* split on SEP; need >= 2 stages and a -q grep in stage 2..n */
    char stage[PSP_STAGE];
    size_t o = 0, si = 0;
    const char *s = t->stmt;
    size_t i = 0;
    int decided = 0;
    while (1) {
        if (s[i] == PSP_SEP || s[i] == '\0') {
            if (i - o >= sizeof stage) {
                return psp_err2("statement stage", t->path,
                                (long)sizeof stage);
            }
            memcpy(stage, s + o, i - o);
            stage[i - o] = '\0';
            si++;
            if (si >= 2 && !decided) {
                long before = t->count;
                psp_stage_check(t, stage);
                if (t->count > before)
                    decided = 1;
            }
            o = i + 1;
            if (s[i] == '\0')
                break;
        }
        i++;
    }
    psp_reset_stmt(t);
    return 0;
}

static int psp_word_end(char c)
{
    return c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|' ||
           c == '(' || c == ')' || c == '\0';
}

/* length of then/do/else keyword at code+i, else 0 */
static int psp_kw_at(const char *s, size_t i)
{
    static const char *const kws[] = { "then", "do", "else" };
    for (size_t k = 0; k < 3; k++) {
        size_t l = strlen(kws[k]);
        if (strncmp(s + i, kws[k], l) == 0 && psp_word_end(s[i + l]))
            return (int)l;
    }
    return 0;
}

static int psp_sep_char(char c)
{
    return c == ';' || c == '&' || c == '(' || c == ')' || c == '{' ||
           c == '}';
}

/* copy the quoted span starting at code[i] into the statement; returns the
 * index just past it */
static size_t psp_quoted(struct psp_tok *t, const char *code, size_t i)
{
    size_t m = strlen(code), j = i + 1;
    char c = code[i];
    if (t->stmt_line == 0)
        t->stmt_line = t->lineno;
    t->stmt[t->slen++] = c;
    while (j < m) {
        char d = code[j];
        if (c == '"' && d == '\\' && j + 1 < m) {
            t->stmt[t->slen++] = d;
            t->stmt[t->slen++] = code[j + 1];
            j += 2;
            continue;
        }
        t->stmt[t->slen++] = d;
        j++;
        if (d == c)
            break;
    }
    t->stmt[t->slen] = '\0';
    return j;
}

static void psp_add_pipe(struct psp_tok *t)
{
    if (t->stmt_line == 0)
        t->stmt_line = t->lineno;
    t->stmt[t->slen++] = PSP_SEP;
    t->stmt[t->slen] = '\0';
}

/* length of a statement separator at code[i] (&&, ||, one separator char, or
 * a then/do/else keyword), else 0; a lone '|' is a pipe, not a separator */
static size_t psp_sep_len(const char *code, size_t i)
{
    char c = code[i];
    if ((c == '&' && code[i + 1] == '&') || (c == '|' && code[i + 1] == '|'))
        return 2;
    if (psp_sep_char(c))
        return 1;
    if (c == '|')
        return 0;
    return (size_t)psp_kw_at(code, i);
}

static int psp_split(struct psp_tok *t, const char *code)
{
    size_t m = strlen(code), i = 0;
    while (i <= m && code[i] != '\0') {
        char c = code[i];
        if (c == '\'' || c == '"') {
            i = psp_quoted(t, code, i);
            continue;
        }
        size_t sl = psp_sep_len(code, i);
        if (sl) {
            if (psp_flush(t))
                return 2;
            i += sl;
            continue;
        }
        if (c == '|') {
            psp_add_pipe(t);
            i++;
            continue;
        }
        if (t->stmt_line == 0 && c != ' ' && c != '\t')
            t->stmt_line = t->lineno;
        t->stmt[t->slen++] = c;
        t->stmt[t->slen] = '\0';
        i++;
    }
    return 0;
}

static int psp_is_idc(char c, int first)
{
    return isalpha((unsigned char)c) || c == '_' ||
           (!first && isdigit((unsigned char)c));
}

/* heredoc open detection on the raw line (replicates the awk match) */
static void psp_hd_open(struct psp_tok *t, const char *raw)
{
    for (size_t i = 0; raw[i] && raw[i + 1]; i++) {
        if (raw[i] != '<' || raw[i + 1] != '<')
            continue;
        size_t j = i + 2;
        int tabs = 0;
        if (raw[j] == '-') {
            tabs = 1;
            j++;
        }
        while (raw[j] == ' ' || raw[j] == '\t')
            j++;
        if (raw[j] == '\'' || raw[j] == '"')
            j++;
        if (!psp_is_idc(raw[j], 1))
            continue;
        size_t d = 0;
        while (psp_is_idc(raw[j], 0) && d + 1 < sizeof t->hd_delim)
            t->hd_delim[d++] = raw[j++];
        t->hd_delim[d] = '\0';
        t->hd_tabs = tabs;
        return;
    }
}

static int psp_hd_body(struct psp_tok *t, const char *line, size_t n)
{
    char buf[PSP_LINE];
    if (n >= sizeof buf)
        return psp_err2("heredoc line", t->path, (long)sizeof buf);
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (n > 0 && buf[n - 1] == '\n')
        buf[n - 1] = '\0';
    char *p = buf;
    if (t->hd_tabs)
        while (*p == '\t')
            p++;
    if (strcmp(p, t->hd_delim) == 0)
        t->hd_delim[0] = '\0';
    return 0;
}

static int psp_prevc_ok(char prevc)
{
    return prevc == '\0' || prevc == ' ' || prevc == '\t' || prevc == ';' ||
           prevc == '&' || prevc == '|' || prevc == '(' || prevc == ')' ||
           prevc == '{' || prevc == '}';
}

/* quote-aware comment strip; returns 2 on overflow */
static int psp_strip(struct psp_tok *t, const char *line, size_t n,
                     char *out, size_t cap)
{
    size_t o = 0;
    char prevc = '\0';
    int insq = t->insq, indq = t->indq;
    for (size_t i = 0; i < n; i++) {
        char c = line[i];
        if (insq) {
            out[o++] = c;
            if (c == '\'')
                insq = 0;
            prevc = c;
        } else if (indq) {
            if (c == '\\' && i + 1 < n) {
                out[o++] = c;
                out[o++] = line[++i];
            } else {
                out[o++] = c;
                if (c == '"')
                    indq = 0;
            }
            prevc = c;
        } else if (c == '\\' && i + 1 < n) {
            out[o++] = c;
            out[o++] = line[++i];
            prevc = 'x';
        } else if (c == '\'') {
            insq = 1;
            out[o++] = c;
            prevc = c;
        } else if (c == '"') {
            indq = 1;
            out[o++] = c;
            prevc = c;
        } else if (c == '#' && psp_prevc_ok(prevc)) {
            break;
        } else {
            out[o++] = c;
            prevc = c;
        }
        t->insq = insq;
        t->indq = indq;
        if (o + 1 >= cap)
            return 1;
    }
    out[o] = '\0';
    return 0;
}

static int psp_tok_line(void *ctx, const char *line, size_t n)
{
    struct psp_tok *t = ctx;
    t->lineno++;
    if (t->hd_delim[0])
        return psp_hd_body(t, line, n);
    char code[PSP_LINE];
    size_t cn = (n > 0 && line[n - 1] == '\n') ? n - 1 : n;
    if (psp_strip(t, line, cn, code, sizeof code))
        return psp_err2("code line", t->path, (long)sizeof code);
    if (t->slen + strlen(code) + 4 >= sizeof t->stmt)
        return psp_err2("statement", t->path, (long)sizeof t->stmt);
    if (psp_split(t, code))
        return 2;
    psp_hd_open(t, line);
    size_t tl = strlen(code);
    while (tl > 0 && (code[tl - 1] == ' ' || code[tl - 1] == '\t'))
        tl--;
    if (tl > 0 && code[tl - 1] == '\\')
        return 0;
    if (t->slen > 0 && t->stmt[t->slen - 1] == PSP_SEP)
        return 0;
    return psp_flush(t);
}

int psp_scan_file(const char *path, long *count, long *first)
{
    int pf = psp_has_pipefail(path);
    if (pf < 0)
        return 2;
    if (!pf) {
        *count = 0;
        return 0;
    }
    static struct psp_tok t;
    memset(&t, 0, sizeof t);
    t.path = path;
    int rc = psp_each_line(path, psp_tok_line, &t);
    if (rc || psp_flush(&t))
        return 2;
    *count = t.count;
    *first = t.first_line;
    return 0;
}

