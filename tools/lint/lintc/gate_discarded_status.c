/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_discarded_status — refuse a shell decision whose exit
 * status the shell throws away, so the check reads as PASS whatever it
 * found. Ported from tools/lint/check_discarded_status.sh (deleted).
 * Selftest: gate_discarded_status_selftest.c.
 *
 * PRONG A: a bare `! cmd` statement under `set -e` never fails the script
 * (bash exempts inverted return values from errexit and from the ERR trap),
 * so a negative assertion spelled that way is decorative. A `!` statement is
 * exempt on exactly four grounds, each a place the status is consumed:
 *   1. inside the condition list of if/elif/while/until (running flag, set
 *      by the opener and cleared by then/do, not "keyword immediately
 *      before");
 *   2. closed by `&&` or `||`;
 *   3. the last command of a brace group, so its value is the function's
 *      return value (checked on the logical line and against a `}` on the
 *      next significant source line);
 *   4. the word after `!` starts with `-` (a find/test predicate).
 *
 * PRONG B: `make ... | head/tail` in a script that never sets pipefail —
 * the pipeline reports the last stage's 0 and a failed build is erased.
 * Hard, no baseline, no allow-comment escape hatch.
 *
 * The scan is a quote-aware character walk, deliberately not a line-shape
 * match: nothing anchors to a column, an indent, or one statement per line.
 * Heredoc bodies are data and are skipped; a still-open quote at end of
 * line continues the logical line.
 *
 * Exit: 0 clean, 1 on any violation, 2 on a broken scan (fail closed).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_discarded_status_priv.h"
#include "gate_no_wallclock_assertion_priv.h"

static const char k_cds_gate[] = "check_discarded_status";

enum { CDS_SQ = 0x27, CDS_DQ = 0x22 };

/* Per-file scanner state; one file at a time, single-threaded. */
struct cds_file {
    int seen_e;
    int seen_pipefail;
    signed char src[CDS_SRCN]; /* 0 empty, 1 lone close brace, 2 other */
    int src_n;
    int insq;
    int indq;
    char hd_delim[CDS_NAME];
    int hd_tabs;
    char logical[CDS_LOGICAL];
    size_t logical_len;
    int logical_line;
    const char *path;
    struct cds_rows *rows;
    int err;
};

static struct cds_file cds_g;

/* Statement-split working set for one logical line. */
static char cds_stm[CDS_LOGICAL + 16];
static size_t cds_stm_off[CDS_NST], cds_stm_len[CDS_NST], cds_stm_use;
static char cds_after[CDS_NST][8];
static int cds_cond[CDS_NST], cds_at[CDS_NST], cds_cnt, cds_incond;
static char cds_cur[CDS_LOGICAL];
static size_t cds_cur_n;

static int cds_is_ws(char c) { return c == ' ' || c == '\t'; }

static int cds_is_alnum(char c)
{
    return wca_idstart(c) || (c >= '0' && c <= '9');
}

static int cds_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* ── tiny string helpers ───────────────────────────────────────────── */

static void cds_trim(const char *s, size_t n, const char **ts, size_t *tn)
{
    size_t i = 0, j = n;
    while (i < j && cds_is_ws(s[i]))
        i++;
    while (j > i && cds_is_ws(s[j - 1]))
        j--;
    *ts = s + i;
    *tn = j - i;
}

static void cds_copy_seg(char *dst, size_t cap, const char *s, size_t n)
{
    size_t i = 0, j = n;
    while (i < j && cds_is_ws(s[i]))
        i++;
    while (j > i && cds_is_ws(s[j - 1]))
        j--;
    if (j - i >= cap)
        j = i + cap - 1;
    memcpy(dst, s + i, j - i);
    dst[j - i] = 0;
}

static void cds_ltrim_buf(char *h)
{
    size_t i = 0;
    while (cds_is_ws(h[i]))
        i++;
    if (i)
        memmove(h, h + i, strlen(h + i) + 1);
}

/* Line reader: 1 got line (newline stripped), 0 EOF, -1 read error,
 * -2 line exceeds cap. */
static int cds_getline(FILE *fp, char *buf, size_t cap, size_t *len)
{
    size_t n = 0;
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n') {
            buf[n] = 0;
            *len = n;
            return 1;
        }
        if (n + 1 >= cap)
            return -2;
        buf[n++] = (char)c;
    }
    if (ferror(fp))
        return -1;
    if (n == 0)
        return 0;
    buf[n] = 0;
    *len = n;
    return 1;
}

/* ── pre-read pass: set -e, pipefail, per-line lookahead class ─────── */

static int cds_flag_run_has_e(const char *s)
{
    size_t i = 0;
    while (wca_idstart(s[i])) {
        if (s[i] == 'e')
            return 1;
        i++;
    }
    return 0;
}

static int cds_o_errexit(const char *s)
{
    size_t i = 2;
    if (s[0] != 'o')
        return 0;
    if (!cds_is_ws(s[i]))
        return 0;
    while (cds_is_ws(s[i]))
        i++;
    return strncmp(s + i, "errexit", 7) == 0;
}

static int cds_line_sets_e(const char *line)
{
    size_t i = 0;
    while (cds_is_ws(line[i]))
        i++;
    if (strncmp(line + i, "set", 3) != 0)
        return 0;
    if (!cds_is_ws(line[i + 3]))
        return 0;
    i += 3;
    while (cds_is_ws(line[i]))
        i++;
    if (line[i] != '-')
        return 0;
    if (cds_flag_run_has_e(line + i + 1))
        return 1;
    return cds_o_errexit(line + i + 1);
}

static signed char cds_line_class(const char *line, size_t n)
{
    const char *t;
    size_t tn;
    cds_trim(line, n, &t, &tn);
    if (tn == 0 || t[0] == '#')
        return 0;
    if (tn == 1 && t[0] == '}')
        return 1;
    if (tn == 2 && t[0] == '}' && t[1] == ';')
        return 1;
    return 2;
}

static int cds_preread_line(struct cds_file *f, const char *line, size_t n)
{
    if (strstr(line, "pipefail"))
        f->seen_pipefail = 1;
    if (cds_line_sets_e(line))
        f->seen_e = 1;
    if (f->src_n >= CDS_SRCN) {
        fprintf(stderr, "%s: %s exceeds %d lines\n", k_cds_gate, f->path,
                CDS_SRCN);
        return 2;
    }
    f->src[f->src_n++] = cds_line_class(line, n);
    return 0;
}

static int cds_preread(struct cds_file *f, const char *path)
{
    char line[CDS_LINE];
    size_t len;
    int st;
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot read %s\n", k_cds_gate, path);
        return 2;
    }
    while ((st = cds_getline(fp, line, sizeof line, &len)) == 1) {
        if (cds_preread_line(f, line, len))
            st = -3;
        if (st < 0)
            break;
    }
    fclose(fp);
    if (st == -2) {
        fprintf(stderr, "%s: line of %s exceeds %d bytes\n", k_cds_gate, path,
                CDS_LINE);
        return 2;
    }
    if (st == -1) {
        fprintf(stderr, "%s: read error on %s\n", k_cds_gate, path);
        return 2;
    }
    return 0;
}

/* ── comment stripping (quote-aware, state across lines) ───────────── */

static size_t cds_esc(const char *line, size_t n, size_t i, char *out,
                      size_t *o)
{
    out[(*o)++] = line[i];
    if (i + 1 < n)
        out[(*o)++] = line[i + 1];
    return i + 2;
}

static size_t cds_strip_comment(struct cds_file *f, const char *line,
                                size_t n, char *out)
{
    size_t i = 0, o = 0;
    char prevc = 0;
    while (i < n) {
        char c = line[i];
        if (f->insq) {
            out[o++] = c;
            if (c == CDS_SQ)
                f->insq = 0;
            prevc = c;
            i++;
            continue;
        }
        if (f->indq) {
            if (c == '\\') {
                i = cds_esc(line, n, i, out, &o);
                prevc = 'x';
                continue;
            }
            out[o++] = c;
            if (c == CDS_DQ)
                f->indq = 0;
            prevc = c;
            i++;
            continue;
        }
        if (c == '\\') {
            i = cds_esc(line, n, i, out, &o);
            prevc = 'x';
            continue;
        }
        if (c == CDS_SQ) {
            f->insq = 1;
            out[o++] = c;
            prevc = c;
            i++;
            continue;
        }
        if (c == CDS_DQ) {
            f->indq = 1;
            out[o++] = c;
            prevc = c;
            i++;
            continue;
        }
        if (c == '#' && (prevc == 0 || strchr(" \t;&|(){}", prevc)))
            break;
        out[o++] = c;
        prevc = c;
        i++;
    }
    out[o] = 0;
    return o;
}

/* ── heredoc tracking ──────────────────────────────────────────────── */

/* Index of the heredoc delimiter word that follows "<<" at j, or n when no
 * delimiter starts there. Sets *tabs for "<<-". */
static size_t cds_hd_word_at(const char *raw, size_t n, size_t j, int *tabs)
{
    if (j < n && raw[j] == '-') {
        *tabs = 1;
        j++;
    }
    while (j < n && cds_is_ws(raw[j]))
        j++;
    if (j < n && (raw[j] == CDS_SQ || raw[j] == CDS_DQ))
        j++;
    if (j >= n || !wca_idstart(raw[j]))
        return n;
    return j;
}

static void cds_hd_detect(struct cds_file *f, const char *raw, size_t n)
{
    for (size_t i = 0; i + 1 < n; i++) {
        size_t j, k, L;
        int tabs = 0;
        if (raw[i] != '<' || raw[i + 1] != '<')
            continue;
        j = cds_hd_word_at(raw, n, i + 2, &tabs);
        if (j >= n)
            continue;
        k = j;
        while (k < n && cds_is_alnum(raw[k]))
            k++;
        f->hd_tabs = tabs;
        L = k - j;
        if (L >= sizeof f->hd_delim)
            L = sizeof f->hd_delim - 1;
        memcpy(f->hd_delim, raw + j, L);
        f->hd_delim[L] = 0;
        return;
    }
}

static void cds_hd_close(struct cds_file *f, const char *raw, size_t n)
{
    const char *p = raw;
    size_t L = n;
    size_t dl;
    if (f->hd_tabs) {
        while (L > 0 && *p == '\t') {
            p++;
            L--;
        }
    }
    dl = strlen(f->hd_delim);
    if (L == dl && strncmp(p, f->hd_delim, L) == 0)
        f->hd_delim[0] = 0;
}

/* ── statement accumulation ────────────────────────────────────────── */

static void cds_acc(struct cds_file *f, const char *s, size_t n)
{
    if (f->err)
        return;
    if (cds_cur_n + n > sizeof cds_cur) {
        fprintf(stderr, "%s: statement exceeds %d bytes\n", k_cds_gate,
                CDS_LOGICAL);
        f->err = 2;
        return;
    }
    memcpy(cds_cur + cds_cur_n, s, n);
    cds_cur_n += n;
}

static void cds_close_stmt(struct cds_file *f, const char *after, int line)
{
    if (f->err)
        return;
    if (cds_cnt >= CDS_NST ||
        cds_stm_use + cds_cur_n + 1 > sizeof cds_stm) {
        fprintf(stderr, "%s: statements per logical line exceed %d\n",
                k_cds_gate, CDS_NST);
        f->err = 2;
        return;
    }
    memcpy(cds_stm + cds_stm_use, cds_cur, cds_cur_n);
    cds_stm[cds_stm_use + cds_cur_n] = 0;
    cds_stm_off[cds_cnt] = cds_stm_use;
    cds_stm_len[cds_cnt] = cds_cur_n;
    snprintf(cds_after[cds_cnt], sizeof cds_after[cds_cnt], "%s", after);
    cds_cond[cds_cnt] = cds_incond;
    cds_at[cds_cnt] = line;
    cds_cnt++;
    cds_stm_use += cds_cur_n + 1;
    cds_cur_n = 0;
}

static void cds_take_quoted(struct cds_file *f, const char *t, size_t n,
                            size_t *i)
{
    char q = t[*i];
    size_t j = *i + 1;
    cds_acc(f, t + *i, 1);
    while (j < n) {
        char d = t[j];
        if (q == CDS_DQ && d == '\\') {
            cds_acc(f, t + j, 1);
            if (j + 1 < n)
                cds_acc(f, t + j + 1, 1);
            j += 2;
            continue;
        }
        cds_acc(f, t + j, 1);
        j++;
        if (d == q)
            break;
    }
    *i = j;
}

static void cds_take_dollar(struct cds_file *f, const char *t, size_t n,
                            size_t *i)
{
    size_t j = *i + 2;
    int depth = 1;
    cds_acc(f, t + *i, 2);
    while (j < n && depth > 0) {
        char d = t[j];
        if (d == '{')
            depth++;
        else if (d == '}')
            depth--;
        cds_acc(f, t + j, 1);
        j++;
    }
    *i = j;
}

static const char *const k_cds_kws[] = { "if",  "elif", "while", "until",
                                         "then", "do",   "else" };

static const char *cds_kw_at(const char *t, size_t n, size_t i, size_t *wl)
{
    for (size_t k = 0; k < sizeof k_cds_kws / sizeof k_cds_kws[0]; k++) {
        const char *w = k_cds_kws[k];
        size_t L = strlen(w);
        char nx;
        if (i + L > n || strncmp(t + i, w, L) != 0)
            continue;
        nx = i + L < n ? t[i + L] : 0;
        if (nx == 0 || cds_is_ws(nx) || strchr(";&|()", nx)) {
            *wl = L;
            return w;
        }
    }
    return NULL;
}

static int cds_kw_cond(const char *w)
{
    if (strcmp(w, "then") == 0 || strcmp(w, "do") == 0)
        return 0;
    if (strcmp(w, "else") == 0)
        return -1;
    return 1;
}

static int cds_amp_redir(const char *t, size_t n, size_t i)
{
    char prev = i > 0 ? t[i - 1] : 0;
    char next = i + 1 < n ? t[i + 1] : 0;
    return prev == '>' || prev == '<' || next == '>' || next == '-' ||
           (next >= '0' && next <= '9');
}

static int cds_sep_word(struct cds_file *f, const char *t, size_t n,
                        size_t *i, int *curline, char c)
{
    const char *w;
    size_t wl;
    if (c == '&' && cds_amp_redir(t, n, *i)) {
        cds_acc(f, &c, 1);
        (*i)++;
        return 1;
    }
    if (c == ';' || c == '&' || c == '(' || c == ')' || c == '{' ||
        c == '}') {
        char a[2];
        a[0] = c;
        a[1] = 0;
        cds_close_stmt(f, a, *curline);
        (*i)++;
        return 1;
    }
    w = cds_kw_at(t, n, *i, &wl);
    if (w) {
        int cc;
        cds_close_stmt(f, w, *curline);
        cc = cds_kw_cond(w);
        if (cc >= 0)
            cds_incond = cc;
        *i += wl;
        return 1;
    }
    return 0;
}

static int cds_sep_step(struct cds_file *f, const char *t, size_t n,
                        size_t *i, int *curline, char c)
{
    if (c == CDS_SQ || c == CDS_DQ) {
        cds_take_quoted(f, t, n, i);
        return 1;
    }
    if (c == '$' && *i + 1 < n && t[*i + 1] == '{') {
        cds_take_dollar(f, t, n, i);
        return 1;
    }
    if (c == '&' && *i + 1 < n && t[*i + 1] == '&') {
        cds_close_stmt(f, "&&", *curline);
        *i += 2;
        return 1;
    }
    if (c == '|' && *i + 1 < n && t[*i + 1] == '|') {
        cds_close_stmt(f, "||", *curline);
        *i += 2;
        return 1;
    }
    return cds_sep_word(f, t, n, i, curline, c);
}

static int cds_split_stmts(struct cds_file *f, const char *t, size_t n,
                           int base)
{
    size_t i = 0;
    int curline = base;
    cds_cnt = 0;
    cds_cur_n = 0;
    cds_stm_use = 0;
    cds_incond = 0;
    while (i < n && !f->err) {
        char c = t[i];
        if (cds_sep_step(f, t, n, &i, &curline, c))
            continue;
        cds_acc(f, &c, 1);
        i++;
    }
    if (!f->err)
        cds_close_stmt(f, "", curline);
    return cds_cnt;
}

/* ── violation rows ────────────────────────────────────────────────── */

static char *cds_row_slot(struct cds_rows *r, char prong)
{
    if (prong == 'A') {
        if (r->nneg >= CDS_ROWS)
            return NULL;
        return r->neg[r->nneg++];
    }
    if (r->nmkp >= CDS_ROWS)
        return NULL;
    return r->mkp[r->nmkp++];
}

static int cds_row_add(struct cds_rows *r, char prong, const char *path,
                       int line, const char *s, size_t sl)
{
    char ex[CDS_SEG];
    char *dst;
    const char *ts;
    size_t tl;
    cds_trim(s, sl, &ts, &tl);
    if (tl > 90) {
        memcpy(ex, ts, 87);
        memcpy(ex + 87, "...", 4);
    } else {
        memcpy(ex, ts, tl);
        ex[tl] = 0;
    }
    dst = cds_row_slot(r, prong);
    if (!dst) {
        fprintf(stderr, "%s: prong %c rows exceed %d\n", k_cds_gate, prong,
                CDS_ROWS);
        return 2;
    }
    if (ovf(snprintf(dst, CDS_ROW, "%s:%d — %s", path, line, ex), CDS_ROW)) {
        fprintf(stderr, "%s: violation row exceeds %d\n", k_cds_gate,
                CDS_ROW);
        return 2;
    }
    return 0;
}

/* ── prong B: make ... | head/tail with no pipefail ────────────────── */

static int cds_word_is(const char *h, const char *w)
{
    size_t L = strlen(w);
    return strncmp(h, w, L) == 0 && (h[L] == 0 || cds_is_ws(h[L]));
}

static int cds_strip_bang_time(char *h)
{
    size_t w = 0, k, ws = 0;
    if (h[0] == '!')
        w = 1;
    else if (strncmp(h, "time", 4) == 0)
        w = 4;
    if (!w)
        return 0;
    k = w;
    while (cds_is_ws(h[k])) {
        k++;
        ws++;
    }
    if (!ws)
        return 0;
    memmove(h, h + k, strlen(h + k) + 1);
    return 1;
}

static int cds_strip_assign(char *h)
{
    size_t i = 0, k;
    int ws = 0;
    if (!wca_idstart(h[0]))
        return 0;
    i = 1;
    while (cds_is_alnum(h[i]))
        i++;
    if (h[i] != '=')
        return 0;
    i++;
    while (h[i] && !cds_is_ws(h[i]))
        i++;
    k = i;
    while (cds_is_ws(h[i])) {
        i++;
        ws++;
    }
    if (!ws)
        return 0;
    memmove(h, h + k, strlen(h + k) + 1);
    return 1;
}

static int cds_head_is_make(char *h)
{
    static const char *const makes[] = { "make", "gmake", "$MAKE",
                                         "${MAKE}", "$(MAKE)" };
    cds_ltrim_buf(h);
    while (cds_strip_bang_time(h))
        cds_ltrim_buf(h);
    while (cds_strip_assign(h))
        cds_ltrim_buf(h);
    for (size_t i = 0; i < sizeof makes / sizeof makes[0]; i++)
        if (cds_word_is(h, makes[i]))
            return 1;
    return 0;
}

static int cds_pipe_parts(const char *s, size_t sl, char *head, char *last)
{
    long first = -1, lastp = -1;
    int np = 1;
    for (size_t i = 0; i < sl; i++) {
        if (s[i] != '|')
            continue;
        if (first < 0)
            first = (long)i;
        lastp = (long)i;
        np++;
    }
    if (np < 2)
        return 0;
    cds_copy_seg(head, CDS_SEG, s, (size_t)first);
    cds_copy_seg(last, CDS_SEG, s + lastp + 1, sl - (size_t)lastp - 1);
    return 1;
}

static int cds_check_make_pipe(struct cds_file *f, const char *s, size_t sl,
                               int line)
{
    char head[CDS_SEG], last[CDS_SEG];
    if (f->seen_pipefail)
        return 0;
    if (!cds_pipe_parts(s, sl, head, last))
        return 0;
    if (!cds_head_is_make(head))
        return 0;
    cds_ltrim_buf(last);
    if (!cds_word_is(last, "head") && !cds_word_is(last, "tail"))
        return 0;
    return cds_row_add(f->rows, 'B', f->path, line, s, sl);
}

/* ── prong A: bare ! cmd under set -e ──────────────────────────────── */

static int cds_stmt_blank(int j)
{
    const char *ts;
    size_t tn;
    cds_trim(cds_stm + cds_stm_off[j], cds_stm_len[j], &ts, &tn);
    return tn == 0;
}

static int cds_trailing_close(int i, int cnt)
{
    if (strcmp(cds_after[i], "}") == 0)
        return 1;
    for (int j = i + 1; j < cnt; j++) {
        if (!cds_stmt_blank(j))
            return 0;
        if (strcmp(cds_after[j], "}") == 0)
            return 1;
        if (cds_after[j][0] != 0 && strcmp(cds_after[j], ";") != 0)
            return 0;
    }
    return -1;
}

static int cds_next_line_closes(struct cds_file *f, int endline)
{
    for (int j = endline + 1; j <= f->src_n; j++)
        if (f->src[j - 1] != 0)
            return f->src[j - 1] == 1;
    return 0;
}

static int cds_after_is_or(int i)
{
    return strcmp(cds_after[i], "&&") == 0 || strcmp(cds_after[i], "||") == 0;
}

static int cds_prong_a(struct cds_file *f, const char *s, size_t sl, int i,
                       int cnt, int endline)
{
    const char *ts;
    size_t tl, j;
    int tc;
    cds_trim(s, sl, &ts, &tl);
    if (tl == 0 || ts[0] != '!')
        return 0;
    j = 1;
    while (j < tl && cds_is_ws(ts[j]))
        j++;
    if (j >= tl)
        return 0;
    if (ts[j] == '=' || ts[j] == '-')
        return 0;
    if (cds_cond[i])
        return 0;
    if (cds_after_is_or(i))
        return 0;
    tc = cds_trailing_close(i, cnt);
    if (tc == 1)
        return 0;
    if (tc == -1 && cds_next_line_closes(f, endline))
        return 0;
    return cds_row_add(f->rows, 'A', f->path, cds_at[i], ts, tl);
}

static int cds_check_statements(struct cds_file *f, const char *t, size_t n,
                                int base, int endline)
{
    int cnt = cds_split_stmts(f, t, n, base);
    int i;
    if (f->err)
        return f->err;
    for (i = 0; i < cnt; i++) {
        const char *s = cds_stm + cds_stm_off[i];
        size_t sl = cds_stm_len[i];
        int rc = cds_check_make_pipe(f, s, sl, cds_at[i]);
        if (rc)
            return rc;
        if (!f->seen_e)
            continue;
        rc = cds_prong_a(f, s, sl, i, cnt, endline);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── logical-line assembly and the per-line driver ─────────────────── */

static int cds_has_nonspace(const char *s)
{
    for (size_t i = 0; s[i]; i++)
        if (!cds_is_ws(s[i]))
            return 1;
    return 0;
}

static void cds_join(const char *out, char *joined)
{
    size_t L = strlen(out), k;
    strcpy(joined, out);
    k = L;
    while (k > 0 && cds_is_ws(joined[k - 1]))
        k--;
    if (k > 0 && joined[k - 1] == '\\') {
        joined[k - 1] = ' ';
        joined[k] = 0;
    }
}

static int cds_continues(const char *t)
{
    size_t n = strlen(t);
    while (n > 0 && cds_is_ws(t[n - 1]))
        n--;
    if (n == 0)
        return 0;
    if (t[n - 1] == '\\')
        return 1;
    if (n >= 2 && t[n - 1] == '&' && t[n - 2] == '&')
        return 1;
    if (n >= 2 && t[n - 1] == '|' && t[n - 2] == '|')
        return 1;
    return t[n - 1] == '|';
}

static int cds_append_logical(struct cds_file *f, const char *joined)
{
    size_t jl = strlen(joined);
    if (f->logical_len + 1 + jl + 1 > sizeof f->logical) {
        fprintf(stderr, "%s: logical line exceeds %d bytes\n", k_cds_gate,
                CDS_LOGICAL);
        return 2;
    }
    f->logical[f->logical_len] = ' ';
    memcpy(f->logical + f->logical_len + 1, joined, jl + 1);
    f->logical_len += 1 + jl;
    return 0;
}

static int cds_flush_logical(struct cds_file *f, int endline)
{
    int rc;
    if (f->logical_len == 0) {
        f->logical_line = 0;
        return 0;
    }
    rc = cds_check_statements(f, f->logical, f->logical_len,
                              f->logical_line, endline);
    f->logical_len = 0;
    f->logical[0] = 0;
    f->logical_line = 0;
    return rc;
}

static int cds_scan_line(struct cds_file *f, const char *raw, size_t n,
                         int fnr, char *out, char *joined)
{
    size_t on;
    if (f->hd_delim[0]) {
        cds_hd_close(f, raw, n);
        return 0;
    }
    on = cds_strip_comment(f, raw, n, out);
    if (f->logical_line == 0 && on > 0 && cds_has_nonspace(out))
        f->logical_line = fnr;
    cds_join(out, joined);
    if (cds_append_logical(f, joined))
        return 2;
    cds_hd_detect(f, raw, n);
    if (f->insq || f->indq)
        return 0;
    if (cds_continues(out))
        return 0;
    return cds_flush_logical(f, fnr);
}

static int cds_scan_pass(struct cds_file *f, const char *path)
{
    char raw[CDS_LINE], out[CDS_LINE], joined[CDS_LINE];
    size_t len;
    int st, fnr = 0;
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "%s: cannot read %s\n", k_cds_gate, path);
        return 2;
    }
    while ((st = cds_getline(fp, raw, sizeof raw, &len)) == 1) {
        int rc;
        fnr++;
        rc = cds_scan_line(f, raw, len, fnr, out, joined);
        if (rc) {
            fclose(fp);
            return rc;
        }
    }
    fclose(fp);
    if (st == -2) {
        fprintf(stderr, "%s: line of %s exceeds %d bytes\n", k_cds_gate,
                path, CDS_LINE);
        return 2;
    }
    if (st == -1) {
        fprintf(stderr, "%s: read error on %s\n", k_cds_gate, path);
        return 2;
    }
    return 0;
}

int cds_scan_file(const char *path, struct cds_rows *r)
{
    struct cds_file *f = &cds_g;
    int rc;
    memset(f, 0, sizeof *f);
    f->path = path;
    f->rows = r;
    rc = cds_preread(f, path);
    if (rc)
        return rc;
    rc = cds_scan_pass(f, path);
    if (rc)
        return rc;
    return cds_flush_logical(f, f->src_n);
}

int cds_scan_list(char files[][CDS_PATH], size_t n, struct cds_rows *r)
{
    size_t i;
    memset(r, 0, sizeof *r);
    for (i = 0; i < n; i++) {
        int rc = cds_scan_file(files[i], r);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── scan-set collection ───────────────────────────────────────────── */

static int cds_floor_env(void)
{
    const char *v = getenv("ZCL_DISCARD_GATE_FILE_FLOOR");
    if (!v || !v[0])
        return -1;
    return atoi(v);
}

static int cds_store_path(char out[][CDS_PATH], size_t cap, size_t *n,
                          const char *p)
{
    if (strlen(p) >= CDS_PATH) {
        fprintf(stderr, "%s: path exceeds %d bytes: %s\n", k_cds_gate,
                CDS_PATH, p);
        return 2;
    }
    if (*n >= cap) {
        fprintf(stderr, "%s: file list exceeds %zu\n", k_cds_gate, cap);
        return 2;
    }
    strcpy(out[*n], p);
    (*n)++;
    return 0;
}

static int cds_glob_dir(const char *dir, const char *pat,
                        char out[][CDS_PATH], size_t cap, size_t *n)
{
    static char names[CDS_NAMES][CDS_NAMELEN];
    size_t nn = 0, i;
    DIR *d = opendir(dir);
    struct dirent *e;
    *n = 0;
    if (!d)
        return 0;
    while ((e = readdir(d)) != NULL) {
        if (fnmatch(pat, e->d_name, 0) != 0)
            continue;
        if (strlen(e->d_name) >= CDS_NAMELEN) {
            closedir(d);
            fprintf(stderr, "%s: glob entry exceeds %d bytes\n", k_cds_gate,
                    CDS_NAMELEN);
            return 2;
        }
        if (nn >= CDS_NAMES) {
            closedir(d);
            fprintf(stderr, "%s: glob matches exceed %d\n", k_cds_gate,
                    CDS_NAMES);
            return 2;
        }
        strcpy(names[nn++], e->d_name);
    }
    closedir(d);
    qsort(names, nn, CDS_NAMELEN, cds_cmp);
    for (i = 0; i < nn; i++) {
        char full[CDS_PATH];
        if (ovf(snprintf(full, sizeof full, "%s/%s", dir, names[i]),
                sizeof full))
            return 2;
        if (cds_store_path(out, cap, n, full))
            return 2;
    }
    return 0;
}

static int cds_collect_glob(char out[][CDS_PATH], size_t cap, size_t *n)
{
    const char *g = getenv("ZCL_DISCARD_GATE_SCAN_GLOB");
    char dir[CDS_PATH], pat[CDS_PATH];
    const char *sl;
    size_t dl;
    *n = 0;
    if (!g || !g[0])
        return 0;
    sl = strrchr(g, '/');
    if (!sl) {
        if (ovf(snprintf(dir, sizeof dir, "."), sizeof dir) ||
            ovf(snprintf(pat, sizeof pat, "%s", g), sizeof pat))
            return 2;
        return cds_glob_dir(dir, pat, out, cap, n);
    }
    dl = (size_t)(sl - g);
    if (dl == 0) {
        strcpy(dir, "/");
    } else {
        if (dl >= sizeof dir) {
            fprintf(stderr, "%s: glob directory exceeds %d bytes\n",
                    k_cds_gate, CDS_PATH);
            return 2;
        }
        memcpy(dir, g, dl);
        dir[dl] = 0;
    }
    if (ovf(snprintf(pat, sizeof pat, "%s", sl + 1), sizeof pat))
        return 2;
    return cds_glob_dir(dir, pat, out, cap, n);
}

static void cds_git_child(int wfd, int rfd)
{
    char *av[4];
    close(rfd);
    dup2(wfd, STDOUT_FILENO);
    close(wfd);
    av[0] = (char *)"git";
    av[1] = (char *)"ls-files";
    av[2] = (char *)"*.sh";
    av[3] = NULL;
    execvp("git", av);
    _exit(127);
}

static int cds_git_store(char out[][CDS_PATH], size_t cap, size_t *n,
                         FILE *fp)
{
    char line[CDS_PATH];
    size_t len;
    int st;
    while ((st = cds_getline(fp, line, sizeof line, &len)) == 1) {
        struct stat sb;
        if (stat(line, &sb) != 0 || !S_ISREG(sb.st_mode))
            continue;
        if (cds_store_path(out, cap, n, line))
            return 2;
    }
    if (st == -2) {
        fprintf(stderr, "%s: git path exceeds %d bytes\n", k_cds_gate,
                CDS_PATH);
        return 2;
    }
    if (st == -1) {
        fprintf(stderr, "%s: read error from git ls-files\n", k_cds_gate);
        return 2;
    }
    return 0;
}

static int cds_collect_git(char out[][CDS_PATH], size_t cap, size_t *n)
{
    int pipefd[2];
    pid_t pid;
    FILE *fp;
    int status = 0;
    *n = 0;
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "%s: pipe failed\n", k_cds_gate);
        return 2;
    }
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed\n", k_cds_gate);
        close(pipefd[0]);
        close(pipefd[1]);
        return 2;
    }
    if (pid == 0)
        cds_git_child(pipefd[1], pipefd[0]);
    close(pipefd[1]);
    fp = fdopen(pipefd[0], "r");
    if (!fp) {
        fprintf(stderr, "%s: fdopen failed\n", k_cds_gate);
        close(pipefd[0]);
        return 2;
    }
    status = cds_git_store(out, cap, n, fp);
    fclose(fp);
    if (waitpid(pid, &status, 0) < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        *n = 0;
        return 0;
    }
    return status;
}

int cds_files_collect(char out[][CDS_PATH], size_t cap, size_t *n,
                      int *floor_out)
{
    const char *g = getenv("ZCL_DISCARD_GATE_SCAN_GLOB");
    int fl = cds_floor_env();
    int rc;
    if (g && g[0]) {
        rc = cds_collect_glob(out, cap, n);
        if (fl < 0)
            fl = 1;
    } else {
        rc = cds_collect_git(out, cap, n);
        if (fl < 0)
            fl = 200;
    }
    if (rc)
        return rc;
    *floor_out = fl;
    if (*n < (size_t)fl) {
        fprintf(stderr,
                "[%s] FATAL — scanned %zu file(s), expected at least %d.\n"
                "        The scan set (git ls-files '*.sh') moved or emptied; refusing to\n"
                "        report clean off a broken scan.\n",
                k_cds_gate, *n, fl);
        return 2;
    }
    return 0;
}

/* ── report ────────────────────────────────────────────────────────── */

static void cds_print_neg(struct cds_rows *r, FILE *out)
{
    int i;
    qsort(r->neg, (size_t)r->nneg, CDS_ROW, cds_cmp);
    fprintf(out,
            "\n[%s] %d bare `! cmd` statement(s) under `set -e` — each one is\n"
            "        a DECORATIVE assertion that cannot fail the script:\n",
            k_cds_gate, r->nneg);
    for (i = 0; i < r->nneg; i++)
        fprintf(out, "  %s\n", r->neg[i]);
    fprintf(out,
            "\n"
            "  Bash does not exit for a failing command whose return value is being\n"
            "  inverted with '!', and the ERR trap is exempt for the same reason — so\n"
            "  'set -E; trap ... ERR' does not rescue it either. Whatever that command\n"
            "  returns, the script continues to its PASS line.\n"
            "\n"
            "  Fix: make the negative assertion exit for itself.\n"
            "      refute() { if \"$@\"; then printf 'expected non-zero from: %%s\\n' \"$*\" >&2; exit 1; fi; }\n"
            "      refute verify_epoch \"$a\" \"$b\" \"$a\"\n"
            "  Reference spelling: tools/ship.sh --selftest.\n"
            "  If the status really is consumed, say so in the syntax — 'if ! cmd; then',\n"
            "  '! cmd || die ...', '! cmd && ...' are all fine and none of them count.\n");
}

static void cds_print_mk(struct cds_rows *r, FILE *out)
{
    int i;
    qsort(r->mkp, (size_t)r->nmkp, CDS_ROW, cds_cmp);
    fprintf(out,
            "\n[%s] %d `make ... | head/tail` pipeline(s) in a script that never\n"
            "        sets pipefail — a FAILED build reports 0 there:\n",
            k_cds_gate, r->nmkp);
    for (i = 0; i < r->nmkp; i++)
        fprintf(out, "  %s\n", r->mkp[i]);
    fprintf(out,
            "\n"
            "  Without pipefail a pipeline reports the LAST stage's status, and\n"
            "  head/tail succeed on any input. The build log looks right and the\n"
            "  next step runs against a binary that was never relinked.\n"
            "\n"
            "  Fix — keep the status. Any of:\n"
            "      make <goal> > build.log 2>&1 || { tail -20 build.log; exit 1; }\n"
            "      set -o pipefail   # then the pipeline reports make's status\n"
            "      make <goal> 2>&1 | tail -20; rc=${PIPESTATUS[0]}\n");
}

int cds_report(struct cds_rows *r, size_t nfiles, FILE *out)
{
    int fail = 0;
    if (r->nneg > 0) {
        cds_print_neg(r, out);
        fail = 1;
    }
    if (r->nmkp > 0) {
        cds_print_mk(r, out);
        fail = 1;
    }
    if (fail)
        return 1;
    fprintf(out,
            "[%s] PASS (%zu *.sh files scanned; no bare `! cmd` assertion under "
            "set -e, no pipefail-less `make | head/tail`; no allow-comment "
            "mechanism exists)\n",
            k_cds_gate, nfiles);
    return 0;
}

int check_discarded_status_run(int argc, char **argv)
{
    static char files[CDS_FILES][CDS_PATH];
    static struct cds_rows rows;
    size_t n = 0;
    int floor = 0;
    (void)argc;
    (void)argv;
    if (cds_files_collect(files, CDS_FILES, &n, &floor))
        return 2;
    if (cds_scan_list(files, n, &rows))
        return 2;
    return cds_report(&rows, n, stdout);
}
