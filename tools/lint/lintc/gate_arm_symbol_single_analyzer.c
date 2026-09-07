/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * check-arm-symbol-single family — the analyzer. A direct, line-oriented
 * port of the original shell gate's embedded awk program (write_analyzer()
 * in tools/lint/check_arm_symbol_single.sh): tracks brace depth (bdepth)
 * and paren depth (pdepth) through one file to find every top-level
 * function DEFINITION (a signature followed, eventually, by "{"), and
 * classifies each one's linkage (static vs. non-static) and whether its
 * "name" is really a SCREAMING_SNAKE_CASE macro, __attribute__, or
 * __declspec token that must not be mistaken for a function name. Split
 * into small single-purpose helpers (one per awk state transition) to
 * keep every function under the complexity cap.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_arm_symbol_single_priv.h"

enum { ASA_LINE = 8192, ASA_SIG = 8192, ASA_NAME = 256, ASA_HINT = 512 };

enum asa_state { ASA_IDLE, ASA_SKIPPING, ASA_COLLECTING };

struct asa_ctx {
    enum asa_state state;
    int bdepth, pdepth;
    int incomment, indefine;
    char prev_idle[ASA_LINE];
    char candidate_name[ASA_NAME];
    char static_hint[ASA_HINT];
    char sig[ASA_SIG];
    int start_line;
};

static void asa_reset(struct asa_ctx *c)
{
    c->state = ASA_IDLE;
    c->bdepth = 0;
    c->pdepth = 0;
    c->incomment = 0;
    c->indefine = 0;
    c->prev_idle[0] = '\0';
    c->candidate_name[0] = '\0';
    c->static_hint[0] = '\0';
    c->sig[0] = '\0';
    c->start_line = 0;
}

static void asa_reset_sig(struct asa_ctx *c)
{
    c->state = ASA_IDLE;
    c->sig[0] = '\0';
    c->pdepth = 0;
    c->candidate_name[0] = '\0';
}

/* ── literal stripping: gsub of a "..." -> `""`, '...' -> `CH` ──────────── */

/* First unescaped occurrence of `quote` at or after `start`; awk's own
 * ERE alternation ([^quote\]|\\.)* necessarily stops at it. */
static int asa_find_close(const char *line, size_t start, char quote,
                          size_t *close_idx)
{
    size_t n = strlen(line);
    size_t j = start;
    while (j < n) {
        if (line[j] == '\\' && j + 1 < n) { j += 2; continue; }
        if (line[j] == quote) { *close_idx = j; return 1; }
        j++;
    }
    return 0;
}

static void asa_strip_literals(char *line)
{
    char out[ASA_LINE];
    size_t oi = 0, n = strlen(line), i = 0;
    while (i < n && oi + 1 < sizeof out) {
        size_t close;
        if (line[i] == '"' && asa_find_close(line, i + 1, '"', &close)) {
            out[oi++] = '"';
            if (oi + 1 < sizeof out) out[oi++] = '"';
            i = close + 1;
            continue;
        }
        if (line[i] == '\'' && asa_find_close(line, i + 1, '\'', &close)) {
            if (oi + 2 < sizeof out) { out[oi++] = 'C'; out[oi++] = 'H'; }
            i = close + 1;
            continue;
        }
        out[oi++] = line[i++];
    }
    out[oi] = '\0';
    snprintf(line, ASA_LINE, "%s", out);
}

/* ── trimming / predicates ──────────────────────────────────────────────── */

static void asa_trim(const char *in, char *out, size_t cap)
{
    const char *p = in;
    while (*p == ' ' || *p == '\t')
        p++;
    size_t n = strlen(p);
    while (n && (p[n - 1] == ' ' || p[n - 1] == '\t'))
        n--;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
}

static int asa_ends_with_semi(const char *line)
{
    size_t n = strlen(line);
    while (n && (line[n - 1] == ' ' || line[n - 1] == '\t'))
        n--;
    return n > 0 && line[n - 1] == ';';
}

static int asa_ends_with_bslash(const char *trimmed)
{
    size_t n = strlen(trimmed);
    while (n && (trimmed[n - 1] == ' ' || trimmed[n - 1] == '\t'))
        n--;
    return n > 0 && trimmed[n - 1] == '\\';
}

static const char *const k_asa_kw[] = {
    "if", "for", "while", "switch", "do", "else", "return", "sizeof",
    "defined", "static_assert", "_Static_assert",
};
enum { ASA_NKW = 11 };

static int asa_is_keyword(const char *s)
{
    for (int i = 0; i < ASA_NKW; i++)
        if (strcmp(s, k_asa_kw[i]) == 0)
            return 1;
    return 0;
}

static int asa_is_screaming(const char *s)
{
    if (!(isupper((unsigned char)s[0]) || s[0] == '_'))
        return 0;
    for (const char *p = s; *p; p++)
        if (!(isupper((unsigned char)*p) || isdigit((unsigned char)*p)
              || *p == '_'))
            return 0;
    return 1;
}

/* Whitespace-boundary search for the literal token "static" anywhere in
 * `hint` — the shell's `(^|[^A-Za-z0-9_])static([^A-Za-z0-9_]|$)`. */
static int asa_hint_has_static(const char *hint)
{
    const char *p = hint;
    while ((p = strstr(p, "static")) != NULL) {
        int before_ok = (p == hint)
            || !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
        char after = p[6];
        int after_ok = after == '\0'
            || !(isalnum((unsigned char)after) || after == '_');
        if (before_ok && after_ok)
            return 1;
        p += 6;
    }
    return 0;
}

static void asa_collapse_ws(const char *in, char *out, size_t cap)
{
    size_t oi = 0;
    const char *p = in;
    while (*p == ' ' || *p == '\t' || *p == '\n')
        p++;
    int last_space = 0;
    for (; *p && oi + 1 < cap; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n') {
            if (!last_space) {
                out[oi++] = ' ';
                last_space = 1;
            }
        } else {
            out[oi++] = *p;
            last_space = 0;
        }
    }
    while (oi > 0 && out[oi - 1] == ' ')
        oi--;
    out[oi] = '\0';
}

static int asa_process_candidate(const char *file, struct asa_ctx *c,
                                 asy_emit_fn emit, void *ctx)
{
    char sigfull[ASA_SIG];
    asa_collapse_ws(c->sig, sigfull, sizeof sigfull);
    if (strncmp(sigfull, "typedef", 7) == 0
        || strncmp(sigfull, "struct ", 7) == 0
        || strncmp(sigfull, "union ", 6) == 0
        || strncmp(sigfull, "enum ", 5) == 0)
        return 0;
    if (c->candidate_name[0] == '\0')
        return 0;
    if (asa_is_keyword(c->candidate_name))
        return 0;
    int is_static = asa_hint_has_static(c->static_hint) ? 1 : 0;
    return emit(file, ctx, c->candidate_name, c->start_line, is_static);
}

/* Count `{`, `}`, `(`, `)` in `line`. */
static void asa_count(const char *line, int *nb, int *ne, int *op, int *cl)
{
    *nb = *ne = *op = *cl = 0;
    for (const char *p = line; *p; p++) {
        if (*p == '{') (*nb)++;
        else if (*p == '}') (*ne)++;
        else if (*p == '(') (*op)++;
        else if (*p == ')') (*cl)++;
    }
}

/* ── comment stripping / directive lines ────────────────────────────────── */

/* Strips string/char literals and the trailing "//" comment, then resolves
 * any block comment (persisting across calls via c->incomment). Returns 1
 * when the whole (rest of the) line is inside an unclosed block comment —
 * nothing left to scan this call. */
static int asa_strip_line_text(struct asa_ctx *c, char *line)
{
    asa_strip_literals(line);
    char *ss = strstr(line, "//");
    if (ss)
        *ss = '\0';
    if (c->incomment) {
        char *close = strstr(line, "*/");
        if (close) {
            memmove(line, close + 2, strlen(close + 2) + 1);
            c->incomment = 0;
        } else {
            return 1;
        }
    }
    for (;;) {
        char *open = strstr(line, "/*");
        if (!open)
            break;
        char *close = strstr(open, "*/");
        if (close) {
            memmove(open, close + 2, strlen(close + 2) + 1);
        } else {
            *open = '\0';
            c->incomment = 1;
            break;
        }
    }
    return 0;
}

/* `#...` lines and `#define` backslash continuations: fully handled here,
 * never reach signature scanning. Returns 1 when consumed. */
static int asa_handle_directive(struct asa_ctx *c, const char *trimmed)
{
    if (c->indefine) {
        if (!asa_ends_with_bslash(trimmed))
            c->indefine = 0;
        return 1;
    }
    if (trimmed[0] == '#') {
        if (asa_ends_with_bslash(trimmed))
            c->indefine = 1;
        return 1;
    }
    return 0;
}

/* ── idle state ──────────────────────────────────────────────────────────── */

static void asa_idle_noparen(struct asa_ctx *c, const char *trimmed, int nb,
                             int ne)
{
    if (nb > 0 || ne > 0) {
        c->bdepth += nb - ne;
        if (c->bdepth < 0)
            c->bdepth = 0;
    }
    if (trimmed[0] != '\0')
        snprintf(c->prev_idle, sizeof c->prev_idle, "%s", trimmed);
}

/* [A-Za-z_][A-Za-z0-9_]*[ \t]*$ anchored at the end of `head`. */
static void asa_extract_ident(const char *head, char *ident, size_t cap)
{
    ident[0] = '\0';
    size_t hl = strlen(head);
    size_t e = hl;
    while (e > 0 && (head[e - 1] == ' ' || head[e - 1] == '\t'))
        e--;
    size_t s = e;
    while (s > 0 && (isalnum((unsigned char)head[s - 1]) || head[s - 1] == '_'))
        s--;
    if (s < e && (isalpha((unsigned char)head[s]) || head[s] == '_')) {
        size_t n = e - s;
        if (n >= cap)
            n = cap - 1;
        memcpy(ident, head + s, n);
        ident[n] = '\0';
    }
}

/* SCREAMING_SNAKE_CASE, __attribute__, __declspec — "not a function name". */
static int asa_classify_ident(const char *ident)
{
    return ident[0] != '\0'
        && (asa_is_screaming(ident) || strcmp(ident, "__attribute__") == 0
            || strcmp(ident, "__declspec") == 0);
}

/* Shared tail of "a complete signature was just recognized, parens already
 * balanced": either a single-line definition (emit + enter the body), a
 * bare prototype (";", not a definition), or K&R-style with the brace
 * still to come (stay/enter COLLECTING). Used both when parens balance on
 * the FIRST line of a signature and when COLLECTING's parens finally
 * balance on a later line. */
static int asa_close_signature(const char *file, struct asa_ctx *c, int nb,
                               int ne, const char *line, asy_emit_fn emit,
                               void *ctx)
{
    if (nb >= 1) {
        int rc = asa_process_candidate(file, c, emit, ctx);
        c->bdepth = nb - ne;
        if (c->bdepth < 0)
            c->bdepth = 0;
        asa_reset_sig(c);
        return rc;
    }
    if (asa_ends_with_semi(line)) {
        asa_reset_sig(c);
        return 0;
    }
    c->state = ASA_COLLECTING;
    c->pdepth = 0;
    return 0;
}

static int asa_idle_withparen(const char *file, struct asa_ctx *c, int fnr,
                              char *line, int nb, int ne, int op, int cl,
                              asy_emit_fn emit, void *ctx)
{
    char *paren = strchr(line, '(');
    size_t headlen = (size_t)(paren - line);
    char head[ASA_LINE];
    if (headlen >= sizeof head)
        headlen = sizeof head - 1;
    memcpy(head, line, headlen);
    head[headlen] = '\0';

    char ident[ASA_NAME];
    asa_extract_ident(head, ident, sizeof ident);
    int is_macro = asa_classify_ident(ident);
    c->pdepth = op - cl;
    if (is_macro || ident[0] == '\0') {
        c->state = ASA_SKIPPING;
        if (c->pdepth <= 0) {
            c->state = ASA_IDLE;
            c->pdepth = 0;
        }
        c->prev_idle[0] = '\0';
        return 0;
    }
    snprintf(c->sig, sizeof c->sig, "%s", line);
    snprintf(c->candidate_name, sizeof c->candidate_name, "%s", ident);
    snprintf(c->static_hint, sizeof c->static_hint, "%s %s", c->prev_idle,
            head);
    c->start_line = fnr;
    c->prev_idle[0] = '\0';
    if (c->pdepth > 0) {
        c->state = ASA_COLLECTING;
        return 0;
    }
    return asa_close_signature(file, c, nb, ne, line, emit, ctx);
}

/* ── skipping / collecting states ───────────────────────────────────────── */

static void asa_state_skipping(struct asa_ctx *c, int op, int cl)
{
    c->pdepth += op - cl;
    if (c->pdepth <= 0) {
        c->state = ASA_IDLE;
        c->pdepth = 0;
    }
}

static int asa_state_collecting(const char *file, struct asa_ctx *c,
                                const char *line, int nb, int ne, int op,
                                int cl, asy_emit_fn emit, void *ctx)
{
    size_t used = strlen(c->sig);
    snprintf(c->sig + used, sizeof c->sig - used, " %s", line);
    c->pdepth += op - cl;
    if (c->pdepth <= 0)
        return asa_close_signature(file, c, nb, ne, line, emit, ctx);
    return 0;
}

/* ── one line, dispatched by state ─────────────────────────────────────── */

static int asa_process_line(const char *file, struct asa_ctx *c, int fnr,
                            char *line, asy_emit_fn emit, void *ctx)
{
    if (asa_strip_line_text(c, line))
        return 0;
    char trimmed[ASA_LINE];
    asa_trim(line, trimmed, sizeof trimmed);
    if (asa_handle_directive(c, trimmed))
        return 0;

    int nb, ne, op, cl;
    asa_count(line, &nb, &ne, &op, &cl);

    if (c->bdepth > 0) {
        c->bdepth += nb - ne;
        if (c->bdepth < 0)
            c->bdepth = 0;
        return 0;
    }
    if (c->state == ASA_IDLE) {
        if (op == 0) {
            asa_idle_noparen(c, trimmed, nb, ne);
            return 0;
        }
        return asa_idle_withparen(file, c, fnr, line, nb, ne, op, cl, emit,
                                  ctx);
    }
    if (c->state == ASA_SKIPPING) {
        asa_state_skipping(c, op, cl);
        return 0;
    }
    if (c->state == ASA_COLLECTING)
        return asa_state_collecting(file, c, line, nb, ne, op, cl, emit, ctx);
    return 0;
}

int asy_analyze_file(const char *path, asy_emit_fn emit, void *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        /* A file present in the scan set (git index or filesystem walk)
         * that cannot be opened is a hole in the scan, not a clean file:
         * report UNPROVEN naming the path rather than silently skipping
         * it (skipping would let a locked-down file hide a real
         * duplicate forever). */
        fprintf(stderr,
                "check_arm_symbol_single: UNPROVEN — cannot read %s: %s\n",
                path, strerror(errno));
        return 2;
    }
    struct asa_ctx c;
    asa_reset(&c);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int fnr = 0;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        fnr++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        char buf[ASA_LINE];
        snprintf(buf, sizeof buf, "%s", line);
        rc = asa_process_line(path, &c, fnr, buf, emit, ctx);
    }
    free(line);
    fclose(f);
    return rc;
}
