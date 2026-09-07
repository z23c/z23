/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the awk row reader of the check-fleet-airship-rules family
 * (the 700-line family ceiling split) — the byte-parity reproduction of
 * the shell gate's row scanner plus the growable string list and the
 * TAB-field accessors every other family file uses. The gate body lives
 * in gate_fleet_airship_rules.c, the scan checks in
 * gate_fleet_airship_rules_rules.c, and the planted-table selftest in
 * gate_fleet_airship_rules_selftest.c; the files share their internals
 * through gate_fleet_airship_rules_priv.h. The parity contract for this
 * reader is documented in gate_fleet_airship_rules.c's header.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_fleet_airship_rules_priv.h"

static const char k_gate[] = "check_fleet_airship_rules";

int far_compile(struct far_rx *rx)
{
    int cr = reg_fail(&rx->start, regcomp(&rx->start,
        "^AIRSHIP_(FACT|ASSET|RULE)\\(", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->close, regcomp(&rx->close, "\\)[[:space:]]*$",
                                          REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->quote, regcomp(&rx->quote, "\"([^\"\\\\]|\\\\.)*\"",
                                          REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->name, regcomp(&rx->name, "^[a-z][a-z0-9_]{0,30}$",
                                         REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&rx->per, regcomp(&rx->per, "^(0|[1-9][0-9]*)$",
                                        REG_EXTENDED));
    return cr;
}

void far_drop(struct far_rx *rx)
{
    regfree(&rx->start);
    regfree(&rx->close);
    regfree(&rx->quote);
    regfree(&rx->name);
    regfree(&rx->per);
}

/* ── growable string list ─────────────────────────────────────────────── */

void far_free(struct far_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static int far_push(struct far_list *l, char *s)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 32;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv) {
            free(s);
            return die("z23-lint: out of memory\n", "");
        }
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n++] = s;
    return 0;
}

int far_add(struct far_list *l, const char *s)
{
    size_t n = strlen(s);
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, s, n + 1);
    return far_push(l, copy);
}

int far_addf(struct far_list *l, const char *fmt, const char *a,
             const char *b, const char *c, const char *d,
             const char *e)
{
    int need = snprintf(NULL, 0, fmt, a, b, c, d, e);
    if (need < 0)
        return die("z23-lint: write failed\n", "");
    char *s = malloc((size_t)need + 1); // raw-alloc-ok:lint-runtime
    if (!s)
        return die("z23-lint: out of memory\n", "");
    if (snprintf(s, (size_t)need + 1, fmt, a, b, c, d, e) != need) {
        free(s);
        return die("z23-lint: write failed\n", "");
    }
    return far_push(l, s);
}

/* ── row field access (TAB-split semantics from the shell) ────────────── */

int far_row_is(const char *row, const char *tag)
{
    size_t n = strlen(tag);
    return strncmp(row, tag, n) == 0 && row[n] == '\t';
}

/* The 1-based nth TAB field copied out; a missing field is empty. */
int far_field(const char *row, int n, char *out, size_t cap)
{
    const char *p = row;
    for (int i = 1; i < n; i++) {
        const char *t = strchr(p, '\t');
        if (!t) {
            out[0] = '\0';
            return 0;
        }
        p = t + 1;
    }
    const char *t = strchr(p, '\t');
    size_t len = t ? (size_t)(t - p) : strlen(p);
    if (len >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* read -r's last-variable remainder: everything past the nth TAB, with
 * leading and trailing TABs stripped. */
int far_read_tail(const char *row, int tabs, char *out, size_t cap)
{
    const char *p = row;
    for (int i = 0; i < tabs; i++) {
        const char *t = strchr(p, '\t');
        if (!t) {
            out[0] = '\0';
            return 0;
        }
        p = t + 1;
    }
    while (*p == '\t')
        p++;
    size_t len = strlen(p);
    while (len && p[len - 1] == '\t')
        len--;
    if (len >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* ── the awk row reader ───────────────────────────────────────────────── */

/* Lift every "..."-with-escapes span out of rest (in place), keeping the
 * inner text of the first three verbatim in p[]. *n counts all of them. */
static int far_take_quoted(struct far_rx *rx, char *rest, char *p[3], int *n)
{
    *n = 0;
    regmatch_t m[1];
    while (regexec(&rx->quote, rest, 1, m, 0) == 0) {
        size_t so = (size_t)m[0].rm_so, eo = (size_t)m[0].rm_eo;
        if (*n < 3) {
            size_t len = eo - so - 2;
            p[*n] = malloc(len + 1); // raw-alloc-ok:lint-runtime
            if (!p[*n])
                return die("z23-lint: out of memory\n", "");
            memcpy(p[*n], rest + so + 1, len);
            p[*n][len] = '\0';
        }
        (*n)++;
        memmove(rest + so, rest + eo, strlen(rest + eo) + 1);
    }
    return 0;
}

/* sub(/^[^(]*\(/, "", rest) then sub(/\)[ \t]*$/, "", rest): cut through
 * the first `(`, then at the leftmost `)` followed only by blanks. */
static void far_strip_parens(char *rest)
{
    char *op = strchr(rest, '(');
    if (op)
        memmove(rest, op + 1, strlen(op + 1) + 1);
    for (size_t i = 0; rest[i]; i++) {
        if (rest[i] != ')')
            continue;
        size_t j = i + 1;
        while (rest[j] == ' ' || rest[j] == '\t')
            j++;
        if (rest[j] == '\0') {
            rest[i] = '\0';
            return;
        }
    }
}

/* gsub(/[ \t]/, "", field) — every blank gone, not just the edges. */
static void far_gsub_blanks(char *s)
{
    char *w = s;
    for (; *s; s++)
        if (*s != ' ' && *s != '\t')
            *w++ = *s;
    *w = '\0';
}

/* awk split(rest, f, ","): empty rest is zero fields; f[] holds the first
 * six (the gate never reads past the fourth). rest is rewritten in place. */
static void far_split(char *rest, char *f[6], int *m)
{
    if (!rest[0]) {
        *m = 0;
        return;
    }
    int n = 1;
    for (const char *p = rest; *p; p++)
        if (*p == ',')
            n++;
    *m = n;
    int i = 0;
    f[i++] = rest;
    for (char *p = rest; *p; p++) {
        if (*p != ',')
            continue;
        *p = '\0';
        if (i < 6)
            f[i] = p + 1;
        i++;
    }
    for (int k = 0; k < i && k < 6; k++)
        far_gsub_blanks(f[k]);
}

static int far_emit_typed(const char *tag, char *rest, char *p[3],
                          struct far_list *rows)
{
    char *f[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
    int m = 0;
    far_split(rest, f, &m);
    if (strcmp(tag, "FACT") == 0 && m == 2)
        return far_addf(rows, "FACT\t%s\t%s", p[0], f[1], "", "", "");
    if (strcmp(tag, "RULE") == 0 && m == 5)
        return far_addf(rows, "RULE\t%s\t%s\t%s\t%s\t%s", p[0], p[1],
                        f[2], f[3], p[2]);
    return far_addf(rows, "MALFORMED\t%s", tag, "", "", "", "");
}

static int far_emit_row(struct far_rx *rx, const char *tag, int want,
                        char *buf, struct far_list *rows)
{
    char *rest = malloc(strlen(buf) + 1); // raw-alloc-ok:lint-runtime
    if (!rest)
        return die("z23-lint: out of memory\n", "");
    strcpy(rest, buf);
    char *p[3] = { NULL, NULL, NULL };
    int n = 0;
    int rc = far_take_quoted(rx, rest, p, &n);
    if (rc == 0) {
        far_strip_parens(rest);
        if (n != want)
            rc = far_addf(rows, "MALFORMED\t%s", tag, "", "", "", "");
        else if (strcmp(tag, "ASSET") == 0
                 && rest[strspn(rest, " \t")] == '\0')
            rc = far_addf(rows, "ASSET\t%s", p[0], "", "", "", "");
        else
            rc = far_emit_typed(tag, rest, p, rows);
    }
    for (int i = 0; i < 3; i++)
        free(p[i]);
    free(rest);
    return rc;
}

static int far_buf_take(struct far_state *st, const char *line)
{
    size_t nl = strlen(line);
    if (st->len + nl + 1 > st->cap) {
        size_t nc = st->cap ? st->cap * 2 : 256;
        while (nc < st->len + nl + 1)
            nc *= 2;
        char *nb = realloc(st->buf, nc); // raw-alloc-ok:lint-runtime
        if (!nb)
            return die("z23-lint: out of memory\n", "");
        st->buf = nb;
        st->cap = nc;
    }
    memcpy(st->buf + st->len, line, nl + 1);
    st->len += nl;
    return 0;
}

static int far_parse_line(struct far_rx *rx, struct far_state *st,
                          const char *line, struct far_list *rows)
{
    if (regexec(&rx->start, line, 0, NULL, 0) == 0) {
        st->in = 1;
        st->len = 0;
        if (st->buf)
            st->buf[0] = '\0';
        const char *t = line + 8;
        const char *op = strchr(t, '(');
        size_t tl = op ? (size_t)(op - t) : strlen(t);
        if (tl >= sizeof st->tag)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(st->tag, t, tl);
        st->tag[tl] = '\0';
        st->want = strcmp(st->tag, "RULE") == 0 ? 3 : 1;
    }
    if (!st->in)
        return 0;
    int rc = far_buf_take(st, line);
    if (rc == 0 && regexec(&rx->close, line, 0, NULL, 0) == 0) {
        st->in = 0;
        rc = far_emit_row(rx, st->tag, st->want, st->buf, rows);
    }
    return rc;
}

int far_parse(struct far_rx *rx, const char *def, struct far_list *rows)
{
    FILE *f = fopen(def, "r");
    if (!f) {
        fprintf(stderr, "%s: FATAL — cannot read scanned file: %s\n",
                k_gate, def);
        return 2;
    }
    struct far_state st = { 0 };
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = far_parse_line(rx, &st, line, rows);
    }
    free(st.buf);
    return fin(f, line, def, rc);
}
