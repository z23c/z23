/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: parsers for the check-remote-command-classes C23 lint gate —
 * the three source-of-truth readers that tools/lint/check_remote_command_
 * classes.sh used to reach through two standalone awk helper programs, now
 * retired.
 *
 * Gates: (parser sibling of check-remote-command-classes; see
 * gate_remote_command_classes.c for the gate entry points)
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_remote_command_classes_priv.h"

/* ── generic ordered string set ──────────────────────────────────────────── */

int rcc_push(struct rcc_list *l, const char *s, size_t n)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, s, n);
    copy[n] = '\0';
    l->v[l->n++] = copy;
    return 0;
}

int rcc_has(const struct rcc_list *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i], s) == 0)
            return 1;
    return 0;
}

int rcc_add_uniq(struct rcc_list *l, const char *s, size_t n)
{
    char tmp[RCC_LEAF];
    if (n >= sizeof tmp)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(tmp, s, n);
    tmp[n] = '\0';
    if (rcc_has(l, tmp))
        return 0;
    return rcc_push(l, s, n);
}

void rcc_free(struct rcc_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static int rcc_strcmp_v(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void rcc_sort(struct rcc_list *l)
{
    if (l->n)
        qsort(l->v, l->n, sizeof *l->v, rcc_strcmp_v);
}

int rcc_row_push(struct rcc_rows *r, const struct rcc_row *row)
{
    if (r->n == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 32;
        struct rcc_row *nv = realloc(r->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        r->v = nv;
        r->cap = nc;
    }
    r->v[r->n++] = *row;
    return 0;
}

void rcc_rows_free(struct rcc_rows *r)
{
    free(r->v);
    r->v = NULL;
    r->n = r->cap = 0;
}

/* ── growable line-join buffer, shared by both multi-line scanners ──────── */

struct rcc_buf { char *s; size_t n, cap; };

static int rcc_buf_grow(struct rcc_buf *b, size_t need)
{
    if (need <= b->cap)
        return 0;
    size_t nc = b->cap ? b->cap * 2 : 256;
    while (nc < need)
        nc *= 2;
    char *ns = realloc(b->s, nc); // raw-alloc-ok:lint-runtime
    if (!ns)
        return die("z23-lint: out of memory\n", "");
    b->s = ns;
    b->cap = nc;
    return 0;
}

static int rcc_buf_set(struct rcc_buf *b, const char *s, size_t n)
{
    if (rcc_buf_grow(b, n + 1))
        return 2;
    memcpy(b->s, s, n);
    b->s[n] = '\0';
    b->n = n;
    return 0;
}

/* buf = buf " " s — the single-space join both awk programs use. */
static int rcc_buf_cat(struct rcc_buf *b, const char *s, size_t n)
{
    if (rcc_buf_grow(b, b->n + 1 + n + 1))
        return 2;
    b->s[b->n] = ' ';
    memcpy(b->s + b->n + 1, s, n);
    b->n += 1 + n;
    b->s[b->n] = '\0';
    return 0;
}

static size_t rcc_chomp(char *line)
{
    size_t n = strlen(line);
    if (n && line[n - 1] == '\n')
        line[--n] = '\0';
    return n;
}

/* First "[^"]*" substring — no escape handling, matching the awk regex
 * exactly. Returns 1 and fills out/cap on a match, 0 on none. */
static int rcc_first_quoted(const char *s, char *out, size_t cap)
{
    const char *p = strchr(s, '"');
    if (!p)
        return 0;
    p++;
    const char *e = strchr(p, '"');
    if (!e)
        return 0;
    size_t n = (size_t)(e - p);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

/* ── source A: every .def file under engine/composition/commands/
 * (replaces the retired command-leaf awk helper) */

/* /^ZCL_COMMAND_(READY_READ|READY_COMMAND|COMPAT_READ|COMPAT_COMMAND|
 * PLANNED_READ|PLANNED_COMMAND|DEV_READ|DEV_COMMAND)\(/ — ZCL_COMMAND_BRANCH
 * never matches, so it is never a leaf. */
static const char k_rcc_leaf_pat[] =
    "^ZCL_COMMAND_(READY_READ|READY_COMMAND|COMPAT_READ|COMPAT_COMMAND|"
    "PLANNED_READ|PLANNED_COMMAND|DEV_READ|DEV_COMMAND)\\(";

static int rcc_leaf_file(const char *path, const regex_t *re,
                         struct rcc_list *leaves)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        (void)nread;
        rcc_chomp(line);
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        const char *paren = strchr(line, '(');
        if (!paren)
            continue;
        struct rcc_buf buf = { NULL, 0, 0 };
        rc = rcc_buf_set(&buf, paren + 1, strlen(paren + 1));
        while (rc == 0 && !strchr(buf.s, '"')) {
            ssize_t n2 = getline(&line, &cap, f);
            if (n2 < 0)
                break;
            rcc_chomp(line);
            rc = rcc_buf_cat(&buf, line, strlen(line));
        }
        if (rc == 0) {
            char litpath[RCC_LEAF];
            if (rcc_first_quoted(buf.s, litpath, sizeof litpath)
                && litpath[0] != '\0')
                rc = rcc_add_uniq(leaves, litpath, strlen(litpath));
        }
        free(buf.s);
    }
    return fin(f, line, path, rc);
}

/* Recursive walk of def_dir for *.def files (find "$DEF_DIR" -type f -name
 * '*.def'); order does not matter — only the resulting leaf SET is used. A
 * present-but-unreadable .def is UNPROVEN exit 2 naming the path (via
 * rcc_leaf_file -> fopen -> die), never silently skipped. */
static int rcc_leaf_walk(const char *dir, const regex_t *re,
                         struct rcc_list *leaves, int *nfiles)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0; /* missing dir: caller's floor reports the hollow scan */
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char full[4096];
        if (ovf(snprintf(full, sizeof full, "%s/%s", dir, e->d_name),
                sizeof full)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (stat(full, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            rc = rcc_leaf_walk(full, re, leaves, nfiles);
            continue;
        }
        size_t n = strlen(e->d_name);
        if (n >= 4 && memcmp(e->d_name + n - 4, ".def", 4) == 0) {
            (*nfiles)++;
            rc = rcc_leaf_file(full, re, leaves);
        }
    }
    closedir(d);
    return rc;
}

int rcc_leaf_dir(const char *def_dir, struct rcc_list *leaves, int *nfiles)
{
    regex_t re;
    int rc = reg_fail(&re, regcomp(&re, k_rcc_leaf_pat, REG_EXTENDED));
    if (rc)
        return rc;
    *nfiles = 0;
    rc = rcc_leaf_walk(def_dir, &re, leaves, nfiles);
    regfree(&re);
    return rc;
}

/* ── source B: the flat AGENT_CONTRACT(...) method table ────────────────── */

/* grep -oE '^AGENT_CONTRACT\("[A-Za-z0-9_.-]+"' | sed 's/^AGENT_CONTRACT("//;
 * s/"$//' — extract the first-argument literal from every line that STARTS
 * with the macro call. */
static const char k_rcc_agent_pat[] =
    "^AGENT_CONTRACT\\(\"[A-Za-z0-9_.-]+\"";

int rcc_agent_defs(const char *agent_def, struct rcc_list *methods)
{
    regex_t re;
    int rc = reg_fail(&re, regcomp(&re, k_rcc_agent_pat, REG_EXTENDED));
    if (rc)
        return rc;
    FILE *f = fopen(agent_def, "r");
    if (!f) {
        regfree(&re);
        return die("z23-lint: cannot open %s\n", agent_def);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        (void)nread;
        rcc_chomp(line);
        regmatch_t m;
        if (regexec(&re, line, 1, &m, 0) != 0)
            continue;
        /* match is `AGENT_CONTRACT("<name>"` — the name is between the
         * first two quotes of the matched span. */
        char name[RCC_LEAF];
        char span[RCC_LEAF];
        size_t sn = (size_t)(m.rm_eo - m.rm_so);
        if (sn >= sizeof span) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        memcpy(span, line + m.rm_so, sn);
        span[sn] = '\0';
        if (rcc_first_quoted(span, name, sizeof name) && name[0] != '\0')
            rc = rcc_add_uniq(methods, name, strlen(name));
    }
    rc = fin(f, line, agent_def, rc);
    regfree(&re);
    return rc;
}

/* ── source C: engine/composition/remote_command_classes.def
 * (the retired class-table awk helper) ───────────────────────────────────────── */

static size_t rcc_quote_count(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        if (*s == '"')
            n++;
    return n;
}

/* REMOTE_CLASS_[A-Z_]+ — first match anywhere in rest. */
static int rcc_class_token(const char *s, char *out, size_t cap,
                           const char **after)
{
    const char *p = strstr(s, "REMOTE_CLASS_");
    if (!p)
        return 0;
    const char *e = p + 13; /* strlen("REMOTE_CLASS_") */
    while ((*e >= 'A' && *e <= 'Z') || *e == '_')
        e++;
    size_t n = (size_t)(e - p);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    if (after)
        *after = e;
    return 1;
}

/* emit(): leaf/cls default "?", reason "". A malformed row is still
 * reported — never silently dropped — so the caller can fail LOUD. */
static int rcc_emit(const char *buf, struct rcc_rows *rows)
{
    if (!buf || buf[0] == '\0')
        return 0;
    struct rcc_row row;
    memset(&row, 0, sizeof row);
    strcpy(row.leaf, "?");
    strcpy(row.cls, "?");
    row.reason[0] = '\0';

    char leaf[RCC_LEAF];
    const char *p = strchr(buf, '"');
    if (p) {
        char span[RCC_REASON];
        if (rcc_first_quoted(p, leaf, sizeof leaf)) {
            if (strlen(leaf) >= sizeof row.leaf)
                return die("z23-lint: derived buffer overflow\n", "");
            strcpy(row.leaf, leaf);
            const char *rest = strchr(p + 1, '"');
            rest = rest ? rest + 1 : p + 1;
            const char *after_cls = NULL;
            char cls[RCC_CLASS];
            if (rcc_class_token(rest, cls, sizeof cls, &after_cls)) {
                if (strlen(cls) >= sizeof row.cls)
                    return die("z23-lint: derived buffer overflow\n", "");
                strcpy(row.cls, cls);
                if (rcc_first_quoted(after_cls, span, sizeof span)) {
                    if (strlen(span) >= sizeof row.reason)
                        return die("z23-lint: derived buffer overflow\n", "");
                    strcpy(row.reason, span);
                }
            }
        }
    }
    /* gsub(/\t/, " ", reason) — tabs would break the tsv the shell produced;
     * the C rows are struct fields, not text, but keep the substitution for
     * output byte-parity with the original tab-joined report lines. */
    for (char *t = row.reason; *t; t++)
        if (*t == '\t')
            *t = ' ';
    row.wellformed = rcc_quote_count(buf) == 4;
    return rcc_row_push(rows, &row);
}

int rcc_table_rows(const char *table_path, struct rcc_rows *rows)
{
    FILE *f = fopen(table_path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", table_path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    struct rcc_buf buf = { NULL, 0, 0 };
    int collecting = 0, depth = 0, rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        (void)nread;
        rcc_chomp(line);
        if (strncmp(line, "REMOTE_COMMAND_CLASS(", 21) == 0) {
            rc = rcc_emit(buf.s, rows);
            if (rc)
                break;
            collecting = 1;
            depth = 0;
            buf.n = 0;
            if (buf.s)
                buf.s[0] = '\0';
            const char *stripped = line + strlen("REMOTE_COMMAND_CLASS");
            rc = rcc_buf_cat(&buf, stripped, strlen(stripped));
            if (rc)
                break;
            for (const char *q = stripped; *q; q++)
                depth += (*q == '(') - (*q == ')');
            if (depth <= 0) {
                collecting = 0;
                rc = rcc_emit(buf.s, rows);
                buf.n = 0;
                if (buf.s)
                    buf.s[0] = '\0';
            }
            continue;
        }
        if (!collecting)
            continue;
        rc = rcc_buf_cat(&buf, line, strlen(line));
        if (rc)
            break;
        for (const char *q = line; *q; q++)
            depth += (*q == '(') - (*q == ')');
        if (depth <= 0) {
            collecting = 0;
            rc = rcc_emit(buf.s, rows);
            buf.n = 0;
            if (buf.s)
                buf.s[0] = '\0';
        }
    }
    if (rc == 0)
        rc = rcc_emit(buf.s, rows);
    free(buf.s);
    return fin(f, line, table_path, rc);
}
