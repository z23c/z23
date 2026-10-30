/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Makefile readers for check-standalone-tools-link: the standalone
 * tool rule scan, the FUZZ_TARGETS / fuzz-ci validation and the windows
 * acceptance catalog coverage test. Each reader fails closed (2 / -1) on a
 * shape it does not recognise.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_standalone_tools_link_priv.h"

const char k_stl_gate[] = "check-standalone-tools-link";

int stl_rd_next(struct stl_rd *r)
{
    if (!fgets(r->buf, sizeof r->buf, r->f))
        return 0;
    r->head = !r->mid;
    size_t n = strlen(r->buf);
    r->mid = !(n && r->buf[n - 1] == '\n');
    if (!r->mid)
        r->buf[n - 1] = '\0';
    return 1;
}

/* 0 added, 1 already present, -1 name or table too large. */
int stl_names_add(struct stl_names *t, const char *s, size_t n)
{
    if (n == 0 || n >= STL_NAME || t->count >= STL_MAX)
        return -1;
    for (int i = 0; i < t->count; i++)
        if (strlen(t->n[i]) == n && strncmp(t->n[i], s, n) == 0)
            return 1;
    memcpy(t->n[t->count], s, n);
    t->n[t->count][n] = '\0';
    t->count++;
    return 0;
}

int stl_names_has(const struct stl_names *t, const char *s)
{
    for (int i = 0; i < t->count; i++)
        if (strcmp(t->n[i], s) == 0)
            return 1;
    return 0;
}

static int stl_namechar(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '.' || c == '-';
}

static int stl_too_big(void)
{
    fprintf(stderr, "%s: a Makefile name is too long or the table is full\n",
            k_stl_gate);
    return 2;
}

/* ^$(BIN_DIR)/<name>:  and  ^$(VAR):  rule heads. */
static int stl_head_a(const char *line, struct stl_names *tools,
                      struct stl_names *vars)
{
    if (strncmp(line, "$(BIN_DIR)/", 11) == 0) {
        size_t i = 11;
        while (stl_namechar(line[i]))
            i++;
        if (i > 11 && line[i] == ':')
            return stl_names_add(tools, line + 11, i - 11) < 0 ? 2 : 0;
        return 0;
    }
    if (line[0] != '$' || line[1] != '(')
        return 0;
    size_t i = 2;
    while (isupper((unsigned char)line[i]) || isdigit((unsigned char)line[i]) ||
           line[i] == '_')
        i++;
    if (i > 2 && line[i] == ')' && line[i + 1] == ':')
        return stl_names_add(vars, line + 2, i - 2) < 0 ? 2 : 0;
    return 0;
}

/* Does `line` read `<var> ws* = ws* $(BIN_DIR)/`? Returns the offset past it. */
static const char *stl_var_assign(const char *line, const char *var)
{
    size_t vl = strlen(var);
    if (strncmp(line, var, vl) != 0)
        return NULL;
    const char *p = line + vl;
    while (isspace((unsigned char)*p))
        p++;
    if (*p != '=')
        return NULL;
    p++;
    while (isspace((unsigned char)*p))
        p++;
    return strncmp(p, "$(BIN_DIR)/", 11) == 0 ? p : NULL;
}

/* sed 's|.*\$(BIN_DIR)/||; s|[[:space:]]*$||' then skip $( and / names. */
static int stl_resolve(const char *p, struct stl_names *tools)
{
    const char *last = p;
    for (const char *q = p; (q = strstr(q, "$(BIN_DIR)/")) != NULL; q++)
        last = q;
    last += 11;
    size_t n = strlen(last);
    while (n && isspace((unsigned char)last[n - 1]))
        n--;
    if (n == 0 || memchr(last, '/', n) || strstr(last, "$(") != NULL)
        return 0;
    return stl_names_add(tools, last, n) < 0 ? 2 : 0;
}

/* Pass B: each variable's FIRST `VAR = $(BIN_DIR)/...` line decides. */
static int stl_pass_b(FILE *f, struct stl_names *tools,
                      const struct stl_names *vars, char *done)
{
    struct stl_rd r = { .f = f };
    while (stl_rd_next(&r)) {
        if (!r.head || !isupper((unsigned char)r.buf[0]))
            continue;
        for (int v = 0; v < vars->count; v++) {
            const char *p = done[v] ? NULL : stl_var_assign(r.buf, vars->n[v]);
            if (!p)
                continue;
            done[v] = 1;
            if (stl_resolve(p, tools) != 0)
                return stl_too_big();
        }
    }
    return 0;
}

int stl_scan_makefile(const char *path, struct stl_names *tools)
{
    static struct stl_names vars;
    static char done[STL_MAX];
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", k_stl_gate, path);
        return 2;
    }
    vars.count = 0;
    memset(done, 0, sizeof done);
    struct stl_rd r = { .f = f };
    int rc = 0;
    while (rc == 0 && stl_rd_next(&r))
        if (r.head)
            rc = stl_head_a(r.buf, tools, &vars) ? stl_too_big() : 0;
    if (rc == 0) {
        rewind(f);
        rc = stl_pass_b(f, tools, &vars, done);
    }
    fclose(f);
    return rc;
}

/* ^NAME[[:space:]]*[:+?]?= */
static int stl_assign_head(const char *line, const char *name)
{
    size_t nl = strlen(name);
    if (strncmp(line, name, nl) != 0)
        return 0;
    const char *p = line + nl;
    while (isspace((unsigned char)*p))
        p++;
    if (*p == ':' || *p == '+' || *p == '?')
        p++;
    return *p == '=';
}

/* ^fuzz-ci[[:space:]]*: */
static int stl_fuzz_ci_head(const char *line)
{
    if (strncmp(line, "fuzz-ci", 7) != 0)
        return 0;
    const char *p = line + 7;
    while (isspace((unsigned char)*p))
        p++;
    return *p == ':';
}

struct stl_fz {
    char target[STL_LINE], ci[STL_LINE];
    int ntarget, nci, over;
};

static int stl_fz_collect(const char *mk, struct stl_fz *z)
{
    FILE *f = fopen(mk, "r");
    if (!f)
        return 2;
    struct stl_rd r = { .f = f };
    while (stl_rd_next(&r)) {
        if (!r.head)
            continue;
        int is_t = stl_assign_head(r.buf, "FUZZ_TARGETS");
        if (!is_t && !stl_fuzz_ci_head(r.buf))
            continue;
        int *cnt = is_t ? &z->ntarget : &z->nci;
        if (*cnt == 0)
            snprintf(is_t ? z->target : z->ci, STL_LINE, "%s", r.buf);
        z->over |= r.mid;
        (*cnt)++;
    }
    fclose(f);
    return 0;
}

/* ^\$\(BIN_DIR\)/fuzz_[a-zA-Z0-9_]+$ */
static int stl_fuzz_tok_ok(const char *p, size_t n)
{
    if (n <= 16 || strncmp(p, "$(BIN_DIR)/fuzz_", 16) != 0)
        return 0;
    for (size_t i = 16; i < n; i++)
        if (!(isalnum((unsigned char)p[i]) || p[i] == '_'))
            return 0;
    return 1;
}

static int stl_fz_tokens(const char *text, struct stl_names *fuzz)
{
    const char *p = text;
    while (*p) {
        p += strspn(p, " \t");
        size_t n = strcspn(p, " \t");
        if (n == 0)
            break;
        if (!stl_fuzz_tok_ok(p, n)) {
            fprintf(stderr, "%s: FATAL — invalid fuzz target: %.*s\n", k_stl_gate,
                    (int)(n < 160 ? n : 160), p);
            return 2;
        }
        if (stl_names_add(fuzz, p + 11, n - 11) < 0)
            return stl_too_big();
        p += n;
    }
    return 0;
}

int stl_load_fuzz(const char *mk, struct stl_names *fuzz)
{
    static struct stl_fz z;
    memset(&z, 0, sizeof z);
    if (stl_fz_collect(mk, &z) != 0) {
        fprintf(stderr, "%s: cannot read %s\n", k_stl_gate, mk);
        return 2;
    }
    if (z.ntarget != 1 || z.over || strncmp(z.target, "FUZZ_TARGETS = ", 15) != 0 ||
        strchr(z.target, '#') || strchr(z.target, '\\')) {
        fprintf(stderr, "%s: FATAL — FUZZ_TARGETS is not one literal uncommented assignment\n",
                k_stl_gate);
        return 2;
    }
    int rc = stl_fz_tokens(z.target + 15, fuzz);
    if (rc != 0)
        return rc;
    if (z.nci != 1 || z.over || strcmp(z.ci, "fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS)") != 0) {
        fprintf(stderr, "%s: FATAL — fuzz-ci prerequisite list changed\n", k_stl_gate);
        return 2;
    }
    return 0;
}

/* Does `line` start assignment `var ws* :=`? Returns the body or NULL. */
static char *stl_cat_body(char *line, const char *var)
{
    size_t vl = strlen(var);
    if (strncmp(line, var, vl) != 0)
        return NULL;
    char *p = line + vl;
    while (*p == ' ' || *p == '\t')
        p++;
    return (p[0] == ':' && p[1] == '=') ? p + 2 : NULL;
}

/* Trailing backslash (after blanks) marks a continuation; strip it. */
static int stl_cat_cont(char *body)
{
    size_t n = strlen(body);
    while (n && (body[n - 1] == ' ' || body[n - 1] == '\t'))
        n--;
    if (n == 0 || body[n - 1] != '\\')
        return 0;
    size_t j = n - 1;
    while (j && (body[j - 1] == ' ' || body[j - 1] == '\t'))
        j--;
    body[j] = '\0';
    return 1;
}

static int stl_cat_tokens(char *body, char (*out)[STL_TOK], int *n)
{
    char *p = body;
    while (*p) {
        p += strspn(p, " \t");
        size_t len = strcspn(p, " \t");
        if (len == 0)
            break;
        if (*n >= STL_TOKS || len >= STL_TOK)
            return -1;
        memcpy(out[*n], p, len);
        out[*n][len] = '\0';
        (*n)++;
        p += len;
    }
    return 0;
}

/* Tokens of one catalog assignment; comment lines skipped, continuations
 * joined. Comments never count: the catalog documents this very coupling. */
static int stl_catalog_collect(const char *path, const char *var,
                               char (*out)[STL_TOK], int *count)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    struct stl_rd r = { .f = f };
    int inrow = 0, n = 0, rc = 0;
    while (rc == 0 && stl_rd_next(&r)) {
        if (r.head && r.buf[strspn(r.buf, " \t")] == '#')
            continue;
        char *body = r.head ? stl_cat_body(r.buf, var) : NULL;
        if (!body && inrow)
            body = r.buf;
        if (!body)
            continue;
        int cont = stl_cat_cont(body);
        rc = stl_cat_tokens(body, out, &n);
        inrow = cont;
    }
    fclose(f);
    *count = n;
    return rc;
}

static int stl_tok_has(char (*t)[STL_TOK], int n, const char *s)
{
    for (int i = 0; i < n; i++)
        if (strcmp(t[i], s) == 0)
            return 1;
    return 0;
}

/* 0 = catalog cross-compiles src under row; 1 = row not in TESTS;
 * 2 = SOURCES row does not name src; -1 = catalog unreadable or oversize. */
int stl_windows_covers(const char *catalog, const char *row, const char *src)
{
    static char listed[STL_TOKS][STL_TOK], sources[STL_TOKS][STL_TOK];
    char var[STL_NAME];
    int nl = 0, ns = 0;
    if (stl_catalog_collect(catalog, "ZCL_WINDOWS_ACCEPTANCE_TESTS", listed, &nl) != 0)
        return -1;
    if (ovf(snprintf(var, sizeof var, "ZCL_WINDOWS_ACCEPTANCE_%s_SOURCES", row),
            sizeof var))
        return -1;
    if (stl_catalog_collect(catalog, var, sources, &ns) != 0)
        return -1;
    if (!stl_tok_has(listed, nl, row))
        return 1;
    return stl_tok_has(sources, ns, src) ? 0 : 2;
}
