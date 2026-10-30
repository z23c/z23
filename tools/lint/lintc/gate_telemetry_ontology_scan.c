/* Copyright 2026 Rhett Creiton - Apache License 2.0
 *
 * purpose: scan-side half of check-telemetry-ontology: manifest parsing
 * (FUNC and TABLE rows, both floors), the function-slicing emission scan
 * (UNANNOTATED FIELD / UNMAPPED EMISSION TARGET), the structural TABLE-row
 * proof (domain match, leaf resolution, shrink-only floor, content
 * contract, no hand-written JSON in fill providers) and the fill-provider
 * count assertion. Ported from tools/lint/check_telemetry_ontology.sh
 * (deleted); the awk function slicer is reimplemented here in C.
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
#include "lintc.h"
#include "gate_telemetry_ontology_priv.h"

static regex_t g_sc_push, g_sc_cnt;

static int to_sc_re_init(void)
{
    static int done = 0;
    int e;
    if (done)
        return 0;
    if ((e = regcomp(&g_sc_push,
                     "json_push_kv_(int|str|bool|dbl|uint)[[:space:]]*[(]",
                     REG_EXTENDED)))
        return reg_fail(&g_sc_push, e);
    if ((e = regcomp(&g_sc_cnt, "^[[:space:]]*([0-9]+)[[:space:]]*$",
                     REG_EXTENDED)))
        return reg_fail(&g_sc_cnt, e);
    done = 1;
    return 0;
}

/* ── section 3: the scan manifest ────────────────────────────────────── */

struct to_man_ctx {
    struct to_state *st;
};

static int to_digits(const char *s)
{
    if (!s[0])
        return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p))
            return 0;
    return 1;
}

static int to_man_table(struct to_state *st, char **tok, int nt,
                        const char *line)
{
    if (nt != 4) {
        fprintf(st->err,
                "%s: FATAL — malformed TABLE row (want\n"
                "  'TABLE <domain> <fields.def> <min-rows>'): %s\n",
                TO_GATE, line);
        return 2;
    }
    if (!to_readable(tok[2])) {
        fprintf(st->err,
                "%s: FATAL — TABLE row names an unreadable field table: %s\n",
                TO_GATE, tok[2]);
        return 2;
    }
    if (!to_digits(tok[3])) {
        fprintf(st->err,
                "%s: FATAL — TABLE row's <min-rows> is not a number: %s\n",
                TO_GATE, line);
        return 2;
    }
    if (st->t_n >= TO_MAX_TBL || strlen(tok[1]) >= TO_DOM ||
        strlen(tok[2]) >= TO_PATH) {
        fprintf(st->err, "%s: TABLE row list exceeds %d\n", TO_GATE,
                TO_MAX_TBL);
        return 2;
    }
    strcpy(st->t_dom[st->t_n], tok[1]);
    strcpy(st->t_def[st->t_n], tok[2]);
    st->t_min[st->t_n] = atoi(tok[3]);
    st->t_n++;
    return 0;
}

static int to_m_find(const struct to_state *st, const char *key)
{
    for (int i = 0; i < st->m_n; i++)
        if (strcmp(st->m_key[i], key) == 0)
            return i;
    return -1;
}

/* Records one function (file, name) once, in first-seen order. */
static int to_man_fn_add(struct to_state *st, char **tok)
{
    if (st->f_n >= TO_MAX_ROWS || strlen(tok[1]) >= TO_PATH ||
        strlen(tok[2]) >= TO_DOM) {
        fprintf(st->err, "%s: manifest function list exceeds %d\n", TO_GATE,
                TO_MAX_ROWS);
        return 2;
    }
    for (int i = 0; i < st->f_n; i++)
        if (strcmp(st->f_file[i], tok[1]) == 0 &&
            strcmp(st->f_fn[i], tok[2]) == 0)
            return 0;
    strcpy(st->f_file[st->f_n], tok[1]);
    strcpy(st->f_fn[st->f_n], tok[2]);
    st->f_n++;
    return 0;
}

static int to_man_func(struct to_state *st, char **tok, int nt,
                       const char *line)
{
    if (nt != 5) {
        fprintf(st->err, "%s: FATAL — malformed manifest row: %s\n", TO_GATE,
                line);
        return 2;
    }
    if (!to_readable(tok[1])) {
        fprintf(st->err,
                "%s: FATAL — manifest names an unreadable file: %s\n", TO_GATE,
                tok[1]);
        return 2;
    }
    if (st->m_n >= TO_MAX_ROWS || strlen(tok[1]) >= TO_PATH ||
        strlen(tok[2]) >= TO_DOM || strlen(tok[3]) >= TO_DOM ||
        strlen(tok[4]) >= TO_PREFIX) {
        fprintf(st->err, "%s: manifest row list exceeds %d\n", TO_GATE,
                TO_MAX_ROWS);
        return 2;
    }
    if (ovf(snprintf(st->m_key[st->m_n], TO_ROWKEY, "%s|%s|%s", tok[1], tok[2],
                     tok[3]), TO_ROWKEY))
        return 2;
    strcpy(st->m_sub[st->m_n], tok[0]);
    strcpy(st->m_prefix[st->m_n],
           strcmp(tok[4], "-") == 0 ? "" : tok[4]);
    st->m_n++;
    return to_man_fn_add(st, tok);
}

static int to_man_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_state *st = ((struct to_man_ctx *)v)->st;
    char stripped[TO_LINE], tokbuf[TO_LINE];
    if (strlen(line) >= sizeof stripped) {
        fprintf(st->err, "%s: manifest line exceeds %d\n", TO_GATE, TO_LINE);
        return 2;
    }
    strcpy(stripped, line);
    char *h = strchr(stripped, '#');
    if (h)
        *h = '\0';
    strcpy(tokbuf, stripped);
    char *tok[8];
    int nt = 0, over = 0;
    for (char *p = strtok(tokbuf, " \t"); p; p = strtok(NULL, " \t")) {
        if (nt < 8)
            tok[nt++] = p;
        else {
            over = 1;
            break;
        }
    }
    if (nt == 0)
        return 0;
    if (over)
        nt = 9;
    if (strcmp(tok[0], "TABLE") == 0)
        return to_man_table(st, tok, nt, stripped);
    return to_man_func(st, tok, nt, stripped);
}

static int to_manifest_file(struct to_state *st, const char *path)
{
    struct to_man_ctx c = { st };
    int rc = to_each_line(path, st->err, to_man_line, &c);
    if (rc == 1) {
        fprintf(st->err,
                "%s: FATAL — required input missing or unreadable: %s\n",
                TO_GATE, path);
        return 2;
    }
    return rc;
}

int to_phase_manifest(struct to_state *st)
{
    int rc = to_manifest_file(st, st->manifest_path);
    if (!rc && st->extra_path[0])
        rc = to_manifest_file(st, st->extra_path);
    if (rc)
        return rc;
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "scan manifest collapsed to %d FUNC rows", st->m_n),
             sizeof hint))
        return 2;
    rc = gate_require_scanned(st->m_n, 20, TO_GATE, hint);
    if (rc)
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "scan manifest carries %d TABLE row(s) for %d registered domain(s) — every table-driven domain needs one",
                     st->t_n, st->reg_n), sizeof hint))
        return 2;
    return gate_require_scanned(st->t_n, st->reg_n, TO_GATE, hint);
}

/* ── the emission scan (function slicing in C) ───────────────────────── */

struct to_slice_ctx {
    struct to_state *st;
    const char *file, *fn;
    long lineno;
    int found, done;
};

static int to_is_def_line(const char *line, const char *fn)
{
    if (!line[0] || line[0] == ' ' || line[0] == '\t' || line[0] == '#' ||
        line[0] == '/' || line[0] == '*')
        return 0;
    size_t fl = strlen(fn);
    for (const char *p = line; *p; p++) {
        if (strncmp(p, fn, fl) != 0)
            continue;
        char prev = p > line ? p[-1] : '\0';
        if (isalnum((unsigned char)prev) || prev == '_')
            continue;
        const char *q = p + fl;
        while (*q == ' ' || *q == '\t')
            q++;
        if (*q == '(')
            return 1;
    }
    return 0;
}

static int to_classify(struct to_slice_ctx *c, const char *obj,
                       const char *field)
{
    struct to_state *st = c->st;
    char mapkey[TO_ROWKEY], key[TO_KEY];
    if (ovf(snprintf(mapkey, sizeof mapkey, "%s|%s|%s", c->file, c->fn, obj),
             sizeof mapkey))
        return 2;
    int idx = to_m_find(st, mapkey);
    if (idx < 0) {
        if (to_viol_has(&st->unmapped, mapkey))
            return 0;
        return to_viol_add(&st->unmapped, st->err,
                           "%s:%ld: %s() emits into unmapped target '%s' "
                           "(first field: %s)",
                           c->file, c->lineno, c->fn, obj, field);
    }
    st->extracted++;
    if (ovf(snprintf(key, sizeof key, "%s|%s%s", st->m_sub[idx],
                     st->m_prefix[idx], field), sizeof key))
        return 2;
    if (to_onto_has(st, key))
        return 0;
    return to_viol_add(&st->unannotated, st->err, "%s:%ld: %s", c->file,
                       c->lineno, key);
}

/* Parses "OBJ," at p (just past the open paren); returns the pointer past the
 * comma, or NULL when it is not an object argument. */
static const char *to_emit_obj(const char *p, char *obj, size_t cap)
{
    while (*p == ' ' || *p == '\t')
        p++;
    const char *o = p;
    while (*p && *p != ',' && *p != ')')
        p++;
    if (*p != ',')
        return NULL;
    size_t on = (size_t)(p - o);
    while (on && (o[on - 1] == ' ' || o[on - 1] == '\t'))
        on--;
    if (on == 0 || on >= cap)
        return NULL;
    memcpy(obj, o, on);
    obj[on] = '\0';
    return p + 1;
}

/* Parses the quoted "FIELD" at p; false when absent or out of range. */
static int to_emit_field(const char *p, char *field, size_t cap)
{
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '"')
        return 0;
    p++;
    const char *f = p;
    while (*p && *p != '"')
        p++;
    size_t fl = (size_t)(p - f);
    if (*p != '"' || fl == 0 || fl >= cap)
        return 0;
    memcpy(field, f, fl);
    field[fl] = '\0';
    return 1;
}

static int to_one_emission(struct to_slice_ctx *c, const char *line,
                           size_t hit)
{
    const char *p = line + hit;
    while (*p && *p != '(')
        p++;
    if (*p != '(')
        return 0;
    char obj[TO_DOM], field[TO_PREFIX];
    p = to_emit_obj(p + 1, obj, sizeof obj);
    if (!p || !to_emit_field(p, field, sizeof field))
        return 0;
    return to_classify(c, obj, field);
}

static int to_emissions(struct to_slice_ctx *c, const char *line)
{
    size_t off = 0;
    regmatch_t m;
    while (line[off] && regexec(&g_sc_push, line + off, 1, &m, 0) == 0) {
        int rc = to_one_emission(c, line, off + (size_t)m.rm_so);
        if (rc)
            return rc;
        off += (size_t)m.rm_eo;
    }
    return 0;
}

static int to_slice_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_slice_ctx *c = v;
    c->lineno++;
    if (c->done)
        return 0;
    if (!c->found) {
        if (!to_is_def_line(line, c->fn))
            return 0;
        c->found = 1;
    }
    if (line[0] == '}') {
        c->done = 1;
        return 0;
    }
    return to_emissions(c, line);
}

static int to_scan_func(struct to_state *st, const char *file,
                        const char *fn)
{
    struct to_slice_ctx c;
    memset(&c, 0, sizeof c);
    c.st = st;
    c.file = file;
    c.fn = fn;
    int rc = to_each_line(file, st->err, to_slice_line, &c);
    if (rc)
        return 2;
    if (!c.found) {
        fprintf(st->err,
                "%s: FATAL — could not slice function '%s' out of %s\n"
                "  Refusing to report PASS off a hollow scan.\n",
                TO_GATE, fn, file);
        return 2;
    }
    return 0;
}

int to_phase_scan(struct to_state *st)
{
    int rc = to_sc_re_init();
    for (int i = 0; !rc && i < st->f_n; i++)
        rc = to_scan_func(st, st->f_file[i], st->f_fn[i]);
    if (rc)
        return rc;
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "extracted field population collapsed to %d — a covered dump function was probably renamed",
                     st->extracted), sizeof hint))
        return 2;
    return gate_require_scanned(st->extracted, 150, TO_GATE, hint);
}

/* ── section 4: TABLE rows, fill providers ───────────────────────────── */

struct to_tl_ctx {
    struct to_state *st;
    const char *dom, *def;
    int rows;
};

static int to_tl_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_tl_ctx *c = v;
    char g[TO_DOM], m[TO_DOM], key[TO_KEY];
    if (!to_leaf_gm(line, g, m))
        return 0;
    c->rows++;
    c->st->table_leaves++;
    if (ovf(snprintf(key, sizeof key, "%s|values.%s.%s", c->dom, g, m),
             sizeof key))
        return 2;
    if (to_onto_has(c->st, key))
        return 0;
    return to_viol_add(&c->st->unresolved, c->st->err, "%s: %s", c->def, key);
}

static regex_t g_td_meta;
static int g_td_ok = 0;

struct to_td_ctx {
    char *out;
    size_t cap;
    int found;
};

static int to_td_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_td_ctx *c = v;
    regmatch_t m[2];
    if (c->found)
        return 0;
    if (regexec(&g_td_meta, line, 2, m, 0) != 0)
        return 0;
    size_t n = (size_t)(m[1].rm_eo - m[1].rm_so);
    if (n >= c->cap)
        n = c->cap - 1;
    memcpy(c->out, line + m[1].rm_so, n);
    c->out[n] = '\0';
    c->found = 1;
    return 0;
}


int to_table_domain(const char *path, char *out, size_t cap, FILE *err)
{
    if (!g_td_ok) {
        int e = regcomp(&g_td_meta,
                        "^[[:space:]]*TL_DOMAIN_META[[:space:]]*\\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*)",
                        REG_EXTENDED);
        if (e)
            return reg_fail(&g_td_meta, e);
        g_td_ok = 1;
    }
    struct to_td_ctx c;
    c.out = out;
    c.cap = cap;
    c.found = 0;
    out[0] = '\0';
    int rc = to_each_line(path, err, to_td_line, &c);
    if (rc == 1) {
        fprintf(err, "%s: FATAL — TABLE row names an unreadable field table: %s\n",
                TO_GATE, path);
        return 2;
    }
    return rc;
}

static int to_fill_wanted(const char *path)
{
    size_t n = strlen(path);
    /* "_fill.c" is 7 bytes: match the suffix length, not 8 */
    return n > 7 && strcmp(path + n - 7, "_fill.c") == 0 &&
           !strstr(path, "/test/");
}

static int to_fill_walk(struct to_state *st, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0; /* the shell find silenced errors on missing roots */
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char sub[TO_PATH];
        if (ovf(snprintf(sub, sizeof sub, "%s/%s", dir, e->d_name),
                 sizeof sub)) {
            fprintf(st->err, "%s: fill scan path exceeds %d\n", TO_GATE,
                    TO_PATH);
            rc = 2;
            break;
        }
        struct stat sb;
        if (lstat(sub, &sb) != 0)
            continue;
        if (S_ISDIR(sb.st_mode))
            rc = to_fill_walk(st, sub);
        else if (S_ISREG(sb.st_mode) && to_fill_wanted(sub))
            rc = to_list_add(st->fill_file, &st->fill_n, TO_MAX_FILL,
                             "fill file list", st->err, sub);
    }
    closedir(d);
    return rc;
}

static int to_fill_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int to_fill_discover(struct to_state *st)
{
    char roots[TO_PATH];
    if (ovf(snprintf(roots, sizeof roots, "%s", st->fill_roots), sizeof roots))
        return 2;
    for (char *r = strtok(roots, " \t"); r; r = strtok(NULL, " \t")) {
        int rc = to_fill_walk(st, r);
        if (rc)
            return rc;
    }
    qsort(st->fill_file, (size_t)st->fill_n, TO_PATH, to_fill_cmp);
    return 0;
}

struct to_grep_ctx {
    const regex_t *re;
    int hit;
};

static int to_grep_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_grep_ctx *c = v;
    if (regexec(c->re, line, 0, NULL, 0) == 0)
        c->hit = 1;
    return 0;
}

struct to_push_ctx {
    struct to_state *st;
    const char *dom, *file;
    long lineno;
};

static int to_push_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_push_ctx *c = v;
    c->lineno++;
    if (regexec(&g_sc_push, line, 0, NULL, 0) != 0)
        return 0;
    return to_viol_add(&c->st->handwritten, c->st->err,
                       "%s:%ld: %s provider hand-writes JSON", c->file,
                       c->lineno, c->dom);
}

static int to_push_scan(struct to_state *st, const char *dom, const char *ff)
{
    struct to_push_ctx c;
    memset(&c, 0, sizeof c);
    c.st = st;
    c.dom = dom;
    c.file = ff;
    int rc = to_each_line(ff, st->err, to_push_line, &c);
    if (rc == 1) {
        fprintf(st->err, "%s: FATAL — grep failed (rc=2) on %s\n", TO_GATE,
                ff);
        return 2;
    }
    return rc;
}

static int to_fill_file(struct to_state *st, const char *dom, const char *ff,
                        const regex_t *redef)
{
    const char *sl = strrchr(ff, '/');
    const char *base = sl ? sl + 1 : ff;
    size_t dl = strlen(dom);
    int interesting = strncmp(base, dom, dl) == 0 && base[dl] == '_';
    if (!interesting) {
        struct to_grep_ctx g = { redef, 0 };
        int rc = to_each_line(ff, st->err, to_grep_line, &g);
        if (rc == 1) {
            fprintf(st->err, "%s: FATAL — grep failed (rc=2) on %s\n",
                    TO_GATE, ff);
            return 2;
        }
        if (rc)
            return rc;
        interesting = g.hit;
    }
    if (!interesting)
        return 0;
    st->fill_scanned++;
    return to_push_scan(st, dom, ff);
}

static int to_fill_domain(struct to_state *st, const char *dom)
{
    regex_t redef;
    char pat[TO_DOM + 48];
    if (ovf(snprintf(pat, sizeof pat, "(^|[^A-Za-z0-9_])%s_dump_state_fill[[:space:]]*[(]",
                     dom), sizeof pat))
        return 2;
    int e = regcomp(&redef, pat, REG_EXTENDED);
    if (e)
        return reg_fail(&redef, e);
    int rc = 0;
    for (int i = 0; i < st->fill_n && !rc; i++)
        rc = to_fill_file(st, dom, st->fill_file[i], &redef);
    regfree(&redef);
    return rc;
}

static struct to_viol g_tbl_dc;

static int to_table_content(struct to_state *st, const char *def)
{
    memset(&g_tbl_dc, 0, sizeof g_tbl_dc);
    int rc = to_content_scan(st, &g_tbl_dc, def, 1);
    if (rc)
        return rc;
    if (g_tbl_dc.n == 0)
        return 0;
    to_viol_print(st->err, &g_tbl_dc);
    fprintf(st->err,
            "[%s] TL_LEAF row(s) above ship an empty means, or carry a\n"
            "  health rule with an empty implies/next.\n",
            TO_GATE);
    st->failed_content = 1;
    return 0;
}

static int to_table_row(struct to_state *st, int i)
{
    const char *dom = st->t_dom[i], *def = st->t_def[i];
    char declared[TO_DOM];
    int rc = to_table_domain(def, declared, sizeof declared, st->err);
    if (rc)
        return rc;
    if (strcmp(declared, dom) != 0) {
        rc = to_viol_add(&st->wrong_domain, st->err,
                         "%s: TL_DOMAIN_META declares '%s', manifest row says '%s'",
                         def, declared[0] ? declared : "<none>", dom);
        if (rc)
            return rc;
    }
    struct to_tl_ctx c = { st, dom, def, 0 };
    rc = to_each_line(def, st->err, to_tl_line, &c);
    if (rc)
        return 2;
    if (c.rows < st->t_min[i]) {
        rc = to_viol_add(&st->shrunk, st->err,
                         "%s: %d TL_LEAF row(s), manifest floor is %d", def,
                         c.rows, st->t_min[i]);
        if (rc)
            return rc;
    }
    if (!to_checked_has(st, def)) {
        rc = to_mark_checked(st, def);
        if (!rc)
            rc = to_table_content(st, def);
    }
    if (rc)
        return rc;
    return to_fill_domain(st, dom);
}

struct to_fc_ctx {
    int found;
    long val;
};

static int to_fc_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_fc_ctx *c = v;
    regmatch_t m[2];
    if (c->found || regexec(&g_sc_cnt, line, 2, m, 0) != 0)
        return 0;
    char buf[32];
    size_t n = (size_t)(m[1].rm_eo - m[1].rm_so);
    if (n >= sizeof buf)
        n = sizeof buf - 1;
    memcpy(buf, line + m[1].rm_so, n);
    buf[n] = '\0';
    c->val = strtol(buf, NULL, 10);
    c->found = 1;
    return 0;
}

static int to_fill_count(struct to_state *st)
{
    if (!to_readable(st->fill_count_path)) {
        fprintf(st->err,
                "%s: FATAL — fill-provider count file missing: %s\n", TO_GATE,
                st->fill_count_path);
        return 2;
    }
    struct to_fc_ctx c;
    memset(&c, 0, sizeof c);
    int rc = to_each_line(st->fill_count_path, st->err, to_fc_line, &c);
    if (rc)
        return 2;
    if (!c.found) {
        fprintf(st->err, "%s: FATAL — %s carries no integer count\n", TO_GATE,
                st->fill_count_path);
        return 2;
    }
    if (st->fill_scanned == (int)c.val)
        return 0;
    if (st->fill_scanned < (int)c.val)
        fprintf(st->err,
                "[%s] FILL PROVIDER COUNT DROPPED — discovered\n"
                "  %d, expected %ld. A provider\n"
                "  vanished or fell out of the discovery shape (most often a\n"
                "  rename), so the hand-written-JSON check just went hollow for\n"
                "  its domain. Find it, or lower the count in %s\n"
                "  deliberately if the provider really was deleted.\n",
                TO_GATE, st->fill_scanned, c.val, st->fill_count_path);
    else
        fprintf(st->err,
                "[%s] FILL PROVIDER COUNT GREW — discovered\n"
                "  %d, expected %ld. A new provider\n"
                "  is now covered by the no-hand-written-JSON rule; record it by\n"
                "  setting the count in %s to %d\n"
                "  in the same commit.\n",
                TO_GATE, st->fill_scanned, c.val, st->fill_count_path,
                st->fill_scanned);
    st->failed_fill = 1;
    return 0;
}

int to_phase_tables(struct to_state *st)
{
    int rc = to_fill_discover(st);
    for (int i = 0; !rc && i < st->t_n; i++)
        rc = to_table_row(st, i);
    if (rc)
        return rc;
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "the TABLE rows contributed %d leaf row(s) across %d row(s) — a field table parsed as empty, so its coverage proof is hollow",
                     st->table_leaves, st->t_n), sizeof hint))
        return 2;
    rc = gate_require_scanned(st->table_leaves, st->t_n, TO_GATE, hint);
    if (rc)
        return rc;
    return to_fill_count(st);
}

/* ── the verdict ─────────────────────────────────────────────────────── */

static int to_report_bucket(struct to_state *st, struct to_viol *v, int which)
{
    if (v->n == 0)
        return 0;
    to_viol_print(st->err, v);
    switch (which) {
    case 0:
        fprintf(st->err,
                "[%s] UNRESOLVED TABLE LEAF — the TL_LEAF row(s) above derive an\n"
                "  ontology path that is in NOTHING the build pastes into g_fields[].\n"
                "  A TL_LEAF is its own ontology row, so this never means \"write a\n"
                "  TELEMETRY_FIELD row\" — it means the table is not wired up: either\n"
                "  the manifest TABLE row names a field table that no #include in\n"
                "  %s pastes, or the row's domain is not the domain that\n"
                "  table is pasted under. Fix the wiring, not the ontology.\n",
                TO_GATE, st->tu_path);
        break;
    case 1:
        fprintf(st->err,
                "[%s] TABLE ROW / TABLE MISMATCH — the manifest row and the field\n"
                "  table disagree about which domain the table belongs to, so the row\n"
                "  would prove coverage of the wrong domain's ontology keys.\n",
                TO_GATE);
        break;
    case 2:
        fprintf(st->err,
                "[%s] TABLE FLOOR BREACHED — a domain lost fields. The floor is\n"
                "  SHRINK-ONLY: raise it when the table grows, and never lower it to\n"
                "  make this pass. If the removal is intended, say so in the commit\n"
                "  and lower the floor in %s deliberately.\n",
                TO_GATE, st->manifest_path);
        break;
    case 3:
        fprintf(st->err,
                "[%s] PROVIDER HAND-WRITES JSON — a `*_fill.c` collector must fill\n"
                "  the typed snapshot through the TELEMETRY_SET_* setters and emit\n"
                "  nothing. telemetry_render() is the only place a telemetry field\n"
                "  becomes JSON; a json_push_kv_* here reintroduces exactly the\n"
                "  unannotated, un-renderable field this gate exists to prevent.\n",
                TO_GATE);
        break;
    case 4:
        fprintf(st->err,
                "[%s] UNMAPPED EMISSION TARGET — the scan manifest does not say\n"
                "  which JSON path the target(s) above sit at, so their fields could\n"
                "  not be checked for meaning at all. Add a row to %s.\n",
                TO_GATE, st->manifest_path);
        break;
    default:
        fprintf(st->err,
                "[%s] UNANNOTATED FIELD x%d — the field(s) above are emitted by a\n"
                "  covered dump function with no meaning row. Add a TELEMETRY_FIELD\n"
                "  row to %s stating what it counts, its health rule, what an\n"
                "  unhealthy value implies, and the next command to run.\n",
                TO_GATE, v->n, st->onto_path);
        break;
    }
    return 1;
}

int to_verdict(struct to_state *st)
{
    int failed = st->failed_content | st->failed_fill;
    failed |= to_report_bucket(st, &st->unresolved, 0);
    failed |= to_report_bucket(st, &st->wrong_domain, 1);
    failed |= to_report_bucket(st, &st->shrunk, 2);
    failed |= to_report_bucket(st, &st->handwritten, 3);
    failed |= to_report_bucket(st, &st->unmapped, 4);
    failed |= to_report_bucket(st, &st->unannotated, 5);
    if (failed) {
        if (strcmp(st->mode, "FAIL") == 0)
            return 1;
        fprintf(st->out,
                "[%s] WARN — violations above were reported, not enforced "
                "(ZCL_LINT_MODE=%s)\n",
                TO_GATE, st->mode);
        return 0;
    }
    fprintf(st->out,
            "[%s] PASS (%d emitted fields over %d FUNC rows, %d table leaves "
            "over %d TABLE rows (%d registered / %d pasted domains, %d merged "
            "rows, %d fill provider(s) checked), all annotated; %d ontology "
            "rows, %d judged, %d questions)\n",
            TO_GATE, st->extracted, st->m_n, st->table_leaves, st->t_n,
            st->reg_n, st->pasted_n, st->dom_table_rows, st->fill_scanned,
            st->onto_count, st->judged, st->questions);
    return 0;
}
