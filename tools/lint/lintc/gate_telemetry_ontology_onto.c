/* Copyright 2026 Rhett Creiton - Apache License 2.0
 *
 * purpose: ontology-side half of check-telemetry-ontology: the declared
 * TELEMETRY_FIELD key set (with judged/question population floors), the
 * table-driven domain registry, the g_fields[] paste-site parse that merges
 * TL_LEAF rows into the key set (with MIS-PAIRED PASTE and HALF-REGISTERED
 * DOMAIN checks), and the per-row empty-means / empty-implies content
 * contract shared by both grammars. Ported from the sed/awk passes of
 * tools/lint/check_telemetry_ontology.sh (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_telemetry_ontology_priv.h"

static regex_t g_on_field, g_on_judged, g_on_question, g_on_tldom, g_on_tlmeta,
    g_on_tlsub, g_on_tlincl, g_on_tlleaf, g_on_rsfield, g_on_rsleaf,
    g_on_rowend, g_on_means, g_on_empty2, g_on_empty1;

struct to_pat {
    regex_t *re;
    const char *pat;
};

/* Compile the ontology and paste-site grammars once, in table order. */
static int to_on_init(void)
{
    static int done = 0;
    static const struct to_pat pats[] = {
        { &g_on_field, "^[[:space:]]*TELEMETRY_FIELD\\(\"([^\"]*)\",[[:space:]]*\"([^\"]*)\"" },
        { &g_on_judged, "TFR_(EXPECT_ZERO|EXPECT_NONZERO|EXPECT_TRUE|EXPECT_FALSE|MIN_ABS|MAX_ABS|MIN_RATIO_OF|MAX_RATIO_OF)" },
        { &g_on_question, "^[[:space:]]*TELEMETRY_QUESTION\\(" },
        { &g_on_tldom, "^[[:space:]]*TL_DOMAIN[[:space:]]*\\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*)" },
        { &g_on_tlmeta, "^[[:space:]]*TL_DOMAIN_META[[:space:]]*\\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*)" },
        { &g_on_tlsub, "^[[:space:]]*#define[[:space:]]+TL_SUB[[:space:]]+\"([^\"]*)\"" },
        { &g_on_tlincl, "^[[:space:]]*#include[[:space:]]+\".*_fields[.]def" },
        { &g_on_tlleaf, "^[[:space:]]*TL_LEAF[[:space:]]*[(]" },
        { &g_on_rsfield, "^[[:space:]]*TELEMETRY_FIELD[[:space:]]*[(]" },
        { &g_on_rsleaf, "^[[:space:]]*TL_LEAF[[:space:]]*[(]" },
        { &g_on_rowend, "\\)[[:space:]]*$" },
        { &g_on_means, "TFS_(INFO|WARN|CRITICAL)[[:space:]]*,[[:space:]]*\"\"[[:space:]]*[,)]" },
        { &g_on_empty2, ",[[:space:]]*\"\"[[:space:]]*,[[:space:]]*\"\"[[:space:]]*\\)" },
        { &g_on_empty1, ",[[:space:]]*\"\"[[:space:]]*\\)[[:space:]]*$" },
    };
    int e;
    if (done)
        return 0;
    for (size_t i = 0; i < sizeof pats / sizeof pats[0]; i++)
        if ((e = regcomp(pats[i].re, pats[i].pat, REG_EXTENDED)))
            return reg_fail(pats[i].re, e);
    done = 1;
    return 0;
}

static void to_cap(char *dst, size_t cap, const char *line, const regmatch_t *m)
{
    size_t n = (size_t)(m->rm_eo - m->rm_so);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, line + m->rm_so, n);
    dst[n] = '\0';
}

int to_onto_has(const struct to_state *st, const char *key)
{
    for (int i = 0; i < st->onto_n; i++)
        if (strcmp(st->onto_key[i], key) == 0)
            return 1;
    return 0;
}

int to_onto_add(struct to_state *st, const char *key)
{
    if (to_onto_has(st, key))
        return 0;
    if (st->onto_n >= TO_MAX_ONTO || strlen(key) >= TO_KEY) {
        fprintf(st->err, "%s: ontology key set exceeds %d x %d\n", TO_GATE,
                TO_MAX_ONTO, TO_KEY);
        return 2;
    }
    strcpy(st->onto_key[st->onto_n++], key);
    return 0;
}

int to_checked_has(const struct to_state *st, const char *path)
{
    for (int i = 0; i < st->checked_n; i++)
        if (strcmp(st->checked[i], path) == 0)
            return 1;
    return 0;
}

/* Append path to a capacity-checked list; overflow is a loud exit 2. */
int to_list_add(char (*list)[TO_PATH], int *n, int cap, const char *what,
                FILE *err, const char *path)
{
    if (*n >= cap || strlen(path) >= TO_PATH) {
        fprintf(err, "%s: %s exceeds %d\n", TO_GATE, what, cap);
        return 2;
    }
    strcpy(list[(*n)++], path);
    return 0;
}

int to_mark_checked(struct to_state *st, const char *path)
{
    return to_list_add(st->checked, &st->checked_n, TO_MAX_CHECKED,
                       "checked-file set", st->err, path);
}

/* ── section 1: the ontology's declared keys ─────────────────────────── */

struct to_onto_ctx {
    struct to_state *st;
};

static int to_onto_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_state *st = ((struct to_onto_ctx *)v)->st;
    regmatch_t m[3];
    if (regexec(&g_on_field, line, 3, m, 0) == 0) {
        char sub[TO_SUB], path[200], key[TO_KEY];
        to_cap(sub, sizeof sub, line, &m[1]);
        to_cap(path, sizeof path, line, &m[2]);
        if (ovf(snprintf(key, sizeof key, "%s|%s", sub, path), sizeof key))
            return 2;
        int rc = to_onto_add(st, key);
        if (rc)
            return rc;
    }
    if (regexec(&g_on_judged, line, 0, NULL, 0) == 0)
        st->judged++;
    if (regexec(&g_on_question, line, 0, NULL, 0) == 0)
        st->questions++;
    return 0;
}

static int to_load_ontology(struct to_state *st)
{
    struct to_onto_ctx c = { st };
    int rc = to_each_line(st->onto_path, st->err, to_onto_line, &c);
    if (rc)
        return 2;
    st->onto_count = st->onto_n;
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "ontology row population collapsed — %s parsed as %d rows",
                     st->onto_path, st->onto_count), sizeof hint))
        return 2;
    rc = gate_require_scanned(st->onto_count, 150, TO_GATE, hint);
    if (rc)
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "judged (non-info) ontology rows collapsed to %d",
                     st->judged), sizeof hint))
        return 2;
    rc = gate_require_scanned(st->judged, 20, TO_GATE, hint);
    if (rc)
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "discovery-index question rows collapsed to %d",
                     st->questions), sizeof hint))
        return 2;
    return gate_require_scanned(st->questions, 8, TO_GATE, hint);
}

/* ── section 1b: domain registry and paste site ──────────────────────── */

struct to_dom_ctx {
    struct to_state *st;
};

static int to_dom_has(const char set[][TO_DOM], int n, const char *d)
{
    for (int i = 0; i < n; i++)
        if (strcmp(set[i], d) == 0)
            return 1;
    return 0;
}

static int to_dom_add(char set[][TO_DOM], int *n, const char *d)
{
    if (to_dom_has(set, *n, d))
        return 0;
    if (*n >= TO_MAX_DOM || strlen(d) >= TO_DOM)
        return 2;
    strcpy(set[(*n)++], d);
    return 0;
}

static int to_reg_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_state *st = ((struct to_dom_ctx *)v)->st;
    regmatch_t m[2];
    if (regexec(&g_on_tldom, line, 2, m, 0) != 0)
        return 0;
    char d[TO_DOM];
    to_cap(d, sizeof d, line, &m[1]);
    if (to_dom_add(st->reg_dom, &st->reg_n, d)) {
        fprintf(st->err, "%s: domain registry exceeds %d\n", TO_GATE,
                TO_MAX_DOM);
        return 2;
    }
    return 0;
}

static int to_load_domains(struct to_state *st)
{
    struct to_dom_ctx c = { st };
    int rc = to_each_line(st->domains_path, st->err, to_reg_line, &c);
    if (rc)
        return 2;
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "%s registered %d domain(s) — the domain registry collapsed",
                     st->domains_path, st->reg_n), sizeof hint))
        return 2;
    return gate_require_scanned(st->reg_n, 8, TO_GATE, hint);
}

static void to_squeeze(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++)
        if (!isspace((unsigned char)*r))
            *w++ = *r;
    *w = '\0';
}

/* "<group> <member>" of a TL_LEAF row, or 0 when the line is not one. */
int to_leaf_gm(const char *line, char *g, char *m)
{
    if (regexec(&g_on_tlleaf, line, 0, NULL, 0) != 0)
        return 0;
    const char *p = strchr(line, '(');
    if (!p)
        return 0;
    char buf[512];
    if (strlen(p + 1) >= sizeof buf)
        return 0;
    strcpy(buf, p + 1);
    char *c1 = strchr(buf, ',');
    if (!c1)
        return 0;
    *c1 = '\0';
    char *c2 = strchr(c1 + 1, ',');
    if (!c2)
        return 0;
    *c2 = '\0';
    to_squeeze(buf);
    to_squeeze(c1 + 1);
    if (!buf[0] || !c1[1] || strlen(buf) >= TO_DOM ||
        strlen(c1 + 1) >= TO_DOM)
        return 0;
    strcpy(g, buf);
    strcpy(m, c1 + 1);
    return 1;
}

struct to_merge_ctx {
    struct to_state *st;
    char sub[TO_DOM];
};

static int to_merge_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_merge_ctx *c = v;
    char g[TO_DOM], m[TO_DOM], key[TO_KEY];
    if (!to_leaf_gm(line, g, m))
        return 0;
    if (ovf(snprintf(key, sizeof key, "%s|values.%s.%s", c->sub, g, m),
             sizeof key)) {
        fprintf(c->st->err, "%s: ontology key exceeds %d\n", TO_GATE, TO_KEY);
        return 2;
    }
    int rc = to_onto_add(c->st, key);
    if (rc)
        return rc;
    c->st->dom_table_rows++;
    return 0;
}

static int to_paste_pair(struct to_state *st, const char *sub,
                         const char *tab)
{
    if (strcmp(sub, tab) != 0)
        return to_viol_add(&st->mispaired, st->err,
                           "%s: #define TL_SUB \"%s\" pastes %s_fields.def",
                           st->tu_path, sub, tab);
    if (to_dom_add(st->pasted_dom, &st->pasted_n, sub)) {
        fprintf(st->err, "%s: pasted-domain set exceeds %d\n", TO_GATE,
                TO_MAX_DOM);
        return 2;
    }
    char dfile[TO_PATH];
    if (ovf(snprintf(dfile, sizeof dfile, "%s/%s_fields.def",
                     st->fields_dir, sub), sizeof dfile))
        return 2;
    if (!to_readable(dfile)) {
        fprintf(st->err,
                "%s: FATAL — %s pastes domain '%s' but its field\n"
                "  table is missing or unreadable: %s\n",
                TO_GATE, st->tu_path, sub, dfile);
        return 2;
    }
    if (st->dom_def_n >= TO_MAX_DOM || strlen(dfile) >= TO_PATH) {
        fprintf(st->err, "%s: pasted field-table list exceeds %d\n", TO_GATE,
                TO_MAX_DOM);
        return 2;
    }
    strcpy(st->dom_def[st->dom_def_n++], dfile);
    struct to_merge_ctx mc;
    mc.st = st;
    strcpy(mc.sub, sub);
    return to_each_line(dfile, st->err, to_merge_line, &mc) ? 2 : 0;
}

struct to_paste_ctx {
    struct to_state *st;
    char cur[TO_DOM];
};

static int to_paste_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_paste_ctx *c = v;
    regmatch_t m[2];
    if (regexec(&g_on_tlsub, line, 2, m, 0) == 0) {
        to_cap(c->cur, sizeof c->cur, line, &m[1]);
        return 0;
    }
    if (c->cur[0] == '\0' || regexec(&g_on_tlincl, line, 0, NULL, 0) != 0)
        return 0;
    const char *q = strchr(line, '"');
    const char *name = q ? q + 1 : line;
    const char *sl = strrchr(name, '/');
    const char *base = sl ? sl + 1 : name;
    const char *end = strstr(base, "_fields.def\"");
    char tab[TO_DOM];
    if (end && end > base && (size_t)(end - base) < sizeof tab) {
        memcpy(tab, base, (size_t)(end - base));
        tab[end - base] = '\0';
        int rc = to_paste_pair(c->st, c->cur, tab);
        c->cur[0] = '\0';
        if (rc)
            return rc;
        return 0;
    }
    c->cur[0] = '\0';
    return 0;
}

static int to_half_check(struct to_state *st)
{
    for (int i = 0; i < st->reg_n; i++)
        if (!to_dom_has(st->pasted_dom, st->pasted_n, st->reg_dom[i]))
            if (to_viol_add(&st->half_reg, st->err,
                            "%s: registered in %s but never pasted into g_fields[]",
                            st->reg_dom[i], st->domains_path))
                return 2;
    for (int i = 0; i < st->pasted_n; i++)
        if (!to_dom_has(st->reg_dom, st->reg_n, st->pasted_dom[i]))
            if (to_viol_add(&st->half_reg, st->err,
                            "%s: pasted into g_fields[] but not registered in %s",
                            st->pasted_dom[i], st->domains_path))
                return 2;
    if (st->half_reg.n == 0)
        return 0;
    to_viol_print(st->err, &st->half_reg);
    fprintf(st->err,
            "[%s] HALF-REGISTERED DOMAIN — the domain registry and the\n"
            "  g_fields[] paste site disagree. A registered domain whose table is\n"
            "  never pasted renders every leaf UNKNOWN with no meaning attached;\n"
            "  a pasted domain that is not registered never appears in a rollup.\n",
            TO_GATE);
    if (strcmp(st->mode, "FAIL") == 0)
        return 1;
    return 0;
}

static int to_parse_paste(struct to_state *st)
{
    if (!to_readable(st->tu_path)) {
        fprintf(st->err,
                "%s: FATAL — the g_fields[] paste site is missing or unreadable:\n"
                "  %s\n",
                TO_GATE, st->tu_path);
        return 2;
    }
    struct to_paste_ctx c;
    memset(&c, 0, sizeof c);
    c.st = st;
    int rc = to_each_line(st->tu_path, st->err, to_paste_line, &c);
    if (rc)
        return 2;
    if (st->mispaired.n) {
        to_viol_print(st->err, &st->mispaired);
        fprintf(st->err,
                "[%s] MIS-PAIRED PASTE — a `#define TL_SUB` names a different\n"
                "  domain than the field table pasted under it, so that table's rows\n"
                "  land in the wrong subsystem and the evaluator will never find\n"
                "  them. Keep each #define adjacent to its own #include.\n",
                TO_GATE);
        if (strcmp(st->mode, "FAIL") == 0)
            return 1;
    }
    rc = to_half_check(st);
    if (rc)
        return rc;
    char hint[320];
    if (ovf(snprintf(hint, sizeof hint,
                     "%s pastes %d domain field table(s) into g_fields[] — the paste site changed shape, so the merged ontology this gate checks against is not what the build produces",
                     st->tu_path, st->pasted_n), sizeof hint))
        return 2;
    rc = gate_require_scanned(st->pasted_n, 8, TO_GATE, hint);
    if (rc)
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "the pasted field tables contributed %d TL_LEAF row(s) — a field table was emptied or its row grammar drifted",
                     st->dom_table_rows), sizeof hint))
        return 2;
    return gate_require_scanned(st->dom_table_rows, 8, TO_GATE, hint);
}

/* ── section 2: per-row content contract (both grammars) ────────────── */

struct to_rc_ctx {
    struct to_state *st;
    struct to_viol *dst;
    const char *path;
    const regex_t *start;
    char buf[TO_BUF];
};

static int to_rc_report(struct to_rc_ctx *c, const char *kind)
{
    const char *p = c->buf;
    while (*p == ' ' || *p == '\t')
        p++;
    return to_viol_add(c->dst, c->st->err, "%s: [%s] %.100s...", c->path, kind,
                       p);
}

static int to_rc_judge(struct to_rc_ctx *c)
{
    if (regexec(&g_on_means, c->buf, 0, NULL, 0) == 0)
        return to_rc_report(c, "empty means");
    if (regexec(&g_on_judged, c->buf, 0, NULL, 0) != 0)
        return 0;
    if (regexec(&g_on_empty2, c->buf, 0, NULL, 0) == 0)
        return to_rc_report(c, "empty implies/next");
    if (regexec(&g_on_empty1, c->buf, 0, NULL, 0) == 0)
        return to_rc_report(c, "empty implies/next");
    return 0;
}

static int to_rc_line(void *v, const char *line, size_t len)
{
    (void)len;
    struct to_rc_ctx *c = v;
    int ends = regexec(&g_on_rowend, line, 0, NULL, 0) == 0;
    if (c->buf[0] == '\0') {
        if (regexec(c->start, line, 0, NULL, 0) != 0)
            return 0;
        if (strlen(line) >= sizeof c->buf) {
            fprintf(c->st->err, "%s: macro row exceeds %d\n", TO_GATE,
                    TO_BUF);
            return 2;
        }
        strcpy(c->buf, line);
    } else {
        size_t used = strlen(c->buf), add = strlen(line);
        if (used + add + 1 >= sizeof c->buf) {
            fprintf(c->st->err, "%s: macro row exceeds %d\n", TO_GATE,
                    TO_BUF);
            return 2;
        }
        c->buf[used] = ' ';
        strcpy(c->buf + used + 1, line);
    }
    if (!ends)
        return 0;
    int rc = to_rc_judge(c);
    c->buf[0] = '\0';
    return rc;
}

int to_content_scan(struct to_state *st, struct to_viol *dst,
                    const char *path, int leaf)
{
    struct to_rc_ctx c;
    memset(&c, 0, sizeof c);
    c.st = st;
    c.dst = dst;
    c.path = path;
    c.start = leaf ? &g_on_rsleaf : &g_on_rsfield;
    int rc = to_each_line(path, st->err, to_rc_line, &c);
    if (rc == 1) {
        fprintf(st->err,
                "%s: FATAL — required input missing or unreadable: %s\n",
                TO_GATE, path);
        return 2;
    }
    return rc;
}

static int to_content_phase(struct to_state *st)
{
    int rc = to_content_scan(st, &st->content_bad, st->onto_path, 0);
    for (int i = 0; !rc && i < st->dom_def_n; i++) {
        rc = to_mark_checked(st, st->dom_def[i]);
        if (!rc)
            rc = to_content_scan(st, &st->content_bad, st->dom_def[i], 1);
    }
    if (rc)
        return rc;
    if (st->content_bad.n == 0)
        return 0;
    to_viol_print(st->err, &st->content_bad);
    fprintf(st->err,
            "[%s] the row(s) above ship an EMPTY `means`, or carry a health\n"
            "  rule while leaving `implies`/`next` empty. Every field must state\n"
            "  what it counts; a judged field must also say what a bad value means\n"
            "  and where to look next. See util/telemetry_ontology.h and\n"
            "  util/telemetry_field_table.h.\n",
            TO_GATE);
    if (strcmp(st->mode, "FAIL") == 0)
        return 1;
    return 0;
}

int to_phase_onto(struct to_state *st)
{
    int rc = to_on_init();
    if (!rc)
        rc = to_load_ontology(st);
    if (!rc)
        rc = to_load_domains(st);
    if (!rc)
        rc = to_parse_paste(st);
    if (!rc)
        rc = to_content_phase(st);
    return rc;
}
