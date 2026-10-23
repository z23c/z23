/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — test-registration drift guard of the C23 lint
 * runtime (check-test-registration). Catalog and runners are read
 * natively; tracked files via lint_git_index_foreach.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { TR_MAX = 4096, TR_NAME = 96, TR_LINE = 8192, TR_ORPH = 64 };

struct tr_set { char n[TR_MAX][TR_NAME]; int c; };
struct tr_map { char n[TR_MAX][TR_NAME]; char f[TR_MAX][RS_PATH]; int c; };
struct tr_rows { char r[TR_ORPH][RS_PATH + 64]; int c; };

static const char k_tr_dir[] = "tests/harness/src";
static const char k_tr_par[] = "tests/harness/src/test_parallel.c";
static const char k_tr_ser[] = "tests/harness/src/test.c";
static const char k_tr_cat[] = "tools/dev/test_group_catalog.def";
static const char k_tr_leaf[] = "tools/dev/test_semantic_leaves.def";

static int tr_has(const struct tr_set *s, const char *n)
{
    int i;
    for (i = 0; i < s->c; i++)
        if (strcmp(s->n[i], n) == 0)
            return 1;
    return 0;
}

static int tr_add(struct tr_set *s, const char *n)
{
    size_t k = strlen(n);
    if (tr_has(s, n))
        return 0;
    if (s->c >= TR_MAX || k >= TR_NAME)
        return die("z23-lint: test-registration overflow\n", "");
    memcpy(s->n[s->c++], n, k + 1);
    return 0;
}

static int tr_add_dup(struct tr_set *s, const char *n, int *dups)
{
    if (tr_has(s, n)) {
        (*dups)++;
        return 0;
    }
    return tr_add(s, n);
}

static int tr_macro_line(char *buf, const char *mac, size_t ml,
                         struct tr_set *s, int *dups)
{
    char *p = buf, *e, name[TR_NAME];
    while (*p == ' ' || *p == '\t')
        p++;
    if (strncmp(p, mac, ml) != 0 || p[ml] != '(')
        return 0;
    p += ml + 1;
    e = strchr(p, ')');
    if (!e)
        return 0;
    *e = '\0';
    if (ovf(snprintf(name, sizeof name, "%s", p), sizeof name))
        return 2;
    return tr_add_dup(s, name, dups);
}

static int tr_parse_macro(const char *path, const char *mac, struct tr_set *s)
{
    FILE *f = fopen(path, "r");
    char buf[TR_LINE];
    int rc = 0, dups = 0;
    size_t ml;
    if (!f) {
        fprintf(stderr, "check_test_registration: FATAL — expected runner "
                        "file missing: %s\n", path);
        fputs("  The test-runner layout drifted; refusing to report "
              "'clean'.\n", stderr);
        return 2;
    }
    ml = strlen(mac);
    s->c = 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f))
        rc = tr_macro_line(buf, mac, ml, s, &dups);
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    if (rc)
        return rc;
    if (dups) {
        fprintf(stderr, "FAIL: duplicate test group registration(s) in %s:\n",
                path);
        fputs("  Each parallel test group must have one canonical row.\n",
              stderr);
        return 1;
    }
    return 0;
}

static int tr_uniq_st(void)
{
    struct tr_set s = {0};
    int d = 0, rc;
    rc = tr_add_dup(&s, "alpha", &d) || tr_add_dup(&s, "beta", &d);
    if (rc || d)
        return die("check_test_registration: FATAL — uniqueness selftest "
                   "rejected clean input\n", "");
    s.c = 0;
    d = 0;
    tr_add_dup(&s, "alpha", &d);
    tr_add_dup(&s, "beta", &d);
    tr_add_dup(&s, "alpha", &d);
    if (d != 1)
        return die("check_test_registration: FATAL — uniqueness negative "
                   "control failed\n", "");
    return 0;
}

static int tr_need(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        return 0;
    fprintf(stderr, "check_test_registration: FATAL — expected runner "
                    "file missing: %s\n", path);
    fputs("  The test-runner layout drifted; refusing to report 'clean'.\n",
          stderr);
    return 2;
}

static int tr_serial(struct tr_set *s)
{
    FILE *f = fopen(k_tr_ser, "r");
    char buf[TR_LINE];
    int rc = 0;
    if (!f) {
        fprintf(stderr, "check_test_registration: FATAL — grep over %s "
                        "failed\n", k_tr_ser);
        return 2;
    }
    s->c = 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        char *p = buf;
        while ((p = strstr(p, "test_")) != NULL) {
            char *q = p + 5, name[TR_NAME];
            size_t n = 0;
            while (n + 1 < sizeof name
                   && (isalnum((unsigned char)*q) || *q == '_'))
                name[n++] = *q++;
            name[n] = '\0';
            if (n && q[0] == '(' && q[1] == ')')
                rc = tr_add(s, name);
            p = q;
        }
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", k_tr_ser);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", k_tr_ser);
    return rc;
}

static int tr_is_entry(const char *path, const char *name)
{
    FILE *f = fopen(path, "r");
    char buf[TR_LINE], want[128];
    int hit = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return -1;
    }
    if (ovf(snprintf(want, sizeof want, "int test_%s(void)", name),
            sizeof want)) {
        fclose(f);
        return -1;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (strcmp(buf, want) == 0) {
            hit = 1;
            break;
        }
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return -1;
    }
    fclose(f);
    return hit;
}

static int tr_is_src(const char *path, const char **base_out)
{
    const char *base;
    size_t n, dl = strlen(k_tr_dir);
    if (strncmp(path, k_tr_dir, dl) != 0 || path[dl] != '/')
        return 0;
    base = path + dl + 1;
    if (strchr(base, '/'))
        return 0;
    n = strlen(base);
    if (n < 3 || strcmp(base + n - 2, ".c") != 0)
        return 0;
    if (strncmp(base, "test_", 5) != 0)
        return 0;
    if (strcmp(base, "test_parallel.c") == 0 || strcmp(base, "test.c") == 0)
        return 0;
    *base_out = base;
    return 1;
}

struct tr_ep_ctx {
    struct tr_set *runs, *seen;
    struct tr_rows *orph;
    int entries;
    int rc;
};

static int tr_note_entry(struct tr_ep_ctx *c, const char *name, const char *path)
{
    if (tr_has(c->seen, name))
        return 0;
    if (tr_add(c->seen, name))
        return 2;
    c->entries++;
    if (tr_has(c->runs, name))
        return 0;
    if (c->orph->c >= TR_ORPH)
        return die("z23-lint: test-registration overflow\n", "");
    if (ovf(snprintf(c->orph->r[c->orph->c], sizeof c->orph->r[0],
                     "%s\t%s", name, path), sizeof c->orph->r[0]))
        return 2;
    c->orph->c++;
    return 0;
}

static int tr_on_test(const char *path, int stage, void *ctx)
{
    if (stage != 0)
        return 0;
    struct tr_ep_ctx *c = ctx;
    const char *base;
    int hit;
    if (c->rc)
        return c->rc;
    if (!tr_is_src(path, &base))
        return 0;
    {
        char nm[TR_NAME];
        size_t n = strlen(base);
        memcpy(nm, base, n - 2);
        nm[n - 2] = '\0';
        hit = tr_is_entry(path, nm + 5);
        if (hit < 0) {
            c->rc = 2;
            return 2;
        }
        if (!hit)
            return 0;
        c->rc = tr_note_entry(c, nm + 5, path);
    }
    return c->rc;
}

static int tr_index_file(struct tr_map *m, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[TR_LINE];
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        char *p, name[TR_NAME];
        size_t k;
        if (strncmp(buf, "int test_", 9) != 0)
            continue;
        p = buf + 9;
        k = 0;
        while (k + 1 < sizeof name
               && (isalnum((unsigned char)*p) || *p == '_'))
            name[k++] = *p++;
        name[k] = '\0';
        if (strcmp(p, "(void)\n") != 0 && strcmp(p, "(void)") != 0)
            continue;
        if (m->c >= TR_MAX) {
            fclose(f);
            return die("z23-lint: test-registration overflow\n", "");
        }
        memcpy(m->n[m->c], name, k + 1);
        memcpy(m->f[m->c], path, strlen(path) + 1);
        m->c++;
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    fclose(f);
    return 0;
}

static int tr_index_defs(struct tr_map *m)
{
    struct dirent **names = NULL;
    int n = scandir(k_tr_dir, &names, NULL, alphasort);
    int rc = 0, i;
    m->c = 0;
    if (n < 0)
        return die("z23-lint: cannot scan %s\n", k_tr_dir);
    for (i = 0; i < n; i++) {
        size_t kn = strlen(names[i]->d_name);
        if (rc == 0 && kn >= 3 && strcmp(names[i]->d_name + kn - 2, ".c") == 0) {
            char path[4096];
            if (ovf(snprintf(path, sizeof path, "%s/%s", k_tr_dir,
                             names[i]->d_name), sizeof path))
                rc = 2;
            else
                rc = tr_index_file(m, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static const char *tr_def_file(const struct tr_map *m, const char *name)
{
    int i;
    for (i = 0; i < m->c; i++)
        if (strcmp(m->n[i], name) == 0)
            return m->f[i];
    return NULL;
}

static int tr_union(struct tr_set *runs, const struct tr_set *cat,
                    const struct tr_set *ser)
{
    int i, rc = 0;
    for (i = 0; rc == 0 && i < cat->c; i++)
        rc = tr_add(runs, cat->n[i]);
    for (i = 0; rc == 0 && i < ser->c; i++)
        rc = tr_add(runs, ser->n[i]);
    return rc;
}

static int tr_walk_src(struct tr_ep_ctx *ep)
{
    struct dirent **names = NULL;
    int n = scandir(k_tr_dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return die("z23-lint: cannot scan %s\n", k_tr_dir);
    for (i = 0; i < n; i++) {
        if (rc == 0) {
            char path[4096];
            if (ovf(snprintf(path, sizeof path, "%s/%s", k_tr_dir,
                             names[i]->d_name), sizeof path))
                rc = 2;
            else
                rc = tr_on_test(path, 0, ep);
        }
        free(names[i]);
    }
    free(names);
    return rc ? rc : ep->rc;
}

/* The shared native git-index reader refuses a mandatory extension it does
 * not interpret by naming it in badext: reading past one could silently
 * yield a PARTIAL file list, so this gate refuses to grade rather than pass
 * on a short list. Same message shape as the other index gates. */
static int tr_from_index(struct tr_ep_ctx *ep)
{
    char badext[5] = "";
    int rc = lint_git_index_foreach(tr_on_test, ep, badext);
    if (badext[0]) {
        fprintf(stderr,
                "z23-lint: UNPROVEN — the git index carries a mandatory\n"
                "  extension ('%s') this native reader does not interpret;\n"
                "  reading past it could silently yield a PARTIAL file\n"
                "  list. Refusing to grade. Re-create the index without\n"
                "  split-index/sparse extensions, or teach\n"
                "  lint_git_index_foreach the extension first.\n",
                badext);
        return 2;
    }
    return rc;
}

static int tr_collect_entries(struct tr_ep_ctx *ep)
{
    int rc;
    if (lint_prod_scan()) {
        rc = tr_from_index(ep);
        if (rc)
            return rc;
        return ep->rc;
    }
    return tr_walk_src(ep);
}

static int tr_drift_one(const char *name, const struct tr_set *cat,
                        const struct tr_map *defs, char drift[][RS_PATH + 64],
                        int *ndrift, int *serial_checked)
{
    const char *df, *base, *parent;
    char pn[TR_NAME];
    size_t k;
    if (tr_has(cat, name)) {
        (*serial_checked)++;
        return 0;
    }
    df = tr_def_file(defs, name);
    if (!df)
        return 0;
    (*serial_checked)++;
    base = strrchr(df, '/');
    base = base ? base + 1 : df;
    parent = base + (strncmp(base, "test_", 5) == 0 ? 5 : 0);
    k = strlen(parent);
    if (k >= 2 && strcmp(parent + k - 2, ".c") == 0)
        k -= 2;
    if (k >= sizeof pn)
        return 0;
    memcpy(pn, parent, k);
    pn[k] = '\0';
    if (tr_has(cat, pn))
        return 0;
    if (*ndrift < 64)
        snprintf(drift[(*ndrift)++], sizeof drift[0], "%s\t%s", name, df);
    return 0;
}

static void tr_print_row(const char *row)
{
    const char *tab = strchr(row, '\t');
    if (!tab)
        return;
    printf("    test_%.*s   (%s)\n", (int)(tab - row), row, tab + 1);
}

static int tr_report(int ndrift, char drift[][RS_PATH + 64],
                     const struct tr_rows *orph, int entries, int catc,
                     int serial_checked)
{
    int i;
    if (ndrift) {
        fputs("FAIL: test(s) dispatched ONLY by the legacy serial runner "
              "(test.c) and\n  ABSENT from the canonical registry in "
              "tools/dev/test_group_catalog.def.\n"
              "  `make test-parallel` is the doctrine runner and the\n"
              "  acceptance gate; build/bin/test_zcl is never run. These "
              "therefore\n  execute in NO gate and prove NOTHING:\n\n",
              stdout);
        for (i = 0; i < ndrift; i++)
            tr_print_row(drift[i]);
        fputs("\n  Fix: add ZCL_TEST_GROUP(<name>) to "
              "tools/dev/test_group_catalog.def — and\n"
              "  RUN it (make t-fast ONLY=test_<name>) before assuming it "
              "passes.\n  Do NOT delete the test, and do NOT silence this by "
              "removing the\n  test.c dispatch.\n", stdout);
        return 1;
    }
    if (orph->c) {
        fputs("FAIL: test entry point(s) DEFINED + COMPILED but dispatched "
              "by NEITHER\n  the canonical catalog nor the serial runner\n"
              "  (test.c). They prove NOTHING — green forever, never "
              "executed:\n\n", stdout);
        for (i = 0; i < orph->c; i++)
            tr_print_row(orph->r[i]);
        fputs("\n  Fix: add ZCL_TEST_GROUP(<name>) to "
              "tools/dev/test_group_catalog.def (the doctrine\n"
              "  `make test` runner), or\n"
              "  dispatch it from tests/harness/src/test.c. Do NOT delete "
              "the test to\n  silence this gate.\n", stdout);
        return 1;
    }
    printf("check_test_registration: clean — all %d test entry points are "
           "dispatched\n  (%d registered in the canonical catalog; the rest "
           "covered by the serial runner)\n  canonical-registry drift: 0 of "
           "%d serial-dispatched name(s)\n  run only under the legacy test.c "
           "runner\n", entries, catc, serial_checked);
    return 0;
}

static int tr_eval(struct tr_set *cat)
{
    static struct tr_set ser, runs, seen;
    static struct tr_rows orph;
    static struct tr_map defs;
    struct tr_ep_ctx ep;
    char drift[64][RS_PATH + 64];
    int ndrift = 0, rc, i, serial_checked = 0;
    ser.c = runs.c = seen.c = orph.c = 0;
    defs.c = 0;
    rc = tr_serial(&ser);
    if (rc)
        return rc;
    rc = tr_union(&runs, cat, &ser);
    if (rc)
        return rc;
    ep.runs = &runs;
    ep.orph = &orph;
    ep.seen = &seen;
    ep.entries = 0;
    ep.rc = 0;
    rc = tr_collect_entries(&ep);
    if (rc)
        return rc;
    if (ep.entries < 100) {
        fprintf(stderr, "check_test_registration: FATAL — only %d "
                        "filename-matching test\n  entry points found under "
                        "%s (expected >=100).\n", ep.entries, k_tr_dir);
        return 2;
    }
    rc = tr_index_defs(&defs);
    if (rc)
        return rc;
    if (defs.c < 100) {
        fprintf(stderr, "check_test_registration: FATAL — indexed only %d "
                        "entry-point\n  definitions under %s (expected "
                        ">=100).\n", defs.c, k_tr_dir);
        return 2;
    }
    for (i = 0; i < ser.c; i++)
        tr_drift_one(ser.n[i], cat, &defs, drift, &ndrift, &serial_checked);
    if (serial_checked < 100) {
        fprintf(stderr, "check_test_registration: FATAL — only %d "
                        "serial-dispatched\n  names resolved against the "
                        "canonical registry (expected >=100).\n",
                serial_checked);
        return 2;
    }
    return tr_report(ndrift, drift, &orph, ep.entries, cat->c, serial_checked);
}

/* ---- semantic-leaf proof --------------------------------------------------
 * Every ZCL_TEST_SEMANTIC_LEAF(<g>) row asserts that tests/harness/src/
 * test_<g>.c is a proof leaf: nothing else can depend on it, so a change to it
 * affects exactly its own group. That claim is PROVEN here, not trusted:
 *  (a) no file-scope function/object definition with external linkage except
 *      the entry point test_<g> (extern declarations/prototypes are fine);
 *  (b) no #include of a .c or .inc body;
 *  (c) the identifier test_<g> appears in no other tracked C source/header/
 *      registry except the runner plumbing (test.c, test_parallel.c).
 * The scan is comment/string/char-literal aware and fails closed: a file
 * scope construct it cannot classify rejects the row (never accepts it). */
enum { TR_BUF = 2 * 1024 * 1024, TR_WHY = 256 };
enum { TW_NONE, TW_STATIC, TW_TYPEDEF, TW_EXTERN, TW_SA, TW_ATTR, TW_TAG,
       TW_QUAL };

static char tr_buf[TR_BUF];

struct tr_leaf { char n[TR_NAME]; char why[TR_WHY]; };
struct tr_leaves { struct tr_leaf l[TR_MAX]; int c; };

struct tr_sc { const char *entry; char why[TR_WHY]; int entry_seen; };

struct tr_dc {
    int ntok, paren, brk, body, post_body;
    int is_static, is_typedef, is_extern, is_assign, is_sa, attr_next;
    int call, funcptr, macro_first, first_tag, has_tag, prev_word;
    char name[TR_NAME], fname[TR_NAME], prev[TR_NAME];
};

static const char *const k_tr_runner_ref[] = { "tests/harness/src/test.c",
                                               "tests/harness/src/test_parallel.c" };

static size_t tr_skip_lit(char *b, size_t i, size_t n, char q)
{
    b[i++] = ' ';
    while (i < n && b[i] != q && b[i] != '\n') {
        if (b[i] == '\\' && i + 1 < n && b[i + 1] != '\n')
            b[i++] = ' ';
        b[i++] = ' ';
    }
    if (i < n && b[i] == q)
        b[i++] = ' ';
    return i;
}

static size_t tr_skip_cmt(char *b, size_t i, size_t n, int block)
{
    while (i < n) {
        if (block && b[i] == '*' && i + 1 < n && b[i + 1] == '/') {
            b[i++] = ' ';
            b[i++] = ' ';
            return i;
        }
        if (!block && b[i] == '\n')
            return i;
        if (b[i] != '\n')
            b[i] = ' ';
        i++;
    }
    return i;
}

/* Blank comments, string and character literals in place (newlines kept). */
static void tr_blank(char *b, size_t n)
{
    size_t i = 0;
    while (i < n) {
        int nx = i + 1 < n;
        if (b[i] == '/' && nx && (b[i + 1] == '*' || b[i + 1] == '/'))
            i = tr_skip_cmt(b, i, n, b[i + 1] == '*');
        else if (b[i] == '"')
            i = tr_skip_lit(b, i, n, '"');
        else if (b[i] == '\'' && !(i && isalnum((unsigned char)b[i - 1])))
            i = tr_skip_lit(b, i, n, '\'');
        else
            i++;
    }
}

/* Blank preprocessor directive lines (with backslash continuations). */
static void tr_blank_directives(char *b, size_t n)
{
    size_t i = 0;
    while (i < n) {
        size_t s = i;
        int esc = 0, dir;
        while (s < n && (b[s] == ' ' || b[s] == '\t'))
            s++;
        dir = s < n && b[s] == '#';
        while (i < n && !(b[i] == '\n' && !esc)) {
            esc = dir && b[i] == '\\';
            if (dir && b[i] != '\n')
                b[i] = ' ';
            i++;
        }
        i++;
    }
}

/* Copy the target of a raw `#include "x"` / `#include <x>` line into out;
 * 0 if the line is not an include directive. */
static int tr_include_target(const char *s, char *out, size_t cap)
{
    size_t k;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s++ != '#')
        return 0;
    while (*s == ' ' || *s == '\t')
        s++;
    if (strncmp(s, "include", 7) != 0)
        return 0;
    s += 7;
    s += strcspn(s, "\"<\n");
    if (*s != '"' && *s != '<')
        return 0;
    s++;
    k = strcspn(s, "\">\n");
    if (k + 1 > cap)
        return 0;
    memcpy(out, s, k);
    out[k] = '\0';
    return 1;
}

static int tr_has_sfx(const char *s, const char *sfx)
{
    size_t k = strlen(s), m = strlen(sfx);
    return k > m && strcmp(s + k - m, sfx) == 0;
}

/* Visit every include target in raw text; fn(target, ctx) returns nonzero to
 * stop and is propagated. */
static int tr_each_include(const char *b, int (*fn)(const char *, void *),
                           void *ctx)
{
    const char *p = b;
    char t[RS_PATH];
    int rc = 0;
    while (!rc && p && *p) {
        if (tr_include_target(p, t, sizeof t))
            rc = fn(t, ctx);
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return rc;
}

static int tr_inc_body_cb(const char *t, void *ctx)
{
    (void)ctx;
    return tr_has_sfx(t, ".c") || tr_has_sfx(t, ".inc");
}

static int tr_includes_body(const char *b)
{
    return tr_each_include(b, tr_inc_body_cb, NULL);
}

/* .def registries are data unless some C file #includes them: record the
 * basename of every included .def so a name mention there only counts when
 * the registry is compiled. */
static struct tr_set tr_incdefs;

static int tr_incdef_cb(const char *t, void *ctx)
{
    const char *base = strrchr(t, '/');
    (void)ctx;
    base = base ? base + 1 : t;
    if (tr_has_sfx(base, ".def") && strlen(base) < TR_NAME)
        return tr_add(&tr_incdefs, base) != 0;
    return 0;
}

static int tr_kw(const char *w)
{
    static const struct { const char *n; int code; } t[] = {
        {"static", TW_STATIC}, {"typedef", TW_TYPEDEF},
        {"extern", TW_EXTERN}, {"_Static_assert", TW_SA},
        {"static_assert", TW_SA}, {"__attribute__", TW_ATTR},
        {"__attribute", TW_ATTR}, {"_Alignas", TW_ATTR},
        {"alignas", TW_ATTR}, {"__declspec", TW_ATTR},
        {"struct", TW_TAG}, {"union", TW_TAG}, {"enum", TW_TAG},
        {"const", TW_QUAL}, {"volatile", TW_QUAL}, {"restrict", TW_QUAL},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if (strcmp(w, t[i].n) == 0)
            return t[i].code;
    return TW_NONE;
}

static void tr_word(struct tr_dc *d, const char *w)
{
    int kw;
    if (d->paren || d->brk)
        return;
    kw = tr_kw(w);
    d->ntok++;
    d->post_body += d->body;
    d->is_static |= kw == TW_STATIC;
    d->is_typedef |= kw == TW_TYPEDEF;
    d->is_extern |= kw == TW_EXTERN;
    d->is_sa |= kw == TW_SA;
    d->attr_next |= kw == TW_ATTR;
    d->has_tag |= kw == TW_TAG;
    d->first_tag |= kw == TW_TAG && d->ntok == 1;
    if (!d->is_assign && kw != TW_QUAL)
        snprintf(d->name, sizeof d->name, "%s", w);
    snprintf(d->prev, sizeof d->prev, "%s", w);
    d->prev_word = 1;
}

static void tr_open_paren(struct tr_dc *d, const char *rest)
{
    if (!d->paren && !d->brk) {
        rest += strspn(rest, " \t\n");
        if (d->attr_next)
            d->attr_next = 0;
        else if (!d->call && !d->is_sa && *rest == '*')
            d->funcptr = 1;
        else if (!d->call && !d->is_sa && d->prev_word) {
            d->call = 1;
            d->macro_first = d->ntok == 1;
            snprintf(d->fname, sizeof d->fname, "%s", d->prev);
        }
        d->ntok++;
    }
    d->paren++;
    d->prev_word = 0;
}

static void tr_punct(struct tr_dc *d, char c, const char *rest)
{
    if (c == '(') {
        tr_open_paren(d, rest);
        return;
    }
    if (c == ')' && d->paren)
        d->paren--;
    else if (c == '[' && !d->paren)
        d->brk++;
    else if (c == ']' && d->brk && !d->paren)
        d->brk--;
    else if (!d->paren && !d->brk) {
        d->ntok++;
        d->is_assign |= c == '=';
    }
    d->prev_word = 0;
}

static int tr_fin_func(const struct tr_dc *d, struct tr_sc *sc)
{
    if (d->macro_first) {
        snprintf(sc->why, sizeof sc->why, "file-scope macro invocation or "
                 "implicit-int definition '%s'", d->fname);
        return 1;
    }
    if (d->call && strcmp(d->fname, sc->entry) == 0) {
        sc->entry_seen = 1;
        return 0;
    }
    if (d->is_static)
        return 0;
    snprintf(sc->why, sizeof sc->why, "non-static function definition '%s'",
             d->call ? d->fname : d->name);
    return 1;
}

/* A statement with a call-shaped declarator and no initializer is a function
 * prototype (fine) unless it is a bare macro invocation (fail closed). */
static int tr_fin_proto(const struct tr_dc *d, struct tr_sc *sc)
{
    if (!d->macro_first)
        return 0;
    snprintf(sc->why, sizeof sc->why, "file-scope macro invocation '%s'",
             d->fname);
    return 1;
}

static int tr_fin_semi(const struct tr_dc *d, struct tr_sc *sc)
{
    if (d->ntok == 0 || d->is_sa || d->is_typedef || d->is_static ||
        d->is_extern)
        return 0;
    if (d->call && !d->funcptr && !d->is_assign)
        return tr_fin_proto(d, sc);
    if (d->first_tag && d->ntok == 2 && !d->body)
        return 0;
    if (d->body && !d->post_body && !d->is_assign)
        return 0;
    snprintf(sc->why, sizeof sc->why, "non-static object definition '%s'",
             d->name);
    return 1;
}

/* 0 aggregate/initializer body, 1 function definition, 2 unrecognized. */
static int tr_brace_kind(const struct tr_dc *d)
{
    if (d->is_assign || d->is_typedef)
        return 0;
    if (d->call || d->funcptr)
        return 1;
    return d->has_tag ? 0 : 2;
}

static int tr_skip_braces(const char *b, size_t *i, size_t n)
{
    int depth = 0;
    for (size_t k = *i; k < n; k++) {
        if (b[k] == '{')
            depth++;
        else if (b[k] == '}' && --depth == 0) {
            *i = k + 1;
            return 0;
        }
    }
    return -1;
}

static int tr_open_brace(struct tr_dc *d, const char *b, size_t *i, size_t n,
                         struct tr_sc *sc)
{
    int kind = tr_brace_kind(d), rc = 0;
    if (tr_skip_braces(b, i, n) != 0) {
        snprintf(sc->why, sizeof sc->why, "unbalanced braces");
        return 1;
    }
    if (kind == 2) {
        snprintf(sc->why, sizeof sc->why, "unclassifiable file-scope block");
        return 1;
    }
    if (kind == 1) {
        rc = tr_fin_func(d, sc);
        memset(d, 0, sizeof *d);
        return rc;
    }
    d->body = 1;
    d->ntok++;
    return 0;
}

static size_t tr_word_end(const char *b, size_t i, size_t n, char *w)
{
    size_t k = 0;
    while (i < n && (isalnum((unsigned char)b[i]) || b[i] == '_')) {
        if (k + 1 < TR_NAME)
            w[k++] = b[i];
        i++;
    }
    w[k] = '\0';
    return i;
}

/* Consume one non-space token at b[*ip]; nonzero when it proves a violation. */
static int tr_scan_tok(struct tr_dc *d, const char *b, size_t *ip, size_t n,
                       struct tr_sc *sc)
{
    size_t i = *ip;
    unsigned char c = (unsigned char)b[i];
    char w[TR_NAME];
    int rc = 0;
    if (isalpha(c) || c == '_') {
        i = tr_word_end(b, i, n, w);
        tr_word(d, w);
    } else if (isdigit(c)) {
        while (i < n && (isalnum((unsigned char)b[i]) || b[i] == '.'))
            i++;
        d->ntok += !d->paren && !d->brk;
    } else if (c == '{' && !d->paren && !d->brk) {
        rc = tr_open_brace(d, b, &i, n, sc);
    } else if (c == ';' && !d->paren) {
        rc = tr_fin_semi(d, sc);
        memset(d, 0, sizeof *d);
        i++;
    } else {
        tr_punct(d, (char)c, b + i + 1);
        i++;
    }
    *ip = i;
    return rc;
}

/* Scan blanked, directive-free source for external-linkage definitions.
 * Returns 0 clean, 1 rejected (sc->why says why). */
static int tr_scan_defs(const char *b, size_t n, struct tr_sc *sc)
{
    struct tr_dc d;
    size_t i = 0;
    memset(&d, 0, sizeof d);
    sc->entry_seen = 0;
    while (i < n) {
        if (isspace((unsigned char)b[i]))
            i++;
        else if (tr_scan_tok(&d, b, &i, n, sc))
            return 1;
    }
    return 0;
}

/* Prove rules (a) and (b) on the text in tr_buf[0..n). */
static int tr_leaf_text(size_t n, struct tr_sc *sc)
{
    if (tr_includes_body(tr_buf)) {
        snprintf(sc->why, sizeof sc->why, "includes a .c or .inc body");
        return 1;
    }
    tr_blank(tr_buf, n);
    tr_blank_directives(tr_buf, n);
    if (tr_scan_defs(tr_buf, n, sc))
        return 1;
    if (!sc->entry_seen) {
        snprintf(sc->why, sizeof sc->why, "does not define its entry point %s",
                 sc->entry);
        return 1;
    }
    return 0;
}

static int tr_load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    *n = fread(tr_buf, 1, TR_BUF - 1, f);
    int bad = ferror(f) || fgetc(f) != EOF;
    fclose(f);
    tr_buf[*n] = '\0';
    return bad;
}

static void tr_leaf_file(struct tr_leaf *lf)
{
    char path[RS_PATH], entry[TR_NAME + 8];
    struct tr_sc sc = {0};
    size_t n = 0;
    if (ovf(snprintf(path, sizeof path, "%s/test_%s.c", k_tr_dir, lf->n),
            sizeof path) ||
        ovf(snprintf(entry, sizeof entry, "test_%s", lf->n), sizeof entry)) {
        snprintf(lf->why, sizeof lf->why, "name too long");
        return;
    }
    sc.entry = entry;
    if (tr_load(path, &n)) {
        snprintf(lf->why, sizeof lf->why, "source file missing or unreadable");
        return;
    }
    if (tr_leaf_text(n, &sc))
        snprintf(lf->why, sizeof lf->why, "%s", sc.why);
}

static struct tr_leaf *tr_leaf_find(struct tr_leaves *ls, const char *g)
{
    for (int i = 0; i < ls->c; i++)
        if (strcmp(ls->l[i].n, g) == 0)
            return &ls->l[i];
    return NULL;
}

/* `int test_<g>(void);` is a declaration, not a use: it names the symbol the
 * runner links against without calling or referencing it. */
static int tr_is_proto_decl(const char *start, const char *p, const char *after)
{
    const char *q = p;
    while (q > start && (q[-1] == ' ' || q[-1] == '\t'))
        q--;
    if (q - start < 3 || strncmp(q - 3, "int", 3) != 0 ||
        (q - start > 3 && (isalnum((unsigned char)q[-4]) || q[-4] == '_')))
        return 0;
    after += strspn(after, " \t");
    if (strncmp(after, "(void)", 6) != 0)
        return 0;
    after += 6;
    after += strspn(after, " \t");
    return *after == ';';
}

/* Rule (c): note every leaf whose entry point `test_<g>` appears as a code
 * identifier in the blanked text of tr_buf, other than in its own file. */
enum { TR_DEFHITS = 4096 };
static struct { int leaf; char path[RS_PATH]; } tr_defhit[TR_DEFHITS];
static int tr_ndefhit;

static void tr_note_ref(struct tr_leaves *ls, struct tr_leaf *lf, const char *path)
{
    char own[RS_PATH];
    snprintf(own, sizeof own, "%s/test_%s.c", k_tr_dir, lf->n);
    if (strcmp(own, path) == 0)
        return;
    if (tr_has_sfx(path, ".def")) {
        if (tr_ndefhit < TR_DEFHITS) {
            tr_defhit[tr_ndefhit].leaf = (int)(lf - ls->l);
            snprintf(tr_defhit[tr_ndefhit].path, RS_PATH, "%s", path);
            tr_ndefhit++;
        } else {
            snprintf(lf->why, sizeof lf->why, "too many registry mentions");
        }
        return;
    }
    snprintf(lf->why, sizeof lf->why, "entry point referenced outside "
             "runner plumbing: %s", path);
}

/* A .def mention counts only when that registry is #included by C. */
static void tr_resolve_defs(struct tr_leaves *ls)
{
    for (int i = 0; i < tr_ndefhit; i++) {
        const char *base = strrchr(tr_defhit[i].path, '/');
        struct tr_leaf *lf = &ls->l[tr_defhit[i].leaf];
        base = base ? base + 1 : tr_defhit[i].path;
        if (!lf->why[0] && tr_has(&tr_incdefs, base))
            snprintf(lf->why, sizeof lf->why, "entry point referenced "
                     "in compiled registry: %s", tr_defhit[i].path);
    }
}

static void tr_refs_in(struct tr_leaves *ls, const char *path)
{
    const char *p = tr_buf;
    char w[TR_NAME];
    while ((p = strstr(p, "test_")) != NULL) {
        struct tr_leaf *lf = NULL;
        int prefixed = p > tr_buf && (isalnum((unsigned char)p[-1]) || p[-1] == '_');
        size_t e = tr_word_end(p, 0, 256, w);
        if (!prefixed && !tr_is_proto_decl(tr_buf, p, p + e))
            lf = tr_leaf_find(ls, w + 5);
        p += e;
        if (!lf || lf->why[0])
            continue;
        tr_note_ref(ls, lf, path);
    }
}

static int tr_ref_suffix(const char *path)
{
    static const char *const sfx[] = { ".c", ".h", ".inc", ".def" };
    size_t k = strlen(path);
    for (size_t i = 0; i < sizeof sfx / sizeof sfx[0]; i++) {
        size_t m = strlen(sfx[i]);
        if (k > m && strcmp(path + k - m, sfx[i]) == 0)
            return 1;
    }
    return 0;
}

static int tr_is_runner_ref(const char *path)
{
    for (size_t i = 0; i < sizeof k_tr_runner_ref / sizeof k_tr_runner_ref[0]; i++)
        if (strcmp(path, k_tr_runner_ref[i]) == 0)
            return 1;
    return 0;
}

static int tr_ref_file(const char *path, struct tr_leaves *ls)
{
    size_t n = 0;
    if (!tr_ref_suffix(path))
        return 0;
    if (tr_load(path, &n)) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    if (!tr_has_sfx(path, ".def") &&
        tr_each_include(tr_buf, tr_incdef_cb, NULL))
        return 2;
    if (tr_is_runner_ref(path) || !strstr(tr_buf, "test_"))
        return 0;
    tr_blank(tr_buf, n);
    tr_refs_in(ls, path);
    return 0;
}

static int tr_ref_index_cb(const char *path, int stage, void *ctx)
{
    return stage == 0 ? tr_ref_file(path, ctx) : 0;
}

static int tr_ref_walk_cb(const char *path, void *ctx)
{
    return tr_ref_file(path, ctx);
}

static int tr_leaf_refs(struct tr_leaves *ls)
{
    char badext[5] = "";
    int rc;
    tr_ndefhit = 0;
    tr_incdefs.c = 0;
    if (!lint_prod_scan()) {
        rc = walk_src("tests/harness/src", 1, tr_ref_walk_cb, ls);
        if (!rc)
            rc = walk_src("tests/harness/include", 1, tr_ref_walk_cb, ls);
        if (!rc)
            tr_resolve_defs(ls);
        return rc;
    }
    rc = lint_git_index_foreach(tr_ref_index_cb, ls, badext);
    if (badext[0]) {
        fprintf(stderr, "z23-lint: UNPROVEN — the git index carries a "
                        "mandatory extension ('%s') this native reader does "
                        "not interpret; refusing to grade.\n", badext);
        return 2;
    }
    if (!rc)
        tr_resolve_defs(ls);
    return rc;
}

static int tr_leaf_gate(const struct tr_set *rows)
{
    static struct tr_leaves ls;
    int i, bad = 0, rc;
    ls.c = 0;
    for (i = 0; i < rows->c; i++) {
        memset(&ls.l[i], 0, sizeof ls.l[i]);
        snprintf(ls.l[i].n, sizeof ls.l[i].n, "%s", rows->n[i]);
        ls.c++;
        tr_leaf_file(&ls.l[i]);
    }
    rc = tr_leaf_refs(&ls);
    if (rc)
        return rc;
    for (i = 0; i < ls.c; i++) {
        if (!ls.l[i].why[0])
            continue;
        if (!bad++)
            fputs("FAIL: ZCL_TEST_SEMANTIC_LEAF row(s) in "
                  "tools/dev/test_semantic_leaves.def are not provable "
                  "leaves:\n", stdout);
        printf("    %s   (%s)\n", ls.l[i].n, ls.l[i].why);
    }
    if (bad)
        fputs("\n  A semantic leaf must define nothing with external linkage "
              "but its test_<g>\n  entry point, include no .c/.inc body, and "
              "be referenced only by the runner.\n  Fix: remove the row (the "
              "file then plans through the semantic graph).\n", stdout);
    return bad ? 1 : 0;
}

int check_test_registration_run(int argc, char **argv)
{
    static struct tr_set leaves;
    struct tr_set cat = {0};
    int rc;
    (void)argc;
    (void)argv;
    rc = tr_uniq_st();
    if (rc)
        return rc;
    rc = tr_need(k_tr_par) || tr_need(k_tr_ser) || tr_need(k_tr_cat)
        || tr_need(k_tr_leaf);
    if (rc)
        return rc;
    rc = tr_parse_macro(k_tr_cat, "ZCL_TEST_GROUP", &cat);
    if (rc)
        return rc;
    rc = tr_parse_macro(k_tr_leaf, "ZCL_TEST_SEMANTIC_LEAF", &leaves);
    if (rc)
        return rc;
    if (cat.c < 100) {
        fprintf(stderr, "check_test_registration: FATAL — only %d test "
                        "catalog entries parsed\n", cat.c);
        return 2;
    }
    rc = tr_leaf_gate(&leaves);
    if (rc)
        return rc;
    return tr_eval(&cat);
}

static int tr_st_parse(void)
{
    struct tr_set s = {0};
    return tr_parse_macro(k_tr_cat, "ZCL_TEST_GROUP", &s) || s.c < 100;
}

static int tr_st_entry(void)
{
    return tr_is_entry("tests/harness/src/test_hex_codec.c", "hex_codec") != 1;
}

/* Prove a literal translation unit through the same text path real rows use. */
static int tr_st_prove(const char *src, const char *entry, struct tr_sc *sc)
{
    int n = snprintf(tr_buf, TR_BUF, "%s", src);
    memset(sc, 0, sizeof *sc);
    sc->entry = entry;
    return n < 0 ? 1 : tr_leaf_text((size_t)n, sc);
}

static int tr_st_expect(const char *label, const char *src, int want_reject,
                        const char *needle)
{
    struct tr_sc sc;
    int rej = tr_st_prove(src, "test_zz", &sc);
    if (rej == want_reject && (!needle || strstr(sc.why, needle)))
        return 0;
    fprintf(stderr, "check_test_registration: FATAL — leaf selftest '%s' "
                    "expected %s (%s), got %s [%s]\n", label,
            want_reject ? "reject" : "accept", needle ? needle : "-",
            rej ? "reject" : "accept", sc.why);
    return 1;
}

static int tr_leaf_st(void)
{
    static const char clean[] =
        "/* int hidden(void) { return 1; } */\n"
        "#include \"test/harness.h\"\n"
        "#define MACRO_FN(x) int x(void) { return 0; }\n"
        "extern int other_symbol(int);\nint proto(void);\n"
        "static int helper(void) { return \"int fake(void) {\"[0]; }\n"
        "static const int tbl[] = { 1, 2 };\n"
        "struct pt { int a; };\ntypedef struct { int b; } pt_t;\n"
        "enum { K_A, K_B };\nstruct fwd;\n"
        "_Static_assert(sizeof(int) == 4, \"x\");\n"
        "int test_zz(void);\nint test_zz(void)\n{\n    return helper();\n}\n";
    int bad = 0;
    bad |= tr_st_expect("clean", clean, 0, NULL);
    bad |= tr_st_expect("helper", "int sbi_consume(void) { return 1; }\n"
                        "int test_zz(void) { return 0; }\n", 1,
                        "non-static function definition 'sbi_consume'");
    bad |= tr_st_expect("object", "int shared = 3;\nint test_zz(void) "
                        "{ return 0; }\n", 1, "non-static object");
    bad |= tr_st_expect("tentative", "int tentative;\nint test_zz(void) "
                        "{ return 0; }\n", 1, "'tentative'");
    bad |= tr_st_expect("aggregate", "struct s { int a; } g;\nint test_zz"
                        "(void) { return 0; }\n", 1, "'g'");
    bad |= tr_st_expect("macro", "DECLARE_THING(x)\nint test_zz(void) "
                        "{ return 0; }\n", 1, "macro");
    bad |= tr_st_expect("include", "#include \"body.c\"\nint test_zz(void) "
                        "{ return 0; }\n", 1, "includes");
    bad |= tr_st_expect("noentry", "static int f(void) { return 0; }\n", 1,
                        "entry point");
    snprintf(tr_buf, TR_BUF, "%s", "int test_p(void);\nint a = test_zz();\n/* test_q */ "
             "\"test_q\" test_zzz\n");
    {
        static struct tr_leaves ls;
        ls.c = 3;
        snprintf(ls.l[0].n, sizeof ls.l[0].n, "zz");
        snprintf(ls.l[1].n, sizeof ls.l[1].n, "q");
        snprintf(ls.l[2].n, sizeof ls.l[2].n, "p");
        memset(ls.l[0].why, 0, sizeof ls.l[0].why);
        memset(ls.l[1].why, 0, sizeof ls.l[1].why);
        memset(ls.l[2].why, 0, sizeof ls.l[2].why);
        tr_blank(tr_buf, strlen(tr_buf));
        tr_refs_in(&ls, "tools/x.c");
        if (!ls.l[0].why[0] || ls.l[1].why[0] || ls.l[2].why[0]) {
            fputs("check_test_registration: FATAL — leaf reference selftest "
                  "failed\n", stderr);
            bad = 1;
        }
    }
    return bad;
}

/* A name in a .def counts only once some C file #includes that registry. */
static int tr_def_st(void)
{
    static struct tr_leaves ls;
    int bad;
    memset(&ls, 0, sizeof ls);
    ls.c = 1;
    snprintf(ls.l[0].n, sizeof ls.l[0].n, "zz");
    tr_ndefhit = 0;
    tr_incdefs.c = 0;
    snprintf(tr_buf, TR_BUF, "%s", "ROW(test_zz)\n");
    tr_refs_in(&ls, "a/data.def");
    tr_resolve_defs(&ls);
    bad = ls.l[0].why[0] != '\0' || tr_ndefhit != 1;
    tr_add(&tr_incdefs, "data.def");
    tr_resolve_defs(&ls);
    bad |= ls.l[0].why[0] == '\0';
    tr_ndefhit = 0;
    tr_incdefs.c = 0;
    if (bad)
        fputs("check_test_registration: FATAL — registry-mention selftest "
              "failed\n", stderr);
    return bad;
}

int check_test_registration_selftest(void)
{
    return st_ok(tr_uniq_st() || tr_st_parse() || tr_st_entry() || tr_leaf_st() ||
                     tr_def_st(),
                 "check_test_registration selftest: PASS — uniqueness "
                 "controls, catalog parse, a filename-matching entry "
                 "point, and the semantic-leaf proof are proven\n");
}
